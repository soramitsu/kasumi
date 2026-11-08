fn shared_read_put(id: &str, value: u64) -> MutationBatch {
    MutationBatch {
        idempotency_key: id.into(),
        read_set: vec![],
        operations: vec![Mutation::Put {
            collection: "docs".into(),
            id: id.into(),
            body: json!({ "value": value }),
            expected: Precondition::Absent,
        }],
    }
}

#[tokio::test]
async fn query_pages_and_snapshot_reads_load_their_documents_through_one_reader() {
    let fixture = CredentialFixture::new().await;
    let ids = ["c", "a", "b"];
    for (value, id) in ids.iter().enumerate() {
        fixture
            .db
            .mutate(fixture.context.clone(), shared_read_put(id, value as u64))
            .await
            .unwrap();
    }
    let generation = fixture.db.engine().generation().unwrap();
    assert!(
        generation.state.collections["docs"]
            .documents
            .values()
            .all(|slot| matches!(slot.as_ref(), DocumentSlot::Stored(_)))
    );
    drop(generation);
    let roots = fixture
        .db
        .engine()
        .application_sources_for_test()
        .unwrap()
        .clone();
    let (opened, open) = roots.reader_cells_for_test();
    // Each point read opens and retires a reader of its own.
    for id in ids {
        assert!(
            fixture
                .db
                .get(&fixture.context, "docs", id)
                .await
                .unwrap()
                .is_some()
        );
    }
    assert_eq!(roots.reader_cells_for_test(), (opened + 3, open));
    // A sorted page loads every candidate twice, for its sort key and for its
    // row, all through one reader.
    let query = |limit: usize| -> QueryRequest {
        serde_json::from_value(json!({
            "collection": "docs",
            "allow_scan": true,
            "sort": ["/value"],
            "limit": limit,
        }))
        .unwrap()
    };
    let page = fixture.db.query(&fixture.context, query(10)).await.unwrap();
    assert_eq!(
        page.rows
            .iter()
            .map(|row| row.id.as_str())
            .collect::<Vec<_>>(),
        ids
    );
    drop(page);
    assert_eq!(roots.reader_cells_for_test(), (opened + 4, open));
    // Its cursor retains no reader; each continuation page opens its own.
    let mut request = query(1);
    let first = fixture
        .db
        .query(&fixture.context, request.clone())
        .await
        .unwrap();
    assert_eq!(roots.reader_cells_for_test(), (opened + 5, open));
    request.cursor = first.cursor.clone();
    drop(first);
    let second = fixture.db.query(&fixture.context, request).await.unwrap();
    assert_eq!(second.rows.len(), 1);
    drop(second);
    assert_eq!(roots.reader_cells_for_test(), (opened + 6, open));
    // A snapshot (batch) read opens one for all of its documents.
    let snapshot = fixture
        .db
        .read_snapshot(
            &fixture.context,
            ReadSnapshotRequest {
                documents: ids
                    .iter()
                    .map(|id| DocumentKey {
                        collection: "docs".into(),
                        id: (*id).into(),
                    })
                    .collect(),
                queries: vec![query(10)],
                time_bounds: None,
            },
        )
        .await
        .unwrap();
    assert!(snapshot.documents.iter().all(|row| row.document.is_some()));
    assert_eq!(snapshot.queries[0].rows.len(), 3);
    drop(snapshot);
    assert_eq!(roots.reader_cells_for_test(), (opened + 7, open));
    // Lease pages share within one page, and keep no reader between pages.
    let lease = fixture
        .db
        .open_snapshot_lease(&fixture.context, OpenSnapshotLease { ttl_ms: 60_000 })
        .await
        .unwrap();
    let (opened, open) = roots.reader_cells_for_test();
    let point = fixture
        .db
        .read_snapshot_page(
            &fixture.context,
            ReadSnapshotPage {
                lease_id: lease.lease_id.clone(),
                documents: ids
                    .iter()
                    .map(|id| DocumentKey {
                        collection: "docs".into(),
                        id: (*id).into(),
                    })
                    .collect(),
            },
        )
        .await
        .unwrap();
    assert_eq!(point.documents.len(), 3);
    drop(point);
    assert_eq!(roots.reader_cells_for_test(), (opened + 1, open));
    let scan = fixture
        .db
        .scan_snapshot_page(
            &fixture.context,
            ScanSnapshotPage {
                lease_id: lease.lease_id.clone(),
                collection: "docs".into(),
                after_id: None,
                limit: 10,
            },
        )
        .await
        .unwrap();
    assert_eq!(scan.documents.len(), 3);
    drop(scan);
    assert_eq!(roots.reader_cells_for_test(), (opened + 2, open));
    fixture
        .db
        .close_snapshot_lease(&fixture.context, &lease.lease_id)
        .await
        .unwrap();
    drop(roots);
    fixture.close().await;
}

#[tokio::test]
async fn document_reads_start_no_load_after_their_native_deadline() {
    let fixture = CredentialFixture::new().await;
    fixture
        .db
        .mutate(fixture.context.clone(), shared_read_put("late", 1))
        .await
        .unwrap();
    let generation = fixture.db.engine().generation().unwrap();
    let roots = fixture
        .db
        .engine()
        .application_sources_for_test()
        .unwrap()
        .clone();
    let cancellation = QueryCancellation::default();
    let load = |reads: &DocumentReads| {
        reads
            .source("docs")?
            .with_record("late", None, &cancellation, |record| {
                assert!(matches!(record, Some(Record::Live(_))));
                Ok(())
            })
            .map_err(source_read_error)
    };
    let (opened, open) = roots.reader_cells_for_test();
    assert_eq!(
        with_document_reads(&generation, std::time::Instant::now(), load).unwrap_err(),
        Error::new(
            ErrorCode::ResourceExhausted,
            "document read deadline exceeded"
        )
    );
    // The refused load opened no reader.
    assert_eq!(roots.reader_cells_for_test(), (opened, open));
    let deadline = std::time::Instant::now() + kasumi_store::NATIVE_READ_TIMEOUT;
    with_document_reads(&generation, deadline, load).unwrap();
    assert_eq!(roots.reader_cells_for_test(), (opened + 1, open));
    drop(generation);
    drop(roots);
    fixture.close().await;
}

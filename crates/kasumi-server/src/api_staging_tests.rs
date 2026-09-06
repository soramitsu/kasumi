#[tokio::test]
async fn native_staging_and_coherent_lease_pages_share_exact_state_and_authority() {
    let fixture = Fixture::new().await;
    let token = fixture.token("person", "tenant-a", "kasumi:read kasumi:write");
    let data = fixture.data();
    let amount = "90071992547409931234567890.123456789";
    let chunks: Vec<_> = (0..2)
        .map(|chunk| kasumi_types::StagedChunk {
            read_set: vec![],
            operations: (chunk * 150..(chunk + 1) * 150)
                .map(|n| kasumi_types::Mutation::Put {
                    collection: "docs".into(),
                    id: format!("r{n:04}"),
                    expected: kasumi_types::Precondition::Absent,
                    body: serde_json::from_str(&format!("{{\"n\":{n},\"amount\":{amount}}}"))
                        .unwrap(),
                })
                .collect(),
        })
        .collect();
    let manifest = kasumi_types::StagedManifest::from_chunks(&chunks).unwrap();
    let reference = kasumi_types::StagedTransactionRef {
        transaction_id: "wire-stage".into(),
        manifest_digest: kasumi_types::staged_digest(&manifest).unwrap().0,
    };
    let begin = kasumi_types::BeginStagedTransaction {
        transaction_id: reference.transaction_id.clone(),
        manifest,
        ttl_ms: 60_000,
    };
    data.begin_staged_transaction(native(
        proto::BeginStagedTransactionRequest {
            request_json: serde_json::to_vec(&begin).unwrap(),
        },
        &token,
    ))
    .await
    .unwrap();
    for (index, chunk) in chunks.into_iter().enumerate() {
        data.append_staged_chunk(native(
            proto::AppendStagedChunkRequest {
                request_json: serde_json::to_vec(&kasumi_types::AppendStagedChunk {
                    transaction: reference.clone(),
                    index,
                    chunk,
                })
                .unwrap(),
            },
            &token,
        ))
        .await
        .unwrap();
    }
    assert_eq!(
        fixture
            .db
            .engine()
            .generation()
            .unwrap()
            .state
            .document_count,
        0
    );
    let open = || proto::OpenSnapshotLeaseRequest {
        request_json: serde_json::to_vec(&kasumi_types::OpenSnapshotLease { ttl_ms: 60_000 })
            .unwrap(),
    };
    let old = data
        .open_snapshot_lease(native(open(), &token))
        .await
        .unwrap()
        .into_inner();
    let old: kasumi_types::SnapshotLease = serde_json::from_slice(&old.response_json).unwrap();
    let commit = data
        .finalize_staged_transaction(native(
            proto::StagedTransactionReference {
                request_json: serde_json::to_vec(&reference).unwrap(),
            },
            &token,
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(commit.versions.is_empty());
    let old_page = data
        .scan_snapshot_page(native(
            proto::ScanSnapshotPageRequest {
                request_json: serde_json::to_vec(&kasumi_types::ScanSnapshotPage {
                    lease_id: old.lease_id.clone(),
                    collection: "docs".into(),
                    after_id: None,
                    limit: 10,
                })
                .unwrap(),
            },
            &token,
        ))
        .await
        .unwrap()
        .into_inner();
    let old_page: kasumi_types::SnapshotScanPage =
        serde_json::from_slice(&old_page.response_json).unwrap();
    assert!(old_page.documents.is_empty());
    assert_eq!(old_page.snapshot.revision, old.revision);
    let fresh = data
        .open_snapshot_lease(native(open(), &token))
        .await
        .unwrap()
        .into_inner();
    let fresh: kasumi_types::SnapshotLease = serde_json::from_slice(&fresh.response_json).unwrap();
    let page = data
        .read_snapshot_page(native(
            proto::ReadSnapshotPageRequest {
                request_json: serde_json::to_vec(&kasumi_types::ReadSnapshotPage {
                    lease_id: fresh.lease_id.clone(),
                    documents: vec![kasumi_types::DocumentKey {
                        collection: "docs".into(),
                        id: "r0299".into(),
                    }],
                })
                .unwrap(),
            },
            &token,
        ))
        .await
        .unwrap()
        .into_inner();
    let page: kasumi_types::SnapshotReadResponse =
        serde_json::from_slice(&page.response_json).unwrap();
    assert_eq!(
        page.documents[0].document.as_ref().unwrap().body["amount"].to_string(),
        amount
    );
    assert_eq!(
        page.documents[0].document.as_ref().unwrap().version,
        commit.revision
    );
    let scan = data
        .scan_snapshot_page(native(
            proto::ScanSnapshotPageRequest {
                request_json: serde_json::to_vec(&kasumi_types::ScanSnapshotPage {
                    lease_id: fresh.lease_id.clone(),
                    collection: "docs".into(),
                    after_id: None,
                    limit: 97,
                })
                .unwrap(),
            },
            &token,
        ))
        .await
        .unwrap()
        .into_inner();
    let scan: kasumi_types::SnapshotScanPage = serde_json::from_slice(&scan.response_json).unwrap();
    assert_eq!(scan.documents.len(), 97);
    assert_eq!(scan.next_after_id.as_deref(), Some("r0096"));
    let status = data
        .staged_transaction_status(native(
            proto::StagedTransactionReference {
                request_json: serde_json::to_vec(&reference).unwrap(),
            },
            &token,
        ))
        .await
        .unwrap()
        .into_inner();
    let status: kasumi_types::StagedTransactionStatus =
        serde_json::from_slice(&status.response_json).unwrap();
    assert_eq!(
        status.outcome.resolved().unwrap().unwrap().revision,
        commit.revision
    );
    let reader = fixture.token("reader", "tenant-a", "kasumi:read");
    assert_eq!(
        data.staged_transaction_status(native(
            proto::StagedTransactionReference {
                request_json: serde_json::to_vec(&reference).unwrap()
            },
            &reader
        ))
        .await
        .unwrap_err()
        .code(),
        Code::PermissionDenied
    );
    assert_eq!(
        data.read_snapshot_page(native(
            proto::ReadSnapshotPageRequest {
                request_json: serde_json::to_vec(&kasumi_types::ReadSnapshotPage {
                    lease_id: fresh.lease_id.clone(),
                    documents: vec![kasumi_types::DocumentKey {
                        collection: "docs".into(),
                        id: "r0000".into()
                    }]
                })
                .unwrap()
            },
            &reader
        ))
        .await
        .unwrap_err()
        .code(),
        Code::FailedPrecondition
    );
    for lease_id in [old.lease_id, fresh.lease_id] {
        data.close_snapshot_lease(native(proto::SnapshotLeaseReference { lease_id }, &token))
            .await
            .unwrap();
    }
    fixture.close().await;
}

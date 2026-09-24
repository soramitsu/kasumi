#[tokio::test]
async fn native_history_archive_and_durable_feed_preserve_exact_rows_and_scope() {
    let fixture = Fixture::new().await;
    fixture
        .db
        .install_archive_destination(
            "cold".into(),
            Arc::new(
                kasumi_store::FilesystemBackupDestination::new(
                    fixture._dir.path().join("persistent/history-backup"),
                    16 << 20,
                    fixture.physical.persistent.clone(),
                )
                .unwrap(),
            ),
        )
        .unwrap();
    let token = fixture.token(
        "person",
        "tenant-a",
        "kasumi:read kasumi:write kasumi:admin",
    );
    let read_only = fixture.token("person", "tenant-a", "kasumi:read");
    let admin = NativeAdmin::new(fixture.registry.clone(), fixture.auth.clone());
    admin
        .create_collection(native(
            proto::CollectionDefinitionRequest {
                definition_json: serde_json::to_vec(&kasumi_types::CollectionDefinition {
                    name: "history".into(),
                    write_mode: kasumi_types::CollectionWriteMode::AppendOnly,
                    retention_class: kasumi_types::CollectionRetentionClass::ArchivableHistory,
                    schema: json!({"type":"object"}),
                    indexes: vec![],
                    strict_read_audit: true,
                })
                .unwrap(),
            },
            &token,
        ))
        .await
        .unwrap();
    let data = fixture.data();
    let batch: kasumi_types::MutationBatch = serde_json::from_str(r#"{"idempotency_key":"native-history","read_set":[],"operations":[{"op":"put","collection":"history","id":"h1","expected":{"kind":"absent"},"body":{"amount":90071992547409931234567890.123456789}}]}"#).unwrap();
    let receipt = data
        .mutate(native(
            proto::MutateRequest {
                batch_json: serde_json::to_vec(&batch).unwrap(),
            },
            &token,
        ))
        .await
        .unwrap()
        .into_inner();
    let request = kasumi_types::ReadChangeFeed {
        collections: BTreeSet::from(["history".into()]),
        start: kasumi_types::ChangeFeedStart::Beginning,
        limit: 10,
    };
    let feed = data
        .read_change_feed(native(
            proto::ReadChangeFeedRequest {
                request_json: serde_json::to_vec(&request).unwrap(),
            },
            &token,
        ))
        .await
        .unwrap()
        .into_inner();
    let feed: kasumi_types::ChangeFeedPage = serde_json::from_slice(&feed.response_json).unwrap();
    let kasumi_types::ChangeFeedPage::Events { events, next, .. } = feed else {
        panic!("unexpected gap")
    };
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].revision, receipt.revision);
    assert_eq!(
        events[0].document.as_ref().unwrap().body["amount"].to_string(),
        "90071992547409931234567890.123456789"
    );
    let archive = kasumi_types::ArchiveHistory {
        archive_id: "native-archive".into(),
        collection: "history".into(),
        cutoff_revision: receipt.revision,
        destination: "cold".into(),
    };
    assert_eq!(
        admin
            .archive_history(native(
                proto::ArchiveHistoryRequest {
                    request_json: serde_json::to_vec(&archive).unwrap()
                },
                &read_only
            ))
            .await
            .unwrap_err()
            .code(),
        Code::PermissionDenied
    );
    admin
        .archive_history(native(
            proto::ArchiveHistoryRequest {
                request_json: serde_json::to_vec(&archive).unwrap(),
            },
            &token,
        ))
        .await
        .unwrap();
    let document = data
        .get(native(
            proto::GetRequest {
                collection: "history".into(),
                id: "h1".into(),
            },
            &token,
        ))
        .await
        .unwrap()
        .into_inner();
    let body: serde_json::Value = serde_json::from_slice(&document.body_json).unwrap();
    assert_eq!(
        body["amount"].to_string(),
        "90071992547409931234567890.123456789"
    );
    assert_eq!(document.version, receipt.revision);
    let request = kasumi_types::ReadChangeFeed {
        collections: BTreeSet::from(["history".into()]),
        start: kasumi_types::ChangeFeedStart::After { cursor: next },
        limit: 10,
    };
    let feed = data
        .read_change_feed(native(
            proto::ReadChangeFeedRequest {
                request_json: serde_json::to_vec(&request).unwrap(),
            },
            &token,
        ))
        .await
        .unwrap()
        .into_inner();
    let feed: kasumi_types::ChangeFeedPage = serde_json::from_slice(&feed.response_json).unwrap();
    assert!(
        matches!(feed, kasumi_types::ChangeFeedPage::Events { events, caught_up: true, .. } if events.is_empty())
    );
    fixture.close().await;
}

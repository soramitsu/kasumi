#[tokio::test]
async fn native_schema_activation_is_atomic_scoped_permanent_and_private() {
    let fixture = Fixture::new().await;
    let token = fixture.token(
        "person",
        "tenant-a",
        "kasumi:read kasumi:write kasumi:admin",
    );
    let read_only = fixture.token("person", "tenant-a", "kasumi:read");
    let wrong_tenant = fixture.token("person", "other", "kasumi:admin");
    let admin = NativeAdmin::new(fixture.registry.clone(), fixture.auth.clone());
    let generation = fixture.db.engine().generation().unwrap();
    let request = kasumi_types::SchemaChangeSet {
        activation_id: "native-financial-schema".into(), expected_incarnation: generation.state.incarnation.clone(), expected_schema_epoch: generation.state.schema_epoch,
        changes: ["journal", "balances"].map(|name| kasumi_types::SchemaChange::Create {
            definition: kasumi_types::CollectionDefinition { name: name.into(), write_mode: kasumi_types::CollectionWriteMode::Mutable, retention_class: kasumi_types::CollectionRetentionClass::Operational,
            schema: serde_json::from_str(r#"{"type":"object","properties":{"amount":{"type":"number","maximum":90071992547409931234567890.123456789}}}"#).unwrap(), indexes: vec![], strict_read_audit: true },
        }).into(),
    };
    let reference = request.reference().unwrap();
    let read = || proto::ReadSchemaRequest { request_json: serde_json::to_vec(&kasumi_types::ReadSchema { collections: BTreeSet::from(["journal".into(), "balances".into()]) }).unwrap() };
    assert_eq!(admin.read_schema(native(read(), &read_only)).await.unwrap_err().code(), Code::PermissionDenied);
    let before = admin.read_schema(native(read(), &token)).await.unwrap().into_inner();
    let before: kasumi_types::SchemaSnapshot = serde_json::from_slice(&before.response_json).unwrap();
    assert!(before.collections.values().all(Option::is_none));
    let wire = || proto::SchemaChangeSetRequest {
        request_json: serde_json::to_vec(&request).unwrap(),
    };
    assert_eq!(
        admin
            .activate_schema(native(wire(), &read_only))
            .await
            .unwrap_err()
            .code(),
        Code::PermissionDenied
    );
    assert!(
        admin
            .activate_schema(native(wire(), &wrong_tenant))
            .await
            .is_err()
    );
    assert!(
        fixture
            .db
            .engine()
            .generation()
            .unwrap()
            .state
            .schema_activations
            .is_empty()
    );
    let receipt = admin
        .activate_schema(native(wire(), &token))
        .await
        .unwrap()
        .into_inner();
    let installed = admin.read_schema(native(read(), &token)).await.unwrap().into_inner();
    let installed: kasumi_types::SchemaSnapshot = serde_json::from_slice(&installed.response_json).unwrap();
    assert_eq!(installed.schema_epoch, before.schema_epoch + 1);
    assert!(installed.collections.values().all(Option::is_some));
    let replay = admin
        .activate_schema(native(wire(), &token))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(receipt.revision, replay.revision);
    let status_wire = || proto::SchemaActivationReference {
        request_json: serde_json::to_vec(&reference).unwrap(),
    };
    assert_eq!(
        admin
            .schema_activation_status(native(status_wire(), &read_only))
            .await
            .unwrap_err()
            .code(),
        Code::PermissionDenied
    );
    let status = admin
        .schema_activation_status(native(status_wire(), &token))
        .await
        .unwrap()
        .into_inner();
    let status: kasumi_types::SchemaActivationStatus =
        serde_json::from_slice(&status.response_json).unwrap();
    assert_eq!(status.outcome.unwrap().revision, receipt.revision);
    let current = fixture.db.engine().generation().unwrap();
    assert_eq!(
        current.state.schema_epoch,
        generation.state.schema_epoch + 1
    );
    assert_eq!(
        current.state.collections["journal"].definition.schema["properties"]["amount"]["maximum"]
            .to_string(),
        "90071992547409931234567890.123456789"
    );
    let mut bad = request.clone();
    bad.expected_schema_epoch = current.state.schema_epoch;
    bad.activation_id = "native-bad".into();
    bad.changes[0] = kasumi_types::SchemaChange::Create {
        definition: kasumi_types::CollectionDefinition {
            name: "must-not-exist".into(),
            write_mode: kasumi_types::CollectionWriteMode::Mutable,
            retention_class: kasumi_types::CollectionRetentionClass::Operational,
            schema: json!({"type":"object"}),
            indexes: vec![],
            strict_read_audit: false,
        },
    };
    assert_eq!(
        admin
            .activate_schema(native(
                proto::SchemaChangeSetRequest {
                    request_json: serde_json::to_vec(&bad).unwrap()
                },
                &token
            ))
            .await
            .unwrap_err()
            .code(),
        Code::AlreadyExists
    );
    assert!(
        !fixture
            .db
            .engine()
            .generation()
            .unwrap()
            .state
            .collections
            .contains_key("must-not-exist")
    );
    let mut injected = serde_json::to_value(&request).unwrap();
    injected["tenant"] = json!("other");
    assert_eq!(
        admin
            .activate_schema(native(
                proto::SchemaChangeSetRequest {
                    request_json: serde_json::to_vec(&injected).unwrap()
                },
                &token
            ))
            .await
            .unwrap_err()
            .code(),
        Code::InvalidArgument
    );
    fixture.close().await;
}

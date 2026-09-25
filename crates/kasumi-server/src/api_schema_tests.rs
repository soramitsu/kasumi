#[tokio::test]
async fn native_policy_limits_readback_is_admin_scoped_and_exact() {
    let fixture = Fixture::new().await;
    let admin = NativeAdmin::new(fixture.registry.clone(), fixture.auth.clone());
    let token = fixture.token("person", "tenant-a", "kasumi:admin");
    let read_only = fixture.token("person", "tenant-a", "kasumi:read");
    let other_tenant = fixture.token("person", "other", "kasumi:admin");
    let request = kasumi_types::ReadPolicyLimits {
        tenant: "tenant-a".into(),
        expected_incarnation: fixture.incarnation.to_string(),
    };
    let wire = |request: &kasumi_types::ReadPolicyLimits| proto::ReadPolicyLimitsRequest {
        request_json: serde_json::to_vec(request).unwrap(),
    };
    assert_eq!(
        admin
            .read_policy_limits(native(wire(&request), &read_only))
            .await
            .unwrap_err()
            .code(),
        Code::PermissionDenied
    );
    assert!(
        admin
            .read_policy_limits(native(wire(&request), &other_tenant))
            .await
            .is_err()
    );
    let mut wrong = request.clone();
    wrong.tenant = "other".into();
    assert_eq!(
        admin
            .read_policy_limits(native(wire(&wrong), &token))
            .await
            .unwrap_err()
            .code(),
        Code::PermissionDenied
    );
    wrong = request.clone();
    wrong.expected_incarnation = uuid::Uuid::new_v4().to_string();
    assert!(
        admin
            .read_policy_limits(native(wire(&wrong), &token))
            .await
            .is_err()
    );

    let before: kasumi_types::PolicyLimitsSnapshot = serde_json::from_slice(
        &admin
            .read_policy_limits(native(wire(&request), &token))
            .await
            .unwrap()
            .into_inner()
            .response_json,
    )
    .unwrap();
    assert_eq!(before.tenant, "tenant-a");
    assert_eq!(before.incarnation, fixture.incarnation.to_string());
    let mut limits = before.limits.clone();
    limits.max_document_bytes = 512 << 10;
    admin
        .set_limits(native(
            proto::SetLimitsRequest {
                limits_json: serde_json::to_vec(&limits).unwrap(),
            },
            &token,
        ))
        .await
        .unwrap();
    let mut policy = before.policy.clone();
    policy.strict_read_audit = true;
    admin
        .set_policy(native(
            proto::SetPolicyRequest {
                policy_json: serde_json::to_vec(&policy).unwrap(),
            },
            &token,
        ))
        .await
        .unwrap();
    let after: kasumi_types::PolicyLimitsSnapshot = serde_json::from_slice(
        &admin
            .read_policy_limits(native(wire(&request), &token))
            .await
            .unwrap()
            .into_inner()
            .response_json,
    )
    .unwrap();
    assert!(after.revision > before.revision);
    assert!(after.policy_epoch > before.policy_epoch);
    assert_eq!(
        serde_json::to_value(after.policy).unwrap(),
        serde_json::to_value(policy).unwrap()
    );
    assert_eq!(
        serde_json::to_value(after.limits).unwrap(),
        serde_json::to_value(&limits).unwrap()
    );
    let mut oversized = limits;
    oversized.max_document_bytes = (1 << 20) + 1;
    assert_eq!(
        admin
            .set_limits(native(
                proto::SetLimitsRequest {
                    limits_json: serde_json::to_vec(&oversized).unwrap(),
                },
                &token,
            ))
            .await
            .unwrap_err()
            .code(),
        Code::InvalidArgument
    );
    fixture.close().await;
}

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
        activation_id: "native-financial-schema".into(), expected_incarnation: generation.state.incarnation.clone(), expected_schema_epoch: generation.state.schema_epoch, read_set: vec![kasumi_types::ReadAssertion::Snapshot { incarnation: generation.state.incarnation.clone(), schema_epoch: generation.state.schema_epoch, policy_epoch: generation.state.policy_epoch }, kasumi_types::ReadAssertion::Before { not_after_ms: u64::MAX }],
        changes: ["journal", "balances"].map(|name| kasumi_types::SchemaChange::Create {
            definition: kasumi_types::CollectionDefinition { name: name.into(), write_mode: kasumi_types::CollectionWriteMode::Mutable, retention_class: kasumi_types::CollectionRetentionClass::Operational,
            schema: serde_json::from_str(r#"{"type":"object","properties":{"amount":{"type":"number","maximum":90071992547409931234567890.123456789}}}"#).unwrap(), indexes: vec![], strict_read_audit: true },
        }).into(),
    };
    let reference = request.reference().unwrap();
    let read = || proto::ReadSchemaRequest {
        request_json: serde_json::to_vec(&kasumi_types::ReadSchema::Named {
            collections: BTreeSet::from(["journal".into(), "balances".into()]),
        })
        .unwrap(),
    };
    assert_eq!(
        admin
            .read_schema(native(read(), &read_only))
            .await
            .unwrap_err()
            .code(),
        Code::PermissionDenied
    );
    let before = admin
        .read_schema(native(read(), &token))
        .await
        .unwrap()
        .into_inner();
    let before: kasumi_types::SchemaSnapshot =
        serde_json::from_slice(&before.response_json).unwrap();
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
    let installed = admin
        .read_schema(native(read(), &token))
        .await
        .unwrap()
        .into_inner();
    let installed: kasumi_types::SchemaSnapshot =
        serde_json::from_slice(&installed.response_json).unwrap();
    assert_eq!(installed.schema_epoch, before.schema_epoch + 1);
    assert!(installed.collections.values().all(Option::is_some));
    let complete = proto::ReadSchemaRequest {
        request_json: serde_json::to_vec(&kasumi_types::ReadSchema::All).unwrap(),
    };
    assert_eq!(
        admin
            .read_schema(native(complete.clone(), &read_only))
            .await
            .unwrap_err()
            .code(),
        Code::PermissionDenied
    );
    let complete = admin
        .read_schema(native(complete, &token))
        .await
        .unwrap()
        .into_inner();
    let complete: kasumi_types::SchemaSnapshot =
        serde_json::from_slice(&complete.response_json).unwrap();
    assert_eq!(
        serde_json::to_value(&complete.collections).unwrap(),
        serde_json::to_value(&installed.collections).unwrap()
    );
    let replay = admin
        .activate_schema(native(wire(), &token))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(receipt.revision, replay.revision);
    let lookup = kasumi_types::ReadSchemaActivation {
        reference: reference.clone(),
        read_set: vec![
            kasumi_types::ReadAssertion::Snapshot {
                incarnation: installed.incarnation.clone(),
                schema_epoch: installed.schema_epoch,
                policy_epoch: installed.policy_epoch,
            },
            kasumi_types::ReadAssertion::Before {
                not_after_ms: u64::MAX,
            },
        ],
    };
    let status_wire = || proto::SchemaActivationStatusRequest {
        request_json: serde_json::to_vec(&lookup).unwrap(),
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
    let stale_lookup = kasumi_types::ReadSchemaActivation {
        reference: reference.clone(),
        read_set: request.read_set.clone(),
    };
    assert_eq!(
        admin
            .schema_activation_status(native(
                proto::SchemaActivationStatusRequest {
                    request_json: serde_json::to_vec(&stale_lookup).unwrap()
                },
                &token
            ))
            .await
            .unwrap_err()
            .code(),
        Code::Aborted
    );
    assert_eq!(
        admin
            .schema_activation_status(native(
                proto::SchemaActivationStatusRequest {
                    request_json: serde_json::to_vec(&reference).unwrap()
                },
                &token
            ))
            .await
            .unwrap_err()
            .code(),
        Code::InvalidArgument
    );
    let mut missing_effect_dependencies = serde_json::to_value(&request).unwrap();
    missing_effect_dependencies
        .as_object_mut()
        .unwrap()
        .remove("read_set");
    assert_eq!(
        admin
            .activate_schema(native(
                proto::SchemaChangeSetRequest {
                    request_json: serde_json::to_vec(&missing_effect_dependencies).unwrap()
                },
                &token
            ))
            .await
            .unwrap_err()
            .code(),
        Code::InvalidArgument
    );

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
    bad.read_set = lookup.read_set.clone();
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

#[tokio::test]
async fn native_admin_json_rejects_unknown_nested_fields_before_mutation() {
    let fixture = Fixture::new().await;
    let token = fixture.token("person", "tenant-a", "kasumi:admin");
    let admin = NativeAdmin::new(fixture.registry.clone(), fixture.auth.clone());
    let generation = fixture.db.engine().generation().unwrap();
    let revision = generation.state.revision;
    let schema_epoch = generation.state.schema_epoch;

    let definition = json!({
        "name": "new-collection",
        "write_mode": "mutable",
        "retention_class": "operational",
        "schema": {"type": "object"},
        "indexes": [{"name": "by-n", "fields": [{"path": "/n", "kind": "number"}]}],
        "strict_read_audit": false
    });
    assert!(serde_json::from_value::<CollectionDefinition>(definition.clone()).is_ok());
    let mut unknown_definition = definition.clone();
    unknown_definition["obsolete_definition"] = json!(true);
    let mut misspelled_unique = definition.clone();
    misspelled_unique["indexes"][0]["uniqe"] = json!(true);
    let mut unknown_field = definition.clone();
    unknown_field["indexes"][0]["fields"][0]["obsolete_kind"] = json!("number");
    for value in [unknown_definition, misspelled_unique, unknown_field] {
        let error = admin
            .create_collection(native(
                proto::CollectionDefinitionRequest {
                    definition_json: serde_json::to_vec(&value).unwrap(),
                },
                &token,
            ))
            .await
            .unwrap_err();
        assert_eq!(error.code(), Code::InvalidArgument);
    }

    let policy = json!({
        "grants": [{
            "principal": "person",
            "collection": null,
            "actions": ["read", "write", "admin"]
        }],
        "strict_read_audit": false
    });
    assert!(serde_json::from_value::<Policy>(policy.clone()).is_ok());
    let mut unknown_policy = policy.clone();
    unknown_policy["obsolete_policy"] = json!(true);
    let mut unknown_grant = policy;
    unknown_grant["grants"][0]["obsolete_scope"] = json!("*");
    for value in [unknown_policy, unknown_grant] {
        let error = admin
            .set_policy(native(
                proto::SetPolicyRequest {
                    policy_json: serde_json::to_vec(&value).unwrap(),
                },
                &token,
            ))
            .await
            .unwrap_err();
        assert_eq!(error.code(), Code::InvalidArgument);
    }

    let mut limits = serde_json::to_value(Limits::default()).unwrap();
    limits["atomic"]["obsolete_limit"] = json!(1);
    let error = admin
        .set_limits(native(
            proto::SetLimitsRequest {
                limits_json: serde_json::to_vec(&limits).unwrap(),
            },
            &token,
        ))
        .await
        .unwrap_err();
    assert_eq!(error.code(), Code::InvalidArgument);

    let change = json!({
        "activation_id": "unknown-nested-field",
        "expected_incarnation": generation.state.incarnation.clone(),
        "expected_schema_epoch": schema_epoch,
        "read_set": [],
        "changes": [{"kind": "create", "definition": definition}]
    });
    assert!(serde_json::from_value::<kasumi_types::SchemaChangeSet>(change.clone()).is_ok());
    let mut unknown_schema_index = change;
    unknown_schema_index["changes"][0]["definition"]["indexes"][0]["uniqe"] = json!(true);
    let error = admin
        .activate_schema(native(
            proto::SchemaChangeSetRequest {
                request_json: serde_json::to_vec(&unknown_schema_index).unwrap(),
            },
            &token,
        ))
        .await
        .unwrap_err();
    assert_eq!(error.code(), Code::InvalidArgument);

    let after = fixture.db.engine().generation().unwrap();
    assert_eq!(after.state.revision, revision);
    assert_eq!(after.state.schema_epoch, schema_epoch);
    assert!(!after.state.collections.contains_key("new-collection"));
    fixture.close().await;
}

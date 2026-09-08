#[tokio::test]
async fn native_resources_and_two_restore_hops_preserve_immutable_issuer_facts() {
    use kasumi_types::{CollectionWriteMode, Mutation, MutationBatch, Precondition};
    let fixture = Fixture::new().await;
    let owner = fixture
        .auth
        .authenticate(&fixture.token(
            "person",
            "tenant-a",
            "kasumi:admin kasumi:read kasumi:write",
        ))
        .await
        .unwrap();
    let mut definition = fixture.db.engine().generation().unwrap().state.collections["docs"]
        .definition
        .clone();
    definition.write_mode = CollectionWriteMode::AppendOnly;
    fixture
        .db
        .administer(owner.clone(), Operation::ReplaceCollection(definition))
        .await
        .unwrap();
    let original = json!({"issuer_incarnation":fixture.incarnation,"immutable_fact":"original approved fact","n":1});
    fixture
        .db
        .mutate(
            owner.clone(),
            MutationBatch {
                idempotency_key: "immutable-source".into(),
                read_set: vec![],
                operations: vec![Mutation::Put {
                    collection: "docs".into(),
                    id: "original".into(),
                    body: original.clone(),
                    expected: Precondition::Absent,
                }],
            },
        )
        .await
        .unwrap();
    let original_document = fixture.db.get(&owner, "docs", "original").await.unwrap();
    let original_bytes = serde_json::to_vec(&original_document).unwrap();
    let old_token = fixture.token(
        "person",
        "tenant-a",
        "kasumi:admin kasumi:read kasumi:write",
    );
    let backup_dir = tempfile::tempdir().unwrap();
    let destination = Arc::new(
        kasumi_store::FilesystemBackupDestination::new(backup_dir.path(), 16 << 20).unwrap(),
    );
    let mut current = fixture.db.clone();
    let mut current_key = Arc::new(LocalKeyProvider::new([3; 32]));
    let mut current_context = owner;
    let mut targets = Vec::new();
    let mut dirs = Vec::new();
    let mut last_links = Vec::new();
    for hop in 1..=2 {
        current
            .install_archive_destination("lineage".into(), destination.clone())
            .unwrap();
        let checkpoint = current
            .backup_checkpoint(current_context.clone(), destination.as_ref())
            .await
            .unwrap();
        let target_incarnation = uuid::Uuid::new_v4();
        let request = kasumi_types::RetireSourceRequest {
            retirement_id: format!("lineage-hop-{hop}"),
            expected_source_incarnation: checkpoint.source_incarnation().into(),
            target_incarnation: target_incarnation.to_string(),
            checkpoint: checkpoint.checkpoint().clone(),
            destination: "lineage".into(),
            not_after_ms: u64::MAX,
        };
        let retired = current
            .retire_source(current_context.clone(), request.clone())
            .await
            .unwrap();
        current
            .retirement_response_fence(&current_context, &retired)
            .unwrap()
            .check()
            .unwrap();
        // Equal signed claims verified in a fresh invocation cannot regain the
        // original accepted request's acknowledgement-only transition fence.
        let old_fresh = fixture
            .auth
            .authenticate(&fixture.resource_token(
                "person",
                "tenant-a",
                "kasumi:admin",
                Some(json!({"kind":"database","incarnation":request.expected_source_incarnation})),
            ))
            .await
            .unwrap();
        assert!(
            current
                .retirement_response_fence(&old_fresh, &retired)
                .is_err()
        );
        assert!(
            current
                .verify_retirement_receipt(old_fresh, &request.reference().unwrap())
                .await
                .is_err()
        );
        let dir = tempfile::tempdir().unwrap();
        let node = NodeStore::open(dir.path().join("node.redb")).unwrap();
        let key = Arc::new(LocalKeyProvider::new([20 + hop as u8; 32]));
        let store = TenantStore::open_fixture(node, "tenant-a".into(), key.clone())
            .await
            .unwrap();
        let stores = kasumi_store::test_utils::with_custody(
            store,
            Arc::new(LocalKeyProvider::new([240 - hop as u8; 32])),
        )
        .await
        .unwrap();
        // Explicit encrypted local restore fixture exercises backup graph and
        // genesis; independent production activation is covered separately.
        let embedded = RequestContext {
            authorization: kasumi_types::RequestAuthorization::service_identity(),
            principal: "person".into(),
            tenant: "tenant-a".into(),
            scopes: BTreeSet::from([Action::Admin, Action::Read, Action::Write]),
            request_id: format!("restore-{hop}"),
        };
        let restored = kasumi_engine::restore_local(
&kasumi_engine::RestoreSource {
                timeout_ms: 300_000,
                destination_alias: "lineage".into(),
                destination: destination.clone(),
                keys: current_key,
            },
stores.clone(),
kasumi_engine::LocalRestoreRequest { checkpoint: checkpoint.checkpoint().clone(), target_incarnation: target_incarnation, source_context: embedded.clone(), target_context: embedded.clone(), source_purpose: kasumi_store::StoragePurpose::LocalFixture },
kasumi_engine::admission::NodeAdmission::new(Default::default()).unwrap(),
fixture.audit.clone(),
)
        .await
        .unwrap();
        restored.complete_restore(embedded.clone()).await.unwrap();
        restored
            .administer(embedded, Operation::Suspend(false))
            .await
            .unwrap();
        let snapshot = restored.engine().snapshot().unwrap();
        let mut substituted: kasumi_types::TenantState = kasumi_engine::TenantEngine::decode_snapshot_state(&snapshot).unwrap();
        substituted.restore_lineage[0].checkpoint.resident_sha256 =
            if substituted.restore_lineage[0].checkpoint.resident_sha256 == "0".repeat(64) {
                "1".repeat(64)
            } else {
                "0".repeat(64)
            };
        if hop == 1 {
            substituted.restored_from = Some(substituted.restore_lineage[0].checkpoint.clone());
        }
        kasumi_types::validate_restore_lineage(
            &substituted.tenant,
            &substituted.incarnation,
            substituted.revision,
            substituted.restored_from.as_ref(),
            &substituted.restore_lineage,
        )
        .unwrap();
        assert!(
            restored
                .engine()
                .restore(&kasumi_engine::TenantEngine::encode_snapshot_state(&substituted, 64 << 20).unwrap())
                .is_err(),
            "shape-valid immutable history substitution must be rejected"
        );
        assert_eq!(restored.engine().snapshot().unwrap(), snapshot);
        restored.shutdown().await.unwrap();
        drop(restored);
        drop(stores);
        let reopened_store = TenantStore::open_fixture(
            NodeStore::open(dir.path().join("node.redb")).unwrap(),
            "tenant-a".into(),
            key.clone(),
        )
        .await
        .unwrap();
        let reopened_stores = kasumi_store::test_utils::with_custody(
            reopened_store,
            Arc::new(LocalKeyProvider::new([240 - hop as u8; 32])),
        )
        .await
        .unwrap();
        let restored = kasumi_engine::open_local_with_incarnation(
            reopened_stores,
            kasumi_types::Policy {
                grants: vec![],
                strict_read_audit: false,
            },
            Limits::default(),
            fixture.audit.clone(),
            target_incarnation,
        )
        .await
        .unwrap();
        assert_eq!(restored.engine().snapshot().unwrap(), snapshot);

        let registry = DatabaseRegistry::default();
        registry.insert(restored.clone()).unwrap();
        let data = NativeData::new(registry.clone(), fixture.auth.clone());
        let admin = NativeAdmin::new(registry, fixture.auth.clone());
        let get = || proto::GetRequest {
            collection: "docs".into(),
            id: "original".into(),
        };
        assert_eq!(
            data.get(native(get(), &old_token))
                .await
                .unwrap_err()
                .code(),
            Code::Unauthenticated
        );
        assert_eq!(
            admin
                .set_suspended(native(
                    proto::SetSuspendedRequest { suspended: true },
                    &old_token
                ))
                .await
                .unwrap_err()
                .code(),
            Code::Unauthenticated
        );
        assert!(!restored.engine().generation().unwrap().state.suspended);
        let token = fixture.resource_token(
            "reader",
            "tenant-a",
            "kasumi:read",
            Some(json!({"kind":"database","incarnation":target_incarnation})),
        );
        let doc = data.get(native(get(), &token)).await.unwrap().into_inner();
        assert_eq!(
            serde_json::from_slice::<Value>(&doc.body_json).unwrap(),
            original
        );
        assert_eq!(doc.version, original_document.version);
        let current_owner_token = fixture.resource_token(
            "person",
            "tenant-a",
            "kasumi:admin kasumi:read kasumi:write",
            Some(json!({"kind":"database","incarnation":target_incarnation})),
        );
        current_context = fixture
            .auth
            .authenticate(&current_owner_token)
            .await
            .unwrap();
        assert_eq!(
            serde_json::to_vec(
                &restored
                    .get(&current_context, "docs", "original")
                    .await
                    .unwrap()
            )
            .unwrap(),
            original_bytes
        );
        let input = kasumi_types::ReadRestoreLineage {
            expected_incarnation: target_incarnation.to_string(),
            collection: "docs".into(),
        };
        let wire = data
            .read_restore_lineage(native(
                proto::ReadRestoreLineageRequest {
                    request_json: serde_json::to_vec(&input).unwrap(),
                },
                &token,
            ))
            .await
            .unwrap()
            .into_inner();
        let observation: kasumi_types::RestoreLineageObservation =
            serde_json::from_slice(&wire.response_json).unwrap();
        observation.validate().unwrap();
        assert_eq!(observation.links.len(), hop);
        assert_eq!(&observation.links[..hop - 1], last_links.as_slice());
        assert_eq!(
            observation.links[hop - 1].source_incarnation,
            checkpoint.source_incarnation()
        );
        assert_eq!(
            observation.links[hop - 1].source_resident_sha256,
            checkpoint.resident_sha256()
        );
        let serialized = String::from_utf8(wire.response_json).unwrap();
        for forbidden in [
            "key_lineage",
            "destination",
            "backup_id",
            "manifest_ciphertext",
            "lineage\"",
        ] {
            assert!(!serialized.contains(forbidden));
        }
        last_links = observation.links;
        for resource in [
            None,
            Some(json!({"kind":"database","incarnation":uuid::Uuid::new_v4()})),
            Some(json!({"kind":"custody","incarnation":target_incarnation})),
            Some(json!({"kind":"control","incarnation":target_incarnation})),
        ] {
            let invalid = fixture.resource_token(
                "person",
                "tenant-a",
                "kasumi:read kasumi:write kasumi:admin",
                resource,
            );
            assert_eq!(
                data.get(native(get(), &invalid)).await.unwrap_err().code(),
                Code::Unauthenticated
            );
        }
        current = restored.clone();
        current_key = key;
        targets.push(restored);
        dirs.push(dir);
    }
    assert_eq!(
        last_links[0].source_incarnation,
        fixture.incarnation.to_string()
    );
    for db in targets {
        db.shutdown().await.unwrap();
    }
    fixture.close().await;
    drop(dirs);
}

// One actual Control journal for the exercised source. Keeping the handle alive
// and reopening its encrypted stores exercises the production claim path.
pub(crate) async fn backup_test_control(
    source: &Arc<Database>,
    context: &RequestContext,
    create: bool,
) -> std::result::Result<(Arc<Database>, RequestContext), crate::SnapshotFailure> {
    let node = source.store.node_store().clone();
    let tenant = crate::control::CONTROL_TENANT.to_owned();
    let keys = Arc::new(LocalKeyProvider::new([0x4a; 32]));
    let custody = Arc::new(LocalKeyProvider::new([0x4b; 32]));
    let access = kasumi_store::StorageAccess::node_control();
    let stores = if create {
        TenantStorageSet::initialize_catalogs(node, tenant, keys, custody, access).await?
    } else {
        TenantStorageSet::open_existing(node, tenant, keys, custody, access).await?
    };
    let mut operator = context.clone();
    operator.tenant = crate::control::CONTROL_TENANT.into();
    crate::test_utils::install_local_replica_audit_placement(stores.application())?;
    let control = crate::open_local_with_incarnation(
        stores,
        Policy {
            strict_read_audit: false,
            grants: vec![Grant {
                principal: operator.principal.clone(),
                collection: None,
                actions: operator.scopes.clone(),
            }],
        },
        Limits::default(),
        source.security_audit.clone(),
        uuid::Uuid::from_u128(444),
    )
    .await?;
    Ok((control, operator))
}

#[tokio::test]
async fn committed_control_claim_precedes_upload_and_recovers_an_unpublished_intent()
-> std::result::Result<(), crate::SnapshotFailure> {
    let fixture = CredentialFixture::new().await;
    let (control, operator) = backup_test_control(&fixture.db, &fixture.context, true).await?;
    fixture.db.install_backup_control(&control, &operator)?;
    let make_destination = |name| {
        kasumi_store::FilesystemBackupDestination::new(
            fixture._directory.path().join("persistent").join(name),
            32 << 20,
            fixture.storage.persistent.clone(),
        )
    };
    let first = Arc::new(make_destination("original")?);
    let other = Arc::new(make_destination("different")?);
    fixture
        .db
        .install_archive_destination("first".into(), first.clone())?;
    fixture
        .db
        .install_archive_destination("second".into(), other.clone())?;
    // Stopped writes give a recovery capture a stable source. Administration
    // retains the right to take or abort that capture while the data is suspended.
    fixture
        .db
        .administer(fixture.context.clone(), Operation::Suspend(true))
        .await?;
    let state = fixture.db.engine.generation()?;
    let id = uuid::Uuid::new_v4();
    let intent = BackupSessionIntent {
        session_id: id,
        tenant: fixture.context.tenant.clone(),
        source_incarnation: state.incarnation().into(),
        revision: state.state.revision,
        principal: fixture.context.principal.clone(),
        request_id: fixture.context.request_id.clone(),
    };
    let bound = fixture
        .db
        .claim_backup_intent(
            &fixture.context,
            first.as_ref(),
            &intent,
            &state,
            Some("first"),
        )
        .await?;
    let retry = fixture
        .db
        .claim_backup_intent(
            &fixture.context,
            first.as_ref(),
            &intent,
            &state,
            Some("first"),
        )
        .await?;
    assert_eq!(bound.as_bytes(), retry.as_bytes());
    let record = fixture
        .db
        .backup_owner(&fixture.context, first.as_ref(), id)
        .await?
        .unwrap();
    assert_eq!(record.claim.intent_ciphertext, bound.as_bytes());
    let tenant_keys = ReadKeyRetentionRequest {
        scope: KeyRetentionScope::Tenant { tenant: fixture.context.tenant.clone() },
        cursor: None, limit: 32,
    };
    let assert_session_keys = |page: &KeyRetentionPage| {
        assert!(page.entries.iter().any(|entry|
            entry.reference == KeyReference::BackupSession { session_id: id }));
    };
    let active = fixture.db.read_key_retention(&fixture.context, tenant_keys.clone()).await?;
    assert_session_keys(&active);
    drop(active);
    let mut different = record.clone();
    different.claim.request_id.push('x');
    assert!(fixture.db.store.with_verified_binding_keys::<()>(&different, None, |_| {
        panic!("a different request exposed wrapping identities")
    }).await.is_err());
    assert_eq!(
        control.engine.generation()?.state.backup_binding_head.count,
        1
    );
    let key_request = ReadKeyRetentionRequest { scope: KeyRetentionScope::Control {}, cursor: None, limit: 1 };
    let before_keys = control.read_key_retention(&operator, key_request.clone()).await?;
    let prior_cursor = before_keys.next_cursor.clone().expect("Control application and custody catalogs");
    drop(before_keys);
    let before_terminal = control.engine.generation()?;
    let initial_counts = before_terminal.control_backup_sessions().unwrap();
    assert_eq!((initial_counts.claimed_without_terminal, initial_counts.completed, initial_counts.aborted), (1, 0, 0));
    assert!(record.position.term > 0 && record.position.index > 0);
    let request = |alias: &str| BackupSessionRequest {
        destination: alias.into(),
        session_id: id,
    };
    assert_eq!(
        fixture
            .db
            .backup_session_status(fixture.context.clone(), request("second"))
            .await
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    assert!(
        other
            .session_get(id, kasumi_store::BackupSessionSlot::Intent, 1)
            .await?
            .is_none()
    );
    assert_eq!(
        fixture
            .db
            .backup_session_status(fixture.context.clone(), request("first"))
            .await?
            .intent,
        intent
    );
    assert!(
        first
            .session_get(id, kasumi_store::BackupSessionSlot::Intent, 1)
            .await?
            .is_none()
    );
    // Stop between the Control terminal commit and the remote outcome creation.
    // Competing aborts must recover the original randomized bytes.
    first.session_put(id, kasumi_store::BackupSessionSlot::Intent, bound.try_clone()?.into()).await?;
    let verified = fixture.db.backup_session(&fixture.context, first.as_ref(), id).await?.unwrap();
    let winner = BackupSessionOutcome::Aborted {
        intent_ciphertext_sha256: verified.intent_ciphertext_sha256().into(),
        session_id: id, principal: fixture.context.principal.clone(), reason: "first abort wins".into(),
    };
    let selected = fixture.db.select_backup_terminal(&fixture.context, first.as_ref(), &verified, &winner).await?;
    let loser = BackupSessionOutcome::Aborted {
        intent_ciphertext_sha256: verified.intent_ciphertext_sha256().into(),
        session_id: id, principal: fixture.context.principal.clone(), reason: "late contender".into(),
    };
    let retry = fixture.db.select_backup_terminal(&fixture.context, first.as_ref(), &verified, &loser).await?;
    assert_eq!(selected.as_bytes(), retry.as_bytes());
    let decided = fixture.db.read_key_retention(&fixture.context, tenant_keys).await?;
    assert_session_keys(&decided);
    drop(decided);
    let stale_keys = control.read_key_retention(&operator, ReadKeyRetentionRequest {
        cursor: Some(prior_cursor), ..key_request
    }).await.unwrap_err();
    assert_eq!(stale_keys.code, ErrorCode::CursorExpired);
    let final_counts = control.engine.generation()?.control_backup_sessions().unwrap();
    assert_eq!((final_counts.claimed_without_terminal, final_counts.completed, final_counts.aborted), (0, 0, 1));
    assert!(final_counts.last_binding_revision > initial_counts.last_binding_revision);
    assert_eq!(before_terminal.control_backup_sessions(), Some(initial_counts));

    assert_eq!(fixture.db.backup_session_status(fixture.context.clone(), request("first")).await?.outcome.as_ref(), Some(&winner));
    assert!(first.session_get(id, kasumi_store::BackupSessionSlot::Outcome, selected.len()).await?.is_none());
    let aborted = fixture
        .db
        .abort_backup_session(
            fixture.context.clone(),
            AbortBackupSession {
                destination: "first".into(),
                session_id: id,
                reason: "interrupted before first upload".into(),
            },
        )
        .await?;
    assert!(matches!(
        aborted.outcome,
        Some(BackupSessionOutcome::Aborted { .. })
    ));
    assert_eq!(
        first
            .session_get(id, kasumi_store::BackupSessionSlot::Intent, bound.len())
            .await?
            .unwrap(),
        bound.as_bytes()
    );
    assert_eq!(aborted.outcome.as_ref(), Some(&winner));
    assert_eq!(first.session_get(id, kasumi_store::BackupSessionSlot::Outcome, selected.len()).await?.unwrap(), selected.as_bytes());
    control.group.snapshot().await?;
    control.shutdown().await?;
    drop(control);
    let (reopened, _) = backup_test_control(&fixture.db, &fixture.context, false).await?;
    let durable = reopened
        .engine
        .generation()?
        .backup_bindings
        .get(id)?
        .unwrap()
        .record;
    assert_eq!(durable, record);
    let decided = reopened.engine.generation()?.backup_bindings.terminal(id)?.unwrap();
    assert_eq!(decided.record, record);
    let terminal = decided.terminal.unwrap();
    assert_eq!(terminal.outcome, winner);
    assert_eq!(terminal.ciphertext, selected.as_bytes());
    reopened.shutdown().await?;
    fixture.close().await;
    Ok(())
}

#[tokio::test]
async fn completed_backup_inventory_discards_partial_key_evidence_when_the_root_is_missing()
-> std::result::Result<(), crate::SnapshotFailure> {
    let fixture = CredentialFixture::new().await;
    let (control, operator) = backup_test_control(&fixture.db, &fixture.context, true).await?;
    fixture.db.install_backup_control(&control, &operator)?;
    let directory = fixture
        ._directory
        .path()
        .join("persistent")
        .join("key-graph");
    let destination = Arc::new(kasumi_store::FilesystemBackupDestination::new(
        &directory,
        64 << 20,
        fixture.storage.persistent.clone(),
    )?);
    fixture
        .db
        .install_archive_destination("key-backup".into(), destination.clone())?;
    let id = uuid::Uuid::new_v4();
    let proof = fixture
        .db
        .backup_checkpoint_named(fixture.context.clone(), "key-backup", id)
        .await?;
    let reference = KeyReference::CompletedBackup {
        backup_id: id,
        checkpoint_sha256: staged_digest(proof.checkpoint())?.0,
    };
    let purpose = control
        .engine
        .generation()?
        .backup_bindings
        .get(id)?
        .expect("selected original backup binding")
        .record
        .claim
        .source_purpose_sha256;
    let verify_origin = |digest| {
        fixture.db.verified_checkpoint_keys(
            &fixture.context,
            destination.as_ref(),
            proof.checkpoint().clone(),
            Some(digest),
            &|_, _, _| Ok(()),
        )
    };
    verify_origin(purpose.clone()).await?;
    let substituted = staged_digest(&("different recovery origin", purpose))?.0;
    let wrong = verify_origin(substituted).await.unwrap_err();
    let cause = wrong
        .operation_error()
        .expect("classified source binding mismatch");
    assert_eq!(cause.code, ErrorCode::Corruption);
    assert_eq!(cause.message, "backup source purpose differs from selected recovery");
    let request = ReadKeyRetentionRequest {
        scope: KeyRetentionScope::Tenant {
            tenant: fixture.context.tenant.clone(),
        },
        cursor: None,
        limit: 32,
    };
    let read = || {
        fixture
            .db
            .read_key_retention(&fixture.context, request.clone())
    };
    let page = read().await?;
    assert!(
        page.entries
            .iter()
            .any(|entry| entry.reference == reference)
    );
    drop(page);
    let manifest = directory.join(format!("sessions/{id}/objects/{id}.kasumi"));
    let offline = manifest.with_extension("offline");
    std::fs::rename(&manifest, &offline)?;
    let partial = read().await?;
    assert!(
        partial
            .entries
            .iter()
            .all(|entry| entry.reference != reference)
    );
    let KeyRetentionCoverage::Incomplete { missing, .. } = &partial.coverage else {
        panic!("unreadable backup graph gave complete coverage");
    };
    assert!(missing.contains(&MissingKeyDependency::RecordUnreadable {
        record_kind: KeyReferenceKind::CompletedBackup,
        id: id.to_string(),
    }));
    let candidate_key = partial.entries.first().expect("installed catalog key").key.identity();
    drop(partial);
    let denied = fixture.db.retire_key_versions(&fixture.context, RetireKeyVersionsRequest {
        retirement_id: "1".into(),
        scope: request.scope.clone(),
        identity: candidate_key,
        retire_below_version: 2,
        expected_coverage_sha256: "f".repeat(64),
    }).await.expect_err("incomplete dependency inventory must refuse retirement");
    assert_eq!(denied.code, ErrorCode::Unavailable);
    let status = fixture.db.key_retirement_status(&fixture.context, KeyRetirementStatusRequest {
        scope: request.scope.clone(), retirement_id: "1".into(),
    }).await?;
    assert_eq!(status.last_ordinal, 0);
    assert!(status.status.is_none());
    drop(status);
    std::fs::rename(offline, manifest)?;
    let repaired = read().await?;
    assert!(
        repaired
            .entries
            .iter()
            .any(|entry| entry.reference == reference)
    );
    drop(repaired);
    fixture.db.shutdown().await?;
    control.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn retirement_decision_rechecks_the_ordered_membership_and_dependency_position()
-> std::result::Result<(), crate::SnapshotFailure> {
    let fixture = CredentialFixture::new().await;
    let (control, operator) = backup_test_control(&fixture.db, &fixture.context, true).await?;
    fixture.db.install_backup_control(&control, &operator)?;
    let destination = Arc::new(kasumi_store::FilesystemBackupDestination::new(
        fixture._directory.path().join("persistent").join("retirement-race"),
        32 << 20,
        fixture.storage.persistent.clone(),
    )?);
    fixture.db.install_archive_destination("race".into(), destination.clone())?;
    let state = control.engine.generation()?;
    let mut begin = BeginKeyRetirement {
        request: RetireKeyVersionsRequest {
            retirement_id: "1".into(),
            scope: KeyRetentionScope::Control {},
            identity: KeyIdentityRef { provider: "file".into(), key_ref: "previous-wrapping-key".into() },
            retire_below_version: 2,
            expected_coverage_sha256: "c".repeat(64),
        },
        membership_epoch: control.group.metrics().membership_config.log_id().as_ref().map_or(0, |id| id.index),
        expected_dependency_sha256: state.state.key_dependency_sha256()?,
    };
    drop(state);
    let epoch = begin.membership_epoch;
    begin.membership_epoch += 1;
    let refused = control.submit(operator.clone(), Operation::BeginKeyRetirement(begin.clone())).await.unwrap_err();
    assert_eq!(refused.code, ErrorCode::Conflict);
    assert!(control.engine.generation()?.state.key_retirements.is_empty());
    begin.membership_epoch = epoch;
    control.submit(operator.clone(), Operation::BeginKeyRetirement(begin.clone())).await?;
    let after_fence = control.engine.generation()?.state.key_dependency_sha256()?;
    // A real backup claim wins the race between the coverage check and decision.
    let generation = fixture.db.engine.generation()?;
    let intent = BackupSessionIntent {
        session_id: uuid::Uuid::new_v4(),
        tenant: fixture.context.tenant.clone(),
        source_incarnation: generation.incarnation().into(),
        revision: generation.state.revision,
        principal: fixture.context.principal.clone(),
        request_id: fixture.context.request_id.clone(),
    };
    fixture.db.claim_backup_intent(&fixture.context, destination.as_ref(), &intent, &generation, Some("race")).await?;
    drop(generation);
    let mut decision = CompleteKeyRetirement {
        retirement_id: "1".into(), request_sha256: begin.request.request_sha256()?,
        expected_dependency_sha256: after_fence.clone(), completed_coverage_sha256: "d".repeat(64),
    };
    let refused = control.submit(operator.clone(), Operation::CompleteKeyRetirement(decision.clone())).await.unwrap_err();
    assert_eq!(refused.code, ErrorCode::Conflict);
    let observed = control.engine.generation()?;
    assert!(observed.state.key_retirements.fence.is_some());
    decision.expected_dependency_sha256 = observed.state.key_dependency_sha256()?;
    assert_ne!(decision.expected_dependency_sha256, after_fence);
    drop(observed);
    control.submit(operator.clone(), Operation::CompleteKeyRetirement(decision)).await?;
    let persisted = control.engine.generation()?.state.key_retirements.clone();
    assert_eq!(persisted.floor(&begin.request.identity), 2);
    control.group.snapshot().await?;
    control.shutdown().await?;
    drop(control);
    let (reopened, _) = backup_test_control(&fixture.db, &fixture.context, false).await?;
    assert_eq!(reopened.engine.generation()?.state.key_retirements, persisted);
    reopened.shutdown().await?;
    fixture.close().await;
    Ok(())
}

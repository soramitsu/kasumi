use super::*;

fn state() -> TenantState {
    TenantEngine::new(
        "tenant".into(),
        "incarnation".into(),
        Policy {
            grants: vec![Grant {
                principal: "owner".into(),
                collection: None,
                actions: BTreeSet::from([Action::Admin, Action::Write]),
            }],
            strict_read_audit: false,
        },
        Limits::default(),
    )
    .unwrap()
    .generation()
    .unwrap()
    .state
    .clone()
}
fn stage(id: &str) -> (String, StagedTransaction) {
    let manifest = StagedManifest::from_chunks(&[StagedChunk {
        read_set: vec![],
        operations: vec![Mutation::Delete {
            collection: "docs".into(),
            id: "row".into(),
            expected: Precondition::Any,
        }],
    }])
    .unwrap();
    (
        identity("owner", id).unwrap(),
        StagedTransaction {
            scope: StagedTransactionScope {
                tenant: "tenant".into(),
                incarnation: "incarnation".into(),
                principal: "owner".into(),
            },
            transaction_id: id.into(),
            manifest_digest: staged_digest(&manifest).unwrap().0,
            manifest,
            chunks: Default::default(),
            stored_chunk_bytes: 0,
            uploaded_payload_bytes: 0,
            uploaded_operations: 0,
            uploaded_read_assertions: 0,
            expires_at_ms: Some(u64::MAX),
            ttl_ms: 86_400_000,
            outcome: StagedOutcome::Uploading,
        },
    )
}
fn failure(code: ErrorCode) -> Result<WriteReceipt> {
    Err(Error::new(code, "\0".repeat(Error::MAX_MESSAGE_BYTES)))
}

#[test]
fn permanent_staged_reservation_bounds_all_terminal_outcomes_and_maximum_counter_widths() {
    let (key, original) = stage("a");
    let initial = permanent_charge(&key, &original).unwrap();
    let capacity = initial.0 + initial.1;
    let mut grew = original.clone();
    grew.stored_chunk_bytes = usize::MAX;
    grew.uploaded_payload_bytes = usize::MAX;
    grew.uploaded_operations = usize::MAX;
    grew.uploaded_read_assertions = usize::MAX;
    let uploaded = permanent_charge(&key, &grew).unwrap();
    assert!(uploaded.0 > initial.0);
    assert_eq!(uploaded.0 + uploaded.1, capacity);
    assert_eq!(uploaded.1, STAGED_OUTCOME_HEADROOM as u64);
    let receipt = WriteReceipt {
        revision: u64::MAX,
        versions: BTreeMap::new(),
    };
    let mut outcomes = vec![
        StagedOutcome::Finished {
            outcome: Ok(receipt.clone()),
        },
        StagedOutcome::Aborted {
            receipt: receipt.clone(),
        },
        StagedOutcome::Expired { receipt },
    ];
    for code in [
        ErrorCode::InvalidArgument,
        ErrorCode::Unauthorized,
        ErrorCode::Forbidden,
        ErrorCode::NotFound,
        ErrorCode::AlreadyExists,
        ErrorCode::Conflict,
        ErrorCode::SchemaViolation,
        ErrorCode::QuotaExceeded,
        ErrorCode::ResourceExhausted,
        ErrorCode::IndexRequired,
        ErrorCode::CursorExpired,
        ErrorCode::Unavailable,
        ErrorCode::UnknownOutcome,
        ErrorCode::Corruption,
        ErrorCode::Sealed,
        ErrorCode::AuditUnavailable,
    ] {
        outcomes.push(StagedOutcome::Finished {
            outcome: failure(code),
        });
    }
    for outcome in outcomes {
        let mut final_record = original.clone();
        final_record.outcome = outcome;
        let (used, reserve) = permanent_charge(&key, &final_record).unwrap();
        assert!(used <= capacity, "{final_record:?}");
        assert_eq!(reserve, 0);
    }
}

#[test]
fn permanent_staged_point_capacity_transfers_to_outcome_and_can_expand_without_identity_reuse() {
    let scratch = crate::codec_fixture::ScratchScope::new(
        kasumi_store::test_utils::TestDiskMemory::new(64 << 20, 32),
    )
    .unwrap();
    let disk = &scratch.disk;
    let mut state = state();
    let (key, original) = stage("a");
    let charge = permanent_charge(&key, &original).unwrap();
    state.limits.atomic.max_permanent_staged_bytes = charge.0 + charge.1;
    replace_record(&mut state, key.clone(), original.clone()).unwrap();
    let mut expired = state.clone();
    expired.revision = 7;
    expire_active(&mut expired, u64::MAX, 7).unwrap();
    assert!(matches!(
        expired.staged_transactions[&key].outcome,
        StagedOutcome::Expired { .. }
    ));
    assert_eq!(expired.reserved_staged_terminal_bytes, 0);
    let expired_rows = persist_terminal_overlay(disk, &state, &mut expired);
    validate_restored(&expired).unwrap();
    expired_rows.validate_state(&expired).unwrap();
    assert!(!expired.staged_transactions.contains_key(&key));
    assert!(matches!(
        expired_rows.get(&key).unwrap().unwrap().stage.outcome,
        StagedOutcome::Expired { .. }
    ));
    let (second_key, second) = stage("b");
    assert_eq!(
        replace_record(&mut state, second_key.clone(), second.clone())
            .unwrap_err()
            .code,
        ErrorCode::QuotaExceeded
    );
    assert_eq!(state.staged_transactions.len(), 1);
    let mut grown = original.clone();
    grown.uploaded_operations = usize::MAX;
    replace_record(&mut state, key.clone(), grown).unwrap();
    assert_eq!(
        state.permanent_staged_bytes + state.reserved_staged_terminal_bytes,
        state.limits.atomic.max_permanent_staged_bytes
    );
    let previous = state.clone();
    let mut final_record = original;
    terminal(&mut final_record, failure(ErrorCode::ResourceExhausted));
    replace_record(&mut state, key.clone(), final_record.clone()).unwrap();
    assert_eq!(state.reserved_staged_terminal_bytes, 0);
    let overlay_bytes = state.permanent_staged_bytes;
    replace_record(&mut state, key.clone(), final_record.clone()).unwrap();
    assert_eq!(state.permanent_staged_bytes, overlay_bytes);
    state.revision = 1;
    let terminal_rows = persist_terminal_overlay(disk, &previous, &mut state);
    assert!(!state.staged_transactions.contains_key(&key));
    assert_eq!(terminal_rows.head().count, 1);
    state.limits.atomic.max_permanent_staged_bytes = state.permanent_staged_bytes;
    let exact = state.permanent_staged_bytes;
    assert_eq!(exact, terminal_rows.head().encoded_bytes);
    assert_eq!(
        replace_record(&mut state, second_key.clone(), second.clone())
            .unwrap_err()
            .code,
        ErrorCode::QuotaExceeded
    );
    assert_eq!(
        terminal_rows.get(&key).unwrap().unwrap().stage.outcome,
        final_record.outcome
    );
    assert_eq!(state.permanent_staged_bytes, exact);
    state.limits.atomic.max_permanent_staged_bytes = 3 << 30;
    validate_limits(&state.limits).unwrap();
    replace_record(&mut state, second_key, second).unwrap();
    validate_restored(&state).unwrap();
    terminal_rows.validate_state(&state).unwrap();
    assert!(!state.staged_transactions.contains_key(&key));
    assert_eq!(
        terminal_rows.get(&key).unwrap().unwrap().stage.outcome,
        final_record.outcome
    );
}

// The ordered apply path moves terminal overlays into their permanent owner
// before validating a published state. Exercise that same transfer here.
fn persist_terminal_overlay(
    disk: &Arc<kasumi_store::ScratchDisk>,
    previous: &TenantState,
    next: &mut TenantState,
) -> crate::staged_terminal::View {
    let owner = crate::staged_terminal::View::empty(&previous.tenant, &previous.incarnation)
        .unwrap()
        .fixture_owner(disk, previous)
        .unwrap();
    let applied = crate::staged_terminal::AppliedIdentity {
        incarnation: next.incarnation.clone(),
        revision: next.revision,
        timestamp_ms: u64::MAX,
        command_sha256: "ab".repeat(32),
        origin: crate::staged_terminal::AppliedOrigin::Fixture,
    };
    crate::staged_terminal::Pending::prepare(&owner, previous, next, &applied)
        .unwrap()
        .persist()
        .unwrap()
}

#[test]
fn permanent_staged_snapshot_boundary_reserves_aggregate_counter_digit_growth() {
    let mut state = state();
    let (key, original) = stage("a");
    replace_record(&mut state, key.clone(), original.clone()).unwrap();
    // Fix the bound after its own decimal width changes in the canonical header.
    for _ in 0..4 {
        let accounting = SnapshotAccounting::rebuild(&state).unwrap();
        state.limits.max_snapshot_bytes = accounting.bytes(&state).unwrap() as u64
            + crate::accounting::staged_headroom(&state).unwrap()
            + 20
            - state.revision.to_string().len() as u64;
    }
    assert!(
        SnapshotAccounting::rebuild(&state)
            .unwrap()
            .fits(&state)
            .unwrap()
    );
    let old_used_digits = state.permanent_staged_bytes.to_string().len();
    let mut terminal_record = original;
    terminal(&mut terminal_record, failure(ErrorCode::ResourceExhausted));
    replace_record(&mut state, key, terminal_record).unwrap();
    assert!(state.permanent_staged_bytes.to_string().len() > old_used_digits);
    assert_eq!(state.reserved_staged_terminal_bytes, 0);
    assert!(
        SnapshotAccounting::rebuild(&state)
            .unwrap()
            .fits(&state)
            .unwrap()
    );
}

#[test]
fn permanent_staged_configuration_rejects_old_count_policy_and_missing_byte_budget() {
    let mut value = serde_json::to_value(AtomicLimits::default()).unwrap();
    let object = value.as_object_mut().unwrap();
    object.remove("max_permanent_staged_bytes");
    assert!(serde_json::from_value::<AtomicLimits>(value.clone()).is_err());
    value["max_transaction_records"] = serde_json::json!(1_000_000);
    assert!(serde_json::from_value::<AtomicLimits>(value.clone()).is_err());
    value["max_permanent_staged_bytes"] = serde_json::json!(3u64 << 30);
    assert!(serde_json::from_value::<AtomicLimits>(value.clone()).is_err());
    value
        .as_object_mut()
        .unwrap()
        .remove("max_transaction_records");
    assert_eq!(
        serde_json::from_value::<AtomicLimits>(value)
            .unwrap()
            .max_permanent_staged_bytes,
        3 << 30
    );
}

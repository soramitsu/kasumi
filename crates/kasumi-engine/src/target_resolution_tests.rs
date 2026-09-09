use super::*;
use crate::target_completion_machine::{CompletionMachine, tests as fixture};
use kasumi_store::{NodeStore, test_utils::LocalKeyProvider};
use std::collections::BTreeSet;

fn state(origin: &TargetOrigin) -> TenantState {
    let incarnation = origin.input.target_incarnation.to_string();
    let mut state = crate::TenantEngine::new(
        origin.materialization.request.tenant.clone(),
        incarnation.clone(),
        Policy {
            grants: vec![Grant {
                principal: "operator".into(),
                collection: None,
                actions: BTreeSet::from([Action::Admin]),
            }],
            strict_read_audit: false,
        },
        Limits::default(),
    )
    .unwrap()
    .generation()
    .unwrap()
    .state
    .clone();
    state.revision_base = origin.materialization.request.checkpoint.revision + 1;
    state.revision = state.revision_base;
    state.target_lifecycle.insert(
        incarnation,
        TargetExecutionState {
            origin: origin.clone(),
            completion: None,
            activation: None,
        },
    );
    state.target_completion_head = Some(
        TargetCompletionHead::empty(origin, state.limits.max_target_resolution_bytes).unwrap(),
    );
    state
}
fn seal(state: &mut TenantState) -> TargetResolutionRecord {
    let origin = state.target_lifecycle[&state.incarnation].origin.clone();
    let original = fixture::attempt(&origin, None, 3, 1, 200, 500);
    let (input, intent) = fixture::resolution(&original, 4);
    let mut machine = CompletionMachine {
        origin: &origin,
        head: state.target_completion_head.as_mut().unwrap(),
        completion: None,
        terminal_bytes: 0,
        maximum_bytes: state.limits.max_target_resolution_bytes,
    };
    machine.prepare(original, None, None).unwrap();
    let fact = machine
        .resolve(input, fixture::applied(intent, 500, 3), None)
        .unwrap();
    state.revision = fact.revision;
    TargetResolutionRecord::Completion(Box::new(fact))
}
fn position(record: &TargetResolutionRecord) -> kasumi_raft::AppliedEntryContext {
    let at = record.position();
    kasumi_raft::AppliedEntryContext {
        log_id: openraft::LogId::new(
            openraft::CommittedLeaderId::new(at.term, at.leader_node_id),
            at.index,
        ),
        previous: None,
        membership: Default::default(),
        command_sha256: at.command_sha256.clone(),
        retirement_seed: None,
    }
}
async fn durable() -> (tempfile::TempDir, Arc<TenantStore>, TenantState, View) {
    let directory = tempfile::tempdir().unwrap();
    let node = NodeStore::create_new(
        directory.path().join("node.redb"),
        kasumi_store::test_utils::NODE_STORE_ID,
        ScratchDisk::fixture(),
    )
    .unwrap();
    let state = state(&fixture::origin());
    let store = TenantStore::open_fixture(
        node,
        state.tenant.clone(),
        Arc::new(LocalKeyProvider::new([93; 32])),
    )
    .await
    .unwrap();
    let empty = View::empty(&state.tenant, &state.incarnation).unwrap();
    let install = empty
        .prepare_install(&store, &state, &"18".repeat(32), false)
        .unwrap();
    store
        .replace_namespaces(&install.replacements(), install.writes())
        .unwrap();
    (directory, store, state, install.view)
}

#[tokio::test]
async fn exact_target_terminal_prefix_hides_unpublished_rows_and_rejects_changed_replay() {
    let (_directory, _store, before, selected) = durable().await;
    let mut next = before.clone();
    let record = seal(&mut next);
    let at = position(&record);
    let pending = Pending::prepare(
        &selected,
        &mut next,
        record.clone(),
        &at,
        TARGET_COMPLETION_RESERVE_BYTES,
    )
    .unwrap();
    let advanced = pending.persist().unwrap();
    assert!(selected.get(&record.key()).unwrap().is_none());
    let TargetResolutionRecord::Completion(fact) = &record else {
        unreachable!()
    };
    let original = fact.input.attempt.intent.request.command_id;
    assert!(selected.terminal_fact(&before, original).unwrap().is_none());
    assert_eq!(
        advanced.terminal_fact(&next, original).unwrap().as_deref(),
        Some(fact.as_ref())
    );
    assert!(
        selected
            .prepared_attempt(&before, original)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        advanced
            .prepared_attempt(&next, original)
            .unwrap()
            .as_deref(),
        Some(fact.input.attempt.as_ref())
    );
    assert!(
        advanced
            .prepared_attempt(&next, uuid::Uuid::from_u128(998))
            .unwrap()
            .is_none()
    );
    assert_eq!(advanced.get(&record.key()).unwrap().unwrap().record, record);
    advanced.validate_state(&next).unwrap();

    let mut replay_state = before.clone();
    assert_eq!(seal(&mut replay_state), record);
    let replay = Pending::prepare(
        &selected,
        &mut replay_state,
        record.clone(),
        &at,
        TARGET_COMPLETION_RESERVE_BYTES,
    )
    .unwrap()
    .persist()
    .unwrap();
    assert_eq!(replay.head(), advanced.head());

    let mut changed = record;
    let TargetResolutionRecord::Completion(fact) = &mut changed else {
        unreachable!()
    };
    fact.position.command_sha256 = "fe".repeat(32);
    let mut changed_state = before;
    seal(&mut changed_state);
    let different = Pending::prepare(
        &selected,
        &mut changed_state,
        changed.clone(),
        &position(&changed),
        TARGET_COMPLETION_RESERVE_BYTES,
    )
    .unwrap();
    assert!(different.persist().is_err());
}

#[test]
fn target_row_binds_actual_generation_command_and_separate_framed_budget() {
    let mut state = state(&fixture::origin());
    let record = seal(&mut state);
    let at = position(&record);
    let row = Row::ordered(&state.target_resolution_head, record, &at).unwrap();
    row.validate(&state).unwrap();
    let mut wrong_command = at;
    wrong_command.command_sha256 = "fa".repeat(32);
    assert!(
        Row::ordered(
            &state.target_resolution_head,
            row.record.clone(),
            &wrong_command
        )
        .is_err()
    );
    let mut relabelled = row.clone();
    relabelled.command_sha256 = "fa".repeat(32);
    assert!(relabelled.validate(&state).is_err());
    let mut future = row.clone();
    let TargetResolutionRecord::Completion(fact) = &mut future.record else {
        unreachable!()
    };
    fact.position.index += 1;
    assert!(future.validate(&state).is_err());
    let mut too_early = state.clone();
    too_early.revision -= 1;
    assert!(row.validate(&too_early).is_err());
    advance(&mut state.target_resolution_head, &row).unwrap();
    assert_eq!(
        state.target_resolution_head.encoded_bytes,
        row.framed_bytes().unwrap()
    );
    assert_eq!(
        snapshot_limit(&state).unwrap(),
        state.limits.max_snapshot_bytes + row.framed_bytes().unwrap()
    );
    state.limits.max_target_resolution_bytes = row.framed_bytes().unwrap() - 1;
    assert!(snapshot_limit(&state).is_err());
}

#[tokio::test]
async fn target_snapshot_catalog_reopens_only_its_exact_committed_prefix() {
    let (_directory, store, before, selected) = durable().await;
    let mut next = before.clone();
    let record = seal(&mut next);
    let advanced = Pending::prepare(
        &selected,
        &mut next,
        record.clone(),
        &position(&record),
        TARGET_COMPLETION_RESERVE_BYTES,
    )
    .unwrap()
    .persist()
    .unwrap();
    let row = advanced.row(1).unwrap();
    let mut staged = Builder::new(
        store.scratch_disk(),
        8 << 20,
        &next.tenant,
        &next.incarnation,
    )
    .unwrap();
    staged.push(&row, &next).unwrap();
    assert!(staged.push(&row, &next).is_err());
    let staged = staged.finish(&next).unwrap();
    let checkpoint = "29".repeat(32);
    assert!(
        staged
            .prepare_install(&store, &next, &checkpoint, true)
            .is_err()
    );
    let writes = advanced.checkpoint_writes(&next, &checkpoint).unwrap();
    store.write_batch(&writes).unwrap();
    let reopened = staged
        .prepare_install(&store, &next, &checkpoint, true)
        .unwrap();
    reopened.view.validate_state(&next).unwrap();
    assert_eq!(reopened.view.get(&record.key()).unwrap().unwrap(), row);
    assert!(selected.get(&record.key()).unwrap().is_none());
    assert!(
        selected
            .prepare_install(&store, &before, &checkpoint, true)
            .is_err()
    );
}

#[test]
fn every_historical_terminal_requires_its_exact_earlier_seal() {
    let mut state = state(&fixture::origin());
    let mut record = seal(&mut state);
    let TargetResolutionRecord::Completion(fact) = &mut record else {
        unreachable!()
    };
    // All supplied records are internally consistent and have recomputed
    // digests, but the claimed predecessor has never appeared in the prefix.
    let mut missing = fact.sealed_reference().unwrap();
    missing.original_command_id = uuid::Uuid::from_u128(999);
    missing.resolution_command_id = uuid::Uuid::from_u128(998);
    missing.resolution_control_revision = 2;
    fact.input.attempt.input.predecessor = Some(missing);
    fact.input.attempt.intent.request.phase_input_sha256 =
        fact.input.attempt.input.digest().unwrap();
    fact.input.attempt.intent.request_sha256 =
        staged_digest(&fact.input.attempt.intent.request).unwrap().0;
    fact.resolution_intent.request.phase_input_sha256 = fact.input.digest().unwrap();
    fact.resolution_intent.request_sha256 =
        staged_digest(&fact.resolution_intent.request).unwrap().0;
    fact.validate().unwrap();
    let row = Row::ordered(
        &state.target_resolution_head,
        record.clone(),
        &position(&record),
    )
    .unwrap();
    row.validate(&state).unwrap();
    let mut builder = Builder::new(
        &ScratchDisk::fixture(),
        8 << 20,
        &state.tenant,
        &state.incarnation,
    )
    .unwrap();
    assert!(builder.push(&row, &state).is_err());
}

#[test]
fn current_selectors_cannot_omit_a_budget_effect_or_the_last_seal() {
    let mut state = state(&fixture::origin());
    let record = seal(&mut state);
    let row = Row::ordered(
        &state.target_resolution_head,
        record.clone(),
        &position(&record),
    )
    .unwrap();
    let mut causal = CausalHead::default();
    validate_causal(&state, &row, &mut causal, |_| Ok(None)).unwrap();
    validate_causal_current(&state, &causal, |_| Ok(Some(row.clone()))).unwrap();
    state.target_completion_head.as_mut().unwrap().predecessor = None;
    assert!(validate_causal_current(&state, &causal, |_| Ok(Some(row.clone()))).is_err());
    let mut state = self::state(&fixture::origin());
    state.limits.max_target_resolution_bytes += 1;
    assert!(validate_current(&state, |_| Ok(None)).is_err());
    state
        .target_completion_head
        .as_mut()
        .unwrap()
        .budget_operation_id = Some(uuid::Uuid::from_u128(444));
    assert!(validate_current(&state, |_| Ok(None)).is_err());
}

#[test]
fn admitted_completion_reserves_hot_audit_and_resident_completion_space() {
    let mut state = state(&fixture::origin());
    let original = fixture::attempt(&fixture::origin(), None, 3, 1, 200, 500);
    state.target_completion_head.as_mut().unwrap().active = Some(Box::new(original.clone()));
    state.limits.audit_retention.hot_bytes = TARGET_COMPLETION_AUDIT_RESERVE_BYTES;
    assert!(crate::accounting::audit_fits(&state));
    let reserved = crate::accounting::snapshot_headroom(&state).unwrap();
    state.audit_retention.hot_bytes = 1;
    assert!(!crate::accounting::audit_fits(&state));
    state.audit_retention.hot_bytes = MAX_AUDIT_EVENT_BYTES as u64;
    state
        .target_lifecycle
        .get_mut(&state.incarnation)
        .unwrap()
        .completion = Some(fixture::completion(&original));
    assert!(crate::accounting::audit_fits(&state));
    assert_eq!(
        reserved - crate::accounting::snapshot_headroom(&state).unwrap(),
        MAX_TARGET_COMPLETION_RECORD_BYTES + MAX_AUDIT_EVENT_BYTES as u64
    );
    state.audit_retention.hot_bytes += 1;
    assert!(!crate::accounting::audit_fits(&state));
    state.target_completion_head.as_mut().unwrap().active = None;
    assert!(crate::accounting::audit_fits(&state));
}

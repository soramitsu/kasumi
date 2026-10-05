//! Closed validation owners exercise actual snapshot decoding and continuity.
//! The public-generation fault is an escape-boundary probe, not history funding.
use super::validation_baseline::{CapturedValidation, UninitializedEngine, ValidationBaseline};
use super::*;
use crate::test_utils::SnapshotFixture as _;
use anyhow::Context as _;
use kasumi_raft::ApplicationSourceCustody as _;
use std::cell::Cell;
use std::io::Read;

#[derive(Clone, Copy)]
struct PublicProbe {
    calls: usize,
    refuse: bool,
}
thread_local! {
    static PUBLIC_PROBE: Cell<Option<PublicProbe>> = const { Cell::new(None) };
}
const PUBLIC_REFUSAL: &str = "test-only public generation escape refused";
pub(super) fn observe_public_generation() -> Result<()> {
    PUBLIC_PROBE.with(|slot| {
        if let Some(mut probe) = slot.get() {
            probe.calls += 1;
            slot.set(Some(probe));
            if probe.refuse {
                return Err(Error::new(ErrorCode::ResourceExhausted, PUBLIC_REFUSAL));
            }
        }
        Ok(())
    })
}
struct ProbeReset(Option<PublicProbe>);
impl Drop for ProbeReset {
    fn drop(&mut self) {
        PUBLIC_PROBE.with(|slot| slot.set(self.0));
    }
}
fn public_probe<R>(refuse: bool, work: impl FnOnce() -> R) -> (R, usize) {
    let reset =
        ProbeReset(PUBLIC_PROBE.with(|slot| slot.replace(Some(PublicProbe { calls: 0, refuse }))));
    let output = work();
    let calls = PUBLIC_PROBE.with(|slot| slot.get().expect("active probe").calls);
    drop(reset);
    (output, calls)
}

#[derive(Debug, PartialEq, Eq)]
enum RestoreLockState {
    Held,
    Available,
    Poisoned,
}
#[derive(Debug, PartialEq, Eq)]
struct RestoreRetirement {
    candidate_retired: bool,
    apply_lock: RestoreLockState,
}
type RestoreObservations = Arc<Mutex<Vec<RestoreRetirement>>>;
thread_local! {
    static RESTORE_PROBE: std::cell::RefCell<Option<RestoreObservations>> = const {
        std::cell::RefCell::new(None)
    };
}
// This witness is after the actual installation/write fields and before the
// actual ApplyOwner. It holds only a weak candidate index owner and records
// observations without panicking during cleanup.
pub(super) struct RestoreRetirementProbe<'engine> {
    engine: &'engine TenantEngine,
    candidate_indexes: std::sync::Weak<QueryIndexes>,
    observations: RestoreObservations,
}
pub(super) fn restore_retirement_probe<'engine>(
    engine: &'engine TenantEngine,
    generation: &Generation,
) -> Option<RestoreRetirementProbe<'engine>> {
    let observations = RESTORE_PROBE.with(|slot| slot.borrow().clone())?;
    Some(RestoreRetirementProbe {
        engine,
        candidate_indexes: Arc::downgrade(&generation.indexes),
        observations,
    })
}
impl Drop for RestoreRetirementProbe<'_> {
    fn drop(&mut self) {
        let apply_lock = match self.engine.apply_lock.try_lock() {
            Ok(_) => RestoreLockState::Available,
            Err(std::sync::TryLockError::WouldBlock) => RestoreLockState::Held,
            Err(std::sync::TryLockError::Poisoned(_)) => RestoreLockState::Poisoned,
        };
        self.observations
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(RestoreRetirement {
                candidate_retired: self.candidate_indexes.upgrade().is_none(),
                apply_lock,
            });
    }
}
struct RestoreProbeScope {
    previous: Option<RestoreObservations>,
    observations: RestoreObservations,
}
impl RestoreProbeScope {
    fn start() -> Self {
        let observations = Arc::new(Mutex::new(Vec::new()));
        Self {
            previous: RESTORE_PROBE.with(|slot| slot.replace(Some(observations.clone()))),
            observations,
        }
    }
}
impl Drop for RestoreProbeScope {
    fn drop(&mut self) {
        RESTORE_PROBE.with(|slot| slot.replace(self.previous.take()));
    }
}

#[derive(Clone)]
struct Candidate {
    state: TenantState,
    receipts: crate::mutation_receipt::View,
    bindings: crate::backup_binding::View,
    terminals: crate::staged_terminal::View,
    targets: crate::target_resolution::View,
}
impl Candidate {
    fn empty(state: TenantState) -> anyhow::Result<Self> {
        Ok(Self {
            receipts: crate::mutation_receipt::View::empty(&state.tenant, &state.incarnation)?,
            bindings: crate::backup_binding::View::empty(&state.incarnation)?,
            terminals: crate::staged_terminal::View::empty(&state.tenant, &state.incarnation)?,
            targets: crate::target_resolution::View::empty(&state.tenant, &state.incarnation)?,
            state,
        })
    }
    fn selected(generation: &Generation) -> Self {
        Self {
            state: generation.state.clone(),
            receipts: generation.receipts.clone(),
            bindings: generation.backup_bindings.clone(),
            terminals: generation.terminals.clone(),
            targets: generation.target_resolutions.clone(),
        }
    }
    fn prepare(&self, engine: &TenantEngine, prior: &ValidationBaseline<'_>) -> Result<Generation> {
        engine.prepare_state(
            prior,
            self.state.clone(),
            self.receipts.clone(),
            self.bindings.clone(),
            self.terminals.clone(),
            self.targets.clone(),
        )
    }
    fn engine(&self) -> anyhow::Result<TenantEngine> {
        // This constructor creates an actually empty verifier, never classifies
        // failed acquisition of an existing Engine as an absent baseline.
        let owner = UninitializedEngine::new(&self.state)?;
        let generation = self.prepare(owner.engine(), &owner.baseline())?;
        Ok(owner.finish(generation))
    }
    fn image(
        &self,
        disk: &Arc<kasumi_store::ScratchDisk>,
    ) -> crate::test_fixture_failure::FixtureResult<kasumi_store::SnapshotImage> {
        kasumi_store::SnapshotImage::capture(disk, self.state.limits.max_snapshot_bytes, |writer| {
            crate::snapshot_codec::write(
                &self.state,
                &self.receipts,
                &self.bindings,
                &self.terminals,
                &self.targets,
                writer,
            )
        })
        .map_err(Into::into)
    }
}
fn fresh() -> TenantEngine {
    TenantEngine::new(
        "validation".into(),
        uuid::Uuid::from_u128(0x765).to_string(),
        Policy {
            grants: vec![Grant {
                principal: "owner".into(),
                collection: None,
                actions: BTreeSet::from([Action::Admin, Action::Read, Action::Write]),
            }],
            strict_read_audit: false,
        },
        Limits::default(),
    )
    .unwrap()
}
fn scratch() -> anyhow::Result<crate::codec_fixture::ScratchScope> {
    crate::codec_fixture::ScratchScope::new(kasumi_store::test_utils::TestDiskMemory::new(
        64 << 20,
        64,
    ))
}
fn context(tenant: &str) -> RequestContext {
    RequestContext {
        authorization: RequestAuthorization::service_identity(),
        principal: "owner".into(),
        tenant: tenant.into(),
        scopes: BTreeSet::from([Action::Admin, Action::Read, Action::Write]),
        request_id: "validation-baseline".into(),
    }
}
fn command(engine: &TenantEngine, revision: u64, operation: Operation) -> Command {
    Command {
        context: context(&engine.tenant),
        timestamp_ms: revision,
        operation,
    }
}
fn put(id: &str) -> Operation {
    Operation::Mutate(MutationBatch {
        idempotency_key: id.into(),
        read_set: vec![],
        operations: vec![Mutation::Put {
            collection: "docs".into(),
            id: id.into(),
            body: serde_json::json!({"id":id}),
            expected: Precondition::Absent,
        }],
    })
}
fn seeded(
    disk: &Arc<kasumi_store::ScratchDisk>,
) -> crate::test_fixture_failure::FixtureResult<TenantEngine> {
    let engine = fresh();
    engine.apply_command(
        disk,
        1,
        command(
            &engine,
            1,
            Operation::CreateCollection(CollectionDefinition {
                name: "docs".into(),
                schema: serde_json::json!({"type":"object"}),
                indexes: vec![],
                strict_read_audit: false,
                retention_class: CollectionRetentionClass::Operational,
                write_mode: CollectionWriteMode::Mutable,
            }),
        ),
    )??;
    engine.apply_command(disk, 2, command(&engine, 2, put("first")))??;
    Ok(engine)
}
struct CountedReader<'a> {
    inner: kasumi_store::SnapshotReader,
    reads: &'a Cell<usize>,
}
impl Read for CountedReader<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        self.reads.set(self.reads.get() + 1);
        self.inner.read(bytes)
    }
}

#[test]
fn validation_baseline_actual_bootstrap_absence_and_public_failure_are_distinct()
-> crate::test_fixture_failure::FixtureResult<()> {
    let scratch = scratch()?;
    let initial = fresh();
    let image = initial.fixture_snapshot(&scratch.disk)?;
    let (opened, calls) = public_probe(true, || TenantEngine::from_bootstrap("validation", &image));
    let opened = opened?;
    assert_eq!(
        calls, 0,
        "actual startup must use its constructor-owned empty baseline"
    );
    assert_eq!(opened.generation()?.state.revision, 0);
    let before = opened.generation()?;
    let (failed, calls) = public_probe(true, || CapturedValidation::capture(&opened));
    let error = match failed {
        Ok(_) => panic!("public acquisition failure became absence"),
        Err(error) => error,
    };
    assert_eq!(
        (error.code, error.message.as_str()),
        (ErrorCode::ResourceExhausted, PUBLIC_REFUSAL)
    );
    assert_eq!(calls, 1);
    assert!(Arc::ptr_eq(&before, &opened.generation()?));
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        public_probe(true, || panic!("restore observer state on unwind"));
    }));
    assert!(unwind.is_err());
    assert!(
        opened.generation().is_ok(),
        "test refusal escaped its RAII scope"
    );
    Ok(())
}

#[test]
fn validation_baseline_sealed_and_poisoned_owners_refuse_before_decode()
-> crate::test_fixture_failure::FixtureResult<()> {
    let scratch = scratch()?;
    for poison in [false, true] {
        let engine = seeded(&scratch.disk)?;
        let image = engine.fixture_snapshot(&scratch.disk)?;
        if poison {
            let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _guard = engine.apply_lock.lock().unwrap();
                panic!("poison actual apply ownership");
            }));
            assert!(unwind.is_err());
        } else {
            engine.seal();
        }
        // This is the actual public fixture restore route; its closed owner
        // must be acquired before opening/decoding the encrypted input.
        let error = engine.restore_candidate(&image).unwrap_err();
        let error = error.operation_error().expect("ordinary owner refusal");
        assert_eq!(
            error.code,
            if poison {
                ErrorCode::Unavailable
            } else {
                ErrorCode::Sealed
            }
        );
        for mode in [
            kasumi_raft::SnapshotRestoreMode::Install,
            kasumi_raft::SnapshotRestoreMode::Reopen,
        ] {
            let reads = Cell::new(0);
            let mut reader = CountedReader {
                inner: image.reader(),
                reads: &reads,
            };
            let restore = kasumi_raft::SnapshotRestoreContext {
                mode,
                backend_sha256: image.sha256().into(),
                meta: kasumi_raft::SnapshotMeta {
                    last_log_id: None,
                    last_membership: Default::default(),
                    snapshot_id: "unread-owner-refusal".into(),
                },
            };
            let failure = <TenantEngine as kasumi_raft::StateMachineBackend>::prepare_restore(
                &engine,
                &restore,
                &mut reader,
            );
            let error = match failure {
                Ok(_) => panic!("unavailable restore owner consumed input"),
                Err(error) => error,
            };
            assert_eq!(reads.get(), 0);
            if poison {
                assert!(error.to_string().contains("tenant apply lock poisoned"));
            } else {
                assert_eq!(
                    error
                        .operation_error()
                        .expect("ordinary restore owner refusal")
                        .root_cause()
                        .downcast_ref::<Error>()
                        .expect("typed current failure")
                        .code,
                    ErrorCode::Sealed
                );
            }
        }
        if !poison {
            let reads = Cell::new(0);
            let mut reader = CountedReader {
                inner: image.reader(),
                reads: &reads,
            };
            let error = <TenantEngine as kasumi_raft::StateMachineBackend>::validate_snapshot(
                &engine,
                &mut reader,
            )
            .expect_err("sealed standalone validation treated current as absent");
            assert_eq!(
                error
                    .operation_error()
                    .expect("ordinary validation owner refusal")
                    .root_cause()
                    .downcast_ref::<Error>()
                    .expect("typed owner failure")
                    .code,
                ErrorCode::Sealed
            );
            assert_eq!(reads.get(), 0);
        }
    }
    Ok(())
}

struct AdvancingReader<'a> {
    inner: kasumi_store::SnapshotReader,
    engine: &'a TenantEngine,
    disk: &'a Arc<kasumi_store::ScratchDisk>,
    advanced: bool,
    failure: Option<kasumi_raft::TestPublicationFailure>,
}
impl Read for AdvancingReader<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        if self.failure.is_some() {
            return Err(std::io::ErrorKind::Other.into());
        }
        if !self.advanced {
            self.advanced = true;
            let outcome =
                match self
                    .engine
                    .apply_command(self.disk, 3, command(self.engine, 3, put("later")))
                {
                    Ok(outcome) => outcome,
                    Err(original) => {
                        self.failure = Some(original);
                        return Err(std::io::ErrorKind::Other.into());
                    }
                };
            outcome.map_err(std::io::Error::other)?;
        }
        self.inner.read(bytes)
    }
}
#[test]
fn validation_baseline_standalone_decode_uses_one_prior_during_real_advance()
-> crate::test_fixture_failure::FixtureResult<()> {
    let scratch = scratch()?;
    let engine = seeded(&scratch.disk)?;
    let original = engine.generation()?;
    let image = engine.fixture_snapshot(&scratch.disk)?;
    let (captured, calls) = public_probe(false, || CapturedValidation::capture(&engine));
    let captured = captured?;
    assert_eq!(calls, 1);
    let mut reader = AdvancingReader {
        inner: image.reader(),
        engine: &engine,
        disk: &scratch.disk,
        advanced: false,
        failure: None,
    };
    let (validated, calls) = public_probe(true, || {
        engine.prepare_snapshot_reader(&captured.baseline(), &scratch.disk, &mut reader, None)
    });
    let validated = validated?;
    assert!(reader.advanced);
    assert!(reader.failure.is_none());
    assert_eq!(calls, 0);
    assert_eq!(validated.state.revision, original.state.revision);
    assert_eq!(validated.receipts.head(), original.receipts.head());
    let advanced = engine.generation()?;
    assert_eq!(advanced.state.revision, 3);
    assert_eq!(
        advanced.state.mutation_receipt_head.count,
        original.state.mutation_receipt_head.count + 1
    );
    assert!(
        advanced.state.collections["docs"]
            .documents
            .contains_key("later")
    );
    // Standalone validation does not publish. A later actual restore acquires
    // the then-current prior and rejects that same now-outdated receipt prefix.
    let error = engine.restore_candidate(&image).unwrap_err();
    let error = error
        .operation_error()
        .expect("ordinary continuity refusal");
    assert_eq!(error.code, ErrorCode::Corruption);
    assert_eq!(
        error.message,
        "snapshot removed or substituted permanent mutation receipts"
    );
    assert!(Arc::ptr_eq(&advanced, &engine.generation()?));
    Ok(())
}

fn control_state() -> TenantState {
    let mut state = crate::backup_binding::tests::state();
    state.revision = 2;
    state
        .lifecycle_control
        .as_mut()
        .unwrap()
        .installation_revision = 1;
    state
}
fn recovery_candidate() -> anyhow::Result<Candidate> {
    let mut state = crate::snapshot_codec::recovery_tests::coordinator();
    let request = state
        .recovery_control
        .operations
        .get_min()
        .unwrap()
        .1
        .request
        .clone();
    state.recovery_control = Default::default();
    let command = recovery::RecoveryCommand {
        authorization: recovery::RecoveryAuthorization {
            context: context(&state.tenant),
            policy_epoch: state.policy_epoch,
            admitted_at_ms: 1000,
            expires_at_ms: 2000,
        },
        mutation: recovery::RecoveryMutation::Start(Box::new(request)),
    };
    recovery::apply(&mut state, &command)?;
    Candidate::empty(state)
}
fn target_candidate(
    disk: &Arc<kasumi_store::ScratchDisk>,
) -> crate::test_fixture_failure::FixtureResult<Candidate> {
    let (mut state, rows) = crate::target_resolution::tests::linked_sealed_successor_rows();
    // The existing machine fixture establishes actual linked target outcomes.
    // Supply its real restoration lineage for complete tenant validation too.
    let origin = state.target_lifecycle[&state.incarnation].origin.clone();
    let checkpoint = origin.materialization.request.checkpoint.clone();
    state.restored_from = Some(checkpoint.clone());
    state.restore_lineage = vec![RestoreLineageLink {
        checkpoint: checkpoint.clone(),
        target_incarnation: state.incarnation.clone(),
    }];
    state.suspended = true;
    state.pending_restore = Some(PendingRestore {
        backup_id: checkpoint.backup_id.to_string(),
        source_revision: checkpoint.revision,
    });
    let mut builder =
        crate::target_resolution::Builder::new(disk, 64 << 20, &state.tenant, &state.incarnation)?;
    for row in rows {
        builder.push(&row, &state)?;
    }
    let targets = builder.finish(&state)?;
    let mut candidate = Candidate::empty(state)?;
    candidate.targets = targets;
    Ok(candidate)
}
fn terminal_candidate(
    disk: &Arc<kasumi_store::ScratchDisk>,
) -> crate::test_fixture_failure::FixtureResult<Candidate> {
    use crate::staged_terminal::{AppliedIdentity, AppliedOrigin, Builder, Row};
    let mut state = fresh().generation()?.state.clone();
    state.revision = 1;
    let manifest = StagedManifest::from_chunks(&[StagedChunk {
        read_set: vec![],
        operations: vec![Mutation::Delete {
            collection: "docs".into(),
            id: "row".into(),
            expected: Precondition::Any,
        }],
    }])?;
    let row = Row {
        ordinal: 1,
        key: staging::identity("owner", "stopped")?,
        previous_sha256: state.staged_terminal_head.sha256.clone(),
        applied: AppliedIdentity {
            incarnation: state.incarnation.clone(),
            revision: 1,
            timestamp_ms: 1,
            command_sha256: "ab".repeat(32),
            origin: AppliedOrigin::Raft {
                term: 1,
                leader: 1,
                index: 1,
                context_sha256: "cd".repeat(32),
            },
        },
        stage: StagedTransaction {
            scope: StagedTransactionScope {
                tenant: state.tenant.clone(),
                incarnation: state.incarnation.clone(),
                principal: "owner".into(),
            },
            transaction_id: "stopped".into(),
            manifest_digest: staged_digest(&manifest)?.0,
            manifest,
            chunks: Default::default(),
            stored_chunk_bytes: 0,
            uploaded_payload_bytes: 0,
            uploaded_operations: 0,
            uploaded_read_assertions: 0,
            expires_at_ms: None,
            ttl_ms: 60000,
            outcome: StagedOutcome::Aborted {
                receipt: WriteReceipt {
                    revision: 1,
                    versions: Default::default(),
                },
            },
        },
    };
    let mut builder = Builder::new(disk, 64 << 20, &state.tenant, &state.incarnation)?;
    builder.push(&row, &state)?;
    crate::staged_terminal::advance(&mut state.staged_terminal_head, &row)?;
    state.permanent_staged_bytes = state.staged_terminal_head.encoded_bytes;
    let terminals = builder.finish(&state.staged_terminal_head)?;
    let mut candidate = Candidate::empty(state)?;
    candidate.terminals = terminals;
    Ok(candidate)
}
fn binding_candidate(
    disk: &Arc<kasumi_store::ScratchDisk>,
) -> crate::test_fixture_failure::FixtureResult<Candidate> {
    let mut state = control_state();
    let mut row = crate::backup_binding::tests::row(
        &state,
        b"exact-original-intent",
        uuid::Uuid::from_u128(50),
    );
    row.applied.revision = 2;
    if let crate::staged_terminal::AppliedOrigin::Raft { index, .. } = &mut row.applied.origin {
        *index = 2;
    }
    row.record.position.index = 2;
    let mut builder = crate::backup_binding::Builder::new(disk, 64 << 20, &state.incarnation)?;
    builder.push(&row, &state)?;
    crate::backup_binding::advance(&mut state.backup_binding_head, &row)?;
    let bindings = builder.finish(&state.backup_binding_head)?;
    let mut candidate = Candidate::empty(state)?;
    candidate.bindings = bindings;
    Ok(candidate)
}
fn assert_continuity(
    disk: &Arc<kasumi_store::ScratchDisk>,
    prior: Candidate,
    incoming: Candidate,
    code: ErrorCode,
    expected: &str,
) -> crate::test_fixture_failure::FixtureResult<()> {
    // Neither rejection may be explained by malformed incoming state or a
    // malformed old fixture. Both pass the actual full validator independently.
    drop(
        incoming
            .engine()
            .with_context(|| format!("incoming fixture: {expected}"))?,
    );
    let engine = prior
        .engine()
        .with_context(|| format!("prior fixture: {expected}"))?;
    let original = engine.generation()?;
    let (captured, calls) = public_probe(false, || CapturedValidation::capture(&engine));
    let captured = captured?;
    assert_eq!(calls, 1);
    let (rejected, calls) = public_probe(true, || incoming.prepare(&engine, &captured.baseline()));
    let error = match rejected {
        Ok(_) => panic!("standalone continuity skipped: {expected}"),
        Err(error) => error,
    };
    assert_eq!((error.code, error.message.as_str()), (code, expected));
    assert_eq!(calls, 0, "standalone validation reloaded public current");
    let apply = ApplyOwner::lock_validation(&engine)?;
    let (rejected, calls) = public_probe(true, || {
        incoming.prepare(&engine, &ValidationBaseline::from_apply(&apply))
    });
    let error = match rejected {
        Ok(_) => panic!("serialized continuity skipped: {expected}"),
        Err(error) => error,
    };
    assert_eq!((error.code, error.message.as_str()), (code, expected));
    assert_eq!(
        calls, 0,
        "apply-owned validation escaped through public generation"
    );
    drop(apply);
    let image = incoming.image(disk)?;
    let (rejected, calls) = public_probe(true, || engine.restore_candidate(&image));
    let error = rejected.expect_err("actual restore accepted a removed immutable prior fact");
    let error = error
        .operation_error()
        .expect("ordinary continuity refusal");
    assert_eq!((error.code, error.message.as_str()), (code, expected));
    assert_eq!(calls, 0);
    assert!(Arc::ptr_eq(&original, &engine.generation()?));
    Ok(())
}

#[test]
fn validation_baseline_recovery_binding_continuity_refuses_valid_rollback()
-> crate::test_fixture_failure::FixtureResult<()> {
    let scratch = scratch()?;
    let disk = &scratch.disk;
    // Actual recovery Start reducer constructs permanent operation/target IDs.
    let prior = recovery_candidate()?;
    let mut incoming = prior.clone();
    incoming.state.recovery_control = Default::default();
    assert_continuity(
        disk,
        prior,
        incoming,
        ErrorCode::Conflict,
        "snapshot removed a permanent target recovery binding",
    )?;
    Ok(())
}

#[test]
fn validation_baseline_target_history_continuity_refuses_valid_rollback()
-> crate::test_fixture_failure::FixtureResult<()> {
    let scratch = scratch()?;
    let disk = &scratch.disk;
    // Immutable target origin; completion rows are removed with their head so
    // this negative remains a valid fresh verifier input with the same lineage.
    let prior = target_candidate(disk)?;
    let mut incoming = prior.clone();
    incoming.state.target_lifecycle.clear();
    incoming.state.target_completion_head = None;
    incoming.targets =
        crate::target_resolution::View::empty(&incoming.state.tenant, &incoming.state.incarnation)?;
    incoming.state.target_resolution_head = incoming.targets.head().clone();
    assert_continuity(
        disk,
        prior,
        incoming,
        ErrorCode::Corruption,
        "snapshot removed target history",
    )?;
    Ok(())
}

#[test]
fn validation_baseline_control_installation_continuity_refuses_valid_rollback()
-> crate::test_fixture_failure::FixtureResult<()> {
    let scratch = scratch()?;
    let disk = &scratch.disk;
    // Installed immutable Control identity.
    let prior = Candidate::empty(control_state())?;
    let mut incoming = prior.clone();
    incoming.state.lifecycle_control = None;
    assert_continuity(
        disk,
        prior,
        incoming,
        ErrorCode::Corruption,
        "snapshot substituted the immutable control installation",
    )?;
    Ok(())
}

#[test]
fn validation_baseline_lifecycle_intent_continuity_refuses_valid_rollback()
-> crate::test_fixture_failure::FixtureResult<()> {
    let scratch = scratch()?;
    let disk = &scratch.disk;
    // An actual fully validated original lifecycle intent, under that install.
    let mut state = control_state();
    state.revision = 3;
    let control = state.lifecycle_control.as_mut().unwrap();
    let mut intent = crate::target_completion_machine::tests::origin().materialization;
    intent.control_incarnation = control.installation.root.control_incarnation;
    intent.installation_generation = control.installation.generation;
    intent.revision = 3;
    intent.request.installation_sha256 = staged_digest(&control.installation)?.0;
    intent.request.authority_partition = control
        .installation
        .partitions
        .keys()
        .next()
        .unwrap()
        .clone();
    intent.request.expected_policy_epoch = state.policy_epoch;
    intent.request_sha256 = staged_digest(&intent.request)?.0;
    control.intents.insert(intent.request.command_id, intent);
    let prior = Candidate::empty(state)?;
    let mut incoming = prior.clone();
    incoming
        .state
        .lifecycle_control
        .as_mut()
        .unwrap()
        .intents
        .clear();
    assert_continuity(
        disk,
        prior,
        incoming,
        ErrorCode::Corruption,
        "snapshot substituted a permanent lifecycle intent",
    )?;
    Ok(())
}

#[test]
fn validation_baseline_staged_terminal_continuity_refuses_valid_rollback()
-> crate::test_fixture_failure::FixtureResult<()> {
    let scratch = scratch()?;
    let disk = &scratch.disk;
    // Canonical encrypted permanent staged row and its authenticated head.
    let prior = terminal_candidate(disk)?;
    let mut incoming = prior.clone();
    incoming.terminals =
        crate::staged_terminal::View::empty(&incoming.state.tenant, &incoming.state.incarnation)?;
    incoming.state.staged_terminal_head = incoming.terminals.head().clone();
    incoming.state.permanent_staged_bytes = 0;
    assert_continuity(
        disk,
        prior,
        incoming,
        ErrorCode::Corruption,
        "snapshot removed or substituted terminal staged history",
    )?;
    Ok(())
}

#[test]
fn validation_baseline_target_terminal_continuity_refuses_valid_rollback()
-> crate::test_fixture_failure::FixtureResult<()> {
    let scratch = scratch()?;
    let disk = &scratch.disk;
    // Real completion-machine sealed rows in an encrypted causal table.
    let prior = target_candidate(disk)?;
    let mut incoming = prior.clone();
    let origin = &incoming.state.target_lifecycle[&incoming.state.incarnation].origin;
    incoming.state.target_completion_head = Some(TargetCompletionHead::empty(
        origin,
        incoming.state.limits.max_target_resolution_bytes,
    )?);
    incoming.targets =
        crate::target_resolution::View::empty(&incoming.state.tenant, &incoming.state.incarnation)?;
    incoming.state.target_resolution_head = incoming.targets.head().clone();
    assert_continuity(
        disk,
        prior,
        incoming,
        ErrorCode::Corruption,
        "snapshot removed or substituted permanent target terminal history",
    )?;
    Ok(())
}

#[test]
fn validation_baseline_backup_binding_continuity_refuses_valid_rollback()
-> crate::test_fixture_failure::FixtureResult<()> {
    let scratch = scratch()?;
    let disk = &scratch.disk;
    // Canonical encrypted permanent backup-binding row.
    let prior = binding_candidate(disk)?;
    let mut incoming = prior.clone();
    incoming.bindings = crate::backup_binding::View::empty(&incoming.state.incarnation)?;
    incoming.state.backup_binding_head = incoming.bindings.head().clone();
    assert_continuity(
        disk,
        prior,
        incoming,
        ErrorCode::Corruption,
        "snapshot removed or substituted permanent backup bindings",
    )?;
    Ok(())
}

#[test]
fn validation_baseline_mutation_receipt_continuity_refuses_valid_rollback()
-> crate::test_fixture_failure::FixtureResult<()> {
    let scratch = scratch()?;
    let disk = &scratch.disk;
    // Real ordinary mutation producer's selected encrypted receipt.
    let engine = seeded(disk)?;
    let prior = Candidate::selected(engine.generation()?.as_ref());
    let mut incoming = prior.clone();
    incoming.receipts =
        crate::mutation_receipt::View::empty(&incoming.state.tenant, &incoming.state.incarnation)?;
    incoming.state.mutation_receipt_head = incoming.receipts.head().clone();
    assert_continuity(
        disk,
        prior,
        incoming,
        ErrorCode::Corruption,
        "snapshot removed or substituted permanent mutation receipts",
    )?;
    Ok(())
}

#[test]
fn validation_baseline_foreign_same_identity_owner_refuses_before_read()
-> crate::test_fixture_failure::FixtureResult<()> {
    let scratch = scratch()?;
    let first = fresh();
    let second = fresh();
    assert_eq!(first.tenant, second.tenant);
    assert_eq!(first.incarnation, second.incarnation);
    let image = first.fixture_snapshot(&scratch.disk)?;
    let captured = CapturedValidation::capture(&first)?;
    let reads = Cell::new(0);
    let mut reader = CountedReader {
        inner: image.reader(),
        reads: &reads,
    };
    let result =
        second.prepare_snapshot_reader(&captured.baseline(), &scratch.disk, &mut reader, None);
    let error = match result {
        Ok(_) => panic!("same-identity foreign baseline accepted"),
        Err(error) => error,
    };
    let error = error
        .operation_error()
        .expect("ordinary foreign baseline refusal");
    assert_eq!(
        (error.code, error.message.as_str()),
        (
            ErrorCode::Corruption,
            "snapshot validation baseline belongs to another engine",
        )
    );
    assert_eq!(reads.get(), 0);
    let error = match snapshot_bundle::read(&second, &captured.baseline(), &mut reader, None) {
        Ok(_) => panic!("foreign baseline reached bundle input/storage"),
        Err(error) => error,
    };
    let error = error
        .operation_error()
        .expect("ordinary bundle owner refusal")
        .downcast_ref::<Error>()
        .expect("bundle refusal preserves the typed foreign owner error");
    assert_eq!(
        (error.code, error.message.as_str()),
        (
            ErrorCode::Corruption,
            "snapshot validation baseline belongs to another engine",
        )
    );
    assert_eq!(reads.get(), 0);
    Ok(())
}

struct SourceFixture {
    engine: Arc<TenantEngine>,
    roots: crate::application_sources::SourceRootsRef,
    stores: Arc<kasumi_store::TenantStorageSet>,
    node: kasumi_store::NodeStore,
    buffers: Arc<kasumi_raft::SnapshotBufferOwner>,
    storage: crate::test_utils::FixtureStorage,
    _directory: tempfile::TempDir,
}
impl SourceFixture {
    async fn new() -> crate::test_fixture_failure::FixtureResult<Self> {
        let directory = kasumi_store::test_utils::private_tempdir()?;
        let (mut persistent, mut scratch) =
            crate::test_utils::fixture_disk_configs(directory.path())?;
        // Reuse the established source-owner fixture policy; these tests do not
        // qualify cache fitting or optional cache retention.
        persistent.native_storage.cache.byte_limit = 0;
        scratch.native_cache_bytes = 0;
        let config = crate::test_utils::isolated_disk_admission_config(
            crate::admission::AdmissionConfig {
                max_inflight_bytes: Some(256 << 20),
                ..Default::default()
            },
            &persistent,
            &scratch,
        )?;
        let admission = crate::admission::NodeAdmission::with_fixed_memory(config, 2 << 30, 0)?;
        let storage =
            crate::test_utils::FixtureStorage::with_admission(&persistent, &scratch, admission)?;
        let node = storage.create_new(
            directory.path().join("persistent/node.kv"),
            kasumi_store::test_utils::NODE_STORE_ID,
        )?;
        let stores = kasumi_store::TenantStorageSet::initialize_catalogs_fixture(
            node.clone(),
            "validation".into(),
            Arc::new(kasumi_store::test_utils::LocalKeyProvider::new([209; 32])),
            Arc::new(kasumi_store::test_utils::LocalKeyProvider::new([210; 32])),
        )
        .await?;
        let initial = fresh();
        let image = initial.fixture_snapshot(stores.application().scratch_disk())?;
        crate::bootstrap::persist_fixture_bootstrap(
            &stores,
            &image,
            1,
            &format!("validation/{}", initial.incarnation),
        )?;
        let (roots, binding) = crate::application_sources::SourceRoots::new(
            stores.clone(),
            storage.admission.clone(),
            kasumi_raft::RaftLimits::default(),
        )?;
        let buffers = storage.admission.snapshot_buffer_owner()?;
        roots.bind_lifecycle(&buffers, binding)?;
        crate::test_utils::install_fixture_audit_placement(stores.application())?;
        let engine = Arc::new(TenantEngine::from_bootstrap("validation", &image)?);
        engine.install_storage_access(stores.application())?;
        engine.install_application_sources(roots.clone(), &image)?;
        Ok(Self {
            engine,
            roots,
            stores,
            node,
            buffers,
            storage,
            _directory: directory,
        })
    }
    async fn close(self) -> crate::test_fixture_failure::FixtureResult<()> {
        self.engine.seal();
        self.buffers.drain_startup().await?;
        std::future::poll_fn(|cx| self.roots.poll_drain(cx)).await?;
        self.storage.admission.drain_snapshot_startups().await?;
        self.stores.shutdown().await?;
        self.node.shutdown().await?;
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn validation_baseline_real_prepared_restore_holds_one_checked_apply_owner()
-> crate::test_fixture_failure::FixtureResult<()> {
    use kasumi_raft::StateMachineBackend as _;
    let fixture = SourceFixture::new().await?;
    let original = fixture.engine.generation()?;
    let image = kasumi_store::SnapshotImage::capture(
        fixture.stores.application().scratch_disk(),
        64 << 20,
        |writer| snapshot_bundle::write(&original, fixture.stores.application(), writer),
    )?;
    let context = kasumi_raft::SnapshotRestoreContext {
        mode: kasumi_raft::SnapshotRestoreMode::Install,
        backend_sha256: image.sha256().into(),
        meta: kasumi_raft::SnapshotMeta {
            last_log_id: None,
            last_membership: Default::default(),
            snapshot_id: "actual-validation-install".into(),
        },
    };
    let (prepared, calls) = public_probe(true, || {
        fixture
            .engine
            .prepare_restore(&context, &mut image.reader())
    });
    let prepared = prepared?;
    assert_eq!(calls, 0);
    assert!(fixture.engine.apply_lock.try_lock().is_err());
    assert!(!prepared.application_writes().is_empty());
    // No fabricated publication: dropping the actual uncommitted preparation
    // releases its checked owner and cancels its exact source preparation.
    drop(prepared);
    assert!(fixture.engine.apply_lock.try_lock().is_ok());
    assert!(Arc::ptr_eq(&original, &fixture.engine.generation()?));
    drop(original);
    drop(image);
    fixture.close().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn validation_baseline_failed_publish_retires_candidate_before_apply_owner()
-> crate::test_fixture_failure::FixtureResult<()> {
    use kasumi_raft::StateMachineBackend as _;
    let fixture = SourceFixture::new().await?;
    let original = fixture.engine.generation()?;
    let image = kasumi_store::SnapshotImage::capture(
        fixture.stores.application().scratch_disk(),
        64 << 20,
        |writer| snapshot_bundle::write(&original, fixture.stores.application(), writer),
    )?;
    let context = kasumi_raft::SnapshotRestoreContext {
        mode: kasumi_raft::SnapshotRestoreMode::Install,
        backend_sha256: image.sha256().into(),
        meta: kasumi_raft::SnapshotMeta {
            last_log_id: None,
            last_membership: Default::default(),
            snapshot_id: "actual-validation-failed-publish".into(),
        },
    };
    let probe = RestoreProbeScope::start();
    let prepared = fixture
        .engine
        .prepare_restore(&context, &mut image.reader())?;
    assert!(fixture.engine.apply_lock.try_lock().is_err());
    assert!(!prepared.application_writes().is_empty());
    // Revoke the actual store after a successful real preparation. Publication
    // must preserve this access error and retire every unpublished owner while
    // the exact previous generation and apply serialization are still held.
    fixture.stores.application().seal();
    let error = prepared
        .publish()
        .expect_err("sealed store published restore");
    assert_eq!(
        error.to_string(),
        "tenant is sealed: key-access lease unavailable or expired"
    );
    assert_eq!(
        *probe.observations.lock().unwrap(),
        vec![RestoreRetirement {
            candidate_retired: true,
            apply_lock: RestoreLockState::Held,
        }]
    );
    assert!(fixture.engine.apply_lock.try_lock().is_ok());
    assert!(Arc::ptr_eq(&original, &fixture.engine.generation()?));
    drop(probe);
    drop(original);
    drop(image);
    fixture.close().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn validation_baseline_real_ordered_retirement_uses_apply_prior_without_public_escape()
-> crate::test_fixture_failure::FixtureResult<()> {
    use kasumi_raft::{AppliedEntryContext, AppliedInput, StateMachineBackend as _};
    let fixture = SourceFixture::new().await?;
    let before = fixture.engine.generation()?;
    let digest = crate::retirement_closure::digest(&before.state, || Ok(()))?;
    let command = Command {
        context: context(&before.state.tenant),
        timestamp_ms: 11,
        operation: Operation::RetireSource(PreparedRetirement {
            // Explicit deterministic rejected-input fixture: this is not a
            // verified backup graph or an authentic successful retirement.
            request: RetireSourceRequest {
                retirement_id: "expired-ordered-baseline".into(),
                expected_source_incarnation: before.state.incarnation.clone(),
                target_incarnation: uuid::Uuid::from_u128(0x766).to_string(),
                checkpoint: FullBackupCheckpoint {
                    tenant: before.state.tenant.clone(),
                    source_incarnation: before.state.incarnation.clone(),
                    revision: 0,
                    resident_sha256: "11".repeat(32),
                    backup_id: uuid::Uuid::from_u128(0x767),
                    manifest_ciphertext_sha256: "22".repeat(32),
                    key_lineage_digest: "33".repeat(32),
                },
                destination: "fixture-backup".into(),
                not_after_ms: 10,
            },
            verified_closure_digest: digest.clone(),
            observation: Some(RetirementObservation {
                revision: 0,
                closure_digest: digest,
            }),
        }),
    };
    let original_source = fixture.engine.retirement_replay_state(&command)?;
    let seed = kasumi_raft::RetirementLogSeed::prepare(&command, original_source)?;
    let bytes = serde_json::to_vec(&command)?;
    let position = AppliedEntryContext {
        log_id: openraft::LogId::new(openraft::CommittedLeaderId::new(1, 1), 1),
        previous: None,
        membership: Default::default(),
        command_sha256: hex::encode(Sha256::digest(&bytes)),
        retirement_seed: Some(seed),
    };
    let (response, calls) = public_probe(true, || {
        kasumi_raft::with_application_publisher_bound_for_test(
            &fixture.buffers,
            &fixture.stores,
            &position,
            |publisher| {
                fixture.engine.apply_with_publisher(
                    &position,
                    AppliedInput::Command(&bytes),
                    publisher,
                )
            },
        )
    });
    let response = response?;
    assert_eq!(
        calls, 0,
        "committed retirement repeated public acquisition under its actual apply guard"
    );
    assert!(response.retirement.is_none());
    let outcome: Result<WriteReceipt> = serde_json::from_slice(&response.data)?;
    let error = outcome.expect_err("expired fixture retirement succeeded");
    assert_eq!(error.code, ErrorCode::Conflict);
    assert_eq!(error.message, "retirement action deadline expired");
    let after = fixture.engine.generation()?;
    assert_eq!(after.state.revision, 1);
    assert!(!after.state.retired);
    assert_eq!(after.state.retirements.len(), 1);
    assert_eq!(before.state.retirements.len(), 0);
    assert!(after.application_selection.get().is_some());
    assert!(fixture.engine.apply_lock.try_lock().is_ok());
    // The actual captured selection is bound to this exact Entry and revision.
    let (_, selected_boundary, selected_revision) = after
        .application_selection
        .get()
        .expect("published selected owner")
        .primary_read_proof(after.state.revision_base)?;
    assert_eq!(selected_revision, after.state.revision);
    assert_eq!(
        selected_boundary,
        crate::primary_tree::records::boundary::producer(
            kasumi_raft::ApplicationBoundaryRef::Entry(&position),
        )
        .expect("actual canonical Entry fingerprint"),
    );
    drop(after);
    drop(before);
    drop(response);
    fixture.close().await
}

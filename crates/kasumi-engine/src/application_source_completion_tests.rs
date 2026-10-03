//! Actual encrypted ordinary commands and the installed completion owner.
//! This is a child of application_sources::tests; it reuses that fixture's
//! registered NodeStore, exact MemoryCore and paired source/startup binding.
use super::*;
use kasumi_raft::{AppliedEntryContext, AppliedInput, AppliedResponse, StateMachineBackend as _};
use kasumi_types::{
    CollectionDefinition, CollectionRetentionClass, CollectionWriteMode, Command, ErrorCode,
    Mutation, MutationBatch, Operation, Precondition, RequestAuthorization, RequestContext,
    WriteReceipt,
};
use serde_json::json;
use sha2::{Digest, Sha256};

struct OrdinaryFixture {
    fixture: Fixture,
    engine: Arc<TenantEngine>,
}
struct Input {
    bytes: Vec<u8>,
    position: AppliedEntryContext,
}
impl OrdinaryFixture {
    async fn new() -> Result<Self> {
        let fixture = Fixture::new().await?;
        crate::test_utils::install_fixture_audit_placement(fixture.stores.application())?;
        let engine = Arc::new(TenantEngine::from_bootstrap(
            "selected-sources",
            &fixture.image,
        )?);
        engine.install_storage_access(fixture.stores.application())?;
        engine.install_application_sources(fixture.roots.clone(), &fixture.image)?;
        Ok(Self { fixture, engine })
    }
    fn input(&self, operation: Operation) -> Result<Input> {
        let current = self.engine.generation()?;
        let revision = current
            .state
            .revision
            .checked_add(1)
            .context("revision overflow")?;
        let index = revision
            .checked_sub(current.state.revision_base)
            .context("revision base")?;
        let command = Command {
            context: RequestContext {
                authorization: RequestAuthorization::service_identity(),
                principal: "owner".into(),
                tenant: "selected-sources".into(),
                scopes: [Action::Read, Action::Write, Action::Admin]
                    .into_iter()
                    .collect(),
                request_id: format!("source-completion-{revision}"),
            },
            timestamp_ms: revision,
            operation,
        };
        let bytes = serde_json::to_vec(&command)?;
        let log = |index| openraft::LogId::new(openraft::CommittedLeaderId::new(1, 1), index);
        Ok(Input {
            position: AppliedEntryContext {
                log_id: log(index),
                previous: (index > 1).then(|| log(index - 1)),
                membership: Default::default(),
                command_sha256: hex::encode(Sha256::digest(&bytes)),
                retirement_seed: None,
            },
            bytes,
        })
    }
    fn apply(&self, input: &Input, after_backend: impl FnOnce()) -> Result<AppliedResponse> {
        kasumi_raft::with_application_publisher_bound_observed_for_test(
            &self.fixture._buffers,
            &self.fixture.stores,
            &input.position,
            |publisher| {
                self.engine.apply_with_publisher(
                    &input.position,
                    AppliedInput::Command(&input.bytes),
                    publisher,
                )
            },
            after_backend,
        )
    }
    async fn close(self) -> Result<()> {
        self.engine.seal();
        drop(self.engine);
        self.fixture.close().await
    }
}
fn definition() -> CollectionDefinition {
    CollectionDefinition {
        name: "docs".into(),
        schema: json!({"type":"object"}),
        indexes: vec![],
        strict_read_audit: false,
        retention_class: CollectionRetentionClass::Operational,
        write_mode: CollectionWriteMode::Mutable,
    }
}
fn put(key: &str, body: serde_json::Value, expected: Precondition) -> Operation {
    Operation::Mutate(MutationBatch {
        idempotency_key: key.into(),
        read_set: vec![],
        operations: vec![Mutation::Put {
            collection: "docs".into(),
            id: "row".into(),
            body,
            expected,
        }],
    })
}
fn selected(fixture: &OrdinaryFixture, input: &Input, expected_handles: usize) -> CellRef {
    let generation = fixture.engine.generation().unwrap();
    let selected = generation
        .application_selection
        .get()
        .expect("actual selected generation");
    let cell = selected.cell.clone();
    assert_eq!(cell.handles.load(Ordering::Acquire), expected_handles);
    assert!(!cell.state.lock().unwrap().closed);
    assert!(matches!(
        cell.position.get().expect("selected source proof").applied(),
        Some(kasumi_raft::SelectedAppliedRef::Entry { log_id, .. }) if log_id == input.position.log_id
    ));
    cell
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ordinary_completion_is_last_selected_owner_through_real_outer_finish() -> Result<()> {
    let fixture = OrdinaryFixture::new().await?;
    let input = fixture.input(Operation::SetPolicy(policy()))?;
    let mut witness = None;
    let response = fixture.apply(&input, || {
        // The backend's actual apply guard ended on this same thread. Its new
        // Generation and the completion each own one selected handle here.
        assert!(fixture.engine.application_guard_available_for_test());
        let cell = selected(&fixture, &input, 2);
        // Remove the actual visible Generation before outer finish. The CellRef
        // witness below is metadata only and cannot keep a selected/native pin.
        fixture.engine.seal();
        assert_eq!(cell.handles.load(Ordering::Acquire), 1);
        assert!(!cell.state.lock().unwrap().closed);
        assert!(cell.state.lock().unwrap().view.is_some());
        witness = Some(cell);
    })?;
    let outcome: kasumi_types::Result<WriteReceipt> = serde_json::from_slice(&response.data)?;
    assert!(outcome.is_ok());
    let witness = witness.expect("real post-backend observation");
    assert_eq!(witness.handles.load(Ordering::Acquire), 0);
    assert!(witness.state.lock().unwrap().closed);
    assert!(witness.state.lock().unwrap().view.is_none());
    assert!(
        !fixture
            .fixture
            .roots
            .gate
            .lock()
            .unwrap()
            .cells
            .contains_key(&witness.id)
    );
    assert!(witness.position.get().is_some());
    let settled = fixture.fixture.roots.completion_snapshot_for_test();
    assert_eq!(settled.phase, super::super::completion::Phase::Settled);
    assert!(settled.preparation_cell.is_none() && settled.queued_reader.is_none());
    assert!(settled.selected_cell.is_none() && settled.retirement_witness.is_none());
    drop(witness);
    drop(response);
    drop(input);
    fixture.close().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ordinary_completion_reuses_only_after_real_accept_reject_and_idempotent_finish()
-> Result<()> {
    let fixture = OrdinaryFixture::new().await?;
    let create = fixture.input(Operation::CreateCollection(definition()))?;
    fixture.apply(&create, || {
        selected(&fixture, &create, 2);
    })?;
    assert_eq!(
        selected(&fixture, &create, 1)
            .handles
            .load(Ordering::Acquire),
        1
    );
    let accepted = fixture.input(put(
        "completion-put",
        json!({"accepted":true}),
        Precondition::Any,
    ))?;
    let response = fixture.apply(&accepted, || {
        selected(&fixture, &accepted, 2);
    })?;
    let receipt: kasumi_types::Result<WriteReceipt> = serde_json::from_slice(&response.data)?;
    let receipt = receipt?;
    let old = fixture.engine.generation()?;
    let rejected = fixture.input(put(
        "completion-reject",
        json!({"rejected":true}),
        Precondition::Version(0),
    ))?;
    let response = fixture.apply(&rejected, || {
        selected(&fixture, &rejected, 2);
    })?;
    let outcome: kasumi_types::Result<WriteReceipt> = serde_json::from_slice(&response.data)?;
    assert_eq!(outcome.unwrap_err().code, ErrorCode::Conflict);
    let after_rejection = fixture.engine.generation()?;
    assert_eq!(
        after_rejection.state.collections["docs"].documents["row"].version,
        receipt.revision
    );
    assert!(Arc::ptr_eq(&old.indexes, &after_rejection.indexes));
    let replay = fixture.input(put(
        "completion-put",
        json!({"accepted":true}),
        Precondition::Any,
    ))?;
    let response = fixture.apply(&replay, || {
        selected(&fixture, &replay, 2);
    })?;
    let outcome: kasumi_types::Result<WriteReceipt> = serde_json::from_slice(&response.data)?;
    assert_eq!(outcome?.revision, receipt.revision);
    let current = fixture.engine.generation()?;
    assert_eq!(
        current.state.collections["docs"].documents["row"].body,
        json!({"accepted":true})
    );
    assert_eq!(
        selected(&fixture, &replay, 1)
            .handles
            .load(Ordering::Acquire),
        1
    );
    drop(current);
    drop(after_rejection);
    drop(old);
    drop(response);
    drop(replay);
    drop(rejected);
    drop(accepted);
    drop(create);
    fixture.close().await
}

#[derive(Debug)]
struct FinishPanic;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ordinary_completion_outer_finish_panic_retains_original_response_after_facade_seal()
-> Result<()> {
    let fixture = OrdinaryFixture::new().await?;
    let input = fixture.input(Operation::SetPolicy(policy()))?;
    let original = Arc::new(FinishPanic);
    let mut witness = None;
    let failure = match fixture.apply(&input, || {
        let cell = selected(&fixture, &input, 2);
        fixture.engine.seal();
        assert_eq!(cell.handles.load(Ordering::Acquire), 1);
        assert!(!cell.state.lock().unwrap().closed);
        witness = Some(cell);
        std::panic::panic_any(original.clone());
    }) {
        Err(error) => error,
        Ok(_) => panic!("real after-backend unwind acknowledged"),
    };
    let witness = witness.expect("actual selected source reached outer finish");
    let inspect = || {
        fixture
            .fixture
            ._buffers
            .try_with_retained_apply_report(|report| {
                let kasumi_raft::RetainedApplyReport::Ordinary(report) = report else {
                    panic!("ordinary failure reduced to a single-error diagnostic")
                };
                assert!(matches!(
                    report.sink,
                    kasumi_raft::ApplyObservationRef::Returned
                ));
                assert!(matches!(
                    report.action,
                    kasumi_raft::ApplyObservationRef::Returned
                ));
                assert!(matches!(
                    report.backend,
                    kasumi_raft::ApplyObservationRef::Returned
                ));
                let kasumi_raft::ApplyObservationRef::Unwound(payload) = report.finish else {
                    panic!("actual finish unwind original absent")
                };
                assert!(Arc::ptr_eq(
                    payload.downcast_ref::<Arc<FinishPanic>>().unwrap(),
                    &original
                ));
                let response = report
                    .response
                    .expect("response must survive failed outer finish");
                let outcome: kasumi_types::Result<WriteReceipt> =
                    serde_json::from_slice(&response.data).unwrap();
                assert!(outcome.is_ok());
                (
                    report.ordinal,
                    payload as *const (dyn std::any::Any + Send) as *const () as usize,
                )
            })
            .expect("terminal report inspection busy")
            .expect("retained failure absent")
    };
    let first = inspect();
    assert_eq!(inspect(), first);
    assert!(witness.position.get().is_some());
    drop(failure);
    assert_eq!(inspect(), first);
    drop(witness);
    drop(input);
    drop(original);
    // Terminal originals have no acknowledgment/disposal protocol in this cut.
    // Keep the real TempDir with its enrolled native/census custody; this does
    // not assert clean shutdown or reset the failed completion for another apply.
    std::mem::forget(fixture);
    Ok(())
}

// Preconstructed, bounded fixture gate; it pauses a real checkpoint and then
// returns its original failure. It cannot certify success or create a source.
pub(crate) struct CompletionPause {
    entered:
        Mutex<Option<tokio::sync::oneshot::Sender<super::super::completion::CompletionSnapshot>>>,
    release: Mutex<std::sync::mpsc::Receiver<()>>,
    original: Mutex<Option<anyhow::Error>>,
}
struct ReleasePause(Option<std::sync::mpsc::SyncSender<()>>);
impl Drop for ReleasePause {
    fn drop(&mut self) {
        if let Some(release) = self.0.take() {
            let _ = release.try_send(());
        }
    }
}
impl CompletionPause {
    fn new(
        original: anyhow::Error,
    ) -> (
        Arc<Self>,
        tokio::sync::oneshot::Receiver<super::super::completion::CompletionSnapshot>,
        ReleasePause,
    ) {
        let (entered, observed) = tokio::sync::oneshot::channel();
        let (release, blocked) = std::sync::mpsc::sync_channel(1);
        (
            Arc::new(Self {
                entered: Mutex::new(Some(entered)),
                release: Mutex::new(blocked),
                original: Mutex::new(Some(original)),
            }),
            observed,
            ReleasePause(Some(release)),
        )
    }
    pub(crate) fn wait(
        &self,
        snapshot: super::super::completion::CompletionSnapshot,
    ) -> Result<()> {
        let entered = self
            .entered
            .lock()
            .unwrap()
            .take()
            .expect("checkpoint entered once");
        let _ = entered.send(snapshot);
        self.release
            .lock()
            .unwrap()
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("fixture did not release actual completion checkpoint");
        Err(self
            .original
            .lock()
            .unwrap()
            .take()
            .expect("actual checkpoint original"))
    }
}
#[derive(Debug)]
struct CheckpointOriginal(Arc<()>);
impl std::fmt::Display for CheckpointOriginal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("actual completion checkpoint failure")
    }
}
impl std::error::Error for CheckpointOriginal {}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ordinary_completion_cancelled_real_group_waiter_keeps_queued_source_and_original()
-> Result<()> {
    use super::super::completion::{CompletionCheckpoint, CompletionFault};
    let fixture = OrdinaryFixture::new().await?;
    let group = Arc::new(
        kasumi_raft::RaftGroup::local(
            1,
            format!(
                "selected-sources/{}",
                fixture.engine.generation()?.state.incarnation
            ),
            fixture.fixture.stores.clone(),
            fixture.engine.clone(),
            fixture.fixture._buffers.clone(),
        )
        .await?,
    );
    let input = fixture.input(Operation::SetPolicy(policy()))?;
    let original = Arc::new(());
    let (gate, reached, release) =
        CompletionPause::new(CheckpointOriginal(original.clone()).into());
    fixture.fixture.roots.arm_completion_fault_for_test(
        CompletionCheckpoint::Queued,
        CompletionFault::Pause(gate.clone()),
    );
    let writing = group.clone();
    let waiter = tokio::spawn(async move { writing.write(input.bytes).await });
    let reached = tokio::time::timeout(std::time::Duration::from_secs(10), reached).await??;
    assert!(reached.queued_reader.is_some());
    assert!(reached.selected_cell.is_none());
    let cell_id = reached
        .preparation_cell
        .expect("actual preowned preparation");
    let cell = fixture
        .fixture
        .roots
        .gate
        .lock()
        .unwrap()
        .cells
        .get(&cell_id)
        .expect("enrolled source")
        .clone();
    assert!(cell.state.lock().unwrap().preparing);
    assert!(!cell.state.lock().unwrap().closed);
    waiter.abort();
    assert!(waiter.await.unwrap_err().is_cancelled());
    drop(group);
    let OrdinaryFixture { fixture, engine } = fixture;
    let observed_engine = Arc::downgrade(&engine);
    drop(engine);
    // The public Raft facade and its write waiter are gone while the real
    // blocking apply still owns its Engine guard and actual queued request.
    // The test's inspection alias is not claimed as a selected source owner.
    drop(release);
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let report = fixture._buffers.try_with_retained_apply_report(|report| {
                let kasumi_raft::RetainedApplyReport::Ordinary(report) = report else {
                    return false;
                };
                if !matches!(report.backend, kasumi_raft::ApplyObservationRef::Returned)
                    || !matches!(report.finish, kasumi_raft::ApplyObservationRef::Returned)
                    || !matches!(
                        report.cleanup,
                        kasumi_raft::ApplyObservationRef::Refused(
                            kasumi_raft::CompletionSettleError::Retained
                        )
                    )
                {
                    return false;
                }
                let kasumi_raft::ApplyObservationRef::Error(error) = report.sink else {
                    return false;
                };
                error
                    .downcast_ref::<CheckpointOriginal>()
                    .is_some_and(|error| Arc::ptr_eq(&error.0, &original))
            });
            if matches!(report, Ok(Some(true))) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await?;
    // This is after the actual backend and outer finish have both returned.
    // It cannot be satisfied by the former stack-only preparation lifetime.
    let held = fixture.roots.completion_snapshot_for_test();
    assert_eq!(held.ordinal, reached.ordinal);
    assert_eq!(held.preparation_cell, Some(cell_id));
    assert_eq!(held.queued_reader, reached.queued_reader);
    assert!(held.selected_cell.is_none());
    assert_eq!(held.phase, super::super::completion::Phase::Retained);
    {
        let state = cell.state.lock().unwrap();
        assert!(state.preparing);
        assert!(!state.closed && state.view.is_none());
    }
    if let Some(engine) = observed_engine.upgrade() {
        assert!(engine.application_guard_available_for_test());
        engine.seal();
    }
    assert!(
        fixture
            ._buffers
            .try_with_retained_apply_report(|report| {
                let kasumi_raft::RetainedApplyReport::Ordinary(report) = report else {
                    panic!("lost ordinary report")
                };
                let kasumi_raft::ApplyObservationRef::Error(error) = report.sink else {
                    panic!("lost queued original")
                };
                assert!(Arc::ptr_eq(
                    &error.downcast_ref::<CheckpointOriginal>().unwrap().0,
                    &original
                ));
                report.response.is_some()
            })
            .unwrap()
            .unwrap()
    );
    let retained = fixture
        .storage
        .admission
        .drain_snapshot_startups()
        .await
        .expect_err("failed delivered group disappeared from installed census");
    assert_eq!(retained.completion(), DrainCompletion::Retained);
    drop(retained);
    drop(gate);
    drop(cell);
    drop(original);
    // Delivered runtime/native disposition is intentionally retained; no claim
    // of positive group shutdown is made after dropping its public facade.
    std::mem::forget(fixture);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ordinary_completion_bound_frozen_branch_keeps_source_without_new_preparation() -> Result<()>
{
    let fixture = OrdinaryFixture::new().await?;
    // Explicit branch fixture only. This sets the retired flag but preserves
    // the actual captured source; it is not an authenticated retirement proof.
    let (old, frozen) = fixture.engine.freeze_current_for_completion_test()?;
    let cell = frozen
        .application_selection
        .get()
        .expect("real selected bootstrap")
        .cell
        .clone();
    let before = fixture.fixture.roots.completion_snapshot_for_test();
    let next_source = fixture.fixture.roots.gate.lock().unwrap().next;
    let input = fixture.input(Operation::SetPolicy(policy()))?;
    let observed_commits = std::cell::Cell::new(0usize);
    let response = kasumi_raft::with_application_publisher_bound_observed_for_test(
        &fixture.fixture._buffers,
        &fixture.fixture.stores,
        &input.position,
        |publisher| {
            let mut observed = GuardObservedPublisher {
                actual: publisher,
                engine: &fixture.engine,
                commits: &observed_commits,
                thread: std::thread::current().id(),
            };
            fixture.engine.apply_with_publisher(
                &input.position,
                AppliedInput::Command(&input.bytes),
                &mut observed,
            )
        },
        || {
            assert!(fixture.engine.application_guard_available_for_test());
            assert!(Arc::ptr_eq(&frozen, &fixture.engine.generation().unwrap()));
            let completion = fixture.fixture.roots.completion_snapshot_for_test();
            assert!(completion.ordinal > before.ordinal);
            assert!(completion.preparation_cell.is_none());
            assert!(completion.queued_reader.is_none());
            assert!(completion.selected_cell.is_none());
            assert_eq!(fixture.fixture.roots.gate.lock().unwrap().next, next_source);
            assert_eq!(cell.handles.load(Ordering::Acquire), 2);
            assert!(!cell.state.lock().unwrap().closed);
        },
    )?;
    assert_eq!(observed_commits.get(), 1);
    let outcome: kasumi_types::Result<WriteReceipt> = serde_json::from_slice(&response.data)?;
    assert_eq!(outcome.unwrap_err().code, ErrorCode::Sealed);
    assert!(response.retirement.is_none());
    assert!(Arc::ptr_eq(&frozen, &fixture.engine.generation()?));
    let after = fixture.fixture.roots.completion_snapshot_for_test();
    assert!(after.preparation_cell.is_none() && after.selected_cell.is_none());
    assert_eq!(fixture.fixture.roots.gate.lock().unwrap().next, next_source);
    assert!(CellRef::ptr_eq(
        &cell,
        &fixture
            .engine
            .generation()?
            .application_selection
            .get()
            .unwrap()
            .cell
    ));
    drop(response);
    drop(input);
    drop(cell);
    drop(frozen);
    drop(old);
    fixture.close().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ordinary_completion_fault_checkpoints_preserve_exact_original_and_source_phase()
-> Result<()> {
    use super::super::completion::{CompletionCheckpoint as C, CompletionFault, Phase};
    for point in [
        C::BeforeQueue,
        C::Queued,
        C::Published,
        C::Captured,
        C::Installed,
        C::Visible,
    ] {
        for unwind in [false, true] {
            // Panics cover both original custodians without duplicating every
            // phase's encrypted fixture: pre-sink preparer and post-capture action.
            if unwind && !matches!(point, C::Queued | C::Captured) {
                continue;
            }
            let fixture = OrdinaryFixture::new().await?;
            let previous = fixture.engine.generation()?;
            let input = fixture.input(Operation::SetPolicy(policy()))?;
            let original = Arc::new(());
            let fault = if unwind {
                CompletionFault::Panic(Box::new(CheckpointOriginal(original.clone())))
            } else {
                CompletionFault::Error(CheckpointOriginal(original.clone()).into())
            };
            fixture
                .fixture
                .roots
                .arm_completion_fault_for_test(point, fault);
            let (namespace, key, limit) = kasumi_raft::primary_applied_cursor_read_spec_for_test();
            let before_cursor = fixture
                .fixture
                .stores
                .custody()
                .store()
                .get_bounded(namespace, key, limit)?;
            let failure = match fixture.apply(&input, || {
                if !unwind || point == C::Queued {
                    assert!(fixture.engine.application_guard_available_for_test());
                }
                let held = fixture.fixture.roots.completion_snapshot_for_test();
                assert!(held.preparation_cell.is_some(), "{point:?}");
                assert_eq!(
                    held.queued_reader.is_some(),
                    matches!(point, C::Queued | C::Published),
                    "{point:?}"
                );
                assert_eq!(
                    held.selected_cell.is_some(),
                    matches!(point, C::Captured | C::Installed | C::Visible),
                    "{point:?}"
                );
            }) {
                Err(error) => error,
                Ok(_) => panic!("faulted actual ordinary invocation acknowledged"),
            };
            let inspect = || {
                fixture
                    .fixture
                    ._buffers
                    .try_with_retained_apply_report(|report| {
                        let kasumi_raft::RetainedApplyReport::Ordinary(report) = report else {
                            panic!("lost ordinary report")
                        };
                        assert!(report.response.is_some());
                        assert!(matches!(
                            report.backend,
                            kasumi_raft::ApplyObservationRef::Returned
                        ));
                        assert!(matches!(
                            report.finish,
                            kasumi_raft::ApplyObservationRef::Returned
                        ));
                        assert!(matches!(
                            report.cleanup,
                            kasumi_raft::ApplyObservationRef::Refused(
                                kasumi_raft::CompletionSettleError::Retained
                            )
                        ));
                        let observation = if matches!(point, C::BeforeQueue | C::Queued) {
                            assert!(matches!(
                                report.action,
                                kasumi_raft::ApplyObservationRef::Returned
                            ));
                            report.sink
                        } else {
                            assert!(matches!(
                                report.sink,
                                kasumi_raft::ApplyObservationRef::Returned
                            ));
                            report.action
                        };
                        let address = match observation {
                            kasumi_raft::ApplyObservationRef::Error(error) if !unwind => {
                                let saved = error.downcast_ref::<CheckpointOriginal>().unwrap();
                                assert!(Arc::ptr_eq(&saved.0, &original));
                                saved as *const CheckpointOriginal as usize
                            }
                            kasumi_raft::ApplyObservationRef::Unwound(payload) if unwind => {
                                let saved = payload.downcast_ref::<CheckpointOriginal>().unwrap();
                                assert!(Arc::ptr_eq(&saved.0, &original));
                                saved as *const CheckpointOriginal as usize
                            }
                            _ => panic!("wrong original phase at {point:?}, unwind={unwind}"),
                        };
                        (report.ordinal, address)
                    })
                    .unwrap()
                    .unwrap()
            };
            let original_address = inspect();
            drop(failure);
            assert_eq!(inspect(), original_address);
            let next_source = fixture.fixture.roots.gate.lock().unwrap().next;
            let refused =
                match fixture.apply(&input, || panic!("failed owner reentered backend finish")) {
                    Err(error) => error,
                    Ok(_) => panic!("terminal ordinary owner reset"),
                };
            assert_eq!(fixture.fixture.roots.gate.lock().unwrap().next, next_source);
            assert_eq!(inspect(), original_address);
            drop(refused);
            let held = fixture.fixture.roots.completion_snapshot_for_test();
            if !unwind {
                assert_eq!(held.phase, Phase::Retained);
            }
            let cell = fixture
                .fixture
                .roots
                .gate
                .lock()
                .unwrap()
                .cells
                .get(&held.preparation_cell.unwrap())
                .unwrap()
                .clone();
            {
                let state = cell.state.lock().unwrap();
                let captured = matches!(point, C::Captured | C::Installed | C::Visible);
                assert_eq!(state.preparing, !captured);
                assert_eq!(state.view.is_some(), captured);
                assert!(!state.closed);
                assert_eq!(
                    cell.handles.load(Ordering::Acquire),
                    if captured {
                        if point == C::Visible { 2 } else { 1 }
                    } else {
                        0
                    }
                );
            }
            let after_cursor = fixture
                .fixture
                .stores
                .custody()
                .store()
                .get_bounded(namespace, key, limit)?;
            let committed = !matches!(point, C::BeforeQueue | C::Queued);
            assert_eq!(
                after_cursor != before_cursor,
                committed,
                "actual cursor at {point:?}"
            );
            let current = fixture.engine.generation()?;
            assert_eq!(Arc::ptr_eq(&previous, &current), point != C::Visible);
            drop(current);
            drop(previous);
            drop(cell);
            drop(before_cursor);
            drop(after_cursor);
            drop(input);
            drop(original);
            // Terminal originals are intentionally retained; no acknowledgment
            // or clean teardown is claimed by this failure-only fixture.
            std::mem::forget(fixture);
        }
    }
    Ok(())
}

#[derive(Default)]
struct CompletionWake(AtomicUsize);
impl std::task::Wake for CompletionWake {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::AcqRel);
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::AcqRel);
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ordinary_completion_drain_registers_before_busy_and_wakes_after_real_guard_release()
-> Result<()> {
    use kasumi_raft::CompletionCustody;
    let fixture = Fixture::new().await?;
    let owner = fixture.roots.completion()?.clone();
    let wake = Arc::new(CompletionWake::default());
    let waker = Waker::from(wake.clone());
    let mut cx = Context::from_waker(&waker);
    fixture.roots.with_completion_state_held_for_test(|| {
        assert!(owner.poll_drain(&mut cx).is_pending());
        assert!(!owner.is_drained());
        assert_eq!(wake.0.load(Ordering::Acquire), 0);
    });
    assert_eq!(wake.0.load(Ordering::Acquire), 1);
    assert!(matches!(owner.poll_drain(&mut cx), Poll::Ready(Ok(()))));
    assert!(owner.is_drained());
    drop(owner);
    drop(waker);
    drop(wake);
    fixture.close().await
}

// Pure observation around the actual publisher/action. Both layers forward
// the same invocation and challenge, and every result comes from the real sink.
struct GuardObservedPublisher<'a> {
    actual: &'a mut dyn kasumi_raft::ApplyPublisher,
    engine: &'a TenantEngine,
    commits: &'a std::cell::Cell<usize>,
    thread: std::thread::ThreadId,
}
struct GuardObservedAction<'a> {
    actual: &'a mut dyn kasumi_raft::CompletionAction,
    engine: &'a TenantEngine,
    commits: &'a std::cell::Cell<usize>,
    thread: std::thread::ThreadId,
}
impl kasumi_raft::CompletionAction for GuardObservedAction<'_> {
    fn run(
        &mut self,
        invocation: &kasumi_raft::CompletionInvocation<'_>,
        publisher: &mut dyn kasumi_raft::ApplyPublisher,
    ) -> Result<()> {
        assert_eq!(std::thread::current().id(), self.thread);
        self.actual.run(
            invocation,
            &mut GuardObservedPublisher {
                actual: publisher,
                engine: self.engine,
                commits: self.commits,
                thread: self.thread,
            },
        )
    }
}
impl kasumi_raft::ApplyPublisher for GuardObservedPublisher<'_> {
    fn with_completion(
        &mut self,
        expected: &kasumi_raft::CompletionIdentity,
        action: &mut dyn kasumi_raft::CompletionAction,
    ) -> std::result::Result<(), kasumi_raft::CompletionCallError> {
        self.actual.with_completion(
            expected,
            &mut GuardObservedAction {
                actual: action,
                engine: self.engine,
                commits: self.commits,
                thread: self.thread,
            },
        )
    }
    fn commit(
        &mut self,
        response: AppliedResponse,
        writes: &[kasumi_store::WriteOp],
    ) -> std::result::Result<(), kasumi_raft::PublishCallError> {
        assert_eq!(std::thread::current().id(), self.thread);
        assert!(!self.engine.application_guard_available_for_test());
        self.commits.set(self.commits.get() + 1);
        self.actual.commit(response, writes)
    }
    fn commit_with_selection<'call>(
        &mut self,
        response: AppliedResponse,
        writes: &[kasumi_store::WriteOp],
        preparer: &mut dyn kasumi_raft::SelectionPreparer,
        challenge: kasumi_raft::PublicationChallenge<'call>,
    ) -> std::result::Result<
        kasumi_raft::JointPublicationReceipt<'call>,
        kasumi_raft::PublishCallError,
    > {
        self.actual
            .commit_with_selection(response, writes, preparer, challenge)
    }
}

#[derive(Debug)]
struct CaptureWakeOriginal;
struct CaptureWake {
    roots: SourceRootsRef,
    cell: Mutex<Option<CellRef>>,
    original: Arc<CaptureWakeOriginal>,
    completion_wake: Option<Arc<CompletionUnwindWake>>,
}
impl std::task::Wake for CaptureWake {
    fn wake(self: Arc<Self>) {
        let cell = self.roots.gate.lock().unwrap().latest.upgrade().unwrap();
        assert_eq!(cell.handles.load(Ordering::Acquire), 1);
        assert!(!cell.state.lock().unwrap().preparing);
        assert!(self.cell.lock().unwrap().replace(cell).is_none());
        if let Some(wake) = &self.completion_wake {
            use kasumi_raft::CompletionCustody;
            let waker = Waker::from(wake.clone());
            assert!(
                self.roots
                    .completion()
                    .unwrap()
                    .poll_drain(&mut Context::from_waker(&waker))
                    .is_pending()
            );
        }
        std::panic::panic_any(self.original.clone());
    }
}
#[derive(Debug)]
struct CompletionWakeOriginal;
struct CompletionUnwindWake {
    original: Arc<CompletionWakeOriginal>,
    calls: AtomicUsize,
}
impl std::task::Wake for CompletionUnwindWake {
    fn wake(self: Arc<Self>) {
        self.calls.fetch_add(1, Ordering::AcqRel);
        std::panic::panic_any(self.original.clone());
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ordinary_completion_capture_wake_unwind_retires_the_actual_counted_handle() -> Result<()> {
    for unwind_completion_wake in [false, true] {
        let fixture = OrdinaryFixture::new().await?;
        let input = fixture.input(Operation::SetPolicy(policy()))?;
        let original = Arc::new(CaptureWakeOriginal);
        let second_original = Arc::new(CompletionWakeOriginal);
        let completion_wake = Arc::new(CompletionUnwindWake {
            original: second_original.clone(),
            calls: AtomicUsize::new(0),
        });
        let wake = Arc::new(CaptureWake {
            roots: fixture.fixture.roots.clone(),
            cell: Mutex::new(None),
            original: original.clone(),
            completion_wake: unwind_completion_wake.then(|| completion_wake.clone()),
        });
        // Fixture-only enrollment in the actual source waiter slot. Calling public
        // poll_drain here would seal preparation before the capture under test.
        // The callback cannot fabricate a selected owner or publication outcome.
        assert!(
            fixture
                .fixture
                .roots
                .gate
                .lock()
                .unwrap()
                .waiter
                .replace(Waker::from(wake.clone()))
                .is_none()
        );
        let failure = match fixture.apply(&input, || {}) {
            Err(error) => error,
            Ok(_) => panic!("real capture wake panic acknowledged"),
        };
        let cell = wake
            .cell
            .lock()
            .unwrap()
            .take()
            .expect("actual finish_capture wake");
        assert_eq!(
            cell.handles.load(Ordering::Acquire),
            0,
            "unwinding must drop a real SelectedApplication"
        );
        {
            let state = cell.state.lock().unwrap();
            assert!(!state.preparing && !state.closing);
            assert!(state.closed && state.view.is_none());
        }
        assert!(
            !fixture
                .fixture
                .roots
                .gate
                .lock()
                .unwrap()
                .cells
                .contains_key(&cell.id)
        );
        let held = fixture.fixture.roots.completion_snapshot_for_test();
        assert_eq!(held.preparation_cell, Some(cell.id));
        assert!(held.selected_cell.is_none());
        let inspect = || {
            fixture
                .fixture
                ._buffers
                .try_with_retained_apply_report(|report| {
                    let kasumi_raft::RetainedApplyReport::Ordinary(report) = report else {
                        panic!("lost capture unwind report")
                    };
                    assert!(matches!(
                        report.sink,
                        kasumi_raft::ApplyObservationRef::Returned
                    ));
                    assert!(matches!(
                        report.backend,
                        kasumi_raft::ApplyObservationRef::Returned
                    ));
                    assert!(matches!(
                        report.finish,
                        kasumi_raft::ApplyObservationRef::Returned
                    ));
                    let kasumi_raft::ApplyObservationRef::Unwound(payload) = report.action else {
                        panic!("lost actual wake payload")
                    };
                    let saved = payload.downcast_ref::<Arc<CaptureWakeOriginal>>().unwrap();
                    assert!(Arc::ptr_eq(saved, &original));
                    (
                        report.ordinal,
                        saved as *const Arc<CaptureWakeOriginal> as usize,
                    )
                })
                .unwrap()
                .unwrap()
        };
        let address = inspect();
        drop(failure);
        assert_eq!(inspect(), address);
        fixture
            .fixture
            .roots
            .with_completion_wake_panic_for_test(|saved| {
                if unwind_completion_wake {
                    assert!(Arc::ptr_eq(
                        saved
                            .unwrap()
                            .downcast_ref::<Arc<CompletionWakeOriginal>>()
                            .unwrap(),
                        &second_original
                    ));
                } else {
                    assert!(saved.is_none());
                }
            });
        if unwind_completion_wake {
            use kasumi_raft::CompletionCustody;
            assert_eq!(completion_wake.calls.load(Ordering::Acquire), 1);
            let owner = fixture.fixture.roots.completion()?;
            let retry_waker = Waker::from(completion_wake.clone());
            assert!(matches!(
                owner.poll_drain(&mut Context::from_waker(&retry_waker)),
                Poll::Ready(Err(kasumi_raft::CompletionSettleError::Retained))
            ));
            assert!(!owner.is_drained());
            assert_eq!(completion_wake.calls.load(Ordering::Acquire), 1);
            assert_eq!(inspect(), address);
        }
        drop(cell);
        drop(wake);
        drop(original);
        drop(input);
        std::mem::forget(fixture);
    }
    Ok(())
}

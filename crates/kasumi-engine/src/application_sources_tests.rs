use super::*;
use crate::{TenantEngine, admission::AdmissionConfig};
use kasumi_raft::{ApplicationSourceCustody, SelectionFailure};
use kasumi_store::{SnapshotImage, test_utils::LocalKeyProvider};
use kasumi_types::{Action, Grant, Limits, Policy, drain::DrainCompletion};

fn policy() -> Policy {
    Policy {
        grants: vec![Grant {
            principal: "owner".into(),
            collection: None,
            actions: std::collections::BTreeSet::from([Action::Admin, Action::Read, Action::Write]),
        }],
        strict_read_audit: false,
    }
}

struct Fixture {
    _directory: tempfile::TempDir,
    storage: crate::test_utils::FixtureStorage,
    node: Arc<kasumi_store::NodeStore>,
    stores: Arc<TenantStorageSet>,
    image: SnapshotImage,
    roots: SourceRootsRef,
    _buffers: Arc<kasumi_raft::SnapshotBufferOwner>,
    budget: u64,
}
impl Fixture {
    async fn new() -> Result<Self> {
        Self::with_bootstrap(1, None).await
    }
    async fn with_bootstrap(node_id: u64, bootstrap: Option<&SnapshotImage>) -> Result<Self> {
        let directory = kasumi_store::test_utils::private_tempdir()?;
        let (mut persistent, mut scratch) =
            crate::test_utils::fixture_disk_configs(directory.path())?;
        persistent.native_storage.cache.byte_limit = 0;
        scratch.native_cache_bytes = 0;
        let config = crate::test_utils::isolated_disk_admission_config(
            AdmissionConfig {
                max_inflight_bytes: Some(256 << 20),
                ..Default::default()
            },
            &persistent,
            &scratch,
        )?;
        let budget = config.max_inflight_bytes.unwrap();
        let admission = NodeAdmission::with_fixed_memory(config, 2 << 30, 0)?;
        let storage =
            crate::test_utils::FixtureStorage::with_admission(&persistent, &scratch, admission)?;
        let node = storage.create_new(
            directory.path().join("persistent/node.kv"),
            kasumi_store::test_utils::NODE_STORE_ID,
        )?;
        let stores = TenantStorageSet::initialize_catalogs_fixture(
            node.clone(),
            "selected-sources".into(),
            Arc::new(LocalKeyProvider::new([119; 32])),
            Arc::new(LocalKeyProvider::new([120; 32])),
        )
        .await?;
        let incarnation = uuid::Uuid::from_u128(73).to_string();
        let engine = TenantEngine::new(
            "selected-sources".into(),
            incarnation.clone(),
            policy(),
            Limits::default(),
        )?;
        let image = match bootstrap {
            Some(image) => image.clone(),
            None => engine.logical_snapshot(stores.application().scratch_disk())?,
        };
        crate::bootstrap::persist_fixture_bootstrap(
            &stores,
            &image,
            node_id,
            &format!("selected-sources/{incarnation}"),
        )?;
        let before_fixed = storage.admission.snapshot().reserved_bytes;
        let (roots, binding) = SourceRoots::new(
            stores.clone(),
            storage.admission.clone(),
            RaftLimits::default(),
        )?;
        let buffers = storage.admission.snapshot_buffer_owner()?;
        roots.bind_lifecycle(&buffers, binding)?;
        assert_eq!(
            storage.admission.snapshot().reserved_bytes - before_fixed,
            SourceRoots::required_fixed_admission_bytes()?
                + kasumi_raft::SnapshotBufferOwner::required_bytes(
                    kasumi_raft::SNAPSHOT_BUFFER_SLOTS
                )?
        );
        Ok(Self {
            _directory: directory,
            storage,
            node,
            stores,
            image,
            roots,
            _buffers: buffers,
            budget,
        })
    }
    fn select(&self) -> Result<SelectedApplication> {
        self.roots
            .prepare()?
            .capture(ApplicationBoundaryRef::Bootstrap(&self.image), false)
    }
    async fn close(self) -> Result<()> {
        self._buffers.drain_startup().await?;
        std::future::poll_fn(|cx| self.roots.poll_drain(cx)).await?;
        assert!(self.roots.is_drained());
        self.storage.admission.drain_snapshot_startups().await?;
        self.stores.shutdown().await?;
        self.node.shutdown().await?;
        Ok(())
    }
}
fn drain(roots: &SourceRoots) -> Poll<DrainResult> {
    roots.poll_drain(&mut Context::from_waker(Waker::noop()))
}

#[tokio::test]
async fn selected_sources_last_selected_handle_closes_during_ordinary_operation() -> Result<()> {
    let fixture = Fixture::new().await?;
    let before = fixture.storage.admission.snapshot();
    let selected = fixture.select()?;
    assert!(selected.cell.position.get().is_some());
    assert!(!selected.cell.state.lock().unwrap().closed);
    let alias = selected.clone();
    drop(selected);
    assert_eq!(fixture.roots.gate.lock().unwrap().cells.len(), 1);
    assert!(!alias.cell.state.lock().unwrap().closed);
    let exact = alias.cell.clone();
    drop(alias);
    assert!(exact.state.lock().unwrap().closed);
    assert!(fixture.roots.gate.lock().unwrap().cells.is_empty());
    drop(exact);
    assert_eq!(
        fixture.storage.admission.snapshot().live_reservations,
        before.live_reservations
    );
    fixture.close().await
}

#[tokio::test]
async fn selected_sources_shutdown_closes_native_parent_with_metadata_alias_alive() -> Result<()> {
    let fixture = Fixture::new().await?;
    let selected = fixture.select()?;
    fixture.roots.finish_reconstruction()?;
    assert!(matches!(drain(&fixture.roots), Poll::Ready(Ok(()))));
    assert!(fixture.roots.is_drained());
    assert!(selected.cell.state.lock().unwrap().closed);
    assert!(selected.cell.position.get().is_some());
    assert!(selected.begin_fork().is_err());
    assert!(fixture.roots.finish_reconstruction().is_err());
    drop(selected);
    fixture.close().await
}

#[tokio::test]
async fn selected_sources_fork_seal_closes_registered_child_before_releasing_permit() -> Result<()>
{
    let fixture = Fixture::new().await?;
    let selected = fixture.select()?;
    let (child, permit) = selected.begin_fork()?;
    let child_cell = child.cell.clone();
    fixture.roots.seal_consumers();
    assert!(matches!(drain(&fixture.roots), Poll::Pending));
    assert!(!fixture.roots.is_drained());
    let error = SelectedApplication::settle_fork(child, permit).unwrap_err();
    assert!(error.to_string().contains("sealed during fork"));
    assert!(child_cell.state.lock().unwrap().closed);
    assert!(selected.cell.state.lock().unwrap().closed);
    assert!(matches!(drain(&fixture.roots), Poll::Ready(Ok(()))));
    assert!(fixture.roots.is_drained());
    assert!(fixture.roots.gate.lock().unwrap().cells.is_empty());
    // The returned original remains independently admitted after cell removal.
    assert!(error.downcast_ref::<SourceFailure>().is_some());
    drop(child_cell);
    drop(selected);
    drop(error);
    fixture.close().await
}

#[tokio::test]
async fn selected_sources_failed_consuming_close_never_becomes_success_from_none() -> Result<()> {
    let fixture = Fixture::new().await?;
    let selected = fixture.select()?;
    let cell = selected.cell.clone();
    let uncounted = cell.state.lock().unwrap().view.as_ref().unwrap().clone();
    drop(selected);
    assert!(!cell.state.lock().unwrap().closed);
    assert!(cell.state.lock().unwrap().view.is_some());
    let Poll::Ready(Err(first)) = drain(&fixture.roots) else {
        panic!("shared native view falsely drained")
    };
    assert_eq!(first.completion(), DrainCompletion::Retained);
    let Poll::Ready(Err(second)) = drain(&fixture.roots) else {
        panic!("repeated close falsely drained")
    };
    assert_eq!(second.completion(), DrainCompletion::Retained);
    assert!(kasumi_types::drain::DrainIssueRef::ptr_eq(
        &first.issues()[0],
        &second.issues()[0]
    ));
    assert!(!fixture.roots.is_drained());
    drop(uncounted);
    let Poll::Ready(Err(final_report)) = drain(&fixture.roots) else {
        panic!("close diagnostic lost")
    };
    assert_eq!(final_report.completion(), DrainCompletion::Complete);
    assert!(cell.state.lock().unwrap().closed);
    assert!(fixture.roots.is_drained());
    drop(cell);
    fixture.close().await
}

#[tokio::test]
async fn selected_sources_canonical_failure_closes_parent_preserves_original_and_issue()
-> Result<()> {
    let fixture = Fixture::new().await?;
    let wrong = TenantEngine::new(
        "selected-sources".into(),
        uuid::Uuid::from_u128(74).to_string(),
        policy(),
        Limits::default(),
    )?
    .logical_snapshot(fixture.stores.application().scratch_disk())?;
    let error = fixture
        .roots
        .prepare()?
        .capture(ApplicationBoundaryRef::Bootstrap(&wrong), false)
        .unwrap_err();
    assert!(
        error
            .chain()
            .any(|cause| cause.is::<SelectionFailure<Workspace>>())
    );
    assert!(fixture.roots.finish_reconstruction().is_err());
    assert!(matches!(drain(&fixture.roots), Poll::Ready(Ok(()))));
    assert!(fixture.roots.is_drained());
    assert!(fixture.roots.gate.lock().unwrap().cells.is_empty());
    assert!(
        error
            .chain()
            .any(|cause| cause.is::<SelectionFailure<Workspace>>())
    );
    drop(error);
    fixture.close().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn selected_sources_real_local_startup_publishes_entry_and_drains_surviving_generation()
-> Result<()> {
    let fixture = Fixture::new().await?;
    let audit_store = kasumi_store::TenantStore::initialize_catalog_fixture(
        fixture.node.clone(),
        crate::SECURITY_TENANT.into(),
        Arc::new(LocalKeyProvider::new([121; 32])),
    )
    .await?;
    let audit = crate::SecurityAudit::initialize(
        audit_store,
        Default::default(),
        fixture.storage.admission.clone(),
    )?;
    crate::test_utils::install_fixture_audit_placement(fixture.stores.application())?;
    let engine = Arc::new(TenantEngine::from_bootstrap(
        "selected-sources",
        &fixture.image,
    )?);
    engine.install_storage_access(fixture.stores.application())?;
    let bootstrap = engine.generation()?;
    let database = crate::service::construction::DatabaseConstruction::new(
        fixture.stores.clone(),
        audit.clone(),
    )?
    .start_local(
        engine.clone(),
        &fixture.image,
        1,
        format!("selected-sources/{}", bootstrap.state.incarnation),
    )
    .await?;
    let generation = engine.generation()?;
    assert!(generation.state.revision > bootstrap.state.revision);
    let initial = bootstrap.application_selection.get().unwrap().cell.clone();
    let current = generation.application_selection.get().unwrap().cell.clone();
    assert!(!CellRef::ptr_eq(&initial, &current));
    assert!(matches!(
        current.position.get().unwrap().applied(),
        Some(kasumi_raft::SelectedAppliedRef::Entry { .. })
    ));
    assert!(!current.position.get().unwrap().is_covered_reconstruction());
    assert!(!initial.state.lock().unwrap().closed);
    drop(bootstrap);
    assert!(initial.state.lock().unwrap().closed);
    database.shutdown().await?;
    assert!(current.state.lock().unwrap().closed);
    // Metadata aliases remain readable but have no native parent left to pin.
    assert!(generation.application_selection.get().is_some());
    drop(generation);
    drop(database);
    drop(engine);
    audit.shutdown().await?;
    fixture.close().await
}

#[tokio::test]
async fn selected_sources_prospective_denial_preserves_cursor_generation_and_original_then_retries()
-> Result<()> {
    use kasumi_raft::StateMachineBackend;
    let fixture = Fixture::new().await?;
    crate::test_utils::install_fixture_audit_placement(fixture.stores.application())?;
    let engine = TenantEngine::from_bootstrap("selected-sources", &fixture.image)?;
    engine.install_storage_access(fixture.stores.application())?;
    engine.install_application_sources(fixture.roots.clone(), &fixture.image)?;
    let previous = engine.generation()?;
    // Fill the actual source class; protected native work slots remain available
    // to the real producer. No configured budget or quote is changed.
    let mut occupied = Vec::new();
    while let Ok(grant) = fixture.storage.admission.reserve_application_source(0) {
        occupied.push(grant);
    }
    let position = kasumi_raft::AppliedEntryContext {
        log_id: openraft::LogId::new(openraft::CommittedLeaderId::new(1, 1), 1),
        previous: None,
        membership: Default::default(),
        command_sha256: "0".repeat(64),
        retirement_seed: None,
    };
    let invoke = |publisher: &mut dyn kasumi_raft::ApplyPublisher| {
        engine.apply_with_publisher(&position, kasumi_raft::AppliedInput::Metadata, publisher)
    };
    let error =
        kasumi_raft::with_application_publisher_for_test(&fixture.stores, &position, invoke)
            .err()
            .context("unfunded source publication succeeded")?;
    assert!(error.chain().any(|cause| {
        cause
            .downcast_ref::<kasumi_types::Error>()
            .is_some_and(|error| error.code == kasumi_types::ErrorCode::ResourceExhausted)
    }));
    assert!(Arc::ptr_eq(&previous, &engine.generation()?));
    assert!(
        fixture
            .stores
            .custody()
            .store()
            .get_bounded("raft.meta", b"applied", 2 << 20)?
            .is_none()
    );
    drop(error);
    drop(occupied);
    kasumi_raft::with_application_publisher_for_test(&fixture.stores, &position, invoke)?;
    let current = engine.generation()?;
    assert!(!Arc::ptr_eq(&previous, &current));
    let selected = current
        .application_selection
        .get()
        .context("published source absent")?;
    let proof = selected
        .cell
        .position
        .get()
        .context("selected proof absent")?;
    assert!(
        matches!(proof.applied(), Some(kasumi_raft::SelectedAppliedRef::Entry { log_id, .. }) if log_id == position.log_id)
    );
    assert!(
        fixture
            .stores
            .custody()
            .store()
            .get_bounded("raft.meta", b"applied", 2 << 20)?
            .is_some()
    );
    drop(current);
    drop(previous);
    engine.seal();
    drop(engine);
    fixture.close().await
}

#[tokio::test]
async fn selected_sources_missing_prospective_callback_never_publishes_generation() -> Result<()> {
    use kasumi_raft::StateMachineBackend;
    struct OmitPreparation<'a> {
        stores: &'a kasumi_store::TenantStorageSet,
        position: &'a kasumi_raft::AppliedEntryContext,
        failure: Option<anyhow::Error>,
    }
    impl kasumi_raft::ApplyPublisher for OmitPreparation<'_> {
        fn with_completion(
            &mut self,
            _: &kasumi_raft::CompletionIdentity,
            _: &mut dyn kasumi_raft::CompletionAction,
        ) -> std::result::Result<(), kasumi_raft::CompletionCallError> {
            Err(kasumi_raft::CompletionCallError::Unsupported)
        }

        fn commit(
            &mut self,
            _: kasumi_raft::AppliedResponse,
            _: &[kasumi_store::WriteOp],
        ) -> std::result::Result<(), kasumi_raft::PublishCallError> {
            panic!("source-enabled Engine must request prospective preparation")
        }
        fn commit_with_selection<'call>(
            &mut self,
            response: kasumi_raft::AppliedResponse,
            writes: &[kasumi_store::WriteOp],
            _: &mut dyn kasumi_raft::SelectionPreparer,
            challenge: kasumi_raft::PublicationChallenge<'call>,
        ) -> std::result::Result<
            kasumi_raft::JointPublicationReceipt<'call>,
            kasumi_raft::PublishCallError,
        > {
            struct Other;
            impl kasumi_raft::SelectionPreparer for Other {
                fn prepare(
                    &mut self,
                    _: &PreparedSelectionPlan,
                    _points: kasumi_store::PreparedTenantPointWorkspace,
                ) -> Result<()> {
                    Ok(())
                }
            }
            let mut receipt = None;
            let outcome = kasumi_raft::with_application_publisher_for_test(
                self.stores,
                self.position,
                |publisher| {
                    receipt = Some(
                        publisher.commit_with_selection(response, writes, &mut Other, challenge)?,
                    );
                    Ok(())
                },
            );
            match outcome {
                Ok(_) => Ok(receipt.expect("actual successful publication")),
                Err(error) => {
                    self.failure = Some(error);
                    Err(kasumi_raft::PublishCallError::Failed)
                }
            }
        }
    }

    let fixture = Fixture::new().await?;
    crate::test_utils::install_fixture_audit_placement(fixture.stores.application())?;
    let engine = TenantEngine::from_bootstrap("selected-sources", &fixture.image)?;
    engine.install_storage_access(fixture.stores.application())?;
    engine.install_application_sources(fixture.roots.clone(), &fixture.image)?;
    let previous = engine.generation()?;
    let position = kasumi_raft::AppliedEntryContext {
        log_id: openraft::LogId::new(openraft::CommittedLeaderId::new(1, 1), 1),
        previous: None,
        membership: Default::default(),
        command_sha256: "0".repeat(64),
        retirement_seed: None,
    };
    let error = engine
        .apply_with_publisher(
            &position,
            kasumi_raft::AppliedInput::Metadata,
            &mut OmitPreparation {
                stores: &fixture.stores,
                position: &position,
                failure: None,
            },
        )
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("omitted or failed source preparation")
    );
    assert!(Arc::ptr_eq(&previous, &engine.generation()?));
    drop(previous);
    engine.seal();
    drop(engine);
    fixture.close().await
}

#[tokio::test]
async fn selected_sources_repeated_prospective_callback_is_sticky_and_cancels_queued_reader()
-> Result<()> {
    struct CapturePlan(Option<(PreparedSelectionPlan, PreparedTenantPointWorkspace)>);
    impl SelectionPreparer for CapturePlan {
        fn prepare(
            &mut self,
            plan: &PreparedSelectionPlan,
            points: kasumi_store::PreparedTenantPointWorkspace,
        ) -> Result<()> {
            self.0 = Some((plan.clone(), points));
            Ok(())
        }
    }
    let fixture = Fixture::new().await?;
    let before_points = fixture.storage.admission.snapshot().live_reservations;
    let position = kasumi_raft::AppliedEntryContext {
        log_id: openraft::LogId::new(openraft::CommittedLeaderId::new(1, 1), 1),
        previous: None,
        membership: Default::default(),
        command_sha256: "0".repeat(64),
        retirement_seed: None,
    };
    let mut actual = CapturePlan(None);
    let response = kasumi_raft::AppliedResponse::application(Vec::new());
    let expectation =
        kasumi_raft::PublicationExpectation::for_entry(&fixture.stores, &position, &[], &response)?;
    kasumi_raft::with_application_publisher_for_test(&fixture.stores, &position, |publisher| {
        let receipt = publisher.commit_with_selection(
            response,
            &[],
            &mut actual,
            expectation.challenge()?,
        )?;
        expectation.consume(
            receipt,
            &actual.0.as_ref().context("actual producer omitted plan")?.0,
        )?;
        Ok(())
    })?;
    let (plan, points) = actual.0.take().context("actual producer omitted plan")?;
    // The same actual producer supplies a second independently funded backing.
    let response = kasumi_raft::AppliedResponse::application(Vec::new());
    let expectation =
        kasumi_raft::PublicationExpectation::for_entry(&fixture.stores, &position, &[], &response)?;
    kasumi_raft::with_application_publisher_for_test(&fixture.stores, &position, |publisher| {
        let receipt = publisher.commit_with_selection(
            response,
            &[],
            &mut actual,
            expectation.challenge()?,
        )?;
        expectation.consume(
            receipt,
            &actual.0.as_ref().context("repeat producer omitted plan")?.0,
        )?;
        Ok(())
    })?;
    let (_, repeated_points) = actual.0.take().context("repeat backing absent")?;
    let held_points = fixture.storage.admission.snapshot().live_reservations;
    assert!(held_points > before_points);
    let census = fixture
        .node
        .persistent_disk()
        .memory()
        .storage_census()
        .snapshot();
    let mut prepared = fixture.roots.publication_preparation();
    prepared.prepare(&plan, points)?;
    let source = prepared.prepared.as_ref().unwrap();
    let id = source
        .queued
        .as_ref()
        .unwrap()
        .registered_reader_id()
        .unwrap();
    assert!(
        source
            .cell
            .workspace
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .planned_peak
            .is_some_and(|peak| peak < 1 << 20)
    );
    let repeated = prepared.prepare(&plan, repeated_points).unwrap_err();
    assert!(repeated.to_string().contains("repeated"));
    let failed = prepared
        .finish_inner()
        .err()
        .context("swallowed duplicate authorized capture")?;
    assert!(failed.to_string().contains("repeated"));
    assert!(fixture.roots.gate.lock().unwrap().cells.is_empty());
    assert!(
        kasumi_store::RegisteredNodeRead::retained(
            fixture.node.persistent_disk().memory().clone(),
            id
        )
        .is_none()
    );
    assert_eq!(
        fixture
            .node
            .persistent_disk()
            .memory()
            .storage_census()
            .snapshot(),
        census
    );
    assert_eq!(
        fixture.storage.admission.snapshot().live_reservations,
        before_points
    );
    drop(actual);
    fixture.close().await
}

#[tokio::test]
async fn selected_sources_routine_bounded_read_error_retires_with_original_report_alive()
-> Result<()> {
    let fixture = Fixture::new().await?;
    // Deliberately corrupt trusted metadata with an encrypted row one byte over
    // the canonical custody bound. The failure must come from the real bounded
    // native read, before JSON decoding or proof validation.
    fixture.stores.write_batch(
        &[],
        &[kasumi_store::WriteOp::put(
            "raft.meta",
            b"applied",
            vec![b'x'; (2 << 20) + 1],
        )],
    )?;
    let error = fixture.select().unwrap_err();
    let failure = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<kasumi_store::NodeScopedReadFailure>())
        .expect("actual native bounded read failure");
    let id = failure.reader_id();
    assert_eq!(
        failure.try_retire_routine(),
        kasumi_store::StorageCensusDisposition::Retired
    );
    assert!(failure.report().has_failures());
    assert!(fixture.roots.gate.lock().unwrap().cells.is_empty());
    // The immutable original error remains reachable while the native database
    // can close and retire. SourceRoots owns no diagnostic-history leak.
    fixture.close().await?;
    let failure = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<kasumi_store::NodeScopedReadFailure>())
        .unwrap();
    assert_eq!(failure.reader_id(), id);
    assert!(failure.report().has_failures());
    assert_eq!(
        failure.try_retire_routine(),
        kasumi_store::StorageCensusDisposition::Retired
    );
    Ok(())
}

#[tokio::test]
async fn selected_sources_fork_keeps_exact_old_native_generation_after_parent_retirement()
-> Result<()> {
    let fixture = Fixture::new().await?;
    fixture.stores.write_batch(
        &[kasumi_store::WriteOp::put(
            "source-fixture",
            b"key",
            b"old".to_vec(),
        )],
        &[],
    )?;
    let parent = fixture.select()?;
    let parent_cell = parent.cell.clone();
    fixture.stores.write_batch(
        &[kasumi_store::WriteOp::put(
            "source-fixture",
            b"key",
            b"new".to_vec(),
        )],
        &[],
    )?;
    let (child, permit) = parent.begin_fork()?;
    let child = SelectedApplication::settle_fork(child, permit)?;
    drop(parent);
    assert!(parent_cell.state.lock().unwrap().closed);
    let view = child
        .cell
        .state
        .lock()
        .unwrap()
        .view
        .as_ref()
        .unwrap()
        .clone();
    assert_eq!(
        view.application_get("source-fixture", b"key", 16)?,
        Some(b"old".to_vec())
    );
    drop(view);
    drop(child);
    assert!(fixture.roots.gate.lock().unwrap().cells.is_empty());
    assert_eq!(
        fixture.stores.application().get("source-fixture", b"key")?,
        Some(b"new".to_vec())
    );
    drop(parent_cell);
    fixture.close().await
}

#[tokio::test]
async fn selected_sources_unknown_capture_panic_without_view_never_drains_as_clean() -> Result<()> {
    let fixture = Fixture::new().await?;
    let preparation = fixture.roots.prepare()?;
    let cell = preparation.cell.clone();
    let original = Arc::new(());
    let payload = std::panic::catch_unwind({
        let original = original.clone();
        move || std::panic::panic_any(original)
    })
    .expect_err("original panic payload");
    preparation.cell.record_failure(
        SourcePanic {
            _payload: Mutex::new(payload),
        }
        .into(),
        false,
    );
    // A missing view does not prove that an unknown capture panic left no
    // native obligation. Only this test knows it injected before acquisition.
    drop(preparation);
    assert!(cell.state.lock().unwrap().closed);
    assert!(cell.native_retained.load(Ordering::Acquire));
    let Poll::Ready(Err(first)) = drain(&fixture.roots) else {
        panic!("unknown capture panic falsely drained")
    };
    let Poll::Ready(Err(second)) = drain(&fixture.roots) else {
        panic!("repeated unknown capture panic falsely drained")
    };
    assert_eq!(first.completion(), DrainCompletion::Retained);
    assert_eq!(second.completion(), DrainCompletion::Retained);
    assert!(kasumi_types::drain::DrainIssueRef::ptr_eq(
        &first.issues()[0],
        &second.issues()[0]
    ));
    assert!(!fixture.roots.is_drained());
    let panic = cell
        .failure
        .get()
        .unwrap()
        .owner
        .original
        .downcast_ref::<SourcePanic>()
        .unwrap();
    assert!(Arc::ptr_eq(
        panic
            ._payload
            .lock()
            .unwrap()
            .downcast_ref::<Arc<()>>()
            .unwrap(),
        &original,
    ));
    // Remove only this injected, never-acquired test cell. Production has no
    // escape hatch for an unknown native panic and must retain it indefinitely.
    let synthetic = {
        let mut gate = fixture.roots.gate.lock().unwrap();
        std::mem::take(&mut gate.cells)
    };
    drop(synthetic);
    drop(cell);
    drop(first);
    drop(second);
    fixture.close().await
}

#[tokio::test]
async fn selected_sources_alias_refusal_preserves_later_actual_native_close_failure() -> Result<()>
{
    let fixture = Fixture::new().await?;
    fixture.stores.write_batch(
        &[kasumi_store::WriteOp::put(
            "source-fixture",
            b"key",
            b"oversized".to_vec(),
        )],
        &[],
    )?;
    let selected = fixture.select()?;
    let cell = selected.cell.clone();
    let uncounted = cell.state.lock().unwrap().view.as_ref().unwrap().clone();
    drop(selected);
    assert!(cell.alias_failure.get().is_some());
    assert!(cell.close_failure.get().is_none());
    let body = uncounted
        .application_get("source-fixture", b"key", 1)
        .unwrap_err();
    let native = body
        .chain()
        .find_map(|cause| cause.downcast_ref::<kasumi_store::NodeScopedReadFailure>())
        .expect("actual bounded native read failure");
    let reader_id = native.reader_id();
    drop(uncounted);
    fixture.roots.retry_retirements();
    let close = cell
        .close_failure
        .get()
        .expect("actual consuming-close failure retained separately");
    let exact = close
        .owner
        .original
        .chain()
        .find_map(|cause| cause.downcast_ref::<kasumi_store::NodeScopedReadFailure>())
        .expect("original consuming-close native owner");
    assert_eq!(exact.reader_id(), reader_id);
    assert!(cell.alias_failure.get().is_some());
    assert!(!cell.state.lock().unwrap().closed);
    assert!(!fixture.roots.gate.lock().unwrap().cells.is_empty());
    assert_eq!(
        native.try_retire_routine(),
        kasumi_store::StorageCensusDisposition::Retired
    );
    // Exact ordinary retry can retire after the external body facade detaches;
    // no shutdown poll or diagnostic destruction is required.
    fixture.roots.retry_retirements();
    assert!(cell.state.lock().unwrap().closed);
    assert!(fixture.roots.gate.lock().unwrap().cells.is_empty());
    assert!(exact.report().has_failures());
    assert!(native.report().has_failures());
    drop(cell);
    fixture.close().await?;
    assert!(
        body.chain()
            .any(|cause| cause.is::<kasumi_store::NodeScopedReadFailure>())
    );
    Ok(())
}

#[tokio::test]
async fn selected_sources_capture_finalization_settles_handle_before_retirement() -> Result<()> {
    let fixture = Fixture::new().await?;
    let mut preparation = fixture.roots.prepare()?;
    let cell = preparation.cell.clone();
    let view = ViewRef::new(fixture.stores.read_view()?, cell._reservation.clone());
    cell.state.lock().unwrap().view = Some(view.clone());
    let workspace = cell.workspace.lock().unwrap().take().unwrap();
    let position = kasumi_raft::selected_application_at(
        &view,
        ApplicationBoundaryRef::Bootstrap(&fixture.image),
        ApplicationSelectionMode::Reconstructing,
        &RaftLimits::default(),
        workspace,
    )?;
    assert!(cell.position.set(position).is_ok());
    drop(view);
    // Hold only the state mutex so finalization must own the admission gate
    // before attempting its one atomic preparation/selected-handle transition.
    let (finalizer, observed_gate) = {
        let state = cell.state.lock().unwrap();
        let finalizer = std::thread::spawn(move || preparation.finish_capture(false));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut observed_gate = false;
        while std::time::Instant::now() < deadline {
            if matches!(
                fixture.roots.gate.try_lock(),
                Err(std::sync::TryLockError::WouldBlock)
            ) {
                observed_gate = true;
                break;
            }
            std::thread::yield_now();
        }
        assert!(state.preparing);
        assert_eq!(cell.handles.load(Ordering::Acquire), 0);
        (finalizer, observed_gate)
    };
    let selected = finalizer.join().expect("source finalizer panicked")?;
    assert!(
        observed_gate,
        "capture must acquire gate before ending preparation"
    );
    assert!(!cell.state.lock().unwrap().preparing);
    assert_eq!(cell.handles.load(Ordering::Acquire), 1);
    fixture.roots.retire(&cell, false);
    assert!(!cell.state.lock().unwrap().closed);
    drop(selected);
    assert!(cell.state.lock().unwrap().closed);
    drop(cell);
    fixture.close().await
}

#[test]
fn selected_sources_maintenance_publication_requires_actual_scope_for_owner_and_growth()
-> Result<()> {
    use crate::audit_maintenance::NodeAuditMaintenance;
    let total = 4 * NodeAuditMaintenance::WORKSPACE_BYTES;
    let make_admission = || {
        NodeAdmission::with_fixed_memory(
            AdmissionConfig {
                max_inflight_bytes: Some(total),
                ..Default::default()
            },
            2 << 30,
            0,
        )
    };
    let admission = make_admission()?;
    let initial = admission.snapshot();
    let pool = NodeAuditMaintenance::install(&admission)?;
    let ordinary = admission.reserve(
        total - admission.snapshot().reserved_bytes - NodeAuditMaintenance::WORKSPACE_BYTES,
        None,
    )?;
    assert!(admission.reserve(1, None).is_err());
    // A pool merely installed on this exact node does not permit spending its
    // free publication headroom for an unscoped selected source.
    assert!(admission.reserve_application_source(1).is_err());
    let foreign = make_admission()?;
    let foreign_pool = NodeAuditMaintenance::install(&foreign)?;
    {
        let _foreign_scope = foreign_pool.enter_scope();
        assert!(admission.reserve_application_source(1).is_err());
    }
    let before = admission.snapshot();
    let mut selected = {
        let _scope = pool.enter_scope();
        admission.reserve_application_source(1024)?
    };
    assert_eq!(
        admission.snapshot().reserved_bytes,
        before.reserved_bytes + 1024
    );
    assert_eq!(
        admission.snapshot().live_reservations,
        before.live_reservations + 1
    );
    assert!(selected.reserve_additional(1).is_err());
    {
        let _foreign_scope = foreign_pool.enter_scope();
        assert!(selected.reserve_additional(1).is_err());
    }
    {
        let _scope = pool.enter_scope();
        selected.reserve_additional(1024)?;
        // The real max-bytes limit remains binding even in the actual scope.
        assert!(
            admission
                .reserve_application_source(NodeAuditMaintenance::WORKSPACE_BYTES)
                .is_err()
        );
    }
    assert_eq!(
        admission.snapshot().reserved_bytes,
        before.reserved_bytes + 2048
    );
    selected.retain(512);
    assert_eq!(
        admission.snapshot().reserved_bytes,
        before.reserved_bytes + 512
    );
    drop(selected);
    assert_eq!(admission.snapshot().reserved_bytes, before.reserved_bytes);
    drop(ordinary);
    drop(pool);
    assert_eq!(admission.snapshot().reserved_bytes, initial.reserved_bytes);
    assert_eq!(
        admission.snapshot().live_reservations,
        initial.live_reservations
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn selected_sources_actual_snapshot_install_and_encrypted_reopen_preserve_identity()
-> Result<()> {
    async fn audit(
        node: &Arc<kasumi_store::NodeStore>,
        admission: &Arc<NodeAdmission>,
        existing: bool,
    ) -> Result<Arc<crate::SecurityAudit>> {
        let key = Arc::new(LocalKeyProvider::new([121; 32]));
        let store = if existing {
            kasumi_store::TenantStore::open_existing_fixture(
                node.clone(),
                crate::SECURITY_TENANT.into(),
                key,
            )
            .await?
        } else {
            kasumi_store::TenantStore::initialize_catalog_fixture(
                node.clone(),
                crate::SECURITY_TENANT.into(),
                key,
            )
            .await?
        };
        if existing {
            crate::SecurityAudit::open(store, Default::default(), admission.clone())
        } else {
            crate::SecurityAudit::initialize(store, Default::default(), admission.clone())
        }
    }
    fn snapshot_identity(
        cell: &Cell,
        expected: &kasumi_raft::SnapshotMeta<u64, kasumi_raft::BasicNode>,
        backend: &str,
        envelope: &str,
    ) {
        let proof = cell
            .position
            .get()
            .expect("actual selected application proof");
        match proof.applied().expect("actual selected applied cursor") {
            kasumi_raft::SelectedAppliedRef::Snapshot {
                meta,
                backend_sha256,
                snapshot_sha256,
            } => {
                assert_eq!(meta, expected);
                assert_eq!(backend_sha256, backend);
                assert_eq!(snapshot_sha256, envelope);
            }
            _ => panic!("restored Generation must select the actual Snapshot boundary"),
        }
        let snapshot = proof.snapshot().expect("actual durable snapshot coverage");
        assert_eq!(snapshot.meta, expected);
        assert_eq!(snapshot.backend_sha256, backend);
        assert_eq!(snapshot.snapshot_sha256, envelope);
        assert!(!snapshot.manifest_id.is_empty());
        assert!(snapshot.bytes > 0 && snapshot.chunks > 0);
        assert!(!proof.is_covered_reconstruction());
    }
    let source = Fixture::new().await?;
    let source_audit = audit(&source.node, &source.storage.admission, false).await?;
    crate::test_utils::install_fixture_audit_placement(source.stores.application())?;
    let source_engine = Arc::new(TenantEngine::from_bootstrap(
        "selected-sources",
        &source.image,
    )?);
    source_engine.install_storage_access(source.stores.application())?;
    let group = format!(
        "selected-sources/{}",
        source_engine.generation()?.state.incarnation
    );
    let source_db = crate::service::construction::DatabaseConstruction::new(
        source.stores.clone(),
        source_audit.clone(),
    )?
    .start_local(source_engine.clone(), &source.image, 1, group.clone())
    .await?;
    let expected = source_db
        .raft_group()
        .linearizable_barrier()
        .await?
        .expect("initialized source log");
    source_db.raft_group().snapshot().await?;
    // The trigger only enqueues work. Wait for actual snapshot publication at
    // this stable local applied position before obtaining the transfer image.
    source_db
        .raft_group()
        .raft()
        .wait(Some(std::time::Duration::from_secs(10)))
        .snapshot(expected, "selected-source durable snapshot")
        .await?;
    let snapshot = source_db
        .raft_group()
        .raft()
        .get_snapshot()
        .await?
        .expect("durable source snapshot");
    assert_eq!(snapshot.meta.last_log_id, Some(expected));
    let meta = snapshot.meta.clone();
    let coverage: serde_json::Value = serde_json::from_slice(
        &source
            .stores
            .custody()
            .store()
            .get_bounded("raft.meta", b"snapshot_coverage", 2 << 20)?
            .expect("durable source coverage"),
    )?;
    let backend = coverage["backend_sha256"]
        .as_str()
        .expect("backend digest")
        .to_owned();
    let envelope = coverage["snapshot_sha256"]
        .as_str()
        .expect("snapshot digest")
        .to_owned();
    assert_eq!(
        serde_json::from_value::<kasumi_raft::SnapshotMeta<u64, kasumi_raft::BasicNode>>(
            coverage["meta"].clone()
        )?,
        meta
    );
    let vote = kasumi_raft::ControlLog::open(source.stores.custody().clone(), 1, group.clone())?
        .read_vote()?
        .expect("actual source vote");

    let mut target = Fixture::with_bootstrap(2, Some(&source.image)).await?;
    let target_audit = audit(&target.node, &target.storage.admission, false).await?;
    crate::test_utils::install_fixture_audit_placement(target.stores.application())?;
    let target_engine = Arc::new(TenantEngine::from_bootstrap(
        "selected-sources",
        &target.image,
    )?);
    target_engine.install_storage_access(target.stores.application())?;
    let bootstrap = target_engine.generation()?;
    let target_db = crate::service::construction::DatabaseConstruction::new(
        target.stores.clone(),
        target_audit.clone(),
    )?
    .start_replicated(
        target_engine.clone(),
        &target.image,
        2,
        group.clone(),
        Arc::new(kasumi_raft::InProcessRouter::default()),
        Default::default(),
    )
    .await?;
    let bootstrap_cell = bootstrap.application_selection.get().unwrap().cell.clone();
    target_db
        .raft_group()
        .raft()
        .install_full_snapshot(vote, snapshot)
        .await?;
    let installed = target_engine.generation()?;
    let installed_cell = installed.application_selection.get().unwrap().cell.clone();
    snapshot_identity(&installed_cell, &meta, &backend, &envelope);
    assert_eq!(
        installed.state.revision,
        source_engine.generation()?.state.revision
    );
    assert!(!CellRef::ptr_eq(&bootstrap_cell, &installed_cell));
    assert!(!bootstrap_cell.state.lock().unwrap().closed);
    drop(bootstrap);
    assert!(bootstrap_cell.state.lock().unwrap().closed);
    target_db.shutdown().await?;
    assert!(installed_cell.state.lock().unwrap().closed);
    snapshot_identity(&installed_cell, &meta, &backend, &envelope);
    drop(target_db);
    drop(target_engine);
    target_audit.shutdown().await?;
    drop(target_audit);
    target.node.shutdown().await?;

    // Reopen the actual encrypted file immediately with a fresh Engine and
    // Database startup. The learner has no local leader/no-op Entry to obscure
    // the Reopen Snapshot selection installed before the serving handoff.
    target.node = target.storage.open_existing(
        target._directory.path().join("persistent/node.kv"),
        kasumi_store::test_utils::NODE_STORE_ID,
    )?;
    target.stores = TenantStorageSet::open_existing_fixture(
        target.node.clone(),
        "selected-sources".into(),
        Arc::new(LocalKeyProvider::new([119; 32])),
        Arc::new(LocalKeyProvider::new([120; 32])),
    )
    .await?;
    let reopened_audit = audit(&target.node, &target.storage.admission, true).await?;
    crate::test_utils::install_fixture_audit_placement(target.stores.application())?;
    let reopened_engine = Arc::new(TenantEngine::from_bootstrap(
        "selected-sources",
        &target.image,
    )?);
    reopened_engine.install_storage_access(target.stores.application())?;
    let reopening_bootstrap = reopened_engine.generation()?;
    let reopened_db = crate::service::construction::DatabaseConstruction::new(
        target.stores.clone(),
        reopened_audit.clone(),
    )?
    .start_replicated(
        reopened_engine.clone(),
        &target.image,
        2,
        group,
        Arc::new(kasumi_raft::InProcessRouter::default()),
        Default::default(),
    )
    .await?;
    let reopened = reopened_engine.generation()?;
    let reopened_cell = reopened.application_selection.get().unwrap().cell.clone();
    snapshot_identity(&reopened_cell, &meta, &backend, &envelope);
    assert!(!CellRef::ptr_eq(&installed_cell, &reopened_cell));
    let reconstructed = reopening_bootstrap
        .application_selection
        .get()
        .unwrap()
        .cell
        .clone();
    assert!(
        reconstructed
            .position
            .get()
            .unwrap()
            .is_covered_reconstruction()
    );
    assert!(!reconstructed.state.lock().unwrap().closed);
    drop(reopening_bootstrap);
    assert!(reconstructed.state.lock().unwrap().closed);
    reopened_db.shutdown().await?;
    assert!(reopened_cell.state.lock().unwrap().closed);
    assert!(installed_cell.state.lock().unwrap().closed);
    drop(reopened);
    drop(installed);
    drop(reopened_db);
    drop(reopened_engine);
    reopened_audit.shutdown().await?;
    drop(reopened_audit);
    target.close().await?;
    source_db.shutdown().await?;
    drop(source_db);
    drop(source_engine);
    source_audit.shutdown().await?;
    drop(source_audit);
    source.close().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn selected_sources_covered_capture_cannot_settle_after_serving_handoff() -> Result<()> {
    let fixture = Fixture::new().await?;
    let audit_store = kasumi_store::TenantStore::initialize_catalog_fixture(
        fixture.node.clone(),
        crate::SECURITY_TENANT.into(),
        Arc::new(LocalKeyProvider::new([121; 32])),
    )
    .await?;
    let audit = crate::SecurityAudit::initialize(
        audit_store,
        Default::default(),
        fixture.storage.admission.clone(),
    )?;
    crate::test_utils::install_fixture_audit_placement(fixture.stores.application())?;
    let engine = Arc::new(TenantEngine::from_bootstrap(
        "selected-sources",
        &fixture.image,
    )?);
    engine.install_storage_access(fixture.stores.application())?;
    let group = format!(
        "selected-sources/{}",
        engine.generation()?.state.incarnation
    );
    let database = crate::service::construction::DatabaseConstruction::new(
        fixture.stores.clone(),
        audit.clone(),
    )?
    .start_local(engine.clone(), &fixture.image, 1, group)
    .await?;
    let generation = engine.generation()?;
    assert!(!generation.state.retired);
    let actual = generation.application_selection.get().unwrap();
    let position = match actual.cell.position.get().unwrap().applied().unwrap() {
        kasumi_raft::SelectedAppliedRef::Entry {
            log_id,
            previous,
            membership,
            command_sha256,
        } => kasumi_raft::AppliedEntryContext {
            log_id,
            previous,
            membership: membership.clone(),
            command_sha256: command_sha256.into(),
            retirement_seed: None,
        },
        _ => panic!("local startup must publish an actual Entry"),
    };
    // This separate, enrolled registry is still reconstructing. Capture the
    // authenticated bootstrap against the actual newer durable Entry; pause
    // only settlement, without injecting a cursor or fabricated proof.
    let mut covered = fixture.roots.prepare()?;
    covered.capture_position(ApplicationBoundaryRef::Bootstrap(&fixture.image));
    let covered_cell = covered.cell.clone();
    assert!(
        covered_cell
            .position
            .get()
            .unwrap()
            .is_covered_reconstruction()
    );
    assert!(!covered_cell.state.lock().unwrap().closed);
    // An already opened primary transport also loses reconstruction-only
    // permission at the handoff; it cannot keep reading through its own pin.
    let covered_selected = fixture
        .roots
        .prepare()?
        .capture(ApplicationBoundaryRef::Bootstrap(&fixture.image), false)?;
    let mut covered_reader = covered_selected.open_primary_reader(&fixture.roots)?;
    let mut reader_workspace = fixture.storage.admission.reserve_document_source(4096)?;
    let mut exact = fixture.roots.prepare()?;
    exact.capture_position(ApplicationBoundaryRef::Entry(&position));
    assert!(
        !exact
            .cell
            .position
            .get()
            .unwrap()
            .is_covered_reconstruction()
    );
    let selected = fixture
        .roots
        .prepare()?
        .capture(ApplicationBoundaryRef::Entry(&position), false)?;
    fixture.roots.finish_reconstruction()?;
    assert!(fixture.roots.gate.lock().unwrap().serving);
    let reader_error = covered_reader
        .with_record(
            &mut reader_workspace,
            4096,
            "engine.primary.meta",
            b"gc",
            64,
            |_| Ok(()),
        )
        .unwrap_err();
    assert!(
        reader_error
            .to_string()
            .contains("covered source cannot lend primary objects after serving")
    );
    covered_reader.close()?;
    drop(covered_selected);
    drop(reader_workspace);

    let error = covered.finish_capture(false).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("covered application reconstruction settled after serving")
    );
    let returned = &error.downcast_ref::<SourceFailure>().unwrap().owner;
    assert!(FailureRef::ptr_eq(
        returned,
        &covered_cell.failure.get().unwrap().owner
    ));
    assert!(covered_cell.state.lock().unwrap().closed);
    assert!(covered_cell.state.lock().unwrap().view.is_none());
    {
        let gate = fixture.roots.gate.lock().unwrap();
        assert!(!gate.cells.contains_key(&covered_cell.id));
        assert!(CellRef::ptr_eq(
            &gate.latest.upgrade().unwrap(),
            &selected.cell
        ));
    }
    drop(covered_cell);
    // The original independently charged diagnostic survives positive native
    // retirement. Exact proof settling across the same mode switch succeeds;
    // this test never fabricates a frozen-generation exception.
    assert!(error.downcast_ref::<SourceFailure>().is_some());
    let exact = exact.finish_capture(false)?;
    assert!(CellRef::ptr_eq(
        &fixture.roots.gate.lock().unwrap().latest.upgrade().unwrap(),
        &exact.cell
    ));
    drop(exact);
    drop(selected);
    drop(generation);
    database.shutdown().await?;
    drop(database);
    drop(engine);
    audit.shutdown().await?;
    drop(audit);
    assert!(error.downcast_ref::<SourceFailure>().is_some());
    fixture.close().await?;
    drop(error);
    Ok(())
}

#[path = "primary_stage_tests.rs"]
mod primary_stage_tests;

#[path = "application_source_allocation_tests.rs"]
pub(crate) mod allocation_tails;

#[path = "primary_read_tests.rs"]
mod primary_read_tests;

#[path = "application_source_quote_tests.rs"]
mod quote_tests;

#[path = "application_source_completion_tests.rs"]
pub(super) mod completion_tests;

#[tokio::test]
async fn selected_sources_actual_entry_hands_point_backing_to_capture_and_queue_cancellation()
-> Result<()> {
    for capture in [false, true] {
        let fixture = Fixture::new().await?;
        let position = kasumi_raft::AppliedEntryContext {
            log_id: openraft::LogId::new(openraft::CommittedLeaderId::new(1, 1), 1),
            previous: None,
            membership: Default::default(),
            command_sha256: "0".repeat(64),
            retirement_seed: None,
        };
        let baseline = fixture.storage.admission.snapshot();
        let response = kasumi_raft::AppliedResponse::application(Vec::new());
        let expectation = kasumi_raft::PublicationExpectation::for_entry(
            &fixture.stores,
            &position,
            &[],
            &response,
        )?;
        let mut preparer = fixture.roots.publication_preparation();
        let mut receipt = None;
        kasumi_raft::with_application_publisher_for_test(
            &fixture.stores,
            &position,
            |publisher| {
                receipt = Some(publisher.commit_with_selection(
                    response,
                    &[],
                    &mut preparer,
                    expectation.challenge()?,
                )?);
                Ok(())
            },
        )?;
        let mut prepared =
            preparer.finish_publication(&expectation, receipt.context("actual receipt absent")?)?;
        assert!(
            prepared.points.is_some(),
            "actual admitted backing was not transferred to RootPreparation"
        );
        let id = prepared
            .queued
            .as_ref()
            .unwrap()
            .registered_reader_id()
            .unwrap();
        assert_eq!(
            fixture
                .node
                .persistent_disk()
                .memory()
                .storage_census()
                .snapshot()
                .readers,
            1
        );
        if capture {
            let selected =
                prepared.capture_in_place(ApplicationBoundaryRef::Entry(&position), false)?;
            assert!(
                prepared.points.is_none(),
                "capture left its plaintext backing resident"
            );
            assert_eq!(
                selected
                    .cell
                    .state
                    .lock()
                    .unwrap()
                    .view
                    .as_ref()
                    .unwrap()
                    .registered_reader_id(),
                Some(id)
            );
            assert!(
                matches!(selected.cell.position.get().unwrap().applied(), Some(kasumi_raft::SelectedAppliedRef::Entry { log_id, .. }) if log_id == position.log_id)
            );
            drop(selected);
        }
        drop(prepared);
        assert!(
            kasumi_store::RegisteredNodeRead::retained(
                fixture.node.persistent_disk().memory().clone(),
                id
            )
            .is_none()
        );
        assert_eq!(
            fixture
                .node
                .persistent_disk()
                .memory()
                .storage_census()
                .snapshot()
                .readers,
            0
        );
        assert_eq!(
            fixture.storage.admission.snapshot().live_reservations,
            baseline.live_reservations
        );
        fixture.close().await?;
    }
    Ok(())
}

#[path = "application_source_point_retirement_tests.rs"]
mod point_retirement_tests;

#[tokio::test]
async fn selected_sources_initial_install_fits_actual_rows_below_format_ceiling() -> Result<()> {
    let fixture = Fixture::new().await?;
    crate::test_utils::install_fixture_audit_placement(fixture.stores.application())?;
    let engine = TenantEngine::from_bootstrap("selected-sources", &fixture.image)?;
    engine.install_storage_access(fixture.stores.application())?;
    // Actual installed ordinary pressure leaves less than the former fixed
    // 2MiB plaintext floor. Native/report accounting and configured caps stay.
    let mut pressure = Vec::new();
    while let Ok(charge) = fixture.storage.admission.reserve_document_source(1 << 20) {
        pressure.push(charge);
    }
    drop(
        pressure
            .pop()
            .context("fixture did not admit initial pressure")?,
    );
    // Positive negative control: the unchanged generic/snapshot ceiling path
    // cannot obtain its larger proof floor at this exact class occupancy.
    assert!(fixture.roots.prepare().is_err());
    engine.install_application_sources(fixture.roots.clone(), &fixture.image)?;
    let generation = engine.generation()?;
    let selected = generation
        .application_selection
        .get()
        .context("initial selection absent")?;
    assert_eq!(
        selected.cell.position.get().unwrap().bootstrap().digest,
        fixture.image.sha256()
    );
    assert!(selected.cell.position.get().unwrap().applied().is_none());
    drop(generation);
    drop(engine);
    drop(pressure);
    fixture.close().await
}

#[path = "application_source_cohort_tests.rs"]
mod cohort_tests;

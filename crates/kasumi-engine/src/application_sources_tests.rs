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
    node: kasumi_store::NodeStore,
    stores: Arc<TenantStorageSet>,
    image: SnapshotImage,
    roots: SourceRootsRef,
    _buffers: Arc<kasumi_raft::SnapshotBufferOwner>,
    budget: u64,
}
impl Fixture {
    async fn new() -> crate::test_fixture_failure::FixtureResult<Self> {
        Self::with_bootstrap(1, None).await
    }
    async fn with_bootstrap(
        node_id: u64,
        bootstrap: Option<&SnapshotImage>,
    ) -> crate::test_fixture_failure::FixtureResult<Self> {
        Self::with_memory(node_id, bootstrap, None).await
    }
    /// `memory` replaces the fixed zero-RSS sample with an explicit source
    /// sampled every 10 ms against a 1 GiB high-water mark.
    async fn with_memory(
        node_id: u64,
        bootstrap: Option<&SnapshotImage>,
        memory: Option<Arc<dyn crate::admission::MemorySource>>,
    ) -> crate::test_fixture_failure::FixtureResult<Self> {
        Self::with_admission(node_id, bootstrap, |config| match memory {
            None => NodeAdmission::with_fixed_memory(config, 2 << 30, 0),
            Some(memory) => NodeAdmission::create(
                AdmissionConfig {
                    sample_interval_ms: 10,
                    max_sample_age_ms: 10,
                    ..config
                },
                1 << 30,
                memory,
                Arc::new(kasumi_clock::SystemLeaseClock),
            ),
        })
        .await
    }

    async fn with_admission(
        node_id: u64,
        bootstrap: Option<&SnapshotImage>,
        governor: impl FnOnce(AdmissionConfig) -> anyhow::Result<Arc<NodeAdmission>>,
    ) -> crate::test_fixture_failure::FixtureResult<Self> {
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
        let admission = governor(config)?;
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
            Some(image) => SnapshotImage::capture(
                stores.application().scratch_disk(),
                image.len(),
                |writer| {
                    std::io::copy(&mut image.reader(), writer)?;
                    Ok(())
                },
            )?,
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
                + kasumi_types::SharedBudgetCharge::required_bytes::<crate::admission::Reservation>(
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
    async fn close(self) -> crate::test_fixture_failure::FixtureResult<()> {
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
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
async fn selected_sources_last_selected_handle_closes_during_ordinary_operation()
-> crate::test_fixture_failure::FixtureResult<()> {
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
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
async fn selected_sources_shutdown_closes_native_parent_with_metadata_alias_alive()
-> crate::test_fixture_failure::FixtureResult<()> {
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
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
async fn selected_sources_fork_seal_closes_registered_child_before_releasing_permit()
-> crate::test_fixture_failure::FixtureResult<()> {
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
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
async fn selected_sources_failed_consuming_close_never_becomes_success_from_none()
-> crate::test_fixture_failure::FixtureResult<()> {
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
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
async fn selected_sources_canonical_failure_closes_parent_preserves_original_and_issue()
-> crate::test_fixture_failure::FixtureResult<()> {
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
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
async fn selected_sources_local_command_publishes_entry_and_drains_surviving_generation()
-> crate::test_fixture_failure::FixtureResult<()> {
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
    assert!(database.raft_group().try_raft().is_none());
    assert_eq!(
        engine.generation()?.state.revision,
        bootstrap.state.revision
    );
    // Standalone startup has no election no-op. A real command advances the
    // selected source while the earlier immutable generation remains pinned.
    database
        .administer(
            kasumi_types::RequestContext::trusted("selected-sources", "owner", [Action::Admin]),
            kasumi_types::Operation::CreateCollection(kasumi_types::CollectionDefinition {
                name: "docs".into(),
                write_mode: kasumi_types::CollectionWriteMode::Mutable,
                retention_class: kasumi_types::CollectionRetentionClass::Operational,
                schema: serde_json::json!({"type": "object"}),
                indexes: vec![],
                strict_read_audit: false,
            }),
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
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
async fn selected_sources_rebase_moves_bootstrap_selection_to_the_current_root()
-> crate::test_fixture_failure::FixtureResult<()> {
    let fixture = Fixture::new().await?;
    crate::test_utils::install_fixture_audit_placement(fixture.stores.application())?;
    let engine = TenantEngine::from_bootstrap("selected-sources", &fixture.image)?;
    engine.install_storage_access(fixture.stores.application())?;
    engine.install_application_sources(fixture.roots.clone(), &fixture.image)?;
    // Reconstruction has not handed the source over to serving yet.
    assert!(engine.stale_application_selection(u64::MAX)?.is_none());
    fixture.roots.finish_reconstruction()?;
    // This node has finished no evacuation, so nothing could be freed.
    assert!(engine.stale_application_selection(0)?.is_none());
    let initial = engine.generation()?;
    let old = initial.application_selection.get().unwrap().cell.clone();
    let revision = initial.state.revision;
    drop(initial);
    // Nothing has been applied, so the authenticated bootstrap is the boundary.
    let stale = engine
        .stale_application_selection(u64::MAX)?
        .context("bootstrap selection predates a later evacuation")?;
    assert!(engine.rebase_application_selection(stale)?);
    let current = engine.generation()?;
    let selected = current.application_selection.get().unwrap();
    assert!(!CellRef::ptr_eq(&old, &selected.cell));
    let position = selected.cell.position.get().unwrap();
    assert!(position.applied().is_none());
    assert!(!position.is_covered_reconstruction());
    assert_eq!(position.bootstrap().digest, fixture.image.sha256());
    assert_eq!(current.state.revision, revision);
    // The superseded view closed with its last Generation handle.
    assert!(old.state.lock().unwrap().closed);
    drop(old);
    drop(current);
    drop(engine);
    fixture.close().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
async fn selected_sources_apply_that_races_a_rebase_wins()
-> crate::test_fixture_failure::FixtureResult<()> {
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
    let incarnation = engine.generation()?.state.incarnation.clone();
    let database = crate::service::construction::DatabaseConstruction::new(
        fixture.stores.clone(),
        audit.clone(),
    )?
    .start_local(
        engine.clone(),
        &fixture.image,
        1,
        format!("selected-sources/{incarnation}"),
    )
    .await?;
    // The rebase observes the current selection outside the apply lock.
    let stale = engine
        .stale_application_selection(u64::MAX)?
        .context("startup selection predates a later evacuation")?;
    // An apply publishes its own selection before the rebase takes the lock.
    let receipt = database
        .administer(
            kasumi_types::RequestContext::trusted("selected-sources", "owner", [Action::Admin]),
            kasumi_types::Operation::CreateCollection(kasumi_types::CollectionDefinition {
                name: "docs".into(),
                write_mode: kasumi_types::CollectionWriteMode::Mutable,
                retention_class: kasumi_types::CollectionRetentionClass::Operational,
                schema: serde_json::json!({"type": "object"}),
                indexes: vec![],
                strict_read_audit: false,
            }),
        )
        .await?;
    let applied = engine.generation()?;
    assert_eq!(applied.state.revision, receipt.revision);
    let applied_cell = applied.application_selection.get().unwrap().cell.clone();
    // The apply wins: the observed selection is no longer current, so the
    // rebase publishes nothing and reports no error.
    assert!(!engine.rebase_application_selection(stale)?);
    assert!(Arc::ptr_eq(&engine.generation()?, &applied));
    drop(applied);
    // A later observation moves the apply's selection, keeping its state.
    let stale = engine
        .stale_application_selection(u64::MAX)?
        .context("applied selection predates a later evacuation")?;
    assert!(engine.rebase_application_selection(stale)?);
    let rebased = engine.generation()?;
    assert_eq!(rebased.state.revision, receipt.revision);
    assert!(rebased.state.collections.contains_key("docs"));
    let selected = rebased.application_selection.get().unwrap();
    assert!(!CellRef::ptr_eq(&applied_cell, &selected.cell));
    let applied_position = applied_cell.position.get().unwrap().applied();
    let rebased_position = selected.cell.position.get().unwrap().applied();
    match (applied_position, rebased_position) {
        (
            Some(kasumi_raft::SelectedAppliedRef::Entry {
                log_id: applied, ..
            }),
            Some(kasumi_raft::SelectedAppliedRef::Entry {
                log_id: rebased, ..
            }),
        ) => assert_eq!(applied, rebased),
        other => panic!(
            "the apply's entry boundary changed: {:?}",
            other.0.is_some()
        ),
    }
    drop(rebased);
    drop(applied_cell);
    // The rebased selection is the position the next proposal is admitted at.
    let next = database
        .administer(
            kasumi_types::RequestContext::trusted("selected-sources", "owner", [Action::Admin]),
            kasumi_types::Operation::CreateCollection(kasumi_types::CollectionDefinition {
                name: "more".into(),
                write_mode: kasumi_types::CollectionWriteMode::Mutable,
                retention_class: kasumi_types::CollectionRetentionClass::Operational,
                schema: serde_json::json!({"type": "object"}),
                indexes: vec![],
                strict_read_audit: false,
            }),
        )
        .await?;
    assert_eq!(next.revision, receipt.revision + 1);
    database.shutdown().await?;
    drop(database);
    drop(engine);
    audit.shutdown().await?;
    fixture.close().await
}

#[tokio::test]
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
async fn selected_sources_rebase_uses_bounded_plan_and_preserves_pending_publication()
-> crate::test_fixture_failure::FixtureResult<()> {
    let fixture = Fixture::new().await?;
    crate::test_utils::install_fixture_audit_placement(fixture.stores.application())?;
    let engine = TenantEngine::from_bootstrap("selected-sources", &fixture.image)?;
    engine.install_storage_access(fixture.stores.application())?;
    engine.install_application_sources(fixture.roots.clone(), &fixture.image)?;
    fixture.roots.finish_reconstruction()?;
    let initial = engine.generation()?;
    let old = initial.application_selection.get().unwrap().cell.clone();
    let stale = engine
        .stale_application_selection(u64::MAX)?
        .context("bootstrap selection predates a later evacuation")?;

    // A proposal may already be admitted while the idle monitor rebases.
    engine.admit_publication()?;
    assert!(fixture.roots.publication.lock().unwrap().is_some());
    let escrow = Arc::as_ptr(fixture.roots.escrow.lock().unwrap().as_ref().unwrap());
    let admission = &fixture.storage.admission;
    let (cache_headroom, _) = admission.policy().cache_work_headroom(fixture.budget);
    let pressure = admission.reserve_resident(
        fixture.budget - admission.snapshot().reserved_bytes - cache_headroom - (8 << 20),
    )?;
    let before = admission.snapshot();
    // The tiny durable bootstrap fits, although the unplanned snapshot ceiling
    // cannot be funded. A refused preparation must return its temporary credit.
    let error = fixture
        .roots
        .prepare()
        .err()
        .context("unplanned selection unexpectedly fit limited headroom")?;
    assert!(error.chain().any(|cause| {
        cause
            .downcast_ref::<kasumi_types::Error>()
            .is_some_and(|error| error.code == kasumi_types::ErrorCode::ResourceExhausted)
    }));
    drop(error);
    assert_eq!(admission.snapshot().reserved_bytes, before.reserved_bytes);
    assert_eq!(
        admission.snapshot().live_reservations,
        before.live_reservations
    );

    assert!(engine.rebase_application_selection(stale)?);
    let current = engine.generation()?;
    let selected = current.application_selection.get().unwrap();
    assert!(!CellRef::ptr_eq(&old, &selected.cell));
    let position = selected.cell.position.get().unwrap();
    assert!(position.applied().is_none());
    assert!(!position.is_covered_reconstruction());
    assert_eq!(position.bootstrap().digest, fixture.image.sha256());
    assert_eq!(current.state.revision, initial.state.revision);
    assert!(fixture.roots.publication.lock().unwrap().is_some());
    assert_eq!(
        Arc::as_ptr(fixture.roots.escrow.lock().unwrap().as_ref().unwrap()),
        escrow
    );
    // Existing readers retain the old root until their last Generation ends.
    assert!(!old.state.lock().unwrap().closed);
    drop(initial);
    assert!(old.state.lock().unwrap().closed);
    drop(pressure);
    drop(old);
    drop(current);
    drop(engine);
    fixture.close().await
}

#[tokio::test]
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
async fn selected_sources_prospective_denial_preserves_cursor_generation_and_original_then_retries()
-> crate::test_fixture_failure::FixtureResult<()> {
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
    assert!(
        error
            .operation_error()
            .expect("ordinary prospective refusal")
            .chain()
            .any(|cause| {
                cause
                    .downcast_ref::<kasumi_types::Error>()
                    .is_some_and(|error| error.code == kasumi_types::ErrorCode::ResourceExhausted)
            })
    );
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
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
async fn selected_sources_missing_prospective_callback_never_publishes_generation()
-> crate::test_fixture_failure::FixtureResult<()> {
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
                |publisher| -> anyhow::Result<()> {
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
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
async fn selected_sources_repeated_prospective_callback_is_sticky_and_cancels_queued_reader()
-> crate::test_fixture_failure::FixtureResult<()> {
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
    kasumi_raft::with_application_publisher_for_test(
        &fixture.stores,
        &position,
        |publisher| -> anyhow::Result<()> {
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
        },
    )?;
    let (plan, points) = actual.0.take().context("actual producer omitted plan")?;
    // The same actual producer supplies a second independently funded backing.
    let response = kasumi_raft::AppliedResponse::application(Vec::new());
    let expectation =
        kasumi_raft::PublicationExpectation::for_entry(&fixture.stores, &position, &[], &response)?;
    kasumi_raft::with_application_publisher_for_test(
        &fixture.stores,
        &position,
        |publisher| -> anyhow::Result<()> {
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
        },
    )?;
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
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
async fn selected_sources_routine_bounded_read_error_retires_with_original_report_alive()
-> crate::test_fixture_failure::FixtureResult<()> {
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
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
async fn selected_sources_fork_keeps_exact_old_native_generation_after_parent_retirement()
-> crate::test_fixture_failure::FixtureResult<()> {
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
        view.application_get("source-fixture", b"key", 16)?
            .as_deref(),
        Some(b"old".as_slice())
    );
    drop(view);
    drop(child);
    assert!(fixture.roots.gate.lock().unwrap().cells.is_empty());
    assert_eq!(
        fixture
            .stores
            .application()
            .get("source-fixture", b"key")?
            .as_deref(),
        Some(b"new".as_slice())
    );
    drop(parent_cell);
    fixture.close().await
}

#[tokio::test]
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
async fn selected_sources_unknown_capture_panic_without_view_never_drains_as_clean()
-> crate::test_fixture_failure::FixtureResult<()> {
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
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
async fn selected_sources_alias_refusal_preserves_later_actual_native_close_failure()
-> crate::test_fixture_failure::FixtureResult<()> {
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
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
async fn selected_sources_capture_finalization_settles_handle_before_retirement()
-> crate::test_fixture_failure::FixtureResult<()> {
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
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
async fn selected_sources_actual_snapshot_install_and_encrypted_reopen_preserve_identity()
-> crate::test_fixture_failure::FixtureResult<()> {
    async fn audit(
        node: &kasumi_store::NodeStore,
        admission: &Arc<NodeAdmission>,
        existing: bool,
    ) -> crate::test_fixture_failure::FixtureResult<Arc<crate::SecurityAudit>> {
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
            Ok(crate::SecurityAudit::open(
                store,
                Default::default(),
                admission.clone(),
            )?)
        } else {
            Ok(crate::SecurityAudit::initialize(
                store,
                Default::default(),
                admission.clone(),
            )?)
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
    fn compound_seek(
        generation: &Arc<crate::Generation>,
        admission: &Arc<NodeAdmission>,
    ) -> crate::test_fixture_failure::FixtureResult<()> {
        use kasumi_query::DocumentSource as _;
        let source = generation.document_source("docs")?;
        let cancellation = kasumi_query::QueryCancellation::default();
        let actual = source
            .ordered_unique_window(
                0,
                std::ops::Bound::Unbounded,
                std::ops::Bound::Unbounded,
                true,
                &cancellation,
            )?
            .expect("selected persisted compound directory");
        assert_eq!(
            actual.iter().map(|(_, id)| id.as_str()).collect::<Vec<_>>(),
            ["point"]
        );
        let query = kasumi_types::QueryRequest::new("docs")
            .sort_desc("/nil")
            .sort_desc("/value")
            .paging(kasumi_types::Paging::Seek);
        let mut memory = kasumi_query::QueryMemory::empty(admission.reserve(0, None)?);
        let page = generation.indexes.seek_page(
            &source,
            &query,
            None,
            &generation.state.limits,
            &|_| Ok(16),
            &cancellation,
            &mut memory,
        )?;
        assert_eq!(
            page.rows.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
            ["point"]
        );
        assert!(page.last_key.is_none());
        Ok(())
    }
    let source = Fixture::with_admission(1, None, NodeAdmission::new_fixture).await?;
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
    .start_replicated(
        source_engine.clone(),
        &source.image,
        1,
        group.clone(),
        Arc::new(kasumi_raft::InProcessRouter::default()),
        Default::default(),
    )
    .await?;
    source_db
        .raft_group()
        .initialize(std::collections::BTreeMap::from([(
            1,
            kasumi_raft::BasicNode::new("snapshot-source"),
        )]))
        .await?;
    source_db
        .raft_group()
        .raft()
        .wait(Some(std::time::Duration::from_secs(10)))
        .current_leader(1, "replicated snapshot source leader")
        .await?;
    let context = kasumi_types::RequestContext {
        authorization: kasumi_types::RequestAuthorization::service_identity(),
        tenant: "selected-sources".into(),
        principal: "owner".into(),
        scopes: std::collections::BTreeSet::from([Action::Admin, Action::Read, Action::Write]),
        request_id: "snapshot-primary-point".into(),
    };
    let body = serde_json::json!({"value": "persisted", "nil": null, "empty": []});
    source_db
        .administer(
            context.clone(),
            kasumi_types::Operation::CreateCollection(kasumi_types::CollectionDefinition {
                name: "docs".into(),
                write_mode: kasumi_types::CollectionWriteMode::Mutable,
                retention_class: kasumi_types::CollectionRetentionClass::Operational,
                schema: serde_json::json!({"type": "object"}),
                indexes: [
                    ("missing", kasumi_types::ScalarType::String),
                    ("nil", kasumi_types::ScalarType::String),
                    ("empty", kasumi_types::ScalarType::StringArray),
                    ("value", kasumi_types::ScalarType::String),
                ]
                .into_iter()
                .map(|(name, kind)| kasumi_types::IndexDefinition {
                    name: name.to_owned(),
                    fields: vec![kasumi_types::IndexField {
                        path: format!("/{name}"),
                        kind,
                    }],
                    unique: name == "value",
                    text: None,
                })
                .chain([kasumi_types::IndexDefinition {
                    name: "nil_value".into(),
                    text: None,
                    unique: true,
                    fields: ["/nil", "/value"]
                        .into_iter()
                        .map(|path| kasumi_types::IndexField {
                            path: path.into(),
                            kind: kasumi_types::ScalarType::String,
                        })
                        .collect(),
                }])
                .collect(),
                strict_read_audit: false,
            }),
        )
        .await?;
    source_db
        .mutate(
            context.clone(),
            kasumi_types::MutationBatch::new().upsert("docs", "point", body.clone()),
        )
        .await?;
    let second_body = serde_json::json!({"value": "zulu"});
    source_db
        .mutate(
            context.clone(),
            kasumi_types::MutationBatch::new().upsert("docs", "alpha", second_body.clone()),
        )
        .await?;
    let duplicates_original = source_db
        .mutate(
            context.clone(),
            kasumi_types::MutationBatch::new().upsert("docs", "duplicate", body.clone()),
        )
        .await
        .unwrap_err();
    assert_eq!(duplicates_original.code, kasumi_types::ErrorCode::Conflict);
    // Ordinary writes alone keep the structured directory current. Before any
    // snapshot exists, the leader's generation reads its postings from the
    // directory its own publication committed with the applied cursor.
    {
        use kasumi_query::DocumentSource as _;
        use std::ops::Bound::Included;
        let ordinary = source_engine.generation()?;
        compound_seek(&ordinary, &source.storage.admission)?;
        let physical = ordinary
            .physical_seek_view("docs", |_| Ok(true))?
            .expect("physical seek worker projection");
        compound_seek(&Arc::new(physical), &source.storage.admission)?;
        let selection = ordinary.application_selection.get().unwrap();
        assert!(
            !selection.has_exact_snapshot(ordinary.state.revision_base, ordinary.state.revision)
        );
        // Four presence rows, seven scalar postings and one complete compound tuple.
        assert_eq!(
            selection.with_structured_records(
                None,
                &ordinary.state,
                || ordinary.indexes.structured_layout_sha256(),
                |tree| Ok(tree.root().count()),
            )?,
            Some(12)
        );
        let docs = ordinary.document_source("docs")?;
        let cancellation = kasumi_query::QueryCancellation::default();
        let (zulu, persisted) = (serde_json::json!("zulu"), serde_json::json!("persisted"));
        for (ordinal, predicate, expected) in [
            (0, kasumi_query::FieldPredicate::Exists(true), vec!["point"]),
            (
                1,
                kasumi_query::FieldPredicate::Exists(false),
                vec!["alpha", "point"],
            ),
            (
                3,
                kasumi_query::FieldPredicate::Equals {
                    value: &zulu,
                    kind: kasumi_types::ScalarType::String,
                },
                vec!["alpha"],
            ),
            (
                3,
                kasumi_query::FieldPredicate::Range {
                    lower: Included(&persisted),
                    upper: Included(&zulu),
                    kind: kasumi_types::ScalarType::String,
                },
                vec!["point", "alpha"],
            ),
        ] {
            let mut ids = Vec::new();
            assert!(
                docs.visit_field_posting(ordinal, predicate, &cancellation, |id| {
                    ids.push(id.to_owned());
                    Ok(())
                })
                .map_err(crate::index_source::into_anyhow)?,
                "ordinary structured directory absent"
            );
            assert_eq!(ids, expected);
        }
        let mut query = kasumi_types::QueryRequest::new("docs");
        query.filter = kasumi_types::Filter::new().eq("/value", serde_json::json!("zulu"));
        let mut memory =
            kasumi_query::QueryMemory::empty(source.storage.admission.reserve(0, None)?);
        let result = crate::test_utils::fixture_query(&ordinary, &query, &mut memory)?;
        assert_eq!(
            result
                .rows
                .iter()
                .map(|row| row.id.as_str())
                .collect::<Vec<_>>(),
            ["alpha"]
        );
        let mut native_rows = Vec::new();
        let selected =
            crate::application_structured::visit_checkpoint_compounds(&ordinary, |key, value| {
                native_rows.push((key.to_vec(), value.to_vec()));
                Ok(())
            })?;
        assert_eq!(selected, 1);
        let mut independent = Vec::new();
        crate::application_structured::visit_compound_rows(
            &ordinary.indexes,
            &mut |key, value| {
                independent.push((key.to_vec(), value.to_vec()));
                Ok(())
            },
        )?;
        assert!(!independent.is_empty());
        assert_eq!(native_rows, independent);
        let applied = kasumi_store::structured_manifest::StructuredManifest::load(
            source.stores.application(),
        )?
        .expect("published field directory")
        .applied
        .expect("exact applied entry");
        for wrong_log in [true, false] {
            let mut substituted = applied.clone();
            if wrong_log {
                substituted.log_sha256[0] ^= 1;
            } else {
                substituted
                    .command_sha256
                    .as_mut()
                    .expect("command identity")[0] ^= 1;
            }
            source_engine.select_wrong_structured_history_for_test(substituted)?;
            let changed = source_engine.generation()?;
            assert!(
                changed
                    .application_selection
                    .get()
                    .unwrap()
                    .with_structured_records(
                        None,
                        &changed.state,
                        || changed.indexes.structured_layout_sha256(),
                        |_| Ok(())
                    )?
                    .is_none()
            );
            let mut memory =
                kasumi_query::QueryMemory::empty(source.storage.admission.reserve(0, None)?);
            let fallback = crate::test_utils::fixture_query(&changed, &query, &mut memory)?;
            assert_eq!(
                fallback
                    .rows
                    .iter()
                    .map(|r| r.id.as_str())
                    .collect::<Vec<_>>(),
                ["alpha"]
            );
            assert_eq!(
                selection.with_structured_records(
                    None,
                    &ordinary.state,
                    || ordinary.indexes.structured_layout_sha256(),
                    |tree| Ok(tree.root().count())
                )?,
                Some(12)
            );
        }
    }
    // Two ordinary metadata publications preserve the original change-feed
    // fixture. The first rejects the foreign base, the next rebuilds it.
    let limits = source_engine.generation()?.state.limits.clone();
    for current in [false, true] {
        source_db
            .administer(
                context.clone(),
                kasumi_types::Operation::SetLimits(limits.clone()),
            )
            .await?;
        let fields = kasumi_store::structured_manifest::StructuredManifest::load(
            source.stores.application(),
        )?
        .unwrap();
        assert!(!current || fields.is_current());
        if fields.is_current() {
            assert_eq!(fields.records.count(), 12);
        }
    }
    // A registered idle worker repairs an actual selected generation with
    // disk-backed documents. A reader pinned before recovery keeps its root.
    {
        let retained = source_engine.generation()?;
        let expected = retained.state.revision;
        source_engine.seed_structured_rebuild_for_test()?;
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            loop {
                let current = source_engine.generation()?;
                anyhow::ensure!(
                    current.state.revision == expected,
                    "structured repair changed its logical revision"
                );
                if current
                    .application_selection
                    .get()
                    .unwrap()
                    .with_structured_records(
                        None,
                        &current.state,
                        || current.indexes.structured_layout_sha256(),
                        |t| Ok(t.root().count()),
                    )?
                    == Some(12)
                {
                    return Ok::<_, anyhow::Error>(());
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        })
        .await??;
        assert_eq!(
            retained
                .application_selection
                .get()
                .unwrap()
                .with_structured_records(
                    None,
                    &retained.state,
                    || retained.indexes.structured_layout_sha256(),
                    |t| Ok(t.root().count())
                )?,
            Some(12)
        );
    }
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
    compound_seek(&reopened, &target.storage.admission)?;
    let physical = reopened
        .physical_seek_view("docs", |_| Ok(true))?
        .expect("reopened seek worker projection");
    compound_seek(&Arc::new(physical), &target.storage.admission)?;
    let checkpoint_rows = reopened
        .application_selection
        .get()
        .unwrap()
        .with_snapshot_records(None, &reopened.state, |tree, _, layout| {
            anyhow::ensure!(
                layout >= kasumi_store::application_manifest::ORDERED_TUPLE_LAYOUT,
                "restored checkpoint lacks compound tuples"
            );
            crate::application_structured::ordered_unique_window(
                tree,
                "docs",
                0,
                std::ops::Bound::Unbounded,
                std::ops::Bound::Unbounded,
                true,
                || true,
            )
        })?
        .expect("authenticated checkpoint compound root");
    assert_eq!(
        checkpoint_rows
            .iter()
            .map(|(_, id)| id.as_str())
            .collect::<Vec<_>>(),
        ["point"]
    );
    let reopened_cell = reopened.application_selection.get().unwrap().cell.clone();
    snapshot_identity(&reopened_cell, &meta, &backend, &envelope);
    let selection = reopened.application_selection.get().unwrap();
    // The installed snapshot selected a rebuilt structured directory; the
    // encrypted reopen verified and kept it, so the postings read below come
    // from the ordinary directory at this exact revision.
    {
        assert_eq!(
            selection.with_structured_records(
                None,
                &reopened.state,
                || reopened.indexes.structured_layout_sha256(),
                |tree| Ok(tree.root().count()),
            )?,
            Some(12)
        );
    }
    for (after, limit, expected) in [
        (None, 1, vec!["alpha"]),
        (Some("alpha"), 2, vec!["point"]),
        (Some("point"), 1, vec![]),
    ] {
        let ids = selection.with_snapshot_records(None, &reopened.state, |tree, _, _| {
            crate::application_records::snapshot_ids_after(tree, "docs", after, limit, || Ok(()))
        })?;
        assert_eq!(ids.context("reopened primary directory missing")?, expected);
    }
    {
        use crate::state::lease_retention::{PageAccess, PageSelection};
        let cancellation = kasumi_query::QueryCancellation::default();
        let clock = Arc::new(kasumi_clock::SystemLeaseClock);
        let term = reopened_db.raft_group().current_term();
        let lease_id = uuid::Uuid::new_v4().to_string();
        let handle = reopened_engine.leases.open(
            &reopened_engine,
            &context,
            reopened.state.limits.cursor_ttl_ms,
            clock,
            term,
            &target.storage.admission,
            lease_id.clone(),
            &cancellation,
        )?;
        for (after_id, expected, more) in [(None, "alpha", true), (Some("alpha"), "point", false)] {
            let page = reopened_engine.leases.select(
                &reopened_engine,
                &lease_id,
                PageSelection::Scan(kasumi_types::ScanSnapshotPage {
                    lease_id: lease_id.clone(),
                    collection: "docs".into(),
                    after_id: after_id.map(str::to_owned),
                    limit: 1,
                }),
                PageAccess {
                    context: &context,
                    term,
                    node: &target.storage.admission,
                    cancellation: &cancellation,
                },
            )?;
            assert!(Arc::ptr_eq(&handle, &page.handle));
            assert_eq!(page.scan_ids, [expected]);
            assert_eq!(page.scan_has_more, more);
        }
        reopened_engine.leases.close(&context, &lease_id)?;
    }
    let mut admitted = 0;
    let Some(crate::application_records::PrimaryPoint::Live(slot)) =
        selection.snapshot_point(&reopened.state, "docs", "point", |bytes| {
            admitted += bytes.len();
            Ok(())
        })?
    else {
        panic!("reopened snapshot must supply the live primary descriptor")
    };
    assert!(admitted > 0);
    assert_eq!(
        slot.load_owned(reopened.document_resolver())?.as_ref().body,
        body
    );
    assert!(matches!(
        selection.snapshot_point(&reopened.state, "docs", "absent", |_| anyhow::bail!(
            "absent point returned a record"
        ))?,
        Some(crate::application_records::PrimaryPoint::Missing)
    ));
    {
        use kasumi_query::DocumentSource;
        let docs = reopened.document_source("docs")?;
        let cancellation = kasumi_query::QueryCancellation::default();
        // Remove the resident descriptors from a private read view. The
        // installed query still resolves the durable point and its body.
        let mut collections = reopened.state.collections.clone();
        let local = collections.get_mut("docs").unwrap();
        local.documents.remove("point");
        // A stale resident archive entry must never trigger an external read:
        // the authenticated directory owns both the point and the scan.
        local.archived_documents.insert(
            "absent".into(),
            Arc::new(kasumi_types::ArchivedDocument {
                version: slot.version(),
                archive_id: "unselected".into(),
                chunk_index: 0,
                document_sha256: "00".repeat(32),
                document_bytes: 1,
                indexed_fields: Default::default(),
            }),
        );
        let detached = Arc::new(reopened.read_view(collections, vec![]));
        let persisted = detached.document_source("docs")?;
        let mut visited = Vec::new();
        kasumi_query::CollectionRecords::visit_records(&persisted, |id, record| {
            if id == "point" {
                assert!(
                    matches!(record, kasumi_query::Record::Live(document) if document.body == body)
                );
            }
            visited.push(id.to_owned());
            Ok(())
        })
        .map_err(crate::index_source::into_anyhow)?;
        assert!(visited.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(visited.iter().any(|id| id == "point"));
        assert!(!visited.iter().any(|id| id == "absent"));
        persisted
            .with_record("point", Some(slot.version()), &cancellation, |record| {
                let Some(kasumi_query::Record::Live(document)) = record else {
                    panic!("persisted query point missing");
                };
                assert_eq!(document.body, body);
                Ok(())
            })
            .map_err(crate::index_source::into_anyhow)?;
        persisted
            .with_record("absent", None, &cancellation, |record| {
                assert!(record.is_none());
                Ok(())
            })
            .map_err(crate::index_source::into_anyhow)?;
        for id in ["point", "absent"] {
            assert!(
                persisted
                    .history_reference(id, &cancellation, |_| {
                        panic!("live or missing point requested archive workspace")
                    })
                    .map_err(crate::index_source::into_anyhow)?
                    .is_none()
            );
        }
        let mut history_rows = Vec::new();
        persisted
            .visit_history_scan(&cancellation, |id, archived| {
                history_rows.push((id.to_owned(), archived));
                Ok(())
            })
            .map_err(crate::index_source::into_anyhow)?;
        assert_eq!(
            history_rows,
            [("alpha".to_owned(), false), ("point".to_owned(), false)]
        );
        for (after, expected) in [
            (None, Some("alpha")),
            (Some("alpha"), Some("point")),
            (Some("point"), None),
        ] {
            let found = docs
                .header_after(after, &cancellation, |row| {
                    Ok(row.map(|h| (h.id.to_owned(), h.version, h.kind)))
                })
                .map_err(crate::index_source::into_anyhow)?;
            let original = expected
                .map(|id| {
                    let header = crate::index_source::header(
                        &reopened.state.collections["docs"],
                        id,
                        reopened.state.revision,
                    )?
                    .unwrap();
                    Ok::<_, kasumi_types::Error>((id.to_owned(), header.version, header.kind))
                })
                .transpose()?;
            assert_eq!(found, original);
        }
        for (ordinal, path, present) in [
            (0, "/empty", true),
            (1, "/missing", false),
            (2, "/nil", true),
        ] {
            for expected in [true, false] {
                let mut disk = Vec::new();
                let available = docs
                    .visit_field_posting(
                        ordinal,
                        kasumi_query::FieldPredicate::Exists(expected),
                        &cancellation,
                        |id| {
                            disk.push(id.to_owned());
                            Ok(())
                        },
                    )
                    .map_err(crate::index_source::into_anyhow)?;
                assert!(available, "installed field directory absent after reopen");
                let mut query = kasumi_types::QueryRequest::new("docs");
                query.filter = if expected {
                    kasumi_types::Filter::new().exists(path)
                } else {
                    kasumi_types::Filter::new().missing(path)
                };
                let mut memory =
                    kasumi_query::QueryMemory::empty(target.storage.admission.reserve(0, None)?);
                let ids = reopened
                    .indexes
                    .indexed_candidate_ids(
                        &docs,
                        &query,
                        &reopened.state.limits,
                        &cancellation,
                        &mut memory,
                    )
                    .map_err(crate::index_source::into_anyhow)?;
                assert_eq!(ids, disk);
                let mut expected_ids = Vec::new();
                if !expected {
                    expected_ids.push("alpha");
                }
                if expected == present {
                    expected_ids.push("point");
                }
                assert_eq!(ids, expected_ids);
            }
        }
        // Combine overlapping native postings after the installing process
        // has closed and this replica has reopened the encrypted store.
        let present = kasumi_types::Filter::new().exists("/empty");
        let zulu = kasumi_types::Filter::new().eq("/value", serde_json::json!("zulu"));
        for (filter, expected) in [
            (present.clone().and(zulu.clone()), Vec::new()),
            (
                kasumi_types::Filter::or([
                    present,
                    zulu,
                    kasumi_types::Filter::new().exists("/nil"),
                ]),
                vec!["alpha", "point"],
            ),
        ] {
            let mut query = kasumi_types::QueryRequest::new("docs");
            query.filter = filter;
            let mut memory =
                kasumi_query::QueryMemory::empty(target.storage.admission.reserve(0, None)?);
            let ids = reopened
                .indexes
                .indexed_candidate_ids(
                    &docs,
                    &query,
                    &reopened.state.limits,
                    &cancellation,
                    &mut memory,
                )
                .map_err(crate::index_source::into_anyhow)?;
            assert_eq!(ids, expected);
        }
        // Value order is opposite to ID order across these two postings.
        // Both the disk visitor and the caller-facing ID-ordered result matter.
        use std::ops::Bound::{Excluded, Included, Unbounded};
        let lo = serde_json::json!("persisted");
        let hi = serde_json::json!("zulu");
        let mut disk_ids = Vec::new();
        assert!(
            docs.visit_field_posting(
                3,
                kasumi_query::FieldPredicate::Range {
                    lower: Included(&lo),
                    upper: Included(&hi),
                    kind: kasumi_types::ScalarType::String,
                },
                &cancellation,
                |id| {
                    disk_ids.push(id.to_owned());
                    Ok(())
                },
            )
            .map_err(crate::index_source::into_anyhow)?
        );
        assert_eq!(disk_ids, ["point", "alpha"]);
        for (ordinal, path, lower, upper, expected_ids) in [
            (
                3,
                "/value",
                Included(&lo),
                Included(&hi),
                vec!["alpha", "point"],
            ),
            (3, "/value", Excluded(&lo), Unbounded, vec!["alpha"]),
            (3, "/value", Unbounded, Excluded(&hi), vec!["point"]),
            (3, "/value", Included(&lo), Excluded(&lo), vec![]),
            (3, "/value", Included(&hi), Included(&lo), vec![]),
            (2, "/nil", Unbounded, Included(&hi), vec![]),
            (1, "/missing", Unbounded, Included(&hi), vec![]),
        ] {
            let mut filter = kasumi_types::Filter::new();
            filter = match lower {
                Included(value) => filter.gte(path, value.clone()),
                Excluded(value) => filter.gt(path, value.clone()),
                Unbounded => filter,
            };
            filter = match upper {
                Included(value) => filter.lte(path, value.clone()),
                Excluded(value) => filter.lt(path, value.clone()),
                Unbounded => filter,
            };
            let mut query = kasumi_types::QueryRequest::new("docs");
            query.filter = filter;
            let mut memory =
                kasumi_query::QueryMemory::empty(target.storage.admission.reserve(0, None)?);
            let ids = reopened
                .indexes
                .indexed_candidate_ids(
                    &docs,
                    &query,
                    &reopened.state.limits,
                    &cancellation,
                    &mut memory,
                )
                .map_err(crate::index_source::into_anyhow)?;
            assert_eq!(ids, expected_ids, "indexed range for field {ordinal}");
        }
        for (values, expected) in [
            (
                vec![hi.clone(), lo.clone(), hi.clone()],
                vec!["alpha", "point"],
            ),
            (vec![lo.clone(), lo.clone()], vec!["point"]),
            (vec![serde_json::json!("absent")], vec![]),
            (vec![], vec![]),
        ] {
            let mut query = kasumi_types::QueryRequest::new("docs");
            query.filter = kasumi_types::Filter::new().is_in("/value", values.clone());
            let mut rows = Vec::new();
            assert!(
                docs.visit_field_posting(
                    3,
                    kasumi_query::FieldPredicate::In {
                        values: &values,
                        kind: kasumi_types::ScalarType::String,
                    },
                    &cancellation,
                    |id| {
                        rows.push(id.to_owned());
                        Ok(())
                    }
                )
                .map_err(crate::index_source::into_anyhow)?
            );
            rows.sort();
            assert_eq!(rows, expected);
            let mut memory =
                kasumi_query::QueryMemory::empty(target.storage.admission.reserve(0, None)?);
            let ids = reopened
                .indexes
                .indexed_candidate_ids(
                    &docs,
                    &query,
                    &reopened.state.limits,
                    &cancellation,
                    &mut memory,
                )
                .map_err(crate::index_source::into_anyhow)?;
            assert_eq!(ids, expected);
        }

        for (needle, expected) in [("persisted", 1), ("other", 0)] {
            let value = serde_json::json!(needle);
            let mut rows = Vec::new();
            assert!(
                docs.visit_field_posting(
                    3,
                    kasumi_query::FieldPredicate::Equals {
                        value: &value,
                        kind: kasumi_types::ScalarType::String
                    },
                    &cancellation,
                    |id| {
                        rows.push(id.to_owned());
                        Ok(())
                    }
                )
                .map_err(crate::index_source::into_anyhow)?
            );
            let mut memory =
                kasumi_query::QueryMemory::empty(target.storage.admission.reserve(0, None)?);
            let mut query = kasumi_types::QueryRequest::new("docs");
            query.filter = kasumi_types::Filter::new().eq("/value", value);
            let result = crate::test_utils::fixture_query(&reopened, &query, &mut memory)?;
            assert_eq!(rows.len(), expected);
            assert_eq!(
                result.rows.iter().map(|row| &row.id).collect::<Vec<_>>(),
                rows.iter().collect::<Vec<_>>()
            );
        }
    }
    let mut visited = Vec::new();
    let feed = &reopened.state.change_feed;
    selection
        .with_snapshot_records(None, &reopened.state, |tree, memory, _| {
            let snapshot_feed = crate::application_records::SnapshotFeed::open(
                tree,
                memory,
                reopened.state.revision,
                &reopened.state,
            )?
            .unwrap();
            snapshot_feed.visit(
                feed.first_available_sequence(),
                feed.first_available_sequence(),
                |sequence, revision, ordinal, count, record| {
                    assert_eq!(record.collection, "docs");
                    let expected = match record.id.as_str() {
                        "point" => &body,
                        "alpha" => &second_body,
                        _ => panic!("unexpected change-feed identity"),
                    };
                    let document = record
                        .document
                        .as_ref()
                        .unwrap()
                        .load_owned(reopened.document_resolver())
                        .map_err(crate::service::document_load_error)?;
                    assert_eq!(&document.as_ref().body, expected);
                    visited.push((sequence, revision, ordinal, count));
                    Ok(true)
                },
            )?;
            Ok(())
        })?
        .expect("reopened change directory");
    assert_eq!(visited.len(), 2);
    assert_eq!((visited[0].0, visited[0].2, visited[0].3), (1, 0, 1));
    assert_eq!((visited[1].0, visited[1].2, visited[1].3), (2, 0, 1));
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
    // This serving entry is newer than the checkpoint but leaves the
    // compound collection unchanged. Read the checkpoint directly so a
    // current ordinary tree cannot satisfy the assertion.
    source_db
        .administer(
            context.clone(),
            kasumi_types::Operation::SetLimits(limits.clone()),
        )
        .await?;
    {
        let current = source_engine.generation()?;
        let retained = current.application_selection.get().unwrap();
        assert!(!retained.has_exact_snapshot(current.state.revision_base, current.state.revision));
        let rows = retained
            .with_checkpoint_ordered_tuples(
                None,
                &current.state,
                std::iter::once("docs"),
                |tree| {
                    crate::application_structured::ordered_unique_window(
                        tree,
                        "docs",
                        0,
                        std::ops::Bound::Unbounded,
                        std::ops::Bound::Unbounded,
                        false,
                        || true,
                    )
                },
            )?
            .expect("unchanged collection lost its checkpoint");
        assert_eq!(
            rows.iter().map(|(_, id)| id.as_str()).collect::<Vec<_>>(),
            ["point"]
        );
        let mut foreign = current.state.clone();
        let changed = foreign.collections.get_mut("docs").unwrap();
        Arc::make_mut(&mut changed.definition).strict_read_audit =
            !changed.definition.strict_read_audit;
        assert!(
            retained
                .with_checkpoint_ordered_tuples(
                    None,
                    &foreign,
                    std::iter::once("docs"),
                    |_| -> anyhow::Result<()> {
                        panic!("changed schema exposed predecessor tuples")
                    },
                )?
                .is_none()
        );
    }
    // A document change invalidates this collection's checkpoint coverage.
    // The first two feed events still come from the immutable directory.
    let third_body = serde_json::json!({"value": "later"});
    source_db
        .mutate(
            context.clone(),
            kasumi_types::MutationBatch::new().upsert("docs", "tail", third_body.clone()),
        )
        .await?;
    let latest = source_engine.generation()?;
    assert!(
        latest
            .application_selection
            .get()
            .unwrap()
            .with_checkpoint_ordered_tuples(
                None,
                &latest.state,
                std::iter::once("docs"),
                |_| -> anyhow::Result<()> {
                    panic!("changed data epoch exposed predecessor tuples")
                },
            )?
            .is_none()
    );
    let base = latest
        .application_selection
        .get()
        .unwrap()
        .with_base_snapshot_records(None, &latest.state, |tree, memory, _, revision| {
            let prefix = crate::application_records::SnapshotFeed::open(
                tree,
                memory,
                revision,
                &latest.state,
            )?
            .context("older directory lost its feed prefix")?;
            Ok((revision, prefix.end_sequence))
        })?
        .context("new log entry lost its selected base snapshot")?;
    assert!(base.0 < latest.state.revision);
    assert_eq!(base.1, 3);
    drop(latest);
    let request = |start, limit| kasumi_types::ReadChangeFeed {
        collections: std::collections::BTreeSet::from(["docs".into()]),
        start,
        limit,
    };
    let initial = source_db
        .read_change_feed(
            &context,
            request(kasumi_types::ChangeFeedStart::Beginning, 1),
        )
        .await?;
    let kasumi_types::ChangeFeedPage::Events {
        events,
        next,
        caught_up,
        ..
    } = initial.as_ref()
    else {
        panic!("expected first retained event");
    };
    assert!(!caught_up);
    assert_eq!((events[0].sequence, events[0].id.as_str()), (1, "point"));
    let after = next.clone();
    drop(initial);
    let continuation = source_db
        .read_change_feed(
            &context,
            request(kasumi_types::ChangeFeedStart::After { cursor: after }, 3),
        )
        .await?;
    let kasumi_types::ChangeFeedPage::Events {
        events, caught_up, ..
    } = continuation.as_ref()
    else {
        panic!("expected mixed snapshot and log events");
    };
    assert!(*caught_up);
    assert_eq!(
        events
            .iter()
            .map(|e| (e.sequence, e.id.as_str()))
            .collect::<Vec<_>>(),
        [(2, "alpha"), (3, "tail")]
    );
    assert_eq!(events[0].document.as_ref().unwrap().body, second_body);
    assert_eq!(events[1].document.as_ref().unwrap().body, third_body);
    drop(continuation);
    source_db.shutdown().await?;
    drop(source_db);
    drop(source_engine);
    source_audit.shutdown().await?;
    drop(source_audit);
    source.close().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
async fn selected_sources_covered_capture_cannot_settle_after_serving_handoff()
-> crate::test_fixture_failure::FixtureResult<()> {
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
    // An already opened document reader also loses reconstruction-only
    // permission at the handoff; it cannot keep reading through its own pin.
    let covered_selected = fixture
        .roots
        .prepare()?
        .capture(ApplicationBoundaryRef::Bootstrap(&fixture.image), false)?;
    // The next replay writer knows which authenticated bootstrap it follows.
    // Its physical selection already includes a later committed entry, so a
    // text query or warmup at that earlier generation still has no directory.
    assert_eq!(
        covered_selected.text_predecessor()?,
        Some(kasumi_store::text_manifest::TextBoundary::Bootstrap)
    );
    assert!(covered_selected.text_boundary()?.is_none());
    let mut covered_reader = covered_selected.open_document_reader(&fixture.roots)?;
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
            crate::document_store::BODIES,
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
    // Close rechecks access through the same refused loan; the child reader
    // is still released.
    let close_error = covered_reader.close().unwrap_err();
    assert!(
        close_error
            .to_string()
            .contains("covered source cannot lend primary objects after serving")
    );
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

#[path = "application_source_allocation_tests.rs"]
pub(crate) mod allocation_tails;

#[path = "application_source_completion_tests.rs"]
pub(super) mod completion_tests;

#[tokio::test]
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
async fn selected_sources_actual_entry_hands_point_backing_to_capture_and_queue_cancellation()
-> crate::test_fixture_failure::FixtureResult<()> {
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
            |publisher| -> anyhow::Result<()> {
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
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
async fn selected_sources_initial_install_fits_actual_rows_below_format_ceiling()
-> crate::test_fixture_failure::FixtureResult<()> {
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

/// The ordinary primary directory follows every applied entry in the paired
/// publication, older generations keep reading their own pinned rows, reopen
/// keeps a directory ahead of its snapshot through covered replay, and a
/// store without one (as deployed revisions leave it) rebuilds from the
/// restored snapshot before replaying its tail.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
async fn selected_sources_ordinary_primary_directory_follows_apply_and_reopens()
-> crate::test_fixture_failure::FixtureResult<()> {
    use kasumi_store::primary_manifest::{self, PrimaryManifest};

    async fn audit(
        node: &kasumi_store::NodeStore,
        admission: &Arc<NodeAdmission>,
        existing: bool,
    ) -> crate::test_fixture_failure::FixtureResult<Arc<crate::SecurityAudit>> {
        let key = Arc::new(LocalKeyProvider::new([121; 32]));
        Ok(if existing {
            let store = kasumi_store::TenantStore::open_existing_fixture(
                node.clone(),
                crate::SECURITY_TENANT.into(),
                key,
            )
            .await?;
            crate::SecurityAudit::open(store, Default::default(), admission.clone())?
        } else {
            let store = kasumi_store::TenantStore::initialize_catalog_fixture(
                node.clone(),
                crate::SECURITY_TENANT.into(),
                key,
            )
            .await?;
            crate::SecurityAudit::initialize(store, Default::default(), admission.clone())?
        })
    }
    async fn start(
        fixture: &Fixture,
        audit: &Arc<crate::SecurityAudit>,
        group: &str,
        initialize: bool,
    ) -> crate::test_fixture_failure::FixtureResult<(Arc<TenantEngine>, Arc<crate::Database>)> {
        crate::test_utils::install_fixture_audit_placement(fixture.stores.application())?;
        let engine = Arc::new(TenantEngine::from_bootstrap(
            "selected-sources",
            &fixture.image,
        )?);
        engine.install_storage_access(fixture.stores.application())?;
        let db = crate::service::construction::DatabaseConstruction::new(
            fixture.stores.clone(),
            audit.clone(),
        )?
        .start_replicated(
            engine.clone(),
            &fixture.image,
            1,
            group.into(),
            Arc::new(kasumi_raft::InProcessRouter::default()),
            Default::default(),
        )
        .await?;
        if initialize {
            db.raft_group()
                .initialize(std::collections::BTreeMap::from([(
                    1,
                    kasumi_raft::BasicNode::new("primary-directory"),
                )]))
                .await?;
        }
        db.raft_group()
            .raft()
            .wait(Some(std::time::Duration::from_secs(20)))
            .current_leader(1, "primary directory leader")
            .await?;
        // The leader's first entry of its term is applied before reads.
        db.raft_group().linearizable_barrier().await?;
        Ok((engine, db))
    }
    /// The selected directory is current at the engine's exact revision and
    /// reproduces every resident primary row.
    fn current(
        engine: &TenantEngine,
        store: &Arc<kasumi_store::TenantStore>,
    ) -> Result<PrimaryManifest> {
        let generation = engine.generation()?;
        let manifest =
            PrimaryManifest::load(store)?.context("ordinary primary directory absent")?;
        ensure!(
            manifest.is_current(),
            "ordinary primary directory went stale"
        );
        ensure!(
            manifest.revision == generation.state.revision,
            "primary directory {} lags generation {}",
            manifest.revision,
            generation.state.revision
        );
        crate::application_primary::verify_rows(
            &**store,
            &manifest,
            &generation.state,
            store.plaintext_memory_owner(),
        )?;
        Ok(manifest)
    }
    async fn stop(
        db: Arc<crate::Database>,
        engine: Arc<TenantEngine>,
        audit: Arc<crate::SecurityAudit>,
        fixture: &mut Fixture,
    ) -> crate::test_fixture_failure::FixtureResult<()> {
        db.shutdown().await?;
        drop(db);
        drop(engine);
        audit.shutdown().await?;
        drop(audit);
        fixture.node.shutdown().await?;
        fixture.node = fixture.storage.open_existing(
            fixture._directory.path().join("persistent/node.kv"),
            kasumi_store::test_utils::NODE_STORE_ID,
        )?;
        fixture.stores = TenantStorageSet::open_existing_fixture(
            fixture.node.clone(),
            "selected-sources".into(),
            Arc::new(LocalKeyProvider::new([119; 32])),
            Arc::new(LocalKeyProvider::new([120; 32])),
        )
        .await?;
        Ok(())
    }

    let mut fixture = Fixture::new().await?;
    let group = format!(
        "selected-sources/{}",
        TenantEngine::from_bootstrap("selected-sources", &fixture.image)?
            .generation()?
            .state
            .incarnation
    );
    let first_audit = audit(&fixture.node, &fixture.storage.admission, false).await?;
    let (engine, db) = start(&fixture, &first_audit, &group, true).await?;
    let store = fixture.stores.application().clone();
    let context = kasumi_types::RequestContext {
        authorization: kasumi_types::RequestAuthorization::service_identity(),
        tenant: "selected-sources".into(),
        principal: "owner".into(),
        scopes: std::collections::BTreeSet::from([Action::Admin, Action::Read, Action::Write]),
        request_id: "ordinary-primary-directory".into(),
    };
    // A pristine store records its directory from the first applied entry.
    let initial = current(&engine, &store)?;
    assert_eq!(initial.page_space, primary_manifest::INITIAL_SPACE[0]);
    db.administer(
        context.clone(),
        kasumi_types::Operation::CreateCollection(kasumi_types::CollectionDefinition {
            name: "docs".into(),
            write_mode: kasumi_types::CollectionWriteMode::Mutable,
            retention_class: kasumi_types::CollectionRetentionClass::Operational,
            schema: serde_json::json!({"type": "object"}),
            indexes: vec![],
            strict_read_audit: false,
        }),
    )
    .await?;
    let mutate = |batch: kasumi_types::MutationBatch| {
        let db = db.clone();
        let context = context.clone();
        async move { db.mutate(context, batch).await }
    };
    mutate(
        kasumi_types::MutationBatch::new()
            .upsert("docs", "a", serde_json::json!({"value": 1}))
            .upsert("docs", "b", serde_json::json!({"value": 2})),
    )
    .await?;
    let pinned = engine.generation()?;
    let pinned_manifest = current(&engine, &store)?;
    assert_eq!(pinned_manifest.records.tree, initial.records.tree);
    assert_eq!(pinned_manifest.document_count, 2);
    mutate(
        kasumi_types::MutationBatch::new()
            .upsert("docs", "a", serde_json::json!({"value": 3}))
            .delete("docs", "b")
            .upsert("docs", "c", serde_json::json!({"value": 4})),
    )
    .await?;
    let edited = current(&engine, &store)?;
    assert!(edited.revision > pinned_manifest.revision);
    assert_eq!(edited.records.tree, initial.records.tree);
    // The earlier generation reads its own rows from its pinned root, after
    // the later edit deleted the pages it uses; the current one reads its own.
    let latest = engine.generation()?;
    let point = |generation: &crate::Generation, id: &str| -> Result<Option<u64>> {
        let selection = generation
            .application_selection
            .get()
            .context("generation selection")?;
        Ok(
            match selection
                .primary_point(None, &generation.state, "docs", id, |_| Ok(()))?
                .context("selected generation has no current primary directory")?
            {
                crate::application_records::PrimaryPoint::Live(slot) => Some(slot.version()),
                crate::application_records::PrimaryPoint::Archived(_) => {
                    anyhow::bail!("unexpected archived primary row")
                }
                crate::application_records::PrimaryPoint::Missing => None,
            },
        )
    };
    let versions = |generation: &crate::Generation| -> Result<Vec<Option<u64>>> {
        ["a", "b", "c"]
            .into_iter()
            .map(|id| point(generation, id))
            .collect()
    };
    let resident = |generation: &crate::Generation| -> Vec<Option<u64>> {
        ["a", "b", "c"]
            .into_iter()
            .map(|id| {
                generation.state.collections["docs"]
                    .documents
                    .get(id)
                    .map(|slot| slot.version())
            })
            .collect()
    };
    assert_eq!(versions(&pinned)?, resident(&pinned));
    assert_eq!(versions(&latest)?, resident(&latest));
    assert!(resident(&pinned)[1].is_some());
    assert_eq!(resident(&latest)[1], None);
    drop((pinned, latest));

    // Snapshot, then advance the log beyond it.
    let expected = db
        .raft_group()
        .linearizable_barrier()
        .await?
        .expect("initialized log");
    db.raft_group().snapshot().await?;
    db.raft_group()
        .raft()
        .wait(Some(std::time::Duration::from_secs(20)))
        .snapshot(expected, "primary directory snapshot")
        .await?;
    mutate(
        kasumi_types::MutationBatch::new()
            .upsert("docs", "d", serde_json::json!({"value": 5}))
            .delete("docs", "a"),
    )
    .await?;
    mutate(kasumi_types::MutationBatch::new().upsert("docs", "e", serde_json::json!({"value": 6})))
        .await?;
    let before = current(&engine, &store)?;
    assert!(before.revision > before.revision_base + expected.index);
    stop(db, engine, first_audit, &mut fixture).await?;

    // Reopen restores the older snapshot. Covered replay below the directory
    // publishes nothing, the entry at its revision reproduces it, and later
    // entries edit the same tree.
    let store = fixture.stores.application().clone();
    let kept = PrimaryManifest::load(&store)?.context("reopened directory absent")?;
    assert!(kept.is_current() && kept.revision >= before.revision);
    assert_eq!(kept.records.tree, before.records.tree);
    let second_audit = audit(&fixture.node, &fixture.storage.admission, true).await?;
    let (engine, db) = start(&fixture, &second_audit, &group, false).await?;
    let reopened = current(&engine, &store)?;
    assert_eq!(reopened.records.tree, before.records.tree);
    assert_eq!(reopened.page_space, before.page_space);
    assert!(reopened.revision >= before.revision);
    let mutate = |batch: kasumi_types::MutationBatch| {
        let db = db.clone();
        let context = context.clone();
        async move { db.mutate(context, batch).await }
    };
    mutate(kasumi_types::MutationBatch::new().upsert("docs", "f", serde_json::json!({"value": 7})))
        .await?;
    let continued = current(&engine, &store)?;
    assert_eq!(continued.records.tree, before.records.tree);
    stop(db, engine, second_audit, &mut fixture).await?;

    // A store without a directory, as deployed revisions leave it, rebuilds
    // one from the restored snapshot and replays its tail onto it.
    let store = fixture.stores.application().clone();
    store.write_batch(&[kasumi_store::WriteOp::delete(
        primary_manifest::MANIFESTS,
        primary_manifest::CURRENT,
    )])?;
    assert_eq!(PrimaryManifest::load(&store)?, None);
    let third_audit = audit(&fixture.node, &fixture.storage.admission, true).await?;
    let (engine, db) = start(&fixture, &third_audit, &group, false).await?;
    let rebuilt = current(&engine, &store)?;
    assert_ne!(rebuilt.records.tree, before.records.tree);
    assert_ne!(rebuilt.page_space, before.page_space);
    let generation = engine.generation()?;
    assert_eq!(
        generation.state.collections["docs"]
            .documents
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["c", "d", "e", "f"]
    );
    // An old physical root claims the same revision from a different log
    // history. The serving reader and next ordinary writer must reject it.
    // The monitor recovers at the new committed position while idle.
    let old_versions = versions(&generation)?;
    engine.select_wrong_primary_history_for_test()?;
    db.mutate(
        context,
        kasumi_types::MutationBatch::new().upsert("docs", "c", serde_json::json!({"value":8})),
    )
    .await?;
    let incomplete = engine.generation()?;
    let idle_revision = incomplete.state.revision;
    let incomplete_selection = incomplete.application_selection.get().unwrap();
    assert!(
        incomplete_selection
            .with_primary_records(None, &incomplete.state, |_, _| Ok(()))?
            .is_none()
    );
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            let now = engine.generation()?;
            ensure!(
                now.state.revision == idle_revision,
                "idle repair invented an applied command"
            );
            if now
                .application_selection
                .get()
                .unwrap()
                .with_primary_records(None, &now.state, |_, _| Ok(()))?
                .is_some()
            {
                ensure!(
                    versions(&now)? == resident(&now),
                    "idle primary rows differ"
                );
                break Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .context("idle primary worker timed out")??;
    assert!(
        incomplete_selection
            .with_primary_records(None, &incomplete.state, |_, _| Ok(()))?
            .is_none()
    );
    assert_eq!(versions(&generation)?, old_versions);
    drop(incomplete);
    drop(generation);
    db.shutdown().await?;
    drop(db);
    drop(engine);
    third_audit.shutdown().await?;
    drop(third_audit);
    fixture.close().await
}

#[path = "document_store_native_tests.rs"]
mod document_store_native_tests;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
async fn text_directory_serves_writes_snapshot_reopen_and_retained_readers()
-> crate::test_fixture_failure::FixtureResult<()> {
    use kasumi_store::text_manifest::TextManifest;
    async fn audit(
        node: &kasumi_store::NodeStore,
        admission: &Arc<NodeAdmission>,
        existing: bool,
    ) -> crate::test_fixture_failure::FixtureResult<Arc<crate::SecurityAudit>> {
        let key = Arc::new(LocalKeyProvider::new([121; 32]));
        Ok(if existing {
            let store = kasumi_store::TenantStore::open_existing_fixture(
                node.clone(),
                crate::SECURITY_TENANT.into(),
                key,
            )
            .await?;
            crate::SecurityAudit::open(store, Default::default(), admission.clone())?
        } else {
            let store = kasumi_store::TenantStore::initialize_catalog_fixture(
                node.clone(),
                crate::SECURITY_TENANT.into(),
                key,
            )
            .await?;
            crate::SecurityAudit::initialize(store, Default::default(), admission.clone())?
        })
    }
    async fn search(
        db: &crate::Database,
        context: &kasumi_types::RequestContext,
        query: &str,
    ) -> crate::test_fixture_failure::FixtureResult<Vec<String>> {
        let response = db
            .query(
                context,
                kasumi_types::QueryRequest::new("docs")
                    .search(kasumi_types::TextSearch::new("text", query)),
            )
            .await?;
        let mut ids: Vec<String> = response
            .as_ref()
            .rows
            .iter()
            .map(|row| row.id.clone())
            .collect();
        ids.sort();
        Ok(ids)
    }
    fn search_generation(
        generation: &Arc<crate::Generation>,
        admission: &Arc<NodeAdmission>,
        query: &str,
    ) -> crate::test_fixture_failure::FixtureResult<Vec<String>> {
        let mut memory = kasumi_query::QueryMemory::empty(admission.reserve(0, None)?);
        let request = kasumi_types::QueryRequest::new("docs")
            .search(kasumi_types::TextSearch::new("text", query));
        let response = crate::test_utils::fixture_query(generation, &request, &mut memory)?;
        let mut ids: Vec<String> = response.rows.into_iter().map(|row| row.id).collect();
        ids.sort();
        Ok(ids)
    }

    // This replicated fixture keeps databases and disk owners live beside the
    // three work reserves that optional text cache leases must preserve.
    let mut source = Fixture::with_admission(1, None, |mut config| {
        let total = config
            .max_inflight_bytes
            .context("fixture admission cap absent")?;
        let (work, _) = config.cache_work_headroom(total);
        config.max_inflight_bytes = Some(
            total
                .checked_add(work)
                .context("text fixture cap overflow")?,
        );
        NodeAdmission::new_fixture(config)
    })
    .await?;
    let admission = &source.storage.admission;
    let (work, _) = admission.policy().cache_work_headroom(source.budget);
    // Withhold only that additional grant until the real monitor reports its
    // capacity decision. The running sampler remains healthy through both phases.
    let constrained = admission.reserve_resident(work)?;
    let source_audit = audit(&source.node, &source.storage.admission, false).await?;
    crate::test_utils::install_fixture_audit_placement(source.stores.application())?;
    let engine = Arc::new(TenantEngine::from_bootstrap(
        "selected-sources",
        &source.image,
    )?);
    engine.install_storage_access(source.stores.application())?;
    let group = format!(
        "selected-sources/{}",
        engine.generation()?.state.incarnation
    );
    let db = crate::service::construction::DatabaseConstruction::new(
        source.stores.clone(),
        source_audit.clone(),
    )?
    .start_replicated(
        engine.clone(),
        &source.image,
        1,
        group.clone(),
        Arc::new(kasumi_raft::InProcessRouter::default()),
        Default::default(),
    )
    .await?;
    db.raft_group()
        .initialize(std::collections::BTreeMap::from([(
            1,
            kasumi_raft::BasicNode::new("text-source"),
        )]))
        .await?;
    db.raft_group()
        .raft()
        .wait(Some(std::time::Duration::from_secs(10)))
        .current_leader(1, "text directory leader")
        .await?;
    let context = kasumi_types::RequestContext {
        authorization: kasumi_types::RequestAuthorization::service_identity(),
        tenant: "selected-sources".into(),
        principal: "owner".into(),
        scopes: std::collections::BTreeSet::from([Action::Admin, Action::Read, Action::Write]),
        request_id: "text-directory".into(),
    };
    db.administer(
        context.clone(),
        kasumi_types::Operation::CreateCollection(kasumi_types::CollectionDefinition {
            name: "docs".into(),
            write_mode: kasumi_types::CollectionWriteMode::Mutable,
            retention_class: kasumi_types::CollectionRetentionClass::Operational,
            schema: serde_json::json!({"type": "object"}),
            indexes: vec![kasumi_types::IndexDefinition {
                name: "text".into(),
                fields: vec![kasumi_types::IndexField {
                    path: "/title".into(),
                    kind: kasumi_types::ScalarType::String,
                }],
                unique: false,
                text: Some(kasumi_types::TextIndex {
                    analyzer: kasumi_types::Analyzer::UnicodeV1,
                }),
            }],
            strict_read_audit: false,
        }),
    )
    .await?;
    for (id, title) in [("a", "alpha shared"), ("b", "beta shared")] {
        db.mutate(
            context.clone(),
            kasumi_types::MutationBatch::new().upsert(
                "docs",
                id,
                serde_json::json!({ "title": title }),
            ),
        )
        .await?;
    }
    // Prove the registered idle worker reaches the published shard set before
    // the first text query has any opportunity to populate it on demand.
    let revision = engine.generation()?.revision();
    tokio::time::timeout(std::time::Duration::from_secs(45), async {
        loop {
            let progress = db.text_warmup_status();
            if progress.revision == Some(revision)
                && progress.state == crate::TextWarmupState::CapacityLimited
                && progress.visited_shards == 0
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    })
    .await
    .context("text warmup did not observe the held cache work reserve")?;
    let snapshot = admission.snapshot();
    eprintln!(
        "idle text warmup constrained revision={revision} charged={} cap={} work_reserve={work} usable={} pressured={}",
        snapshot.reserved_bytes,
        admission.policy().max_inflight_bytes.unwrap(),
        snapshot.sample_usable,
        snapshot.pressured
    );
    drop(constrained);
    tokio::time::timeout(std::time::Duration::from_secs(45), async {
        loop {
            let progress = db.text_warmup_status();
            if progress.revision == Some(revision)
                && progress.state == crate::TextWarmupState::Complete
                && progress.visited_shards == 2
                && progress.skipped_shards == 0
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    })
    .await
    .with_context(|| format!(
        "selected text warmup did not complete before the first search: expected {revision}, observed {:?}, sample usable = {}, pressure = {}",
        db.text_warmup_status(), source.storage.admission.snapshot().sample_usable,
        source.storage.admission.snapshot().pressured
    ))?;
    let before_search = source
        .storage
        .admission
        .snapshot()
        .resident_reserved_bytes_by_origin
        .text_shard_cache;
    assert!(before_search > 0);
    assert_eq!(search(&db, &context, "shared").await?, ["a", "b"]);
    let generation = engine.generation()?;
    // Ordinary writes keep the directory current at every published revision
    // and build no resident text index.
    assert_eq!(
        generation.indexes.text_residency(),
        kasumi_query::TextResidency::Directory
    );
    let manifest = TextManifest::load(source.stores.application())?.unwrap();
    assert!(manifest.is_current());
    assert_eq!(manifest.revision, generation.state.revision);
    drop(generation);

    let expected = db
        .raft_group()
        .linearizable_barrier()
        .await?
        .expect("initialized text log");
    db.raft_group().snapshot().await?;
    db.raft_group()
        .raft()
        .wait(Some(std::time::Duration::from_secs(10)))
        .snapshot(expected, "text directory snapshot")
        .await?;
    // Entries after the snapshot replay as covered publications on reopen.
    db.mutate(
        context.clone(),
        kasumi_types::MutationBatch::new()
            .upsert("docs", "a", serde_json::json!({"title": "gamma shared"}))
            .delete("docs", "b"),
    )
    .await?;
    assert_eq!(search(&db, &context, "shared").await?, ["a"]);
    assert!(search(&db, &context, "alpha").await?.is_empty());
    assert!(search(&db, &context, "beta").await?.is_empty());

    // A retained generation keeps searching its own revision after later
    // writes edit the directory.
    let retained = engine.generation()?;
    db.mutate(
        context.clone(),
        kasumi_types::MutationBatch::new().upsert(
            "docs",
            "c",
            serde_json::json!({"title": "delta shared"}),
        ),
    )
    .await?;
    assert_eq!(search(&db, &context, "shared").await?, ["a", "c"]);
    assert_eq!(
        search_generation(&retained, &source.storage.admission, "shared")?,
        ["a"]
    );
    assert!(search_generation(&retained, &source.storage.admission, "delta")?.is_empty());
    drop(retained);
    let before = TextManifest::load(source.stores.application())?.unwrap();

    // Installing the snapshot on another node rebuilds its directory from the
    // snapshot's staged bodies at exactly the snapshot revision.
    let snapshot = db
        .raft_group()
        .raft()
        .get_snapshot()
        .await?
        .expect("durable text snapshot");
    let vote = kasumi_raft::ControlLog::open(source.stores.custody().clone(), 1, group.clone())?
        .read_vote()?
        .expect("text source vote");
    let target = Fixture::with_bootstrap(2, Some(&source.image)).await?;
    let target_audit = audit(&target.node, &target.storage.admission, false).await?;
    crate::test_utils::install_fixture_audit_placement(target.stores.application())?;
    let target_engine = Arc::new(TenantEngine::from_bootstrap(
        "selected-sources",
        &target.image,
    )?);
    target_engine.install_storage_access(target.stores.application())?;
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
    target_db
        .raft_group()
        .raft()
        .install_full_snapshot(vote, snapshot)
        .await?;
    let installed = target_engine.generation()?;
    assert_eq!(
        installed.indexes.text_residency(),
        kasumi_query::TextResidency::Directory
    );
    let rebuilt = TextManifest::load(target.stores.application())?.unwrap();
    assert!(rebuilt.is_current());
    assert_eq!(rebuilt.revision, installed.state.revision);
    assert_eq!(rebuilt.shards, 1);
    assert_eq!(
        search_generation(&installed, &target.storage.admission, "shared")?,
        ["a", "b"]
    );
    assert_eq!(
        search_generation(&installed, &target.storage.admission, "beta")?,
        ["b"]
    );
    drop(installed);
    target_db.shutdown().await?;
    drop(target_db);
    drop(target_engine);
    target_audit.shutdown().await?;
    drop(target_audit);
    target.close().await?;

    db.shutdown().await?;
    drop(db);
    drop(engine);
    source_audit.shutdown().await?;
    drop(source_audit);
    source.stores.shutdown().await?;
    source.node.shutdown().await?;

    // Reopen the encrypted store: the directory is current ahead of the
    // snapshot, so it is kept and serves without rebuilding.
    source.node = source.storage.open_existing(
        source._directory.path().join("persistent/node.kv"),
        kasumi_store::test_utils::NODE_STORE_ID,
    )?;
    source.stores = TenantStorageSet::open_existing_fixture(
        source.node.clone(),
        "selected-sources".into(),
        Arc::new(LocalKeyProvider::new([119; 32])),
        Arc::new(LocalKeyProvider::new([120; 32])),
    )
    .await?;
    let reopened_audit = audit(&source.node, &source.storage.admission, true).await?;
    crate::test_utils::install_fixture_audit_placement(source.stores.application())?;
    let engine = Arc::new(TenantEngine::from_bootstrap(
        "selected-sources",
        &source.image,
    )?);
    engine.install_storage_access(source.stores.application())?;
    let db = crate::service::construction::DatabaseConstruction::new(
        source.stores.clone(),
        reopened_audit.clone(),
    )?
    .start_replicated(
        engine.clone(),
        &source.image,
        1,
        group,
        Arc::new(kasumi_raft::InProcessRouter::default()),
        Default::default(),
    )
    .await?;
    db.raft_group()
        .raft()
        .wait(Some(std::time::Duration::from_secs(10)))
        .current_leader(1, "reopened text directory leader")
        .await?;
    let reopened = engine.generation()?;
    assert_eq!(
        reopened.indexes.text_residency(),
        kasumi_query::TextResidency::Directory
    );
    let kept = TextManifest::load(source.stores.application())?.unwrap();
    assert_eq!(kept.page_space, before.page_space);
    assert_eq!(kept.records.tree, before.records.tree);
    assert!(kept.is_current() && kept.revision >= before.revision);
    drop(reopened);
    assert_eq!(search(&db, &context, "shared").await?, ["a", "c"]);
    assert_eq!(search(&db, &context, "gamma").await?, ["a"]);
    assert!(search(&db, &context, "beta").await?.is_empty());

    db.mutate(
        context.clone(),
        kasumi_types::MutationBatch::new().upsert(
            "docs",
            "d",
            serde_json::json!({"title": "epsilon shared"}),
        ),
    )
    .await?;
    assert_eq!(search(&db, &context, "shared").await?, ["a", "c", "d"]);
    let latest = engine.generation()?;
    let manifest = TextManifest::load(source.stores.application())?.unwrap();
    assert!(manifest.is_current());
    assert_eq!(manifest.revision, latest.state.revision);
    assert_eq!(manifest.page_space, before.page_space);
    // The installed selector stays at this entry while the secondary alone
    // receives an empty current directory from another log, command, or a
    // legacy manifest without history. Cached shards cannot supply that view.
    let boundary = manifest.boundary.expect("ordinary text directory history");
    let mut wrong_log = boundary.clone();
    let mut wrong_command = boundary;
    let kasumi_store::text_manifest::TextBoundary::Applied { log_sha256, .. } = &mut wrong_log
    else {
        panic!("expected text entry position");
    };
    log_sha256[0] ^= 1;
    let kasumi_store::text_manifest::TextBoundary::Applied {
        command_sha256: Some(command),
        ..
    } = &mut wrong_command
    else {
        panic!("expected text command digest");
    };
    command[0] ^= 1;
    for foreign in [Some(wrong_log), Some(wrong_command), None] {
        engine.substitute_text_history_for_test(foreign)?;
        let denied = db
            .query(
                &context,
                kasumi_types::QueryRequest::new("docs")
                    .search(kasumi_types::TextSearch::new("text", "shared")),
            )
            .await
            .expect_err("foreign text directory refused");
        assert_eq!(denied.code, kasumi_types::ErrorCode::Unavailable);
        assert_eq!(
            search_generation(&latest, &source.storage.admission, "shared")?,
            ["a", "c", "d"]
        );
    }
    tokio::time::timeout(std::time::Duration::from_secs(45), async {
        loop {
            let progress = db.text_warmup_status();
            if progress.revision == Some(latest.revision())
                && progress.state == crate::TextWarmupState::DirectoryUnavailable
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    })
    .await
    .context("text warmup accepted the unbound selection")?;
    for current in [false, true] {
        db.administer(
            context.clone(),
            kasumi_types::Operation::SetLimits(latest.state.limits.clone()),
        )
        .await?;
        let stored = TextManifest::load(source.stores.application())?.unwrap();
        assert_eq!(stored.is_current(), current);
        let selection = engine.generation()?;
        let expected = selection
            .application_selection
            .get()
            .unwrap()
            .text_boundary()?
            .unwrap();
        assert!(stored.matches(&expected));
    }
    assert_eq!(search(&db, &context, "shared").await?, ["a", "c", "d"]);
    drop(latest);

    db.shutdown().await?;
    drop(db);
    drop(engine);
    reopened_audit.shutdown().await?;
    drop(reopened_audit);
    source.close().await
}

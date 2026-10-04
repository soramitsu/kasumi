use super::*;
use crate::admission::snapshot_work::{
    SnapshotObservation, SnapshotPanicPhase, SnapshotPreparationFailure,
};
use crate::admission::{AdmissionConfig, NodeAdmission, WorkFence};
use crate::document_source::GenerationDocumentSource;
use crate::{Generation, TenantEngine};
use kasumi_query::{
    CollectionRecords, Header, QueryIndexes, QueryMemory, ReadResult, Record, SourceIdentity,
};
use kasumi_store::{
    NodeDiskMemoryAdmission, NodeScopedReadFailure, NodeStore, StorageAccess, TenantReadView,
    TenantStore, WriteOp,
};
use kasumi_types::{
    Action, CollectionDefinition, CollectionRetentionClass, CollectionState, CollectionWriteMode,
    Document, Error, ErrorCode, Grant, Policy, QueryRequest,
};
use serde_json::json;
use std::{
    collections::BTreeMap,
    future::Future,
    sync::{
        Condvar, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

struct Fixture {
    store: Arc<TenantStore>,
    node: Arc<NodeStore>,
    physical: crate::test_utils::FixtureStorage,
    generation: Arc<Generation>,
    max_bytes: u64,
    _directory: tempfile::TempDir,
}
impl Fixture {
    async fn new() -> Arc<Self> {
        Self::with_probe(None).await
    }
    async fn with_probe(
        probe: Option<(
            Arc<dyn crate::admission::MemorySource>,
            Arc<dyn kasumi_clock::LeaseClock>,
        )>,
    ) -> Arc<Self> {
        let directory = kasumi_store::test_utils::private_tempdir().unwrap();
        let (persistent, scratch) =
            crate::test_utils::fixture_disk_configs(directory.path()).unwrap();
        let config = crate::test_utils::isolated_disk_admission_config(
            AdmissionConfig {
                high_water_bytes: Some(1 << 30),
                low_water_bytes: Some(900 << 20),
                max_inflight_bytes: Some(128 << 20),
                max_inflight_operations: 1,
                max_reservations: 128,
                max_snapshot_startups: 2,
                max_startup_scopes: 2,
                ..Default::default()
            },
            &persistent,
            &scratch,
        )
        .unwrap();
        let max_bytes = config.max_inflight_bytes.unwrap();
        let admission = match probe {
            Some((probe, clock)) => NodeAdmission::create(config, 1 << 30, probe, clock).unwrap(),
            None => NodeAdmission::with_fixed_memory(config, 1 << 30, 0).unwrap(),
        };
        let physical =
            crate::test_utils::FixtureStorage::with_admission(&persistent, &scratch, admission)
                .unwrap();
        let node = physical
            .create_new(
                directory.path().join("persistent/node.kv"),
                kasumi_store::test_utils::NODE_STORE_ID,
            )
            .unwrap();
        let store = TenantStore::initialize_catalog(
            node.clone(),
            crate::SECURITY_TENANT.into(),
            Arc::new(kasumi_store::test_utils::LocalKeyProvider::new([49; 32])),
            StorageAccess::security_audit(),
        )
        .await
        .unwrap();
        let document = Document {
            id: "a".into(),
            version: 7,
            body: json!({"actual_disk_body": "x".repeat(4096)}),
        };
        store
            .write_batch(&[WriteOp::put(
                "docs",
                b"a",
                serde_json::to_vec(&document).unwrap(),
            )])
            .unwrap();
        let engine = TenantEngine::new(
            "tenant".into(),
            "incarnation".into(),
            Policy {
                grants: vec![Grant {
                    principal: "owner".into(),
                    collection: None,
                    actions: [Action::Admin].into_iter().collect(),
                }],
                strict_read_audit: false,
            },
            Limits::default(),
        )
        .unwrap();
        let collection = CollectionState {
            definition: CollectionDefinition {
                name: "docs".into(),
                write_mode: CollectionWriteMode::Mutable,
                retention_class: CollectionRetentionClass::Operational,
                schema: json!({"type": "object"}),
                indexes: vec![],
                strict_read_audit: false,
            },
            data_epoch: 7,
            documents: [("a".to_owned(), Arc::new(document))].into_iter().collect(),
            archived_documents: Default::default(),
            archived_document_bytes: 0,
        };
        let mut generation = engine
            .generation()
            .unwrap()
            .read_view(BTreeMap::from([("docs".into(), collection)]), vec![]);
        generation.state.revision = 7;
        generation.state.limits.max_query_candidates = 4;
        generation.state.limits.max_query_groups = 4;
        generation.state.limits.max_result_bytes = 32 << 10;
        generation.indexes = Arc::new(crate::index_source::build(&generation.state).unwrap());
        Arc::new(Self {
            store,
            node,
            physical,
            generation: Arc::new(generation),
            max_bytes,
            _directory: directory,
        })
    }
    fn admission(&self) -> &Arc<NodeAdmission> {
        &self.physical.admission
    }
    async fn close(&self) {
        self.store.shutdown().await.unwrap();
        self.node.shutdown().await.unwrap();
    }
}

#[derive(Default)]
struct Gate {
    started: AtomicBool,
    released: Mutex<bool>,
    wake: Condvar,
    hold: bool,
    reads: AtomicUsize,
    cleanup_calls: AtomicUsize,
    cleanup_ready: AtomicBool,
    read_failure_address: AtomicUsize,
    close_failure_address: AtomicUsize,
    panic_address: AtomicUsize,
}
impl Gate {
    async fn started(&self) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while !self.started.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }
    fn wait(&self) {
        self.started.store(true, Ordering::Release);
        if self.hold {
            drop(
                self.wake
                    .wait_while(self.released.lock().unwrap(), |released| !*released)
                    .unwrap(),
            );
        }
    }
    fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.wake.notify_all();
    }
}
#[derive(Clone, Copy)]
enum Mode {
    Read,
    BoundExceeded,
    PanicAfterRead,
}
#[derive(Debug)]
struct SourceFailure(anyhow::Error);
impl std::fmt::Display for SourceFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}
impl StdError for SourceFailure {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(self.0.as_ref())
    }
}
#[derive(Debug)]
struct ActualWorkerPanic(u64);

// Test adapter reads and decodes the actual encrypted record for each loan.
// Only its one-row logical header/index directory is resident fixture metadata;
// this does not introduce a production disk source or claim source accounting.
struct DiskSource {
    view: Option<TenantReadView>,
    selected: GenerationDocumentSource,
    gate: Arc<Gate>,
    mode: Mode,
}
impl CollectionRecords for DiskSource {
    type Failure = SourceFailure;
    fn identity(&self) -> SourceIdentity<'_> {
        SourceIdentity::new(self, "tenant", "incarnation", "docs")
    }
    fn definition(&self) -> &CollectionDefinition {
        self.selected.definition()
    }
    fn visit_records(
        &self,
        mut lend: impl for<'a> FnMut(&'a str, Record<'a>) -> kasumi_types::Result<()>,
    ) -> ReadResult<(), Self::Failure> {
        self.with_record("a", Some(7), &QueryCancellation::default(), |record| {
            lend("a", record.expect("fixture record"))
        })
    }
}
impl DocumentSource for DiskSource {
    fn indexes(&self) -> &QueryIndexes {
        self.selected.indexes()
    }
    fn with_record<T>(
        &self,
        id: &str,
        expected_version: Option<u64>,
        token: &QueryCancellation,
        lend: impl for<'a> FnOnce(Option<Record<'a>>) -> kasumi_types::Result<T>,
    ) -> ReadResult<T, Self::Failure> {
        token.check()?;
        let bytes = self.view.as_ref().expect("selected source").get(
            "docs",
            id.as_bytes(),
            if matches!(self.mode, Mode::BoundExceeded) {
                1
            } else {
                32 << 10
            },
        );
        self.gate.reads.fetch_add(1, Ordering::AcqRel);
        // Gate after the real source operation: cancellation cannot erase an
        // already-produced original native failure or its child custody.
        if let Err(error) = &bytes {
            let failure = error
                .downcast_ref::<NodeScopedReadFailure>()
                .expect("original registered native failure");
            self.gate
                .read_failure_address
                .store(std::ptr::from_ref(failure) as usize, Ordering::Release);
        }
        self.gate.wait();
        let bytes = bytes.map_err(|error| ReadFailure::Source(SourceFailure(error)))?;
        if matches!(self.mode, Mode::PanicAfterRead) {
            let payload = Box::new(ActualWorkerPanic(713));
            self.gate.panic_address.store(
                std::ptr::from_ref(payload.as_ref()) as usize,
                Ordering::Release,
            );
            std::panic::resume_unwind(payload);
        }
        token.check()?;
        let document = bytes
            .map(|bytes| serde_json::from_slice::<Document>(&bytes))
            .transpose()
            .map_err(|error| ReadFailure::Source(SourceFailure(error.into())))?;
        if document.as_ref().is_some_and(|document| document.id != id)
            || expected_version.is_some_and(|version| {
                document
                    .as_ref()
                    .is_none_or(|document| document.version != version)
            })
        {
            return Err(Error::new(ErrorCode::Corruption, "fixture source version differs").into());
        }
        let result = lend(document.as_ref().map(Record::Live))?;
        token.check()?;
        Ok(result)
    }
    fn header_after<T>(
        &self,
        after: Option<&str>,
        token: &QueryCancellation,
        lend: impl for<'a> FnOnce(Option<Header<'a>>) -> kasumi_types::Result<T>,
    ) -> ReadResult<T, Self::Failure> {
        self.selected
            .header_after(after, token, lend)
            .map_err(|error| ReadFailure::Query(error.into_query_error()))
    }
}
struct DiskOwner {
    source: Option<DiskSource>,
    close_failure: Option<SourceFailure>,
    // Keep the physical fixture/private directories alive on retained failure.
    fixture: Arc<Fixture>,
    gate: Arc<Gate>,
}
impl QuerySourceOwner for DiskOwner {
    type Source = DiskSource;
    fn source(&self) -> &DiskSource {
        self.source.as_ref().expect("active source")
    }
    fn validate_memory(&self, core: &Arc<MemoryCore>) -> anyhow::Result<()> {
        let expected: Arc<dyn NodeDiskMemoryAdmission> = core.clone();
        anyhow::ensure!(
            Arc::ptr_eq(self.fixture.physical.persistent.memory(), &expected),
            "source persistent provider differs"
        );
        anyhow::ensure!(
            Arc::ptr_eq(self.fixture.physical.scratch.memory(), &expected),
            "source scratch provider differs"
        );
        Ok(())
    }
    fn backing_bytes(&self) -> anyhow::Result<u64> {
        // Fixed gate/error envelope plus the fixture's bounded 32 KiB encoded
        // read and one known 4 KiB String/object decode loan. This is a local
        // component-test bound, not an arbitrary JSON/failure payload quote.
        // Native read owners/diagnostics additionally keep actual installed
        // provider reservations. The quote precedes every source get/decode.
        Ok(64 << 10)
    }
    fn poll_cleanup(&mut self, _: &mut Context<'_>) -> Poll<DrainCompletion> {
        self.gate.cleanup_calls.fetch_add(1, Ordering::AcqRel);
        if !self.gate.cleanup_ready.load(Ordering::Acquire) {
            return Poll::Ready(DrainCompletion::Retained);
        }
        if self.close_failure.is_some() {
            return Poll::Ready(DrainCompletion::Retained);
        }
        if let Some(source) = self.source.as_mut()
            && let Some(view) = source.view.take()
            && let Err(error) = view.close()
        {
            let failure = error
                .downcast_ref::<NodeScopedReadFailure>()
                .expect("original explicit close report");
            self.gate
                .close_failure_address
                .store(std::ptr::from_ref(failure) as usize, Ordering::Release);
            self.close_failure = Some(SourceFailure(error));
            return Poll::Ready(DrainCompletion::Retained);
        }
        drop(self.source.take());
        Poll::Ready(DrainCompletion::Complete)
    }
    fn visit_diagnostics(&self, visit: &mut dyn FnMut(&(dyn StdError + 'static))) {
        if let Some(error) = &self.close_failure {
            visit(error);
        }
    }
}
fn plan(
    fixture: &Arc<Fixture>,
    mode: Mode,
    hold: bool,
) -> (
    QuerySourcePlan<DiskOwner>,
    Arc<Gate>,
    QueryCancellation,
    Arc<WorkFence>,
) {
    let gate = Arc::new(Gate {
        hold,
        cleanup_ready: AtomicBool::new(true),
        ..Default::default()
    });
    let token = QueryCancellation::default();
    let fence = Arc::new(WorkFence::default());
    let registration = Arc::new(fence.begin(token.clone()).unwrap());
    let view = fixture.store.read_view().unwrap();
    assert!(
        view.registered_reader_id().is_some(),
        "actual installed registered read path"
    );
    let source = DiskSource {
        view: Some(view),
        selected: fixture.generation.document_source("docs").unwrap(),
        gate: gate.clone(),
        mode,
    };
    let source = DiskOwner {
        source: Some(source),
        close_failure: None,
        fixture: fixture.clone(),
        gate: gate.clone(),
    };
    let request: QueryRequest =
        serde_json::from_value(json!({"collection": "docs", "allow_scan": true, "limit": 1}))
            .unwrap();
    let mut input = QueryInput {
        request,
        memory: QueryMemory::empty(
            fixture
                .admission()
                .reserve(64 << 10, Some(token.clone()))
                .unwrap(),
        ),
    };
    input
        .memory
        .reserve(super::super::query_input_workspace(&input.request, 1).unwrap())
        .unwrap();
    let permit = Arc::new(tokio::sync::Semaphore::new(1))
        .try_acquire_owned()
        .unwrap();
    (
        QuerySourcePlan {
            source,
            limits: fixture.generation.state.limits.clone(),
            input,
            permit,
            registration,
        },
        gate,
        token,
        fence,
    )
}
async fn cleanup_rejected(mut plan: QuerySourcePlan<DiskOwner>) {
    assert_eq!(
        std::future::poll_fn(|cx| plan.source.poll_cleanup(cx)).await,
        DrainCompletion::Complete
    );
    drop(plan);
}
async fn fence_pending(fence: &WorkFence) {
    let mut waiting = Box::pin(fence.drain());
    assert!(
        std::future::poll_fn(|cx| Poll::Ready(waiting.as_mut().poll(cx)))
            .await
            .is_pending()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn existing_grant_query_uses_one_operation_plus_one_metadata_slot_and_claims_after_close() {
    let fixture = Fixture::new().await;
    let (plan, gate, token, fence) = plan(&fixture, Mode::Read, false);
    let admitted = fixture.admission().snapshot();
    assert_eq!(admitted.inflight_operations, 1);
    let work = match fixture
        .admission()
        .prepare_snapshot_work_from_existing::<QuerySourceWork<DiskOwner>>(plan)
    {
        Ok(work) => work,
        Err(_) => panic!("existing last operation must prepare"),
    };
    let prepared = fixture.admission().snapshot();
    assert_eq!(prepared.inflight_operations, 1);
    assert_eq!(prepared.live_reservations, admitted.live_reservations + 1);
    assert!(prepared.reserved_bytes > admitted.reserved_bytes);
    assert!(
        fixture.admission().reserve(1, None).is_err(),
        "operation limit remains saturated"
    );
    assert!(work.claim().is_err(), "unstarted source is not cleaned up");
    gate.cleanup_ready.store(false, Ordering::Release);
    work.start().unwrap();
    let pending_close = work.ready().await;
    assert_eq!(pending_close.completion(), DrainCompletion::Retained);
    assert!(
        work.claim().is_err(),
        "completed output cannot escape unacknowledged source cleanup"
    );
    fence_pending(&fence).await;
    gate.cleanup_ready.store(true, Ordering::Release);
    let ready = work.ready().await;
    drop(pending_close);
    assert!(gate.reads.load(Ordering::Acquire) > 0);
    assert!(gate.cleanup_calls.load(Ordering::Acquire) > 0);
    let mut output = work
        .claim()
        .unwrap_or_else(|_| panic!("positive source close permits claim"))
        .into_output();
    assert_eq!(
        output.response.as_ref().unwrap().0.rows[0].body,
        json!({"actual_disk_body": "x".repeat(4096)})
    );
    fence_pending(&fence).await;
    drop(work);
    assert!(
        !token.is_cancelled(),
        "successful adopted claim transfers cancellation authority"
    );
    assert_eq!(ready.drain().await.completion(), DrainCompletion::Complete);
    drop(ready);
    assert!(
        !token.is_cancelled(),
        "stale report has no post-claim cancellation authority"
    );
    // Force provider consultation even if spare logical peak remains, and
    // exercise a real next-stage page clone under the claimed grant.
    let response = &output.response.as_ref().unwrap().0;
    let page_bytes =
        kasumi_query::query_response_clone_bytes(response, 0..response.rows.len()).unwrap();
    let growth = output
        .memory
        .peak_bytes()
        .checked_sub(output.memory.live_bytes())
        .unwrap()
        .checked_add(page_bytes)
        .unwrap();
    output.memory.reserve(growth).unwrap();
    let page = response.clone();
    assert_eq!(
        page.rows[0].body,
        json!({"actual_disk_body": "x".repeat(4096)})
    );
    drop(page);
    output.memory.release(growth).unwrap();
    token.cancel();
    let ledger = (output.memory.live_bytes(), output.memory.peak_bytes());
    let growth = ledger
        .1
        .checked_sub(ledger.0)
        .unwrap()
        .checked_add(1)
        .unwrap();
    assert_eq!(
        output.memory.reserve(growth).unwrap_err().code,
        ErrorCode::ResourceExhausted
    );
    assert_eq!(
        (output.memory.live_bytes(), output.memory.peak_bytes()),
        ledger
    );
    assert_eq!(
        fixture.admission().snapshot().inflight_operations,
        1,
        "claimed output owns original grant"
    );
    drop(output);
    fence.drain().await;
    assert_eq!(fixture.admission().snapshot().inflight_operations, 0);
    fixture.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn canceled_waiter_keeps_original_native_read_and_explicit_close_failure() {
    let fixture = Fixture::new().await;
    let (plan, gate, token, fence) = plan(&fixture, Mode::BoundExceeded, true);
    let reader = plan
        .source
        .source()
        .view
        .as_ref()
        .unwrap()
        .registered_reader_id()
        .unwrap();
    let work = fixture
        .admission()
        .prepare_snapshot_work_from_existing::<QuerySourceWork<DiskOwner>>(plan)
        .unwrap_or_else(|_| panic!("prepare"));
    let id = work.id();
    work.start().unwrap();
    gate.started().await;
    let mut waiting = Box::pin(work.ready());
    assert!(
        std::future::poll_fn(|cx| Poll::Ready(waiting.as_mut().poll(cx)))
            .await
            .is_pending()
    );
    drop(waiting);
    drop(work);
    assert!(token.is_cancelled(), "same original operation cancellation");
    let report = fixture
        .admission()
        .memory()
        .snapshot_work_at(id.slot)
        .unwrap();
    assert_eq!(report.id(), id);
    let mut draining = Box::pin(report.drain());
    assert!(
        std::future::poll_fn(|cx| Poll::Ready(draining.as_mut().poll(cx)))
            .await
            .is_pending()
    );
    drop(draining);
    assert_eq!(gate.cleanup_calls.load(Ordering::Acquire), 0);
    fence_pending(&fence).await;
    gate.release();
    let retained = report.drain().await;
    assert_eq!(retained.completion(), DrainCompletion::Retained);
    let mut saw_read = false;
    let mut saw_close = false;
    retained.visit(|observation| match observation {
        SnapshotObservation::Failure(error) => {
            let source = error.downcast_ref::<SourceFailure>().unwrap();
            let original = source.0.downcast_ref::<NodeScopedReadFailure>().unwrap();
            assert_eq!(original.reader_id(), reader);
            assert!(matches!(
                original.report().read_failure(),
                kasumi_kv::TerminalObservation::Returned(Err(
                    kasumi_kv::BoundedReadError::BoundExceeded
                ))
            ));
            assert_eq!(
                std::ptr::from_ref(original) as usize,
                gate.read_failure_address.load(Ordering::Acquire)
            );
            assert_eq!(original.stage(), "view read");
            saw_read = true;
        }
        SnapshotObservation::Diagnostic(error) => {
            let source = error.downcast_ref::<SourceFailure>().unwrap();
            let original = source.0.downcast_ref::<NodeScopedReadFailure>().unwrap();
            assert_eq!(original.reader_id(), reader);
            assert!(matches!(
                original.report().read_failure(),
                kasumi_kv::TerminalObservation::Returned(Err(
                    kasumi_kv::BoundedReadError::BoundExceeded
                ))
            ));
            assert_eq!(
                std::ptr::from_ref(original) as usize,
                gate.close_failure_address.load(Ordering::Acquire)
            );
            // Explicit close reports the already-failed native body. This is
            // not an injected physical close fault or a successful retirement.
            assert_eq!(original.stage(), "body");
            saw_close = true;
        }
        _ => {}
    });
    assert!(saw_read && saw_close);
    assert_eq!(report.drain().await.completion(), DrainCompletion::Retained);
    assert_eq!(fixture.admission().snapshot().inflight_operations, 1);
    fence_pending(&fence).await;
    // Deliberately retained: no forced census reset, error erasure, source
    // shutdown or private-directory deletion while native custody remains.
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn worker_unwind_retains_actual_view_registration_and_original_payload() {
    let fixture = Fixture::new().await;
    let (plan, gate, _, fence) = plan(&fixture, Mode::PanicAfterRead, false);
    let work = fixture
        .admission()
        .prepare_snapshot_work_from_existing::<QuerySourceWork<DiskOwner>>(plan)
        .unwrap_or_else(|_| panic!("prepare"));
    let id = work.id();
    work.start().unwrap();
    let report = work.ready().await;
    drop(work);
    assert_eq!(report.drain().await.completion(), DrainCompletion::Retained);
    let mut saw_panic = false;
    report.visit(|observation| {
        if let SnapshotObservation::Panic { phase, payload } = observation {
            assert_eq!(phase, SnapshotPanicPhase::Run);
            let original = payload.downcast_ref::<ActualWorkerPanic>().unwrap();
            assert_eq!(original.0, 713);
            assert_eq!(
                std::ptr::from_ref(original) as usize,
                gate.panic_address.load(Ordering::Acquire)
            );
            saw_panic = true;
        }
    });
    assert!(saw_panic);
    assert_eq!(
        gate.cleanup_calls.load(Ordering::Acquire),
        0,
        "opaque unwind cannot imply safe cleanup"
    );
    assert!(
        fixture
            .admission()
            .memory()
            .snapshot_work_at(id.slot)
            .is_some()
    );
    assert_eq!(fixture.admission().snapshot().inflight_operations, 1);
    fence_pending(&fence).await;
}

#[tokio::test]
async fn rejected_metadata_admission_returns_exact_selected_source_for_cleanup() {
    let fixture = Fixture::new().await;
    let (plan, gate, _, fence) = plan(&fixture, Mode::Read, false);
    let id = plan
        .source
        .source()
        .view
        .as_ref()
        .unwrap()
        .registered_reader_id()
        .unwrap();
    let ledger = (
        plan.input.memory.live_bytes(),
        plan.input.memory.peak_bytes(),
    );
    let before = fixture.admission().snapshot();
    let protected_slots = 128 - before.live_reservations;
    let protection = fixture
        .admission()
        .memory()
        .protect_ordinary(0, protected_slots)
        .unwrap();
    let rejection = match fixture
        .admission()
        .prepare_snapshot_work_from_existing::<QuerySourceWork<DiskOwner>>(plan)
    {
        Err(rejection) => rejection,
        Ok(_) => panic!("ordinary protected slots must refuse metadata"),
    };
    assert_eq!(
        rejection.error().unwrap().code,
        ErrorCode::ResourceExhausted
    );
    let after = fixture.admission().snapshot();
    assert_eq!(after.reserved_bytes, before.reserved_bytes);
    assert_eq!(after.live_reservations, before.live_reservations);
    assert_eq!(after.inflight_operations, 1);
    assert_eq!(gate.cleanup_calls.load(Ordering::Acquire), 0);
    let (plan, error) = rejection.into_parts();
    assert_eq!(error.error().unwrap().code, ErrorCode::ResourceExhausted);
    assert_eq!(
        (
            plan.input.memory.live_bytes(),
            plan.input.memory.peak_bytes()
        ),
        ledger
    );
    assert_eq!(
        plan.source
            .source()
            .view
            .as_ref()
            .unwrap()
            .registered_reader_id(),
        Some(id)
    );
    fence_pending(&fence).await;
    drop(protection);
    let bytes = fixture
        .max_bytes
        .checked_sub(before.reserved_bytes)
        .unwrap();
    let protection = fixture
        .admission()
        .memory()
        .protect_ordinary(bytes, 0)
        .unwrap();
    let rejection = match fixture
        .admission()
        .prepare_snapshot_work_from_existing::<QuerySourceWork<DiskOwner>>(plan)
    {
        Err(rejected) => rejected,
        Ok(_) => panic!("ordinary protected bytes must refuse metadata"),
    };
    assert_eq!(
        rejection.error().unwrap().code,
        ErrorCode::ResourceExhausted
    );
    let after = fixture.admission().snapshot();
    assert_eq!(after.reserved_bytes, before.reserved_bytes);
    assert_eq!(after.live_reservations, before.live_reservations);
    assert_eq!(after.inflight_operations, 1);
    let (plan, _) = rejection.into_parts();
    assert_eq!(
        (
            plan.input.memory.live_bytes(),
            plan.input.memory.peak_bytes()
        ),
        ledger
    );
    assert_eq!(
        plan.source
            .source()
            .view
            .as_ref()
            .unwrap()
            .registered_reader_id(),
        Some(id)
    );
    assert_eq!(gate.cleanup_calls.load(Ordering::Acquire), 0);
    drop(protection);
    cleanup_rejected(plan).await;
    fence.drain().await;
    assert_eq!(fixture.admission().snapshot().inflight_operations, 0);
    fixture.close().await;
}

#[tokio::test]
async fn foreign_core_and_already_canceled_existing_grants_are_rejected_unchanged() {
    let fixture = Fixture::new().await;
    let (plan, gate, token, fence) = plan(&fixture, Mode::Read, false);
    let foreign = NodeAdmission::with_fixed_memory(AdmissionConfig::default(), 1 << 30, 0).unwrap();
    let rejected =
        match foreign.prepare_snapshot_work_from_existing::<QuerySourceWork<DiskOwner>>(plan) {
            Err(rejected) => rejected,
            Ok(_) => panic!("foreign actual source provider must fail"),
        };
    assert!(
        matches!(rejected.failure(), SnapshotPreparationFailure::Plan(error) if error.to_string() == "source persistent provider differs")
    );
    let (mut plan, _) = rejected.into_parts();
    // A valid source provider does not excuse a grant from another governor.
    let original_memory = std::mem::replace(
        &mut plan.input.memory,
        QueryMemory::empty(foreign.reserve(64 << 10, Some(token.clone())).unwrap()),
    );
    let rejected = match fixture
        .admission()
        .prepare_snapshot_work_from_existing::<QuerySourceWork<DiskOwner>>(plan)
    {
        Err(rejected) => rejected,
        Ok(_) => panic!("foreign actual operation grant must fail"),
    };
    assert_eq!(rejected.error().unwrap().code, ErrorCode::Conflict);
    let (mut plan, _) = rejected.into_parts();
    drop(std::mem::replace(&mut plan.input.memory, original_memory));
    token.cancel();
    let before = fixture.admission().snapshot();
    let rejected = match fixture
        .admission()
        .prepare_snapshot_work_from_existing::<QuerySourceWork<DiskOwner>>(plan)
    {
        Err(rejected) => rejected,
        Ok(_) => panic!("canceled existing grant must fail"),
    };
    assert_eq!(rejected.error().unwrap().code, ErrorCode::ResourceExhausted);
    assert_eq!(
        fixture.admission().snapshot().reserved_bytes,
        before.reserved_bytes
    );
    assert_eq!(gate.cleanup_calls.load(Ordering::Acquire), 0);
    let (plan, _) = rejected.into_parts();
    cleanup_rejected(plan).await;
    fence.drain().await;
    fixture.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn canceled_successful_read_drains_source_and_unclaimed_output_before_registration() {
    let fixture = Fixture::new().await;
    let (plan, gate, token, fence) = plan(&fixture, Mode::Read, true);
    let admitted = fixture.admission().snapshot();
    let work = fixture
        .admission()
        .prepare_snapshot_work_from_existing::<QuerySourceWork<DiskOwner>>(plan)
        .unwrap_or_else(|_| panic!("prepare"));
    let prepared = fixture.admission().snapshot();
    let metadata_bytes = prepared.reserved_bytes - admitted.reserved_bytes;
    assert_eq!(prepared.live_reservations, admitted.live_reservations + 1);
    let id = work.id();
    work.start().unwrap();
    gate.started().await;
    drop(work);
    assert!(token.is_cancelled());
    let report = fixture
        .admission()
        .memory()
        .snapshot_work_at(id.slot)
        .unwrap();
    fence_pending(&fence).await;
    gate.release();
    let complete = report.drain().await;
    assert_eq!(complete.completion(), DrainCompletion::Complete);
    assert!(
        fixture
            .admission()
            .memory()
            .snapshot_work_at(id.slot)
            .is_none()
    );
    assert!(gate.cleanup_calls.load(Ordering::Acquire) > 0);
    fence.drain().await;
    assert_eq!(fixture.admission().snapshot().inflight_operations, 0);
    // The report still owns its fixed metadata; no discarded response/input or
    // original operation count remains behind the positive cleanup result.
    let retained = fixture.admission().snapshot();
    drop(complete);
    drop(report);
    let dropped = fixture.admission().snapshot();
    assert_eq!(retained.live_reservations, dropped.live_reservations + 1);
    assert_eq!(
        retained.reserved_bytes - dropped.reserved_bytes,
        metadata_bytes
    );
    fixture.close().await;
}

#[tokio::test]
async fn cancellation_before_start_closes_unused_source_without_executing_query() {
    let fixture = Fixture::new().await;
    let (plan, gate, token, fence) = plan(&fixture, Mode::Read, false);
    let initial_live = plan.input.memory.live_bytes();
    let initial_peak = plan.input.memory.peak_bytes();
    assert!(initial_live > 0 && initial_peak >= initial_live);
    let work = fixture
        .admission()
        .prepare_snapshot_work_from_existing::<QuerySourceWork<DiskOwner>>(plan)
        .unwrap_or_else(|_| panic!("prepare"));
    let id = work.id();
    drop(work);
    assert!(token.is_cancelled());
    let report = fixture
        .admission()
        .memory()
        .snapshot_work_at(id.slot)
        .unwrap();
    assert_eq!(report.drain().await.completion(), DrainCompletion::Complete);
    assert_eq!(gate.reads.load(Ordering::Acquire), 0);
    assert_eq!(gate.cleanup_calls.load(Ordering::Acquire), 1);
    fence.drain().await;
    assert_eq!(fixture.admission().snapshot().inflight_operations, 0);
    drop(report);
    fixture.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn preclaim_drain_cancels_adopted_token_and_prevents_late_claim() {
    let fixture = Fixture::new().await;
    let (plan, gate, token, fence) = plan(&fixture, Mode::Read, false);
    gate.cleanup_ready.store(false, Ordering::Release);
    let work = fixture
        .admission()
        .prepare_snapshot_work_from_existing::<QuerySourceWork<DiskOwner>>(plan)
        .unwrap_or_else(|_| panic!("prepare"));
    work.start().unwrap();
    let ready = work.ready().await;
    assert!(!token.is_cancelled());
    // Deterministically give drain the control-lock linearization point before
    // the late claimant. The actual output exists, but source close is paused.
    let closing = ready.drain().await;
    assert_eq!(closing.completion(), DrainCompletion::Retained);
    assert!(token.is_cancelled());
    assert!(work.claim().is_err());
    fence_pending(&fence).await;
    gate.cleanup_ready.store(true, Ordering::Release);
    let complete = closing.drain().await;
    assert_eq!(complete.completion(), DrainCompletion::Complete);
    assert!(
        work.claim().is_err(),
        "pre-claim drain never transfers the grant"
    );
    fence.drain().await;
    assert_eq!(fixture.admission().snapshot().inflight_operations, 0);
    drop(complete);
    drop(closing);
    drop(ready);
    drop(work);
    fixture.close().await;
}

#[tokio::test]
async fn preparation_sampler_panic_returns_exact_plan_payload_and_unused_source() {
    struct Clock(std::sync::atomic::AtomicU64);
    impl kasumi_clock::LeaseClock for Clock {
        fn now(&self) -> Duration {
            Duration::from_millis(self.0.load(Ordering::Acquire))
        }
    }
    struct Probe {
        armed: AtomicBool,
        address: AtomicUsize,
    }
    impl crate::admission::MemorySource for Probe {
        fn resident_bytes(&self) -> anyhow::Result<u64> {
            if self.armed.swap(false, Ordering::AcqRel) {
                let payload = Box::new(ActualWorkerPanic(919));
                self.address.store(
                    std::ptr::from_ref(payload.as_ref()) as usize,
                    Ordering::Release,
                );
                std::panic::resume_unwind(payload);
            }
            Ok(0)
        }
    }
    let clock = Arc::new(Clock(std::sync::atomic::AtomicU64::new(0)));
    let probe = Arc::new(Probe {
        armed: AtomicBool::new(false),
        address: AtomicUsize::new(0),
    });
    let fixture = Fixture::with_probe(Some((probe.clone(), clock.clone()))).await;
    let (plan, gate, token, fence) = plan(&fixture, Mode::Read, false);
    let reader = plan
        .source
        .source()
        .view
        .as_ref()
        .unwrap()
        .registered_reader_id()
        .unwrap();
    let ledger = (
        plan.input.memory.live_bytes(),
        plan.input.memory.peak_bytes(),
    );
    let before = fixture.admission().snapshot();
    probe.armed.store(true, Ordering::Release);
    clock.0.store(2000, Ordering::Release);
    let rejection = match fixture
        .admission()
        .prepare_snapshot_work_from_existing::<QuerySourceWork<DiskOwner>>(plan)
    {
        Err(rejection) => rejection,
        Ok(_) => panic!("real stale RSS probe must unwind during metadata admission"),
    };
    let SnapshotPreparationFailure::Panic(payload) = rejection.failure() else {
        panic!("preserve original panic outcome")
    };
    let original = payload.downcast_ref::<ActualWorkerPanic>().unwrap();
    assert_eq!(original.0, 919);
    assert_eq!(
        std::ptr::from_ref(original) as usize,
        probe.address.load(Ordering::Acquire)
    );
    let after = fixture.admission().snapshot();
    assert_eq!(after.reserved_bytes, before.reserved_bytes);
    assert_eq!(after.live_reservations, before.live_reservations);
    assert_eq!(after.inflight_operations, 1);
    assert!(after.pressured && !after.sample_usable);
    assert!(
        token.is_cancelled(),
        "real sampler panic fences the existing token"
    );
    assert!(
        fixture.admission().memory().snapshot_work_at(0).is_none(),
        "unpublished ticket rolled back"
    );
    assert_eq!(gate.cleanup_calls.load(Ordering::Acquire), 0);
    fence_pending(&fence).await;
    let (plan, failure) = rejection.into_parts();
    assert_eq!(
        plan.source
            .source()
            .view
            .as_ref()
            .unwrap()
            .registered_reader_id(),
        Some(reader)
    );
    assert_eq!(
        (
            plan.input.memory.live_bytes(),
            plan.input.memory.peak_bytes()
        ),
        ledger
    );
    cleanup_rejected(plan).await;
    fence.drain().await;
    assert_eq!(fixture.admission().snapshot().inflight_operations, 0);
    let SnapshotPreparationFailure::Panic(payload) = failure else {
        panic!("original owned panic handoff")
    };
    assert_eq!(
        std::ptr::from_ref(payload.downcast_ref::<ActualWorkerPanic>().unwrap()) as usize,
        probe.address.load(Ordering::Acquire)
    );
    drop(payload);
    fixture.close().await;
}

//! Real encrypted COW batches on a synthetic durable image. Memory admission is
//! the installed provider; only physical extent accounting is the fixture model.
use super::*;
use kasumi_kv::{
    AdmissionError, BackendCloseOutcome, CacheMemoryLease, CacheMemoryQuote, GroupFile,
    OwnerFailed, ResidentLease, RootSlot, SegmentGroupBackend, StorageAdmission,
    TransactionReserveError, TransactionSpacePlan, backends::InMemoryGroup,
};
use kasumi_store::{DiskMemoryLease, NodeDiskMemoryAdmission, SnapshotImage};
use std::{
    ffi::OsStr,
    io,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};

// The existing Store synthetic fixture uses this same physical extent ceiling.
// It is not a byte-memory grant; every native resident request below is real.
const SYNTHETIC_EXTENT_LIMIT: u64 = 256 << 30;
struct NativeAdmission {
    memory: Arc<dyn NodeDiskMemoryAdmission>,
    failed: AtomicBool,
    extent: AtomicU64,
}
impl NativeAdmission {
    fn map(&self, error: io::Error) -> AdmissionError {
        if error.kind() == io::ErrorKind::OutOfMemory {
            AdmissionError::CapacityDenied
        } else {
            self.owner_failed();
            AdmissionError::OwnerFailed
        }
    }
}
impl StorageAdmission for NativeAdmission {
    fn check_owner(&self) -> std::result::Result<(), OwnerFailed> {
        if self.failed.load(Ordering::Acquire) {
            Err(OwnerFailed)
        } else {
            Ok(())
        }
    }
    fn reserve_workspace(
        &self,
        bytes: u64,
    ) -> std::result::Result<Box<dyn ResidentLease>, AdmissionError> {
        self.check_owner()
            .map_err(|_| AdmissionError::OwnerFailed)?;
        // Exact installed constructor pattern: provider owns its concrete token
        // quote; this additional quote covers the outer native trait-object Box.
        let outer = DiskMemoryLease::token_allocation_bytes::<DiskMemoryLease>()
            .map_err(|error| self.map(error))?;
        let request = bytes
            .checked_add(outer)
            .ok_or(AdmissionError::CapacityDenied)?;
        let lease = self
            .memory
            .clone()
            .reserve_installed(request)
            .map_err(|error| self.map(error))?;
        Ok(Box::new(lease))
    }
    fn quote_cache_memory(
        &self,
        bytes: u64,
    ) -> std::result::Result<CacheMemoryQuote, AdmissionError> {
        self.memory
            .quote_cache_memory(bytes)
            .map_err(|error| self.map(error))
    }
    fn reserve_cache_memory(
        self: Arc<Self>,
        bytes: u64,
    ) -> std::result::Result<CacheMemoryLease, AdmissionError> {
        self.check_owner()
            .map_err(|_| AdmissionError::OwnerFailed)?;
        self.memory
            .clone()
            .reserve_cache_memory(bytes)
            .map_err(|error| self.map(error))
    }
    fn reserve_growth(
        &self,
        current: u64,
        requested: u64,
    ) -> std::result::Result<(), AdmissionError> {
        self.check_owner()
            .map_err(|_| AdmissionError::OwnerFailed)?;
        if requested < current || requested > SYNTHETIC_EXTENT_LIMIT {
            return Err(AdmissionError::CapacityDenied);
        }
        self.extent.fetch_max(requested, Ordering::AcqRel);
        Ok(())
    }
    fn settle_growth(&self, actual: u64) -> std::result::Result<(), OwnerFailed> {
        self.check_owner()?;
        if actual > SYNTHETIC_EXTENT_LIMIT {
            self.owner_failed();
            return Err(OwnerFailed);
        }
        self.extent.store(actual, Ordering::Release);
        Ok(())
    }
    fn owner_failed(&self) {
        self.failed.store(true, Ordering::Release);
    }
}

#[derive(Debug)]
struct FinishError {
    ordinal: usize,
}
impl std::fmt::Display for FinishError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "COW actual postcommit finish {}", self.ordinal)
    }
}
impl std::error::Error for FinishError {}
struct FaultState {
    active: Option<TransactionSpacePlan>,
    armed: Option<(usize, io::Error)>,
    failed: Option<TransactionSpacePlan>,
    finishes: usize,
    closes: usize,
}
#[derive(Clone)]
struct Backend {
    group: InMemoryGroup,
    state: Arc<Mutex<FaultState>>,
}
impl Backend {
    fn arm(&self, ordinal: usize) -> usize {
        let error = io::Error::other(FinishError { ordinal });
        let address = error
            .get_ref()
            .unwrap()
            .downcast_ref::<FinishError>()
            .unwrap() as *const FinishError as usize;
        let mut state = self.state.lock().unwrap();
        assert!(ordinal > 0 && state.armed.is_none() && state.active.is_none());
        state.armed = Some((ordinal, error));
        address
    }
}
impl SegmentGroupBackend for Backend {
    fn reserve_transaction(
        &self,
        plan: &TransactionSpacePlan,
    ) -> std::result::Result<(), TransactionReserveError> {
        self.group.reserve_transaction(plan)?;
        assert!(self.state.lock().unwrap().active.replace(*plan).is_none());
        Ok(())
    }
    fn finish_transaction(&self, group: [u8; 16], batch: u64) -> io::Result<()> {
        let mut state = self.state.lock().unwrap();
        let plan = state.active.expect("actual native claim remains owned");
        assert_eq!((plan.group_id, plan.batch_seq), (group, batch));
        state.finishes += 1;
        if let Some((remaining, _)) = state.armed.as_mut() {
            *remaining -= 1;
            if *remaining == 0 {
                state.failed = Some(plan);
                return Err(state.armed.take().unwrap().1);
            }
        }
        self.group.finish_transaction(group, batch)?;
        state.active = None;
        Ok(())
    }
    fn cancel_transaction(&self, group: [u8; 16], batch: u64) -> io::Result<()> {
        self.group.cancel_transaction(group, batch)?;
        let plan = self
            .state
            .lock()
            .unwrap()
            .active
            .take()
            .expect("actual cancelled claim");
        assert_eq!((plan.group_id, plan.batch_seq), (group, batch));
        Ok(())
    }
    fn read_root(
        &self,
        slot: RootSlot,
        out: &mut [u8; kasumi_kv::ROOT_SLOT_BYTES],
    ) -> io::Result<()> {
        self.group.read_root(slot, out)
    }
    fn write_root(
        &self,
        slot: RootSlot,
        bytes: &[u8; kasumi_kv::ROOT_SLOT_BYTES],
    ) -> io::Result<()> {
        self.group.write_root(slot, bytes)
    }
    fn sync_root(&self) -> io::Result<()> {
        self.group.sync_root()
    }
    fn visit_entries(&self, visitor: &mut dyn FnMut(&OsStr) -> io::Result<()>) -> io::Result<()> {
        self.group.visit_entries(visitor)
    }
    fn exists(&self, file: GroupFile) -> io::Result<bool> {
        self.group.exists(file)
    }
    fn create(&self, file: GroupFile) -> io::Result<()> {
        self.group.create(file)
    }
    fn len(&self, file: GroupFile) -> io::Result<u64> {
        self.group.len(file)
    }
    fn read(&self, file: GroupFile, at: u64, out: &mut [u8]) -> io::Result<()> {
        self.group.read(file, at, out)
    }
    fn write(&self, file: GroupFile, at: u64, bytes: &[u8]) -> io::Result<()> {
        self.group.write(file, at, bytes)
    }
    fn set_len(&self, file: GroupFile, len: u64) -> io::Result<()> {
        self.group.set_len(file, len)
    }
    fn sync(&self, file: GroupFile) -> io::Result<()> {
        self.group.sync(file)
    }
    fn unlink(&self, file: GroupFile) -> io::Result<()> {
        self.group.unlink(file)
    }
    fn sync_names(&self) -> io::Result<()> {
        self.group.sync_names()
    }
    fn close(&self) -> BackendCloseOutcome {
        self.state.lock().unwrap().closes += 1;
        self.group.close()
    }
}

// The explicit fixed wrapper layouts have preclaimed fixture backing. This
// does not claim complete opaque io::Error shell or synthetic InMemoryGroup
// disk-image allocator accounting; actual native memory requests are measured.
struct Owners {
    backend: Backend,
    admission: Arc<NativeAdmission>,
    _metadata: Option<Reservation>,
}
impl Drop for Owners {
    fn drop(&mut self) {
        if Arc::strong_count(&self.admission) > 1 || Arc::strong_count(&self.backend.state) > 1 {
            // An early assertion/error must not refund the backing of adapters
            // still held by actual native/census custody. Clone only Arc handles;
            // the same fixed grant moves into a preallocated test failure slot.
            let retained = HeldFailure::Abandoned {
                _backend: self.backend.clone(),
                _admission: self.admission.clone(),
                _metadata: self._metadata.take().expect("actual fixture grant"),
            };
            let mut slots = RETAINED_FAILURES
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            if let Some(slot) = slots.iter_mut().find(|slot| slot.is_none()) {
                *slot = Some(retained);
            } else {
                // Defensive overflow during a cascading failing test still must
                // not release unresolved custody. Four covers both two-arm owners.
                std::mem::forget(retained);
            }
        }
    }
}
impl Owners {
    fn new(storage: &crate::test_utils::FixtureStorage, group: InMemoryGroup) -> Result<Self> {
        let bytes = (std::mem::size_of::<NativeAdmission>()
            + std::mem::size_of::<Mutex<FaultState>>()
            + 4 * std::mem::size_of::<usize>()
            + std::mem::size_of::<FinishError>()
            + 3 * 4096) as u64;
        let metadata = storage.admission.reserve_resident(bytes)?;
        let memory = storage.persistent.memory().clone();
        assert!(Arc::ptr_eq(&memory, storage.scratch.memory()));
        let expected: Arc<dyn NodeDiskMemoryAdmission> = storage.admission.memory().clone();
        assert!(Arc::ptr_eq(&memory, &expected));
        let admission = Arc::new(NativeAdmission {
            memory,
            failed: AtomicBool::new(false),
            extent: AtomicU64::new(0),
        });
        // Observe a real native workspace charge before any database creation.
        let request = 1234 + DiskMemoryLease::token_allocation_bytes::<DiskMemoryLease>()?;
        let quote = admission.memory.quote_installed(request)?;
        let before = storage.admission.snapshot();
        let token = admission.reserve_workspace(1234)?;
        let after = storage.admission.snapshot();
        assert_eq!(after.reserved_bytes - before.reserved_bytes, quote);
        assert_eq!(after.live_reservations - before.live_reservations, 1);
        token.retire();
        assert_eq!(
            storage.admission.snapshot().reserved_bytes,
            before.reserved_bytes
        );
        let backend = Backend {
            group,
            state: Arc::new(Mutex::new(FaultState {
                active: None,
                armed: None,
                failed: None,
                finishes: 0,
                closes: 0,
            })),
        };
        Ok(Self {
            backend,
            admission,
            _metadata: Some(metadata),
        })
    }
}
struct Scope {
    fixture: Fixture,
    owners: Owners,
}
impl Scope {
    async fn new() -> Result<Self> {
        let mut owners = None;
        let fixture = Fixture::new_with_node(|storage, _| {
            let created = Owners::new(storage, InMemoryGroup::new())?;
            owners = Some(created);
            let created = owners.as_ref().unwrap();
            kasumi_store::NodeStore::create_fixture_backend_on_disk(
                created.backend.clone(),
                created.admission.clone(),
                storage.persistent.clone(),
                storage.scratch.clone(),
            )
        })
        .await;
        match fixture {
            Ok(fixture) => Ok(Self {
                fixture,
                owners: owners.context("fixture owners absent")?,
            }),
            Err(original) => match owners {
                Some(owners) => retain_failed(HeldFailure::Setup { owners, original }),
                None => Err(original),
            },
        }
    }
    async fn reopen<'a>(&'a self, image: &SnapshotImage) -> Result<Restarted<'a>> {
        self.reopen_after(image, None).await
    }
    async fn reopen_after<'a>(
        &'a self,
        image: &SnapshotImage,
        final_operation: Option<Operation>,
    ) -> Result<Restarted<'a>> {
        // Take durable bytes before any original owner drain, close, or Drop.
        let group = self.owners.backend.group.crash();
        // Probe only after preserving the crash image. The real backend rejects
        // an already-active claim before root validation, without another effect.
        let plan = self.owners.backend.state.lock().unwrap().failed.unwrap();
        match self.owners.backend.group.reserve_transaction(&plan) {
            Err(TransactionReserveError::Failed(original)) => {
                assert_eq!(original.kind(), io::ErrorKind::WouldBlock)
            }
            other => panic!("actual original claim was not retained: {other:?}"),
        }
        let source = &self.fixture.storage;
        let storage = crate::test_utils::FixtureStorage {
            admission: source.admission.clone(),
            persistent: source.persistent.clone(),
            scratch: source.scratch.clone(),
        };
        let input = storage.admission.reserve_resident(32 << 20)?;
        let owners = Owners::new(&storage, group)?;
        let built = async {
            let node = kasumi_store::NodeStore::open_fixture_backend_on_disk(
                owners.backend.clone(),
                owners.admission.clone(),
                storage.persistent.clone(),
                storage.scratch.clone(),
            )?;
            let stores = TenantStorageSet::open_existing_fixture(
                node.clone(),
                "cow".into(),
                Arc::new(LocalKeyProvider::new([77; 32])),
                Arc::new(LocalKeyProvider::new([78; 32])),
            )
            .await?;
            let (roots, binding) = SourceRoots::new(
                stores.clone(),
                storage.admission.clone(),
                kasumi_raft::RaftLimits::default(),
            )?;
            let buffers = storage.admission.snapshot_buffer_owner()?;
            roots.bind_lifecycle(&buffers, binding)?;
            // This authenticated bootstrap image was retained before the seed. The
            // real selected-source capture verifies its digest against reopened
            // application manifest and custody, including newer replay coverage.
            let engine = TenantEngine::from_bootstrap("cow", image)?;
            engine.install_storage_access(stores.application())?;
            engine.install_application_sources(roots.clone(), image)?;
            let fixture = Fixture {
                engine,
                roots,
                stores,
                node,
                storage,
                _buffers: buffers,
                _input: input,
                _directory: None,
            };
            // Re-run actual accepted producers at the identical original positions.
            // The sink's CoveredReplay branch preserves the current durable cursor.
            // Only positions strictly older than that exact Entry are reconstructed;
            // selection distinguishes actual producer equality from the sink branch.
            fixture.seed(1, false)?;
            let intermediate = fixture.engine.generation()?;
            assert_eq!(intermediate.state.revision, 2);
            let refusal = crate::primary_tree::read::SelectedPrimary::open(
                intermediate
                    .application_selection
                    .get()
                    .context("intermediate source absent")?,
                &fixture.roots,
                &intermediate.state,
                "docs",
            )
            .err()
            .context("older covered source gained a serving capability")?;
            assert!(
                refusal
                    .original()
                    .to_string()
                    .contains("covered primary source has no exact producer binding"),
                "wrong intermediate-source refusal: {refusal:?}"
            );
            drop(refusal);
            drop(intermediate);
            // This is the original fresh baseline's actual accepted policy Entry3,
            // whose log/previous/membership/command hash matches durable applied3.
            // No raw Generation or prior graph capability is injected on reopen.
            fixture.publish(Operation::SetPolicy(policy()))?;
            if let Some(operation) = final_operation {
                // Entry3 is now strictly older than actual committed mutation4.
                let intermediate = fixture.engine.generation()?;
                let refusal = crate::primary_tree::read::SelectedPrimary::open(
                    intermediate
                        .application_selection
                        .get()
                        .context("intermediate policy source absent")?,
                    &fixture.roots,
                    &intermediate.state,
                    "docs",
                )
                .err()
                .context("older policy gained a serving primary proof")?;
                assert!(
                    refusal
                        .original()
                        .to_string()
                        .contains("covered primary source has no exact producer binding")
                );
                drop(refusal);
                drop(intermediate);
                // Authentic deterministic command preparation at the original
                // position, with empty primary effects; never rerun COW/fresh.
                fixture.publish(operation)?;
            }
            fixture.roots.finish_reconstruction()?;
            assert!(!Arc::ptr_eq(&fixture.stores, &self.fixture.stores));
            assert!(!Arc::ptr_eq(&fixture.node, &self.fixture.node));
            Ok::<_, anyhow::Error>(fixture)
        }
        .await;
        let fixture = match built {
            Ok(fixture) => fixture,
            Err(original) => retain_failed(HeldFailure::Setup { owners, original }),
        };
        Ok(Restarted {
            fixture,
            owners,
            _original: self,
        })
    }
}
struct Restarted<'a> {
    fixture: Fixture,
    owners: Owners,
    // Directory and installed provider outlive the reopened synthetic owner.
    _original: &'a Scope,
}
impl Restarted<'_> {
    async fn close(self) {
        // The original shares this admission and still owns live sources. Only
        // its final cleanup may drain the global startup inventory.
        cleanup(self.fixture, self.owners, false).await;
    }
}

// A failed qualification keeps its actual observations, underlying owners and
// credit inspectable in a fixed test-local slot. No failed branch is reported
// as success, acknowledged, reset, or converted into a new cleanup attempt.
struct Cleanup {
    roots: Option<SourceRootsRef>,
    stores: Option<Arc<TenantStorageSet>>,
    node: Option<Arc<kasumi_store::NodeStore>>,
    buffers: Option<Arc<kasumi_raft::SnapshotBufferOwner>>,
    storage: crate::test_utils::FixtureStorage,
    _input: Reservation,
    _directory: Option<tempfile::TempDir>,
    reports: [Option<kasumi_types::drain::DrainResult>; 4],
    owners: Owners,
}
#[allow(
    clippy::large_enum_variant,
    reason = "four inline test custody slots retain exact reports and grants without allocating a new failure shell"
)]
enum HeldFailure {
    Setup {
        owners: Owners,
        original: anyhow::Error,
    },
    Shutdown(Cleanup),
    Abandoned {
        _backend: Backend,
        _admission: Arc<NativeAdmission>,
        _metadata: Reservation,
    },
}
static RETAINED_FAILURES: Mutex<[Option<HeldFailure>; 4]> = Mutex::new([const { None }; 4]);
fn retain_failed(failure: HeldFailure) -> ! {
    match &failure {
        HeldFailure::Setup { original, owners } => eprintln!(
            "COW synthetic setup retained: {original:#}; backend aliases {}, admission aliases {}",
            Arc::strong_count(&owners.backend.state),
            Arc::strong_count(&owners.admission)
        ),
        HeldFailure::Abandoned { .. } => unreachable!("only retained by Owners::drop"),
        HeldFailure::Shutdown(scope) => eprintln!(
            "COW synthetic cleanup retained: {:?}; backend aliases {}, admission aliases {}",
            scope.reports,
            Arc::strong_count(&scope.owners.backend.state),
            Arc::strong_count(&scope.owners.admission)
        ),
    }
    let mut held = RETAINED_FAILURES
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    if let Some(slot) = held.iter_mut().find(|slot| slot.is_none()) {
        *slot = Some(failure);
        drop(held);
        panic!(
            "COW fixture qualification failed; exact owner/report/grant retained in fixed custody"
        );
    }
    // Never drop another Owners while holding the custody mutex. Overflow is
    // itself a failed qualification; unresolved backing is conservatively kept.
    drop(held);
    std::mem::forget(failure);
    panic!("COW fixture failure custody exceeded its four fixed slots");
}
async fn cleanup(fixture: Fixture, owners: Owners, global: bool) {
    let Fixture {
        engine,
        roots,
        stores,
        node,
        storage,
        _buffers,
        _input,
        _directory,
    } = fixture;
    drop(engine);
    let mut scope = Cleanup {
        roots: Some(roots),
        stores: Some(stores),
        node: Some(node),
        buffers: Some(_buffers),
        storage,
        _input,
        _directory,
        reports: [const { None }; 4],
        owners,
    };
    scope.reports[0] =
        Some(std::future::poll_fn(|cx| scope.roots.as_ref().unwrap().poll_drain(cx)).await);
    if global {
        scope.reports[1] = Some(scope.storage.admission.drain_snapshot_startups().await);
    }
    scope.reports[2] = Some(scope.stores.as_ref().unwrap().shutdown().await);
    scope.reports[3] = Some(scope.node.as_ref().unwrap().shutdown().await);
    if scope.reports.iter().flatten().any(|result| result.is_err())
        || !scope.roots.as_ref().unwrap().is_drained()
    {
        retain_failed(HeldFailure::Shutdown(scope));
    }
    // Positive close is separate from the still-observable original uncertain
    // claim. No finish/cancel is supplied by cleanup and no rollback is claimed.
    drop(scope.roots.take());
    drop(scope.stores.take());
    drop(scope.node.take());
    drop(scope.buffers.take());
    if Arc::strong_count(&scope.owners.admission) != 1
        || Arc::strong_count(&scope.owners.backend.state) != 1
    {
        retain_failed(HeldFailure::Shutdown(scope));
    }
    assert_eq!(scope.owners.backend.state.lock().unwrap().closes, 1);
    // The adapter/control allocations retire before their external fixed grant.
    drop(scope);
}

// Retained under the fixture's existing input reservation. This is exact
// physical evidence from the old one-leaf graph, not a selected capability.
struct OldPhysical {
    mapping_key: [u8; 56],
    mapping_bytes: Vec<u8>,
    mapping: records::CatalogEntry,
    manifest_bytes: Vec<u8>,
    manifest: Manifest,
    page_bytes: Vec<u8>,
    leaf: tree::Leaf,
    canonical: Vec<u8>,
}
impl OldPhysical {
    fn capture(fixture: &Fixture, selected: Selector, generation: &Generation) -> Result<Self> {
        let name_hash = decode(records::name_hash("docs"))?;
        let mapping_key = records::CatalogEntry::key(selected.catalog, name_hash);
        let (mapping_bytes, mapping) = fixture.read(
            "engine.primary.catalog",
            &mapping_key,
            records::CATALOG_ENTRY_BYTES,
            |bytes| {
                let bytes = bytes.context("old physical mapping absent")?;
                let mapping = decode(records::CatalogEntry::decode(bytes))?;
                assert_eq!(mapping.catalog, selected.catalog);
                assert_eq!(mapping.scope, selected.scope);
                assert_eq!(mapping.name_hash, name_hash);
                Ok((bytes.to_vec(), mapping))
            },
        )?;
        let (manifest_bytes, manifest) = fixture.read(
            "engine.primary.manifests",
            &key(mapping.manifest.id),
            records::MANIFEST_BYTES,
            |bytes| {
                let bytes = bytes.context("old physical manifest absent")?;
                let manifest = decode(Manifest::decode_referenced(bytes, mapping.manifest))?;
                decode(manifest.validate_context(selected.scope, name_hash, selected.revision))?;
                Ok((bytes.to_vec(), manifest))
            },
        )?;
        let (page_bytes, leaf) = Self::page(fixture, manifest, None)?;
        let document = &generation.state.collections["docs"].documents[&id(0, false)];
        assert_eq!(document.id, id(0, false));
        assert_eq!(document.version, 2);
        assert_eq!(document.body, json!({"value":0}));
        let canonical = serde_json::to_vec(document)?;
        assert_eq!(canonical.len() as u64, leaf.object.encoded_bytes);
        assert_eq!(
            <[u8; 32]>::from(Sha256::digest(&canonical)),
            leaf.object.sha256
        );
        let out = Self {
            mapping_key,
            mapping_bytes,
            mapping,
            manifest_bytes,
            manifest,
            page_bytes,
            leaf,
            canonical,
        };
        out.object(fixture)?;
        Ok(out)
    }
    fn page(
        fixture: &Fixture,
        manifest: Manifest,
        expected: Option<&[u8]>,
    ) -> Result<(Vec<u8>, tree::Leaf)> {
        let root = manifest.root.context("one-leaf root absent")?;
        assert_eq!(root.level, 0);
        fixture.read(
            "engine.primary.pages",
            &key(root.reference.id),
            tree::PAGE_BYTES,
            |bytes| {
                let bytes = bytes.context("old physical page absent")?;
                if let Some(expected) = expected {
                    assert_eq!(bytes, expected);
                }
                let page = decode(tree::validate(
                    bytes,
                    tree::ExpectedPage {
                        tree_id: manifest.tree_id,
                        reference: root.reference,
                        generation_ceiling: manifest.data_epoch,
                        level: 0,
                        totals: manifest.totals,
                        range: tree::KeyRange::default(),
                    },
                ))?;
                let mut entries = page.entries();
                let entry = entries.next().context("one-leaf entry absent")?;
                assert_eq!(entry.id, id(0, false));
                assert!(entries.next().is_none());
                let tree::Value::Leaf(leaf) = entry.value else {
                    anyhow::bail!("old entry not leaf")
                };
                assert_eq!(leaf.kind, tree::RecordKind::Live);
                assert_eq!(leaf.version, 2);
                Ok((bytes.to_vec(), leaf))
            },
        )
    }
    fn object(&self, fixture: &Fixture) -> Result<()> {
        let mut grant = fixture.storage.admission.reserve_document_source(4096)?;
        let mut reader = fixture.roots.open_primary_current()?;
        let mut at = 0;
        let read = crate::primary_tree::stage::cow::visit_physical_for_test(
            &mut reader,
            &mut grant,
            self.manifest.scope,
            self.leaf.object,
            self.manifest.tree_id,
            records::ResourceKind::Live,
            |payload| {
                assert_eq!(payload, &self.canonical[at..at + payload.len()]);
                at += payload.len();
                Ok(())
            },
        );
        let closed = reader.close();
        // Hold BOTH original outcomes through these assertions; neither failure
        // is translated into physical integrity or clean disposal evidence.
        assert!(
            read.is_ok(),
            "physical object inspection: {read:?}; close: {closed:?}"
        );
        assert!(closed.is_ok(), "physical object close: {closed:?}");
        assert_eq!(at, self.canonical.len());
        Ok(())
    }
    fn verify(&self, fixture: &Fixture) -> Result<()> {
        fixture.read(
            "engine.primary.catalog",
            &self.mapping_key,
            records::CATALOG_ENTRY_BYTES,
            |bytes| {
                let bytes = bytes.context("reopened physical mapping absent")?;
                assert_eq!(bytes, self.mapping_bytes);
                assert_eq!(decode(records::CatalogEntry::decode(bytes))?, self.mapping);
                Ok(())
            },
        )?;
        self.verify_resources(fixture)
    }
    fn verify_resources(&self, fixture: &Fixture) -> Result<()> {
        fixture.read(
            "engine.primary.manifests",
            &key(self.mapping.manifest.id),
            records::MANIFEST_BYTES,
            |bytes| {
                let bytes = bytes.context("reopened physical manifest absent")?;
                assert_eq!(bytes, self.manifest_bytes);
                assert_eq!(
                    decode(Manifest::decode_referenced(bytes, self.mapping.manifest))?,
                    self.manifest
                );
                Ok(())
            },
        )?;
        let (_, leaf) = Self::page(fixture, self.manifest, Some(&self.page_bytes))?;
        assert_eq!(leaf, self.leaf);
        self.object(fixture)
    }
}

fn original_unknown(error: &anyhow::Error, expected: usize, ordinal: usize) {
    let commit = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<kasumi_kv::CommitError>())
        .expect("actual native CommitError retained in COW failure");
    let kasumi_kv::StorageError::UnknownCommit(original) = &commit.0 else {
        panic!("actual native unknown outcome required: {commit:?}");
    };
    let original = original
        .get_ref()
        .unwrap()
        .downcast_ref::<FinishError>()
        .expect("exact original finish error");
    assert_eq!(original as *const FinishError as usize, expected);
    assert_eq!(original.ordinal, ordinal);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn primary_cow_unknown_staging_reopens_complete_pending_and_chunk_batches() -> Result<()> {
    for finish in [1, 3] {
        let scope = Scope::new().await?;
        let fixture = &scope.fixture;
        let image = fixture
            .engine
            .logical_snapshot(fixture.stores.application().scratch_disk())?;
        assert_eq!(
            image.sha256(),
            crate::bootstrap::persisted_bootstrap_digest(fixture.stores.application())?
        );
        fixture.seed(1, false)?;
        let prior = fixture.fresh()?;
        let selected = fixture.selector()?;
        let old_epoch = fixture.epoch(selected.projection_epoch)?;
        let old_tail = fixture.attempt(selected.activation_attempt)?;
        let old_generation = fixture.engine.generation()?;
        let old_physical = OldPhysical::capture(fixture, selected, &old_generation)?;
        let custody = fixture
            .stores
            .custody()
            .store()
            .get("raft.meta", b"applied")?;
        let command_input = fixture.command(puts(
            "large",
            vec![(
                "docs".into(),
                id(0, false),
                json!({"new":"x".repeat(200_000)}),
            )],
        ))?;
        let prepared = fixture.prepare(&command_input)?;
        let (authority, failure, address) = {
            let (mut authority, input) = prepared.accepted()?.primary_input()?.split();
            let address = scope.owners.backend.arm(finish);
            let before_finishes = scope.owners.backend.state.lock().unwrap().finishes;
            let failure =
                PendingReplacement::prepare(&mut authority, &input, prior, &mut || Ok(()))
                    .err()
                    .context("faulted staging produced a successful capability")?;
            original_unknown(failure.original(), address, finish);
            {
                let observed = scope.owners.backend.state.lock().unwrap();
                assert_eq!(observed.finishes - before_finishes, finish);
                assert_eq!(observed.active, observed.failed);
                assert!(observed.failed.is_some() && observed.armed.is_none());
                assert_eq!(observed.closes, 0, "no close repairs the crash source");
            }
            assert!(scope.owners.admission.check_owner().is_err());
            let retry = fixture
                .stores
                .write_batch(&[put("cow.fenced-probe", b"never", b"published")], &[])
                .unwrap_err();
            assert!(
                retry.chain().any(|cause| matches!(
                    cause.downcast_ref::<kasumi_kv::CoreError>(),
                    Some(kasumi_kv::CoreError::OwnerFailed)
                )),
                "fenced retry lost its actual owner failure: {retry:#}"
            );
            drop(retry);
            assert!(Arc::ptr_eq(&old_generation, &fixture.engine.generation()?));
            (authority, failure, address)
        };
        // Release only the accepted apply borrow; the exact original failure,
        // old source and staged operations remain live through recovery checks.
        drop(authority);
        drop(prepared);
        drop(command_input);
        let restarted = scope.reopen(&image).await?;
        let reopened = &restarted.fixture;
        let proposed = failure
            .proposed_writes()
            .context("failed batch custody missing")?;
        assert_eq!(proposed.len(), 2);
        for write in proposed {
            let WriteOp::Put {
                namespace,
                key,
                value,
            } = write
            else {
                anyhow::bail!("staging unexpectedly retained a delete");
            };
            reopened.read(namespace, key, value.len(), |actual| {
                assert_eq!(
                    actual,
                    Some(value.as_slice()),
                    "partial recovered {namespace} batch"
                );
                Ok(())
            })?;
        }
        assert!(matches!(&proposed[0], WriteOp::Put { namespace, .. }
            if namespace == if finish == 1 { "engine.primary.attempts" } else { "engine.primary.chunks" }));
        assert!(matches!(&proposed[1], WriteOp::Put { namespace, .. }
            if namespace == if finish == 1 { "engine.primary.epochs" } else { "engine.primary.inventory" }));
        assert!(
            reopened
                .stores
                .application()
                .get("cow.fenced-probe", b"never")?
                .is_none()
        );
        assert_eq!(reopened.selector()?, selected);
        assert_eq!(reopened.attempt(old_tail.id)?, old_tail);
        assert_eq!(
            reopened
                .stores
                .custody()
                .store()
                .get("raft.meta", b"applied")?,
            custody
        );
        let epoch = reopened.epoch(old_epoch.id)?;
        let pending = epoch.pending.context("committed pending branch lost")?;
        let attempt = reopened.attempt(pending)?;
        assert_eq!(attempt.phase, records::AttemptPhase::Building);
        assert_eq!(attempt.previous, Some(old_tail.id));
        assert_eq!(attempt.next, None);
        assert_eq!(attempt.epoch, old_epoch.id);
        assert_eq!(attempt.scope, selected.scope);
        assert_eq!(attempt.retire_count, 0);
        assert_eq!(attempt.abort_object_cursor, 0);
        assert_eq!(attempt.journal_erase_cursor, 0);
        let object = tree::ObjectId {
            attempt: pending,
            ordinal: 0,
        };
        let inventory = reopened.read(
            "engine.primary.inventory",
            &key(object),
            records::INVENTORY_BYTES,
            |bytes| bytes.map(|b| decode(Inventory::decode(b))).transpose(),
        )?;
        if finish == 1 {
            assert_eq!(attempt.next_object, 0);
            assert_eq!(attempt.live_resources, 0);
            assert_eq!(epoch.live_resources, old_epoch.live_resources);
            assert!(inventory.is_none());
        } else {
            assert_eq!(attempt.next_object, 1);
            assert_eq!(attempt.live_resources, 1);
            assert_eq!(epoch.live_resources, old_epoch.live_resources + 1);
            let inventory = inventory.context("chunk progress inventory absent")?;
            assert_eq!(inventory.id, object);
            assert_eq!(inventory.scope, selected.scope);
            assert_eq!(inventory.kind, records::ResourceKind::Live);
            assert_eq!(inventory.phase, records::InventoryPhase::Allocating);
            assert_eq!(inventory.completed_units, 1);
            assert_eq!(inventory.cleanup_unit_cursor, 0);
            assert!(inventory.total_units > 1);
            // Abort parses/authenticates the actual chunk before deletion; it
            // cannot pass merely because the Inventory claims one completed unit.
        }
        let mut authority = reopened.engine.lock_primary_apply()?;
        let mut abort = PrimaryStage::resume_incremental_abort(&mut authority)?
            .context("reopened pending missing")?;
        let zero = reopened.attempt(pending)?;
        let (next, done) = abort.incremental_abort_step(0)?;
        abort = next;
        assert!(!done);
        assert_eq!(reopened.attempt(pending)?, zero);
        let mut settled = false;
        for _ in 0..16 {
            let (next, done) = abort.incremental_abort_step(1)?;
            abort = next;
            if done {
                settled = true;
                break;
            }
        }
        assert!(settled);
        abort.close()?;
        drop(authority);
        assert_eq!(reopened.epoch(old_epoch.id)?, old_epoch);
        assert_eq!(reopened.attempt(old_tail.id)?, old_tail);
        assert_eq!(reopened.selector()?, selected);
        assert!(reopened.read(
            "engine.primary.attempts",
            &pending,
            records::ATTEMPT_BYTES,
            |b| Ok(b.is_none())
        )?);
        let generation = reopened.engine.generation()?;
        let binding = generation
            .application_selection
            .get()
            .context("exact replay source absent")?;
        let (bootstrap, fingerprint, revision) =
            binding.primary_read_proof(generation.state.revision_base)?;
        assert_eq!(revision, 3);
        assert_eq!(generation.state.revision, revision);
        assert_eq!(bootstrap, selected.bootstrap_sha256);
        assert_eq!(fingerprint.kind, selected.boundary);
        assert_eq!(fingerprint.sha256, selected.boundary_digest);
        let reader = crate::primary_tree::read::SelectedPrimary::open(
            binding,
            &reopened.roots,
            &generation.state,
            "docs",
        )
        .unwrap();
        let (reader, version) = reader
            .lookup(&id(0, false), |record| {
                let kasumi_query::Record::Live(document) = record else {
                    anyhow::bail!("old selected kind differs")
                };
                assert_eq!(document.id, id(0, false));
                assert_eq!(document.body, json!({"value":0}));
                assert_eq!(serde_json::to_vec(document)?, old_physical.canonical);
                Ok(document.version)
            })
            .unwrap();
        assert_eq!(version, Some(2));
        reader.close().unwrap();
        // Independent physical preservation evidence remains useful even though
        // the final replay now has the exact original producer binding.
        old_physical.verify(reopened)?;
        drop(generation);
        original_unknown(failure.original(), address, finish);
        restarted.close().await;
        drop(failure);
        drop(old_generation);
        drop(old_physical);
        drop(image);
        let Scope { fixture, owners } = scope;
        cleanup(fixture, owners, true).await;
    }
    Ok(())
}

#[path = "primary_cow_unknown_abort_tests.rs"]
mod unknown_abort;

#[path = "primary_cow_unknown_publication_tests.rs"]
mod unknown_publication;

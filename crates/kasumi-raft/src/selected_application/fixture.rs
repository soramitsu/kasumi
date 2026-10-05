use super::*;
use kasumi_store::{DiskMemoryLease, NodeDiskMemoryAdmission, StorageCensus};
use std::{
    io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

const LIMIT: u64 = 256 << 20;
const SLOTS: usize = 4096;
const TOKEN: u64 = 4096;
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Census {
    pub bytes: u64,
    pub peak_bytes: u64,
    pub slots: usize,
    pub proof_bytes: u64,
    pub proof_slots: usize,
    pub proof_peak: u64,
    pub retains: u64,
}
pub(super) struct Memory {
    census: StorageCensus,
    state: Mutex<Census>,
    base: u64,
    installed_requests: AtomicUsize,
    deny_installed: AtomicBool,
}
impl Memory {
    pub fn new() -> Arc<Self> {
        let base = StorageCensus::required_bytes(SLOTS).unwrap()
            + (std::mem::size_of::<Self>() + 16) as u64
            + 4096;
        assert!(base < LIMIT);
        let memory = Arc::new(Self {
            census: StorageCensus::allocate(SLOTS).unwrap(),
            state: Mutex::new(Census::default()),
            base,
            installed_requests: AtomicUsize::new(0),
            deny_installed: AtomicBool::new(false),
        });
        let provider: Arc<dyn NodeDiskMemoryAdmission> = memory.clone();
        memory.census.bind_provider(&provider).unwrap();
        memory
    }
    pub fn installed_requests(&self) -> usize {
        self.installed_requests.load(Ordering::Relaxed)
    }
    pub fn deny_installed(&self, denied: bool) {
        self.deny_installed.store(denied, Ordering::Relaxed);
    }
    pub fn snapshot(&self) -> Census {
        *self.state.lock().unwrap()
    }
    pub fn reset_peak(&self) {
        let mut state = self.state.lock().unwrap();
        state.peak_bytes = state.bytes;
    }
    fn take(self: &Arc<Self>, bytes: u64, proof: bool) -> io::Result<Grant> {
        let mut state = self.state.lock().unwrap();
        let next = state
            .bytes
            .checked_add(bytes)
            .ok_or(io::ErrorKind::OutOfMemory)?;
        if next + self.base > LIMIT || state.slots >= SLOTS {
            return Err(io::ErrorKind::OutOfMemory.into());
        }
        state.bytes = next;
        state.peak_bytes = state.peak_bytes.max(next);
        state.slots += 1;
        if proof {
            state.proof_bytes += bytes;
            state.proof_slots += 1;
        }
        Ok(Grant {
            memory: self.clone(),
            bytes,
            proof,
        })
    }
    pub fn workspace(self: &Arc<Self>, limit: u64) -> Workspace {
        Workspace {
            grant: self.take(1024, true).unwrap(),
            baseline: 1024,
            limit,
            reject_retain: false,
        }
    }
}
struct Grant {
    memory: Arc<Memory>,
    bytes: u64,
    proof: bool,
}
impl Drop for Grant {
    fn drop(&mut self) {
        let mut state = self.memory.state.lock().unwrap();
        state.bytes -= self.bytes;
        state.slots -= 1;
        if self.proof {
            state.proof_bytes -= self.bytes;
            state.proof_slots -= 1;
        }
    }
}
impl kasumi_kv::SourceMemoryProvider for Memory {}
impl NodeDiskMemoryAdmission for Memory {
    fn quote_installed(&self, bytes: u64) -> io::Result<u64> {
        bytes
            .checked_add(TOKEN)
            .ok_or_else(|| io::ErrorKind::OutOfMemory.into())
    }
    fn storage_census(&self) -> &StorageCensus {
        &self.census
    }
    fn reserve_installed(self: Arc<Self>, bytes: u64) -> io::Result<DiskMemoryLease> {
        self.installed_requests.fetch_add(1, Ordering::Relaxed);
        if self.deny_installed.load(Ordering::Relaxed) {
            return Err(io::Error::other(
                "prepared capture installed admission denied",
            ));
        }
        // The concrete Box and provider token backing are prepaid before new.
        let bytes = bytes.checked_add(TOKEN).ok_or(io::ErrorKind::OutOfMemory)?;
        Ok(DiskMemoryLease::new(self.take(bytes, false)?))
    }
    fn install_native_constructor(
        self: Arc<Self>,
        install: &mut kasumi_store::NativeConstructorInstall<'_>,
    ) -> io::Result<()> {
        let provider: Arc<dyn NodeDiskMemoryAdmission> = self.clone();
        let permit = install
            .try_begin_bind(provider)
            .map_err(|_| std::io::ErrorKind::InvalidInput)?;
        self.installed_requests.fetch_add(1, Ordering::Relaxed);
        if self.deny_installed.load(Ordering::Relaxed) {
            return Err(io::Error::other(
                "prepared capture installed admission denied",
            ));
        }
        let bytes = permit
            .request_bytes()
            .checked_add(DiskMemoryLease::token_allocation_bytes::<Grant>()?)
            .ok_or(io::ErrorKind::OutOfMemory)?;
        match self.take(bytes, false) {
            Ok(token) => {
                permit.bind(token);
                Ok(())
            }
            Err(error) if error.kind() == io::ErrorKind::OutOfMemory => {
                Err(permit.refuse_capacity(error))
            }
            Err(error) => Err(error),
        }
    }
    fn quote_cache_memory(&self, bytes: u64) -> io::Result<kasumi_kv::CacheMemoryQuote> {
        kasumi_kv::CacheMemoryQuote::new(bytes, TOKEN)
            .ok_or_else(|| io::ErrorKind::OutOfMemory.into())
    }
    fn reserve_cache_memory(self: Arc<Self>, _: u64) -> io::Result<kasumi_kv::CacheMemoryLease> {
        // Fixture config explicitly sets optional cache to zero. Required
        // output/page leases still use the bounded installed provider above.
        Err(io::ErrorKind::OutOfMemory.into())
    }
}
#[derive(Debug)]
pub(super) struct Denied(pub &'static str);
impl std::fmt::Display for Denied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for Denied {}
pub(super) struct Workspace {
    grant: Grant,
    baseline: u64,
    limit: u64,
    pub reject_retain: bool,
}
impl SelectionWorkspace for Workspace {
    fn require_memory(&self, view: &SelectionReadIdentity<'_>) -> Result<()> {
        let memory: Arc<dyn NodeDiskMemoryAdmission> = self.grant.memory.clone();
        view.require_memory(&memory)
    }
    fn ensure_peak(&mut self, bytes: u64) -> Result<()> {
        let target = self
            .baseline
            .checked_add(bytes)
            .context("fixture quote overflow")?;
        if target > self.limit {
            return Err(Denied("selection fixture denied").into());
        }
        if target <= self.grant.bytes {
            return Ok(());
        }
        let mut state = self.grant.memory.state.lock().unwrap();
        let next = state
            .bytes
            .checked_add(target - self.grant.bytes)
            .context("fixture total overflow")?;
        if next + self.grant.memory.base > LIMIT {
            return Err(Denied("installed fixture denied").into());
        }
        state.bytes = next;
        state.peak_bytes = state.peak_bytes.max(next);
        state.proof_bytes += target - self.grant.bytes;
        state.proof_peak = state.proof_peak.max(target);
        self.grant.bytes = target;
        Ok(())
    }
    fn retain(&mut self, bytes: u64) -> Result<()> {
        if self.reject_retain {
            return Err(Denied("selection fixture retain denied").into());
        }
        let target = self
            .baseline
            .checked_add(bytes)
            .context("fixture retain overflow")?;
        ensure!(target <= self.grant.bytes, "retain attempted growth");
        let mut state = self.grant.memory.state.lock().unwrap();
        state.bytes -= self.grant.bytes - target;
        state.proof_bytes -= self.grant.bytes - target;
        state.retains += 1;
        self.grant.bytes = target;
        Ok(())
    }
}

pub(super) struct Fixture {
    pub stores: Arc<kasumi_store::TenantStorageSet>,
    pub node: kasumi_store::NodeStore,
    pub image: SnapshotImage,
    pub memory: Arc<Memory>,
    _directory: tempfile::TempDir,
    _scratch: tempfile::TempDir,
}
impl Fixture {
    pub async fn new() -> Result<Self> {
        use kasumi_store::{test_utils::*, *};
        let directory = private_tempdir()?;
        let scratch_directory = private_tempdir()?;
        let memory = Memory::new();
        let scratch = ScratchDisk::fixture(scratch_directory.path(), memory.clone());
        let path = directory.path().join("selected-proof.kv");
        let disk = retry_disk_registry(|| NodeDisk::fixture_for_path(&path, memory.clone()))?;
        let node = NodeStore::create_new(
            path,
            NODE_STORE_ID,
            disk,
            scratch.clone(),
            node_storage_config(),
        )
        .expect("registered node for the admitted selection fixture");
        let app = TenantStore::initialize_catalog_fixture_with_clock(
            node.clone(),
            "selected-proof".into(),
            Arc::new(LocalKeyProvider::new([71; 32])),
            Arc::new(ManualClock::new()),
        )
        .await?;
        let custody = TenantStore::initialize_catalog_fixture_with_clock(
            node.clone(),
            CustodyStore::catalog_name("selected-proof"),
            Arc::new(LocalKeyProvider::new([72; 32])),
            Arc::new(ManualClock::new()),
        )
        .await?;
        let stores = with_domains(app, custody)?;
        let image =
            SnapshotImage::from_bytes(&scratch, b"authenticated fixture application genesis")?;
        let manifest = ApplicationBootstrapManifest {
            format: 2,
            bytes: image.len(),
            chunks: 1,
            digest: image.sha256().into(),
        };
        let mut custody = Vec::from(crate::control::initial_storage_identity(
            1,
            "selected-proof",
        )?);
        custody.push(WriteOp::put(
            META,
            b"application_bootstrap_sha256",
            serde_json::to_vec(image.sha256())?,
        ));
        stores.initialize_state(
            &[WriteOp::put(
                "engine.bootstrap",
                b"manifest",
                serde_json::to_vec(&manifest)?,
            )],
            &custody,
        )?;
        Ok(Self {
            stores,
            node,
            image,
            memory,
            _directory: directory,
            _scratch: scratch_directory,
        })
    }
    pub fn select(
        &self,
        view: &TenantStorageReadView,
        expected: ApplicationBoundaryRef<'_>,
        mode: ApplicationSelectionMode,
    ) -> std::result::Result<SelectedApplicationPosition<Workspace>, SelectionFailure<Workspace>>
    {
        selected_application_at(
            view,
            expected,
            mode,
            &RaftLimits::default(),
            self.memory.workspace(128 << 20),
        )
    }
    pub async fn close(self) -> Result<()> {
        assert_eq!(self.memory.snapshot().proof_slots, 0);
        assert_eq!(self.memory.storage_census().snapshot().readers, 0);
        self.stores.shutdown().await?;
        self.node.shutdown().await?;
        Ok(())
    }
}

pub(super) fn entry(index: u64) -> AppliedEntryContext {
    AppliedEntryContext {
        log_id: LogId::new(openraft::CommittedLeaderId::new(1, 1), index),
        previous: (index > 0)
            .then(|| LogId::new(openraft::CommittedLeaderId::new(1, 1), index - 1)),
        membership: StoredMembership::default(),
        command_sha256: crate::command::sha256(format!("entry-{index}").as_bytes()),
        retirement_seed: None,
    }
}

/// Exercise the real canonical installation producer; only its metadata is
/// published here because this component does not read or certify body chunks.
pub(super) fn install_snapshot(fixture: &Fixture, index: u64) -> Result<SnapshotRestoreContext> {
    let meta = SnapshotMeta {
        last_log_id: Some(entry(index).log_id),
        last_membership: StoredMembership::default(),
        snapshot_id: uuid::Uuid::new_v4().to_string(),
    };
    let snapshot = crate::storage::SnapshotEnvelope {
        version: 2,
        kind: SnapshotKind::Application,
        meta: meta.clone(),
        backend: fixture.image.clone(),
        retirement: None,
        first_membership: None,
        initialization_association: None,
    };
    let image = snapshot.encode(1 << 20)?;
    let manifest = SnapshotManifest {
        version: 1,
        sha256: image.sha256().into(),
        id: uuid::Uuid::new_v4().to_string(),
        bytes: image.len(),
        chunks: 1,
    };
    let coverage = SnapshotCoverage {
        kind: SnapshotKind::Application,
        manifest_id: manifest.id.clone(),
        snapshot_sha256: manifest.sha256.clone(),
        backend_sha256: fixture.image.sha256().into(),
        meta: meta.clone(),
    };
    let mut installation = crate::snapshot_custody::installation_writes(
        fixture.stores.custody(),
        &meta,
        None,
        None,
        None,
        &coverage.backend_sha256,
        &coverage.snapshot_sha256,
    )?;
    assert!(installation.records.is_none());
    installation.writes.push(kasumi_store::WriteOp::put(
        META,
        b"snapshot_coverage",
        crate::storage::encode_snapshot_coverage(&coverage)?,
    ));
    fixture.stores.write_batch(
        &[kasumi_store::WriteOp::put(
            "raft.snapshot",
            b"current",
            serde_json::to_vec(&manifest)?,
        )],
        &installation.writes,
    )?;
    Ok(SnapshotRestoreContext {
        mode: crate::SnapshotRestoreMode::Reopen,
        backend_sha256: coverage.backend_sha256,
        meta,
    })
}

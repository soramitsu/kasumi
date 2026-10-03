use kasumi_engine::{SECURITY_TENANT, SecurityAudit};
use kasumi_store::{NodeStore, TenantStore, test_utils::LocalKeyProvider};
use std::sync::Arc;

/// Query-only functional fixtures use an explicit ceiling independently of
/// their encrypted disk admission. Runtime ownership tests use Reservation.
#[allow(dead_code)]
pub struct QueryWorkspaceFixture;
impl kasumi_query::QueryWorkspace for QueryWorkspaceFixture {
    fn ensure_peak(&mut self, bytes: u64) -> kasumi_types::Result<()> {
        if bytes > 64 << 20 {
            return Err(kasumi_types::Error::new(
                kasumi_types::ErrorCode::ResourceExhausted,
                "query fixture workspace limit",
            ));
        }
        Ok(())
    }
}
#[allow(dead_code)]
pub fn query_memory() -> kasumi_query::QueryMemory<QueryWorkspaceFixture> {
    kasumi_query::QueryMemory::empty(QueryWorkspaceFixture)
}

/// Opt in to fixed-field restore diagnostics across async and blocking workers.
/// Dependency logging stays disabled regardless of any host RUST_LOG setting.
#[allow(dead_code)]
pub fn restore_phase_trace() {
    if std::env::var_os("KASUMI_TEST_RESTORE_TRACE").as_deref() != Some(std::ffi::OsStr::new("1")) {
        return;
    }
    static INITIALIZE: std::sync::Once = std::sync::Once::new();
    INITIALIZE.call_once(|| {
        use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
        tracing_subscriber::registry()
            .with(tracing_subscriber::filter::filter_fn(|metadata| {
                metadata.target() == "kasumi_engine::restore_phase"
                    && *metadata.level() <= tracing::Level::DEBUG
            }))
            .with(
                tracing_subscriber::fmt::layer()
                    .with_ansi(false)
                    .without_time()
                    .with_writer(std::io::stderr),
            )
            .try_init()
            .expect("restore phase diagnostics require the test's sole global subscriber");
    });
}

/// Explicit physical fixture lifetime. The caller retains the persistent
/// parent; this value retains the separate private scratch directory and the
/// original owners through shutdown and reopen.
#[allow(dead_code)]
pub struct PhysicalFixture {
    pub storage: kasumi_engine::test_utils::FixtureStorage,
    pub initial_disk_metadata_bytes: u64,
    _scratch_directory: tempfile::TempDir,
}
#[allow(dead_code)]
impl PhysicalFixture {
    pub fn new(path: &std::path::Path, config: kasumi_engine::admission::AdmissionConfig) -> Self {
        let scratch_directory = kasumi_store::test_utils::private_tempdir().unwrap();
        let persistent = kasumi_store::NodeDisk::fixture_config(path).unwrap();
        let scratch = kasumi_store::ScratchDiskConfig {
            directory: scratch_directory.path().to_owned(),
            max_bytes: 256 << 30,
            min_free_bytes: 0,
            native_cache_bytes: 8 << 20,
        };
        let storage =
            kasumi_engine::test_utils::FixtureStorage::open(&persistent, &scratch, config).unwrap();
        let initial_disk_metadata_bytes = storage.admission.snapshot().resident_reserved_bytes;
        Self {
            storage,
            initial_disk_metadata_bytes,
            _scratch_directory: scratch_directory,
        }
    }
}

/// The exact runtime facade is required before the service ledger can open.
#[allow(dead_code)]
pub async fn security_audit(
    node: Arc<NodeStore>,
    admission: Arc<kasumi_engine::admission::NodeAdmission>,
) -> Arc<SecurityAudit> {
    let store = TenantStore::initialize_catalog_fixture(
        node,
        SECURITY_TENANT.into(),
        Arc::new(LocalKeyProvider::new([0xA7; 32])),
    )
    .await
    .unwrap();
    SecurityAudit::initialize(
        store,
        kasumi_types::AuditRetentionBudget::default(),
        admission,
    )
    .unwrap()
}

/// Reopen a previously initialized ledger under its exact physical memory core.
#[allow(dead_code)]
pub async fn existing_security_audit(
    node: Arc<NodeStore>,
    admission: Arc<kasumi_engine::admission::NodeAdmission>,
) -> Arc<SecurityAudit> {
    let store = TenantStore::open_existing_fixture(
        node,
        SECURITY_TENANT.into(),
        Arc::new(LocalKeyProvider::new([0xA7; 32])),
    )
    .await
    .unwrap();
    SecurityAudit::open(
        store,
        kasumi_types::AuditRetentionBudget::default(),
        admission,
    )
    .unwrap()
}

#[allow(dead_code)]
pub fn local_restore_request(
    context: kasumi_types::RequestContext,
    checkpoint: &kasumi_types::FullBackupCheckpoint,
    target: uuid::Uuid,
) -> kasumi_engine::LocalRestoreRequest {
    kasumi_engine::LocalRestoreRequest {
        checkpoint: checkpoint.clone(),
        target_incarnation: target,
        source_context: context.clone(),
        target_context: context,
        source_purpose: kasumi_store::StoragePurpose::LocalFixture,
    }
}

/// Structurally valid input for tests whose source never completes an I/O.
#[allow(dead_code)]
pub fn unavailable_checkpoint(tenant: &str, id: uuid::Uuid) -> kasumi_types::FullBackupCheckpoint {
    kasumi_types::FullBackupCheckpoint {
        tenant: tenant.into(),
        source_incarnation: uuid::Uuid::new_v4().to_string(),
        revision: 1,
        resident_sha256: "00".repeat(32),
        backup_id: id,
        manifest_ciphertext_sha256: "00".repeat(32),
        key_lineage_digest: "00".repeat(32),
    }
}

/// Pure ordered-apply fixture with an explicit bounded scratch owner. The
/// caller retains this scope until copied generations and images are dropped.
/// These fixtures do not construct serving or Raft capabilities.
#[allow(dead_code)]
pub struct FixtureEngine {
    engine: kasumi_engine::TenantEngine,
    pub disk: Arc<kasumi_store::ScratchDisk>,
    _directory: tempfile::TempDir,
}
#[allow(dead_code)]
impl FixtureEngine {
    pub fn new(
        memory: Arc<dyn kasumi_store::NodeDiskMemoryAdmission>,
        tenant: String,
        incarnation: String,
        policy: kasumi_types::Policy,
        limits: kasumi_types::Limits,
    ) -> kasumi_types::Result<Self> {
        let directory = kasumi_store::test_utils::private_tempdir().unwrap();
        let disk = kasumi_store::ScratchDisk::fixture(directory.path(), memory);
        let engine = kasumi_engine::TenantEngine::new(tenant, incarnation, policy, limits)?;
        Ok(Self {
            engine,
            disk,
            _directory: directory,
        })
    }
}
impl std::ops::Deref for FixtureEngine {
    type Target = kasumi_engine::TenantEngine;
    fn deref(&self) -> &Self::Target {
        &self.engine
    }
}

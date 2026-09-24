use super::*;
use crate::admission::{AdmissionConfig, MemoryCore};
use kasumi_store::{
    CensusCancellation, DiskMemoryRequirements, NodeDisk, NodeDiskConfig, NodeDiskPhase, NodeStore,
    ScratchDisk, ScratchDiskConfig, TenantStore,
    test_utils::{LocalKeyProvider, NODE_STORE_ID, retry_disk_registry},
};
use kasumi_types::{Limits, Policy};
use std::path::Path;

struct Fixture {
    node: Arc<NodeStore>,
    stores: Arc<TenantStorageSet>,
    audit: Arc<SecurityAudit>,
    admission: Arc<NodeAdmission>,
}

fn metadata_bytes(plan: DiskMemoryRequirements) -> anyhow::Result<u64> {
    [
        plan.owner_bytes,
        plan.registry_bytes,
        plan.device_bytes,
        plan.registration_bytes,
    ]
    .into_iter()
    .try_fold(0_u64, |total, bytes| {
        total
            .checked_add(MemoryCore::required_installed_reservation_bytes(bytes)?)
            .ok_or_else(|| anyhow::anyhow!("fixture metadata charge overflow"))
    })
}

impl Fixture {
    async fn new(
        path: &Path,
        disk: &NodeDiskConfig,
        scratch: &ScratchDiskConfig,
        config: AdmissionConfig,
    ) -> anyhow::Result<Self> {
        let admission = NodeAdmission::with_fixed_memory(config, 2 << 30, 0)?;
        let memory = admission.memory().clone();
        let scratch = retry_disk_registry(|| ScratchDisk::open_fixture(scratch, memory.clone()))?;
        let persistent = retry_disk_registry(|| {
            NodeDisk::open_fixture(disk, memory.clone(), &CensusCancellation::default())
        })?;
        let node = NodeStore::create_new(path, NODE_STORE_ID, persistent, scratch)?;
        let audit_store = TenantStore::initialize_catalog_fixture(
            node.clone(),
            crate::SECURITY_TENANT.into(),
            Arc::new(LocalKeyProvider::new([181; 32])),
        )
        .await?;
        let audit = SecurityAudit::initialize(audit_store, Default::default(), admission.clone())?;
        let stores = TenantStorageSet::initialize_catalogs_fixture(
            node.clone(),
            "construction".into(),
            Arc::new(LocalKeyProvider::new([182; 32])),
            Arc::new(LocalKeyProvider::new([183; 32])),
        )
        .await?;
        Ok(Self {
            node,
            stores,
            audit,
            admission,
        })
    }

    async fn close(self) -> anyhow::Result<()> {
        self.audit.shutdown().await?;
        self.stores.shutdown().await?;
        self.admission.drain_snapshot_startups().await?;
        self.node.shutdown().await?;
        Ok(())
    }
}

#[tokio::test]
async fn foreign_equal_policy_core_is_rejected_before_bootstrap_or_raft_startup()
-> anyhow::Result<()> {
    let left_directory = kasumi_store::test_utils::private_tempdir()?;
    let right_directory = kasumi_store::test_utils::private_tempdir()?;
    kasumi_store::private_files::create_directory(&left_directory.path().join("persistent"))?;
    kasumi_store::private_files::create_directory(&right_directory.path().join("persistent"))?;
    let left_path = left_directory.path().join("persistent/node.kv");
    let right_path = right_directory.path().join("persistent/node.kv");
    let left_disk = NodeDisk::fixture_config(&left_path)?;
    let right_disk = NodeDisk::fixture_config(&right_path)?;
    let scratch_config = |root: &Path| ScratchDiskConfig {
        directory: root.join("scratch"),
        max_bytes: 64 << 20,
        min_free_bytes: 0,
    };
    let left_scratch = scratch_config(left_directory.path());
    let right_scratch = scratch_config(right_directory.path());
    let required = |disk: &NodeDiskConfig, scratch: &ScratchDiskConfig| -> anyhow::Result<u64> {
        metadata_bytes(NodeDisk::memory_requirements(disk)?)?
            .checked_add(metadata_bytes(ScratchDisk::memory_requirements(scratch)?)?)
            .ok_or_else(|| anyhow::anyhow!("fixture metadata charge overflow"))
    };
    let metadata = required(&left_disk, &left_scratch)?.max(required(&right_disk, &right_scratch)?);
    // One identical explicit policy for both actual cores. New installed owner
    // metadata is added once above the fixture's bounded operation allowance.
    let config = AdmissionConfig::default();
    let total = (256_u64 << 20)
        .checked_add(NodeAdmission::required_bookkeeping_bytes(&config)?)
        .and_then(|bytes| bytes.checked_add(metadata))
        .ok_or_else(|| anyhow::anyhow!("fixture admission budget overflow"))?;
    let config = AdmissionConfig {
        max_inflight_bytes: Some(total),
        ..config
    };
    let left = Fixture::new(&left_path, &left_disk, &left_scratch, config.clone()).await?;
    let right = Fixture::new(&right_path, &right_disk, &right_scratch, config).await?;
    assert!(!left.admission.shares_memory(&right.admission));
    let before_left = left.admission.snapshot();
    let before_right = right.admission.snapshot();
    let disk_before = right.node.persistent_disk().snapshot();
    let result = crate::bootstrap::fixtures::open_fixture(
        right.stores.clone(),
        Policy::default(),
        Limits::default(),
        left.audit.clone(),
    )
    .await;
    let error = match result {
        Ok(_) => panic!("foreign core must be rejected before startup"),
        Err(error) => error,
    };
    assert_eq!(
        error.to_string(),
        "engine and physical storage memory owners differ"
    );
    for (admission, before) in [
        (&left.admission, before_left),
        (&right.admission, before_right),
    ] {
        let after = admission.snapshot();
        assert_eq!(after.reserved_bytes, before.reserved_bytes);
        assert_eq!(after.live_reservations, before.live_reservations);
    }
    for store in [right.stores.application(), right.stores.custody().store()] {
        assert!(store.get("engine.deployment", b"mode")?.is_none());
        assert!(store.get("engine.bootstrap", b"manifest")?.is_none());
        assert!(store.get("raft.meta", b"node_id")?.is_none());
    }
    let disk_after = right.node.persistent_disk().snapshot();
    assert_eq!(disk_after.phase, NodeDiskPhase::Open);
    assert_eq!(disk_after.charged_bytes, disk_before.charged_bytes);
    assert_eq!(disk_after.pending_bytes, disk_before.pending_bytes);
    let exact = DatabaseConstruction::new(right.stores.clone(), right.audit.clone())?;
    assert!(Arc::ptr_eq(exact.admission(), &right.admission));
    drop(exact);
    left.close().await?;
    right.close().await?;
    Ok(())
}

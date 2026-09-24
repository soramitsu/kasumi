//! Explicit shared-process policy for the replicated runtime fixtures.
use crate::runtime_memory::RuntimeStorage;
use anyhow::{Context, Result, ensure};
use kasumi_engine::admission::{AdmissionConfig, MemoryCore, NodeAdmission};
use kasumi_store::{NodeDisk, NodeDiskConfig, ScratchDisk, ScratchDiskConfig};
use std::{collections::BTreeSet, path::Path};

pub(crate) struct ClusterStorage {
    pub storage: RuntimeStorage,
    pub persistent: NodeDiskConfig,
    pub data_scratch: Vec<ScratchDiskConfig>,
    pub issuer_scratch: Vec<[ScratchDiskConfig; 2]>,
}
struct Budget {
    policy: AdmissionConfig,
    original_payload: u64,
    bookkeeping: u64,
    disk_metadata: u64,
}
fn add(left: u64, right: u64) -> Result<u64> {
    left.checked_add(right)
        .context("shared fixture memory overflow")
}
fn multiply(bytes: u64, count: usize) -> Result<u64> {
    bytes
        .checked_mul(u64::try_from(count)?)
        .context("shared fixture memory overflow")
}

/// The old fixture has one live facade per data/audit governor, and one core-only
/// request budget per issuer. Preserve all of their original payload ceilings;
/// replace duplicated bookkeeping with the actual shared owner census.
fn budget(
    original: &AdmissionConfig,
    data_nodes: usize,
    issuers: usize,
    facade_peak: usize,
    persistent: &NodeDiskConfig,
    scratch: &[ScratchDiskConfig],
) -> Result<Budget> {
    ensure!(
        data_nodes > 0 && facade_peak > 0,
        "shared fixture has no node facades"
    );
    let live_facades = data_nodes
        .checked_add(issuers)
        .context("fixture facade count overflow")?;
    let original_governors = live_facades
        .checked_add(issuers)
        .context("fixture governor count overflow")?;
    ensure!(
        facade_peak >= live_facades,
        "fixture facade peak omits live owners"
    );
    let total = original.resolved_fixture_total_bytes()?;
    let old_core = MemoryCore::required_bookkeeping_bytes(original)?;
    let old_full = NodeAdmission::required_bookkeeping_bytes(original)?;
    let full_payload = total
        .checked_sub(old_full)
        .context("original fixture cannot admit a facade")?;
    let core_payload = total
        .checked_sub(old_core)
        .context("original fixture cannot admit its core")?;
    let original_payload = add(
        multiply(full_payload, live_facades)?,
        multiply(core_payload, issuers)?,
    )?;
    let mut policy = original.clone();
    policy.max_inflight_operations = original
        .max_inflight_operations
        .checked_mul(original_governors)
        .context("fixture operation capacity overflow")?;
    policy.max_reservations = original
        .max_reservations
        .checked_mul(original_governors)
        .context("fixture reservation capacity overflow")?;
    policy.max_startup_scopes = original
        .max_startup_scopes
        .checked_mul(original_governors)
        .context("fixture startup scope capacity overflow")?;
    let core = MemoryCore::required_bookkeeping_bytes(&policy)?;
    let facade = NodeAdmission::required_bookkeeping_bytes(&policy)?
        .checked_sub(core)
        .context("shared fixture facade bookkeeping underflow")?;
    let bookkeeping = add(core, multiply(facade, facade_peak)?)?;
    let mut disk_metadata = kasumi_engine::test_utils::isolated_metadata_bytes(
        NodeDisk::memory_requirements(persistent)?,
    )?;
    let mut paths = BTreeSet::new();
    for config in scratch {
        // Every entry denotes an actual distinct isolated scratch installation.
        // Reopens reuse that owner; duplicate entries would invent headroom.
        ensure!(
            paths.insert(&config.directory),
            "duplicate fixture scratch owner"
        );
        crate::persistent_disk::validate(persistent, config, std::iter::empty())?;
        disk_metadata = add(
            disk_metadata,
            kasumi_engine::test_utils::isolated_metadata_bytes(ScratchDisk::memory_requirements(
                config,
            )?)?,
        )?;
    }
    policy.max_inflight_bytes = Some(add(add(original_payload, bookkeeping)?, disk_metadata)?);
    // Preserve the existing RSS policy. An aggregate that does not fit is an
    // explicit fixture error, never permission to raise the high-water mark.
    policy.resolved_fixture_total_bytes()?;
    Ok(Budget {
        policy,
        original_payload,
        bookkeeping,
        disk_metadata,
    })
}

impl ClusterStorage {
    pub(crate) fn prepare(
        directory: &Path,
        data_nodes: usize,
        canonical: bool,
        original: &AdmissionConfig,
        scratch_template: &ScratchDiskConfig,
    ) -> Result<Self> {
        let mut persistent = crate::persistent_disk::fixture_config(&directory.join("persistent"));
        let issuers = if canonical { 3 } else { 0 };
        if canonical {
            let recovery = directory.join("canonical-recovery");
            kasumi_store::private_files::create_directory(&recovery)?;
            let root = recovery.join("persistent");
            kasumi_store::private_files::create_directory(&root)?;
            // The persistent owner inventories its complete namespace at open.
            // These real verifier and target-generation directories must exist
            // before that census, not appear behind the owner's back later.
            for node in 1..=3 {
                kasumi_store::private_files::create_directory(
                    &root.join(format!("verifier-{node}")),
                )?;
                kasumi_store::private_files::create_directory(
                    &root.join(format!("target-generations-{node}")),
                )?;
            }
            persistent.roots.insert("recovery".into(), root);
        }
        let data_scratch = (0..data_nodes)
            .map(|node| ScratchDiskConfig {
                directory: directory.join(format!("scratch-{node}")),
                ..scratch_template.clone()
            })
            .collect::<Vec<_>>();
        let issuer_scratch = (0..issuers)
            .map(|index| {
                ["audit", "authority"].map(|role| ScratchDiskConfig {
                    directory: directory.join(format!("issuer-scratch-{}-{role}", index + 1)),
                    // Preserve the original two separate ScratchDisk::fixture quotas.
                    max_bytes: 256 << 30,
                    min_free_bytes: 0,
                })
            })
            .collect::<Vec<_>>();
        let scratch = data_scratch
            .iter()
            .chain(issuer_scratch.iter().flatten())
            .cloned()
            .collect::<Vec<_>>();
        // Journal initialization is serial alongside the three data + three
        // issuer facades. Other setup runs before the data generation starts.
        let facade_peak = data_nodes
            .checked_add(issuers)
            .and_then(|n| n.checked_add(usize::from(canonical)))
            .context("fixture facade peak overflow")?;
        let plan = budget(
            original,
            data_nodes,
            issuers,
            facade_peak,
            &persistent,
            &scratch,
        )?;
        let total = plan.policy.max_inflight_bytes.unwrap();
        ensure!(
            total
                .checked_sub(plan.bookkeeping)
                .and_then(|n| n.checked_sub(plan.disk_metadata))
                == Some(plan.original_payload),
            "fixture payload accounting differs from original governors"
        );
        let memory = MemoryCore::new(plan.policy.clone())?;
        let storage = RuntimeStorage::fixture(plan.policy, memory)?;
        // The complete explicit root set is installed before any issuer or data
        // file, installation marker, audit archive, or verifier can be created.
        storage.open_persistent(&persistent)?;
        Ok(Self {
            storage,
            persistent,
            data_scratch,
            issuer_scratch,
        })
    }
}

#[cfg(test)]
#[path = "runtime_cluster_storage_tests.rs"]
mod tests;

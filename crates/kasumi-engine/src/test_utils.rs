//! Explicit fixture-only codecs and admission accounting helpers. These are
//! not portable snapshots, storage capabilities, or production restore APIs.
use crate::TenantEngine;
pub use crate::bootstrap::fixtures::{
    open_fixture, open_fixture_replicated, open_fixture_with_incarnation,
};
use kasumi_store::SnapshotImage;
use kasumi_types::{Error, ErrorCode, Result, TenantState};

/// Preserve an explicit fixture payload cap while admitting the real core and
/// its first runtime facade. An unspecified production-derived cap is unchanged.
pub fn admission_config_with_bookkeeping(
    mut config: crate::admission::AdmissionConfig,
) -> anyhow::Result<crate::admission::AdmissionConfig> {
    if let Some(payload_bytes) = config.max_inflight_bytes {
        config.max_inflight_bytes = Some(
            payload_bytes
                .checked_add(crate::admission::NodeAdmission::required_bookkeeping_bytes(
                    &config,
                )?)
                .ok_or_else(|| anyhow::anyhow!("fixture admission byte cap overflow"))?,
        );
    }
    Ok(config)
}

/// Plan one fresh core/facade and TWO fresh isolated fixture devices: one
/// persistent owner and one scratch owner. The explicit cap is the unchanged
/// operation/resident payload allowance; all eight disk metadata leases and the
/// core/facade bookkeeping are added separately. Do not use this plan for cached
/// owners or a shared physical device, and do not add bookkeeping a second time.
/// RSS limits remain explicit and unchanged; callers must provide real headroom.
pub fn isolated_disk_admission_config(
    mut config: crate::admission::AdmissionConfig,
    persistent: &kasumi_store::NodeDiskConfig,
    scratch: &kasumi_store::ScratchDiskConfig,
) -> anyhow::Result<crate::admission::AdmissionConfig> {
    let payload = config.max_inflight_bytes.ok_or_else(|| {
        anyhow::anyhow!("isolated disk fixture requires an explicit payload byte cap")
    })?;
    let mut total = payload
        .checked_add(crate::admission::NodeAdmission::required_bookkeeping_bytes(
            &config,
        )?)
        .ok_or_else(|| anyhow::anyhow!("isolated disk fixture byte cap overflow"))?;
    total = total
        .checked_add(isolated_disk_metadata_bytes(persistent, scratch)?)
        .ok_or_else(|| anyhow::anyhow!("isolated disk fixture byte cap overflow"))?;
    config.max_inflight_bytes = Some(total);
    Ok(config)
}

/// Metadata for TWO fresh isolated fixture devices only. Add this to an
/// existing canonical total cap without adding core/facade bookkeeping again.
/// All eight separately boxed leases use the actual provider's charge formula.
pub fn isolated_disk_metadata_bytes(
    persistent: &kasumi_store::NodeDiskConfig,
    scratch: &kasumi_store::ScratchDiskConfig,
) -> anyhow::Result<u64> {
    isolated_metadata_bytes(kasumi_store::NodeDisk::memory_requirements(persistent)?)?
        .checked_add(isolated_metadata_bytes(
            kasumi_store::ScratchDisk::memory_requirements(scratch)?,
        )?)
        .ok_or_else(|| anyhow::anyhow!("isolated disk fixture byte cap overflow"))
}

/// Metadata for ONE fresh isolated fixture owner/device. Each of its four
/// actual leases includes the provider allocation fee. This does not admit an
/// unused sibling disk, a runtime facade, or a shared/cached device twice.
pub fn isolated_metadata_bytes(
    required: kasumi_store::DiskMemoryRequirements,
) -> anyhow::Result<u64> {
    let mut total = 0_u64;
    for component in [
        required.owner_bytes,
        required.registry_bytes,
        required.device_bytes,
        required.registration_bytes,
    ] {
        total = total
            .checked_add(
                crate::admission::MemoryCore::required_installed_reservation_bytes(component)?,
            )
            .ok_or_else(|| anyhow::anyhow!("isolated disk fixture byte cap overflow"))?;
    }
    Ok(total)
}

/// Add only newly required physical-owner metadata to the old configured total.
/// Resolving the default uses the canonical detected host/container ceiling;
/// this does not allocate a temporary core, add bookkeeping twice, or raise RSS.
pub fn isolated_disk_config_with_metadata(
    mut config: crate::admission::AdmissionConfig,
    persistent: &kasumi_store::NodeDiskConfig,
    scratch: &kasumi_store::ScratchDiskConfig,
) -> anyhow::Result<crate::admission::AdmissionConfig> {
    config.max_inflight_bytes = Some(
        config
            .resolved_fixture_total_bytes()?
            .checked_add(isolated_disk_metadata_bytes(persistent, scratch)?)
            .ok_or_else(|| anyhow::anyhow!("isolated disk fixture byte cap overflow"))?,
    );
    config.validate()?;
    Ok(config)
}

/// Explicit sibling roots within a private directory retained by the caller.
/// Only fixture directory setup occurs here; no governor or disk is opened.
pub fn fixture_disk_configs(
    root: &std::path::Path,
) -> anyhow::Result<(
    kasumi_store::NodeDiskConfig,
    kasumi_store::ScratchDiskConfig,
)> {
    let persistent = root.join("persistent");
    kasumi_store::private_files::create_directory(&persistent)?;
    Ok((
        kasumi_store::NodeDisk::fixture_config(persistent.join("node.kv"))?,
        kasumi_store::ScratchDiskConfig {
            directory: root.join("scratch"),
            max_bytes: 256 << 30,
            min_free_bytes: 0,
        },
    ))
}

/// Explicit fixture storage scope. The caller retains the enclosing private
/// directories and this scope through all file users and every close/reopen.
/// Disk registries intentionally retain actual owners and their metadata after
/// this value drops; dropping a fixture scope never claims those bytes are free.
pub struct FixtureStorage {
    pub admission: std::sync::Arc<crate::admission::NodeAdmission>,
    pub persistent: std::sync::Arc<kasumi_store::NodeDisk>,
    pub scratch: std::sync::Arc<kasumi_store::ScratchDisk>,
}
impl FixtureStorage {
    /// Create one fresh fixture core/facade and two fresh isolated disk devices.
    /// `config` is the original TOTAL policy, including existing bookkeeping.
    /// Only newly required disk metadata is added. Reopens reuse this scope.
    pub fn open(
        persistent: &kasumi_store::NodeDiskConfig,
        scratch: &kasumi_store::ScratchDiskConfig,
        config: crate::admission::AdmissionConfig,
    ) -> anyhow::Result<Self> {
        let config = isolated_disk_config_with_metadata(config, persistent, scratch)?;
        let admission = crate::admission::NodeAdmission::new(config)?;
        Self::with_admission(persistent, scratch, admission)
    }

    /// Use an explicit already-planned facade. Fixed-memory and shared-process
    /// fixtures account for their actual owners before calling this constructor.
    /// No budget, operation limit, RSS ceiling or facade identity changes here.
    pub fn with_admission(
        persistent: &kasumi_store::NodeDiskConfig,
        scratch: &kasumi_store::ScratchDiskConfig,
        admission: std::sync::Arc<crate::admission::NodeAdmission>,
    ) -> anyhow::Result<Self> {
        use kasumi_store::test_utils::retry_disk_registry;
        let memory = admission.memory().clone();
        let persistent = retry_disk_registry(|| {
            kasumi_store::NodeDisk::open_fixture(
                persistent,
                memory.clone(),
                &kasumi_store::CensusCancellation::default(),
            )
        })?;
        let scratch = retry_disk_registry(|| {
            kasumi_store::ScratchDisk::open_fixture(scratch, memory.clone())
        })?;
        Ok(Self {
            admission,
            persistent,
            scratch,
        })
    }

    pub fn create_new(
        &self,
        path: impl AsRef<std::path::Path>,
        id: uuid::Uuid,
    ) -> anyhow::Result<std::sync::Arc<kasumi_store::NodeStore>> {
        kasumi_store::NodeStore::create_new(path, id, self.persistent.clone(), self.scratch.clone())
    }

    pub fn open_existing(
        &self,
        path: impl AsRef<std::path::Path>,
        id: uuid::Uuid,
    ) -> anyhow::Result<std::sync::Arc<kasumi_store::NodeStore>> {
        kasumi_store::NodeStore::open_existing(
            path,
            id,
            self.persistent.clone(),
            self.scratch.clone(),
        )
    }
}

/// One coherent snapshot measures operation and resident payload charges without
/// concealing bookkeeping in the production counters or core accounting tests.
pub fn reserved_payload_bytes(admission: &crate::admission::NodeAdmission) -> u64 {
    let snapshot = admission.snapshot();
    snapshot
        .reserved_bytes
        .checked_sub(snapshot.bookkeeping_bytes)
        .expect("admission bookkeeping exceeds its total charge")
}

pub trait SnapshotFixture {
    fn fixture_snapshot(
        &self,
        disk: &std::sync::Arc<kasumi_store::ScratchDisk>,
    ) -> Result<SnapshotImage>;
    fn fixture_restore(&self, candidate: &SnapshotImage) -> Result<()>;
}
impl SnapshotFixture for TenantEngine {
    fn fixture_snapshot(
        &self,
        disk: &std::sync::Arc<kasumi_store::ScratchDisk>,
    ) -> Result<SnapshotImage> {
        self.logical_snapshot(disk)
    }
    fn fixture_restore(&self, candidate: &SnapshotImage) -> Result<()> {
        self.restore_candidate(candidate)
    }
}
pub trait SnapshotFixtureState {
    fn write_fixture(&self, writer: &mut dyn std::io::Write) -> anyhow::Result<()>;
}
impl SnapshotFixtureState for TenantState {
    fn write_fixture(&self, writer: &mut dyn std::io::Write) -> anyhow::Result<()> {
        write_candidate(self, None, None, None, None, writer)
    }
}
impl SnapshotFixtureState for crate::Generation {
    fn write_fixture(&self, writer: &mut dyn std::io::Write) -> anyhow::Result<()> {
        crate::snapshot_codec::write(
            &self.state,
            &self.receipts,
            &self.backup_bindings,
            &self.terminals,
            &self.target_resolutions,
            writer,
        )
    }
}
#[derive(Clone)]
pub struct SnapshotCandidate(crate::snapshot_codec::Decoded);
impl std::ops::Deref for SnapshotCandidate {
    type Target = TenantState;
    fn deref(&self) -> &TenantState {
        &self.0.state
    }
}
impl std::ops::DerefMut for SnapshotCandidate {
    fn deref_mut(&mut self) -> &mut TenantState {
        &mut self.0.state
    }
}
impl SnapshotFixtureState for SnapshotCandidate {
    fn write_fixture(&self, writer: &mut dyn std::io::Write) -> anyhow::Result<()> {
        write_candidate(
            &self.0.state,
            Some(&self.0.receipts),
            Some(&self.0.backup_bindings),
            Some(&self.0.terminals),
            Some(&self.0.target_resolutions),
            writer,
        )
    }
}
pub fn encode_snapshot_candidate(
    disk: &std::sync::Arc<kasumi_store::ScratchDisk>,
    state: &impl SnapshotFixtureState,
    max_bytes: u64,
) -> Result<SnapshotImage> {
    SnapshotImage::capture(disk, max_bytes, |writer| state.write_fixture(writer))
        .map_err(|error| Error::new(ErrorCode::Corruption, error.to_string()))
}
/// Authenticate the complete snapshot framing, digest and EOF before selecting
/// bytes charged by SnapshotAccounting. Staged terminal rows count toward that
/// quota even though their permanent table bodies do not occupy resident state.
/// Ordinary receipt and target-resolution rows retain separate byte budgets.
pub fn snapshot_accounted_bytes(candidate: &SnapshotImage) -> Result<u64> {
    crate::snapshot_codec::inspect(&mut candidate.reader())
        .and_then(|summary| {
            summary
                .resident_bytes()?
                .checked_add(summary.kinds[21].framed_bytes)
                .ok_or_else(|| anyhow::anyhow!("accounted snapshot byte overflow"))
        })
        .map_err(|error| Error::new(ErrorCode::Corruption, error.to_string()))
}
pub fn decode_snapshot_candidate(candidate: &SnapshotImage) -> Result<SnapshotCandidate> {
    crate::snapshot_codec::read(candidate.disk(), &mut candidate.reader())
        .map(SnapshotCandidate)
        .map_err(|error| Error::new(ErrorCode::Corruption, error.to_string()))
}

// Corruption fixtures must be able to encode intentionally inconsistent heads.
// This path is feature gated and never grants publication or a storage capability.
fn write_candidate(
    state: &TenantState,
    receipts: Option<&crate::mutation_receipt::View>,
    backup_bindings: Option<&crate::backup_binding::View>,
    terminals: Option<&crate::staged_terminal::View>,
    target_resolutions: Option<&crate::target_resolution::View>,
    writer: &mut dyn std::io::Write,
) -> anyhow::Result<()> {
    let mut encoder = crate::snapshot_codec::Encoder::new(writer)?;
    for kind in 0..21 {
        if kind == 5
            && let Some(receipts) = receipts
        {
            for row in receipts.records() {
                encoder.record(crate::snapshot_codec::Record::Receipt(Box::new(row?)))?;
            }
        }
        for record in crate::snapshot_codec::records(state, kind, None)? {
            encoder.record(record?)?;
        }
    }
    if let Some(terminals) = terminals {
        for row in terminals.records() {
            encoder.record(crate::snapshot_codec::Record::Terminal(Box::new(row?)))?;
        }
    }
    if let Some(target_resolutions) = target_resolutions {
        for row in target_resolutions.records() {
            encoder.record(crate::snapshot_codec::Record::TargetResolution(Box::new(
                row?,
            )))?;
        }
    }
    for record in crate::snapshot_codec::records(state, 23, None)? {
        encoder.record(record?)?;
    }
    if let Some(bindings) = backup_bindings {
        for row in bindings.records() {
            encoder.record(crate::snapshot_codec::Record::BackupBinding(Box::new(row?)))?;
        }
    }
    encoder.finish()
}

#[cfg(test)]
mod physical_fixture_tests {
    use super::*;
    use crate::admission::{AdmissionConfig, NodeAdmission};
    use std::sync::Arc;

    #[tokio::test]
    async fn installed_metadata_preserves_the_exact_original_payload_allowance()
    -> anyhow::Result<()> {
        let directory = kasumi_store::test_utils::private_tempdir()?;
        let (persistent, scratch) = fixture_disk_configs(directory.path())?;
        let payload = 64_u64 << 20;
        let config = AdmissionConfig {
            max_inflight_bytes: Some(payload),
            ..Default::default()
        };
        let config = isolated_disk_admission_config(config, &persistent, &scratch)?;
        let admission = NodeAdmission::with_fixed_memory(config, 2 << 30, 0)?;
        let before = admission.snapshot();
        let metadata = isolated_disk_metadata_bytes(&persistent, &scratch)?;
        let storage = FixtureStorage::with_admission(&persistent, &scratch, admission.clone())?;
        let after = admission.snapshot();
        assert_eq!(
            after.reserved_bytes.checked_sub(before.reserved_bytes),
            Some(metadata)
        );
        assert_eq!(after.live_reservations - before.live_reservations, 8);
        assert_eq!(after.inflight_operations, before.inflight_operations);
        assert_eq!(after.bookkeeping_bytes, before.bookkeeping_bytes);
        let payload_lease = admission.reserve(payload, None)?;
        assert!(admission.reserve(1, None).is_err());
        drop(payload_lease);
        let path = directory.path().join("persistent/node.kv");
        let first = storage.create_new(&path, kasumi_store::test_utils::NODE_STORE_ID)?;
        assert!(Arc::ptr_eq(first.persistent_disk(), &storage.persistent));
        assert!(Arc::ptr_eq(first.scratch_disk(), &storage.scratch));
        first.shutdown().await?;
        drop(first);
        let reopened = storage.open_existing(&path, kasumi_store::test_utils::NODE_STORE_ID)?;
        assert!(Arc::ptr_eq(reopened.persistent_disk(), &storage.persistent));
        assert!(admission.snapshot().reserved_bytes > after.reserved_bytes);
        reopened.shutdown().await?;
        drop(reopened);
        assert_eq!(admission.snapshot().reserved_bytes, after.reserved_bytes);
        admission.drain_snapshot_startups().await?;
        drop(storage);
        // Installed physical owners retain their actual metadata leases after
        // public callers disappear. It is not reusable operation capacity.
        assert_eq!(admission.snapshot().resident_reserved_bytes, metadata);
        Ok(())
    }

    #[test]
    fn configured_total_planning_preserves_existing_bookkeeping_and_limits() -> anyhow::Result<()> {
        let directory = kasumi_store::test_utils::private_tempdir()?;
        let (persistent, scratch) = fixture_disk_configs(directory.path())?;
        let config = admission_config_with_bookkeeping(AdmissionConfig {
            max_inflight_bytes: Some(64 << 20),
            max_inflight_operations: 7,
            ..Default::default()
        })?;
        let old_total = config.max_inflight_bytes.unwrap();
        let planned = isolated_disk_config_with_metadata(config.clone(), &persistent, &scratch)?;
        assert_eq!(
            planned.max_inflight_bytes,
            Some(old_total + isolated_disk_metadata_bytes(&persistent, &scratch)?)
        );
        let mut unchanged = planned;
        unchanged.max_inflight_bytes = config.max_inflight_bytes;
        assert_eq!(unchanged, config);
        Ok(())
    }
}

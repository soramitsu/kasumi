//! Explicit positive workload allowance, separate from the invalid legacy total.
use crate::admission::{AdmissionConfig, NodeAdmission};
use crate::audit_maintenance::NodeAuditMaintenance;
use anyhow::{Context as _, Result};
use kasumi_store::{NodeDiskConfig, ScratchDiskConfig};

// Actual native/opening owners, selected roots and command work share this
// declared payload allowance. It is independent of all mandatory floors below.
const WORKLOAD_BYTES: u64 = 128 << 20;

struct Plan {
    config: AdmissionConfig,
    workload: u64,
    bookkeeping: u64,
    devices: u64,
    snapshots: u64,
    sources: u64,
    security_audit: u64,
    audit_escrow: u64,
    ordinary_protection: u64,
    cache_work: u64,
}
impl Plan {
    fn new(persistent: &NodeDiskConfig, scratch: &ScratchDiskConfig) -> Result<Self> {
        let mut config = AdmissionConfig::default();
        let bookkeeping = NodeAdmission::required_bookkeeping_bytes(&config)?;
        let devices = crate::test_utils::isolated_disk_metadata_bytes(persistent, scratch)?;
        let snapshots =
            kasumi_raft::SnapshotBufferOwner::required_bytes(kasumi_raft::SNAPSHOT_BUFFER_SLOTS)?;
        let sources = crate::application_sources::SourceRoots::required_fixed_admission_bytes()?;
        let security_audit = kasumi_types::AuditRetentionBudget::MAINTENANCE_BYTES;
        let audit_escrow = NodeAuditMaintenance::WORKSPACE_BYTES;
        let ordinary_protection = NodeAuditMaintenance::WORKSPACE_BYTES;
        let mut total = 0_u64;
        for bytes in [
            WORKLOAD_BYTES,
            bookkeeping,
            devices,
            snapshots,
            sources,
            security_audit,
            audit_escrow,
            ordinary_protection,
        ] {
            total = total
                .checked_add(bytes)
                .context("replica fixture budget overflow")?;
        }
        // The actual audit obligations already exceed the default's saturation
        // point. Confirm the canonical policy gives the same floor after adding it.
        let cache_work = config.cache_work_headroom(total).0;
        total = total
            .checked_add(cache_work)
            .context("replica cache-work budget overflow")?;
        anyhow::ensure!(
            config.cache_work_headroom(total).0 == cache_work,
            "replica cache-work quote changed while composing its total"
        );
        config.max_inflight_bytes = Some(total);
        config.validate()?;
        Ok(Self {
            config,
            workload: WORKLOAD_BYTES,
            bookkeeping,
            devices,
            snapshots,
            sources,
            security_audit,
            audit_escrow,
            ordinary_protection,
            cache_work,
        })
    }
    fn fixed_and_protected(&self) -> u64 {
        self.bookkeeping
            + self.devices
            + self.snapshots
            + self.sources
            + self.security_audit
            + self.audit_escrow
            + self.ordinary_protection
            + self.cache_work
    }
}

pub(in crate::bootstrap) fn planned_config(
    persistent: &NodeDiskConfig,
    scratch: &ScratchDiskConfig,
) -> Result<AdmissionConfig> {
    let plan = Plan::new(persistent, scratch)?;
    anyhow::ensure!(
        plan.config.max_inflight_bytes == Some(plan.fixed_and_protected() + plan.workload),
        "replica fixture workload is not independent of fixed obligations"
    );
    Ok(plan.config)
}

/// Preserve the original invalid configuration only for its explicit negative
/// test. Do not use a measured deficit to turn this into a positive fixture.
pub(super) fn legacy_invalid_config(
    persistent: &NodeDiskConfig,
    scratch: &ScratchDiskConfig,
) -> Result<AdmissionConfig> {
    Ok(AdmissionConfig {
        max_inflight_bytes: Some(
            (384_u64 << 20)
                .checked_add(crate::test_utils::isolated_disk_metadata_bytes(
                    persistent, scratch,
                )?)
                .context("legacy fixture metadata budget overflow")?,
        ),
        ..Default::default()
    })
}

#[test]
fn replica_plan_keeps_workload_separate_and_proves_legacy_total_invalid() -> Result<()> {
    let directory = kasumi_store::test_utils::private_tempdir()?;
    let (persistent, scratch) = crate::test_utils::fixture_disk_configs(directory.path())?;
    let plan = Plan::new(&persistent, &scratch)?;
    let legacy = legacy_invalid_config(&persistent, &scratch)?
        .max_inflight_bytes
        .unwrap();
    // Same declared audit/cache obligations alone consume the old non-device
    // total. The actual core/facade/snapshot/source owner quotes are additional.
    assert_eq!(
        legacy,
        plan.devices
            + plan.security_audit
            + plan.audit_escrow
            + plan.ordinary_protection
            + plan.cache_work
    );
    assert!(plan.fixed_and_protected() > legacy);
    assert_eq!(
        plan.config.max_inflight_bytes.unwrap() - plan.fixed_and_protected(),
        WORKLOAD_BYTES
    );
    assert_eq!(
        plan.config.max_reservations,
        AdmissionConfig::default().max_reservations
    );
    assert_eq!(plan.config.high_water_bytes, None);
    Ok(())
}

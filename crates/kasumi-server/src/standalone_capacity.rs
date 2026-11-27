//! What a node's roster needs from the configuration that hosts it.
//!
//! Control and every tenant without its own database run as groups on one
//! memory core and in the node's shared database. Each open group holds a
//! startup-inventory slot, about a dozen admission ledger charges and pins of
//! the shared database for as long as it is open. When a standalone roster
//! outgrew these, activation failed at tenant N: with `ResourceExhausted` at
//! the 64th tenant's preparation in a generated installation, or, at the
//! shared pins, with an uncertain outcome. Staging and every configuration
//! load now refuse such a roster first with `RosterExceedsCapacity`, which
//! names the setting and the value the roster needs.
//!
//! The shared database also keeps `critical_pin_reserve` of its snapshot pins
//! from ordinary credits (snapshot leases and cursors), so that client
//! holders can never starve writes, applies and their successor captures,
//! the service audit, Control or activation (Codex G02 ruling, section 3).
use crate::audit_destination::{AuditDestinationConfig, TenantAuditPlacementConfig};
use crate::runtime::{DeploymentMode, RuntimeConfig};

/// Admission ledger charges an open standalone group (Control or a tenant)
/// holds while idle. Installed 1,000-tenant runs measured 12.0 per group.
pub const GROUP_RESERVATIONS: usize = 12;
/// Ledger charges the node holds besides its groups: 12,052 live charges at
/// 1,001 groups less 12 per group, rounded up.
pub const NODE_RESERVATIONS: usize = 64;
/// Ledger charges left for request and maintenance work, besides the cache
/// work reserve.
pub const WORK_RESERVATIONS: usize = 1024;
/// Directory owners a standalone node keeps open besides tenant audit
/// destinations (5 at idle, measured), with room for backups and staging.
/// Every local tenant audit cache shares one directory owner.
pub const NODE_DIRECTORY_OWNERS: u32 = 32;
/// Standing pin credits per application of the shared database: its current
/// selection and the older one its located rows may still read through.
pub const STANDING_PINS_PER_GROUP: usize = 2;
/// Pins one admitted critical job may hold: two borrowed generations with
/// their fallbacks, two native read views, a publication writer and a
/// prospective successor capture.
pub const PINS_PER_CRITICAL_JOB: usize = 8;
/// Independently scheduled critical jobs besides tenant work: Control,
/// service-audit records, activation or reopen, and required maintenance.
pub const NODE_CRITICAL_JOBS: usize = 4;
/// Pins a roster must leave for ordinary credits.
pub const MIN_ORDINARY_PINS: usize = 256;
/// The `setting` of a refusal at the shared database's pins. Its pin count
/// is fixed; the reserve grows with the tenants and with
/// `admission.max_inflight_operations`.
pub const SHARED_PINS_SETTING: &str =
    "snapshot pins of the shared node database (reserve plus 256 ordinary)";

/// A roster the configuration cannot host.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RosterExceedsCapacity {
    /// Configured tenants, the initial tenant included.
    pub tenants: usize,
    /// The setting that is too small.
    pub setting: &'static str,
    pub configured: u64,
    /// What this roster needs.
    pub required: u64,
    /// The most tenants the configured value holds, for a per-tenant limit.
    pub holds: Option<usize>,
}
impl std::fmt::Display for RosterExceedsCapacity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the standalone roster of {} tenants needs {} of at least {}, but it is {}",
            self.tenants, self.setting, self.required, self.configured
        )?;
        if let Some(holds) = self.holds {
            write!(f, ", which holds {holds} tenants")?;
        }
        if self.setting == SHARED_PINS_SETTING {
            write!(
                f,
                "; the pin count is fixed: lower admission.max_inflight_operations with the \
                 installation stopped or stage fewer tenants"
            )
        } else {
            write!(
                f,
                "; raise it with the installation stopped (docs/standalone.md lists a 1,000-tenant \
                 profile) or stage fewer tenants"
            )
        }
    }
}
impl std::error::Error for RosterExceedsCapacity {}

/// Pins of the shared node database kept from ordinary credits for `tenants`
/// tenants sharing it and `concurrency` admitted tenant jobs:
/// R(T, C) = 2(T + 1) + 8(min(T, C) + 4). The first term covers every
/// application's standing selections (Control included); the second every
/// critical job, including slots promised but not yet bound.
pub fn critical_pin_reserve(tenants: usize, concurrency: usize) -> usize {
    STANDING_PINS_PER_GROUP
        .saturating_mul(tenants.saturating_add(1))
        .saturating_add(
            PINS_PER_CRITICAL_JOB
                .saturating_mul(tenants.min(concurrency).saturating_add(NODE_CRITICAL_JOBS)),
        )
}

/// The reserve the ruling sizes for this configuration's roster, uncapped.
pub fn ruled_pin_reserve(config: &RuntimeConfig) -> usize {
    critical_pin_reserve(
        config.tenants.len(),
        config.admission.max_inflight_operations,
    )
}

/// The reserve this configuration's shared node database keeps. A
/// standalone roster that needs more is refused by `check`; any other node
/// keeps at least `MIN_ORDINARY_PINS` ordinary pins, and its open logs
/// `snapshot_pin_reserve_capped` when that cap applies.
pub fn configured_pin_reserve(config: &RuntimeConfig) -> usize {
    ruled_pin_reserve(config).min(kasumi_store::SHARED_NODE_SNAPSHOT_PINS - MIN_ORDINARY_PINS)
}

/// Ledger charges a standalone node with `tenants` tenants needs: its idle
/// groups and node charges, the cache work reserve and work headroom.
pub fn required_reservations(config: &RuntimeConfig, tenants: usize) -> usize {
    let policy = &config.admission;
    let cache_slots = policy
        .cache_work_reserve_slots
        .unwrap_or((policy.max_reservations / 4).clamp(1, 64));
    NODE_RESERVATIONS
        .saturating_add(WORK_RESERVATIONS)
        .saturating_add(cache_slots)
        .saturating_add(tenants.saturating_add(1).saturating_mul(GROUP_RESERVATIONS))
}

/// Directory owners a standalone roster needs: the node's own and one per
/// distinct external filesystem audit destination. Local caches share one.
pub fn required_directory_owners(config: &RuntimeConfig) -> u32 {
    let external = config
        .tenant_audit_placements
        .values()
        .filter_map(|placement| match placement {
            TenantAuditPlacementConfig::External {
                destination: AuditDestinationConfig::Filesystem { directory },
            } => Some(directory),
            _ => None,
        })
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    NODE_DIRECTORY_OWNERS.saturating_add(u32::try_from(external).unwrap_or(u32::MAX))
}

/// The most tenants `available` holds at `per_group` per group (Control
/// counts as one) beyond `fixed`.
fn holds(available: u64, fixed: u64, per_group: u64) -> usize {
    usize::try_from(available.saturating_sub(fixed) / per_group.max(1))
        .unwrap_or(usize::MAX)
        .saturating_sub(1)
}

/// Check a standalone configuration's roster against the limits every open
/// group draws on, in the order a growing roster would reach them.
/// Replicated nodes are not sized here.
pub fn check(config: &RuntimeConfig) -> Result<(), RosterExceedsCapacity> {
    if config.mode != DeploymentMode::Standalone || config.control.is_none() {
        return Ok(());
    }
    let tenants = config.tenants.len();
    let groups = tenants.saturating_add(1);
    let refuse = |setting, configured: u64, required: u64, holds| RosterExceedsCapacity {
        tenants,
        setting,
        configured,
        required,
        holds,
    };
    let startups = config.admission.max_snapshot_startups;
    if startups < groups {
        return Err(refuse(
            "admission.max_snapshot_startups",
            startups as u64,
            groups as u64,
            Some(startups.saturating_sub(1)),
        ));
    }
    let reservations = config.admission.max_reservations;
    let needed = required_reservations(config, tenants);
    if reservations < needed {
        let fixed = needed - groups * GROUP_RESERVATIONS;
        return Err(refuse(
            "admission.max_reservations",
            reservations as u64,
            needed as u64,
            Some(holds(
                reservations as u64,
                fixed as u64,
                GROUP_RESERVATIONS as u64,
            )),
        ));
    }
    let directories = config.persistent_disk.max_open_directories;
    let owners = required_directory_owners(config);
    if directories < owners {
        return Err(refuse(
            "persistent_disk.max_open_directories",
            directories.into(),
            owners.into(),
            None,
        ));
    }
    let pins = kasumi_store::SHARED_NODE_SNAPSHOT_PINS;
    let concurrency = config.admission.max_inflight_operations;
    let needed = critical_pin_reserve(tenants, concurrency).saturating_add(MIN_ORDINARY_PINS);
    if pins < needed {
        let holds = (0..tenants).rev().find(|tenants| {
            critical_pin_reserve(*tenants, concurrency).saturating_add(MIN_ORDINARY_PINS) <= pins
        });
        return Err(refuse(
            SHARED_PINS_SETTING,
            pins as u64,
            needed as u64,
            holds,
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_pin_reserve_follows_the_ruling() {
        // R(T, C) = 2(T + 1) + 8(min(T, C) + 4).
        assert_eq!(critical_pin_reserve(1_000, 64), 2_546);
        assert_eq!(critical_pin_reserve(1_164, 64), 2_874);
        assert_eq!(critical_pin_reserve(63, 64), 664);
        assert_eq!(critical_pin_reserve(1, 64), 44);
        assert!(
            critical_pin_reserve(1_164, 64) + MIN_ORDINARY_PINS
                <= kasumi_store::SHARED_NODE_SNAPSHOT_PINS
        );
    }

    /// The installed metadata quote of a disk's components, as
    /// `generated_admission` charges it.
    fn quote(required: kasumi_store::DiskMemoryRequirements) -> u64 {
        [
            required.owner_bytes,
            required.registry_bytes,
            required.device_bytes,
            required.registration_bytes,
        ]
        .into_iter()
        .map(|bytes| {
            kasumi_engine::admission::MemoryCore::required_installed_reservation_bytes(bytes)
                .unwrap()
        })
        .sum()
    }

    /// The generated admission total docs/admission.md quotes (2 GiB of
    /// payload, five 64 MiB audit units and the installed metadata of both
    /// disks) for an installation path of `length` characters, with the
    /// persistent and scratch metadata quotes.
    fn generated(length: usize) -> (u64, u64, u64) {
        let base = std::path::PathBuf::from(format!("/{}", "i".repeat(length - 1)));
        let persistent = crate::persistent_disk::initial_config(
            std::collections::BTreeMap::from([
                ("data".into(), base.join("data")),
                ("backups".into(), base.join("backups")),
            ]),
            kasumi_store::DirectoryPolicy::fixture(),
            kasumi_store::FileAllocationPolicy::fixture(),
        )
        .unwrap();
        let scratch = kasumi_store::ScratchDiskConfig {
            directory: base.join("scratch"),
            ..crate::runtime::example_config(
                kasumi_store::DirectoryPolicy::fixture(),
                kasumi_store::FileAllocationPolicy::fixture(),
            )
            .unwrap()
            .scratch_disk
        };
        let total = crate::runtime::generated_admission(&persistent, &scratch)
            .unwrap()
            .max_inflight_bytes
            .unwrap();
        (
            total,
            quote(kasumi_store::NodeDisk::memory_requirements(&persistent).unwrap()),
            quote(kasumi_store::ScratchDisk::memory_requirements(&scratch).unwrap()),
        )
    }

    #[test]
    fn generated_admission_matches_the_documented_quote() {
        let quoted = [35, 36, 62, 4096].map(generated);
        eprintln!(
            "generated admission (total, persistent quote, scratch quote) for 35, 36, 62 and 4,096 characters: {quoted:?}"
        );
        for (total, persistent, scratch) in quoted {
            assert_eq!(
                total,
                (2 << 30)
                    + 5 * kasumi_types::AuditRetentionBudget::MAINTENANCE_BYTES
                    + persistent
                    + scratch
            );
        }
        assert!(quoted.windows(2).all(|pair| pair[0].0 <= pair[1].0));
    }

    /// A standalone configuration with `tenants` tenants and the generated
    /// admission and disk limits.
    fn standalone(tenants: usize) -> RuntimeConfig {
        let mut config = crate::runtime::example_config(
            kasumi_store::DirectoryPolicy::fixture(),
            kasumi_store::FileAllocationPolicy::fixture(),
        )
        .unwrap();
        config.mode = DeploymentMode::Standalone;
        let template = config.tenants[0].clone();
        config.tenants = (0..tenants)
            .map(|index| crate::runtime::TenantConfig {
                tenant: format!("tenant-{index}"),
                ..template.clone()
            })
            .collect();
        config
    }

    /// The generated configuration holds Control and 63 tenants: the 64th is
    /// refused at the startup inventory, naming it and what it holds. The
    /// 1,000-tenant profile holds 1,000 tenants and refuses past its ledger.
    #[test]
    fn rosters_are_refused_at_the_first_limit_they_exceed() {
        assert_eq!(check(&standalone(63)), Ok(()));
        let refused = check(&standalone(64)).unwrap_err();
        assert_eq!(
            refused,
            RosterExceedsCapacity {
                tenants: 64,
                setting: "admission.max_snapshot_startups",
                configured: 64,
                required: 65,
                holds: Some(63),
            }
        );
        assert!(refused.to_string().contains("which holds 63 tenants"));
        let profile = |tenants| {
            let mut config = standalone(tenants);
            config.admission.max_snapshot_startups = 1_001;
            config.admission.max_reservations = 16_384;
            config.admission.max_inflight_bytes = Some(6 << 30);
            config.persistent_disk.max_open_directories = 1_536;
            config
        };
        assert_eq!(check(&profile(1_000)), Ok(()));
        // The generated reservation ledger alone holds 244 tenants.
        let mut ledger = standalone(300);
        ledger.admission.max_snapshot_startups = 1_001;
        let refused = check(&ledger).unwrap_err();
        assert_eq!(refused.setting, "admission.max_reservations");
        assert_eq!(refused.holds, Some(244));
        // Past 1,268 tenants the profile's ledger refuses, before its pins.
        let mut larger = profile(1_269);
        larger.admission.max_snapshot_startups = 1_270;
        let refused = check(&larger).unwrap_err();
        assert_eq!(refused.setting, "admission.max_reservations");
        assert_eq!(refused.holds, Some(1_268));
        // With a ledger large enough, the shared database's pins refuse.
        larger.admission.max_snapshot_startups = 2_000;
        larger.admission.max_reservations = 1 << 20;
        let mut pins = larger.clone();
        pins.tenants = standalone(1_700).tenants;
        let refused = check(&pins).unwrap_err();
        assert_eq!(refused.setting, SHARED_PINS_SETTING, "{refused}");
        assert_eq!(refused.holds, Some(1_647));
        assert!(
            refused
                .to_string()
                .contains("lower admission.max_inflight_operations"),
            "{refused}"
        );
        // Above the cap the reserve keeps 256 ordinary pins; only a node
        // `check` skips can reach it.
        assert_eq!(
            ruled_pin_reserve(&pins),
            critical_pin_reserve(1_700, pins.admission.max_inflight_operations)
        );
        assert_eq!(
            configured_pin_reserve(&pins),
            kasumi_store::SHARED_NODE_SNAPSHOT_PINS - MIN_ORDINARY_PINS
        );
        // Directory owners: the node's own plus external destinations.
        let mut directories = standalone(1);
        directories.persistent_disk.max_open_directories = NODE_DIRECTORY_OWNERS - 1;
        let refused = check(&directories).unwrap_err();
        assert_eq!(
            (refused.setting, refused.holds),
            ("persistent_disk.max_open_directories", None)
        );
        // Replicated nodes are not sized here.
        let mut replicated = standalone(64);
        replicated.mode = DeploymentMode::Replicated;
        assert_eq!(check(&replicated), Ok(()));
    }
}

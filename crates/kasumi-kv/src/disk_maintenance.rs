//! Bounded scheduling and the error boundary of the persisted compaction cycle.
//!
//! A step spends at most `units` bounded read-side items (a file probe, a
//! leaf or pack plan, `WALK_WORK_PER_UNIT` walker items) and `mutations`
//! durable publications (a maintenance commit, a phase transition, a garbage
//! retirement, or one unlink plus forget). Local outcomes — capacity
//! pressure and other refusals that leave every committed effect known — are
//! reported as a deferral with a step-count backoff and never fail the
//! caller. I/O, corruption, unknown outcomes and owner failure stay fatal and
//! fence through the ordinary `DiskState::run` path.

use super::*;
use crate::root::CompactionPhase;

/// Allowance of one maintenance call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaintenanceBudget {
    pub units: usize,
    pub mutations: usize,
}

/// Why a step stopped without a fatal error. Every cursor is kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MaintenanceDeferral {
    /// Workspace, memory or disk-space admission refused.
    Capacity,
    /// Another local refusal; the static reason is reported.
    Rejected(&'static str),
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum StorageCompactionPhase {
    #[default]
    Idle,
    Evacuating,
    Reclaiming,
    Packing,
}

impl StorageCompactionPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Evacuating => "evacuating",
            Self::Reclaiming => "reclaiming",
            Self::Packing => "packing",
        }
    }

    pub(crate) fn from_phase(phase: CompactionPhase) -> Self {
        match phase {
            CompactionPhase::Idle => Self::Idle,
            CompactionPhase::Evacuating => Self::Evacuating,
            CompactionPhase::Reclaiming => Self::Reclaiming,
            CompactionPhase::Packing => Self::Packing,
        }
    }
}

/// Work done by one step.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MaintenanceProgress {
    pub units: usize,
    pub mutations: usize,
    /// Nothing is due: the cycle is Idle and its measurement is current.
    pub idle: bool,
    pub deferred: Option<MaintenanceDeferral>,
    /// The phase after this step.
    pub phase: StorageCompactionPhase,
    pub phase_changed: bool,
    pub relocated_bytes: u64,
    pub reclaimed_files: u64,
    pub reclaimed_bytes: u64,
}

/// A database-level step; `Busy` while a writer holds the write gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MaintenanceStep {
    Busy,
    Ran(MaintenanceProgress),
}

/// Scheduling policy. A cycle becomes due when the measured retained bytes
/// reach `max(baseline * growth_percent / 100, baseline + slack_bytes)` or the
/// file count reaches the analogous file threshold.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaintenancePolicy {
    pub growth_percent: u32,
    pub slack_bytes: u64,
    pub slack_files: u64,
    /// Budget of the step every `Database::begin_write` runs first.
    pub inline_units: usize,
    pub inline_mutations: usize,
    pub capacity_backoff_steps: u64,
    pub rejected_backoff_steps: u64,
}

impl Default for MaintenancePolicy {
    fn default() -> Self {
        Self {
            growth_percent: 200,
            slack_bytes: 256 << 20,
            slack_files: 16,
            inline_units: 32,
            inline_mutations: 1,
            capacity_backoff_steps: 256,
            rejected_backoff_steps: 65_536,
        }
    }
}

impl MaintenancePolicy {
    pub fn validate(&self) -> Result<(), CoreError> {
        if self.growth_percent <= 100
            || self.growth_percent > 100_000
            || self.capacity_backoff_steps == 0
            || self.rejected_backoff_steps == 0
            || (self.inline_units == 0) != (self.inline_mutations == 0)
        {
            return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "maintenance policy is invalid",
            )));
        }
        Ok(())
    }

    pub(crate) fn inline_budget(&self) -> MaintenanceBudget {
        MaintenanceBudget {
            units: self.inline_units,
            mutations: self.inline_mutations,
        }
    }

    fn threshold(&self, baseline: u64, slack: u64) -> u64 {
        let grown = u128::from(baseline) * u128::from(self.growth_percent) / 100;
        u64::try_from(grown)
            .unwrap_or(u64::MAX)
            .max(baseline.saturating_add(slack))
    }

    pub(crate) fn trigger_bytes(&self, baseline: u64) -> u64 {
        self.threshold(baseline, self.slack_bytes)
    }

    pub(crate) fn trigger_files(&self, baseline: u64) -> u64 {
        self.threshold(baseline, self.slack_files)
    }
}

/// Owner-checked observation of one store's retained files and cycle.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StorageMaintenanceStatus {
    pub phase: StorageCompactionPhase,
    pub cycle: u64,
    /// A census completed in this process lifetime; file figures are its
    /// result and may lag files created since.
    pub measured: bool,
    pub segment_files: u64,
    pub segment_bytes: u64,
    pub arena_files: u64,
    pub arena_bytes: u64,
    /// Files recorded as garbage and still owed an unlink.
    pub garbage_files: u64,
    pub baseline_bytes: u64,
    pub baseline_files: u64,
    pub trigger_bytes: u64,
    pub trigger_files: u64,
    /// Old files the last completed reclamation kept only for pinned roots.
    pub snapshot_retained_files: u64,
    pub snapshot_retained_bytes: u64,
    pub reclaimed_files_total: u64,
    pub reclaimed_bytes_total: u64,
    pub relocated_bytes_total: u64,
    pub reclaim_invalidations_total: u64,
    pub capacity_deferrals_total: u64,
    pub rejected_deferrals_total: u64,
    pub cycles_completed: u64,
    pub requested: bool,
    pub last_deferral: Option<MaintenanceDeferral>,
}

/// A durable publication fits the remaining step budget.
pub(super) fn can_mutate(budget: MaintenanceBudget, progress: &MaintenanceProgress) -> bool {
    progress.mutations < budget.mutations
}

/// Present segment and arena files with identifiers in `[floor, next)`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Measurement {
    pub(super) segment_files: u64,
    pub(super) segment_bytes: u64,
    pub(super) arena_files: u64,
    pub(super) arena_bytes: u64,
    /// The newest confirmed identifiers when this census started.
    pub(super) last_segment_id: u64,
    pub(super) last_directory_id: u64,
}

impl Measurement {
    pub(super) fn files(&self) -> u64 {
        self.segment_files.saturating_add(self.arena_files)
    }
    pub(super) fn bytes(&self) -> u64 {
        self.segment_bytes.saturating_add(self.arena_bytes)
    }
}

/// The lowest identifier of each kind that can still be present.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct FileFloor {
    pub(super) segment: u64,
    pub(super) arena: u64,
}

impl Default for FileFloor {
    fn default() -> Self {
        Self {
            segment: 1,
            arena: 1,
        }
    }
}

/// One probe (exists, then len) per identifier, segments first.
pub(super) struct Census {
    measurement: Measurement,
    next_segment: u64,
    end_segment: u64,
    next_arena: u64,
    end_arena: u64,
}

impl Census {
    pub(super) fn start(floor: FileFloor, root: &Superblock) -> Self {
        let (end_segment, end_arena) = root.next_file_ids();
        Self {
            measurement: Measurement {
                last_segment_id: root.last_segment_id(),
                last_directory_id: root.last_directory_id(),
                ..Measurement::default()
            },
            next_segment: floor.segment,
            end_segment,
            next_arena: floor.arena,
            end_arena,
        }
    }

    /// Probe within `units`; returns the units charged and the completed
    /// measurement once every identifier was probed.
    pub(super) fn step(
        &mut self,
        backend: &dyn SegmentGroupBackend,
        units: usize,
    ) -> Result<(usize, Option<Measurement>), CoreError> {
        let mut used = 0;
        while used < units {
            let file = if self.next_segment < self.end_segment {
                self.next_segment += 1;
                GroupFile::segment(self.next_segment - 1)
            } else if self.next_arena < self.end_arena {
                self.next_arena += 1;
                GroupFile::directory(self.next_arena - 1)
            } else {
                return Ok((used, Some(self.measurement)));
            };
            used += 1;
            if !backend.exists(file)? {
                continue;
            }
            let len = backend.len(file)?;
            let (files, bytes) = match file.kind {
                crate::group::FileKind::Segment => (
                    &mut self.measurement.segment_files,
                    &mut self.measurement.segment_bytes,
                ),
                _ => (
                    &mut self.measurement.arena_files,
                    &mut self.measurement.arena_bytes,
                ),
            };
            *files += 1;
            *bytes = bytes.saturating_add(len);
        }
        let complete = self.next_segment >= self.end_segment && self.next_arena >= self.end_arena;
        Ok((used, complete.then_some(self.measurement)))
    }
}

/// Volatile scheduler state; the cycle itself is in the root.
#[derive(Default)]
pub(super) struct Maintenance {
    pub(super) policy: MaintenancePolicy,
    steps: u64,
    backoff_until: u64,
    pub(super) last_deferral: Option<MaintenanceDeferral>,
    capacity_deferrals: u64,
    rejected_deferrals: u64,
    pub(super) relocated_bytes: u64,
    pub(super) cycles_completed: u64,
}

fn rejected_reason(error: &CoreError) -> &'static str {
    match error.rejected_cause() {
        Some(crate::CoreErrorCause::InvalidInput(reason)) => reason,
        Some(crate::CoreErrorCause::MissingTable) => "maintenance met a missing table",
        Some(crate::CoreErrorCause::AllocationRefused(_)) => "native allocation refused",
        _ => "maintenance step refused",
    }
}

impl DiskState {
    /// One bounded maintenance step. Local outcomes return `Ok` with
    /// `deferred` set; only fatal errors return `Err`, after fencing.
    pub(crate) fn maintenance_step(
        &mut self,
        budget: MaintenanceBudget,
    ) -> Result<MaintenanceProgress, CoreError> {
        self.owner.check()?;
        let mut progress = MaintenanceProgress::default();
        self.maintenance.steps = self.maintenance.steps.saturating_add(1);
        if self.maintenance.steps < self.maintenance.backoff_until {
            progress.deferred = self.maintenance.last_deferral;
            progress.phase = self.storage_phase()?;
            return Ok(progress);
        }
        let result = self.run(|state| state.compact_steps(budget, &mut progress));
        match result {
            Ok(()) => {
                self.maintenance.last_deferral = None;
                progress.phase = self.storage_phase()?;
                Ok(progress)
            }
            Err(error)
                if error.fences_owner()
                    || self.owner.failed.load(Ordering::Acquire)
                    || self.writer.is_fenced()
                    || matches!(error.cause(), crate::CoreErrorCause::Closed) =>
            {
                Err(error)
            }
            Err(error) => {
                let (deferral, backoff) = if error.is_capacity_denied() {
                    self.maintenance.capacity_deferrals += 1;
                    (
                        MaintenanceDeferral::Capacity,
                        self.maintenance.policy.capacity_backoff_steps,
                    )
                } else {
                    self.maintenance.rejected_deferrals += 1;
                    (
                        MaintenanceDeferral::Rejected(rejected_reason(&error)),
                        self.maintenance.policy.rejected_backoff_steps,
                    )
                };
                self.local_reclaim_failure()?;
                self.maintenance.last_deferral = Some(deferral);
                self.maintenance.backoff_until = self.maintenance.steps.saturating_add(backoff);
                progress.deferred = Some(deferral);
                progress.phase = self.storage_phase()?;
                Ok(progress)
            }
        }
    }

    pub(crate) fn inline_maintenance_budget(&self) -> MaintenanceBudget {
        self.maintenance.policy.inline_budget()
    }

    pub(crate) fn configure_maintenance(
        &mut self,
        policy: MaintenancePolicy,
    ) -> Result<(), CoreError> {
        self.owner.check()?;
        policy.validate()?;
        self.maintenance.policy = policy;
        Ok(())
    }

    /// Ask for a cycle regardless of thresholds. An explicit request also
    /// clears any backoff so its first step runs immediately.
    pub(crate) fn request_compaction(&mut self) -> Result<(), CoreError> {
        self.owner.check()?;
        self.compact.requested = true;
        self.maintenance.backoff_until = 0;
        Ok(())
    }

    fn storage_phase(&self) -> Result<StorageCompactionPhase, CoreError> {
        Ok(StorageCompactionPhase::from_phase(
            self.owner.lock()?.compaction().phase(),
        ))
    }

    pub(crate) fn maintenance_status(&self) -> Result<StorageMaintenanceStatus, CoreError> {
        self.owner.check()?;
        let root = self.owner.lock()?;
        let record = *root.compaction();
        let garbage = root.garbage().len() as u64;
        drop(root);
        let measurement = self.compact.measurement;
        let policy = &self.maintenance.policy;
        let totals = &self.reclaim.totals;
        Ok(StorageMaintenanceStatus {
            phase: StorageCompactionPhase::from_phase(record.phase()),
            cycle: record.cycle(),
            measured: measurement.is_some(),
            segment_files: measurement.map_or(0, |m| m.segment_files),
            segment_bytes: measurement.map_or(0, |m| m.segment_bytes),
            arena_files: measurement.map_or(0, |m| m.arena_files),
            arena_bytes: measurement.map_or(0, |m| m.arena_bytes),
            garbage_files: garbage,
            baseline_bytes: record.baseline_bytes(),
            baseline_files: record.baseline_files(),
            trigger_bytes: policy.trigger_bytes(record.baseline_bytes()),
            trigger_files: policy.trigger_files(record.baseline_files()),
            snapshot_retained_files: totals.pin_retained_files,
            snapshot_retained_bytes: totals.pin_retained_bytes,
            reclaimed_files_total: totals.reclaimed_files,
            reclaimed_bytes_total: totals.reclaimed_bytes,
            relocated_bytes_total: self.maintenance.relocated_bytes,
            reclaim_invalidations_total: totals.invalidations,
            capacity_deferrals_total: self.maintenance.capacity_deferrals,
            rejected_deferrals_total: self.maintenance.rejected_deferrals,
            cycles_completed: self.maintenance.cycles_completed,
            requested: self.compact.requested,
            last_deferral: self.maintenance.last_deferral,
        })
    }
}

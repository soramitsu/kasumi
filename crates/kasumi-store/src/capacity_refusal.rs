//! Typed capacity refusals of the persistent and scratch disk owners. A
//! refusal names the admission check that refused and carries the byte or
//! entry counts it compared, never a path, tenant or key. It is `Copy`, so
//! denial paths stay allocation-free; it reaches callers as the typed
//! `ReserveError::Capacity` and is otherwise kept in the owner's snapshot.
use serde::Serialize;
use std::io;

/// The admission check that refused a reservation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapacityCheck {
    /// Children of one persistent directory, counting those that other
    /// namespace batches reserved, against the directory policy.
    PersistentDirectoryEntries,
    /// Persistent regular files, counting reserved ones, against
    /// `max_persistent_files`.
    PersistentFiles,
    /// Open persistent file owners, counting reserved descriptors, against
    /// `max_open_files`.
    PersistentOpenFiles,
    /// Charged persistent extents against `max_bytes`; foreground work
    /// leaves `maintenance_reserve_bytes` free.
    PersistentExtent,
    /// The filesystem floor: the device's promised growth, this request and
    /// `min_free_bytes` must fit the sampled `f_bavail`.
    PersistentFilesystemFloor,
    /// Charged scratch extents against the scratch `max_bytes`.
    ScratchExtent,
    /// Scratch files, counting reserved ones.
    ScratchFiles,
    /// The scratch owner's filesystem floor, as for the persistent one.
    ScratchFilesystemFloor,
}

impl CapacityCheck {
    pub const PERSISTENT: [Self; 5] = [
        Self::PersistentDirectoryEntries,
        Self::PersistentFiles,
        Self::PersistentOpenFiles,
        Self::PersistentExtent,
        Self::PersistentFilesystemFloor,
    ];
    pub const SCRATCH: [Self; 3] = [
        Self::ScratchExtent,
        Self::ScratchFiles,
        Self::ScratchFilesystemFloor,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PersistentDirectoryEntries => "persistent_directory_entries",
            Self::PersistentFiles => "persistent_files",
            Self::PersistentOpenFiles => "persistent_open_files",
            Self::PersistentExtent => "persistent_extent",
            Self::PersistentFilesystemFloor => "persistent_filesystem_floor",
            Self::ScratchExtent => "scratch_extent",
            Self::ScratchFiles => "scratch_files",
            Self::ScratchFilesystemFloor => "scratch_filesystem_floor",
        }
    }

    /// The position of this check in its owner's `PERSISTENT` or `SCRATCH` list.
    pub(crate) const fn slot(self) -> usize {
        match self {
            Self::PersistentDirectoryEntries | Self::ScratchExtent => 0,
            Self::PersistentFiles | Self::ScratchFiles => 1,
            Self::PersistentOpenFiles | Self::ScratchFilesystemFloor => 2,
            Self::PersistentExtent => 3,
            Self::PersistentFilesystemFloor => 4,
        }
    }

    pub const fn is_floor(self) -> bool {
        matches!(
            self,
            Self::PersistentFilesystemFloor | Self::ScratchFilesystemFloor
        )
    }
}

/// One refused check and the figures it compared. For a floor check
/// `in_use` is the device's promised growth (pending bytes), `limit` the
/// sampled `f_bavail`, `min_free` the floor and `filesystem` the device
/// number of the filesystem whose floor refused; for every other check
/// `min_free` is zero, `limit` is the configured ceiling and `filesystem`
/// is `None`, because those budgets are one owner total.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct CapacityRefusal {
    pub check: CapacityCheck,
    /// The increment the refused request asked for.
    pub requested: u64,
    /// What already counted against `limit` before this request.
    pub in_use: u64,
    pub limit: u64,
    pub min_free: u64,
    pub filesystem: Option<u64>,
}

impl CapacityRefusal {
    /// What the check could still have admitted: `limit - in_use - min_free`,
    /// negative once the floor is already overdrawn. The request was refused
    /// because `requested` exceeded it.
    pub fn headroom(&self) -> i128 {
        floor_headroom(self.limit, self.in_use, self.min_free)
    }
}

impl std::fmt::Display for CapacityRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.check.is_floor() {
            write!(f, "check={}", self.check.as_str())?;
            if let Some(device) = self.filesystem {
                write!(f, " filesystem={device}")?;
            }
            write!(
                f,
                " requested={} available={} pending={} min_free={} headroom={}",
                self.requested,
                self.limit,
                self.in_use,
                self.min_free,
                self.headroom(),
            )
        } else {
            write!(
                f,
                "check={} requested={} in_use={} limit={}",
                self.check.as_str(),
                self.requested,
                self.in_use,
                self.limit,
            )
        }
    }
}

impl std::error::Error for CapacityRefusal {}

/// The margin a floor check compares a request against: sampled `f_bavail`
/// less the device's promised growth and its `min_free` floor. A request of
/// `bytes` passes the floor exactly when `bytes <= floor_headroom(..)`.
pub(crate) fn floor_headroom(available: u64, pending: u64, min_free: u64) -> i128 {
    i128::from(available) - i128::from(pending) - i128::from(min_free)
}

/// Process-lifetime refusal counts of one owner's checks, kept with its
/// accounting state. Recording neither allocates nor fails.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RefusalLedger<const N: usize> {
    counts: [u64; N],
    last: Option<CapacityRefusal>,
}

impl<const N: usize> RefusalLedger<N> {
    pub(crate) fn record(&mut self, refusal: CapacityRefusal) -> CapacityRefusal {
        if let Some(count) = self.counts.get_mut(refusal.check.slot()) {
            *count = count.saturating_add(1);
        }
        self.last = Some(refusal);
        refusal
    }

    /// A fixed array, so a snapshot that reports it does not allocate.
    pub(crate) fn counts(&self, checks: [CapacityCheck; N]) -> [CapacityRefusalCount; N] {
        checks.map(|check| CapacityRefusalCount {
            check,
            refusals: self.counts[check.slot()],
        })
    }

    pub(crate) fn last(&self) -> Option<CapacityRefusal> {
        self.last
    }
}

impl<const N: usize> Default for RefusalLedger<N> {
    fn default() -> Self {
        Self {
            counts: [0; N],
            last: None,
        }
    }
}

/// How often one check refused since its owner opened in this process.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct CapacityRefusalCount {
    pub check: CapacityCheck,
    pub refusals: u64,
}

/// A refused reservation: either a typed capacity refusal, or an
/// observation or accounting failure that keeps its original `io::Error`.
/// Converting into `io::Error` maps a refusal to `StorageFull` without
/// allocating; callers that want the figures match on `Capacity` first.
#[derive(Debug)]
pub enum ReserveError {
    Capacity(CapacityRefusal),
    Failed(io::Error),
}

impl ReserveError {
    pub fn refusal(&self) -> Option<&CapacityRefusal> {
        match self {
            Self::Capacity(refusal) => Some(refusal),
            Self::Failed(_) => None,
        }
    }

    pub fn kind(&self) -> io::ErrorKind {
        match self {
            Self::Capacity(_) => io::ErrorKind::StorageFull,
            Self::Failed(error) => error.kind(),
        }
    }
}

impl From<io::Error> for ReserveError {
    fn from(error: io::Error) -> Self {
        Self::Failed(error)
    }
}

impl From<io::ErrorKind> for ReserveError {
    fn from(kind: io::ErrorKind) -> Self {
        Self::Failed(kind.into())
    }
}

impl From<ReserveError> for io::Error {
    fn from(error: ReserveError) -> Self {
        match error {
            ReserveError::Capacity(_) => io::ErrorKind::StorageFull.into(),
            ReserveError::Failed(error) => error,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_names_the_check_and_only_counts() {
        let floor = CapacityRefusal {
            check: CapacityCheck::PersistentFilesystemFloor,
            requested: 4096,
            in_use: 7 << 30,
            limit: 7 << 30,
            min_free: 256 << 20,
            filesystem: Some(2049),
        };
        assert_eq!(floor.headroom(), -(256 << 20));
        assert_eq!(
            floor.to_string(),
            format!(
                "check=persistent_filesystem_floor filesystem=2049 requested=4096 available={} pending={} min_free={} headroom=-{}",
                7u64 << 30,
                7u64 << 30,
                256u64 << 20,
                256u64 << 20
            )
        );
        let files = CapacityRefusal {
            check: CapacityCheck::PersistentOpenFiles,
            requested: 3,
            in_use: 1022,
            limit: 1024,
            min_free: 0,
            filesystem: None,
        };
        assert_eq!(
            files.to_string(),
            "check=persistent_open_files requested=3 in_use=1022 limit=1024"
        );
        let error: io::Error = ReserveError::Capacity(files).into();
        assert_eq!(error.kind(), io::ErrorKind::StorageFull);
        assert!(
            error.get_ref().is_none(),
            "refusals convert without a payload"
        );
    }

    #[test]
    fn ledger_counts_each_check_in_its_own_slot() {
        let mut ledger = RefusalLedger::<5>::default();
        for check in CapacityCheck::PERSISTENT {
            for _ in 0..=check.slot() {
                ledger.record(CapacityRefusal {
                    check,
                    requested: 1,
                    in_use: 0,
                    limit: 0,
                    min_free: 0,
                    filesystem: None,
                });
            }
        }
        for count in ledger.counts(CapacityCheck::PERSISTENT) {
            assert_eq!(count.refusals, count.check.slot() as u64 + 1);
        }
        assert_eq!(
            ledger.last().map(|refusal| refusal.check),
            Some(CapacityCheck::PersistentFilesystemFloor)
        );
        let mut scratch = RefusalLedger::<3>::default();
        scratch.record(CapacityRefusal {
            check: CapacityCheck::ScratchFilesystemFloor,
            requested: 1,
            in_use: 0,
            limit: 0,
            min_free: 0,
            filesystem: None,
        });
        assert_eq!(
            scratch
                .counts(CapacityCheck::SCRATCH)
                .iter()
                .map(|count| count.refusals)
                .collect::<Vec<_>>(),
            [0, 0, 1]
        );
    }
}

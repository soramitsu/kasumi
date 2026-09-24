//! One physical-inode key space for file and directory enrollment.
//!
//! The retained owner can create up to N files after a census enrolled up to
//! N + R directories. A replacement census visits at most N non-root entries,
//! so its union is bounded by N + R. These different peaks must both be funded.
use super::{AccountedDirectory, AccountedFile, NamespaceBinding};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum AccountedInode {
    File(AccountedFile),
    Directory(AccountedDirectory),
}
impl AccountedInode {
    pub(super) fn binding(&self) -> NamespaceBinding {
        match self {
            Self::File(entry) => entry.binding,
            Self::Directory(entry) => entry.binding,
        }
    }
    pub(super) fn file(&self) -> Option<&AccountedFile> {
        match self {
            Self::File(entry) => Some(entry),
            Self::Directory(_) => None,
        }
    }
    pub(super) fn file_mut(&mut self) -> Option<&mut AccountedFile> {
        match self {
            Self::File(entry) => Some(entry),
            Self::Directory(_) => None,
        }
    }
    pub(super) fn directory(&self) -> Option<&AccountedDirectory> {
        match self {
            Self::Directory(entry) => Some(entry),
            Self::File(_) => None,
        }
    }
    pub(super) fn directory_mut(&mut self) -> Option<&mut AccountedDirectory> {
        match self {
            Self::Directory(entry) => Some(entry),
            Self::File(_) => None,
        }
    }
}

/// Checked cardinalities, independent of readdir's treatment of dot entries.
/// Do not replace the retained limit by `census`: that reduces file admission
/// when the owner retains directories from an earlier census.
pub(super) fn capacities(entries: u64, roots: u64) -> Option<(u64, u64)> {
    let census = entries.checked_add(roots)?;
    let retained = census.checked_add(entries)?;
    Some((retained, census))
}

#[cfg(test)]
#[path = "ledger/tests.rs"]
mod tests;

/// Retained physical capacity and the smaller census logical cardinality.
pub(super) fn map_limits(config: &super::NodeDiskConfig) -> std::io::Result<(usize, usize)> {
    let roots = u64::try_from(config.roots.len()).map_err(|_| crate::disk_memory::overflow())?;
    let (retained, census) =
        capacities(config.max_census_entries, roots).ok_or_else(crate::disk_memory::overflow)?;
    Ok((
        usize::try_from(retained).map_err(|_| crate::disk_memory::overflow())?,
        usize::try_from(census).map_err(|_| crate::disk_memory::overflow())?,
    ))
}

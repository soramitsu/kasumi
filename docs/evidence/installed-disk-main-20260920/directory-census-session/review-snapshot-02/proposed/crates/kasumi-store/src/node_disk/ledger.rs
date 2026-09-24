//! One physical-inode key space for file and directory enrollment.
//!
//! Both retained banks fund the entire permitted namespace F + D + R. Census
//! work includes dot and EOF observations but never spends logical inode slots.
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

/// Retained and replacement banks have the same full logical inode capacity.
pub(super) fn capacities(files: u64, subdirectories: u64, roots: u64) -> Option<(u64, u64)> {
    let capacity = files.checked_add(subdirectories)?.checked_add(roots)?;
    Some((capacity, capacity))
}

#[cfg(test)]
#[path = "ledger/tests.rs"]
mod tests;

/// Both retained bank capacities, independent of census step work.
pub(super) fn map_limits(config: &super::NodeDiskConfig) -> std::io::Result<(usize, usize)> {
    let roots = u64::try_from(config.roots.len()).map_err(|_| crate::disk_memory::overflow())?;
    let (retained, census) =
        capacities(config.max_persistent_files, config.max_persistent_subdirectories, roots).ok_or_else(crate::disk_memory::overflow)?;
    Ok((
        usize::try_from(retained).map_err(|_| crate::disk_memory::overflow())?,
        usize::try_from(census).map_err(|_| crate::disk_memory::overflow())?,
    ))
}

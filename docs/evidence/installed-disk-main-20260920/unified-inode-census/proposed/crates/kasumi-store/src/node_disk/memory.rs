//! Fixed, checked resident workspace for retained metadata and its replacement peak.
use super::{AccountedInode, Identity, NodeDisk, NodeDiskConfig, census, directory, file, ledger};
use crate::disk_memory::{self, add, mul, size};
use std::{io, os::unix::ffi::OsStrExt, sync::Weak};

const FIXED_OWNER_WORKSPACE: u64 = 64 << 10;
const NATIVE_HANDLE_WORKSPACE: u64 = 4096;
const ALLOCATION_HEADROOM: u64 = 64;
const DIRECTORY_STREAM_WORKSPACE: u64 = 64 << 10;

// Covers a bounded table's load factor, power-of-two capacity and old/new
// allocations during growth. These are workspace estimates, not a promise
// about std's private allocator layout. Existing and replacement ledgers coexist.
fn table<T>(count: u64) -> io::Result<u64> {
    add(mul(mul(count.max(4), 4)?, add(size::<T>()?, 16)?)?, 4096)
}
impl NodeDisk {
    pub fn required_metadata_bytes(config: &NodeDiskConfig) -> anyhow::Result<u64> {
        config.validate()?;
        let depth = u64::from(config.max_depth);
        let handles = u64::from(config.max_open_files);
        let name = add(u64::from(config.max_name_bytes), 1)?;
        // Census visits at most N non-root entries, but later admission can
        // fill N file slots while all census directories remain. Existing and
        // replacement maps therefore have different simultaneous maxima.
        let (retained, replacement) = ledger::capacities(
            config.max_census_entries,
            u64::try_from(config.roots.len()).map_err(|_| disk_memory::overflow())?,
        )
        .ok_or_else(disk_memory::overflow)?;
        let ledgers = add(
            table::<(Identity, AccountedInode)>(retained)?,
            table::<(Identity, AccountedInode)>(replacement)?,
        )?;
        let live = table::<(Identity, Weak<file::FileOwner>)>(handles)?;
        let components = mul(
            depth,
            add(mul(2, size::<std::ffi::CString>()?)?, ALLOCATION_HEADROOM)?,
        )?;
        let paths = add(mul(2, name)?, mul(2, mul(depth, name)?)?)?;
        let handle = add(
            add(size::<file::FileOwner>()?, 16)?,
            add(NATIVE_HANDLE_WORKSPACE, add(paths, components)?)?,
        )?;
        // Publication prepares a new owner/path while the old owner is live.
        let owners = mul(add(handles, 1)?, handle)?;
        let directory_owner = add(
            add(size::<directory::DirectoryOwner>()?, 16)?,
            add(NATIVE_HANDLE_WORKSPACE, add(paths, components)?)?,
        )?;
        let directory_owners = mul(
            add(u64::from(config.max_open_directories), 1)?,
            directory_owner,
        )?;
        let cursors = mul(
            depth,
            add(
                DIRECTORY_STREAM_WORKSPACE,
                mul(4, size::<census::Cursor>()?)?,
            )?,
        )?;
        let census = add(cursors, add(name, 4096)?)?;
        let mut roots = 0;
        for (label, path) in &config.roots {
            let label = u64::try_from(label.len()).map_err(|_| disk_memory::overflow())?;
            let path = u64::try_from(path.as_os_str().as_bytes().len())
                .map_err(|_| disk_memory::overflow())?;
            let copies = mul(4, add(add(label, path)?, 1)?)?;
            let ancestors = mul(add(depth, 1)?, ALLOCATION_HEADROOM)?;
            let root = add(
                add(4096, size::<census::Root>()?)?,
                add(size::<NodeDiskConfig>()?, add(copies, ancestors)?)?,
            )?;
            roots = add(roots, root)?;
        }
        let base = add(FIXED_OWNER_WORKSPACE, disk_memory::arc::<Self>()?)?;
        Ok(add(
            base,
            add(
                ledgers,
                add(
                    live,
                    add(add(owners, directory_owners)?, add(census, roots)?)?,
                )?,
            )?,
        )?)
    }
}

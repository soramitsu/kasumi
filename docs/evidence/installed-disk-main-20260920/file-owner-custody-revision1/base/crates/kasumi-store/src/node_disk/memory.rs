//! Fixed, checked resident workspace for retained metadata and its replacement peak.
use super::{
    AccountedInode, Identity, NodeDisk, NodeDiskConfig, census, directory, file, fixed_map, ledger,
};
use crate::disk_memory::{self, add, mul, size};
use std::{io, os::unix::ffi::OsStrExt, sync::Weak};

const FIXED_OWNER_WORKSPACE: u64 = 64 << 10;
const NATIVE_HANDLE_WORKSPACE: u64 = 4096;
const ALLOCATION_HEADROOM: u64 = 64;
const DIRECTORY_STREAM_WORKSPACE: u64 = 64 << 10;

// A fixed HashMap bank has one pinned backing allocation. Keep the existing
// per-allocation platform allowance explicit; requested bytes alone do not
// prove allocator/RSS ownership. Two banks remain resident throughout census.
fn banks<V>(count: usize) -> io::Result<u64> {
    mul(2, add(fixed_map::bank_bytes::<V>(count)?, 4096)?)
}
impl NodeDisk {
    pub fn required_metadata_bytes(config: &NodeDiskConfig) -> anyhow::Result<u64> {
        config.validate()?;
        let depth = u64::from(config.max_depth);
        let handles = u64::from(config.max_open_files);
        let name = add(u64::from(config.max_name_bytes), 1)?;
        let (retained, _replacement) = ledger::map_limits(config)?;
        // Both banks fund the full F+D+R namespace. The inactive bank receives
        // census and is also the pre-effect tombstone rebuild workspace.
        // No third map and no post-publication expansion allocation exist.
        let ledgers = banks::<AccountedInode>(retained)?;
        let live = banks::<Weak<file::FileOwner>>(
            usize::try_from(handles).map_err(|_| disk_memory::overflow())?,
        )?;
        let components = mul(
            depth,
            add(mul(2, size::<std::ffi::CString>()?)?, ALLOCATION_HEADROOM)?,
        )?;
        let paths = add(mul(2, name)?, mul(2, mul(depth, name)?)?)?;
        let parent_ancestry = disk_memory::allocation::<Identity>(depth)?;
        let handle = add(
            add(size::<file::FileOwner>()?, 16)?,
            add(
                NATIVE_HANDLE_WORKSPACE,
                add(parent_ancestry, add(paths, components)?)?,
            )?,
        )?;
        // Publication prepares a new owner/path while the old owner is live.
        // A terminal reader/writer has one counted file owner for its complete
        // lifetime. Fund its actual fixed buffer/header plus streaming hash
        // state per H slot, including the prepared owner, before any operation.
        // Returned ciphertext allocations keep the existing caller byte bound.
        let terminal_io = add(
            crate::backup_sessions::filesystem::TERMINAL_IO_BUFFER_BYTES as u64,
            add(mul(2, size::<sha2::Sha256>()?)?, ALLOCATION_HEADROOM)?,
        )?;
        let owners = mul(add(handles, 1)?, add(handle, terminal_io)?)?;
        let directory_owner = add(
            add(size::<directory::DirectoryOwner>()?, 16)?,
            add(
                NATIVE_HANDLE_WORKSPACE,
                add(parent_ancestry, add(paths, components)?)?,
            )?,
        )?;
        let directory_owners = mul(
            add(u64::from(config.max_open_directories), 1)?,
            directory_owner,
        )?;
        // Operational cursors retain counted DirectoryOwners, so a census may
        // not overlap them. At most max_depth operational streams reuse these
        // existing census slots. This does not qualify the underlying native
        // stream allowance or the allocator physical footprint.
        if size::<directory::NodeDiskDirectoryCursor>()? > mul(4, size::<census::Cursor>()?)? {
            return Err(io::Error::from(io::ErrorKind::InvalidData).into());
        }
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
        // A single six-part plan retains exact names until settlement. Its actual
        // Arc allocations transfer into the already counted future owner slots;
        // only plan paths/components remain additional to those owner envelopes.
        let root_path = config
            .roots
            .values()
            .map(|path| path.as_os_str().as_bytes().len())
            .max()
            .unwrap_or(0);
        let root_path = u64::try_from(root_path).map_err(|_| disk_memory::overflow())?;
        // Per part: retained exact plan components plus caller absolute PathBuf,
        // request view and a bounded collection slot. These remain live while
        // actual owner backing transfers. All six slots are funded, even for a
        // smaller plan. Native allocator/RSS qualification remains separate.
        let caller_path = add(add(root_path, mul(depth, name)?)?, 1)?;
        let caller_slot = add(
            add(caller_path, 256)?,
            size::<super::batch::NamespacePart<'static>>()?,
        )?;
        let admission_paths = mul(
            super::batch::MAX_NAMESPACE_PARTS as u64,
            add(add(paths, components)?, caller_slot)?,
        )?;
        let base = add(
            add(FIXED_OWNER_WORKSPACE, admission_paths)?,
            disk_memory::arc::<Self>()?,
        )?;
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

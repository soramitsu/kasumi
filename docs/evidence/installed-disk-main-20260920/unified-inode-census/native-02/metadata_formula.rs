#![allow(dead_code)]
use std::{collections::{BTreeMap,HashMap},ffi::CString,fs::File,path::PathBuf,sync::{Arc,Mutex,Weak}};
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Ord, PartialOrd)] struct Identity(u64,u64);
#[derive(Clone, Copy, Debug, PartialEq, Eq)] struct NamespaceBinding([u8;32]);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AccountedFile {
    binding: NamespaceBinding,
    bytes: u64,
    pending: u64,
    actual_len: u64,
    reserved_len: u64,
    settled: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AccountedDirectory {
    binding: NamespaceBinding,
    parent: Option<Identity>,
    bytes: u64,
    len: u64,
    children: u64,
    live_handles: u32,
}
impl AccountedFile {
    fn durable(binding: NamespaceBinding, bytes: u64, pending: u64, len: u64) -> Self {
        Self {
            binding,
            bytes,
            pending,
            actual_len: len,
            reserved_len: len,
            settled: true,
        }
    }
}
#[path = "/Users/mtakemiya/dev/kasumi/target/installed-disk-validation/unified-inode-census/proposed/crates/kasumi-store/src/node_disk/ledger.rs"] mod ledger;
use ledger::AccountedInode;
extern crate self as anyhow;
pub type Result<T> = std::result::Result<T,std::io::Error>;
extern crate self as uuid;
#[repr(transparent)] pub struct Uuid([u8;16]);
mod libc { pub enum DIR {} }
trait NodeDiskMemoryAdmission: Send + Sync {}
trait RetireLease: Send + Sync {}
struct DiskMemoryLease(Option<Box<dyn RetireLease>>);
type Lease = DiskMemoryLease;
pub struct NodeDiskConfig {
    /// Exact private, non-overlapping persistent roots on one filesystem.
    pub roots: BTreeMap<String, PathBuf>,
    pub max_bytes: u64,
    pub maintenance_reserve_bytes: u64,
    pub min_free_bytes: u64,
    /// Simultaneous file owners. Each owner retains at most two descriptors.
    pub max_open_files: u32,
    /// Independent operational directory descriptors, separate from file owners.
    pub max_open_directories: u32,
    /// Bounds census traversal work and the separately admitted file count.
    /// Directories also occupy the unified inode ledger. File creation retains
    /// its full count allowance after census; it does not spend directory slots.
    /// An incomplete census never opens admission; new files require a free slot.
    pub max_census_entries: u64,
    /// Bounds traversal stack, ownership ancestor locks and path walk depth.
    pub max_depth: u32,
    /// Bound each directory entry before copying its name.
    pub max_name_bytes: u32,
}
impl NodeDiskConfig { fn validate(&self) -> Result<()> { Ok(()) } }
pub enum NodeDiskPhase {
    Open,
    Paused,
    Failed,
}
struct State {
    phase: NodeDiskPhase,
    bytes: u64,
    pending: u64,
    files: u64,
    open_files: u32,
    open_directories: u32,
    directory_bytes: u64,
    directories: u64,
    live: HashMap<Identity, Weak<file::FileOwner>>,
    accounted: HashMap<Identity, AccountedInode>,
}
pub struct NodeDisk {
    config: NodeDiskConfig,
    memory: Arc<dyn NodeDiskMemoryAdmission>,
    roots: BTreeMap<String, Root>,
    _ancestor_locks: Vec<File>,
    device: DeviceDisk,
    unit: u64,
    state: Mutex<State>,
    #[cfg(test)]
    available_override: Mutex<Option<u64>>,
    #[cfg(test)]
    available_error: AtomicBool,
    #[cfg(test)]
    // Prepare fixture synchronization as well: Darwin's std mutex creates its
    // native mutex lazily, and these hooks first run inside measured I/O/Drop.
    after_file_close: Mutex<Option<file::ClosePause>>,
    #[cfg(test)]
    shrink_failure: Mutex<Option<file::ShrinkFailure>>,
    #[cfg(test)]
    parent_sync_failure: AtomicBool,
    #[cfg(test)]
    namespace_failure: std::sync::atomic::AtomicU8,
    // Every covered collection/path/descriptor owner is destroyed first.
    _memory_charge: Lease,
}
pub(crate) struct DeviceDisk {
    device: Arc<Device>,
    id: uuid::Uuid,
}
struct Device;
mod file { use super::*;
struct Budget {
    file: Option<File>,
    bytes: u64,
    pending: u64,
    reserved_len: u64,
    actual_len: u64,
    settled: bool,
}
pub(super) struct FileOwner {
    disk: Arc<NodeDisk>,
    root: String,
    relative: PathBuf,
    // Parent path names are validated and allocated once during acquisition.
    // I/O verifies every current ancestor using these original names.
    parent_names: Box<[CString]>,
    parent: Option<File>,
    name: Option<CString>,
    identity: Identity,
    binding: NamespaceBinding,
    budget: Option<Mutex<Budget>>,
    registration: usize,
}
}
mod directory { use super::*;
pub(super) struct DirectoryOwner {
    disk: Arc<NodeDisk>,
    root: String,
    names: Box<[CString]>,
    identity: Identity,
    file: Option<File>,
    #[cfg(test)]
    after_close: Option<std::sync::Mutex<Option<ClosePause>>>,
}
}
mod census { use super::*;
pub(super) struct Root {
    pub(super) path: PathBuf,
    // Prepared before the owner is published. std path conversion may allocate
    // for long paths and cannot be used after redb's winning commit header.
    path_c: CString,
    pub(super) file: File,
    pub(super) identity: Identity,
}
pub(super) struct Cursor {
    identity: Identity,
    binding: NamespaceBinding,
    file: File,
    entries: *mut libc::DIR,
}
}
use census::Root;
mod disk_memory { use std::io; const ALLOCATION_ALLOWANCE:u64=4096;
pub(crate) fn overflow() -> io::Error {
    io::ErrorKind::InvalidInput.into()
}
pub(crate) fn add(left: u64, right: u64) -> io::Result<u64> {
    left.checked_add(right).ok_or_else(overflow)
}
pub(crate) fn mul(left: u64, right: u64) -> io::Result<u64> {
    left.checked_mul(right).ok_or_else(overflow)
}
pub(crate) fn size<T>() -> io::Result<u64> {
    u64::try_from(std::mem::size_of::<T>()).map_err(|_| overflow())
}
pub(crate) fn allocation<T>(count: u64) -> io::Result<u64> {
    add(mul(size::<T>()?, count)?, ALLOCATION_ALLOWANCE)
}
pub(crate) fn arc<T>() -> io::Result<u64> {
    add(allocation::<T>(1)?, 2 * size::<usize>()?)
}


}
#[path = "/Users/mtakemiya/dev/kasumi/target/installed-disk-validation/unified-inode-census/proposed/crates/kasumi-store/src/node_disk/memory.rs"] mod memory;
fn main() {
    println!("Exact proposed memory.rs and ledger.rs, extracted field declarations; stub validation and external pointed-to implementations. Layout/formula evidence only, not compiled production/RSS qualification.");
    println!("AccountedFile={} AccountedDirectory={} AccountedInode={} Identity={} FileOwner={} DirectoryOwner={} State={} NodeDisk={}", size_of::<AccountedFile>(),size_of::<AccountedDirectory>(),size_of::<AccountedInode>(),size_of::<Identity>(),size_of::<file::FileOwner>(),size_of::<directory::DirectoryOwner>(),size_of::<State>(),size_of::<NodeDisk>());
    for (entries,handles,roots) in [(1_000_000,4096,vec![("data", "/var/lib/kasumi/data")]), (1_000_000,4096,vec![("data", "/var/lib/kasumi/data"),("metadata", "/var/lib/kasumi/metadata")]), (16_384,256,vec![("fixture", "/tmp/fixture-root-xx")])] {
        let config=NodeDiskConfig{roots:roots.iter().map(|(k,v)|(k.to_string(),PathBuf::from(v))).collect(),max_bytes:128<<30,maintenance_reserve_bytes:1<<30,min_free_bytes:1<<30,max_open_files:handles,max_open_directories:handles,max_census_entries:entries,max_depth:64,max_name_bytes:255};
        let (old,new)=ledger::capacities(entries,roots.len() as u64).unwrap();
        let table=|n:u64| 4*n.max(4)*(size_of::<(Identity,AccountedInode)>() as u64+16)+4096;
        let total=NodeDisk::required_metadata_bytes(&config).unwrap();
        println!("entries={entries} file_handles={handles} directory_handles={handles} roots={roots:?} old_max={old} new_max={new} old_table_bytes={} new_table_bytes={} total_metadata={total} mib={:.6} remaining_2gib={} ",table(old),table(new),total as f64/(1<<20) as f64,(2u64<<30)-total);
    }
}

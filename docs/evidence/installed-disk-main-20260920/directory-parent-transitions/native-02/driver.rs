#![allow(dead_code)]
#[path = "/Users/mtakemiya/dev/kasumi/target/installed-disk-validation/directory-parent-transitions/native-02/disk_memory.rs"] mod disk_memory;
#[path = "/Users/mtakemiya/dev/kasumi/target/installed-disk-validation/directory-parent-transitions/native-02/device_disk.rs"] mod device_disk;
mod node_disk;
pub use disk_memory::DiskOpenError;
use std::{collections::BTreeMap, path::{Path,PathBuf}, sync::Arc, os::unix::fs::{DirBuilderExt, MetadataExt}};
use node_disk::{NodeDisk,NodeDiskConfig,DirectoryPolicy,CensusCancellation,DiskWork,NodeDiskPhase};
struct FixtureAdmission;
impl disk_memory::NodeDiskMemoryAdmission for FixtureAdmission {
    fn reserve_installed(self:Arc<Self>, _bytes:u64)->std::io::Result<disk_memory::DiskMemoryLease> {
        Ok(disk_memory::DiskMemoryLease::new(()))
    }
}
fn mkdir(path:&Path) { std::fs::DirBuilder::new().mode(0o700).create(path).unwrap(); }
fn main() {
    println!("Exact proposed NodeDisk/census/directory/file/namespace/ledger/memory implementation with frozen existing disk_memory/device_disk. Fixture-only memory provider, no RSS or filesystem-growth qualification.");
    let root=PathBuf::from(std::env::args_os().nth(1).unwrap());assert!(!root.exists());mkdir(&root);
    for name in ["child","a","a/b","c"] { mkdir(&root.join(name)); }
    let config=NodeDiskConfig {roots:BTreeMap::from([("data".into(),root.clone())]),max_bytes:64<<20,maintenance_reserve_bytes:1<<20,min_free_bytes:0,max_open_files:16,max_open_directories:1,directory_policy:DirectoryPolicy::new(1<<20,32768).unwrap(),max_census_entries:16384,max_depth:64,max_name_bytes:255};
    let disk=NodeDisk::open(&config,Arc::new(FixtureAdmission),&CensusCancellation::default()).unwrap();
    let initial=disk.snapshot();assert_eq!(initial.persistent_directories,5);assert_eq!(initial.charged_bytes,5<<20);
    let dir=disk.open_directory("data",Path::new("")).unwrap();
    let file=disk.create_file("data",Path::new("first"),DiskWork::Foreground).unwrap();dir.sync_all().unwrap();
    assert_eq!(disk.snapshot().open_directories,1);assert_eq!(disk.snapshot().open_files,1);
    let file=disk.publish_file(file,"data",Path::new("second")).unwrap();dir.sync_all().unwrap();
    let file=disk.publish_file(file,"data",Path::new("child/last")).unwrap();dir.sync_all().unwrap();
    disk.delete_file(file).unwrap();dir.sync_all().unwrap();assert_eq!(disk.snapshot().persistent_files,0);
    assert_eq!(disk.snapshot().charged_bytes,initial.charged_bytes);drop(dir);
    println!("PASS managed create, same-parent rename, cross-parent rename, unlink, retained directory reads and independent quotas");
    let file=disk.create_file("data",Path::new("a/b/file"),DiskWork::Foreground).unwrap();
    let old=root.join("a/b").metadata().unwrap().ino();
    std::fs::rename(root.join("a"),root.join("swap")).unwrap();
    std::fs::rename(root.join("c"),root.join("a")).unwrap();
    std::fs::rename(root.join("swap"),root.join("c")).unwrap();
    std::fs::rename(root.join("c/b"),root.join("a/b")).unwrap();
    assert_eq!(root.join("a/b").metadata().unwrap().ino(),old);
    assert!(file.sync_all().is_err());assert_eq!(disk.snapshot().phase,NodeDiskPhase::Failed);drop(file);
    assert_eq!(disk.snapshot().open_files,0);disk.reconcile(&CensusCancellation::default()).unwrap();
    let file=disk.open_file("data",Path::new("a/b/file")).unwrap();disk.delete_file(file).unwrap();disk.pause().unwrap();
    println!("PASS surviving final parent inode does not hide an exchanged ancestor; actual file custody drains and fresh census repairs");
    let mut production=config.clone();production.max_census_entries=1_000_000;production.max_open_files=4096;production.max_open_directories=4096;production.roots=BTreeMap::from([("data".into(),PathBuf::from("/var/lib/kasumi/data"))]);
    let requirements=NodeDisk::memory_requirements(&production).unwrap();
    println!("metadata owner={} registry={} device={} registration={} max_bytes_2GiB={} RSS_plus_existing_reservations_headroom={}",requirements.owner_bytes,requirements.registry_bytes,requirements.device_bytes,requirements.registration_bytes,2u64<<30,(2u64<<30)-requirements.owner_bytes);
}

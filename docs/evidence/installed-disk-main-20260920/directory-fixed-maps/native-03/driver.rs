#![allow(dead_code, unused_imports)]
mod disk_memory;
mod device_disk;
mod node_disk;
mod private_files;
#[cfg(test)] mod test_utils;
#[cfg(test)] mod allocation_tests;
pub use disk_memory::{DiskOpenError, DiskMemoryLease, NodeDiskMemoryAdmission};
pub use node_disk::*;
fn main() {
    use std::{collections::BTreeMap,path::PathBuf};
    let config=NodeDiskConfig { roots:BTreeMap::from([("data".into(),PathBuf::from("/var/lib/kasumi/data"))]),max_bytes:64<<30,maintenance_reserve_bytes:8<<30,min_free_bytes:0,max_open_files:4096,max_open_directories:4096,directory_policy:DirectoryPolicy::new(1<<20,32768).unwrap(),max_census_entries:1_000_000,max_depth:64,max_name_bytes:255};
    let needed=NodeDisk::memory_requirements(&config).unwrap();
    println!("production owner={} registry={} device={} registration={} uncommitted_two_GiB_headroom={} RSS_plus_other_reservations=UNQUALIFIED",needed.owner_bytes,needed.registry_bytes,needed.device_bytes,needed.registration_bytes,(2u64<<30)-needed.owner_bytes-needed.registry_bytes-needed.device_bytes-needed.registration_bytes);
}

#![allow(dead_code, unused_imports)]
mod disk_memory;
mod device_disk;
mod node_disk;
mod private_files;
#[cfg(test)] mod test_utils;
#[cfg(test)] mod allocation_tests;
pub use disk_memory::{DiskOpenError, DiskMemoryLease, NodeDiskMemoryAdmission};
pub use node_disk::*;
fn main() { println!("production cursor modules compile; native tests exercise exact cfg(test) modules"); }

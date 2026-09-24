#[path = "/Users/mtakemiya/dev/kasumi/target/installed-disk-validation/disk-memory-lease-retirement/proposed/crates/kasumi-store/src/allocation_tests.rs"]
mod allocation_tests;
#[path = "lease-extracted.rs"]
mod disk_memory;
pub use disk_memory::{DiskMemoryLease,NodeDiskMemoryAdmission};
#[path = "provider-extracted.rs"]
mod test_utils;

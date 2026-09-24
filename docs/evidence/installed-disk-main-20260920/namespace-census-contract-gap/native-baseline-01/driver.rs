#![allow(dead_code,unused_imports)]
mod disk_memory; mod device_disk; mod node_disk; mod private_files; mod test_utils;
pub use disk_memory::{DiskOpenError, DiskMemoryLease, NodeDiskMemoryAdmission};
pub use node_disk::*;
use std::path::Path;
fn main() -> anyhow::Result<()> {
    let root = test_utils::private_tempdir()?;
    let mut config = NodeDisk::fixture_config(root.path().join("anchor"))?;
    config.max_census_entries = 8;
    let memory = test_utils::TestDiskMemory::new(256 << 20, 4096);
    let disk = test_utils::retry_disk_registry(|| NodeDisk::open_fixture(&config, memory.clone(), &CensusCancellation::default()))?;
    for index in 0..7 {
        let name = format!("file-{index}");
        let file = disk.create_file("fixture",Path::new(&name),DiskWork::Foreground)?;
        file.sync_all()?; file.settle_growth(0)?; drop(file);
        println!("accepted_and_settled={} persistent_files={} live_files={}",index+1,disk.snapshot().persistent_files,disk.snapshot().open_files);
    }
    disk.pause()?;
    let before = disk.snapshot();
    println!("baseline N={} admitted_files={} before_reconcile_bytes={} pending={}",config.max_census_entries,before.persistent_files,before.charged_bytes,before.pending_bytes);
    let outcome = disk.reconcile(&CensusCancellation::default());
    println!("after_reconcile phase={:?} retained_files={} retained_bytes={} memory_bytes={}",disk.snapshot().phase,disk.snapshot().persistent_files,disk.snapshot().charged_bytes,memory.snapshot().used_bytes);
    outcome?;
    println!("complete census accepted the same namespace");
    Ok(())
}

from pathlib import Path
p=Path(__file__).parent/'proposed/crates/kasumi-store/src/scratch_disk.rs'
s=p.read_text().replace('sync::{Arc, Mutex, Weak}','sync::{Arc, Mutex}')
s=s.replace('owner: Weak<ScratchDisk>,\n    // Covers this actual registry box and any inline owner Arc retained by Weak.','owner: Arc<ScratchDisk>,\n    // Installed ownership, like NodeDisk: this entry and its actual owner remain\n    // funded together until process exit, including external Weak observers.')
s=s.replace('''        let registry_bytes = disk_memory::add(
            disk_memory::allocation::<disk_memory::Entry<RegisteredScratch>>(1)?,
            disk_memory::arc::<Self>()?,
        )?;''','''        let registry_bytes =
            disk_memory::allocation::<disk_memory::Entry<RegisteredScratch>>(1)?;''')
s=s.replace('''        while let Some(dead) = registry.remove(|entry| entry.owner.strong_count() == 0) {
            drop(dead);
        }
        let existing = registry
            .iter()
            .filter_map(|entry| entry.owner.upgrade())
            .find(|owner| owner.config.directory == config.directory);''','''        let existing = registry
            .find(|entry| entry.owner.config.directory == config.directory)
            .map(|entry| entry.owner.clone());''')
s=s.replace('owner: Arc::downgrade(&disk),','owner: disk.clone(),')
start=s.index('impl Drop for ScratchDisk {');end=s.index('\nfn check_directory',start)
s=s[:start]+s[end:]
s=s.replace('fn scratch_reuse_and_actual_last_owner_drop_keep_exact_metadata_custody()', 'fn installed_scratch_reuse_keeps_metadata_funded_after_public_strong_handles_drop()')
s=s.replace('''        drop(same);
        assert_eq!(memory.snapshot(), held);
        drop(disk);
        assert_eq!(memory.snapshot().used_bytes, 0);
        assert_eq!(memory.snapshot().live_reservations, 0);''','''        let external_weak = Arc::downgrade(&disk);
        drop(same);
        assert_eq!(memory.snapshot(), held);
        drop(disk);
        assert_eq!(memory.snapshot(), held);
        let retained = external_weak.upgrade().expect("installed registry retains actual owner");
        let reopened = crate::test_utils::retry_disk_registry(|| {
            ScratchDisk::open_fixture(&config, memory.clone())
        }).unwrap();
        assert!(Arc::ptr_eq(&retained, &reopened));
        assert_eq!(memory.snapshot(), held);
        drop(retained);
        drop(reopened);
        drop(external_weak);
        assert_eq!(memory.snapshot(), held);''')
start=s.index('    #[test]\n    fn busy_scratch_registry_retains_weak_allocation_charge_until_real_removal()')
end=s.index('\n}\n\n#[cfg(test)]\nmod registry_busy_tests',start)
s=s[:start]+'''    #[test]
    fn scratch_file_release_does_not_release_installed_owner_or_registry_memory() {
        use std::io::Write;
        let directory = tempfile::tempdir().unwrap();
        let config = config(&directory, "scratch");
        let memory = TestDiskMemory::new(total(&config), 4);
        let disk = crate::test_utils::retry_disk_registry(|| {
            ScratchDisk::open_fixture(&config, memory.clone())
        }).unwrap();
        let held = memory.snapshot();
        let mut spool = crate::EncryptedSpool::new(&disk, 1 << 20).unwrap();
        spool.write_all(b"a real encrypted scratch file").unwrap();
        spool.flush().unwrap();
        assert_eq!(disk.snapshot().live_files, 1);
        assert!(disk.snapshot().charged_bytes > 0);
        drop(spool);
        assert_eq!(disk.snapshot().live_files, 0);
        assert_eq!(disk.snapshot().charged_bytes, 0);
        assert_eq!(disk.snapshot().filesystem_pending_bytes, 0);
        assert_eq!(memory.snapshot(), held);
        drop(disk);
        assert_eq!(memory.snapshot(), held);
    }
''' +s[end:]
p.write_text(s)

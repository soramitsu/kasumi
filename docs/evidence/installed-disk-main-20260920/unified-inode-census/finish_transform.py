from pathlib import Path
p=Path(__file__).resolve().parent/'proposed'
def edit(rel, replacements):
 f=p/rel;s=f.read_text()
 for a,b in replacements:
  assert a in s,(rel,a)
  s=s.replace(a,b)
 f.write_text(s)
mem='crates/kasumi-store/src/node_disk/memory.rs'
f=p/mem;s=f.read_text();s=s.replace('    AccountedDirectory, AccountedFile, Identity, NodeDisk, NodeDiskConfig, census, directory, file,','    AccountedInode, Identity, NodeDisk, NodeDiskConfig, census, directory, file, ledger,')
a=s.index('        let directory_ledgers =');b=s.index('        let live =',a)
s=s[:a]+'''        // Census visits at most N non-root entries, but later admission can
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
'''+s[b:];s=s.replace('                add(ledgers, directory_ledgers)?,','                ledgers,');f.write_text(s)
edit('crates/kasumi-store/src/node_disk/tests.rs',[
('assert!(disk.state.lock().unwrap().accounted.is_empty());','assert_eq!(disk.state.lock().unwrap().files, 0);'),
('assert_eq!(disk.state.lock().unwrap().accounted.len(), 3);','assert_eq!(disk.state.lock().unwrap().files, 3);'),
('disk.lock_state().accounted[&identity].settled','disk.lock_state().accounted[&identity].file().unwrap().settled'),
('disk.lock_state().accounted.values().next().unwrap().binding','disk.lock_state().accounted.values().filter_map(AccountedInode::file).next().unwrap().binding')])
edit('crates/kasumi-store/src/node_disk/directory/tests.rs',[
('let root = &state.directories[&Identity::of(&directory.path().metadata().unwrap())];','let root = state.accounted[&Identity::of(&directory.path().metadata().unwrap())].directory().unwrap();'),
('let child = &state.directories[&Identity::of(&child.metadata().unwrap())];','let child = state.accounted[&Identity::of(&child.metadata().unwrap())].directory().unwrap();'),
('let original = disk.lock_state().directories.clone();','let original = disk.lock_state().accounted.clone();'),
('assert_eq!(disk.lock_state().directories, original);','assert_eq!(disk.lock_state().accounted, original);')])
f=p/'crates/kasumi-store/src/node_disk/directory/tests.rs';s=f.read_text()+'''
#[test]
fn file_capacity_remains_independent_of_directory_membership() {
    let (directory, mut config, memory) = fixture();
    config.max_census_entries = 8;
    crate::private_files::create_directory(&directory.path().join("child")).unwrap();
    let disk = open(&config, &memory);
    // Both directories remain enrolled as each of the original eight file
    // slots is filled. Capping the union at N (+ roots) denies too early.
    for index in 0..8 {
        let relative = std::path::PathBuf::from(format!("file-{index}"));
        let file = disk.create_file("data", &relative, super::super::DiskWork::Foreground).unwrap();
        file.sync_all().unwrap();
        drop(file);
    }
    let state = disk.lock_state();
    assert_eq!(state.files, 8);
    assert_eq!(state.directories, 2);
    assert_eq!(state.accounted.len(), 10);
    drop(state);
    assert_eq!(disk.create_file("data", std::path::Path::new("overflow"), super::super::DiskWork::Foreground).unwrap_err().kind(), std::io::ErrorKind::StorageFull);
    assert!(!directory.path().join("overflow").exists());
    // This unchanged work limit may reject recensus even though the files
    // were individually admitted. Failure retains the entire old union.
    let old = disk.lock_state().accounted.clone();
    assert!(disk.reconcile(&CensusCancellation::default()).is_err());
    assert_eq!(disk.lock_state().accounted, old);
}
''';f.write_text(s)
# Required configuration field: all external production/fixture literals.
edit('crates/kasumi-server/src/persistent_disk.rs',[
('        max_open_files: 4096,','        max_open_files: 4096,\n        max_open_directories: 4096,'),
('    config.max_open_files = 256;','    config.max_open_files = 256;\n    config.max_open_directories = 256;')])
edit('crates/kasumi-server/src/runtime_memory.rs',[
('            max_open_files: 256,','            max_open_files: 256,\n            max_open_directories: 256,')])
f=p/'docs/standalone.md';s=f.read_text();s += '''
The first-release directory owner requires `persistent_disk.max_open_directories`
explicitly; the generated installed policy uses 4,096 directory owners alongside
4,096 file owners. There is no default or legacy field alias. The inode ledger
uses one physical-identity key space for files and directories. The one-million
limit continues to bound census work and separately retained regular-file count;
it is not a combined file/directory admission cap. Directory namespace mutation
adoption and filesystem growth qualification remain required before this draft
can become the installed implementation.
''';f.write_text(s)

from pathlib import Path
import shutil
root=Path('/Users/mtakemiya/dev/kasumi')
out=root/'target/installed-disk-validation/102-redb-terminal-corrections'
paths=['vendor/redb-4.2.0/src/tree_store/page_store/cached_file.rs','vendor/redb-4.2.0/src/retained_transaction_tests.rs','vendor/redb-4.2.0/src/admission/tests.rs','vendor/redb-4.2.0/src/db.rs']
for path in paths:
    for side in ['base','proposed']:
        dest=out/side/path
        dest.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(root/path,dest)
def edit(path,old,new):
    p=out/'proposed'/path
    text=p.read_text()
    assert text.count(old)==1,(path,text.count(old),old[:100])
    p.write_text(text.replace(old,new))
edit(paths[0],'''    fn io<T>(&self, result: core::result::Result<T, crate::io::Error>) -> Result<T> {
        result.map_err(|_| {
            self.fail_owner();
            StorageError::OwnerFailed
        })
    }''','''    fn io<T>(&self, result: core::result::Result<T, crate::io::Error>) -> Result<T> {
        result.map_err(|error| {
            // Fence later access without replacing this operation's original
            // I/O object. Its caller owns the actual cause of the uncertainty.
            self.fail_owner();
            StorageError::Io(error)
        })
    }''')
p=out/'proposed'/paths[0]
p.write_text(p.read_text()+'''\n#[cfg(test)]
#[path = "checked_backend_tests.rs"]
mod checked_backend_tests;
''')
edit(paths[1],'''    StorageBackend, TableDefinition, backends::FileBackend,''','''    StorageBackend, TableDefinition, TransactionError, backends::FileBackend,''')
edit(paths[1],'''    let reopened = Database::open(fixture.file.path(), fixture.owner).unwrap();''','''    let reopened = Database::builder(fixture.owner)
        .set_page_size(512)
        .set_region_size(16 << 10)
        .open(fixture.file.path())
        .unwrap();''')
edit(paths[1],'''    let recovered = Database::open(image.path(), crate::test_admission()).unwrap();''','''    let recovered = Database::builder(crate::test_admission())
        .set_page_size(512)
        .set_region_size(16 << 10)
        .open(image.path())
        .unwrap();''')
edit(paths[1],'''    assert!(write.transaction().is_none());
    let counts = fixture.counts();
    assert_eq!(terminal_error(&write.abort()), original);
    assert_eq!(terminal_error(&write.commit()), original);
    assert_eq!(fixture.counts(), counts);
    retain_failure(0, fixture, write);''','''    assert!(write.transaction().is_none());
    assert!(fixture.owner.failed.load(Ordering::Acquire));
    let counts = fixture.counts();
    assert!(matches!(
        fixture.database.begin_read(),
        Err(TransactionError::Storage(StorageError::OwnerFailed))
    ));
    assert!(matches!(
        fixture.database.begin_write(),
        Err(TransactionError::Storage(StorageError::OwnerFailed))
    ));
    assert_eq!(terminal_error(&write.abort()), original);
    assert_eq!(terminal_error(&write.commit()), original);
    assert_eq!(fixture.counts(), counts);
    retain_failure(0, fixture, write);''')
edit(paths[2],'''    StorageError, TableDefinition,
''','''    StorageError, TableDefinition, TransactionError,
''')
edit(paths[2],'''        assert!(matches!(
            write.commit(),
            Err(CommitError::Storage(StorageError::OwnerFailed))
        ));
        assert!(db.begin_write().is_err());
        assert!(db.begin_read().is_err());''','''        assert!(matches!(
            write.commit(),
            Err(CommitError::Storage(StorageError::Io(error)))
                if error.kind() == std::io::ErrorKind::Other
        ));
        assert!(matches!(
            db.begin_write(),
            Err(TransactionError::Storage(StorageError::OwnerFailed))
        ));
        assert!(matches!(
            db.begin_read(),
            Err(TransactionError::Storage(StorageError::OwnerFailed))
        ));''')
edit(paths[2],'''        db.close(),
        Err(CloseError::Storage(StorageError::OwnerFailed))
''','''        db.close(),
        Err(CloseError::Storage(StorageError::Io(error)))
            if error.kind() == std::io::ErrorKind::Other
''')
edit(paths[2],'''        result,
        Err(CommitError::Storage(StorageError::OwnerFailed))
    ));
    assert_eq!(allocations, 0);''','''        result,
        Err(CommitError::Storage(StorageError::Io(error)))
            if error.kind() == std::io::ErrorKind::Other
    ));
    assert_eq!(allocations, 0);''')
edit(paths[3],'''            result,
            CommitError::Storage(StorageError::OwnerFailed)
        ));
        let result = db.begin_write().err().unwrap();''','''            result,
            CommitError::Storage(StorageError::Io(error)) if error.kind() == ErrorKind::Other
        ));
        let result = db.begin_write().err().unwrap();''')
print('Prepared production mapping and four directly affected fixture/assertion changes; actual source unchanged.')

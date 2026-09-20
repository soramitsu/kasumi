//! The first release accepts exact canonical identities and rejects alternate protocols.
//! Identical canonical bytes are not a legacy decoder, regardless of their producer.
#[path = "common/admission.rs"]
mod admission_support;

#[derive(Debug)]
struct CollidingUserType;

impl redb::Value for CollidingUserType {
    type SelfType<'a> = u32;
    type AsBytes<'a> = [u8; 4];

    fn fixed_width() -> Option<usize> {
        Some(4)
    }

    fn from_bytes<'a>(data: &'a [u8]) -> u32
    where
        Self: 'a,
    {
        u32::from_le_bytes(data.try_into().unwrap())
    }

    fn as_bytes<'a, 'b: 'a>(value: &'a u32) -> [u8; 4]
    where
        Self: 'b,
    {
        value.to_le_bytes()
    }

    fn type_name() -> redb::TypeName {
        redb::TypeName::new("u32")
    }
}

fn create_tempfile() -> tempfile::NamedTempFile {
    tempfile::NamedTempFile::new().unwrap()
}

#[test]
fn upstream_single_phase_files_are_rejected_without_migration() {
    for format_v3 in [false, true] {
        let file = create_tempfile();
        {
            let db = redb2_6::Database::builder()
                .create_with_file_format_v3(format_v3)
                .create(file.path())
                .unwrap();
            let write = db.begin_write().unwrap();
            let table: redb2_6::TableDefinition<u64, Option<u32>> =
                redb2_6::TableDefinition::new("old");
            write
                .open_table(table)
                .unwrap()
                .insert(7, Some(11))
                .unwrap();
            write.commit().unwrap();
        }
        // Clean upstream close can mark the shared v3 layout as two-phase.
        // Force the unsupported one-phase protocol for this rejection case.
        let mut before = std::fs::read(file.path()).unwrap();
        before[9] &= !4;
        std::fs::write(file.path(), &before).unwrap();
        assert!(redb::Database::open(file.path(), admission_support::admission()).is_err());
        assert_eq!(
            std::fs::read(file.path()).unwrap(),
            before,
            "rejected file was mutated"
        );
    }
}

#[test]
fn upstream_savepoints_do_not_enable_a_legacy_open() {
    let file = create_tempfile();
    {
        let db = redb2_6::Database::builder()
            .create_with_file_format_v3(true)
            .create(file.path())
            .unwrap();
        let write = db.begin_write().unwrap();
        write.persistent_savepoint().unwrap();
        write.commit().unwrap();
    }
    let mut bytes = std::fs::read(file.path()).unwrap();
    bytes[9] &= !4;
    std::fs::write(file.path(), bytes).unwrap();
    assert!(redb::Database::open(file.path(), admission_support::admission()).is_err());
}

// The bug this guards against: a composite of a user-defined type must never silently alias the
// built-in composite with the same name string. Opening an `Option<user "u32">` table under the
// built-in `Option<u32>` must now fail with a type mismatch rather than misinterpreting the data.
#[test]
fn composite_of_user_type_does_not_alias_builtin() {
    let tmpfile = create_tempfile();
    let db = redb::Database::create(tmpfile.path(), crate::admission_support::admission()).unwrap();
    {
        let def: redb::TableDefinition<u64, Option<CollidingUserType>> =
            redb::TableDefinition::new("table");
        let txn = db.begin_write().unwrap();
        {
            let mut table = txn.open_table(def).unwrap();
            table.insert(&1u64, &Some(7u32)).unwrap();
        }
        txn.commit().unwrap();
    }

    let builtin_def: redb::TableDefinition<u64, Option<u32>> = redb::TableDefinition::new("table");
    let txn = db.begin_write().unwrap();
    assert!(matches!(
        txn.open_table(builtin_def),
        Err(redb::TableError::TableTypeMismatch { .. })
    ));
    txn.abort().unwrap();
}

// Canonical built-in and user composites have distinct identities in both directions.
#[test]
fn builtin_composite_does_not_alias_user_type() {
    let tmpfile = create_tempfile();
    let db = redb::Database::create(tmpfile.path(), crate::admission_support::admission()).unwrap();
    {
        let def: redb::TableDefinition<u64, Option<u32>> = redb::TableDefinition::new("table");
        let txn = db.begin_write().unwrap();
        {
            let mut table = txn.open_table(def).unwrap();
            table.insert(&1u64, &Some(7u32)).unwrap();
        }
        txn.commit().unwrap();
    }

    let user_def: redb::TableDefinition<u64, Option<CollidingUserType>> =
        redb::TableDefinition::new("table");
    let txn = db.begin_write().unwrap();
    assert!(matches!(
        txn.open_table(user_def),
        Err(redb::TableError::TableTypeMismatch { .. })
    ));
    txn.abort().unwrap();
}

#[test]
fn recognized_header_does_not_enable_old_composite_aliases() {
    use redb::ReadableDatabase;
    let file = create_tempfile();
    {
        let db = redb2_6::Database::builder()
            .create_with_file_format_v3(true)
            .create(file.path())
            .unwrap();
        let write = db.begin_write().unwrap();
        let table: redb2_6::TableDefinition<u64, Option<u32>> =
            redb2_6::TableDefinition::new("old");
        write
            .open_table(table)
            .unwrap()
            .insert(7, Some(11))
            .unwrap();
        write.commit().unwrap();
    }
    // A producer can emit byte-identical canonical headers. Exact table identity
    // still prevents selecting a decoder through an obsolete composite spelling.
    let db = redb::Database::open(file.path(), admission_support::admission()).unwrap();
    let read = db.begin_read().unwrap();
    let builtin: redb::TableDefinition<u64, Option<u32>> = redb::TableDefinition::new("old");
    let user: redb::TableDefinition<u64, Option<CollidingUserType>> =
        redb::TableDefinition::new("old");
    assert!(matches!(
        read.open_table(builtin),
        Err(redb::TableError::TableTypeMismatch { .. })
    ));
    assert!(matches!(
        read.open_table(user),
        Err(redb::TableError::TableTypeMismatch { .. })
    ));
    drop(read);
    db.close().unwrap();
}

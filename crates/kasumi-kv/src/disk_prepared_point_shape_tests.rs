use super::*;

#[test]
fn prepared_shape_uses_same_root_table_and_owner_without_output_or_new_grants() {
    let admission = Admission::new(u64::MAX);
    let database = crate::Database::builder(admission.clone(), GROUP, CacheConfig::default())
        .create_with_backend(InMemoryGroup::new())
        .unwrap();
    let other = crate::Database::builder(admission.clone(), [44; 16], CacheConfig::default())
        .create_with_backend(InMemoryGroup::new())
        .unwrap();
    const TABLE: crate::TableDefinition<&[u8], &[u8]> = crate::TableDefinition::new("shape");
    let write = database.begin_write().unwrap();
    write
        .open_table(TABLE)
        .unwrap()
        .insert(b"key", [7u8; 4097].as_slice())
        .unwrap();
    write.commit().unwrap();
    let old = database.begin_read().unwrap();
    let mut workspace = old.prepare_point_read(0).unwrap();
    let write = database.begin_write().unwrap();
    write
        .open_table(TABLE)
        .unwrap()
        .insert(b"key", b"new")
        .unwrap();
    write.commit().unwrap();
    let current = database.begin_read().unwrap();
    let foreign = other.begin_read().unwrap();
    let requests = admission.calls.load(Ordering::Acquire);
    admission.limit.store(0, Ordering::Release);
    for _ in 0..3 {
        assert_eq!(
            old.point_length_prepared("shape", b"key", &mut workspace)
                .unwrap(),
            Some(4097)
        );
        assert_eq!(
            current
                .point_length_prepared("shape", b"key", &mut workspace)
                .unwrap(),
            Some(3)
        );
        assert_eq!(
            old.point_length_prepared("shape", b"absent", &mut workspace)
                .unwrap(),
            None
        );
        assert!(matches!(
            old.point_length_prepared("missing", b"key", &mut workspace),
            Err(CoreError::MissingTable)
        ));
        assert!(matches!(
            foreign.point_length_prepared("shape", b"key", &mut workspace),
            Err(CoreError::InvalidInput(_))
        ));
        assert_eq!(workspace.capacity(), 0);
    }
    assert_eq!(admission.calls.load(Ordering::Acquire), requests);
    admission.limit.store(u64::MAX, Ordering::Release);
    drop((workspace, old, current, foreign));
    database.close().unwrap();
    other.close().unwrap();
}

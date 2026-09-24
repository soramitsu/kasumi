use super::*;
use crate::{
    Database, DatabaseCloseSettlement, MultimapTableDefinition, ReadableDatabase, TableDefinition,
};

const TABLE: TableDefinition<u64, u64> = TableDefinition::new("retained-read");
const BYTES: TableDefinition<&[u8], &[u8]> = TableDefinition::new("retained-bytes");
const MULTI: MultimapTableDefinition<u64, u64> = MultimapTableDefinition::new("retained-multi");

#[test]
fn closed_byte_reads_return_bounded_owned_values_from_one_snapshot() {
    let file = crate::create_tempfile();
    let db = Database::create(file.path(), crate::test_admission()).unwrap();
    let write = db.begin_write().unwrap();
    {
        let mut table = write.open_table(BYTES).unwrap();
        table
            .insert(b"tenant/a".as_slice(), b"alpha".as_slice())
            .unwrap();
        table
            .insert(b"tenant/b".as_slice(), b"bravo".as_slice())
            .unwrap();
    }
    write.commit().unwrap();
    let mut database = db.retain();
    let mut read = database.database().unwrap().begin_read_retained().unwrap();
    read.check_bytes_table(BYTES).unwrap();
    assert_eq!(
        read.get_bytes(BYTES, b"tenant/a", 5).unwrap().unwrap(),
        b"alpha".to_vec()
    );
    assert!(matches!(
        read.get_bytes(BYTES, b"tenant/a", 4),
        Err(BoundedReadError::BoundExceeded)
    ));
    let first = read
        .next_bytes(BYTES, b"tenant/", None, 5)
        .unwrap()
        .unwrap();
    assert_eq!(
        (first.key.as_slice(), first.value.as_slice()),
        (&b"tenant/a"[..], &b"alpha"[..])
    );
    let second = read
        .next_bytes(BYTES, b"tenant/", Some(&first.key), 5)
        .unwrap()
        .unwrap();
    assert_eq!(
        (second.key.as_slice(), second.value.as_slice()),
        (&b"tenant/b"[..], &b"bravo"[..])
    );
    assert!(
        read.next_bytes(BYTES, b"tenant/", Some(&second.key), 5)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        read.close(&database).settlement(),
        ReadCloseSettlement::Settled
    );
    assert!(matches!(
        read.get_bytes(BYTES, b"tenant/a", 5),
        Err(BoundedReadError::Closed)
    ));
    assert_eq!(
        read.dispose_settled(&database).settlement(),
        ReadCloseSettlement::Disposed
    );
    assert_eq!(
        database.close().settlement(),
        DatabaseCloseSettlement::Settled
    );
}

#[test]
fn untyped_handles_created_before_retention_pin_the_actual_snapshot() {
    let file = crate::create_tempfile();
    let db = Database::create(file.path(), crate::test_admission()).unwrap();
    let write = db.begin_write().unwrap();
    drop(write.open_table(BYTES).unwrap());
    drop(write.open_multimap_table(MULTI).unwrap());
    write.commit().unwrap();
    let mut database = db.retain();
    let raw = database.database().unwrap().begin_read().unwrap();
    let untyped_table = raw.open_untyped_table(BYTES).unwrap();
    let untyped_multi = raw.open_untyped_multimap_table(MULTI).unwrap();
    let mut read = raw.retain();
    assert_eq!(
        read.close(&database).settlement(),
        ReadCloseSettlement::WaitingForGuards
    );
    drop(untyped_table);
    assert_eq!(
        read.close(&database).settlement(),
        ReadCloseSettlement::WaitingForGuards
    );
    drop(untyped_multi);
    assert_eq!(
        read.close(&database).settlement(),
        ReadCloseSettlement::Settled
    );
    assert_eq!(
        read.dispose_settled(&database).settlement(),
        ReadCloseSettlement::Disposed
    );
    assert_eq!(
        database.close().settlement(),
        DatabaseCloseSettlement::Settled
    );
}

#[test]
fn a_table_guard_keeps_the_exact_read_snapshot_through_a_busy_close() {
    let file = crate::create_tempfile();
    let db = Database::create(file.path(), crate::test_admission()).unwrap();
    let write = db.begin_write().unwrap();
    {
        let mut table = write.open_table(TABLE).unwrap();
        table.insert(1, 2).unwrap();
    }
    write.commit().unwrap();
    let mut database = db.retain();
    let mut read = database.database().unwrap().begin_read_retained().unwrap();
    let original = std::ptr::from_ref(read.transaction.as_ref().unwrap());
    let table = read
        .transaction
        .as_ref()
        .unwrap()
        .open_table(TABLE)
        .unwrap();
    assert_eq!(
        read.close(&database).settlement(),
        ReadCloseSettlement::WaitingForGuards
    );
    assert!(matches!(
        read.report().release(),
        TerminalObservation::NotEntered
    ));
    assert_eq!(
        std::ptr::from_ref(read.transaction.as_ref().unwrap()),
        original
    );
    assert_eq!(
        database.close().settlement(),
        DatabaseCloseSettlement::WaitingForTransactions
    );
    drop(table);
    assert_eq!(
        read.close(&database).settlement(),
        ReadCloseSettlement::Settled
    );
    assert!(matches!(
        read.report().release(),
        TerminalObservation::Returned(Ok(()))
    ));
    assert!(read.report().retains_transaction());
    assert!(read.transaction.is_some());
    assert_eq!(
        database.close().settlement(),
        DatabaseCloseSettlement::WaitingForTransactions
    );
    assert_eq!(
        read.dispose_settled(&database).settlement(),
        ReadCloseSettlement::Disposed
    );
    assert!(matches!(
        read.report().disposal(),
        TerminalObservation::Returned(Ok(()))
    ));
    assert!(!read.report().retains_transaction());
    assert_eq!(
        read.close(&database).settlement(),
        ReadCloseSettlement::Disposed
    );
    assert_eq!(
        database.close().settlement(),
        DatabaseCloseSettlement::Settled
    );
}

#[test]
fn another_database_cannot_dispose_the_read_snapshot() {
    let first_file = crate::create_tempfile();
    let second_file = crate::create_tempfile();
    let first = Database::create(first_file.path(), crate::test_admission()).unwrap();
    let second = Database::create(second_file.path(), crate::test_admission()).unwrap();
    let mut first = first.retain();
    let mut second = second.retain();
    let mut read = first.database().unwrap().begin_read_retained().unwrap();
    assert_eq!(read.close(&second).settlement(), ReadCloseSettlement::Open);
    assert!(matches!(
        read.report().release(),
        TerminalObservation::NotEntered
    ));
    assert_eq!(
        read.close(&first).settlement(),
        ReadCloseSettlement::Settled
    );
    assert_eq!(
        read.dispose_settled(&second).settlement(),
        ReadCloseSettlement::Settled
    );
    assert_eq!(
        read.dispose_settled(&first).settlement(),
        ReadCloseSettlement::Disposed
    );
    assert_eq!(first.close().settlement(), DatabaseCloseSettlement::Settled);
    assert_eq!(
        second.close().settlement(),
        DatabaseCloseSettlement::Settled
    );
}

#[test]
fn failed_non_consuming_release_preserves_the_exact_snapshot_and_error() {
    let file = crate::create_tempfile();
    let db = Database::create(file.path(), crate::test_admission()).unwrap();
    let mut database = db.retain();
    let mut read = database.database().unwrap().begin_read_retained().unwrap();
    let original_transaction = std::ptr::from_ref(read.transaction.as_ref().unwrap());
    read.fail_release_before_effect = true;
    assert_eq!(
        read.close(&database).settlement(),
        ReadCloseSettlement::Retained
    );
    let original_error = {
        let report = read.report();
        let TerminalObservation::Returned(Err(error)) = report.release() else {
            panic!("expected original release error");
        };
        assert!(matches!(error, StorageError::OwnerFailed));
        std::ptr::from_ref(error)
    };
    assert!(read.report().retains_transaction());
    assert_eq!(
        std::ptr::from_ref(read.transaction.as_ref().unwrap()),
        original_transaction
    );
    assert_eq!(
        read.close(&database).settlement(),
        ReadCloseSettlement::Retained
    );
    let report = read.report();
    let TerminalObservation::Returned(Err(error)) = report.release() else {
        panic!("original release error was replaced");
    };
    assert_eq!(std::ptr::from_ref(error), original_error);
    drop(report);
    // Test-only cleanup of an owner that production must retain in its census.
    read.transaction.take().unwrap().close().unwrap();
    assert_eq!(
        database.close().settlement(),
        DatabaseCloseSettlement::Settled
    );
}

#[test]
fn disposal_unwind_never_claims_the_consumed_snapshot_is_still_retained() {
    let file = crate::create_tempfile();
    let db = Database::create(file.path(), crate::test_admission()).unwrap();
    let mut database = db.retain();
    let mut read = database.database().unwrap().begin_read_retained().unwrap();
    assert_eq!(
        read.close(&database).settlement(),
        ReadCloseSettlement::Settled
    );
    read.panic_after_disposal_take = true;
    assert_eq!(
        read.dispose_settled(&database).settlement(),
        ReadCloseSettlement::DisposalUncertain
    );
    assert!(!read.report().retains_transaction());
    let original = {
        let report = read.report();
        let TerminalObservation::Panicked(payload) = report.disposal() else {
            panic!("original disposal panic missing");
        };
        std::ptr::from_ref(payload)
    };
    assert_eq!(
        read.dispose_settled(&database).settlement(),
        ReadCloseSettlement::DisposalUncertain
    );
    let report = read.report();
    let TerminalObservation::Panicked(payload) = report.disposal() else {
        panic!("original disposal panic was replaced");
    };
    assert!(std::ptr::eq(original, std::ptr::from_ref(payload)));
    assert_eq!(
        database.close().settlement(),
        DatabaseCloseSettlement::Settled
    );
}

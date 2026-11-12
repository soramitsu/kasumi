use super::retired_log_read_error;
use crate::{DefensiveError, ErrorSubject, StorageError, StorageIOError, Violation};

#[test]
fn retired_read_only_cancels_its_typed_unavailable_prefix() {
    let error: StorageError<u64> =
        DefensiveError::new(ErrorSubject::Logs, Violation::LogReadPrefixUnavailable { start: 7 }).into();
    assert!(retired_log_read_error(&error, true, Some(7)));
    // Live streams still fail closed; snapshots and unrelated requests cannot borrow this excuse.
    assert!(!retired_log_read_error(&error, false, Some(7)));
    assert!(!retired_log_read_error(&error, true, None));
    assert!(!retired_log_read_error(&error, true, Some(8)));
}

#[test]
fn retirement_never_hides_io_authentication_or_defensive_failures() {
    let errors: [StorageError<u64>; 3] = [
        StorageIOError::read_logs(&std::io::Error::other("disk read failed")).into(),
        StorageIOError::read_logs(&std::io::Error::other("authentication failed")).into(),
        DefensiveError::new(ErrorSubject::Logs, Violation::LogIndexNotFound { want: 7, got: None }).into(),
    ];
    for error in errors {
        assert!(!retired_log_read_error(&error, true, Some(7)));
        assert!(!retired_log_read_error(&error, false, Some(7)));
    }
}

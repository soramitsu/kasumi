//! A read snapshot retained through a non-consuming close attempt.
//! The embedding owner must separately register and admit its lifetime.
use super::ReadTransaction;
use crate::db::TransactionGuard;
use crate::{
    RetainedDatabase, StorageError, TableDefinition, TableError, TableHandle,
    TerminalObservation,
};
use std::{
    any::Any,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::Arc,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadCloseSettlement {
    Open,
    /// A table still owns the exact snapshot guard. No release call entered.
    WaitingForGuards,
    /// The tracker release returned, but the transaction is still installed
    /// until explicit disposal runs with the same database witness.
    Settled,
    /// The exact transaction was positively disposed.
    Disposed,
    /// Disposal unwound. Its original payload remains, but the transaction
    /// may have been partly destroyed; no exact live-snapshot claim is made.
    DisposalUncertain,
    /// The non-consuming release failed or unwound. The exact transaction
    /// remains installed, and the original error/payload is retained.
    Retained,
}

/// A closed, byte-table read failure. No redb handle or iterator escapes.
#[derive(Debug)]
pub enum BoundedReadError {
    Closed,
    BoundExceeded,
    Table(TableError),
    Storage(StorageError),
}
impl std::fmt::Display for BoundedReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Closed => f.write_str("retained read snapshot is closed"),
            Self::BoundExceeded => f.write_str("retained read bound exceeded"),
            Self::Table(error) => error.fmt(f),
            Self::Storage(error) => error.fmt(f),
        }
    }
}
impl std::error::Error for BoundedReadError {}

/// One owned encrypted row from the same read snapshot.
pub struct BoundedReadRow {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

const MAX_TABLE_NAME_BYTES: usize = 128;
const MAX_READ_KEY_BYTES: usize = 8192;
const MAX_READ_VALUE_BYTES: usize = 64 << 20;

fn copy_bounded(bytes: &[u8], maximum: usize) -> Result<Vec<u8>, BoundedReadError> {
    if bytes.len() > maximum {
        return Err(BoundedReadError::BoundExceeded);
    }
    let mut owned = Vec::new();
    owned
        .try_reserve_exact(bytes.len())
        .map_err(|_| BoundedReadError::Storage(StorageError::CapacityDenied))?;
    owned.extend_from_slice(bytes);
    Ok(owned)
}

enum Observation<E> {
    NotEntered,
    Entered,
    Returned(Result<(), E>),
    Panicked(Box<dyn Any + Send>),
}
impl<E> Observation<E> {
    fn borrow(&self) -> TerminalObservation<'_, E> {
        match self {
            Self::NotEntered => TerminalObservation::NotEntered,
            Self::Entered => TerminalObservation::Entered,
            Self::Returned(result) => TerminalObservation::Returned(result.as_ref().copied()),
            Self::Panicked(payload) => TerminalObservation::Panicked(payload.as_ref()),
        }
    }
}

/// Retains the exact read transaction while table guards or a close outcome
/// remain unresolved. An embedding census must own this value before dispatch;
/// the type does not claim to admit tracker, cache or diagnostic allocations.
#[must_use = "retain the exact read snapshot through close and report disposal"]
pub struct RetainedReadTransaction {
    transaction: Option<ReadTransaction>,
    release: Observation<StorageError>,
    disposal: Observation<std::convert::Infallible>,
    settlement: ReadCloseSettlement,
    #[cfg(test)]
    fail_release_before_effect: bool,
    #[cfg(test)]
    panic_after_disposal_take: bool,
}

#[must_use = "inspect the original close attempt and actual snapshot settlement"]
pub struct ReadCloseReport<'a> {
    owner: &'a RetainedReadTransaction,
}
impl ReadCloseReport<'_> {
    pub fn settlement(&self) -> ReadCloseSettlement {
        self.owner.settlement
    }
    pub fn release(&self) -> TerminalObservation<'_, StorageError> {
        self.owner.release.borrow()
    }
    pub fn disposal(&self) -> TerminalObservation<'_, std::convert::Infallible> {
        self.owner.disposal.borrow()
    }
    pub fn retains_transaction(&self) -> bool {
        self.owner.transaction.is_some()
    }
}

impl ReadTransaction {
    /// Transfer the actual snapshot to caller-owned retained custody.
    /// Only `Database::begin_read_retained` may invoke this constructor; public
    /// callers never receive the raw transaction before retained admission.
    pub(crate) fn retain(self) -> RetainedReadTransaction {
        RetainedReadTransaction {
            transaction: Some(self),
            release: Observation::NotEntered,
            disposal: Observation::NotEntered,
            settlement: ReadCloseSettlement::Open,
            #[cfg(test)]
            fail_release_before_effect: false,
            #[cfg(test)]
            panic_after_disposal_take: false,
        }
    }
}

impl RetainedReadTransaction {
    fn readable(&self) -> Result<&ReadTransaction, BoundedReadError> {
        if !matches!(
            self.settlement,
            ReadCloseSettlement::Open | ReadCloseSettlement::WaitingForGuards
        ) {
            return Err(BoundedReadError::Closed);
        }
        self.transaction.as_ref().ok_or(BoundedReadError::Closed)
    }

    fn validate_table(table: TableDefinition<&[u8], &[u8]>) -> Result<(), BoundedReadError> {
        if table.name().len() > MAX_TABLE_NAME_BYTES {
            Err(BoundedReadError::BoundExceeded)
        } else {
            Ok(())
        }
    }

    /// Verify the exact typed table in this snapshot without exposing a guard.
    pub fn check_bytes_table(
        &self,
        definition: TableDefinition<&[u8], &[u8]>,
    ) -> Result<(), BoundedReadError> {
        Self::validate_table(definition)?;
        self.readable()?
            .open_table(definition)
            .map_err(BoundedReadError::Table)?;
        Ok(())
    }

    /// Copy one byte value under a caller limit and the fixed first-release
    /// ceiling. The embedding owner must still admit the returned allocation.
    pub fn get_bytes(
        &self,
        definition: TableDefinition<&[u8], &[u8]>,
        key: &[u8],
        max_value_bytes: usize,
    ) -> Result<Option<Vec<u8>>, BoundedReadError> {
        Self::validate_table(definition)?;
        if key.len() > MAX_READ_KEY_BYTES || max_value_bytes > MAX_READ_VALUE_BYTES {
            return Err(BoundedReadError::BoundExceeded);
        }
        let table = self
            .readable()?
            .open_table(definition)
            .map_err(BoundedReadError::Table)?;
        let value = table.get(key).map_err(BoundedReadError::Storage)?;
        value
            .as_ref()
            .map(|value| copy_bounded(value.value(), max_value_bytes))
            .transpose()
    }

    /// Resume at most one row from the same pinned snapshot. The returned key
    /// and value are owned and bounded; no table, iterator or page guard escapes.
    pub fn next_bytes(
        &self,
        definition: TableDefinition<&[u8], &[u8]>,
        prefix: &[u8],
        after: Option<&[u8]>,
        max_value_bytes: usize,
    ) -> Result<Option<BoundedReadRow>, BoundedReadError> {
        Self::validate_table(definition)?;
        if prefix.len() > MAX_READ_KEY_BYTES
            || after
                .is_some_and(|after| after.len() > MAX_READ_KEY_BYTES || !after.starts_with(prefix))
            || max_value_bytes > MAX_READ_VALUE_BYTES
        {
            return Err(BoundedReadError::BoundExceeded);
        }
        let table = self
            .readable()?
            .open_table(definition)
            .map_err(BoundedReadError::Table)?;
        let start = after.unwrap_or(prefix);
        let range = table.range(start..).map_err(BoundedReadError::Storage)?;
        for entry in range {
            let (key, value) = entry.map_err(BoundedReadError::Storage)?;
            let key_bytes = key.value();
            if after.is_some_and(|after| key_bytes <= after) {
                continue;
            }
            if !key_bytes.starts_with(prefix) {
                return Ok(None);
            }
            return Ok(Some(BoundedReadRow {
                key: copy_bounded(key_bytes, MAX_READ_KEY_BYTES)?,
                value: copy_bounded(value.value(), max_value_bytes)?,
            }));
        }
        Ok(None)
    }

    pub fn report(&self) -> ReadCloseReport<'_> {
        ReadCloseReport { owner: self }
    }

    /// Release the tracker registration without moving or destroying the exact
    /// transaction. A busy table guard leaves it installed for a later attempt.
    /// A failed release or unwind is terminal and remains reportable; no replay
    /// or destructor is attempted by this method.
    pub fn close(&mut self, database: &RetainedDatabase) -> ReadCloseReport<'_> {
        if !matches!(
            self.settlement,
            ReadCloseSettlement::Open | ReadCloseSettlement::WaitingForGuards
        ) {
            return self.report();
        }
        let transaction = self.transaction.as_ref().expect("live read owner");
        let guard = transaction.tree.transaction_guard();
        let TransactionGuard::Read { tracker, .. } = guard.as_ref() else {
            unreachable!("read transaction has a read guard")
        };
        if !database.owns_transaction(tracker, &transaction.mem) {
            return self.report();
        }
        if Arc::strong_count(guard) != 1 {
            self.settlement = ReadCloseSettlement::WaitingForGuards;
            return self.report();
        }
        self.settlement = ReadCloseSettlement::Retained;
        self.release = Observation::Entered;
        #[cfg(test)]
        let fail_before_effect = self.fail_release_before_effect;
        self.release = match catch_unwind(AssertUnwindSafe(|| {
            #[cfg(test)]
            if fail_before_effect {
                return Err(StorageError::OwnerFailed);
            }
            guard.release_read_retained()
        })) {
            Ok(result) => Observation::Returned(result),
            Err(payload) => Observation::Panicked(payload),
        };
        if matches!(self.release, Observation::Returned(Ok(()))) {
            self.settlement = ReadCloseSettlement::Settled;
        }
        self.report()
    }

    /// Retire the already-released transaction while borrowing the same actual
    /// database owner. A destructor unwind is an explicitly uncertain disposal;
    /// it is never reported as retained exact snapshot custody or retried.
    pub fn dispose_settled(&mut self, database: &RetainedDatabase) -> ReadCloseReport<'_> {
        if self.settlement != ReadCloseSettlement::Settled {
            return self.report();
        }
        let transaction = self.transaction.as_ref().expect("settled read owner");
        let guard = transaction.tree.transaction_guard();
        let TransactionGuard::Read { tracker, .. } = guard.as_ref() else {
            unreachable!("read transaction has a read guard")
        };
        if !database.owns_transaction(tracker, &transaction.mem) {
            return self.report();
        }
        self.disposal = Observation::Entered;
        #[cfg(test)]
        let panic_after_take = self.panic_after_disposal_take;
        self.disposal = match catch_unwind(AssertUnwindSafe(|| {
            let transaction = self.transaction.take();
            #[cfg(test)]
            if panic_after_take {
                std::panic::panic_any("injected read disposal panic");
            }
            drop(transaction);
        })) {
            Ok(()) => Observation::Returned(Ok(())),
            Err(payload) => Observation::Panicked(payload),
        };
        self.settlement = if matches!(self.disposal, Observation::Returned(Ok(()))) {
            ReadCloseSettlement::Disposed
        } else {
            ReadCloseSettlement::DisposalUncertain
        };
        self.report()
    }
}

#[cfg(test)]
#[path = "retained_read_transaction_tests.rs"]
mod tests;

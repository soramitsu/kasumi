use crate::sync::{Condvar, Mutex};
use crate::tree_store::TransactionalMemory;
use crate::{Key, Result, Savepoint, TypeName, Value};
use alloc::collections::BTreeSet;
use alloc::collections::btree_map::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cmp::Ordering;
use core::mem::size_of;
#[cfg(feature = "logging")]
use log::debug;

#[derive(Copy, Clone, Hash, Ord, PartialOrd, Eq, PartialEq, Debug)]
pub(crate) struct TransactionId(u64);

impl TransactionId {
    pub(crate) fn new(value: u64) -> TransactionId {
        Self(value)
    }

    pub(crate) fn raw_id(self) -> u64 {
        self.0
    }

    pub(crate) fn next(self) -> TransactionId {
        TransactionId(self.0 + 1)
    }

    pub(crate) fn increment(&mut self) -> TransactionId {
        let next = self.next();
        *self = next;
        next
    }
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub(crate) struct SavepointId(pub u64);

impl SavepointId {
    pub(crate) fn next(self) -> SavepointId {
        SavepointId(self.0 + 1)
    }
}

impl Value for SavepointId {
    type SelfType<'a> = SavepointId;
    type AsBytes<'a> = [u8; size_of::<u64>()];

    fn fixed_width() -> Option<usize> {
        Some(size_of::<u64>())
    }

    fn from_bytes<'a>(data: &'a [u8]) -> Self::SelfType<'a>
    where
        Self: 'a,
    {
        SavepointId(u64::from_le_bytes(data.try_into().unwrap()))
    }

    fn as_bytes<'a, 'b: 'a>(value: &'a Self::SelfType<'b>) -> Self::AsBytes<'a>
    where
        Self: 'b,
    {
        value.0.to_le_bytes()
    }

    fn type_name() -> TypeName {
        TypeName::internal("redb::SavepointId")
    }
}

impl Key for SavepointId {
    fn compare(data1: &[u8], data2: &[u8]) -> Ordering {
        Self::from_bytes(data1).0.cmp(&Self::from_bytes(data2).0)
    }
}

struct State {
    next_savepoint_id: SavepointId,
    // reference count of read transactions per transaction id
    live_read_transactions: BTreeMap<TransactionId, u64>,
    next_transaction_id: TransactionId,
    live_write_transaction: Option<TransactionId>,
    valid_savepoints: BTreeMap<SavepointId, TransactionId>,
    // Subset of valid_savepoints that are persistent
    persistent_savepoints: BTreeSet<SavepointId>,
    // Set when the Database was dropped while a write transaction was live. That transaction
    // keeps the database open, and end_write_transaction() hands the close back to it when
    // it ends
    deferred_close: Option<Arc<TransactionalMemory>>,
}

pub(crate) struct TransactionTracker {
    state: Mutex<State>,
    live_write_transaction_available: Condvar,
}

impl TransactionTracker {
    pub(crate) fn new(next_transaction_id: TransactionId) -> Self {
        Self {
            state: Mutex::new(State {
                next_savepoint_id: SavepointId(0),
                live_read_transactions: BTreeMap::default(),
                next_transaction_id,
                live_write_transaction: None,
                valid_savepoints: BTreeMap::default(),
                persistent_savepoints: BTreeSet::default(),
                deferred_close: None,
            }),
            live_write_transaction_available: Condvar::new(),
        }
    }

    pub(crate) fn start_write_transaction(&self) -> TransactionId {
        let mut state = self.state.lock().unwrap();
        while state.live_write_transaction.is_some() {
            state = self.live_write_transaction_available.wait(state).unwrap();
        }
        assert!(state.live_write_transaction.is_none());
        let transaction_id = state.next_transaction_id.increment();
        #[cfg(feature = "logging")]
        debug!("Beginning write transaction id={transaction_id:?}");
        state.live_write_transaction = Some(transaction_id);

        transaction_id
    }

    // Returns the deferred close, if the Database was dropped while this transaction was live.
    // The caller must close the database, now that the write transaction has ended
    pub(crate) fn end_write_transaction(
        &self,
        id: TransactionId,
    ) -> Option<Arc<TransactionalMemory>> {
        let mut state = self.state.lock().unwrap();
        assert_eq!(state.live_write_transaction.unwrap(), id);
        state.live_write_transaction = None;
        self.live_write_transaction_available.notify_one();
        state.deferred_close.take()
    }

    // Defers the database close to the end of the live write transaction, if one exists.
    // Returns false if there is no live write transaction, in which case the caller must close
    // the database itself. The check and the handoff share the state lock, making this atomic
    // with end_write_transaction(), so exactly one side performs the close
    pub(crate) fn defer_close_if_write_transaction_live(
        &self,
        mem: &Arc<TransactionalMemory>,
    ) -> bool {
        let mut state = self.state.lock().unwrap();
        if state.live_write_transaction.is_some() {
            state.deferred_close = Some(mem.clone());
            true
        } else {
            false
        }
    }

    pub(crate) fn restore_savepoint_counter_state(&self, next_savepoint: SavepointId) {
        let mut state = self.state.lock().unwrap();
        assert!(state.valid_savepoints.is_empty());
        assert!(state.persistent_savepoints.is_empty());
        state.next_savepoint_id = next_savepoint;
    }

    pub(crate) fn register_persistent_savepoint(&self, savepoint: &Savepoint) {
        let mut state = self.state.lock().unwrap();
        state
            .live_read_transactions
            .entry(savepoint.get_transaction_id())
            .and_modify(|x| *x += 1)
            .or_insert(1);
        state
            .valid_savepoints
            .insert(savepoint.get_id(), savepoint.get_transaction_id());
        state.persistent_savepoints.insert(savepoint.get_id());
    }

    // Marks an already-registered savepoint as persistent
    pub(crate) fn mark_savepoint_persistent(&self, id: SavepointId) {
        let mut state = self.state.lock().unwrap();
        assert!(state.valid_savepoints.contains_key(&id));
        state.persistent_savepoints.insert(id);
    }

    pub(crate) fn register_read_transaction(
        &self,
        mem: &TransactionalMemory,
    ) -> Result<TransactionId> {
        let mut state = self.state.lock()?;
        let id = mem.get_last_committed_transaction_id()?;
        state
            .live_read_transactions
            .entry(id)
            .and_modify(|x| *x += 1)
            .or_insert(1);

        Ok(id)
    }

    pub(crate) fn deallocate_read_transaction(&self, id: TransactionId) {
        let mut state = self.state.lock().unwrap();
        let ref_count = state.live_read_transactions.get_mut(&id).unwrap();
        *ref_count -= 1;
        if *ref_count == 0 {
            state.live_read_transactions.remove(&id);
        }
    }

    pub(crate) fn any_savepoint_exists(&self) -> bool {
        !self.state.lock().unwrap().valid_savepoints.is_empty()
    }

    pub(crate) fn any_persistent_savepoint_exists(&self) -> bool {
        !self.state.lock().unwrap().persistent_savepoints.is_empty()
    }

    // True if a borrowed ephemeral savepoint pins a root during maintenance.
    pub(crate) fn any_ephemeral_savepoint_exists(&self) -> bool {
        let state = self.state.lock().unwrap();
        state
            .valid_savepoints
            .keys()
            .any(|id| !state.persistent_savepoints.contains(id))
    }

    pub(crate) fn any_user_read_reference_exists(&self) -> bool {
        !self.state.lock().unwrap().live_read_transactions.is_empty()
    }

    pub(crate) fn allocate_savepoint(&self, transaction_id: TransactionId) -> SavepointId {
        let mut state = self.state.lock().unwrap();
        let id = state.next_savepoint_id.next();
        state.next_savepoint_id = id;
        state.valid_savepoints.insert(id, transaction_id);
        id
    }

    // Deallocates the given savepoint and its matching reference count on the transcation
    pub(crate) fn deallocate_savepoint(&self, savepoint: SavepointId, transaction: TransactionId) {
        {
            let mut state = self.state.lock().unwrap();
            state.valid_savepoints.remove(&savepoint);
            state.persistent_savepoints.remove(&savepoint);
        }
        self.deallocate_read_transaction(transaction);
    }

    pub(crate) fn is_valid_savepoint(&self, id: SavepointId) -> bool {
        self.state
            .lock()
            .unwrap()
            .valid_savepoints
            .contains_key(&id)
    }

    pub(crate) fn list_savepoints_after(&self, id: SavepointId) -> Vec<SavepointId> {
        self.state
            .lock()
            .unwrap()
            .valid_savepoints
            .range((
                core::ops::Bound::Excluded(id),
                core::ops::Bound::Unbounded::<SavepointId>,
            ))
            .map(|(x, _)| *x)
            .collect()
    }

    // Removes the given savepoints from the in-memory `valid_savepoints` map without touching
    // live_read_transactions refs. The caller is responsible for making sure those refs are
    // released by some other means: ephemeral `Savepoint::drop` or `deallocate_savepoint`
    // (called via `delete_persistent_savepoint`) do that for their respective savepoint kinds.
    //
    // Savepoints that have already been removed (for example, by `deallocate_savepoint` earlier
    // in the same transaction) are silently skipped.
    pub(crate) fn invalidate_savepoints(&self, savepoints: impl IntoIterator<Item = SavepointId>) {
        let mut state = self.state.lock().unwrap();
        for id in savepoints {
            state.valid_savepoints.remove(&id);
            state.persistent_savepoints.remove(&id);
        }
    }

    // The oldest savepoint, ignoring the given savepoint ids. Used by committing transactions
    // to compute the savepoint horizon as it will be after their staged savepoint deletions
    // are applied on commit.
    pub(crate) fn oldest_savepoint_excluding(
        &self,
        exclude: &BTreeSet<SavepointId>,
    ) -> Option<(SavepointId, TransactionId)> {
        self.state
            .lock()
            .unwrap()
            .valid_savepoints
            .iter()
            .find(|(id, _)| !exclude.contains(id))
            .map(|(id, txn_id)| (*id, *txn_id))
    }

    pub(crate) fn oldest_live_read_transaction(&self) -> Option<TransactionId> {
        self.state
            .lock()
            .unwrap()
            .live_read_transactions
            .keys()
            .next()
            .copied()
    }
}

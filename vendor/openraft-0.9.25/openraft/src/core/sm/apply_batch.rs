//! One actual applied-result owner, shared until normal core consumption.
use std::fmt;
use std::sync::{Arc, Mutex};

use crate::core::{ApplyResult, ApplyingEntry};
use crate::error::ShutdownRetainedOwner;
use crate::{LogId, RaftTypeConfig, StorageError, StorageIOError};

pub(crate) struct ApplyBatch<C: RaftTypeConfig> {
    state: Mutex<State<C>>,
}
struct State<C: RaftTypeConfig> {
    batch: Option<Batch<C>>,
    delivering: bool,
}
struct Batch<C: RaftTypeConfig> {
    since: u64,
    end: u64,
    last: LogId<C::NodeId>,
    entries: std::vec::IntoIter<ApplyingEntry<C::NodeId, C::Node>>,
    results: std::vec::IntoIter<C::R>,
}
impl<C: RaftTypeConfig> fmt::Debug for ApplyBatch<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        f.debug_struct("UnconsumedApplyBatch")
            .field("range", &state.batch.as_ref().map(|batch| batch.since..batch.end))
            .field("delivering", &state.delivering)
            .finish()
    }
}
impl<C: RaftTypeConfig> ApplyBatch<C> {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State {
                batch: None,
                delivering: false,
            }),
        })
    }
    pub(crate) fn publish(&self, result: ApplyResult<C>) {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        assert!(
            state.batch.is_none() && !state.delivering,
            "previous applied response was not consumed"
        );
        state.batch = Some(Batch {
            since: result.since,
            end: result.end,
            last: result.last_applied,
            entries: result.applying_entries.into_iter(),
            results: result.apply_results.into_iter(),
        });
    }
    pub(crate) fn progress(&self) -> Result<(u64, u64, LogId<C::NodeId>), StorageError<C::NodeId>> {
        let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let batch = state.batch.as_ref().ok_or_else(Self::invalid)?;
        let expected = batch.end.checked_sub(batch.since).ok_or_else(Self::invalid)?;
        if state.delivering || batch.entries.len() as u64 != expected || batch.results.len() as u64 != expected {
            return Err(Self::invalid());
        }
        Ok((batch.since, batch.end, batch.last.clone()))
    }
    pub(crate) fn next(&self) -> Result<(ApplyingEntry<C::NodeId, C::Node>, C::R), StorageError<C::NodeId>> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        if state.delivering {
            return Err(Self::invalid());
        }
        let batch = state.batch.as_mut().ok_or_else(Self::invalid)?;
        // Check both before moving either actual object out of the retained cell.
        if batch.entries.len() == 0 || batch.results.len() == 0 {
            return Err(Self::invalid());
        }
        let result = (batch.entries.next().unwrap(), batch.results.next().unwrap());
        state.delivering = true;
        Ok(result)
    }
    pub(crate) fn delivered(&self) {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        assert!(state.delivering, "apply response delivery was not started");
        state.delivering = false;
    }
    pub(crate) fn finish(&self) -> Result<(), StorageError<C::NodeId>> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let batch = state.batch.as_ref().ok_or_else(Self::invalid)?;
        if state.delivering || batch.entries.len() != 0 || batch.results.len() != 0 {
            return Err(Self::invalid());
        }
        // Both iterators are empty; no arbitrary application response is dropped.
        state.batch = None;
        Ok(())
    }
    pub(crate) fn retained(self: &Arc<Self>) -> Option<ShutdownRetainedOwner> {
        let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        (state.batch.is_some() || state.delivering).then(|| ShutdownRetainedOwner::applied(self.clone()))
    }
    fn invalid() -> StorageError<C::NodeId> {
        StorageIOError::read_state_machine(anyerror::AnyError::error(
            "applied response batch is incomplete or unconsumed",
        ))
        .into()
    }
}

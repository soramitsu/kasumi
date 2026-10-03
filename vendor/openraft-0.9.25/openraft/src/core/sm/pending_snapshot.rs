//! Fixed custody for a received snapshot waiting for prior committed application.
use std::fmt;
use std::sync::{Arc, Mutex};

use tokio::sync::OwnedMutexGuard;

use crate::core::raft_msg::ResultSender;
use crate::error::ShutdownRetainedOwner;
use crate::raft::SnapshotResponse;
use crate::{LogId, RaftTypeConfig, Snapshot, Vote};

pub(crate) struct IncomingSnapshot<C: RaftTypeConfig> {
    pub(crate) vote: Vote<C::NodeId>,
    pub(crate) snapshot: Snapshot<C>,
    pub(crate) tx: ResultSender<C, SnapshotResponse<C::NodeId>>,
}
pub(crate) struct PendingSnapshot<C: RaftTypeConfig> {
    state: Mutex<State<C>>,
}
struct State<C: RaftTypeConfig> {
    incoming: Option<IncomingSnapshot<C>>,
    permit: Option<OwnedMutexGuard<()>>,
    activated: bool,
    accepting: bool,
}
impl<C: RaftTypeConfig> fmt::Debug for PendingSnapshot<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        f.debug_struct("PendingIncomingSnapshot")
            .field(
                "last_log_id",
                &state.incoming.as_ref().and_then(|incoming| incoming.snapshot.meta.last_log_id.as_ref()),
            )
            .field("activated", &state.activated)
            .field("accepting", &state.accepting)
            .finish()
    }
}
impl<C: RaftTypeConfig> PendingSnapshot<C> {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State {
                incoming: None,
                permit: None,
                activated: false,
                accepting: false,
            }),
        })
    }
    pub(crate) fn offer(&self, incoming: IncomingSnapshot<C>, permit: OwnedMutexGuard<()>) {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        assert!(
            state.incoming.is_none() && state.permit.is_none() && !state.accepting,
            "incoming snapshot permit reused"
        );
        state.incoming = Some(incoming);
        state.permit = Some(permit);
        state.activated = false;
    }
    pub(crate) fn activate(&self) {
        self.state.lock().unwrap_or_else(|error| error.into_inner()).activated = true;
    }
    pub(crate) fn take_ready(
        &self,
        committed: Option<&LogId<C::NodeId>>,
        applied: Option<&LogId<C::NodeId>>,
    ) -> Option<IncomingSnapshot<C>> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        if !state.activated || state.accepting {
            return None;
        }
        let incoming = state.incoming.as_ref()?;
        // A newer snapshot can purge the committed range. An obsolete snapshot
        // causes no purge, so a continued stream of commits cannot move this
        // wait target forever beyond the snapshot's fixed boundary.
        if incoming.snapshot.meta.last_log_id.as_ref() > committed && applied < committed {
            return None;
        }
        state.accepting = true;
        state.incoming.take()
    }
    pub(crate) fn accepted(&self) {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        assert!(state.accepting && state.incoming.is_none());
        state.accepting = false;
        state.activated = false;
        let permit = state.permit.take();
        drop(state);
        // Unknown engine unwind never reaches this normal handoff transition.
        drop(permit);
    }
    pub(crate) fn retained(self: &Arc<Self>) -> Option<ShutdownRetainedOwner> {
        let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        (state.incoming.is_some() || state.permit.is_some() || state.accepting)
            .then(|| ShutdownRetainedOwner::snapshot(self.clone()))
    }
}

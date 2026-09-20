//! One charged startup operation, retained in place across cancelled callers.
//! Polling the operation owns its nested JoinHandles; no coordinator or reaper
//! task can be aborted while it owns those handles.
use crate::{CustodyRaftGroup, RaftGroup, SnapshotBufferOwner};
use anyhow::{Result, ensure};
use kasumi_types::drain::{DrainCompletion, DrainFailure, DrainResult};
use std::{
    any::Any,
    future::Future,
    panic::{AssertUnwindSafe, catch_unwind},
    pin::Pin,
    sync::Mutex,
    task::{Context, Poll},
};

pub(crate) const STARTUP_WORKSPACE: u64 = 64 << 10;
type Opening = Pin<Box<dyn Future<Output = Result<StartedGroup>> + Send>>;
type Cleaning = Pin<Box<dyn Future<Output = DrainResult> + Send>>;

/// Preserve the actual unwind payload, including non-string application values.
/// The mutex makes the original Send-only payload safe to retain in a DrainIssue.
pub(crate) struct StartupPollPanic {
    pub(crate) payload: Mutex<Box<dyn Any + Send>>,
    phase: &'static str,
}
impl StartupPollPanic {
    fn new(payload: Box<dyn Any + Send>, phase: &'static str) -> Self {
        Self {
            payload: Mutex::new(payload),
            phase,
        }
    }
}
impl std::fmt::Debug for StartupPollPanic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StartupPollPanic")
            .field("phase", &self.phase)
            .field(
                "payload_type",
                &self
                    .payload
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .as_ref()
                    .type_id(),
            )
            .finish_non_exhaustive()
    }
}
impl std::fmt::Display for StartupPollPanic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} poll panicked; original payload and poisoned future retained",
            self.phase
        )
    }
}
impl std::error::Error for StartupPollPanic {}

pub(crate) enum StartedGroup {
    Serving(RaftGroup),
    Custody(CustodyRaftGroup),
    #[cfg(test)]
    Fixture(crate::startup_owner_tests::FixtureGroup),
}
impl StartedGroup {
    async fn shutdown(self) -> DrainResult {
        let result = match self {
            Self::Serving(group) => group.shutdown().await,
            Self::Custody(group) => group.shutdown().await,
            #[cfg(test)]
            Self::Fixture(group) => group.shutdown().await,
        };
        result.map_err(|error| {
            error
                .downcast::<DrainFailure>()
                .expect("group shutdown returns typed drain evidence")
        })
    }
}
async fn cleanup(group: Option<StartedGroup>) -> DrainResult {
    match group {
        Some(group) => group.shutdown().await,
        None => Ok(()),
    }
}

pub(crate) enum UnresolvedFuture {
    Opening { _future: Opening },
    Cleaning { _future: Cleaning },
}
#[derive(Default)]
pub(crate) enum StartupState {
    #[default]
    Idle,
    Opening(Opening),
    Cleaning(Cleaning),
    Delivered,
    Finished(DrainResult),
    // A panicked or otherwise unresolved future is never polled or dropped.
    Retained {
        _future: UnresolvedFuture,
        failure: DrainFailure,
    },
}
impl StartupState {
    pub(crate) fn can_release_custody(&self) -> bool {
        matches!(self, Self::Idle | Self::Delivered | Self::Finished(_))
    }
    pub(crate) fn install<F>(&mut self, future: F) -> Result<()>
    where
        F: Future<Output = Result<StartedGroup>> + Send + 'static,
    {
        ensure!(
            matches!(self, Self::Idle),
            "snapshot owner already has a startup operation"
        );
        // Replacement briefly owns both allocations: reserve their sum.
        ensure!(
            std::mem::size_of_val(&future)
                .checked_add(std::mem::size_of_val(&cleanup(None)))
                .is_some_and(|bytes| bytes as u64 <= STARTUP_WORKSPACE),
            "Raft startup future and cleanup exceed their reserved workspace"
        );
        *self = Self::Opening(Box::pin(future));
        Ok(())
    }
    #[cfg(test)]
    pub(crate) fn install_cleanup_fixture<F>(&mut self, future: F)
    where
        F: Future<Output = DrainResult> + Send + 'static,
    {
        assert!(matches!(self, Self::Idle));
        assert!(std::mem::size_of_val(&future) as u64 <= STARTUP_WORKSPACE);
        *self = Self::Cleaning(Box::pin(future));
    }
    fn retain(&mut self, failure: DrainFailure) {
        let future = match std::mem::take(self) {
            Self::Opening(future) => UnresolvedFuture::Opening { _future: future },
            Self::Cleaning(future) => UnresolvedFuture::Cleaning { _future: future },
            _ => unreachable!("only a polled future becomes unresolved"),
        };
        *self = Self::Retained {
            _future: future,
            failure,
        };
    }
    fn panic(
        &mut self,
        owner: &SnapshotBufferOwner,
        payload: Box<dyn Any + Send>,
        phase: &'static str,
    ) -> DrainFailure {
        let failure = owner.record_startup_poll_panic(StartupPollPanic::new(payload, phase));
        self.retain(failure.clone());
        failure
    }
    fn poll_opening(
        &mut self,
        owner: &SnapshotBufferOwner,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<StartedGroup, DrainFailure>> {
        let result = match self {
            Self::Opening(future) => catch_unwind(AssertUnwindSafe(|| future.as_mut().poll(cx))),
            Self::Retained { failure, .. } => return Poll::Ready(Err(failure.clone())),
            _ => unreachable!("opening future expected"),
        };
        match result {
            Err(payload) => Poll::Ready(Err(self.panic(owner, payload, "Raft startup"))),
            Ok(Poll::Pending) => Poll::Pending,
            Ok(Poll::Ready(Ok(group))) => Poll::Ready(Ok(group)),
            Ok(Poll::Ready(Err(error))) => {
                let failure = owner.record_startup_error(error);
                if failure.completion() == DrainCompletion::Retained {
                    self.retain(failure.clone());
                } else {
                    *self = Self::Finished(Err(failure.clone()));
                }
                Poll::Ready(Err(failure))
            }
        }
    }
    pub(crate) async fn claim(&mut self, owner: &SnapshotBufferOwner) -> Result<StartedGroup> {
        // Synchronous enrollment can be followed by a census before this
        // claimant is first polled. Never poll an already completed operation.
        if !matches!(self, Self::Opening(_) | Self::Retained { .. }) {
            return Err(match self.drain(owner).await {
                Err(failure) => failure,
                Ok(()) => owner.record_startup_error(anyhow::anyhow!(
                    "Raft startup result was reclaimed by shutdown"
                )),
            }
            .into());
        }
        let group = std::future::poll_fn(|cx| self.poll_opening(owner, cx)).await?;
        if let Err(error) = owner.check_startup() {
            let failure = owner.record_startup_error(error.into());
            *self = Self::Cleaning(Box::pin(cleanup(Some(group))));
            let cleanup = self.drain(owner).await;
            return Err(cleanup.err().unwrap_or(failure).into());
        }
        *self = Self::Delivered;
        Ok(group)
    }
    pub(crate) async fn drain(&mut self, owner: &SnapshotBufferOwner) -> DrainResult {
        std::future::poll_fn(|cx| {
            loop {
                match self {
                    Self::Idle | Self::Delivered => return Poll::Ready(Ok(())),
                    Self::Finished(result) => return Poll::Ready(result.clone()),
                    Self::Retained { failure, .. } => return Poll::Ready(Err(failure.clone())),
                    Self::Opening(_) => match self.poll_opening(owner, cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Ok(group)) => {
                            *self = Self::Cleaning(Box::pin(cleanup(Some(group))))
                        }
                        Poll::Ready(Err(failure)) => return Poll::Ready(Err(failure)),
                    },
                    Self::Cleaning(future) => {
                        match catch_unwind(AssertUnwindSafe(|| future.as_mut().poll(cx))) {
                            Err(payload) => {
                                return Poll::Ready(Err(self.panic(
                                    owner,
                                    payload,
                                    "Raft startup cleanup",
                                )));
                            }
                            Ok(Poll::Pending) => return Poll::Pending,
                            Ok(Poll::Ready(Err(failure)))
                                if failure.completion() == DrainCompletion::Retained =>
                            {
                                let failure = owner.record_startup_error(failure.into());
                                self.retain(failure.clone());
                                return Poll::Ready(Err(failure));
                            }
                            Ok(Poll::Ready(result)) => *self = Self::Finished(result),
                        }
                    }
                }
            }
        })
        .await
    }
}

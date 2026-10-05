//! One charged startup operation, retained in place across cancelled callers.
//! Polling the operation owns its nested JoinHandles; no coordinator or reaper
//! task can be aborted while it owns those handles.
use crate::{CustodyRaftGroup, RaftGroup, SnapshotBufferOwner};
use anyhow::{Result, ensure};
use kasumi_store::ScratchOperationFailure;
use kasumi_types::drain::{DrainCompletion, DrainFailure, DrainResult};
use std::{
    any::Any,
    future::Future,
    panic::{AssertUnwindSafe, catch_unwind},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

pub(crate) const STARTUP_WORKSPACE: u64 = 64 << 10;
type Opening = Pin<Box<dyn Future<Output = Result<StartedGroup, ScratchOperationFailure>> + Send>>;

enum OpeningFailure {
    Recorded(DrainFailure),
    Preparation {
        original: ScratchOperationFailure,
        diagnostic: DrainFailure,
    },
}
impl OpeningFailure {
    fn diagnostic(&self) -> &DrainFailure {
        match self {
            Self::Recorded(diagnostic) | Self::Preparation { diagnostic, .. } => diagnostic,
        }
    }
    fn into_operation(self) -> ScratchOperationFailure {
        match self {
            Self::Recorded(diagnostic) => ScratchOperationFailure::Operation(diagnostic.into()),
            Self::Preparation { original, .. } => original,
        }
    }
}
pub(crate) struct Cleaning {
    future: Pin<Box<dyn Future<Output = DrainResult> + Send>>,
    // Independent of the async generator: unwinding its poll must not drop
    // the exact group before the outer startup owner retains this holder.
    _group: Option<Arc<dyn Send + Sync>>,
}

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

/// A synchronous final readiness callback can panic after Opening returned
/// the actual group. Catch that unwind while the group stays on the claim
/// stack, then move it into the existing retained cleanup before any await.
pub(crate) struct ApplicationSourceHandoffPanic {
    pub(crate) payload: Mutex<Box<dyn Any + Send>>,
}
impl std::fmt::Debug for ApplicationSourceHandoffPanic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApplicationSourceHandoffPanic")
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
impl std::fmt::Display for ApplicationSourceHandoffPanic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("application source readiness panicked; original payload retained")
    }
}
impl std::error::Error for ApplicationSourceHandoffPanic {}

pub(crate) enum StartedGroup {
    Serving(RaftGroup),
    Custody(CustodyRaftGroup),
    #[cfg(test)]
    Fixture(crate::startup_owner_tests::FixtureGroup),
}
impl StartedGroup {
    async fn shutdown(&mut self) -> DrainResult {
        match self {
            Self::Serving(group) => group.shutdown().await,
            Self::Custody(group) => group.shutdown().await,
            #[cfg(test)]
            Self::Fixture(group) => group.shutdown().await,
        }
    }
}
type CleanupGroup = Arc<tokio::sync::Mutex<StartedGroup>>;
async fn cleanup_group(group: CleanupGroup) -> DrainResult {
    group.lock().await.shutdown().await
}
fn cleanup_workspace_bytes() -> usize {
    fn future_bytes<F: Future>(_: fn(CleanupGroup) -> F) -> usize {
        std::mem::size_of::<F>()
    }
    future_bytes(cleanup_group)
        + std::mem::size_of::<tokio::sync::Mutex<StartedGroup>>()
        + std::mem::size_of::<[usize; 2]>()
        + std::mem::align_of::<tokio::sync::Mutex<StartedGroup>>()
        - 1
}
fn cleanup(group: StartedGroup) -> Cleaning {
    // Both heap backings, including overlap with the original Opening, were
    // admitted by install before startup effects. Erasure adds no allocation.
    let group = Arc::new(tokio::sync::Mutex::new(group));
    Cleaning {
        future: Box::pin(cleanup_group(group.clone())),
        _group: Some(group),
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
        F: Future<Output = Result<StartedGroup, ScratchOperationFailure>> + Send + 'static,
    {
        ensure!(
            matches!(self, Self::Idle),
            "snapshot owner already has a startup operation"
        );
        // Replacement briefly owns both allocations: reserve their sum.
        ensure!(
            std::mem::size_of_val(&future)
                .checked_add(cleanup_workspace_bytes())
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
        *self = Self::Cleaning(Cleaning {
            future: Box::pin(future),
            _group: None,
        });
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
    ) -> Poll<std::result::Result<StartedGroup, OpeningFailure>> {
        let result = match self {
            Self::Opening(future) => catch_unwind(AssertUnwindSafe(|| future.as_mut().poll(cx))),
            Self::Retained { failure, .. } => {
                return Poll::Ready(Err(OpeningFailure::Recorded(failure.clone())));
            }
            _ => unreachable!("opening future expected"),
        };
        match result {
            Err(payload) => Poll::Ready(Err(OpeningFailure::Recorded(self.panic(
                owner,
                payload,
                "Raft startup",
            )))),
            Ok(Poll::Pending) => Poll::Pending,
            Ok(Poll::Ready(Ok(group))) => Poll::Ready(Ok(group)),
            Ok(Poll::Ready(Err(error))) => {
                let failure = match error {
                    ScratchOperationFailure::Operation(error) => {
                        OpeningFailure::Recorded(owner.record_startup_error(error))
                    }
                    original @ (ScratchOperationFailure::Creation(_)
                    | ScratchOperationFailure::AdmissionRefused(_)) => {
                        let diagnostic = owner.record_startup_preparation(&original);
                        OpeningFailure::Preparation {
                            original,
                            diagnostic,
                        }
                    }
                };
                let diagnostic = failure.diagnostic();
                if diagnostic.completion() == DrainCompletion::Retained {
                    self.retain(diagnostic.clone());
                } else {
                    *self = Self::Finished(Err(diagnostic.clone()));
                }
                Poll::Ready(Err(failure))
            }
        }
    }
    pub(crate) async fn claim(
        &mut self,
        owner: &SnapshotBufferOwner,
    ) -> Result<StartedGroup, ScratchOperationFailure> {
        // Synchronous enrollment can be followed by a census before this
        // claimant is first polled. Never poll an already completed operation.
        if !matches!(self, Self::Opening(_) | Self::Retained { .. }) {
            return Err(ScratchOperationFailure::Operation(
                match self.drain(owner).await {
                    Err(failure) => failure,
                    Ok(()) => owner.record_startup_error(anyhow::anyhow!(
                        "Raft startup result was reclaimed by shutdown"
                    )),
                }
                .into(),
            ));
        }
        let group = std::future::poll_fn(|cx| self.poll_opening(owner, cx))
            .await
            .map_err(OpeningFailure::into_operation)?;
        // Full Opening includes replay and, for a local group, initialization
        // and its linearizable barrier. Validate source reconstruction before
        // transferring this actual group; a refusal enters retained cleanup
        // synchronously, before any await can be canceled.
        let ready = catch_unwind(AssertUnwindSafe(|| {
            owner
                .check_startup()
                .map_err(anyhow::Error::from)
                .and_then(|()| owner.finish_application_source_reconstruction())
                // Node shutdown can close delivery while a synchronous source
                // validator runs. Never transfer the resulting group afterward.
                .and_then(|()| owner.check_startup().map_err(anyhow::Error::from))
        }))
        .unwrap_or_else(|payload| {
            Err(ApplicationSourceHandoffPanic {
                payload: Mutex::new(payload),
            }
            .into())
        });
        if let Err(error) = ready {
            let failure = owner.record_startup_error(error);
            *self = Self::Cleaning(cleanup(group));
            let cleanup = self.drain(owner).await;
            return Err(ScratchOperationFailure::Operation(
                cleanup.err().unwrap_or(failure).into(),
            ));
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
                    Self::Retained { failure, .. } => {
                        return Poll::Ready(Err(failure.clone()));
                    }
                    Self::Opening(_) => match self.poll_opening(owner, cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Ok(group)) => *self = Self::Cleaning(cleanup(group)),
                        Poll::Ready(Err(failure)) => {
                            return Poll::Ready(Err(failure.diagnostic().clone()));
                        }
                    },
                    Self::Cleaning(future) => {
                        match catch_unwind(AssertUnwindSafe(|| future.future.as_mut().poll(cx))) {
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
                                // The same holder retains both the completed
                                // future and the independently owned group.
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

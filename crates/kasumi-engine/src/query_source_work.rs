//! Retained canonical query execution for a future fallible document source.
//!
//! This is not wired to Database yet. That handoff needs a database-local census
//! of exact SnapshotWorkId generations, sealed preparation, and explicit drain
//! before WorkFence/storage shutdown. A shared MemoryCore traversal is not a
//! substitute: it would drain another tenant's work and miss preparation races.

use super::{QueryInput, QueryOutput};
use crate::admission::snapshot_work::{ExistingGrantOperation, SnapshotOperation};
use crate::admission::{MemoryCore, Reservation, WorkRegistration};
use kasumi_query::{DocumentSource, QueryCancellation, ReadFailure};
use kasumi_types::{Limits, drain::DrainCompletion};
use std::{
    error::Error as StdError,
    sync::Arc,
    task::{Context, Poll},
};

/// Trusted retained source/pin, selected before the worker starts. Its source is
/// immutable while run borrows it. Validation and backing quotes perform no I/O
/// or source acquisition. validate_memory must check actual governed owners,
/// never an independently supplied core tag. Source bodies/loan workspace and
/// original failures need their own bounded admission; arbitrary Error payloads
/// are not covered by the fixed worker metadata quote.
///
/// Cleanup must retain a consuming close failure or interrupted close in self,
/// lend original diagnostics, and return Retained until retirement is proved.
/// Complete means all selected resources are retired (including an unused
/// source on pre-start cancellation); merely dropping a view is not proof.
/// If a returned Failure owns a live native child, this owner must retain a
/// matching diagnostic/cleanup facade and remain Retained until that child's
/// retirement is proved; a Failure cannot hide work from poll_cleanup.
/// The caller must also drive cleanup on a rejected preparation's returned plan.
pub(super) trait QuerySourceOwner: Send + 'static {
    type Source: DocumentSource;
    fn source(&self) -> &Self::Source;
    fn validate_memory(&self, core: &Arc<MemoryCore>) -> anyhow::Result<()>;
    fn backing_bytes(&self) -> anyhow::Result<u64>;
    fn poll_cleanup(&mut self, cx: &mut Context<'_>) -> Poll<DrainCompletion>;
    fn visit_diagnostics(&self, visit: &mut dyn FnMut(&(dyn StdError + 'static)));
}

/// Fields depending on the existing grant precede that grant; registration is
/// last. Rejected preparation returns this exact owner for explicit cleanup.
pub(super) struct QuerySourcePlan<S: QuerySourceOwner> {
    pub(super) source: S,
    pub(super) limits: Limits,
    pub(super) input: QueryInput,
    pub(super) permit: tokio::sync::OwnedSemaphorePermit,
    pub(super) registration: Arc<WorkRegistration>,
}

pub(super) struct QuerySourceWork<S: QuerySourceOwner> {
    source: S,
    limits: Limits,
    input: Option<QueryInput>,
    cancellation: QueryCancellation,
    permit: Option<tokio::sync::OwnedSemaphorePermit>,
    registration: Option<Arc<WorkRegistration>>,
}

/// The output itself keeps its original request, grant and registration. A
/// claimed output hands off to the existing page/output pipeline; a discarded
/// output is destroyed while this retained owner still covers its allocations.
pub(super) struct QuerySourceOutput(Option<QueryOutput>);
impl QuerySourceOutput {
    pub(super) fn into_output(mut self) -> QueryOutput {
        self.0.take().expect("claimed query output")
    }
}

impl<S: QuerySourceOwner> ExistingGrantOperation for QuerySourceWork<S> {
    fn existing_grant(plan: &Self::Plan) -> &Reservation {
        plan.input.memory.workspace()
    }
}
impl<S: QuerySourceOwner> SnapshotOperation for QuerySourceWork<S> {
    type Plan = QuerySourcePlan<S>;
    type Output = QuerySourceOutput;
    type Failure = <S::Source as kasumi_query::CollectionRecords>::Failure;

    fn validate_memory(plan: &Self::Plan, core: &Arc<MemoryCore>) -> anyhow::Result<()> {
        plan.source.validate_memory(core)
    }
    fn backing_bytes(plan: &Self::Plan) -> anyhow::Result<u64> {
        // Request/output backing stays under the unchanged QueryMemory grant.
        // Self/Output inline layouts and Tokio control backing are quoted by
        // SnapshotWork; source-specific extra backing is admitted here.
        plan.source.backing_bytes()
    }
    fn allocate(plan: Self::Plan, cancellation: QueryCancellation) -> Self {
        // Infallible inert field move only. In particular, do not acquire a
        // storage view or call provider code after preparation takes the plan.
        Self {
            source: plan.source,
            limits: plan.limits,
            input: Some(plan.input),
            cancellation,
            permit: Some(plan.permit),
            registration: Some(plan.registration),
        }
    }
    fn run(&mut self) -> std::result::Result<Self::Output, Self::Failure> {
        let input = self.input.as_mut().expect("query runs once");
        let source = self.source.source();
        let response = match source.indexes().execute_with_cancellation(
            source,
            &input.request,
            &self.limits,
            &self.cancellation,
            &mut input.memory,
        ) {
            Ok(response) => Ok(response),
            Err(ReadFailure::Query(error)) => Err(error),
            Err(ReadFailure::Source(error)) => return Err(error),
        };
        let input = self.input.take().expect("retained query input");
        Ok(QuerySourceOutput(Some(QueryOutput {
            response,
            request: input.request,
            memory: input.memory,
            _registration: self
                .registration
                .as_ref()
                .expect("active source registration")
                .clone(),
        })))
    }
    fn poll_cleanup(&mut self, cx: &mut Context<'_>) -> Poll<DrainCompletion> {
        match self.source.poll_cleanup(cx) {
            Poll::Ready(DrainCompletion::Complete) => {
                // A failed/unstarted query keeps input until source cleanup is
                // positive. A successful query transferred it to its output.
                drop(self.input.take());
                drop(self.permit.take());
                drop(self.registration.take());
                Poll::Ready(DrainCompletion::Complete)
            }
            other => other,
        }
    }
    fn poll_discard(output: &mut Self::Output, _: &mut Context<'_>) -> Poll<DrainCompletion> {
        drop(output.0.take());
        Poll::Ready(DrainCompletion::Complete)
    }
    fn visit_diagnostics(&self, visit: &mut dyn FnMut(&(dyn StdError + 'static))) {
        self.source.visit_diagnostics(visit);
    }
    fn visit_output_diagnostics(_: &Self::Output, _: &mut dyn FnMut(&(dyn StdError + 'static))) {}
}

#[cfg(test)]
#[path = "query_source_work_tests.rs"]
mod tests;

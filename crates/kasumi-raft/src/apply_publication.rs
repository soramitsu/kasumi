//! A synchronous application callback retains the exact durable outcome until
//! the backend has finished releasing its prepared state. The named Entry sink
//! performs the actual paired publication; only Engine selects its generation.

use crate::AppliedResponse;
use anyhow::Result;
use kasumi_store::WriteOp;
use std::fmt;

#[path = "publication_receipt.rs"]
pub(crate) mod receipt;
pub use receipt::{
    JointPublicationReceipt, PublicationChallenge, PublicationExpectation,
    PublicationExpectationError,
};

/// An adapter-assigned command or consensus-only application step.
#[derive(Clone, Copy, Debug)]
pub enum AppliedInput<'a> {
    Command(&'a [u8]),
    Metadata,
}

/// A non-owning notification. The publisher retains the original storage error
/// even if the backend catches this marker and subsequently returns success.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublishCallError {
    Failed,
    Repeated,
}

impl fmt::Display for PublishCallError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Failed => "application publication failed; publisher retains its error",
            Self::Repeated => "application publication was already attempted",
        })
    }
}

impl std::error::Error for PublishCallError {}

/// Publish one prepared response and its bounded application writes. The backend
/// must call this exactly once before releasing its prepared application state.
/// Returning a marker does not transfer the original failure out of the publisher.
pub trait SelectionPreparer {
    /// Called after the exact producer effects are known and before durable
    /// publication. The implementation retains its preparation independently
    /// of the caller/proposer until capture or explicit cancellation settles.
    fn prepare(
        &mut self,
        plan: &crate::PreparedSelectionPlan,
        points: kasumi_store::PreparedTenantPointWorkspace,
    ) -> Result<()>;
}

pub trait ApplyPublisher {
    fn with_completion(
        &mut self,
        expected: &crate::CompletionIdentity,
        action: &mut dyn crate::CompletionAction,
    ) -> std::result::Result<(), crate::CompletionCallError>;
    fn commit(
        &mut self,
        response: AppliedResponse,
        application_writes: &[WriteOp],
    ) -> std::result::Result<(), PublishCallError>;
    /// Prepare from the actual producer plan before the durable publication.
    fn commit_with_selection<'call>(
        &mut self,
        response: AppliedResponse,
        application_writes: &[WriteOp],
        preparer: &mut dyn SelectionPreparer,
        challenge: PublicationChallenge<'call>,
    ) -> std::result::Result<JointPublicationReceipt<'call>, PublishCallError>;
}

// Keep the already owned response inline: boxing it would add an allocation
// after a successful sink and introduce another fallible publication step.
#[allow(clippy::large_enum_variant)]
enum Phase {
    Ready,
    Running,
    Committed(AppliedResponse),
    Failed(anyhow::Error),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PublicationViolation {
    Missing,
    Repeated,
    Interrupted,
}

/// Both errors may own independent retained resources, including through an
/// anyhow context. Neither is replaced by its message or a shared wrapper.
#[derive(Debug)]
pub(crate) struct ApplyPublicationFailure {
    pub(crate) violation: Option<PublicationViolation>,
    pub(crate) publication: Option<anyhow::Error>,
    pub(crate) backend: Option<anyhow::Error>,
}

impl fmt::Display for ApplyPublicationFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.violation {
            Some(PublicationViolation::Missing) => {
                formatter.write_str("backend succeeded without application publication")?
            }
            Some(PublicationViolation::Repeated) => {
                formatter.write_str("backend attempted application publication more than once")?
            }
            Some(PublicationViolation::Interrupted) => {
                formatter.write_str("application publication did not return an outcome")?
            }
            None => formatter.write_str("application publication and backend both failed")?,
        }
        if let Some(error) = &self.publication {
            write!(formatter, "; publication: {error}")?;
        }
        if let Some(error) = &self.backend {
            write!(formatter, "; backend: {error}")?;
        }
        Ok(())
    }
}

impl std::error::Error for ApplyPublicationFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.publication
            .as_ref()
            .or(self.backend.as_ref())
            .map(|error| error.as_ref())
    }
}

/// Borrows the adapter's synchronous storage sink. The sink runs at most once;
/// success moves the response into this owner without cloning or allocating.
/// Keep this owner outside any unwind catcher around backend execution so its
/// retained failure survives until `finish` examines the backend's outcome.
#[cfg(test)]
type PlainSink<'a> = dyn FnMut(&AppliedResponse, &[WriteOp]) -> Result<()> + 'a;
pub(crate) enum SinkFailure {
    Unproven(anyhow::Error),
    CommittedAccessDenied(kasumi_store::CommittedAccessDenied),
}
impl From<anyhow::Error> for SinkFailure {
    fn from(error: anyhow::Error) -> Self {
        Self::Unproven(error)
    }
}
impl SinkFailure {
    pub(crate) fn into_parts(self) -> (anyhow::Error, bool) {
        match self {
            Self::Unproven(error) => (error, false),
            Self::CommittedAccessDenied(denied) => (denied.into_error(), true),
        }
    }
    fn into_error(self) -> anyhow::Error {
        self.into_parts().0
    }
}
pub(crate) type SinkResult<T> = std::result::Result<T, SinkFailure>;

pub(crate) trait PublicationSink {
    fn plain(&mut self, response: &AppliedResponse, writes: &[WriteOp]) -> SinkResult<()>;
    fn selected<'call>(
        &mut self,
        response: &AppliedResponse,
        writes: &[WriteOp],
        preparer: &mut dyn SelectionPreparer,
        challenge: PublicationChallenge<'call>,
    ) -> SinkResult<JointPublicationReceipt<'call>>;
}
enum Sink<'a> {
    #[cfg(test)]
    Plain(&'a mut PlainSink<'a>),
    Planned(&'a mut (dyn PublicationSink + 'a)),
}

pub(crate) struct ApplyPublication<'a> {
    sink: Sink<'a>,
    phase: Phase,
    repeated: bool,
    completion: Option<&'a crate::apply_failure::ApplyFailureSlot>,
    ordinary: Option<u64>,
}

impl<'a> ApplyPublication<'a> {
    #[cfg(test)]
    pub(crate) fn new(sink: &'a mut PlainSink<'a>) -> Self {
        Self {
            sink: Sink::Plain(sink),
            phase: Phase::Ready,
            repeated: false,
            completion: None,
            ordinary: None,
        }
    }

    pub(crate) fn new_with_selection(sink: &'a mut (dyn PublicationSink + 'a)) -> Self {
        Self {
            sink: Sink::Planned(sink),
            phase: Phase::Ready,
            repeated: false,
            completion: None,
            ordinary: None,
        }
    }

    pub(crate) fn new_bound(
        sink: &'a mut (dyn PublicationSink + 'a),
        slot: &'a crate::apply_failure::ApplyFailureSlot,
    ) -> Self {
        let mut publication = Self::new_with_selection(sink);
        publication.completion = Some(slot);
        publication
    }
    /// Stores backend ownership before any outer callback. Ordinary failure is
    /// returned as the already admitted diagnostic, never a new composite box.
    pub(crate) fn finish_observed(
        self,
        backend: std::thread::Result<Result<()>>,
        after_backend: impl FnOnce(),
    ) -> std::result::Result<FinishedPublication, FinishFailure> {
        if let Some(ordinal) = self.ordinary {
            let slot = self.completion.expect("ordinary slot");
            slot.completion().record_backend(backend);
            let finished = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                after_backend();
                slot.completion().finish(ordinal)
            }));
            let positive = match finished {
                Ok(positive) => positive,
                Err(payload) => {
                    slot.completion().finish_panic(payload);
                    false
                }
            };
            if !positive {
                return Err(FinishFailure::Retained(slot.diagnostic()));
            }
            return Ok(FinishedPublication {
                response: slot.completion().take_response(ordinal),
                acknowledgment: Some((slot.clone(), ordinal)),
            });
        }
        let backend = backend.unwrap_or_else(|payload| {
            Err(crate::apply_failure::ApplyBackendPanic::new(payload).into())
        });
        self.finish(backend)
            .map(|response| FinishedPublication {
                response,
                acknowledgment: None,
            })
            .map_err(FinishFailure::Single)
    }

    /// Call only after backend execution, including its memory publication,
    /// has finished. A successful sink alone never authorizes an acknowledgment.
    pub(crate) fn finish(self, backend: Result<()>) -> Result<AppliedResponse> {
        if self.repeated {
            let publication = match self.phase {
                Phase::Failed(error) => Some(error),
                _ => None,
            };
            return Err(ApplyPublicationFailure {
                violation: Some(PublicationViolation::Repeated),
                publication,
                backend: backend.err(),
            }
            .into());
        }
        match (self.phase, backend) {
            (Phase::Committed(response), Ok(())) => Ok(response),
            (Phase::Ready | Phase::Committed(_), Err(error)) | (Phase::Failed(error), Ok(())) => {
                Err(error)
            }
            (Phase::Failed(publication), Err(backend)) => Err(ApplyPublicationFailure {
                violation: None,
                publication: Some(publication),
                // Even a marker can carry independently owned anyhow contexts.
                // Retain it rather than infer ownership from downcast_ref.
                backend: Some(backend),
            }
            .into()),
            (Phase::Ready, Ok(())) => Err(ApplyPublicationFailure {
                violation: Some(PublicationViolation::Missing),
                publication: None,
                backend: None,
            }
            .into()),
            (Phase::Running, backend) => Err(ApplyPublicationFailure {
                violation: Some(PublicationViolation::Interrupted),
                publication: None,
                backend: backend.err(),
            }
            .into()),
        }
    }
}

/// Only this borrowed facade enters an ordinary action. Recursive entry never
/// acquires the report lock or invokes another external action.
struct CompletionPublisher<'borrow, 'env> {
    parent: &'borrow mut ApplyPublication<'env>,
    slot: &'env crate::apply_failure::ApplyFailureSlot,
}
impl ApplyPublisher for CompletionPublisher<'_, '_> {
    fn with_completion(
        &mut self,
        _: &crate::CompletionIdentity,
        _: &mut dyn crate::CompletionAction,
    ) -> std::result::Result<(), crate::CompletionCallError> {
        self.slot.completion().repeated();
        Err(crate::CompletionCallError::Recorded)
    }
    fn commit(
        &mut self,
        response: AppliedResponse,
        writes: &[WriteOp],
    ) -> std::result::Result<(), PublishCallError> {
        self.parent.commit(response, writes)
    }
    fn commit_with_selection<'call>(
        &mut self,
        response: AppliedResponse,
        writes: &[WriteOp],
        preparer: &mut dyn SelectionPreparer,
        challenge: PublicationChallenge<'call>,
    ) -> std::result::Result<JointPublicationReceipt<'call>, PublishCallError> {
        self.parent
            .commit_with_selection(response, writes, preparer, challenge)
    }
}

pub(crate) enum FinishFailure {
    Single(anyhow::Error),
    Retained(crate::apply_failure::RetainedApplyFailure),
}
pub(crate) struct FinishedPublication {
    pub(crate) response: AppliedResponse,
    pub(crate) acknowledgment: Option<(crate::apply_failure::ApplyFailureSlot, u64)>,
}
pub(crate) fn acknowledge_publication(
    acknowledgment: Option<(crate::apply_failure::ApplyFailureSlot, u64)>,
) {
    if let Some((slot, ordinal)) = acknowledgment {
        slot.completion().acknowledge(ordinal)
    }
}

impl ApplyPublisher for ApplyPublication<'_> {
    fn with_completion(
        &mut self,
        expected: &crate::CompletionIdentity,
        action: &mut dyn crate::CompletionAction,
    ) -> std::result::Result<(), crate::CompletionCallError> {
        let slot = self
            .completion
            .ok_or(crate::CompletionCallError::Unsupported)?;
        if self.ordinary.is_some() {
            slot.completion().repeated();
            return Err(crate::CompletionCallError::Recorded);
        }
        if !matches!(self.phase, Phase::Ready) {
            let ordinal = slot.completion().begin(
                slot.completion()
                    .identity()
                    .ok_or(crate::CompletionCallError::Unsupported)?,
            )?;
            self.ordinary = Some(ordinal);
            let (response, error, running) = match std::mem::replace(&mut self.phase, Phase::Ready)
            {
                Phase::Committed(response) => (Some(response), None, false),
                Phase::Failed(error) => (None, Some(error), false),
                Phase::Running => (None, None, true),
                Phase::Ready => unreachable!("checked phase"),
            };
            slot.completion().adopt_plain(response, error, running);
            return Err(crate::CompletionCallError::Recorded);
        }
        let ordinal = slot.completion().begin(expected)?;
        self.ordinary = Some(ordinal);
        let invocation = crate::CompletionInvocation::new(
            slot.completion().identity().expect("bound identity"),
            ordinal,
        );
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            action.run(&invocation, &mut CompletionPublisher { parent: self, slot })
        }));
        slot.completion().action(result)
    }
    fn commit(
        &mut self,
        response: AppliedResponse,
        application_writes: &[WriteOp],
    ) -> std::result::Result<(), PublishCallError> {
        if let Some(ordinal) = self.ordinary {
            let slot = self.completion.expect("ordinary slot");
            return slot
                .completion()
                .sink(ordinal, response, |response| match &mut self.sink {
                    Sink::Planned(sink) => sink.plain(response, application_writes),
                    #[cfg(test)]
                    Sink::Plain(sink) => sink(response, application_writes).map_err(Into::into),
                });
        }
        self.enter()?;
        let outcome = match &mut self.sink {
            Sink::Planned(sink) => sink
                .plain(&response, application_writes)
                .map_err(SinkFailure::into_error),
            #[cfg(test)]
            Sink::Plain(sink) => sink(&response, application_writes),
        };
        self.complete(response, outcome)
    }
    fn commit_with_selection<'call>(
        &mut self,
        response: AppliedResponse,
        application_writes: &[WriteOp],
        preparer: &mut dyn SelectionPreparer,
        challenge: PublicationChallenge<'call>,
    ) -> std::result::Result<JointPublicationReceipt<'call>, PublishCallError> {
        if let Some(ordinal) = self.ordinary {
            let slot = self.completion.expect("ordinary slot");
            return slot
                .completion()
                .sink(ordinal, response, |response| match &mut self.sink {
                    Sink::Planned(sink) => {
                        sink.selected(response, application_writes, preparer, challenge)
                    }
                    #[cfg(test)]
                    Sink::Plain(_) => {
                        Err(anyhow::anyhow!("publisher lacks a prospective selection plan").into())
                    }
                });
        }
        self.enter()?;
        let outcome = match &mut self.sink {
            Sink::Planned(sink) => sink
                .selected(&response, application_writes, preparer, challenge)
                .map_err(SinkFailure::into_error),
            #[cfg(test)]
            Sink::Plain(_) => Err(anyhow::anyhow!(
                "publisher lacks a prospective selection plan"
            )),
        };
        self.complete(response, outcome)
    }
}
impl ApplyPublication<'_> {
    fn enter(&mut self) -> std::result::Result<(), PublishCallError> {
        if !matches!(self.phase, Phase::Ready) {
            self.repeated = true;
            return Err(PublishCallError::Repeated);
        }
        // A caught sink panic must leave an interrupted state, never Ready.
        self.phase = Phase::Running;
        Ok(())
    }
    fn complete<T>(
        &mut self,
        response: AppliedResponse,
        outcome: Result<T>,
    ) -> std::result::Result<T, PublishCallError> {
        match outcome {
            Ok(output) => {
                self.phase = Phase::Committed(response);
                Ok(output)
            }
            Err(error) => {
                self.phase = Phase::Failed(error);
                Err(PublishCallError::Failed)
            }
        }
    }
}

/// Actual adapter-owned Entry sink. Production keeps its existing metadata
/// check and control lock; the test adapter uses its caller's serialization.
pub(crate) struct EntryPublicationSink<'env> {
    stores: &'env kasumi_store::TenantStorageSet,
    position: &'env crate::AppliedEntryContext,
    gate: Option<&'env std::sync::Mutex<()>>,
    metadata: bool,
}
impl<'env> EntryPublicationSink<'env> {
    pub(crate) fn new(
        stores: &'env kasumi_store::TenantStorageSet,
        position: &'env crate::AppliedEntryContext,
        gate: Option<&'env std::sync::Mutex<()>>,
        metadata: bool,
    ) -> Self {
        Self {
            stores,
            position,
            gate,
            metadata,
        }
    }
    fn run<T>(
        &self,
        response: &AppliedResponse,
        publish: impl FnOnce() -> SinkResult<T>,
    ) -> SinkResult<T> {
        if self.metadata && (!response.data.is_empty() || response.retirement.is_some()) {
            return Err(anyhow::anyhow!(
                "metadata publication has an application response or retirement"
            )
            .into());
        }
        let _guard = self
            .gate
            .map(|gate| {
                gate.lock()
                    .map_err(|_| anyhow::anyhow!("control publication lock poisoned"))
            })
            .transpose()?;
        publish()
    }
}
impl PublicationSink for EntryPublicationSink<'_> {
    fn plain(&mut self, response: &AppliedResponse, writes: &[WriteOp]) -> SinkResult<()> {
        self.run(response, || {
            let prepared = crate::control::prepare_applied(
                self.stores,
                self.position,
                response.retirement.as_ref(),
            )?;
            publication_outcome(prepared.publish_outcome(self.stores, writes)?)
        })
    }
    fn selected<'call>(
        &mut self,
        response: &AppliedResponse,
        writes: &[WriteOp],
        preparer: &mut dyn SelectionPreparer,
        challenge: PublicationChallenge<'call>,
    ) -> SinkResult<JointPublicationReceipt<'call>> {
        self.run(response, || {
            let entered = challenge
                .enter(self.stores, self.position, response, writes)
                .map_err(anyhow::Error::from)?;
            let (prepared, plan, points) = crate::control::prepare_applied_and_selection(
                self.stores,
                self.position,
                response.retirement.as_ref(),
                writes,
            )?;
            let receipt = entered.prepare(&plan).map_err(anyhow::Error::from)?;
            preparer.prepare(&plan, points)?;
            publication_outcome(prepared.publish_outcome(self.stores, writes)?)?;
            Ok(receipt.mint())
        })
    }
}

fn publication_outcome(outcome: kasumi_store::DomainPublicationOutcome) -> SinkResult<()> {
    match outcome {
        kasumi_store::DomainPublicationOutcome::Acknowledged => Ok(()),
        kasumi_store::DomainPublicationOutcome::CommittedAccessDenied(denied) => {
            Err(SinkFailure::CommittedAccessDenied(denied))
        }
    }
}

/// Execute a test backend against the actual custody producer and publication
/// failure owner. No caller-built plan or synthetic successful sink is accepted.
/// The test caller serializes its real stores; this helper mints no serving guard.
#[cfg(any(test, feature = "test-utils"))]
pub fn with_application_publisher_for_test(
    stores: &kasumi_store::TenantStorageSet,
    position: &crate::AppliedEntryContext,
    invoke: impl FnOnce(&mut dyn ApplyPublisher) -> Result<()>,
) -> Result<AppliedResponse> {
    let mut sink = EntryPublicationSink::new(stores, position, None, false);
    let mut publication = ApplyPublication::new_with_selection(&mut sink);
    let backend =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| invoke(&mut publication)))
            .unwrap_or_else(|payload| {
                Err(crate::apply_failure::ApplyBackendPanic::new(payload).into())
            });
    publication.finish(backend)
}

/// Execute the actual bound adapter through outer finish. The response is handed
/// to the test caller only after positive settlement; no fabricated receipt.
#[cfg(any(test, feature = "test-utils"))]
pub fn with_application_publisher_bound_for_test(
    buffers: &crate::SnapshotBufferOwner,
    stores: &kasumi_store::TenantStorageSet,
    position: &crate::AppliedEntryContext,
    invoke: impl FnOnce(&mut dyn ApplyPublisher) -> Result<()>,
) -> Result<AppliedResponse> {
    with_application_publisher_bound_observed_for_test(buffers, stores, position, invoke, || {})
}
#[cfg(any(test, feature = "test-utils"))]
pub fn with_application_publisher_bound_observed_for_test(
    buffers: &crate::SnapshotBufferOwner,
    stores: &kasumi_store::TenantStorageSet,
    position: &crate::AppliedEntryContext,
    invoke: impl FnOnce(&mut dyn ApplyPublisher) -> Result<()>,
    after_backend: impl FnOnce(),
) -> Result<AppliedResponse> {
    if let Some(failure) = buffers.apply_failure() {
        return Err(failure.into());
    }
    let mut sink = EntryPublicationSink::new(stores, position, None, false);
    let mut publication = ApplyPublication::new_bound(&mut sink, buffers.apply_slot());
    let backend =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| invoke(&mut publication)));
    match publication.finish_observed(backend, after_backend) {
        Ok(FinishedPublication {
            response,
            acknowledgment,
        }) => {
            acknowledge_publication(acknowledgment);
            Ok(response)
        }
        Err(FinishFailure::Retained(failure)) => Err(failure.into()),
        Err(FinishFailure::Single(error)) => Err(buffers.retain_apply_failure(error).into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Debug)]
    struct OwnedError {
        identity: &'static str,
        drops: Arc<AtomicUsize>,
    }

    impl fmt::Display for OwnedError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str(self.identity)
        }
    }
    impl std::error::Error for OwnedError {}
    impl Drop for OwnedError {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn owned(identity: &'static str, drops: &Arc<AtomicUsize>) -> anyhow::Error {
        OwnedError {
            identity,
            drops: drops.clone(),
        }
        .into()
    }

    fn response() -> AppliedResponse {
        AppliedResponse::application(vec![1, 2, 3])
    }

    fn failure(result: Result<AppliedResponse>) -> anyhow::Error {
        match result {
            Ok(_) => panic!("invalid publication returned a response"),
            Err(error) => error,
        }
    }

    fn protocol(error: &anyhow::Error) -> &ApplyPublicationFailure {
        error.downcast_ref().expect("owned publication failure")
    }

    #[test]
    fn successful_sink_borrows_writes_and_returns_the_exact_owned_response() {
        let calls = Cell::new(0);
        let response = response();
        let response_pointer = response.data.as_ptr();
        let writes = [WriteOp::put("application", b"key", vec![4, 5])];
        let mut sink = |observed: &AppliedResponse, observed_writes: &[WriteOp]| {
            calls.set(calls.get() + 1);
            assert_eq!(observed.data.as_ptr(), response_pointer);
            assert_eq!(observed.data, [1, 2, 3]);
            assert!(observed.retirement.is_none());
            assert!(std::ptr::eq(observed_writes, writes.as_slice()));
            Ok(())
        };
        let mut publication = ApplyPublication::new(&mut sink);
        let publisher: &mut dyn ApplyPublisher = &mut publication;
        publisher.commit(response, &writes).unwrap();
        let selected = publication.finish(Ok(())).unwrap();
        assert_eq!(calls.get(), 1);
        assert_eq!(selected.data.as_ptr(), response_pointer);
        assert_eq!(selected.data, [1, 2, 3]);
    }

    #[test]
    fn missing_callback_rejects_backend_success_without_invoking_sink() {
        let mut sink = |_: &AppliedResponse, _: &[WriteOp]| -> Result<()> {
            panic!("missing callback invoked its sink")
        };
        let error = failure(ApplyPublication::new(&mut sink).finish(Ok(())));
        assert_eq!(
            protocol(&error).violation,
            Some(PublicationViolation::Missing)
        );
    }

    #[test]
    fn preparation_failure_returns_its_original_owner_without_missing_violation() {
        let drops = Arc::new(AtomicUsize::new(0));
        let mut sink = |_: &AppliedResponse, _: &[WriteOp]| -> Result<()> {
            panic!("failed preparation invoked its sink")
        };
        let error =
            failure(ApplyPublication::new(&mut sink).finish(Err(owned("preparation", &drops))));
        assert_eq!(
            error.downcast_ref::<OwnedError>().unwrap().identity,
            "preparation"
        );
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        drop(error);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn caught_duplicate_after_success_is_sticky_and_never_reinvokes_sink() {
        let calls = Cell::new(0);
        let mut sink = |_: &AppliedResponse, _: &[WriteOp]| {
            calls.set(calls.get() + 1);
            Ok(())
        };
        let mut publication = ApplyPublication::new(&mut sink);
        publication.commit(response(), &[]).unwrap();
        for _ in 0..2 {
            assert_eq!(
                publication.commit(response(), &[]),
                Err(PublishCallError::Repeated)
            );
        }
        let error = failure(publication.finish(Ok(())));
        assert_eq!(
            protocol(&error).violation,
            Some(PublicationViolation::Repeated)
        );
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn swallowed_sink_failure_retains_its_original_error_until_finish_owner_drops() {
        let drops = Arc::new(AtomicUsize::new(0));
        let mut original = Some(owned("publication", &drops));
        let mut sink = |_: &AppliedResponse, _: &[WriteOp]| Err(original.take().unwrap());
        let mut publication = ApplyPublication::new(&mut sink);
        assert_eq!(
            publication.commit(response(), &[]),
            Err(PublishCallError::Failed)
        );
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        let error = failure(publication.finish(Ok(())));
        assert_eq!(
            error.downcast_ref::<OwnedError>().unwrap().identity,
            "publication"
        );
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        drop(error);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn caught_duplicate_after_failure_keeps_the_original_failure_owner() {
        let drops = Arc::new(AtomicUsize::new(0));
        let calls = Cell::new(0);
        let mut original = Some(owned("publication", &drops));
        let mut sink = |_: &AppliedResponse, _: &[WriteOp]| {
            calls.set(calls.get() + 1);
            Err(original.take().unwrap())
        };
        let mut publication = ApplyPublication::new(&mut sink);
        assert_eq!(
            publication.commit(response(), &[]),
            Err(PublishCallError::Failed)
        );
        assert_eq!(
            publication.commit(response(), &[]),
            Err(PublishCallError::Repeated)
        );
        let error = failure(publication.finish(Ok(())));
        let retained = protocol(&error);
        assert_eq!(retained.violation, Some(PublicationViolation::Repeated));
        assert_eq!(
            retained
                .publication
                .as_ref()
                .unwrap()
                .downcast_ref::<OwnedError>()
                .unwrap()
                .identity,
            "publication"
        );
        assert_eq!(calls.get(), 1);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        drop(error);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn propagated_marker_and_its_owned_context_do_not_replace_sink_error() {
        let publication_drops = Arc::new(AtomicUsize::new(0));
        let context_drops = Arc::new(AtomicUsize::new(0));
        let mut original = Some(owned("publication", &publication_drops));
        let mut sink = |_: &AppliedResponse, _: &[WriteOp]| Err(original.take().unwrap());
        let mut publication = ApplyPublication::new(&mut sink);
        let marker = publication.commit(response(), &[]).unwrap_err();
        let backend = anyhow::Error::new(marker).context(OwnedError {
            identity: "backend context",
            drops: context_drops.clone(),
        });
        assert!(backend.downcast_ref::<PublishCallError>().is_some());
        let error = failure(publication.finish(Err(backend)));
        let retained = protocol(&error);
        assert!(retained.violation.is_none());
        assert_eq!(
            retained
                .publication
                .as_ref()
                .unwrap()
                .downcast_ref::<OwnedError>()
                .unwrap()
                .identity,
            "publication"
        );
        assert_eq!(
            retained
                .backend
                .as_ref()
                .unwrap()
                .downcast_ref::<PublishCallError>(),
            Some(&PublishCallError::Failed)
        );
        assert_eq!(
            retained
                .backend
                .as_ref()
                .unwrap()
                .downcast_ref::<OwnedError>()
                .unwrap()
                .identity,
            "backend context"
        );
        assert_eq!(publication_drops.load(Ordering::SeqCst), 0);
        assert_eq!(context_drops.load(Ordering::SeqCst), 0);
        drop(error);
        assert_eq!(publication_drops.load(Ordering::SeqCst), 1);
        assert_eq!(context_drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn independent_backend_and_publication_errors_keep_both_exact_owners() {
        let publication_drops = Arc::new(AtomicUsize::new(0));
        let backend_drops = Arc::new(AtomicUsize::new(0));
        let mut original = Some(owned("publication", &publication_drops));
        let mut sink = |_: &AppliedResponse, _: &[WriteOp]| Err(original.take().unwrap());
        let mut publication = ApplyPublication::new(&mut sink);
        assert_eq!(
            publication.commit(response(), &[]),
            Err(PublishCallError::Failed)
        );
        let error = failure(publication.finish(Err(owned("backend", &backend_drops))));
        let retained = protocol(&error);
        assert_eq!(
            retained
                .publication
                .as_ref()
                .unwrap()
                .downcast_ref::<OwnedError>()
                .unwrap()
                .identity,
            "publication"
        );
        assert_eq!(
            retained
                .backend
                .as_ref()
                .unwrap()
                .downcast_ref::<OwnedError>()
                .unwrap()
                .identity,
            "backend"
        );
        assert_eq!(publication_drops.load(Ordering::SeqCst), 0);
        assert_eq!(backend_drops.load(Ordering::SeqCst), 0);
        drop(error);
        assert_eq!(publication_drops.load(Ordering::SeqCst), 1);
        assert_eq!(backend_drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn postcommit_backend_failure_cannot_acknowledge_the_stored_response() {
        let drops = Arc::new(AtomicUsize::new(0));
        let mut sink = |_: &AppliedResponse, _: &[WriteOp]| Ok(());
        let mut publication = ApplyPublication::new(&mut sink);
        publication.commit(response(), &[]).unwrap();
        let error = failure(publication.finish(Err(owned("release", &drops))));
        assert_eq!(
            error.downcast_ref::<OwnedError>().unwrap().identity,
            "release"
        );
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        drop(error);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn caught_sink_panic_leaves_running_and_cannot_be_swallowed_into_success() {
        let calls = Cell::new(0);
        let mut sink = |_: &AppliedResponse, _: &[WriteOp]| -> Result<()> {
            calls.set(calls.get() + 1);
            panic!("injected sink panic")
        };
        let mut publication = ApplyPublication::new(&mut sink);
        assert!(catch_unwind(AssertUnwindSafe(|| publication.commit(response(), &[]))).is_err());
        let error = failure(publication.finish(Ok(())));
        assert_eq!(
            protocol(&error).violation,
            Some(PublicationViolation::Interrupted)
        );
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn retry_after_caught_sink_panic_is_a_sticky_duplicate_without_reentry() {
        let calls = Cell::new(0);
        let mut sink = |_: &AppliedResponse, _: &[WriteOp]| -> Result<()> {
            calls.set(calls.get() + 1);
            panic!("injected sink panic")
        };
        let mut publication = ApplyPublication::new(&mut sink);
        assert!(catch_unwind(AssertUnwindSafe(|| publication.commit(response(), &[]))).is_err());
        assert_eq!(
            publication.commit(response(), &[]),
            Err(PublishCallError::Repeated)
        );
        let error = failure(publication.finish(Ok(())));
        assert_eq!(
            protocol(&error).violation,
            Some(PublicationViolation::Repeated)
        );
        assert_eq!(calls.get(), 1);
    }
}

#[cfg(test)]
#[path = "apply_completion_tests.rs"]
mod completion_tests;

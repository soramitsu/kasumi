//! Exact installed completion identity and synchronous borrowed invocation.
//! A name alone grants nothing; the real adapter checks its installed binding.
use crate::ApplyPublisher;
use std::{
    fmt,
    task::{Context, Poll},
};

/// Nonzero-sized stable anchor embedded in the actual admitted completion owner.
/// It is intentionally neither Clone nor a transferable publication capability.
#[derive(Default)]
pub struct CompletionIdentity {
    _anchor: u8,
}
impl CompletionIdentity {
    pub const fn new() -> Self {
        Self { _anchor: 0 }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompletionCallError {
    Unsupported,
    Foreign,
    Repeated,
    Closed,
    IdentifierExhausted,
    Recorded,
}
impl fmt::Display for CompletionCallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unsupported => "publisher has no installed ordinary completion",
            Self::Foreign => "ordinary completion belongs to another installed owner",
            Self::Repeated => "ordinary completion was already entered",
            Self::Closed => "ordinary completion owner is closed",
            Self::IdentifierExhausted => "ordinary completion invocation exhausted",
            Self::Recorded => "ordinary completion failed; original observations retained",
        })
    }
}
impl std::error::Error for CompletionCallError {}
impl From<CompletionCallError> for kasumi_store::ScratchOperationFailure {
    fn from(original: CompletionCallError) -> Self {
        Self::Operation(anyhow::Error::new(original))
    }
}

/// The actual adapter's one invocation. A borrowed token cannot outlive the
/// synchronous action; private construction and ordinal prevent substitution.
pub struct CompletionInvocation<'a> {
    identity: &'a CompletionIdentity,
    ordinal: u64,
    input_retention: Option<&'a crate::ApplicationInputLoan>,
}
impl<'a> CompletionInvocation<'a> {
    pub(crate) fn new(identity: &'a CompletionIdentity, ordinal: u64) -> Self {
        Self {
            identity,
            ordinal,
            input_retention: None,
        }
    }
    pub(crate) fn with_input_retention(
        mut self,
        input: Option<&'a crate::ApplicationInputLoan>,
    ) -> Self {
        self.input_retention = input;
        self
    }
    /// Same already paid encoded input/control. None identifies an unsupported
    /// input producer (transport/replay/stored/retirement/metadata). This is not
    /// reducer/candidate credit, native admission or a completion verdict.
    pub fn input_retention(&self) -> Option<&crate::ApplicationInputLoan> {
        self.input_retention
    }
    pub fn ordinal(&self) -> u64 {
        self.ordinal
    }
    pub fn require_identity(
        &self,
        identity: &CompletionIdentity,
    ) -> Result<(), CompletionCallError> {
        if std::ptr::eq(self.identity, identity) {
            Ok(())
        } else {
            Err(CompletionCallError::Foreign)
        }
    }
    /// Identify this exact returned error allocation while the actual action
    /// still owns it. The identity alone proves no retirement or acknowledgment.
    pub fn action_failure_identity(
        &self,
        original: &anyhow::Error,
    ) -> CompletionActionFailureIdentity {
        CompletionActionFailureIdentity {
            binding: std::ptr::from_ref(self.identity) as usize,
            ordinal: self.ordinal,
            original: std::ptr::from_ref::<dyn std::error::Error + Send + Sync>(original.as_ref())
                as *const () as usize,
        }
    }
}

/// An opaque observation of one real action's unchanged error allocation.
/// A custody owner may return it only after retiring that error's exact work.
/// It never authorizes taking the failed response or resetting the failure.
#[derive(Clone, Copy)]
pub struct CompletionActionFailureIdentity {
    binding: usize,
    ordinal: u64,
    original: usize,
}
impl CompletionActionFailureIdentity {
    pub(crate) fn matches(
        self,
        binding: &CompletionIdentity,
        ordinal: u64,
        original: &anyhow::Error,
    ) -> bool {
        self.binding == std::ptr::from_ref(binding) as usize
            && self.ordinal == ordinal
            && self.original
                == std::ptr::from_ref::<dyn std::error::Error + Send + Sync>(original.as_ref())
                    as *const () as usize
    }

    /// Borrow the already captured proof against the binding address observed
    /// by the actual checked begin. Inspection invokes no custody callback.
    #[cfg(any(test, feature = "test-utils"))]
    pub(crate) fn matches_observed(
        self,
        binding_address: usize,
        ordinal: u64,
        original: &anyhow::Error,
    ) -> bool {
        self.binding == binding_address
            && self.ordinal == ordinal
            && self.original
                == std::ptr::from_ref::<dyn std::error::Error + Send + Sync>(original.as_ref())
                    as *const () as usize
    }
}

/// The action acquires/releases its guards synchronously inside this call.
/// Neither the action nor any guard is moved into retained Raft storage.
pub trait CompletionAction {
    fn run(
        &mut self,
        invocation: &CompletionInvocation<'_>,
        publisher: &mut dyn ApplyPublisher,
    ) -> Result<(), kasumi_store::ScratchOperationFailure>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompletionVerdict {
    Success,
    Failed,
}
/// Created only by real outer finish, after original verdict custody is stored.
pub struct CompletionFinalization<'a> {
    invocation: CompletionInvocation<'a>,
    verdict: CompletionVerdict,
}
impl<'a> CompletionFinalization<'a> {
    pub(crate) fn new(
        identity: &'a CompletionIdentity,
        ordinal: u64,
        verdict: CompletionVerdict,
    ) -> Self {
        Self {
            invocation: CompletionInvocation::new(identity, ordinal),
            verdict,
        }
    }
    pub fn ordinal(&self) -> u64 {
        self.invocation.ordinal()
    }
    pub fn verdict(&self) -> CompletionVerdict {
        self.verdict
    }
    pub fn require_identity(
        &self,
        identity: &CompletionIdentity,
    ) -> Result<(), CompletionCallError> {
        self.invocation.require_identity(identity)
    }
}

/// Fixed cleanup notification only. Originals remain in the exact Engine owner;
/// deliberately no Error/anyhow conversion creates another failure shell.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompletionSettleError {
    Busy,
    Retained,
    Foreign,
    Protocol,
}
pub trait CompletionCustody: Send + Sync {
    fn identity(&self) -> &CompletionIdentity;
    fn settle(&self, finalization: CompletionFinalization<'_>)
    -> Result<(), CompletionSettleError>;
    /// Called after real writers stop, before application source drain. Startup
    /// serialization can be held, so this must never reenter startup APIs.
    fn poll_drain(&self, cx: &mut Context<'_>) -> Poll<Result<(), CompletionSettleError>>;
    fn is_drained(&self) -> bool;
    /// Lend only a positively retired exact action-error identity after sealed
    /// drain. Unknown errors, panics and callbacks without a work census retain
    /// the default refusal. Raft invokes this outside its report mutex.
    fn retired_action_failure(&self) -> Option<CompletionActionFailureIdentity> {
        None
    }
}
trait RetireCompletion: CompletionCustody {
    fn retire(self: Box<Self>);
}
impl<T: CompletionCustody> RetireCompletion for T {
    fn retire(self: Box<Self>) {
        let owner = {
            let allocation = self;
            *allocation
        };
        drop(owner);
    }
}
/// The concrete owner carries credit through this erasure allocation's actual
/// deallocation. It has no cloning or raw-token extraction API.
pub struct CompletionBinding {
    owner: Option<Box<dyn RetireCompletion>>,
}
impl CompletionBinding {
    pub fn required_bytes<T: CompletionCustody>() -> anyhow::Result<u64> {
        std::mem::size_of::<T>()
            .checked_next_power_of_two()
            .and_then(|n| n.checked_add(64))
            .and_then(|n| u64::try_from(n).ok())
            .ok_or_else(|| anyhow::anyhow!("completion binding quote overflow"))
    }
    /// Caller has preclaimed the constructor's quote and moved that credit into owner.
    pub fn new<T: CompletionCustody + 'static>(owner: T) -> Self {
        Self {
            owner: Some(Box::new(owner)),
        }
    }
    #[cfg(any(test, feature = "test-utils"))]
    pub fn allocation_address(&self) -> usize {
        std::ptr::from_ref(self.owner.as_deref().expect("completion binding")) as *const () as usize
    }
}
impl CompletionCustody for CompletionBinding {
    fn identity(&self) -> &CompletionIdentity {
        self.owner.as_ref().expect("completion binding").identity()
    }
    fn settle(
        &self,
        finalization: CompletionFinalization<'_>,
    ) -> Result<(), CompletionSettleError> {
        self.owner
            .as_ref()
            .expect("completion binding")
            .settle(finalization)
    }
    fn poll_drain(&self, cx: &mut Context<'_>) -> Poll<Result<(), CompletionSettleError>> {
        self.owner
            .as_ref()
            .expect("completion binding")
            .poll_drain(cx)
    }
    fn is_drained(&self) -> bool {
        self.owner
            .as_ref()
            .expect("completion binding")
            .is_drained()
    }
    fn retired_action_failure(&self) -> Option<CompletionActionFailureIdentity> {
        self.owner
            .as_ref()
            .expect("completion binding")
            .retired_action_failure()
    }
}
impl Drop for CompletionBinding {
    fn drop(&mut self) {
        if let Some(owner) = self.owner.take() {
            owner.retire();
        }
    }
}

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

/// The actual adapter's one invocation. A borrowed token cannot outlive the
/// synchronous action; private construction and ordinal prevent substitution.
pub struct CompletionInvocation<'a> {
    identity: &'a CompletionIdentity,
    ordinal: u64,
}
impl<'a> CompletionInvocation<'a> {
    pub(crate) fn new(identity: &'a CompletionIdentity, ordinal: u64) -> Self {
        Self { identity, ordinal }
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
}

/// The action acquires/releases its guards synchronously inside this call.
/// Neither the action nor any guard is moved into retained Raft storage.
pub trait CompletionAction {
    fn run(
        &mut self,
        invocation: &CompletionInvocation<'_>,
        publisher: &mut dyn ApplyPublisher,
    ) -> anyhow::Result<()>;
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
}
impl Drop for CompletionBinding {
    fn drop(&mut self) {
        if let Some(owner) = self.owner.take() {
            owner.retire();
        }
    }
}

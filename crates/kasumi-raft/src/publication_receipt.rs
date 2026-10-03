//! A synchronous, one-use invocation identity. Content hashes bind the actual
//! producer/effects; a borrowed nonzero anchor distinguishes identical replays.
use crate::{AppliedEntryContext, AppliedResponse, PreparedSelectionPlan};
use kasumi_store::{TenantStorageSet, TenantStore, WriteOp};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{cell::Cell, fmt, io::Write};

type Hash = [u8; 32];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublicationExpectationError {
    Encoding,
    Length,
    Repeated,
    WrongPhase,
    ForeignInvocation,
    BindingMismatch,
}
impl fmt::Display for PublicationExpectationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Encoding => "publication fingerprint encoding failed",
            Self::Length => "publication fingerprint length overflow",
            Self::Repeated => "publication challenge was already issued",
            Self::WrongPhase => "publication receipt is not committed",
            Self::ForeignInvocation => "publication receipt belongs to another invocation",
            Self::BindingMismatch => "publication receipt binding differs",
        })
    }
}
impl std::error::Error for PublicationExpectationError {}

type Result<T> = std::result::Result<T, PublicationExpectationError>;

#[derive(Clone, Copy, PartialEq, Eq)]
enum InvocationState {
    Fresh,
    Issued,
    Entered,
    Committed,
    Consumed,
    Rejected,
}

/// Caller-owned expected inputs, not proof that publication occurred. Its
/// private nonzero anchor cannot be reset or moved while a token borrows it.
///
/// ```compile_fail
/// use kasumi_raft::{AppliedEntryContext, AppliedResponse, PublicationExpectation};
/// fn move_borrowed(stores: &kasumi_store::TenantStorageSet, position: &AppliedEntryContext) {
///     let response = AppliedResponse::application(Vec::new());
///     let expected = PublicationExpectation::for_entry(stores, position, &[], &response).unwrap();
///     let challenge = expected.challenge().unwrap();
///     drop(expected);
///     drop(challenge);
/// }
/// ```
#[must_use]
pub struct PublicationExpectation<'env> {
    anchor: Cell<InvocationState>,
    stores: &'env TenantStorageSet,
    position: &'env AppliedEntryContext,
    writes: &'env [WriteOp],
    response: Hash,
}
/// A challenge is consumed by one synchronous publisher call.
///
/// ```compile_fail
/// use kasumi_raft::PublicationChallenge;
/// fn duplicate(challenge: PublicationChallenge<'_>) { let _ = challenge.clone(); }
/// ```
#[must_use]
pub struct PublicationChallenge<'call> {
    anchor: &'call Cell<InvocationState>,
    stores: &'call TenantStorageSet,
    position: &'call AppliedEntryContext,
    writes: &'call [WriteOp],
    response: Hash,
}

/// Only the real producer's successful publication can mint this value. It
/// borrows neither the publisher nor the source preparer's mutable reference.
///
/// ```compile_fail
/// use kasumi_raft::JointPublicationReceipt;
/// fn extend<'a>(receipt: JointPublicationReceipt<'a>) -> JointPublicationReceipt<'static> {
///     receipt
/// }
/// ```
/// ```compile_fail
/// use kasumi_raft::JointPublicationReceipt;
/// fn require_send<T: Send>() {}
/// require_send::<JointPublicationReceipt<'static>>();
/// ```
/// ```compile_fail
/// use kasumi_raft::{JointPublicationReceipt, PublicationExpectation, PreparedSelectionPlan};
/// fn twice(expected: &PublicationExpectation<'_>, plan: &PreparedSelectionPlan, receipt: JointPublicationReceipt<'_>) {
///     let _ = expected.consume(receipt, plan);
///     let _ = expected.consume(receipt, plan);
/// }
/// ```
#[must_use]
pub struct JointPublicationReceipt<'call> {
    anchor: &'call Cell<InvocationState>,
    application: &'call TenantStore,
    custody: &'call TenantStore,
    binding: ReceiptBinding,
}
struct ReceiptBinding {
    producer: Hash,
    context: Hash,
    plan: Hash,
    application: Hash,
    joint: Hash,
    response: Hash,
}

impl<'env> PublicationExpectation<'env> {
    pub fn for_entry(
        stores: &'env TenantStorageSet,
        position: &'env AppliedEntryContext,
        application_writes: &'env [WriteOp],
        response: &AppliedResponse,
    ) -> Result<Self> {
        // Validate concrete serializations before the caller moves its response.
        producer_fingerprint(position)?;
        context_fingerprint(position)?;
        application_fingerprint(application_writes)?;
        Ok(Self {
            anchor: Cell::new(InvocationState::Fresh),
            stores,
            position,
            writes: application_writes,
            response: response_fingerprint(response)?,
        })
    }
    pub fn challenge(&self) -> Result<PublicationChallenge<'_>> {
        if self.anchor.get() != InvocationState::Fresh {
            return Err(PublicationExpectationError::Repeated);
        }
        self.anchor.set(InvocationState::Issued);
        Ok(PublicationChallenge {
            anchor: &self.anchor,
            stores: self.stores,
            position: self.position,
            writes: self.writes,
            response: self.response,
        })
    }
    pub fn consume(
        &self,
        receipt: JointPublicationReceipt<'_>,
        actual_prepared_plan: &PreparedSelectionPlan,
    ) -> Result<()> {
        // A reentrant preparer must not mutate Entered: the unique actual sink
        // still owns its challenge and must mint infallibly after publication.
        if self.anchor.get() != InvocationState::Committed {
            return Err(PublicationExpectationError::WrongPhase);
        }
        self.anchor.set(InvocationState::Rejected);
        if !std::ptr::eq(&self.anchor, receipt.anchor) {
            return Err(PublicationExpectationError::ForeignInvocation);
        }
        let producer = producer_fingerprint(self.position)?;
        let context = context_fingerprint(self.position)?;
        if !std::ptr::eq(self.stores.application().as_ref(), receipt.application)
            || !std::ptr::eq(self.stores.custody().store().as_ref(), receipt.custody)
            || !actual_prepared_plan.belongs_to(self.stores)
            || receipt.binding.producer != producer
            || receipt.binding.context != context
            || receipt.binding.application != application_fingerprint(self.writes)?
            || receipt.binding.response != self.response
            || receipt.binding.joint != actual_prepared_plan.joint_effects_fingerprint()
            || receipt.binding.plan
                != actual_prepared_plan.publication_fingerprint(producer, context)
        {
            return Err(PublicationExpectationError::BindingMismatch);
        }
        self.anchor.set(InvocationState::Consumed);
        Ok(())
    }
}

// This module is a child of apply_publication. Only that actual producer
// corridor can enter a challenge and construct the precomputed mint owner.
pub(super) struct EnteredPublication<'call> {
    challenge: PublicationChallenge<'call>,
    producer: Hash,
    context: Hash,
    application: Hash,
}
pub(super) struct PreparedReceipt<'call> {
    anchor: &'call Cell<InvocationState>,
    application: &'call TenantStore,
    custody: &'call TenantStore,
    binding: ReceiptBinding,
}
impl<'call> PublicationChallenge<'call> {
    pub(super) fn enter(
        self,
        stores: &TenantStorageSet,
        position: &AppliedEntryContext,
        response: &AppliedResponse,
        writes: &[WriteOp],
    ) -> Result<EnteredPublication<'call>> {
        if self.anchor.get() != InvocationState::Issued {
            return Err(PublicationExpectationError::WrongPhase);
        }
        let producer = producer_fingerprint(position)?;
        let context = context_fingerprint(position)?;
        let application = application_fingerprint(writes)?;
        if !std::sync::Arc::ptr_eq(self.stores.application(), stores.application())
            || !std::sync::Arc::ptr_eq(self.stores.custody().store(), stores.custody().store())
            || producer != producer_fingerprint(self.position)?
            || context != context_fingerprint(self.position)?
            || application != application_fingerprint(self.writes)?
            || self.response != response_fingerprint(response)?
        {
            return Err(PublicationExpectationError::BindingMismatch);
        }
        self.anchor.set(InvocationState::Entered);
        Ok(EnteredPublication {
            challenge: self,
            producer,
            context,
            application,
        })
    }
}
impl<'call> EnteredPublication<'call> {
    pub(super) fn prepare(self, plan: &PreparedSelectionPlan) -> Result<PreparedReceipt<'call>> {
        if !plan.belongs_to(self.challenge.stores) {
            return Err(PublicationExpectationError::BindingMismatch);
        }
        Ok(PreparedReceipt {
            anchor: self.challenge.anchor,
            application: self.challenge.stores.application().as_ref(),
            custody: self.challenge.stores.custody().store().as_ref(),
            binding: ReceiptBinding {
                producer: self.producer,
                context: self.context,
                plan: plan.publication_fingerprint(self.producer, self.context),
                application: self.application,
                joint: plan.joint_effects_fingerprint(),
                response: self.challenge.response,
            },
        })
    }
}
impl<'call> PreparedReceipt<'call> {
    /// Called only after this producer's actual publish returned success. Every
    /// fallible comparison/hash precedes publication; this path has no callbacks,
    /// assertions, serialization, allocation, or destructors of user-owned data.
    pub(super) fn mint(self) -> JointPublicationReceipt<'call> {
        #[cfg(test)]
        {
            // Observe the real successful sink's exact mint body. Assertions
            // run only in lib tests; production has no diagnostic after commit.
            crate::selected_application::allocation_tests::require_no_allocations(|| {
                self.mint_inner()
            })
        }
        #[cfg(not(test))]
        self.mint_inner()
    }
    fn mint_inner(self) -> JointPublicationReceipt<'call> {
        self.anchor.set(InvocationState::Committed);
        JointPublicationReceipt {
            anchor: self.anchor,
            application: self.application,
            custody: self.custody,
            binding: self.binding,
        }
    }
}

struct HashWriter(Sha256);
impl Write for HashWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn encoded(value: &impl Serialize) -> Result<Hash> {
    let mut writer = HashWriter(Sha256::new());
    serde_json::to_writer(&mut writer, value).map_err(|_| PublicationExpectationError::Encoding)?;
    Ok(writer.0.finalize().into())
}
fn producer_fingerprint(position: &AppliedEntryContext) -> Result<Hash> {
    // Preserve primary_boundary's existing Entry fingerprint bytes.
    encoded(&(
        "kasumi.primary.entry.v1",
        &position.log_id,
        &position.previous,
        &position.membership,
        &position.command_sha256,
    ))
}
fn context_fingerprint(position: &AppliedEntryContext) -> Result<Hash> {
    // The primary fingerprint does not contain the retirement seed. Bind that
    // additional actual producer input without changing primary format bytes.
    encoded(&(
        "kasumi.publication.context.v1",
        producer_fingerprint(position)?,
        &position.retirement_seed,
    ))
}
fn response_fingerprint(response: &AppliedResponse) -> Result<Hash> {
    let mut hash = Sha256::new();
    hash.update(b"kasumi.publication.response.v1");
    bytes(&mut hash, &response.data)?;
    hash.update(encoded(&response.retirement)?);
    Ok(hash.finalize().into())
}
fn bytes(hash: &mut Sha256, value: &[u8]) -> Result<()> {
    let len = u64::try_from(value.len()).map_err(|_| PublicationExpectationError::Length)?;
    hash.update(len.to_be_bytes());
    hash.update(value);
    Ok(())
}
fn effects(hash: &mut Sha256, writes: &[WriteOp]) -> Result<()> {
    let count = u64::try_from(writes.len()).map_err(|_| PublicationExpectationError::Length)?;
    hash.update(count.to_be_bytes());
    for write in writes {
        match write {
            WriteOp::Put {
                namespace,
                key,
                value,
            } => {
                hash.update([1]);
                bytes(hash, namespace.as_bytes())?;
                bytes(hash, key)?;
                bytes(hash, value)?;
            }
            WriteOp::Delete { namespace, key } => {
                hash.update([2]);
                bytes(hash, namespace.as_bytes())?;
                bytes(hash, key)?;
            }
        }
    }
    Ok(())
}
fn application_fingerprint(writes: &[WriteOp]) -> Result<Hash> {
    let mut hash = Sha256::new();
    hash.update(b"kasumi.publication.application.v1");
    effects(&mut hash, writes)?;
    Ok(hash.finalize().into())
}
pub(crate) fn joint_effects_fingerprint(
    application: &[WriteOp],
    custody: &[WriteOp],
) -> Result<Hash> {
    let mut hash = Sha256::new();
    hash.update(b"kasumi.publication.joint.v1");
    hash.update([1]);
    effects(&mut hash, application)?;
    hash.update([2]);
    effects(&mut hash, custody)?;
    Ok(hash.finalize().into())
}

//! Installed independent authority trust and non-renewable acquisition proofs.
//! Wire records are not live access authority. Only signature verification tied
//! to an original local attempt can construct a lease.
mod control;
pub use control::*;
mod gate;
mod lifecycle;
mod lifecycle_gate;
mod lifecycle_proof;
pub use lifecycle::*;
pub use lifecycle_gate::{LifecycleFence, LifecycleGate};
pub use lifecycle_proof::*;
mod proof;
mod target;
pub use target::*;
mod target_stop;
pub use target_stop::*;
mod protocol;
pub use gate::{ServingFence, ServingGate};
pub use proof::{
    AuthoritySigner, AuthorityTrust, LeaseAttempt, ServingBoot, VerifiedActivation, VerifiedLease,
};
pub use protocol::*;
#[cfg(test)]
mod tests;

mod maintenance;
pub use maintenance::*;

mod signing;
pub use signing::*;
mod live_trust;
pub use live_trust::*;

mod live_signer;
pub use live_signer::*;

#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;

mod signer_maintenance;
pub use signer_maintenance::*;

pub use kasumi_types::{
    ActivateTargetInput, AuthorityAction, AuthorityCommand, AuthorityOutcome, AuthorityReceipt,
    CommittedActivation, LifecycleAuthorityIdentity, LifecycleAuthorityReference,
    LocalTargetCleanupFact, RecoveryTarget, SignedAuthorityReceipt, SignedLocalTargetCleanup,
    SignedTargetStop, TargetRuntimeOutcome, TargetRuntimeRequest, TargetRuntimeResponse,
    TargetRuntimeStep, TargetStopObservation, TargetStopReference, validate_nodes,
};

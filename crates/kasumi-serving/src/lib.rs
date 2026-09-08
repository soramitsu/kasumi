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

mod target_runtime_protocol;
pub use target_runtime_protocol::*;

mod maintenance;
pub use maintenance::*;

mod signing;
pub use signing::*;
mod live_trust;
pub use live_trust::*;

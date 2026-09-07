//! Installed independent authority trust and non-renewable acquisition proofs.
//! Wire records are not live access authority. Only signature verification tied
//! to an original local attempt can construct a lease.
mod gate;
mod proof;
mod protocol;
pub use gate::{ServingFence, ServingGate};
pub use proof::{
    AuthoritySigner, AuthorityTrust, LeaseAttempt, ServingBoot, VerifiedActivation, VerifiedLease,
};
pub use protocol::*;
#[cfg(test)]
mod tests;

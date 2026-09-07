//! A separate replicated storage authority, never a municipality quorum.
mod service;
mod state;
pub use service::{AuthenticatedNode, AuthorityResponseFence, IndependentAuthority};
pub use state::AuthorityInstallation;

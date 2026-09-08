//! A separate replicated storage authority, never a municipality quorum.
mod installation;
mod service;
mod state;
pub use installation::{
    AuthorityBootstrap, AuthorityInstallation, AuthorityMaintenanceTransport, AuthorityNodeSettings,
};
pub use service::{AuthenticatedNode, AuthorityResponseFence, IndependentAuthority};

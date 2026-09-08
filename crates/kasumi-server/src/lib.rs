//! Authenticated network adapters. All data operations delegate to kasumi-engine.
pub mod administration;
pub mod api;
mod audit_cli;
pub mod audit_destination;
pub mod auth;
pub mod authority_runtime;
pub mod cluster;
pub mod lifecycle_runtime;
pub mod local_auth;
pub mod local_recovery;
pub mod mcp;
pub mod rpc;
pub mod runtime;
pub mod serving_runtime;
pub mod standalone;
pub mod standalone_cli;
pub mod standalone_key_backup;
pub mod tls;
pub mod tls_reload;

mod target_phase_runtime;
pub mod target_runtime_config;

pub mod target_runtime;

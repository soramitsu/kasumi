//! Authenticated network adapters. All data operations delegate to kasumi-engine.
pub mod administration;
pub mod api;
pub mod auth;
pub mod authority_client;
pub mod authority_runtime;
pub mod cluster;
pub mod lifecycle_runtime;
pub mod local_auth;
pub mod mcp;
pub mod rpc;
pub mod runtime;
pub mod serving_runtime;
pub mod standalone;
pub mod standalone_cli;
pub mod tls;
pub mod tls_reload;

mod target_phase_runtime;
pub mod target_runtime_config;

pub mod target_runtime;

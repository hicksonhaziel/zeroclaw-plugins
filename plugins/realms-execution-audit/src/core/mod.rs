//! Pure, deterministic healthcheck and Realms execution-audit logic.
//!
//! This module has no WIT, WASI, HTTP, filesystem, environment, clock,
//! randomness, model, or ZeroClaw host dependency.

pub mod account;
pub mod audit;
pub mod audit_error;
pub mod cursor;
pub mod decoder;
pub mod error;
pub mod evidence;
pub mod execution;
pub mod governance;
pub mod health;
pub mod limits;
pub mod output;
pub mod policy;
pub mod pubkey;
pub mod rpc;

pub use error::CapabilityError;
pub use health::{
    validate_action, validate_get_health_response, HealthResult, RpcEndpoint, ToolAction,
};

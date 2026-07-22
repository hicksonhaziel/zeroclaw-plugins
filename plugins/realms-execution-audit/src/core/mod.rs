//! Pure, deterministic capability-scaffold logic.
//!
//! This module has no WIT, WASI, HTTP, filesystem, environment, clock,
//! randomness, model, or ZeroClaw host dependency.

pub mod error;
pub mod health;
pub mod limits;

pub use error::CapabilityError;
pub use health::{
    validate_action, validate_get_health_response, HealthResult, RpcEndpoint, ToolAction,
};

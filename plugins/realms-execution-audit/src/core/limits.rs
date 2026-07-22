//! Explicit resource and output limits for the capability scaffold.

/// Largest configured RPC endpoint accepted from the trusted host section.
pub const MAX_ENDPOINT_BYTES: usize = 128;
/// Largest caller-controlled action string accepted by the production parser.
pub const MAX_ACTION_BYTES: usize = 32;
/// Largest complete execute envelope, including host-injected config.
pub const MAX_EXECUTE_ARGS_BYTES: usize = 512;
/// Largest RPC response body accepted for parsing.
pub const MAX_RESPONSE_BYTES: usize = 512;
/// Connection timeout used by the WASI HTTP adapter.
pub const HTTP_TIMEOUT_SECS: u64 = 10;
/// Hard upper bound for any rendered agent-facing error.
pub const MAX_ERROR_OUTPUT_BYTES: usize = 64;
/// Hard upper bound for a successful scaffold result.
pub const MAX_SUCCESS_OUTPUT_BYTES: usize = 64;

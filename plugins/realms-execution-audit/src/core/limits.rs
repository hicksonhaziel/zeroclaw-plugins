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

// SPL Governance v3.1.1 Phase 2 limits. These intentionally cover the pinned
// Devnet fixture, not arbitrary DAO sizes.
pub const MAX_ACCOUNT_DATA_BYTES: usize = 4_096;
pub const MAX_PROPOSAL_OPTIONS: usize = 8;
pub const MAX_TRANSACTIONS_PER_OPTION: usize = 16;
/// Largest bounded high-water index span scanned during future discovery.
pub const MAX_TRANSACTION_INDEX_SPAN: usize = 64;
pub const MAX_INSTRUCTIONS_PER_TRANSACTION: usize = 8;
pub const MAX_ACCOUNTS_PER_INSTRUCTION: usize = 32;
pub const MAX_INSTRUCTION_DATA_BYTES: usize = 1_024;
pub const MAX_TOTAL_EXECUTABLE_BYTES: usize = 8_192;
pub const MAX_DISPLAY_TEXT_FIELD_BYTES: usize = 256;
pub const MAX_DISCARDED_DISPLAY_TEXT_BYTES: usize = 1_024;
/// Hard upper bound for a successful scaffold result.
pub const MAX_SUCCESS_OUTPUT_BYTES: usize = 64;

//! Explicit resource and output limits for healthcheck and audit operations.

/// Largest configured RPC endpoint accepted from the trusted host section.
pub const MAX_ENDPOINT_BYTES: usize = 128;
/// Largest caller-controlled action string accepted by the production parser.
pub const MAX_ACTION_BYTES: usize = 32;
/// Largest complete execute envelope, including host-injected config.
pub const MAX_EXECUTE_ARGS_BYTES: usize = 512;
/// Largest healthcheck RPC response body accepted for parsing.
pub const MAX_RESPONSE_BYTES: usize = 512;
/// Connection timeout used by the WASI HTTP adapter.
pub const HTTP_TIMEOUT_SECS: u64 = 10;
/// Hard upper bound for any rendered agent-facing error.
pub const MAX_ERROR_OUTPUT_BYTES: usize = 64;

// SPL Governance v3.1.1 parsing limits. These intentionally cover the pinned
// Devnet proof, not arbitrary DAO sizes.
pub const MAX_ACCOUNT_DATA_BYTES: usize = 4_096;
pub const MAX_PROPOSAL_OPTIONS: usize = 8;
pub const MAX_TRANSACTIONS_PER_OPTION: usize = 16;
/// Largest bounded high-water index span scanned during transaction discovery.
pub const MAX_TRANSACTION_INDEX_SPAN: usize = 64;
pub const MAX_INSTRUCTIONS_PER_TRANSACTION: usize = 8;
pub const MAX_ACCOUNTS_PER_INSTRUCTION: usize = 32;
pub const MAX_INSTRUCTION_DATA_BYTES: usize = 1_024;
pub const MAX_TOTAL_EXECUTABLE_BYTES: usize = 8_192;
pub const MAX_DISPLAY_TEXT_FIELD_BYTES: usize = 256;
pub const MAX_DISCARDED_DISPLAY_TEXT_BYTES: usize = 1_024;
/// Hard upper bound for the successful four-line healthcheck result.
pub const MAX_SUCCESS_OUTPUT_BYTES: usize = 64;

// Bounded proposal-audit retrieval limits.
pub const MAX_PROPOSAL_ADDRESS_BYTES: usize = 44;
pub const MAX_RPC_REQUEST_BYTES: usize = 4_096;
pub const MAX_SINGLE_ACCOUNT_RESPONSE_BYTES: usize = 8_192;
pub const MAX_FINAL_BATCH_RESPONSE_BYTES: usize = 409_600;
pub const MAX_TOTAL_RPC_RESPONSE_BYTES: usize = 434_176;
pub const MAX_RPC_CALLS: usize = 4;
pub const MAX_AGGREGATE_DISCOVERY_POSITIONS: usize = 64;
pub const MAX_FINAL_BATCH_ADDRESSES: usize = 67;
pub const MAX_BASE64_ACCOUNT_BYTES: usize = 5_464;
pub const MAX_RPC_API_VERSION_BYTES: usize = 32;
pub const MAX_AUDIT_OUTPUT_BYTES: usize = 4_096;
pub const MAX_UNRESOLVED_SAMPLES: usize = 8;
/// Verified finding samples retained by the pure analysis result and renderer.
pub const MAX_FINDING_SAMPLES: usize = 2;
/// Samples rendered in the normal agent-facing result; the total remains in counts.
pub const MAX_RENDERED_UNRESOLVED_SAMPLES: usize = 1;
pub const MAX_LOG_ATTRS_BYTES: usize = 256;

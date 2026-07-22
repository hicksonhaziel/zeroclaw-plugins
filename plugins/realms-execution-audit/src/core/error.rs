//! Typed errors whose rendered forms are static and bounded.

use std::fmt;

use super::limits::MAX_ERROR_OUTPUT_BYTES;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapabilityError {
    InputTooLarge,
    ActionTooLarge,
    MalformedInput,
    UnsupportedAction,
    MissingRpcUrl,
    EmptyRpcUrl,
    RpcUrlTooLarge,
    RpcUrlNotHttps,
    MalformedRpcUrl,
    RequestFailed,
    ResponseReadFailed,
    HttpStatus,
    ResponseTooLarge,
    InvalidJson,
    RpcError,
    InvalidRpcEnvelope,
    UnexpectedHealth,
}

impl CapabilityError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::InputTooLarge => "input_too_large",
            Self::ActionTooLarge => "action_too_large",
            Self::MalformedInput => "malformed_input",
            Self::UnsupportedAction => "unsupported_action",
            Self::MissingRpcUrl => "missing_rpc_url",
            Self::EmptyRpcUrl => "empty_rpc_url",
            Self::RpcUrlTooLarge => "rpc_url_too_large",
            Self::RpcUrlNotHttps => "rpc_url_not_https",
            Self::MalformedRpcUrl => "malformed_rpc_url",
            Self::RequestFailed => "request_failed",
            Self::ResponseReadFailed => "response_read_failed",
            Self::HttpStatus => "http_status_error",
            Self::ResponseTooLarge => "response_too_large",
            Self::InvalidJson => "invalid_json",
            Self::RpcError => "rpc_error",
            Self::InvalidRpcEnvelope => "invalid_rpc_envelope",
            Self::UnexpectedHealth => "unexpected_rpc_health",
        }
    }

    pub fn render(self) -> String {
        let rendered = format!("error={}", self.code());
        debug_assert!(rendered.len() <= MAX_ERROR_OUTPUT_BYTES);
        rendered
    }
}

impl fmt::Display for CapabilityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for CapabilityError {}

//! Pure validation and deterministic result shaping for the Phase 1 healthcheck.

use std::fmt;

use serde::Deserialize;

use super::error::CapabilityError;
use super::limits::{
    MAX_ACTION_BYTES, MAX_ENDPOINT_BYTES, MAX_RESPONSE_BYTES, MAX_SUCCESS_OUTPUT_BYTES,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ToolAction {
    Healthcheck,
    Audit {
        schema_version: u8,
        proposal: super::pubkey::Pubkey,
    },
}

pub fn validate_action(action: &str) -> Result<ToolAction, CapabilityError> {
    if action.len() > MAX_ACTION_BYTES {
        return Err(CapabilityError::ActionTooLarge);
    }
    match action {
        "healthcheck" => Ok(ToolAction::Healthcheck),
        _ => Err(CapabilityError::UnsupportedAction),
    }
}

/// Validated endpoint value. `Debug` is always redacted and `Display` is
/// deliberately unavailable, preventing accidental URL inclusion.
///
/// ```compile_fail
/// use mandate_core::core::RpcEndpoint;
/// let endpoint = RpcEndpoint::parse("https://example.com").unwrap();
/// let _ = format!("{endpoint}");
/// ```
#[derive(Clone, Eq, PartialEq)]
pub struct RpcEndpoint(String);

impl fmt::Debug for RpcEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RpcEndpoint(<redacted>)")
    }
}

impl RpcEndpoint {
    pub fn parse(value: &str) -> Result<Self, CapabilityError> {
        if value.is_empty() {
            return Err(CapabilityError::EmptyRpcUrl);
        }
        if value.len() > MAX_ENDPOINT_BYTES {
            return Err(CapabilityError::RpcUrlTooLarge);
        }
        if !value.starts_with("https://") {
            return Err(CapabilityError::RpcUrlNotHttps);
        }
        if value
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
        {
            return Err(CapabilityError::MalformedRpcUrl);
        }

        let remainder = &value["https://".len()..];
        let authority = remainder.split(['/', '?', '#']).next().unwrap_or_default();
        if authority.is_empty()
            || authority.contains('@')
            || value.contains('#')
            || remainder.contains("://")
        {
            return Err(CapabilityError::MalformedRpcUrl);
        }
        Ok(Self(value.to_owned()))
    }

    #[cfg(target_family = "wasm")]
    /// Exposes the validated endpoint only to a component HTTP adapter.
    ///
    /// Shared-core consumers must keep this value out of logs and tool output.
    pub fn expose_to_http_adapter(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HealthResult;

impl HealthResult {
    pub const fn render(self) -> &'static str {
        const OUTPUT: &str = "status=ok\nconfig=validated\nhttps=ok\nrpc_health=ok";
        const _: () = assert!(OUTPUT.len() <= MAX_SUCCESS_OUTPUT_BYTES);
        OUTPUT
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonRpcHealth {
    jsonrpc: String,
    result: String,
    id: u64,
}

pub fn validate_get_health_response(
    status: u16,
    body: &[u8],
) -> Result<HealthResult, CapabilityError> {
    if status != 200 {
        return Err(CapabilityError::HttpStatus);
    }
    if body.len() > MAX_RESPONSE_BYTES {
        return Err(CapabilityError::ResponseTooLarge);
    }

    let value: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| CapabilityError::InvalidJson)?;
    if value.get("error").is_some_and(|error| !error.is_null()) {
        return Err(CapabilityError::RpcError);
    }
    let response: JsonRpcHealth =
        serde_json::from_value(value).map_err(|_| CapabilityError::InvalidRpcEnvelope)?;
    if response.jsonrpc != "2.0" || response.id != 1 {
        return Err(CapabilityError::InvalidRpcEnvelope);
    }
    if response.result != "ok" {
        return Err(CapabilityError::UnexpectedHealth);
    }
    Ok(HealthResult)
}

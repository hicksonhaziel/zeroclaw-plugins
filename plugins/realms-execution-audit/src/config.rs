//! Trusted host-configuration adapter.

use std::collections::HashMap;

use serde::Deserialize;

use crate::core::health::{validate_action, RpcEndpoint, ToolAction};
use crate::core::limits::MAX_EXECUTE_ARGS_BYTES;
use crate::core::CapabilityError;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecuteEnvelope {
    action: String,
    #[serde(rename = "__config", default)]
    config: HashMap<String, String>,
}

#[derive(Debug)]
pub struct ValidatedExecution {
    pub action: ToolAction,
    pub endpoint: RpcEndpoint,
}

pub fn parse_host_execution(args: &str) -> Result<ValidatedExecution, CapabilityError> {
    if args.len() > MAX_EXECUTE_ARGS_BYTES {
        return Err(CapabilityError::InputTooLarge);
    }
    let envelope: ExecuteEnvelope =
        serde_json::from_str(args).map_err(|_| CapabilityError::MalformedInput)?;
    let action = validate_action(&envelope.action)?;
    let raw_endpoint = envelope
        .config
        .get("rpc_url")
        .ok_or(CapabilityError::MissingRpcUrl)?;
    let endpoint = RpcEndpoint::parse(raw_endpoint)?;
    Ok(ValidatedExecution { action, endpoint })
}

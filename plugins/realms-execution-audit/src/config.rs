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
    #[serde(default)]
    schema_version: Option<u8>,
    #[serde(default)]
    proposal: Option<String>,
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
    let action = match validate_action(&envelope.action) {
        Ok(ToolAction::Healthcheck) => {
            if envelope.schema_version.is_some() || envelope.proposal.is_some() {
                return Err(CapabilityError::InvalidActionFields);
            }
            ToolAction::Healthcheck
        }
        Err(CapabilityError::UnsupportedAction) if envelope.action == "audit" => {
            if envelope.schema_version != Some(1) {
                return Err(CapabilityError::UnsupportedSchema);
            }
            let proposal = envelope
                .proposal
                .as_deref()
                .and_then(crate::core::pubkey::Pubkey::from_base58)
                .ok_or(CapabilityError::InvalidProposal)?;
            ToolAction::Audit {
                schema_version: 1,
                proposal,
            }
        }
        Ok(ToolAction::Audit { .. }) => return Err(CapabilityError::UnsupportedAction),
        Err(error) => return Err(error),
    };
    let raw_endpoint = envelope
        .config
        .get("rpc_url")
        .ok_or(CapabilityError::MissingRpcUrl)?;
    let endpoint = RpcEndpoint::parse(raw_endpoint)?;
    Ok(ValidatedExecution { action, endpoint })
}

//! Strict untrusted-request and trusted host-configuration boundary.

use std::collections::HashMap;

use mandate_core::core::health::RpcEndpoint;
use mandate_core::core::pubkey::Pubkey;
use mandate_core::core::vote::{VoteBuildError, VoteChoice};
use mandate_core::core::vote_service::{expected_fingerprint, VoteBuildRequest};
use serde::Deserialize;

pub const MAX_VOTE_EXECUTE_ARGS_BYTES: usize = 1_024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecuteEnvelope {
    action: String,
    schema_version: u8,
    proposal: String,
    governing_token_owner: String,
    governance_authority: String,
    payer: String,
    vote: String,
    expected_execution_fingerprint: String,
    #[serde(rename = "__config", default)]
    config: HashMap<String, String>,
}

pub struct ValidatedVoteExecution {
    pub request: VoteBuildRequest,
    pub endpoint: RpcEndpoint,
}

pub fn parse_host_execution(args: &str) -> Result<ValidatedVoteExecution, VoteBuildError> {
    if args.len() > MAX_VOTE_EXECUTE_ARGS_BYTES {
        return Err(VoteBuildError::Serialization);
    }
    let envelope: ExecuteEnvelope =
        serde_json::from_str(args).map_err(|_| VoteBuildError::Serialization)?;
    if envelope.action != "build_vote" || envelope.schema_version != 1 {
        return Err(VoteBuildError::UnsupportedVote);
    }
    let parse_key =
        |value: &str| Pubkey::from_base58(value).ok_or(VoteBuildError::WrongRelationship);
    let vote = match envelope.vote.as_str() {
        "deny" => VoteChoice::Deny,
        "approve" => VoteChoice::Approve,
        _ => return Err(VoteBuildError::UnsupportedVote),
    };
    let endpoint = envelope
        .config
        .get("rpc_url")
        .ok_or(VoteBuildError::RpcFailed)
        .and_then(|value| RpcEndpoint::parse(value).map_err(|_| VoteBuildError::RpcFailed))?;
    Ok(ValidatedVoteExecution {
        request: VoteBuildRequest {
            proposal: parse_key(&envelope.proposal)?,
            governing_token_owner: parse_key(&envelope.governing_token_owner)?,
            governance_authority: parse_key(&envelope.governance_authority)?,
            payer: parse_key(&envelope.payer)?,
            vote,
            expected_execution_fingerprint: expected_fingerprint(
                &envelope.expected_execution_fingerprint,
            )?,
        },
        endpoint,
    })
}

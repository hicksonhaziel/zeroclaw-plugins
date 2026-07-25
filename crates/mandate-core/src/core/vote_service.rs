//! Transport-independent Phase 5B vote-build orchestration.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::core::account::AccountSnapshot;
use crate::core::audit::{run_audit, AuditComplete, AuditOutcome};
use crate::core::governance::pda::{
    derive_realm_config, derive_token_owner_record, derive_vote_record,
};
use crate::core::governance::{parse_governance, parse_proposal, parse_realm};
use crate::core::pubkey::Pubkey;
use crate::core::rpc::{
    multiple_accounts_request, parse_multiple_accounts, AccountObservation, HttpResponse,
    RpcRequest, RpcTransport,
};
use crate::core::vote::{
    build_unsigned_transaction, enforce_vote_policy, parse_expected_fingerprint,
    parse_token_owner_record, render_signing_summary, validate_authority, validate_realm_config,
    validate_voting_state, CastVotePlan, SigningSummary, UnsignedTransaction, VoteBuildError,
    VoteChoice,
};

pub const MAX_VOTE_RPC_CALLS: usize = 7;
pub const MAX_VOTE_VALIDATION_ADDRESSES: usize = 72;
pub const MAX_VOTE_BATCH_RESPONSE_BYTES: usize = 430_080;
pub const MAX_BLOCK_TIME_RESPONSE_BYTES: usize = 512;
pub const MAX_BLOCKHASH_RESPONSE_BYTES: usize = 1_024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VoteBuildRequest {
    pub proposal: Pubkey,
    pub governing_token_owner: Pubkey,
    pub governance_authority: Pubkey,
    pub payer: Pubkey,
    pub vote: VoteChoice,
    pub expected_execution_fingerprint: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VoteBuildComplete {
    pub output: String,
    pub transaction: UnsignedTransaction,
    pub final_slot: u64,
    pub deadline: u64,
    pub last_valid_block_height: u64,
}

pub fn run_vote_build<T: RpcTransport>(
    transport: &mut T,
    request: VoteBuildRequest,
) -> Result<VoteBuildComplete, VoteBuildError> {
    let mut budget = VoteTransportBudget {
        inner: transport,
        calls: 0,
    };
    let audit = match run_audit(&mut budget, request.proposal) {
        AuditOutcome::Complete(audit) => audit,
        AuditOutcome::Incomplete(_) | AuditOutcome::Failed(_) => {
            return Err(VoteBuildError::AuditFailed)
        }
    };
    if audit.execution_fingerprint.0 != request.expected_execution_fingerprint {
        return Err(VoteBuildError::FingerprintMismatch);
    }
    enforce_vote_policy(
        request.vote,
        true,
        audit.analysis.status,
        audit.analysis.risk_level,
    )?;
    if audit.proposal_state != 2 {
        return Err(VoteBuildError::ProposalNotVoting);
    }

    let (voter_record_address, _) = derive_token_owner_record(
        audit.governance_program,
        audit.realm,
        audit.governing_token_mint,
        request.governing_token_owner,
    )
    .map_err(|_| VoteBuildError::WrongPda)?;
    let (vote_record_address, _) = derive_vote_record(
        audit.governance_program,
        audit.proposal,
        voter_record_address,
    )
    .map_err(|_| VoteBuildError::WrongPda)?;
    let (realm_config_address, _) = derive_realm_config(audit.governance_program, audit.realm)
        .map_err(|_| VoteBuildError::WrongPda)?;

    let mut addresses = audit
        .security_bindings
        .iter()
        .map(|binding| binding.address)
        .collect::<Vec<_>>();
    for address in [
        audit.proposal_owner_record,
        voter_record_address,
        vote_record_address,
        realm_config_address,
    ] {
        if !addresses.contains(&address) {
            addresses.push(address);
        }
    }
    if addresses.len() > MAX_VOTE_VALIDATION_ADDRESSES
        || addresses.iter().copied().collect::<BTreeSet<_>>().len() != addresses.len()
    {
        return Err(VoteBuildError::WrongRelationship);
    }

    let validation_request = multiple_accounts_request(
        5,
        &addresses,
        audit.authoritative_slot,
        MAX_VOTE_BATCH_RESPONSE_BYTES,
    )
    .map_err(|_| VoteBuildError::RpcFailed)?;
    let validation_response = budget
        .send(&validation_request)
        .map_err(|_| VoteBuildError::RpcFailed)?;
    if validation_response.body.len() > validation_request.response_limit {
        return Err(VoteBuildError::RpcFailed);
    }
    let (context, values) = parse_multiple_accounts(validation_response, 5, &addresses)
        .map_err(|_| VoteBuildError::RpcFailed)?;
    if context.slot < audit.authoritative_slot {
        return Err(VoteBuildError::RpcFailed);
    }
    let by_address = addresses
        .iter()
        .copied()
        .zip(values.iter())
        .collect::<BTreeMap<_, _>>();
    verify_security_bindings(&audit, &by_address)?;

    let proposal_observation = present(&by_address, audit.proposal)?;
    let governance_observation = present(&by_address, audit.governance)?;
    let realm_observation = present(&by_address, audit.realm)?;
    let proposal =
        parse_proposal(&snapshot(proposal_observation)).map_err(|_| VoteBuildError::Governance)?;
    let governance = parse_governance(&snapshot(governance_observation))
        .map_err(|_| VoteBuildError::Governance)?;
    let realm =
        parse_realm(&snapshot(realm_observation)).map_err(|_| VoteBuildError::Governance)?;
    if proposal.governance != governance.address
        || governance.realm != realm.address
        || proposal.governing_token_mint != audit.governing_token_mint
        || proposal.token_owner_record != audit.proposal_owner_record
    {
        return Err(VoteBuildError::WrongRelationship);
    }

    let voter_observation = present(&by_address, voter_record_address)?;
    require_governance_owner(voter_observation, audit.governance_program)?;
    let voter = parse_token_owner_record(&snapshot(voter_observation))
        .map_err(|_| VoteBuildError::Governance)?;
    if voter.address != voter_record_address
        || voter.realm != audit.realm
        || voter.governing_token_mint != audit.governing_token_mint
        || voter.governing_token_owner != request.governing_token_owner
    {
        return Err(VoteBuildError::WrongRelationship);
    }
    validate_authority(&voter, request.governance_authority)?;

    let proposal_owner_observation = present(&by_address, audit.proposal_owner_record)?;
    require_governance_owner(proposal_owner_observation, audit.governance_program)?;
    let proposal_owner = parse_token_owner_record(&snapshot(proposal_owner_observation))
        .map_err(|_| VoteBuildError::Governance)?;
    if proposal_owner.address != audit.proposal_owner_record
        || proposal_owner.realm != audit.realm
        || proposal_owner.governing_token_mint != audit.governing_token_mint
    {
        return Err(VoteBuildError::WrongRelationship);
    }

    match by_address.get(&vote_record_address) {
        Some(None) => {}
        Some(Some(_)) => return Err(VoteBuildError::ExistingVoteRecord),
        None => return Err(VoteBuildError::RpcFailed),
    }
    if let Some(Some(config)) = by_address.get(&realm_config_address) {
        require_governance_owner(config, audit.governance_program)?;
        validate_realm_config(&snapshot(config), audit.realm)?;
    }

    let block_time_request = scalar_request(
        6,
        "getBlockTime",
        serde_json::json!([context.slot]),
        MAX_BLOCK_TIME_RESPONSE_BYTES,
    )?;
    let block_time_response = budget
        .send(&block_time_request)
        .map_err(|_| VoteBuildError::RpcFailed)?;
    let chain_time = parse_scalar::<Option<i64>>(block_time_response, 6)?
        .ok_or(VoteBuildError::MissingChainTime)?;
    if chain_time < 0 {
        return Err(VoteBuildError::MissingChainTime);
    }
    let deadline = validate_voting_state(
        &proposal,
        governance.voting_base_time,
        governance.voting_cool_off_time,
        chain_time,
    )?;

    let blockhash_request = scalar_request(
        7,
        "getLatestBlockhash",
        serde_json::json!([{
            "commitment": "finalized",
            "minContextSlot": context.slot
        }]),
        MAX_BLOCKHASH_RESPONSE_BYTES,
    )?;
    let blockhash_response = budget
        .send(&blockhash_request)
        .map_err(|_| VoteBuildError::RpcFailed)?;
    let blockhash = parse_blockhash(blockhash_response, 7)?;
    if blockhash.context.slot < context.slot {
        return Err(VoteBuildError::RpcFailed);
    }
    if budget.calls != MAX_VOTE_RPC_CALLS {
        return Err(VoteBuildError::RpcFailed);
    }
    let recent_blockhash =
        decode_hash(&blockhash.value.blockhash).ok_or(VoteBuildError::InvalidBlockhash)?;

    let plan = CastVotePlan {
        governance_program: audit.governance_program,
        realm: audit.realm,
        governance: audit.governance,
        proposal: audit.proposal,
        proposal_owner_record: audit.proposal_owner_record,
        voter_token_owner_record: voter_record_address,
        governance_authority: request.governance_authority,
        vote_record: vote_record_address,
        governing_token_mint: audit.governing_token_mint,
        payer: request.payer,
        realm_config: realm_config_address,
        vote: request.vote,
    };
    let transaction = build_unsigned_transaction(plan, recent_blockhash)?;
    let summary = SigningSummary {
        schema_version: 1,
        action: "build_vote",
        status: "ready_for_external_signing",
        custody_tier: "t1_unsigned",
        vote: "deny",
        proposal: audit.proposal.to_base58(),
        governance: audit.governance.to_base58(),
        realm: audit.realm.to_base58(),
        governing_token_owner: request.governing_token_owner.to_base58(),
        governance_authority: request.governance_authority.to_base58(),
        payer: request.payer.to_base58(),
        execution_fingerprint: crate::core::vote::hex_sha256(&audit.execution_fingerprint.0),
        analysis_status: analysis_status(audit.analysis.status),
        risk_level: audit.analysis.risk_level.map(risk_level),
        recent_blockhash: blockhash.value.blockhash,
        last_valid_block_height: blockhash.value.last_valid_block_height,
        required_external_signers: transaction
            .required_signers
            .iter()
            .copied()
            .map(Pubkey::to_base58)
            .collect(),
        unsigned_transaction_base64: transaction.transaction_base64.clone(),
        transaction_fingerprint: crate::core::vote::hex_sha256(&transaction.transaction_sha256),
        message_fingerprint: crate::core::vote::hex_sha256(&transaction.message_sha256),
        unsigned: true,
        submitted: false,
        summary: "Deny vote verified and built unsigned; Mandate did not sign or submit.",
    };
    let output = render_signing_summary(&summary)?;
    Ok(VoteBuildComplete {
        output,
        transaction,
        final_slot: context.slot,
        deadline,
        last_valid_block_height: blockhash.value.last_valid_block_height,
    })
}

struct VoteTransportBudget<'a, T> {
    inner: &'a mut T,
    calls: usize,
}

impl<T: RpcTransport> RpcTransport for VoteTransportBudget<'_, T> {
    fn send(
        &mut self,
        request: &RpcRequest,
    ) -> Result<HttpResponse, crate::core::audit_error::AuditError> {
        if self.calls >= MAX_VOTE_RPC_CALLS {
            return Err(crate::core::audit_error::AuditError::Transport);
        }
        let response = self.inner.send(request)?;
        self.calls += 1;
        if response.body.len() > request.response_limit {
            return Err(crate::core::audit_error::AuditError::ResponseTooLarge);
        }
        Ok(response)
    }
}

fn verify_security_bindings(
    audit: &AuditComplete,
    values: &BTreeMap<Pubkey, &Option<AccountObservation>>,
) -> Result<(), VoteBuildError> {
    for binding in &audit.security_bindings {
        let value = values
            .get(&binding.address)
            .ok_or(VoteBuildError::RpcFailed)?;
        match (
            binding.owner,
            binding.executable,
            binding.data_sha256,
            value,
        ) {
            (None, None, None, None) => {}
            (Some(owner), Some(executable), Some(hash), Some(account))
                if account.owner == owner
                    && account.executable == executable
                    && <[u8; 32]>::from(Sha256::digest(&account.data)) == hash => {}
            _ => return Err(VoteBuildError::FingerprintMismatch),
        }
    }
    Ok(())
}

fn present<'a>(
    values: &'a BTreeMap<Pubkey, &Option<AccountObservation>>,
    address: Pubkey,
) -> Result<&'a AccountObservation, VoteBuildError> {
    values
        .get(&address)
        .and_then(|value| value.as_ref())
        .ok_or(VoteBuildError::WrongRelationship)
}

fn require_governance_owner(
    account: &AccountObservation,
    program: Pubkey,
) -> Result<(), VoteBuildError> {
    if account.owner == program && !account.executable {
        Ok(())
    } else {
        Err(VoteBuildError::Governance)
    }
}

fn snapshot(account: &AccountObservation) -> AccountSnapshot<'_> {
    AccountSnapshot {
        address: account.address,
        owner: account.owner,
        data: &account.data,
    }
}

#[derive(Serialize)]
struct RequestEnvelope {
    jsonrpc: &'static str,
    id: u64,
    method: &'static str,
    params: serde_json::Value,
}

fn scalar_request(
    id: u64,
    method: &'static str,
    params: serde_json::Value,
    response_limit: usize,
) -> Result<RpcRequest, VoteBuildError> {
    let body = serde_json::to_vec(&RequestEnvelope {
        jsonrpc: "2.0",
        id,
        method,
        params,
    })
    .map_err(|_| VoteBuildError::RpcFailed)?;
    if body.len() > crate::core::limits::MAX_RPC_REQUEST_BYTES {
        return Err(VoteBuildError::RpcFailed);
    }
    Ok(RpcRequest {
        id,
        body,
        response_limit,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope<T> {
    jsonrpc: String,
    id: u64,
    result: Option<T>,
    error: Option<RpcError>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RpcError {
    code: i64,
    message: String,
}

fn parse_scalar<T: for<'de> Deserialize<'de>>(
    response: HttpResponse,
    id: u64,
) -> Result<T, VoteBuildError> {
    if response.status != 200 || response.body.len() > MAX_BLOCKHASH_RESPONSE_BYTES {
        return Err(VoteBuildError::RpcFailed);
    }
    let envelope: Envelope<T> =
        serde_json::from_slice(&response.body).map_err(|_| VoteBuildError::RpcFailed)?;
    if envelope.jsonrpc != "2.0" || envelope.id != id {
        return Err(VoteBuildError::RpcFailed);
    }
    match (envelope.result, envelope.error) {
        (Some(result), None) => Ok(result),
        (None, Some(error)) => {
            let _ = (error.code, error.message.len());
            Err(VoteBuildError::RpcFailed)
        }
        _ => Err(VoteBuildError::RpcFailed),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BlockhashResult {
    context: BlockhashContext,
    value: BlockhashValue,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BlockhashContext {
    slot: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BlockhashValue {
    blockhash: String,
    #[serde(rename = "lastValidBlockHeight")]
    last_valid_block_height: u64,
}

fn parse_blockhash(response: HttpResponse, id: u64) -> Result<BlockhashResult, VoteBuildError> {
    parse_scalar(response, id)
}

fn decode_hash(value: &str) -> Option<[u8; 32]> {
    if value.is_empty() || value.len() > 44 {
        return None;
    }
    let mut bytes = [0u8; 32];
    let size = bs58::decode(value).onto(&mut bytes).ok()?;
    (size == 32 && bs58::encode(bytes).into_string() == value).then_some(bytes)
}

fn analysis_status(value: crate::core::policy::AnalysisStatus) -> &'static str {
    match value {
        crate::core::policy::AnalysisStatus::Complete => "complete",
        crate::core::policy::AnalysisStatus::Unresolved => "unresolved",
    }
}

fn risk_level(value: crate::core::policy::RiskLevel) -> &'static str {
    match value {
        crate::core::policy::RiskLevel::Low => "low",
        crate::core::policy::RiskLevel::Medium => "medium",
        crate::core::policy::RiskLevel::High => "high",
        crate::core::policy::RiskLevel::Critical => "critical",
    }
}

pub fn expected_fingerprint(value: &str) -> Result<[u8; 32], VoteBuildError> {
    parse_expected_fingerprint(value)
}

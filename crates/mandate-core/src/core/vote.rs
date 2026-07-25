//! Pure SPL Governance v3.1.1 vote validation and unsigned transaction building.
//!
//! Canonical oracle: `solana-program-library` governance-v3.1.1 commit
//! `a15fee9d3782c83dfb1f75cb3959d973e0b80d6d`, notably
//! `instruction.rs::cast_vote`, `processor/process_cast_vote.rs`,
//! `state/{token_owner_record,vote_record,proposal,realm_config}.rs`.

use std::collections::BTreeMap;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::core::account::{validate_snapshot, AccountSnapshot};
use crate::core::cursor::Cursor;
use crate::core::governance::{GovernanceError, ProposalAccount};
use crate::core::policy::{AnalysisStatus, RiskLevel};
use crate::core::pubkey::{Pubkey, SYSTEM_PROGRAM};

const TOKEN_OWNER_RECORD_V2: u8 = 17;
const VOTE_RECORD_V2: u8 = 12;
const REALM_CONFIG: u8 = 11;
const TOKEN_OWNER_RECORD_LAYOUT_VERSION: u8 = 1;
const PROPOSAL_STATE_VOTING: u8 = 2;
const CAST_VOTE_DISCRIMINANT: u8 = 13;
const VOTE_DENY_DISCRIMINANT: u8 = 1;
const MAX_UNSIGNED_TRANSACTION_BYTES: usize = 1_232;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VoteChoice {
    Deny,
    Approve,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VoteBuildError {
    AuditFailed,
    RpcFailed,
    Governance,
    WrongPda,
    WrongRelationship,
    InvalidAuthority,
    ExistingVoteRecord,
    ProposalNotVoting,
    VotingExpired,
    MissingChainTime,
    FingerprintMismatch,
    MalformedFingerprint,
    PolicyBlocked,
    UnsupportedVote,
    UnsupportedRealmConfig,
    InvalidBlockhash,
    TransactionTooLarge,
    Serialization,
}

impl VoteBuildError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::AuditFailed => "fresh_audit_failed",
            Self::RpcFailed => "rpc_validation_failed",
            Self::Governance => "governance_validation_failed",
            Self::WrongPda => "pda_mismatch",
            Self::WrongRelationship => "relationship_mismatch",
            Self::InvalidAuthority => "invalid_governance_authority",
            Self::ExistingVoteRecord => "vote_record_exists",
            Self::ProposalNotVoting => "proposal_not_voting",
            Self::VotingExpired => "voting_expired",
            Self::MissingChainTime => "chain_time_unavailable",
            Self::FingerprintMismatch => "execution_fingerprint_mismatch",
            Self::MalformedFingerprint => "malformed_execution_fingerprint",
            Self::PolicyBlocked => "vote_blocked_by_policy",
            Self::UnsupportedVote => "unsupported_vote",
            Self::UnsupportedRealmConfig => "unsupported_realm_config",
            Self::InvalidBlockhash => "invalid_blockhash",
            Self::TransactionTooLarge => "transaction_too_large",
            Self::Serialization => "transaction_serialization_failed",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenOwnerRecord {
    pub address: Pubkey,
    pub realm: Pubkey,
    pub governing_token_mint: Pubkey,
    pub governing_token_owner: Pubkey,
    pub governance_delegate: Option<Pubkey>,
}

pub fn parse_token_owner_record(
    snapshot: &AccountSnapshot<'_>,
) -> Result<TokenOwnerRecord, GovernanceError> {
    validate_snapshot(snapshot, TOKEN_OWNER_RECORD_V2)?;
    let mut cursor = Cursor::new(snapshot.data);
    let _account_type = cursor.read_u8()?;
    let realm = cursor.read_pubkey()?;
    let governing_token_mint = cursor.read_pubkey()?;
    let governing_token_owner = cursor.read_pubkey()?;
    let _deposit_amount = cursor.read_u64()?;
    let _unrelinquished_votes = cursor.read_u64()?;
    let _outstanding_proposals = cursor.read_u8()?;
    if cursor.read_u8()? != TOKEN_OWNER_RECORD_LAYOUT_VERSION {
        return Err(GovernanceError::UnsupportedAccountVersion);
    }
    require_zero(cursor.read_exact(6)?)?;
    let governance_delegate = cursor.read_option(Cursor::read_pubkey)?;
    require_zero(cursor.read_exact(128)?)?;
    if governance_delegate.is_none() {
        // `AccountMaxSize` allocates room for `Some(Pubkey)` even when the
        // Borsh option is None; v3.1.1 loads this account unchecked.
        require_zero(cursor.read_exact(32)?)?;
    }
    cursor.finish()?;
    Ok(TokenOwnerRecord {
        address: snapshot.address,
        realm,
        governing_token_mint,
        governing_token_owner,
        governance_delegate,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VoteRecord {
    pub address: Pubkey,
    pub proposal: Pubkey,
    pub governing_token_owner: Pubkey,
    pub is_relinquished: bool,
}

pub fn parse_vote_record(snapshot: &AccountSnapshot<'_>) -> Result<VoteRecord, GovernanceError> {
    validate_snapshot(snapshot, VOTE_RECORD_V2)?;
    let mut cursor = Cursor::new(snapshot.data);
    let _account_type = cursor.read_u8()?;
    let proposal = cursor.read_pubkey()?;
    let governing_token_owner = cursor.read_pubkey()?;
    let is_relinquished = cursor.read_bool()?;
    let _voter_weight = cursor.read_u64()?;
    match cursor.read_u8()? {
        0 => {
            let count = cursor.read_count(crate::core::limits::MAX_PROPOSAL_OPTIONS)?;
            for _ in 0..count {
                let _rank = cursor.read_u8()?;
                let weight = cursor.read_u8()?;
                if weight > 100 {
                    return Err(GovernanceError::InvalidEncoding);
                }
            }
        }
        1..=3 => {}
        _ => return Err(GovernanceError::InvalidEncoding),
    }
    require_zero(cursor.read_exact(8)?)?;
    cursor.finish()?;
    Ok(VoteRecord {
        address: snapshot.address,
        proposal,
        governing_token_owner,
        is_relinquished,
    })
}

/// Validates a present v3.1.1 RealmConfig and rejects voter-weight add-ins.
pub fn validate_realm_config(
    snapshot: &AccountSnapshot<'_>,
    expected_realm: Pubkey,
) -> Result<(), VoteBuildError> {
    validate_snapshot(snapshot, REALM_CONFIG).map_err(|_| VoteBuildError::Governance)?;
    let mut cursor = Cursor::new(snapshot.data);
    let _kind = cursor.read_u8().map_err(|_| VoteBuildError::Governance)?;
    if cursor
        .read_pubkey()
        .map_err(|_| VoteBuildError::Governance)?
        != expected_realm
    {
        return Err(VoteBuildError::WrongRelationship);
    }
    for _ in 0..2 {
        if cursor
            .read_option(Cursor::read_pubkey)
            .map_err(|_| VoteBuildError::Governance)?
            .is_some()
            || cursor
                .read_option(Cursor::read_pubkey)
                .map_err(|_| VoteBuildError::Governance)?
                .is_some()
        {
            return Err(VoteBuildError::UnsupportedRealmConfig);
        }
        if cursor.read_u8().map_err(|_| VoteBuildError::Governance)? > 2 {
            return Err(VoteBuildError::Governance);
        }
        require_zero(
            cursor
                .read_exact(8)
                .map_err(|_| VoteBuildError::Governance)?,
        )
        .map_err(|_| VoteBuildError::Governance)?;
    }
    require_zero(
        cursor
            .read_exact(110)
            .map_err(|_| VoteBuildError::Governance)?,
    )
    .map_err(|_| VoteBuildError::Governance)?;
    cursor.finish().map_err(|_| VoteBuildError::Governance)
}

pub fn validate_authority(
    record: &TokenOwnerRecord,
    authority: Pubkey,
) -> Result<(), VoteBuildError> {
    if authority == record.governing_token_owner
        || record
            .governance_delegate
            .is_some_and(|delegate| delegate == authority)
    {
        Ok(())
    } else {
        Err(VoteBuildError::InvalidAuthority)
    }
}

pub fn validate_voting_state(
    proposal: &ProposalAccount,
    voting_base_time: u32,
    voting_cool_off_time: u32,
    chain_unix_timestamp: i64,
) -> Result<u64, VoteBuildError> {
    if proposal.state != PROPOSAL_STATE_VOTING {
        return Err(VoteBuildError::ProposalNotVoting);
    }
    let voting_at = proposal
        .voting_at
        .ok_or(VoteBuildError::ProposalNotVoting)?;
    let deadline = voting_at
        .checked_add(i64::from(voting_base_time))
        .and_then(|value| value.checked_add(i64::from(voting_cool_off_time)))
        .ok_or(VoteBuildError::VotingExpired)?;
    if deadline < chain_unix_timestamp {
        return Err(VoteBuildError::VotingExpired);
    }
    u64::try_from(deadline).map_err(|_| VoteBuildError::VotingExpired)
}

pub fn parse_expected_fingerprint(value: &str) -> Result<[u8; 32], VoteBuildError> {
    let hex = value
        .strip_prefix("sha256:")
        .ok_or(VoteBuildError::MalformedFingerprint)?;
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(VoteBuildError::MalformedFingerprint);
    }
    let mut bytes = [0u8; 32];
    for (index, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        let part = core::str::from_utf8(chunk).map_err(|_| VoteBuildError::MalformedFingerprint)?;
        bytes[index] =
            u8::from_str_radix(part, 16).map_err(|_| VoteBuildError::MalformedFingerprint)?;
    }
    Ok(bytes)
}

pub fn enforce_vote_policy(
    vote: VoteChoice,
    retrieval_complete: bool,
    analysis_status: AnalysisStatus,
    risk_level: Option<RiskLevel>,
) -> Result<(), VoteBuildError> {
    match vote {
        VoteChoice::Deny if retrieval_complete => Ok(()),
        VoteChoice::Deny => Err(VoteBuildError::PolicyBlocked),
        VoteChoice::Approve
            if !retrieval_complete
                || analysis_status == AnalysisStatus::Unresolved
                || risk_level == Some(RiskLevel::Critical) =>
        {
            Err(VoteBuildError::PolicyBlocked)
        }
        VoteChoice::Approve => Err(VoteBuildError::UnsupportedVote),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CastVotePlan {
    pub governance_program: Pubkey,
    pub realm: Pubkey,
    pub governance: Pubkey,
    pub proposal: Pubkey,
    pub proposal_owner_record: Pubkey,
    pub voter_token_owner_record: Pubkey,
    pub governance_authority: Pubkey,
    pub vote_record: Pubkey,
    pub governing_token_mint: Pubkey,
    pub payer: Pubkey,
    pub realm_config: Pubkey,
    pub vote: VoteChoice,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlanAccountMeta {
    pub pubkey: Pubkey,
    pub signer: bool,
    pub writable: bool,
}

impl CastVotePlan {
    pub fn instruction_data(self) -> Result<[u8; 2], VoteBuildError> {
        match self.vote {
            VoteChoice::Deny => Ok([CAST_VOTE_DISCRIMINANT, VOTE_DENY_DISCRIMINANT]),
            VoteChoice::Approve => Err(VoteBuildError::UnsupportedVote),
        }
    }

    pub fn account_metas(self) -> [PlanAccountMeta; 11] {
        [
            meta(self.realm, false, false),
            meta(self.governance, false, true),
            meta(self.proposal, false, true),
            meta(self.proposal_owner_record, false, true),
            meta(self.voter_token_owner_record, false, true),
            meta(self.governance_authority, true, false),
            meta(self.vote_record, false, true),
            meta(self.governing_token_mint, false, false),
            meta(self.payer, true, true),
            meta(SYSTEM_PROGRAM, false, false),
            meta(self.realm_config, false, false),
        ]
    }
}

const fn meta(pubkey: Pubkey, signer: bool, writable: bool) -> PlanAccountMeta {
    PlanAccountMeta {
        pubkey,
        signer,
        writable,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnsignedTransaction {
    pub bytes: Vec<u8>,
    pub message_bytes: Vec<u8>,
    pub transaction_base64: String,
    pub transaction_sha256: [u8; 32],
    pub message_sha256: [u8; 32],
    pub required_signers: Vec<Pubkey>,
}

#[derive(Clone, Copy, Default)]
struct KeyFlags {
    signer: bool,
    writable: bool,
    invoked: bool,
}

pub fn build_unsigned_transaction(
    plan: CastVotePlan,
    recent_blockhash: [u8; 32],
) -> Result<UnsignedTransaction, VoteBuildError> {
    let metas = plan.account_metas();
    let data = plan.instruction_data()?;
    let mut keys = BTreeMap::<Pubkey, KeyFlags>::new();
    keys.entry(plan.governance_program).or_default().invoked = true;
    for item in metas {
        let flags = keys.entry(item.pubkey).or_default();
        flags.signer |= item.signer;
        flags.writable |= item.writable;
    }
    keys.entry(plan.payer).or_default().signer = true;
    keys.entry(plan.payer).or_default().writable = true;
    keys.remove(&plan.payer);

    let mut account_keys = vec![plan.payer];
    for (signer, writable) in [(true, true), (true, false), (false, true), (false, false)] {
        account_keys.extend(keys.iter().filter_map(|(key, flags)| {
            (flags.signer == signer && flags.writable == writable).then_some(*key)
        }));
    }
    let required = account_keys
        .iter()
        .filter(|key| *key == &plan.payer || keys.get(key).is_some_and(|flags| flags.signer))
        .count();
    let readonly_signed = account_keys
        .iter()
        .filter(|key| {
            keys.get(key)
                .is_some_and(|flags| flags.signer && !flags.writable)
        })
        .count();
    let readonly_unsigned = account_keys
        .iter()
        .filter(|key| {
            keys.get(key)
                .is_some_and(|flags| !flags.signer && !flags.writable)
        })
        .count();
    let to_u8 = |value: usize| u8::try_from(value).map_err(|_| VoteBuildError::Serialization);
    let mut message = vec![
        to_u8(required)?,
        to_u8(readonly_signed)?,
        to_u8(readonly_unsigned)?,
    ];
    push_shortvec(&mut message, account_keys.len())?;
    for key in &account_keys {
        message.extend_from_slice(key.as_bytes());
    }
    message.extend_from_slice(&recent_blockhash);
    push_shortvec(&mut message, 1)?;
    message.push(index_of(&account_keys, plan.governance_program)?);
    push_shortvec(&mut message, metas.len())?;
    for item in metas {
        message.push(index_of(&account_keys, item.pubkey)?);
    }
    push_shortvec(&mut message, data.len())?;
    message.extend_from_slice(&data);

    let mut transaction = Vec::new();
    push_shortvec(&mut transaction, required)?;
    transaction.resize(
        transaction
            .len()
            .checked_add(
                required
                    .checked_mul(64)
                    .ok_or(VoteBuildError::TransactionTooLarge)?,
            )
            .ok_or(VoteBuildError::TransactionTooLarge)?,
        0,
    );
    transaction.extend_from_slice(&message);
    if transaction.len() > MAX_UNSIGNED_TRANSACTION_BYTES {
        return Err(VoteBuildError::TransactionTooLarge);
    }
    let required_signers = account_keys[..required].to_vec();
    Ok(UnsignedTransaction {
        transaction_base64: STANDARD.encode(&transaction),
        transaction_sha256: Sha256::digest(&transaction).into(),
        message_sha256: Sha256::digest(&message).into(),
        bytes: transaction,
        message_bytes: message,
        required_signers,
    })
}

fn index_of(keys: &[Pubkey], needle: Pubkey) -> Result<u8, VoteBuildError> {
    keys.iter()
        .position(|key| *key == needle)
        .and_then(|index| u8::try_from(index).ok())
        .ok_or(VoteBuildError::Serialization)
}

fn push_shortvec(output: &mut Vec<u8>, mut value: usize) -> Result<(), VoteBuildError> {
    loop {
        let mut byte = u8::try_from(value & 0x7f).map_err(|_| VoteBuildError::Serialization)?;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        output.push(byte);
        if value == 0 {
            return Ok(());
        }
    }
}

#[derive(Serialize)]
pub struct SigningSummary {
    pub schema_version: u8,
    pub action: &'static str,
    pub status: &'static str,
    pub custody_tier: &'static str,
    pub vote: &'static str,
    pub proposal: String,
    pub governance: String,
    pub realm: String,
    pub governing_token_owner: String,
    pub governance_authority: String,
    pub payer: String,
    pub execution_fingerprint: String,
    pub analysis_status: &'static str,
    pub risk_level: Option<&'static str>,
    pub recent_blockhash: String,
    pub last_valid_block_height: u64,
    pub required_external_signers: Vec<String>,
    pub unsigned_transaction_base64: String,
    pub transaction_fingerprint: String,
    pub message_fingerprint: String,
    pub unsigned: bool,
    pub submitted: bool,
    pub summary: &'static str,
}

pub fn render_signing_summary(summary: &SigningSummary) -> Result<String, VoteBuildError> {
    let output = serde_json::to_string(summary).map_err(|_| VoteBuildError::Serialization)?;
    if output.len() > 4_096 {
        Err(VoteBuildError::TransactionTooLarge)
    } else {
        Ok(output)
    }
}

pub fn hex_sha256(bytes: &[u8; 32]) -> String {
    let mut output = String::with_capacity(71);
    output.push_str("sha256:");
    for byte in bytes {
        use core::fmt::Write;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn require_zero(bytes: &[u8]) -> Result<(), GovernanceError> {
    if bytes.iter().all(|byte| *byte == 0) {
        Ok(())
    } else {
        Err(GovernanceError::InvalidEncoding)
    }
}

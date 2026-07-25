use core::fmt;

use super::governance::GovernanceError;
use super::limits::MAX_ACCOUNT_DATA_BYTES;
use super::pubkey::{is_supported_governance_program, Pubkey};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccountKind {
    RealmConfig,
    VoteRecordV2,
    ProposalTransactionV2,
    ProposalV2,
    RealmV2,
    TokenOwnerRecordV2,
    MintGovernanceV2,
}

pub struct AccountSnapshot<'a> {
    pub address: Pubkey,
    pub owner: Pubkey,
    pub data: &'a [u8],
}

impl fmt::Debug for AccountSnapshot<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AccountSnapshot")
            .field("address", &self.address)
            .field("owner", &self.owner)
            .field("data", &"<redacted>")
            .finish()
    }
}

pub(crate) fn validate_snapshot(
    snapshot: &AccountSnapshot<'_>,
    expected_type: u8,
) -> Result<(), GovernanceError> {
    let kind = identify_account(snapshot)?;
    if discriminator(kind) != expected_type {
        return Err(GovernanceError::UnsupportedAccountType);
    }
    Ok(())
}

pub fn identify_account(snapshot: &AccountSnapshot<'_>) -> Result<AccountKind, GovernanceError> {
    if snapshot.data.len() > MAX_ACCOUNT_DATA_BYTES {
        return Err(GovernanceError::AccountDataTooLarge);
    }
    if !is_supported_governance_program(snapshot.owner) {
        return Err(GovernanceError::WrongProgramOwner);
    }
    let account_type = snapshot
        .data
        .first()
        .copied()
        .ok_or(GovernanceError::TruncatedAccount)?;
    match account_type {
        11 => Ok(AccountKind::RealmConfig),
        12 => Ok(AccountKind::VoteRecordV2),
        13 => Ok(AccountKind::ProposalTransactionV2),
        14 => Ok(AccountKind::ProposalV2),
        16 => Ok(AccountKind::RealmV2),
        17 => Ok(AccountKind::TokenOwnerRecordV2),
        20 => Ok(AccountKind::MintGovernanceV2),
        1..=10 => Err(GovernanceError::UnsupportedAccountVersion),
        _ => Err(GovernanceError::UnsupportedAccountType),
    }
}

const fn discriminator(kind: AccountKind) -> u8 {
    match kind {
        AccountKind::RealmConfig => 11,
        AccountKind::VoteRecordV2 => 12,
        AccountKind::ProposalTransactionV2 => 13,
        AccountKind::ProposalV2 => 14,
        AccountKind::RealmV2 => 16,
        AccountKind::TokenOwnerRecordV2 => 17,
        AccountKind::MintGovernanceV2 => 20,
    }
}

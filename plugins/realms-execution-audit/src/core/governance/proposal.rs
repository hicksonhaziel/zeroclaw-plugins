use crate::core::account::{validate_snapshot, AccountSnapshot};
use crate::core::cursor::Cursor;
use crate::core::limits::{
    MAX_DISCARDED_DISPLAY_TEXT_BYTES, MAX_DISPLAY_TEXT_FIELD_BYTES, MAX_PROPOSAL_OPTIONS,
    MAX_TRANSACTIONS_PER_OPTION, MAX_TRANSACTION_INDEX_SPAN,
};
use crate::core::pubkey::Pubkey;

use super::governance_account::{read_small_enum, read_threshold};
use super::realm::require_zero;
use super::GovernanceError;

const PROPOSAL_V2: u8 = 14;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProposalOption {
    pub transactions_executed_count: u16,
    pub transactions_count: u16,
    pub transactions_next_index: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProposalAccount {
    pub address: Pubkey,
    pub governance: Pubkey,
    pub governing_token_mint: Pubkey,
    pub state: u8,
    pub options: Vec<ProposalOption>,
    pub execution_flags: u8,
}

pub fn parse_proposal(snapshot: &AccountSnapshot<'_>) -> Result<ProposalAccount, GovernanceError> {
    validate_snapshot(snapshot, PROPOSAL_V2)?;
    let mut cursor = Cursor::new(snapshot.data);
    let _account_type = cursor.read_u8()?;
    let governance = cursor.read_pubkey()?;
    let governing_token_mint = cursor.read_pubkey()?;
    let state = read_small_enum(&mut cursor, 9)?;
    let _token_owner_record = cursor.read_pubkey()?;
    let _signatory_count = cursor.read_u8()?;
    let _signed_count = cursor.read_u8()?;
    read_vote_type(&mut cursor)?;
    let option_count = cursor.read_count(MAX_PROPOSAL_OPTIONS)?;
    let mut options = Vec::with_capacity(option_count);
    let mut display_bytes = 0usize;
    for _ in 0..option_count {
        discard_display(&mut cursor, &mut display_bytes)?;
        let _vote_weight = cursor.read_u64()?;
        read_small_enum(&mut cursor, 2)?;
        let transactions_executed_count = cursor.read_u16()?;
        let transactions_count = cursor.read_u16()?;
        let transactions_next_index = cursor.read_u16()?;
        if usize::from(transactions_count) > MAX_TRANSACTIONS_PER_OPTION
            || usize::from(transactions_next_index) > MAX_TRANSACTION_INDEX_SPAN
            || transactions_executed_count > transactions_count
            || transactions_count > transactions_next_index
        {
            return Err(GovernanceError::DeclaredTransactionCountMismatch);
        }
        options.push(ProposalOption {
            transactions_executed_count,
            transactions_count,
            transactions_next_index,
        });
    }
    let _deny_weight = cursor.read_option_u64()?;
    let _reserved1 = cursor.read_u8()?;
    let _abstain_weight = cursor.read_option_u64()?;
    let _start_at = cursor.read_option_i64()?;
    let _draft_at = cursor.read_i64()?;
    let _signing_at = cursor.read_option_i64()?;
    let _voting_at = cursor.read_option_i64()?;
    let _voting_slot = cursor.read_option_u64()?;
    let _voting_completed = cursor.read_option_i64()?;
    let _executing_at = cursor.read_option_i64()?;
    let _closed_at = cursor.read_option_i64()?;
    let execution_flags = read_small_enum(&mut cursor, 2)?;
    let _max_vote_weight = cursor.read_option_u64()?;
    let _max_voting_time = cursor.read_option_u32()?;
    match cursor.read_u8()? {
        0 => {}
        1 => read_threshold(&mut cursor)?,
        _ => return Err(GovernanceError::InvalidEncoding),
    }
    require_zero(cursor.read_exact(64)?)?;
    discard_display(&mut cursor, &mut display_bytes)?;
    discard_display(&mut cursor, &mut display_bytes)?;
    let _veto_weight = cursor.read_u64()?;
    // AccountMaxSize reserves 32 zero bytes beyond the v3.1.1 Borsh payload.
    require_zero(cursor.read_exact(32)?)?;
    cursor.finish()?;
    Ok(ProposalAccount {
        address: snapshot.address,
        governance,
        governing_token_mint,
        state,
        options,
        execution_flags,
    })
}

fn read_vote_type(cursor: &mut Cursor<'_>) -> Result<(), GovernanceError> {
    match cursor.read_u8()? {
        0 => Ok(()),
        1 => {
            read_small_enum(cursor, 1)?;
            let _minimum = cursor.read_u8()?;
            let _maximum = cursor.read_u8()?;
            let _winning = cursor.read_u8()?;
            Ok(())
        }
        _ => Err(GovernanceError::InvalidEncoding),
    }
}

fn discard_display(cursor: &mut Cursor<'_>, total: &mut usize) -> Result<(), GovernanceError> {
    let length = cursor.read_count(MAX_DISPLAY_TEXT_FIELD_BYTES)?;
    *total = total
        .checked_add(length)
        .ok_or(GovernanceError::DisplayTextTooLarge)?;
    if *total > MAX_DISCARDED_DISPLAY_TEXT_BYTES {
        return Err(GovernanceError::DisplayTextTooLarge);
    }
    let _discarded = cursor.read_exact(length)?;
    Ok(())
}

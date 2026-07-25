use crate::core::account::{validate_snapshot, AccountSnapshot};
use crate::core::cursor::Cursor;
use crate::core::limits::{
    MAX_ACCOUNTS_PER_INSTRUCTION, MAX_INSTRUCTIONS_PER_TRANSACTION, MAX_INSTRUCTION_DATA_BYTES,
    MAX_TOTAL_EXECUTABLE_BYTES,
};
use crate::core::pubkey::Pubkey;

use super::governance_account::read_small_enum;
use super::realm::require_zero;
use super::GovernanceError;

const PROPOSAL_TRANSACTION_V2: u8 = 13;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountMeta {
    pub pubkey: Pubkey,
    pub is_signer: bool,
    pub is_writable: bool,
}

#[derive(Clone, PartialEq, Eq)]
pub struct Instruction {
    pub program_id: Pubkey,
    pub accounts: Vec<AccountMeta>,
    pub data: Vec<u8>,
}

impl fmt::Debug for Instruction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Instruction")
            .field("program_id", &self.program_id)
            .field("accounts", &self.accounts)
            .field("data", &"<redacted>")
            .field("data_len", &self.data.len())
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProposalTransactionAccount {
    pub address: Pubkey,
    pub proposal: Pubkey,
    pub option_index: u8,
    pub transaction_index: u16,
    pub hold_up_time: u32,
    pub instructions: Vec<Instruction>,
    pub executed_at: Option<i64>,
    pub execution_status: u8,
}

pub fn parse_proposal_transaction(
    snapshot: &AccountSnapshot<'_>,
) -> Result<ProposalTransactionAccount, GovernanceError> {
    validate_snapshot(snapshot, PROPOSAL_TRANSACTION_V2)?;
    let mut cursor = Cursor::new(snapshot.data);
    let _account_type = cursor.read_u8()?;
    let proposal = cursor.read_pubkey()?;
    let option_index = cursor.read_u8()?;
    let transaction_index = cursor.read_u16()?;
    let hold_up_time = cursor.read_u32()?;
    let instruction_count = cursor.read_count(MAX_INSTRUCTIONS_PER_TRANSACTION)?;
    let mut total_executable_bytes = 0usize;
    let mut instructions = Vec::with_capacity(instruction_count);
    for _ in 0..instruction_count {
        let program_id = cursor.read_pubkey()?;
        total_executable_bytes = add_total(total_executable_bytes, 32)?;
        let account_count = cursor.read_count(MAX_ACCOUNTS_PER_INSTRUCTION)?;
        let mut accounts = Vec::with_capacity(account_count);
        for _ in 0..account_count {
            let pubkey = cursor.read_pubkey()?;
            let is_signer = cursor.read_bool()?;
            let is_writable = cursor.read_bool()?;
            total_executable_bytes = add_total(total_executable_bytes, 34)?;
            accounts.push(AccountMeta {
                pubkey,
                is_signer,
                is_writable,
            });
        }
        let data_length = cursor.read_count(MAX_INSTRUCTION_DATA_BYTES)?;
        total_executable_bytes = add_total(total_executable_bytes, data_length)?;
        let data = cursor.read_exact(data_length)?.to_vec();
        instructions.push(Instruction {
            program_id,
            accounts,
            data,
        });
    }
    let executed_at = cursor.read_option_i64()?;
    let execution_status = read_small_enum(&mut cursor, 2)?;
    require_zero(cursor.read_exact(8)?)?;
    // AccountMaxSize budgets the eight-byte Some payload even when the Borsh
    // Option is None; the program's unchecked account loader leaves it zeroed.
    if executed_at.is_none() {
        require_zero(cursor.read_exact(8)?)?;
    }
    cursor.finish()?;
    Ok(ProposalTransactionAccount {
        address: snapshot.address,
        proposal,
        option_index,
        transaction_index,
        hold_up_time,
        instructions,
        executed_at,
        execution_status,
    })
}

fn add_total(current: usize, amount: usize) -> Result<usize, GovernanceError> {
    let total = current
        .checked_add(amount)
        .ok_or(GovernanceError::TotalExecutableBytesTooLarge)?;
    if total > MAX_TOTAL_EXECUTABLE_BYTES {
        Err(GovernanceError::TotalExecutableBytesTooLarge)
    } else {
        Ok(total)
    }
}
use core::fmt;

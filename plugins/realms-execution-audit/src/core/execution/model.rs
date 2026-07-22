use crate::core::governance::{Instruction, ProposalTransactionAccount};
use crate::core::pubkey::Pubkey;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionModel {
    pub realm: Pubkey,
    pub governance: Pubkey,
    pub proposal: Pubkey,
    pub governing_token_mint: Pubkey,
    pub proposal_state: u8,
    pub execution_flags: u8,
    pub options: Vec<OrderedOption>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrderedOption {
    pub option_index: u8,
    pub transactions_executed_count: u16,
    pub transactions: Vec<OrderedTransaction>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrderedTransaction {
    pub address: Pubkey,
    pub transaction_index: u16,
    pub hold_up_time: u32,
    pub instructions: Vec<Instruction>,
    pub executed_at: Option<i64>,
    pub execution_status: u8,
}

impl From<ProposalTransactionAccount> for OrderedTransaction {
    fn from(transaction: ProposalTransactionAccount) -> Self {
        Self {
            address: transaction.address,
            transaction_index: transaction.transaction_index,
            hold_up_time: transaction.hold_up_time,
            instructions: transaction.instructions,
            executed_at: transaction.executed_at,
            execution_status: transaction.execution_status,
        }
    }
}

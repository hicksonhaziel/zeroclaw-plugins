use std::collections::BTreeMap;

use crate::core::execution::{ExecutionModel, OrderedOption, OrderedTransaction};
use crate::core::limits::MAX_TOTAL_EXECUTABLE_BYTES;

use super::{
    GovernanceAccount, GovernanceError, ProposalAccount, ProposalTransactionAccount, RealmAccount,
};

pub fn validate_and_reconstruct(
    realm: &RealmAccount,
    governance: &GovernanceAccount,
    proposal: &ProposalAccount,
    transactions: Vec<ProposalTransactionAccount>,
) -> Result<ExecutionModel, GovernanceError> {
    if governance.realm != realm.address {
        return Err(GovernanceError::WrongRealmRelationship);
    }
    if proposal.governance != governance.address {
        return Err(GovernanceError::WrongGovernanceRelationship);
    }
    if proposal.governing_token_mint != realm.community_mint
        && Some(proposal.governing_token_mint) != realm.council_mint
    {
        return Err(GovernanceError::InvalidGoverningMint);
    }

    let expected_total = proposal.options.iter().try_fold(0usize, |total, option| {
        total
            .checked_add(usize::from(option.transactions_count))
            .ok_or(GovernanceError::DeclaredTransactionCountMismatch)
    })?;
    if transactions.len() != expected_total {
        return Err(GovernanceError::DeclaredTransactionCountMismatch);
    }

    let mut grouped: BTreeMap<u8, BTreeMap<u16, ProposalTransactionAccount>> = BTreeMap::new();
    let mut total_executable_bytes = 0usize;
    for transaction in transactions {
        if transaction.proposal != proposal.address {
            return Err(GovernanceError::WrongProposalRelationship);
        }
        let option = proposal
            .options
            .get(usize::from(transaction.option_index))
            .ok_or(GovernanceError::OutOfRangeOptionIndex)?;
        if transaction.transaction_index >= option.transactions_next_index {
            return Err(GovernanceError::TransactionIndexOutOfRange);
        }
        for instruction in &transaction.instructions {
            total_executable_bytes = checked_executable_add(total_executable_bytes, 32)?;
            total_executable_bytes = checked_executable_add(
                total_executable_bytes,
                instruction
                    .accounts
                    .len()
                    .checked_mul(34)
                    .ok_or(GovernanceError::TotalExecutableBytesTooLarge)?,
            )?;
            total_executable_bytes =
                checked_executable_add(total_executable_bytes, instruction.data.len())?;
        }
        if grouped
            .entry(transaction.option_index)
            .or_default()
            .insert(transaction.transaction_index, transaction)
            .is_some()
        {
            return Err(GovernanceError::DuplicateTransactionIndex);
        }
    }

    let mut ordered_options = Vec::with_capacity(proposal.options.len());
    for (option_index, declared) in proposal.options.iter().enumerate() {
        let index =
            u8::try_from(option_index).map_err(|_| GovernanceError::OutOfRangeOptionIndex)?;
        #[allow(clippy::manual_unwrap_or_default)]
        let records = match grouped.remove(&index) {
            Some(records) => records,
            None => BTreeMap::new(),
        };
        if records.len() != usize::from(declared.transactions_count) {
            return Err(GovernanceError::DeclaredTransactionCountMismatch);
        }
        let ordered_transactions = records
            .into_values()
            .map(OrderedTransaction::from)
            .collect::<Vec<_>>();
        let executed_count = ordered_transactions
            .iter()
            .filter(|transaction| transaction.executed_at.is_some())
            .count();
        if executed_count != usize::from(declared.transactions_executed_count)
            || ordered_transactions.iter().any(|transaction| {
                (transaction.executed_at.is_some() && transaction.execution_status == 0)
                    || (transaction.executed_at.is_none() && transaction.execution_status != 0)
            })
        {
            return Err(GovernanceError::DeclaredTransactionCountMismatch);
        }
        ordered_options.push(OrderedOption {
            option_index: index,
            transactions_executed_count: declared.transactions_executed_count,
            transactions: ordered_transactions,
        });
    }
    if !grouped.is_empty() {
        return Err(GovernanceError::OutOfRangeOptionIndex);
    }

    Ok(ExecutionModel {
        realm: realm.address,
        governance: governance.address,
        proposal: proposal.address,
        governing_token_mint: proposal.governing_token_mint,
        proposal_state: proposal.state,
        execution_flags: proposal.execution_flags,
        options: ordered_options,
    })
}

fn checked_executable_add(current: usize, amount: usize) -> Result<usize, GovernanceError> {
    let total = current
        .checked_add(amount)
        .ok_or(GovernanceError::TotalExecutableBytesTooLarge)?;
    if total > MAX_TOTAL_EXECUTABLE_BYTES {
        Err(GovernanceError::TotalExecutableBytesTooLarge)
    } else {
        Ok(total)
    }
}

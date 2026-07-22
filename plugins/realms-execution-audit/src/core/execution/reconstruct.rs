use crate::core::governance::relationship::validate_and_reconstruct;
use crate::core::governance::{
    GovernanceAccount, GovernanceError, ProposalAccount, ProposalTransactionAccount, RealmAccount,
};

use super::ExecutionModel;

pub fn reconstruct_execution(
    realm: &RealmAccount,
    governance: &GovernanceAccount,
    proposal: &ProposalAccount,
    transactions: Vec<ProposalTransactionAccount>,
) -> Result<ExecutionModel, GovernanceError> {
    validate_and_reconstruct(realm, governance, proposal, transactions)
}

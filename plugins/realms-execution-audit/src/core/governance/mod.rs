mod governance_account;
mod proposal;
mod proposal_transaction;
mod realm;
pub mod relationship;

pub use governance_account::{parse_governance, GovernanceAccount, GovernanceKind};
pub use proposal::{parse_proposal, ProposalAccount, ProposalOption};
pub use proposal_transaction::{
    parse_proposal_transaction, AccountMeta, Instruction, ProposalTransactionAccount,
};
pub use realm::{parse_realm, RealmAccount};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GovernanceError {
    AccountDataTooLarge,
    WrongProgramOwner,
    UnsupportedAccountType,
    UnsupportedAccountVersion,
    TruncatedAccount,
    UnexpectedTrailingData,
    InvalidEncoding,
    CountTooLarge,
    DisplayTextTooLarge,
    TotalExecutableBytesTooLarge,
    WrongRealmRelationship,
    WrongGovernanceRelationship,
    WrongProposalRelationship,
    InvalidGoverningMint,
    DuplicateTransactionIndex,
    TransactionIndexOutOfRange,
    OutOfRangeOptionIndex,
    DeclaredTransactionCountMismatch,
}

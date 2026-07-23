use crate::core::pubkey::Pubkey;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityType {
    MintTokens,
    FreezeAccount,
    AccountOwner,
    CloseAccount,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Effect {
    SystemTransfer {
        source: Pubkey,
        destination: Pubkey,
        lamports: u64,
    },
    TokenTransfer {
        source: Pubkey,
        destination: Pubkey,
        authority: Pubkey,
        amount_atomic: u64,
        instruction_decimals: Option<u8>,
    },
    TokenAuthorityChange {
        target: Pubkey,
        current_authority: Pubkey,
        authority_type: AuthorityType,
        new_authority: Option<Pubkey>,
    },
    TokenAccountClose {
        account: Pubkey,
        lamport_destination: Pubkey,
        authority: Pubkey,
    },
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnalysisStatus {
    Complete,
    Unresolved,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnresolvedReason {
    UnsupportedProgram,
    UnsupportedInstruction,
    MalformedInstruction,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InstructionLocation {
    pub option_index: u8,
    pub transaction_index: u16,
    pub instruction_index: u16,
    pub program: Pubkey,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Finding {
    pub risk_level: RiskLevel,
    pub effect: Effect,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnresolvedInstruction {
    pub location: InstructionLocation,
    pub reason: UnresolvedReason,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnalysisReport {
    pub status: AnalysisStatus,
    pub risk_level: Option<RiskLevel>,
    pub known_finding_count: usize,
    pub finding_samples: Vec<Finding>,
    pub unresolved_instruction_count: usize,
    pub unresolved_samples: Vec<UnresolvedInstruction>,
}

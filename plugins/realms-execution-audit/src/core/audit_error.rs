use core::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditError {
    Transport,
    HttpStatus,
    ResponseTooLarge,
    InvalidJson,
    InvalidRpcEnvelope,
    WrongRpcId,
    RpcError,
    InvalidContext,
    SlotRegression,
    MissingParent,
    UnsupportedEncoding,
    InvalidBase64,
    AccountTooLarge,
    InvalidPublicKey,
    WrongOwner,
    InvalidResponseLength,
    DuplicateAddress,
    SnapshotChanged,
    DiscoveryLimit,
    PdaDerivation,
    TransactionPdaMismatch,
    Governance,
    OutputTooLarge,
}

impl AuditError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Transport => "rpc_transport_failed",
            Self::HttpStatus => "rpc_http_status",
            Self::ResponseTooLarge => "rpc_response_too_large",
            Self::InvalidJson => "rpc_invalid_json",
            Self::InvalidRpcEnvelope => "rpc_invalid_envelope",
            Self::WrongRpcId => "rpc_wrong_id",
            Self::RpcError => "rpc_error",
            Self::InvalidContext => "rpc_invalid_context",
            Self::SlotRegression => "rpc_slot_regression",
            Self::MissingParent => "missing_parent_account",
            Self::UnsupportedEncoding => "unsupported_account_encoding",
            Self::InvalidBase64 => "invalid_account_base64",
            Self::AccountTooLarge => "account_data_too_large",
            Self::InvalidPublicKey => "invalid_public_key",
            Self::WrongOwner => "unexpected_account_owner",
            Self::InvalidResponseLength => "invalid_positional_response",
            Self::DuplicateAddress => "duplicate_requested_address",
            Self::SnapshotChanged => "preliminary_snapshot_changed",
            Self::DiscoveryLimit => "transaction_discovery_limit",
            Self::PdaDerivation => "pda_derivation_failed",
            Self::TransactionPdaMismatch => "transaction_pda_mismatch",
            Self::Governance => "governance_validation_failed",
            Self::OutputTooLarge => "audit_output_too_large",
        }
    }

    pub const fn is_incomplete(self) -> bool {
        matches!(
            self,
            Self::MissingParent
                | Self::WrongOwner
                | Self::SnapshotChanged
                | Self::DiscoveryLimit
                | Self::TransactionPdaMismatch
                | Self::Governance
        )
    }
}

impl fmt::Display for AuditError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for AuditError {}

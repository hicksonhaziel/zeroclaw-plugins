use sha2::{Digest, Sha256};

use crate::core::audit_error::AuditError;
use crate::core::execution::Fingerprint;
use crate::core::pubkey::Pubkey;
use crate::core::rpc::AccountObservation;

pub const EVIDENCE_V1_DOMAIN: &[u8] = b"mandate:evidence-snapshot:v1";
const FINALIZED_COMMITMENT_TAG: u8 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservationRole {
    Proposal,
    Governance,
    Realm,
    ProposalTransaction {
        option_index: u8,
        transaction_index: u16,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FinalObservation {
    pub role: ObservationRole,
    pub address: Pubkey,
    pub account: Option<AccountObservation>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceSnapshot {
    pub execution_fingerprint: Fingerprint,
    pub governance_program: Pubkey,
    pub authoritative_slot: u64,
    pub observations: Vec<FinalObservation>,
}

/// Hashes only the final authoritative account snapshot. Preliminary RPC
/// request IDs, slots, lamports, rent epochs, methods, and bodies are absent.
pub fn fingerprint_evidence_v1(snapshot: &EvidenceSnapshot) -> Result<Fingerprint, AuditError> {
    let mut hash = Sha256::new();
    hash.update(EVIDENCE_V1_DOMAIN);
    hash.update(snapshot.execution_fingerprint.0);
    hash.update(snapshot.governance_program.as_bytes());
    hash.update([FINALIZED_COMMITMENT_TAG]);
    hash.update(snapshot.authoritative_slot.to_le_bytes());
    let count =
        u16::try_from(snapshot.observations.len()).map_err(|_| AuditError::DiscoveryLimit)?;
    hash.update(count.to_le_bytes());
    for observation in &snapshot.observations {
        match observation.role {
            ObservationRole::Proposal => hash.update([1]),
            ObservationRole::Governance => hash.update([2]),
            ObservationRole::Realm => hash.update([3]),
            ObservationRole::ProposalTransaction {
                option_index,
                transaction_index,
            } => {
                hash.update([4, option_index]);
                hash.update(transaction_index.to_le_bytes());
            }
        }
        hash.update(observation.address.as_bytes());
        match &observation.account {
            None => hash.update([0]),
            Some(account) => {
                hash.update([1]);
                hash.update(account.owner.as_bytes());
                hash.update([u8::from(account.executable)]);
                hash.update(account.lamports.to_le_bytes());
                hash.update(account.rent_epoch.to_le_bytes());
                let length =
                    u32::try_from(account.data.len()).map_err(|_| AuditError::AccountTooLarge)?;
                hash.update(length.to_le_bytes());
                hash.update(Sha256::digest(&account.data));
            }
        }
    }
    Ok(Fingerprint(hash.finalize().into()))
}

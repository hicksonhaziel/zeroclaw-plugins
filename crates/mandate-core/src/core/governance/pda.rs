use curve25519_dalek::edwards::CompressedEdwardsY;
use sha2::{Digest, Sha256};

use crate::core::pubkey::Pubkey;

const GOVERNANCE_SEED: &[u8] = b"governance";
const PDA_MARKER: &[u8] = b"ProgramDerivedAddress";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PdaError {
    NoViableBump,
}

/// Derives the v3.1.1 ProposalTransaction PDA without a Solana SDK dependency.
///
/// The pinned `solana-program` 1.14.12 implementation tests bump values from
/// 255 down through 1 and returns the first SHA-256 digest which is not a valid
/// compressed Edwards point. Unlike the upstream convenience API, this helper
/// returns a typed error instead of panicking if no bump is viable.
pub fn derive_proposal_transaction(
    program_id: Pubkey,
    proposal: Pubkey,
    option_index: u8,
    transaction_index: u16,
) -> Result<(Pubkey, u8), PdaError> {
    let option = [option_index];
    let transaction = transaction_index.to_le_bytes();
    for bump in (1..=u8::MAX).rev() {
        let bump_seed = [bump];
        let mut hasher = Sha256::new();
        for seed in [
            GOVERNANCE_SEED,
            proposal.as_bytes().as_slice(),
            option.as_slice(),
            transaction.as_slice(),
            bump_seed.as_slice(),
        ] {
            hasher.update(seed);
        }
        hasher.update(program_id.as_bytes());
        hasher.update(PDA_MARKER);
        let digest: [u8; 32] = hasher.finalize().into();
        if CompressedEdwardsY(digest).decompress().is_none() {
            return Ok((Pubkey::new(digest), bump));
        }
    }
    Err(PdaError::NoViableBump)
}

fn derive_governance_pda(program_id: Pubkey, seeds: &[&[u8]]) -> Result<(Pubkey, u8), PdaError> {
    for bump in (1..=u8::MAX).rev() {
        let bump_seed = [bump];
        let mut hasher = Sha256::new();
        for seed in seeds {
            hasher.update(seed);
        }
        hasher.update(bump_seed);
        hasher.update(program_id.as_bytes());
        hasher.update(PDA_MARKER);
        let digest: [u8; 32] = hasher.finalize().into();
        if CompressedEdwardsY(digest).decompress().is_none() {
            return Ok((Pubkey::new(digest), bump));
        }
    }
    Err(PdaError::NoViableBump)
}

/// SPL Governance v3.1.1 TokenOwnerRecord PDA.
pub fn derive_token_owner_record(
    program_id: Pubkey,
    realm: Pubkey,
    governing_token_mint: Pubkey,
    governing_token_owner: Pubkey,
) -> Result<(Pubkey, u8), PdaError> {
    derive_governance_pda(
        program_id,
        &[
            GOVERNANCE_SEED,
            realm.as_bytes(),
            governing_token_mint.as_bytes(),
            governing_token_owner.as_bytes(),
        ],
    )
}

/// SPL Governance v3.1.1 VoteRecord PDA.
pub fn derive_vote_record(
    program_id: Pubkey,
    proposal: Pubkey,
    token_owner_record: Pubkey,
) -> Result<(Pubkey, u8), PdaError> {
    derive_governance_pda(
        program_id,
        &[
            GOVERNANCE_SEED,
            proposal.as_bytes(),
            token_owner_record.as_bytes(),
        ],
    )
}

/// SPL Governance v3.1.1 RealmConfig PDA.
pub fn derive_realm_config(program_id: Pubkey, realm: Pubkey) -> Result<(Pubkey, u8), PdaError> {
    derive_governance_pda(program_id, &[b"realm-config", realm.as_bytes()])
}

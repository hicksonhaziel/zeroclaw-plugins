use sha2::{Digest, Sha256};

use crate::core::governance::GovernanceError;

use super::ExecutionModel;

pub const FINGERPRINT_V1_DOMAIN: &[u8] = b"mandate:execution-fingerprint:v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fingerprint(pub [u8; 32]);

/// Hashes the canonical Phase 2 execution encoding.
///
/// Encoding starts with `mandate:execution-fingerprint:v1`, followed by realm,
/// governance, proposal, and governing-mint pubkeys; proposal execution flags;
/// and a little-endian u16 option count. Each option contains its u8 index and
/// LE u16 surviving transaction count. Each transaction contains its account
/// pubkey, LE u16 index, LE u32 hold-up time, and LE u16 instruction count.
/// Each instruction contains program ID,
/// LE u16 account count, ordered metas (pubkey + signer byte + writable byte),
/// and LE u32 data length plus exact data bytes. Proposal state, executed
/// transaction count, executed-at, execution status, and display text are
/// lifecycle/display data and are absent.
pub fn fingerprint_v1(model: &ExecutionModel) -> Result<Fingerprint, GovernanceError> {
    let mut hash = Sha256::new();
    hash.update(FINGERPRINT_V1_DOMAIN);
    hash.update(model.realm.as_bytes());
    hash.update(model.governance.as_bytes());
    hash.update(model.proposal.as_bytes());
    hash.update(model.governing_token_mint.as_bytes());
    hash.update([model.execution_flags]);
    update_u16(&mut hash, model.options.len())?;
    for option in &model.options {
        hash.update([option.option_index]);
        update_u16(&mut hash, option.transactions.len())?;
        for transaction in &option.transactions {
            hash.update(transaction.address.as_bytes());
            hash.update(transaction.transaction_index.to_le_bytes());
            hash.update(transaction.hold_up_time.to_le_bytes());
            update_u16(&mut hash, transaction.instructions.len())?;
            for instruction in &transaction.instructions {
                hash.update(instruction.program_id.as_bytes());
                update_u16(&mut hash, instruction.accounts.len())?;
                for account in &instruction.accounts {
                    hash.update(account.pubkey.as_bytes());
                    hash.update([u8::from(account.is_signer), u8::from(account.is_writable)]);
                }
                let data_len = u32::try_from(instruction.data.len())
                    .map_err(|_| GovernanceError::TotalExecutableBytesTooLarge)?;
                hash.update(data_len.to_le_bytes());
                hash.update(&instruction.data);
            }
        }
    }
    Ok(Fingerprint(hash.finalize().into()))
}

fn update_u16(hash: &mut Sha256, value: usize) -> Result<(), GovernanceError> {
    let value = u16::try_from(value).map_err(|_| GovernanceError::CountTooLarge)?;
    hash.update(value.to_le_bytes());
    Ok(())
}

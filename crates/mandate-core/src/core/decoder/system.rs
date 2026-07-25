use crate::core::governance::{AccountMeta, Instruction};
use crate::core::policy::Effect;

use super::DecodeFailure;

const TRANSFER_DISCRIMINANT: [u8; 4] = 2u32.to_le_bytes();

pub(super) fn decode(instruction: &Instruction) -> Result<Effect, DecodeFailure> {
    let discriminant = instruction
        .data
        .get(..4)
        .ok_or(DecodeFailure::MalformedInstruction)?;
    if discriminant != TRANSFER_DISCRIMINANT {
        return Err(DecodeFailure::UnsupportedInstruction);
    }
    if instruction.data.len() != 12 {
        return Err(DecodeFailure::MalformedInstruction);
    }
    if instruction.accounts.len() != 2 {
        return Err(DecodeFailure::MalformedInstruction);
    }
    let source = &instruction.accounts[0];
    let destination = &instruction.accounts[1];
    require_meta(source, true, true)?;
    require_meta(destination, false, true)?;
    let amount = instruction.data[4..12]
        .try_into()
        .map(u64::from_le_bytes)
        .map_err(|_| DecodeFailure::MalformedInstruction)?;
    Ok(Effect::SystemTransfer {
        source: source.pubkey,
        destination: destination.pubkey,
        lamports: amount,
    })
}

fn require_meta(meta: &AccountMeta, signer: bool, writable: bool) -> Result<(), DecodeFailure> {
    if meta.is_signer == signer && meta.is_writable == writable {
        Ok(())
    } else {
        Err(DecodeFailure::MalformedInstruction)
    }
}

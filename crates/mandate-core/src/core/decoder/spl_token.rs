use crate::core::governance::{AccountMeta, Instruction};
use crate::core::policy::{AuthorityType, Effect};
use crate::core::pubkey::Pubkey;

use super::DecodeFailure;

const TRANSFER: u8 = 3;
const SET_AUTHORITY: u8 = 6;
const CLOSE_ACCOUNT: u8 = 9;
const TRANSFER_CHECKED: u8 = 12;
const MAX_MULTISIG_SIGNERS: usize = 11;

pub(super) fn decode(instruction: &Instruction) -> Result<Effect, DecodeFailure> {
    let opcode = instruction
        .data
        .first()
        .copied()
        .ok_or(DecodeFailure::MalformedInstruction)?;
    match opcode {
        TRANSFER => decode_transfer(instruction, false),
        TRANSFER_CHECKED => decode_transfer(instruction, true),
        SET_AUTHORITY => decode_set_authority(instruction),
        CLOSE_ACCOUNT => decode_close(instruction),
        _ => Err(DecodeFailure::UnsupportedInstruction),
    }
}

fn decode_transfer(instruction: &Instruction, checked: bool) -> Result<Effect, DecodeFailure> {
    let expected_len = if checked { 10 } else { 9 };
    let authority_index = if checked { 3 } else { 2 };
    if instruction.data.len() != expected_len {
        return Err(DecodeFailure::MalformedInstruction);
    }
    let minimum_accounts = authority_index + 1;
    validate_authority(&instruction.accounts, authority_index)?;
    if instruction.accounts.len() < minimum_accounts {
        return Err(DecodeFailure::MalformedInstruction);
    }
    require_meta(&instruction.accounts[0], false, true)?;
    let destination_index = if checked {
        require_meta(&instruction.accounts[1], false, false)?;
        2
    } else {
        1
    };
    require_meta(&instruction.accounts[destination_index], false, true)?;
    let amount = u64::from_le_bytes(
        instruction.data[1..9]
            .try_into()
            .map_err(|_| DecodeFailure::MalformedInstruction)?,
    );
    Ok(Effect::TokenTransfer {
        source: instruction.accounts[0].pubkey,
        destination: instruction.accounts[destination_index].pubkey,
        authority: instruction.accounts[authority_index].pubkey,
        amount_atomic: amount,
        instruction_decimals: if checked {
            Some(instruction.data[9])
        } else {
            None
        },
    })
}

fn decode_set_authority(instruction: &Instruction) -> Result<Effect, DecodeFailure> {
    if instruction.data.len() < 3 {
        return Err(DecodeFailure::MalformedInstruction);
    }
    let authority_type = match instruction.data[1] {
        0 => AuthorityType::MintTokens,
        1 => AuthorityType::FreezeAccount,
        2 => AuthorityType::AccountOwner,
        3 => AuthorityType::CloseAccount,
        _ => return Err(DecodeFailure::MalformedInstruction),
    };
    let new_authority = match instruction.data[2] {
        0 if instruction.data.len() == 3 => None,
        1 if instruction.data.len() == 35 => {
            let bytes: [u8; 32] = instruction.data[3..35]
                .try_into()
                .map_err(|_| DecodeFailure::MalformedInstruction)?;
            Some(Pubkey::new(bytes))
        }
        _ => return Err(DecodeFailure::MalformedInstruction),
    };
    validate_authority(&instruction.accounts, 1)?;
    require_meta(&instruction.accounts[0], false, true)?;
    Ok(Effect::TokenAuthorityChange {
        target: instruction.accounts[0].pubkey,
        current_authority: instruction.accounts[1].pubkey,
        authority_type,
        new_authority,
    })
}

fn decode_close(instruction: &Instruction) -> Result<Effect, DecodeFailure> {
    if instruction.data != [CLOSE_ACCOUNT] {
        return Err(DecodeFailure::MalformedInstruction);
    }
    validate_authority(&instruction.accounts, 2)?;
    require_meta(&instruction.accounts[0], false, true)?;
    require_meta(&instruction.accounts[1], false, true)?;
    Ok(Effect::TokenAccountClose {
        account: instruction.accounts[0].pubkey,
        lamport_destination: instruction.accounts[1].pubkey,
        authority: instruction.accounts[2].pubkey,
    })
}

fn validate_authority(
    accounts: &[AccountMeta],
    authority_index: usize,
) -> Result<(), DecodeFailure> {
    let authority = accounts
        .get(authority_index)
        .ok_or(DecodeFailure::MalformedInstruction)?;
    if authority.is_writable {
        return Err(DecodeFailure::MalformedInstruction);
    }
    let signers = accounts
        .get(authority_index + 1..)
        .ok_or(DecodeFailure::MalformedInstruction)?;
    if signers.is_empty() {
        if !authority.is_signer {
            return Err(DecodeFailure::MalformedInstruction);
        }
    } else {
        if authority.is_signer || signers.len() > MAX_MULTISIG_SIGNERS {
            return Err(DecodeFailure::MalformedInstruction);
        }
        if signers
            .iter()
            .any(|signer| !signer.is_signer || signer.is_writable)
        {
            return Err(DecodeFailure::MalformedInstruction);
        }
    }
    Ok(())
}

fn require_meta(meta: &AccountMeta, signer: bool, writable: bool) -> Result<(), DecodeFailure> {
    if meta.is_signer == signer && meta.is_writable == writable {
        Ok(())
    } else {
        Err(DecodeFailure::MalformedInstruction)
    }
}

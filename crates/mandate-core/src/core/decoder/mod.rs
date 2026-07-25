mod spl_token;
mod system;

use crate::core::governance::Instruction;
use crate::core::policy::Effect;
use crate::core::pubkey::{CLASSIC_SPL_TOKEN_PROGRAM, SYSTEM_PROGRAM};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeFailure {
    UnsupportedProgram,
    UnsupportedInstruction,
    MalformedInstruction,
}

pub fn decode_instruction(instruction: &Instruction) -> Result<Effect, DecodeFailure> {
    if instruction.program_id == SYSTEM_PROGRAM {
        system::decode(instruction)
    } else if instruction.program_id == CLASSIC_SPL_TOKEN_PROGRAM {
        spl_token::decode(instruction)
    } else {
        Err(DecodeFailure::UnsupportedProgram)
    }
}

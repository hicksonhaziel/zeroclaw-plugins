use crate::core::account::{validate_snapshot, AccountSnapshot};
use crate::core::cursor::Cursor;
use crate::core::pubkey::Pubkey;

use super::realm::require_zero;
use super::GovernanceError;

const MINT_GOVERNANCE_V2: u8 = 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GovernanceKind {
    MintV2,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GovernanceAccount {
    pub address: Pubkey,
    pub kind: GovernanceKind,
    pub realm: Pubkey,
    pub governed_account: Pubkey,
}

pub fn parse_governance(
    snapshot: &AccountSnapshot<'_>,
) -> Result<GovernanceAccount, GovernanceError> {
    validate_snapshot(snapshot, MINT_GOVERNANCE_V2)?;
    let mut cursor = Cursor::new(snapshot.data);
    let _account_type = cursor.read_u8()?;
    let realm = cursor.read_pubkey()?;
    let governed_account = cursor.read_pubkey()?;
    let _reserved1 = cursor.read_u32()?;
    read_threshold(&mut cursor)?;
    let _minimum_weight = cursor.read_u64()?;
    let _hold_up = cursor.read_u32()?;
    let _voting_base = cursor.read_u32()?;
    read_small_enum(&mut cursor, 2)?;
    read_threshold(&mut cursor)?;
    read_threshold(&mut cursor)?;
    let _minimum_council = cursor.read_u64()?;
    read_small_enum(&mut cursor, 2)?;
    read_threshold(&mut cursor)?;
    let _cool_off = cursor.read_u32()?;
    let _deposit_exempt = cursor.read_u8()?;
    require_zero(cursor.read_exact(120)?)?;
    let _active_proposals = cursor.read_u64()?;
    // v3.1.1 allocates GovernanceV2 at 236 bytes although its Borsh payload is
    // 234 bytes. Canonical account loading ignores exactly these two bytes.
    require_zero(cursor.read_exact(2)?)?;
    cursor.finish()?;
    Ok(GovernanceAccount {
        address: snapshot.address,
        kind: GovernanceKind::MintV2,
        realm,
        governed_account,
    })
}

pub(crate) fn read_small_enum(cursor: &mut Cursor<'_>, maximum: u8) -> Result<u8, GovernanceError> {
    let value = cursor.read_u8()?;
    if value <= maximum {
        Ok(value)
    } else {
        Err(GovernanceError::InvalidEncoding)
    }
}

pub(crate) fn read_threshold(cursor: &mut Cursor<'_>) -> Result<(), GovernanceError> {
    match cursor.read_u8()? {
        0 | 1 => {
            let _percentage = cursor.read_u8()?;
            Ok(())
        }
        2 => Ok(()),
        _ => Err(GovernanceError::InvalidEncoding),
    }
}

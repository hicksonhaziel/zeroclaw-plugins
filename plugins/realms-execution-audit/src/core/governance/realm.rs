use crate::core::account::{validate_snapshot, AccountSnapshot};
use crate::core::cursor::Cursor;
use crate::core::limits::{MAX_DISCARDED_DISPLAY_TEXT_BYTES, MAX_DISPLAY_TEXT_FIELD_BYTES};
use crate::core::pubkey::Pubkey;

use super::GovernanceError;

const REALM_V2: u8 = 16;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RealmAccount {
    pub address: Pubkey,
    pub community_mint: Pubkey,
    pub council_mint: Option<Pubkey>,
}

pub fn parse_realm(snapshot: &AccountSnapshot<'_>) -> Result<RealmAccount, GovernanceError> {
    validate_snapshot(snapshot, REALM_V2)?;
    let mut cursor = Cursor::new(snapshot.data);
    let _account_type = cursor.read_u8()?;
    let community_mint = cursor.read_pubkey()?;
    let _legacy1 = cursor.read_u8()?;
    let _legacy2 = cursor.read_u8()?;
    require_zero(cursor.read_exact(6)?)?;
    let _minimum_weight = cursor.read_u64()?;
    match cursor.read_u8()? {
        0 | 1 => {
            let _weight = cursor.read_u64()?;
        }
        _ => return Err(GovernanceError::InvalidEncoding),
    }
    let council_mint = cursor.read_option(Cursor::read_pubkey)?;
    require_zero(cursor.read_exact(6)?)?;
    let _legacy_proposal_count = cursor.read_u16()?;
    let _authority = cursor.read_option(Cursor::read_pubkey)?;
    let name_len = cursor.read_count(MAX_DISPLAY_TEXT_FIELD_BYTES)?;
    if name_len > MAX_DISCARDED_DISPLAY_TEXT_BYTES {
        return Err(GovernanceError::DisplayTextTooLarge);
    }
    let _name = cursor.read_exact(name_len)?;
    require_zero(cursor.read_exact(128)?)?;
    cursor.finish()?;
    Ok(RealmAccount {
        address: snapshot.address,
        community_mint,
        council_mint,
    })
}

pub(crate) fn require_zero(bytes: &[u8]) -> Result<(), GovernanceError> {
    if bytes.iter().all(|byte| *byte == 0) {
        Ok(())
    } else {
        Err(GovernanceError::UnsupportedAccountVersion)
    }
}

use core::fmt;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Pubkey([u8; 32]);

impl Pubkey {
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn from_base58(value: &str) -> Option<Self> {
        if value.is_empty() || value.len() > 44 {
            return None;
        }
        let mut bytes = [0u8; 32];
        let length = bs58::decode(value).onto(&mut bytes).ok()?;
        if length != bytes.len() || bs58::encode(bytes).into_string() != value {
            return None;
        }
        Some(Self(bytes))
    }

    pub fn to_base58(self) -> String {
        bs58::encode(self.0).into_string()
    }
}

impl fmt::Debug for Pubkey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Pubkey(")?;
        for byte in self.0.iter().take(4) {
            write!(formatter, "{byte:02x}")?;
        }
        formatter.write_str("…)")
    }
}

pub const MAINNET_GOVERNANCE_PROGRAM: Pubkey = Pubkey::new([
    234, 228, 53, 189, 238, 117, 183, 52, 205, 89, 62, 207, 154, 48, 75, 128, 36, 186, 40, 152,
    103, 183, 105, 177, 249, 60, 167, 187, 184, 142, 70, 254,
]);

pub const TEST_GOVERNANCE_PROGRAM: Pubkey = Pubkey::new([
    3, 245, 217, 68, 77, 66, 174, 6, 35, 149, 226, 162, 174, 219, 191, 182, 240, 244, 166, 25, 252,
    149, 181, 150, 32, 101, 97, 90, 133, 48, 11, 30,
]);

pub const SYSTEM_PROGRAM: Pubkey = Pubkey::new([0; 32]);

/// Classic SPL Token Program (`Tokenkeg...`), deliberately excluding Token-2022.
pub const CLASSIC_SPL_TOKEN_PROGRAM: Pubkey = Pubkey::new([
    6, 221, 246, 225, 215, 101, 161, 147, 217, 203, 225, 70, 206, 235, 121, 172, 28, 180, 133, 237,
    95, 91, 55, 145, 58, 140, 245, 133, 126, 255, 0, 169,
]);

pub fn is_supported_governance_program(owner: Pubkey) -> bool {
    owner == MAINNET_GOVERNANCE_PROGRAM || owner == TEST_GOVERNANCE_PROGRAM
}

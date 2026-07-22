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

pub fn is_supported_governance_program(owner: Pubkey) -> bool {
    owner == MAINNET_GOVERNANCE_PROGRAM || owner == TEST_GOVERNANCE_PROGRAM
}

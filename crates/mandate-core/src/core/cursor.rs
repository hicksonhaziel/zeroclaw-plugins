use super::governance::GovernanceError;
use super::pubkey::Pubkey;

pub(crate) struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    pub(crate) fn finish(self) -> Result<(), GovernanceError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(GovernanceError::UnexpectedTrailingData)
        }
    }

    pub(crate) fn read_exact(&mut self, length: usize) -> Result<&'a [u8], GovernanceError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(GovernanceError::InvalidEncoding)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(GovernanceError::TruncatedAccount)?;
        self.offset = end;
        Ok(value)
    }

    pub(crate) fn read_u8(&mut self) -> Result<u8, GovernanceError> {
        Ok(self.read_exact(1)?[0])
    }

    pub(crate) fn read_bool(&mut self) -> Result<bool, GovernanceError> {
        match self.read_u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(GovernanceError::InvalidEncoding),
        }
    }

    pub(crate) fn read_u16(&mut self) -> Result<u16, GovernanceError> {
        let value: [u8; 2] = self
            .read_exact(2)?
            .try_into()
            .map_err(|_| GovernanceError::TruncatedAccount)?;
        Ok(u16::from_le_bytes(value))
    }

    pub(crate) fn read_u32(&mut self) -> Result<u32, GovernanceError> {
        let value: [u8; 4] = self
            .read_exact(4)?
            .try_into()
            .map_err(|_| GovernanceError::TruncatedAccount)?;
        Ok(u32::from_le_bytes(value))
    }

    pub(crate) fn read_u64(&mut self) -> Result<u64, GovernanceError> {
        let value: [u8; 8] = self
            .read_exact(8)?
            .try_into()
            .map_err(|_| GovernanceError::TruncatedAccount)?;
        Ok(u64::from_le_bytes(value))
    }

    pub(crate) fn read_i64(&mut self) -> Result<i64, GovernanceError> {
        let value: [u8; 8] = self
            .read_exact(8)?
            .try_into()
            .map_err(|_| GovernanceError::TruncatedAccount)?;
        Ok(i64::from_le_bytes(value))
    }

    pub(crate) fn read_pubkey(&mut self) -> Result<Pubkey, GovernanceError> {
        let value: [u8; 32] = self
            .read_exact(32)?
            .try_into()
            .map_err(|_| GovernanceError::TruncatedAccount)?;
        Ok(Pubkey::new(value))
    }

    pub(crate) fn read_count(&mut self, maximum: usize) -> Result<usize, GovernanceError> {
        let value =
            usize::try_from(self.read_u32()?).map_err(|_| GovernanceError::CountTooLarge)?;
        if value > maximum {
            return Err(GovernanceError::CountTooLarge);
        }
        Ok(value)
    }

    pub(crate) fn read_option_u64(&mut self) -> Result<Option<u64>, GovernanceError> {
        self.read_option(Self::read_u64)
    }

    pub(crate) fn read_option_i64(&mut self) -> Result<Option<i64>, GovernanceError> {
        self.read_option(Self::read_i64)
    }

    pub(crate) fn read_option_u32(&mut self) -> Result<Option<u32>, GovernanceError> {
        self.read_option(Self::read_u32)
    }

    pub(crate) fn read_option<T>(
        &mut self,
        reader: fn(&mut Self) -> Result<T, GovernanceError>,
    ) -> Result<Option<T>, GovernanceError> {
        match self.read_u8()? {
            0 => Ok(None),
            1 => reader(self).map(Some),
            _ => Err(GovernanceError::InvalidEncoding),
        }
    }
}

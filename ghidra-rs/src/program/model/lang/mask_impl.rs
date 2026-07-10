use crate::program::model::lang::sleigh::walker::MemBuffer;
use crate::program::model::lang::{IncompatibleMaskException, Mask};
use crate::program::model::mem::MemoryAccessException;
use std::fmt;

/// Implements the [`Mask`] trait as a byte array.
///
/// This mirrors Ghidra's `MaskImpl`.
#[derive(Debug, Clone)]
pub struct MaskImpl {
    mask: Vec<u8>,
}

impl MaskImpl {
    /// Constructs a mask from a byte array.
    ///
    /// # Arguments
    /// * `msk` - the bits that make up the mask.
    pub fn new(msk: &[u8]) -> Self {
        Self { mask: msk.to_vec() }
    }
}

impl PartialEq for MaskImpl {
    fn eq(&self, other: &Self) -> bool {
        self.mask == other.mask
    }
}

impl Eq for MaskImpl {}

impl fmt::Display for MaskImpl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.mask {
            write!(f, "{:02X}", byte)?;
        }
        Ok(())
    }
}

impl Mask for MaskImpl {
    fn equals_mask(&self, mask: &[u8]) -> bool {
        self.mask == mask
    }

    fn apply_mask<'a>(
        &self,
        cde: &[u8],
        results: &'a mut [u8],
    ) -> Result<&'a mut [u8], IncompatibleMaskException> {
        if cde.len() < self.mask.len() || results.len() < cde.len() {
            return Err(IncompatibleMaskException::new());
        }
        for i in 0..self.mask.len() {
            results[i] = self.mask[i] & cde[i];
        }
        for i in self.mask.len()..cde.len() {
            results[i] = cde[i];
        }
        Ok(results)
    }

    fn apply_mask_with_offset(
        &self,
        cde: &[u8],
        cde_offset: usize,
        results: &mut [u8],
        results_offset: usize,
    ) -> Result<(), IncompatibleMaskException> {
        if cde.len() < cde_offset + self.mask.len()
            || results.len() < results_offset + self.mask.len()
        {
            return Err(IncompatibleMaskException::new());
        }
        for i in 0..self.mask.len() {
            results[results_offset + i] = self.mask[i] & cde[cde_offset + i];
        }
        Ok(())
    }

    fn apply_mask_buffer(&self, buffer: &dyn MemBuffer) -> Result<Vec<u8>, MemoryAccessException> {
        let mut bytes = vec![0u8; self.mask.len()];
        let bytes_read = buffer.get_bytes(&mut bytes, 0);
        if bytes_read != self.mask.len() {
            return Err(MemoryAccessException::new("Could not read enough bytes"));
        }
        for i in 0..self.mask.len() {
            bytes[i] &= self.mask[i];
        }
        Ok(bytes)
    }

    fn equal_masked_value(
        &self,
        cde: &[u8],
        target: &[u8],
    ) -> Result<bool, IncompatibleMaskException> {
        if cde.len() < self.mask.len() || target.len() < self.mask.len() {
            return Err(IncompatibleMaskException::new());
        }
        for i in 0..self.mask.len() {
            if target[i] != (self.mask[i] & cde[i]) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn complement_mask(
        &self,
        msk: &[u8],
        results: &mut [u8],
    ) -> Result<(), IncompatibleMaskException> {
        if results.len() < self.mask.len() || results.len() < msk.len() {
            return Err(IncompatibleMaskException::new());
        }
        let k = self.mask.len().max(msk.len());
        for i in 0..k {
            let mut b: u8 = if i < self.mask.len() {
                self.mask[i] ^ 0xff
            }
            else {
                0xff
            };
            b = if i < msk.len() { b & msk[i] } else { 0 };
            results[i] = b;
        }
        Ok(())
    }

    fn sub_mask(&self, msk: &[u8]) -> Result<bool, IncompatibleMaskException> {
        if self.mask.len() < msk.len() {
            return Ok(false);
        }
        for i in 0..msk.len() {
            let b = !self.mask[i] & msk[i];
            if b != 0 {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn get_bytes(&self) -> Vec<u8> {
        self.mask.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};

    struct MockMemBuffer {
        data: Vec<u8>,
    }

    impl MemBuffer for MockMemBuffer {
        fn get_address(&self) -> Address {
            let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
            Address::new(space, 0)
        }

        fn get_byte(&self, offset: i32) -> Result<u8, MemoryAccessException> {
            self.data
                .get(offset as usize)
                .copied()
                .ok_or_else(|| MemoryAccessException::new("out of bounds"))
        }

        fn get_bytes(&self, buf: &mut [u8], offset: i32) -> usize {
            if offset < 0 || offset as usize >= self.data.len() {
                return 0;
            }
            let start = offset as usize;
            let available = self.data.len() - start;
            let to_read = std::cmp::min(buf.len(), available);
            buf[..to_read].copy_from_slice(&self.data[start..start + to_read]);
            to_read
        }

        fn is_big_endian(&self) -> bool {
            true
        }
    }

    #[test]
    fn new_copies_bytes() {
        let src = vec![0xAA, 0xBB];
        let mask = MaskImpl::new(&src);
        assert_eq!(mask.get_bytes(), src);
    }

    #[test]
    fn equals_mask_true() {
        let mask = MaskImpl::new(&[0xFF, 0x0F]);
        assert!(mask.equals_mask(&[0xFF, 0x0F]));
    }

    #[test]
    fn equals_mask_false_different_length() {
        let mask = MaskImpl::new(&[0xFF, 0x0F]);
        assert!(!mask.equals_mask(&[0xFF]));
    }

    #[test]
    fn partial_eq_compares_bytes() {
        let a = MaskImpl::new(&[0xFF, 0x0F]);
        let b = MaskImpl::new(&[0xFF, 0x0F]);
        let c = MaskImpl::new(&[0xFF, 0x00]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn display_formats_uppercase_hex() {
        let mask = MaskImpl::new(&[0x0a, 0xff, 0x03]);
        assert_eq!(mask.to_string(), "0AFF03");
    }

    #[test]
    fn apply_mask_masks_prefix_and_copies_tail() {
        let mask = MaskImpl::new(&[0xFF, 0x0F]);
        let cde = vec![0xAA, 0xBB, 0xCC];
        let mut results = vec![0u8; 3];
        mask.apply_mask(&cde, &mut results).unwrap();
        assert_eq!(results, vec![0xAA, 0x0B, 0xCC]);
    }

    #[test]
    fn apply_mask_errors_when_cde_shorter_than_mask() {
        let mask = MaskImpl::new(&[0xFF, 0x0F]);
        let cde = vec![0xAA];
        let mut results = vec![0u8; 1];
        assert!(mask.apply_mask(&cde, &mut results).is_err());
    }

    #[test]
    fn apply_mask_errors_when_results_shorter_than_cde() {
        let mask = MaskImpl::new(&[0xFF]);
        let cde = vec![0xAA, 0xBB];
        let mut results = vec![0u8; 1];
        assert!(mask.apply_mask(&cde, &mut results).is_err());
    }

    #[test]
    fn apply_mask_with_offset_basic() {
        let mask = MaskImpl::new(&[0x0F, 0xFF]);
        let cde = vec![0x00, 0xAA, 0xBB, 0xCC];
        let mut results = vec![0u8; 4];
        mask.apply_mask_with_offset(&cde, 1, &mut results, 2)
            .unwrap();
        assert_eq!(results, vec![0x00, 0x00, 0x0A, 0xBB]);
    }

    #[test]
    fn apply_mask_with_offset_errors_on_bounds() {
        let mask = MaskImpl::new(&[0xFF, 0xFF]);
        let cde = vec![0xAA, 0xBB];
        let mut results = vec![0u8; 3];
        assert!(mask
            .apply_mask_with_offset(&cde, 1, &mut results, 2)
            .is_err());
    }

    #[test]
    fn apply_mask_buffer_reads_and_masks() {
        let mask = MaskImpl::new(&[0xFF, 0x0F]);
        let buffer = MockMemBuffer {
            data: vec![0xAA, 0xBB],
        };
        let result = mask.apply_mask_buffer(&buffer).unwrap();
        assert_eq!(result, vec![0xAA, 0x0B]);
    }

    #[test]
    fn apply_mask_buffer_errors_when_insufficient_bytes() {
        let mask = MaskImpl::new(&[0xFF, 0x0F]);
        let buffer = MockMemBuffer { data: vec![0xAA] };
        assert!(mask.apply_mask_buffer(&buffer).is_err());
    }

    #[test]
    fn equal_masked_value_true() {
        let mask = MaskImpl::new(&[0xFF, 0x0F]);
        let cde = vec![0xAA, 0xBB];
        let target = vec![0xAA, 0x0B];
        assert!(mask.equal_masked_value(&cde, &target).unwrap());
    }

    #[test]
    fn equal_masked_value_false() {
        let mask = MaskImpl::new(&[0xFF, 0x0F]);
        let cde = vec![0xAA, 0xBB];
        let target = vec![0xAA, 0x0C];
        assert!(!mask.equal_masked_value(&cde, &target).unwrap());
    }

    #[test]
    fn equal_masked_value_errors_on_short_arrays() {
        let mask = MaskImpl::new(&[0xFF, 0x0F]);
        let cde = vec![0xAA];
        let target = vec![0xAA];
        assert!(mask.equal_masked_value(&cde, &target).is_err());
    }

    #[test]
    fn sub_mask_true_when_subset() {
        let mask = MaskImpl::new(&[0xFF, 0x0F]);
        assert!(mask.sub_mask(&[0xFF, 0x03]).unwrap());
    }

    #[test]
    fn sub_mask_false_when_not_subset() {
        let mask = MaskImpl::new(&[0xFF, 0x0F]);
        assert!(!mask.sub_mask(&[0xFF, 0xF0]).unwrap());
    }

    #[test]
    fn sub_mask_false_when_msk_longer_than_mask() {
        let mask = MaskImpl::new(&[0xFF]);
        assert!(!mask.sub_mask(&[0xFF, 0x0F]).unwrap());
    }

    #[test]
    fn complement_mask_basic() {
        let mask = MaskImpl::new(&[0xFF, 0x00, 0x0F]);
        let msk = vec![0xAA, 0xBB, 0xCC];
        let mut results = vec![0u8; 3];
        mask.complement_mask(&msk, &mut results).unwrap();
        assert_eq!(results, vec![0x00, 0xBB, 0xC0]);
    }

    #[test]
    fn complement_mask_handles_msk_longer_than_mask() {
        let mask = MaskImpl::new(&[0xFF]);
        let msk = vec![0xAA, 0xBB];
        let mut results = vec![0u8; 2];
        mask.complement_mask(&msk, &mut results).unwrap();
        assert_eq!(results, vec![0x00, 0xBB]);
    }

    #[test]
    fn complement_mask_errors_when_results_too_short() {
        let mask = MaskImpl::new(&[0xFF, 0x00]);
        let msk = vec![0xAA, 0xBB, 0xCC];
        let mut results = vec![0u8; 2];
        assert!(mask.complement_mask(&msk, &mut results).is_err());
    }

    #[test]
    fn get_bytes_returns_clone() {
        let src = vec![0x12, 0x34];
        let mask = MaskImpl::new(&src);
        assert_eq!(mask.get_bytes(), src);
    }
}

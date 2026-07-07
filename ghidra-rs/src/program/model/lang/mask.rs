use crate::program::model::lang::IncompatibleMaskException;
use crate::program::model::lang::sleigh::walker::MemBuffer;
use crate::program::model::mem::MemoryAccessException;

/// Mask trait for performing bit tests on an array of bits.
///
/// The Mask trait is used to perform some basic bit tests on an array of bits.
/// This mirrors Ghidra's `Mask` interface.
pub trait Mask: Send + Sync {
    /// Test if the mask represented by the byte array is equal to this one.
    ///
    /// # Arguments
    /// * `mask` - mask represented as byte array
    ///
    /// # Returns
    /// true if the masks are the same, false otherwise
    fn equals_mask(&self, mask: &[u8]) -> bool;

    /// Apply the mask to a byte array.
    ///
    /// # Arguments
    /// * `cde` - the array that contains the values to be masked
    /// * `results` - the array to contain the results
    ///
    /// # Returns
    /// the resulting byte array (results is modified in place)
    ///
    /// # Errors
    /// Returns `IncompatibleMaskException` if byte arrays are not of the correct size
    fn apply_mask<'a>(
        &self,
        cde: &[u8],
        results: &'a mut [u8],
    ) -> Result<&'a mut [u8], IncompatibleMaskException>;

    /// Apply the mask to a byte array with offsets.
    ///
    /// # Arguments
    /// * `cde` - the array that contains the values to be masked
    /// * `cde_offset` - the offset into the array that contains the values to be masked
    /// * `results` - the array to contain the results
    /// * `results_offset` - the offset into the array that contains the results
    ///
    /// # Errors
    /// Returns `IncompatibleMaskException` if byte arrays are not of the correct size
    fn apply_mask_with_offset(
        &self,
        cde: &[u8],
        cde_offset: usize,
        results: &mut [u8],
        results_offset: usize,
    ) -> Result<(), IncompatibleMaskException>;

    /// Apply the mask to a memory buffer.
    ///
    /// # Arguments
    /// * `buffer` - the memory buffer that contains the values to be masked
    ///
    /// # Returns
    /// the resulting masked byte array
    ///
    /// # Errors
    /// Returns `MemoryAccessException` if mask exceeds the available data within buffer
    fn apply_mask_buffer(&self, buffer: &dyn MemBuffer) -> Result<Vec<u8>, MemoryAccessException>;

    /// Tests if the results of applying the mask to the given array matches a target array.
    ///
    /// # Arguments
    /// * `cde` - the source bytes
    /// * `target` - the result bytes to be tested
    ///
    /// # Returns
    /// true if the target array is equal to the source array with the mask applied
    ///
    /// # Errors
    /// Returns `IncompatibleMaskException` if byte arrays are not of the correct size
    fn equal_masked_value(&self, cde: &[u8], target: &[u8]) -> Result<bool, IncompatibleMaskException>;

    /// Applies the complement of the mask to the given byte array.
    ///
    /// # Arguments
    /// * `msk` - the bytes to apply the inverted mask
    /// * `results` - the array for storing the results
    ///
    /// # Returns
    /// unit (results is modified in place)
    ///
    /// # Errors
    /// Returns `IncompatibleMaskException` if byte arrays are not of the correct size
    fn complement_mask(&self, msk: &[u8], results: &mut [u8]) -> Result<(), IncompatibleMaskException>;

    /// Tests if the given mask matches this mask for the first n bytes,
    /// where n is the size of the given mask.
    ///
    /// # Arguments
    /// * `msk` - the bytes to be tested to see if they match the first bytes of this mask
    ///
    /// # Returns
    /// true if the bytes match up to the length of the passed in byte array
    ///
    /// # Errors
    /// Returns `IncompatibleMaskException` if byte arrays are not of the correct size
    fn sub_mask(&self, msk: &[u8]) -> Result<bool, IncompatibleMaskException>;

    /// Returns the bytes that make up this mask.
    fn get_bytes(&self) -> Vec<u8>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct SimpleMask {
        bytes: Vec<u8>,
    }

    impl SimpleMask {
        fn new(bytes: Vec<u8>) -> Self {
            SimpleMask { bytes }
        }
    }

    impl Mask for SimpleMask {
        fn equals_mask(&self, mask: &[u8]) -> bool {
            self.bytes == mask
        }

        fn apply_mask<'a>(
            &self,
            cde: &[u8],
            results: &'a mut [u8],
        ) -> Result<&'a mut [u8], IncompatibleMaskException> {
            if cde.len() != self.bytes.len() || results.len() != self.bytes.len() {
                return Err(IncompatibleMaskException::with_message("mask size mismatch"));
            }
            for i in 0..cde.len() {
                results[i] = cde[i] & self.bytes[i];
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
            if cde_offset + self.bytes.len() > cde.len()
                || results_offset + self.bytes.len() > results.len()
            {
                return Err(IncompatibleMaskException::with_message("offset exceeds array bounds"));
            }
            for i in 0..self.bytes.len() {
                results[results_offset + i] = cde[cde_offset + i] & self.bytes[i];
            }
            Ok(())
        }

        fn apply_mask_buffer(&self, buffer: &dyn MemBuffer) -> Result<Vec<u8>, MemoryAccessException> {
            let mut result = vec![0u8; self.bytes.len()];
            for i in 0..self.bytes.len() {
                let byte = buffer.get_byte(i as i32)?;
                result[i] = byte & self.bytes[i];
            }
            Ok(result)
        }

        fn equal_masked_value(&self, cde: &[u8], target: &[u8]) -> Result<bool, IncompatibleMaskException> {
            if cde.len() != self.bytes.len() || target.len() != self.bytes.len() {
                return Err(IncompatibleMaskException::with_message("mask size mismatch"));
            }
            for i in 0..cde.len() {
                if (cde[i] & self.bytes[i]) != target[i] {
                    return Ok(false);
                }
            }
            Ok(true)
        }

        fn complement_mask(&self, msk: &[u8], results: &mut [u8]) -> Result<(), IncompatibleMaskException> {
            if msk.len() != self.bytes.len() || results.len() != self.bytes.len() {
                return Err(IncompatibleMaskException::with_message("mask size mismatch"));
            }
            for i in 0..msk.len() {
                results[i] = msk[i] & !self.bytes[i];
            }
            Ok(())
        }

        fn sub_mask(&self, msk: &[u8]) -> Result<bool, IncompatibleMaskException> {
            if msk.len() > self.bytes.len() {
                return Err(IncompatibleMaskException::with_message("submask exceeds mask length"));
            }
            for i in 0..msk.len() {
                if self.bytes[i] != msk[i] {
                    return Ok(false);
                }
            }
            Ok(true)
        }

        fn get_bytes(&self) -> Vec<u8> {
            self.bytes.clone()
        }
    }

    #[test]
    fn equals_mask_equal() {
        let mask = SimpleMask::new(vec![0xFF, 0x00, 0xFF]);
        assert!(mask.equals_mask(&[0xFF, 0x00, 0xFF]));
    }

    #[test]
    fn equals_mask_not_equal() {
        let mask = SimpleMask::new(vec![0xFF, 0x00, 0xFF]);
        assert!(!mask.equals_mask(&[0xFF, 0xFF, 0xFF]));
    }

    #[test]
    fn equals_mask_different_length() {
        let mask = SimpleMask::new(vec![0xFF, 0x00]);
        assert!(!mask.equals_mask(&[0xFF, 0x00, 0xFF]));
    }

    #[test]
    fn apply_mask_basic() {
        let mask = SimpleMask::new(vec![0xFF, 0x0F, 0x00]);
        let cde = vec![0xAA, 0xBB, 0xCC];
        let mut results = vec![0x00, 0x00, 0x00];
        mask.apply_mask(&cde, &mut results).unwrap();
        assert_eq!(results, vec![0xAA, 0x0B, 0x00]);
    }

    #[test]
    fn apply_mask_size_mismatch() {
        let mask = SimpleMask::new(vec![0xFF, 0x00]);
        let cde = vec![0xAA, 0xBB, 0xCC];
        let mut results = vec![0x00, 0x00];
        assert!(mask.apply_mask(&cde, &mut results).is_err());
    }

    #[test]
    fn apply_mask_results_size_mismatch() {
        let mask = SimpleMask::new(vec![0xFF, 0x00, 0xFF]);
        let cde = vec![0xAA, 0xBB, 0xCC];
        let mut results = vec![0x00, 0x00];
        assert!(mask.apply_mask(&cde, &mut results).is_err());
    }

    #[test]
    fn apply_mask_with_offset_basic() {
        let mask = SimpleMask::new(vec![0x0F, 0xFF]);
        let cde = vec![0x00, 0xAA, 0xBB, 0xCC];
        let mut results = vec![0x00, 0x00, 0x00, 0x00];
        mask
            .apply_mask_with_offset(&cde, 1, &mut results, 2)
            .unwrap();
        assert_eq!(results, vec![0x00, 0x00, 0x0A, 0xBB]);
    }

    #[test]
    fn apply_mask_with_offset_exceeds_bounds() {
        let mask = SimpleMask::new(vec![0xFF, 0xFF]);
        let cde = vec![0xAA, 0xBB];
        let mut results = vec![0x00, 0x00, 0x00];
        assert!(mask
            .apply_mask_with_offset(&cde, 1, &mut results, 2)
            .is_err());
    }

    #[test]
    fn equal_masked_value_true() {
        let mask = SimpleMask::new(vec![0xFF, 0x0F, 0x00]);
        let cde = vec![0xAA, 0xBB, 0xCC];
        let target = vec![0xAA, 0x0B, 0x00];
        assert!(mask.equal_masked_value(&cde, &target).unwrap());
    }

    #[test]
    fn equal_masked_value_false() {
        let mask = SimpleMask::new(vec![0xFF, 0x0F, 0x00]);
        let cde = vec![0xAA, 0xBB, 0xCC];
        let target = vec![0xAA, 0x0C, 0x00];
        assert!(!mask.equal_masked_value(&cde, &target).unwrap());
    }

    #[test]
    fn equal_masked_value_size_mismatch() {
        let mask = SimpleMask::new(vec![0xFF, 0x00]);
        let cde = vec![0xAA, 0xBB, 0xCC];
        let target = vec![0xAA, 0x00];
        assert!(mask.equal_masked_value(&cde, &target).is_err());
    }

    #[test]
    fn complement_mask_basic() {
        let mask = SimpleMask::new(vec![0xFF, 0x00, 0x0F]);
        let msk = vec![0xAA, 0xBB, 0xCC];
        let mut results = vec![0x00, 0x00, 0x00];
        mask.complement_mask(&msk, &mut results).unwrap();
        assert_eq!(results, vec![0x00, 0xBB, 0xC0]);
    }

    #[test]
    fn complement_mask_size_mismatch() {
        let mask = SimpleMask::new(vec![0xFF, 0x00]);
        let msk = vec![0xAA, 0xBB, 0xCC];
        let mut results = vec![0x00, 0x00];
        assert!(mask.complement_mask(&msk, &mut results).is_err());
    }

    #[test]
    fn sub_mask_match() {
        let mask = SimpleMask::new(vec![0xFF, 0x00, 0xFF]);
        assert!(mask.sub_mask(&[0xFF, 0x00]).unwrap());
    }

    #[test]
    fn sub_mask_no_match() {
        let mask = SimpleMask::new(vec![0xFF, 0x00, 0xFF]);
        assert!(!mask.sub_mask(&[0xFF, 0xFF]).unwrap());
    }

    #[test]
    fn sub_mask_exceeds_length() {
        let mask = SimpleMask::new(vec![0xFF, 0x00]);
        assert!(mask.sub_mask(&[0xFF, 0x00, 0xFF]).is_err());
    }

    #[test]
    fn sub_mask_empty() {
        let mask = SimpleMask::new(vec![0xFF, 0x00, 0xFF]);
        assert!(mask.sub_mask(&[]).unwrap());
    }

    #[test]
    fn get_bytes_basic() {
        let bytes = vec![0xFF, 0x00, 0xAA];
        let mask = SimpleMask::new(bytes.clone());
        assert_eq!(mask.get_bytes(), bytes);
    }
}

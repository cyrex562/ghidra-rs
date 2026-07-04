use crate::program::model::address::Address;

/// API for accessing a binary load image using different methods behind the scenes.
///
/// Corresponds to `ghidra.pcode.loadimage.LoadImage`.
#[deprecated(since = "12.1", note = "for removal")]
pub trait LoadImage {
    /// Load data into a buffer from a specific address in the load image.
    ///
    /// # Arguments
    ///
    /// * `buf` - Buffer to fill with loaded data
    /// * `size` - Number of bytes to load
    /// * `addr` - Address in the load image to read from
    /// * `buf_offset` - Offset within the buffer to start writing
    /// * `generate_initialized_mask` - If true, return an initialized bit mask for loaded bytes;
    ///   if false, uninitialized memory reads should be reported via a memory fault handler
    ///
    /// # Returns
    ///
    /// An initialized bit mask (one bit per byte loaded) if `generate_initialized_mask` is true
    /// and some bytes were uninitialized, or `None` if all loaded bytes were known to be initialized.
    fn load_fill(
        &self,
        buf: &mut [u8],
        size: i32,
        addr: &Address,
        buf_offset: i32,
        generate_initialized_mask: bool,
    ) -> Option<Vec<u8>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};

    struct MockLoadImage {
        data: Vec<u8>,
    }

    impl LoadImage for MockLoadImage {
        fn load_fill(
            &self,
            buf: &mut [u8],
            size: i32,
            _addr: &Address,
            buf_offset: i32,
            _generate_initialized_mask: bool,
        ) -> Option<Vec<u8>> {
            let offset = buf_offset as usize;
            let len = (size as usize).min(buf.len() - offset).min(self.data.len());
            if len > 0 {
                buf[offset..offset + len].copy_from_slice(&self.data[..len]);
            }
            None
        }
    }

    #[test]
    fn mock_load_image_fills_buffer() {
        let mock = MockLoadImage {
            data: vec![0x01, 0x02, 0x03, 0x04],
        };
        let ram = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 0);
        let addr = Address::new(ram, 0x1000);

        let mut buf = [0u8; 8];
        let result = mock.load_fill(&mut buf, 4, &addr, 0, false);

        assert_eq!(buf[0..4], [0x01, 0x02, 0x03, 0x04]);
        assert_eq!(buf[4..], [0, 0, 0, 0]);
        assert_eq!(result, None);
    }

    #[test]
    fn mock_load_image_respects_buffer_offset() {
        let mock = MockLoadImage {
            data: vec![0xAA, 0xBB],
        };
        let ram = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 0);
        let addr = Address::new(ram, 0x2000);

        let mut buf = [0u8; 8];
        let result = mock.load_fill(&mut buf, 2, &addr, 3, false);

        assert_eq!(buf[0..3], [0, 0, 0]);
        assert_eq!(buf[3..5], [0xAA, 0xBB]);
        assert_eq!(buf[5..], [0, 0, 0]);
        assert_eq!(result, None);
    }

    #[test]
    fn mock_load_image_respects_size_limit() {
        let mock = MockLoadImage {
            data: vec![0x11, 0x22, 0x33, 0x44, 0x55],
        };
        let ram = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 0);
        let addr = Address::new(ram, 0x3000);

        let mut buf = [0u8; 10];
        let result = mock.load_fill(&mut buf, 2, &addr, 1, false);

        assert_eq!(buf[0], 0);
        assert_eq!(buf[1..3], [0x11, 0x22]);
        assert_eq!(buf[3..], [0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(result, None);
    }
}

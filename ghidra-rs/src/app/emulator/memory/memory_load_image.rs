use crate::pcode::load_image::LoadImage;
use crate::program::model::address::Address;

/// Extended load image interface that supports write-back and cleanup operations.
///
/// Corresponds to `ghidra.app.emulator.memory.MemoryLoadImage`.
#[deprecated(since = "12.1", note = "for removal")]
pub trait MemoryLoadImage: LoadImage {
    /// Write data back to the specified address in the load image.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Data to write back
    /// * `size` - Number of bytes to write
    /// * `addr` - Address in the load image to write to
    /// * `offset` - Offset within the bytes buffer to start reading from
    fn write_back(&mut self, bytes: &[u8], size: i32, addr: &Address, offset: i32);

    /// Release any resources held by this load image.
    fn dispose(&mut self);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};

    struct TestMemoryLoadImage {
        data: Vec<u8>,
        written_data: Vec<u8>,
    }

    impl TestMemoryLoadImage {
        fn new(data: Vec<u8>) -> Self {
            Self {
                data,
                written_data: Vec::new(),
            }
        }
    }

    impl LoadImage for TestMemoryLoadImage {
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

    impl MemoryLoadImage for TestMemoryLoadImage {
        fn write_back(&mut self, bytes: &[u8], size: i32, _addr: &Address, offset: i32) {
            let start = offset as usize;
            let len = (size as usize).min(bytes.len() - start);
            if len > 0 {
                self.written_data.extend_from_slice(&bytes[start..start + len]);
            }
        }

        fn dispose(&mut self) {
            self.data.clear();
            self.written_data.clear();
        }
    }

    #[test]
    fn test_memory_load_image_write_back_basic() {
        let ram = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 0);
        let addr = Address::new(ram, 0x1000);
        let mut img = TestMemoryLoadImage::new(vec![0x00, 0x00, 0x00, 0x00]);

        let data = [0xAA, 0xBB, 0xCC, 0xDD];
        img.write_back(&data, 4, &addr, 0);

        assert_eq!(img.written_data, vec![0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn test_memory_load_image_write_back_with_offset() {
        let ram = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 0);
        let addr = Address::new(ram, 0x2000);
        let mut img = TestMemoryLoadImage::new(vec![0x00, 0x00, 0x00, 0x00]);

        let data = [0xFF, 0xFF, 0xAA, 0xBB];
        img.write_back(&data, 2, &addr, 2);

        assert_eq!(img.written_data, vec![0xAA, 0xBB]);
    }

    #[test]
    fn test_memory_load_image_write_back_multiple_calls() {
        let ram = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 0);
        let addr = Address::new(ram, 0x3000);
        let mut img = TestMemoryLoadImage::new(vec![0x00; 8]);

        let data1 = [0x11, 0x22, 0x33, 0x44];
        img.write_back(&data1, 4, &addr, 0);

        let data2 = [0x55, 0x66, 0x77, 0x88];
        img.write_back(&data2, 4, &addr, 0);

        assert_eq!(img.written_data, vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
    }

    #[test]
    fn test_memory_load_image_dispose_clears_data() {
        let ram = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 0);
        let addr = Address::new(ram, 0x4000);
        let mut img = TestMemoryLoadImage::new(vec![0x11, 0x22, 0x33, 0x44]);

        let data = [0xAA, 0xBB];
        img.write_back(&data, 2, &addr, 0);

        assert!(!img.data.is_empty());
        assert!(!img.written_data.is_empty());

        img.dispose();

        assert!(img.data.is_empty());
        assert!(img.written_data.is_empty());
    }

    #[test]
    fn test_memory_load_image_load_fill_inherited() {
        let ram = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 0);
        let addr = Address::new(ram, 0x5000);
        let img = TestMemoryLoadImage::new(vec![0x01, 0x02, 0x03, 0x04]);

        let mut buf = [0u8; 8];
        img.load_fill(&mut buf, 4, &addr, 0, false);

        assert_eq!(buf[0..4], [0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn test_memory_load_image_write_back_respects_size() {
        let ram = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 0);
        let addr = Address::new(ram, 0x6000);
        let mut img = TestMemoryLoadImage::new(vec![0x00; 8]);

        let data = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        img.write_back(&data, 3, &addr, 0);

        assert_eq!(img.written_data, vec![0x11, 0x22, 0x33]);
    }
}

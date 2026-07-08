use std::cell::RefCell;
use std::io;
use std::rc::Rc;

use crate::filesystem::ghidra::g_binary_reader::ByteProvider;

/// Bit flag (in a block pointer) indicating the block is a direct pointer.
pub const IS_DIRECT_POINTER: u32 = 1 << 30;
/// Bit flag (in a block pointer) indicating the block is stored uncompressed.
pub const IS_UNCOMPRESSED: u32 = 1 << 31;

/// A single data block within a cramfs file.
///
/// Mirrors `CramFsBlock` from the original Ghidra Java source.
///
/// See <https://github.com/torvalds/linux/tree/master/fs/cramfs>.
pub struct CramFsBlock {
    block_pointer: i32,
    start_address: i32,
    is_direct_pointer: bool,
    is_compressed: bool,
    block_size: i32,
    provider: Rc<RefCell<dyn ByteProvider>>,
}

impl CramFsBlock {
    /// This constructor is for regular contiguous blocks in a cramfs file
    /// that do not have the extension flag set.
    ///
    /// * `start` - the address for the start of this block.
    /// * `block_size` - the size of the cramfs block.
    /// * `provider` - the byte provider for the block header.
    pub fn new(start: i32, block_size: i32, provider: Rc<RefCell<dyn ByteProvider>>) -> Self {
        CramFsBlock {
            block_pointer: start,
            start_address: start,
            is_direct_pointer: false,
            is_compressed: false,
            block_size,
            provider,
        }
    }

    /// Returns the block pointer for the cramfs block.
    pub fn block_pointer(&self) -> i32 {
        self.block_pointer
    }

    /// Returns true if the block is a direct pointer.
    pub fn is_direct_pointer(&self) -> bool {
        self.is_direct_pointer
    }

    /// Returns true if the block is compressed.
    pub fn is_compressed(&self) -> bool {
        self.is_compressed
    }

    /// Returns the size of the cramfs block.
    pub fn block_size(&self) -> i32 {
        self.block_size
    }

    /// Reads the data block in its entirety.
    ///
    /// # Errors
    /// Returns `Err` if there is an error while reading the data block.
    pub fn read_block(&self) -> io::Result<Vec<u8>> {
        self.provider
            .borrow_mut()
            .read_bytes(self.start_address as u64, self.block_size as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct VecProvider(Vec<u8>);

    impl ByteProvider for VecProvider {
        fn length(&mut self) -> io::Result<u64> {
            Ok(self.0.len() as u64)
        }
        fn is_valid_index(&mut self, index: u64) -> bool {
            index < self.0.len() as u64
        }
        fn read_byte(&mut self, index: u64) -> io::Result<u8> {
            self.0
                .get(index as usize)
                .copied()
                .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))
        }
        fn read_bytes(&mut self, index: u64, length: usize) -> io::Result<Vec<u8>> {
            let start = index as usize;
            let end = start + length;
            self.0
                .get(start..end)
                .map(|s| s.to_vec())
                .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))
        }
        fn write_byte(&mut self, _index: u64, _value: u8) -> io::Result<()> {
            unimplemented!()
        }
        fn write_bytes(&mut self, _index: u64, _values: &[u8]) -> io::Result<()> {
            unimplemented!()
        }
    }

    fn provider(data: Vec<u8>) -> Rc<RefCell<dyn ByteProvider>> {
        Rc::new(RefCell::new(VecProvider(data)))
    }

    #[test]
    fn new_sets_block_pointer_and_start_address_to_start() {
        let block = CramFsBlock::new(16, 4, provider(vec![0u8; 32]));
        assert_eq!(block.block_pointer(), 16);
    }

    #[test]
    fn new_defaults_to_not_direct_and_not_compressed() {
        let block = CramFsBlock::new(0, 4, provider(vec![0u8; 32]));
        assert!(!block.is_direct_pointer());
        assert!(!block.is_compressed());
    }

    #[test]
    fn block_size_returns_constructed_size() {
        let block = CramFsBlock::new(0, 12, provider(vec![0u8; 32]));
        assert_eq!(block.block_size(), 12);
    }

    #[test]
    fn read_block_reads_bytes_from_start_address() {
        let mut data = vec![0u8; 8];
        data.extend_from_slice(&[1, 2, 3, 4]);
        let block = CramFsBlock::new(8, 4, provider(data));
        assert_eq!(block.read_block().unwrap(), vec![1, 2, 3, 4]);
    }

    #[test]
    fn read_block_past_end_of_provider_errors() {
        let block = CramFsBlock::new(0, 16, provider(vec![0u8; 4]));
        assert!(block.read_block().is_err());
    }

    #[test]
    fn is_direct_pointer_flag_value() {
        assert_eq!(IS_DIRECT_POINTER, 0x4000_0000);
    }

    #[test]
    fn is_uncompressed_flag_value() {
        assert_eq!(IS_UNCOMPRESSED, 0x8000_0000);
    }
}

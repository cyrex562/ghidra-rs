pub mod dyld_architecture;
pub mod dyld_cache_image;
pub mod dyld_cache_image_info;
pub mod dyld_cache_mapping_and_slide_info;
pub mod dyld_cache_mapping_info;
pub mod dyld_cache_slide_info_common;
pub mod dyld_chained_ptr;
pub mod dyld_fixup;

/// Test-only in-memory [`BinaryReader`](crate::app::util::bin::binary_reader::BinaryReader)
/// shared by this module's structure-parsing tests.
#[cfg(test)]
pub(crate) mod test_support {
    use std::cell::RefCell;
    use std::io;
    use std::rc::Rc;

    use crate::app::util::bin::binary_reader::BinaryReader;
    use crate::filesystem::ghidra::g_binary_reader::GByteStore;

    struct VecStore(Vec<u8>);

    impl GByteStore for VecStore {
        fn length(&mut self) -> io::Result<u64> {
            Ok(self.0.len() as u64)
        }
        fn is_valid_index(&mut self, index: u64) -> bool {
            index < self.0.len() as u64
        }
        fn read_byte(&mut self, index: u64) -> io::Result<u8> {
            self.0.get(index as usize).copied().ok_or(io::Error::from(io::ErrorKind::UnexpectedEof))
        }
        fn read_bytes(&mut self, index: u64, length: usize) -> io::Result<Vec<u8>> {
            let start = index as usize;
            self.0
                .get(start..start + length)
                .map(|s| s.to_vec())
                .ok_or(io::Error::from(io::ErrorKind::UnexpectedEof))
        }
        fn write_byte(&mut self, _index: u64, _value: u8) -> io::Result<()> {
            Err(io::Error::from(io::ErrorKind::Unsupported))
        }
        fn write_bytes(&mut self, _index: u64, _values: &[u8]) -> io::Result<()> {
            Err(io::Error::from(io::ErrorKind::Unsupported))
        }
    }

    /// A reader over an owned byte vector.
    pub(crate) struct VecReader {
        provider: Rc<RefCell<dyn GByteStore>>,
        little_endian: bool,
        index: u64,
    }

    impl VecReader {
        pub(crate) fn new(data: Vec<u8>, little_endian: bool) -> Self {
            VecReader { provider: Rc::new(RefCell::new(VecStore(data))), little_endian, index: 0 }
        }
    }

    impl BinaryReader for VecReader {
        fn length(&self) -> io::Result<u64> {
            self.provider.borrow_mut().length()
        }
        fn is_valid_index(&self, index: u64) -> bool {
            self.provider.borrow_mut().is_valid_index(index)
        }
        fn get_pointer_index(&self) -> u64 {
            self.index
        }
        fn set_pointer_index(&mut self, index: u64) -> u64 {
            std::mem::replace(&mut self.index, index)
        }
        fn is_little_endian(&self) -> bool {
            self.little_endian
        }
        fn set_little_endian(&mut self, is_little_endian: bool) {
            self.little_endian = is_little_endian;
        }
        fn read_byte(&self, index: u64) -> io::Result<u8> {
            self.provider.borrow_mut().read_byte(index)
        }
        fn read_byte_array(&self, index: u64, n: usize) -> io::Result<Vec<u8>> {
            self.provider.borrow_mut().read_bytes(index, n)
        }
        fn get_byte_provider(&self) -> Rc<RefCell<dyn GByteStore>> {
            Rc::clone(&self.provider)
        }
        fn clone_at(&self, new_index: u64) -> Box<dyn BinaryReader> {
            Box::new(VecReader {
                provider: Rc::clone(&self.provider),
                little_endian: self.little_endian,
                index: new_index,
            })
        }
    }
}

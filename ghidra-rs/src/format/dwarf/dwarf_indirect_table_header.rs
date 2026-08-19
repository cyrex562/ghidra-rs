use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;

/// Base structure holding the shared state of indirect table headers (DWARFAddressListHeader,
/// DWARFLocationListHeader, etc).
///
/// Mirrors the concrete fields and methods of the abstract Java class
/// `DWARFIndirectTableHeader`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DWARFIndirectTableHeaderBase {
    start_offset: u64,
    end_offset: u64,
    first_element_offset: u64,
}

impl DWARFIndirectTableHeaderBase {
    pub fn new(start_offset: u64, end_offset: u64, first_element_offset: u64) -> Self {
        DWARFIndirectTableHeaderBase {
            start_offset,
            end_offset,
            first_element_offset,
        }
    }

    /// Mirrors `DWARFIndirectTableHeader.getStartOffset()`.
    pub fn get_start_offset(&self) -> u64 {
        self.start_offset
    }

    /// Mirrors `DWARFIndirectTableHeader.getFirstElementOffset()`.
    pub fn get_first_element_offset(&self) -> u64 {
        self.first_element_offset
    }

    /// Mirrors `DWARFIndirectTableHeader.getEndOffset()`.
    pub fn get_end_offset(&self) -> u64 {
        self.end_offset
    }
}

/// Abstract interface for indirect table headers, declaring the abstract method
/// from the Java class `DWARFIndirectTableHeader`.
///
/// Concrete implementations should embed a `DWARFIndirectTableHeaderBase` and implement
/// this trait to define the offset lookup behavior specific to their header type.
pub trait DWARFIndirectTableHeader {
    /// Mirrors `DWARFIndirectTableHeader.getOffset(int, BinaryReader)`.
    fn get_offset(&self, index: i32, reader: &dyn BinaryReader) -> io::Result<i64>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::ghidra::g_binary_reader::ByteProvider;
    use std::cell::RefCell;
    use std::rc::Rc;

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
            Err(io::Error::new(io::ErrorKind::Unsupported, "read-only"))
        }
        fn write_bytes(&mut self, _index: u64, _values: &[u8]) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "read-only"))
        }
    }

    /// A minimal `BinaryReader` implementation backed by an in-memory byte vector, for testing.
    struct TestReader {
        provider: Rc<RefCell<dyn ByteProvider>>,
        index: u64,
        little_endian: bool,
    }

    impl TestReader {
        fn new(bytes: Vec<u8>) -> Self {
            TestReader {
                provider: Rc::new(RefCell::new(VecProvider(bytes))),
                index: 0,
                little_endian: true,
            }
        }
    }

    impl BinaryReader for TestReader {
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
            let prev = self.index;
            self.index = index;
            prev
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
        fn read_byte_array(&self, index: u64, n_elements: usize) -> io::Result<Vec<u8>> {
            self.provider.borrow_mut().read_bytes(index, n_elements)
        }
        fn get_byte_provider(&self) -> Rc<RefCell<dyn ByteProvider>> {
            Rc::clone(&self.provider)
        }
        fn clone_at(&self, new_index: u64) -> Box<dyn BinaryReader> {
            Box::new(TestReader {
                provider: Rc::clone(&self.provider),
                index: new_index,
                little_endian: self.little_endian,
            })
        }
    }

    #[test]
    fn base_creation_and_getters() {
        let base = DWARFIndirectTableHeaderBase::new(0x100, 0x200, 0x150);
        assert_eq!(base.get_start_offset(), 0x100);
        assert_eq!(base.get_end_offset(), 0x200);
        assert_eq!(base.get_first_element_offset(), 0x150);
    }

    #[test]
    fn base_construction_with_different_offsets() {
        let base = DWARFIndirectTableHeaderBase::new(0, 0x1000, 0x500);
        assert_eq!(base.get_start_offset(), 0);
        assert_eq!(base.get_end_offset(), 0x1000);
        assert_eq!(base.get_first_element_offset(), 0x500);
    }

    #[test]
    fn base_clone_and_equality() {
        let base1 = DWARFIndirectTableHeaderBase::new(0x100, 0x200, 0x150);
        let base2 = base1.clone();
        assert_eq!(base1, base2);
    }
}

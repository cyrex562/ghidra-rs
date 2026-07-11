use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;

use super::debug_code_view_constants;
use super::debug_symbol::{DebugSymbol, DebugSymbolBase};

/// Mirrors the `S_UDT32` Java class in `ghidra.app.util.bin.format.pe.debug`.
///
/// A user-defined type symbol (type `0x1003`) that contains a checksum and a name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SUdt32 {
    base: DebugSymbolBase,
    checksum: i32,
}

impl SUdt32 {
    /// Creates a new `SUdt32` by reading from the given binary reader at the
    /// specified index, mirroring the Java constructor.
    ///
    /// # Arguments
    ///
    /// * `reader` - A binary reader positioned at the structure's data.
    /// * `length` - The record length.
    /// * `symbol_type` - The record type.
    /// * `ptr` - The starting byte offset in the reader.
    ///
    /// # Errors
    ///
    /// Returns an `io::Error` if reading from the reader fails, or if the symbol
    /// type is not `S_UDT32` (0x1003).
    pub fn new(
        reader: &dyn BinaryReader,
        length: i16,
        symbol_type: i16,
        ptr: u64,
    ) -> io::Result<Self> {
        let mut base = DebugSymbolBase::default();
        base.process_debug_symbol(length, symbol_type);

        if symbol_type != debug_code_view_constants::S_UDT32 as i16 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Incorrect type!",
            ));
        }

        let mut offset = ptr;

        let checksum = reader.read_int(offset)?;
        offset += 4;

        let type_len = reader.read_byte(offset)?;
        offset += 1;

        base.name = reader.read_ascii_string_fixed(offset, type_len as usize)?;

        Ok(SUdt32 { base, checksum })
    }

    /// Returns the checksum value.
    pub fn checksum(&self) -> i32 {
        self.checksum
    }
}

impl DebugSymbol for SUdt32 {
    fn length(&self) -> i16 {
        self.base.length()
    }

    fn symbol_type(&self) -> i16 {
        self.base.symbol_type()
    }

    fn name(&self) -> &str {
        self.base.name()
    }

    fn section(&self) -> i16 {
        self.base.section()
    }

    fn offset(&self) -> i32 {
        self.base.offset()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    use crate::filesystem::ghidra::g_binary_reader::ByteProvider;

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
                .ok_or(io::Error::from(io::ErrorKind::UnexpectedEof))
        }

        fn read_bytes(&mut self, index: u64, length: usize) -> io::Result<Vec<u8>> {
            let start = index as usize;
            let end = start + length;
            self.0
                .get(start..end)
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

    struct MockReader {
        provider: Rc<RefCell<dyn ByteProvider>>,
        little_endian: bool,
        current_index: u64,
    }

    impl MockReader {
        fn new(data: Vec<u8>, little_endian: bool) -> Self {
            MockReader {
                provider: Rc::new(RefCell::new(VecProvider(data))),
                little_endian,
                current_index: 0,
            }
        }
    }

    impl BinaryReader for MockReader {
        fn length(&self) -> io::Result<u64> {
            self.provider.borrow_mut().length()
        }

        fn is_valid_index(&self, index: u64) -> bool {
            self.provider.borrow_mut().is_valid_index(index)
        }

        fn get_pointer_index(&self) -> u64 {
            self.current_index
        }

        fn set_pointer_index(&mut self, index: u64) -> u64 {
            let prev = self.current_index;
            self.current_index = index;
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
            Box::new(MockReader {
                provider: Rc::clone(&self.provider),
                little_endian: self.little_endian,
                current_index: new_index,
            })
        }
    }

    fn build_data(checksum: i32, name: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&checksum.to_le_bytes());
        data.push(name.len() as u8);
        data.extend_from_slice(name);
        data
    }

    #[test]
    fn new_reads_fields_correctly() {
        let data = build_data(0x1234_5678, b"test");
        let reader = MockReader::new(data, true);
        let sym = SUdt32::new(&reader, 9, 0x1003, 0).unwrap();

        assert_eq!(sym.length(), 9);
        assert_eq!(sym.symbol_type(), 0x1003);
        assert_eq!(sym.checksum(), 0x1234_5678);
        assert_eq!(sym.name(), "test");
    }

    #[test]
    fn checksum_is_read_correctly() {
        let data = build_data(0xDEAD_BEEFu32 as i32, b"sym");
        let reader = MockReader::new(data, true);
        let sym = SUdt32::new(&reader, 8, 0x1003, 0).unwrap();

        assert_eq!(sym.checksum(), 0xDEAD_BEEFu32 as i32);
    }

    #[test]
    fn name_is_read_with_correct_length() {
        let data = build_data(100, b"mytype");
        let reader = MockReader::new(data, true);
        let sym = SUdt32::new(&reader, 11, 0x1003, 0).unwrap();

        assert_eq!(sym.name(), "mytype");
    }

    #[test]
    fn empty_name() {
        let data = build_data(0, b"");
        let reader = MockReader::new(data, true);
        let sym = SUdt32::new(&reader, 5, 0x1003, 0).unwrap();

        assert_eq!(sym.name(), "");
    }

    #[test]
    fn incorrect_type_returns_error() {
        let data = build_data(0, b"test");
        let reader = MockReader::new(data, true);
        let result = SUdt32::new(&reader, 9, 0x9999u16 as i16, 0);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn negative_checksum_preserved() {
        let data = build_data(-1234, b"neg");
        let reader = MockReader::new(data, true);
        let sym = SUdt32::new(&reader, 8, 0x1003, 0).unwrap();

        assert_eq!(sym.checksum(), -1234);
    }

    #[test]
    fn trait_object_dispatch() {
        let data = build_data(0xABCD_EF01u32 as i32, b"type");
        let reader = MockReader::new(data, true);
        let sym: Box<dyn DebugSymbol> = Box::new(SUdt32::new(&reader, 9, 0x1003, 0).unwrap());

        assert_eq!(sym.length(), 9);
        assert_eq!(sym.symbol_type(), 0x1003);
        assert_eq!(sym.name(), "type");
        assert_eq!(sym.section(), 0);
        assert_eq!(sym.offset(), 0);
    }

    #[test]
    fn clone_equality() {
        let data = build_data(555, b"clone");
        let reader = MockReader::new(data, true);
        let sym = SUdt32::new(&reader, 10, 0x1003, 0).unwrap();
        let cloned = sym.clone();

        assert_eq!(sym, cloned);
    }

    #[test]
    fn negative_length_preserved() {
        let data = build_data(0, b"x");
        let reader = MockReader::new(data, true);
        let sym = SUdt32::new(&reader, -1, 0x1003, 0).unwrap();

        assert_eq!(sym.length(), -1);
    }
}

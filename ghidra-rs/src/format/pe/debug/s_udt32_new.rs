use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;

use super::debug_symbol::{DebugSymbol, DebugSymbolBase};

/// Represents a user-defined type symbol (S_UDT32_NEW) in CodeView format.
///
/// Mirrors the `S_UDT32_NEW` Java class in `ghidra.app.util.bin.format.pe.debug`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SUdt32New {
    base: DebugSymbolBase,
    sym_type: i32,
}

impl SUdt32New {
    /// Creates a new `SUdt32New` by reading from the given binary reader at the
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
    /// Returns an `io::Result::Err` if reading from the reader fails.
    pub fn new(
        reader: &dyn BinaryReader,
        length: i16,
        symbol_type: i16,
        ptr: u64,
    ) -> io::Result<Self> {
        let mut base = DebugSymbolBase::default();
        base.process_debug_symbol(length, symbol_type);

        let mut offset = ptr;

        let sym_type = reader.read_int(offset)?;
        offset += 4;

        let name_len = reader.read_byte(offset)? as usize;
        offset += 1;

        base.name = reader.read_ascii_string_fixed(offset, name_len)?;

        Ok(SUdt32New { base, sym_type })
    }

    /// Returns the symbol type.
    pub fn sym_type(&self) -> i32 {
        self.sym_type
    }
}

impl DebugSymbol for SUdt32New {
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

    fn build_data() -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&0x12345678i32.to_le_bytes()); // symType
        data.push(4); // nameLen = 4
        data.extend_from_slice(b"test"); // name
        data
    }

    #[test]
    fn new_reads_fields_correctly() {
        let reader = MockReader::new(build_data(), true);
        let sym = SUdt32New::new(&reader, 13, 0x1505, 0).unwrap();

        assert_eq!(sym.length(), 13);
        assert_eq!(sym.symbol_type(), 0x1505);
        assert_eq!(sym.sym_type(), 0x12345678);
        assert_eq!(sym.name(), "test");
    }

    #[test]
    fn sym_type_is_read_correctly() {
        let mut data = Vec::new();
        data.extend_from_slice(&(-1i32).to_le_bytes()); // symType = -1
        data.push(3); // nameLen = 3
        data.extend_from_slice(b"typ"); // name

        let reader = MockReader::new(data, true);
        let sym = SUdt32New::new(&reader, 12, 0x1505, 0).unwrap();

        assert_eq!(sym.sym_type(), -1);
    }

    #[test]
    fn empty_name() {
        let mut data = Vec::new();
        data.extend_from_slice(&0u32.to_le_bytes());
        data.push(0); // nameLen = 0

        let reader = MockReader::new(data, true);
        let sym = SUdt32New::new(&reader, 5, 0x1505, 0).unwrap();

        assert_eq!(sym.name(), "");
    }

    #[test]
    fn name_is_read_as_fixed_length_string() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x11223344i32.to_le_bytes());
        data.push(6); // nameLen = 6
        data.extend_from_slice(b"symbol"); // name

        let reader = MockReader::new(data, true);
        let sym = SUdt32New::new(&reader, 15, 0x1505, 0).unwrap();

        assert_eq!(sym.name(), "symbol");
    }

    #[test]
    fn trait_object_dispatch() {
        let reader = MockReader::new(build_data(), true);
        let sym: Box<dyn DebugSymbol> =
            Box::new(SUdt32New::new(&reader, 13, 0x1505, 0).unwrap());

        assert_eq!(sym.length(), 13);
        assert_eq!(sym.symbol_type(), 0x1505);
        assert_eq!(sym.offset(), 0);
        assert_eq!(sym.section(), 0);
        assert_eq!(sym.name(), "test");
    }

    #[test]
    fn clone_equality() {
        let reader = MockReader::new(build_data(), true);
        let sym = SUdt32New::new(&reader, 13, 0x1505, 0).unwrap();
        let cloned = sym.clone();

        assert_eq!(sym, cloned);
    }

    #[test]
    fn negative_sym_type_preserved() {
        let mut data = Vec::new();
        data.extend_from_slice(&(-0x12345678i32).to_le_bytes());
        data.push(2); // nameLen = 2
        data.extend_from_slice(b"xy");

        let reader = MockReader::new(data, true);
        let sym = SUdt32New::new(&reader, 11, 0x1505, 0).unwrap();

        assert_eq!(sym.sym_type(), -0x12345678);
    }

    #[test]
    fn zero_sym_type() {
        let mut data = Vec::new();
        data.extend_from_slice(&0i32.to_le_bytes());
        data.push(3); // nameLen = 3
        data.extend_from_slice(b"udt");

        let reader = MockReader::new(data, true);
        let sym = SUdt32New::new(&reader, 12, 0x1505, 0).unwrap();

        assert_eq!(sym.sym_type(), 0);
        assert_eq!(sym.name(), "udt");
    }
}

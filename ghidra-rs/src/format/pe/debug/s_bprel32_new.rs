use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;

use super::debug_symbol::{DebugSymbol, DebugSymbolBase};

/// Represents a base pointer relative symbol (S_BPREL32_NEW) in CodeView format.
///
/// Mirrors the `S_BPREL32_NEW` Java class in `ghidra.app.util.bin.format.pe.debug`.
///
/// A base pointer relative symbol identifies variables relative to the frame pointer,
/// commonly used for stack-based local variables in optimized code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SBprel32New {
    base: DebugSymbolBase,
    variable_type: i16,
    symbol_type: i16,
}

impl SBprel32New {
    /// Creates a new `SBprel32New` by reading from the given binary reader at the
    /// specified offset, mirroring the Java constructor.
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
        record_type: i16,
        ptr: u64,
    ) -> io::Result<Self> {
        let mut base = DebugSymbolBase::default();
        base.process_debug_symbol(length, record_type);

        let mut offset = ptr;

        base.offset = reader.read_int(offset)? as i32;
        offset += 4;

        let variable_type = reader.read_short(offset)?;
        offset += 2;

        let symbol_type = reader.read_short(offset)?;
        offset += 2;

        let name_len = reader.read_byte(offset)? as usize;
        offset += 1;

        base.name = reader.read_ascii_string_fixed(offset, name_len)?;

        Ok(SBprel32New {
            base,
            variable_type,
            symbol_type,
        })
    }

    /// Returns the variable type.
    pub fn variable_type(&self) -> i16 {
        self.variable_type
    }

    /// Returns the symbol type.
    pub fn symbol_type(&self) -> i16 {
        self.symbol_type
    }
}

impl DebugSymbol for SBprel32New {
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

    #[test]
    fn new_reads_fields_correctly() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x1000_0000i32.to_le_bytes()); // offset = 0x10000000
        data.extend_from_slice(&42i16.to_le_bytes()); // variable_type = 42
        data.extend_from_slice(&7i16.to_le_bytes()); // symbol_type = 7
        data.push(4); // name length = 4
        data.extend_from_slice(b"test"); // name = "test"

        let reader = MockReader::new(data, true);
        let sym = SBprel32New::new(&reader, 15, 0x0009, 0).unwrap();

        assert_eq!(sym.length(), 15);
        assert_eq!(DebugSymbol::symbol_type(&sym), 0x0009);
        assert_eq!(sym.offset(), 0x1000_0000);
        assert_eq!(sym.variable_type(), 42);
        assert_eq!(sym.symbol_type(), 7);
        assert_eq!(sym.name(), "test");
        assert_eq!(sym.section(), 0);
    }

    #[test]
    fn name_is_read_with_length_prefix() {
        let mut data = Vec::new();
        data.extend_from_slice(&0_i32.to_le_bytes()); // offset = 0
        data.extend_from_slice(&1i16.to_le_bytes()); // variable_type = 1
        data.extend_from_slice(&2i16.to_le_bytes()); // symbol_type = 2
        data.push(5); // name length = 5
        data.extend_from_slice(b"hello"); // name = "hello"
        data.extend_from_slice(b"extra"); // extra data that shouldn't be read

        let reader = MockReader::new(data, true);
        let sym = SBprel32New::new(&reader, 12, 0x0009, 0).unwrap();

        assert_eq!(sym.name(), "hello");
    }

    #[test]
    fn empty_name_with_zero_length() {
        let mut data = Vec::new();
        data.extend_from_slice(&100i32.to_le_bytes()); // offset = 100
        data.extend_from_slice(&5i16.to_le_bytes()); // variable_type = 5
        data.extend_from_slice(&10i16.to_le_bytes()); // symbol_type = 10
        data.push(0); // name length = 0

        let reader = MockReader::new(data, true);
        let sym = SBprel32New::new(&reader, 8, 0x0009, 0).unwrap();

        assert_eq!(sym.name(), "");
        assert_eq!(sym.offset(), 100);
    }

    #[test]
    fn offset_is_read_as_i32() {
        let mut data = Vec::new();
        data.extend_from_slice(&0xDEADBEEFu32.to_le_bytes());
        data.extend_from_slice(&0i16.to_le_bytes());
        data.extend_from_slice(&0i16.to_le_bytes());
        data.push(0);

        let reader = MockReader::new(data, true);
        let sym = SBprel32New::new(&reader, 10, 0, 0).unwrap();

        assert_eq!(sym.offset(), 0xDEADBEEFu32 as i32);
    }

    #[test]
    fn variable_type_and_symbol_type_are_preserved() {
        let mut data = Vec::new();
        data.extend_from_slice(&500i32.to_le_bytes()); // offset
        data.extend_from_slice(&0x1234i16.to_le_bytes()); // variable_type = 0x1234
        data.extend_from_slice(&0x5678i16.to_le_bytes()); // symbol_type = 0x5678
        data.push(3); // name length = 3
        data.extend_from_slice(b"foo"); // name = "foo"

        let reader = MockReader::new(data, true);
        let sym = SBprel32New::new(&reader, 14, 0x0009, 0).unwrap();

        assert_eq!(sym.variable_type(), 0x1234);
        assert_eq!(sym.symbol_type(), 0x5678);
    }

    #[test]
    fn trait_object_dispatch() {
        let mut data = Vec::new();
        data.extend_from_slice(&256i32.to_le_bytes());
        data.extend_from_slice(&11i16.to_le_bytes());
        data.extend_from_slice(&22i16.to_le_bytes());
        data.push(2);
        data.extend_from_slice(b"xy");

        let reader = MockReader::new(data, true);
        let sym: Box<dyn DebugSymbol> =
            Box::new(SBprel32New::new(&reader, 12, 0x0009, 0).unwrap());

        assert_eq!(sym.length(), 12);
        assert_eq!(sym.symbol_type(), 0x0009);
        assert_eq!(sym.offset(), 256);
        assert_eq!(sym.section(), 0);
        assert_eq!(sym.name(), "xy");
    }

    #[test]
    fn clone_equality() {
        let mut data = Vec::new();
        data.extend_from_slice(&1000i32.to_le_bytes());
        data.extend_from_slice(&33i16.to_le_bytes());
        data.extend_from_slice(&44i16.to_le_bytes());
        data.push(6);
        data.extend_from_slice(b"symbol");

        let reader = MockReader::new(data, true);
        let sym = SBprel32New::new(&reader, 16, 0x0009, 0).unwrap();
        let cloned = sym.clone();

        assert_eq!(sym, cloned);
    }

    #[test]
    fn negative_offset() {
        let mut data = Vec::new();
        data.extend_from_slice(&(-50i32).to_le_bytes());
        data.extend_from_slice(&1i16.to_le_bytes());
        data.extend_from_slice(&2i16.to_le_bytes());
        data.push(3);
        data.extend_from_slice(b"neg");

        let reader = MockReader::new(data, true);
        let sym = SBprel32New::new(&reader, 12, 0x0009, 0).unwrap();

        assert_eq!(sym.offset(), -50);
    }
}

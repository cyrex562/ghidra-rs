use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;

use super::debug_code_view_constants;
use super::debug_symbol::{DebugSymbol, DebugSymbolBase};

/// Mirrors the `S_DATAREF` Java class in `ghidra.app.util.bin.format.pe.debug`.
///
/// A data reference symbol (type `0x0401`) that contains a checksum and reference information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SDataref {
    base: DebugSymbolBase,
    checksum: i32,
}

impl SDataref {
    /// Creates a new `SDataref` by reading from the given binary reader at the
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
    /// type is not `S_DATAREF` (0x0401).
    pub fn new(
        reader: &dyn BinaryReader,
        length: i16,
        symbol_type: i16,
        ptr: u64,
    ) -> io::Result<Self> {
        let mut base = DebugSymbolBase::default();
        base.process_debug_symbol(length, symbol_type);

        if symbol_type != debug_code_view_constants::S_DATAREF as i16 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Incorrect type!",
            ));
        }

        let mut offset = ptr;

        let checksum = reader.read_int(offset)?;
        offset += 4;

        base.offset = reader.read_int(offset)?;
        offset += 4;

        base.section = reader.read_short(offset)?;

        Ok(SDataref { base, checksum })
    }

    /// Returns the checksum value.
    pub fn checksum(&self) -> i32 {
        self.checksum
    }
}

impl DebugSymbol for SDataref {
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
        data.extend_from_slice(&0x1000_0000i32.to_le_bytes()); // checksum
        data.extend_from_slice(&0x2000_0000i32.to_le_bytes()); // offset
        data.extend_from_slice(&42i16.to_le_bytes()); // section

        let reader = MockReader::new(data, true);
        let sym = SDataref::new(&reader, 10, 0x0401, 0).unwrap();

        assert_eq!(sym.length(), 10);
        assert_eq!(sym.symbol_type(), 0x0401);
        assert_eq!(sym.checksum(), 0x1000_0000);
        assert_eq!(sym.offset(), 0x2000_0000);
        assert_eq!(sym.section(), 42);
    }

    #[test]
    fn incorrect_type_returns_error() {
        let mut data = Vec::new();
        data.extend_from_slice(&0_i32.to_le_bytes());
        data.extend_from_slice(&0_i32.to_le_bytes());
        data.extend_from_slice(&0i16.to_le_bytes());

        let reader = MockReader::new(data, true);
        let result = SDataref::new(&reader, 10, 0x0999, 0);

        assert!(result.is_err());
    }

    #[test]
    fn correct_type_constant_succeeds() {
        let mut data = Vec::new();
        data.extend_from_slice(&100_i32.to_le_bytes());
        data.extend_from_slice(&200_i32.to_le_bytes());
        data.extend_from_slice(&5i16.to_le_bytes());

        let reader = MockReader::new(data, true);
        let sym = SDataref::new(
            &reader,
            10,
            debug_code_view_constants::S_DATAREF as i16,
            0,
        )
        .unwrap();

        assert_eq!(sym.checksum(), 100);
        assert_eq!(sym.offset(), 200);
        assert_eq!(sym.section(), 5);
    }

    #[test]
    fn negative_checksum_preserved() {
        let mut data = Vec::new();
        data.extend_from_slice(&(-1234_i32).to_le_bytes());
        data.extend_from_slice(&0_i32.to_le_bytes());
        data.extend_from_slice(&0i16.to_le_bytes());

        let reader = MockReader::new(data, true);
        let sym = SDataref::new(&reader, 10, 0x0401, 0).unwrap();

        assert_eq!(sym.checksum(), -1234);
    }

    #[test]
    fn negative_offset_preserved() {
        let mut data = Vec::new();
        data.extend_from_slice(&0_i32.to_le_bytes());
        data.extend_from_slice(&(-5000_i32).to_le_bytes());
        data.extend_from_slice(&0i16.to_le_bytes());

        let reader = MockReader::new(data, true);
        let sym = SDataref::new(&reader, 10, 0x0401, 0).unwrap();

        assert_eq!(sym.offset(), -5000);
    }

    #[test]
    fn trait_object_dispatch() {
        let mut data = Vec::new();
        data.extend_from_slice(&(0xDEAD_BEEFu32 as i32).to_le_bytes());
        data.extend_from_slice(&0x1234_5678i32.to_le_bytes());
        data.extend_from_slice(&99i16.to_le_bytes());

        let reader = MockReader::new(data, true);
        let sym: Box<dyn DebugSymbol> = Box::new(SDataref::new(&reader, 10, 0x0401, 0).unwrap());

        assert_eq!(sym.length(), 10);
        assert_eq!(sym.symbol_type(), 0x0401);
        assert_eq!(sym.section(), 99);
        assert_eq!(sym.offset(), 0x1234_5678);
    }

    #[test]
    fn clone_equality() {
        let mut data = Vec::new();
        data.extend_from_slice(&111_i32.to_le_bytes());
        data.extend_from_slice(&222_i32.to_le_bytes());
        data.extend_from_slice(&33i16.to_le_bytes());

        let reader = MockReader::new(data, true);
        let sym = SDataref::new(&reader, 10, 0x0401, 0).unwrap();
        let cloned = sym.clone();

        assert_eq!(sym, cloned);
    }

    #[test]
    fn negative_length_preserved() {
        let mut data = Vec::new();
        data.extend_from_slice(&0_i32.to_le_bytes());
        data.extend_from_slice(&0_i32.to_le_bytes());
        data.extend_from_slice(&0i16.to_le_bytes());

        let reader = MockReader::new(data, true);
        let sym = SDataref::new(&reader, -1, 0x0401, 0).unwrap();

        assert_eq!(sym.length(), -1);
    }
}

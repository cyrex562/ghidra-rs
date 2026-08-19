use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;

use super::debug_symbol::{DebugSymbol, DebugSymbolBase};

/// Represents a PE debug data symbol (S_LDATA32, S_GDATA32, or S_PUB32) with extended fields.
///
/// Mirrors the `DataSym32_new` Java class in `ghidra.app.util.bin.format.pe.debug`.
///
/// ```text
/// typedef struct DATASYM32_NEW {
///     unsigned short  reclen;         // Record length
///     unsigned short  rectyp;         // S_LDATA32, S_GDATA32 or S_PUB32
///     CVTYPEINDEX     typind;
///     unsigned long   off;
///     unsigned short  seg;
///     unsigned char   name[1];        // Length-prefixed name
/// } DATASYM32_NEW;
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataSym32New {
    base: DebugSymbolBase,
    type_index: i32,
    name_char: u8,
}

impl DataSym32New {
    /// Creates a new `DataSym32New` by reading from the given binary reader at the
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
        let type_index = reader.read_int(offset)? as i32;
        offset += 4;

        base.offset = reader.read_int(offset)? as i32;
        offset += 4;

        base.section = reader.read_short(offset)?;
        offset += 2;

        let name_char = reader.read_byte(offset)?;
        offset += 1;

        base.name = reader.read_ascii_string(offset)?;

        Ok(DataSym32New {
            base,
            type_index,
            name_char,
        })
    }

    /// Returns the type index.
    pub fn type_index(&self) -> i32 {
        self.type_index
    }

    /// Returns the name character (the length prefix of the name).
    pub fn name_char(&self) -> u8 {
        self.name_char
    }
}

impl DebugSymbol for DataSym32New {
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
        data.extend_from_slice(&5i32.to_le_bytes()); // type_index = 5
        data.extend_from_slice(&0x0000_1000u32.to_le_bytes()); // offset = 0x00001000
        data.extend_from_slice(&2i16.to_le_bytes()); // section = 2
        data.push(0x74); // name_char = 't'
        data.extend_from_slice(b"est\0"); // name = "est\0"

        let reader = MockReader::new(data, true);
        let sym = DataSym32New::new(&reader, 20, 0x0011, 0).unwrap();

        assert_eq!(sym.length(), 20);
        assert_eq!(sym.symbol_type(), 0x0011);
        assert_eq!(sym.offset(), 0x1000);
        assert_eq!(sym.section(), 2);
        assert_eq!(sym.type_index(), 5);
        assert_eq!(sym.name_char(), 0x74);
        assert_eq!(sym.name(), "est");
    }

    #[test]
    fn name_is_read_as_null_terminated_string() {
        let mut data = Vec::new();
        data.extend_from_slice(&10i32.to_le_bytes()); // type_index
        data.extend_from_slice(&0_i32.to_le_bytes()); // offset
        data.extend_from_slice(&1i16.to_le_bytes()); // section
        data.push(0x68); // name_char = 'h'
        data.extend_from_slice(b"ello\0"); // name = "ello\0"
        data.extend_from_slice(b"extra"); // extra data that shouldn't be read

        let reader = MockReader::new(data, true);
        let sym = DataSym32New::new(&reader, 18, 0x1234, 0).unwrap();

        assert_eq!(sym.name(), "ello");
        assert_eq!(sym.name_char(), 0x68);
    }

    #[test]
    fn offset_is_read_as_i32() {
        let mut data = Vec::new();
        data.extend_from_slice(&0i32.to_le_bytes());
        data.extend_from_slice(&0xDEADBEEFu32.to_le_bytes());
        data.extend_from_slice(&0i16.to_le_bytes());
        data.push(0); // name_char
        data.push(0); // null terminator for name

        let reader = MockReader::new(data, true);
        let sym = DataSym32New::new(&reader, 10, 0, 0).unwrap();

        assert_eq!(sym.offset(), 0xDEADBEEFu32 as i32);
    }

    #[test]
    fn type_index_is_read_as_i32() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x12345678i32.to_le_bytes()); // type_index
        data.extend_from_slice(&1000_i32.to_le_bytes()); // offset
        data.extend_from_slice(&3i16.to_le_bytes()); // section
        data.push(0x61); // name_char = 'a'
        data.extend_from_slice(b"b\0");

        let reader = MockReader::new(data, true);
        let sym = DataSym32New::new(&reader, 15, 0x42, 0).unwrap();

        assert_eq!(sym.type_index(), 0x12345678);
    }

    #[test]
    fn trait_object_dispatch() {
        let mut data = Vec::new();
        data.extend_from_slice(&7i32.to_le_bytes());
        data.extend_from_slice(&1000_i32.to_le_bytes());
        data.extend_from_slice(&3i16.to_le_bytes());
        data.push(0x61); // name_char = 'a'
        data.extend_from_slice(b"b\0");

        let reader = MockReader::new(data, true);
        let sym: Box<dyn DebugSymbol> =
            Box::new(DataSym32New::new(&reader, 15, 0x42, 0).unwrap());

        assert_eq!(sym.length(), 15);
        assert_eq!(sym.symbol_type(), 0x42);
        assert_eq!(sym.offset(), 1000);
        assert_eq!(sym.section(), 3);
        assert_eq!(sym.name(), "b");
    }

    #[test]
    fn empty_name_when_immediately_null_terminated() {
        let mut data = Vec::new();
        data.extend_from_slice(&0i32.to_le_bytes());
        data.extend_from_slice(&0_i32.to_le_bytes());
        data.extend_from_slice(&0i16.to_le_bytes());
        data.push(0); // name_char = 0
        data.push(0); // null terminator

        let reader = MockReader::new(data, true);
        let sym = DataSym32New::new(&reader, 8, 0, 0).unwrap();

        assert_eq!(sym.name(), "");
        assert_eq!(sym.name_char(), 0);
    }

    #[test]
    fn clone_equality() {
        let mut data = Vec::new();
        data.extend_from_slice(&12i32.to_le_bytes());
        data.extend_from_slice(&512_i32.to_le_bytes());
        data.extend_from_slice(&4i16.to_le_bytes());
        data.push(0x73); // name_char = 's'
        data.extend_from_slice(b"ym\0");

        let reader = MockReader::new(data, true);
        let sym = DataSym32New::new(&reader, 16, 0x11, 0).unwrap();
        let cloned = sym.clone();

        assert_eq!(sym, cloned);
    }

    #[test]
    fn negative_offset() {
        let mut data = Vec::new();
        data.extend_from_slice(&0i32.to_le_bytes());
        data.extend_from_slice(&(-100_i32).to_le_bytes());
        data.extend_from_slice(&1i16.to_le_bytes());
        data.push(0x6E); // name_char = 'n'
        data.extend_from_slice(b"eg\0");

        let reader = MockReader::new(data, true);
        let sym = DataSym32New::new(&reader, 12, 0, 0).unwrap();

        assert_eq!(sym.offset(), -100);
        assert_eq!(sym.name(), "eg");
    }
}

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;

use super::debug_symbol::{DebugSymbol, DebugSymbolBase};

/// Represents a global data symbol (S_GDATA32_NEW) in CodeView format.
///
/// Mirrors the `S_GDATA32_NEW` Java class in `ghidra.app.util.bin.format.pe.debug`.
///
/// ```text
/// typedef struct GDATA32_NEW {
///     unsigned short  reclen;         // Record length
///     unsigned short  rectyp;         // S_GDATA32_NEW
///     unsigned long   unknown;
///     unsigned long   off;
///     unsigned short  seg;
///     unsigned char   name[1];        // Length-prefixed name
/// } GDATA32_NEW;
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SGdata32New {
    base: DebugSymbolBase,
    unknown: i32,
}

impl SGdata32New {
    /// Creates a new `SGdata32New` by reading from the given binary reader at the
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

        let unknown = reader.read_int(offset)?;
        offset += 4;

        base.offset = reader.read_int(offset)?;
        offset += 4;

        base.section = reader.read_short(offset)?;
        offset += 2;

        let name_len = reader.read_byte(offset)? as usize;
        offset += 1;

        base.name = reader.read_ascii_string_fixed(offset, name_len)?;

        Ok(SGdata32New { base, unknown })
    }

    /// Returns the unknown field value.
    pub fn unknown(&self) -> i32 {
        self.unknown
    }
}

impl DebugSymbol for SGdata32New {
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
        data.extend_from_slice(&42i32.to_le_bytes()); // unknown
        data.extend_from_slice(&0x2000_0000u32.to_le_bytes()); // offset
        data.extend_from_slice(&3i16.to_le_bytes()); // section
        data.push(5); // nameLen = 5
        data.extend_from_slice(b"myvar"); // name

        let reader = MockReader::new(data, true);
        let sym = SGdata32New::new(&reader, 19, 0x0003, 0).unwrap();

        assert_eq!(sym.length(), 19);
        assert_eq!(sym.symbol_type(), 0x0003);
        assert_eq!(sym.unknown(), 42);
        assert_eq!(sym.offset(), 0x2000_0000);
        assert_eq!(sym.section(), 3);
        assert_eq!(sym.name(), "myvar");
    }

    #[test]
    fn name_is_read_as_fixed_length_string() {
        let mut data = Vec::new();
        data.extend_from_slice(&100i32.to_le_bytes());
        data.extend_from_slice(&0x1000_0000i32.to_le_bytes());
        data.extend_from_slice(&1i16.to_le_bytes());
        data.push(4); // nameLen = 4
        data.extend_from_slice(b"test");
        data.extend_from_slice(b"extra"); // extra data that shouldn't be read

        let reader = MockReader::new(data, true);
        let sym = SGdata32New::new(&reader, 18, 0x0003, 0).unwrap();

        assert_eq!(sym.name(), "test");
    }

    #[test]
    fn empty_name() {
        let mut data = Vec::new();
        data.extend_from_slice(&0i32.to_le_bytes());
        data.extend_from_slice(&0i32.to_le_bytes());
        data.extend_from_slice(&0i16.to_le_bytes());
        data.push(0); // nameLen = 0

        let reader = MockReader::new(data, true);
        let sym = SGdata32New::new(&reader, 12, 0x0003, 0).unwrap();

        assert_eq!(sym.name(), "");
    }

    #[test]
    fn trait_object_dispatch() {
        let mut data = Vec::new();
        data.extend_from_slice(&7i32.to_le_bytes());
        data.extend_from_slice(&1000_i32.to_le_bytes());
        data.extend_from_slice(&3i16.to_le_bytes());
        data.push(2); // nameLen = 2
        data.extend_from_slice(b"ab");

        let reader = MockReader::new(data, true);
        let sym: Box<dyn DebugSymbol> =
            Box::new(SGdata32New::new(&reader, 15, 0x42, 0).unwrap());

        assert_eq!(sym.length(), 15);
        assert_eq!(sym.symbol_type(), 0x42);
        assert_eq!(sym.offset(), 1000);
        assert_eq!(sym.section(), 3);
        assert_eq!(sym.name(), "ab");
    }

    #[test]
    fn clone_equality() {
        let mut data = Vec::new();
        data.extend_from_slice(&12i32.to_le_bytes());
        data.extend_from_slice(&512_i32.to_le_bytes());
        data.extend_from_slice(&4i16.to_le_bytes());
        data.push(3); // nameLen = 3
        data.extend_from_slice(b"sym");

        let reader = MockReader::new(data, true);
        let sym = SGdata32New::new(&reader, 16, 0x11, 0).unwrap();
        let cloned = sym.clone();

        assert_eq!(sym, cloned);
    }

    #[test]
    fn negative_unknown_preserved() {
        let mut data = Vec::new();
        data.extend_from_slice(&(-1i32).to_le_bytes());
        data.extend_from_slice(&100i32.to_le_bytes());
        data.extend_from_slice(&1i16.to_le_bytes());
        data.push(2); // nameLen = 2
        data.extend_from_slice(b"ab");

        let reader = MockReader::new(data, true);
        let sym = SGdata32New::new(&reader, 14, 0x0003, 0).unwrap();

        assert_eq!(sym.unknown(), -1);
    }

    #[test]
    fn negative_offset_preserved() {
        let mut data = Vec::new();
        data.extend_from_slice(&0i32.to_le_bytes());
        data.extend_from_slice(&(-500i32).to_le_bytes());
        data.extend_from_slice(&2i16.to_le_bytes());
        data.push(1); // nameLen = 1
        data.extend_from_slice(b"x");

        let reader = MockReader::new(data, true);
        let sym = SGdata32New::new(&reader, 13, 0x0003, 0).unwrap();

        assert_eq!(sym.offset(), -500);
    }
}

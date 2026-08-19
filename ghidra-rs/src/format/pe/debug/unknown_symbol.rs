use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;

use super::debug_symbol::{DebugSymbol, DebugSymbolBase};

/// Represents an unknown debug symbol in CodeView format.
///
/// Mirrors the `UnknownSymbol` Java class in `ghidra.app.util.bin.format.pe.debug`.
///
/// Used for symbols whose type is not recognized; it stores the raw bytes
/// of the symbol data for later analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownSymbol {
    base: DebugSymbolBase,
    unknown: Vec<u8>,
}

impl UnknownSymbol {
    /// Creates a new `UnknownSymbol` by reading from the given binary reader at the
    /// specified index, mirroring the Java constructor.
    ///
    /// # Arguments
    ///
    /// * `reader` - A binary reader positioned at the structure's data.
    /// * `length` - The record length (number of bytes to read).
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

        let unknown = reader.read_byte_array(ptr, length as usize)?;

        Ok(UnknownSymbol { base, unknown })
    }

    /// Returns the raw unknown bytes.
    pub fn unknown(&self) -> &[u8] {
        &self.unknown
    }
}

impl DebugSymbol for UnknownSymbol {
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
    fn new_reads_unknown_bytes_correctly() {
        let data = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let reader = MockReader::new(data.clone(), true);
        let sym = UnknownSymbol::new(&reader, 5, 0x1234, 0).unwrap();

        assert_eq!(sym.length(), 5);
        assert_eq!(sym.symbol_type(), 0x1234);
        assert_eq!(sym.unknown(), &[0x01, 0x02, 0x03, 0x04, 0x05][..]);
    }

    #[test]
    fn new_at_nonzero_offset() {
        let mut data = vec![0xFF, 0xFF];
        data.extend_from_slice(&[0xAA, 0xBB, 0xCC]);
        let reader = MockReader::new(data, true);
        let sym = UnknownSymbol::new(&reader, 3, 0x5678, 2).unwrap();

        assert_eq!(sym.length(), 3);
        assert_eq!(sym.symbol_type(), 0x5678);
        assert_eq!(sym.unknown(), &[0xAA, 0xBB, 0xCC][..]);
    }

    #[test]
    fn empty_unknown_bytes() {
        let data = vec![];
        let reader = MockReader::new(data, true);
        let sym = UnknownSymbol::new(&reader, 0, 0x0000, 0).unwrap();

        assert_eq!(sym.length(), 0);
        assert_eq!(sym.symbol_type(), 0x0000);
        assert_eq!(sym.unknown(), &[] as &[u8]);
    }

    #[test]
    fn single_byte() {
        let data = vec![0x42];
        let reader = MockReader::new(data, true);
        let sym = UnknownSymbol::new(&reader, 1, 0x9999u16 as i16, 0).unwrap();

        assert_eq!(sym.length(), 1);
        assert_eq!(sym.unknown(), &[0x42][..]);
    }

    #[test]
    fn large_byte_array() {
        let data: Vec<u8> = (0..256).map(|i| (i % 256) as u8).collect();
        let reader = MockReader::new(data.clone(), true);
        let sym = UnknownSymbol::new(&reader, 256, 0x0001, 0).unwrap();

        assert_eq!(sym.length(), 256);
        assert_eq!(sym.unknown(), &data[..]);
    }

    #[test]
    fn trait_object_dispatch() {
        let data = vec![0x10, 0x20, 0x30];
        let reader = MockReader::new(data, true);
        let sym: Box<dyn DebugSymbol> =
            Box::new(UnknownSymbol::new(&reader, 3, 0x1111, 0).unwrap());

        assert_eq!(sym.length(), 3);
        assert_eq!(sym.symbol_type(), 0x1111);
        assert_eq!(sym.name(), "");
        assert_eq!(sym.section(), 0);
        assert_eq!(sym.offset(), 0);
    }

    #[test]
    fn clone_equality() {
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let reader = MockReader::new(data, true);
        let sym = UnknownSymbol::new(&reader, 4, 0x0042, 0).unwrap();
        let cloned = sym.clone();

        assert_eq!(sym, cloned);
    }

    #[test]
    fn read_error_propagates() {
        let data = vec![0x01, 0x02];
        let reader = MockReader::new(data, true);
        let result = UnknownSymbol::new(&reader, 10, 0x0000, 0);

        assert!(result.is_err());
    }
}

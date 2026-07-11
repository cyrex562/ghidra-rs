use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;

use super::debug_symbol::{DebugSymbol, DebugSymbolBase};
use super::debug_code_view_constants;

/// Mirrors the `S_ALIGN` Java class in `ghidra.app.util.bin.format.pe.debug`.
///
/// An alignment-padding symbol (type `0x0402`) that carries a sequence of padding bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SAlign {
    base: DebugSymbolBase,
    pad: Vec<u8>,
}

impl SAlign {
    /// Creates a new `SAlign` by reading from the given binary reader at the
    /// specified index, mirroring the Java constructor.
    ///
    /// # Arguments
    ///
    /// * `reader` - A binary reader positioned at the structure's data.
    /// * `length` - The record length (number of padding bytes).
    /// * `symbol_type` - The record type (must be `S_ALIGN` = 0x0402).
    /// * `ptr` - The starting byte offset in the reader.
    ///
    /// # Errors
    ///
    /// Returns an `io::Result::Err` if the type is not `S_ALIGN` or if reading from
    /// the reader fails.
    pub fn new(
        reader: &dyn BinaryReader,
        length: i16,
        symbol_type: i16,
        ptr: u64,
    ) -> io::Result<Self> {
        if symbol_type != debug_code_view_constants::S_ALIGN as i16 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Incorrect type!",
            ));
        }

        let mut base = DebugSymbolBase::default();
        base.process_debug_symbol(length, symbol_type);

        let pad = reader.read_byte_array(ptr, length.max(0) as usize)?;

        Ok(SAlign { base, pad })
    }

    /// Checks if the padding is all 0xff bytes (end-of-table marker).
    pub fn is_eot(&self) -> bool {
        self.pad.iter().all(|&b| b == 0xff)
    }
}

impl DebugSymbol for SAlign {
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
    fn new_reads_pad_correctly() {
        let data = vec![0x00, 0x11, 0x22, 0x33];
        let reader = MockReader::new(data, true);
        let sym = SAlign::new(&reader, 4, 0x0402, 0).unwrap();

        assert_eq!(sym.length(), 4);
        assert_eq!(sym.symbol_type(), 0x0402);
        assert_eq!(sym.pad, vec![0x00, 0x11, 0x22, 0x33]);
    }

    #[test]
    fn is_eot_true_for_all_ff() {
        let data = vec![0xff, 0xff, 0xff];
        let reader = MockReader::new(data, true);
        let sym = SAlign::new(&reader, 3, 0x0402, 0).unwrap();

        assert!(sym.is_eot());
    }

    #[test]
    fn is_eot_true_for_single_ff() {
        let data = vec![0xff];
        let reader = MockReader::new(data, true);
        let sym = SAlign::new(&reader, 1, 0x0402, 0).unwrap();

        assert!(sym.is_eot());
    }

    #[test]
    fn is_eot_false_when_mixed_bytes() {
        let data = vec![0xff, 0x00, 0xff];
        let reader = MockReader::new(data, true);
        let sym = SAlign::new(&reader, 3, 0x0402, 0).unwrap();

        assert!(!sym.is_eot());
    }

    #[test]
    fn is_eot_false_when_single_non_ff() {
        let data = vec![0x00];
        let reader = MockReader::new(data, true);
        let sym = SAlign::new(&reader, 1, 0x0402, 0).unwrap();

        assert!(!sym.is_eot());
    }

    #[test]
    fn incorrect_type_returns_error() {
        let data = vec![0x00, 0x11];
        let reader = MockReader::new(data, true);
        let result = SAlign::new(&reader, 2, 0x9999u16 as i16, 0);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn empty_pad() {
        let data = vec![];
        let reader = MockReader::new(data, true);
        let sym = SAlign::new(&reader, 0, 0x0402, 0).unwrap();

        assert_eq!(sym.pad, Vec::<u8>::new());
        assert!(sym.is_eot());
    }

    #[test]
    fn trait_object_dispatch() {
        let data = vec![0xff, 0xff];
        let reader = MockReader::new(data, true);
        let sym: Box<dyn DebugSymbol> = Box::new(SAlign::new(&reader, 2, 0x0402, 0).unwrap());

        assert_eq!(sym.length(), 2);
        assert_eq!(sym.symbol_type(), 0x0402);
        assert_eq!(sym.name(), "");
        assert_eq!(sym.section(), 0);
        assert_eq!(sym.offset(), 0);
    }

    #[test]
    fn clone_equality() {
        let data = vec![0x01, 0x02, 0x03];
        let reader = MockReader::new(data, true);
        let sym = SAlign::new(&reader, 3, 0x0402, 0).unwrap();
        let cloned = sym.clone();

        assert_eq!(sym, cloned);
    }

    #[test]
    fn negative_length_preserved() {
        let data = vec![0x00];
        let reader = MockReader::new(data, true);
        let sym = SAlign::new(&reader, -1, 0x0402, 0).unwrap();

        assert_eq!(sym.length(), -1);
    }
}

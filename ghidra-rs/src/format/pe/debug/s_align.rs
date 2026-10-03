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
        reader: &BinaryReader,
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


    #[test]
    fn new_reads_pad_correctly() {
        let data = vec![0x00, 0x11, 0x22, 0x33];
        let reader = BinaryReader::from_bytes(data, true);
        let sym = SAlign::new(&reader, 4, 0x0402, 0).unwrap();

        assert_eq!(sym.length(), 4);
        assert_eq!(sym.symbol_type(), 0x0402);
        assert_eq!(sym.pad, vec![0x00, 0x11, 0x22, 0x33]);
    }

    #[test]
    fn is_eot_true_for_all_ff() {
        let data = vec![0xff, 0xff, 0xff];
        let reader = BinaryReader::from_bytes(data, true);
        let sym = SAlign::new(&reader, 3, 0x0402, 0).unwrap();

        assert!(sym.is_eot());
    }

    #[test]
    fn is_eot_true_for_single_ff() {
        let data = vec![0xff];
        let reader = BinaryReader::from_bytes(data, true);
        let sym = SAlign::new(&reader, 1, 0x0402, 0).unwrap();

        assert!(sym.is_eot());
    }

    #[test]
    fn is_eot_false_when_mixed_bytes() {
        let data = vec![0xff, 0x00, 0xff];
        let reader = BinaryReader::from_bytes(data, true);
        let sym = SAlign::new(&reader, 3, 0x0402, 0).unwrap();

        assert!(!sym.is_eot());
    }

    #[test]
    fn is_eot_false_when_single_non_ff() {
        let data = vec![0x00];
        let reader = BinaryReader::from_bytes(data, true);
        let sym = SAlign::new(&reader, 1, 0x0402, 0).unwrap();

        assert!(!sym.is_eot());
    }

    #[test]
    fn incorrect_type_returns_error() {
        let data = vec![0x00, 0x11];
        let reader = BinaryReader::from_bytes(data, true);
        let result = SAlign::new(&reader, 2, 0x9999u16 as i16, 0);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn empty_pad() {
        let data = vec![];
        let reader = BinaryReader::from_bytes(data, true);
        let sym = SAlign::new(&reader, 0, 0x0402, 0).unwrap();

        assert_eq!(sym.pad, Vec::<u8>::new());
        assert!(sym.is_eot());
    }

    #[test]
    fn trait_object_dispatch() {
        let data = vec![0xff, 0xff];
        let reader = BinaryReader::from_bytes(data, true);
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
        let reader = BinaryReader::from_bytes(data, true);
        let sym = SAlign::new(&reader, 3, 0x0402, 0).unwrap();
        let cloned = sym.clone();

        assert_eq!(sym, cloned);
    }

    #[test]
    fn negative_length_preserved() {
        let data = vec![0x00];
        let reader = BinaryReader::from_bytes(data, true);
        let sym = SAlign::new(&reader, -1, 0x0402, 0).unwrap();

        assert_eq!(sym.length(), -1);
    }
}

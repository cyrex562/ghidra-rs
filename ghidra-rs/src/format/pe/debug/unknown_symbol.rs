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
        reader: &BinaryReader,
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


    #[test]
    fn new_reads_unknown_bytes_correctly() {
        let data = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let reader = BinaryReader::from_bytes(data.clone(), true);
        let sym = UnknownSymbol::new(&reader, 5, 0x1234, 0).unwrap();

        assert_eq!(sym.length(), 5);
        assert_eq!(sym.symbol_type(), 0x1234);
        assert_eq!(sym.unknown(), &[0x01, 0x02, 0x03, 0x04, 0x05][..]);
    }

    #[test]
    fn new_at_nonzero_offset() {
        let mut data = vec![0xFF, 0xFF];
        data.extend_from_slice(&[0xAA, 0xBB, 0xCC]);
        let reader = BinaryReader::from_bytes(data, true);
        let sym = UnknownSymbol::new(&reader, 3, 0x5678, 2).unwrap();

        assert_eq!(sym.length(), 3);
        assert_eq!(sym.symbol_type(), 0x5678);
        assert_eq!(sym.unknown(), &[0xAA, 0xBB, 0xCC][..]);
    }

    #[test]
    fn empty_unknown_bytes() {
        let data = vec![];
        let reader = BinaryReader::from_bytes(data, true);
        let sym = UnknownSymbol::new(&reader, 0, 0x0000, 0).unwrap();

        assert_eq!(sym.length(), 0);
        assert_eq!(sym.symbol_type(), 0x0000);
        assert_eq!(sym.unknown(), &[] as &[u8]);
    }

    #[test]
    fn single_byte() {
        let data = vec![0x42];
        let reader = BinaryReader::from_bytes(data, true);
        let sym = UnknownSymbol::new(&reader, 1, 0x9999u16 as i16, 0).unwrap();

        assert_eq!(sym.length(), 1);
        assert_eq!(sym.unknown(), &[0x42][..]);
    }

    #[test]
    fn large_byte_array() {
        let data: Vec<u8> = (0..256).map(|i| (i % 256) as u8).collect();
        let reader = BinaryReader::from_bytes(data.clone(), true);
        let sym = UnknownSymbol::new(&reader, 256, 0x0001, 0).unwrap();

        assert_eq!(sym.length(), 256);
        assert_eq!(sym.unknown(), &data[..]);
    }

    #[test]
    fn trait_object_dispatch() {
        let data = vec![0x10, 0x20, 0x30];
        let reader = BinaryReader::from_bytes(data, true);
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
        let reader = BinaryReader::from_bytes(data, true);
        let sym = UnknownSymbol::new(&reader, 4, 0x0042, 0).unwrap();
        let cloned = sym.clone();

        assert_eq!(sym, cloned);
    }

    #[test]
    fn read_error_propagates() {
        let data = vec![0x01, 0x02];
        let reader = BinaryReader::from_bytes(data, true);
        let result = UnknownSymbol::new(&reader, 10, 0x0000, 0);

        assert!(result.is_err());
    }
}

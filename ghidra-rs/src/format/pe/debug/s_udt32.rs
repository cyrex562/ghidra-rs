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
        reader: &BinaryReader,
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
        let reader = BinaryReader::from_bytes(data, true);
        let sym = SUdt32::new(&reader, 9, 0x1003, 0).unwrap();

        assert_eq!(sym.length(), 9);
        assert_eq!(sym.symbol_type(), 0x1003);
        assert_eq!(sym.checksum(), 0x1234_5678);
        assert_eq!(sym.name(), "test");
    }

    #[test]
    fn checksum_is_read_correctly() {
        let data = build_data(0xDEAD_BEEFu32 as i32, b"sym");
        let reader = BinaryReader::from_bytes(data, true);
        let sym = SUdt32::new(&reader, 8, 0x1003, 0).unwrap();

        assert_eq!(sym.checksum(), 0xDEAD_BEEFu32 as i32);
    }

    #[test]
    fn name_is_read_with_correct_length() {
        let data = build_data(100, b"mytype");
        let reader = BinaryReader::from_bytes(data, true);
        let sym = SUdt32::new(&reader, 11, 0x1003, 0).unwrap();

        assert_eq!(sym.name(), "mytype");
    }

    #[test]
    fn empty_name() {
        let data = build_data(0, b"");
        let reader = BinaryReader::from_bytes(data, true);
        let sym = SUdt32::new(&reader, 5, 0x1003, 0).unwrap();

        assert_eq!(sym.name(), "");
    }

    #[test]
    fn incorrect_type_returns_error() {
        let data = build_data(0, b"test");
        let reader = BinaryReader::from_bytes(data, true);
        let result = SUdt32::new(&reader, 9, 0x9999u16 as i16, 0);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn negative_checksum_preserved() {
        let data = build_data(-1234, b"neg");
        let reader = BinaryReader::from_bytes(data, true);
        let sym = SUdt32::new(&reader, 8, 0x1003, 0).unwrap();

        assert_eq!(sym.checksum(), -1234);
    }

    #[test]
    fn trait_object_dispatch() {
        let data = build_data(0xABCD_EF01u32 as i32, b"type");
        let reader = BinaryReader::from_bytes(data, true);
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
        let reader = BinaryReader::from_bytes(data, true);
        let sym = SUdt32::new(&reader, 10, 0x1003, 0).unwrap();
        let cloned = sym.clone();

        assert_eq!(sym, cloned);
    }

    #[test]
    fn negative_length_preserved() {
        let data = build_data(0, b"x");
        let reader = BinaryReader::from_bytes(data, true);
        let sym = SUdt32::new(&reader, -1, 0x1003, 0).unwrap();

        assert_eq!(sym.length(), -1);
    }
}

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
        reader: &BinaryReader,
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


    fn build_data() -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&0x12345678i32.to_le_bytes()); // symType
        data.push(4); // nameLen = 4
        data.extend_from_slice(b"test"); // name
        data
    }

    #[test]
    fn new_reads_fields_correctly() {
        let reader = BinaryReader::from_bytes(build_data(), true);
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

        let reader = BinaryReader::from_bytes(data, true);
        let sym = SUdt32New::new(&reader, 12, 0x1505, 0).unwrap();

        assert_eq!(sym.sym_type(), -1);
    }

    #[test]
    fn empty_name() {
        let mut data = Vec::new();
        data.extend_from_slice(&0u32.to_le_bytes());
        data.push(0); // nameLen = 0

        let reader = BinaryReader::from_bytes(data, true);
        let sym = SUdt32New::new(&reader, 5, 0x1505, 0).unwrap();

        assert_eq!(sym.name(), "");
    }

    #[test]
    fn name_is_read_as_fixed_length_string() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x11223344i32.to_le_bytes());
        data.push(6); // nameLen = 6
        data.extend_from_slice(b"symbol"); // name

        let reader = BinaryReader::from_bytes(data, true);
        let sym = SUdt32New::new(&reader, 15, 0x1505, 0).unwrap();

        assert_eq!(sym.name(), "symbol");
    }

    #[test]
    fn trait_object_dispatch() {
        let reader = BinaryReader::from_bytes(build_data(), true);
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
        let reader = BinaryReader::from_bytes(build_data(), true);
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

        let reader = BinaryReader::from_bytes(data, true);
        let sym = SUdt32New::new(&reader, 11, 0x1505, 0).unwrap();

        assert_eq!(sym.sym_type(), -0x12345678);
    }

    #[test]
    fn zero_sym_type() {
        let mut data = Vec::new();
        data.extend_from_slice(&0i32.to_le_bytes());
        data.push(3); // nameLen = 3
        data.extend_from_slice(b"udt");

        let reader = BinaryReader::from_bytes(data, true);
        let sym = SUdt32New::new(&reader, 12, 0x1505, 0).unwrap();

        assert_eq!(sym.sym_type(), 0);
        assert_eq!(sym.name(), "udt");
    }
}

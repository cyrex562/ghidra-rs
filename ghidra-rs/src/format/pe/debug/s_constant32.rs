use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;

use super::debug_symbol::{DebugSymbol, DebugSymbolBase};

/// Mirrors the `S_CONSTANT32` Java class in `ghidra.app.util.bin.format.pe.debug`.
///
/// A constant symbol (type `0x0201`) carrying only an unnamed constant value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SConstant32 {
    base: DebugSymbolBase,
}

impl SConstant32 {
    /// Creates a new `SConstant32` by reading from the given binary reader at the
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
        let _unknown1 = reader.read_int(offset)?;
        offset += 4;

        let _unknown2 = reader.read_short(offset)?;
        offset += 2;

        let name_len = reader.read_byte(offset)? as usize;
        offset += 1;

        base.name = reader.read_ascii_string_fixed(offset, name_len)?;

        Ok(SConstant32 { base })
    }
}

impl DebugSymbol for SConstant32 {
    fn length(&self) -> i16 {
        self.base.length()
    }

    fn symbol_type(&self) -> i16 {
        self.base.symbol_type()
    }

    fn name(&self) -> &str {
        &self.base.name
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
    fn new_reads_fields_correctly() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x1000_0000u32.to_le_bytes()); // unknown1
        data.extend_from_slice(&42i16.to_le_bytes()); // unknown2
        data.push(4); // nameLen = 4
        data.extend_from_slice(b"test"); // name

        let reader = BinaryReader::from_bytes(data, true);
        let sym = SConstant32::new(&reader, 15, 0x0201, 0).unwrap();

        assert_eq!(sym.length(), 15);
        assert_eq!(sym.symbol_type(), 0x0201);
        assert_eq!(sym.name(), "test");
    }

    #[test]
    fn empty_name_when_name_len_is_zero() {
        let mut data = Vec::new();
        data.extend_from_slice(&0_i32.to_le_bytes());
        data.extend_from_slice(&0i16.to_le_bytes());
        data.push(0); // nameLen = 0

        let reader = BinaryReader::from_bytes(data, true);
        let sym = SConstant32::new(&reader, 7, 0x0201, 0).unwrap();

        assert_eq!(sym.name(), "");
    }

    #[test]
    fn single_character_name() {
        let mut data = Vec::new();
        data.extend_from_slice(&100_i32.to_le_bytes());
        data.extend_from_slice(&50i16.to_le_bytes());
        data.push(1); // nameLen = 1
        data.extend_from_slice(b"x");

        let reader = BinaryReader::from_bytes(data, true);
        let sym = SConstant32::new(&reader, 8, 0x0201, 0).unwrap();

        assert_eq!(sym.name(), "x");
    }

    #[test]
    fn longer_name() {
        let mut data = Vec::new();
        data.extend_from_slice(&0_i32.to_le_bytes());
        data.extend_from_slice(&0i16.to_le_bytes());
        data.push(9); // nameLen = 9
        data.extend_from_slice(b"longnames");

        let reader = BinaryReader::from_bytes(data, true);
        let sym = SConstant32::new(&reader, 16, 0x0201, 0).unwrap();

        assert_eq!(sym.name(), "longnames");
    }

    #[test]
    fn trait_object_dispatch() {
        let mut data = Vec::new();
        data.extend_from_slice(&100_i32.to_le_bytes());
        data.extend_from_slice(&50i16.to_le_bytes());
        data.push(3); // nameLen = 3
        data.extend_from_slice(b"abc");

        let reader = BinaryReader::from_bytes(data, true);
        let sym: Box<dyn DebugSymbol> =
            Box::new(SConstant32::new(&reader, 12, 0x0201, 0).unwrap());

        assert_eq!(sym.length(), 12);
        assert_eq!(sym.symbol_type(), 0x0201);
        assert_eq!(sym.name(), "abc");
        assert_eq!(sym.section(), 0);
        assert_eq!(sym.offset(), 0);
    }

    #[test]
    fn clone_equality() {
        let mut data = Vec::new();
        data.extend_from_slice(&0_i32.to_le_bytes());
        data.extend_from_slice(&0i16.to_le_bytes());
        data.push(2); // nameLen = 2
        data.extend_from_slice(b"xy");

        let reader = BinaryReader::from_bytes(data, true);
        let sym = SConstant32::new(&reader, 9, 0x0201, 0).unwrap();
        let cloned = sym.clone();

        assert_eq!(sym, cloned);
    }

    #[test]
    fn negative_length_preserved() {
        let mut data = Vec::new();
        data.extend_from_slice(&0_i32.to_le_bytes());
        data.extend_from_slice(&0i16.to_le_bytes());
        data.push(0);

        let reader = BinaryReader::from_bytes(data, true);
        let sym = SConstant32::new(&reader, -1, 0x0201, 0).unwrap();

        assert_eq!(sym.length(), -1);
    }
}

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;

use super::debug_symbol::{DebugSymbol, DebugSymbolBase};

/// Represents a local data symbol (S_LDATA32_NEW) in CodeView format.
///
/// Mirrors the `S_LDATA32_NEW` Java class in `ghidra.app.util.bin.format.pe.debug`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SLdata32New {
    base: DebugSymbolBase,
    reserved: i32,
    padding: Vec<u8>,
}

impl SLdata32New {
    /// Creates a new `SLdata32New` by reading from the given binary reader at the
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

        let reserved = reader.read_int(offset)?;
        offset += 4;

        base.offset = reader.read_int(offset)?;
        offset += 4;

        base.section = reader.read_short(offset)?;
        offset += 2;

        let name_len = reader.read_byte(offset)? as usize;
        offset += 1;

        base.name = reader.read_ascii_string_fixed(offset, name_len)?;
        offset += name_len as u64;

        let size_of_padding = (length as usize).saturating_sub(13 + name_len);
        let padding = reader.read_byte_array(offset, size_of_padding)?;

        Ok(SLdata32New {
            base,
            reserved,
            padding,
        })
    }

    /// Returns the reserved field value.
    pub fn reserved(&self) -> i32 {
        self.reserved
    }

    /// Returns the padding bytes.
    pub fn padding(&self) -> &[u8] {
        &self.padding
    }
}

impl DebugSymbol for SLdata32New {
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
        data.extend_from_slice(&42i32.to_le_bytes()); // reserved
        data.extend_from_slice(&0x2000_0000u32.to_le_bytes()); // offset
        data.extend_from_slice(&3i16.to_le_bytes()); // section
        data.push(5); // nameLen = 5
        data.extend_from_slice(b"myvar"); // name
        data.extend_from_slice(&[0xAA, 0xBB, 0xCC]); // padding
        data
    }

    #[test]
    fn new_reads_fields_correctly() {
        let reader = BinaryReader::from_bytes(build_data(), true);
        let sym = SLdata32New::new(&reader, 21, 0x0003, 0).unwrap();

        assert_eq!(sym.length(), 21);
        assert_eq!(sym.symbol_type(), 0x0003);
        assert_eq!(sym.reserved(), 42);
        assert_eq!(sym.offset(), 0x2000_0000);
        assert_eq!(sym.section(), 3);
        assert_eq!(sym.name(), "myvar");
        assert_eq!(sym.padding(), &[0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn name_is_read_as_fixed_length_string() {
        let mut data = Vec::new();
        data.extend_from_slice(&100i32.to_le_bytes());
        data.extend_from_slice(&0x1000_0000i32.to_le_bytes());
        data.extend_from_slice(&1i16.to_le_bytes());
        data.push(4); // nameLen = 4
        data.extend_from_slice(b"test");
        data.extend_from_slice(&[0xDD, 0xEE]); // padding

        let reader = BinaryReader::from_bytes(data, true);
        let sym = SLdata32New::new(&reader, 19, 0x0003, 0).unwrap();

        assert_eq!(sym.name(), "test");
        assert_eq!(sym.padding(), &[0xDD, 0xEE]);
    }

    #[test]
    fn empty_name() {
        let mut data = Vec::new();
        data.extend_from_slice(&0i32.to_le_bytes());
        data.extend_from_slice(&0i32.to_le_bytes());
        data.extend_from_slice(&0i16.to_le_bytes());
        data.push(0); // nameLen = 0
        data.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55]);

        let reader = BinaryReader::from_bytes(data, true);
        let sym = SLdata32New::new(&reader, 18, 0x0003, 0).unwrap();

        assert_eq!(sym.name(), "");
        assert_eq!(sym.padding(), &[0x11, 0x22, 0x33, 0x44, 0x55]);
    }

    #[test]
    fn padding_calculation_matches_java_logic() {
        let mut data = Vec::new();
        data.extend_from_slice(&50i32.to_le_bytes());
        data.extend_from_slice(&0x3000_0000i32.to_le_bytes());
        data.extend_from_slice(&2i16.to_le_bytes());
        data.push(6); // nameLen = 6
        data.extend_from_slice(b"foobar");
        data.extend_from_slice(&[0xFF, 0x00, 0xFF]);

        let reader = BinaryReader::from_bytes(data, true);
        let sym = SLdata32New::new(&reader, 22, 0x0003, 0).unwrap();

        let name_len = 6;
        let expected_padding_size = 22 - 13 - name_len;
        assert_eq!(expected_padding_size, 3);
        assert_eq!(sym.padding().len(), 3);
        assert_eq!(sym.padding(), &[0xFF, 0x00, 0xFF]);
    }

    #[test]
    fn no_padding_when_exact_size() {
        let mut data = Vec::new();
        data.extend_from_slice(&0i32.to_le_bytes());
        data.extend_from_slice(&0i32.to_le_bytes());
        data.extend_from_slice(&0i16.to_le_bytes());
        data.push(3); // nameLen = 3
        data.extend_from_slice(b"xyz");

        let reader = BinaryReader::from_bytes(data, true);
        let sym = SLdata32New::new(&reader, 16, 0x0003, 0).unwrap();

        assert_eq!(sym.padding().len(), 0);
    }

    #[test]
    fn trait_object_dispatch() {
        let reader = BinaryReader::from_bytes(build_data(), true);
        let sym: Box<dyn DebugSymbol> =
            Box::new(SLdata32New::new(&reader, 21, 0x0003, 0).unwrap());

        assert_eq!(sym.length(), 21);
        assert_eq!(sym.symbol_type(), 0x0003);
        assert_eq!(sym.offset(), 0x2000_0000);
        assert_eq!(sym.section(), 3);
        assert_eq!(sym.name(), "myvar");
    }

    #[test]
    fn clone_equality() {
        let reader = BinaryReader::from_bytes(build_data(), true);
        let sym = SLdata32New::new(&reader, 21, 0x0003, 0).unwrap();
        let cloned = sym.clone();

        assert_eq!(sym, cloned);
    }

    #[test]
    fn negative_reserved_preserved() {
        let mut data = Vec::new();
        data.extend_from_slice(&(-1i32).to_le_bytes());
        data.extend_from_slice(&100i32.to_le_bytes());
        data.extend_from_slice(&1i16.to_le_bytes());
        data.push(2); // nameLen = 2
        data.extend_from_slice(b"ab");
        data.extend_from_slice(&[0x99]);

        let reader = BinaryReader::from_bytes(data, true);
        let sym = SLdata32New::new(&reader, 16, 0x0003, 0).unwrap();

        assert_eq!(sym.reserved(), -1);
    }

    #[test]
    fn negative_offset_preserved() {
        let mut data = Vec::new();
        data.extend_from_slice(&0i32.to_le_bytes());
        data.extend_from_slice(&(-500i32).to_le_bytes());
        data.extend_from_slice(&2i16.to_le_bytes());
        data.push(1); // nameLen = 1
        data.extend_from_slice(b"x");
        data.extend_from_slice(&[0x77]);

        let reader = BinaryReader::from_bytes(data, true);
        let sym = SLdata32New::new(&reader, 15, 0x0003, 0).unwrap();

        assert_eq!(sym.offset(), -500);
    }
}

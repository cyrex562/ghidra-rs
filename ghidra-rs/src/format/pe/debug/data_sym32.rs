use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;

use super::debug_symbol::{DebugSymbol, DebugSymbolBase};

/// Represents a PE debug data symbol (S_LDATA32, S_GDATA32, or S_PUB32).
///
/// Mirrors the `DataSym32` Java class in `ghidra.app.util.bin.format.pe.debug`.
///
/// ```text
/// typedef struct DATASYM32 {
///     unsigned short  reclen;         // Record length
///     unsigned short  rectyp;         // S_LDATA32, S_GDATA32 or S_PUB32
///     CV_uoff32_t     off;            // (unsigned long)
///     unsigned short  seg;
///     CV_typ_t        typind;         // Type index (unsigned short)
///     unsigned char   name[1];        // Length-prefixed name
/// } DATASYM32;
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataSym32 {
    base: DebugSymbolBase,
    type_index: i16,
    name_char: u8,
}

impl DataSym32 {
    /// Creates a new `DataSym32` by reading from the given binary reader at the
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
        base.offset = reader.read_int(offset)? as i32;
        offset += 4;

        base.section = reader.read_short(offset)?;
        offset += 2;

        let type_index = reader.read_short(offset)?;
        offset += 2;

        let name_char = reader.read_byte(offset)?;
        offset += 1;

        base.name = reader.read_ascii_string(offset)?;

        Ok(DataSym32 {
            base,
            type_index,
            name_char,
        })
    }

    /// Returns the type index.
    pub fn type_index(&self) -> i16 {
        self.type_index
    }

    /// Returns the name character (the length prefix of the name).
    pub fn name_char(&self) -> u8 {
        self.name_char
    }
}

impl DebugSymbol for DataSym32 {
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
    fn new_reads_fields_correctly() {
        // Build test data: offset (i32), section (i16), type_index (i16), name_char (u8), name (null-terminated)
        let mut data = Vec::new();
        data.extend_from_slice(&0x0000_1000u32.to_le_bytes()); // offset = 0x00001000
        data.extend_from_slice(&2i16.to_le_bytes()); // section = 2
        data.extend_from_slice(&5i16.to_le_bytes()); // type_index = 5
        data.push(0x74); // name_char = 't' (first byte, stored but not used as length)
        data.extend_from_slice(b"est\0"); // name = "est\0" (null-terminated)

        let reader = BinaryReader::from_bytes(data, true);
        let sym = DataSym32::new(&reader, 20, 0x0011, 0).unwrap();

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
        data.extend_from_slice(&0_i32.to_le_bytes()); // offset
        data.extend_from_slice(&1i16.to_le_bytes()); // section
        data.extend_from_slice(&10i16.to_le_bytes()); // type_index
        data.push(0x68); // name_char = 'h' (first byte, stored separately)
        data.extend_from_slice(b"ello\0"); // name = "ello\0" (null-terminated)
        data.extend_from_slice(b"extra"); // extra data that shouldn't be read

        let reader = BinaryReader::from_bytes(data, true);
        let sym = DataSym32::new(&reader, 18, 0x1234, 0).unwrap();

        assert_eq!(sym.name(), "ello");
        assert_eq!(sym.name_char(), 0x68);
    }

    #[test]
    fn offset_is_read_as_i32() {
        let mut data = Vec::new();
        data.extend_from_slice(&0xDEADBEEFu32.to_le_bytes());
        data.extend_from_slice(&0i16.to_le_bytes());
        data.extend_from_slice(&0i16.to_le_bytes());
        data.push(0); // name_char
        data.push(0); // null terminator for name

        let reader = BinaryReader::from_bytes(data, true);
        let sym = DataSym32::new(&reader, 10, 0, 0).unwrap();

        assert_eq!(sym.offset(), 0xDEADBEEFu32 as i32);
    }

    #[test]
    fn trait_object_dispatch() {
        let mut data = Vec::new();
        data.extend_from_slice(&1000_i32.to_le_bytes());
        data.extend_from_slice(&3i16.to_le_bytes());
        data.extend_from_slice(&7i16.to_le_bytes());
        data.push(0x61); // name_char = 'a'
        data.extend_from_slice(b"b\0");

        let reader = BinaryReader::from_bytes(data, true);
        let sym: Box<dyn DebugSymbol> = Box::new(DataSym32::new(&reader, 15, 0x42, 0).unwrap());

        assert_eq!(sym.length(), 15);
        assert_eq!(sym.symbol_type(), 0x42);
        assert_eq!(sym.offset(), 1000);
        assert_eq!(sym.section(), 3);
        assert_eq!(sym.name(), "b");
    }

    #[test]
    fn empty_name_when_immediately_null_terminated() {
        let mut data = Vec::new();
        data.extend_from_slice(&0_i32.to_le_bytes());
        data.extend_from_slice(&0i16.to_le_bytes());
        data.extend_from_slice(&0i16.to_le_bytes());
        data.push(0); // name_char = 0 (null byte, could be the length or start of name)
        data.push(0); // null terminator

        let reader = BinaryReader::from_bytes(data, true);
        let sym = DataSym32::new(&reader, 8, 0, 0).unwrap();

        assert_eq!(sym.name(), "");
        assert_eq!(sym.name_char(), 0);
    }

    #[test]
    fn clone_equality() {
        let mut data = Vec::new();
        data.extend_from_slice(&512_i32.to_le_bytes());
        data.extend_from_slice(&4i16.to_le_bytes());
        data.extend_from_slice(&12i16.to_le_bytes());
        data.push(0x73); // name_char = 's'
        data.extend_from_slice(b"ym\0");

        let reader = BinaryReader::from_bytes(data, true);
        let sym = DataSym32::new(&reader, 16, 0x11, 0).unwrap();
        let cloned = sym.clone();

        assert_eq!(sym, cloned);
    }
}

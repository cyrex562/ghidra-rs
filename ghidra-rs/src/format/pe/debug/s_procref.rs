use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;

use super::debug_symbol::{DebugSymbol, DebugSymbolBase};

/// Mirrors the `S_PROCREF` Java class in `ghidra.app.util.bin.format.pe.debug`.
///
/// A procedure reference symbol (type `0x0400`) that contains a checksum, module
/// index, and (when the checksum is zero) an inline name padded to a 4/8/16-byte
/// boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SProcref {
    base: DebugSymbolBase,
    module: i32,
    checksum: i32,
    padding_len: i32,
}

impl SProcref {
    /// Creates a new `SProcref` by reading from the given binary reader at the
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
    /// Returns an `io::Error` if reading from the reader fails.
    pub fn new(
        reader: &BinaryReader,
        length: i16,
        symbol_type: i16,
        ptr: u64,
    ) -> io::Result<Self> {
        let mut base = DebugSymbolBase::default();
        base.process_debug_symbol(length, symbol_type);

        let mut offset = ptr;

        let checksum = reader.read_int(offset)?;
        offset += 4;

        base.offset = reader.read_int(offset)?;
        offset += 4;

        let module = reader.read_int(offset)?;
        offset += 4;

        let mut padding_len = 0i32;

        if checksum == 0 {
            let name_len = reader.read_byte(offset)?;
            offset += 1;

            base.name = reader.read_ascii_string_fixed(offset, name_len as usize)?;
            offset += name_len as u64;

            let val = offset & 0xf;

            padding_len = match val {
                0x1..=0x3 => 0x4 - val as i32,
                0x5..=0x7 => 0x8 - val as i32,
                0x9..=0xb => 0xc - val as i32,
                0xd..=0xf => 0x10 - val as i32,
                _ => 0,
            };
        }

        Ok(SProcref {
            base,
            module,
            checksum,
            padding_len,
        })
    }

    /// Returns the module index.
    pub fn module(&self) -> i32 {
        self.module
    }

    /// Returns the checksum value.
    pub fn checksum(&self) -> i32 {
        self.checksum
    }
}

impl DebugSymbol for SProcref {
    fn length(&self) -> i16 {
        let mut len = self.base.length();
        if self.checksum == 0 {
            len += 1 + self.base.name().len() as i16 + self.padding_len as i16;
        }
        len
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
    fn new_reads_fields_correctly_when_checksum_nonzero() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x1000_0000i32.to_le_bytes()); // checksum
        data.extend_from_slice(&0x2000_0000i32.to_le_bytes()); // offset
        data.extend_from_slice(&0x3000_0000i32.to_le_bytes()); // module

        let reader = BinaryReader::from_bytes(data, true);
        let sym = SProcref::new(&reader, 12, 0x0400, 0).unwrap();

        assert_eq!(sym.length(), 12);
        assert_eq!(sym.symbol_type(), 0x0400);
        assert_eq!(sym.checksum(), 0x1000_0000);
        assert_eq!(sym.offset(), 0x2000_0000);
        assert_eq!(sym.module(), 0x3000_0000);
        assert_eq!(sym.name(), "");
    }

    #[test]
    fn reads_inline_name_when_checksum_zero() {
        let mut data = Vec::new();
        data.extend_from_slice(&0_i32.to_le_bytes()); // checksum == 0
        data.extend_from_slice(&0x2000_0000i32.to_le_bytes()); // offset
        data.extend_from_slice(&7_i32.to_le_bytes()); // module
        data.push(3); // name length
        data.extend_from_slice(b"abc"); // name
        data.extend_from_slice(&[0u8; 8]); // extra padding room

        let reader = BinaryReader::from_bytes(data, true);
        let sym = SProcref::new(&reader, 20, 0x0400, 0).unwrap();

        assert_eq!(sym.checksum(), 0);
        assert_eq!(sym.module(), 7);
        assert_eq!(sym.name(), "abc");
        // ptr after name = 4 + 4 + 4 + 1 + 3 = 16, 16 & 0xf == 0 -> no padding
        assert_eq!(sym.length(), 20 + 1 + 3);
    }

    #[test]
    fn padding_len_computed_for_unaligned_name_end() {
        let mut data = Vec::new();
        data.extend_from_slice(&0_i32.to_le_bytes()); // checksum == 0
        data.extend_from_slice(&0_i32.to_le_bytes()); // offset
        data.extend_from_slice(&0_i32.to_le_bytes()); // module
        data.push(2); // name length
        data.extend_from_slice(b"ab"); // name
        data.extend_from_slice(&[0u8; 8]); // extra padding room

        let reader = BinaryReader::from_bytes(data, true);
        let sym = SProcref::new(&reader, 15, 0x0400, 0).unwrap();

        // ptr after name = 4 + 4 + 4 + 1 + 2 = 15, 15 & 0xf == 0xf -> padding = 0x10 - 0xf = 1
        assert_eq!(sym.name(), "ab");
        assert_eq!(sym.length(), 15 + 1 + 2 + 1);
    }

    #[test]
    fn negative_checksum_preserved() {
        let mut data = Vec::new();
        data.extend_from_slice(&(-1234_i32).to_le_bytes());
        data.extend_from_slice(&0_i32.to_le_bytes());
        data.extend_from_slice(&0_i32.to_le_bytes());

        let reader = BinaryReader::from_bytes(data, true);
        let sym = SProcref::new(&reader, 12, 0x0400, 0).unwrap();

        assert_eq!(sym.checksum(), -1234);
    }

    #[test]
    fn negative_offset_and_module_preserved() {
        let mut data = Vec::new();
        data.extend_from_slice(&1_i32.to_le_bytes());
        data.extend_from_slice(&(-5000_i32).to_le_bytes());
        data.extend_from_slice(&(-42_i32).to_le_bytes());

        let reader = BinaryReader::from_bytes(data, true);
        let sym = SProcref::new(&reader, 12, 0x0400, 0).unwrap();

        assert_eq!(sym.offset(), -5000);
        assert_eq!(sym.module(), -42);
    }

    #[test]
    fn trait_object_dispatch() {
        let mut data = Vec::new();
        data.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        data.extend_from_slice(&0x1234_5678i32.to_le_bytes());
        data.extend_from_slice(&99_i32.to_le_bytes());

        let reader = BinaryReader::from_bytes(data, true);
        let sym: Box<dyn DebugSymbol> = Box::new(SProcref::new(&reader, 12, 0x0400, 0).unwrap());

        assert_eq!(sym.length(), 12);
        assert_eq!(sym.symbol_type(), 0x0400);
        assert_eq!(sym.offset(), 0x1234_5678);
    }

    #[test]
    fn clone_equality() {
        let mut data = Vec::new();
        data.extend_from_slice(&111_i32.to_le_bytes());
        data.extend_from_slice(&222_i32.to_le_bytes());
        data.extend_from_slice(&333_i32.to_le_bytes());

        let reader = BinaryReader::from_bytes(data, true);
        let sym = SProcref::new(&reader, 12, 0x0400, 0).unwrap();
        let cloned = sym.clone();

        assert_eq!(sym, cloned);
    }

    #[test]
    fn negative_length_preserved() {
        let mut data = Vec::new();
        data.extend_from_slice(&1_i32.to_le_bytes());
        data.extend_from_slice(&0_i32.to_le_bytes());
        data.extend_from_slice(&0_i32.to_le_bytes());

        let reader = BinaryReader::from_bytes(data, true);
        let sym = SProcref::new(&reader, -1, 0x0400, 0).unwrap();

        assert_eq!(sym.length(), -1);
    }
}

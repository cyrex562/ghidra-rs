use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;

use super::debug_symbol::{DebugSymbol, DebugSymbolBase};

/// Represents an object name symbol (S_OBJNAME) in CodeView format.
///
/// Mirrors the `S_OBJNAME` Java class in `ghidra.app.util.bin.format.pe.debug`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SObjname {
    base: DebugSymbolBase,
    signature: i32,
    name_len: u8,
    padding: Vec<u8>,
}

impl SObjname {
    /// Creates a new `SObjname` by reading from the given binary reader at the
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

        let signature = reader.read_int(offset)?;
        offset += 4;

        let name_len = reader.read_byte(offset)?;
        offset += 1;

        base.name = reader.read_ascii_string_fixed(offset, name_len as usize)?;
        offset += (name_len as u64) + 1;

        let size_of_padding = 2 + 4 + 4 + 4 + 1 + (name_len as usize) + 1;
        let padding = reader.read_byte_array(offset, size_of_padding)?;

        Ok(SObjname {
            base,
            signature,
            name_len,
            padding,
        })
    }

    /// Returns the signature value.
    pub fn signature(&self) -> i32 {
        self.signature
    }

    /// Returns the name length.
    pub fn name_len(&self) -> u8 {
        self.name_len
    }

    /// Returns the padding bytes.
    pub fn padding(&self) -> &[u8] {
        &self.padding
    }
}

impl DebugSymbol for SObjname {
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
        data.extend_from_slice(&0x12345678i32.to_le_bytes()); // signature
        data.push(4); // nameLen = 4
        data.extend_from_slice(b"test"); // name
        data.push(0); // null terminator or padding
        // padding: 2 + 4 + 4 + 4 + 1 + 4 + 1 = 20 bytes
        data.extend_from_slice(&[0xAA; 20]);
        data
    }

    #[test]
    fn new_reads_fields_correctly() {
        let reader = BinaryReader::from_bytes(build_data(), true);
        let sym = SObjname::new(&reader, 32, 0x1101, 0).unwrap();

        assert_eq!(sym.length(), 32);
        assert_eq!(sym.symbol_type(), 0x1101);
        assert_eq!(sym.signature(), 0x12345678);
        assert_eq!(sym.name_len(), 4);
        assert_eq!(sym.name(), "test");
        assert_eq!(sym.padding().len(), 20);
    }

    #[test]
    fn signature_is_read_correctly() {
        let mut data = Vec::new();
        data.extend_from_slice(&(-1i32).to_le_bytes()); // signature = -1
        data.push(3); // nameLen = 3
        data.extend_from_slice(b"obj"); // name
        data.push(0);
        data.extend_from_slice(&[0x00; 20]);

        let reader = BinaryReader::from_bytes(data, true);
        let sym = SObjname::new(&reader, 32, 0x1101, 0).unwrap();

        assert_eq!(sym.signature(), -1);
    }

    #[test]
    fn empty_name() {
        let mut data = Vec::new();
        data.extend_from_slice(&0u32.to_le_bytes());
        data.push(0); // nameLen = 0
        data.push(0); // null terminator
        data.extend_from_slice(&[0xFF; 20]);

        let reader = BinaryReader::from_bytes(data, true);
        let sym = SObjname::new(&reader, 26, 0x1101, 0).unwrap();

        assert_eq!(sym.name_len(), 0);
        assert_eq!(sym.name(), "");
        assert_eq!(sym.padding().len(), 16);
    }

    #[test]
    fn name_is_read_as_fixed_length_string() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x11223344i32.to_le_bytes());
        data.push(6); // nameLen = 6
        data.extend_from_slice(b"module"); // name
        data.push(0);
        data.extend_from_slice(&[0x99; 22]);

        let reader = BinaryReader::from_bytes(data, true);
        let sym = SObjname::new(&reader, 33, 0x1101, 0).unwrap();

        assert_eq!(sym.name(), "module");
        assert_eq!(sym.name_len(), 6);
    }

    #[test]
    fn trait_object_dispatch() {
        let reader = BinaryReader::from_bytes(build_data(), true);
        let sym: Box<dyn DebugSymbol> =
            Box::new(SObjname::new(&reader, 32, 0x1101, 0).unwrap());

        assert_eq!(sym.length(), 32);
        assert_eq!(sym.symbol_type(), 0x1101);
        assert_eq!(sym.offset(), 0);
        assert_eq!(sym.section(), 0);
        assert_eq!(sym.name(), "test");
    }

    #[test]
    fn clone_equality() {
        let reader = BinaryReader::from_bytes(build_data(), true);
        let sym = SObjname::new(&reader, 32, 0x1101, 0).unwrap();
        let cloned = sym.clone();

        assert_eq!(sym, cloned);
    }

    #[test]
    fn padding_size_calculation() {
        let mut data = Vec::new();
        data.extend_from_slice(&0i32.to_le_bytes());
        data.push(5); // nameLen = 5
        data.extend_from_slice(b"hello");
        data.push(0);
        // Expected padding size = 2 + 4 + 4 + 4 + 1 + 5 + 1 = 21
        data.extend_from_slice(&[0xDD; 21]);

        let reader = BinaryReader::from_bytes(data, true);
        let sym = SObjname::new(&reader, 36, 0x1101, 0).unwrap();

        assert_eq!(sym.name_len(), 5);
        assert_eq!(sym.name(), "hello");
        assert_eq!(sym.padding().len(), 21);
    }

    #[test]
    fn negative_signature_preserved() {
        let mut data = Vec::new();
        data.extend_from_slice(&(-0x12345678i32).to_le_bytes());
        data.push(2); // nameLen = 2
        data.extend_from_slice(b"xy");
        data.push(0);
        data.extend_from_slice(&[0x11; 20]);

        let reader = BinaryReader::from_bytes(data, true);
        let sym = SObjname::new(&reader, 28, 0x1101, 0).unwrap();

        assert_eq!(sym.signature(), -0x12345678);
    }
}

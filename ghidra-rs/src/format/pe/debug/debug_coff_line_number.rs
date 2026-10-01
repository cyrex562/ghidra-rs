use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;

/// Represents the COFF Line number data structure.
///
/// Mirrors the `DebugCOFFLineNumber` Java class in
/// `ghidra.app.util.bin.format.pe.debug`.
///
/// ```text
/// typedef struct _IMAGE_LINENUMBER {
///    union {
///        DWORD   SymbolTableIndex; // Symbol table index of function name if Linenumber is 0.
///        DWORD   VirtualAddress;   // Virtual address of line number.
///    } Type;
///    WORD    Linenumber;           // Line number.
/// } IMAGE_LINENUMBER;
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DebugCOFFLineNumber {
    /// Symbol table index of function name, if line_number is 0.
    /// Shares storage with `virtual_address` (union in C).
    symbol_table_index: u32,
    /// Virtual address of line number.
    /// Shares storage with `symbol_table_index` (union in C).
    virtual_address: u32,
    /// Line number.
    line_number: u32,
}

impl DebugCOFFLineNumber {
    /// The size of the `IMAGE_LINENUMBER` structure, in bytes.
    pub const IMAGE_SIZEOF_LINENUMBER: usize = 6;

    /// Creates a new `DebugCOFFLineNumber` by reading from the given binary reader at the
    /// specified index, mirroring the Java constructor.
    ///
    /// # Arguments
    ///
    /// * `reader` - A binary reader positioned at the structure's data.
    /// * `index` - The starting byte offset in the reader.
    ///
    /// # Errors
    ///
    /// Returns an `io::Result::Err` if reading from the reader fails.
    pub fn new(reader: &BinaryReader, index: u64) -> io::Result<Self> {
        let symbol_table_index = reader.read_int(index)? as u32;
        let virtual_address = reader.read_int(index)? as u32;
        let line_number = reader.read_short(index + 4)? as u16 as u32;

        Ok(DebugCOFFLineNumber {
            symbol_table_index,
            virtual_address,
            line_number,
        })
    }

    /// Returns the symbol table index of function name, if line number is 0.
    pub fn symbol_table_index(&self) -> u32 {
        self.symbol_table_index
    }

    /// Returns the virtual address of the line number.
    pub fn virtual_address(&self) -> u32 {
        self.virtual_address
    }

    /// Returns the line number.
    pub fn line_number(&self) -> u32 {
        self.line_number
    }
}

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn read_structure_little_endian() {
        let data = vec![
            0x12, 0x34, 0x56, 0x78, // Union: either 0x78563412 (LE) or 0x12345678 (BE)
            0xAB, 0xCD,             // Line number: 0xCDAB in LE, 0xABCD in BE
        ];

        let reader = BinaryReader::from_bytes(data, true);
        let line_num = DebugCOFFLineNumber::new(&reader, 0).expect("failed to read");

        assert_eq!(line_num.symbol_table_index(), 0x78563412);
        assert_eq!(line_num.virtual_address(), 0x78563412);
        assert_eq!(line_num.line_number(), 0xCDAB);
    }

    #[test]
    fn structure_size_is_6_bytes() {
        assert_eq!(DebugCOFFLineNumber::IMAGE_SIZEOF_LINENUMBER, 6);
    }

    #[test]
    fn union_fields_match() {
        let data = vec![0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x01];
        let reader = BinaryReader::from_bytes(data, true);
        let line_num = DebugCOFFLineNumber::new(&reader, 0).expect("failed to read");

        assert_eq!(line_num.symbol_table_index(), 0xFFFFFFFF);
        assert_eq!(line_num.virtual_address(), 0xFFFFFFFF);
    }

    #[test]
    fn zero_values() {
        let data = vec![0, 0, 0, 0, 0, 0];
        let reader = BinaryReader::from_bytes(data, true);
        let line_num = DebugCOFFLineNumber::new(&reader, 0).expect("failed to read");

        assert_eq!(line_num.symbol_table_index(), 0);
        assert_eq!(line_num.virtual_address(), 0);
        assert_eq!(line_num.line_number(), 0);
    }

    #[test]
    fn read_at_non_zero_offset() {
        let data = vec![
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Padding
            0x11, 0x22, 0x33, 0x44,             // Union at offset 6
            0x55, 0x66,                         // Line number at offset 10
        ];

        let reader = BinaryReader::from_bytes(data, true);
        let line_num = DebugCOFFLineNumber::new(&reader, 6).expect("failed to read");

        assert_eq!(line_num.symbol_table_index(), 0x44332211);
        assert_eq!(line_num.line_number(), 0x6655);
    }

    #[test]
    fn unsigned_short_conversion() {
        let data = vec![
            0x00, 0x00, 0x00, 0x00, // Union
            0xFF, 0xFF,             // Line number: 0xFFFF as u16 -> 0x0000FFFF as u32
        ];

        let reader = BinaryReader::from_bytes(data, true);
        let line_num = DebugCOFFLineNumber::new(&reader, 0).expect("failed to read");

        assert_eq!(line_num.line_number(), 0xFFFF);
    }

    #[test]
    fn clone_equality() {
        let data = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let reader = BinaryReader::from_bytes(data, true);
        let line_num1 = DebugCOFFLineNumber::new(&reader, 0).expect("failed to read");
        let line_num2 = line_num1.clone();

        assert_eq!(line_num1, line_num2);
    }
}

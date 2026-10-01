use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::format::pe::debug::debug_coff_symbol::DebugCOFFSymbol;
use crate::format::pe::debug::debug_coff_symbols_header::DebugCOFFSymbolsHeader;
use crate::format::seam_stubs::{DEBUG_COFF_SYMBOL_IMAGE_SIZEOF_SYMBOL, NT_HEADER_MAX_SANE_COUNT};

/// Represents a COFF Symbol Table.
///
/// Mirrors the `DebugCOFFSymbolTable` Java class in
/// `ghidra.app.util.bin.format.pe.debug`.
///
/// ```text
/// typedef struct {
///     // Symbol table entries follow
/// } COFF_SYMBOL_TABLE;
/// ```
pub struct DebugCOFFSymbolTable {
    /// Pointer to the symbol table in the file.
    ptr_to_symbol_table: i32,
    /// Number of symbols in the table.
    symbol_count: i32,
    /// The COFF symbols defined in this table.
    symbols: Vec<DebugCOFFSymbol>,
}

impl DebugCOFFSymbolTable {
    /// Creates a new `DebugCOFFSymbolTable` by reading from the given binary reader,
    /// mirroring the Java constructor.
    ///
    /// # Arguments
    ///
    /// * `reader` - A binary reader positioned at the structure's data.
    /// * `coff_header` - The COFF symbols header containing metadata about the symbol table.
    /// * `offset` - The base offset for addresses.
    ///
    /// # Errors
    ///
    /// Returns an `io::Result::Err` if reading from the reader fails.
    pub fn new(
        reader: &BinaryReader,
        coff_header: &DebugCOFFSymbolsHeader,
        offset: i32,
    ) -> io::Result<Self> {
        let ptr_to_symbol_table = coff_header.get_first_symbol_lva() + offset;
        let symbol_count = coff_header.get_number_of_symbols();

        // TODO: should symbol table info in NT Header agree with info in COFF Header?

        // NOTE: this mirrors the Java loop's fixed 18-byte stride per iteration, which does NOT
        // skip over a symbol's own trailing auxiliary-symbol slots -- an auxiliary slot is
        // therefore misread as if it were its own `DebugCOFFSymbol`, exactly as the original
        // Java does (`DebugCOFFSymbolTable.java`'s constructor has no aux-aware skip either).
        let string_table_index =
            (ptr_to_symbol_table + (symbol_count * DEBUG_COFF_SYMBOL_IMAGE_SIZEOF_SYMBOL as i32)) as u64;
        let mut symbols = Vec::new();
        if symbol_count < NT_HEADER_MAX_SANE_COUNT {
            for i in 0..symbol_count {
                let index =
                    (ptr_to_symbol_table + (i * DEBUG_COFF_SYMBOL_IMAGE_SIZEOF_SYMBOL as i32)) as u64;
                symbols.push(DebugCOFFSymbol::new(reader, index, string_table_index)?);
            }
        }

        Ok(DebugCOFFSymbolTable {
            ptr_to_symbol_table,
            symbol_count,
            symbols,
        })
    }

    /// Returns the index into the string table, calculated from the symbol table size.
    ///
    /// The string table starts after all symbols.
    pub(crate) fn get_string_table_index(&self) -> u64 {
        (self.ptr_to_symbol_table + (self.symbol_count * DEBUG_COFF_SYMBOL_IMAGE_SIZEOF_SYMBOL as i32)) as u64
    }

    /// Returns the COFF symbols defined in this COFF symbol table.
    pub fn get_symbols(&self) -> &[DebugCOFFSymbol] {
        &self.symbols
    }
}

#[cfg(test)]
mod tests {
    use super::*;


    struct MockDebugDirectory {
        ptr: i32,
    }

    impl crate::format::seam_stubs::DebugDirectory for MockDebugDirectory {
        fn get_pointer_to_raw_data(&self) -> i32 {
            self.ptr
        }
    }

    struct AlwaysValid;
    impl crate::format::pe::offset_validator::OffsetValidator for AlwaysValid {
        fn check_pointer(&self, _ptr: u64) -> bool {
            true
        }
        fn check_rva(&self, _rva: u64) -> bool {
            true
        }
    }

    /// Builds a `DebugCOFFSymbolsHeader` with the given `number_of_symbols` /
    /// `first_symbol_lva`, and all other fields zeroed, by encoding them into the reader's
    /// backing bytes at offset 0 (mirrors the header's own binary layout).
    fn mock_header(number_of_symbols: i32, first_symbol_lva: i32) -> (BinaryReader, DebugCOFFSymbolsHeader) {
        let mut data = Vec::new();
        data.extend_from_slice(&(number_of_symbols as u32).to_le_bytes());
        data.extend_from_slice(&(first_symbol_lva as u32).to_le_bytes());
        data.extend(std::iter::repeat(0u8).take(6 * 4));
        data.extend(std::iter::repeat(0u8).take(1000));

        let reader = BinaryReader::from_bytes(data, true);
        let debug_dir = MockDebugDirectory { ptr: 0 };
        let validator = AlwaysValid;
        let header = DebugCOFFSymbolsHeader::new(&reader, &debug_dir, &validator)
            .expect("failed to construct mock header");
        (reader, header)
    }

    #[test]
    fn create_empty_table() {
        let (reader, header) = mock_header(0, 100);

        let table = DebugCOFFSymbolTable::new(&reader, &header, 0).expect("failed to create table");
        assert_eq!(table.symbol_count, 0);
        assert_eq!(table.ptr_to_symbol_table, 100);
        assert_eq!(table.symbols.len(), 0);
    }

    #[test]
    fn create_table_with_max_sane_count() {
        let (reader, header) = mock_header(NT_HEADER_MAX_SANE_COUNT, 100);

        let table = DebugCOFFSymbolTable::new(&reader, &header, 0).expect("failed to create table");
        assert_eq!(table.symbol_count, NT_HEADER_MAX_SANE_COUNT);
        assert_eq!(table.ptr_to_symbol_table, 100);
    }

    #[test]
    fn create_table_exceeds_max_sane_count() {
        let (reader, header) = mock_header(NT_HEADER_MAX_SANE_COUNT + 1, 100);

        let table = DebugCOFFSymbolTable::new(&reader, &header, 0).expect("failed to create table");
        assert_eq!(table.symbol_count, NT_HEADER_MAX_SANE_COUNT + 1);
        assert_eq!(table.symbols.len(), 0);
    }

    #[test]
    fn string_table_index_calculation() {
        let (reader, header) = mock_header(5, 100);

        let table = DebugCOFFSymbolTable::new(&reader, &header, 0).expect("failed to create table");
        let string_table_index = table.get_string_table_index();
        assert_eq!(string_table_index, (100 + (5 * DEBUG_COFF_SYMBOL_IMAGE_SIZEOF_SYMBOL as i32)) as u64);
    }

    #[test]
    fn with_offset() {
        let (reader, header) = mock_header(0, 100);

        let table = DebugCOFFSymbolTable::new(&reader, &header, 200).expect("failed to create table");
        assert_eq!(table.ptr_to_symbol_table, 300); // 100 + 200
    }
}

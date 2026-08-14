use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::format::seam_stubs::{
    DebugCOFFSymbol, DebugCOFFSymbolsHeader, DEBUG_COFF_SYMBOL_IMAGE_SIZEOF_SYMBOL,
    NT_HEADER_MAX_SANE_COUNT,
};

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
    symbols: Vec<Box<dyn DebugCOFFSymbol>>,
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
        _reader: &dyn BinaryReader,
        coff_header: &dyn DebugCOFFSymbolsHeader,
        offset: i32,
    ) -> io::Result<Self> {
        let ptr_to_symbol_table = coff_header.get_first_symbol_lva() + offset;
        let symbol_count = coff_header.get_number_of_symbols();

        // TODO: should symbol table info in NT Header agree with info in COFF Header?

        let symbols: Vec<Box<dyn DebugCOFFSymbol>> = if symbol_count < NT_HEADER_MAX_SANE_COUNT {
            // Since DebugCOFFSymbol is not yet ported, we return an empty vector for now.
            // When DebugCOFFSymbol is ported, this will be:
            // (0..symbol_count)
            //     .map(|i| {
            //         Box::new(DebugCOFFSymbol::new(
            //             reader,
            //             (ptr_to_symbol_table + (i * DEBUG_COFF_SYMBOL_IMAGE_SIZEOF_SYMBOL as i32)) as u64,
            //             self,
            //         )?) as Box<dyn DebugCOFFSymbol>
            //     })
            //     .collect::<io::Result<Vec<_>>>()?
            Vec::new()
        } else {
            Vec::new()
        };

        Ok(DebugCOFFSymbolTable {
            ptr_to_symbol_table,
            symbol_count,
            symbols,
        })
    }

    /// Returns the index into the string table, calculated from the symbol table size.
    ///
    /// The string table starts after all symbols.
    fn get_string_table_index(&self) -> i32 {
        self.ptr_to_symbol_table + (self.symbol_count * DEBUG_COFF_SYMBOL_IMAGE_SIZEOF_SYMBOL as i32)
    }

    /// Returns the COFF symbols defined in this COFF symbol table.
    pub fn get_symbols(&self) -> &[Box<dyn DebugCOFFSymbol>] {
        &self.symbols
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    use crate::filesystem::ghidra::g_binary_reader::ByteProvider;

    struct VecProvider(Vec<u8>);

    impl ByteProvider for VecProvider {
        fn length(&mut self) -> io::Result<u64> {
            Ok(self.0.len() as u64)
        }

        fn is_valid_index(&mut self, index: u64) -> bool {
            index < self.0.len() as u64
        }

        fn read_byte(&mut self, index: u64) -> io::Result<u8> {
            self.0
                .get(index as usize)
                .copied()
                .ok_or(io::Error::from(io::ErrorKind::UnexpectedEof))
        }

        fn read_bytes(&mut self, index: u64, length: usize) -> io::Result<Vec<u8>> {
            let start = index as usize;
            let end = start + length;
            self.0
                .get(start..end)
                .map(|s| s.to_vec())
                .ok_or(io::Error::from(io::ErrorKind::UnexpectedEof))
        }

        fn write_byte(&mut self, _index: u64, _value: u8) -> io::Result<()> {
            Err(io::Error::from(io::ErrorKind::Unsupported))
        }

        fn write_bytes(&mut self, _index: u64, _values: &[u8]) -> io::Result<()> {
            Err(io::Error::from(io::ErrorKind::Unsupported))
        }
    }

    struct MockReader {
        provider: Rc<RefCell<dyn ByteProvider>>,
        little_endian: bool,
        current_index: u64,
    }

    impl MockReader {
        fn new(data: Vec<u8>, little_endian: bool) -> Self {
            MockReader {
                provider: Rc::new(RefCell::new(VecProvider(data))),
                little_endian,
                current_index: 0,
            }
        }
    }

    impl BinaryReader for MockReader {
        fn length(&self) -> io::Result<u64> {
            self.provider.borrow_mut().length()
        }

        fn is_valid_index(&self, index: u64) -> bool {
            self.provider.borrow_mut().is_valid_index(index)
        }

        fn get_pointer_index(&self) -> u64 {
            self.current_index
        }

        fn set_pointer_index(&mut self, index: u64) -> u64 {
            let old = self.current_index;
            self.current_index = index;
            old
        }

        fn is_little_endian(&self) -> bool {
            self.little_endian
        }

        fn set_little_endian(&mut self, is_little_endian: bool) {
            self.little_endian = is_little_endian;
        }

        fn read_byte(&self, index: u64) -> io::Result<u8> {
            self.provider.borrow_mut().read_byte(index)
        }

        fn read_byte_array(&self, index: u64, n_elements: usize) -> io::Result<Vec<u8>> {
            self.provider.borrow_mut().read_bytes(index, n_elements)
        }

        fn get_byte_provider(&self) -> Rc<RefCell<dyn ByteProvider>> {
            Rc::clone(&self.provider)
        }

        fn clone_at(&self, new_index: u64) -> Box<dyn BinaryReader> {
            Box::new(MockReader {
                provider: Rc::clone(&self.provider),
                little_endian: self.little_endian,
                current_index: new_index,
            })
        }
    }

    struct MockCOFFHeader {
        number_of_symbols: i32,
        first_symbol_lva: i32,
    }

    impl DebugCOFFSymbolsHeader for MockCOFFHeader {
        fn get_symbol_table(&self) -> Box<dyn crate::format::seam_stubs::DebugCOFFSymbolTable> {
            panic!("not implemented")
        }

        fn get_line_numbers(&self) -> Vec<Box<dyn crate::format::seam_stubs::DebugCOFFLineNumber>> {
            Vec::new()
        }

        fn get_number_of_symbols(&self) -> i32 {
            self.number_of_symbols
        }

        fn get_first_symbol_lva(&self) -> i32 {
            self.first_symbol_lva
        }

        fn get_number_of_linenumbers(&self) -> i32 {
            0
        }

        fn get_first_linenumber_lva(&self) -> i32 {
            0
        }

        fn get_first_byte_of_code_rva(&self) -> i32 {
            0
        }

        fn get_last_byte_of_code_rva(&self) -> i32 {
            0
        }

        fn get_first_byte_of_data_rva(&self) -> i32 {
            0
        }

        fn get_last_byte_of_data_rva(&self) -> i32 {
            0
        }
    }

    #[test]
    fn create_empty_table() {
        let data = vec![0u8; 1000];
        let reader = MockReader::new(data, true);
        let header = MockCOFFHeader {
            number_of_symbols: 0,
            first_symbol_lva: 100,
        };

        let table = DebugCOFFSymbolTable::new(&reader, &header, 0).expect("failed to create table");
        assert_eq!(table.symbol_count, 0);
        assert_eq!(table.ptr_to_symbol_table, 100);
        assert_eq!(table.symbols.len(), 0);
    }

    #[test]
    fn create_table_with_max_sane_count() {
        let data = vec![0u8; 100000];
        let reader = MockReader::new(data, true);
        let header = MockCOFFHeader {
            number_of_symbols: NT_HEADER_MAX_SANE_COUNT,
            first_symbol_lva: 100,
        };

        let table = DebugCOFFSymbolTable::new(&reader, &header, 0).expect("failed to create table");
        assert_eq!(table.symbol_count, NT_HEADER_MAX_SANE_COUNT);
        assert_eq!(table.ptr_to_symbol_table, 100);
    }

    #[test]
    fn create_table_exceeds_max_sane_count() {
        let data = vec![0u8; 100000];
        let reader = MockReader::new(data, true);
        let header = MockCOFFHeader {
            number_of_symbols: NT_HEADER_MAX_SANE_COUNT + 1,
            first_symbol_lva: 100,
        };

        let table = DebugCOFFSymbolTable::new(&reader, &header, 0).expect("failed to create table");
        assert_eq!(table.symbol_count, NT_HEADER_MAX_SANE_COUNT + 1);
        assert_eq!(table.symbols.len(), 0);
    }

    #[test]
    fn string_table_index_calculation() {
        let data = vec![0u8; 1000];
        let reader = MockReader::new(data, true);
        let header = MockCOFFHeader {
            number_of_symbols: 5,
            first_symbol_lva: 100,
        };

        let table = DebugCOFFSymbolTable::new(&reader, &header, 0).expect("failed to create table");
        let string_table_index = table.get_string_table_index();
        assert_eq!(string_table_index, 100 + (5 * DEBUG_COFF_SYMBOL_IMAGE_SIZEOF_SYMBOL as i32));
    }

    #[test]
    fn with_offset() {
        let data = vec![0u8; 1000];
        let reader = MockReader::new(data, true);
        let header = MockCOFFHeader {
            number_of_symbols: 0,
            first_symbol_lva: 100,
        };

        let table = DebugCOFFSymbolTable::new(&reader, &header, 200).expect("failed to create table");
        assert_eq!(table.ptr_to_symbol_table, 300); // 100 + 200
    }
}

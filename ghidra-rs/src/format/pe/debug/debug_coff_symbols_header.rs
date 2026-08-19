use std::io;

use crate::app::util::bin::binary_reader::{BinaryReader, SIZEOF_INT};
use crate::format::pe::debug::debug_coff_line_number::DebugCOFFLineNumber;
use crate::format::pe::debug::debug_coff_symbol_table::DebugCOFFSymbolTable;
use crate::format::pe::offset_validator::OffsetValidator;
use crate::format::seam_stubs::{DebugDirectory, NT_HEADER_MAX_SANE_COUNT};
use crate::util::msg::Msg;

/// A class to represent the COFF Symbols Header.
///
/// Mirrors the `DebugCOFFSymbolsHeader` Java class in
/// `ghidra.app.util.bin.format.pe.debug`.
///
/// ```text
/// typedef struct _IMAGE_COFF_SYMBOLS_HEADER {
///   DWORD   NumberOfSymbols;
///   DWORD   LvaToFirstSymbol;
///   DWORD   NumberOfLinenumbers;
///   DWORD   LvaToFirstLinenumber;
///   DWORD   RvaToFirstByteOfCode;
///   DWORD   RvaToLastByteOfCode;
///   DWORD   RvaToFirstByteOfData;
///   DWORD   RvaToLastByteOfData;
/// } IMAGE_COFF_SYMBOLS_HEADER, *PIMAGE_COFF_SYMBOLS_HEADER;
/// ```
pub struct DebugCOFFSymbolsHeader {
    number_of_symbols: i32,
    lva_to_first_symbol: i32,
    number_of_linenumbers: i32,
    lva_to_first_linenumber: i32,
    rva_to_first_byte_of_code: i32,
    rva_to_last_byte_of_code: i32,
    rva_to_first_byte_of_data: i32,
    rva_to_last_byte_of_data: i32,

    symbol_table: Option<DebugCOFFSymbolTable>,
    line_numbers: Vec<DebugCOFFLineNumber>,
}

impl DebugCOFFSymbolsHeader {
    /// Creates a new `DebugCOFFSymbolsHeader` by reading from the given binary reader,
    /// mirroring the Java constructor.
    ///
    /// # Arguments
    ///
    /// * `reader` - the binary reader
    /// * `debug_dir` - the debug directory associated to this COFF symbol header
    /// * `validator` - validates the raw file pointer taken from `debug_dir`
    ///
    /// # Errors
    ///
    /// Returns an `io::Result::Err` if reading from the reader fails.
    pub fn new(
        reader: &dyn BinaryReader,
        debug_dir: &dyn DebugDirectory,
        validator: &dyn OffsetValidator,
    ) -> io::Result<Self> {
        // Java widens the int pointer to a long via sign extension before use.
        let ptr0 = debug_dir.get_pointer_to_raw_data() as i64 as u64;
        if !validator.check_pointer(ptr0) {
            Msg::error("DebugCOFFSymbolsHeader", &format!("Invalid pointer {ptr0:x}"));
            return Ok(DebugCOFFSymbolsHeader {
                number_of_symbols: 0,
                lva_to_first_symbol: 0,
                number_of_linenumbers: 0,
                lva_to_first_linenumber: 0,
                rva_to_first_byte_of_code: 0,
                rva_to_last_byte_of_code: 0,
                rva_to_first_byte_of_data: 0,
                rva_to_last_byte_of_data: 0,
                symbol_table: None,
                line_numbers: Vec::new(),
            });
        }

        let mut ptr = ptr0;
        let number_of_symbols = reader.read_int(ptr)?;
        ptr += SIZEOF_INT;
        let lva_to_first_symbol = reader.read_int(ptr)?;
        ptr += SIZEOF_INT;
        let number_of_linenumbers = reader.read_int(ptr)?;
        ptr += SIZEOF_INT;
        let lva_to_first_linenumber = reader.read_int(ptr)?;
        ptr += SIZEOF_INT;
        let rva_to_first_byte_of_code = reader.read_int(ptr)?;
        ptr += SIZEOF_INT;
        let rva_to_last_byte_of_code = reader.read_int(ptr)?;
        ptr += SIZEOF_INT;
        let rva_to_first_byte_of_data = reader.read_int(ptr)?;
        ptr += SIZEOF_INT;
        let rva_to_last_byte_of_data = reader.read_int(ptr)?;
        ptr += SIZEOF_INT;

        let mut line_numbers = Vec::new();
        if number_of_linenumbers > 0 && number_of_linenumbers < NT_HEADER_MAX_SANE_COUNT {
            for _ in 0..number_of_linenumbers {
                line_numbers.push(DebugCOFFLineNumber::new(reader, ptr)?);
                ptr += DebugCOFFLineNumber::IMAGE_SIZEOF_LINENUMBER as u64;
            }
        }

        let mut header = DebugCOFFSymbolsHeader {
            number_of_symbols,
            lva_to_first_symbol,
            number_of_linenumbers,
            lva_to_first_linenumber,
            rva_to_first_byte_of_code,
            rva_to_last_byte_of_code,
            rva_to_first_byte_of_data,
            rva_to_last_byte_of_data,
            symbol_table: None,
            line_numbers,
        };

        let symbol_table =
            DebugCOFFSymbolTable::new(reader, &header, debug_dir.get_pointer_to_raw_data())?;
        header.symbol_table = Some(symbol_table);

        Ok(header)
    }

    /// Returns the COFF symbol table.
    pub fn get_symbol_table(&self) -> Option<&DebugCOFFSymbolTable> {
        self.symbol_table.as_ref()
    }

    /// Returns the COFF line numbers.
    pub fn get_line_numbers(&self) -> &[DebugCOFFLineNumber] {
        &self.line_numbers
    }

    /// Returns the number of symbols in this header.
    pub fn get_number_of_symbols(&self) -> i32 {
        self.number_of_symbols
    }

    /// Returns the LVA of the first symbol.
    pub fn get_first_symbol_lva(&self) -> i32 {
        self.lva_to_first_symbol
    }

    /// Returns the number of line numbers in this header.
    pub fn get_number_of_linenumbers(&self) -> i32 {
        self.number_of_linenumbers
    }

    /// Returns the LVA of the first line number.
    pub fn get_first_linenumber_lva(&self) -> i32 {
        self.lva_to_first_linenumber
    }

    /// Returns the RVA of the first code byte.
    pub fn get_first_byte_of_code_rva(&self) -> i32 {
        self.rva_to_first_byte_of_code
    }

    /// Returns the RVA of the last code byte.
    pub fn get_last_byte_of_code_rva(&self) -> i32 {
        self.rva_to_last_byte_of_code
    }

    /// Returns the RVA of the first data byte.
    pub fn get_first_byte_of_data_rva(&self) -> i32 {
        self.rva_to_first_byte_of_data
    }

    /// Returns the RVA of the last data byte.
    pub fn get_last_byte_of_data_rva(&self) -> i32 {
        self.rva_to_last_byte_of_data
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

    struct MockDebugDirectory {
        ptr: i32,
    }

    impl DebugDirectory for MockDebugDirectory {
        fn get_pointer_to_raw_data(&self) -> i32 {
            self.ptr
        }
    }

    struct AlwaysValid;
    impl OffsetValidator for AlwaysValid {
        fn check_pointer(&self, _ptr: u64) -> bool {
            true
        }
        fn check_rva(&self, _rva: u64) -> bool {
            true
        }
    }

    struct AlwaysInvalid;
    impl OffsetValidator for AlwaysInvalid {
        fn check_pointer(&self, _ptr: u64) -> bool {
            false
        }
        fn check_rva(&self, _rva: u64) -> bool {
            false
        }
    }

    fn le_u32(v: u32) -> [u8; 4] {
        v.to_le_bytes()
    }

    #[test]
    fn reads_header_fields() {
        let mut data = Vec::new();
        data.extend_from_slice(&le_u32(3)); // NumberOfSymbols
        data.extend_from_slice(&le_u32(100)); // LvaToFirstSymbol
        data.extend_from_slice(&le_u32(0)); // NumberOfLinenumbers
        data.extend_from_slice(&le_u32(0)); // LvaToFirstLinenumber
        data.extend_from_slice(&le_u32(10)); // RvaToFirstByteOfCode
        data.extend_from_slice(&le_u32(20)); // RvaToLastByteOfCode
        data.extend_from_slice(&le_u32(30)); // RvaToFirstByteOfData
        data.extend_from_slice(&le_u32(40)); // RvaToLastByteOfData
        data.extend(std::iter::repeat(0u8).take(200));

        let reader = MockReader::new(data, true);
        let debug_dir = MockDebugDirectory { ptr: 0 };
        let validator = AlwaysValid;

        let header = DebugCOFFSymbolsHeader::new(&reader, &debug_dir, &validator)
            .expect("failed to construct header");

        assert_eq!(header.get_number_of_symbols(), 3);
        assert_eq!(header.get_first_symbol_lva(), 100);
        assert_eq!(header.get_number_of_linenumbers(), 0);
        assert_eq!(header.get_first_linenumber_lva(), 0);
        assert_eq!(header.get_first_byte_of_code_rva(), 10);
        assert_eq!(header.get_last_byte_of_code_rva(), 20);
        assert_eq!(header.get_first_byte_of_data_rva(), 30);
        assert_eq!(header.get_last_byte_of_data_rva(), 40);
        assert!(header.get_line_numbers().is_empty());
        assert!(header.get_symbol_table().is_some());
    }

    #[test]
    fn reads_line_numbers() {
        let mut data = Vec::new();
        data.extend_from_slice(&le_u32(0)); // NumberOfSymbols
        data.extend_from_slice(&le_u32(0)); // LvaToFirstSymbol
        data.extend_from_slice(&le_u32(2)); // NumberOfLinenumbers
        data.extend_from_slice(&le_u32(0)); // LvaToFirstLinenumber
        data.extend_from_slice(&le_u32(0)); // RvaToFirstByteOfCode
        data.extend_from_slice(&le_u32(0)); // RvaToLastByteOfCode
        data.extend_from_slice(&le_u32(0)); // RvaToFirstByteOfData
        data.extend_from_slice(&le_u32(0)); // RvaToLastByteOfData
        // Two IMAGE_LINENUMBER entries (6 bytes each).
        data.extend_from_slice(&le_u32(111));
        data.extend_from_slice(&5u16.to_le_bytes());
        data.extend_from_slice(&le_u32(222));
        data.extend_from_slice(&7u16.to_le_bytes());
        data.extend(std::iter::repeat(0u8).take(200));

        let reader = MockReader::new(data, true);
        let debug_dir = MockDebugDirectory { ptr: 0 };
        let validator = AlwaysValid;

        let header = DebugCOFFSymbolsHeader::new(&reader, &debug_dir, &validator)
            .expect("failed to construct header");

        let line_numbers = header.get_line_numbers();
        assert_eq!(line_numbers.len(), 2);
        assert_eq!(line_numbers[0].symbol_table_index(), 111);
        assert_eq!(line_numbers[0].line_number(), 5);
        assert_eq!(line_numbers[1].symbol_table_index(), 222);
        assert_eq!(line_numbers[1].line_number(), 7);
    }

    #[test]
    fn invalid_pointer_yields_default_header() {
        let data = vec![0u8; 32];
        let reader = MockReader::new(data, true);
        let debug_dir = MockDebugDirectory { ptr: 0x1234 };
        let validator = AlwaysInvalid;

        let header = DebugCOFFSymbolsHeader::new(&reader, &debug_dir, &validator)
            .expect("invalid pointer should still return a header, not an error");

        assert_eq!(header.get_number_of_symbols(), 0);
        assert_eq!(header.get_first_symbol_lva(), 0);
        assert!(header.get_line_numbers().is_empty());
        assert!(header.get_symbol_table().is_none());
    }
}

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::coff::coff_constants;
use crate::format::coff::coff_symbol_aux::CoffSymbolAux;
use crate::format::coff::coff_symbol_type::T_NULL;
use crate::program::model::data::data_type::DataType;

/// A COFF symbol table entry.
///
/// Port of `ghidra.app.util.bin.format.coff.CoffSymbol`. The Java class has no subclasses, so
/// per this crate's shape rule it ports as a plain `struct` rather than a trait.
///
/// The Java constructor also parses `e_numaux` trailing `CoffSymbolAux` records via
/// `CoffSymbolAuxFactory`, dispatching on this symbol's derived type / storage class to one of
/// eight concrete aux-record subclasses (`CoffSymbolAuxFilename`, `CoffSymbolAuxSection`,
/// `CoffSymbolAuxTagName`, `CoffSymbolAuxEndOfStruct`, `CoffSymbolAuxBeginningOfBlock`,
/// `CoffSymbolAuxFunction`, `CoffSymbolAuxArray`, `CoffSymbolAuxDefault`). None of those are
/// ported yet, so -- mirroring the precedent in
/// [`DebugCOFFSymbol`](crate::format::pe::debug::debug_coff_symbol::DebugCOFFSymbol) for the
/// analogous PE symbol table -- [`CoffSymbol::new`] still reads `e_numaux` faithfully and
/// advances the reader past each aux record's bytes (each COFF aux record is the same size as a
/// primary symbol table entry, [`coff_constants::SYMBOL_SIZEOF`]), but leaves
/// [`auxiliary_symbols`](Self::auxiliary_symbols) empty until the aux-record subclasses land.
/// This means [`is_section`](Self::is_section) can never observe a `CoffSymbolAuxSection` and
/// so always returns `false`, matching Java only when a symbol truly has no aux records.
#[derive(Default)]
pub struct CoffSymbol {
    e_name: String,
    e_value: i32,
    e_scnum: i16,
    e_type: i16,
    e_sclass: i8,
    e_numaux: i8,
    auxiliary_symbols: Vec<Box<dyn CoffSymbolAux>>,
}

impl CoffSymbol {
    /// Reads a `CoffSymbol` from `reader` at its current position.
    ///
    /// Port of the package-private Java constructor `CoffSymbol(BinaryReader, CoffFileHeader)`.
    /// Takes the two `CoffFileHeader` accessors this constructor actually reads
    /// (`getSymbolTablePointer()`, `getSymbolTableEntries()`) directly rather than a
    /// `&CoffFileHeader`: `CoffFileHeader` owns the very `reader` passed in here, so a reference
    /// to the whole header would alias the mutable reader borrow when
    /// [`CoffFileHeader::parse`](crate::format::coff::coff_file_header::CoffFileHeader::parse)
    /// calls this constructor.
    pub fn new(
        reader: &mut dyn BinaryReader,
        symbol_table_pointer: i32,
        symbol_table_entries: i32,
    ) -> io::Result<Self> {
        let e_name = if reader.peek_next_int()? == 0 {
            // Look up name in string table.
            reader.read_next_int()?; // skip null
            let name_index = reader.read_next_int()?; // string table index
            let string_table_index = symbol_table_pointer as i64
                + (symbol_table_entries as i64 * coff_constants::SYMBOL_SIZEOF as i64);
            reader.read_ascii_string((string_table_index + name_index as i64) as u64)?
        } else {
            reader.read_next_ascii_string_fixed(coff_constants::SYMBOL_NAME_LENGTH)?
        };

        let e_value = reader.read_next_int()?;
        let e_scnum = reader.read_next_short()?;
        let e_type = reader.read_next_short()?;
        let e_sclass = reader.read_next_byte()? as i8;
        let e_numaux = reader.read_next_byte()? as i8;

        // See the struct's own docs for why aux symbols are counted but not constructed.
        for _ in 0..e_numaux {
            for _ in 0..coff_constants::SYMBOL_SIZEOF {
                reader.read_next_byte()?;
            }
        }

        Ok(CoffSymbol {
            e_name,
            e_value,
            e_scnum,
            e_type,
            e_sclass,
            e_numaux,
            auxiliary_symbols: Vec::new(),
        })
    }

    /// Returns the name of this symbol.
    ///
    /// Port of `getName()`.
    pub fn name(&self) -> &str {
        &self.e_name
    }

    /// Returns the value of this symbol, as an unsigned 32-bit quantity.
    ///
    /// Port of `getValue()`.
    pub fn value(&self) -> u32 {
        self.e_value as u32
    }

    /// Adds `offset` to the value; this must be performed before relocations in order to
    /// achieve the proper result.
    ///
    /// Port of `move(int offset)` (renamed: `move` is a Rust keyword).
    pub fn add_offset(&mut self, offset: i32) {
        self.e_value = self.e_value.wrapping_add(offset);
    }

    /// Returns the section number of this symbol.
    ///
    /// Port of `getSectionNumber()`.
    pub fn section_number(&self) -> i16 {
        self.e_scnum
    }

    /// Returns the basic type of this symbol.
    ///
    /// Port of `getBasicType()`.
    pub fn basic_type(&self) -> i32 {
        self.e_type as i32 & 0xf
    }

    /// Returns the `derived_index`'th derived type of this symbol.
    ///
    /// Port of `getDerivedType(int)`.
    ///
    /// # Panics
    /// Panics if `derived_index` is not in `1..=6`, mirroring Java's `RuntimeException`.
    pub fn derived_type(&self, derived_index: i32) -> i32 {
        assert!(
            (1..=6).contains(&derived_index),
            "1 <= derivedIndex <= 6"
        );
        let mut derived_type = (self.e_type as i32 & 0xffff) >> 4;
        if derived_index > 1 {
            derived_type >>= derived_index * 2;
        }
        derived_type & 0x3
    }

    /// Returns the storage class of this symbol.
    ///
    /// Port of `getStorageClass()`.
    pub fn storage_class(&self) -> i8 {
        self.e_sclass
    }

    /// Returns the number of auxiliary symbols associated with this symbol.
    ///
    /// Port of `getAuxiliaryCount()`.
    pub fn auxiliary_count(&self) -> i8 {
        self.e_numaux
    }

    /// Returns the auxiliary symbols associated with this symbol.
    ///
    /// Port of `getAuxiliarySymbols()`. See the struct's own docs for why this is always empty.
    pub fn auxiliary_symbols(&self) -> &[Box<dyn CoffSymbolAux>] {
        &self.auxiliary_symbols
    }

    /// Returns true if this symbol represents a section.
    ///
    /// Port of `isSection()`. See the struct's own docs for why this always returns `false`.
    pub fn is_section(&self) -> bool {
        if self.e_type as u32 != T_NULL || self.e_value != 0 {
            return false;
        }
        if self.e_sclass as i32
            != crate::format::coff::coff_symbol_storage_class::C_STAT
        {
            return false;
        }
        self.auxiliary_symbols
            .iter()
            .any(|_aux| false /* no CoffSymbolAuxSection instances are ever constructed */)
    }
}

impl StructConverter for CoffSymbol {
    /// Mirrors `toDataType()`. Not yet buildable: it requires `StructureDataType` (a mutable,
    /// constructible `Structure`), which is not ported yet.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Err(ToDataTypeError::Io(io::Error::new(
            io::ErrorKind::Unsupported,
            "CoffSymbol::to_data_type requires StructureDataType, which is not yet ported",
        )))
    }
}

impl std::fmt::Display for CoffSymbol {
    /// Mirrors `toString()`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} Value=0x{:x} {} {} {}",
            self.e_name, self.e_value, self.e_scnum, self.e_type, self.e_sclass
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    use crate::filesystem::ghidra::g_binary_reader::GByteStore;

    struct VecProvider(Vec<u8>);

    impl GByteStore for VecProvider {
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
        provider: Rc<RefCell<dyn GByteStore>>,
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
        fn get_byte_provider(&self) -> Rc<RefCell<dyn GByteStore>> {
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

    /// Builds a symbol table entry with an inline short name (union's first 4 bytes non-zero),
    /// matching the layout `CoffSymbol::new` expects.
    fn short_name_symbol_bytes(name: &str, value: i32, scnum: i16, type_: i16, sclass: u8) -> Vec<u8> {
        let mut data = Vec::new();
        let mut name_bytes = [0u8; 8];
        let bytes = name.as_bytes();
        name_bytes[..bytes.len()].copy_from_slice(bytes);
        data.extend_from_slice(&name_bytes);
        data.extend_from_slice(&value.to_le_bytes());
        data.extend_from_slice(&scnum.to_le_bytes());
        data.extend_from_slice(&type_.to_le_bytes());
        data.push(sclass);
        data.push(0); // e_numaux
        data
    }

    #[test]
    fn parses_inline_short_name() {
        let data = short_name_symbol_bytes("main", 0x1000, 1, 0x20, 2);
        let mut reader = MockReader::new(data, true);
        let sym = CoffSymbol::new(&mut reader, 0, 0).expect("failed to parse symbol");
        assert_eq!(sym.name(), "main");
        assert_eq!(sym.value(), 0x1000);
        assert_eq!(sym.section_number(), 1);
        assert_eq!(sym.basic_type(), 0);
        assert_eq!(sym.storage_class(), 2);
        assert_eq!(sym.auxiliary_count(), 0);
    }

    #[test]
    fn parses_long_name_from_string_table() {
        let mut data = Vec::new();
        data.extend_from_slice(&0i32.to_le_bytes()); // Short == 0 -> use long name
        data.extend_from_slice(&4i32.to_le_bytes()); // Long: offset 4 into string table
        data.extend_from_slice(&0x2000i32.to_le_bytes()); // value
        data.extend_from_slice(&(-1i16).to_le_bytes()); // sectionNumber
        data.extend_from_slice(&0i16.to_le_bytes()); // type
        data.push(3); // storageClass (C_STAT)
        data.push(0); // e_numaux

        // header.getSymbolTablePointer() + header.getSymbolTableEntries() * SYMBOL_SIZEOF == 100.
        let symbol_table_pointer = 100 - (2 * coff_constants::SYMBOL_SIZEOF as i32);
        let mut full = data.clone();
        full.resize(100, 0);
        full.extend_from_slice(b"\0\0\0\0longsymbolname\0");

        let mut reader = MockReader::new(full, true);
        let sym = CoffSymbol::new(&mut reader, symbol_table_pointer, 2).expect("failed to parse symbol");
        assert_eq!(sym.name(), "longsymbolname");
        assert_eq!(sym.section_number(), -1);
        assert_eq!(sym.storage_class(), 3);
    }

    #[test]
    fn derived_type_extracts_nested_bits() {
        let data = short_name_symbol_bytes("f", 0, 0, 0x0024 /* DT_PTR<<4 | T_NULL */, 0);
        let mut reader = MockReader::new(data, true);
        let sym = CoffSymbol::new(&mut reader, 0, 0).expect("failed to parse symbol");
        assert_eq!(sym.basic_type(), 0x4);
        assert_eq!(sym.derived_type(1), 0x2);
    }

    #[test]
    #[should_panic(expected = "1 <= derivedIndex <= 6")]
    fn derived_type_rejects_out_of_range_index() {
        let data = short_name_symbol_bytes("f", 0, 0, 0, 0);
        let mut reader = MockReader::new(data, true);
        let sym = CoffSymbol::new(&mut reader, 0, 0).expect("failed to parse symbol");
        sym.derived_type(0);
    }

    #[test]
    fn to_string_matches_java_format() {
        let data = short_name_symbol_bytes("foo", 0x10, 2, 0x30, 6);
        let mut reader = MockReader::new(data, true);
        let sym = CoffSymbol::new(&mut reader, 0, 0).expect("failed to parse symbol");
        assert_eq!(sym.to_string(), "foo Value=0x10 2 48 6");
    }

    #[test]
    fn is_section_is_false_without_constructed_aux_records() {
        // A symbol that Java's isSection() would recognize as a section symbol (T_NULL type,
        // zero value, C_STAT storage class) still reports false here because no
        // CoffSymbolAuxSection is ever constructed -- see the struct's own docs.
        let data = short_name_symbol_bytes("sect", 0, 0, 0, 3);
        let mut reader = MockReader::new(data, true);
        let sym = CoffSymbol::new(&mut reader, 0, 0).expect("failed to parse symbol");
        assert!(!sym.is_section());
    }
}

//! Port of `ghidra.app.util.bin.format.pef.LoaderInfoHeader`.
//!
//! See Apple's PEFBinaryFormat.h:
//! ```text
//! struct PEFLoaderInfoHeader {
//!     SInt32  mainSection;              // Section containing the main symbol, -1 => none.
//!     UInt32  mainOffset;                // Offset of main symbol.
//!     SInt32  initSection;              // Section containing the init routine's TVector, -1 => none.
//!     UInt32  initOffset;                // Offset of the init routine's TVector.
//!     SInt32  termSection;              // Section containing the term routine's TVector, -1 => none.
//!     UInt32  termOffset;                // Offset of the term routine's TVector.
//!     UInt32  importedLibraryCount;      // Number of imported libraries.
//!     UInt32  totalImportedSymbolCount;  // Total number of imported symbols.
//!     UInt32  relocSectionCount;         // Number of sections with relocations.
//!     UInt32  relocInstrOffset;          // Offset of the relocation instructions.
//!     UInt32  loaderStringsOffset;       // Offset of the loader string table.
//!     UInt32  exportHashOffset;          // Offset of the export hash table.
//!     UInt32  exportHashTablePower;      // Export hash table size as log 2.
//!     UInt32  exportedSymbolCount;       // Number of exported symbols.
//! };
//! ```
//!
//! `ImportedLibrary`, `ImportedSymbol`, `ExportedSymbolHashSlot`, `ExportedSymbolKey` and
//! `ExportedSymbol` are not ported yet, so they are held as minimal
//! [`seam_stubs`](crate::format::seam_stubs) placeholders: each parses exactly the bytes its real
//! Java constructor reads sequentially (so the container's byte layout stays intact for whatever
//! follows), skipping the absolute-offset name lookup into the loader string table since none of
//! `LoaderInfoHeader`'s own members read it back.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::pef::loader_relocation_header::LoaderRelocationHeader;
use crate::format::seam_stubs::{
    ExportedSymbol, ExportedSymbolHashSlot, ExportedSymbolKey, ImportedLibrary, ImportedSymbol,
    SectionHeader, StructConverterUtilDataType,
};
use crate::program::model::data::data_type::DataType;

/// Fixed size, in bytes, of the on-disk `PEFLoaderInfoHeader` structure.
///
/// Port of `LoaderInfoHeader.SIZEOF`.
pub const SIZEOF: i32 = 56;

/// Describes a PEF container's loader section: the imported-library/-symbol tables, per-section
/// relocations, and the exported-symbol hash table.
///
/// Port of `ghidra.app.util.bin.format.pef.LoaderInfoHeader`.
pub struct LoaderInfoHeader {
    section: Box<dyn SectionHeader>,

    main_section: i32,
    main_offset: i32,
    init_section: i32,
    init_offset: i32,
    term_section: i32,
    term_offset: i32,
    imported_library_count: i32,
    total_imported_symbol_count: i32,
    reloc_section_count: i32,
    reloc_instr_offset: i32,
    loader_strings_offset: i32,
    export_hash_offset: i32,
    export_hash_table_power: i32,
    exported_symbol_count: i32,

    imported_libraries: Vec<ImportedLibrary>,
    imported_symbols: Vec<ImportedSymbol>,
    relocations: Vec<LoaderRelocationHeader>,
    exported_hash_slots: Vec<ExportedSymbolHashSlot>,
    exported_symbol_keys: Vec<ExportedSymbolKey>,
    exported_symbols: Vec<ExportedSymbol>,
}

impl LoaderInfoHeader {
    /// Reads a [`LoaderInfoHeader`] and its associated tables from `reader`, restoring `reader`'s
    /// pointer index before returning (matching Java's `try`/`finally`).
    ///
    /// Port of `LoaderInfoHeader(BinaryReader, SectionHeader)`.
    pub fn new(reader: &mut dyn BinaryReader, section: Box<dyn SectionHeader>) -> io::Result<Self> {
        let old_index = reader.get_pointer_index();
        let container_offset = section.get_container_offset();

        let result = (|| -> io::Result<LoaderInfoHeader> {
            reader.set_pointer_index(container_offset as u64);

            let main_section = reader.read_next_int()?;
            let main_offset = reader.read_next_int()?;
            let init_section = reader.read_next_int()?;
            let init_offset = reader.read_next_int()?;
            let term_section = reader.read_next_int()?;
            let term_offset = reader.read_next_int()?;
            let imported_library_count = reader.read_next_int()?;
            let total_imported_symbol_count = reader.read_next_int()?;
            let reloc_section_count = reader.read_next_int()?;
            let reloc_instr_offset = reader.read_next_int()?;
            let loader_strings_offset = reader.read_next_int()?;
            let export_hash_offset = reader.read_next_int()?;
            let export_hash_table_power = reader.read_next_int()?;
            let exported_symbol_count = reader.read_next_int()?;

            let mut header = LoaderInfoHeader {
                section,
                main_section,
                main_offset,
                init_section,
                init_offset,
                term_section,
                term_offset,
                imported_library_count,
                total_imported_symbol_count,
                reloc_section_count,
                reloc_instr_offset,
                loader_strings_offset,
                export_hash_offset,
                export_hash_table_power,
                exported_symbol_count,
                imported_libraries: Vec::new(),
                imported_symbols: Vec::new(),
                relocations: Vec::new(),
                exported_hash_slots: Vec::new(),
                exported_symbol_keys: Vec::new(),
                exported_symbols: Vec::new(),
            };

            for _ in 0..imported_library_count {
                let library = ImportedLibrary::new(reader, &header)?;
                header.imported_libraries.push(library);
            }
            for _ in 0..total_imported_symbol_count {
                let symbol = ImportedSymbol::new(reader, &header)?;
                header.imported_symbols.push(symbol);
            }
            for _ in 0..reloc_section_count {
                let relocation = LoaderRelocationHeader::new(reader, &header)?;
                header.relocations.push(relocation);
            }

            let export_index = (container_offset as i64 + export_hash_offset as i64) as u64;
            reader.set_pointer_index(export_index);

            let n_exported = 2f64.powi(export_hash_table_power) as i32;
            for _ in 0..n_exported {
                let slot = ExportedSymbolHashSlot::new(reader)?;
                header.exported_hash_slots.push(slot);
            }
            for _ in 0..exported_symbol_count {
                let key = ExportedSymbolKey::new(reader)?;
                header.exported_symbol_keys.push(key);
            }
            for i in 0..exported_symbol_count {
                let symbol = {
                    let key = &header.exported_symbol_keys[i as usize];
                    ExportedSymbol::new(reader, &header, key)?
                };
                header.exported_symbols.push(symbol);
            }

            Ok(header)
        })();

        reader.set_pointer_index(old_index);
        result
    }

    /// The mainSection field (4 bytes) specifies the number of the section in this container
    /// that contains the main symbol. If the fragment does not have a main symbol, this field is
    /// set to -1.
    ///
    /// Port of `LoaderInfoHeader.getMainSection()`.
    pub fn main_section(&self) -> i32 {
        self.main_section
    }

    /// The mainOffset field (4 bytes) indicates the offset (in bytes) from the beginning of the
    /// section to the main symbol.
    ///
    /// Port of `LoaderInfoHeader.getMainOffset()`.
    pub fn main_offset(&self) -> i32 {
        self.main_offset
    }

    /// The initSection field (4 bytes) contains the number of the section containing the
    /// initialization function's transition vector. If no initialization function exists, this
    /// field is set to -1.
    ///
    /// Port of `LoaderInfoHeader.getInitSection()`.
    pub fn init_section(&self) -> i32 {
        self.init_section
    }

    /// The initOffset field (4 bytes) indicates the offset (in bytes) from the beginning of the
    /// section to the initialization function's transition vector.
    ///
    /// Port of `LoaderInfoHeader.getInitOffset()`.
    pub fn init_offset(&self) -> i32 {
        self.init_offset
    }

    /// The termSection field (4 bytes) contains the number of the section containing the
    /// termination routine's transition vector. If no termination routine exists, this field is
    /// set to -1.
    ///
    /// Port of `LoaderInfoHeader.getTermSection()`.
    pub fn term_section(&self) -> i32 {
        self.term_section
    }

    /// The termOffset field (4 bytes) indicates the offset (in bytes) from the beginning of the
    /// section to the termination routine's transition vector.
    ///
    /// Port of `LoaderInfoHeader.getTermOffset()`.
    pub fn term_offset(&self) -> i32 {
        self.term_offset
    }

    /// The importedLibraryCount field (4 bytes) indicates the number of imported libraries.
    ///
    /// Port of `LoaderInfoHeader.getImportedLibraryCount()`.
    pub fn imported_library_count(&self) -> i32 {
        self.imported_library_count
    }

    /// The totalImportedSymbolCount field (4 bytes) indicates the total number of imported
    /// symbols.
    ///
    /// Port of `LoaderInfoHeader.getTotalImportedSymbolCount()`.
    pub fn total_imported_symbol_count(&self) -> i32 {
        self.total_imported_symbol_count
    }

    /// The relocSectionCount field (4 bytes) indicates the number of sections containing
    /// load-time relocations.
    ///
    /// Port of `LoaderInfoHeader.getRelocSectionCount()`.
    pub fn reloc_section_count(&self) -> i32 {
        self.reloc_section_count
    }

    /// The relocInstrOffset field (4 bytes) indicates the offset (in bytes) from the beginning
    /// of the loader section to the start of the relocations area.
    ///
    /// Port of `LoaderInfoHeader.getRelocInstrOffset()`.
    pub fn reloc_instr_offset(&self) -> i32 {
        self.reloc_instr_offset
    }

    /// The loaderStringsOffset field (4 bytes) indicates the offset (in bytes) from the
    /// beginning of the loader section to the start of the loader string table.
    ///
    /// Port of `LoaderInfoHeader.getLoaderStringsOffset()`.
    pub fn loader_strings_offset(&self) -> i32 {
        self.loader_strings_offset
    }

    /// The exportHashOffset field (4 bytes) indicates the offset (in bytes) from the beginning
    /// of the loader section to the start of the export hash table.
    ///
    /// Port of `LoaderInfoHeader.getExportHashOffset()`.
    pub fn export_hash_offset(&self) -> i32 {
        self.export_hash_offset
    }

    /// The exportHashTablePower field (4 bytes) indicates the number of hash index values,
    /// expressed as a power of two.
    ///
    /// Port of `LoaderInfoHeader.getExportHashTablePower()`.
    pub fn export_hash_table_power(&self) -> i32 {
        self.export_hash_table_power
    }

    /// The exportedSymbolCount field (4 bytes) indicates the number of symbols exported from
    /// this container.
    ///
    /// Port of `LoaderInfoHeader.getExportedSymbolCount()`.
    pub fn exported_symbol_count(&self) -> i32 {
        self.exported_symbol_count
    }

    /// Returns the section corresponding to this loader.
    ///
    /// Port of `LoaderInfoHeader.getSection()`.
    pub fn section(&self) -> &dyn SectionHeader {
        self.section.as_ref()
    }

    /// Finds the PEF library that contains the specified imported symbol index.
    ///
    /// Port of `LoaderInfoHeader.findLibrary(int)`.
    pub fn find_library(&self, symbol_index: i32) -> Option<&ImportedLibrary> {
        self.imported_libraries.iter().find(|library| {
            symbol_index >= library.first_imported_symbol()
                && symbol_index < library.first_imported_symbol() + library.imported_symbol_count()
        })
    }

    /// Port of `LoaderInfoHeader.getImportedLibraries()`.
    pub fn imported_libraries(&self) -> &[ImportedLibrary] {
        &self.imported_libraries
    }

    /// Port of `LoaderInfoHeader.getImportedSymbols()`.
    pub fn imported_symbols(&self) -> &[ImportedSymbol] {
        &self.imported_symbols
    }

    /// Port of `LoaderInfoHeader.getRelocations()`.
    pub fn relocations(&self) -> &[LoaderRelocationHeader] {
        &self.relocations
    }

    /// Port of `LoaderInfoHeader.getExportedHashSlots()`.
    pub fn exported_hash_slots(&self) -> &[ExportedSymbolHashSlot] {
        &self.exported_hash_slots
    }

    /// Port of `LoaderInfoHeader.getExportedSymbolKeys()`.
    pub fn exported_symbol_keys(&self) -> &[ExportedSymbolKey] {
        &self.exported_symbol_keys
    }

    /// Port of `LoaderInfoHeader.getExportedSymbols()`.
    pub fn exported_symbols(&self) -> &[ExportedSymbol] {
        &self.exported_symbols
    }
}

impl StructConverter for LoaderInfoHeader {
    /// Port of `LoaderInfoHeader.toDataType()`, which delegates to
    /// `StructConverterUtil.toDataType(getClass())`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Ok(Box::new(StructConverterUtilDataType::to_data_type("LoaderInfoHeader", SIZEOF)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal in-memory [`BinaryReader`] sufficient for this module's tests: sequential
    /// big-endian 16/32-bit reads and pointer-index manipulation.
    struct MockReader {
        bytes: Vec<u8>,
        pos: u64,
    }

    impl MockReader {
        fn new(bytes: Vec<u8>) -> Self {
            MockReader { bytes, pos: 0 }
        }
    }

    impl BinaryReader for MockReader {
        fn length(&self) -> io::Result<u64> {
            Ok(self.bytes.len() as u64)
        }
        fn is_valid_index(&self, index: u64) -> bool {
            index < self.bytes.len() as u64
        }
        fn get_pointer_index(&self) -> u64 {
            self.pos
        }
        fn set_pointer_index(&mut self, index: u64) -> u64 {
            let old = self.pos;
            self.pos = index;
            old
        }
        fn is_little_endian(&self) -> bool {
            false
        }
        fn set_little_endian(&mut self, _is_little_endian: bool) {}
        fn read_byte(&self, index: u64) -> io::Result<u8> {
            self.bytes
                .get(index as usize)
                .copied()
                .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))
        }
        fn read_byte_array(&self, index: u64, n_elements: usize) -> io::Result<Vec<u8>> {
            let start = index as usize;
            let end = start + n_elements;
            self.bytes
                .get(start..end)
                .map(|s| s.to_vec())
                .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))
        }
        fn get_byte_provider(
            &self,
        ) -> std::rc::Rc<std::cell::RefCell<dyn crate::filesystem::ghidra::g_binary_reader::ByteProvider>>
        {
            unimplemented!("not needed by LoaderInfoHeader tests")
        }
        fn clone_at(&self, _new_index: u64) -> Box<dyn BinaryReader> {
            unimplemented!("not needed by LoaderInfoHeader tests")
        }
        fn clone_reader(&self) -> Box<dyn BinaryReader> {
            unimplemented!("not needed by LoaderInfoHeader tests")
        }
        fn as_big_endian(&self) -> Box<dyn BinaryReader> {
            unimplemented!("not needed by LoaderInfoHeader tests")
        }
        fn as_little_endian(&self) -> Box<dyn BinaryReader> {
            unimplemented!("not needed by LoaderInfoHeader tests")
        }
    }

    struct MockSectionHeader {
        container_offset: i32,
    }

    impl SectionHeader for MockSectionHeader {
        fn get_container_offset(&self) -> i32 {
            self.container_offset
        }
    }

    fn write_i32_be(buf: &mut Vec<u8>, value: i32) {
        buf.extend_from_slice(&value.to_be_bytes());
    }

    /// Builds a well-formed 56-byte header with every field zero (no imports, no relocations,
    /// a single all-zero export hash slot, no exported symbols) starting at container offset 0.
    fn zero_header_bytes() -> Vec<u8> {
        let mut buf = Vec::new();
        for _ in 0..14 {
            write_i32_be(&mut buf, 0);
        }
        buf
    }

    #[test]
    fn parses_header_fields_with_all_zero_fixture() {
        let mut reader = MockReader::new(zero_header_bytes());
        let section = Box::new(MockSectionHeader { container_offset: 0 });

        let header = LoaderInfoHeader::new(&mut reader, section).unwrap();

        assert_eq!(header.main_section(), 0);
        assert_eq!(header.imported_library_count(), 0);
        assert_eq!(header.reloc_section_count(), 0);
        assert_eq!(header.exported_symbol_count(), 0);
        assert!(header.imported_libraries().is_empty());
        assert!(header.relocations().is_empty());
        assert_eq!(header.exported_hash_slots().len(), 1);
        assert!(header.exported_symbols().is_empty());
        assert_eq!(header.section().get_container_offset(), 0);
    }

    #[test]
    fn restores_pointer_index_after_reading() {
        // 8 bytes of leading padding, then the 56-byte zero header at container offset 8.
        let mut bytes = vec![0u8; 8];
        bytes.extend(zero_header_bytes());
        let mut reader = MockReader::new(bytes);
        reader.set_pointer_index(3);
        let section = Box::new(MockSectionHeader { container_offset: 8 });

        LoaderInfoHeader::new(&mut reader, section).unwrap();

        // Matches Java's `finally { reader.setPointerIndex(oldIndex); }`.
        assert_eq!(reader.get_pointer_index(), 3);
    }

    #[test]
    fn find_library_locates_owning_library_by_symbol_index() {
        let mut buf = Vec::new();
        // mainSection .. termOffset
        for _ in 0..6 {
            write_i32_be(&mut buf, 0);
        }
        write_i32_be(&mut buf, 1); // importedLibraryCount
        write_i32_be(&mut buf, 0); // totalImportedSymbolCount
        write_i32_be(&mut buf, 0); // relocSectionCount
        write_i32_be(&mut buf, 0); // relocInstrOffset
        write_i32_be(&mut buf, 0); // loaderStringsOffset
        write_i32_be(&mut buf, 80); // exportHashOffset (56 header + 24 library bytes)
        write_i32_be(&mut buf, 0); // exportHashTablePower
        write_i32_be(&mut buf, 0); // exportedSymbolCount
        assert_eq!(buf.len(), 56);

        // ImportedLibrary: nameOffset, oldImpVersion, currentVersion (unused by the stub).
        write_i32_be(&mut buf, 0);
        write_i32_be(&mut buf, 0);
        write_i32_be(&mut buf, 0);
        write_i32_be(&mut buf, 5); // importedSymbolCount
        write_i32_be(&mut buf, 10); // firstImportedSymbol
        buf.push(0); // options
        buf.push(0); // reservedA
        buf.extend_from_slice(&0i16.to_be_bytes()); // reservedB
        assert_eq!(buf.len(), 80);

        // Single export hash slot at exportHashOffset (0).
        write_i32_be(&mut buf, 0);
        assert_eq!(buf.len(), 84);

        let mut reader = MockReader::new(buf);
        let section = Box::new(MockSectionHeader { container_offset: 0 });

        let header = LoaderInfoHeader::new(&mut reader, section).unwrap();

        assert_eq!(header.imported_libraries().len(), 1);
        assert!(header.find_library(9).is_none());
        assert!(header.find_library(10).is_some());
        assert!(header.find_library(14).is_some());
        assert!(header.find_library(15).is_none());
    }

    #[test]
    fn to_data_type_reports_fixed_header_length() {
        let mut reader = MockReader::new(zero_header_bytes());
        let section = Box::new(MockSectionHeader { container_offset: 0 });
        let header = LoaderInfoHeader::new(&mut reader, section).unwrap();

        let dt = header.to_data_type().unwrap();
        assert_eq!(dt.get_length(), SIZEOF);
        assert_eq!(dt.get_name(), "LoaderInfoHeader");
    }
}

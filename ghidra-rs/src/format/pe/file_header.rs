//! Port of `ghidra.app.util.bin.format.pe.FileHeader`.
//!
//! ```text
//! typedef struct _IMAGE_FILE_HEADER {
//!     WORD    Machine;                            // MANDATORY
//!     WORD    NumberOfSections;                   // USED
//!     DWORD   TimeDateStamp;
//!     DWORD   PointerToSymbolTable;
//!     DWORD   NumberOfSymbols;
//!     WORD    SizeOfOptionalHeader;                // USED
//!     WORD    Characteristics;                     // MANDATORY
//! } IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
//! ```
//!
//! **Section headers not yet modeled**: `ghidra.app.util.bin.format.pe.SectionHeader` (the
//! per-section `IMAGE_SECTION_HEADER` type `FileHeader.processSections()` parses into
//! `sectionHeaders`) is a separate, not-yet-ported 640-line class with its own large surface
//! (name/characteristics/relocations/line numbers, `readSectionHeader` factory, ...). Faithfully
//! porting it is out of scope for this class -- it is scheduled later in the recursive-descent
//! order (`SectionHeader.java`, still `TODO`). `processSections`, `getSectionHeaders`,
//! `getSectionHeader(int)`, `getSectionHeader(String)`, and `getSectionHeaderContaining` are
//! therefore deferred: sections are never populated, and the accessors return empty/`None`,
//! matching the `None`-returning default already used by every current caller of
//! `FileHeader::get_section_header` (`LoadConfigDirectory`, via
//! `crate::format::pe::seam_stubs::SectionHeader`, an unrelated *minimal* placeholder built only
//! for that caller's two-field need -- not to be confused with the real, unported
//! `ghidra.app.util.bin.format.pe.SectionHeader`).
//!
//! **Symbol parsing wired into the constructor**: Java's constructor only reads the fixed 20-byte
//! header (`parse()`); `processSymbols()`/`processSections()` are called afterward by `NTHeader`
//! once the surrounding `OptionalHeader` exists. Since `NTHeader` itself is still only a seam
//! placeholder trait in this crate (no real orchestration code exists to call these at the right
//! time), [`FileHeader::new`] calls [`process_symbols`](FileHeader::process_symbols) itself right
//! after reading the header, using the real
//! [`DebugCOFFSymbol`](crate::format::pe::debug::debug_coff_symbol::DebugCOFFSymbol) port. This
//! should be revisited once `NTHeader` gets a real, orchestrating port.
//!
//! **Write path not ported**: `writeHeader`/`addSection`/`computeAlignedNewPosition` (PE-file
//! *mutation*, used by a PE builder feature, not the importer/analysis path) need
//! `RandomAccessFile`/`DataConverter`/`MemoryBlock`/`DataDirectory`/`BoundImportDataDirectory`/
//! `PortableExecutable`, none of which are ported. Omitted entirely rather than stubbed, since
//! nothing in this crate calls them yet.
//!
//! **`to_data_type` not yet buildable**: same limitation as `ImageCor20Header`/
//! `DefaultDataDirectory`/`LoadConfigDirectory` -- the `WORD`/`DWORD` singletons Java uses to
//! build the structure are still traits without a concrete instantiable form.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::pe::debug::debug_coff_symbol::DebugCOFFSymbol;
use crate::format::pe::machine_constants::{
    IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_ARM, IMAGE_FILE_MACHINE_ARM64,
    IMAGE_FILE_MACHINE_ARMNT, IMAGE_FILE_MACHINE_I386,
};
use crate::format::pe::machine_name;
use crate::format::seam_stubs::NTHeader;
use crate::program::model::data::data_type::DataType;
use crate::util::msg::Msg;

/// Port of `FileHeader.NAME`.
pub const NAME: &str = "IMAGE_FILE_HEADER";
/// Port of `FileHeader.IMAGE_SIZEOF_FILE_HEADER`.
pub const IMAGE_SIZEOF_FILE_HEADER: i32 = 20;

/// Port of `FileHeader.IMAGE_FILE_RELOCS_STRIPPED`.
pub const IMAGE_FILE_RELOCS_STRIPPED: i16 = 0x0001;
/// Port of `FileHeader.IMAGE_FILE_EXECUTABLE_IMAGE`.
pub const IMAGE_FILE_EXECUTABLE_IMAGE: i16 = 0x0002;
/// Port of `FileHeader.IMAGE_FILE_LINE_NUMS_STRIPPED`.
pub const IMAGE_FILE_LINE_NUMS_STRIPPED: i16 = 0x0004;
/// Port of `FileHeader.IMAGE_FILE_LOCAL_SYMS_STRIPPED`.
pub const IMAGE_FILE_LOCAL_SYMS_STRIPPED: i16 = 0x0008;
/// Port of `FileHeader.IMAGE_FILE_AGGRESIVE_WS_TRIM`.
pub const IMAGE_FILE_AGGRESIVE_WS_TRIM: i16 = 0x0010;
/// Port of `FileHeader.IMAGE_FILE_LARGE_ADDRESS_AWARE`.
pub const IMAGE_FILE_LARGE_ADDRESS_AWARE: i16 = 0x0020;
/// Port of `FileHeader.IMAGE_FILE_BYTES_REVERSED_LO`.
pub const IMAGE_FILE_BYTES_REVERSED_LO: i16 = 0x0080;
/// Port of `FileHeader.IMAGE_FILE_32BIT_MACHINE`.
pub const IMAGE_FILE_32BIT_MACHINE: i16 = 0x0100;
/// Port of `FileHeader.IMAGE_FILE_DEBUG_STRIPPED`.
pub const IMAGE_FILE_DEBUG_STRIPPED: i16 = 0x0200;
/// Port of `FileHeader.IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP`.
pub const IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP: i16 = 0x0400;
/// Port of `FileHeader.IMAGE_FILE_NET_RUN_FROM_SWAP`.
pub const IMAGE_FILE_NET_RUN_FROM_SWAP: i16 = 0x0800;
/// Port of `FileHeader.IMAGE_FILE_SYSTEM`.
pub const IMAGE_FILE_SYSTEM: i16 = 0x1000;
/// Port of `FileHeader.IMAGE_FILE_DLL`.
pub const IMAGE_FILE_DLL: i16 = 0x2000;
/// Port of `FileHeader.IMAGE_FILE_UP_SYSTEM_ONLY`.
pub const IMAGE_FILE_UP_SYSTEM_ONLY: i16 = 0x4000;
/// Port of `FileHeader.IMAGE_FILE_BYTES_REVERSED_HI`.
pub const IMAGE_FILE_BYTES_REVERSED_HI: i16 = 0x8000u16 as i16;

/// Port of `FileHeader.LORDPE_SYMBOL_TABLE`.
const LORDPE_SYMBOL_TABLE: i32 = 0x726F_4C5B;
/// Port of `FileHeader.LORDPE_NUMBER_OF_SYMBOLS`.
const LORDPE_NUMBER_OF_SYMBOLS: i32 = 0x5D45_5064u32 as i32;

/// The size of a Java `DebugCOFFSymbolAux.IMAGE_SIZEOF_AUX_SYMBOL`. `DebugCOFFSymbolAux` is not
/// ported yet (only a minimal marker-ish trait placeholder exists), so this constant is
/// reproduced directly (its value never changes: it is the fixed size of an `IMAGE_AUX_SYMBOL`
/// record), same convention as `CliStreamHeader`'s `DWORD_LEN`.
const IMAGE_SIZEOF_AUX_SYMBOL: i32 = 18;

/// Port of `ghidra.app.util.bin.format.pe.FileHeader`.
pub struct FileHeader {
    pub machine: i16,
    pub number_of_sections: i32,
    pub time_date_stamp: i32,
    pub pointer_to_symbol_table: i32,
    pub number_of_symbols: i32,
    pub size_of_optional_header: i16,
    pub characteristics: i16,
    symbols: Vec<DebugCOFFSymbol>,
}

impl FileHeader {
    /// Port of `FileHeader(BinaryReader, int, NTHeader)` + `parse()`. See this module's docs for
    /// why `process_symbols` is called here rather than externally by `NTHeader`.
    pub fn new(reader: &mut dyn BinaryReader, start_index: i64, nt_header: &dyn NTHeader) -> io::Result<Self> {
        reader.set_pointer_index(start_index as u64);

        let machine = reader.read_next_short()?;
        let number_of_sections = reader.read_next_unsigned_short()? as i32;
        let time_date_stamp = reader.read_next_int()?;
        let pointer_to_symbol_table = reader.read_next_int()?;
        let number_of_symbols = reader.read_next_int()?;
        let size_of_optional_header = reader.read_next_short()?;
        let characteristics = reader.read_next_short()?;

        let mut file_header = FileHeader {
            machine,
            number_of_sections,
            time_date_stamp,
            pointer_to_symbol_table,
            number_of_symbols,
            size_of_optional_header,
            characteristics,
            symbols: Vec::new(),
        };
        file_header.process_symbols(nt_header, reader)?;
        Ok(file_header)
    }

    /// Port of `FileHeader.getMachine()`.
    pub fn get_machine(&self) -> i16 {
        self.machine
    }

    /// Port of `FileHeader.getMachineName()`.
    pub fn get_machine_name(&self) -> String {
        machine_name::get_name_i16(self.machine)
    }

    /// Port of `FileHeader.isX86()`.
    pub fn is_x86(&self) -> bool {
        matches!(
            self.machine as u16,
            IMAGE_FILE_MACHINE_I386 | IMAGE_FILE_MACHINE_AMD64
        )
    }

    /// Port of `FileHeader.isArm()`.
    pub fn is_arm(&self) -> bool {
        matches!(
            self.machine as u16,
            IMAGE_FILE_MACHINE_ARM | IMAGE_FILE_MACHINE_ARM64 | IMAGE_FILE_MACHINE_ARMNT
        )
    }

    /// Port of `FileHeader.getNumberOfSections()`.
    pub fn get_number_of_sections(&self) -> i32 {
        self.number_of_sections
    }

    /// Port of `FileHeader.getSectionHeaders()`. Always empty -- see this module's docs.
    pub fn get_section_headers(&self) -> &[()] {
        &[]
    }

    /// Port of `FileHeader.getSymbols()`.
    pub fn get_symbols(&self) -> &[DebugCOFFSymbol] {
        &self.symbols
    }

    /// Port of `FileHeader.getSectionHeaderContaining(int)`. Always `None` -- see this module's
    /// docs.
    pub fn get_section_header_containing(&self, _virtual_addr: i32) -> Option<()> {
        None
    }

    /// Port of `FileHeader.getSectionHeader(int)`. Always `None` -- see this module's docs. This
    /// is the one accessor an existing caller
    /// ([`LoadConfigDirectory`](crate::format::pe::load_config_directory::LoadConfigDirectory))
    /// already depends on through the `NTHeader`/`FileHeader` seam placeholders, so the return
    /// type matches what that caller already expects: the *minimal*, unrelated
    /// `crate::format::pe::seam_stubs::SectionHeader` two-field placeholder (not the real,
    /// unported `ghidra.app.util.bin.format.pe.SectionHeader`).
    pub fn get_section_header(
        &self,
        _index: i32,
    ) -> Option<Box<dyn crate::format::pe::seam_stubs::SectionHeader>> {
        None
    }

    /// Port of `FileHeader.getSectionHeader(String)`. Always `None` -- see this module's docs.
    pub fn get_section_header_by_name(&self, _name: &str) -> Option<()> {
        None
    }

    /// Port of `FileHeader.getTimeDateStamp()`.
    pub fn get_time_date_stamp(&self) -> i32 {
        self.time_date_stamp
    }

    /// Port of `FileHeader.getPointerToSymbolTable()`.
    pub fn get_pointer_to_symbol_table(&self) -> i32 {
        self.pointer_to_symbol_table
    }

    /// Port of `FileHeader.getNumberOfSymbols()`.
    pub fn get_number_of_symbols(&self) -> i32 {
        self.number_of_symbols
    }

    /// Port of `FileHeader.getSizeOfOptionalHeader()`.
    pub fn get_size_of_optional_header(&self) -> i16 {
        self.size_of_optional_header
    }

    /// Port of `FileHeader.getCharacteristics()`.
    pub fn get_characteristics(&self) -> i16 {
        self.characteristics
    }

    /// Port of `FileHeader.getPointerToSections()`. Java reads
    /// `ntHeader.getFileHeader().sizeOfOptionalHeader` rather than `this.sizeOfOptionalHeader`;
    /// in every real usage `ntHeader.getFileHeader()` returns `this` itself, so this port reads
    /// `self.size_of_optional_header` directly instead of round-tripping back out through
    /// `nt_header` (which, now that `FileHeader` is a concrete struct rather than a `NTHeader`-
    /// owned trait object, would require `nt_header` to already own a second, possibly-different
    /// `FileHeader`).
    pub fn get_pointer_to_sections(&self, start_index: i64, nt_header: &dyn NTHeader) -> i32 {
        let size_opt_hdr = self.size_of_optional_header;
        let ptr_to_sections = start_index as i32 + IMAGE_SIZEOF_FILE_HEADER + size_opt_hdr as i32;
        let test_size = if nt_header.get_optional_header().is64bit() {
            crate::format::pe::constants::IMAGE_SIZEOF_NT_OPTIONAL64_HEADER
        }
        else {
            crate::format::pe::constants::IMAGE_SIZEOF_NT_OPTIONAL32_HEADER
        };
        if size_opt_hdr as u32 != test_size {
            Msg::warn("FileHeader", &format!("Non-standard optional header size: {size_opt_hdr} bytes"));
        }
        ptr_to_sections
    }

    /// Port of `FileHeader.processSections(OptionalHeader, boolean)`. Deferred -- see this
    /// module's docs. Always a no-op.
    pub fn process_sections(&mut self) {
        // Not yet supported: `SectionHeader` is not ported.
    }

    /// Port of `FileHeader.processSymbols()`.
    fn process_symbols(&mut self, nt_header: &dyn NTHeader, reader: &mut dyn BinaryReader) -> io::Result<()> {
        if nt_header.is_rva_resoltion_section_aligned() {
            // Symbol table offsets are only valid when parsing from file, not memory.
            return Ok(());
        }

        if self.is_lord_pe() {
            return Ok(());
        }

        let old_index = reader.get_pointer_index();

        let symbol_table_offset = self.get_pointer_to_symbol_table();
        if symbol_table_offset == 0 {
            return Ok(());
        }
        if self.number_of_symbols < 0 || self.number_of_symbols > crate::format::seam_stubs::NT_HEADER_MAX_SANE_COUNT {
            Msg::error(
                "FileHeader",
                &format!("Invalid symbol count: {:x}", self.number_of_symbols),
            );
            return Ok(());
        }

        let string_table_offset = self.get_string_table_offset(nt_header, reader)?;

        let mut symbol_table_offset = symbol_table_offset as i64;
        let mut i = 0;
        while i < self.number_of_symbols {
            if symbol_table_offset < 0 || symbol_table_offset as u64 >= reader.length()? {
                Msg::error(
                    "FileHeader",
                    &format!("Invalid symbol table file index: {symbol_table_offset:x}"),
                );
                break;
            }

            // Java passes a possibly-negative `long` `stringTableOffset` straight through; a
            // negative value only matters if a symbol turns out to need string-table indirection
            // (`longVal > 0` inside `DebugCOFFSymbol`'s constructor), which added to Java's
            // silently-wrapping `long` arithmetic would produce a small/garbage offset. Rust's
            // `u64` addition panics on overflow instead of wrapping, so a negative sentinel is
            // clamped to 0 here rather than reproducing the bit pattern of -1 -- this only
            // affects the already-degenerate case where `pointerToSymbolTable` is invalid.
            let string_table_index = string_table_offset.max(0) as u64;
            let symbol = DebugCOFFSymbol::new(reader, symbol_table_offset as u64, string_table_index)?;

            let number_of_aux_symbols = symbol.get_number_of_aux_symbols();

            symbol_table_offset += DebugCOFFSymbol::IMAGE_SIZEOF_SYMBOL as i64;
            symbol_table_offset += IMAGE_SIZEOF_AUX_SYMBOL as i64 * number_of_aux_symbols as i64;

            if number_of_aux_symbols > 0 {
                i += number_of_aux_symbols;
            }

            self.symbols.push(symbol);
            i += 1;
        }

        reader.set_pointer_index(old_index);
        Ok(())
    }

    /// Port of `FileHeader.getStringTableOffset()`.
    fn get_string_table_offset(&self, nt_header: &dyn NTHeader, reader: &dyn BinaryReader) -> io::Result<i64> {
        if nt_header.is_rva_resoltion_section_aligned() {
            // String table offsets are only valid when parsing from file, not memory.
            return Ok(-1);
        }
        if self.pointer_to_symbol_table <= 0 || self.number_of_symbols < 0 {
            return Ok(-1);
        }
        let symbol_table_len = self.number_of_symbols as i64 * DebugCOFFSymbol::IMAGE_SIZEOF_SYMBOL as i64;
        if self.pointer_to_symbol_table as i64 + symbol_table_len > reader.length()? as i64 {
            return Ok(-1);
        }
        Ok(self.pointer_to_symbol_table as i64 + symbol_table_len)
    }

    /// Port of `FileHeader.isLordPE()`.
    pub fn is_lord_pe(&self) -> bool {
        self.get_pointer_to_symbol_table() == LORDPE_SYMBOL_TABLE
            && self.get_number_of_symbols() == LORDPE_NUMBER_OF_SYMBOLS
    }
}

impl StructConverter for FileHeader {
    /// Mirrors `toDataType()`. Not yet buildable -- see this module's docs.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Err(ToDataTypeError::Io(io::Error::new(
            io::ErrorKind::Unsupported,
            "FileHeader::to_data_type requires WORD/DWORD DataType singletons, which are not \
             yet ported to a concrete instantiable form",
        )))
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
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "eof"))
        }
        fn read_bytes(&mut self, index: u64, length: usize) -> io::Result<Vec<u8>> {
            let start = index as usize;
            let end = start + length;
            if end > self.0.len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "eof"));
            }
            Ok(self.0[start..end].to_vec())
        }
        fn write_byte(&mut self, _index: u64, _value: u8) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "read-only"))
        }
        fn write_bytes(&mut self, _index: u64, _values: &[u8]) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "read-only"))
        }
    }

    pub(crate) struct FixtureReader {
        provider: Rc<RefCell<dyn ByteProvider>>,
        little_endian: bool,
        current_index: u64,
    }

    impl FixtureReader {
        pub(crate) fn new(data: Vec<u8>) -> Self {
            FixtureReader {
                provider: Rc::new(RefCell::new(VecProvider(data))),
                little_endian: true,
                current_index: 0,
            }
        }
    }

    impl BinaryReader for FixtureReader {
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
            Box::new(FixtureReader {
                provider: Rc::clone(&self.provider),
                little_endian: self.little_endian,
                current_index: new_index,
            })
        }
    }

    pub(crate) struct FakeNtHeader {
        pub(crate) rva_aligned: bool,
    }

    impl NTHeader for FakeNtHeader {
        fn get_name(&self) -> String {
            "NT".to_string()
        }
        fn is_rva_resoltion_section_aligned(&self) -> bool {
            self.rva_aligned
        }
        fn get_file_header(&self) -> &FileHeader {
            unimplemented!()
        }
        fn get_optional_header(&self) -> Box<dyn crate::format::seam_stubs::OptionalHeader> {
            unimplemented!()
        }
        fn to_data_type(&self) -> io::Result<Box<dyn DataType>> {
            unimplemented!()
        }
        fn rva_to_pointer(&self, rva: i32) -> i32 {
            rva
        }
        fn rva_to_pointer_long(&self, rva: i64) -> i64 {
            rva
        }
        fn check_pointer(&self, _ptr: i64) -> bool {
            true
        }
        fn check_rva(&self, _rva: i64) -> bool {
            true
        }
        fn va_to_pointer(&self, va: i32) -> i32 {
            va
        }
    }

    fn header_bytes(machine: i16, number_of_sections: i16, size_of_optional_header: i16, characteristics: i16) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&machine.to_le_bytes());
        bytes.extend_from_slice(&number_of_sections.to_le_bytes());
        bytes.extend_from_slice(&0i32.to_le_bytes()); // TimeDateStamp
        bytes.extend_from_slice(&0i32.to_le_bytes()); // PointerToSymbolTable
        bytes.extend_from_slice(&0i32.to_le_bytes()); // NumberOfSymbols
        bytes.extend_from_slice(&size_of_optional_header.to_le_bytes());
        bytes.extend_from_slice(&characteristics.to_le_bytes());
        bytes
    }

    #[test]
    fn parses_fixed_20_byte_header() {
        let bytes = header_bytes(IMAGE_FILE_MACHINE_I386 as i16, 3, 0xe0, IMAGE_FILE_EXECUTABLE_IMAGE);
        let mut reader = FixtureReader::new(bytes);
        let nt_header = FakeNtHeader { rva_aligned: true };

        let fh = FileHeader::new(&mut reader, 0, &nt_header).unwrap();

        assert_eq!(fh.get_machine(), IMAGE_FILE_MACHINE_I386 as i16);
        assert_eq!(fh.get_number_of_sections(), 3);
        assert_eq!(fh.get_size_of_optional_header(), 0xe0);
        assert_eq!(fh.get_characteristics(), IMAGE_FILE_EXECUTABLE_IMAGE);
        assert_eq!(fh.get_pointer_to_symbol_table(), 0);
        assert_eq!(fh.get_number_of_symbols(), 0);
        assert!(fh.get_symbols().is_empty());
    }

    #[test]
    fn is_x86_and_is_arm_classify_known_machines() {
        let mut reader = FixtureReader::new(header_bytes(IMAGE_FILE_MACHINE_I386 as i16, 0, 0, 0));
        let nt_header = FakeNtHeader { rva_aligned: true };
        let fh = FileHeader::new(&mut reader, 0, &nt_header).unwrap();
        assert!(fh.is_x86());
        assert!(!fh.is_arm());

        let mut reader = FixtureReader::new(header_bytes(IMAGE_FILE_MACHINE_AMD64 as i16, 0, 0, 0));
        let fh = FileHeader::new(&mut reader, 0, &nt_header).unwrap();
        assert!(fh.is_x86());

        let mut reader = FixtureReader::new(header_bytes(IMAGE_FILE_MACHINE_ARM64 as i16, 0, 0, 0));
        let fh = FileHeader::new(&mut reader, 0, &nt_header).unwrap();
        assert!(fh.is_arm());
        assert!(!fh.is_x86());
    }

    #[test]
    fn get_machine_name_delegates_to_machine_name_module() {
        let mut reader = FixtureReader::new(header_bytes(IMAGE_FILE_MACHINE_I386 as i16, 0, 0, 0));
        let nt_header = FakeNtHeader { rva_aligned: true };
        let fh = FileHeader::new(&mut reader, 0, &nt_header).unwrap();
        assert_eq!(fh.get_machine_name(), machine_name::get_name_i16(IMAGE_FILE_MACHINE_I386 as i16));
    }

    #[test]
    fn symbols_are_not_parsed_when_rva_resolution_is_section_aligned() {
        // Non-zero pointerToSymbolTable/numberOfSymbols, but RVA-resolution is section-aligned
        // (i.e. parsing from memory, not file), so Java skips symbol table parsing entirely.
        let mut bytes = header_bytes(IMAGE_FILE_MACHINE_I386 as i16, 0, 0, 0);
        bytes[8..12].copy_from_slice(&100i32.to_le_bytes()); // PointerToSymbolTable
        bytes[12..16].copy_from_slice(&1i32.to_le_bytes()); // NumberOfSymbols
        let mut reader = FixtureReader::new(bytes);
        let nt_header = FakeNtHeader { rva_aligned: true };

        let fh = FileHeader::new(&mut reader, 0, &nt_header).unwrap();
        assert!(fh.get_symbols().is_empty());
    }

    #[test]
    fn is_lord_pe_detects_magic_values() {
        let mut bytes = header_bytes(IMAGE_FILE_MACHINE_I386 as i16, 0, 0, 0);
        bytes[8..12].copy_from_slice(&LORDPE_SYMBOL_TABLE.to_le_bytes());
        bytes[12..16].copy_from_slice(&LORDPE_NUMBER_OF_SYMBOLS.to_le_bytes());
        let mut reader = FixtureReader::new(bytes);
        let nt_header = FakeNtHeader { rva_aligned: true };

        let fh = FileHeader::new(&mut reader, 0, &nt_header).unwrap();
        assert!(fh.is_lord_pe());
    }

    #[test]
    fn to_data_type_is_not_yet_buildable() {
        let mut reader = FixtureReader::new(header_bytes(IMAGE_FILE_MACHINE_I386 as i16, 0, 0, 0));
        let nt_header = FakeNtHeader { rva_aligned: true };
        let fh = FileHeader::new(&mut reader, 0, &nt_header).unwrap();
        assert!(fh.to_data_type().is_err());
    }

    #[test]
    fn get_section_header_is_always_none() {
        let mut reader = FixtureReader::new(header_bytes(IMAGE_FILE_MACHINE_I386 as i16, 0, 0, 0));
        let nt_header = FakeNtHeader { rva_aligned: true };
        let fh = FileHeader::new(&mut reader, 0, &nt_header).unwrap();
        assert!(fh.get_section_header(0).is_none());
    }
}

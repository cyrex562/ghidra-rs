use std::cell::RefCell;
use std::io;
use std::rc::Rc;

use thiserror::Error;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::filesystem::ghidra::g_binary_reader::GByteStore;
use crate::format::coff::aout_header_factory::create_aout_header;
use crate::format::coff::coff_exception::CoffException;
use crate::format::coff::coff_machine_type;
use crate::format::coff::coff_symbol::CoffSymbol;
use crate::format::seam_stubs::{AoutHeader, CoffSectionHeader};
use crate::program::model::data::data_type::DataType;
use crate::util::task::TaskMonitor;

/// Error produced while constructing or parsing a [`CoffFileHeader`].
///
/// Stands in for the two checked exceptions Java declares across the constructor and `parse()`
/// (`IOException`, `CoffException`).
#[derive(Debug, Error)]
pub enum CoffFileHeaderError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Coff(#[from] CoffException),
}

/// A concrete [`BinaryReader`] backed by a [`GByteStore`].
///
/// The crate does not yet have a canonical production implementer of the `BinaryReader` trait
/// (only test mocks exist so far, plus a handful of other per-module private adapters such as
/// `ElfInfoItem`'s `ProviderBinaryReader`), so [`CoffFileHeader::new`] constructs this minimal
/// one -- mirroring the `GByteStore`-backed constructor of the original `BinaryReader.java`
/// class -- and keeps it for the file header's lifetime.
pub(crate) struct CoffBinaryReader {
    provider: Rc<RefCell<dyn GByteStore>>,
    is_little_endian: bool,
    current_index: u64,
}

impl CoffBinaryReader {
    pub(crate) fn new(provider: Rc<RefCell<dyn GByteStore>>, is_little_endian: bool) -> Self {
        CoffBinaryReader { provider, is_little_endian, current_index: 0 }
    }
}

impl BinaryReader for CoffBinaryReader {
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
        let previous = self.current_index;
        self.current_index = index;
        previous
    }

    fn is_little_endian(&self) -> bool {
        self.is_little_endian
    }

    fn set_little_endian(&mut self, is_little_endian: bool) {
        self.is_little_endian = is_little_endian;
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
        Box::new(CoffBinaryReader {
            provider: Rc::clone(&self.provider),
            is_little_endian: self.is_little_endian,
            current_index: new_index,
        })
    }
}

/// A COFF file header.
///
/// Port of `ghidra.app.util.bin.format.coff.CoffFileHeader`. The Java class has no subclasses,
/// so per this crate's shape rule it ports as a plain `struct` rather than a trait. This
/// replaces the `seam_stubs::CoffFileHeader` placeholder trait that `AoutHeaderFactory`,
/// `CoffRelocationContext`, and `CoffRelocationHandler` were built against; those are updated to
/// hold/reference this concrete type.
///
/// `parseSectionHeaders()` and the section-header portion of `parse()` construct
/// `CoffSectionHeader`/`CoffSectionHeader{1,2,3}` instances via `CoffSectionHeaderFactory`, none
/// of which are ported yet (only an empty marker-trait placeholder exists for
/// [`CoffSectionHeader`](crate::format::seam_stubs::CoffSectionHeader), with no factory and no
/// byte layout to skip by). [`sections`](Self::sections) therefore stays empty until those land;
/// see [`parse_section_headers`](Self::parse_section_headers) and
/// [`parse`](Self::parse) for details. `AoutHeaderFactory::create_aout_header` similarly cannot
/// yet construct a real `AoutHeader`/`AoutHeaderMIPS` when an optional header is present, so
/// `parse()` propagates that as an error in that case (a COFF file with `f_opthdr == 0` --
/// common for plain object files -- parses fully).
pub struct CoffFileHeader {
    f_magic: i16,
    f_nscns: i16,
    f_timdat: i32,
    f_symptr: i32,
    f_nsyms: i32,
    f_opthdr: i16,
    f_flags: i16,
    f_target_id: i16,
    reader: Box<dyn BinaryReader>,
    aout_header: Option<Box<dyn AoutHeader>>,
    sections: Vec<Box<dyn CoffSectionHeader>>,
    symbols: Vec<CoffSymbol>,
}

impl CoffFileHeader {
    /// Reads a `CoffFileHeader` from `provider`, probing both little- and big-endian
    /// interpretations to find one under which the header is valid.
    ///
    /// Port of `CoffFileHeader(GByteStore)`.
    pub fn new(provider: Rc<RefCell<dyn GByteStore>>) -> Result<Self, CoffFileHeaderError> {
        // Probe for matches using both little and big endian.
        let mut reader: Box<dyn BinaryReader> =
            Box::new(CoffBinaryReader::new(Rc::clone(&provider), true));
        if !Self::probe_valid(reader.as_ref())? {
            reader.set_little_endian(false);
            if !Self::probe_valid(reader.as_ref())? {
                return Err(CoffException::new("Not a valid COFF file").into());
            }
        }

        let f_magic = reader.read_next_short()?;
        let f_nscns = reader.read_next_short()?;
        let f_timdat = reader.read_next_int()?;
        let f_symptr = reader.read_next_int()?;
        let f_nsyms = reader.read_next_int()?;
        let f_opthdr = reader.read_next_short()?;
        let f_flags = reader.read_next_short()?;

        let f_target_id = if Self::is_coff_level_one_or_two(f_magic) {
            reader.read_next_short()?
        } else {
            0
        };

        Ok(CoffFileHeader {
            f_magic,
            f_nscns,
            f_timdat,
            f_symptr,
            f_nsyms,
            f_opthdr,
            f_flags,
            f_target_id,
            reader,
            aout_header: None,
            sections: Vec::new(),
            symbols: Vec::new(),
        })
    }

    fn is_coff_level_one_or_two(magic: i16) -> bool {
        let magic = magic as u16;
        magic == coff_machine_type::TICOFF1MAGIC || magic == coff_machine_type::TICOFF2MAGIC
    }

    /// Returns the magic COFF file identifier.
    ///
    /// Port of `getMagic()`.
    pub fn magic(&self) -> i16 {
        self.f_magic
    }

    /// Returns the number of sections in this COFF file.
    ///
    /// Port of `getSectionCount()`.
    pub fn section_count(&self) -> i16 {
        self.f_nscns
    }

    /// Returns the time stamp of when this file was created.
    ///
    /// Port of `getTimestamp()`.
    pub fn timestamp(&self) -> i32 {
        self.f_timdat
    }

    /// Returns the file offset to the symbol table.
    ///
    /// Port of `getSymbolTablePointer()`.
    pub fn symbol_table_pointer(&self) -> i32 {
        self.f_symptr
    }

    /// Returns the number of symbols in the symbol table.
    ///
    /// Port of `getSymbolTableEntries()`.
    pub fn symbol_table_entries(&self) -> i32 {
        self.f_nsyms
    }

    /// Returns the size in bytes of the optional header. The optional header immediately
    /// follows the file header and immediately precedes the section headers.
    ///
    /// Port of `getOptionalHeaderSize()`.
    pub fn optional_header_size(&self) -> i16 {
        self.f_opthdr
    }

    /// Returns the flags about this COFF.
    ///
    /// Port of `getFlags()`.
    pub fn flags(&self) -> i16 {
        self.f_flags
    }

    /// Returns the specific target id.
    ///
    /// Port of `getTargetID()`.
    ///
    /// # Errors
    /// Returns [`CoffException`] if this header is not COFF level one or two.
    pub fn target_id(&self) -> Result<i16, CoffException> {
        if !Self::is_coff_level_one_or_two(self.f_magic) {
            return Err(CoffException::new(
                "Calling this method is not valid for this COFF header type.",
            ));
        }
        Ok(self.f_target_id)
    }

    /// Returns the image base.
    ///
    /// Port of `getImageBase(boolean)`.
    pub fn image_base(&self, is_windows_platform: bool) -> i64 {
        if is_windows_platform && self.f_opthdr != 0 {
            0x80
        } else {
            0
        }
    }

    /// Returns the machine name.
    ///
    /// Port of `getMachineName()`.
    pub fn machine_name(&self) -> String {
        if Self::is_coff_level_one_or_two(self.f_magic) {
            self.f_target_id.to_string()
        } else {
            self.f_magic.to_string()
        }
    }

    /// Port of `getMachine()`.
    pub fn machine(&self) -> i16 {
        if Self::is_coff_level_one_or_two(self.f_magic) {
            self.f_target_id
        } else {
            self.f_magic
        }
    }

    /// Reads just the section headers, not including line numbers and relocations.
    ///
    /// Port of `parseSectionHeaders()`. See the struct's own docs for why
    /// [`sections`](Self::sections) stays empty: `CoffSectionHeaderFactory` and its
    /// `CoffSectionHeader{,1,2,3}` products are not ported yet, so no section headers can
    /// actually be constructed. Java restores the reader's position in a `finally` block
    /// regardless of what happens inside, so leaving the reader's position untouched here (this
    /// is a no-op) is externally equivalent for callers that only care about position.
    pub fn parse_section_headers(&mut self) -> io::Result<()> {
        Ok(())
    }

    /// Finishes the parsing of this file header: the optional (a.out) header, section headers,
    /// and symbol table.
    ///
    /// Port of `parse(TaskMonitor)`. See the struct's own docs for the optional-header and
    /// section-header limitations.
    pub fn parse(&mut self, monitor: &dyn TaskMonitor) -> Result<(), CoffFileHeaderError> {
        monitor.set_message("Completing file header parsing...");
        let original_index = self.reader.get_pointer_index();
        let result = self.parse_inner();
        self.reader.set_pointer_index(original_index);
        result
    }

    fn parse_inner(&mut self) -> Result<(), CoffFileHeaderError> {
        self.reader.set_pointer_index(self.sizeof() as u64);
        self.aout_header =
            create_aout_header(self.reader.as_mut(), self.f_opthdr, self.f_magic)?;

        // See parse_section_headers()'s docs: real CoffSectionHeader instances cannot be
        // constructed yet, so the section-header loop (and the per-section `section.parse(...)`
        // Java performs here) is skipped; `sections` stays empty.

        self.reader.set_pointer_index(self.f_symptr as u64);
        let mut i: i32 = 0;
        while i < self.f_nsyms {
            let symbol =
                CoffSymbol::new(self.reader.as_mut(), self.f_symptr, self.f_nsyms)?;
            i += 1 + symbol.auxiliary_count() as i32;
            self.symbols.push(symbol);
        }

        Ok(())
    }

    /// Returns the sections in this COFF header. See the struct's own docs for why this is
    /// always empty for now.
    ///
    /// Port of `getSections()`.
    pub fn sections(&self) -> &[Box<dyn CoffSectionHeader>] {
        &self.sections
    }

    /// Returns the symbols in this COFF header.
    ///
    /// Port of `getSymbols()`.
    pub fn symbols(&self) -> &[CoffSymbol] {
        &self.symbols
    }

    /// Port of `getSymbolAtIndex(long)`.
    pub fn symbol_at_index(&self, index: i64) -> Option<&CoffSymbol> {
        let mut actual_index: i64 = 0;
        for symbol in &self.symbols {
            if actual_index == index {
                return Some(symbol);
            }
            actual_index += 1;
            actual_index += symbol.auxiliary_symbols().len() as i64;
        }
        None
    }

    /// Returns the size (in bytes) of this COFF file header.
    ///
    /// Port of `sizeof()`.
    pub fn sizeof(&self) -> i32 {
        if Self::is_coff_level_one_or_two(self.f_magic) {
            22
        } else {
            20
        }
    }

    /// Returns the a.out optional header, if any. See the struct's own docs for why this stays
    /// `None` whenever `optional_header_size() != 0` (the optional header could not actually be
    /// parsed).
    ///
    /// Port of `getOptionalHeader()`.
    pub fn optional_header(&self) -> Option<&dyn AoutHeader> {
        self.aout_header.as_deref()
    }

    fn probe_valid(reader: &dyn BinaryReader) -> io::Result<bool> {
        const MIN_BYTE_LENGTH: u64 = 22;
        const COFF_NULL_SANITY_CHECK_LEN: usize = 64;

        if reader.length()? < MIN_BYTE_LENGTH {
            return Ok(false);
        }

        let magic = reader.read_short(0)? as u16;

        if magic == coff_machine_type::IMAGE_FILE_MACHINE_UNKNOWN
            && reader.length()? > COFF_NULL_SANITY_CHECK_LEN as u64
        {
            let header_bytes = reader.read_byte_array(0, COFF_NULL_SANITY_CHECK_LEN)?;
            if header_bytes.iter().all(|&b| b == 0) {
                return Ok(false);
            }
        }

        Ok(coff_machine_type::is_machine_type_defined(magic))
    }

    /// Tests if the underlying byte provider holds a valid `CoffFileHeader`.
    ///
    /// Port of `isValid()`.
    pub fn is_valid(&self) -> io::Result<bool> {
        Self::probe_valid(self.reader.as_ref())
    }
}

impl StructConverter for CoffFileHeader {
    /// Mirrors `toDataType()`. Not yet buildable: it requires `StructureDataType` (a mutable,
    /// constructible `Structure`), which is not ported yet.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Err(ToDataTypeError::Io(io::Error::new(
            io::ErrorKind::Unsupported,
            "CoffFileHeader::to_data_type requires StructureDataType, which is not yet ported",
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// Builds a minimal valid (level 0, i.e. not TI COFF) little-endian COFF file header: magic
    /// `IMAGE_FILE_MACHINE_I386`, `nscns` sections, `nsyms` symbols at `symptr`, zero optional
    /// header size (so `parse()` doesn't need `AoutHeader`), zero flags.
    fn minimal_header_bytes(nscns: i16, symptr: i32, nsyms: i32) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&0x014ci16.to_le_bytes()); // f_magic: IMAGE_FILE_MACHINE_I386
        data.extend_from_slice(&nscns.to_le_bytes()); // f_nscns
        data.extend_from_slice(&0i32.to_le_bytes()); // f_timdat
        data.extend_from_slice(&symptr.to_le_bytes()); // f_symptr
        data.extend_from_slice(&nsyms.to_le_bytes()); // f_nsyms
        data.extend_from_slice(&0i16.to_le_bytes()); // f_opthdr
        data.extend_from_slice(&0i16.to_le_bytes()); // f_flags
        // isValid()'s MIN_BYTE_LENGTH is 22 (the size of a level-one/two header, the largest
        // fixed-size header), so pad a 20-byte plain header out to that length; real COFF files
        // always have more data (sections/symbols) following the header anyway.
        data.resize(22, 0);
        data
    }

    fn provider(bytes: Vec<u8>) -> Rc<RefCell<dyn GByteStore>> {
        Rc::new(RefCell::new(VecProvider(bytes)))
    }

    struct NoopMonitor;
    impl TaskMonitor for NoopMonitor {
        fn is_cancelled(&self) -> bool {
            false
        }
        fn set_show_progress_value(&self, _show: bool) {}
        fn set_message(&self, _message: &str) {}
        fn get_message(&self) -> String {
            String::new()
        }
        fn set_progress(&self, _value: i64) {}
        fn initialize(&self, _max: i64) {}
        fn set_maximum(&self, _max: i64) {}
        fn get_maximum(&self) -> i64 {
            0
        }
        fn set_indeterminate(&self, _indeterminate: bool) {}
        fn is_indeterminate(&self) -> bool {
            false
        }
        fn check_cancelled(&self) -> Result<(), crate::util::exception::CancelledException> {
            Ok(())
        }
        fn increment_progress(&self, _amount: i64) {}
        fn get_progress(&self) -> i64 {
            0
        }
        fn cancel(&self) {}
        fn add_cancelled_listener(&self, _listener: Box<dyn crate::util::task::CancelledListener>) {}
        fn remove_cancelled_listener(&self, _listener: &dyn crate::util::task::CancelledListener) {}
        fn set_cancel_enabled(&self, _enabled: bool) {}
        fn is_cancel_enabled(&self) -> bool {
            true
        }
        fn clear_cancelled(&self) {}
    }

    #[test]
    fn parses_minimal_valid_header() {
        let bytes = minimal_header_bytes(0, 0, 0);
        let header = CoffFileHeader::new(provider(bytes)).expect("should parse");
        assert_eq!(header.magic(), 0x014c);
        assert_eq!(header.section_count(), 0);
        assert_eq!(header.symbol_table_pointer(), 0);
        assert_eq!(header.symbol_table_entries(), 0);
        assert_eq!(header.optional_header_size(), 0);
        assert_eq!(header.sizeof(), 20);
    }

    #[test]
    fn rejects_too_short_buffer() {
        let bytes = vec![0u8; 4];
        match CoffFileHeader::new(provider(bytes)) {
            Err(CoffFileHeaderError::Coff(_)) => {}
            Err(other) => panic!("expected CoffFileHeaderError::Coff, got a different error variant instead: {other}"),
            Ok(_) => panic!("too short buffer should not parse as a valid header"),
        }
    }

    #[test]
    fn coff_level_one_adds_target_id_field_and_sizeof_22() {
        let mut data = Vec::new();
        data.extend_from_slice(&(coff_machine_type::TICOFF1MAGIC as i16).to_le_bytes());
        data.extend_from_slice(&0i16.to_le_bytes()); // f_nscns
        data.extend_from_slice(&0i32.to_le_bytes()); // f_timdat
        data.extend_from_slice(&0i32.to_le_bytes()); // f_symptr
        data.extend_from_slice(&0i32.to_le_bytes()); // f_nsyms
        data.extend_from_slice(&0i16.to_le_bytes()); // f_opthdr
        data.extend_from_slice(&0i16.to_le_bytes()); // f_flags
        data.extend_from_slice(&7i16.to_le_bytes()); // f_target_id

        let header = CoffFileHeader::new(provider(data)).expect("should parse");
        assert_eq!(header.sizeof(), 22);
        assert_eq!(header.target_id().expect("level one has target id"), 7);
        assert_eq!(header.machine_name(), "7");
    }

    #[test]
    fn target_id_errors_for_non_level_one_or_two_header() {
        let bytes = minimal_header_bytes(0, 0, 0);
        let header = CoffFileHeader::new(provider(bytes)).expect("should parse");
        assert!(header.target_id().is_err());
    }

    #[test]
    fn parse_populates_symbol_table() {
        // Header: 0 sections, symbol table of 1 entry immediately after the (padded) header.
        let symptr = 22;
        let mut data = minimal_header_bytes(0, symptr, 1);

        // One symbol table entry (18 bytes): inline short name "sym", value, scnum, type,
        // sclass, numaux = 0.
        let mut name = [0u8; 8];
        name[..3].copy_from_slice(b"sym");
        data.extend_from_slice(&name);
        data.extend_from_slice(&0x1234i32.to_le_bytes()); // value
        data.extend_from_slice(&1i16.to_le_bytes()); // scnum
        data.extend_from_slice(&0i16.to_le_bytes()); // type
        data.push(2); // sclass
        data.push(0); // numaux

        let mut header = CoffFileHeader::new(provider(data)).expect("should parse header");
        header.parse(&NoopMonitor).expect("should parse symbol table");

        assert_eq!(header.symbols().len(), 1);
        assert_eq!(header.symbols()[0].name(), "sym");
        assert_eq!(header.symbols()[0].value(), 0x1234);
        assert_eq!(header.symbol_at_index(0).map(|s| s.name()), Some("sym"));
        assert!(header.symbol_at_index(1).is_none());
    }

    #[test]
    fn is_valid_reflects_underlying_bytes() {
        let bytes = minimal_header_bytes(0, 0, 0);
        let header = CoffFileHeader::new(provider(bytes)).expect("should parse");
        assert!(header.is_valid().expect("should not error"));
    }
}

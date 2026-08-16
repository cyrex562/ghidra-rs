//! Port of `ghidra.app.util.bin.format.pe.DebugDataDirectory`.
//!
//! Points to an array of `IMAGE_DEBUG_DIRECTORY` structures.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::ghidra_random_access_file::GhidraRandomAccessFile;
use crate::format::pe::pe_markupable::PeMarkupable;
use crate::format::seam_stubs::{
    DebugCodeViewEntry, DebugDirectoryEntry, DebugDirectoryParser, DebugMiscEntry, MessageLog,
    NTHeader, PeUtils,
};
use crate::program::model::address::{Address, AddressSpace};
use crate::program::model::listing::program::Program;
use crate::util::data_converter::DataConverter;
use crate::util::msg::Msg;
use crate::util::task::TaskMonitor;

const NAME: &str = "IMAGE_DIRECTORY_ENTRY_DEBUG";

/// The `IMAGE_DIRECTORY_ENTRY_DEBUG` slot index into `OptionalHeader.getDataDirectories()`,
/// mirroring `OptionalHeader.IMAGE_DIRECTORY_ENTRY_DEBUG`.
const IMAGE_DIRECTORY_ENTRY_DEBUG: i64 = 6;

/// Port of `ghidra.app.util.bin.format.pe.DebugDataDirectory`.
///
/// The abstract Java base class `DataDirectory` is not ported yet, so the
/// `virtualAddress`/`size`/`hasParsed` state and behavior it provided (`processDataDirectory`,
/// `getPointer`, ...) is folded directly into this concrete leaf type instead of being modeled as
/// a separate seam, mirroring the precedent set by
/// [`COMDescriptorDataDirectory`](crate::format::pe::com_descriptor_data_directory::COMDescriptorDataDirectory).
pub struct DebugDataDirectory {
    virtual_address: i32,
    size: i32,
    has_parsed: bool,
    parser: Option<DebugDirectoryParser>,
}

impl DebugDataDirectory {
    /// Port of `DebugDataDirectory(NTHeader, BinaryReader)`, which also runs
    /// `DataDirectory.processDataDirectory`.
    pub fn new(nt_header: &dyn NTHeader, reader: &mut dyn BinaryReader) -> io::Result<Self> {
        let mut directory =
            DebugDataDirectory { virtual_address: 0, size: 0, has_parsed: false, parser: None };
        directory.process_data_directory(nt_header, reader)?;
        Ok(directory)
    }

    /// Port of `DataDirectory.processDataDirectory`.
    fn process_data_directory(
        &mut self,
        nt_header: &dyn NTHeader,
        reader: &mut dyn BinaryReader,
    ) -> io::Result<()> {
        self.virtual_address = reader.read_next_int()?;
        self.size = reader.read_next_int()?;

        if self.virtual_address == 0 {
            return Ok(());
        }

        if !nt_header.check_rva(self.virtual_address as i64) {
            Msg::warn(
                "DebugDataDirectory",
                &format!(
                    "Skipping DataDirectory '{}'. RVA outside of image (RVA: {:#x}, Size: {:#x}). Could be a file-only data directory.",
                    self.get_directory_name(),
                    self.virtual_address,
                    self.size
                ),
            );
            return Ok(());
        }

        if self.size < 0 {
            Msg::warn(
                "DebugDataDirectory",
                &format!(
                    "Skipping DataDirectory '{}'. Invalid size (Size: {:#x}).",
                    self.get_directory_name(),
                    self.size
                ),
            );
            return Ok(());
        }

        self.has_parsed = self.parse(nt_header, reader)?;
        Ok(())
    }

    /// Port of `DebugDataDirectory.getDirectoryName()`.
    pub fn get_directory_name(&self) -> String {
        NAME.to_string()
    }

    /// Port of `DebugDataDirectory.parse()`. Java reads `reader`/`ntHeader`/`size` from fields
    /// inherited off `DataDirectory`; this port threads them through explicitly since they are
    /// only needed transiently, during construction.
    pub fn parse(&mut self, nt_header: &dyn NTHeader, reader: &dyn BinaryReader) -> io::Result<bool> {
        let ptr = self.get_pointer(nt_header);
        if ptr < 0 {
            return Ok(false);
        }

        let size_of_image = nt_header.get_optional_header().get_size_of_image();
        let parser =
            DebugDirectoryParser::new(reader, ptr as i64 as u64, self.size, size_of_image)?;
        self.parser = Some(parser);
        Ok(true)
    }

    /// Port of `DataDirectory.getVirtualAddress()`.
    pub fn get_virtual_address(&self) -> i32 {
        self.virtual_address
    }

    /// Port of `DataDirectory.setVirtualAddress(int)`.
    pub fn set_virtual_address(&mut self, addr: i32) {
        self.virtual_address = addr;
    }

    /// Port of `DataDirectory.getSize()`.
    pub fn get_size(&self) -> i32 {
        self.size
    }

    /// Port of `DataDirectory.setSize(int)`.
    pub fn set_size(&mut self, size: i32) {
        self.size = size;
    }

    /// Port of `DataDirectory.hasParsedCorrectly()`.
    pub fn has_parsed_correctly(&self) -> bool {
        self.has_parsed
    }

    /// Port of `DataDirectory.getPointer()`.
    pub fn get_pointer(&self, nt_header: &dyn NTHeader) -> i32 {
        if self.virtual_address == 0 {
            return -1;
        }
        let ptr = nt_header.rva_to_pointer(self.virtual_address);
        if ptr < 0 {
            Msg::error(
                "DebugDataDirectory",
                &format!("Invalid file index for {:#x}", self.virtual_address),
            );
        }
        ptr
    }

    /// Port of `DebugDataDirectory.getParser()`.
    pub fn get_parser(&self) -> Option<&DebugDirectoryParser> {
        self.parser.as_ref()
    }

    /// Port of `DataDirectory.createDirectoryBookmark`; a no-op until `Program` exposes a
    /// bookmark manager (same limitation as `create_directory_bookmark` in
    /// `com_descriptor_data_directory.rs`).
    fn create_directory_bookmark(&self, _program: &dyn Program, _addr: &Address) {}

    /// Port of the private `DataDirectory.createFragment`/`findFragment` helpers; always reports
    /// failure until `Listing`'s module/fragment tree is wired up here (same limitation as
    /// `create_directory_bookmark` above).
    fn create_fragment(
        &self,
        _program: &dyn Program,
        _fragment_name: &str,
        _start: &Address,
        _end: &Address,
    ) -> bool {
        false
    }

    /// Port of the private `DebugDataDirectory.getDataAddress`.
    fn get_data_address(
        &self,
        dd: &DebugDirectoryEntry,
        is_binary: bool,
        space: &std::sync::Arc<AddressSpace>,
        nt_header: &dyn NTHeader,
    ) -> Option<Address> {
        let ptr: i64 = if is_binary {
            let ptr = dd.get_pointer_to_raw_data() as i64;
            if ptr != 0 && !nt_header.check_pointer(ptr) {
                Msg::error("DebugDataDirectory", &format!("Invalid pointer {:x}", ptr));
                return None;
            }
            ptr
        } else {
            dd.get_address_of_raw_data() as i64
        };

        if ptr != 0 {
            if is_binary {
                return Some(space.address(ptr));
            }
            return Some(space.address(ptr + nt_header.get_optional_header().get_image_base()));
        }
        None
    }

    /// Port of the private `DebugDataDirectory.markupDebugCodeView`. `PdbInfoCodeView`/
    /// `PdbInfoDotNet` detection isn't modeled by [`DebugCodeViewEntry`] yet (see its doc
    /// comment), so `get_pdb_info`/`get_dot_net_pdb_info` always return `None` and there is
    /// nothing to mark up here yet beyond resolving the data address.
    fn markup_debug_code_view(
        &self,
        _program: &dyn Program,
        is_binary: bool,
        _log: &dyn MessageLog,
        space: &std::sync::Arc<AddressSpace>,
        nt_header: &dyn NTHeader,
    ) {
        let parser = match &self.parser {
            Some(p) => p,
            None => return,
        };
        if let Some(dcv) = parser.get_debug_code_view() {
            let _data_addr =
                self.get_data_address(dcv.get_debug_directory(), is_binary, space, nt_header);
        }
    }

    /// Port of the private `DebugDataDirectory.markupDebigMisc`.
    fn markup_debug_misc(
        &self,
        program: &dyn Program,
        is_binary: bool,
        log: &dyn MessageLog,
        space: &std::sync::Arc<AddressSpace>,
        nt_header: &dyn NTHeader,
    ) -> io::Result<()> {
        let parser = match &self.parser {
            Some(p) => p,
            None => return Ok(()),
        };
        if let Some(dm) = parser.get_debug_misc() {
            if let Some(data_addr) =
                self.get_data_address(dm.get_debug_directory(), is_binary, space, nt_header)
            {
                let dt = dm.to_data_type()?;
                PeUtils::create_data(program, &data_addr, dt.as_ref(), log)?;
            }
        }
        Ok(())
    }

    /// Port of `DataDirectory.writeBytes` as overridden by `DebugDataDirectory.writeBytes`.
    ///
    /// Java derives `templateDDD` (this directory's counterpart inside `template`) via
    /// `template.getNTHeader().getOptionalHeader().getDataDirectories()[IMAGE_DIRECTORY_ENTRY_DEBUG]`,
    /// downcast to `DebugDataDirectory`. `PortableExecutable` / the full `OptionalHeader` /
    /// the polymorphic `DataDirectory[]` table are not ported yet, and `DataDirectory` is a
    /// concrete-leaf-per-subtype seam rather than a trait object (per the DebugDataDirectory
    /// dependency-context notes), so
    /// this port takes the already-resolved `template` and `number_of_rva_and_sizes` directly
    /// instead of re-deriving them through that lookup.
    pub fn write_bytes(
        &self,
        raf: &mut GhidraRandomAccessFile,
        dc: &dyn DataConverter,
        template: &DebugDataDirectory,
        number_of_rva_and_sizes: i64,
        nt_header: &dyn NTHeader,
    ) -> io::Result<()> {
        if number_of_rva_and_sizes <= IMAGE_DIRECTORY_ENTRY_DEBUG {
            return Ok(());
        }
        if template.size == 0 {
            return Ok(());
        }

        let template_dirs: &[DebugDirectoryEntry] = match &template.parser {
            Some(p) => p.get_debug_directories(),
            None => return Ok(()),
        };
        let dirs: &[DebugDirectoryEntry] = match &self.parser {
            Some(p) => p.get_debug_directories(),
            None => return Ok(()),
        };

        for (i, d) in dirs.iter().enumerate() {
            d.write_header(raf, dc)?;

            if d.get_size_of_data() == 0 || d.get_pointer_to_raw_data() == 0 {
                continue;
            }

            let ptr = d.get_pointer_to_raw_data();
            if !nt_header.check_pointer(ptr as i64) {
                Msg::error("DebugDataDirectory", &format!("Invalid pointer {:x}", ptr));
                continue;
            }

            raf.seek(ptr as i64)?;
            if let Some(t) = template_dirs.get(i) {
                raf.write(&t.to_bytes(dc))?;
            }
        }

        Ok(())
    }

    /// Port of the package-private `DebugDataDirectory.updatePointers(int, int)`.
    pub(crate) fn update_pointers(&mut self, offset: i32, post_offset: i32) {
        if let Some(parser) = self.parser.as_mut() {
            for d in parser.get_debug_directories_mut() {
                if d.get_size_of_data() == 0 || d.get_pointer_to_raw_data() == 0 {
                    continue;
                }
                d.update_pointers(offset, post_offset);
            }
        }
    }
}

impl std::fmt::Display for DebugDataDirectory {
    /// Port of `DataDirectory.toString()`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "VirtualAddress: {:#x} Size: {} bytes",
            self.virtual_address, self.size
        )
    }
}

impl PeMarkupable for DebugDataDirectory {
    /// Port of `DebugDataDirectory.markup(...)`.
    fn markup(
        &self,
        program: &dyn Program,
        is_binary: bool,
        monitor: &dyn TaskMonitor,
        log: &dyn MessageLog,
        nt_header: &dyn NTHeader,
    ) -> Result<(), Box<dyn std::error::Error>> {
        monitor.set_message(&format!("{}: debug...", Program::get_name(program)));

        let addr = match PeUtils::get_markup_address(program, is_binary, nt_header, self.virtual_address) {
            Some(addr) => addr,
            None => return Ok(()),
        };

        let contains = program
            .get_memory()
            .map(|memory| memory.contains(&addr))
            .unwrap_or(false);
        if !contains {
            return Ok(());
        }

        self.create_directory_bookmark(program, &addr);

        let space = match program
            .get_address_factory()
            .and_then(|factory| factory.get_default_address_space())
        {
            Some(space) => space,
            None => return Ok(()),
        };

        let mut addr = addr;
        if let Some(parser) = &self.parser {
            for dd in parser.get_debug_directories() {
                let dt = dd.to_data_type()?;
                PeUtils::create_data(program, &addr, dt.as_ref(), log)?;
                addr = addr.add(DebugDirectoryEntry::IMAGE_SIZEOF_DEBUG_DIRECTORY as i64)?;

                if let Some(data_addr) = self.get_data_address(dd, is_binary, &space, nt_header) {
                    let end = data_addr.add(dd.get_size_of_data() as i64)?;
                    let success =
                        self.create_fragment(program, "Debug Data", &data_addr, &end);
                    if !success {
                        log.append_msg("Unable to create fragment: Debug Data");
                    }
                }
            }
        }

        self.markup_debug_misc(program, is_binary, log, &space, nt_header)?;
        self.markup_debug_code_view(program, is_binary, log, &space, nt_header);

        Ok(())
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

    struct FixtureReader {
        provider: Rc<RefCell<dyn ByteProvider>>,
        little_endian: bool,
        current_index: u64,
    }

    impl FixtureReader {
        fn new(data: Vec<u8>) -> Self {
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

    struct FixtureOptionalHeader {
        size_of_image: i64,
    }

    impl crate::format::seam_stubs::OptionalHeader for FixtureOptionalHeader {
        fn get_size_of_image(&self) -> i64 {
            self.size_of_image
        }
        fn get_image_base(&self) -> i64 {
            0x400000
        }
    }

    struct FixtureNtHeader {
        rva_ok: bool,
        size_of_image: i64,
    }

    impl NTHeader for FixtureNtHeader {
        fn get_name(&self) -> String {
            String::new()
        }
        fn is_rva_resoltion_section_aligned(&self) -> bool {
            true
        }
        fn get_file_header(&self) -> Box<dyn crate::format::seam_stubs::FileHeader> {
            unimplemented!()
        }
        fn get_optional_header(&self) -> Box<dyn crate::format::seam_stubs::OptionalHeader> {
            Box::new(FixtureOptionalHeader { size_of_image: self.size_of_image })
        }
        fn to_data_type(&self) -> io::Result<Box<dyn crate::program::model::data::data_type::DataType>> {
            unimplemented!()
        }
        fn rva_to_pointer(&self, rva: i32) -> i32 {
            // Identity mapping: RVA == pointer, mirroring an unrelocated single-section image.
            rva
        }
        fn rva_to_pointer_long(&self, rva: i64) -> i64 {
            rva
        }
        fn check_pointer(&self, _ptr: i64) -> bool {
            true
        }
        fn check_rva(&self, _rva: i64) -> bool {
            self.rva_ok
        }
        fn va_to_pointer(&self, va: i32) -> i32 {
            va
        }
    }

    /// Builds `[VirtualAddress][Size]` followed by `count` `IMAGE_DEBUG_DIRECTORY` entries, each
    /// with the given `(type, size_of_data)`; `pointer_to_raw_data`/`address_of_raw_data` are left
    /// zero, which keeps every entry's blob read skipped.
    fn directory_bytes(virtual_address: i32, entries: &[(i32, i32)]) -> Vec<u8> {
        let size = entries.len() as i32 * DebugDirectoryEntry::IMAGE_SIZEOF_DEBUG_DIRECTORY;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&virtual_address.to_le_bytes());
        bytes.extend_from_slice(&size.to_le_bytes());
        for &(ty, size_of_data) in entries {
            bytes.extend_from_slice(&0i32.to_le_bytes()); // Characteristics
            bytes.extend_from_slice(&0i32.to_le_bytes()); // TimeDateStamp
            bytes.extend_from_slice(&0i16.to_le_bytes()); // MajorVersion
            bytes.extend_from_slice(&0i16.to_le_bytes()); // MinorVersion
            bytes.extend_from_slice(&ty.to_le_bytes()); // Type
            bytes.extend_from_slice(&size_of_data.to_le_bytes()); // SizeOfData
            bytes.extend_from_slice(&0i32.to_le_bytes()); // AddressOfRawData
            bytes.extend_from_slice(&0i32.to_le_bytes()); // PointerToRawData
        }
        bytes
    }

    #[test]
    fn directory_name_matches_java_constant() {
        let mut reader = FixtureReader::new(vec![0u8; 8]);
        let nt_header = FixtureNtHeader { rva_ok: true, size_of_image: 0x1000 };
        let directory = DebugDataDirectory::new(&nt_header, &mut reader).unwrap();
        assert_eq!(directory.get_directory_name(), "IMAGE_DIRECTORY_ENTRY_DEBUG");
    }

    #[test]
    fn zero_virtual_address_skips_parsing() {
        let bytes = directory_bytes(0, &[]);
        let mut reader = FixtureReader::new(bytes);
        let nt_header = FixtureNtHeader { rva_ok: true, size_of_image: 0x1000 };

        let directory = DebugDataDirectory::new(&nt_header, &mut reader).unwrap();

        assert_eq!(directory.get_virtual_address(), 0);
        assert!(!directory.has_parsed_correctly());
        assert!(directory.get_parser().is_none());
    }

    #[test]
    fn invalid_rva_skips_parsing() {
        let bytes = directory_bytes(8, &[(DebugDirectoryParser::IMAGE_DEBUG_TYPE_UNKNOWN, 0)]);
        let mut reader = FixtureReader::new(bytes);
        let nt_header = FixtureNtHeader { rva_ok: false, size_of_image: 0x1000 };

        let directory = DebugDataDirectory::new(&nt_header, &mut reader).unwrap();

        assert!(!directory.has_parsed_correctly());
        assert!(directory.get_parser().is_none());
    }

    #[test]
    fn parses_debug_directory_entries_and_tags_description() {
        // Two entries: one Unknown, one Borland. Each entry has SizeOfData == 0, so the parser
        // loop's `if debugDir.getSizeOfData() == 0 break;` guard stops after the first one,
        // mirroring the Java behavior exactly (a zero-length entry always halts the scan).
        let bytes = directory_bytes(
            8,
            &[
                (DebugDirectoryParser::IMAGE_DEBUG_TYPE_UNKNOWN, 0),
                (DebugDirectoryParser::IMAGE_DEBUG_TYPE_BORLAND, 0),
            ],
        );
        let mut reader = FixtureReader::new(bytes);
        let nt_header = FixtureNtHeader { rva_ok: true, size_of_image: 0x1000 };

        let directory = DebugDataDirectory::new(&nt_header, &mut reader).unwrap();

        assert!(directory.has_parsed_correctly());
        let parser = directory.get_parser().expect("parser should be set");
        assert_eq!(parser.get_debug_directories().len(), 0);
    }

    #[test]
    fn parses_multiple_nonzero_debug_directory_entries() {
        let bytes = directory_bytes(
            8,
            &[
                (DebugDirectoryParser::IMAGE_DEBUG_TYPE_UNKNOWN, 4),
                (DebugDirectoryParser::IMAGE_DEBUG_TYPE_BORLAND, 4),
            ],
        );
        let mut reader = FixtureReader::new(bytes);
        let nt_header = FixtureNtHeader { rva_ok: true, size_of_image: 0x1000 };

        let directory = DebugDataDirectory::new(&nt_header, &mut reader).unwrap();

        assert!(directory.has_parsed_correctly());
        let parser = directory.get_parser().expect("parser should be set");
        let dirs = parser.get_debug_directories();
        assert_eq!(dirs.len(), 2);
        assert_eq!(dirs[0].get_type(), DebugDirectoryParser::IMAGE_DEBUG_TYPE_UNKNOWN);
        assert_eq!(dirs[0].get_description(), Some("Unknown"));
        assert_eq!(dirs[1].get_type(), DebugDirectoryParser::IMAGE_DEBUG_TYPE_BORLAND);
        assert_eq!(dirs[1].get_description(), Some("Borland"));
    }

    #[test]
    fn get_pointer_matches_nt_header_rva_to_pointer() {
        let bytes = directory_bytes(8, &[]);
        let mut reader = FixtureReader::new(bytes);
        let nt_header = FixtureNtHeader { rva_ok: true, size_of_image: 0x1000 };
        let directory = DebugDataDirectory::new(&nt_header, &mut reader).unwrap();

        assert_eq!(directory.get_pointer(&nt_header), 8);
    }

    #[test]
    fn get_pointer_is_negative_one_when_virtual_address_is_zero() {
        let mut reader = FixtureReader::new(vec![0u8; 8]);
        let nt_header = FixtureNtHeader { rva_ok: true, size_of_image: 0x1000 };
        let directory = DebugDataDirectory::new(&nt_header, &mut reader).unwrap();

        assert_eq!(directory.get_pointer(&nt_header), -1);
    }

    #[test]
    fn display_matches_java_to_string_format() {
        let bytes = directory_bytes(8, &[]);
        let mut reader = FixtureReader::new(bytes);
        let nt_header = FixtureNtHeader { rva_ok: true, size_of_image: 0x1000 };
        let directory = DebugDataDirectory::new(&nt_header, &mut reader).unwrap();

        assert_eq!(directory.to_string(), "VirtualAddress: 0x8 Size: 0 bytes");
    }

    #[test]
    fn write_bytes_is_noop_when_number_of_rva_and_sizes_too_small() {
        let bytes = directory_bytes(8, &[(DebugDirectoryParser::IMAGE_DEBUG_TYPE_UNKNOWN, 4)]);
        let mut reader = FixtureReader::new(bytes);
        let nt_header = FixtureNtHeader { rva_ok: true, size_of_image: 0x1000 };
        let directory = DebugDataDirectory::new(&nt_header, &mut reader).unwrap();

        let dc = crate::util::little_endian_data_converter::LittleEndianDataConverter;
        let f = tempfile::NamedTempFile::new().unwrap();
        let mut raf = GhidraRandomAccessFile::new(f.path(), "rw").unwrap();

        let result = directory.write_bytes(&mut raf, &dc, &directory, 3, &nt_header);
        assert!(result.is_ok());
        raf.close().unwrap();
    }

    #[test]
    fn update_pointers_skips_zero_size_entries() {
        let bytes = directory_bytes(8, &[(DebugDirectoryParser::IMAGE_DEBUG_TYPE_UNKNOWN, 0)]);
        let mut reader = FixtureReader::new(bytes);
        let nt_header = FixtureNtHeader { rva_ok: true, size_of_image: 0x1000 };
        let mut directory = DebugDataDirectory::new(&nt_header, &mut reader).unwrap();

        // No entries were kept (SizeOfData == 0 halts the scan), so this is a no-op that must
        // not panic.
        directory.update_pointers(4, 8);
        assert_eq!(directory.get_parser().unwrap().get_debug_directories().len(), 0);
    }
}

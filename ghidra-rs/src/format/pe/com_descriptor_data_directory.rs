//! Port of `ghidra.app.util.bin.format.pe.COMDescriptorDataDirectory`.
//!
//! This value has been renamed to `IMAGE_DIRECTORY_ENTRY_COMHEADER`.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::format::pe::pe_markupable::PeMarkupable;
use crate::format::seam_stubs::{ImageCor20Header, MessageLog, NTHeader, PeUtils};
use crate::program::model::address::Address;
use crate::program::model::listing::program::Program;
use crate::util::msg::Msg;
use crate::util::task::TaskMonitor;

const NAME: &str = "IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR";

/// Port of `ghidra.app.util.bin.format.pe.COMDescriptorDataDirectory`.
///
/// The abstract Java base class `DataDirectory` is not ported yet, so the
/// `virtualAddress`/`size`/`hasParsed` state and behavior it provided (`processDataDirectory`,
/// `getPointer`, ...) is folded directly into this concrete leaf type instead of being modeled as
/// a separate seam; this is the only `DataDirectory` subclass ported so far.
pub struct COMDescriptorDataDirectory {
    virtual_address: i32,
    size: i32,
    has_parsed: bool,
    header: Option<ImageCor20Header>,
}

impl COMDescriptorDataDirectory {
    /// Port of `COMDescriptorDataDirectory(NTHeader, BinaryReader)`, which also runs
    /// `DataDirectory.processDataDirectory`.
    pub fn new(nt_header: &dyn NTHeader, reader: &mut dyn BinaryReader) -> io::Result<Self> {
        let mut directory = COMDescriptorDataDirectory {
            virtual_address: 0,
            size: 0,
            has_parsed: false,
            header: None,
        };
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
                "COMDescriptorDataDirectory",
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
                "COMDescriptorDataDirectory",
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

    /// Port of `COMDescriptorDataDirectory.getHeader()`.
    pub fn get_header(&self) -> Option<&ImageCor20Header> {
        self.header.as_ref()
    }

    /// Port of `COMDescriptorDataDirectory.getDirectoryName()`.
    pub fn get_directory_name(&self) -> String {
        NAME.to_string()
    }

    /// Port of `COMDescriptorDataDirectory.parse()`. Java reads `reader`/`ntHeader` from fields
    /// inherited off `DataDirectory`; this port threads them through explicitly since they are
    /// only needed transiently, during construction.
    pub fn parse(
        &mut self,
        nt_header: &dyn NTHeader,
        reader: &mut dyn BinaryReader,
    ) -> io::Result<bool> {
        let ptr = self.get_pointer(nt_header);
        if ptr < 0 {
            return Ok(false);
        }

        let mut header = ImageCor20Header::new(reader, ptr as u64, nt_header)?;

        let mut parsed = false;
        if nt_header.should_parse_cli_headers() {
            parsed = header.parse()?;
        }
        self.header = Some(header);
        Ok(parsed)
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
                "COMDescriptorDataDirectory",
                &format!("Invalid file index for {:#x}", self.virtual_address),
            );
        }
        ptr
    }

    /// Port of `DataDirectory.createDirectoryBookmark`; a no-op until `Program` exposes a
    /// bookmark manager (same limitation as `markup_error_or_warning` in
    /// `abstract_elf_relocation_handler.rs`).
    fn create_directory_bookmark(&self, _program: &dyn Program, _addr: &Address) {}
}

impl std::fmt::Display for COMDescriptorDataDirectory {
    /// Port of `DataDirectory.toString()`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "VirtualAddress: {:#x} Size: {} bytes",
            self.virtual_address, self.size
        )
    }
}

impl PeMarkupable for COMDescriptorDataDirectory {
    /// Port of `COMDescriptorDataDirectory.markup(...)`.
    fn markup(
        &self,
        program: &dyn Program,
        is_binary: bool,
        monitor: &dyn TaskMonitor,
        log: &dyn MessageLog,
        nt_header: &dyn NTHeader,
    ) -> Result<(), Box<dyn std::error::Error>> {
        monitor.set_message(&format!(
            "[{}]: com descriptor(s)...",
            Program::get_name(program)
        ));

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

        let header = match self.header.as_ref() {
            Some(header) => header,
            None => return Ok(()),
        };
        let dt = header.to_data_type()?;
        PeUtils::create_data(program, &addr, dt.as_ref(), log)?;

        if self.has_parsed {
            header.markup(program, is_binary, monitor, log, nt_header)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    use crate::filesystem::ghidra::g_binary_reader::ByteProvider;
    use crate::program::model::data::data_type::DataType;

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

    struct FixtureNtHeader {
        rva_ok: bool,
        parse_cli_headers: bool,
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
            unimplemented!()
        }
        fn to_data_type(&self) -> io::Result<Box<dyn DataType>> {
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
        fn should_parse_cli_headers(&self) -> bool {
            self.parse_cli_headers
        }
    }

    fn directory_bytes(virtual_address: i32, size: i32, cor20_header: &[u8]) -> Vec<u8> {
        // IMAGE_DATA_DIRECTORY (8 bytes), followed by the IMAGE_COR20_HEADER it points at.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&virtual_address.to_le_bytes());
        bytes.extend_from_slice(&size.to_le_bytes());
        bytes.extend_from_slice(cor20_header);
        bytes
    }

    fn cor20_header_bytes(cb: i32, major: i16, minor: i16) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&cb.to_le_bytes());
        bytes.extend_from_slice(&major.to_le_bytes());
        bytes.extend_from_slice(&minor.to_le_bytes());
        bytes
    }

    #[test]
    fn directory_name_matches_java_constant() {
        let mut reader = FixtureReader::new(vec![0u8; 8]);
        let nt_header = FixtureNtHeader { rva_ok: true, parse_cli_headers: true };
        let directory = COMDescriptorDataDirectory::new(&nt_header, &mut reader).unwrap();
        assert_eq!(directory.get_directory_name(), "IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR");
    }

    #[test]
    fn zero_virtual_address_skips_parsing() {
        let bytes = directory_bytes(0, 0, &[]);
        let mut reader = FixtureReader::new(bytes);
        let nt_header = FixtureNtHeader { rva_ok: true, parse_cli_headers: true };

        let directory = COMDescriptorDataDirectory::new(&nt_header, &mut reader).unwrap();

        assert_eq!(directory.get_virtual_address(), 0);
        assert!(!directory.has_parsed_correctly());
        assert!(directory.get_header().is_none());
    }

    #[test]
    fn invalid_rva_skips_parsing() {
        let bytes = directory_bytes(8, 0x48, &cor20_header_bytes(0x48, 2, 5));
        let mut reader = FixtureReader::new(bytes);
        let nt_header = FixtureNtHeader { rva_ok: false, parse_cli_headers: true };

        let directory = COMDescriptorDataDirectory::new(&nt_header, &mut reader).unwrap();

        assert!(!directory.has_parsed_correctly());
        assert!(directory.get_header().is_none());
    }

    #[test]
    fn parses_header_when_cli_headers_enabled() {
        let bytes = directory_bytes(8, 0x48, &cor20_header_bytes(0x48, 2, 5));
        let mut reader = FixtureReader::new(bytes);
        let nt_header = FixtureNtHeader { rva_ok: true, parse_cli_headers: true };

        let directory = COMDescriptorDataDirectory::new(&nt_header, &mut reader).unwrap();

        assert_eq!(directory.get_virtual_address(), 8);
        assert_eq!(directory.get_size(), 0x48);
        assert!(directory.has_parsed_correctly());
        let header = directory.get_header().expect("header should be parsed");
        assert_eq!(header.cb, 0x48);
        assert_eq!(header.major_runtime_version, 2);
        assert_eq!(header.minor_runtime_version, 5);
    }

    #[test]
    fn header_built_but_not_parsed_when_cli_headers_disabled() {
        // Java still constructs ImageCor20Header, it just skips calling header.parse().
        let bytes = directory_bytes(8, 0x48, &cor20_header_bytes(0x48, 2, 5));
        let mut reader = FixtureReader::new(bytes);
        let nt_header = FixtureNtHeader { rva_ok: true, parse_cli_headers: false };

        let directory = COMDescriptorDataDirectory::new(&nt_header, &mut reader).unwrap();

        assert!(!directory.has_parsed_correctly());
        assert!(directory.get_header().is_some());
    }

    #[test]
    fn get_pointer_matches_nt_header_rva_to_pointer() {
        let bytes = directory_bytes(8, 0x48, &cor20_header_bytes(0x48, 2, 5));
        let mut reader = FixtureReader::new(bytes);
        let nt_header = FixtureNtHeader { rva_ok: true, parse_cli_headers: true };
        let directory = COMDescriptorDataDirectory::new(&nt_header, &mut reader).unwrap();

        assert_eq!(directory.get_pointer(&nt_header), 8);
    }

    #[test]
    fn get_pointer_is_negative_one_when_virtual_address_is_zero() {
        let mut reader = FixtureReader::new(vec![0u8; 8]);
        let nt_header = FixtureNtHeader { rva_ok: true, parse_cli_headers: true };
        let directory = COMDescriptorDataDirectory::new(&nt_header, &mut reader).unwrap();

        assert_eq!(directory.get_pointer(&nt_header), -1);
    }

    #[test]
    fn display_matches_java_to_string_format() {
        let bytes = directory_bytes(8, 0x48, &cor20_header_bytes(0x48, 2, 5));
        let mut reader = FixtureReader::new(bytes);
        let nt_header = FixtureNtHeader { rva_ok: true, parse_cli_headers: true };
        let directory = COMDescriptorDataDirectory::new(&nt_header, &mut reader).unwrap();

        assert_eq!(directory.to_string(), "VirtualAddress: 0x8 Size: 72 bytes");
    }
}

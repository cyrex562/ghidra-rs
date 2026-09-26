//! Port of `ghidra.app.util.bin.format.pe.cli.CliMetadataRoot`.
//!
//! The header of a `CliMetadataDirectory`, matching ISO 23271 II.24.2.
//!
//! **Stream construction deferred**: Java's `parse()` builds five concrete stream objects
//! (`CliStreamGuid`/`CliStreamUserStrings`/`CliStreamStrings`/`CliStreamBlob`/
//! `CliStreamMetadata`) from the `cli.streams` subpackage, which is entirely unported -- only
//! marker/near-marker trait placeholders exist for those names in
//! [`crate::format::seam_stubs`], with no constructors to call. [`parse`](CliMetadataRoot::parse)
//! therefore does the real bookkeeping bit (nothing to do here; there is no per-stream state to
//! flip since streams are never actually constructed) and always reports success, matching Java's
//! vacuous-success default when a named header is absent. The five
//! `get_*_stream`/`get_metadata_stream` accessors correspondingly always return `None` for now.
//!
//! `markup` does not depend on that gap: it only needs each
//! [`CliStreamHeader::markup`](crate::format::pe::cli::cli_stream_header::CliStreamHeader::markup),
//! which itself is a no-op while `stream` is `None` -- so the label-creation and per-header
//! markup ordering (metadata header last) is ported faithfully.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::pe::cli::cli_stream_header::CliStreamHeader;
use crate::format::pe::pe_markupable::PeMarkupable;
use crate::app::util::importer::message_log::MessageLog;
use crate::format::seam_stubs::{NTHeader, NT_HEADER_MAX_SANE_COUNT};
use crate::program::model::data::data_type::DataType;
use crate::program::model::listing::program::Program;
use crate::util::msg::Msg;
use crate::util::task::TaskMonitor;

/// Port of `CliMetadataRoot.NAME`.
pub const NAME: &str = "CLI_METADATA_HEADER";
/// Port of `CliMetadataRoot.PATH`.
pub const PATH: &str = "/PE/CLI";

/// The name of the `#~` stream, which is always markup'd last (see [`CliMetadataRoot::markup`]).
const METADATA_STREAM_NAME: &str = "#~";

/// Port of `ghidra.app.util.bin.format.pe.cli.CliMetadataRoot`.
pub struct CliMetadataRoot {
    file_offset: i64,
    rva: i32,
    signature: i32,
    major_version: i16,
    minor_version: i16,
    reserved: i32,
    version_length: i32,
    version: Option<String>,
    flags: i16,
    streams_count: i16,
    /// Port of `streamHeaderMap`: a `LinkedHashMap<String, CliStreamHeader>`. Kept as an
    /// insertion-ordered `Vec` instead (matching iteration order for
    /// [`get_stream_headers`](Self::get_stream_headers)/[`markup`](Self::markup)), with
    /// name lookups done by linear scan in [`get_stream_header`](Self::get_stream_header) --
    /// there are only ever a handful of streams (typically `#~`, `#Strings`, `#US`, `#GUID`,
    /// `#Blob`), so a `HashMap` would not pay for itself.
    stream_headers: Vec<CliStreamHeader>,
}

impl CliMetadataRoot {
    /// Port of `CliMetadataRoot(BinaryReader, int)`.
    pub fn new(reader: &mut dyn BinaryReader, rva: i32) -> io::Result<Self> {
        let file_offset = reader.get_pointer_index() as i64;

        let signature = reader.read_next_int()?;
        let major_version = reader.read_next_short()?;
        let minor_version = reader.read_next_short()?;
        let reserved = reader.read_next_int()?;
        let version_length = reader.read_next_int()?;
        let version = if version_length > 0 && version_length < NT_HEADER_MAX_SANE_COUNT {
            let bytes = reader.read_next_byte_array(version_length as usize)?;
            Some(String::from_utf8_lossy(&bytes).into_owned())
        } else {
            None
        };
        let flags = reader.read_next_short()?;
        let streams_count = reader.read_next_short()?;

        let mut stream_headers = Vec::with_capacity(streams_count.max(0) as usize);
        for _ in 0..streams_count {
            stream_headers.push(CliStreamHeader::new(reader)?);
        }

        Ok(CliMetadataRoot {
            file_offset,
            rva,
            signature,
            major_version,
            minor_version,
            reserved,
            version_length,
            version,
            flags,
            streams_count,
            stream_headers,
        })
    }

    /// Port of `CliMetadataRoot.parse()`. See this module's docs for why the five concrete
    /// stream objects are never actually constructed yet.
    pub fn parse(&mut self) -> io::Result<bool> {
        Ok(true)
    }

    /// Port of `CliMetadataRoot.markup(Program, boolean, TaskMonitor, MessageLog, NTHeader)`.
    pub fn markup(
        &self,
        program: &dyn Program,
        is_binary: bool,
        monitor: &dyn TaskMonitor,
        log: &MessageLog,
        nt_header: &dyn NTHeader,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Java: `program.getSymbolTable().createLabel(start, NAME, SourceType.ANALYSIS)`, where
        // `start = program.getImageBase().add(getRva())`. `PeMarkupable::markup` only hands out a
        // `&dyn Program` (shared, not `&mut`), and `SymbolTable::create_label` needs `&mut self`
        // reached through `Program::get_symbol_table(&mut self)` -- there is no in-repo precedent
        // for creating a label from inside a `PeMarkupable` impl for exactly this reason (see this
        // module's docs). The address is still computed, matching Java as far as this port can.
        match program.get_image_base().map(|base| base.add(self.rva as i64)) {
            Some(Ok(_start)) => {
                log.append_msg(&format!(
                    "CliMetadataRoot: labeling {NAME} at the CLI metadata header address is not \
                     yet supported (no mutable SymbolTable reachable from PeMarkupable::markup)"
                ));
            }
            Some(Err(e)) => {
                Msg::warn("CliMetadataRoot", &format!("Invalid symbol address: {e}"));
            }
            None => {
                Msg::warn("CliMetadataRoot", &"Program has no image base; cannot label CLI metadata header");
            }
        }

        // Markup streams. Must markup Metadata stream last.
        for header in &self.stream_headers {
            if header.get_name() != METADATA_STREAM_NAME {
                header.markup(program, is_binary, monitor, log, nt_header)?;
            }
        }
        if let Some(metadata_header) = self.get_stream_header(METADATA_STREAM_NAME) {
            metadata_header.markup(program, is_binary, monitor, log, nt_header)?;
        }

        Ok(())
    }

    /// Port of `CliMetadataRoot.getFileOffset()`.
    pub fn get_file_offset(&self) -> i64 {
        self.file_offset
    }

    /// Port of `CliMetadataRoot.getRva()`.
    pub fn get_rva(&self) -> i32 {
        self.rva
    }

    /// Port of `CliMetadataRoot.getSignature()`.
    pub fn get_signature(&self) -> i32 {
        self.signature
    }

    /// Port of `CliMetadataRoot.getMajorVersion()`.
    pub fn get_major_version(&self) -> i16 {
        self.major_version
    }

    /// Port of `CliMetadataRoot.getMinorVersion()`.
    pub fn get_minor_version(&self) -> i16 {
        self.minor_version
    }

    /// Port of `CliMetadataRoot.getReserved()`.
    pub fn get_reserved(&self) -> i32 {
        self.reserved
    }

    /// Port of `CliMetadataRoot.getVersionLength()`.
    pub fn get_version_length(&self) -> i32 {
        self.version_length
    }

    /// Port of `CliMetadataRoot.getVersion()`.
    pub fn get_version(&self) -> Option<&str> {
        self.version.as_deref()
    }

    /// Port of `CliMetadataRoot.getFlags()`.
    pub fn get_flags(&self) -> i16 {
        self.flags
    }

    /// Port of `CliMetadataRoot.getStreamsCount()`.
    pub fn get_streams_count(&self) -> i16 {
        self.streams_count
    }

    /// Port of `CliMetadataRoot.getStreamHeaders()`.
    pub fn get_stream_headers(&self) -> &[CliStreamHeader] {
        &self.stream_headers
    }

    /// Port of `CliMetadataRoot.getStreamHeader(String)`.
    pub fn get_stream_header(&self, name: &str) -> Option<&CliStreamHeader> {
        self.stream_headers.iter().find(|h| h.get_name() == name)
    }

    /// Port of `CliMetadataRoot.getBlobOffsetAtIndex(int)`.
    pub fn get_blob_offset_at_index(&self, index: i32) -> i32 {
        let Some(blob_header) = self.get_stream_header("#Blob") else {
            return -1; // TODO: this isn't a nice way of doing this (Java's own comment).
        };
        self.file_offset as i32 + blob_header.get_offset() + index
    }
}

impl StructConverter for CliMetadataRoot {
    /// Mirrors `toDataType()`. Not yet buildable: Java's structure is `DWORD Signature; WORD
    /// MajorVersion; WORD MinorVersion; DWORD Reserved; DWORD VersionLength; CHAR
    /// Version[versionLength]; WORD Flags; WORD StreamsCount;` followed by each stream header's
    /// own `toDataType()` -- neither `DWordDataType`/`WordDataType`/`CharDataType` has a
    /// concrete, instantiable singleton yet, and
    /// [`CliStreamHeader::to_data_type`](crate::format::pe::cli::cli_stream_header::CliStreamHeader::to_data_type)
    /// is itself not yet buildable for the same reason.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Err(ToDataTypeError::Io(io::Error::new(
            io::ErrorKind::Unsupported,
            "CliMetadataRoot::to_data_type requires DWORD/WORD/CHAR DataType singletons, which \
             are not yet ported to a concrete instantiable form",
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    use crate::filesystem::ghidra::g_binary_reader::GByteStore;
    use crate::format::pe::file_header::FileHeader;
    use crate::format::seam_stubs::OptionalHeader;
    use crate::util::task::DummyMonitor;

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

    struct FixtureReader {
        provider: Rc<RefCell<dyn GByteStore>>,
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
        fn get_byte_provider(&self) -> Rc<RefCell<dyn GByteStore>> {
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

    fn stream_header_bytes(offset: i32, size: i32, name: &str) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&offset.to_le_bytes());
        b.extend_from_slice(&size.to_le_bytes());
        let mut name_bytes = name.as_bytes().to_vec();
        name_bytes.push(0);
        while name_bytes.len() % 4 != 0 {
            name_bytes.push(0);
        }
        b.extend_from_slice(&name_bytes);
        b
    }

    /// Builds a full `CliMetadataRoot` byte sequence: signature, versions, reserved,
    /// version-length-prefixed version string (padded like Java's real files pad it, though the
    /// header itself does not require 4-byte alignment on the version), flags, streams count,
    /// then each stream header back-to-back.
    fn root_bytes(version: &str, headers: &[Vec<u8>]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&0x424a_5342u32.to_le_bytes()); // Signature
        b.extend_from_slice(&1i16.to_le_bytes()); // MajorVersion
        b.extend_from_slice(&1i16.to_le_bytes()); // MinorVersion
        b.extend_from_slice(&0i32.to_le_bytes()); // Reserved
        b.extend_from_slice(&(version.len() as i32).to_le_bytes()); // VersionLength
        b.extend_from_slice(version.as_bytes());
        b.extend_from_slice(&0i16.to_le_bytes()); // Flags
        b.extend_from_slice(&(headers.len() as i16).to_le_bytes()); // StreamsCount
        for h in headers {
            b.extend_from_slice(h);
        }
        b
    }

    #[test]
    fn parses_header_fields_and_stream_headers() {
        let headers = vec![stream_header_bytes(0x6c, 0x1c, "#~"), stream_header_bytes(0x88, 0x40, "#Strings")];
        let bytes = root_bytes("v4.0.30319", &headers);
        let mut reader = FixtureReader::new(bytes);

        let root = CliMetadataRoot::new(&mut reader, 0x2050).unwrap();

        assert_eq!(root.get_signature(), 0x424a5342u32 as i32);
        assert_eq!(root.get_major_version(), 1);
        assert_eq!(root.get_minor_version(), 1);
        assert_eq!(root.get_version(), Some("v4.0.30319"));
        assert_eq!(root.get_streams_count(), 2);
        assert_eq!(root.get_rva(), 0x2050);
        assert_eq!(root.get_stream_headers().len(), 2);

        let metadata_header = root.get_stream_header("#~").unwrap();
        assert_eq!(metadata_header.get_offset(), 0x6c);
        assert_eq!(metadata_header.get_size(), 0x1c);

        let strings_header = root.get_stream_header("#Strings").unwrap();
        assert_eq!(strings_header.get_offset(), 0x88);

        assert!(root.get_stream_header("#GUID").is_none());
    }

    #[test]
    fn parse_reports_success_even_without_streams_subpackage() {
        let bytes = root_bytes("", &[]);
        let mut reader = FixtureReader::new(bytes);
        let mut root = CliMetadataRoot::new(&mut reader, 0).unwrap();
        assert!(root.parse().unwrap());
        assert!(root.get_stream_header("#~").is_none());
    }

    #[test]
    fn get_blob_offset_at_index_uses_blob_header_offset() {
        let headers = vec![stream_header_bytes(0x100, 0x40, "#Blob")];
        let bytes = root_bytes("", &headers);
        let mut reader = FixtureReader::new(bytes);
        let root = CliMetadataRoot::new(&mut reader, 0).unwrap();

        let offset = root.get_blob_offset_at_index(0x10);
        assert_eq!(offset, root.get_file_offset() as i32 + 0x100 + 0x10);
    }

    #[test]
    fn get_blob_offset_at_index_is_negative_one_without_blob_stream() {
        let bytes = root_bytes("", &[]);
        let mut reader = FixtureReader::new(bytes);
        let root = CliMetadataRoot::new(&mut reader, 0).unwrap();
        assert_eq!(root.get_blob_offset_at_index(5), -1);
    }

    #[test]
    fn to_data_type_is_not_yet_buildable() {
        let bytes = root_bytes("", &[]);
        let mut reader = FixtureReader::new(bytes);
        let root = CliMetadataRoot::new(&mut reader, 0).unwrap();
        assert!(root.to_data_type().is_err());
    }

    struct FixtureOptionalHeader;
    impl OptionalHeader for FixtureOptionalHeader {
        fn get_size_of_image(&self) -> i64 {
            0
        }
        fn get_image_base(&self) -> i64 {
            0
        }
    }

    /// Builds a real [`FileHeader`] for test fixtures (machine = `IMAGE_FILE_MACHINE_I386`,
    /// everything else zeroed), parsed via a throwaway `NTHeader` that skips symbol table
    /// parsing.
    fn build_file_header() -> FileHeader {
        struct DummyNtForConstruction;
        impl NTHeader for DummyNtForConstruction {
            fn get_name(&self) -> String {
                unimplemented!()
            }
            fn is_rva_resoltion_section_aligned(&self) -> bool {
                true
            }
            fn get_file_header(&self) -> &FileHeader {
                unimplemented!()
            }
            fn get_optional_header(&self) -> Box<dyn OptionalHeader> {
                unimplemented!()
            }
            fn to_data_type(&self) -> io::Result<Box<dyn DataType>> {
                unimplemented!()
            }
            fn rva_to_pointer(&self, _rva: i32) -> i32 {
                unimplemented!()
            }
            fn rva_to_pointer_long(&self, _rva: i64) -> i64 {
                unimplemented!()
            }
            fn check_pointer(&self, _ptr: i64) -> bool {
                unimplemented!()
            }
            fn check_rva(&self, _rva: i64) -> bool {
                unimplemented!()
            }
            fn va_to_pointer(&self, _va: i32) -> i32 {
                unimplemented!()
            }
        }

        let mut bytes = 0x014ci16.to_le_bytes().to_vec();
        bytes.extend_from_slice(&[0u8; 18]);
        let mut reader = FixtureReader::new(bytes);
        FileHeader::new(&mut reader, 0, &DummyNtForConstruction).unwrap()
    }

    struct FixtureNtHeader {
        file_header: FileHeader,
    }
    impl FixtureNtHeader {
        fn new() -> Self {
            FixtureNtHeader { file_header: build_file_header() }
        }
    }
    impl NTHeader for FixtureNtHeader {
        fn get_name(&self) -> String {
            "NT".to_string()
        }
        fn is_rva_resoltion_section_aligned(&self) -> bool {
            true
        }
        fn get_file_header(&self) -> &FileHeader {
            &self.file_header
        }
        fn get_optional_header(&self) -> Box<dyn OptionalHeader> {
            Box::new(FixtureOptionalHeader)
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

    struct NoImageBaseProgram;
    impl crate::framework::model::DomainObject for NoImageBaseProgram {}
    impl Program for NoImageBaseProgram {
        fn get_name(&self) -> String {
            "cli_metadata_root_test".to_string()
        }
        fn get_language_id(&self) -> String {
            "test:LE:32:default".to_string()
        }
    }

    #[test]
    fn markup_orders_metadata_stream_last_and_logs_missing_symbol_table() {
        let headers = vec![
            stream_header_bytes(0x10, 0x8, "#Strings"),
            stream_header_bytes(0x20, 0x8, "#~"),
            stream_header_bytes(0x30, 0x8, "#GUID"),
        ];
        let bytes = root_bytes("", &headers);
        let mut reader = FixtureReader::new(bytes);
        let root = CliMetadataRoot::new(&mut reader, 0x1000).unwrap();

        let program = NoImageBaseProgram;
        let monitor = DummyMonitor;
        let log = MessageLog::new();
        let nt_header = FixtureNtHeader::new();

        root.markup(&program, true, &monitor, &log, &nt_header).unwrap();

        // No image base -> the "cannot label" path is a Msg::warn, not a MessageLog entry, so the
        // log should be empty (every CliStreamHeader has no stream set, so their own `markup` is
        // a no-op that adds nothing either).
        assert!(log.messages().is_empty());
    }
}

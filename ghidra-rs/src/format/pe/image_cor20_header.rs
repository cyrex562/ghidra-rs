//! Port of `ghidra.app.util.bin.format.pe.ImageCor20Header`.
//!
//! ```text
//! typedef struct IMAGE_COR20_HEADER
//! {
//!     // Header versioning
//!    DWORD                   cb;                      // Size of the structure
//!    WORD                    MajorRuntimeVersion;     // Version of the CLR Runtime
//!    WORD                    MinorRuntimeVersion;     // Version of the CLR Runtime
//!
//!    // Symbol table and startup information
//!    IMAGE_DATA_DIRECTORY    MetaData;                // A Data Directory giving RVA and Size of MetaData
//!    DWORD                   Flags;
//!    union {
//!      DWORD                 EntryPointRVA;           // Points to the .NET native EntryPoint method
//!      DWORD                 EntryPointToken;         // Points to the .NET IL EntryPoint method
//!    };
//!
//!    // Binding information
//!    IMAGE_DATA_DIRECTORY    Resources;               // A Data Directory for Resources, which are referenced in the MetaData
//!    IMAGE_DATA_DIRECTORY    StrongNameSignature;     // A Data Directory for unique .NET assembly signatures
//!
//!    // Regular fixup and binding information
//!    IMAGE_DATA_DIRECTORY    CodeManagerTable;        // Always 0
//!    IMAGE_DATA_DIRECTORY    VTableFixups;            // Not well documented VTable used by languages who don't follow the common type system runtime model
//!    IMAGE_DATA_DIRECTORY    ExportAddressTableJumps; // Always 0 in normal .NET assemblies, only present in native images
//!
//!    // Precompiled image info (internal use only - set to zero)
//!    IMAGE_DATA_DIRECTORY    ManagedNativeHeader;
//!
//!};
//! ```
//!
//! **`to_data_type` not yet buildable**: same limitation as `DefaultDataDirectory`/
//! `CliMetadataDirectory`/`LoadConfigDirectory` -- the `DWORD`/`WORD` singletons Java uses to
//! build the structure are still traits without a concrete instantiable form.
//!
//! **`.NET` entry-point resolution not yet supported**: Java's non-native-entry-point branch of
//! `markup` downcasts the CLI metadata's `#~` stream to `CliStreamMetadata` and walks its
//! `MethodDef` table to find the entry point's RVA. `CliAbstractStream` (the stream trait
//! actually returned by `CliStreamHeader::get_stream`) has no downcast hook to
//! `CliStreamMetadata` yet -- this is only reachable once the `cli.streams` subpackage is
//! ported. That branch logs and skips instead of resolving an address, matching the
//! already-established convention in `CliMetadataRoot::markup` for a `Program`-mutation gap
//! (see below) rather than inventing a downcast.
//!
//! **Native entry point not registered**: Java calls
//! `program.getSymbolTable().addExternalEntryPoint(...)`, but `PeMarkupable::markup` only hands
//! out a `&dyn Program` (shared, not `&mut`), so a mutable `SymbolTable` is not reachable here --
//! the same gap already documented on `CliMetadataRoot::markup`. The entry point address is
//! still computed and logged.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::pe::cli::cli_metadata_directory::CliMetadataDirectory;
use crate::format::pe::default_data_directory::DefaultDataDirectory;
use crate::format::pe::pe_markupable::PeMarkupable;
use crate::app::util::importer::message_log::MessageLog;
use crate::format::seam_stubs::{NTHeader};
use crate::program::model::address::Address;
use crate::program::model::data::category_path::CategoryPath;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::enum_::Enum;
use crate::program::model::data::enum_data_type::EnumDataType;
use crate::program::model::listing::program::Program;
use crate::util::msg::Msg;
use crate::util::task::TaskMonitor;

/// Port of `ImageCor20Header.NAME`.
const NAME: &str = "IMAGE_COR20_HEADER";

/// Port of `ghidra.app.util.bin.format.pe.ImageCor20Header`.
pub struct ImageCor20Header {
    pub cb: i32,
    pub major_runtime_version: i16,
    pub minor_runtime_version: i16,
    metadata: CliMetadataDirectory,
    flags: i32,
    entry_point_token: i32,
    entry_point_va: Option<Address>,
    resources: DefaultDataDirectory,
    strong_name_signature: DefaultDataDirectory,
    code_manager_table: DefaultDataDirectory,
    v_table_fixups: DefaultDataDirectory,
    export_address_table_jumps: DefaultDataDirectory,
    managed_native_header: DefaultDataDirectory,
}

impl ImageCor20Header {
    /// Port of `ImageCor20Header(BinaryReader, long, NTHeader)`.
    pub fn new(
        reader: &mut dyn BinaryReader,
        index: u64,
        nt_header: &dyn NTHeader,
    ) -> io::Result<Self> {
        let orig_index = reader.get_pointer_index();
        reader.set_pointer_index(index);

        let cb = reader.read_next_int()?;
        let major_runtime_version = reader.read_next_short()?;
        let minor_runtime_version = reader.read_next_short()?;
        let metadata = CliMetadataDirectory::new(nt_header, reader)?;
        let flags = reader.read_next_int()?;
        let entry_point_token = reader.read_next_int()?;
        let resources = DefaultDataDirectory::new(nt_header, reader)?;
        let strong_name_signature = DefaultDataDirectory::new(nt_header, reader)?;
        let code_manager_table = DefaultDataDirectory::new(nt_header, reader)?;
        let v_table_fixups = DefaultDataDirectory::new(nt_header, reader)?;
        let export_address_table_jumps = DefaultDataDirectory::new(nt_header, reader)?;
        let managed_native_header = DefaultDataDirectory::new(nt_header, reader)?;

        reader.set_pointer_index(orig_index);

        Ok(ImageCor20Header {
            cb,
            major_runtime_version,
            minor_runtime_version,
            metadata,
            flags,
            entry_point_token,
            entry_point_va: None,
            resources,
            strong_name_signature,
            code_manager_table,
            v_table_fixups,
            export_address_table_jumps,
            managed_native_header,
        })
    }

    /// Port of `ImageCor20Header.parse()`. `reader`/`nt_header` are threaded through explicitly
    /// (rather than stored on `self`, as Java's `CliMetadataDirectory` does) for the same reason
    /// documented on `CliMetadataDirectory::parse` -- they are only needed transiently, to
    /// re-seek to the metadata root's RVA.
    pub fn parse(&mut self, nt_header: &dyn NTHeader, reader: &mut dyn BinaryReader) -> io::Result<bool> {
        let mut success = true;
        success &= self.metadata.parse(nt_header, reader)?;
        success &= self.resources.parse();
        success &= self.strong_name_signature.parse();
        success &= self.code_manager_table.parse();
        success &= self.v_table_fixups.parse();
        success &= self.export_address_table_jumps.parse();
        success &= self.managed_native_header.parse();
        Ok(success)
    }

    /// Port of `ImageCor20Header.getCb()`.
    pub fn get_cb(&self) -> i32 {
        self.cb
    }

    /// Port of `ImageCor20Header.getMajorRuntimeVersion()`.
    pub fn get_major_runtime_version(&self) -> i16 {
        self.major_runtime_version
    }

    /// Port of `ImageCor20Header.getMinorRuntimeVersion()`.
    pub fn get_minor_runtime_version(&self) -> i16 {
        self.minor_runtime_version
    }

    /// Port of `ImageCor20Header.getMetadata()`.
    pub fn get_metadata(&self) -> &CliMetadataDirectory {
        &self.metadata
    }

    /// Port of `ImageCor20Header.getFlags()`.
    pub fn get_flags(&self) -> i32 {
        self.flags
    }

    /// Port of `ImageCor20Header.getEntryPointToken()`.
    pub fn get_entry_point_token(&self) -> i32 {
        self.entry_point_token
    }

    /// Port of `ImageCor20Header.getEntryPointVA()`.
    pub fn get_entry_point_va(&self) -> Option<&Address> {
        self.entry_point_va.as_ref()
    }

    /// Port of `ImageCor20Header.getResources()`.
    pub fn get_resources(&self) -> &DefaultDataDirectory {
        &self.resources
    }

    /// Port of `ImageCor20Header.getStrongNameSignature()`.
    pub fn get_strong_name_signature(&self) -> &DefaultDataDirectory {
        &self.strong_name_signature
    }

    /// Port of `ImageCor20Header.getCodeManagerTable()`.
    pub fn get_code_manager_table(&self) -> &DefaultDataDirectory {
        &self.code_manager_table
    }

    /// Port of `ImageCor20Header.getVTableFixups()`.
    pub fn get_v_table_fixups(&self) -> &DefaultDataDirectory {
        &self.v_table_fixups
    }

    /// Port of `ImageCor20Header.getExportAddressTableJumps()`.
    pub fn get_export_address_table_jumps(&self) -> &DefaultDataDirectory {
        &self.export_address_table_jumps
    }

    /// Port of `ImageCor20Header.getManagedNativeHeader()`.
    pub fn get_managed_native_header(&self) -> &DefaultDataDirectory {
        &self.managed_native_header
    }
}

impl PeMarkupable for ImageCor20Header {
    /// Port of `ImageCor20Header.markup(...)`.
    fn markup(
        &self,
        program: &dyn Program,
        is_binary: bool,
        monitor: &dyn TaskMonitor,
        log: &MessageLog,
        nt_header: &dyn NTHeader,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if !self.metadata.has_parsed_correctly() {
            return Ok(());
        }

        self.metadata.markup(program, is_binary, monitor, log, nt_header)?;

        if self.entry_point_token > 0 {
            // DLLs won't have an entry point.
            if (self.flags & ImageCor20Flags::COMIMAGE_FLAGS_NATIVE_ENTRYPOINT)
                == ImageCor20Flags::COMIMAGE_FLAGS_NATIVE_ENTRYPOINT
            {
                // Native entry point.
                match program.get_image_base() {
                    Some(base) => match base.add(self.entry_point_token as i64) {
                        Ok(_addr) => {
                            log.append_msg(
                                "ImageCor20Header: cannot add external entry point for the \
                                 native entry point (no mutable SymbolTable reachable from \
                                 PeMarkupable::markup)",
                            );
                        }
                        Err(e) => {
                            Msg::warn(
                                "ImageCor20Header",
                                &format!("Invalid native entry point address: {e}"),
                            );
                        }
                    },
                    None => {
                        Msg::warn(
                            "ImageCor20Header",
                            &"Program has no image base; cannot resolve native entry point",
                        );
                    }
                }
            }
            else {
                // .NET entry point -- see this module's docs for why this cannot be resolved yet.
                log.append_msg(
                    "ImageCor20Header: resolving the .NET entry point via the CliStreamMetadata \
                     MethodDef table is not yet supported (CliAbstractStream has no downcast to \
                     CliStreamMetadata yet)",
                );
            }
        }

        Ok(())
    }
}

impl StructConverter for ImageCor20Header {
    /// Mirrors `toDataType()`. Not yet buildable -- see this module's docs.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Err(ToDataTypeError::Io(io::Error::new(
            io::ErrorKind::Unsupported,
            "ImageCor20Header::to_data_type requires DWORD/WORD DataType singletons, which are \
             not yet ported to a concrete instantiable form",
        )))
    }
}

/// Port of the static nested class `ImageCor20Header.ImageCor20Flags`, data type for
/// [`ImageCor20Header`]'s `flags` field.
pub struct ImageCor20Flags {
    pub flags: i32,
}

impl ImageCor20Flags {
    /// Port of `ImageCor20Flags.PATH`.
    pub const PATH: &'static str = "/PE/CLI/Flags";

    /// Port of `ImageCor20Flags.COMIMAGE_FLAGS_ILONLY`.
    pub const COMIMAGE_FLAGS_ILONLY: i32 = 0x0000_0001;
    /// Port of `ImageCor20Flags.COMIMAGE_FLAGS_32BITREQUIRED`.
    pub const COMIMAGE_FLAGS_32BITREQUIRED: i32 = 0x0000_0002;
    /// Port of `ImageCor20Flags.COMIMAGE_FLAGS_IL_LIBRARY`.
    pub const COMIMAGE_FLAGS_IL_LIBRARY: i32 = 0x0000_0004;
    /// Port of `ImageCor20Flags.COMIMAGE_FLAGS_STRONGNAMESIGNED`.
    pub const COMIMAGE_FLAGS_STRONGNAMESIGNED: i32 = 0x0000_0008;
    /// Port of `ImageCor20Flags.COMIMAGE_FLAGS_NATIVE_ENTRYPOINT`.
    pub const COMIMAGE_FLAGS_NATIVE_ENTRYPOINT: i32 = 0x0000_0010;
    /// Port of `ImageCor20Flags.COMIMAGE_FLAGS_TRACKDEBUGDATA`.
    pub const COMIMAGE_FLAGS_TRACKDEBUGDATA: i32 = 0x0001_0000;

    /// Port of `ImageCor20Flags()`.
    pub fn new() -> Self {
        ImageCor20Flags { flags: 0 }
    }
}

impl Default for ImageCor20Flags {
    fn default() -> Self {
        Self::new()
    }
}

impl StructConverter for ImageCor20Flags {
    /// Port of `ImageCor20Flags()`'s constructor body (an `EnumDataType` is built at
    /// construction time in Java; here it is built lazily in `to_data_type`, matching how
    /// `LoadConfigDirectory::GuardFlags::to_data_type` handles the analogous
    /// `EnumDataType`-backed nested class).
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        let category_path = CategoryPath::parse(Self::PATH)
            .map_err(|e| ToDataTypeError::Io(io::Error::new(io::ErrorKind::InvalidInput, e)))?;
        let mut enum_dt = EnumDataType::new_in_category(category_path, "COR20_Flags", 4);
        let prefix = "COMIMAGE_FLAGS_";
        enum_dt.add(&format!("{prefix}ILONLY"), Self::COMIMAGE_FLAGS_ILONLY as i64);
        enum_dt.add(&format!("{prefix}32BITREQUIRED"), Self::COMIMAGE_FLAGS_32BITREQUIRED as i64);
        enum_dt.add(&format!("{prefix}IL_LIBRARY"), Self::COMIMAGE_FLAGS_IL_LIBRARY as i64);
        enum_dt.add(&format!("{prefix}STRONGNAMESIGNED"), Self::COMIMAGE_FLAGS_STRONGNAMESIGNED as i64);
        enum_dt.add(&format!("{prefix}NATIVE_ENTRYPOINT"), Self::COMIMAGE_FLAGS_NATIVE_ENTRYPOINT as i64);
        enum_dt.add(&format!("{prefix}TRACKDEBUGDATA"), Self::COMIMAGE_FLAGS_TRACKDEBUGDATA as i64);
        Ok(Box::new(enum_dt))
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

    struct FakeNtHeader {
        rva_ok: bool,
    }

    impl NTHeader for FakeNtHeader {
        fn get_name(&self) -> String {
            "NT".to_string()
        }
        fn is_rva_resoltion_section_aligned(&self) -> bool {
            true
        }
        fn get_file_header(&self) -> &crate::format::pe::file_header::FileHeader {
            unimplemented!()
        }
        fn get_optional_header(&self) -> Box<dyn crate::format::seam_stubs::OptionalHeader> {
            unimplemented!()
        }
        fn to_data_type(&self) -> io::Result<Box<dyn DataType>> {
            unimplemented!()
        }
        fn rva_to_pointer(&self, rva: i32) -> i32 {
            if self.rva_ok {
                rva
            }
            else {
                -1
            }
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

    /// Builds the fixed 72-byte `IMAGE_COR20_HEADER` layout: cb(4) + major(2) + minor(2) +
    /// MetaData directory(8) + Flags(4) + EntryPointToken(4) + six more directories(8 each).
    /// Every nested directory is given a zero virtual address so none of them try to follow an
    /// RVA into data this fixture doesn't provide.
    fn cor20_header_bytes(cb: i32, major: i16, minor: i16, flags: i32, entry_point_token: i32) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&cb.to_le_bytes());
        bytes.extend_from_slice(&major.to_le_bytes());
        bytes.extend_from_slice(&minor.to_le_bytes());
        bytes.extend_from_slice(&0i32.to_le_bytes()); // MetaData.VirtualAddress
        bytes.extend_from_slice(&0i32.to_le_bytes()); // MetaData.Size
        bytes.extend_from_slice(&flags.to_le_bytes());
        bytes.extend_from_slice(&entry_point_token.to_le_bytes());
        for _ in 0..6 {
            bytes.extend_from_slice(&0i32.to_le_bytes()); // VirtualAddress
            bytes.extend_from_slice(&0i32.to_le_bytes()); // Size
        }
        bytes
    }

    #[test]
    fn constructor_reads_fixed_fields_and_restores_pointer() {
        let bytes = cor20_header_bytes(0x48, 2, 5, 0, 0);
        let mut reader = FixtureReader::new(bytes);
        reader.set_pointer_index(0x99);
        let nt_header = FakeNtHeader { rva_ok: true };

        let header = ImageCor20Header::new(&mut reader, 0, &nt_header).unwrap();

        assert_eq!(header.get_cb(), 0x48);
        assert_eq!(header.get_major_runtime_version(), 2);
        assert_eq!(header.get_minor_runtime_version(), 5);
        assert_eq!(header.get_flags(), 0);
        assert_eq!(header.get_entry_point_token(), 0);
        // Pointer index is restored to what it was before construction, matching Java.
        assert_eq!(reader.get_pointer_index(), 0x99);
    }

    #[test]
    fn parse_aggregates_directory_results() {
        let bytes = cor20_header_bytes(0x48, 2, 5, 0, 0);
        let mut reader = FixtureReader::new(bytes);
        let nt_header = FakeNtHeader { rva_ok: true };

        let mut header = ImageCor20Header::new(&mut reader, 0, &nt_header).unwrap();
        // MetaData directory has virtualAddress == 0, so CliMetadataDirectory::parse() returns
        // false (getPointer() == -1) -- matching Java's `success &= metadata.parse()`.
        assert!(!header.parse(&nt_header, &mut reader).unwrap());
    }

    #[test]
    fn markup_is_a_no_op_when_metadata_did_not_parse() {
        let bytes = cor20_header_bytes(0x48, 2, 5, 0, 1);
        let mut reader = FixtureReader::new(bytes);
        let nt_header = FakeNtHeader { rva_ok: true };
        let header = ImageCor20Header::new(&mut reader, 0, &nt_header).unwrap();
        assert!(!header.get_metadata().has_parsed_correctly());

        struct StubProgram;
        impl crate::framework::model::DomainObject for StubProgram {}
        impl Program for StubProgram {
            fn get_name(&self) -> String {
                "image_cor20_header_test".to_string()
            }
            fn get_language_id(&self) -> String {
                "test:LE:32:default".to_string()
            }
        }
        let program = StubProgram;
        let monitor = crate::util::task::DummyMonitor;
        let log = MessageLog::new();
        // Should return Ok without touching `program`/`monitor`/`log` at all, since
        // `metadata.has_parsed_correctly()` is false.
        assert!(header.markup(&program, true, &monitor, &log, &nt_header).is_ok());
    }

    #[test]
    fn image_cor20_flags_to_data_type_builds_all_variants() {
        let flags = ImageCor20Flags::new();
        let dt = flags.to_data_type().unwrap();
        assert_eq!(dt.get_name(), "COR20_Flags");
        assert_eq!(dt.get_length(), 4);
    }

    #[test]
    fn to_data_type_is_not_yet_buildable() {
        let bytes = cor20_header_bytes(0x48, 2, 5, 0, 0);
        let mut reader = FixtureReader::new(bytes);
        let nt_header = FakeNtHeader { rva_ok: true };
        let header = ImageCor20Header::new(&mut reader, 0, &nt_header).unwrap();
        assert!(header.to_data_type().is_err());
    }
}

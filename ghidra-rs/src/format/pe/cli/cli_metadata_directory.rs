//! Port of `ghidra.app.util.bin.format.pe.cli.CliMetadataDirectory`.
//!
//! The Metadata directory found in `ImageCor20Header`. The abstract Java base class
//! `DataDirectory` is not ported yet (same situation documented in
//! `COMDescriptorDataDirectory`/`DefaultDataDirectory`), so the
//! `virtualAddress`/`size`/`hasParsed` state and behavior it provided (`getPointer`,
//! `hasParsedCorrectly`) is folded directly into this concrete leaf type instead of being modeled
//! as a separate seam.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::pe::cli::cli_metadata_root::CliMetadataRoot;
use crate::format::pe::pe_markupable::PeMarkupable;
use crate::app::util::importer::message_log::MessageLog;
use crate::format::seam_stubs::{NTHeader, PeUtils};
use crate::program::model::data::data_type::DataType;
use crate::program::model::listing::program::Program;
use crate::util::task::TaskMonitor;

/// Port of `CliMetadataDirectory.NAME`.
const NAME: &str = "CLI_METADATA_DIRECTORY";

/// Port of `ghidra.app.util.bin.format.pe.cli.CliMetadataDirectory`.
pub struct CliMetadataDirectory {
    virtual_address: i32,
    size: i32,
    has_parsed: bool,
    metadata_root: Option<CliMetadataRoot>,
}

impl CliMetadataDirectory {
    /// Port of `CliMetadataDirectory(NTHeader, BinaryReader)`. Unlike `DataDirectory`'s other
    /// subclasses, this constructor does NOT run `processDataDirectory` -- Java's constructor
    /// reads `virtualAddress`/`size` directly and defers everything else (including RVA
    /// validation) to `parse()`.
    pub fn new(_nt_header: &dyn NTHeader, reader: &mut dyn BinaryReader) -> io::Result<Self> {
        let virtual_address = reader.read_next_int()?;
        let size = reader.read_next_int()?;
        Ok(CliMetadataDirectory { virtual_address, size, has_parsed: false, metadata_root: None })
    }

    /// Port of `CliMetadataDirectory.getMetadataRoot()`.
    pub fn get_metadata_root(&self) -> Option<&CliMetadataRoot> {
        self.metadata_root.as_ref()
    }

    /// Port of `CliMetadataDirectory.getDirectoryName()`.
    pub fn get_directory_name(&self) -> String {
        NAME.to_string()
    }

    /// Port of `DataDirectory.getPointer()`. Java stashes `ntHeader`/`virtualAddress` as instance
    /// fields set during construction; this port takes `nt_header` explicitly since it is not
    /// stored (same convention as `COMDescriptorDataDirectory::get_pointer`).
    fn get_pointer(&self, nt_header: &dyn NTHeader) -> i32 {
        if self.virtual_address == 0 {
            return -1;
        }
        nt_header.rva_to_pointer(self.virtual_address)
    }

    /// Port of `CliMetadataDirectory.parse()`.
    pub fn parse(&mut self, nt_header: &dyn NTHeader, reader: &mut dyn BinaryReader) -> io::Result<bool> {
        let ptr = self.get_pointer(nt_header);
        if ptr < 0 || self.size == 0 {
            return Ok(false);
        }

        let orig_index = reader.get_pointer_index();
        reader.set_pointer_index(ptr as u64);
        let mut root = CliMetadataRoot::new(reader, self.virtual_address)?;
        self.has_parsed = root.parse()?;
        self.metadata_root = Some(root);
        reader.set_pointer_index(orig_index);
        Ok(self.has_parsed)
    }

    /// Port of `DataDirectory.hasParsedCorrectly()`.
    pub fn has_parsed_correctly(&self) -> bool {
        self.has_parsed
    }

    /// Port of `DataDirectory.getVirtualAddress()`.
    pub fn get_virtual_address(&self) -> i32 {
        self.virtual_address
    }

    /// Port of `DataDirectory.getSize()`.
    pub fn get_size(&self) -> i32 {
        self.size
    }
}

impl PeMarkupable for CliMetadataDirectory {
    /// Port of `CliMetadataDirectory.markup(...)`.
    fn markup(
        &self,
        program: &dyn Program,
        is_binary: bool,
        monitor: &dyn TaskMonitor,
        log: &MessageLog,
        nt: &dyn NTHeader,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let Some(metadata_root) = self.metadata_root.as_ref() else {
            return Ok(());
        };

        monitor.set_message(&format!("[{}]: CLI metadata...", Program::get_name(program)));

        let Some(addr) = PeUtils::get_markup_address(program, is_binary, nt, self.virtual_address) else {
            return Ok(());
        };
        let contains = program.get_memory().map(|memory| memory.contains(&addr)).unwrap_or(false);
        if !contains {
            return Ok(());
        }

        // Create data type. NOTE: `CliMetadataRoot::to_data_type` is not yet buildable (see its
        // own docs), so this currently always short-circuits with an error here, matching how
        // `COMDescriptorDataDirectory::markup` propagates the same not-yet-buildable error from
        // `ImageCor20Header::to_data_type`.
        let dt = metadata_root.to_data_type()?;
        PeUtils::create_data(program, &addr, dt.as_ref(), log)?;

        // Markup metadata header.
        metadata_root.markup(program, is_binary, monitor, log, nt)?;

        Ok(())
    }
}

impl StructConverter for CliMetadataDirectory {
    /// Mirrors `toDataType()`. Not yet buildable: Java builds a 2-field structure out of the
    /// `DWORD` singleton, which is still a trait without a concrete, instantiable `Box<dyn
    /// DataType>` form in this crate (same limitation documented on
    /// `DefaultDataDirectory::to_data_type`/`CliMetadataRoot::to_data_type`).
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Err(ToDataTypeError::Io(io::Error::new(
            io::ErrorKind::Unsupported,
            "CliMetadataDirectory::to_data_type requires a DWORD DataType singleton, which is \
             not yet ported to a concrete instantiable form",
        )))
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
            } else {
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

    #[test]
    fn constructor_reads_virtual_address_and_size() {
        // virtualAddress=0x2000, size=0x48
        let mut reader = FixtureReader::new(vec![0x00, 0x20, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00]);
        let dir = CliMetadataDirectory::new(&FakeNtHeader { rva_ok: true }, &mut reader).unwrap();
        assert_eq!(dir.get_virtual_address(), 0x2000);
        assert_eq!(dir.get_size(), 0x48);
        assert!(!dir.has_parsed_correctly());
        assert!(dir.get_metadata_root().is_none());
        assert_eq!(dir.get_directory_name(), "CLI_METADATA_DIRECTORY");
    }

    #[test]
    fn parse_fails_when_pointer_invalid() {
        let mut reader = FixtureReader::new(vec![0x00, 0x20, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00]);
        let mut dir = CliMetadataDirectory::new(&FakeNtHeader { rva_ok: true }, &mut reader).unwrap();
        let nt = FakeNtHeader { rva_ok: false };
        let mut reader2 = FixtureReader::new(vec![0u8; 0x30]);
        assert!(!dir.parse(&nt, &mut reader2).unwrap());
        assert!(dir.get_metadata_root().is_none());
    }

    #[test]
    fn parse_fails_when_size_zero() {
        // virtualAddress=0x10, size=0
        let mut reader = FixtureReader::new(vec![0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        let mut dir = CliMetadataDirectory::new(&FakeNtHeader { rva_ok: true }, &mut reader).unwrap();
        let nt = FakeNtHeader { rva_ok: true };
        let mut reader2 = FixtureReader::new(vec![0u8; 0x30]);
        assert!(!dir.parse(&nt, &mut reader2).unwrap());
    }

    #[test]
    fn to_data_type_is_not_yet_buildable() {
        let dir = CliMetadataDirectory {
            virtual_address: 0,
            size: 0,
            has_parsed: false,
            metadata_root: None,
        };
        assert!(dir.to_data_type().is_err());
    }
}

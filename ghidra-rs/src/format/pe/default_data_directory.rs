//! Port of `ghidra.app.util.bin.format.pe.DefaultDataDirectory`.
//!
//! The abstract Java base class `DataDirectory` is not ported yet (same situation documented in
//! `COMDescriptorDataDirectory`), so the `virtualAddress`/`size`/`hasParsed` state and behavior it
//! provided (`processDataDirectory`, `getPointer`, ...) is folded directly into this concrete leaf
//! type instead of being modeled as a separate seam. Unlike `COMDescriptorDataDirectory`, every
//! override here is a genuine no-op in Java (`parse()` just returns `true`, `markup()` does
//! nothing), so this port has no extra behavior to add beyond the shared `processDataDirectory`
//! logic.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::pe::pe_markupable::PeMarkupable;
use crate::format::seam_stubs::{MessageLog, NTHeader};
use crate::program::model::data::data_type::DataType;
use crate::program::model::listing::program::Program;
use crate::util::msg::Msg;
use crate::util::task::TaskMonitor;

/// Port of `DataDirectory.TITLE`, used by `DefaultDataDirectory.getDirectoryName()`.
const TITLE: &str = "IMAGE_DATA_DIRECTORY";

/// Port of `ghidra.app.util.bin.format.pe.DefaultDataDirectory`.
pub struct DefaultDataDirectory {
    virtual_address: i32,
    size: i32,
    has_parsed: bool,
}

impl DefaultDataDirectory {
    /// Port of `DefaultDataDirectory(NTHeader, BinaryReader)`, which just runs
    /// `DataDirectory.processDataDirectory`.
    pub fn new(nt_header: &dyn NTHeader, reader: &mut dyn BinaryReader) -> io::Result<Self> {
        let mut directory = DefaultDataDirectory { virtual_address: 0, size: 0, has_parsed: false };
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
                "DefaultDataDirectory",
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
                "DefaultDataDirectory",
                &format!(
                    "Skipping DataDirectory '{}'. Invalid size (Size: {:#x}).",
                    self.get_directory_name(),
                    self.size
                ),
            );
            return Ok(());
        }

        self.has_parsed = self.parse();
        Ok(())
    }

    /// Port of `DefaultDataDirectory.getDirectoryName()`.
    pub fn get_directory_name(&self) -> String {
        TITLE.to_string()
    }

    /// Port of `DefaultDataDirectory.parse()`; a documented no-op in Java.
    pub fn parse(&self) -> bool {
        true
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

impl PeMarkupable for DefaultDataDirectory {
    /// Port of `DefaultDataDirectory.markup(...)`; a documented no-op in Java.
    fn markup(
        &self,
        _program: &dyn Program,
        _is_binary: bool,
        _monitor: &dyn TaskMonitor,
        _log: &dyn MessageLog,
        _nt_header: &dyn NTHeader,
    ) -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }
}

impl StructConverter for DefaultDataDirectory {
    /// Mirrors `toDataType()`. Not yet buildable: Java builds a 2-field `IMAGE_DATA_DIRECTORY`
    /// structure out of the `DWORD` singleton, which is still a trait without a concrete,
    /// instantiable `Box<dyn DataType>` form in this crate (same limitation documented on
    /// `LoadConfigDirectory::to_data_type`/`CliMetadataRoot::to_data_type`).
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Err(ToDataTypeError::Io(io::Error::new(
            io::ErrorKind::Unsupported,
            "DefaultDataDirectory::to_data_type requires a DWORD DataType singleton, which is \
             not yet ported to a concrete instantiable form",
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

    struct FakeNtHeader;
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
            rva
        }
        fn rva_to_pointer_long(&self, rva: i64) -> i64 {
            rva
        }
        fn check_pointer(&self, _ptr: i64) -> bool {
            true
        }
        fn check_rva(&self, rva: i64) -> bool {
            rva >= 0 && rva < 0x1000
        }
        fn va_to_pointer(&self, va: i32) -> i32 {
            va
        }
    }

    #[test]
    fn parses_zero_directory_as_absent() {
        let mut reader = FixtureReader::new(vec![0, 0, 0, 0, 0, 0, 0, 0]);
        let dd = DefaultDataDirectory::new(&FakeNtHeader, &mut reader).unwrap();
        assert_eq!(dd.get_virtual_address(), 0);
        assert_eq!(dd.get_size(), 0);
        // `parse()` was never invoked (virtualAddress == 0 short-circuits), matching Java.
        assert!(!dd.has_parsed_correctly());
    }

    #[test]
    fn parses_valid_directory_and_reports_success() {
        // virtualAddress=0x100, size=0x20
        let mut reader = FixtureReader::new(vec![0x00, 0x01, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00]);
        let dd = DefaultDataDirectory::new(&FakeNtHeader, &mut reader).unwrap();
        assert_eq!(dd.get_virtual_address(), 0x100);
        assert_eq!(dd.get_size(), 0x20);
        assert!(dd.has_parsed_correctly());
        assert_eq!(dd.get_directory_name(), "IMAGE_DATA_DIRECTORY");
    }

    #[test]
    fn to_data_type_is_not_yet_buildable() {
        let dd = DefaultDataDirectory { virtual_address: 0, size: 0, has_parsed: false };
        assert!(dd.to_data_type().is_err());
    }
}

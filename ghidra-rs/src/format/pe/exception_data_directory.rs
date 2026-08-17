//! Port of `ghidra.app.util.bin.format.pe.ExceptionDataDirectory`.
//!
//! Represents the `IMAGE_DIRECTORY_ENTRY_EXCEPTION` data directory, which points at an
//! architecture-specific table of runtime function entries used for exception handling.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::format::pe::image_runtime_function_entries::ImageRuntimeFunctionEntries;
use crate::format::pe::pe_markupable::PeMarkupable;
use crate::format::seam_stubs::{
    ImageRuntimeFunctionEntriesArm, ImageRuntimeFunctionEntriesX86, LoadConfigDirectory,
    MessageLog, NTHeader, PeUtils,
};
use crate::program::model::address::Address;
use crate::program::model::listing::program::Program;
use crate::util::msg::Msg;
use crate::util::task::TaskMonitor;

const NAME: &str = "IMAGE_DIRECTORY_ENTRY_EXCEPTION";

/// Port of `ghidra.app.util.bin.format.pe.ExceptionDataDirectory`.
///
/// The abstract Java base class `DataDirectory` is not ported yet, so the
/// `virtualAddress`/`size`/`hasParsed` state and behavior it provided (`processDataDirectory`,
/// `getPointer`, ...) is folded directly into this concrete leaf type instead of being modeled as
/// a separate seam, mirroring the precedent set by
/// [`DebugDataDirectory`](crate::format::pe::debug_data_directory::DebugDataDirectory) and
/// [`COMDescriptorDataDirectory`](crate::format::pe::com_descriptor_data_directory::COMDescriptorDataDirectory).
pub struct ExceptionDataDirectory {
    virtual_address: i32,
    size: i32,
    has_parsed: bool,
    lc_dir: Option<LoadConfigDirectory>,
    function_entries: Option<Box<dyn ImageRuntimeFunctionEntries>>,
}

impl ExceptionDataDirectory {
    /// Port of `ExceptionDataDirectory(NTHeader, BinaryReader, LoadConfigDirectory)`, which also
    /// runs `DataDirectory.processDataDirectory`.
    pub fn new(
        nt_header: &dyn NTHeader,
        reader: &mut dyn BinaryReader,
        lc_dir: Option<LoadConfigDirectory>,
    ) -> io::Result<Self> {
        let mut directory = ExceptionDataDirectory {
            virtual_address: 0,
            size: 0,
            has_parsed: false,
            lc_dir,
            function_entries: None,
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
                "ExceptionDataDirectory",
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
                "ExceptionDataDirectory",
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

    /// Port of `ExceptionDataDirectory.getDirectoryName()`.
    pub fn get_directory_name(&self) -> String {
        NAME.to_string()
    }

    /// Port of `ExceptionDataDirectory.parse()`. Java reads `reader`/`ntHeader`/`size` from
    /// fields inherited off `DataDirectory`; this port threads them through explicitly since they
    /// are only needed transiently, during construction.
    ///
    /// Java swallows any `IOException` raised while picking/constructing the architecture-specific
    /// function-entries table (logging it and falling through to `return false`) rather than
    /// propagating it; that is mirrored here by folding the `Result` into the returned `bool`
    /// instead of `?`-ing it out of this function.
    pub fn parse(&mut self, nt_header: &dyn NTHeader, reader: &mut dyn BinaryReader) -> io::Result<bool> {
        let ptr = self.get_pointer(nt_header);
        if ptr < 0 {
            return Ok(false);
        }

        let old_index = reader.get_pointer_index();
        reader.set_pointer_index(ptr as u64);

        let file_header = nt_header.get_file_header();
        let is_chpe = self
            .lc_dir
            .as_ref()
            .map(|lc| lc.get_chpe_metadata_pointer() != 0)
            .unwrap_or(false);

        let outcome: io::Result<bool> = if file_header.is_x86() && !is_chpe {
            ImageRuntimeFunctionEntriesX86::new(reader, self.size, nt_header).map(|entries| {
                self.function_entries = Some(Box::new(entries));
                true
            })
        } else if file_header.is_arm() || is_chpe {
            ImageRuntimeFunctionEntriesArm::new(reader, self.size, nt_header).map(|entries| {
                self.function_entries = Some(Box::new(entries));
                true
            })
        } else {
            Msg::error(
                "ExceptionDataDirectory",
                &format!(
                    "Exception Data unsupported architecture: {:#04x}",
                    file_header.get_machine()
                ),
            );
            self.function_entries = None;
            Ok(true)
        };

        reader.set_pointer_index(old_index);

        match outcome {
            Ok(parsed) => Ok(parsed),
            Err(e) => {
                Msg::error(
                    "ExceptionDataDirectory",
                    &format!("Failed to parse ExceptionDataDirectory: {}", e),
                );
                Ok(false)
            }
        }
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
                "ExceptionDataDirectory",
                &format!("Invalid file index for {:#x}", self.virtual_address),
            );
        }
        ptr
    }

    /// Port of `ExceptionDataDirectory.functionEntries` accessor; not present in the Java source
    /// (the field is private with no getter), but exposed here so tests and callers outside this
    /// module can observe which architecture-specific table `parse()` picked.
    pub fn get_function_entries(&self) -> Option<&dyn ImageRuntimeFunctionEntries> {
        self.function_entries.as_deref()
    }

    /// Port of `DataDirectory.createDirectoryBookmark`; a no-op until `Program` exposes a
    /// bookmark manager (same limitation as `create_directory_bookmark` in
    /// `debug_data_directory.rs`/`com_descriptor_data_directory.rs`).
    fn create_directory_bookmark(&self, _program: &dyn Program, _addr: &Address) {}
}

impl std::fmt::Display for ExceptionDataDirectory {
    /// Port of `DataDirectory.toString()`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "VirtualAddress: {:#x} Size: {} bytes",
            self.virtual_address, self.size
        )
    }
}

impl PeMarkupable for ExceptionDataDirectory {
    /// Port of `ExceptionDataDirectory.markup(...)`.
    fn markup(
        &self,
        program: &dyn Program,
        is_binary: bool,
        _monitor: &dyn TaskMonitor,
        log: &dyn MessageLog,
        nt_header: &dyn NTHeader,
    ) -> Result<(), Box<dyn std::error::Error>> {
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

        if let Some(entries) = &self.function_entries {
            entries.markup(program, addr, log)?;
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
    use crate::format::seam_stubs::FileHeader;
    use crate::format::seam_stubs::OptionalHeader;
    use crate::format::pe::machine_constants::{
        IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_ARM64, IMAGE_FILE_MACHINE_I386,
    };

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

    struct FixtureFileHeader {
        machine: i16,
    }

    impl FileHeader for FixtureFileHeader {
        fn get_machine(&self) -> i16 {
            self.machine
        }
        fn is_x86(&self) -> bool {
            matches!(
                self.machine as u16,
                IMAGE_FILE_MACHINE_I386 | IMAGE_FILE_MACHINE_AMD64
            )
        }
        fn is_arm(&self) -> bool {
            matches!(self.machine as u16, IMAGE_FILE_MACHINE_ARM64)
        }
    }

    struct FixtureOptionalHeader;

    impl OptionalHeader for FixtureOptionalHeader {
        fn get_size_of_image(&self) -> i64 {
            0x1000
        }
        fn get_image_base(&self) -> i64 {
            0x400000
        }
    }

    struct FixtureNtHeader {
        rva_ok: bool,
        machine: i16,
    }

    impl NTHeader for FixtureNtHeader {
        fn get_name(&self) -> String {
            String::new()
        }
        fn is_rva_resoltion_section_aligned(&self) -> bool {
            true
        }
        fn get_file_header(&self) -> Box<dyn FileHeader> {
            Box::new(FixtureFileHeader { machine: self.machine })
        }
        fn get_optional_header(&self) -> Box<dyn OptionalHeader> {
            Box::new(FixtureOptionalHeader)
        }
        fn to_data_type(&self) -> io::Result<Box<dyn crate::program::model::data::data_type::DataType>> {
            unimplemented!()
        }
        fn rva_to_pointer(&self, rva: i32) -> i32 {
            // Identity mapping: RVA == pointer, mirroring an unrelocated single-section image.
            rva
        }
        fn rva_to_pointer_long(&self, rva: i64) -> i64 {
            rva as i64
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

    fn directory_bytes(virtual_address: i32, size: i32) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&virtual_address.to_le_bytes());
        bytes.extend_from_slice(&size.to_le_bytes());
        bytes
    }

    #[test]
    fn directory_name_matches_java_constant() {
        let mut reader = FixtureReader::new(vec![0u8; 8]);
        let nt_header = FixtureNtHeader { rva_ok: true, machine: IMAGE_FILE_MACHINE_I386 as i16 };
        let directory = ExceptionDataDirectory::new(&nt_header, &mut reader, None).unwrap();
        assert_eq!(directory.get_directory_name(), "IMAGE_DIRECTORY_ENTRY_EXCEPTION");
    }

    #[test]
    fn zero_virtual_address_skips_parsing() {
        let bytes = directory_bytes(0, 0);
        let mut reader = FixtureReader::new(bytes);
        let nt_header = FixtureNtHeader { rva_ok: true, machine: IMAGE_FILE_MACHINE_I386 as i16 };

        let directory = ExceptionDataDirectory::new(&nt_header, &mut reader, None).unwrap();

        assert_eq!(directory.get_virtual_address(), 0);
        assert!(!directory.has_parsed_correctly());
        assert!(directory.get_function_entries().is_none());
    }

    #[test]
    fn invalid_rva_skips_parsing() {
        let bytes = directory_bytes(8, 0x18);
        let mut reader = FixtureReader::new(bytes);
        let nt_header = FixtureNtHeader { rva_ok: false, machine: IMAGE_FILE_MACHINE_I386 as i16 };

        let directory = ExceptionDataDirectory::new(&nt_header, &mut reader, None).unwrap();

        assert!(!directory.has_parsed_correctly());
        assert!(directory.get_function_entries().is_none());
    }

    #[test]
    fn x86_machine_picks_x86_function_entries() {
        let bytes = directory_bytes(8, 0x18);
        let mut reader = FixtureReader::new(bytes);
        let nt_header = FixtureNtHeader { rva_ok: true, machine: IMAGE_FILE_MACHINE_AMD64 as i16 };

        let directory = ExceptionDataDirectory::new(&nt_header, &mut reader, None).unwrap();

        assert!(directory.has_parsed_correctly());
        assert!(directory.get_function_entries().is_some());
    }

    #[test]
    fn arm_machine_picks_arm_function_entries() {
        let bytes = directory_bytes(8, 0x18);
        let mut reader = FixtureReader::new(bytes);
        let nt_header = FixtureNtHeader { rva_ok: true, machine: IMAGE_FILE_MACHINE_ARM64 as i16 };

        let directory = ExceptionDataDirectory::new(&nt_header, &mut reader, None).unwrap();

        assert!(directory.has_parsed_correctly());
        assert!(directory.get_function_entries().is_some());
    }

    #[test]
    fn chpe_load_config_forces_arm_function_entries_even_for_x86_machine() {
        let bytes = directory_bytes(8, 0x18);
        let mut reader = FixtureReader::new(bytes);
        let nt_header = FixtureNtHeader { rva_ok: true, machine: IMAGE_FILE_MACHINE_AMD64 as i16 };
        let lc_dir = LoadConfigDirectory::new(0x2000);

        let directory =
            ExceptionDataDirectory::new(&nt_header, &mut reader, Some(lc_dir)).unwrap();

        // Java: `isChpe` short-circuits the X86 branch (`isX86() && !isChpe`) and is itself an
        // alternative for the ARM branch (`isArm() || isChpe`), so a CHPE image always picks the
        // ARM table regardless of the reported machine type.
        assert!(directory.has_parsed_correctly());
        assert!(directory.get_function_entries().is_some());
    }

    #[test]
    fn unsupported_architecture_leaves_function_entries_none() {
        let bytes = directory_bytes(8, 0x18);
        let mut reader = FixtureReader::new(bytes);
        // Neither x86 nor ARM: the `MIPS16` machine constant, which Java's `isX86`/`isArm`
        // switches both fall through on.
        let nt_header = FixtureNtHeader { rva_ok: true, machine: 0x0266 };

        let directory = ExceptionDataDirectory::new(&nt_header, &mut reader, None).unwrap();

        assert!(directory.has_parsed_correctly());
        assert!(directory.get_function_entries().is_none());
    }

    #[test]
    fn get_pointer_matches_nt_header_rva_to_pointer() {
        let bytes = directory_bytes(8, 0x18);
        let mut reader = FixtureReader::new(bytes);
        let nt_header = FixtureNtHeader { rva_ok: true, machine: IMAGE_FILE_MACHINE_I386 as i16 };
        let directory = ExceptionDataDirectory::new(&nt_header, &mut reader, None).unwrap();

        assert_eq!(directory.get_pointer(&nt_header), 8);
    }

    #[test]
    fn get_pointer_is_negative_one_when_virtual_address_is_zero() {
        let mut reader = FixtureReader::new(vec![0u8; 8]);
        let nt_header = FixtureNtHeader { rva_ok: true, machine: IMAGE_FILE_MACHINE_I386 as i16 };
        let directory = ExceptionDataDirectory::new(&nt_header, &mut reader, None).unwrap();

        assert_eq!(directory.get_pointer(&nt_header), -1);
    }

    #[test]
    fn display_matches_java_to_string_format() {
        let bytes = directory_bytes(8, 0x18);
        let mut reader = FixtureReader::new(bytes);
        let nt_header = FixtureNtHeader { rva_ok: true, machine: IMAGE_FILE_MACHINE_I386 as i16 };
        let directory = ExceptionDataDirectory::new(&nt_header, &mut reader, None).unwrap();

        assert_eq!(directory.to_string(), "VirtualAddress: 0x8 Size: 24 bytes");
    }
}

//! Port of `ghidra.app.util.bin.format.pe.LoadConfigDirectory`.
//!
//! Represents the `IMAGE_LOAD_CONFIG_DIRECTORY` data structure defined in `winnt.h`.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::pe::seam_stubs::{ImageArm64ecMetadata, ImageChpeMetadataX86, ImageDynamicRelocationTable};
use crate::format::seam_stubs::{FileHeader, NTHeader, OptionalHeader};
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::enum_::Enum;
use crate::program::model::data::enum_data_type::EnumDataType;
use crate::util::msg::Msg;

/// Port of `LoadConfigDirectory.NAME32`.
pub const NAME32: &str = "IMAGE_LOAD_CONFIG_DIRECTORY32";
/// Port of `LoadConfigDirectory.NAME64`.
pub const NAME64: &str = "IMAGE_LOAD_CONFIG_DIRECTORY64";

/// Port of `ghidra.app.util.bin.format.pe.LoadConfigDirectory`.
///
/// The nested nested structures (`GuardFlags`, `CodeIntegrity`) are ported as sibling structs
/// below, matching the Java static nested classes.
///
/// `NTHeader`/`FileHeader`/`OptionalHeader`/`SectionHeader` are all still unported forward
/// references (this class sits on a dependency cycle, hence `mode=trait` in the descent order --
/// see `crate::format::seam_stubs`/`crate::format::pe::seam_stubs` for the minimal placeholders
/// used here); `ImageArm64ecMetadata`/`ImageChpeMetadataX86`/`ImageDynamicRelocationTable` are
/// similarly unported and modeled as placeholders in `crate::format::pe::seam_stubs` that record
/// only what this constructor captures, without parsing their own contents.
#[derive(Default)]
pub struct LoadConfigDirectory {
    pub size: i32,
    pub time_date_stamp: i32,
    pub major_version: i16,
    pub minor_version: i16,
    pub global_flags_clear: i32,
    pub global_flags_set: i32,
    pub critical_section_default_timeout: i32,
    pub de_commit_free_block_threshold: i64,
    pub de_commit_total_free_threshold: i64,
    pub lock_prefix_table: i64,
    pub maximum_allocation_size: i64,
    pub virtual_memory_threshold: i64,
    pub process_affinity_mask: i64,
    pub process_heap_flags: i32,
    pub csd_version: i16,
    pub dependent_load_flags: i16,
    pub edit_list: i64,
    pub security_cookie: i64,
    pub se_handler_table: i64,
    pub se_handler_count: i64,
    pub guard_cfc_check_function_pointer: i64,
    pub guard_cf_dispatch_function_pointer: i64,
    pub guard_cf_function_table: i64,
    pub guard_cf_function_count: i64,
    pub guard_flags: Option<GuardFlags>,
    pub code_integrity: Option<CodeIntegrity>,
    pub guard_address_taken_iat_entry_table: i64,
    pub guard_address_taken_iat_entry_count: i64,
    pub guard_long_jump_target_table: i64,
    pub guard_long_jump_target_count: i64,
    pub dynamic_value_reloc_table: i64,
    pub chpe_metadata_pointer: i64,
    pub guard_rf_failure_routine: i64,
    pub guard_rf_failure_routine_function_pointer: i64,
    pub dynamic_value_reloc_table_offset: i32,
    pub dynamic_value_reloc_table_section: i16,
    pub reserved2: i16,
    pub guard_rf_verify_stack_pointer_function_pointer: i64,
    pub hot_patch_table_offset: i32,
    pub reserved3: i32,
    pub enclave_configuration_pointer: i64,
    pub volatile_metadata_pointer: i64,
    pub guard_eh_continuation_table: i64,
    pub guard_eh_continuation_count: i64,
    pub guard_xfg_check_function_pointer: i64,
    pub guard_xfg_dispatch_function_pointer: i64,
    pub guard_xfg_table_dispatch_function_pointer: i64,
    pub cast_guard_os_determined_failure_mode: i64,
    pub guard_memcpy_function_pointer: i64,
    pub uma_function_pointers: i64,

    pub is64bit: bool,
    pub dvrt: Option<ImageDynamicRelocationTable>,
    pub chpe_metadata_x86: Option<ImageChpeMetadataX86>,
    pub arm64ec_metadata: Option<ImageArm64ecMetadata>,
}

impl LoadConfigDirectory {
    /// Port of the package-private `LoadConfigDirectory(BinaryReader, int, NTHeader)`.
    pub fn new(reader: &mut dyn BinaryReader, index: u64, nt: &dyn NTHeader) -> io::Result<Self> {
        let optional_header = nt.get_optional_header();
        let is64bit = optional_header.is64bit();

        let old_index = reader.get_pointer_index();
        reader.set_pointer_index(index);

        let mut lc = LoadConfigDirectory { is64bit, ..Default::default() };

        // Read original fields.
        lc.size = reader.read_next_int()?;
        lc.time_date_stamp = reader.read_next_int()?;
        lc.major_version = reader.read_next_short()?;
        lc.minor_version = reader.read_next_short()?;
        lc.global_flags_clear = reader.read_next_int()?;
        lc.global_flags_set = reader.read_next_int()?;
        lc.critical_section_default_timeout = reader.read_next_int()?;
        lc.de_commit_free_block_threshold = read_pointer(reader, is64bit)?;
        lc.de_commit_total_free_threshold = read_pointer(reader, is64bit)?;
        lc.lock_prefix_table = read_pointer(reader, is64bit)?;
        lc.maximum_allocation_size = read_pointer(reader, is64bit)?;
        lc.virtual_memory_threshold = read_pointer(reader, is64bit)?;
        if is64bit {
            lc.process_affinity_mask = read_pointer(reader, is64bit)?;
            lc.process_heap_flags = reader.read_next_int()?;
        } else {
            lc.process_heap_flags = reader.read_next_int()?;
            lc.process_affinity_mask = read_pointer(reader, is64bit)?;
        }
        lc.csd_version = reader.read_next_short()?;
        lc.dependent_load_flags = reader.read_next_short()?;
        lc.edit_list = read_pointer(reader, is64bit)?;

        // If the structure size indicates there are more fields, we are dealing with a newer
        // version of the structure. Each size check represents a new version of the structure.
        let has_more = |reader: &dyn BinaryReader| (reader.get_pointer_index() - index) < lc.size as u64;

        if has_more(reader) {
            lc.security_cookie = read_pointer(reader, is64bit)?;
            lc.se_handler_table = read_pointer(reader, is64bit)?;
            lc.se_handler_count = read_pointer(reader, is64bit)?;
        }
        if has_more(reader) {
            lc.guard_cfc_check_function_pointer = read_pointer(reader, is64bit)?;
            lc.guard_cf_dispatch_function_pointer = read_pointer(reader, is64bit)?;
            lc.guard_cf_function_table = read_pointer(reader, is64bit)?;
            lc.guard_cf_function_count = read_pointer(reader, is64bit)?;
            lc.guard_flags = Some(GuardFlags::new(reader.read_next_int()?));
        }
        if has_more(reader) {
            lc.code_integrity = Some(CodeIntegrity::new(reader)?);
        }
        if has_more(reader) {
            lc.guard_address_taken_iat_entry_table = read_pointer(reader, is64bit)?;
            lc.guard_address_taken_iat_entry_count = read_pointer(reader, is64bit)?;
            lc.guard_long_jump_target_table = read_pointer(reader, is64bit)?;
            lc.guard_long_jump_target_count = read_pointer(reader, is64bit)?;
        }
        if has_more(reader) {
            lc.dynamic_value_reloc_table = read_pointer(reader, is64bit)?;
            lc.chpe_metadata_pointer = read_pointer(reader, is64bit)?;
        }
        if has_more(reader) {
            lc.guard_rf_failure_routine = read_pointer(reader, is64bit)?;
            lc.guard_rf_failure_routine_function_pointer = read_pointer(reader, is64bit)?;
            lc.dynamic_value_reloc_table_offset = reader.read_next_int()?;
            lc.dynamic_value_reloc_table_section = reader.read_next_short()?;
            lc.reserved2 = reader.read_next_short()?;
        }
        if has_more(reader) {
            lc.guard_rf_verify_stack_pointer_function_pointer = read_pointer(reader, is64bit)?;
            lc.hot_patch_table_offset = reader.read_next_int()?;
        }
        if has_more(reader) {
            lc.reserved3 = reader.read_next_int()?;
        }
        if has_more(reader) {
            lc.enclave_configuration_pointer = read_pointer(reader, is64bit)?;
        }
        if has_more(reader) {
            lc.volatile_metadata_pointer = read_pointer(reader, is64bit)?;
        }
        if has_more(reader) {
            lc.guard_eh_continuation_table = read_pointer(reader, is64bit)?;
        }
        if has_more(reader) {
            lc.guard_eh_continuation_count = read_pointer(reader, is64bit)?;
        }
        if has_more(reader) {
            lc.guard_xfg_check_function_pointer = read_pointer(reader, is64bit)?;
        }
        if has_more(reader) {
            lc.guard_xfg_dispatch_function_pointer = read_pointer(reader, is64bit)?;
        }
        if has_more(reader) {
            lc.guard_xfg_table_dispatch_function_pointer = read_pointer(reader, is64bit)?;
        }
        if has_more(reader) {
            lc.cast_guard_os_determined_failure_mode = read_pointer(reader, is64bit)?;
        }
        if has_more(reader) {
            lc.guard_memcpy_function_pointer = read_pointer(reader, is64bit)?;
        }
        if has_more(reader) {
            lc.uma_function_pointers = read_pointer(reader, is64bit)?;
        }

        // Parse the CHPE Metadata.
        if lc.chpe_metadata_pointer != 0 {
            let file_header = nt.get_file_header();
            let ptr = nt.va_to_pointer_long(lc.chpe_metadata_pointer);
            let mut r = reader.clone_at(ptr as u64);
            if file_header.is_arm() {
                lc.arm64ec_metadata =
                    Some(ImageArm64ecMetadata::new(r.as_mut(), nt, lc.chpe_metadata_pointer)?);
            }
            if file_header.is_x86() {
                lc.chpe_metadata_x86 =
                    Some(ImageChpeMetadataX86::new(r.as_mut(), nt, lc.chpe_metadata_pointer)?);
            }
        }

        // Parse the Dynamic Value Relocation Table (DVRT).
        if lc.dynamic_value_reloc_table_offset != 0 && lc.dynamic_value_reloc_table_section != 0 {
            let section = file_header_section(
                nt.get_file_header().as_ref(),
                lc.dynamic_value_reloc_table_section as i32 - 1,
            );
            match section {
                Some(section) => {
                    let file_offset =
                        section.get_pointer_to_raw_data() as i64 + lc.dynamic_value_reloc_table_offset as i64;
                    let rva = section.get_virtual_address() as i64 + lc.dynamic_value_reloc_table_offset as i64;
                    let mut r = reader.clone_at(file_offset as u64);
                    lc.dvrt = Some(ImageDynamicRelocationTable::new(r.as_mut(), rva, is64bit)?);
                }
                None => {
                    let msg = format!(
                        "Dynamic value relocation table specifies invalid section number: {}",
                        lc.dynamic_value_reloc_table_section
                    );
                    Msg::error("LoadConfigDirectory", &msg);
                }
            }
        }

        reader.set_pointer_index(old_index);

        Ok(lc)
    }

    /// Port of `LoadConfigDirectory.getSize()`.
    pub fn get_size(&self) -> i32 {
        self.size
    }

    /// Port of `LoadConfigDirectory.getCriticalSectionDefaultTimeout()`.
    pub fn get_critical_section_default_timeout(&self) -> i32 {
        self.critical_section_default_timeout
    }

    /// Port of `LoadConfigDirectory.getSeHandlerTable()`.
    pub fn get_se_handler_table(&self) -> i64 {
        self.se_handler_table
    }

    /// Port of `LoadConfigDirectory.getSeHandlerCount()`.
    pub fn get_se_handler_count(&self) -> i64 {
        self.se_handler_count
    }

    /// Port of `LoadConfigDirectory.getCfgGuardFlags()`.
    pub fn get_cfg_guard_flags(&self) -> Option<&GuardFlags> {
        self.guard_flags.as_ref()
    }

    /// Port of `LoadConfigDirectory.getCfgCheckFunctionPointer()`.
    pub fn get_cfg_check_function_pointer(&self) -> i64 {
        self.guard_cfc_check_function_pointer
    }

    /// Port of `LoadConfigDirectory.getCfgDispatchFunctionPointer()`.
    pub fn get_cfg_dispatch_function_pointer(&self) -> i64 {
        self.guard_cf_dispatch_function_pointer
    }

    /// Port of `LoadConfigDirectory.getCfgFunctionTablePointer()`.
    pub fn get_cfg_function_table_pointer(&self) -> i64 {
        self.guard_cf_function_table
    }

    /// Port of `LoadConfigDirectory.getCfgFunctionCount()`.
    pub fn get_cfg_function_count(&self) -> i64 {
        self.guard_cf_function_count
    }

    /// Port of `LoadConfigDirectory.getGuardAddressIatTableTablePointer()`.
    pub fn get_guard_address_iat_table_table_pointer(&self) -> i64 {
        self.guard_address_taken_iat_entry_table
    }

    /// Port of `LoadConfigDirectory.getGuardAddressIatTableCount()`.
    pub fn get_guard_address_iat_table_count(&self) -> i64 {
        self.guard_address_taken_iat_entry_count
    }

    /// Port of `LoadConfigDirectory.getChpeMetadataPointer()`.
    pub fn get_chpe_metadata_pointer(&self) -> i64 {
        self.chpe_metadata_pointer
    }

    /// Port of `LoadConfigDirectory.getRfgFailureRoutine()`.
    pub fn get_rfg_failure_routine(&self) -> i64 {
        self.guard_rf_failure_routine
    }

    /// Port of `LoadConfigDirectory.getRfgFailureRoutineFunctionPointer()`.
    pub fn get_rfg_failure_routine_function_pointer(&self) -> i64 {
        self.guard_rf_failure_routine_function_pointer
    }

    /// Port of `LoadConfigDirectory.getRfgVerifyStackPointerFunctionPointer()`.
    pub fn get_rfg_verify_stack_pointer_function_pointer(&self) -> i64 {
        self.guard_rf_verify_stack_pointer_function_pointer
    }

    /// Port of `LoadConfigDirectory.getDynamicRelocationTable()`.
    pub fn get_dynamic_relocation_table(&self) -> Option<&ImageDynamicRelocationTable> {
        self.dvrt.as_ref()
    }

    /// Port of `LoadConfigDirectory.getArm64ecMetadata()`.
    pub fn get_arm64ec_metadata(&self) -> Option<&ImageArm64ecMetadata> {
        self.arm64ec_metadata.as_ref()
    }

    /// Port of `LoadConfigDirectory.getChpeMetadataX86()`.
    pub fn get_chpe_metadata_x86(&self) -> Option<&ImageChpeMetadataX86> {
        self.chpe_metadata_x86.as_ref()
    }
}

impl StructConverter for LoadConfigDirectory {
    /// Mirrors `toDataType()`. Not yet fully buildable: the scalar built-in datatype singletons
    /// Java's version adds fields with (`DWORD`/`WORD`/`QWORD`/`Pointer32DataType`/
    /// `Pointer64DataType`) are still traits without a concrete, instantiable `Box<dyn DataType>`
    /// form in this crate (see `crate::app::util::bin::struct_converter`'s module docs), so the
    /// full versioned `IMAGE_LOAD_CONFIG_DIRECTORY{32,64}` structure cannot be assembled yet.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Err(ToDataTypeError::Io(io::Error::new(
            io::ErrorKind::Unsupported,
            "LoadConfigDirectory::to_data_type requires WORD/DWORD/QWORD/Pointer32/64 DataType \
             singletons, which are not yet ported to a concrete instantiable form",
        )))
    }
}

/// Port of `LoadConfigDirectory.readPointer(BinaryReader)`.
fn read_pointer(reader: &mut dyn BinaryReader, is64bit: bool) -> io::Result<i64> {
    if is64bit {
        reader.read_next_long()
    } else {
        reader.read_next_unsigned_int().map(|v| v as i64)
    }
}

/// Small helper wrapping `FileHeader::get_section_header`'s `Option` return so call sites read
/// like the Java null check.
fn file_header_section(
    file_header: &dyn FileHeader,
    index: i32,
) -> Option<Box<dyn crate::format::pe::seam_stubs::SectionHeader>> {
    file_header.get_section_header(index)
}

/// Port of the static nested class `LoadConfigDirectory.GuardFlags` -- Control Flow Guard flags.
pub struct GuardFlags {
    pub flags: i32,
}

impl GuardFlags {
    /// Port of `GuardFlags.NAME`.
    pub const NAME: &'static str = "IMAGE_GUARD_FLAGS";

    /// Port of `GuardFlags(int)`.
    pub fn new(flags: i32) -> Self {
        GuardFlags { flags }
    }

    /// Port of `GuardFlags.getFlags()`.
    pub fn get_flags(&self) -> i32 {
        self.flags
    }
}

impl StructConverter for GuardFlags {
    /// Port of `GuardFlags.toDataType()`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        let mut enum_dt = EnumDataType::new(Self::NAME, 4);
        enum_dt.add("IMAGE_GUARD_CF_INSTRUMENTED", 0x0000_0100);
        enum_dt.add("IMAGE_GUARD_CFW_INSTRUMENTED", 0x0000_0200);
        enum_dt.add("IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT", 0x0000_0400);
        enum_dt.add("IMAGE_GUARD_SECURITY_COOKIE_UNUSED", 0x0000_0800);
        enum_dt.add("IMAGE_GUARD_PROTECT_DELAYLOAD_IAT", 0x0000_1000);
        enum_dt.add("IMAGE_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION", 0x0000_2000);
        enum_dt.add("IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT", 0x0000_4000);
        enum_dt.add("IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION", 0x0000_8000);
        enum_dt.add("IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT", 0x0001_0000);
        enum_dt.add("IMAGE_GUARD_RF_INSTRUMENTED", 0x0002_0000);
        enum_dt.add("IMAGE_GUARD_RF_ENABLE", 0x0004_0000);
        enum_dt.add("IMAGE_GUARD_RF_STRICT", 0x0008_0000);
        enum_dt.add("IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK_1", 0x1000_0000);
        enum_dt.add("IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK_2", 0x2000_0000);
        enum_dt.add("IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK_4", 0x4000_0000);
        enum_dt.add("IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK_8", 0x8000_0000u32 as i64);
        Ok(Box::new(enum_dt))
    }
}

/// Port of the static nested class `LoadConfigDirectory.CodeIntegrity`.
pub struct CodeIntegrity {
    pub flags: i16,
    pub catalog: i16,
    pub catalog_offset: i32,
    pub reserved: i32,
}

impl CodeIntegrity {
    /// Port of `CodeIntegrity.NAME`.
    pub const NAME: &'static str = "IMAGE_LOAD_CONFIG_CODE_INTEGRITY";

    /// Port of `CodeIntegrity(BinaryReader)`.
    pub fn new(reader: &mut dyn BinaryReader) -> io::Result<Self> {
        Ok(CodeIntegrity {
            flags: reader.read_next_short()?,
            catalog: reader.read_next_short()?,
            catalog_offset: reader.read_next_int()?,
            reserved: reader.read_next_int()?,
        })
    }
}

impl std::fmt::Display for CodeIntegrity {
    /// Port of `CodeIntegrity.toString()`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "flags=0x{:x}, catalog=0x{:x}, catalogOffset=0x{:x}, reserved=0x{:x}",
            self.flags as u16, self.catalog as u16, self.catalog_offset, self.reserved
        )
    }
}

impl StructConverter for CodeIntegrity {
    /// Mirrors `CodeIntegrity.toDataType()`. See
    /// [`LoadConfigDirectory::to_data_type`] for why this is not yet buildable (needs
    /// `WORD`/`DWORD` concrete singletons).
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Err(ToDataTypeError::Io(io::Error::new(
            io::ErrorKind::Unsupported,
            "CodeIntegrity::to_data_type requires WORD/DWORD DataType singletons, which are not \
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

    fn reader_for(bytes: Vec<u8>) -> FixtureReader {
        FixtureReader::new(bytes)
    }

    struct FixtureOptionalHeader {
        is64: bool,
    }
    impl OptionalHeader for FixtureOptionalHeader {
        fn get_size_of_image(&self) -> i64 {
            0
        }
        fn get_image_base(&self) -> i64 {
            0
        }
        fn is64bit(&self) -> bool {
            self.is64
        }
    }

    struct FixtureFileHeader;
    impl FileHeader for FixtureFileHeader {
        fn get_machine(&self) -> i16 {
            0x8664u16 as i16
        }
        fn is_x86(&self) -> bool {
            true
        }
        fn is_arm(&self) -> bool {
            false
        }
    }

    struct FixtureNtHeader {
        is64: bool,
    }
    impl NTHeader for FixtureNtHeader {
        fn get_name(&self) -> String {
            "NT".to_string()
        }
        fn is_rva_resoltion_section_aligned(&self) -> bool {
            true
        }
        fn get_file_header(&self) -> Box<dyn FileHeader> {
            Box::new(FixtureFileHeader)
        }
        fn get_optional_header(&self) -> Box<dyn OptionalHeader> {
            Box::new(FixtureOptionalHeader { is64: self.is64 })
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

    /// The fixed byte length of [`base32_bytes`]'s output: every field Java reads
    /// unconditionally, up to and including `EditList`, for a 32-bit image.
    const BASE32_LEN: u32 = 60;

    /// Builds the fixed [`BASE32_LEN`]-byte "base" 32-bit `IMAGE_LOAD_CONFIG_DIRECTORY32` header
    /// (through `EditList`), matching every field Java reads unconditionally before the
    /// version-size checks kick in. `size` is only written into the leading `Size` field (it
    /// does not affect how many bytes this function emits); callers wanting the version-checked
    /// tail fields to parse must append additional bytes themselves and pass a `size` at least
    /// that large.
    fn base32_bytes(size: u32) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&size.to_le_bytes()); // Size
        b.extend_from_slice(&0x1234_5678u32.to_le_bytes()); // TimeDateStamp
        b.extend_from_slice(&1u16.to_le_bytes()); // MajorVersion
        b.extend_from_slice(&0u16.to_le_bytes()); // MinorVersion
        b.extend_from_slice(&0u32.to_le_bytes()); // GlobalFlagsClear
        b.extend_from_slice(&0u32.to_le_bytes()); // GlobalFlagsSet
        b.extend_from_slice(&0u32.to_le_bytes()); // CriticalSectionDefaultTimeout
        b.extend_from_slice(&0u32.to_le_bytes()); // DeCommitFreeBlockThreshold
        b.extend_from_slice(&0u32.to_le_bytes()); // DeCommitTotalFreeThreshold
        b.extend_from_slice(&0u32.to_le_bytes()); // LockPrefixTable
        b.extend_from_slice(&0u32.to_le_bytes()); // MaximumAllocationSize
        b.extend_from_slice(&0u32.to_le_bytes()); // VirtualMemoryThreshold
        b.extend_from_slice(&0u32.to_le_bytes()); // ProcessHeapFlags (32-bit order)
        b.extend_from_slice(&0u32.to_le_bytes()); // ProcessAffinityMask
        b.extend_from_slice(&0u16.to_le_bytes()); // CsdVersion
        b.extend_from_slice(&0u16.to_le_bytes()); // DependentLoadFlags
        b.extend_from_slice(&0u32.to_le_bytes()); // EditList
        b
    }

    #[test]
    fn parses_minimal_32bit_directory() {
        let size = BASE32_LEN;
        let bytes = base32_bytes(size);
        assert_eq!(bytes.len() as u32, size);
        let mut reader = reader_for(bytes);
        let nt = FixtureNtHeader { is64: false };

        let lc = LoadConfigDirectory::new(&mut reader, 0, &nt).unwrap();

        assert_eq!(lc.get_size(), size as i32);
        assert_eq!(lc.time_date_stamp, 0x1234_5678u32 as i32);
        assert_eq!(lc.major_version, 1);
        assert!(!lc.is64bit);
        // The structure was exactly `size` bytes, so none of the versioned tail fields parsed.
        assert!(lc.get_cfg_guard_flags().is_none());
        assert_eq!(lc.get_chpe_metadata_pointer(), 0);
        assert!(lc.get_dynamic_relocation_table().is_none());
    }

    #[test]
    fn parses_guard_cf_block_when_size_allows() {
        // Base header + the SecurityCookie/SEHandlerTable/SEHandlerCount block that Java always
        // reads before the GuardCF block once `size` says there's more (3 pointers = 12 bytes)
        // + a GuardFlags-bearing GuardCF tail (4 pointers + 1 DWORD = 20 bytes).
        let base = base32_bytes(BASE32_LEN + 12 + 20);
        let mut bytes = base;
        bytes.extend_from_slice(&0xAAAAu32.to_le_bytes()); // SecurityCookie
        bytes.extend_from_slice(&0xBBBBu32.to_le_bytes()); // SEHandlerTable
        bytes.extend_from_slice(&0xCCCCu32.to_le_bytes()); // SEHandlerCount
        bytes.extend_from_slice(&0x1000u32.to_le_bytes()); // GuardCFCheckFunctionPointer
        bytes.extend_from_slice(&0x2000u32.to_le_bytes()); // GuardCFDispatchFunctionPointer
        bytes.extend_from_slice(&0x3000u32.to_le_bytes()); // GuardCFFunctionTable
        bytes.extend_from_slice(&5u32.to_le_bytes()); // GuardCFFunctionCount
        bytes.extend_from_slice(&0x0000_0300u32.to_le_bytes()); // GuardFlags

        let mut reader = reader_for(bytes);
        let nt = FixtureNtHeader { is64: false };

        let lc = LoadConfigDirectory::new(&mut reader, 0, &nt).unwrap();

        assert_eq!(lc.security_cookie, 0xAAAA);
        assert_eq!(lc.get_se_handler_table(), 0xBBBB);
        assert_eq!(lc.get_se_handler_count(), 0xCCCC);
        assert_eq!(lc.get_cfg_check_function_pointer(), 0x1000);
        assert_eq!(lc.get_cfg_dispatch_function_pointer(), 0x2000);
        assert_eq!(lc.get_cfg_function_table_pointer(), 0x3000);
        assert_eq!(lc.get_cfg_function_count(), 5);
        assert_eq!(lc.get_cfg_guard_flags().unwrap().get_flags(), 0x0000_0300);
    }

    #[test]
    fn read_pointer_uses_64bit_width_when_is64bit() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0x1122_3344_5566_7788u64.to_le_bytes());
        let mut reader = reader_for(bytes.clone());
        let value = read_pointer(&mut reader, true).unwrap();
        assert_eq!(value as u64, 0x1122_3344_5566_7788u64);

        bytes.truncate(4);
        let mut reader32 = reader_for(vec![0x88, 0x77, 0x66, 0x55]);
        let value32 = read_pointer(&mut reader32, false).unwrap();
        assert_eq!(value32 as u32, 0x5566_7788);
    }

    #[test]
    fn guard_flags_to_data_type_builds_enum() {
        let gf = GuardFlags::new(0x0000_0100);
        let dt = gf.to_data_type().unwrap();
        assert_eq!(dt.get_name(), GuardFlags::NAME);
    }
}

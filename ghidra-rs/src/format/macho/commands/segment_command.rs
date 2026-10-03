//! Port of `ghidra.app.util.bin.format.macho.commands.SegmentCommand`.
//!
//! Represents a `segment_command` / `segment_command_64` structure. See
//! `EXTERNAL_HEADERS/mach-o/loader.h`.

use std::fmt;
use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::app::util::importer::message_log::MessageLog;
use crate::format::macho::commands::load_command::{markup_raw_binary_base, LoadCommand, LoadCommandBase};
use crate::format::macho::commands::load_command_types::{LC_SEGMENT, LC_SEGMENT_64};
use crate::format::macho::commands::segment_constants::{
    FLAG_APPLE_PROTECTED, PROTECTION_R, PROTECTION_W, PROTECTION_X,
};
use crate::format::macho::mach_constants::{is_magic, MH_CIGAM_64, MH_MAGIC, MH_MAGIC_64, NAME_LENGTH};
use crate::format::macho::mach_exception::MachException;
use crate::format::macho::mach_header::MachHeader;
use crate::format::macho::mach_header_file_types::MH_DYLIB_STUB;
use crate::format::macho::section::Section;
use crate::format::macho::section_types::S_ZEROFILL;
use crate::format::macho::struct_builder::{fixed_string, MachStruct};
use crate::format::seam_stubs::FlatProgramAPI;
use crate::program::model::address::Address;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::structure_data_type::StructureDataType;
use crate::program::model::listing::program_module::ProgramModule;
use crate::program::model::symbol::SourceType;
use crate::util::task::TaskMonitor;

/// A Mach-O `segment_command` (32-bit) or `segment_command_64` structure, with its sections.
///
/// Port of `ghidra.app.util.bin.format.macho.commands.SegmentCommand`.
#[derive(Debug, Clone)]
pub struct SegmentCommand {
    base: LoadCommandBase,
    segname: String,
    vmaddr: i64,
    vmsize: i64,
    fileoff: i64,
    filesize: i64,
    maxprot: i32,
    initprot: i32,
    nsects: i64,
    flags: i32,
    is32bit: bool,
    sections: Vec<Section>,
}

impl SegmentCommand {
    /// Java: `SegmentCommand(BinaryReader, boolean)`.
    pub fn new(reader: &mut BinaryReader, is32bit: bool) -> io::Result<Self> {
        let base = LoadCommandBase::new(reader)?;
        let segname = reader.read_next_ascii_string_fixed(NAME_LENGTH)?;
        let (vmaddr, vmsize, fileoff, filesize) = if is32bit {
            (
                reader.read_next_unsigned_int()? as i64,
                reader.read_next_unsigned_int()? as i64,
                reader.read_next_unsigned_int()? as i64,
                reader.read_next_unsigned_int()? as i64,
            )
        } else {
            (
                reader.read_next_long()?,
                reader.read_next_long()?,
                reader.read_next_long()?,
                reader.read_next_long()?,
            )
        };
        let maxprot = reader.read_next_int()?;
        let initprot = reader.read_next_int()?;
        let mut cmd = SegmentCommand {
            base,
            segname,
            vmaddr,
            vmsize,
            fileoff,
            filesize,
            maxprot,
            initprot,
            nsects: 0,
            flags: 0,
            is32bit,
            sections: Vec::new(),
        };
        cmd.nsects = cmd.check_count(reader.read_next_unsigned_int()? as i64)?;
        cmd.flags = reader.read_next_int()?;
        for _ in 0..cmd.nsects {
            cmd.sections.push(Section::new(reader, is32bit)?);
        }
        Ok(cmd)
    }

    /// Java: `getSections()`.
    pub fn get_sections(&self) -> &[Section] {
        &self.sections
    }

    /// Mutable access to the sections, used by `MachHeader`'s name sanitizing (Java mutates the
    /// list's elements through `getSections()`).
    pub fn get_sections_mut(&mut self) -> &mut [Section] {
        &mut self.sections
    }

    /// Java: `getSectionContaining(Address)`. Note the inclusive end, as in Java.
    pub fn get_section_containing(&self, address: &Address) -> Option<&Section> {
        let offset = address.offset();
        self.sections.iter().find(|section| {
            let start = section.get_address();
            let end = start.wrapping_add(section.get_size());
            offset >= start && offset <= end
        })
    }

    /// Java: `getSectionByName(String)`.
    pub fn get_section_by_name(&self, section_name: &str) -> Option<&Section> {
        self.sections.iter().find(|s| s.get_section_name() == section_name)
    }

    /// Java: `getSegmentName()`.
    pub fn get_segment_name(&self) -> &str {
        &self.segname
    }

    /// Java: `setSegmentName(String)`.
    pub fn set_segment_name(&mut self, name: impl Into<String>) {
        self.segname = name.into();
    }

    /// Java: `getVMaddress()`. Masks off a possible chained fixup found in kernelcache segment
    /// addresses.
    pub fn get_vm_address(&self) -> i64 {
        if (self.vmaddr & 0xfff0_0000_0000) == 0xfff0_0000_0000 {
            return self.vmaddr | 0xffff_0000_0000_0000u64 as i64;
        }
        self.vmaddr
    }

    /// Java: `setVMaddress(long)`.
    pub fn set_vm_address(&mut self, vmaddr: i64) {
        self.vmaddr = vmaddr;
    }

    /// Java: `getVMsize()`.
    pub fn get_vm_size(&self) -> i64 {
        self.vmsize
    }

    /// Java: `setVMsize(long)`.
    pub fn set_vm_size(&mut self, vm_size: i64) {
        self.vmsize = vm_size;
    }

    /// Java: `getFileOffset()`.
    pub fn get_file_offset(&self) -> i64 {
        self.fileoff
    }

    /// Java: `setFileOffset(long)`.
    pub fn set_file_offset(&mut self, file_offset: i64) {
        self.fileoff = file_offset;
    }

    /// Java: `getFileSize()`.
    pub fn get_file_size(&self) -> i64 {
        self.filesize
    }

    /// Java: `setFileSize(long)`.
    pub fn set_file_size(&mut self, file_size: i64) {
        self.filesize = file_size;
    }

    /// Java: `getMaxProtection()`.
    pub fn get_max_protection(&self) -> i32 {
        self.maxprot
    }

    /// Java: `getInitProtection()`.
    pub fn get_init_protection(&self) -> i32 {
        self.initprot
    }

    /// Java: `isRead()`.
    pub fn is_read(&self) -> bool {
        (self.initprot as u32 & PROTECTION_R) != 0
    }

    /// Java: `isWrite()`.
    pub fn is_write(&self) -> bool {
        (self.initprot as u32 & PROTECTION_W) != 0
    }

    /// Java: `isExecute()`.
    pub fn is_execute(&self) -> bool {
        (self.initprot as u32 & PROTECTION_X) != 0
    }

    /// Java: `getNumberOfSections()`.
    pub fn get_number_of_sections(&self) -> i64 {
        self.nsects
    }

    /// Java: `getFlags()`.
    pub fn get_flags(&self) -> i32 {
        self.flags
    }

    /// Java: `isAppleProtected()`.
    pub fn is_apple_protected(&self) -> bool {
        (self.flags as u32 & FLAG_APPLE_PROTECTED) != 0
    }

    /// Java: `is32bit()`.
    pub fn is32bit(&self) -> bool {
        self.is32bit
    }

    /// Java: `contains(long)`, an unsigned comparison against the raw (unmasked) address.
    pub fn contains(&self, addr: i64) -> bool {
        (addr as u64) >= (self.vmaddr as u64)
            && (addr as u64) < (self.vmaddr.wrapping_add(self.vmsize) as u64)
    }

    /// Java: `toDataType()`, returning the concrete structure.
    pub fn to_structure(&self) -> Result<StructureDataType, ToDataTypeError> {
        let mut s = MachStruct::new(self.get_command_name());
        s.dword("cmd")?.dword("cmdsize")?;
        s.add_len(fixed_string()?, NAME_LENGTH as i32, "segname", None)?;
        for name in ["vmaddr", "vmsize", "fileoff", "filesize"] {
            if self.is32bit {
                s.dword(name)?;
            } else {
                s.qword(name)?;
            }
        }
        s.dword("maxprot")?.dword("initprot")?.dword("nsects")?.dword("flags")?;
        s.finish_structure()
    }

    /// Java: `create(int, String, long, long, long, long, int, int, int)`. Creates a new segment
    /// command byte array (with no sections).
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        magic: u32,
        name: &str,
        vm_addr: i64,
        vm_size: i64,
        file_offset: i64,
        file_size: i64,
        max_prot: i32,
        init_prot: i32,
        flags: i32,
    ) -> Result<Vec<u8>, MachException> {
        if name.len() > 16 {
            return Err(MachException::new(format!("Segment name cannot exceed 16 bytes: {name}")));
        }
        let size = Self::size(magic)?;
        let big_endian = magic == MH_MAGIC;
        let is64bit = magic == MH_CIGAM_64 || magic == MH_MAGIC_64;
        let mut bytes = vec![0u8; size as usize];
        let put32 = |b: &mut [u8], off: usize, v: u32| {
            let v = if big_endian { v.to_be_bytes() } else { v.to_le_bytes() };
            b[off..off + 4].copy_from_slice(&v);
        };
        let put64 = |b: &mut [u8], off: usize, v: u64| {
            let v = if big_endian { v.to_be_bytes() } else { v.to_le_bytes() };
            b[off..off + 8].copy_from_slice(&v);
        };
        put32(&mut bytes, 0x00, if is64bit { LC_SEGMENT_64 } else { LC_SEGMENT });
        put32(&mut bytes, 0x04, size as u32);
        bytes[0x08..0x08 + name.len()].copy_from_slice(name.as_bytes());
        if is64bit {
            put64(&mut bytes, 0x18, vm_addr as u64);
            put64(&mut bytes, 0x20, vm_size as u64);
            put64(&mut bytes, 0x28, file_offset as u64);
            put64(&mut bytes, 0x30, file_size as u64);
            put32(&mut bytes, 0x38, max_prot as u32);
            put32(&mut bytes, 0x3c, init_prot as u32);
            put32(&mut bytes, 0x40, 0);
            put32(&mut bytes, 0x44, flags as u32);
        } else {
            put32(&mut bytes, 0x18, vm_addr as u32);
            put32(&mut bytes, 0x1c, vm_size as u32);
            put32(&mut bytes, 0x20, file_offset as u32);
            put32(&mut bytes, 0x24, file_size as u32);
            put32(&mut bytes, 0x28, max_prot as u32);
            put32(&mut bytes, 0x2c, init_prot as u32);
            put32(&mut bytes, 0x30, 0);
            put32(&mut bytes, 0x34, flags as u32);
        }
        Ok(bytes)
    }

    /// Java: `size(int)`. The size in bytes of a segment command for the given magic.
    pub fn size(magic: u32) -> Result<i32, MachException> {
        if !is_magic(magic) {
            return Err(MachException::new(format!("Invalid magic: 0x{magic:x}")));
        }
        let is64bit = magic == MH_CIGAM_64 || magic == MH_MAGIC_64;
        Ok(if is64bit { 0x48 } else { 0x38 })
    }

    fn markup_sections_raw(
        &self,
        header: &MachHeader,
        api: &dyn FlatProgramAPI,
        base_address: &Address,
        parent_module: &mut dyn ProgramModule,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), String> {
        let err = |e: &dyn fmt::Display| e.to_string();
        let addr = base_address.space().address(self.get_start_index() as i64);
        let mut section_address =
            addr.add(self.to_data_type().map_err(|e| err(&e))?.get_length() as i64).map_err(|e| err(&e))?;
        for section in &self.sections {
            if monitor.is_cancelled() {
                return Ok(());
            }
            let section_dt = section.to_data_type().map_err(|e| err(&e))?;
            let section_dt_len = section_dt.get_length();
            api.create_data(&section_address, section_dt).map_err(|e| err(&e))?;
            api.set_plate_comment(&section_address, &section.to_string());
            section_address = section_address.add(section_dt_len as i64).map_err(|e| err(&e))?;

            if section.get_type() as u32 == S_ZEROFILL {
                continue;
            }
            if header.get_file_type() as u32 == MH_DYLIB_STUB {
                continue;
            }

            let section_byte_addr =
                base_address.add(section.get_offset() as i64).map_err(|e| err(&e))?;
            if section.get_size() > 0 {
                api.create_label(&section_byte_addr, section.get_section_name(), true, SourceType::Imported)
                    .map_err(|e| err(&e))?;
                api.create_fragment(parent_module, "SECTION_BYTES", &section_byte_addr, section.get_size())
                    .map_err(|e| err(&e))?;
            }

            if section.get_relocation_offset() > 0 {
                let reloc_start_addr =
                    base_address.add(section.get_relocation_offset() as i64).map_err(|e| err(&e))?;
                let mut offset = 0i64;
                for reloc in section.get_relocations() {
                    if monitor.is_cancelled() {
                        return Ok(());
                    }
                    let reloc_dt = reloc.to_data_type().map_err(|e| err(&e))?;
                    let reloc_dt_len = reloc_dt.get_length();
                    let reloc_addr = reloc_start_addr.add(offset).map_err(|e| err(&e))?;
                    api.create_data(&reloc_addr, reloc_dt).map_err(|e| err(&e))?;
                    api.set_plate_comment(&reloc_addr, &reloc.to_string());
                    offset += reloc_dt_len as i64;
                }
                api.create_fragment(
                    parent_module,
                    &format!("{}_Relocations", section.get_section_name()),
                    &reloc_start_addr,
                    offset,
                )
                .map_err(|e| err(&e))?;
            }
        }
        Ok(())
    }
}

impl StructConverter for SegmentCommand {
    /// Java: `toDataType()`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Ok(Box::new(self.to_structure()?))
    }
}

impl LoadCommand for SegmentCommand {
    fn base(&self) -> &LoadCommandBase {
        &self.base
    }

    fn get_command_name(&self) -> String {
        "segment_command".to_string()
    }

    fn markup_raw_binary(
        &self,
        header: &MachHeader,
        api: &dyn FlatProgramAPI,
        base_address: &Address,
        parent_module: &mut dyn ProgramModule,
        monitor: &dyn TaskMonitor,
        log: &MessageLog,
    ) {
        markup_raw_binary_base(self, header, api, base_address, parent_module, monitor, log);
        if let Err(message) =
            self.markup_sections_raw(header, api, base_address, parent_module, monitor)
        {
            log.append_msg(&format!("Unable to create {} - {message}", self.get_command_name()));
        }
    }
}

impl fmt::Display for SegmentCommand {
    /// Java: `toString()`, the segment name.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.segname)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::macho::mach_constants::MH_CIGAM;
    use crate::format::macho::mach_header::test_support::Bytes;
    use crate::format::macho::section::test_support::section_bytes;

    #[test]
    fn parses_64_bit_segment_with_sections() {
        let mut b = Bytes::new(true);
        b.u32(LC_SEGMENT_64)
            .u32(72 + 2 * 80)
            .name("__DATA", 16)
            .u64(0x1_0000_4000)
            .u64(0x2000)
            .u64(0x4000)
            .u64(0x1000)
            .u32(3)
            .u32(3)
            .u32(2)
            .u32(FLAG_APPLE_PROTECTED);
        b.raw(&section_bytes(false, true, "__data", "__DATA", 0x1_0000_4000, 0x10, 0x4000, 0, 0, 0));
        b.raw(&section_bytes(false, true, "__bss", "__DATA", 0x1_0000_5000, 0x20, 0, 0, 0, S_ZEROFILL));
        let mut r = BinaryReader::from_bytes(b.buf, true);
        let seg = SegmentCommand::new(&mut r, false).unwrap();
        assert_eq!(r.get_pointer_index(), 72 + 160);
        assert_eq!(seg.get_command_type() as u32, LC_SEGMENT_64);
        assert_eq!(seg.get_command_size(), 232);
        assert_eq!(seg.get_segment_name(), "__DATA");
        assert_eq!(seg.get_vm_address(), 0x1_0000_4000);
        assert_eq!(seg.get_vm_size(), 0x2000);
        assert_eq!(seg.get_file_offset(), 0x4000);
        assert_eq!(seg.get_file_size(), 0x1000);
        assert!(seg.is_read() && seg.is_write() && !seg.is_execute());
        assert!(seg.is_apple_protected());
        assert_eq!(seg.get_number_of_sections(), 2);
        assert_eq!(seg.get_section_by_name("__bss").unwrap().get_size(), 0x20);
        assert!(seg.get_section_by_name("__nope").is_none());
        assert!(seg.contains(0x1_0000_5fff));
        assert!(!seg.contains(0x1_0000_6000));
        assert_eq!(seg.to_string(), "__DATA");
        assert_eq!(seg.get_command_name(), "segment_command");
    }

    #[test]
    fn section_containing_is_end_inclusive() {
        let mut b = Bytes::new(false);
        b.u32(LC_SEGMENT).u32(56 + 68).name("__TEXT", 16).u32(0x1000).u32(0x1000).u32(0).u32(0x1000);
        b.u32(5).u32(5).u32(1).u32(0);
        b.raw(&section_bytes(true, false, "__text", "__TEXT", 0x1100, 0x10, 0x100, 0, 0, 0));
        let seg = SegmentCommand::new(&mut BinaryReader::from_bytes(b.buf, false), true).unwrap();
        assert!(seg.is32bit());
        use crate::program::model::address::{AddressSpace, AddressSpaceType};
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let at = |o: i64| space.address(o);
        assert!(seg.get_section_containing(&at(0x1110)).is_some());
        assert!(seg.get_section_containing(&at(0x1111)).is_none());
        assert!(seg.get_section_containing(&at(0x10ff)).is_none());
    }

    #[test]
    fn kernelcache_vm_address_is_sign_extended() {
        let bytes = SegmentCommand::create(
            MH_CIGAM_64, "__TEXT", 0xfff0_0000_4000u64 as i64, 0x100, 0, 0, 5, 5, 0,
        )
        .unwrap();
        let seg = SegmentCommand::new(&mut BinaryReader::from_bytes(bytes, true), false).unwrap();
        assert_eq!(seg.get_vm_address() as u64, 0xffff_fff0_0000_4000);
    }

    #[test]
    fn create_round_trips_both_widths() {
        let b64 = SegmentCommand::create(MH_CIGAM_64, "__LINKEDIT", 0x5000, 0x100, 0x3000, 0x80, 1, 1, 0)
            .unwrap();
        assert_eq!(b64.len(), 0x48);
        let s = SegmentCommand::new(&mut BinaryReader::from_bytes(b64, true), false).unwrap();
        assert_eq!(s.get_segment_name(), "__LINKEDIT");
        assert_eq!(s.get_file_offset(), 0x3000);
        assert_eq!(s.get_number_of_sections(), 0);

        let b32 = SegmentCommand::create(MH_MAGIC, "__TEXT", 0x1000, 0x20, 0, 0x20, 7, 5, 0).unwrap();
        assert_eq!(b32.len(), 0x38);
        let s = SegmentCommand::new(&mut BinaryReader::from_bytes(b32, false), true).unwrap();
        assert_eq!(s.get_command_type() as u32, LC_SEGMENT);
        assert_eq!(s.get_vm_size(), 0x20);
        assert_eq!(s.get_max_protection(), 7);
        assert!(s.is_execute());

        assert_eq!(SegmentCommand::size(MH_CIGAM).unwrap(), 0x38);
        assert!(SegmentCommand::size(0).is_err());
        assert!(SegmentCommand::create(MH_MAGIC, "__A_VERY_LONG_NAME_", 0, 0, 0, 0, 0, 0, 0).is_err());
    }

    #[test]
    fn data_type_layouts_match_java() {
        use crate::format::macho::struct_builder::test_support::fields;
        let b64 = SegmentCommand::create(MH_CIGAM_64, "__TEXT", 0, 0, 0, 0, 0, 0, 0).unwrap();
        let s = SegmentCommand::new(&mut BinaryReader::from_bytes(b64, true), false).unwrap();
        let dt = s.to_structure().unwrap();
        assert_eq!(dt.get_name(), "segment_command");
        assert_eq!(dt.get_length(), 0x48);
        assert_eq!(fields(&dt)[2], ("segname".to_string(), 8, 16));
        let b32 = SegmentCommand::create(MH_MAGIC, "__TEXT", 0, 0, 0, 0, 0, 0, 0).unwrap();
        let s = SegmentCommand::new(&mut BinaryReader::from_bytes(b32, false), true).unwrap();
        assert_eq!(s.to_structure().unwrap().get_length(), 0x38);
    }

    #[test]
    fn huge_section_count_is_rejected() {
        let mut b = Bytes::new(true);
        b.u32(LC_SEGMENT_64).u32(72).name("__X", 16).u64(0).u64(0).u64(0).u64(0);
        b.u32(0).u32(0).u32(0x8000_0000).u32(0);
        assert!(SegmentCommand::new(&mut BinaryReader::from_bytes(b.buf, true), false).is_err());
    }
}

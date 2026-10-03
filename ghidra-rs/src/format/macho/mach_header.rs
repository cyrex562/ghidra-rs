//! Port of `ghidra.app.util.bin.format.macho.MachHeader`.
//!
//! Represents a `mach_header` / `mach_header_64` structure and owns the header's parsed
//! [load commands](LoadCommandKind). See `EXTERNAL_HEADERS/mach-o/loader.h`.
//!
//! Java's `getLoadCommands(Class<T>)`/`getFirstLoadCommand(Class<T>)` filter the command list by
//! runtime class. The load-command family is closed (every instance is built by
//! [`load_command_factory`](crate::format::macho::commands::load_command_factory)), so this port
//! stores the commands as the [`LoadCommandKind`] enum and filters with the typed
//! [`get_load_commands_of`](MachHeader::get_load_commands_of)/
//! [`get_first_load_command`](MachHeader::get_first_load_command) instead of reflection.

use std::fmt;
use std::rc::Rc;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::opinion::dyld_cache_utils::SplitDyldCache;
use crate::app::util::bin::byte_provider::ByteProvider;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::macho::commands::dynamic_library_command::DynamicLibraryCommand;
use crate::format::macho::commands::load_command::LoadCommand;
use crate::format::macho::commands::load_command_factory;
use crate::format::macho::commands::load_command_kind::{LoadCommandKind, LoadCommandVariant};
use crate::format::macho::commands::load_command_types::{
    LC_REEXPORT_DYLIB, LC_SEGMENT, LC_SEGMENT_64,
};
use crate::format::macho::commands::segment_command::SegmentCommand;
use crate::format::macho::cpu_types::{get_processor, CPU_ARCH_ABI64};
use crate::format::macho::mach_constants::{is_magic, MH_CIGAM, MH_CIGAM_64, MH_MAGIC, MH_MAGIC_64};
use crate::format::macho::mach_exception::MachException;
use crate::format::macho::mach_header_file_types::get_file_type_name;
use crate::format::macho::mach_header_flags::get_flags;
use crate::format::macho::section::Section;
use crate::format::macho::struct_builder::MachStruct;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::structure_data_type::StructureDataType;
use crate::program::model::mem::memory::is_valid_memory_block_name;

const MAX_LOAD_COMMANDS: i32 = 32_768;

/// A Mach-O `mach_header` (32-bit) or `mach_header_64` structure.
///
/// Port of `ghidra.app.util.bin.format.macho.MachHeader`.
pub struct MachHeader {
    magic: i32,
    cpu_type: i32,
    cpu_sub_type: i32,
    file_type: i32,
    n_cmds: i32,
    size_of_cmds: i32,
    flags: i32,
    reserved: i32,

    is32bit: bool,
    commands: Vec<LoadCommandKind>,
    command_index: u64,
    reader: BinaryReader,
    mach_header_start_index_in_provider: u64,
    mach_header_start_index: u64,
    parsed: bool,
}

impl fmt::Debug for MachHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MachHeader")
            .field("magic", &format_args!("{:#x}", self.magic))
            .field("cpu_type", &self.cpu_type)
            .field("file_type", &self.file_type)
            .field("n_cmds", &self.n_cmds)
            .field("start_index_in_provider", &self.mach_header_start_index_in_provider)
            .field("parsed", &self.parsed)
            .finish()
    }
}

impl MachHeader {
    /// Java: `isMachHeader(ByteProvider)`. True if the provider starts with a Mach header magic
    /// signature.
    pub fn is_mach_header(provider: &Rc<dyn ByteProvider>) -> bool {
        provider.length() > 4
            && read_magic(provider, 0).map(|m| is_magic(m as u32)).unwrap_or(false)
    }

    /// Java: `MachHeader(ByteProvider)`. Assumes the header starts at index 0.
    pub fn new(provider: Rc<dyn ByteProvider>) -> Result<Self, MachException> {
        Self::with_start_index(provider, 0)
    }

    /// Java: `MachHeader(ByteProvider, long)`. Assumes the header starts at
    /// `mach_header_start_index_in_provider`, with the rest of the Mach-O relative to it.
    pub fn with_start_index(
        provider: Rc<dyn ByteProvider>,
        mach_header_start_index_in_provider: u64,
    ) -> Result<Self, MachException> {
        Self::with_start_index_relative(provider, mach_header_start_index_in_provider, true)
    }

    /// Java: `MachHeader(ByteProvider, long, boolean)`.
    ///
    /// `is_remaining_macho_relative_to_start_index` is true if the rest of the Mach-O uses
    /// indexes relative to the header start (common in UBI and kernel cache files), false if it
    /// uses absolute indexing from 0 (common in DYLD cache files).
    pub fn with_start_index_relative(
        provider: Rc<dyn ByteProvider>,
        mach_header_start_index_in_provider: u64,
        is_remaining_macho_relative_to_start_index: bool,
    ) -> Result<Self, MachException> {
        let magic = read_magic(&provider, mach_header_start_index_in_provider)?;
        if !is_magic(magic as u32) {
            return Err(MachException::new("Invalid Mach-O binary."));
        }
        let mach_header_start_index = if is_remaining_macho_relative_to_start_index {
            mach_header_start_index_in_provider
        } else {
            0
        };
        let little_endian = magic as u32 == MH_CIGAM || magic as u32 == MH_CIGAM_64;
        let mut reader = BinaryReader::new(provider, little_endian);
        reader.set_pointer_index(mach_header_start_index_in_provider + 4); // skip magic number

        let cpu_type = reader.read_next_int()?;
        let cpu_sub_type = reader.read_next_int()?;
        let file_type = reader.read_next_int()?;
        let n_cmds = reader.read_next_int()?;
        let size_of_cmds = reader.read_next_int()?;
        let flags = reader.read_next_int()?;

        let is32bit = (cpu_type & CPU_ARCH_ABI64) == 0;
        let reserved = if is32bit { 0 } else { reader.read_next_int()? };
        let command_index = reader.get_pointer_index();

        Ok(MachHeader {
            magic,
            cpu_type,
            cpu_sub_type,
            file_type,
            n_cmds,
            size_of_cmds,
            flags,
            reserved,
            is32bit,
            commands: Vec::new(),
            command_index,
            reader,
            mach_header_start_index_in_provider,
            mach_header_start_index,
            parsed: false,
        })
    }

    /// Java: `parse()`. Parses this header's load commands; a no-op once parsed.
    pub fn parse(&mut self) -> Result<&mut Self, MachException> {
        self.parse_split(None)
    }

    /// Java: `parse(SplitDyldCache)`. `split_dyld_cache` is the split DYLD cache this header
    /// resides in, or `None` if a split DYLD cache is not being used; with one, commands whose
    /// data lives in `__LINKEDIT` read it from whichever cache file maps that segment.
    ///
    /// Segment load commands are parsed first, since commands whose data lives in `__LINKEDIT`
    /// need that segment to have been parsed.
    pub fn parse_split(
        &mut self,
        split_dyld_cache: Option<&SplitDyldCache>,
    ) -> Result<&mut Self, MachException> {
        if self.parsed {
            return Ok(self);
        }
        self.validate_num_load_commands()?;

        let mut reader = self.reader.clone();
        let mut current_index = self.command_index;
        let mut segment_indexes = Vec::new();
        let mut non_segment_indexes = Vec::new();
        for _ in 0..self.n_cmds {
            reader.set_pointer_index(current_index);
            let cmd_type = reader.read_next_int()? as u32;
            let size = reader.read_next_unsigned_int()?;
            if cmd_type == LC_SEGMENT || cmd_type == LC_SEGMENT_64 {
                segment_indexes.push(current_index);
            } else {
                non_segment_indexes.push(current_index);
            }
            current_index = current_index.wrapping_add(size);
        }
        for index in segment_indexes.into_iter().chain(non_segment_indexes) {
            reader.set_pointer_index(index);
            let lc = load_command_factory::get_load_command(&mut reader, self, split_dyld_cache)?;
            self.commands.push(lc);
        }
        self.reader = reader;
        sanitize_segment_section_names(
            self.commands.iter_mut().filter_map(SegmentCommand::from_kind_mut),
        );
        self.parsed = true;
        Ok(self)
    }

    /// Java: `parseSegments()`. Parses only this header's segment load commands.
    pub fn parse_segments(&mut self) -> Result<Vec<SegmentCommand>, MachException> {
        self.validate_num_load_commands()?;
        let mut segments = Vec::new();
        self.reader.set_pointer_index(self.command_index);
        for _ in 0..self.n_cmds {
            let cmd_type = self.reader.peek_next_int()? as u32;
            if cmd_type == LC_SEGMENT || cmd_type == LC_SEGMENT_64 {
                segments.push(SegmentCommand::new(&mut self.reader, self.is32bit)?);
            } else {
                self.skip_load_command()?;
            }
        }
        sanitize_segment_section_names(segments.iter_mut());
        Ok(segments)
    }

    /// Java: `parseReexports()`. Parses only this header's `LC_REEXPORT_DYLIB` commands.
    pub fn parse_reexports(&mut self) -> Result<Vec<DynamicLibraryCommand>, MachException> {
        self.validate_num_load_commands()?;
        let mut cmds = Vec::new();
        self.reader.set_pointer_index(self.command_index);
        for _ in 0..self.n_cmds {
            let cmd_type = self.reader.peek_next_int()? as u32;
            if cmd_type == LC_REEXPORT_DYLIB {
                let cmd = DynamicLibraryCommand::new(&mut self.reader)?;
                self.reader.set_pointer_index(cmd.get_start_index());
                cmds.push(cmd);
            }
            self.skip_load_command()?;
        }
        Ok(cmds)
    }

    /// Java: `parseAndCheck(int)`. True if this header contains a load command of the given
    /// [type](crate::format::macho::commands::load_command_types).
    pub fn parse_and_check(&mut self, load_command_type: u32) -> Result<bool, MachException> {
        self.validate_num_load_commands()?;
        self.reader.set_pointer_index(self.command_index);
        for _ in 0..self.n_cmds {
            if self.reader.peek_next_int()? as u32 == load_command_type {
                return Ok(true);
            }
            self.skip_load_command()?;
        }
        Ok(false)
    }

    /// Reads a load command's `cmd`/`cmdsize` and moves past the command.
    fn skip_load_command(&mut self) -> Result<(), MachException> {
        self.reader.read_next_int()?;
        let size = self.reader.read_next_unsigned_int()?;
        let next = self.reader.get_pointer_index().wrapping_add(size).wrapping_sub(8);
        self.reader.set_pointer_index(next);
        Ok(())
    }

    /// Java: `getMagic()`.
    pub fn get_magic(&self) -> i32 {
        self.magic
    }

    /// Java: `getCpuType()`.
    pub fn get_cpu_type(&self) -> i32 {
        self.cpu_type
    }

    /// Java: `getImageBase()`. Always 0.
    pub fn get_image_base(&self) -> i64 {
        0
    }

    /// Java: `getCpuSubType()`.
    pub fn get_cpu_sub_type(&self) -> i32 {
        self.cpu_sub_type
    }

    /// Java: `getFileType()`.
    pub fn get_file_type(&self) -> i32 {
        self.file_type
    }

    /// Java: `getNumberOfCommands()`.
    pub fn get_number_of_commands(&self) -> i32 {
        self.n_cmds
    }

    /// Java: `getSizeOfCommands()`.
    pub fn get_size_of_commands(&self) -> i32 {
        self.size_of_cmds
    }

    /// Java: `getFlags()`.
    pub fn get_flags(&self) -> i32 {
        self.flags
    }

    /// Java: `getReserved()`. The field only exists in 64-bit headers.
    pub fn get_reserved(&self) -> Result<i32, MachException> {
        if self.is32bit {
            return Err(MachException::new("Field does not exist for 32 bit Mach-O files."));
        }
        Ok(self.reserved)
    }

    /// Java: `toDataType()`, returning the concrete structure.
    pub fn to_structure(&self) -> Result<StructureDataType, ToDataTypeError> {
        let mut s = MachStruct::new("mach_header");
        for name in ["magic", "cputype", "cpusubtype", "filetype", "ncmds", "sizeofcmds", "flags"] {
            s.dword(name)?;
        }
        if !self.is32bit {
            s.dword("reserved")?;
        }
        s.finish_structure()
    }

    /// Java: `getStartIndex()`. The start index used for calculating offsets: 0 for things such
    /// as the DYLD shared cache, where offsets are based off the beginning of the file.
    pub fn get_start_index(&self) -> u64 {
        self.mach_header_start_index
    }

    /// Java: `getStartIndexInProvider()`. The offset of this header in the provider.
    pub fn get_start_index_in_provider(&self) -> u64 {
        self.mach_header_start_index_in_provider
    }

    /// The provider this header (and its sections' bytes) is read from.
    ///
    /// Rust addition: Java's `Section.getDataStream` reaches the provider through the reader it
    /// was parsed with, which is always this header's reader (see
    /// [`Section`](crate::format::macho::section)'s module docs).
    pub fn get_byte_provider(&self) -> &Rc<dyn ByteProvider> {
        self.reader.get_byte_provider()
    }

    /// Java: `is32bit()`.
    pub fn is32bit(&self) -> bool {
        self.is32bit
    }

    /// Java: `getAddressSize()`.
    pub fn get_address_size(&self) -> i32 {
        if self.is32bit {
            4
        } else {
            8
        }
    }

    /// Java: `getAllSegments()`.
    pub fn get_all_segments(&self) -> Vec<&SegmentCommand> {
        self.get_load_commands_of::<SegmentCommand>()
    }

    /// Java: `getSegment(String)`. `None` stands in for Java's `null`.
    pub fn get_segment(&self, segment_name: &str) -> Option<&SegmentCommand> {
        self.get_all_segments().into_iter().find(|s| s.get_segment_name() == segment_name)
    }

    /// Java: `getSection(String, String)`.
    pub fn get_section(&self, segment_name: &str, section_name: &str) -> Option<&Section> {
        self.get_segment(segment_name)?.get_section_by_name(section_name)
    }

    /// Java: `getAllSections()`.
    pub fn get_all_sections(&self) -> Vec<&Section> {
        self.get_all_segments().into_iter().flat_map(|s| s.get_sections().iter()).collect()
    }

    /// Java: `getLoadCommands()`.
    pub fn get_load_commands(&self) -> &[LoadCommandKind] {
        &self.commands
    }

    /// Mutable access to the parsed load commands, for callers that edit them in place the way
    /// Java code mutates the objects `getLoadCommands()` hands out (e.g. `ExtractedMacho`
    /// resizing segments and appending symbols).
    pub fn get_load_commands_mut(&mut self) -> &mut [LoadCommandKind] {
        &mut self.commands
    }

    /// Java: `getLoadCommands(Class<T>)`.
    pub fn get_load_commands_of<T: LoadCommandVariant>(&self) -> Vec<&T> {
        self.commands.iter().filter_map(T::from_kind).collect()
    }

    /// Java: `getFirstLoadCommand(Class<T>)`. `None` stands in for Java's `null`.
    pub fn get_first_load_command<T: LoadCommandVariant>(&self) -> Option<&T> {
        self.commands.iter().find_map(T::from_kind)
    }

    /// Java: `isLittleEndian()`.
    pub fn is_little_endian(&self) -> bool {
        self.magic as u32 == MH_CIGAM || self.magic as u32 == MH_CIGAM_64
    }

    /// Java: `getSize()`. The size of this header in bytes (excluding load commands).
    pub fn get_size(&self) -> i64 {
        self.command_index as i64 - self.mach_header_start_index_in_provider as i64
    }

    /// Java: `getDescription()`.
    pub fn get_description(&self) -> String {
        let flags = get_flags(self.flags as u32);
        format!(
            "Magic: 0x{:x}\nCPU Type: {}\nFile Type: {}\nFlags: 0x{:b}\n[{}]\n",
            self.magic,
            get_processor(self.cpu_type, self.cpu_sub_type),
            get_file_type_name(self.file_type as u32),
            self.flags,
            flags.join(", ")
        )
    }

    /// Java: the private `validateNumLoadCommands()`.
    fn validate_num_load_commands(&self) -> Result<(), MachException> {
        if self.n_cmds > MAX_LOAD_COMMANDS || self.n_cmds < 0 {
            return Err(MachException::new(format!(
                "Invalid number of load commands ({})",
                self.n_cmds
            )));
        }
        Ok(())
    }

    /// Java: `create(int, int, int, int, int, int, int, int)`. Creates a new Mach header byte
    /// array; `reserved` is ignored for 32-bit magic.
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        magic: u32,
        cpu_type: i32,
        cpu_sub_type: i32,
        file_type: i32,
        n_cmds: i32,
        size_of_cmds: i32,
        flags: i32,
        reserved: i32,
    ) -> Result<Vec<u8>, MachException> {
        if !is_magic(magic) {
            return Err(MachException::new(format!("Invalid magic: 0x{magic:x}")));
        }
        // Java: DataConverter.getInstance(magic == MH_MAGIC) -- big-endian only for MH_MAGIC, so
        // MH_MAGIC_64 yields a little-endian 64-bit header (its bytes read back as MH_CIGAM_64).
        let big_endian = magic == MH_MAGIC;
        let is64bit = magic == MH_CIGAM_64 || magic == MH_MAGIC_64;
        let put = |v: u32| if big_endian { v.to_be_bytes() } else { v.to_le_bytes() };
        let mut bytes = Vec::with_capacity(if is64bit { 0x20 } else { 0x1c });
        for v in [magic, cpu_type as u32, cpu_sub_type as u32, file_type as u32, n_cmds as u32] {
            bytes.extend(put(v));
        }
        bytes.extend(put(size_of_cmds as u32));
        bytes.extend(put(flags as u32));
        if is64bit {
            bytes.extend(put(reserved as u32));
        }
        Ok(bytes)
    }
}

impl StructConverter for MachHeader {
    /// Java: `toDataType()`.
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        Ok(Box::new(self.to_structure()?))
    }
}

impl fmt::Display for MachHeader {
    /// Java: `toString()`, which is `getDescription()`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.get_description())
    }
}

/// Java: the private `readMagic(ByteProvider, long)`; the magic is always read big-endian.
fn read_magic(provider: &Rc<dyn ByteProvider>, index: u64) -> std::io::Result<i32> {
    BinaryReader::new(Rc::clone(provider), false).read_int(index)
}

/// Java: the private `sanitizeSegmentSectionNames(List<SegmentCommand>)`.
///
/// Sanitizes invalid segment/section names so they can be used as memory blocks and program tree
/// modules: names with an embedded NUL, `.o` files whose one segment has a blank name, and names
/// that are complete garbage bytes.
fn sanitize_segment_section_names<'a>(segments: impl Iterator<Item = &'a mut SegmentCommand>) {
    let invalid = |s: &str| s.trim().is_empty() || !is_valid_memory_block_name(s);
    for (i, segment) in segments.enumerate() {
        let name = segment.get_segment_name().replace('\0', "_");
        segment.set_segment_name(name);
        if invalid(segment.get_segment_name()) {
            segment.set_segment_name(format!("__INVALID.{i}"));
        }
        for (j, section) in segment.get_sections_mut().iter_mut().enumerate() {
            let seg = section.get_segment_name().replace('\0', "_");
            section.set_segment_name(seg);
            let sect = section.get_section_name().replace('\0', "_");
            section.set_section_name(sect);
            if invalid(section.get_segment_name()) {
                section.set_segment_name(format!("__INVALID.{i}"));
            }
            if invalid(section.get_section_name()) {
                section.set_section_name(format!("__invalid.{j}"));
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    //! Builders for synthetic Mach-O images.

    use std::rc::Rc;

    use crate::app::util::bin::byte_array_provider::ByteArrayProvider;
    use crate::app::util::bin::byte_provider::ByteProvider;

    /// Endian-aware byte appender used to lay out synthetic Mach-O images.
    pub(crate) struct Bytes {
        pub(crate) little: bool,
        pub(crate) buf: Vec<u8>,
    }

    impl Bytes {
        pub(crate) fn new(little: bool) -> Self {
            Bytes { little, buf: Vec::new() }
        }
        pub(crate) fn u32(&mut self, v: u32) -> &mut Self {
            let b = if self.little { v.to_le_bytes() } else { v.to_be_bytes() };
            self.buf.extend(b);
            self
        }
        pub(crate) fn u64(&mut self, v: u64) -> &mut Self {
            let b = if self.little { v.to_le_bytes() } else { v.to_be_bytes() };
            self.buf.extend(b);
            self
        }
        pub(crate) fn u16(&mut self, v: u16) -> &mut Self {
            let b = if self.little { v.to_le_bytes() } else { v.to_be_bytes() };
            self.buf.extend(b);
            self
        }
        pub(crate) fn u8(&mut self, v: u8) -> &mut Self {
            self.buf.push(v);
            self
        }
        /// `s` NUL-padded (or truncated) to `len` bytes.
        pub(crate) fn name(&mut self, s: &str, len: usize) -> &mut Self {
            let mut v = s.as_bytes().to_vec();
            v.resize(len, 0);
            self.buf.extend(v);
            self
        }
        pub(crate) fn raw(&mut self, v: &[u8]) -> &mut Self {
            self.buf.extend_from_slice(v);
            self
        }
        pub(crate) fn pad_to(&mut self, len: usize) -> &mut Self {
            self.buf.resize(len, 0);
            self
        }
        pub(crate) fn len(&self) -> usize {
            self.buf.len()
        }
    }

    /// Wraps `bytes` as a shared provider.
    pub(crate) fn provider(bytes: Vec<u8>) -> Rc<dyn ByteProvider> {
        Rc::new(ByteArrayProvider::new(bytes))
    }

    /// A parsed 64-bit little-endian x86-64 executable header with no load commands.
    pub(crate) fn empty_header64() -> super::MachHeader {
        use crate::format::macho::cpu_types::CPU_TYPE_X86_64;
        use crate::format::macho::mach_constants::MH_MAGIC_64;
        let bytes = super::MachHeader::create(MH_MAGIC_64, CPU_TYPE_X86_64, 3, 2, 0, 0, 0, 0).unwrap();
        let mut h = super::MachHeader::new(provider(bytes)).unwrap();
        h.parse().unwrap();
        h
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{provider, Bytes};
    use super::*;
    use crate::format::macho::commands::load_command_types::{LC_ID_DYLIB, LC_UUID};
    use std::rc::Rc;
    use crate::format::macho::commands::uuid_command::UuidCommand;
    use crate::format::macho::cpu_types::{CPU_TYPE_ARM_64, CPU_TYPE_POWERPC, CPU_TYPE_X86_64};
    use crate::format::macho::mach_header_file_types::{MH_DYLIB, MH_EXECUTE};
    use crate::format::macho::struct_builder::test_support::names;

    /// A 64-bit little-endian executable with `__PAGEZERO`/`__TEXT` segments (the latter with
    /// one `__text` section), an `LC_UUID` placed *before* the segments, and an `LC_ID_DYLIB`.
    fn image64() -> Vec<u8> {
        let mut b = Bytes::new(true);
        let header_len = 32;
        let uuid_len = 24;
        let pagezero_len = 72;
        let text_len = 72 + 80;
        let dylib_len = 24 + 16;
        let sizeofcmds = uuid_len + pagezero_len + text_len + dylib_len;
        b.u32(MH_CIGAM_64.swap_bytes()) // written LE -> reads back as MH_CIGAM_64 big-endian
            .u32(CPU_TYPE_X86_64 as u32)
            .u32(3)
            .u32(MH_EXECUTE)
            .u32(4)
            .u32(sizeofcmds as u32)
            .u32(0x0020_0085)
            .u32(0);
        assert_eq!(b.len(), header_len);
        // LC_UUID
        b.u32(LC_UUID).u32(uuid_len as u32).raw(&[0xab; 16]);
        // __PAGEZERO, garbage NUL inside the name
        b.u32(LC_SEGMENT_64)
            .u32(pagezero_len as u32)
            .name("__PAGE\0ZERO", 16)
            .u64(0)
            .u64(0x1_0000_0000)
            .u64(0)
            .u64(0)
            .u32(0)
            .u32(0)
            .u32(0)
            .u32(0);
        // __TEXT with one section
        b.u32(LC_SEGMENT_64)
            .u32(text_len as u32)
            .name("__TEXT", 16)
            .u64(0x1_0000_0000)
            .u64(0x1000)
            .u64(0)
            .u64(0x1000)
            .u32(5)
            .u32(5)
            .u32(1)
            .u32(0);
        b.name("__text", 16)
            .name("__TEXT", 16)
            .u64(0x1_0000_0800)
            .u64(0x10)
            .u32(0x800)
            .u32(4)
            .u32(0)
            .u32(0)
            .u32(0x8000_0400)
            .u32(0)
            .u32(0)
            .u32(0);
        // LC_ID_DYLIB, name at offset 24
        let name_off = b.len() + 24;
        b.u32(LC_ID_DYLIB).u32(dylib_len as u32).u32(24).u32(0x1234).u32(0x10000).u32(0x10000);
        b.name("libfoo.dylib", 16);
        assert_eq!(b.len(), name_off + 16);
        b.pad_to(0x1000);
        b.buf
    }

    #[test]
    fn is_mach_header_checks_magic() {
        assert!(MachHeader::is_mach_header(&provider(image64())));
        assert!(!MachHeader::is_mach_header(&provider(vec![0, 0, 0, 0, 0])));
        assert!(!MachHeader::is_mach_header(&provider(vec![0xcf, 0xfa, 0xed, 0xfe])));
    }

    #[test]
    fn rejects_bad_magic() {
        let err = MachHeader::new(provider(vec![0u8; 64])).unwrap_err();
        assert_eq!(err.message(), "Invalid Mach-O binary.");
    }

    #[test]
    fn header_fields_64_bit_little_endian() {
        let h = MachHeader::new(provider(image64())).unwrap();
        assert_eq!(h.get_magic() as u32, MH_CIGAM_64);
        assert!(h.is_little_endian());
        assert!(!h.is32bit());
        assert_eq!(h.get_address_size(), 8);
        assert_eq!(h.get_cpu_type(), CPU_TYPE_X86_64);
        assert_eq!(h.get_cpu_sub_type(), 3);
        assert_eq!(h.get_file_type() as u32, MH_EXECUTE);
        assert_eq!(h.get_number_of_commands(), 4);
        assert_eq!(h.get_flags(), 0x0020_0085);
        assert_eq!(h.get_reserved().unwrap(), 0);
        assert_eq!(h.get_size(), 32);
        assert_eq!(h.get_start_index(), 0);
        assert!(h.get_load_commands().is_empty(), "nothing parsed yet");
    }

    #[test]
    fn parse_puts_segments_first_and_sanitizes_names() {
        let mut h = MachHeader::new(provider(image64())).unwrap();
        h.parse().unwrap();
        let kinds: Vec<String> =
            h.get_load_commands().iter().map(|c| c.get_command_name()).collect();
        assert_eq!(kinds, ["segment_command", "segment_command", "uuid_command", "dylib_command"]);
        let segs: Vec<&str> = h.get_all_segments().iter().map(|s| s.get_segment_name()).collect();
        assert_eq!(segs, ["__PAGE_ZERO", "__TEXT"]);
        assert_eq!(h.get_segment("__TEXT").unwrap().get_vm_address(), 0x1_0000_0000);
        assert!(h.get_segment("__DATA").is_none());
        let text = h.get_section("__TEXT", "__text").unwrap();
        assert_eq!(text.get_address(), 0x1_0000_0800);
        assert_eq!(h.get_all_sections().len(), 1);
        let uuid = h.get_first_load_command::<UuidCommand>().unwrap();
        assert_eq!(uuid.get_uuid(), &[0xab; 16]);
        let dylibs = h.get_load_commands_of::<DynamicLibraryCommand>();
        assert_eq!(dylibs.len(), 1);
        assert_eq!(dylibs[0].get_dynamic_library().get_name().get_string(), "libfoo.dylib");
        // Parsing twice is a no-op.
        h.parse().unwrap();
        assert_eq!(h.get_load_commands().len(), 4);
    }

    #[test]
    fn parse_segments_and_parse_and_check() {
        let mut h = MachHeader::new(provider(image64())).unwrap();
        let segs = h.parse_segments().unwrap();
        assert_eq!(segs.len(), 2);
        assert_eq!(segs[0].get_segment_name(), "__PAGE_ZERO");
        assert_eq!(segs[1].get_sections()[0].get_section_name(), "__text");
        assert!(h.parse_and_check(LC_UUID).unwrap());
        assert!(h.parse_and_check(LC_ID_DYLIB).unwrap());
        assert!(!h.parse_and_check(LC_REEXPORT_DYLIB).unwrap());
        assert!(h.parse_reexports().unwrap().is_empty());
    }

    #[test]
    fn header_at_offset_relative_and_absolute() {
        let mut bytes = vec![0u8; 0x100];
        bytes.extend(image64());
        let h = MachHeader::with_start_index(provider(bytes.clone()), 0x100).unwrap();
        assert_eq!(h.get_start_index(), 0x100);
        assert_eq!(h.get_start_index_in_provider(), 0x100);
        assert_eq!(h.get_size(), 32);
        let h = MachHeader::with_start_index_relative(provider(bytes), 0x100, false).unwrap();
        assert_eq!(h.get_start_index(), 0);
        assert_eq!(h.get_start_index_in_provider(), 0x100);
    }

    #[test]
    fn big_endian_32_bit_header() {
        let bytes =
            MachHeader::create(MH_MAGIC, CPU_TYPE_POWERPC, 0, MH_DYLIB as i32, 0, 0, 1, 99).unwrap();
        assert_eq!(bytes.len(), 0x1c);
        assert_eq!(&bytes[..4], &[0xfe, 0xed, 0xfa, 0xce]);
        let mut h = MachHeader::new(provider(bytes)).unwrap();
        assert!(!h.is_little_endian());
        assert!(h.is32bit());
        assert_eq!(h.get_cpu_type(), CPU_TYPE_POWERPC);
        assert_eq!(h.get_file_type() as u32, MH_DYLIB);
        assert_eq!(h.get_size(), 0x1c);
        assert_eq!(
            h.get_reserved().unwrap_err().message(),
            "Field does not exist for 32 bit Mach-O files."
        );
        h.parse().unwrap();
        assert!(h.get_load_commands().is_empty());
        assert_eq!(names(&h.to_structure().unwrap()).len(), 7);
    }

    #[test]
    fn create_64_bit_little_endian_round_trips() {
        let bytes =
            MachHeader::create(MH_MAGIC_64, CPU_TYPE_ARM_64, 0, MH_EXECUTE as i32, 2, 0x40, 0, 7)
                .unwrap();
        assert_eq!(bytes.len(), 0x20);
        let h = MachHeader::new(provider(bytes)).unwrap();
        assert!(h.is_little_endian());
        assert_eq!(h.get_number_of_commands(), 2);
        assert_eq!(h.get_size_of_commands(), 0x40);
        assert_eq!(h.get_reserved().unwrap(), 7);
        let s = h.to_structure().unwrap();
        assert_eq!(s.get_length(), 32);
        assert_eq!(names(&s).last().unwrap(), "reserved");
        assert!(MachHeader::create(0x1234, 0, 0, 0, 0, 0, 0, 0).is_err());
    }

    #[test]
    fn too_many_load_commands_is_rejected() {
        let bytes = MachHeader::create(MH_MAGIC_64, CPU_TYPE_ARM_64, 0, 2, 40_000, 0, 0, 0).unwrap();
        let mut h = MachHeader::new(provider(bytes)).unwrap();
        assert_eq!(h.parse().unwrap_err().message(), "Invalid number of load commands (40000)");
    }

    /// A DYLD-cache file whose only mapping covers `[0x2000_0000, +0x1000)` at file offset 0;
    /// `linkedit` bytes are placed at file offset 0x800.
    fn cache_file(linkedit: &[u8]) -> Vec<u8> {
        let mut b = Bytes::new(true);
        b.name("dyld_v1  x86_64", 16).u32(0x28).u32(1).u32(0).u32(0).u64(0);
        b.u64(0x2000_0000).u64(0x1000).u64(0).u32(1).u32(1);
        b.pad_to(0x800).raw(linkedit);
        b.pad_to(0x1000);
        b.buf
    }

    /// A Mach-O with a `__LINKEDIT` segment at `linkedit_vm` and an `LC_FUNCTION_STARTS` whose
    /// data is at file offset 0x800 (in whichever file maps `__LINKEDIT`).
    fn image_with_function_starts(linkedit_vm: u64) -> Vec<u8> {
        let mut b = Bytes::new(true);
        b.u32(MH_CIGAM_64.swap_bytes()).u32(CPU_TYPE_X86_64 as u32).u32(3).u32(MH_DYLIB).u32(2);
        b.u32(72 + 16).u32(0).u32(0);
        b.u32(LC_SEGMENT_64).u32(72).name("__LINKEDIT", 16).u64(linkedit_vm).u64(0x1000);
        b.u64(0).u64(0x1000).u32(1).u32(1).u32(0).u32(0);
        b.u32(crate::format::macho::commands::load_command_types::LC_FUNCTION_STARTS).u32(16).u32(0x800).u32(4);
        b.pad_to(0x1000);
        b.buf
    }

    #[test]
    fn split_cache_linkedit_comes_from_the_mapping_file() {
        use crate::app::util::bin::binary_reader::BinaryReader;
        use crate::app::util::importer::message_log::MessageLog;
        use crate::app::util::opinion::dyld_cache_utils::SplitDyldCache;
        use crate::format::macho::commands::function_starts_command::FunctionStartsCommand;
        use crate::format::macho::dyld::dyld_cache_header::DyldCacheHeader;
        use crate::program::model::address::{AddressSpace, AddressSpaceType};
        use crate::util::task::DummyMonitor;

        let cache = provider(cache_file(&[0x10, 0x20, 0x00, 0x00]));
        let mut ch = DyldCacheHeader::new(&BinaryReader::new(Rc::clone(&cache), true)).unwrap();
        ch.parse_from_file(false, &MessageLog::new(), &DummyMonitor).unwrap();
        let split = SplitDyldCache::from_parts(vec![cache], vec![ch], vec!["cache".into()]);

        let mut h = MachHeader::new(provider(image_with_function_starts(0x2000_0000))).unwrap();
        h.parse_split(Some(&split)).unwrap();
        let fs = h.get_first_load_command::<FunctionStartsCommand>().expect("function starts parsed");
        let space = AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0);
        let starts = fs.find_function_start_addrs(&space.address(0x1000)).unwrap();
        let offs: Vec<i64> = starts.iter().map(|a| a.offset()).collect();
        assert_eq!(offs, [0x1010, 0x1030], "deltas read from the cache file, not the image");

        // __LINKEDIT not mapped by any cache file: the command is corrupt.
        let mut h = MachHeader::new(provider(image_with_function_starts(0x9000_0000))).unwrap();
        h.parse_split(Some(&split)).unwrap();
        let corrupt = h.get_load_commands_of::<crate::format::macho::commands::corrupt_load_command::CorruptLoadCommand>();
        assert_eq!(corrupt.len(), 1);
        assert_eq!(corrupt[0].get_problem().to_string(), "__LINKEDIT segment not found in DYLD cache");
    }

    #[test]
    fn description_matches_java() {
        let bytes =
            MachHeader::create(MH_MAGIC_64, CPU_TYPE_X86_64, 3, MH_EXECUTE as i32, 0, 0, 0x5, 0)
                .unwrap();
        let h = MachHeader::new(provider(bytes)).unwrap();
        assert_eq!(
            h.to_string(),
            "Magic: 0xcffaedfe\nCPU Type: x86\nFile Type: EXECUTE\nFlags: 0x101\n[NOUNDEFS, DYLDLINK]\n"
        );
    }
}

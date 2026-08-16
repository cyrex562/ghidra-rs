//! Minimal placeholder traits for core types that a ported interface references before the real
//! Rust port of that type exists yet. Each stub exposes only the members needed by the
//! interface(s) that currently reference it, and is expected to be replaced (or grown into a
//! supertrait of) the real port once that Java class is ported. See `STUBS.tsv` for provenance.

use crate::app::util::opinion::unix_aout_program_loader::{DOT_BSS, DOT_DATA, DOT_TEXT};
use crate::format::dwarf::attribs::dwarf_attribute_def::DWARFAttributeDef;
use crate::format::dwarf::attribs::dwarf_form::DWARFForm;
use crate::format::dwarf::dwarf_abbreviation::DWARFAbbreviation;
use crate::format::dwarf::expression::dwarf_expression::DWARFExpression;
use crate::format::dwarf::external::object_type::ObjectType;
use crate::filesystem::ghidra::g_binary_reader::GBinaryReader;
use crate::format::dwarf::dwarf_range::DWARFRange;
use crate::format::elf::elf_load_helper::ElfLoadHelper;
use crate::format::golang::go_ver::GoVer;
use crate::format::golang::go_ver_range::GoVerRange;
use crate::format::pdb2::pdbreader::r#type::abstract_ms_type::AbstractMsType;
use crate::format::pe::rich::ms_product_type::MsProductType;
use crate::format::unixaout::unix_aout_symbol::UnixAoutSymbol;
use crate::program::model::address::Address;
use crate::program::model::listing::Program as ListingProgram;
use crate::program::model::mem::MemoryBlock;

/// Placeholder for `ghidra.app.util.datatype.microsoft.GUID`, referenced by
/// [`PdbByteReader::parse_guid`](crate::format::pdb2::pdbreader::pdb_byte_reader::PdbByteReader::parse_guid)
/// before the real class is ported. Only the fields and constructor `PdbByteReader` needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Guid {
    pub data1: i32,
    pub data2: i16,
    pub data3: i16,
    pub data4: Vec<u8>,
}

impl Guid {
    pub fn new(data1: i32, data2: i16, data3: i16, data4: Vec<u8>) -> Self {
        Guid { data1, data2, data3, data4 }
    }
}

/// Placeholder for `ghidra.app.util.bin.format.pdb2.pdbreader.PdbReaderOptions`, referenced by
/// [`AbstractPdb`] before the real class is ported. Models just the two charset accessors that
/// [`PdbByteReader::parse_string`](crate::format::pdb2::pdbreader::pdb_byte_reader::PdbByteReader::parse_string)
/// needs.
pub struct PdbReaderOptions {
    pub one_byte_charset: crate::format::pdb2::pdbreader::pdb_byte_reader::PdbCharset,
    pub two_byte_charset: crate::format::pdb2::pdbreader::pdb_byte_reader::PdbCharset,
}

impl PdbReaderOptions {
    pub fn one_byte_charset(&self) -> crate::format::pdb2::pdbreader::pdb_byte_reader::PdbCharset {
        self.one_byte_charset
    }

    pub fn two_byte_charset(&self) -> crate::format::pdb2::pdbreader::pdb_byte_reader::PdbCharset {
        self.two_byte_charset
    }
}

/// Placeholder for `ghidra.app.util.bin.format.pdb2.pdbreader.AbstractPdb`, referenced by
/// [`PdbByteReader::parse_string`](crate::format::pdb2::pdbreader::pdb_byte_reader::PdbByteReader::parse_string)
/// and by
/// [`AbstractCobol0MsType::parent_type`](crate::format::pdb2::pdbreader::type::abstract_cobol0_ms_type::AbstractCobol0MsType::parent_type)
/// before the real class is ported.
pub trait AbstractPdb {
    fn pdb_reader_options(&self) -> &PdbReaderOptions;

    /// Placeholder for `AbstractPdb.getTypeRecord(RecordNumber)`, needed to resolve the type
    /// pointed to by a [`RecordNumber`].
    fn get_type_record(&self, record_number: RecordNumber) -> Box<dyn AbstractMsType>;
}

/// Placeholder for `ghidra.app.util.bin.format.pdb2.pdbreader.C13ChecksumType`, referenced by
/// [`C13FileChecksum::to_display_string`](crate::format::pdb2::pdbreader::c13_file_checksum::C13FileChecksum::to_display_string)
/// before the real enum is ported. Models only the `fromValue` lookup and the `toString()`
/// display name that the checksum's display string needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum C13ChecksumType {
    UnknownChecksumType,
    NoneChecksumType,
    Md5ChecksumType,
    Sha1ChecksumType,
    Sha256ChecksumType,
}

impl C13ChecksumType {
    pub fn from_value(val: i32) -> Self {
        match val {
            0x00 => C13ChecksumType::NoneChecksumType,
            0x01 => C13ChecksumType::Md5ChecksumType,
            0x02 => C13ChecksumType::Sha1ChecksumType,
            0x03 => C13ChecksumType::Sha256ChecksumType,
            _ => C13ChecksumType::UnknownChecksumType,
        }
    }
}

impl std::fmt::Display for C13ChecksumType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            C13ChecksumType::UnknownChecksumType => "UnknownChecksumType",
            C13ChecksumType::NoneChecksumType => "NoneChecksumType",
            C13ChecksumType::Md5ChecksumType => "Md5ChecksumType",
            C13ChecksumType::Sha1ChecksumType => "Sha1ChecksumType",
            C13ChecksumType::Sha256ChecksumType => "Sha256ChecksumType",
        };
        f.write_str(name)
    }
}

/// Placeholder for `ghidra.app.util.bin.format.pdb2.pdbreader.RecordNumber`, referenced by
/// [`MsType`](crate::format::pdb2::pdbreader::type::ms_type::MsType) before the real class is
/// ported. Models only the `NO_TYPE` sentinel that `MsType::record_number`'s default needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RecordNumber {
    pub number: i32,
}

impl RecordNumber {
    pub const T_NOTYPE: i32 = 0;

    pub fn no_type() -> Self {
        RecordNumber { number: Self::T_NOTYPE }
    }
}

/// Placeholder for `ghidra.app.util.bin.format.pdb2.pdbreader.msf.MsfFileReader`, referenced by
/// [`Msf::file_reader`](crate::format::pdb2::pdbreader::msf::msf::Msf::file_reader) before the
/// real class is ported. `Msf` only ever returns this type opaquely, so no members are needed
/// yet.
pub trait MsfFileReaderLike {}

/// Placeholder for `ghidra.app.util.bin.format.pdb2.pdbreader.msf.MsfStream`, referenced by
/// [`Msf::stream`](crate::format::pdb2::pdbreader::msf::msf::Msf::stream) before the real class
/// is ported. `Msf` only ever returns this type opaquely, so no members are needed yet.
pub trait MsfStreamLike {}

/// Placeholder for `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.AbstractMsSymbol`,
/// referenced by
/// [`MsSymbolIterator`](crate::format::pdb2::pdbreader::ms_symbol_iterator::MsSymbolIterator)
/// before the real class is ported. `MsSymbolIterator` only ever passes this type opaquely
/// (as `Box<dyn AbstractMsSymbol>`), so no members are needed yet.
pub trait AbstractMsSymbol {}

/// Placeholder for `ghidra.app.util.bin.format.pdb2.pdbreader.PdbDebugInfo`, referenced by
/// [`GlobalReferenceIterator`](crate::format::pdb2::pdbreader::global_reference_iterator::GlobalReferenceIterator)
/// before the real class is ported. Models only the accessor needed to resolve a module's
/// symbol records stream number.
pub trait PdbDebugInfo {
    fn get_symbol_records_stream_number(&self) -> i32;
}

/// Placeholders for the two `ghidra.app.util.bin.format.pdb2.pdbreader.msf.MsfStream` public
/// static constants, referenced by
/// [`GlobalReferenceIterator`](crate::format::pdb2::pdbreader::global_reference_iterator::GlobalReferenceIterator)
/// before the real class is ported.
pub const NIL_STREAM_NUMBER: i32 = 0xffff;
pub const MAX_STREAM_LENGTH: i32 = i32::MAX;

/// Placeholder for `ghidra.app.util.bin.format.pdb2.pdbreader.C11Lines`, referenced by
/// [`Module::line_information`](crate::format::pdb2::pdbreader::module::Module::line_information)
/// before the real class is ported. `Module` only ever passes this type opaquely (as
/// `Box<dyn C11LinesLike>`), so no members are needed yet.
pub trait C11LinesLike {}

/// Placeholder for `ghidra.app.util.bin.format.pdb2.pdbreader.C13Section`, referenced by
/// [`C13SectionIteratorLike`] before the real class is ported. `Module` only ever passes this
/// type opaquely (as `Box<dyn C13SectionLike>`), so no members are needed yet.
pub trait C13SectionLike {}

/// Placeholder for `ghidra.app.util.bin.format.pdb2.pdbreader.C13SectionIterator`, referenced by
/// [`Module::c13_section_iterator`](crate::format::pdb2::pdbreader::module::Module::c13_section_iterator)
/// before the real class is ported. Models only the `Iterator` surface (`hasNext`/`next`) that
/// `Module`'s callers need.
pub trait C13SectionIteratorLike {
    fn has_next(&self) -> bool;
    fn next(&mut self) -> Option<Box<dyn C13SectionLike>>;
}

/// Placeholder for `ghidra.app.util.bin.format.pe.NTHeader`, referenced by
/// [`PeMarkupable`](crate::format::pe::pe_markupable::PeMarkupable) before the real class
/// is ported. Models only the methods needed for PE markup operations.
/// The maximum sane count for symbols, from `NTHeader.MAX_SANE_COUNT`.
pub const NT_HEADER_MAX_SANE_COUNT: i32 = 0x10000;

/// Placeholder for `ghidra.app.util.bin.format.pe.NTHeader`, referenced by
/// [`DebugCOFFSymbolTable`](crate::format::pe::debug::debug_coff_symbol_table::DebugCOFFSymbolTable)
/// before the real class is ported. `NTHeader` is a concrete Java class (not an interface),
/// so it is modeled here as a trait object for now until the real port is available.
pub trait NTHeader: Send + Sync {
    fn get_name(&self) -> String;
    fn is_rva_resoltion_section_aligned(&self) -> bool;
    fn get_file_header(&self) -> Box<dyn FileHeader>;
    fn get_optional_header(&self) -> Box<dyn OptionalHeader>;
    fn to_data_type(&self) -> std::io::Result<Box<dyn crate::program::model::data::data_type::DataType>>;
    fn rva_to_pointer(&self, rva: i32) -> i32;
    /// Mirrors the `rvaToPointer(long)` overload (distinct from `rva_to_pointer` above, which
    /// mirrors `rvaToPointer(int)`); used by [`PEx64UnwindInfo::read_unwind_info`](crate::format::pe::pex64_unwind_info::PEx64UnwindInfo::read_unwind_info)
    /// to follow chained unwind info, where the offset is a Java `long`. Returns -1 if not valid.
    fn rva_to_pointer_long(&self, rva: i64) -> i64;
    fn check_pointer(&self, ptr: i64) -> bool;
    fn check_rva(&self, rva: i64) -> bool;
    fn va_to_pointer(&self, va: i32) -> i32;
}

/// Placeholder for `ghidra.app.util.bin.format.pe.FileHeader`, referenced by
/// [`NTHeader`] before the real class is ported.
pub trait FileHeader: Send + Sync {}

/// Placeholder for `ghidra.app.util.bin.format.pe.OptionalHeader`, referenced by
/// [`NTHeader`] before the real class is ported.
pub trait OptionalHeader: Send + Sync {}

/// Placeholder for `ghidra.app.util.importer.MessageLog`, referenced by
/// [`PeMarkupable`](crate::format::pe::pe_markupable::PeMarkupable) before the real class
/// is ported. Models only the methods needed for PE markup operations.
pub trait MessageLog: Send + Sync {
    fn copy_from(&self, log: &dyn MessageLog);
    fn append_msg(&self, message: &str);
    fn append_exception(&self, t: &dyn Throwable);
    fn error(&self, originator: &str, message: &str);
    fn has_messages(&self) -> bool;
    fn clear(&self);
    fn set_status(&self, status: &str);
    fn clear_status(&self);
    fn get_status(&self) -> String;
    fn to_string(&self) -> String;
    fn write(&self, owner: &dyn Class, message_header: &str);
}

/// Placeholder for Java `Throwable`, referenced by
/// [`MessageLog`] before the real class is ported.
pub trait Throwable: Send + Sync {}

/// Placeholder for Java `Class`, referenced by
/// [`MessageLog`] before the real class is ported.
pub trait Class: Send + Sync {}

/// Placeholder for `ghidra.app.util.bin.format.ne.SegmentRelocation`, referenced by
/// [`Segment`](crate::format::ne::segment::Segment) before the real class is ported.
/// `SegmentRelocation` is a concrete Java class (not an interface), so it is modeled here as a
/// concrete struct rather than a trait object. Models the reader-driven constructor and the
/// `offset` accessor that `Segment` needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegmentRelocation {
    segment: i32,
    r#type: i8,
    flagbyte: i8,
    offset: i16,
    target_segment: i16,
    target_offset: i16,
}

impl SegmentRelocation {
    pub fn new(
        reader: &mut dyn crate::app::util::bin::binary_reader::BinaryReader,
        segment: i32,
    ) -> std::io::Result<Self> {
        let r#type = reader.read_next_byte()? as i8;
        let flagbyte = reader.read_next_byte()? as i8;
        let offset = reader.read_next_short()?;
        let target_segment = reader.read_next_short()?;
        let target_offset = reader.read_next_short()?;

        Ok(SegmentRelocation {
            segment,
            r#type,
            flagbyte,
            offset,
            target_segment,
            target_offset,
        })
    }

    pub fn get_offset(&self) -> i16 {
        self.offset
    }
}

/// Placeholder for `ghidra.app.util.bin.format.ne.EntryPoint`, referenced by
/// [`EntryTableBundle`](crate::format::ne::entry_table_bundle::EntryTableBundle) before the real
/// class is ported. `EntryPoint` is a concrete Java class (not an interface), so it is modeled
/// here as a concrete struct rather than a trait object, consistent with [`SegmentRelocation`]
/// above. The Java constructor takes a back-reference to the owning `EntryTableBundle` solely to
/// query `isMoveable()`, which is fixed by the time any `EntryPoint` is constructed; this stub
/// takes that flag directly instead of an owning back-reference, avoiding an ownership cycle with
/// `EntryTableBundle`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntryPoint {
    flagword: i8,
    instruction: i16,
    segment: i8,
    offset: i16,
    is_moveable: bool,
}

impl EntryPoint {
    pub fn new(
        reader: &mut dyn crate::app::util::bin::binary_reader::BinaryReader,
        is_moveable: bool,
    ) -> std::io::Result<Self> {
        let flagword = reader.read_next_byte()? as i8;

        let mut instruction = 0i16;
        let mut segment = 0i8;
        if is_moveable {
            instruction = reader.read_next_short()?;
            segment = reader.read_next_byte()? as i8;
        }

        let offset = reader.read_next_short()?;

        Ok(EntryPoint {
            flagword,
            instruction,
            segment,
            offset,
            is_moveable,
        })
    }

    pub fn get_flagword(&self) -> i8 {
        self.flagword
    }

    /// # Panics
    /// Panics if this entry point is not moveable, mirroring the Java
    /// `RuntimeException("Entry point is not moveable!")`.
    pub fn get_instruction(&self) -> i16 {
        assert!(self.is_moveable, "Entry point is not moveable!");
        self.instruction
    }

    /// # Panics
    /// Panics if this entry point is not moveable, mirroring the Java
    /// `RuntimeException("Entry point is not moveable!")`.
    pub fn get_segment(&self) -> i8 {
        assert!(self.is_moveable, "Entry point is not moveable!");
        self.segment
    }

    pub fn get_offset(&self) -> i16 {
        self.offset
    }
}

/// Placeholder for `ghidra.app.util.bin.format.ne.Resource`, referenced by
/// [`ResourceType`] before the real class is ported. `Resource` is a concrete Java class (with
/// subclasses elsewhere in the tree, but none of them change how many bytes the constructor
/// consumes), so it is modeled here as a concrete struct rather than a trait object, consistent
/// with [`SegmentRelocation`] and [`EntryPoint`] above. The Java constructor takes a
/// back-reference to the owning `ResourceTable` solely to resolve the alignment shift count (for
/// `getFileOffsetShifted`/`getFileLengthShifted`); that value is already known by the time any
/// `Resource` is constructed, so this stub takes it directly instead of an owning back-reference,
/// avoiding an ownership cycle with `ResourceTable`. `getBytes`/`toString` additionally need the
/// owning table's resource names and reader, which aren't available yet at construction time and
/// aren't called by anything in the crate, so they're omitted here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Resource {
    file_offset: i16,
    file_length: i16,
    flagword: i16,
    resource_id: i16,
    handle: i16,
    usage: i16,
    alignment_shift_count: i16,
}

impl Resource {
    /// The resource is not fixed.
    pub const FLAG_MOVEABLE: i16 = 0x0010;
    /// The resource can be shared.
    pub const FLAG_PURE: i16 = 0x0020;
    /// The resource is preloaded.
    pub const FLAG_PRELOAD: i16 = 0x0040;

    pub fn new(
        reader: &mut dyn crate::app::util::bin::binary_reader::BinaryReader,
        alignment_shift_count: i16,
    ) -> std::io::Result<Self> {
        let file_offset = reader.read_next_short()?;
        let file_length = reader.read_next_short()?;
        let flagword = reader.read_next_short()?;
        let resource_id = reader.read_next_short()?;
        let handle = reader.read_next_short()?;
        let usage = reader.read_next_short()?;

        Ok(Resource {
            file_offset,
            file_length,
            flagword,
            resource_id,
            handle,
            usage,
            alignment_shift_count,
        })
    }

    pub fn get_file_offset(&self) -> i16 {
        self.file_offset
    }

    pub fn get_file_length(&self) -> i16 {
        self.file_length
    }

    pub fn get_flagword(&self) -> i16 {
        self.flagword
    }

    pub fn get_resource_id(&self) -> i16 {
        self.resource_id
    }

    pub fn get_handle(&self) -> i16 {
        self.handle
    }

    pub fn get_usage(&self) -> i16 {
        self.usage
    }

    pub fn is_moveable(&self) -> bool {
        (self.flagword & Self::FLAG_MOVEABLE) != 0
    }

    pub fn is_pure(&self) -> bool {
        (self.flagword & Self::FLAG_PURE) != 0
    }

    pub fn is_preload(&self) -> bool {
        (self.flagword & Self::FLAG_PRELOAD) != 0
    }

    /// `this.getFileOffset() << rt.getAlignmentShiftCount()`, both operands widened as unsigned
    /// 16-bit values before shifting, mirroring `Short.toUnsignedInt`.
    pub fn get_file_offset_shifted(&self) -> i32 {
        let shift = (self.alignment_shift_count as u16) as u32;
        ((self.file_offset as u16) as i32).wrapping_shl(shift)
    }

    /// `this.getFileLength() << rt.getAlignmentShiftCount()`, both operands widened as unsigned
    /// 16-bit values before shifting, mirroring `Short.toUnsignedInt`.
    pub fn get_file_length_shifted(&self) -> i32 {
        let shift = (self.alignment_shift_count as u16) as u32;
        ((self.file_length as u16) as i32).wrapping_shl(shift)
    }
}

/// Placeholder for `ghidra.app.util.bin.format.ne.ResourceType`, referenced by
/// [`ResourceTable`](crate::format::ne::resource_table::ResourceTable) before the real class is
/// ported. `ResourceType` is a concrete Java class (not an interface), so it is modeled here as a
/// concrete struct rather than a trait object, consistent with [`SegmentRelocation`] and
/// [`EntryPoint`] above. The Java constructor takes a back-reference to the owning
/// `ResourceTable` solely to forward it into each `Resource` it constructs; this stub takes the
/// alignment shift count directly instead (see [`Resource`] above), avoiding an ownership cycle
/// with `ResourceTable`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceType {
    type_id: i16,
    count: i16,
    reserved: i32,
    resources: Vec<Resource>,
}

impl ResourceType {
    //0x00 is not defined...?
    /// Constant indicating cursor resource type.
    pub const RT_CURSOR: i16 = 0x01;
    /// Constant indicating bitmap resource type.
    pub const RT_BITMAP: i16 = 0x02;
    /// Constant indicating icon resource type.
    pub const RT_ICON: i16 = 0x03;
    /// Constant indicating menu resource type.
    pub const RT_MENU: i16 = 0x04;
    /// Constant indicating dialog resource type.
    pub const RT_DIALOG: i16 = 0x05;
    /// Constant indicating string resource type.
    pub const RT_STRING: i16 = 0x06;
    /// Constant indicating font directory resource type.
    pub const RT_FONTDIR: i16 = 0x07;
    /// Constant indicating font resource type.
    pub const RT_FONT: i16 = 0x08;
    /// Constant indicating an accelerator resource type.
    pub const RT_ACCELERATOR: i16 = 0x09;
    /// Constant indicating RC data resource type.
    pub const RT_RCDATA: i16 = 0x0a;
    /// Constant indicating message table resource type.
    pub const RT_MESSAGETABLE: i16 = 0x0b;
    /// Constant indicating cursor group resource type.
    pub const RT_GROUP_CURSOR: i16 = 0x0c;
    //0x0d is not defined...?
    /// Constant indicating icon group resource type.
    pub const RT_GROUP_ICON: i16 = 0x0e;
    //0x0f is not defined...?
    /// Constant indicating version resource type.
    pub const RT_VERSION: i16 = 0x10;

    pub fn new(
        reader: &mut dyn crate::app::util::bin::binary_reader::BinaryReader,
        alignment_shift_count: i16,
    ) -> std::io::Result<Self> {
        let type_id = reader.read_next_short()?;
        if type_id == 0 {
            // not a valid resource type...
            return Ok(ResourceType {
                type_id,
                count: 0,
                reserved: 0,
                resources: Vec::new(),
            });
        }

        let count = reader.read_next_short()?;
        let reserved = reader.read_next_int()?;

        let count_int = (count as u16) as usize;
        let mut resources = Vec::with_capacity(count_int);
        for _ in 0..count_int {
            resources.push(Resource::new(reader, alignment_shift_count)?);
        }

        Ok(ResourceType {
            type_id,
            count,
            reserved,
            resources,
        })
    }

    pub fn get_type_id(&self) -> i16 {
        self.type_id
    }

    pub fn get_count(&self) -> i16 {
        self.count
    }

    pub fn get_reserved(&self) -> i32 {
        self.reserved
    }

    pub fn get_resources(&self) -> &[Resource] {
        &self.resources
    }
}

impl std::fmt::Display for ResourceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if (self.type_id & 0x8000u16 as i16) == 0 {
            return write!(f, "UnknownResourceType_{}", self.type_id);
        }
        let idx = self.type_id & 0x7fff;
        let name = match idx {
            Self::RT_CURSOR => "Cursor",
            Self::RT_BITMAP => "Bitmap",
            Self::RT_ICON => "Icon",
            Self::RT_MENU => "Menu",
            Self::RT_DIALOG => "Dialog Box",
            Self::RT_STRING => "String Table",
            Self::RT_FONTDIR => "Font Directory",
            Self::RT_FONT => "Font",
            Self::RT_ACCELERATOR => "Accelerator Table",
            Self::RT_RCDATA => "Resource Data",
            Self::RT_MESSAGETABLE => "Message Table",
            Self::RT_GROUP_CURSOR => "Cursor Directory",
            Self::RT_GROUP_ICON => "Icon Directory",
            Self::RT_VERSION => "Version Information",
            _ => return write!(f, "Unknown_{}", idx),
        };
        f.write_str(name)
    }
}

/// Placeholder for `ghidra.app.util.bin.format.ne.InformationBlock`, referenced by
/// [`WindowsHeader`](crate::format::ne::windows_header::WindowsHeader) before the real class is
/// ported. `InformationBlock` is a concrete Java class, so it is modeled as a concrete struct.
/// Only the constructor and the offset/count accessors `WindowsHeader`'s constructor needs to
/// locate the other NE tables are exposed; the many flag/display-string getters on the real class
/// are left for the real port.
pub struct InformationBlock {
    segment_table_offset: i16,
    segment_count: i16,
    segment_alignment_shift_count: i16,
    resource_table_offset: i16,
    resident_name_table_offset: i16,
    module_reference_table_offset: i16,
    module_reference_table_count: i16,
    imported_names_table_offset: i16,
    entry_table_offset: i16,
    entry_table_size: i16,
    non_resident_name_table_offset: i32,
    non_resident_name_table_size: i16,
}

impl InformationBlock {
    /// The magic number for Windows NE files ('NE'), mirroring
    /// `WindowsHeader.IMAGE_NE_SIGNATURE`.
    const IMAGE_NE_SIGNATURE: i16 = 0x454E;

    pub fn new(
        reader: &mut dyn crate::app::util::bin::binary_reader::BinaryReader,
        index: u64,
    ) -> std::io::Result<Self> {
        let old_index = reader.get_pointer_index();
        reader.set_pointer_index(index);

        let ne_magic = reader.read_next_short()?;
        if ne_magic != Self::IMAGE_NE_SIGNATURE {
            reader.set_pointer_index(old_index);
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                crate::format::ne::invalid_windows_header_exception::InvalidWindowsHeaderException::new(
                    "Not a valid Windows NE header",
                ),
            ));
        }

        let _ne_ver = reader.read_next_byte()?;
        let _ne_rev = reader.read_next_byte()?;
        let ne_enttab = reader.read_next_short()?;
        let ne_cbenttab = reader.read_next_short()?;
        let _ne_crc = reader.read_next_int()?;
        let _ne_flags_prog = reader.read_next_byte()?;
        let _ne_flags_app = reader.read_next_byte()?;
        let _ne_autodata = reader.read_next_short()?;
        let _ne_heap = reader.read_next_short()?;
        let _ne_stack = reader.read_next_short()?;
        let _ne_csip = reader.read_next_int()?;
        let _ne_sssp = reader.read_next_int()?;
        let ne_cseg = reader.read_next_short()?;
        let ne_cmod = reader.read_next_short()?;
        let ne_cbnrestab = reader.read_next_short()?;
        let ne_segtab = reader.read_next_short()?;
        let ne_rsrctab = reader.read_next_short()?;
        let ne_restab = reader.read_next_short()?;
        let ne_modtab = reader.read_next_short()?;
        let ne_imptab = reader.read_next_short()?;
        let ne_nrestab = reader.read_next_int()?;
        let _ne_cmovent = reader.read_next_short()?;
        let ne_align = reader.read_next_short()?;
        let _ne_cres = reader.read_next_short()?;
        let _ne_exetyp = reader.read_next_byte()?;
        let _ne_flagsothers = reader.read_next_byte()?;
        let _ne_pretthunks = reader.read_next_short()?;
        let _ne_psegrefbytes = reader.read_next_short()?;
        let _ne_swaparea = reader.read_next_short()?;
        let _ne_expver = reader.read_next_short()?;

        reader.set_pointer_index(old_index);

        Ok(InformationBlock {
            segment_table_offset: ne_segtab,
            segment_count: ne_cseg,
            segment_alignment_shift_count: ne_align,
            resource_table_offset: ne_rsrctab,
            resident_name_table_offset: ne_restab,
            module_reference_table_offset: ne_modtab,
            module_reference_table_count: ne_cmod,
            imported_names_table_offset: ne_imptab,
            entry_table_offset: ne_enttab,
            entry_table_size: ne_cbenttab,
            non_resident_name_table_offset: ne_nrestab,
            non_resident_name_table_size: ne_cbnrestab,
        })
    }

    /// Index to the start of the segment table, relative to the beginning of the NE header.
    pub fn get_segment_table_offset(&self) -> i16 {
        self.segment_table_offset
    }

    /// Number of segments in the segment table.
    pub fn get_segment_count(&self) -> i16 {
        self.segment_count
    }

    /// Shift count used to align the logical sector.
    pub fn get_segment_alignment_shift_count(&self) -> i16 {
        self.segment_alignment_shift_count
    }

    /// Index to the start of the resource table, relative to the beginning of the NE header.
    pub fn get_resource_table_offset(&self) -> i16 {
        self.resource_table_offset
    }

    /// Index to the start of the resident name table, relative to the beginning of the NE
    /// header.
    pub fn get_resident_name_table_offset(&self) -> i16 {
        self.resident_name_table_offset
    }

    /// Index to the start of the module reference table, relative to the beginning of the NE
    /// header.
    pub fn get_module_reference_table_offset(&self) -> i16 {
        self.module_reference_table_offset
    }

    /// Number of entries in the module reference table.
    pub fn get_module_reference_table_count(&self) -> i16 {
        self.module_reference_table_count
    }

    /// Index to the start of the imported names table, relative to the beginning of the NE
    /// header.
    pub fn get_imported_names_table_offset(&self) -> i16 {
        self.imported_names_table_offset
    }

    /// Index to the start of the entry table, relative to the beginning of the NE header.
    pub fn get_entry_table_offset(&self) -> i16 {
        self.entry_table_offset
    }

    /// Number of bytes in the entry table.
    pub fn get_entry_table_size(&self) -> i16 {
        self.entry_table_size
    }

    /// Index to the start of the non-resident name table, relative to the beginning of the file.
    pub fn get_non_resident_name_table_offset(&self) -> i32 {
        self.non_resident_name_table_offset
    }

    /// Number of bytes in the non-resident name table.
    pub fn get_non_resident_name_table_size(&self) -> i16 {
        self.non_resident_name_table_size
    }
}

/// Placeholder for `ghidra.app.util.bin.format.ne.SegmentTable`, referenced by
/// [`WindowsHeader`](crate::format::ne::windows_header::WindowsHeader) before the real class is
/// ported. `SegmentTable` is a concrete Java class, so it is modeled as a concrete struct wrapping
/// the already-ported [`Segment`](crate::format::ne::segment::Segment). The real class also
/// consults a `SegmentedAddressSpace` to assign each segment's starting address segment number
/// when `baseAddr` is non-null; that address-space bookkeeping is left for the real port, so this
/// stub always assigns sequential segment numbers starting from `base_addr`'s segment (or 0).
pub struct SegmentTable {
    segments: Vec<crate::format::ne::segment::Segment>,
}

impl SegmentTable {
    pub fn new(
        reader: &mut dyn crate::app::util::bin::binary_reader::BinaryReader,
        base_addr: Option<&crate::program::model::address::segmented_address::SegmentedAddress>,
        index: u64,
        segment_count: i16,
        shift_align_count: i16,
    ) -> std::io::Result<Self> {
        let old_index = reader.get_pointer_index();
        reader.set_pointer_index(index);

        let shift_align_value = (1i32 << (shift_align_count as u32)) as i16;
        let segment_count_usize = (segment_count as u16) as usize;
        let mut cur_segment = base_addr.map(|addr| addr.segment() as i32).unwrap_or(0);

        let mut segments = Vec::with_capacity(segment_count_usize);
        for _ in 0..segment_count_usize {
            segments.push(crate::format::ne::segment::Segment::new(
                reader,
                shift_align_value,
                cur_segment,
            )?);
            cur_segment += 1;
        }

        reader.set_pointer_index(old_index);

        Ok(SegmentTable { segments })
    }

    /// Returns the segments defined in this segment table.
    pub fn get_segments(&self) -> &[crate::format::ne::segment::Segment] {
        &self.segments
    }
}

/// Placeholder for `ghidra.app.util.bin.format.ne.EntryTable`, referenced by
/// [`WindowsHeader`](crate::format::ne::windows_header::WindowsHeader) before the real class is
/// ported. `EntryTable` is a concrete Java class, so it is modeled as a concrete struct wrapping
/// the already-ported
/// [`EntryTableBundle`](crate::format::ne::entry_table_bundle::EntryTableBundle).
pub struct EntryTable {
    bundles: Vec<crate::format::ne::entry_table_bundle::EntryTableBundle>,
}

impl EntryTable {
    pub fn new(
        reader: &mut dyn crate::app::util::bin::binary_reader::BinaryReader,
        index: u64,
        _byte_count: i16,
    ) -> std::io::Result<Self> {
        let old_index = reader.get_pointer_index();
        reader.set_pointer_index(index);

        let mut bundles = Vec::new();
        loop {
            let bundle = crate::format::ne::entry_table_bundle::EntryTableBundle::new(reader)?;
            if bundle.get_count() == 0 {
                break;
            }
            bundles.push(bundle);
        }

        reader.set_pointer_index(old_index);

        Ok(EntryTable { bundles })
    }

    /// Returns the entry table bundles in this entry table.
    pub fn get_bundles(&self) -> &[crate::format::ne::entry_table_bundle::EntryTableBundle] {
        &self.bundles
    }
}

/// Placeholder for `ghidra.app.util.bin.format.pe.rich.RichProduct`, referenced by
/// [`CompId::product_description`](crate::format::pe::rich::comp_id::CompId::product_description)
/// before the real class is ported.
pub trait RichProduct: Send + Sync {
    fn get_product_version(&self) -> String;
    fn get_product_type(&self) -> MsProductType;
    fn to_string(&self) -> String;
}

/// Placeholder for `ghidra.app.util.bin.format.pe.rich.RichHeaderUtils`, referenced by
/// [`CompId::product_description`](crate::format::pe::rich::comp_id::CompId::product_description)
/// before the real class is ported. `RichHeaderUtils` is a concrete Java class (not an
/// interface), so it is modeled here as a trait that returns the product information.
pub trait RichHeaderUtils: Send + Sync {
    fn get_product(&self, id: i32) -> Option<Box<dyn RichProduct>>;
}

/// Placeholder for `ghidra.app.util.bin.format.pe.rich.RichHeaderRecord`, referenced by
/// [`RichTable`](crate::format::pe::rich_table::RichTable) before the real class is ported.
/// `RichHeaderRecord` is a concrete Java class (not an interface), so it is modeled here as a
/// concrete struct wrapping the already-ported
/// [`CompId`](crate::format::pe::rich::comp_id::CompId), consistent with the other concrete-class
/// stubs above.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RichHeaderRecord {
    record_index: i32,
    comp_id: crate::format::pe::rich::comp_id::CompId,
    count: i32,
}

impl RichHeaderRecord {
    pub fn new(record_index: i32, compid: i32, count: i32) -> Self {
        RichHeaderRecord {
            record_index,
            comp_id: crate::format::pe::rich::comp_id::CompId::new(compid),
            count,
        }
    }

    pub fn get_index(&self) -> i32 {
        self.record_index
    }

    pub fn get_comp_id(&self) -> crate::format::pe::rich::comp_id::CompId {
        self.comp_id
    }

    pub fn get_object_count(&self) -> i32 {
        self.count
    }
}

impl std::fmt::Display for RichHeaderRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:x} Count: {}", self.comp_id.value(), self.count)
    }
}

/// Placeholder for `ghidra.app.util.bin.format.pe.rich.PERichTableDataType`, referenced by
/// [`RichTable::to_data_type`](crate::format::pe::rich_table::RichTable::to_data_type) before the
/// real class is ported. `PERichTableDataType` is a concrete Java class (not an interface), so it
/// is modeled here as a concrete struct. `RichTable` only ever constructs and returns this type
/// opaquely, so no members are needed yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PERichTableDataType;

impl PERichTableDataType {
    pub fn new() -> Self {
        PERichTableDataType
    }
}

impl crate::program::model::data::data_type::DataType for PERichTableDataType {}

/// Placeholder for `ghidra.app.util.bin.format.pe.PEx64UnwindInfoDataType`, referenced by
/// [`PEx64UnwindInfo::to_data_type`](crate::format::pe::pex64_unwind_info::PEx64UnwindInfo)
/// before the real (`DynamicDataType`-derived) class is ported. `PEx64UnwindInfoDataType` is a
/// concrete Java class (not an interface), so it is modeled here as a concrete struct.
/// `PEx64UnwindInfo` only ever returns the shared `INSTANCE` opaquely, so no members are needed
/// yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PEx64UnwindInfoDataType;

impl PEx64UnwindInfoDataType {
    /// Mirrors the Java `PEx64UnwindInfoDataType.INSTANCE` static field.
    pub fn instance() -> Self {
        PEx64UnwindInfoDataType
    }
}

impl crate::program::model::data::data_type::DataType for PEx64UnwindInfoDataType {}

/// Placeholder for the nested record `ImageRuntimeFunctionEntries_X86.ImageRuntimeFunctionEntry_X86`,
/// referenced by [`PEx64UnwindInfo::read_unwind_info`](crate::format::pe::pex64_unwind_info::PEx64UnwindInfo::read_unwind_info)
/// when following a chained `UNWIND_INFO`. `ImageRuntimeFunctionEntries_X86` (the enclosing class)
/// is a concrete Java class, so this nested record is modeled here as a concrete struct with only
/// the fields `PEx64UnwindInfo` constructs; `markup`/`to_data_type` will be added when
/// `ImageRuntimeFunctionEntries_X86` itself is ported.
#[derive(Debug, Clone)]
pub struct ImageRuntimeFunctionEntryX86 {
    pub begin_address: u64,
    pub end_address: u64,
    pub unwind_info_address_or_data: u64,
    pub unwind_info: Option<Box<crate::format::pe::pex64_unwind_info::PEx64UnwindInfo>>,
}

impl ImageRuntimeFunctionEntryX86 {
    pub fn new(
        begin_address: u64,
        end_address: u64,
        unwind_info_address_or_data: u64,
        unwind_info: crate::format::pe::pex64_unwind_info::PEx64UnwindInfo,
    ) -> Self {
        ImageRuntimeFunctionEntryX86 {
            begin_address,
            end_address,
            unwind_info_address_or_data,
            unwind_info: Some(Box::new(unwind_info)),
        }
    }
}

/// Placeholder for the unported Java type `PdbInfoCodeView`, referenced by `PdbInfo`.
/// Only defines the instance methods needed by PdbInfo. The static factory methods
/// (is_match, read) will be part of the concrete implementation.
pub trait PdbInfoCodeView: Send + Sync {
    fn is_valid(&self) -> bool;
    fn serialize_to_options(&self, options: &dyn crate::framework::options::options::Options);
    fn to_data_type(&self) -> Box<dyn crate::program::model::data::data_type::DataType>;
}

/// Placeholder for the unported Java type `PdbInfoDotNet`, referenced by `PdbInfo`.
/// Only defines the instance methods needed by PdbInfo. The static factory methods
/// (is_match, read) will be part of the concrete implementation.
pub trait PdbInfoDotNet: Send + Sync {
    fn is_valid(&self) -> bool;
    fn serialize_to_options(&self, options: &dyn crate::framework::options::options::Options);
    fn to_data_type(&self) -> Box<dyn crate::program::model::data::data_type::DataType>;
}

/// Placeholder for `ghidra.app.util.bin.MemoryByteProvider`, referenced by
/// [`read_item_from_block`](crate::format::elf::info::elf_info_item::read_item_from_block) before
/// the real class is ported. Only `createMemoryBlockByteProvider` and the `getName`/`getMemory`
/// accessors that `ElfInfoItem` needs are modeled; unlike the auto-generated stub shape, this is
/// backed by the crate's real [`ByteProvider`](crate::filesystem::ghidra::g_binary_reader::ByteProvider)
/// trait (rather than a disconnected placeholder trait) so it can actually back a `BinaryReader`.
pub struct MemoryByteProvider {
    memory: std::sync::Arc<dyn crate::program::model::mem::Memory>,
    block_name: String,
    start: crate::program::model::address::Address,
    length: u64,
}

impl MemoryByteProvider {
    /// Mirrors `MemoryByteProvider.createMemoryBlockByteProvider(Memory, MemoryBlock)`.
    pub fn create_memory_block_byte_provider(
        memory: std::sync::Arc<dyn crate::program::model::mem::Memory>,
        block: &dyn crate::program::model::mem::MemoryBlock,
    ) -> Self {
        MemoryByteProvider {
            memory,
            block_name: block.get_name().to_string(),
            start: block.get_start(),
            length: block.get_size(),
        }
    }

    /// Mirrors `new MemoryByteProvider(Memory, AddressSpace)`, referenced by
    /// [`ClassFileAnalysisState::new`](crate::format::javaclass::class_file_analysis_state::ClassFileAnalysisState::new)
    /// before the real class is ported. Bytes are relative to the space's minimum address, and
    /// the provider extends to the highest address of any memory block in the same address space
    /// (mirroring the private `findAddressSpaceMax` helper); if no block occupies the space, the
    /// provider is empty.
    pub fn new(
        memory: std::sync::Arc<dyn crate::program::model::mem::Memory>,
        space: &std::sync::Arc<crate::program::model::address::AddressSpace>,
    ) -> Self {
        let base_address = space.min_address();
        let max_address = Self::find_address_space_max(memory.as_ref(), &base_address);
        let length = match &max_address {
            Some(max) => (max.subtract(&base_address).max(0) as u64).saturating_add(1),
            None => 0,
        };
        MemoryByteProvider {
            memory,
            block_name: space.name().to_string(),
            start: base_address,
            length,
        }
    }

    /// Mirrors the private `MemoryByteProvider.findAddressSpaceMax(Memory, Address)` helper:
    /// the highest end address, among this memory's blocks that share `min_addr`'s address space
    /// and end at or after it, or `None` if no such block exists.
    fn find_address_space_max(
        memory: &dyn crate::program::model::mem::Memory,
        min_addr: &crate::program::model::address::Address,
    ) -> Option<crate::program::model::address::Address> {
        let mut max_addr: Option<crate::program::model::address::Address> = None;
        for block in memory.get_blocks() {
            let end = block.get_end();
            if !end.same_address_space(min_addr) || end < *min_addr {
                continue;
            }
            if max_addr.as_ref().is_none_or(|current| end >= *current) {
                max_addr = Some(end);
            }
        }
        max_addr
    }

    pub fn get_name(&self) -> &str {
        &self.block_name
    }

    pub fn get_memory(&self) -> &std::sync::Arc<dyn crate::program::model::mem::Memory> {
        &self.memory
    }
}

impl crate::filesystem::ghidra::g_binary_reader::ByteProvider for MemoryByteProvider {
    fn length(&mut self) -> std::io::Result<u64> {
        Ok(self.length)
    }

    fn is_valid_index(&mut self, index: u64) -> bool {
        index < self.length
    }

    fn read_byte(&mut self, index: u64) -> std::io::Result<u8> {
        if index >= self.length {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                format!("Index {index} out of bounds for section '{}'", self.block_name),
            ));
        }
        let addr = self
            .start
            .add(index as i64)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        self.memory
            .get_byte(&addr)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
    }

    fn read_bytes(&mut self, index: u64, length: usize) -> std::io::Result<Vec<u8>> {
        let end = index
            .checked_add(length as u64)
            .filter(|&end| end <= self.length);
        if end.is_none() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                format!(
                    "Range [{index}, {index}+{length}) out of bounds for section '{}'",
                    self.block_name
                ),
            ));
        }
        let addr = self
            .start
            .add(index as i64)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        let mut buf = vec![0u8; length];
        let n_read = self.memory.get_bytes(&addr, &mut buf);
        if n_read != length {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                format!("Short read at index {index} in section '{}'", self.block_name),
            ));
        }
        Ok(buf)
    }

    fn write_byte(&mut self, _index: u64, _value: u8) -> std::io::Result<()> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "MemoryByteProvider does not support writes",
        ))
    }

    fn write_bytes(&mut self, _index: u64, _values: &[u8]) -> std::io::Result<()> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "MemoryByteProvider does not support writes",
        ))
    }
}

/// Placeholder for `ghidra.app.util.bin.format.elf.ElfSectionHeader`, referenced by
/// [`ElfSymbol::parse`](crate::format::elf::elf_symbol::ElfSymbol::parse) and by
/// [`ElfLoadAdapter`](crate::format::elf::extend::elf_load_adapter::ElfLoadAdapter) before the real
/// class is ported. Only the accessors those two need.
pub trait ElfSectionHeader: Send + Sync {
    fn get_name_as_string(&self) -> String;

    /// `ElfSectionHeader.getElfHeader()` -- the header this section belongs to.
    fn get_elf_header(&self) -> std::sync::Arc<dyn ElfHeader>;

    /// `ElfSectionHeader.getAddress()` -- `sh_addr`, the address of the section in memory, or 0
    /// if the section is not loaded.
    fn get_address(&self) -> i64;

    /// `ElfSectionHeader.getFlags()` -- the `sh_flags` bit set (`SHF_*`).
    fn get_flags(&self) -> i64;

    /// `ElfSectionHeader.getLogicalSize()` -- the uncompressed size of the section's data, which
    /// differs from `sh_size` only for a `SHF_COMPRESSED` section.
    fn get_logical_size(&self) -> i64;

    /// `ElfSectionHeader.isExecutable()`, whose Java body is exactly this flag test.
    fn is_executable(&self) -> bool {
        (self.get_flags() & crate::format::elf::elf_section_header_constants::SHF_EXECINSTR as i64)
            != 0
    }
}

/// Placeholder for `ghidra.app.util.bin.format.elf.ElfProgramHeader`, referenced by
/// [`ElfLoadAdapter`](crate::format::elf::extend::elf_load_adapter::ElfLoadAdapter) before the real
/// class is ported. Only the segment members the load adapter reads.
pub trait ElfProgramHeader: Send + Sync {
    /// `ElfProgramHeader.getFlags()` -- the `p_flags` bit set (`PF_*`).
    fn get_flags(&self) -> i32;

    /// `ElfProgramHeader.getVirtualAddress()` -- `p_vaddr`, as an addressable word offset.
    fn get_virtual_address(&self) -> i64;

    /// `ElfProgramHeader.getFileSize()` -- `p_filesz`, the number of bytes backing this segment
    /// in the file.
    fn get_file_size(&self) -> i64;

    /// `ElfProgramHeader.getMemorySize()` -- `p_memsz`, the segment's size in memory.
    fn get_memory_size(&self) -> i64;

    /// `ElfProgramHeader.isExecute()`, whose Java body is exactly this flag test.
    fn is_execute(&self) -> bool {
        (self.get_flags() & crate::format::elf::elf_program_header_constants::PF_X as i32) != 0
    }
}

/// Placeholder for `ghidra.app.util.bin.format.elf.ElfHeader`, referenced by
/// [`ElfSymbol::parse`](crate::format::elf::elf_symbol::ElfSymbol::parse),
/// [`ElfLoadAdapter`](crate::format::elf::extend::elf_load_adapter::ElfLoadAdapter), and
/// [`elf_loader_options_factory`](crate::app::util::opinion::elf_loader_options_factory) before
/// the real class is ported: the 32/64-bit discriminator that selects the `Elf32_Sym`/`Elf64_Sym`
/// field order, the section list used to name a `STT_SECTION` symbol, the `e_type` predicate the
/// load adapter needs, and the image-base fields `elf_loader_options_factory` reads.
pub trait ElfHeader: Send + Sync {
    fn is32_bit(&self) -> bool;

    /// `ElfHeader.is64Bit()`. `EI_CLASS` admits only the two widths, so this is the negation of
    /// [`is32_bit`](Self::is32_bit).
    fn is64_bit(&self) -> bool {
        !self.is32_bit()
    }

    /// `ElfHeader.isRelocatable()` -- true for an `ET_REL` object file.
    fn is_relocatable(&self) -> bool;

    /// `ElfHeader.isSharedObject()` -- true for an `ET_DYN` shared object. Defaults to `false`
    /// so the pre-existing mock implementors elsewhere (none of which exercise this predicate)
    /// keep compiling unchanged.
    fn is_shared_object(&self) -> bool {
        false
    }

    /// `ElfHeader.findImageBase()` -- the image base recorded/derived from the file, or `0` if
    /// none could be determined. Defaults to `0`, matching "no image base found", for the same
    /// reason as [`is_shared_object`](Self::is_shared_object).
    fn find_image_base(&self) -> i64 {
        0
    }

    /// `ElfHeader.getImageBase()` -- the image base as currently set on this header. Defaults to
    /// `0` for the same reason as [`is_shared_object`](Self::is_shared_object).
    fn get_image_base(&self) -> i64 {
        0
    }

    fn get_sections(&self) -> Vec<Box<dyn ElfSectionHeader>>;

    /// `ElfHeader.isBigEndian()`, needed by
    /// [`ElfLoader::find_supported_load_specs`](crate::app::util::opinion::elf_loader::ElfLoader::find_supported_load_specs).
    /// Defaults to `false`, matching the other endian/width predicates' "not exercised by
    /// pre-existing mock implementors" default (see [`is_shared_object`](Self::is_shared_object)).
    fn is_big_endian(&self) -> bool {
        false
    }

    /// `ElfHeader.isLittleEndian()`, needed by the same caller as
    /// [`is_big_endian`](Self::is_big_endian). Unlike Java's independent field check, this
    /// defaults to the negation of [`is_big_endian`](Self::is_big_endian) (mirroring
    /// [`is64_bit`](Self::is64_bit)'s derivation from [`is32_bit`](Self::is32_bit)) so a stub
    /// implementor only needs to override one of the pair.
    fn is_little_endian(&self) -> bool {
        !self.is_big_endian()
    }

    /// `ElfHeader.getMachineName()`, needed by
    /// [`ElfLoader::find_supported_load_specs`](crate::app::util::opinion::elf_loader::ElfLoader::find_supported_load_specs).
    /// Defaults to the empty string for the same "not exercised by pre-existing mock
    /// implementors" reason as [`is_shared_object`](Self::is_shared_object).
    fn get_machine_name(&self) -> String {
        String::new()
    }

    /// `ElfHeader.getFlags()` -- a string rendering of the numeric `e_flags` field, needed by the
    /// same caller as [`get_machine_name`](Self::get_machine_name). Defaults to the empty string
    /// for the same reason.
    fn get_flags(&self) -> String {
        String::new()
    }

    /// `ElfHeader.parseSectionHeaders()`, needed by
    /// [`ElfLoader`](crate::app::util::opinion::elf_loader::ElfLoader)'s Golang-section
    /// detection. Java re-parses (idempotently; the header already parses its sections during
    /// construction) and can fail with an `IOException`; this stub holds nothing to (re-)parse,
    /// so the default is a no-op success.
    fn parse_section_headers(&self) -> std::io::Result<()> {
        Ok(())
    }

    /// Placeholder for `ElfHeader.getLoadAdapter()`, needed by
    /// [`ElfRelocationContextBase::get_load_adapter`](crate::format::elf::relocation::elf_relocation_context::ElfRelocationContextBase::get_load_adapter).
    ///
    /// Java never returns null here (an unrecognized machine still gets the default adapter), but
    /// this stub has no adapter registry to fall back on, so the default answers `None`.
    fn get_load_adapter(
        &self,
    ) -> Option<crate::format::elf::extend::elf_load_adapter::ElfLoadAdapter> {
        None
    }

    /// `ElfHeader.getDynamicType(int)` -- looks up the enum-like dynamic type for a `d_tag`
    /// value, needed by
    /// [`ElfDynamic::get_tag_type`](crate::format::elf::elf_dynamic::ElfDynamic::get_tag_type).
    /// Java returns `null` when the type map hasn't been built yet or the tag is unrecognized;
    /// the stub has no type registry, so the default always answers `None`.
    fn get_dynamic_type(&self, _type_: i32) -> Option<Box<dyn ElfDynamicType>> {
        None
    }
}

/// Placeholder for `ghidra.app.util.bin.format.elf.ElfDynamicType`, referenced by
/// [`ElfLoadAdapter::add_dynamic_types`](crate::format::elf::extend::elf_load_adapter::ElfLoadAdapter::add_dynamic_types)
/// and by
/// [`ElfDynamic`](crate::format::elf::elf_dynamic::ElfDynamic) before the real class is ported.
/// `value`/`name` stand in for the Java class's public `final` fields of the same name.
pub trait ElfDynamicType: Send + Sync {
    /// `ElfDynamicType.value` -- the `d_tag` value this type represents.
    fn value(&self) -> i32;

    /// `ElfDynamicType.name` -- the type's symbolic name, e.g. `"DT_SYMTAB"`.
    fn name(&self) -> String;
}

/// Placeholder for `ghidra.app.util.bin.format.elf.ElfProgramHeaderType`, referenced by
/// [`ElfLoadAdapter::add_program_header_types`](crate::format::elf::extend::elf_load_adapter::ElfLoadAdapter::add_program_header_types)
/// before the real class is ported. Only used as the value type of the extension type map.
pub trait ElfProgramHeaderType: Send + Sync {}

/// Placeholder for `ghidra.app.util.bin.format.elf.ElfSectionHeaderType`, referenced by
/// [`ElfLoadAdapter::add_section_header_types`](crate::format::elf::extend::elf_load_adapter::ElfLoadAdapter::add_section_header_types)
/// before the real class is ported. Only used as the value type of the extension type map.
pub trait ElfSectionHeaderType: Send + Sync {}

/// Placeholder for `ghidra.app.util.bin.format.elf.ElfDefaultGotPltMarkup`, referenced by
/// [`ElfLoadAdapter::process_got_plt`](crate::format::elf::extend::elf_load_adapter::ElfLoadAdapter::process_got_plt)
/// before the real class is ported.
///
/// Unlike the other stubs in this file this one is a struct rather than a trait, because the load
/// adapter *constructs* it (`new ElfDefaultGotPltMarkup(elfLoadHelper)`) rather than receiving
/// one. The real class walks the dynamic table and marks up the GOT/PLT; the placeholder retains
/// nothing and does nothing, so the default `processGotPlt` is currently a no-op rather than
/// producing fabricated markup.
pub struct ElfDefaultGotPltMarkup;

impl ElfDefaultGotPltMarkup {
    /// `new ElfDefaultGotPltMarkup(ElfLoadHelper)`. The real class retains the helper; this
    /// placeholder performs no markup and so stores nothing.
    pub fn new(elf_load_helper: &dyn ElfLoadHelper) -> Self {
        let _ = elf_load_helper;
        ElfDefaultGotPltMarkup
    }

    /// `ElfDefaultGotPltMarkup.process(TaskMonitor)`. Answers the monitor's cancellation state --
    /// the one part of the real behaviour that can be honoured without the markup itself.
    pub fn process(
        &self,
        monitor: &dyn crate::util::task::TaskMonitor,
    ) -> Result<(), crate::util::exception::CancelledException> {
        monitor.check_cancelled()
    }
}

/// Placeholder for `ghidra.app.util.bin.format.elf.ElfStringTable`, referenced by
/// [`ElfSymbol::init_symbol_name`](crate::format::elf::elf_symbol::ElfSymbol::init_symbol_name)
/// before the real class is ported.
pub trait ElfStringTable: Send + Sync {
    fn read_string(
        &self,
        reader: &dyn crate::app::util::bin::binary_reader::BinaryReader,
        string_offset: i64,
    ) -> String;
}

/// Placeholder for `ghidra.app.util.bin.format.elf.ElfSymbolTable`, referenced by
/// [`ElfSymbol::get_extended_section_header_index`](crate::format::elf::elf_symbol::ElfSymbol::get_extended_section_header_index)
/// before the real class is ported. Only the `SHT_SYMTAB_SHNDX` lookup that resolves an
/// `SHN_XINDEX` section index.
pub trait ElfSymbolTable: Send + Sync {
    fn get_extended_section_index(
        &self,
        sym: &crate::format::elf::elf_symbol::ElfSymbol,
    ) -> i32;

    /// Placeholder for `ElfSymbolTable.getSymbol(int)`, needed by
    /// [`ElfRelocationContextBase::get_symbol`](crate::format::elf::relocation::elf_relocation_context::ElfRelocationContextBase::get_symbol).
    /// `None` stands in for Java's `null` return on an out-of-range index.
    fn get_symbol(&self, symbol_index: i32) -> Option<crate::format::elf::elf_symbol::ElfSymbol> {
        let _ = symbol_index;
        None
    }

    /// Placeholder for `ElfSymbolTable.getSymbolName(int)`, needed by
    /// [`ElfRelocationContextBase::get_symbol_name`](crate::format::elf::relocation::elf_relocation_context::ElfRelocationContextBase::get_symbol_name).
    /// `None` stands in for Java's `null` return on an out-of-range index.
    fn get_symbol_name(&self, symbol_index: i32) -> Option<String> {
        let _ = symbol_index;
        None
    }
}

/// Placeholder for `ghidra.app.util.bin.format.elf.ElfRelocation`, referenced by
/// [`ElfRelocationContext::process_relocation`](crate::format::elf::relocation::elf_relocation_context::ElfRelocationContext::process_relocation)
/// and by [`RiscvElfRelocationContext::get_hi20_relocation`](crate::format::elf::relocation::riscv_elf_relocation_context::RiscvElfRelocationContext::get_hi20_relocation)
/// before the real class is ported.
pub trait ElfRelocation: Send + Sync {
    /// `ElfRelocation.getSymbolIndex()` -- the symbol table index encoded in `r_info`.
    fn get_symbol_index(&self) -> i32;

    /// `ElfRelocation.getType()` -- the relocation type ID encoded in `r_info`.
    fn get_type(&self) -> i32;

    /// `ElfRelocation.getOffset()` -- the relocation's target offset (`r_offset`).
    fn get_offset(&self) -> i64 {
        0
    }

    /// `ElfRelocation.getRelocationIndex()` -- this relocation's index within its table, needed by
    /// [`MipsElfRelocationContext::next_relocation_has_same_offset`](crate::format::elf::relocation::mips_elf_relocation_context::MipsElfRelocationContext::next_relocation_has_same_offset).
    /// The default answers `-1` ("index unknown"), which that lookup already treats as "there is
    /// no next relocation".
    fn get_relocation_index(&self) -> i32 {
        -1
    }

    /// `MIPS_Elf64Relocation.getSpecialSymbolIndex()` -- the `r_ssym` field of the modified ELF-64
    /// relocation entry MIPS uses, read by the second slot of a packed MIPS-64 relocation.
    ///
    /// Java declares this on the `MIPS_Elf64Relocation` subclass and reaches it by downcasting the
    /// `ElfRelocation` the context was handed. Rust trait objects cannot be downcast, and the
    /// relocation arrives through [`ElfRelocationContext::process_relocation_for_symbol`](crate::format::elf::relocation::elf_relocation_context::ElfRelocationContext::process_relocation_for_symbol)
    /// as a `&dyn ElfRelocation`, so the accessor is declared here instead. The default answers
    /// `0`, the value a non-MIPS-64 entry has no `r_ssym` for.
    fn get_special_symbol_index(&self) -> i32 {
        0
    }
}

/// Placeholder for `ghidra.app.util.bin.format.elf.ElfRelocationTable`, referenced by
/// [`ElfRelocationContext::start_relocation_table_processing`](crate::format::elf::relocation::elf_relocation_context::ElfRelocationContext::start_relocation_table_processing)
/// and by [`RiscvElfRelocationContext::get_hi20_relocation`](crate::format::elf::relocation::riscv_elf_relocation_context::RiscvElfRelocationContext::get_hi20_relocation)
/// before the real class is ported.
pub trait ElfRelocationTable: Send + Sync {
    /// `ElfRelocationTable.hasAddendRelocations()` -- true for `RELA`-style tables, whose entries
    /// carry their own addend.
    fn has_addend_relocations(&self) -> bool;

    /// `ElfRelocationTable.getAssociatedSymbolTable()`, which is `null` (here `None`) when the
    /// table has no associated symbol table.
    fn get_associated_symbol_table(&self) -> Option<std::sync::Arc<dyn ElfSymbolTable>>;

    /// `ElfRelocationTable.getRelocations()` -- every relocation entry, in file order.
    fn get_relocations(&self) -> Vec<Box<dyn ElfRelocation>> {
        Vec::new()
    }

    /// `ElfRelocationTable.getSectionToBeRelocated()` -- the section these relocations apply to,
    /// which is `null` (here `None`) for a dynamic relocation table. Needed by
    /// [`MipsElfRelocationContext`](crate::format::elf::relocation::mips_elf_relocation_context::MipsElfRelocationContext),
    /// which names its fabricated GOT block after it.
    fn get_section_to_be_relocated(&self) -> Option<std::sync::Arc<dyn ElfSectionHeader>> {
        None
    }
}

/// Placeholder for `ghidra.app.util.bin.format.elf.relocation.ElfRelocationHandler`, referenced by
/// [`ElfRelocationContext`](crate::format::elf::relocation::elf_relocation_context::ElfRelocationContext)
/// before the abstract handler and its ~20 architecture-specific subclasses are ported. Only the
/// members the relocation context dispatches to.
pub trait ElfRelocationHandler: Send + Sync {
    /// `ElfRelocationHandler.getRelrRelocationType()`; 0 means RELR is unsupported.
    fn get_relr_relocation_type(&self) -> i32 {
        0
    }

    /// `ElfRelocationHandler.createRelocationContext(...)`, which returns `null` (here `None`)
    /// unless the handler defines a custom context.
    fn create_relocation_context(
        &self,
        load_helper: std::sync::Arc<dyn ElfLoadHelper>,
        symbol_map: std::sync::Arc<
            std::collections::HashMap<
                crate::format::elf::elf_symbol::ElfSymbol,
                crate::program::model::address::Address,
            >,
        >,
    ) -> Option<
        Box<dyn crate::format::elf::relocation::elf_relocation_context::ElfRelocationContext>,
    > {
        let _ = (load_helper, symbol_map);
        None
    }

    /// `ElfRelocationHandler.relocate(...)` -- the architecture-specific fixup.
    fn relocate(
        &self,
        context: &dyn crate::format::elf::relocation::elf_relocation_context::ElfRelocationContext,
        relocation: &dyn ElfRelocation,
        relocation_address: &crate::program::model::address::Address,
    ) -> Result<
        crate::program::model::reloc::RelocationResult,
        crate::format::elf::relocation::elf_relocation_context::RelocationProcessingError,
    >;

    /// `ElfRelocationHandler.markAsError(Program, Address, int, String, int, String, MessageLog)`.
    /// Argument order follows the Java overload (symbol *name* before symbol *index*).
    fn mark_as_error(
        &self,
        program: &dyn crate::program::model::listing::program::Program,
        relocation_address: &crate::program::model::address::Address,
        type_id: i32,
        symbol_name: Option<&str>,
        symbol_index: i32,
        msg: &str,
        log: &dyn MessageLog,
    );

    /// `ElfRelocationHandler.markAsWarning(Program, Address, int, String, int, String, MessageLog)`.
    fn mark_as_warning(
        &self,
        program: &dyn crate::program::model::listing::program::Program,
        relocation_address: &crate::program::model::address::Address,
        type_id: i32,
        symbol_name: Option<&str>,
        symbol_index: i32,
        msg: &str,
        log: &dyn MessageLog,
    );
}

/// Placeholder for `ghidra.app.util.bin.format.elf.relocation.MIPS_ElfRelocationHandler`,
/// referenced by
/// [`MipsElfRelocationContext`](crate::format::elf::relocation::mips_elf_relocation_context::MipsElfRelocationContext)
/// before the handler itself is ported -- the forward edge of the context/handler dependency
/// cycle.
///
/// Java's `MIPS_ElfRelocationContext extends ElfRelocationContext<MIPS_ElfRelocationHandler>`
/// narrows the inherited `handler` field to this type so it can reach three members the handler
/// inherits from `AbstractElfRelocationHandler`: `getRelocationType`, `markAsUndefined`, and the
/// abstract 8-argument `relocate`. The last of those is already declared by the ported
/// [`AbstractElfRelocationHandler`](crate::format::elf::relocation::abstract_elf_relocation_handler::AbstractElfRelocationHandler),
/// so this stub inherits it rather than redeclaring it; the other two live on the concrete
/// [`AbstractElfRelocationHandlerBase`](crate::format::elf::relocation::abstract_elf_relocation_handler::AbstractElfRelocationHandlerBase)
/// struct in Rust and so have to be declared here.
pub trait MipsElfRelocationHandler:
    ElfRelocationHandler
    + crate::format::elf::relocation::abstract_elf_relocation_handler::AbstractElfRelocationHandler<
        crate::format::elf::relocation::mips_elf_relocation_type::MipsElfRelocationType,
    >
{
    /// Upcast to the general handler trait, which
    /// [`ElfRelocationContextBase`](crate::format::elf::relocation::elf_relocation_context::ElfRelocationContextBase)
    /// stores. Implementors write `self`. Stands in for Java's implicit widening of the narrowed
    /// `handler` field.
    fn as_elf_relocation_handler(self: std::sync::Arc<Self>) -> std::sync::Arc<dyn ElfRelocationHandler>;

    /// `AbstractElfRelocationHandler.getRelocationType(int)`, narrowed to MIPS. `None` stands in
    /// for Java's `null` return on an unrecognized type ID.
    fn get_relocation_type(
        &self,
        type_id: i32,
    ) -> Option<crate::format::elf::relocation::mips_elf_relocation_type::MipsElfRelocationType>;

    /// `AbstractElfRelocationHandler.markAsUndefined(Program, Address, int, String, int,
    /// MessageLog)`.
    fn mark_as_undefined(
        &self,
        program: &dyn crate::program::model::listing::program::Program,
        relocation_address: &crate::program::model::address::Address,
        type_id: i32,
        symbol_name: Option<&str>,
        symbol_index: i32,
        log: &dyn MessageLog,
    );
}

/// Placeholder for `MIPS_ElfRelocationHandler.MIPS_DeferredRelocation`, the nested class that
/// captures a HI16/GOT16 relocation whose processing must wait for the matching LO16 relocation.
///
/// The fields are Java's `final` package-private fields, read directly by the handler; they stay
/// public here for the same reason. `relocAddr`/`elfSymbol` are `Option` because a deferred
/// relocation may be recorded for the null symbol.
pub struct MipsDeferredRelocation {
    /// `relocType` -- the deferred relocation's type.
    pub reloc_type: crate::format::elf::relocation::mips_elf_relocation_type::MipsElfRelocationType,
    /// `elfSymbol` -- the symbol the deferred relocation applies to.
    pub elf_symbol: Option<crate::format::elf::elf_symbol::ElfSymbol>,
    /// `relocAddr` -- the address the relocation will be applied at.
    pub reloc_addr: crate::program::model::address::Address,
    /// `oldValueL` -- the original value read from `relocAddr`.
    pub old_value: i64,
    /// `addendL` -- the relocation addend.
    pub addend: i64,
    /// `isGpDisp` -- true if the relocation's symbol is `_gp_disp`.
    pub is_gp_disp: bool,
}

impl MipsDeferredRelocation {
    /// `MIPS_DeferredRelocation.markUnprocessed(MIPS_ElfRelocationContext, String)` -- mark a
    /// deferred relocation that never received its missing dependency as an error.
    ///
    /// Java takes the MIPS context but reads only `getProgram()`/`getLog()` off it, both of which
    /// live on the shared [`ElfRelocationContextBase`](crate::format::elf::relocation::elf_relocation_context::ElfRelocationContextBase);
    /// taking the base directly keeps this placeholder independent of the context port.
    pub fn mark_unprocessed(
        &self,
        context: &crate::format::elf::relocation::elf_relocation_context::ElfRelocationContextBase,
        missing_dependency_name: &str,
    ) {
        use crate::format::elf::relocation::elf_relocation_type::ElfRelocationType;
        let symbol_name = self.elf_symbol.as_ref().and_then(|s| s.get_name_as_string());
        let symbol_index = self
            .elf_symbol
            .as_ref()
            .map_or(-1, |s| s.get_symbol_table_index() as i32);
        elf_relocation_handler::mark_as_error(
            context.get_program().as_ref(),
            &self.reloc_addr,
            self.reloc_type.type_id(),
            symbol_index,
            symbol_name,
            &format!("Relocation missing required {missing_dependency_name}"),
            context.get_log().as_ref(),
        );
    }
}

/// Placeholders for the `ElfRelocationHandler` *static* markup helpers. They are free functions
/// rather than [`ElfRelocationHandler`] methods because the relocation context (and
/// [`AbstractElfRelocationHandlerBase`](crate::format::elf::relocation::abstract_elf_relocation_handler::AbstractElfRelocationHandlerBase),
/// which inherits them from `ElfRelocationHandler` in Java) calls them without a handler
/// instance in hand.
///
/// [`markup_error_or_warning`] drives the program's `BookmarkManager`, which is not ported yet,
/// so it currently only forwards the message to the import log (and, for
/// `bookmarkNoHandlerError`, does nothing at all -- Java deliberately passes a `null` log there so
/// the failure is bookmarked but not logged).
pub mod elf_relocation_handler {
    use super::MessageLog;
    use crate::format::elf::elf_symbol::FORMATTED_NO_NAME;
    use crate::program::model::address::Address;
    use crate::program::model::listing::program::Program;

    /// `ElfRelocationHandler.GOT_BLOCK_NAME` -- the name prefix of a fabricated GOT block.
    pub const GOT_BLOCK_NAME: &str = "%got";

    /// `ElfRelocationHandler.bookmarkNoHandlerError(Program, Address, int, int, String)`.
    pub fn bookmark_no_handler_error(
        program: &dyn Program,
        relocation_address: &Address,
        type_id: i32,
        symbol_index: i32,
        symbol_name: Option<&str>,
    ) {
        let _ = (program, relocation_address, type_id, symbol_index, symbol_name);
    }

    /// `ElfRelocationHandler.getDefaultRelocationTypeDetail(int)`. Used when no
    /// [`ElfRelocationType`](crate::format::elf::relocation::elf_relocation_type::ElfRelocationType)
    /// value was resolved for `typeId`, so the name it would have supplied is unavailable.
    pub fn get_default_relocation_type_detail(type_id: i32) -> String {
        format!("Type = {} (0x{:x})", type_id as u32, type_id as u32)
    }

    /// `ElfRelocationHandler.markupErrorOrWarning(Program, String, String, Address, String, int,
    /// String, String, MessageLog)`.
    ///
    /// `bookmark_type` is accepted (and ignored) to keep the signature faithful to Java; the
    /// bookmark itself cannot be realized until `Program::get_bookmark_manager` exists.
    pub fn markup_error_or_warning(
        program: &dyn Program,
        main_msg: &str,
        tail_msg: Option<&str>,
        relocation_address: &Address,
        reloc_type_detail: &str,
        symbol_index: i32,
        symbol_name: Option<&str>,
        bookmark_type: &str,
        log: Option<&dyn MessageLog>,
    ) {
        let _ = (program, bookmark_type, symbol_index);
        let tail = tail_msg
            .filter(|s| !s.is_empty())
            .map(|s| format!(" - {s}"))
            .unwrap_or_default();
        let symbol_name = symbol_name.filter(|s| !s.is_empty()).unwrap_or(FORMATTED_NO_NAME);
        if let Some(log) = log {
            log.append_msg(&format!(
                "{main_msg}: {reloc_type_detail} at {relocation_address} (Symbol = {symbol_name}){tail}"
            ));
        }
    }

    /// `ElfRelocationHandler.markAsError(Program, Address, int, int, String, String, MessageLog)`
    /// -- the static overload, which takes the symbol *index* before the symbol *name*.
    pub fn mark_as_error(
        program: &dyn Program,
        relocation_address: &Address,
        type_id: i32,
        symbol_index: i32,
        symbol_name: Option<&str>,
        msg: &str,
        log: &dyn MessageLog,
    ) {
        markup_error_or_warning(
            program,
            "Elf Relocation Error",
            Some(msg),
            relocation_address,
            &get_default_relocation_type_detail(type_id),
            symbol_index,
            symbol_name,
            crate::program::model::listing::bookmark_type::ERROR,
            Some(log),
        );
    }
}

/// Placeholder for `ghidra.app.util.bin.format.elf.ElfSymbolNameUtils`, referenced by
/// [`AbstractElfRelocationHandlerBase`](crate::format::elf::relocation::abstract_elf_relocation_handler::AbstractElfRelocationHandlerBase)
/// before the real class -- and the `SymbolUtilities.replaceInvalidChars` engine it delegates to
/// -- are ported. Only the entry point the abstract handler needs.
pub mod elf_symbol_name_utils {
    /// `ElfSymbolNameUtils.replaceInvalidChars(String)`. The real implementation escapes control
    /// characters, DEL, and spaces via `SymbolUtilities.replaceInvalidChars`; until that lands
    /// this is the identity function (the "already valid" case Java's javadoc calls out).
    pub fn replace_invalid_chars(name: &str) -> String {
        name.to_string()
    }
}

/// Placeholder for `ghidra.app.util.bin.format.pe.debug.DebugCOFFSymbolAux`, referenced by
/// [`DebugCOFFSymbol`] before the real class is ported.
pub trait DebugCOFFSymbolAux: Send + Sync {
    fn to_string(&self) -> String;
}

/// The size of the `IMAGE_SYMBOL` structure, in bytes.
pub const DEBUG_COFF_SYMBOL_IMAGE_SIZEOF_SYMBOL: usize = 18;

/// Placeholder for `ghidra.app.util.bin.format.pe.debug.DebugCOFFSymbol`, referenced by
/// [`DebugCOFFSymbolTable`](crate::format::pe::debug::debug_coff_symbol_table::DebugCOFFSymbolTable)
/// before the real class is ported. Models the methods and constants needed by `DebugCOFFSymbolTable`.
pub trait DebugCOFFSymbol: Send + Sync {
    fn get_auxiliary_symbols(&self) -> Vec<Box<dyn DebugCOFFSymbolAux>>;
    fn get_name(&self) -> String;
    fn get_value(&self) -> i32;
    fn get_value_as_string(&self) -> String;
    fn get_section_number(&self) -> i32;
    fn get_section_number_as_string(&self) -> String;
    fn get_type(&self) -> i32;
    fn get_type_as_string(&self) -> String;
    fn get_storage_class(&self) -> i32;
    fn get_storage_class_as_string(&self) -> String;
    fn get_number_of_aux_symbols(&self) -> i32;
    fn to_data_type(&self) -> std::io::Result<Box<dyn crate::program::model::data::data_type::DataType>>;
    fn to_string(&self) -> String;
}

/// Placeholder for `ghidra.app.util.bin.format.pe.debug.DebugCOFFLineNumber`, referenced by
/// [`DebugCOFFSymbolsHeader`] before the real class is ported.
pub trait DebugCOFFLineNumber: Send + Sync {
    fn to_string(&self) -> String;
}

/// Placeholder for `ghidra.app.util.bin.format.pe.debug.DebugDirectory`, referenced by
/// [`DebugCOFFSymbolsHeader`](crate::format::pe::debug::debug_coff_symbols_header::DebugCOFFSymbolsHeader)
/// before the real class is ported. Models only the method needed by `DebugCOFFSymbolsHeader`.
pub trait DebugDirectory: Send + Sync {
    fn get_pointer_to_raw_data(&self) -> i32;
}

/// Placeholder for `ghidra.app.util.bin.format.pe.debug.DebugCOFFSymbolTable`, referenced by
/// [`DebugCOFFSymbolsHeader`] before the real class is ported.
pub trait DebugCOFFSymbolTable: Send + Sync {
    fn get_symbols(&self) -> Vec<Box<dyn DebugCOFFSymbol>>;
    fn get_string_table_index(&self) -> i32;
}

/// Placeholder for `ghidra.app.util.bin.format.coff.AoutHeader`, referenced by
/// [`AoutHeaderFactory`](crate::format::coff::aout_header_factory) before the real class is ported.
pub trait AoutHeader: Send + Sync {
    fn get_magic(&self) -> i16;
    fn get_version_stamp(&self) -> i16;
    fn get_text_size(&self) -> i32;
    fn get_initialized_data_size(&self) -> i32;
    fn get_uninitialized_data_size(&self) -> i32;
    fn get_entry(&self) -> i32;
    fn get_text_start(&self) -> i32;
    fn get_initialized_data_start(&self) -> i32;
    fn to_data_type(&self) -> std::io::Result<Box<dyn crate::program::model::data::data_type::DataType>>;
}

/// Placeholder for `ghidra.app.util.bin.format.coff.AoutHeaderMIPS`, referenced by
/// [`AoutHeaderFactory`](crate::format::coff::aout_header_factory) before the real class is ported.
pub trait AoutHeaderMIPS: AoutHeader + Send + Sync {
    fn get_uninitialized_data_start(&self) -> i32;
    fn get_gpr_mask(&self) -> i32;
    fn get_cpr_mask(&self) -> Vec<i32>;
    fn get_gp_value(&self) -> i32;
}

/// Placeholder for `ghidra.app.util.bin.format.coff.CoffSectionHeader`, referenced by
/// [`CoffFileHeader`] before the real class is ported.
pub trait CoffSectionHeader: Send + Sync {
}

/// Placeholder for `ghidra.app.util.bin.format.coff.CoffSymbol`, referenced by
/// [`CoffFileHeader`] before the real class is ported.
pub trait CoffSymbol: Send + Sync {
}

/// Placeholder for `ghidra.app.util.bin.format.coff.CoffFileHeader`, referenced by
/// [`AoutHeaderFactory`](crate::format::coff::aout_header_factory) before the real class is ported.
pub trait CoffFileHeader: Send + Sync {
    fn get_magic(&self) -> i16;
    fn get_section_count(&self) -> i16;
    fn get_timestamp(&self) -> i32;
    fn get_symbol_table_pointer(&self) -> i32;
    fn get_symbol_table_entries(&self) -> i32;
    fn get_optional_header_size(&self) -> i16;
    fn get_flags(&self) -> i16;
    fn get_target_id(&self) -> std::io::Result<i16>;
    fn get_image_base(&self, is_windows_platform: bool) -> i64;
    fn get_machine_name(&self) -> String;
    fn get_machine(&self) -> i16;
    fn parse_section_headers(&self) -> std::io::Result<()>;
    fn parse(&self, monitor: &dyn crate::util::task::TaskMonitor) -> std::io::Result<()>;
    fn get_sections(&self) -> Vec<Box<dyn CoffSectionHeader>>;
    fn get_symbols(&self) -> Vec<Box<dyn CoffSymbol>>;
    fn get_symbol_at_index(&self, index: i64) -> Box<dyn CoffSymbol>;
    fn sizeof(&self) -> i32;
    fn get_optional_header(&self) -> Box<dyn AoutHeader>;
    fn is_valid(&self) -> std::io::Result<bool>;
    fn to_data_type(&self) -> std::io::Result<Box<dyn crate::program::model::data::data_type::DataType>>;
}

/// Placeholder for `ghidra.app.util.bin.format.coff.CoffRelocation`, referenced by
/// [`CoffRelocationHandler`](crate::format::coff::relocation::coff_relocation_handler) before the real class is ported.
pub trait CoffRelocation: Send + Sync {
    fn sizeof(&self) -> i32;
    fn get_address(&self) -> i64;
    fn get_symbol_index(&self) -> i64;
    fn get_extended_address(&self) -> i16;
    fn get_type(&self) -> i16;
    fn to_data_type(&self) -> std::io::Result<Box<dyn crate::program::model::data::data_type::DataType>>;
}

/// Placeholder for `ghidra.app.util.bin.format.macho.commands.SegmentCommand`, referenced by
/// [`LoadCommand`](crate::format::macho::commands::load_command::LoadCommand) before the real
/// class is ported. Only the accessors `LoadCommand`'s `getContainingSegment`/`fileOffsetToAddress`
/// need.
pub trait SegmentCommand: Send + Sync {
    /// `SegmentCommand.getVMaddress()`.
    fn get_v_maddress(&self) -> i64;
    /// `SegmentCommand.getFileOffset()`.
    fn get_file_offset(&self) -> i64;
    /// `SegmentCommand.getFileSize()`.
    fn get_file_size(&self) -> i64;
}

/// Placeholder for `ghidra.app.util.bin.format.macho.MachHeader`, referenced by
/// [`LoadCommand`](crate::format::macho::commands::load_command::LoadCommand) before the real
/// class is ported. Only the two segment lookups `LoadCommand`'s `fileOffsetToAddress`/
/// `getContainingSegment` need.
pub trait MachHeader: Send + Sync {
    /// `MachHeader.getSegment(String)`. `None` stands in for Java's `null` return when no segment
    /// with the given name exists.
    fn get_segment(&self, segment_name: &str) -> Option<Box<dyn SegmentCommand>>;
    /// `MachHeader.getAllSegments()`.
    fn get_all_segments(&self) -> Vec<Box<dyn SegmentCommand>>;

    /// `MachHeader.getAllSections()`, needed by
    /// [`MachoRelocation::find_target_section`](crate::format::macho::relocation::macho_relocation::MachoRelocation::find_target_section).
    ///
    /// Defaults to empty so existing implementors (e.g. `LoadCommand`'s `MockMachHeader`) are
    /// unaffected.
    fn get_all_sections(&self) -> Vec<Section> {
        Vec::new()
    }

    /// Stands in for `MachHeader.getFirstLoadCommand(SymbolTableCommand.class)`, narrowed to the
    /// one load command type [`MachoRelocation`](crate::format::macho::relocation::macho_relocation::MachoRelocation)
    /// needs -- Rust has no reflection-based generic lookup by `Class`. `None` stands in for
    /// Java's `null` return when the header has no symbol table command.
    ///
    /// Defaults to `None` so existing implementors are unaffected.
    fn get_symbol_table_command(&self) -> Option<SymbolTableCommand> {
        None
    }
}

/// Placeholder for `ghidra.app.util.bin.format.macho.RelocationInfo`, referenced by
/// [`MachoRelocation`](crate::format::macho::relocation::macho_relocation::MachoRelocation)
/// before the real class is ported. Concrete Java class (not an interface); models only the
/// three accessors `MachoRelocation` needs (`getValue`/`isExternal`/`isScattered`) plus a
/// `Display` impl standing in for `toString()`, which `MachoRelocation::toString` embeds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RelocationInfo {
    value: i32,
    external: bool,
    scattered: bool,
}

impl RelocationInfo {
    pub fn new(value: i32, external: bool, scattered: bool) -> Self {
        RelocationInfo { value, external, scattered }
    }

    /// `RelocationInfo.getValue()`.
    pub fn get_value(&self) -> i32 {
        self.value
    }

    /// `RelocationInfo.isExternal()`.
    pub fn is_external(&self) -> bool {
        self.external
    }

    /// `RelocationInfo.isScattered()`.
    pub fn is_scattered(&self) -> bool {
        self.scattered
    }
}

impl std::fmt::Display for RelocationInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Value: 0x{:x}, External: {}, Scattered: {}",
            self.value, self.external, self.scattered
        )
    }
}

/// Placeholder for `ghidra.app.util.bin.format.macho.Section`, referenced by
/// [`MachoRelocation`](crate::format::macho::relocation::macho_relocation::MachoRelocation)
/// before the real class is ported. Concrete Java class (not an interface); models only the
/// accessors `MachoRelocation` needs (`getAddress`/`getSectionName`) plus a `Display` impl
/// standing in for `toString()`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Section {
    address: i64,
    section_name: String,
}

impl Section {
    pub fn new(address: i64, section_name: impl Into<String>) -> Self {
        Section { address, section_name: section_name.into() }
    }

    /// `Section.getAddress()`.
    pub fn get_address(&self) -> i64 {
        self.address
    }

    /// `Section.getSectionName()`.
    pub fn get_section_name(&self) -> &str {
        &self.section_name
    }
}

impl std::fmt::Display for Section {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.section_name)
    }
}

/// Placeholder for `ghidra.app.util.bin.format.macho.commands.NList`, referenced by
/// [`MachoRelocation`](crate::format::macho::relocation::macho_relocation::MachoRelocation)
/// before the real class is ported. Concrete Java class (not an interface); models only the two
/// accessors `MachoRelocation` needs (`getValue`/`getString`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NList {
    value: i64,
    string: String,
}

impl NList {
    pub fn new(value: i64, string: impl Into<String>) -> Self {
        NList { value, string: string.into() }
    }

    /// `NList.getValue()`.
    pub fn get_value(&self) -> i64 {
        self.value
    }

    /// `NList.getString()`.
    pub fn get_string(&self) -> &str {
        &self.string
    }
}

/// Placeholder for `ghidra.app.util.bin.format.macho.commands.SymbolTableCommand`, referenced by
/// [`MachoRelocation`](crate::format::macho::relocation::macho_relocation::MachoRelocation)
/// before the real class is ported. Concrete Java class (not an interface); models only the one
/// accessor `MachoRelocation` needs (`getSymbolAt`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SymbolTableCommand {
    symbols: Vec<NList>,
}

impl SymbolTableCommand {
    pub fn new(symbols: Vec<NList>) -> Self {
        SymbolTableCommand { symbols }
    }

    /// `SymbolTableCommand.getSymbolAt(int)`. `None` stands in for Java's `null` return on an
    /// out-of-range index.
    pub fn get_symbol_at(&self, index: i32) -> Option<&NList> {
        if index < 0 {
            return None;
        }
        self.symbols.get(index as usize)
    }
}

/// Placeholder for `ghidra.util.NumericUtilities`, referenced by
/// [`MachoRelocation`](crate::format::macho::relocation::macho_relocation::MachoRelocation)
/// before the real class is ported. `NumericUtilities` is a `private`-constructor static-method
/// utility class (not an interface), so it is modeled here as a free function rather than a
/// trait, consistent with [`MachConstants`](crate::format::macho::mach_constants) and other
/// already-ported static-utility classes. Only `toHexString(long)`, the one overload
/// `MachoRelocation` needs.
pub mod numeric_utilities {
    /// `NumericUtilities.toHexString(long)`: `"0x" + Long.toHexString(value)`, where
    /// `Long.toHexString` treats `value` as unsigned 64-bit.
    pub fn to_hex_string(value: i64) -> String {
        format!("0x{:x}", value as u64)
    }
}

/// Placeholder for `ghidra.program.flatapi.FlatProgramAPI`, referenced by
/// [`LoadCommand::markup_raw_binary`](crate::format::macho::commands::load_command::LoadCommand::markup_raw_binary)
/// before the real class is ported. Only the three members that legacy raw-binary markup path
/// needs (`createFragment`, `createData`, `setPlateComment`); the other ~120 `FlatProgramAPI`
/// methods are left for the real port.
pub trait FlatProgramAPI: Send + Sync {
    /// `FlatProgramAPI.createFragment(ProgramModule, String, Address, long)`.
    fn create_fragment(
        &self,
        module: &mut dyn crate::program::model::listing::program_module::ProgramModule,
        fragment_name: &str,
        start: &crate::program::model::address::Address,
        length: i64,
    ) -> std::io::Result<Box<dyn crate::program::model::listing::program_fragment::ProgramFragment>>;

    /// `FlatProgramAPI.createData(Address, DataType)`.
    fn create_data(
        &self,
        address: &crate::program::model::address::Address,
        data_type: Box<dyn crate::program::model::data::data_type::DataType>,
    ) -> std::io::Result<Box<dyn crate::program::model::listing::data::Data>>;

    /// `FlatProgramAPI.setPlateComment(Address, String)`.
    fn set_plate_comment(&self, address: &crate::program::model::address::Address, comment: &str) -> bool;

    /// `FlatProgramAPI.getCurrentProgram()`, needed by
    /// [`DyldChainedFixupsCommand::markup_raw_binary`](crate::format::macho::commands::chained::dyld_chained_fixups_command::DyldChainedFixupsCommand::markup_raw_binary)
    /// to resolve the file-offset-relative address of the chained-fixups header data. Grown
    /// (defaulted to `None`, so existing implementors keep compiling) alongside the other
    /// `FlatProgramAPI` members above.
    fn get_current_program(&self) -> Option<std::sync::Arc<dyn crate::program::model::listing::Program>> {
        None
    }
}

/// Placeholder for `ghidra.program.model.listing.Program`, referenced by
/// `CodeSignatureBlobParser`'s stub types before the real class is ported.
pub trait Program: Send + Sync {
}

/// Placeholder for `ghidra.app.util.bin.format.macho.commands.codesignature.CodeSignatureBlobIndex`,
/// referenced by `CodeSignatureSuperBlob` before the real class is ported.
pub trait CodeSignatureBlobIndex: Send + Sync {
}

/// Placeholder for `ghidra.app.util.bin.format.macho.commands.codesignature.CodeSignatureGenericBlob`,
/// referenced by `CodeSignatureBlobParser` before the real class is ported.
pub trait CodeSignatureGenericBlob: Send + Sync {
    fn get_magic(&self) -> i32;
    fn get_length(&self) -> i64;
    fn markup(&self, program: &dyn Program, address: &crate::program::model::address::Address, header: &dyn MachHeader, monitor: &dyn crate::util::task::TaskMonitor, log: &dyn MessageLog) -> std::io::Result<()>;
    fn to_data_type(&self) -> std::io::Result<Box<dyn crate::program::model::data::data_type::DataType>>;
}

/// Placeholder for `ghidra.app.util.bin.format.macho.commands.codesignature.CodeSignatureCodeDirectory`,
/// referenced by `CodeSignatureBlobParser` before the real class is ported.
pub trait CodeSignatureCodeDirectory: Send + Sync {
    fn markup(&self, program: &dyn Program, addr: &crate::program::model::address::Address, header: &dyn MachHeader, monitor: &dyn crate::util::task::TaskMonitor, log: &dyn MessageLog) -> std::io::Result<()>;
    fn to_data_type(&self) -> std::io::Result<Box<dyn crate::program::model::data::data_type::DataType>>;
}

/// Placeholder for `ghidra.app.util.bin.format.macho.commands.codesignature.CodeSignatureSuperBlob`,
/// referenced by `CodeSignatureBlobParser` before the real class is ported.
pub trait CodeSignatureSuperBlob: Send + Sync {
    fn get_count(&self) -> i32;
    fn get_index_entries(&self) -> Vec<Box<dyn CodeSignatureBlobIndex>>;
    fn get_index_blobs(&self) -> Vec<Box<dyn CodeSignatureGenericBlob>>;
    fn markup(&self, program: &dyn Program, addr: &crate::program::model::address::Address, header: &dyn MachHeader, monitor: &dyn crate::util::task::TaskMonitor, log: &dyn MessageLog) -> std::io::Result<()>;
    fn to_data_type(&self) -> std::io::Result<Box<dyn crate::program::model::data::data_type::DataType>>;
}

/// Placeholder for `ghidra.app.util.bin.format.macho.commands.chained.DyldChainedImport`,
/// referenced by
/// [`dyld_chained_fixups`](crate::format::macho::commands::chained::dyld_chained_fixups) before
/// the real class is ported. Only the two accessors chained-fixup resolution needs.
pub trait DyldChainedImport: Send + Sync {
    /// `DyldChainedImport.getName()`.
    fn get_name(&self) -> String;
    /// `DyldChainedImport.getLibOrdinal()`.
    fn get_lib_ordinal(&self) -> i32;
}

/// Placeholder for `ghidra.app.util.bin.format.macho.commands.chained.DyldChainedImports`,
/// referenced by
/// [`dyld_chained_fixups`](crate::format::macho::commands::chained::dyld_chained_fixups) before
/// the real class is ported. Only the ordinal lookup chained-fixup resolution needs.
pub trait DyldChainedImports: Send + Sync {
    /// `DyldChainedImports.getChainedImport(int)`.
    fn get_chained_import(&self, ordinal: i32) -> Box<dyn DyldChainedImport>;
}

/// Placeholder for `ghidra.app.util.opinion.MachoProgramBuilder`, referenced by
/// [`dyld_chained_fixups`](crate::format::macho::commands::chained::dyld_chained_fixups) before
/// the real class is ported. Only the two static helpers chained-pointer fixup needs; modeled as
/// a trait object (rather than free functions) since the caller must be handed a seam for the
/// not-yet-ported class.
pub trait MachoProgramBuilder: Send + Sync {
    /// `MachoProgramBuilder.createOneByteFunction(Program, String, Address)`.
    fn create_one_byte_function(
        &self,
        program: &mut dyn crate::program::model::listing::Program,
        name: &str,
        address: &crate::program::model::address::Address,
    ) -> Option<Box<dyn crate::program::model::listing::Function>>;

    /// `MachoProgramBuilder.fixupExternalLibrary(Program, List<String>, int, String)`.
    fn fixup_external_library(
        &self,
        program: &mut dyn crate::program::model::listing::Program,
        library_paths: &[String],
        library_ordinal: i32,
        symbol: &str,
    ) -> std::io::Result<()>;
}

/// Placeholder for `ghidra.app.util.MemoryBlockUtils`, referenced by
/// [`dyld_chained_fixups`](crate::format::macho::commands::chained::dyld_chained_fixups) before
/// the real class is ported. Only the `addExternalBlock` helper chained-pointer fixup needs.
pub trait MemoryBlockUtils: Send + Sync {
    /// `MemoryBlockUtils.addExternalBlock(Program, long, MessageLog)`.
    fn add_external_block(
        &self,
        program: &mut dyn crate::program::model::listing::Program,
        size: i64,
        log: &dyn MessageLog,
    ) -> std::io::Result<crate::program::model::address::Address>;
}

/// Placeholder for `ghidra.app.util.bin.format.macho.commands.LinkEditDataCommand`, referenced by
/// [`DyldChainedFixupsCommand`](crate::format::macho::commands::chained::dyld_chained_fixups_command::DyldChainedFixupsCommand)
/// before the real class is ported. `LinkEditDataCommand` is a concrete Java class (not an
/// interface) that itself extends `LoadCommand`, so it is modeled here as a concrete struct
/// wrapping the already-ported [`LoadCommandBase`](crate::format::macho::commands::load_command::LoadCommandBase)
/// plus the `dataoff`/`datasize` fields -- the only state the one in-repo consumer needs. Java's
/// `markup`/`markupRawBinary`/`toDataType` all resolve the *overridden* `getCommandName()` through
/// virtual dispatch once a subclass like `DyldChainedFixupsCommand` is involved, so those methods
/// are intentionally not duplicated here: the consumer flattens the inherited
/// `LoadCommand` -> `LinkEditDataCommand` behaviour into its own `LoadCommand` impl instead, using
/// only the state this placeholder exposes.
pub struct LinkEditDataCommand {
    base: crate::format::macho::commands::load_command::LoadCommandBase,
    dataoff: i64,
    datasize: i64,
}

impl LinkEditDataCommand {
    /// `LinkEditDataCommand(BinaryReader, BinaryReader)`.
    pub fn new(
        load_command_reader: &mut dyn crate::app::util::bin::binary_reader::BinaryReader,
        data_reader: &mut dyn crate::app::util::bin::binary_reader::BinaryReader,
    ) -> std::io::Result<Self> {
        let base = crate::format::macho::commands::load_command::LoadCommandBase::new(
            load_command_reader,
        )?;
        let dataoff = load_command_reader.read_next_unsigned_int()? as i64;
        let datasize = load_command_reader.read_next_unsigned_int()? as i64;
        data_reader.set_pointer_index(dataoff as u64);
        Ok(LinkEditDataCommand { base, dataoff, datasize })
    }

    /// Accessor to the shared `LoadCommand` state, mirroring how [`LoadCommand`](crate::format::macho::commands::load_command::LoadCommand)
    /// implementors expose their own [`LoadCommandBase`](crate::format::macho::commands::load_command::LoadCommandBase).
    pub fn base(&self) -> &crate::format::macho::commands::load_command::LoadCommandBase {
        &self.base
    }

    /// `LinkEditDataCommand.getLinkerDataOffset()`.
    pub fn dataoff(&self) -> i64 {
        self.dataoff
    }

    /// `LinkEditDataCommand.getLinkerDataSize()`.
    pub fn datasize(&self) -> i64 {
        self.datasize
    }

    /// `LinkEditDataCommand.toDataType()`. The real Java body builds a `cmd`/`cmdsize`/`dataoff`/
    /// `datasize` `linkedit_data_command` structure using the (virtual) `getCommandName()`; since
    /// this placeholder cannot know the most-derived command name, and
    /// [`StructureDataType`](crate::program::model::data::structure_data_type::StructureDataType)
    /// has no concrete Rust constructor yet, it stands in with an opaque placeholder
    /// [`DataType`](crate::program::model::data::data_type::DataType).
    pub fn to_data_type(
        &self,
    ) -> std::io::Result<Box<dyn crate::program::model::data::data_type::DataType>> {
        Ok(Box::new(LinkEditDataCommandDataType))
    }
}

/// Placeholder [`DataType`](crate::program::model::data::data_type::DataType) returned by
/// [`LinkEditDataCommand::to_data_type`]. Concrete Java class, not an interface; modeled as an
/// opaque marker like [`PERichTableDataType`] above, consistent with the other not-yet-ported
/// `toDataType()` results in this file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LinkEditDataCommandDataType;

impl crate::program::model::data::data_type::DataType for LinkEditDataCommandDataType {}

/// Placeholder for `ghidra.app.util.bin.format.macho.commands.chained.DyldChainedFixupHeader`,
/// referenced by [`DyldChainedFixupsCommand`](crate::format::macho::commands::chained::dyld_chained_fixups_command::DyldChainedFixupsCommand)
/// before the real class is ported. `DyldChainedFixupHeader` is a concrete Java class (not an
/// interface), so it is modeled here as a concrete struct. The numeric header fields and the
/// nested [`DyldChainedStartsInImage`] are parsed faithfully; `chainedImports` cannot be, since
/// `ghidra.app.util.bin.format.macho.commands.chained.DyldChainedImports` (already referenced
/// elsewhere in this crate as the trait [`DyldChainedImports`]) has no concrete Rust implementor
/// yet to construct one from -- it is left `None` until one exists.
pub struct DyldChainedFixupHeader {
    fixups_version: i64,
    starts_offset: i64,
    imports_offset: i64,
    symbols_offset: i64,
    imports_count: i64,
    imports_format: i32,
    symbols_format: i32,
    chained_starts_in_image: DyldChainedStartsInImage,
    chained_imports: Option<Box<dyn DyldChainedImports>>,
}

impl DyldChainedFixupHeader {
    /// `DyldChainedFixupHeader(BinaryReader)`.
    pub fn new(
        reader: &mut dyn crate::app::util::bin::binary_reader::BinaryReader,
    ) -> std::io::Result<Self> {
        let ptr_index = reader.get_pointer_index();

        let fixups_version = reader.read_next_unsigned_int()? as i64;
        let starts_offset = reader.read_next_unsigned_int()? as i64;
        let imports_offset = reader.read_next_unsigned_int()? as i64;
        let symbols_offset = reader.read_next_unsigned_int()? as i64;
        let imports_count = reader.read_next_unsigned_int()? as i64;
        let imports_format = reader.read_next_int()?;
        let symbols_format = reader.read_next_int()?;

        reader.set_pointer_index((ptr_index as i64 + starts_offset) as u64);
        let chained_starts_in_image = DyldChainedStartsInImage::new(reader)?;

        // `chainedImports = new DyldChainedImports(reader, this)` /
        // `chainedImports.initSymbols(reader, this)` are not reproduced here: `DyldChainedImports`
        // has no concrete Rust implementor yet (see the struct doc above).
        Ok(DyldChainedFixupHeader {
            fixups_version,
            starts_offset,
            imports_offset,
            symbols_offset,
            imports_count,
            imports_format,
            symbols_format,
            chained_starts_in_image,
            chained_imports: None,
        })
    }

    /// `DyldChainedFixupHeader.toDataType()`. See [`LinkEditDataCommand::to_data_type`] for why
    /// this is an opaque placeholder rather than a real `dyld_chained_fixups_header` layout.
    pub fn to_data_type(
        &self,
    ) -> std::io::Result<Box<dyn crate::program::model::data::data_type::DataType>> {
        Ok(Box::new(DyldChainedFixupHeaderDataType))
    }

    /// `DyldChainedFixupHeader.markup(Program, Address, MachHeader, TaskMonitor, MessageLog)`.
    /// The real body marks up the nested starts-in-image structure and the imports/symbols
    /// tables; since `chained_imports` is always `None` here (see the struct doc above) and the
    /// starts-in-image markup itself needs the not-yet-ported `DataUtilities.createData` plumbing
    /// this placeholder doesn't have a `Program` handle to drive, this is a documented no-op.
    pub fn markup(
        &self,
        _program: &mut dyn crate::program::model::listing::Program,
        _address: &crate::program::model::address::Address,
        _header: &dyn MachHeader,
        _monitor: &dyn crate::util::task::TaskMonitor,
        _log: &dyn MessageLog,
    ) -> Result<(), crate::util::exception::CancelledException> {
        Ok(())
    }

    /// `DyldChainedFixupHeader.getFixupsVersion()`.
    pub fn get_fixups_version(&self) -> i64 {
        self.fixups_version
    }

    /// `DyldChainedFixupHeader.getStartsOffset()`.
    pub fn get_starts_offset(&self) -> i64 {
        self.starts_offset
    }

    /// `DyldChainedFixupHeader.getImportsOffset()`.
    pub fn get_imports_offset(&self) -> i64 {
        self.imports_offset
    }

    /// `DyldChainedFixupHeader.getSymbolsOffset()`.
    pub fn get_symbols_offset(&self) -> i64 {
        self.symbols_offset
    }

    /// `DyldChainedFixupHeader.getImportsCount()`.
    pub fn get_imports_count(&self) -> i64 {
        self.imports_count
    }

    /// `DyldChainedFixupHeader.getImportsFormat()`.
    pub fn get_imports_format(&self) -> i32 {
        self.imports_format
    }

    /// `DyldChainedFixupHeader.getSymbolsFormat()`.
    pub fn get_symbols_format(&self) -> i32 {
        self.symbols_format
    }

    /// `DyldChainedFixupHeader.isCompress()`.
    pub fn is_compress(&self) -> bool {
        self.symbols_format != 0
    }

    /// `DyldChainedFixupHeader.getChainedStartsInImage()`.
    pub fn get_chained_starts_in_image(&self) -> &DyldChainedStartsInImage {
        &self.chained_starts_in_image
    }

    /// `DyldChainedFixupHeader.getChainedImports()`.
    pub fn get_chained_imports(&self) -> Option<&dyn DyldChainedImports> {
        self.chained_imports.as_deref()
    }
}

/// Placeholder [`DataType`](crate::program::model::data::data_type::DataType) returned by
/// [`DyldChainedFixupHeader::to_data_type`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DyldChainedFixupHeaderDataType;

impl crate::program::model::data::data_type::DataType for DyldChainedFixupHeaderDataType {}

/// Placeholder for `ghidra.app.util.bin.format.macho.commands.chained.DyldChainedStartsInImage`,
/// referenced by [`DyldChainedFixupHeader`] before the real class is ported.
/// `DyldChainedStartsInImage` is a concrete Java class (not an interface), so it is modeled here
/// as a concrete struct. Unlike its owner [`DyldChainedFixupHeader`], this type has no forward
/// references to not-yet-ported classes, so its constructor and accessors are ported faithfully.
pub struct DyldChainedStartsInImage {
    seg_count: i32,
    seg_info_offset: Vec<i32>,
    chained_starts: Vec<DyldChainedStartsInSegment>,
}

impl DyldChainedStartsInImage {
    /// `DyldChainedStartsInImage(BinaryReader)`.
    pub fn new(
        reader: &mut dyn crate::app::util::bin::binary_reader::BinaryReader,
    ) -> std::io::Result<Self> {
        let ptr_index = reader.get_pointer_index();

        let seg_count = reader.read_next_int()?;
        let seg_info_offset = reader.read_next_int_array(seg_count.max(0) as usize)?;

        let mut chained_starts = Vec::new();
        for &offset in &seg_info_offset {
            if offset != 0 {
                reader.set_pointer_index((ptr_index as i64 + offset as i64) as u64);
                chained_starts.push(DyldChainedStartsInSegment::new(reader)?);
            }
        }

        Ok(DyldChainedStartsInImage { seg_count, seg_info_offset, chained_starts })
    }

    /// `DyldChainedStartsInImage.toDataType()`. See [`LinkEditDataCommand::to_data_type`] for why
    /// this is an opaque placeholder rather than a real `dyld_chained_starts_in_image` layout.
    pub fn to_data_type(
        &self,
    ) -> std::io::Result<Box<dyn crate::program::model::data::data_type::DataType>> {
        Ok(Box::new(DyldChainedStartsInImageDataType))
    }

    /// `DyldChainedStartsInImage.getSegCount()`.
    pub fn get_seg_count(&self) -> i32 {
        self.seg_count
    }

    /// `DyldChainedStartsInImage.getSegInfoOffset()`.
    pub fn get_seg_info_offset(&self) -> &[i32] {
        &self.seg_info_offset
    }

    /// `DyldChainedStartsInImage.getChainedStarts()`.
    pub fn get_chained_starts(&self) -> &[DyldChainedStartsInSegment] {
        &self.chained_starts
    }
}

/// Placeholder [`DataType`](crate::program::model::data::data_type::DataType) returned by
/// [`DyldChainedStartsInImage::to_data_type`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DyldChainedStartsInImageDataType;

impl crate::program::model::data::data_type::DataType for DyldChainedStartsInImageDataType {}

/// Placeholder for `ghidra.app.util.bin.format.macho.commands.chained.DyldChainedStartsInSegment`,
/// referenced by [`DyldChainedStartsInImage`] before the real class is ported.
/// `DyldChainedStartsInSegment` is a concrete Java class (not an interface), so it is modeled here
/// as a concrete struct. Like its owner, this type has no forward references to not-yet-ported
/// classes, so its constructor and accessors are ported faithfully; only `markup` (currently a
/// `// TODO?` no-op in the Java source too) is left unimplemented.
pub struct DyldChainedStartsInSegment {
    size: i32,
    page_size: i16,
    pointer_format: i16,
    segment_offset: i64,
    max_valid_pointer: i32,
    page_count: i16,
    page_starts: Vec<i16>,
}

impl DyldChainedStartsInSegment {
    /// `DyldChainedStartsInSegment(BinaryReader)`.
    pub fn new(
        reader: &mut dyn crate::app::util::bin::binary_reader::BinaryReader,
    ) -> std::io::Result<Self> {
        let size = reader.read_next_int()?;
        let page_size = reader.read_next_short()?;
        let pointer_format = reader.read_next_short()?;
        let segment_offset = reader.read_next_long()?;
        let max_valid_pointer = reader.read_next_int()?;
        let page_count = reader.read_next_short()?;
        let page_starts = reader.read_next_short_array(page_count.max(0) as usize)?;

        Ok(DyldChainedStartsInSegment {
            size,
            page_size,
            pointer_format,
            segment_offset,
            max_valid_pointer,
            page_count,
            page_starts,
        })
    }

    /// `DyldChainedStartsInSegment.toDataType()`. See [`LinkEditDataCommand::to_data_type`] for
    /// why this is an opaque placeholder rather than a real `dyld_chained_starts_in_segment`
    /// layout.
    pub fn to_data_type(
        &self,
    ) -> std::io::Result<Box<dyn crate::program::model::data::data_type::DataType>> {
        Ok(Box::new(DyldChainedStartsInSegmentDataType))
    }

    /// `DyldChainedStartsInSegment.getSize()`.
    pub fn get_size(&self) -> i32 {
        self.size
    }

    /// `DyldChainedStartsInSegment.getPageSize()`.
    pub fn get_page_size(&self) -> i16 {
        self.page_size
    }

    /// `DyldChainedStartsInSegment.getPointerFormat()`.
    pub fn get_pointer_format(&self) -> i16 {
        self.pointer_format
    }

    /// `DyldChainedStartsInSegment.getSegmentOffset()`.
    pub fn get_segment_offset(&self) -> i64 {
        self.segment_offset
    }

    /// `DyldChainedStartsInSegment.getMaxValidPointer()`.
    pub fn get_max_valid_pointer(&self) -> i32 {
        self.max_valid_pointer
    }

    /// `DyldChainedStartsInSegment.getPageCount()`.
    pub fn get_page_count(&self) -> i16 {
        self.page_count
    }

    /// `DyldChainedStartsInSegment.getPageStarts()`.
    pub fn get_page_starts(&self) -> &[i16] {
        &self.page_starts
    }
}

/// Placeholder [`DataType`](crate::program::model::data::data_type::DataType) returned by
/// [`DyldChainedStartsInSegment::to_data_type`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DyldChainedStartsInSegmentDataType;

impl crate::program::model::data::data_type::DataType for DyldChainedStartsInSegmentDataType {}

/// Placeholder for the unported Java type `ClassSearcher`, referenced by `ElfInfoProducer`.
/// Generated stub: only a shape hint. The method needed by `ElfInfoProducer` is
/// `get_elf_info_producer_instances`, which returns trait objects of ElfInfoProducer.
pub struct ClassSearcher;

impl ClassSearcher {
    /// Placeholder for `ClassSearcher.getInstances(ElfInfoProducer.class)`.
    /// Returns instances of ElfInfoProducer that have been discovered via classpath scanning.
    /// In the Rust port, this is a placeholder that returns an empty list until the real
    /// discovery mechanism is implemented. When real ElfInfoProducer implementations are
    /// discovered in the Rust codebase, they should be registered here.
    pub fn get_elf_info_producer_instances() -> Vec<std::sync::Arc<dyn crate::format::elf::info::elf_info_producer::ElfInfoProducer>> {
        Vec::new()
    }
}

/// Placeholder for `ghidra.app.util.bin.format.pef.SectionHeader`, referenced by
/// [`LoaderInfoHeader`](crate::format::pef::loader_info_header::LoaderInfoHeader) and
/// [`LoaderRelocationHeader`](crate::format::pef::loader_relocation_header::LoaderRelocationHeader)
/// before the real class is ported. Only the accessor those constructors need: the byte offset
/// (within the whole PEF container) of the section this header describes.
pub trait SectionHeader: Send + Sync {
    /// `SectionHeader.getContainerOffset()`.
    fn get_container_offset(&self) -> i32;
}

/// Placeholder for `ghidra.app.util.bin.format.pef.ImportedLibrary`, referenced by
/// [`LoaderInfoHeader`](crate::format::pef::loader_info_header::LoaderInfoHeader) before the real
/// class is ported. Parses the fixed 24-byte header fields (matching `ImportedLibrary`'s
/// sequential reads) and exposes the two accessors `LoaderInfoHeader::find_library` needs. The
/// library name (read via an absolute offset into the loader string table, which does not affect
/// the sequential reader position) is left for the real port.
pub struct ImportedLibrary {
    name_offset: i32,
    old_imp_version: i32,
    current_version: i32,
    imported_symbol_count: i32,
    first_imported_symbol: i32,
    options: i8,
    reserved_a: i8,
    reserved_b: i16,
}

impl ImportedLibrary {
    /// Port of `ImportedLibrary(BinaryReader, LoaderInfoHeader)`, minus the name lookup.
    pub fn new(
        reader: &mut dyn crate::app::util::bin::binary_reader::BinaryReader,
        _loader: &crate::format::pef::loader_info_header::LoaderInfoHeader,
    ) -> std::io::Result<Self> {
        Ok(ImportedLibrary {
            name_offset: reader.read_next_int()?,
            old_imp_version: reader.read_next_int()?,
            current_version: reader.read_next_int()?,
            imported_symbol_count: reader.read_next_int()?,
            first_imported_symbol: reader.read_next_int()?,
            options: reader.read_next_byte()? as i8,
            reserved_a: reader.read_next_byte()? as i8,
            reserved_b: reader.read_next_short()?,
        })
    }

    /// `ImportedLibrary.getNameOffset()`.
    pub fn name_offset(&self) -> i32 {
        self.name_offset
    }
    /// `ImportedLibrary.getOldImpVersion()`.
    pub fn old_imp_version(&self) -> i32 {
        self.old_imp_version
    }
    /// `ImportedLibrary.getCurrentVersion()`.
    pub fn current_version(&self) -> i32 {
        self.current_version
    }
    /// `ImportedLibrary.getImportedSymbolCount()`.
    pub fn imported_symbol_count(&self) -> i32 {
        self.imported_symbol_count
    }
    /// `ImportedLibrary.getFirstImportedSymbol()`.
    pub fn first_imported_symbol(&self) -> i32 {
        self.first_imported_symbol
    }
    /// `ImportedLibrary.getOptions()`.
    pub fn options(&self) -> i8 {
        self.options
    }
    /// `ImportedLibrary.getReservedA()`.
    pub fn reserved_a(&self) -> i8 {
        self.reserved_a
    }
    /// `ImportedLibrary.getReservedB()`.
    pub fn reserved_b(&self) -> i16 {
        self.reserved_b
    }
}

/// Placeholder for `ghidra.app.util.bin.format.pef.ImportedSymbol`, referenced by
/// [`LoaderInfoHeader`](crate::format::pef::loader_info_header::LoaderInfoHeader) before the real
/// class is ported. Parses the packed 4-byte symbol-class/name-offset word; the symbol name
/// (read via an absolute offset into the loader string table) is left for the real port.
pub struct ImportedSymbol {
    symbol_class: i32,
    symbol_name_offset: i32,
}

impl ImportedSymbol {
    /// Port of `ImportedSymbol(BinaryReader, LoaderInfoHeader)`, minus the name lookup.
    pub fn new(
        reader: &mut dyn crate::app::util::bin::binary_reader::BinaryReader,
        _loader: &crate::format::pef::loader_info_header::LoaderInfoHeader,
    ) -> std::io::Result<Self> {
        let value = reader.read_next_int()?;
        Ok(ImportedSymbol {
            symbol_class: ((value as u32) >> 24) as i32,
            symbol_name_offset: value & 0x00ff_ffff,
        })
    }

    /// `ImportedSymbol.getSymbolClass()`'s underlying raw class byte (before masking to the low
    /// nibble that `SymbolClass.get` expects).
    pub fn symbol_class(&self) -> i32 {
        self.symbol_class
    }
    /// `ImportedSymbol.getSymbolNameOffset()`.
    pub fn symbol_name_offset(&self) -> i32 {
        self.symbol_name_offset
    }
}

/// Placeholder for `ghidra.app.util.bin.format.pef.ExportedSymbolHashSlot`, referenced by
/// [`LoaderInfoHeader`](crate::format::pef::loader_info_header::LoaderInfoHeader) before the real
/// class is ported.
pub struct ExportedSymbolHashSlot {
    symbol_count: i32,
    index_of_first_export_key: i32,
}

impl ExportedSymbolHashSlot {
    /// Port of `ExportedSymbolHashSlot(BinaryReader)`.
    pub fn new(
        reader: &mut dyn crate::app::util::bin::binary_reader::BinaryReader,
    ) -> std::io::Result<Self> {
        let count_and_start = reader.read_next_int()?;
        Ok(ExportedSymbolHashSlot {
            symbol_count: count_and_start >> 18,
            index_of_first_export_key: count_and_start & 0x12,
        })
    }

    /// `ExportedSymbolHashSlot.getSymbolCount()`.
    pub fn symbol_count(&self) -> i32 {
        self.symbol_count
    }
    /// `ExportedSymbolHashSlot.getIndexOfFirstExportKey()`.
    pub fn index_of_first_export_key(&self) -> i32 {
        self.index_of_first_export_key
    }
}

/// Placeholder for `ghidra.app.util.bin.format.pef.ExportedSymbolKey`, referenced by
/// [`LoaderInfoHeader`](crate::format::pef::loader_info_header::LoaderInfoHeader) before the real
/// class is ported.
pub struct ExportedSymbolKey {
    full_hash_word: i32,
    name_length: i16,
    hash_value: i16,
}

impl ExportedSymbolKey {
    /// Port of `ExportedSymbolKey(BinaryReader)`.
    pub fn new(
        reader: &mut dyn crate::app::util::bin::binary_reader::BinaryReader,
    ) -> std::io::Result<Self> {
        let value = reader.read_next_int()?;
        Ok(ExportedSymbolKey {
            full_hash_word: value,
            name_length: (value >> 16) as i16,
            hash_value: (value & 0xffff) as i16,
        })
    }

    /// `ExportedSymbolKey.getFullHashWord()`.
    pub fn full_hash_word(&self) -> i32 {
        self.full_hash_word
    }
    /// `ExportedSymbolKey.getNameLength()`.
    pub fn name_length(&self) -> i16 {
        self.name_length
    }
    /// `ExportedSymbolKey.getHashValue()`.
    pub fn hash_value(&self) -> i16 {
        self.hash_value
    }
}

/// Placeholder for `ghidra.app.util.bin.format.pef.ExportedSymbol`, referenced by
/// [`LoaderInfoHeader`](crate::format::pef::loader_info_header::LoaderInfoHeader) before the real
/// class is ported. Parses the fixed 10-byte header fields; the symbol name (read via an
/// absolute offset into the loader string table, using `key.getNameLength()` as the read length)
/// is left for the real port.
pub struct ExportedSymbol {
    class_and_name: i32,
    symbol_value: i32,
    section_index: i16,
}

impl ExportedSymbol {
    /// Port of `ExportedSymbol(BinaryReader, LoaderInfoHeader, ExportedSymbolKey)`, minus the
    /// name lookup.
    pub fn new(
        reader: &mut dyn crate::app::util::bin::binary_reader::BinaryReader,
        _loader: &crate::format::pef::loader_info_header::LoaderInfoHeader,
        _key: &ExportedSymbolKey,
    ) -> std::io::Result<Self> {
        Ok(ExportedSymbol {
            class_and_name: reader.read_next_int()?,
            symbol_value: reader.read_next_int()?,
            section_index: reader.read_next_short()?,
        })
    }

    /// `ExportedSymbol.getNameOffset()`.
    pub fn name_offset(&self) -> i32 {
        self.class_and_name & 0x00ff_ffff
    }
    /// `ExportedSymbol.getSymbolValue()`.
    pub fn symbol_value(&self) -> i32 {
        self.symbol_value
    }
    /// `ExportedSymbol.getSectionIndex()`.
    pub fn section_index(&self) -> i16 {
        self.section_index
    }
}

/// Placeholder for `ghidra.app.util.bin.format.pef.RelocationFactory`, referenced by
/// [`LoaderRelocationHeader`](crate::format::pef::loader_relocation_header::LoaderRelocationHeader)
/// before the real class is ported. `RelocationFactory` is a concrete Java class (not an
/// interface) whose single static method dispatches across ten `Reloc*` relocation-opcode
/// subclasses (`RelocByIndexGroup`, `RelocBySectDWithSkip`, `RelocIncrPosition`,
/// `RelocLgByImport`, `RelocLgRepeat`, `RelocLgSetOrBySection`, `RelocSetPosition`,
/// `RelocSmRepeat`, `RelocUndefinedOpcode`, `RelocValueGroup`), none of which are ported yet, so
/// this stub cannot yet replicate the real dispatch/match logic. It exists so
/// `LoaderRelocationHeader`'s constructor compiles and works for the (common) `relocCount == 0`
/// case, which never calls it.
pub struct RelocationFactory;

impl RelocationFactory {
    /// Placeholder for `RelocationFactory.getRelocation(BinaryReader)`.
    ///
    /// # Panics
    /// Always panics: none of the ten `Reloc*` relocation-opcode subclasses this dispatches to
    /// are ported yet, so there is nothing to construct/match against.
    pub fn get_relocation(
        _reader: &mut dyn crate::app::util::bin::binary_reader::BinaryReader,
    ) -> crate::program::model::reloc::relocation::Relocation {
        unimplemented!("RelocationFactory.getRelocation: PEF Reloc* opcode subclasses not yet ported")
    }
}

/// Placeholder for `ghidra.app.util.bin.StructConverterUtil`, referenced by `StructConverter`
/// implementors (e.g.
/// [`LoaderRelocationHeader`](crate::format::pef::loader_relocation_header::LoaderRelocationHeader))
/// whose Java `toDataType()` delegates to `StructConverterUtil.toDataType(getClass())`.
/// `StructConverterUtil` is a concrete Java class (not an interface) that reflects over an
/// object's private fields to build a `Structure` datatype; reflection has no Rust equivalent, so
/// this stub instead builds an opaquely-named placeholder `DataType` with the caller-supplied
/// name and byte length, mirroring the precedent set by `OmfIndex`'s placeholder datatypes
/// (`format::omf::omf_index`).
pub struct StructConverterUtilDataType {
    name: String,
    length: i32,
}

impl StructConverterUtilDataType {
    /// Placeholder for `StructConverterUtil.toDataType(Class)` (called as
    /// `StructConverterUtil.toDataType(getClass())` from a `StructConverter` implementor).
    pub fn to_data_type(name: impl Into<String>, length: i32) -> Self {
        StructConverterUtilDataType { name: name.into(), length }
    }
}

impl crate::program::model::data::data_type::DataType for StructConverterUtilDataType {
    fn get_name(&self) -> String {
        self.name.clone()
    }

    fn get_length(&self) -> i32 {
        self.length
    }
}

// ---------------------------------------------------------------------------
// ghidra.app.util.bin.format.unixaout
//
// The a.out header and its three file tables are referenced by
// [`UnixAoutProgramLoader`](crate::app::util::opinion::unix_aout_program_loader::UnixAoutProgramLoader)
// before those classes are ported. Each stub below models only the members that loader touches.
// `UnixAoutSymbol` itself is already ported, so it is used directly rather than stubbed.
// ---------------------------------------------------------------------------

/// Placeholder for the `UnixAoutHeader.AoutType` enum.
///
/// Only [`name`](AoutType::name) is modeled: `UnixAoutProgramLoader.loadAout` logs
/// `header.getExecutableType().name()`, which for a Java enum is its constant's identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AoutType {
    Omagic,
    Nmagic,
    Zmagic,
    Qmagic,
    Cmagic,
    Unknown,
}

impl AoutType {
    /// Java `Enum.name()` -- the constant's identifier, which a.out spells in upper case.
    pub fn name(self) -> &'static str {
        match self {
            AoutType::Omagic => "OMAGIC",
            AoutType::Nmagic => "NMAGIC",
            AoutType::Zmagic => "ZMAGIC",
            AoutType::Qmagic => "QMAGIC",
            AoutType::Cmagic => "CMAGIC",
            AoutType::Unknown => "UNKNOWN",
        }
    }
}

/// Placeholder for `ghidra.app.util.bin.format.unixaout.UnixAoutHeader`, referenced by
/// [`UnixAoutProgramLoader`](crate::app::util::opinion::unix_aout_program_loader::UnixAoutProgramLoader)
/// before the real class is ported. Models the section-geometry accessors, the executable type,
/// the reader the loader builds its tables from, and `markup`.
///
/// Not `Send + Sync`: Java's header owns the `BinaryReader` it was parsed from, and this crate's
/// ported [`GBinaryReader`] holds its provider in an `Rc<RefCell<_>>`.
pub trait UnixAoutHeader {
    /// `UnixAoutHeader.getReader()`. Java hands back the single reader the header was parsed
    /// with; because that reader is a concrete ported type here, implementors return an
    /// equivalent reader over the same provider instead of a borrow of a stored one. Every
    /// caller in the loader either re-positions the reader itself (the table constructors) or
    /// only reaches through it for the provider, so a fresh reader behaves identically.
    fn get_reader(&self) -> GBinaryReader;

    fn get_executable_type(&self) -> AoutType;

    fn get_text_size(&self) -> i64;
    fn get_data_size(&self) -> i64;
    fn get_bss_size(&self) -> i64;
    fn get_sym_size(&self) -> i64;
    fn get_str_size(&self) -> i64;
    fn get_entry_point(&self) -> i64;
    fn get_text_reloc_size(&self) -> i64;
    fn get_data_reloc_size(&self) -> i64;
    fn get_text_offset(&self) -> i64;
    fn get_data_offset(&self) -> i64;
    fn get_text_reloc_offset(&self) -> i64;
    fn get_data_reloc_offset(&self) -> i64;
    fn get_sym_offset(&self) -> i64;
    fn get_str_offset(&self) -> i64;
    fn get_text_addr(&self) -> i64;
    fn get_data_addr(&self) -> i64;
    fn get_bss_addr(&self) -> i64;

    /// `UnixAoutHeader.markup(Program, Address)`. Takes `&mut dyn Program` rather than Java's
    /// `Program`, because the real body reaches `program.getListing()` to create data, and this
    /// crate's [`Program::get_listing`] requires a mutable borrow.
    fn markup(
        &self,
        program: &mut dyn ListingProgram,
        header_address: &Address,
    ) -> std::io::Result<()>;
}

/// Placeholder for `ghidra.app.util.bin.format.unixaout.UnixAoutStringTable`.
pub trait UnixAoutStringTable {
    /// `UnixAoutStringTable.readString(long)`; `None` stands in for Java's `null` return.
    fn read_string(&self, string_offset: u64) -> Option<String>;

    /// `UnixAoutStringTable.markup(Program, MemoryBlock)`. See [`UnixAoutHeader::markup`] for why
    /// `program` is `&mut`.
    fn markup(
        &self,
        program: &mut dyn ListingProgram,
        block: &dyn MemoryBlock,
    ) -> std::io::Result<()>;
}

/// Placeholder for `ghidra.app.util.bin.format.unixaout.UnixAoutSymbolTable`.
pub trait UnixAoutSymbolTable {
    /// `UnixAoutSymbolTable.iterator()` (the class implements `Iterable<UnixAoutSymbol>`).
    fn iterator(&self) -> Box<dyn Iterator<Item = &UnixAoutSymbol> + '_>;

    /// `UnixAoutSymbolTable.get(int)`. Java indexes a `List` and throws on an out-of-range index;
    /// the loader only ever calls this after a `symbolNum < size()` guard, so `None` stands in.
    fn get(&self, symbol_num: usize) -> Option<&UnixAoutSymbol>;

    /// `UnixAoutSymbolTable.size()` -- the number of entries, not a byte count.
    fn size(&self) -> u64;

    /// `UnixAoutSymbolTable.markup(Program, MemoryBlock)`. See [`UnixAoutHeader::markup`] for why
    /// `program` is `&mut`.
    fn markup(
        &self,
        program: &mut dyn ListingProgram,
        block: &dyn MemoryBlock,
    ) -> std::io::Result<()>;
}

/// Placeholder for `ghidra.app.util.bin.format.unixaout.UnixAoutRelocation`, a concrete Java class
/// whose fields are all public and read directly by
/// [`UnixAoutProgramLoader::apply_relocations`](crate::app::util::opinion::unix_aout_program_loader::UnixAoutProgramLoader).
/// Modeled as a struct (not a trait) to match that shape; the bit-field-decoding constructor
/// belongs to that class's own port and is not reproduced here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct UnixAoutRelocation {
    pub address: u64,
    pub symbol_num: u32,
    pub flags: u8,
    pub pc_relative_addressing: bool,
    pub pointer_length: u8,
    pub r#extern: bool,
    pub base_relative: bool,
    pub jmp_table: bool,
    pub relative: bool,
    pub copy: bool,
}

impl UnixAoutRelocation {
    /// `UnixAoutRelocation.getSymbolName(UnixAoutSymbolTable)`. Implemented rather than stubbed
    /// because the body is entirely made of members that already exist here, and the loader's
    /// relocation-table rows carry its result.
    pub fn get_symbol_name(&self, symtab: Option<&dyn UnixAoutSymbolTable>) -> Option<String> {
        if self.r#extern {
            let symtab = symtab?;
            if u64::from(self.symbol_num) < symtab.size() {
                return symtab.get(self.symbol_num as usize)?.name.clone();
            }
            return None;
        }

        match self.symbol_num {
            4 => Some(DOT_TEXT.to_string()),
            6 => Some(DOT_DATA.to_string()),
            8 => Some(DOT_BSS.to_string()),
            _ => None,
        }
    }
}

/// Placeholder for `ghidra.app.util.bin.format.unixaout.UnixAoutRelocationTable`.
pub trait UnixAoutRelocationTable {
    /// `UnixAoutRelocationTable.iterator()` (the class implements `Iterable<UnixAoutRelocation>`).
    fn iterator(&self) -> Box<dyn Iterator<Item = &UnixAoutRelocation> + '_>;

    /// `UnixAoutRelocationTable.markup(Program, MemoryBlock)`. See [`UnixAoutHeader::markup`] for
    /// why `program` is `&mut`.
    fn markup(
        &self,
        program: &mut dyn ListingProgram,
        block: &dyn MemoryBlock,
    ) -> std::io::Result<()>;
}

/// Constructors for the a.out file tables, standing in for the Java classes' own constructors
/// (`UnixAoutProgramLoader.buildTables` is the only caller). Each reads its table out of the
/// binary; that parsing belongs to those classes' ports, so these are not implemented yet.
pub mod unix_aout_tables {
    use super::{
        GBinaryReader, UnixAoutRelocationTable, UnixAoutStringTable, UnixAoutSymbolTable,
    };
    use crate::app::seam_stubs::MessageLog;

    /// `new UnixAoutStringTable(BinaryReader, long fileOffset, long fileSize)`.
    pub fn new_string_table(
        reader: GBinaryReader,
        file_offset: i64,
        file_size: i64,
    ) -> std::io::Result<Box<dyn UnixAoutStringTable>> {
        let _ = (reader, file_offset, file_size);
        unimplemented!("unix_aout_tables::new_string_table placeholder not overridden")
    }

    /// `new UnixAoutSymbolTable(BinaryReader, long fileOffset, long fileSize, UnixAoutStringTable,
    /// MessageLog)`.
    pub fn new_symbol_table(
        reader: GBinaryReader,
        file_offset: i64,
        file_size: i64,
        strtab: Option<&dyn UnixAoutStringTable>,
        log: &dyn MessageLog,
    ) -> std::io::Result<Box<dyn UnixAoutSymbolTable>> {
        let _ = (reader, file_offset, file_size, strtab, log);
        unimplemented!("unix_aout_tables::new_symbol_table placeholder not overridden")
    }

    /// `new UnixAoutRelocationTable(BinaryReader, long fileOffset, long fileSize,
    /// UnixAoutSymbolTable)`.
    pub fn new_relocation_table(
        reader: GBinaryReader,
        file_offset: i64,
        file_size: i64,
        symtab: Option<&dyn UnixAoutSymbolTable>,
    ) -> std::io::Result<Box<dyn UnixAoutRelocationTable>> {
        let _ = (reader, file_offset, file_size, symtab);
        unimplemented!("unix_aout_tables::new_relocation_table placeholder not overridden")
    }
}

/// Which concrete `attribute_info` subclass
/// [`AttributeFactory::get`](crate::format::javaclass::attributes::attribute_factory::get) would
/// have constructed. Stands in for the ~25 still-unported concrete Java classes
/// (`AnnotationDefaultAttribute`, `BootstrapMethodsAttribute`, `CodeAttribute`,
/// `ConstantValueAttribute`, `DeprecatedAttribute`, `EnclosingMethodAttribute`,
/// `ExceptionsAttribute`, `InnerClassesAttribute`, `LineNumberTableAttribute`,
/// `LocalVariableTableAttribute`, `LocalVariableTypeTableAttribute`, `MethodParametersAttribute`,
/// `ModuleAttribute`, `ModuleMainClassAttribute`, `ModulePackagesAttribute`, `NestHostAttribute`,
/// `NestMembersAttribute`, `RuntimeInvisibleAnnotationsAttribute`,
/// `RuntimeParameterAnnotationsAttribute` (both parameter-annotation variants),
/// `RuntimeVisibleAnnotationsAttribute`, `SignatureAttribute`, `SourceDebugExtensionAttribute`,
/// `SourceFileAttribute`, `StackMapTableAttribute`, `SyntheticAttribute`, and
/// `UnsupportedAttributeInfo`) that `AttributeFactory` dispatches to by attribute name. None of
/// their attribute-specific fields are needed by `AttributeFactory` itself, so only the
/// discriminant is modeled here; each variant is expected to be replaced by the real ported type
/// once that Java class is ported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttributeInfoKind {
    AnnotationDefault,
    BootstrapMethods,
    Code,
    ConstantValue,
    Deprecated,
    EnclosingMethod,
    Exceptions,
    InnerClasses,
    LineNumberTable,
    LocalVariableTable,
    LocalVariableTypeTable,
    MethodParameters,
    Module,
    ModuleMainClass,
    ModulePackages,
    NestHost,
    NestMembers,
    RuntimeInvisibleAnnotations,
    RuntimeInvisibleParameterAnnotations,
    RuntimeVisibleAnnotations,
    RuntimeVisibleParameterAnnotations,
    Signature,
    SourceDebugExtension,
    SourceFile,
    StackMapTable,
    Synthetic,
    Unsupported,
}

/// Placeholder for `ghidra.javaclass.format.attributes.AbstractAttributeInfo`, the common base
/// every JVM class file `attribute_info` structure extends, referenced by
/// [`AttributeFactory::get`](crate::format::javaclass::attributes::attribute_factory::get) as its
/// return type before any of the ~25 concrete subclasses are ported. `AbstractAttributeInfo` is a
/// concrete Java class (not an interface), so it is modeled here as a concrete struct rather than
/// a trait object. Models only the common 6-byte `attribute_info` header
/// (`attribute_name_index` + `attribute_length`) that every subclass constructor reads via
/// `super(reader)`, tagged with [`AttributeInfoKind`] to record which subclass would have been
/// constructed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AbstractAttributeInfo {
    offset: u64,
    attribute_name_index: u32,
    attribute_length: i32,
    kind: AttributeInfoKind,
}

impl AbstractAttributeInfo {
    /// Reads the common `attribute_info` header (`u2 attribute_name_index; u4 attribute_length;`)
    /// starting at the reader's current position, mirroring
    /// `AbstractAttributeInfo(BinaryReader)`. Since no concrete subclass is ported yet to parse
    /// the attribute-specific `info[attribute_length]` payload that follows, this generic stub
    /// skips over it directly so the reader ends up correctly positioned at the start of the next
    /// attribute, matching where a real subclass constructor would have left it.
    pub fn new(
        reader: &mut dyn crate::app::util::bin::binary_reader::BinaryReader,
        kind: AttributeInfoKind,
    ) -> std::io::Result<Self> {
        let offset = reader.get_pointer_index();
        let attribute_name_index = reader.read_next_unsigned_short()?;
        let attribute_length = reader.read_next_int()?;

        if attribute_length > 0 {
            let next = reader.get_pointer_index() + attribute_length as u64;
            reader.set_pointer_index(next);
        }

        Ok(AbstractAttributeInfo { offset, attribute_name_index, attribute_length, kind })
    }

    /// `AbstractAttributeInfo.getOffset()`.
    pub fn get_offset(&self) -> u64 {
        self.offset
    }

    /// `AbstractAttributeInfo.getAttributeNameIndex()` (already masked to an unsigned 16-bit
    /// value, matching the Java getter's `& 0xffff`).
    pub fn get_attribute_name_index(&self) -> u32 {
        self.attribute_name_index
    }

    /// `AbstractAttributeInfo.getAttributeLength()`.
    pub fn get_attribute_length(&self) -> i32 {
        self.attribute_length
    }

    /// Not present on the Java base class; records which concrete subclass this placeholder
    /// stands in for. See [`AttributeInfoKind`].
    pub fn kind(&self) -> AttributeInfoKind {
        self.kind
    }
}

/// Placeholder for `ghidra.javaclass.format.constantpool.ConstantPoolUtf8Info`, referenced by
/// [`AttributeFactory::get`](crate::format::javaclass::attributes::attribute_factory::get) to
/// resolve an attribute's name. `ConstantPoolUtf8Info` is a concrete Java class extending the
/// already-ported
/// [`AbstractConstantPoolInfoJava`](crate::format::javaclass::constantpool::abstract_constant_pool_info_java::AbstractConstantPoolInfoJava)
/// (not an interface), so it is modeled here as a concrete struct. `AbstractConstantPoolInfoJava`
/// was ported without its subclasses' data (only `offset`/`tag`), so this stub re-derives the
/// UTF-8 string on demand straight from the class file bytes at the entry's offset (`u1 tag; u2
/// length; u1 bytes[length];`) rather than caching it at constant-pool-build time like the real
/// class does.
pub struct ConstantPoolUtf8Info {
    string: String,
}

impl ConstantPoolUtf8Info {
    /// Reads the `length` + `bytes` fields of a `CONSTANT_Utf8_info` entry directly from
    /// `reader`, given the already-parsed `entry` (whose `offset` points at the entry's `tag`
    /// byte). Caller must have already verified `entry.get_tag() ==
    /// constant_pool_tags_java::CONSTANT_UTF8`.
    pub fn from_entry(
        reader: &dyn crate::app::util::bin::binary_reader::BinaryReader,
        entry: &crate::format::javaclass::constantpool::abstract_constant_pool_info_java::AbstractConstantPoolInfoJava,
    ) -> std::io::Result<Self> {
        let length = reader.read_unsigned_short(entry.get_offset() + 1)? as usize;
        let string = reader.read_utf8_string_fixed(entry.get_offset() + 3, length)?;
        Ok(ConstantPoolUtf8Info { string })
    }

    /// `ConstantPoolUtf8Info.getString()`.
    pub fn get_string(&self) -> &str {
        &self.string
    }
}

/// Placeholder for `ghidra.javaclass.format.attributes.AnnotationJava`, referenced by
/// [`AnnotationElementValue`](crate::format::javaclass::attributes::annotation_element_value::AnnotationElementValue)
/// as a forward reference: `AnnotationJava` is mutually recursive with
/// `AnnotationElementValue` through the not-yet-ported `AnnotationElementValuePair`
/// (`AnnotationJava` -> `AnnotationElementValuePair` -> `AnnotationElementValue`). `AnnotationJava`
/// is a concrete Java class (not an interface), so it is modeled here as a concrete struct. Only
/// the `type_index`/`number_of_element_value_pairs` header (`u2 type_index; u2
/// num_element_value_pairs;`) is read; the nested `element_value_pairs` table needs
/// `AnnotationElementValuePair`, so it is left unparsed (and, since its encoded size cannot be
/// computed without decoding it, an annotation-tagged `element_value` nested inside another
/// `element_value` array cannot be read past this header until that type lands).
pub struct AnnotationJava {
    type_index: u32,
    number_of_element_value_pairs: u32,
}

impl AnnotationJava {
    /// Reads the `annotation` header, mirroring `AnnotationJava(BinaryReader)`.
    pub fn new(
        reader: &mut dyn crate::app::util::bin::binary_reader::BinaryReader,
    ) -> std::io::Result<Self> {
        let type_index = reader.read_next_unsigned_short()?;
        let number_of_element_value_pairs = reader.read_next_unsigned_short()?;
        Ok(AnnotationJava { type_index, number_of_element_value_pairs })
    }

    /// `AnnotationJava.getTypeIndex()` (already masked to an unsigned 16-bit value, matching the
    /// Java getter's `& 0xffff`).
    pub fn get_type_index(&self) -> u32 {
        self.type_index
    }

    /// `AnnotationJava.getNumberOfElementValuePairs()` (already masked to an unsigned 16-bit
    /// value, matching the Java getter's `& 0xffff`).
    pub fn get_number_of_element_value_pairs(&self) -> u32 {
        self.number_of_element_value_pairs
    }
}

/// Placeholder for the nested enum `TransientProgramProperties.SCOPE`, referenced by
/// [`TransientProgramProperties::get_property`] before the real class is ported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransientPropertyScope {
    /// Value is released when the program is closed.
    Program,
    /// Value is released when the current analysis session is finished.
    AnalysisSession,
}

type TransientPropertyKey = (usize, std::any::TypeId);

static TRANSIENT_PROPERTIES: std::sync::OnceLock<
    std::sync::Mutex<
        std::collections::HashMap<TransientPropertyKey, std::sync::Arc<dyn std::any::Any + Send + Sync>>,
    >,
> = std::sync::OnceLock::new();

fn transient_properties_map() -> &'static std::sync::Mutex<
    std::collections::HashMap<TransientPropertyKey, std::sync::Arc<dyn std::any::Any + Send + Sync>>,
> {
    TRANSIENT_PROPERTIES.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

/// Placeholder for `ghidra.app.plugin.core.analysis.TransientProgramProperties`, referenced by
/// [`ClassFileAnalysisState::get_state`](crate::format::javaclass::class_file_analysis_state::ClassFileAnalysisState::get_state)
/// before the real class is ported. `TransientProgramProperties` is a concrete Java class (not an
/// interface), so it is modeled here as a zero-sized type backed by a process-global cache,
/// consistent with the `OnceLock<Mutex<HashMap<..>>>` pattern used elsewhere in this crate (see
/// [`ClassTranslator`](crate::util::classfinder::class_translator::ClassTranslator)). Only
/// `getProperty` is modeled -- the only member `ClassFileAnalysisState.getState` needs -- and its
/// generic `key`/`clazz` parameters are collapsed into the single type parameter `T`, matching
/// that call site (which always uses the value's own type as both). The real class additionally
/// releases `AnalysisSession`-scoped properties when analysis ends and `Program`-scoped
/// properties when the program closes; neither release path is modeled here, so cached values
/// live for the process's lifetime.
pub struct TransientProgramProperties;

impl TransientProgramProperties {
    /// Mirrors `TransientProgramProperties.getProperty(Program, Object, SCOPE, Class,
    /// PropertyValueSupplier)`. Returns the cached value for `program`, if present; otherwise
    /// calls `supplier` to create it, caches it, and returns it.
    pub fn get_property<T, E>(
        program: &std::sync::Arc<dyn ListingProgram>,
        _scope: TransientPropertyScope,
        supplier: impl FnOnce() -> Result<T, E>,
    ) -> Result<std::sync::Arc<T>, E>
    where
        T: std::any::Any + Send + Sync,
    {
        let key: TransientPropertyKey =
            (std::sync::Arc::as_ptr(program) as *const () as usize, std::any::TypeId::of::<T>());

        {
            let map = transient_properties_map().lock().unwrap();
            if let Some(existing) = map.get(&key) {
                if let Ok(value) = std::sync::Arc::clone(existing).downcast::<T>() {
                    return Ok(value);
                }
            }
        }

        let value = std::sync::Arc::new(supplier()?);
        let mut map = transient_properties_map().lock().unwrap();
        let entry = map
            .entry(key)
            .or_insert_with(|| value.clone() as std::sync::Arc<dyn std::any::Any + Send + Sync>);
        Ok(std::sync::Arc::clone(entry)
            .downcast::<T>()
            .expect("TransientProgramProperties: type mismatch for cached property"))
    }
}

/// Placeholder for `ghidra.javaclass.format.attributes.CodeAttribute`, referenced by
/// [`MethodInfoJava::get_code_attribute`] and
/// [`JavaLoader`](crate::app::util::opinion::java_loader::JavaLoader) before the real class is
/// ported. `CodeAttribute` is a concrete Java class (not an interface), so it is modeled here as
/// a concrete struct. `JavaLoader.createMethodMemoryBlocks` only ever reads
/// `getCodeLength()`/`getCodeOffset()`, so only those two fields (of the `Code_attribute`
/// structure's `max_stack`/`max_locals`/`code_length`/`code[]`/exception table/attributes) are
/// modeled; the rest needs `AttributeFactory`'s constant-pool-driven parsing and is left for the
/// real port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodeAttribute {
    code_length: i32,
    code_offset: i64,
}

impl CodeAttribute {
    pub fn new(code_length: i32, code_offset: i64) -> Self {
        CodeAttribute { code_length, code_offset }
    }

    /// `CodeAttribute.getCodeLength()`.
    pub fn get_code_length(&self) -> i32 {
        self.code_length
    }

    /// `CodeAttribute.getCodeOffset()`.
    pub fn get_code_offset(&self) -> i64 {
        self.code_offset
    }
}

/// Placeholder for `ghidra.javaclass.format.MethodInfoJava`, referenced by
/// [`ClassFileJava::get_methods`],
/// [`ClassFileAnalysisState`](crate::format::javaclass::class_file_analysis_state::ClassFileAnalysisState),
/// and [`JavaLoader`](crate::app::util::opinion::java_loader::JavaLoader) before the real class is
/// ported. `MethodInfoJava` is a concrete Java class (not an interface), so it is modeled here as
/// a concrete struct. `ClassFileAnalysisState` only ever stored and returned these opaquely (keyed
/// by address in its method map), so this stub originally kept only the file offset; grown here
/// with `name_index`/`descriptor_index`/`code_attribute` for `JavaLoader`, which additionally
/// resolves each method's name and code bytes. The rest of the real class (access flags,
/// attributes, `toDataType`) still needs `AttributeFactory`'s constant-pool-driven parsing and is
/// left for the real port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MethodInfoJava {
    offset: i64,
    name_index: i32,
    descriptor_index: i32,
    code_attribute: Option<CodeAttribute>,
}

impl MethodInfoJava {
    /// Constructs a `MethodInfoJava` with only its file offset set, as used by
    /// [`ClassFileAnalysisState`](crate::format::javaclass::class_file_analysis_state::ClassFileAnalysisState),
    /// which never inspects the other fields.
    pub fn new(offset: i64) -> Self {
        MethodInfoJava { offset, name_index: 0, descriptor_index: 0, code_attribute: None }
    }

    /// Constructs a `MethodInfoJava` with every field this stub models, as used by
    /// [`JavaLoader`](crate::app::util::opinion::java_loader::JavaLoader).
    pub fn with_details(
        offset: i64,
        name_index: i32,
        descriptor_index: i32,
        code_attribute: Option<CodeAttribute>,
    ) -> Self {
        MethodInfoJava { offset, name_index, descriptor_index, code_attribute }
    }

    /// `MethodInfoJava.getOffset()`.
    pub fn get_offset(&self) -> i64 {
        self.offset
    }

    /// `MethodInfoJava.getNameIndex()`.
    pub fn get_name_index(&self) -> i32 {
        self.name_index
    }

    /// `MethodInfoJava.getDescriptorIndex()`.
    pub fn get_descriptor_index(&self) -> i32 {
        self.descriptor_index
    }

    /// `MethodInfoJava.getCodeAttribute()`.
    pub fn get_code_attribute(&self) -> Option<CodeAttribute> {
        self.code_attribute
    }
}

/// Placeholder for `ghidra.javaclass.format.ClassFileJava`, referenced by
/// [`ClassFileAnalysisState`](crate::format::javaclass::class_file_analysis_state::ClassFileAnalysisState)
/// and [`JavaLoader`](crate::app::util::opinion::java_loader::JavaLoader) before the real class is
/// ported. `ClassFileJava` is a concrete Java class (not an interface), so it is modeled here as a
/// concrete struct. Both callers only ever construct one from a reader and walk
/// [`get_methods`](Self::get_methods) (`JavaLoader` additionally reads
/// [`get_constant_pool`](Self::get_constant_pool)), so only that surface is modeled; the real
/// constructor parses the whole class file format (constant pool, fields, attributes), which
/// needs `AttributeFactory` and the concrete `ConstantPoolInfoJava` variants that aren't ported
/// yet, so this stub's constructor consumes nothing from `reader` and reports an empty constant
/// pool and zero methods, deferring real parsing to the eventual `ClassFileJava` port.
pub struct ClassFileJava {
    constant_pool: Vec<
        crate::format::javaclass::constantpool::abstract_constant_pool_info_java::AbstractConstantPoolInfoJava,
    >,
    methods: Vec<MethodInfoJava>,
}

impl ClassFileJava {
    /// Mirrors `ClassFileJava(BinaryReader)`. See the type-level doc for why this does not yet
    /// parse the class file format.
    pub fn new(
        reader: &mut dyn crate::app::util::bin::binary_reader::BinaryReader,
    ) -> std::io::Result<Self> {
        let _ = reader;
        Ok(ClassFileJava { constant_pool: Vec::new(), methods: Vec::new() })
    }

    /// Test-only constructor bypassing byte parsing, used to exercise
    /// [`ClassFileAnalysisState::build_method_map`](crate::format::javaclass::class_file_analysis_state::ClassFileAnalysisState)
    /// without a real class file parser.
    #[cfg(test)]
    pub fn from_methods(methods: Vec<MethodInfoJava>) -> Self {
        ClassFileJava { constant_pool: Vec::new(), methods }
    }

    /// Test-only constructor additionally carrying a constant pool, used to exercise
    /// [`JavaLoader`](crate::app::util::opinion::java_loader::JavaLoader) without a real class
    /// file parser.
    #[cfg(test)]
    pub fn from_constant_pool_and_methods(
        constant_pool: Vec<
            crate::format::javaclass::constantpool::abstract_constant_pool_info_java::AbstractConstantPoolInfoJava,
        >,
        methods: Vec<MethodInfoJava>,
    ) -> Self {
        ClassFileJava { constant_pool, methods }
    }

    /// `ClassFileJava.getMethods()`.
    pub fn get_methods(&self) -> &[MethodInfoJava] {
        &self.methods
    }

    /// `ClassFileJava.getConstantPool()`.
    pub fn get_constant_pool(
        &self,
    ) -> &[crate::format::javaclass::constantpool::abstract_constant_pool_info_java::AbstractConstantPoolInfoJava]
    {
        &self.constant_pool
    }
}

/// Placeholder for `ghidra.javaclass.format.JavaClassUtil`, referenced by
/// [`ClassFileAnalysisState`](crate::format::javaclass::class_file_analysis_state::ClassFileAnalysisState)
/// and [`JavaLoader`](crate::app::util::opinion::java_loader::JavaLoader) before the real class is
/// ported. `JavaClassUtil` is a concrete Java class (not an interface, and in fact a utility class
/// of only static members), so it is modeled here as a zero-sized type with associated
/// functions/constants. `isClassFile` is unused by either caller and left for the real port.
pub struct JavaClassUtil;

impl JavaClassUtil {
    /// `JavaClassUtil.LOOKUP_ADDRESS`.
    pub const LOOKUP_ADDRESS: i64 = 0xE0000000;

    /// `JavaClassUtil.METHOD_INDEX_SIZE`: 65536 is the maximum size of the `methods_count` item
    /// in a class file.
    pub const METHOD_INDEX_SIZE: u64 = 65536 * 4;

    /// `JavaClassUtil.toLookupAddress(Program, int)`. `methodIndex * 4` mirrors Java's 32-bit
    /// (wrapping) int multiplication before the sign-extending widen to `long`.
    pub fn to_lookup_address(
        program: &dyn ListingProgram,
        method_index: i32,
    ) -> crate::program::model::address::Address {
        let address_factory = program
            .get_address_factory()
            .expect("JavaClassUtil.toLookupAddress: program has no address factory");
        let default_address_space = address_factory
            .get_default_address_space()
            .expect("JavaClassUtil.toLookupAddress: program has no default address space");
        default_address_space.address(Self::LOOKUP_ADDRESS + method_index.wrapping_mul(4) as i64)
    }
}

/// Placeholder for the unported Java type `DWARFCompilationUnit`, referenced by
/// `DWARFAttributeValue` and `DWARFLine`. Only includes the methods actually needed by those
/// types. Everything except `get_dwarf_version` has a stub default so that test doubles which
/// only model a version number keep compiling; the real port will supply all of them.
pub trait DWARFCompilationUnit: Send + Sync {
    fn get_dwarf_version(&self) -> i16;

    /// Mirrors `DWARFCompilationUnit.getIntSize()` (inherited from `DWARFUnitHeader.getIntSize()`),
    /// referenced by `DWARFFormContext`'s compact constructor. Defaults to 4 (DWARF_32), the
    /// common case, so test doubles that don't model 64-bit DWARF keep compiling.
    fn get_int_size(&self) -> i32 {
        4
    }

    /// Mirrors `DWARFCompilationUnit.getCompileDirectory()`, which returns `null` when the
    /// compilation unit has no `DW_AT_comp_dir`.
    fn get_compile_directory(&self) -> Option<String> {
        None
    }

    /// Mirrors `DWARFCompilationUnit.getPointerSize()`.
    fn get_pointer_size(&self) -> i8 {
        0
    }

    /// Mirrors `DWARFCompilationUnit.getProgram()`. The real method never returns `null`; the
    /// `Option` here only exists so stub implementations that don't model a `DWARFProgram` can
    /// return `None`.
    fn get_program(&self) -> Option<&dyn DWARFProgram> {
        None
    }

    /// Mirrors `DWARFCompilationUnit.getDIEContainer()`. As with `get_program`, the `Option` is
    /// only for stub implementations that don't model a container.
    fn get_die_container(&self) -> Option<&dyn DIEContainer> {
        None
    }

    /// Mirrors `DWARFCompilationUnit.getPCRange()`, referenced by
    /// [`DWARFLocationList::read_v4`](crate::format::dwarf::dwarf_location_list::DWARFLocationList::read_v4)
    /// and `read_v5` as the initial base address. Defaults to [`DWARFRange::EMPTY`] so existing
    /// test doubles that don't model a PC range keep compiling.
    fn get_pc_range(&self) -> DWARFRange {
        DWARFRange::EMPTY
    }

    /// Mirrors `DWARFCompilationUnit.getAbbreviation(int)`, which returns `null` when the
    /// compilation unit's abbreviation table has no entry for that code. The abbreviation is
    /// shared by every DIE that uses it, hence the [`Arc`](std::sync::Arc).
    fn get_abbreviation(&self, _ac: i32) -> Option<std::sync::Arc<DWARFAbbreviation>> {
        None
    }

    /// Mirrors `DWARFCompilationUnit.getLine()`, the line table this compilation unit's
    /// `DW_AT_stmt_list` points at, referenced by
    /// [`DIEAggregate::get_source_file`](crate::format::dwarf::die_aggregate::DIEAggregate::get_source_file).
    /// `None` stands in for a compilation unit with no line table.
    fn get_line(&self) -> Option<&crate::format::dwarf::line::dwarf_line::DWARFLine> {
        None
    }

    /// Mirrors `DWARFUnitHeader.getUnitNumber()`, which `DebugInfoEntry::read` only uses to
    /// describe a bad abbreviation code.
    fn get_unit_number(&self) -> i32 {
        0
    }

    /// Mirrors `DWARFUnitHeader.getStartOffset()`, used alongside `get_unit_number` in the same
    /// error message.
    fn get_start_offset(&self) -> u64 {
        0
    }
}

/// Placeholder for `DWARFCompilationUnit.readV4(DWARFUnitHeader, BinaryReader)`, the forward
/// cycle edge from
/// [`DWARFUnitHeader::read`](crate::format::dwarf::dwarf_unit_header::DWARFUnitHeader::read):
/// `DWARFCompilationUnit` is `DWARFUnitHeader`'s single subclass and has not been ported yet, so
/// there is no real implementation to dispatch to. Returns an "unsupported" error until
/// `DWARFCompilationUnit` is ported and this call site is updated to its real factory method.
pub fn dwarf_compilation_unit_read_v4(
    partial: crate::format::dwarf::dwarf_unit_header::DWARFUnitHeader,
    _reader: &mut dyn crate::app::util::bin::binary_reader::BinaryReader,
) -> std::io::Result<Box<dyn DWARFCompilationUnit>> {
    let _ = partial;
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "DWARFCompilationUnit.readV4 is not yet implemented (DWARFCompilationUnit has not been ported)",
    ))
}

/// Placeholder for `DWARFCompilationUnit.readV5(DWARFUnitHeader, BinaryReader)`, the DWARF5
/// counterpart of [`dwarf_compilation_unit_read_v4`].
pub fn dwarf_compilation_unit_read_v5(
    partial: crate::format::dwarf::dwarf_unit_header::DWARFUnitHeader,
    _reader: &mut dyn crate::app::util::bin::binary_reader::BinaryReader,
) -> std::io::Result<Box<dyn DWARFCompilationUnit>> {
    let _ = partial;
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "DWARFCompilationUnit.readV5 is not yet implemented (DWARFCompilationUnit has not been ported)",
    ))
}

/// Placeholder for the unported Java type `DWARFProgram`, referenced by `DWARFLine` and
/// `DWARFExpressionEvaluator`. Only the members those types reach for are modeled. Everything the
/// evaluator added has a stub default so that existing test doubles keep compiling; the real port
/// will supply all of them.
pub trait DWARFProgram: Send + Sync {
    /// Mirrors `DWARFProgram.isAddr0Tombstone()`.
    fn is_addr0_tombstone(&self) -> bool;

    /// Mirrors `DWARFProgram.getImportSummary()`.
    fn get_import_summary(&self) -> &DWARFImportSummary;

    /// Mirrors `DWARFProgram.getRegisterMappings()`, which returns `null` when the language has no
    /// DWARF register mapping file. The mappings are shared with every evaluator built from this
    /// program, hence the [`Arc`](std::sync::Arc).
    fn get_register_mappings(
        &self,
    ) -> Option<std::sync::Arc<crate::format::dwarf::dwarf_register_mappings::DWARFRegisterMappings>>
    {
        None
    }

    /// Mirrors `DWARFProgram.getGhidraProgram().getLanguage()`. The real chain never returns
    /// `null`; the `Option` only exists so stub implementations that don't model a Ghidra program
    /// can return `None`.
    fn get_language(&self) -> Option<std::sync::Arc<dyn crate::program::model::lang::language::Language>> {
        None
    }

    /// Mirrors `DWARFProgram.getStackSpace()`. As with [`Self::get_language`], the `Option` is only
    /// for stub implementations that don't model an address factory.
    fn get_stack_space(
        &self,
    ) -> Option<std::sync::Arc<crate::program::model::address::AddressSpace>> {
        None
    }

    /// Mirrors `DWARFProgram.getDataAddress(long)`, which applies the program's base address fixup
    /// to `offset` and resolves it in the default address space. As with [`Self::get_language`],
    /// the `Option` is only for stub implementations that don't model an address factory.
    fn get_data_address(&self, _offset: i64) -> Option<Address> {
        None
    }

    /// Mirrors `DWARFProgram.getDefaultIntSize()`, referenced by `DWARFUnitHeader::read`.
    /// Defaults to 4 (DWARF_32), the common case, so existing test doubles that don't model
    /// 64-bit DWARF keep compiling.
    fn get_default_int_size(&self) -> i32 {
        4
    }
}

/// Placeholder for the unported Java type `DWARFImportSummary`, referenced by `DWARFLine`. The
/// Java class is a concrete class whose counters are public mutable `int` fields that callers
/// increment in place; they are modeled here as atomics so they can be bumped through a shared
/// reference. Only the two counters `DWARFLine` touches are modeled.
#[derive(Debug, Default)]
pub struct DWARFImportSummary {
    tombstoned_source_line_entry_skipped_count: std::sync::atomic::AtomicI32,
    bad_source_file_count: std::sync::atomic::AtomicI32,
}

impl DWARFImportSummary {
    pub fn new() -> Self {
        Self::default()
    }

    /// Mirrors `summary.tombstonedSourceLineEntrySkippedCount++`.
    pub fn increment_tombstoned_source_line_entry_skipped_count(&self) {
        self.tombstoned_source_line_entry_skipped_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn get_tombstoned_source_line_entry_skipped_count(&self) -> i32 {
        self.tombstoned_source_line_entry_skipped_count
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Mirrors `summary.badSourceFileCount++`.
    pub fn increment_bad_source_file_count(&self) {
        self.bad_source_file_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn get_bad_source_file_count(&self) -> i32 {
        self.bad_source_file_count.load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// Placeholder for the unported Java type `DIEContainer`, referenced by `DWARFLine` and
/// `DWARFMacroHeader`. `getLine` and `getMacroEntries` default to reporting themselves
/// unsupported, so test doubles that only model `getDebugLineReader` (e.g.
/// [`crate::format::dwarf::line::dwarf_line::tests::MockDIEContainer`]) keep compiling.
pub trait DIEContainer: Send + Sync {
    /// Mirrors `DIEContainer.getDebugLineReader()`, which returns `null` when the binary has no
    /// `.debug_line` section.
    fn get_debug_line_reader(&self) -> Option<Box<dyn crate::app::util::bin::binary_reader::BinaryReader>>;

    /// Mirrors `DIEContainer.getLine(long, DWARFCompilationUnit, boolean)`, referenced by
    /// `DWARFMacroHeader::read_v5`.
    fn get_line(
        &self,
        _offset: u64,
        _cu: &dyn DWARFCompilationUnit,
        _read_if_missing: bool,
    ) -> std::io::Result<crate::format::dwarf::line::dwarf_line::DWARFLine> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "DIEContainer.getLine is not yet implemented (DIEContainer has not been ported)",
        ))
    }

    /// Mirrors `DIEContainer.getString(DWARFForm, long, DWARFCompilationUnit)`, referenced by the
    /// string forms of `DWARFForm::read_value`. `offset` is a `.debug_str`-style byte offset for
    /// the `DW_FORM_strp*` forms and an index into a string-offsets table for the `DW_FORM_strx*`
    /// forms; `form` is what tells the container which of the two it is.
    fn get_string(
        &self,
        _form: DWARFForm,
        _offset: u64,
        _cu: &dyn DWARFCompilationUnit,
    ) -> std::io::Result<String> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "DIEContainer.getString is not yet implemented (DIEContainer has not been ported)",
        ))
    }

    /// Mirrors `DIEContainer.getMacroEntries(DWARFMacroHeader)`, referenced by
    /// `DWARFMacroHeader::get_entries`.
    fn get_macro_entries(
        &self,
        _macro_header: std::sync::Arc<crate::format::dwarf::r#macro::dwarf_macro_header::DWARFMacroHeader>,
    ) -> std::io::Result<Vec<Box<dyn crate::format::dwarf::r#macro::entry::dwarf_macro_info_entry::DWARFMacroInfoEntry>>>
    {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "DIEContainer.getMacroEntries is not yet implemented (DIEContainer has not been ported)",
        ))
    }

    /// Mirrors `DIEContainer.getReaderForCompUnit(DWARFCompilationUnit)`, used by
    /// [`DebugInfoEntry::get_attribute_value`](crate::format::dwarf::debug_info_entry::DebugInfoEntry::get_attribute_value)
    /// to re-read an attribute value on demand. `None` stands in for a container that has no
    /// `.debug_info` reader.
    fn get_reader_for_comp_unit(
        &self,
        _cu: &dyn DWARFCompilationUnit,
    ) -> Option<Box<dyn crate::app::util::bin::binary_reader::BinaryReader>> {
        None
    }

    /// Mirrors `DIEContainer.getParentOf(int)`, which returns `null` for the root DIE. The
    /// container owns every DIE, so the DIEs it hands back are borrowed from it.
    fn get_parent_of(
        &self,
        _die_index: i32,
    ) -> Option<&crate::format::dwarf::debug_info_entry::DebugInfoEntry> {
        None
    }

    /// Mirrors `DIEContainer.getParentDepth(int)`, where the root DIE is depth 0.
    fn get_parent_depth(&self, _die_index: i32) -> i32 {
        -1
    }

    /// Mirrors `DIEContainer.getChildrenOf(int)`.
    fn get_children_of(
        &self,
        _die_index: i32,
    ) -> Vec<&crate::format::dwarf::debug_info_entry::DebugInfoEntry> {
        Vec::new()
    }

    /// Mirrors `DIEContainer.getChildCount(int)`.
    fn get_child_count(&self, _die_index: i32) -> i32 {
        0
    }

    /// Mirrors `DIEContainer.getPositionInParent(DebugInfoEntry, Predicate<DWARFTag>)`, which
    /// returns -1 when the DIE has no parent. The Java predicate is passed each sibling's tag,
    /// which is `null` for a terminator DIE, hence the [`Option`].
    fn get_position_in_parent(
        &self,
        _die: &crate::format::dwarf::debug_info_entry::DebugInfoEntry,
        _dw_tag_filter: &dyn Fn(Option<DWARFTag>) -> bool,
    ) -> i32 {
        -1
    }

    /// Mirrors `DIEContainer.getAddress(DWARFForm, long, DWARFCompilationUnit)`, which resolves an
    /// index into the `.debug_addr` table (`DW_FORM_addrx*`) to the address it holds. Referenced by
    /// [`DWARFExpressionEvaluator`](crate::format::dwarf::expression::dwarf_expression_evaluator::DWARFExpressionEvaluator)
    /// for `DW_OP_addrx` / `DW_OP_constx`.
    fn get_address(
        &self,
        _form: DWARFForm,
        _value: i64,
        _cu: &dyn DWARFCompilationUnit,
    ) -> std::io::Result<i64> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "DIEContainer.getAddress is not yet implemented (DIEContainer has not been ported)",
        ))
    }

    /// Mirrors `DIEContainer.getProgram()`, referenced by `DWARFUnitHeader::read`/`new`. The real
    /// method never returns `null`; the `Option` here only exists so stub test doubles that don't
    /// model a `DWARFProgram` can return `None`.
    fn get_program(&self) -> Option<std::sync::Arc<dyn DWARFProgram>> {
        None
    }

    /// Mirrors `DIEContainer.getDIE(DWARFForm, long, DWARFCompilationUnit)`, which resolves a
    /// reference attribute's raw value to the DIE it points at (`Ok(None)` where Java returns
    /// `null`). Referenced by
    /// [`DIEAggregate::create_from_head`](crate::format::dwarf::die_aggregate::DIEAggregate::create_from_head)
    /// to follow `DW_AT_abstract_origin` / `DW_AT_specification`. The container owns every DIE, so
    /// the DIE it hands back is borrowed from it.
    fn get_die(
        &self,
        _form: DWARFForm,
        _raw_offset: i64,
        _cu: &dyn DWARFCompilationUnit,
    ) -> std::io::Result<Option<&crate::format::dwarf::debug_info_entry::DebugInfoEntry>> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "DIEContainer.getDIE is not yet implemented (DIEContainer has not been ported)",
        ))
    }

    /// Mirrors `DIEContainer.getAggregate(DebugInfoEntry)`. The real container caches the
    /// aggregate it built for each head DIE; with no cache to consult, this builds a fresh one,
    /// which is what the cache would have held.
    fn get_aggregate<'a>(
        &'a self,
        die: &'a crate::format::dwarf::debug_info_entry::DebugInfoEntry,
    ) -> crate::format::dwarf::die_aggregate::DIEAggregate<'a> {
        crate::format::dwarf::die_aggregate::DIEAggregate::create_from_head(die)
    }

    /// Mirrors `DIEContainer.getLocationList(DIEAggregate, DWARFAttributeId)`, which parses the
    /// aggregate's location attribute (a single expression, or a `.debug_loc`/`.debug_loclists`
    /// list) into a [`DWARFLocationList`](crate::format::dwarf::dwarf_location_list::DWARFLocationList).
    fn get_location_list(
        &self,
        _diea: &crate::format::dwarf::die_aggregate::DIEAggregate<'_>,
        _attr_id: crate::format::dwarf::attribs::dwarf_attribute_id::DWARFAttributeId,
    ) -> std::io::Result<crate::format::dwarf::dwarf_location_list::DWARFLocationList> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "DIEContainer.getLocationList is not yet implemented (DIEContainer has not been ported)",
        ))
    }

    /// Mirrors `DIEContainer.getRangeList(DIEAggregate, DWARFAttributeId)`, the `DWARFRangeList`
    /// counterpart of [`Self::get_location_list`].
    fn get_range_list(
        &self,
        _diea: &crate::format::dwarf::die_aggregate::DIEAggregate<'_>,
        _attribute: crate::format::dwarf::attribs::dwarf_attribute_id::DWARFAttributeId,
    ) -> std::io::Result<DWARFRangeList> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "DIEContainer.getRangeList is not yet implemented (DIEContainer has not been ported)",
        ))
    }
}

/// Placeholder for the unported Java type `DWARFLocation`, referenced by
/// [`DWARFLocationList`](crate::format::dwarf::dwarf_location_list::DWARFLocationList).
/// `DWARFLocation` is a concrete Java class (not an interface), so this is modeled as a plain
/// struct rather than a trait object, per the ported type's convention. Only the constructors and
/// accessors `DWARFLocationList` needs are included; `getOffset`/`getResolvedValue`/
/// `setResolvedValue` are not modeled since nothing in-scope calls them yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DWARFLocation {
    /// `None` mirrors a `null` `addressRange`, which Java treats as "valid for any pc"
    /// (`isWildcard()`).
    address_range: Option<DWARFRange>,
    expr: Vec<u8>,
}

impl DWARFLocation {
    /// Mirrors `DWARFLocation(DWARFRange, byte[])`.
    pub fn new(address_range: DWARFRange, expr: Vec<u8>) -> Self {
        DWARFLocation { address_range: Some(address_range), expr }
    }

    /// Mirrors `DWARFLocation(long, long, byte[])`.
    pub fn from_bounds(start: u64, end: u64, expr: Vec<u8>) -> Self {
        DWARFLocation::new(DWARFRange::new(start, end), expr)
    }

    /// Mirrors `DWARFLocation(null, expr)`, used for wildcard ranges (valid for any pc).
    pub fn wildcard(expr: Vec<u8>) -> Self {
        DWARFLocation { address_range: None, expr }
    }

    /// Mirrors `DWARFLocation.getRange()`.
    pub fn get_range(&self) -> Option<DWARFRange> {
        self.address_range
    }

    /// Mirrors `DWARFLocation.getExpr()`.
    pub fn get_expr(&self) -> &[u8] {
        &self.expr
    }

    /// Mirrors `DWARFLocation.isWildcard()`.
    pub fn is_wildcard(&self) -> bool {
        self.address_range.is_none()
    }

    /// Mirrors `DWARFLocation.contains(long)`.
    pub fn contains(&self, addr: u64) -> bool {
        self.address_range.map_or(true, |range| range.contains(addr))
    }
}

impl std::fmt::Display for DWARFLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let range_str =
            self.address_range.map(|r| r.to_string()).unwrap_or_else(|| "null".to_string());
        write!(f, "DWARFLocation: range: {}, expr: {:?}", range_str, self.expr)
    }
}

/// Placeholder for the unported `ghidra.app.util.bin.format.dwarf.DWARFTag`, referenced by
/// `DebugInfoEntry` and `DWARFAbbreviation`. The real type is a Java enum of ~70 named constants
/// plus `DW_TAG_UNKNOWN`; this stub keeps only the raw tag id, which is all `DebugInfoEntry` needs
/// (it compares tags for equality and formats their id). Consequently [`fmt::Display`] renders the
/// raw id rather than the enum constant name Java's `%s` would print.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DWARFTag {
    raw_tag_id: i32,
}

impl DWARFTag {
    /// Mirrors `DWARFTag.of(int)`. Java maps an unrecognized id to `DW_TAG_UNKNOWN`, collapsing
    /// all unknown ids together; this stub keeps them distinct.
    pub fn of(tag_id: i32) -> DWARFTag {
        DWARFTag { raw_tag_id: tag_id }
    }

    /// Mirrors `DWARFTag.getId()`.
    pub fn get_id(&self) -> i32 {
        self.raw_tag_id
    }

    /// Mirrors `DWARFTag.name(int)`. The real enum returns its constant name for a recognized tag
    /// and falls back to `"DW_TAG_??? %d (0x%x)"` only for `DW_TAG_UNKNOWN`; since this stub has
    /// no catalog of known tag constants, every tag renders through that fallback format.
    pub fn name(&self, raw_tag_id: i32) -> String {
        format!("DW_TAG_??? {0} (0x{0:x})", raw_tag_id)
    }
}

impl std::fmt::Display for DWARFTag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DW_TAG_0x{:x}", self.raw_tag_id)
    }
}

/// Placeholder for the unported
/// `ghidra.app.util.bin.format.dwarf.attribs.DWARFMissingAttributeValue`: the value
/// `DebugInfoEntry::get_attribute_value` substitutes when deserializing an attribute fails.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DWARFMissingAttributeValue;

impl crate::format::dwarf::attribs::dwarf_attribute_value::DWARFAttributeValue
    for DWARFMissingAttributeValue
{
    fn get_value_string(&self, _cu: &dyn DWARFCompilationUnit, _def: &dyn DWARFAttributeDef) -> String {
        "<missing>".to_string()
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// Placeholder for `ghidra.app.util.bin.format.dwarf.line.DWARFLineProgramExecutor`, referenced by
/// `DWARFLine::get_line_program_executor`. The real class is a concrete class that steps the DWARF
/// line-number program, which is a substantial port of its own; this placeholder just captures the
/// constructor arguments (so callers -- and their tests -- can verify what the line table header
/// hands the executor) and reports row extraction as unsupported.
pub struct DWARFLineProgramExecutor {
    pub reader: Box<dyn crate::app::util::bin::binary_reader::BinaryReader>,
    pub end_offset: u64,
    pub pointer_size: i8,
    pub opcode_base: i32,
    pub line_base: i32,
    pub line_range: i32,
    pub minimum_instruction_length: i32,
    pub default_is_stmt: bool,
    pub is_addr0_tombstone: bool,
}

impl DWARFLineProgramExecutor {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        reader: Box<dyn crate::app::util::bin::binary_reader::BinaryReader>,
        end_offset: u64,
        pointer_size: i8,
        opcode_base: i32,
        line_base: i32,
        line_range: i32,
        minimum_instruction_length: i32,
        default_is_stmt: bool,
        is_addr0_tombstone: bool,
    ) -> Self {
        DWARFLineProgramExecutor {
            reader,
            end_offset,
            pointer_size,
            opcode_base,
            line_base,
            line_range,
            minimum_instruction_length,
            default_is_stmt,
            is_addr0_tombstone,
        }
    }

    /// Mirrors `DWARFLineProgramExecutor.allRows()`. Executing the line-number program isn't
    /// ported yet, so this reports itself as unsupported rather than silently returning no rows.
    pub fn all_rows(
        &mut self,
    ) -> std::io::Result<Vec<crate::format::dwarf::line::dwarf_line_program_state::DWARFLineProgramState>>
    {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "DWARFLineProgramExecutor.allRows is not yet implemented (DWARFLineProgramExecutor has not been ported)",
        ))
    }

    /// Mirrors `DWARFLineProgramExecutor.close()` (the Java class is `Closeable`).
    pub fn close(&mut self) {}
}

/// Placeholder for `ghidra.app.util.bin.format.dwarf.line.DWARFLineContentType`, referenced by
/// `DWARFFile::read_v5`. Java models this as an enum (not an interface), so it is modeled here as
/// a concrete enum, per the crate's convention for enum-shaped Java types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DWARFLineContentType {
    DwLnctPath,
    DwLnctDirectoryIndex,
    DwLnctTimestamp,
    DwLnctSize,
    DwLnctMd5,
    DwLnctLoUser,
    DwLnctHiUser,
    /// Mirrors the Java `DW_LNCT_UNKNOWN(-1)` fallback value that `of()` returns for any id it
    /// doesn't recognize.
    DwLnctUnknown,
}

impl DWARFLineContentType {
    /// Mirrors `DWARFLineContentType.of(int)`.
    pub fn of(id: i32) -> Self {
        match id {
            0x1 => Self::DwLnctPath,
            0x2 => Self::DwLnctDirectoryIndex,
            0x3 => Self::DwLnctTimestamp,
            0x4 => Self::DwLnctSize,
            0x5 => Self::DwLnctMd5,
            0x2000 => Self::DwLnctLoUser,
            0x3fff => Self::DwLnctHiUser,
            _ => Self::DwLnctUnknown,
        }
    }
}

/// Placeholder for the nested `DWARFLineContentType.Def`, referenced by `DWARFFile::read_v5`.
/// Only the two accessors that call site needs are modeled.
pub struct DWARFLineContentTypeDef {
    pub attribute_id: DWARFLineContentType,
    pub attribute_form: DWARFForm,
}

impl DWARFLineContentTypeDef {
    /// Mirrors `DWARFLineContentType.Def.read(BinaryReader)`, which reads a content type code and
    /// a form code, both unsigned LEB128, resolving the latter through `DWARFForm.of()`. Java
    /// would go on to throw a `NullPointerException` reading a value through an unrecognized
    /// form; this reports the unrecognized code instead.
    pub fn read(
        reader: &mut dyn crate::app::util::bin::binary_reader::BinaryReader,
    ) -> std::io::Result<Self> {
        let content_type_code =
            crate::app::util::bin::leb128_info::LEB128Info::unsigned(reader)?.as_u_int32()?;
        let form_code =
            crate::app::util::bin::leb128_info::LEB128Info::unsigned(reader)?.as_u_int32()?;

        let attribute_form = DWARFForm::of(form_code as i32).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Unknown DWARF Form in line content type def: {form_code:#x}"),
            )
        })?;

        Ok(DWARFLineContentTypeDef {
            attribute_id: DWARFLineContentType::of(content_type_code as i32),
            attribute_form,
        })
    }

    pub fn get_attribute_id(&self) -> DWARFLineContentType {
        self.attribute_id
    }

    pub fn get_attribute_form(&self) -> DWARFForm {
        self.attribute_form
    }
}

impl DWARFAttributeDef for DWARFLineContentTypeDef {
    fn get_attribute_form(&self) -> DWARFForm {
        self.attribute_form
    }
}

/// Placeholder for `ghidra.app.util.bin.format.dwarf.attribs.DWARFStringAttribute`, referenced by
/// `DWARFFile::read_v5`. `DWARFStringAttribute` is a concrete Java class implementing
/// `DWARFAttributeValue`, so it is modeled here as a concrete struct rather than a trait object.
pub struct DWARFStringAttribute {
    pub value: String,
}

impl DWARFStringAttribute {
    pub fn new(value: impl Into<String>) -> Self {
        DWARFStringAttribute { value: value.into() }
    }

    pub fn get_value(&self, _cu: &dyn DWARFCompilationUnit) -> String {
        self.value.clone()
    }
}

impl crate::format::dwarf::attribs::dwarf_attribute_value::DWARFAttributeValue for DWARFStringAttribute {
    fn get_value_string(&self, cu: &dyn DWARFCompilationUnit, _def: &dyn DWARFAttributeDef) -> String {
        format!("\"{}\"", self.get_value(cu))
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// Placeholder for `ghidra.app.util.bin.format.dwarf.attribs.DWARFNumericAttribute`, referenced by
/// `DWARFFile::read_v5` and `DWARFForm::read_value`. `DWARFNumericAttribute` is a concrete Java
/// class implementing `DWARFAttributeValue`, so it is modeled here as a concrete struct rather
/// than a trait object. The real class backs its value with a `Scalar` that masks the value to
/// `bit_length` and applies `signed`; this stub records those three alongside the ambiguity flag
/// but stores the value verbatim, so `get_value`/`get_unsigned_value` both read the same `i64`.
pub struct DWARFNumericAttribute {
    pub value: i64,
    pub bit_length: i32,
    pub signed: bool,
    pub ambiguous: bool,
}

impl DWARFNumericAttribute {
    /// Mirrors `DWARFNumericAttribute(long)`: 64 bits, signed, unambiguous.
    pub fn new(value: i64) -> Self {
        Self::with_ambiguous_signedness(64, value, true, false)
    }

    /// Mirrors `DWARFNumericAttribute(int, long, boolean)`.
    pub fn with_bit_length(bit_length: i32, value: i64, signed: bool) -> Self {
        Self::with_ambiguous_signedness(bit_length, value, signed, false)
    }

    /// Mirrors `DWARFNumericAttribute(int, long, boolean, boolean)`.
    pub fn with_ambiguous_signedness(
        bit_length: i32,
        value: i64,
        signed: bool,
        ambiguous: bool,
    ) -> Self {
        DWARFNumericAttribute { value, bit_length, signed, ambiguous }
    }

    /// Mirrors `DWARFNumericAttribute.isAmbiguousSignedness()`.
    pub fn is_ambiguous_signedness(&self) -> bool {
        self.ambiguous
    }

    pub fn get_value(&self) -> i64 {
        self.value
    }

    pub fn get_unsigned_value(&self) -> i64 {
        self.value
    }

    /// Mirrors `DWARFNumericAttribute.getUnsignedIntExact()`, which throws `InvalidDataException`
    /// for a value outside `0..=Integer.MAX_VALUE`.
    pub fn get_unsigned_int_exact(&self) -> std::io::Result<i32> {
        if self.value < 0 || self.value > i32::MAX as i64 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "Value out of range for positive java 32 bit unsigned int: {}",
                    self.value
                ),
            ));
        }
        Ok(self.value as i32)
    }
}

impl crate::format::dwarf::attribs::dwarf_attribute_value::DWARFAttributeValue for DWARFNumericAttribute {
    fn get_value_string(&self, _cu: &dyn DWARFCompilationUnit, _def: &dyn DWARFAttributeDef) -> String {
        format!("{}", self.value)
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// Placeholder for `ghidra.app.util.bin.format.dwarf.attribs.DWARFIndirectAttribute`, referenced
/// by `DWARFForm::read_value`. The Java class extends `DWARFNumericAttribute` (its value is an
/// index into a lookup table rather than the final value); Rust has no inheritance, so this stub
/// repeats the one accessor `DWARFForm` and its callers need instead of embedding the base class.
pub struct DWARFIndirectAttribute {
    pub index: i64,
}

impl DWARFIndirectAttribute {
    pub fn new(index: i64) -> Self {
        DWARFIndirectAttribute { index }
    }

    /// Mirrors `DWARFIndirectAttribute.getIndex()`, which goes through
    /// `DWARFNumericAttribute.getUnsignedIntExact()` and so rejects out-of-range values.
    pub fn get_index(&self) -> std::io::Result<i32> {
        if self.index < 0 || self.index > i32::MAX as i64 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Value out of range for positive java 32 bit unsigned int: {}", self.index),
            ));
        }
        Ok(self.index as i32)
    }
}

impl crate::format::dwarf::attribs::dwarf_attribute_value::DWARFAttributeValue for DWARFIndirectAttribute {
    /// The real `getValueString` resolves the index through the DIE container to describe the
    /// element it points at; that lookup isn't ported, so this falls through to the same plain
    /// number Java prints when the lookup fails.
    fn get_value_string(&self, _cu: &dyn DWARFCompilationUnit, _def: &dyn DWARFAttributeDef) -> String {
        format!("{}", self.index)
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// Placeholder for `ghidra.app.util.bin.format.dwarf.attribs.DWARFBooleanAttribute`, referenced by
/// `DWARFForm::read_value`. `DWARFBooleanAttribute` is a concrete Java class implementing
/// `DWARFAttributeValue`, so it is modeled here as a concrete struct rather than a trait object.
pub struct DWARFBooleanAttribute {
    pub value: bool,
}

impl DWARFBooleanAttribute {
    pub fn new(value: bool) -> Self {
        DWARFBooleanAttribute { value }
    }

    pub fn get_value(&self) -> bool {
        self.value
    }
}

impl crate::format::dwarf::attribs::dwarf_attribute_value::DWARFAttributeValue for DWARFBooleanAttribute {
    fn get_value_string(&self, _cu: &dyn DWARFCompilationUnit, _def: &dyn DWARFAttributeDef) -> String {
        format!("{}", self.value)
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// Placeholder for `ghidra.app.util.bin.format.dwarf.attribs.DWARFBlobAttribute`, referenced by
/// `DWARFFile::read_v5`. `DWARFBlobAttribute` is a concrete Java class implementing
/// `DWARFAttributeValue`, so it is modeled here as a concrete struct rather than a trait object.
pub struct DWARFBlobAttribute {
    pub bytes: Vec<u8>,
}

impl DWARFBlobAttribute {
    pub fn new(bytes: Vec<u8>) -> Self {
        DWARFBlobAttribute { bytes }
    }

    pub fn get_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn get_length(&self) -> i32 {
        self.bytes.len() as i32
    }
}

impl crate::format::dwarf::attribs::dwarf_attribute_value::DWARFAttributeValue for DWARFBlobAttribute {
    fn get_value_string(&self, _cu: &dyn DWARFCompilationUnit, _def: &dyn DWARFAttributeDef) -> String {
        format!("[{}]{:02x?}", self.bytes.len(), self.bytes)
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// Placeholder for `ghidra.formats.gfilesystem.FSUtilities`, referenced by
/// `DWARFFile::get_path_name`. `FSUtilities` is a concrete Java class (a utility class of only
/// static members), so it is modeled here as a zero-sized type with an associated function. Only
/// `appendPath` (the single static method that call site needs) is modeled.
pub struct FSUtilities;

impl FSUtilities {
    /// Mirrors `FSUtilities.appendPath(String...)`, joining non-empty path segments with `/`,
    /// avoiding a doubled separator when a segment already starts or ends with one. The real
    /// method returns `null` when every argument is `null`; that case doesn't apply here since
    /// Rust `&str` arguments can't be null, so this always returns a `String` (possibly empty).
    pub fn append_path(paths: &[&str]) -> String {
        let mut buffer = String::new();
        for &path in paths {
            if path.is_empty() {
                continue;
            }

            let empty_buffer = buffer.is_empty();
            let buffer_ends_with_slash =
                !empty_buffer && matches!(buffer.chars().last(), Some('/') | Some('\\'));
            let path_starts_with_slash = matches!(path.chars().next(), Some('/') | Some('\\'));

            let path = if path_starts_with_slash && buffer_ends_with_slash {
                &path[1..]
            } else {
                path
            };
            if !buffer_ends_with_slash && !path_starts_with_slash && !empty_buffer {
                buffer.push('/');
            }
            buffer.push_str(path);
        }
        buffer
    }
}

/// Placeholder for `ghidra.app.util.bin.format.dwarf.macro.DWARFMacroOpcode`, referenced by
/// `DWARFMacroInfoEntry`. `DWARFMacroOpcode` is a Java enum (not an interface), so it is modeled
/// here as a concrete Rust enum carrying the real `DW_MACRO_*` raw opcode and description values,
/// rather than a trait object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DWARFMacroOpcode {
    /// Not an official DWARF opcode; represents the entry with opcode 0 that terminates a macro
    /// unit.
    MacroUnitTerminator,
    DwMacroDefine,
    DwMacroUndef,
    DwMacroStartFile,
    DwMacroEndFile,
    DwMacroDefineStrp,
    DwMacroUndefStrp,
    DwMacroImport,
    DwMacroDefineSup,
    DwMacroUndefSup,
    DwMacroImportSup,
    DwMacroDefineStrx,
    DwMacroUndefStrx,
}

impl DWARFMacroOpcode {
    /// All variants, in Java enum declaration order; used by [`Self::of`].
    const VALUES: [DWARFMacroOpcode; 13] = [
        DWARFMacroOpcode::MacroUnitTerminator,
        DWARFMacroOpcode::DwMacroDefine,
        DWARFMacroOpcode::DwMacroUndef,
        DWARFMacroOpcode::DwMacroStartFile,
        DWARFMacroOpcode::DwMacroEndFile,
        DWARFMacroOpcode::DwMacroDefineStrp,
        DWARFMacroOpcode::DwMacroUndefStrp,
        DWARFMacroOpcode::DwMacroImport,
        DWARFMacroOpcode::DwMacroDefineSup,
        DWARFMacroOpcode::DwMacroUndefSup,
        DWARFMacroOpcode::DwMacroImportSup,
        DWARFMacroOpcode::DwMacroDefineStrx,
        DWARFMacroOpcode::DwMacroUndefStrx,
    ];

    /// Mirrors `DWARFMacroOpcode.getRawOpcode()`.
    pub fn get_raw_opcode(&self) -> i32 {
        match self {
            Self::MacroUnitTerminator => 0,
            Self::DwMacroDefine => 0x1,
            Self::DwMacroUndef => 0x2,
            Self::DwMacroStartFile => 0x3,
            Self::DwMacroEndFile => 0x4,
            Self::DwMacroDefineStrp => 0x5,
            Self::DwMacroUndefStrp => 0x6,
            Self::DwMacroImport => 0x7,
            Self::DwMacroDefineSup => 0x8,
            Self::DwMacroUndefSup => 0x9,
            Self::DwMacroImportSup => 0xa,
            Self::DwMacroDefineStrx => 0xb,
            Self::DwMacroUndefStrx => 0xc,
        }
    }

    /// Mirrors `DWARFMacroOpcode.getDescription()`.
    pub fn get_description(&self) -> String {
        match self {
            Self::MacroUnitTerminator => "unknown",
            Self::DwMacroDefine
            | Self::DwMacroDefineStrp
            | Self::DwMacroDefineSup
            | Self::DwMacroDefineStrx => "#define",
            Self::DwMacroUndef
            | Self::DwMacroUndefStrp
            | Self::DwMacroUndefSup
            | Self::DwMacroUndefStrx => "#undef",
            Self::DwMacroStartFile => "startfile",
            Self::DwMacroEndFile => "endfile",
            Self::DwMacroImport | Self::DwMacroImportSup => "#include",
        }
        .to_string()
    }

    /// Mirrors `DWARFMacroOpcode.getOperandForms()`: the form each of this opcode's operands is
    /// encoded with, from the Java constructor's varargs `operandForms`.
    pub fn get_operand_forms(&self) -> &'static [DWARFForm] {
        use DWARFForm::*;
        match self {
            Self::MacroUnitTerminator | Self::DwMacroEndFile => &[],
            Self::DwMacroDefine | Self::DwMacroUndef => &[DwFormUdata, DwFormString],
            Self::DwMacroStartFile => &[DwFormUdata, DwFormUdata],
            Self::DwMacroDefineStrp | Self::DwMacroUndefStrp => &[DwFormUdata, DwFormStrp],
            Self::DwMacroImport | Self::DwMacroImportSup => &[DwFormSecOffset],
            Self::DwMacroDefineSup | Self::DwMacroUndefSup => &[DwFormUdata, DwFormStrpSup],
            Self::DwMacroDefineStrx | Self::DwMacroUndefStrx => &[DwFormUdata, DwFormStrx],
        }
    }

    /// Mirrors `DWARFMacroOpcode.of(int)`: a linear search over the enum's values, returning
    /// `None` (Java `null`) if no variant matches.
    pub fn of(opcode_val: i32) -> Option<Self> {
        Self::VALUES.into_iter().find(|opcode| opcode.get_raw_opcode() == opcode_val)
    }

    /// Mirrors `DWARFMacroOpcode.defaultOpcodeOperandMap`, used by `DWARFMacroHeader::read_v5` as
    /// the starting opcode table before an optional per-unit table (if present) overrides it.
    pub fn default_opcode_operand_map() -> std::collections::HashMap<i32, Vec<DWARFForm>> {
        Self::VALUES
            .iter()
            .map(|opcode| (opcode.get_raw_opcode(), opcode.get_operand_forms().to_vec()))
            .collect()
    }
}

/// Placeholder for the nested `DWARFMacroOpcode.Def` (a `DWARFAttributeDef<DWARFMacroOpcode>`),
/// referenced by `DWARFMacroInfoEntry`. Mirrors the three fields the Java constructor forwards to
/// `DWARFAttributeDef`'s constructor (`attributeId`, `rawAttributeId`, `attributeForm`); the
/// fourth (`implicitValue`) is always `-1` ("N/A") for a macro opcode def, so it's omitted here.
pub struct DWARFMacroOpcodeDef {
    pub opcode: DWARFMacroOpcode,
    pub raw_opcode: i32,
    pub form: DWARFForm,
}

impl DWARFMacroOpcodeDef {
    pub fn new(opcode: DWARFMacroOpcode, raw_opcode: i32, form: DWARFForm) -> Self {
        DWARFMacroOpcodeDef { opcode, raw_opcode, form }
    }
}

impl DWARFAttributeDef for DWARFMacroOpcodeDef {
    fn get_attribute_form(&self) -> DWARFForm {
        self.form
    }
}

/// Minimal placeholders for the five unported Java macro-entry subclasses that
/// `DWARFMacroInfoEntry::to_specialized_form` dispatches to (`DWARFMacroDefine`, `DWARFMacroUndef`,
/// `DWARFMacroStartFile`, `DWARFMacroEndFile`, `DWARFMacroImport`). Each extends
/// `DWARFMacroInfoEntry` in Java and is expected to have a copy-constructor that wraps a generic
/// `DWARFMacroInfoEntry`; these stubs offer exactly that shape (and nothing else) so dispatch
/// compiles, using the inherited (non-overridden) `to_string`. Replace each with its real port,
/// which will add the subclass-specific getters and (for `DWARFMacroDefine`/`DWARFMacroStartFile`)
/// override `to_string`.
macro_rules! macro_info_entry_placeholder {
    ($name:ident) => {
        pub struct $name {
            base: crate::format::dwarf::r#macro::entry::dwarf_macro_info_entry::DWARFMacroInfoEntryBase,
        }

        impl $name {
            pub fn new(
                other: crate::format::dwarf::r#macro::entry::dwarf_macro_info_entry::DWARFMacroInfoEntryBase,
            ) -> Self {
                $name { base: other }
            }
        }

        impl crate::format::dwarf::r#macro::entry::dwarf_macro_info_entry::DWARFMacroInfoEntry
            for $name
        {
            fn base(
                &self,
            ) -> &crate::format::dwarf::r#macro::entry::dwarf_macro_info_entry::DWARFMacroInfoEntryBase
            {
                &self.base
            }
        }
    };
}

macro_info_entry_placeholder!(DWARFMacroDefine);
macro_info_entry_placeholder!(DWARFMacroUndef);
macro_info_entry_placeholder!(DWARFMacroStartFile);
macro_info_entry_placeholder!(DWARFMacroEndFile);
macro_info_entry_placeholder!(DWARFMacroImport);

/// Placeholder for the unported Java type `DWARFFunction`, referenced by `DWARFFunctionFixup`.
/// Generated stub: only a shape hint. Receivers default to `&self` (some may need `&mut self`);
/// unknown in-repo types map to trait objects. Replace with the real port when available.
pub trait DWARFFunction: Send + Sync {
    fn read(&self, diea: &crate::format::dwarf::die_aggregate::DIEAggregate<'_>) -> std::io::Result<Box<dyn DWARFFunction>>;
    fn get_program(&self) -> Box<dyn DWARFProgram>;
    fn get_descriptive_name(&self) -> String;
    fn get_range_list(&self) -> DWARFRangeList;
    fn get_calling_convention_name(&self) -> String;
    fn get_body(&self) -> Box<dyn AddressSetView>;
    fn get_entry_pc(&self) -> i64;
    fn get_local_var_by_offset(&self, offset: i64) -> Box<dyn DWARFVariable>;
    fn is_in_local_var_storage_area(&self, offset: i64) -> bool;
    fn has_conflict_with_param_storage(&self, dvar: &dyn DWARFVariable) -> std::io::Result<bool>;
    fn has_conflict_with_existing_local_variable_storage(&self, dvar: &dyn DWARFVariable) -> std::io::Result<bool>;
    fn get_all_param_names(&self) -> Vec<String>;
    fn get_all_local_variable_names(&self) -> Vec<String>;
    fn get_existing_local_variable_names(&self) -> Vec<String>;
    fn get_non_param_symbol_names(&self) -> Vec<String>;
    fn get_parameters(&self, include_storage_detail: bool) -> std::io::Result<Vec<Box<dyn Parameter>>>;
    fn get_parameter_definitions(&self) -> Vec<Box<dyn ParameterDefinition>>;
    fn commit_local_variable(&self, dvar: &dyn DWARFVariable);
    fn get_func_body(&self, diea: &crate::format::dwarf::die_aggregate::DIEAggregate<'_>, flatten_disjoint: bool) -> std::io::Result<Box<dyn AddressRange>>;
    fn get_func_body_ranges(&self, diea: &crate::format::dwarf::die_aggregate::DIEAggregate<'_>) -> std::io::Result<DWARFRangeList>;
    fn sync_with_existing_ghidra_function(&self, create_if_missing: bool) -> bool;
    fn run_fixups(&self);
    fn update_function_signature(&self);
    fn as_function_definition(&self, include_cc: bool) -> Box<dyn FunctionDefinition>;
    fn to_string(&self) -> String;
}

/// Placeholder for `ghidra.app.util.bin.format.dwarf.DWARFRangeList`, referenced by
/// `DWARFFunction` and by
/// [`DIEAggregate::get_range_list`](crate::format::dwarf::die_aggregate::DIEAggregate::get_range_list).
/// `DWARFRangeList` is a concrete Java class (not an interface), so it is modeled as a struct
/// rather than a trait object. The real class also knows how to read itself from `.debug_ranges` /
/// `.debug_rnglists`; only the accessors over an already-built list are modeled here.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DWARFRangeList {
    ranges: Vec<DWARFRange>,
}

impl DWARFRangeList {
    /// Mirrors `DWARFRangeList(List<DWARFRange>)`.
    pub fn new(ranges: Vec<DWARFRange>) -> Self {
        DWARFRangeList { ranges }
    }

    /// Mirrors `DWARFRangeList.isEmpty()`.
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// Mirrors `DWARFRangeList.get(int)`, which throws `IndexOutOfBoundsException` where this
    /// returns `None`.
    pub fn get(&self, index: usize) -> Option<&DWARFRange> {
        self.ranges.get(index)
    }

    /// Mirrors `DWARFRangeList.ranges()`.
    pub fn ranges(&self) -> &[DWARFRange] {
        &self.ranges
    }

    /// Mirrors `DWARFRangeList.getListCount()`.
    pub fn get_list_count(&self) -> usize {
        self.ranges.len()
    }

    /// Mirrors `DWARFRangeList.getFirst()`, which returns `null` for an empty list.
    pub fn get_first(&self) -> Option<&DWARFRange> {
        self.ranges.first()
    }

    /// Mirrors `DWARFRangeList.getLast()`, which returns `null` for an empty list.
    pub fn get_last(&self) -> Option<&DWARFRange> {
        self.ranges.last()
    }

    /// Mirrors `DWARFRangeList.getFlattenedRange()`, the span from the first range's start to the
    /// last range's end, or `null` (here `None`) for an empty list.
    pub fn get_flattened_range(&self) -> Option<DWARFRange> {
        Some(DWARFRange::new(self.get_first()?.from(), self.get_last()?.to()))
    }
}

impl std::fmt::Display for DWARFRangeList {
    /// Mirrors `DWARFRangeList.toString()`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DWARFRangeList [ranges={:?}]", self.ranges)
    }
}

/// Placeholder for `ghidra.program.model.address.AddressSetView`, referenced by `DWARFFunction`.
pub trait AddressSetView: Send + Sync {}

/// Placeholder for `ghidra.app.util.bin.format.dwarf.DWARFVariable`, referenced by `DWARFFunction`.
pub trait DWARFVariable: Send + Sync {}

/// Placeholder for `ghidra.app.util.bin.format.dwarf.external.ExternalDebugInfo`, referenced by `DebugStreamProvider`.
pub trait ExternalDebugInfo: Send + Sync {
    fn from_program(&self, program: &dyn Program) -> Box<dyn ExternalDebugInfo>;
    fn for_build_id(&self, build_id: &str) -> Box<dyn ExternalDebugInfo>;
    fn for_debug_link(&self, debug_link_filename: &str, crc: i32) -> Box<dyn ExternalDebugInfo>;
    fn has_debug_link(&self) -> bool;
    fn get_filename(&self) -> String;
    fn get_crc(&self) -> i32;
    fn get_build_id(&self) -> String;
    fn has_build_id(&self) -> bool;
    fn get_object_type(&self) -> ObjectType;
    fn get_extra(&self) -> String;
    fn with_type(&self, new_object_type: ObjectType, new_extra: &str) -> Box<dyn ExternalDebugInfo>;
    fn to_string(&self) -> String;
}

/// Placeholder for `ghidra.app.util.bin.format.dwarf.sectionprovider.DWARFSectionProviderFactory`,
/// referenced by `DWARFSectionProvider` before the real class is ported.
/// `DWARFSectionProviderFactory` is a concrete Java class (not an interface), so it is modeled here
/// as a trait that returns section providers. The real class maintains a registry of factory
/// functions for creating different section provider implementations.
pub trait DWARFSectionProviderFactory: Send + Sync {
    /// Creates a section provider for the given program.
    ///
    /// # Arguments
    /// * `program` - the program to create a section provider for
    /// * `monitor` - a task monitor for long operations
    ///
    /// # Returns
    /// A new `DWARFSectionProvider` for the given program
    fn create_section_provider_for(
        &self,
        program: &dyn Program,
        monitor: &dyn crate::util::task::TaskMonitor,
    ) -> Box<dyn crate::format::dwarf::sectionprovider::dwarf_section_provider::DWARFSectionProvider>;
}

/// Placeholder for `ghidra.program.model.listing.Parameter`, referenced by `DWARFFunction`.
pub trait Parameter: Send + Sync {}

/// Placeholder for `ghidra.app.util.bin.format.dwarf.ParameterDefinition`, referenced by `DWARFFunction`.
pub trait ParameterDefinition: Send + Sync {}

/// Placeholder for `ghidra.program.model.address.AddressRange`, referenced by `DWARFFunction`.
pub trait AddressRange: Send + Sync {}

/// Placeholder for `ghidra.program.model.listing.FunctionDefinition`, referenced by `DWARFFunction`.
pub trait FunctionDefinition: Send + Sync {}

/// Placeholder for `ghidra.app.util.bin.format.dwarf.DWARFUtil`, referenced by
/// [`DWARFExpressionEvaluator`](crate::format::dwarf::expression::dwarf_expression_evaluator::DWARFExpressionEvaluator).
/// The Java class is a utility class of only static members, so it is modeled here as a zero-sized
/// type with associated functions; only the two varnode predicates the evaluator uses are present.
pub struct DWARFUtil;

impl DWARFUtil {
    /// Mirrors `DWARFUtil.isStackVarnode(Varnode)`.
    pub fn is_stack_varnode(varnode: &crate::program::model::pcode::Varnode) -> bool {
        varnode.get_address().space().space_type()
            == crate::program::model::address::AddressSpaceType::Stack
    }

    /// Mirrors `DWARFUtil.isConstVarnode(Varnode)`.
    pub fn is_const_varnode(varnode: &crate::program::model::pcode::Varnode) -> bool {
        varnode.get_address().space().space_type()
            == crate::program::model::address::AddressSpaceType::Constant
    }
}

/// Placeholder for the unported `ghidra.app.util.bin.format.dwarf.expression.DWARFExpressionOpCode`,
/// referenced by
/// [`DWARFExpressionEvaluator`](crate::format::dwarf::expression::dwarf_expression_evaluator::DWARFExpressionEvaluator).
/// The Java type is an enum whose constants carry both a raw opcode value and the operand types an
/// instruction of that opcode takes; this stub keeps the opcode values (the evaluator dispatches on
/// them, and on `lit`/`reg`/`breg` opcode *ranges*) and leaves the operand-type table to the real
/// port. Variants are spelled exactly as the Java constants so that `{:?}` renders what Java's
/// `toString()` does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[allow(non_camel_case_types)]
#[repr(u8)]
pub enum DWARFExpressionOpCode {
    /// Special value, not a real DWARF opcode.
    DW_OP_unknown_opcode = 0,
    DW_OP_addr = 0x3,
    DW_OP_deref = 0x6,
    DW_OP_const1u = 0x8,
    DW_OP_const1s = 0x9,
    DW_OP_const2u = 0xa,
    DW_OP_const2s = 0xb,
    DW_OP_const4u = 0xc,
    DW_OP_const4s = 0xd,
    DW_OP_const8u = 0xe,
    DW_OP_const8s = 0xf,
    DW_OP_constu = 0x10,
    DW_OP_consts = 0x11,
    DW_OP_dup = 0x12,
    DW_OP_drop = 0x13,
    DW_OP_over = 0x14,
    DW_OP_pick = 0x15,
    DW_OP_swap = 0x16,
    DW_OP_rot = 0x17,
    DW_OP_xderef = 0x18,
    DW_OP_abs = 0x19,
    DW_OP_and = 0x1a,
    DW_OP_div = 0x1b,
    DW_OP_minus = 0x1c,
    DW_OP_mod = 0x1d,
    DW_OP_mul = 0x1e,
    DW_OP_neg = 0x1f,
    DW_OP_not = 0x20,
    DW_OP_or = 0x21,
    DW_OP_plus = 0x22,
    DW_OP_plus_uconst = 0x23,
    DW_OP_shl = 0x24,
    DW_OP_shr = 0x25,
    DW_OP_shra = 0x26,
    DW_OP_xor = 0x27,
    DW_OP_bra = 0x28,
    DW_OP_eq = 0x29,
    DW_OP_ge = 0x2a,
    DW_OP_gt = 0x2b,
    DW_OP_le = 0x2c,
    DW_OP_lt = 0x2d,
    DW_OP_ne = 0x2e,
    DW_OP_skip = 0x2f,
    DW_OP_lit0 = 0x30,
    DW_OP_lit1 = 0x31,
    DW_OP_lit2 = 0x32,
    DW_OP_lit3 = 0x33,
    DW_OP_lit4 = 0x34,
    DW_OP_lit5 = 0x35,
    DW_OP_lit6 = 0x36,
    DW_OP_lit7 = 0x37,
    DW_OP_lit8 = 0x38,
    DW_OP_lit9 = 0x39,
    DW_OP_lit10 = 0x3a,
    DW_OP_lit11 = 0x3b,
    DW_OP_lit12 = 0x3c,
    DW_OP_lit13 = 0x3d,
    DW_OP_lit14 = 0x3e,
    DW_OP_lit15 = 0x3f,
    DW_OP_lit16 = 0x40,
    DW_OP_lit17 = 0x41,
    DW_OP_lit18 = 0x42,
    DW_OP_lit19 = 0x43,
    DW_OP_lit20 = 0x44,
    DW_OP_lit21 = 0x45,
    DW_OP_lit22 = 0x46,
    DW_OP_lit23 = 0x47,
    DW_OP_lit24 = 0x48,
    DW_OP_lit25 = 0x49,
    DW_OP_lit26 = 0x4a,
    DW_OP_lit27 = 0x4b,
    DW_OP_lit28 = 0x4c,
    DW_OP_lit29 = 0x4d,
    DW_OP_lit30 = 0x4e,
    DW_OP_lit31 = 0x4f,
    DW_OP_reg0 = 0x50,
    DW_OP_reg1 = 0x51,
    DW_OP_reg2 = 0x52,
    DW_OP_reg3 = 0x53,
    DW_OP_reg4 = 0x54,
    DW_OP_reg5 = 0x55,
    DW_OP_reg6 = 0x56,
    DW_OP_reg7 = 0x57,
    DW_OP_reg8 = 0x58,
    DW_OP_reg9 = 0x59,
    DW_OP_reg10 = 0x5a,
    DW_OP_reg11 = 0x5b,
    DW_OP_reg12 = 0x5c,
    DW_OP_reg13 = 0x5d,
    DW_OP_reg14 = 0x5e,
    DW_OP_reg15 = 0x5f,
    DW_OP_reg16 = 0x60,
    DW_OP_reg17 = 0x61,
    DW_OP_reg18 = 0x62,
    DW_OP_reg19 = 0x63,
    DW_OP_reg20 = 0x64,
    DW_OP_reg21 = 0x65,
    DW_OP_reg22 = 0x66,
    DW_OP_reg23 = 0x67,
    DW_OP_reg24 = 0x68,
    DW_OP_reg25 = 0x69,
    DW_OP_reg26 = 0x6a,
    DW_OP_reg27 = 0x6b,
    DW_OP_reg28 = 0x6c,
    DW_OP_reg29 = 0x6d,
    DW_OP_reg30 = 0x6e,
    DW_OP_reg31 = 0x6f,
    DW_OP_breg0 = 0x70,
    DW_OP_breg1 = 0x71,
    DW_OP_breg2 = 0x72,
    DW_OP_breg3 = 0x73,
    DW_OP_breg4 = 0x74,
    DW_OP_breg5 = 0x75,
    DW_OP_breg6 = 0x76,
    DW_OP_breg7 = 0x77,
    DW_OP_breg8 = 0x78,
    DW_OP_breg9 = 0x79,
    DW_OP_breg10 = 0x7a,
    DW_OP_breg11 = 0x7b,
    DW_OP_breg12 = 0x7c,
    DW_OP_breg13 = 0x7d,
    DW_OP_breg14 = 0x7e,
    DW_OP_breg15 = 0x7f,
    DW_OP_breg16 = 0x80,
    DW_OP_breg17 = 0x81,
    DW_OP_breg18 = 0x82,
    DW_OP_breg19 = 0x83,
    DW_OP_breg20 = 0x84,
    DW_OP_breg21 = 0x85,
    DW_OP_breg22 = 0x86,
    DW_OP_breg23 = 0x87,
    DW_OP_breg24 = 0x88,
    DW_OP_breg25 = 0x89,
    DW_OP_breg26 = 0x8a,
    DW_OP_breg27 = 0x8b,
    DW_OP_breg28 = 0x8c,
    DW_OP_breg29 = 0x8d,
    DW_OP_breg30 = 0x8e,
    DW_OP_breg31 = 0x8f,
    DW_OP_regx = 0x90,
    DW_OP_fbreg = 0x91,
    DW_OP_bregx = 0x92,
    DW_OP_piece = 0x93,
    DW_OP_deref_size = 0x94,
    DW_OP_xderef_size = 0x95,
    DW_OP_nop = 0x96,
    DW_OP_push_object_address = 0x97,
    DW_OP_call2 = 0x98,
    DW_OP_call4 = 0x99,
    DW_OP_call_ref = 0x9a,
    DW_OP_form_tls_address = 0x9b,
    DW_OP_call_frame_cfa = 0x9c,
    DW_OP_bit_piece = 0x9d,
    DW_OP_implicit_value = 0x9e,
    DW_OP_stack_value = 0x9f,
    DW_OP_implicit_pointer = 0xa0,
    DW_OP_addrx = 0xa1,
    DW_OP_constx = 0xa2,
    DW_OP_entry_value = 0xa3,
    DW_OP_const_type = 0xa4,
    DW_OP_regval_type = 0xa5,
    DW_OP_deref_type = 0xa6,
    DW_OP_xderef_type = 0xa7,
    DW_OP_convert = 0xa8,
    DW_OP_reinterpret = 0xa9,
}

impl DWARFExpressionOpCode {
    /// Mirrors `DWARFExpressionOpCode.getOpCodeValue()`.
    pub fn get_op_code_value(self) -> u8 {
        self as u8
    }

    /// Mirrors `DWARFExpressionOpCode.isInRange(op, lo, hi)`: true if `op`'s raw value is within
    /// the inclusive `lo..hi` range.
    pub fn is_in_range(op: Self, lo: Self, hi: Self) -> bool {
        lo as u8 <= op as u8 && op as u8 <= hi as u8
    }

    /// Mirrors `DWARFExpressionOpCode.getRelativeOpCodeOffset(baseOp)`: e.g. `DW_OP_reg12` relative
    /// to `DW_OP_reg0` is 12.
    pub fn get_relative_op_code_offset(self, base_op: Self) -> i32 {
        self as i32 - base_op as i32
    }

    /// Mirrors `DWARFExpressionOpCode.toString(DWARFRegisterMappings)`, which appends the mapped
    /// Ghidra register name to the `reg`/`breg` opcodes.
    pub fn to_string_with_reg_mapping(
        self,
        reg_mapping: Option<&crate::format::dwarf::dwarf_register_mappings::DWARFRegisterMappings>,
    ) -> String {
        use DWARFExpressionOpCode::*;
        let reg_idx = if Self::is_in_range(self, DW_OP_reg0, DW_OP_reg31) {
            self.get_relative_op_code_offset(DW_OP_reg0)
        } else if Self::is_in_range(self, DW_OP_breg0, DW_OP_breg31) {
            self.get_relative_op_code_offset(DW_OP_breg0)
        } else {
            -1
        };
        let reg = if reg_idx >= 0 {
            reg_mapping.and_then(|rm| rm.ghidra_reg(reg_idx))
        } else {
            None
        };
        match reg {
            Some(reg) => format!("{self}({})", reg.borrow().name()),
            None => self.to_string(),
        }
    }
}

impl std::fmt::Display for DWARFExpressionOpCode {
    /// The variant names are spelled exactly as Java's enum constants, so `{:?}` is Java's
    /// `toString()`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Placeholder for the unported
/// `ghidra.app.util.bin.format.dwarf.expression.DWARFExpressionInstruction`, referenced by
/// [`DWARFExpressionEvaluator`](crate::format::dwarf::expression::dwarf_expression_evaluator::DWARFExpressionEvaluator).
/// `DWARFExpressionInstruction` is a concrete Java class, so it is modeled as a struct; only the
/// opcode, operand values and expression-relative offset the evaluator reads are kept. The blob
/// operand, the operand-type table, the `read` parser and the readelf-style operand formatting are
/// left to the real port.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DWARFExpressionInstruction {
    /// Mirrors the `protected final` field the evaluator reads directly as `instr.opcode`.
    pub opcode: DWARFExpressionOpCode,
    offset: i32,
    operands: Vec<i64>,
}

impl DWARFExpressionInstruction {
    /// Mirrors `DWARFExpressionInstruction(op, operandTypes, operands, blob, offset)`, minus the
    /// operand types and blob this stub does not model.
    pub fn new(opcode: DWARFExpressionOpCode, operands: Vec<i64>, offset: i32) -> Self {
        DWARFExpressionInstruction { opcode, offset, operands }
    }

    /// Mirrors `DWARFExpressionInstruction.getOperandValue(int)`, which throws
    /// `ArrayIndexOutOfBoundsException` for an operand the instruction does not have.
    ///
    /// # Panics
    /// Panics if `opindex` is out of range, as the Java array access does.
    pub fn get_operand_value(&self, opindex: usize) -> i64 {
        self.operands[opindex]
    }

    /// Mirrors `DWARFExpressionInstruction.getOperandCount()`.
    pub fn get_operand_count(&self) -> usize {
        self.operands.len()
    }

    /// Mirrors `DWARFExpressionInstruction.getOffset()`: the byte offset of this instruction from
    /// the start of the expression.
    pub fn get_offset(&self) -> i32 {
        self.offset
    }

    /// Mirrors `DWARFExpressionInstruction.toGenericForm()`: a copy of this instruction with all
    /// its operands removed (and, per the Java implementation, its offset reset to 0).
    pub fn to_generic_form(&self) -> Self {
        DWARFExpressionInstruction { opcode: self.opcode, offset: 0, operands: Vec::new() }
    }
}

impl std::fmt::Display for DWARFExpressionInstruction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.opcode)?;
        if !self.operands.is_empty() {
            let operands: Vec<String> = self.operands.iter().map(|o| o.to_string()).collect();
            write!(f, " [{}]", operands.join(", "))?;
        }
        Ok(())
    }
}

/// Which of the `DWARFExpressionException` subclasses an error is, along with the extra state that
/// subclass carries.
///
/// Java models these as four classes (`DWARFExpressionException`, its subclass
/// `DWARFExpressionUnsupportedOpException`, *its* subclass
/// `DWARFExpressionTerminalDerefException`, and `DWARFExpressionValueException`); Rust has no
/// exception hierarchy, so they collapse into one error type discriminated by this enum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DWARFExpressionExceptionKind {
    /// Plain `DWARFExpressionException`.
    Generic,
    /// `DWARFExpressionUnsupportedOpException`: the evaluator does not implement this instruction.
    UnsupportedOp(DWARFExpressionInstruction),
    /// `DWARFExpressionTerminalDerefException` (a subclass of the unsupported-op exception): the
    /// expression ended with a `DW_OP_deref` of the given location, which some callers can still
    /// make use of.
    TerminalDeref(DWARFExpressionInstruction, crate::program::model::pcode::Varnode),
    /// `DWARFExpressionValueException`: the value of the given varnode could not be fetched.
    Value(crate::program::model::pcode::Varnode),
}

/// Placeholder for the unported
/// `ghidra.app.util.bin.format.dwarf.expression.DWARFExpressionException` and its three subclasses,
/// referenced by
/// [`DWARFExpressionEvaluator`](crate::format::dwarf::expression::dwarf_expression_evaluator::DWARFExpressionEvaluator).
/// Carries the expression and the position within it that caused the problem back up the call
/// chain, exactly as the Java exception does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DWARFExpressionException {
    message: String,
    kind: DWARFExpressionExceptionKind,
    expr: Option<DWARFExpression>,
    instr_index: i32,
}

impl DWARFExpressionException {
    /// Mirrors `DWARFExpressionException(String)`.
    pub fn new(message: impl Into<String>) -> Self {
        DWARFExpressionException {
            message: message.into(),
            kind: DWARFExpressionExceptionKind::Generic,
            expr: None,
            instr_index: -1,
        }
    }

    /// Mirrors `DWARFExpressionUnsupportedOpException(DWARFExpressionInstruction)`.
    pub fn unsupported_op(instr: DWARFExpressionInstruction) -> Self {
        DWARFExpressionException {
            message: format!("Unsupported instruction {instr}"),
            kind: DWARFExpressionExceptionKind::UnsupportedOp(instr),
            expr: None,
            instr_index: -1,
        }
    }

    /// Mirrors `DWARFExpressionTerminalDerefException(DWARFExpressionInstruction, Varnode)`, whose
    /// superclass constructor builds the same "Unsupported instruction" message.
    pub fn terminal_deref(
        instr: DWARFExpressionInstruction,
        varnode: crate::program::model::pcode::Varnode,
    ) -> Self {
        DWARFExpressionException {
            message: format!("Unsupported instruction {instr}"),
            kind: DWARFExpressionExceptionKind::TerminalDeref(instr, varnode),
            expr: None,
            instr_index: -1,
        }
    }

    /// Mirrors `DWARFExpressionValueException(Varnode)`.
    pub fn value(vn: crate::program::model::pcode::Varnode) -> Self {
        DWARFExpressionException {
            message: format!("Unable to access value of {vn}"),
            kind: DWARFExpressionExceptionKind::Value(vn),
            expr: None,
            instr_index: -1,
        }
    }

    /// Which Java exception class this stands in for.
    pub fn kind(&self) -> &DWARFExpressionExceptionKind {
        &self.kind
    }

    /// Mirrors `DWARFExpressionException.getExpression()`.
    pub fn get_expression(&self) -> Option<&DWARFExpression> {
        self.expr.as_ref()
    }

    /// Mirrors `DWARFExpressionException.setExpression(DWARFExpression)`.
    pub fn set_expression(&mut self, expr: DWARFExpression) {
        self.expr = Some(expr);
    }

    /// Mirrors `DWARFExpressionException.getInstructionIndex()`.
    pub fn get_instruction_index(&self) -> i32 {
        self.instr_index
    }

    /// Mirrors `DWARFExpressionException.setInstructionIndex(int)`.
    pub fn set_instruction_index(&mut self, instr_index: i32) {
        self.instr_index = instr_index;
    }

    /// The `DWARFExpressionUnsupportedOpException`/`DWARFExpressionTerminalDerefException`
    /// `getInstruction()` accessor.
    pub fn get_instruction(&self) -> Option<&DWARFExpressionInstruction> {
        match &self.kind {
            DWARFExpressionExceptionKind::UnsupportedOp(instr)
            | DWARFExpressionExceptionKind::TerminalDeref(instr, _) => Some(instr),
            _ => None,
        }
    }

    /// The `DWARFExpressionTerminalDerefException`/`DWARFExpressionValueException` `getVarnode()`
    /// accessor.
    pub fn get_varnode(&self) -> Option<&crate::program::model::pcode::Varnode> {
        match &self.kind {
            DWARFExpressionExceptionKind::TerminalDeref(_, vn)
            | DWARFExpressionExceptionKind::Value(vn) => Some(vn),
            _ => None,
        }
    }
}

impl std::fmt::Display for DWARFExpressionException {
    /// Mirrors `DWARFExpressionException.getMessage()`, which appends the expression (if known).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)?;
        if let Some(expr) = &self.expr {
            write!(f, "\n{}", expr.to_string_formatted(self.instr_index, false, false, None))?;
        }
        Ok(())
    }
}

impl std::error::Error for DWARFExpressionException {}

/// Placeholder for `ghidra.app.util.bin.format.dwarf.external.DebugInfoProviderRegistry`,
/// referenced by `DebugInfoProviderCreatorContext` before the real class is ported.
pub trait DebugInfoProviderRegistry: Send + Sync {
    fn get_instance(&self) -> Box<dyn DebugInfoProviderRegistry>;
    fn register(&self, test_func: &dyn std::any::Any, create_func: &dyn std::any::Any);
    fn new_context(&self, program: &dyn crate::program::model::listing::Program) -> Box<dyn std::any::Any>;
    fn create(&self, name: &str, context: &dyn std::any::Any) -> Box<dyn crate::format::dwarf::external::debug_info_provider::DebugInfoProvider>;
}

/// Placeholder for `ghidra.app.util.bin.format.golang.structmapping.FieldContext`,
/// referenced by `FieldMarkupFunction` before the real class is ported.
pub trait FieldContext<T>: Send + Sync {
    fn get_structure_instance(&self) -> &T;
    fn get_address(&self) -> Address;
    fn get_value(&self, expected_type: &dyn std::any::Any) -> std::io::Result<Box<dyn std::any::Any>>;
}

/// Placeholder for `ghidra.app.util.bin.format.golang.structmapping.MarkupSession`,
/// referenced by `FieldMarkupFunction` before the real class is ported.
pub trait MarkupSession: Send + Sync {
    fn get_program(&self) -> Box<dyn crate::program::model::listing::Program>;
    fn get_mapping_context(&self) -> Box<dyn std::any::Any>;
    fn get_markedup_addresses(&self) -> Box<dyn std::any::Any>;
    fn markup(&self, obj: &dyn std::any::Any, nested: bool) -> std::io::Result<()>;
    fn markup_address(
        &self,
        addr: Address,
        dt: &dyn crate::program::model::data::data_type::DataType,
    ) -> std::io::Result<()>;
    fn markup_address_if_undefined(
        &self,
        addr: Address,
        dt: &dyn crate::program::model::data::data_type::DataType,
    ) -> std::io::Result<()>;
    fn label_structure(&self, obj: &dyn std::any::Any, symbol_name: &str, namespace_name: &str) -> std::io::Result<()>;
    fn label_address(&self, addr: Address, symbol_name: &str) -> std::io::Result<()>;
    /// Mirrors the `MarkupSession.labelAddress(Address, String, String)` overload; Rust traits
    /// have no overloading, so the namespace-qualified form gets its own name.
    fn label_address_in_namespace(
        &self,
        addr: Address,
        symbol_name: &str,
        namespace_name: &str,
    ) -> std::io::Result<()>;
    fn append_comment(
        &self,
        field_context: &dyn std::any::Any,
        comment_type: &dyn std::any::Any,
        prefix: &str,
        comment: &str,
        sep: &str,
    ) -> std::io::Result<()>;
    fn markup_structure(&self, structure_context: &dyn std::any::Any, nested: bool) -> std::io::Result<()>;
    fn markup_array_element_references(
        &self,
        array_addr: Address,
        element_size: i32,
        target_addrs: Vec<Address>,
    ) -> std::io::Result<()>;
    fn create_function_if_missing(
        &self,
        name: &str,
        ns: &dyn std::any::Any,
        addr: Address,
    ) -> Box<dyn std::any::Any>;
    fn add_reference(&self, field_context: &dyn std::any::Any, ref_dest: Address);
    fn log_warning_at(&self, addr: Address, msg: &str);
}

/// Placeholder for `ghidra.app.util.bin.format.golang.structmapping.FieldOutputInfo`,
/// referenced by `FieldOutputFunction` before the real class is ported.
pub trait FieldOutputInfo<T>: Send + Sync {
    fn get_field(&self) -> Box<dyn std::any::Any>;
    fn get_ordinal(&self) -> i32;
    fn is_variable_length(&self) -> bool;
    fn get_output_func(&self) -> Option<Box<dyn std::any::Any>>;
    fn get_value(&self, struct_instance: &T, expected_type: &dyn std::any::Any) -> std::io::Result<Box<dyn std::any::Any>>;
    fn set_output_func_class(&self, func_class: &dyn std::any::Any, getter_name: Option<&str>);
}

/// Placeholder for `ghidra.app.util.bin.format.golang.structmapping.StructureMappingInfo`,
/// referenced by `StructureContext` (and, through it, by `StructureMarkup`) before the real
/// class is ported.
pub trait StructureMappingInfo<T>: Send + Sync {
    fn structure_name(&self) -> String;
}

/// Placeholder for `ghidra.app.util.bin.format.golang.structmapping.StructureContext`,
/// referenced by `FieldOutputFunction` before the real class is ported.
pub trait StructureContext<T>: Send + Sync {
    fn get_mapping_info(&self) -> Box<dyn StructureMappingInfo<T>>;
    fn get_data_type_mapper(&self) -> Box<dyn std::any::Any>;
    fn get_containing_field_data_type(&self) -> Box<dyn crate::program::model::data::data_type::DataType>;
    fn get_structure_address(&self) -> Address;
    fn get_field_address(&self, field_offset: i64) -> Address;
    fn get_field_location(&self, field_offset: i64) -> i64;
    fn get_structure_start(&self) -> i64;
    fn get_structure_end(&self) -> i64;
    fn get_structure_length(&self) -> i32;
    fn get_structure_instance(&self) -> &T;
    fn get_reader(&self) -> Box<dyn crate::app::util::bin::binary_reader::BinaryReader>;
    fn get_field_reader(
        &self,
        field_offset: i64,
    ) -> Box<dyn crate::app::util::bin::binary_reader::BinaryReader>;
    fn create_field_context(&self, fmi: &dyn std::any::Any, include_reader: bool) -> Box<dyn std::any::Any>;
    fn get_structure_data_type(&self) -> std::io::Result<Box<dyn crate::program::model::data::structure::Structure>>;
    fn to_string(&self) -> String;
}

/// Placeholder for `ghidra.app.util.bin.format.golang.rtti.types.GoMethod`, referenced by
/// [`GoUncommonType`](crate::format::golang::rtti::types::go_uncommon_type::GoUncommonType)
/// before the real class is ported.
pub trait GoMethod: Send + Sync {
    fn get_name(&self) -> String;
}

/// Placeholder for `ghidra.app.util.bin.format.golang.rtti.GoName`, referenced by
/// [`GoUncommonType`](crate::format::golang::rtti::types::go_uncommon_type::GoUncommonType)
/// before the real class is ported.
pub trait GoName: Send + Sync {
    fn get_name(&self) -> String;
}

/// Placeholder for `ghidra.app.util.bin.format.golang.rtti.GoSlice`, referenced by
/// [`GoUncommonType`](crate::format::golang::rtti::types::go_uncommon_type::GoUncommonType) and
/// [`GoItab`](crate::format::golang::rtti::go_itab::GoItab) before the real class is ported.
pub trait GoSlice: Send + Sync {
    fn is_valid(&self, element_size: i32) -> bool;
    fn read_go_methods(&self) -> std::io::Result<Vec<Box<dyn GoMethod>>>;
    /// Mirrors `GoSlice.getLen()`.
    fn get_len(&self) -> i64;
    /// Mirrors `GoSlice.getSubSlice(long, long, long)`.
    fn get_sub_slice(&self, start_element: i64, element_count: i64, element_size: i64) -> Box<dyn GoSlice>;
    /// Mirrors `GoSlice.readUIntList(int)`.
    fn read_u_int_list(&self, int_size: i32) -> std::io::Result<Vec<i64>>;
    /// Mirrors `GoSlice.markupElementReferences(int, List, MarkupSession)`.
    fn markup_element_references(
        &self,
        element_size: i32,
        target_addrs: Vec<Address>,
        session: &dyn MarkupSession,
    ) -> std::io::Result<()>;
    /// Mirrors the `GoSlice.markupArray(String, String, DataType, boolean, MarkupSession)`
    /// overload (the `Class<?>`-based overload isn't needed by any current caller).
    fn markup_array(
        &self,
        slice_name: &str,
        namespace_name: &str,
        element_type: Option<&dyn crate::program::model::data::data_type::DataType>,
        ptr: bool,
        session: &dyn MarkupSession,
    ) -> std::io::Result<()>;
    /// Mirrors `GoSlice.getArrayAddress()`.
    fn get_array_address(&self) -> Address;
    /// Mirrors `GoSlice.getElementOffset(long, long)`.
    fn get_element_offset(&self, element_size: i64, element_index: i64) -> i64;
    /// Mirrors `GoSlice.readUIntElement(int, int)`.
    fn read_u_int_element(&self, int_size: i32, element_index: i32) -> std::io::Result<i64>;
    /// Mirrors `GoSlice.getElementReader(int, int)`.
    fn get_element_reader(
        &self,
        element_size: i32,
        element_index: i32,
    ) -> Box<dyn crate::app::util::bin::binary_reader::BinaryReader>;
}

/// Placeholder for `ghidra.app.util.bin.format.golang.rtti.GoRttiMapper`, referenced by
/// [`GoUncommonType`](crate::format::golang::rtti::types::go_uncommon_type::GoUncommonType) and
/// [`GoBaseType`](crate::format::golang::rtti::types::go_base_type::GoBaseType) before the real
/// class is ported.
pub trait GoRttiMapper: Send + Sync {
    fn resolve_name_off(&self, ptr_in_module: i64, off: i64) -> std::io::Result<Option<Box<dyn GoName>>>;
    fn new_slice(&self, array: i64, len: i64, cap: i64) -> Box<dyn GoSlice>;
    fn go_method_structure_length(&self) -> i32;
    /// Mirrors `GoRttiMapper.getGoVer()`.
    fn get_go_ver(&self) -> GoVer;
    /// Mirrors `GoRttiMapper.getSafeName(GoNameSupplier, T, String)`, simplified to return the
    /// resolved name string directly rather than a `GoName` wrapper, since every current call
    /// site immediately calls `.getName()` on the result. `fallback_structure_name` and
    /// `fallback_structure_start` stand in for the `StructureContext<T>` that the real method
    /// derives its fallback name from when `supplier` fails or returns nothing.
    fn get_safe_name(
        &self,
        supplier: &dyn Fn() -> std::io::Result<Option<Box<dyn GoName>>>,
        fallback_structure_name: &str,
        fallback_structure_start: i64,
        default_value: &str,
    ) -> String;
    /// Mirrors `GoRttiMapper.getGoTypes()`.
    fn get_go_types(&self) -> Box<dyn GoTypeManager>;
    /// Mirrors `GoRttiMapper.getPtrSize()`.
    fn get_ptr_size(&self) -> i32;
    /// Mirrors `DataTypeMapper.getCodeAddress(long)`, inherited by `GoRttiMapper`.
    fn get_code_address(&self, offset: i64) -> Address;
    /// Simplified stand-in for the Java call chain
    /// `getProgram().getMemory().getLoadedAndInitializedAddressSet().contains(addr)`, following
    /// the same simplification precedent as [`get_safe_name`](Self::get_safe_name): every current
    /// call site only cares about the boolean result, not `Program`/`Memory` themselves.
    fn is_loaded_and_initialized(&self, addr: Address) -> bool;
    /// Mirrors `DataTypeMapper.getDataAddress(long)`, inherited by `GoRttiMapper`.
    fn get_data_address(&self, offset: i64) -> Address;
    /// Mirrors `DataTypeMapper.getReader(long)`, inherited by `GoRttiMapper`.
    fn get_reader(&self, position: i64) -> Box<dyn crate::app::util::bin::binary_reader::BinaryReader>;
    /// Mirrors `GoRttiMapper.findContainingModuleByFuncData(long)`. The Java method returns
    /// `null` when no module contains the offset, which every caller checks for.
    fn find_containing_module_by_func_data(&self, offset: i64) -> Option<Box<dyn GoModuledata>>;
    /// Static factory `GoSymbolName.parse(String)`, exposed as an instance method because a
    /// trait object cannot dispatch a Rust associated function. Every current call site already
    /// holds the `GoRttiMapper`, so routing the parse through it costs nothing and lets the real
    /// `GoSymbolName` port supply the implementation later.
    fn parse_symbol_name(&self, s: &str) -> Box<dyn GoSymbolName>;
    /// Simplified stand-in for `getProgram().getFunctionManager().getFunctionAt(addr)`, following
    /// the same precedent as [`is_loaded_and_initialized`](Self::is_loaded_and_initialized): the
    /// call sites want the function, not the `Program`/`FunctionManager` chain that produces it.
    fn get_function_at(
        &self,
        addr: &Address,
    ) -> Option<std::sync::Arc<dyn crate::program::model::listing::function::Function>>;
    /// Simplified stand-in for `new ArrayDataType(elementType, numElements, -1, getDTM())`.
    /// `ghidra.program.model.data.ArrayDataType` is not ported yet, and the `DataTypeManager`
    /// argument is always this mapper's own DTM, so the whole construction collapses to one call.
    fn new_array_data_type(
        &self,
        element_type: &dyn crate::program::model::data::data_type::DataType,
        num_elements: i32,
    ) -> Box<dyn crate::program::model::data::data_type::DataType>;
    /// Simplified stand-in for `getProgram().getSourceFileManager().addSourceFile(sourceFile)`.
    /// Takes `&self` because the real mapper reaches a mutable manager through its `Program`
    /// handle rather than through this borrow.
    fn add_source_file(
        &self,
        source_file: &crate::program::database::sourcemap::SourceFile,
    ) -> Result<(), Box<dyn std::error::Error>>;
    /// Simplified stand-in for
    /// `getProgram().getSourceFileManager().addSourceMapEntry(sourceFile, lineNumber, baseAddr, length)`.
    /// See [`add_source_file`](Self::add_source_file) for why this takes `&self`.
    fn add_source_map_entry(
        &self,
        source_file: &crate::program::database::sourcemap::SourceFile,
        line_number: i32,
        base_addr: &Address,
        length: i64,
    ) -> Result<(), Box<dyn std::error::Error>>;
}

/// Placeholder for `ghidra.app.util.bin.format.golang.rtti.GoModuledata`, referenced by
/// [`GoFuncData`](crate::format::golang::rtti::go_func_data::GoFuncData) before the real class is
/// ported. Only the members `GoFuncData` needs are declared; the nullable Java getters are
/// modelled as `Option` because `GoFuncData` null-checks each of them.
pub trait GoModuledata: Send + Sync {
    /// Mirrors `GoModuledata.getText()`.
    fn get_text(&self) -> Address;
    /// Mirrors `GoModuledata.getGofunc()`.
    fn get_gofunc(&self) -> i64;
    /// Mirrors `GoModuledata.getFuncnametab()`.
    fn get_funcnametab(&self) -> Option<Box<dyn GoSlice>>;
    /// Mirrors `GoModuledata.getCutab()`.
    fn get_cutab(&self) -> Option<Box<dyn GoSlice>>;
    /// Mirrors `GoModuledata.getFiletab()`.
    fn get_filetab(&self) -> Option<Box<dyn GoSlice>>;
    /// Mirrors `GoModuledata.getPclntable()`.
    fn get_pclntable(&self) -> Option<Box<dyn GoSlice>>;
    /// Mirrors `GoModuledata.getPctab()`.
    fn get_pctab(&self) -> Option<Box<dyn GoSlice>>;
    /// Stands in for `new GoPcValueEvaluator(funcData, offset)`. The Java constructor takes the
    /// `GoFuncData` only to reach this moduledata (for `getGoBinary().getMinLC()` and
    /// `getPcValueTable()`) plus the function's entry PC, so moving the factory here breaks the
    /// `GoFuncData` <-> `GoPcValueEvaluator` construction cycle without losing any input.
    fn new_pc_value_evaluator(
        &self,
        offset: i64,
        func_entry: i64,
    ) -> std::io::Result<Box<dyn GoPcValueEvaluator>>;
}

/// Placeholder for `ghidra.app.util.bin.format.golang.rtti.GoPcValueEvaluator`, referenced by
/// [`GoFuncData`](crate::format::golang::rtti::go_func_data::GoFuncData) before the real class is
/// ported. Evaluation advances an internal reader cursor, value, and PC, so every stepping method
/// takes `&mut self`.
pub trait GoPcValueEvaluator: Send + Sync {
    /// Mirrors `GoPcValueEvaluator.getPC()`.
    fn get_pc(&self) -> i64;
    /// Mirrors `GoPcValueEvaluator.reset()`.
    fn reset(&mut self);
    /// Mirrors `GoPcValueEvaluator.getMaxPC()`.
    fn get_max_pc(&mut self) -> std::io::Result<i64>;
    /// Mirrors `GoPcValueEvaluator.eval(long)`.
    fn eval(&mut self, target_pc: i64) -> std::io::Result<i32>;
    /// Mirrors `GoPcValueEvaluator.evalNext()`.
    fn eval_next(&mut self) -> std::io::Result<i32>;
    /// Mirrors `GoPcValueEvaluator.evalAll(long)`.
    fn eval_all(&mut self, target_pc: i64) -> std::io::Result<Vec<i32>>;
    /// Mirrors `GoPcValueEvaluator.markup(MarkupSession)`.
    fn markup(&mut self, session: &dyn MarkupSession) -> std::io::Result<()>;
}

/// Placeholder for `ghidra.app.util.bin.format.golang.rtti.types.GoTypeFlag`, referenced by
/// [`GoBaseType`](crate::format::golang::rtti::types::go_base_type::GoBaseType) before the real
/// class is ported. `GoTypeFlag` is a concrete Java enum (not an interface), so it is modeled
/// here as a concrete enum. Its only real dependencies ([`GoVer`] and [`GoVerRange`]) are already
/// ported, so this mirrors the Java enum's logic 1:1 rather than being a bare shape hint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GoTypeFlag {
    Uncommon,
    ExtraStar,
    Named,
    RegularMemory,
    UnrolledBitmap,
    GCMaskOnDemand,
    DirectIFace,
}

impl GoTypeFlag {
    const ALL: [GoTypeFlag; 7] = [
        GoTypeFlag::Uncommon,
        GoTypeFlag::ExtraStar,
        GoTypeFlag::Named,
        GoTypeFlag::RegularMemory,
        GoTypeFlag::UnrolledBitmap,
        GoTypeFlag::GCMaskOnDemand,
        GoTypeFlag::DirectIFace,
    ];

    /// Mirrors `GoTypeFlag.getValue()`.
    pub fn value(self) -> i32 {
        match self {
            GoTypeFlag::Uncommon => 1 << 0,
            GoTypeFlag::ExtraStar => 1 << 1,
            GoTypeFlag::Named => 1 << 2,
            GoTypeFlag::RegularMemory => 1 << 3,
            GoTypeFlag::UnrolledBitmap => 1 << 4,
            GoTypeFlag::GCMaskOnDemand => 1 << 4,
            GoTypeFlag::DirectIFace => 1 << 5,
        }
    }

    fn valid_versions(self) -> GoVerRange {
        match self {
            GoTypeFlag::Uncommon
            | GoTypeFlag::ExtraStar
            | GoTypeFlag::Named
            | GoTypeFlag::RegularMemory => GoVerRange::ALL,
            GoTypeFlag::UnrolledBitmap => GoVerRange::parse("1.22-1.23"),
            GoTypeFlag::GCMaskOnDemand | GoTypeFlag::DirectIFace => GoVerRange::parse("1.24-"),
        }
    }

    /// Mirrors `GoTypeFlag.isSet(int, GoVer)`.
    pub fn is_set(self, i: i32, ver: GoVer) -> bool {
        self.valid_versions().contains(ver) && (i & self.value()) != 0
    }

    /// Mirrors `GoTypeFlag.isValid(int, GoVer)`.
    pub fn is_valid(b: i32, ver: GoVer) -> bool {
        let mut remaining = b;
        for flag in Self::ALL {
            if flag.valid_versions().contains(ver) {
                remaining &= !flag.value();
            }
        }
        remaining == 0
    }

    /// Mirrors `GoTypeFlag.parseFlags(int, GoVer)`.
    pub fn parse_flags(b: i32, ver: GoVer) -> Vec<GoTypeFlag> {
        Self::ALL.into_iter().filter(|flag| flag.is_set(b, ver)).collect()
    }
}

/// Placeholder for `ghidra.app.util.bin.format.golang.rtti.types.GoType`, referenced by
/// [`GoBaseType::get_ptr_to_this`](crate::format::golang::rtti::types::go_base_type::GoBaseType::get_ptr_to_this)
/// and [`GoItab`](crate::format::golang::rtti::go_itab::GoItab) before the real class is ported.
pub trait GoType: Send + Sync {
    /// Mirrors `GoType.getName()`.
    fn get_name(&self) -> String;
    /// Mirrors `GoType.getSymbolName()`.
    fn get_symbol_name(&self) -> Box<dyn GoSymbolName>;
    /// Mirrors `GoType.getStructureNamespace()`.
    fn get_structure_namespace(&self) -> std::io::Result<String>;
    /// Mirrors `GoType.discoverGoTypes(Set)`.
    fn discover_go_types(&self, discovered_types: &mut std::collections::HashSet<i64>) -> std::io::Result<bool>;
    /// Downcast hook mirroring Java's `result instanceof GoInterfaceType ifaceType` pattern,
    /// following the same `self: Box<Self>` downcast convention as
    /// [`DataType::into_array`](crate::program::model::data::data_type::DataType::into_array).
    /// Defaults to `None`; the real `GoInterfaceType` port overrides it to return `Some(self)`.
    fn into_interface_type(self: Box<Self>) -> Option<Box<dyn GoInterfaceType>> {
        None
    }
}

/// Placeholder for `ghidra.app.util.bin.format.golang.rtti.GoTypeManager`, referenced by
/// [`GoBaseType::get_ptr_to_this`](crate::format::golang::rtti::types::go_base_type::GoBaseType::get_ptr_to_this)
/// and [`GoItab`](crate::format::golang::rtti::go_itab::GoItab) before the real class is ported.
pub trait GoTypeManager: Send + Sync {
    fn resolve_type_off(&self, ptr_in_module: i64, off: i64) -> std::io::Result<Box<dyn GoType>>;
    /// Mirrors `GoTypeManager.getType(long)`.
    fn get_type(&self, offset: i64) -> std::io::Result<Box<dyn GoType>>;
    /// Mirrors `GoTypeManager.getDataType(String)`.
    fn get_data_type(
        &self,
        type_name: &str,
    ) -> std::io::Result<Box<dyn crate::program::model::data::data_type::DataType>>;
}

/// Placeholder for `ghidra.app.util.bin.format.golang.rtti.GoSymbolName`, referenced by
/// [`GoItab`](crate::format::golang::rtti::go_itab::GoItab) before the real class is ported.
pub trait GoSymbolName: Send + Sync {
    /// Mirrors `GoSymbolName.asString()`.
    fn as_string(&self) -> String;
    /// Mirrors the `packagePath()` record accessor (a.k.a. `getPackagePath()`), which is `null`
    /// for symbols that carry no package path.
    fn package_path(&self) -> Option<String>;
}

/// Placeholder for `ghidra.app.util.bin.format.golang.rtti.types.GoInterfaceType`, referenced by
/// [`GoItab`](crate::format::golang::rtti::go_itab::GoItab) before the real class is ported.
pub trait GoInterfaceType: Send + Sync {
    /// Mirrors `GoInterfaceType.getMethodsSlice()`.
    fn get_methods_slice(&self) -> Box<dyn GoSlice>;
    /// Mirrors `GoInterfaceType.getMethods()`.
    fn get_methods(&self) -> std::io::Result<Vec<Box<dyn GoIMethod>>>;
    /// Mirrors `GoInterfaceType.getMethodListString()`.
    fn get_method_list_string(&self) -> std::io::Result<String>;
    /// Mirrors `GoType.getName()`, inherited (unchanged) by `GoInterfaceType` in Java.
    fn get_name(&self) -> String;
    /// Mirrors `GoType.discoverGoTypes(Set)`, overridden by `GoInterfaceType` in Java.
    fn discover_go_types(&self, discovered_types: &mut std::collections::HashSet<i64>) -> std::io::Result<bool>;
}

/// Placeholder for `ghidra.app.util.bin.format.golang.rtti.types.GoIMethod`, referenced by
/// [`GoItab`](crate::format::golang::rtti::go_itab::GoItab) before the real class is ported.
/// `GoItab` only ever stores and returns this type opaquely, so no members are needed yet.
pub trait GoIMethod: Send + Sync {}

/// The one `ghidra.app.util.bin.format.pe.ResourceDataDirectory` static that
/// [`library_lookup_table`](crate::app::util::opinion::library_lookup_table) reaches, standing in
/// for the class until the real port lands. Java hangs it off the class itself; Rust has no
/// static trait methods, so -- as with the other statics-only seams in this crate -- it becomes a
/// free function in a module named for the Java class.
///
/// The rest of `ResourceDataDirectory` (the `<resource>` tree walker, its `markup`, ...) is a
/// large unported subsystem and is deliberately not modeled here.
pub mod resource_data_directory {
    /// Port of `ResourceDataDirectory.getPeResourceProperty(String)`: the `Program` property name
    /// under which the PE resource entry named `key` is recorded. Implemented for real (it is
    /// pure string manipulation) so callers see the same property names Java produces.
    pub fn get_pe_resource_property(key: &str) -> String {
        format!("PE Property[{}]", key.replace('.', "_dot_"))
    }
}


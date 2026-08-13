//! Minimal placeholder traits for core types that a ported interface references before the real
//! Rust port of that type exists yet. Each stub exposes only the members needed by the
//! interface(s) that currently reference it, and is expected to be replaced (or grown into a
//! supertrait of) the real port once that Java class is ported. See `STUBS.tsv` for provenance.

use crate::format::pdb2::pdbreader::r#type::abstract_ms_type::AbstractMsType;
use crate::format::pe::rich::ms_product_type::MsProductType;

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
}

/// Placeholder for `ghidra.app.util.bin.format.MemoryLoadable`, referenced by
/// [`ElfLoadAdapter::get_filtered_load_input_stream`](crate::format::elf::extend::elf_load_adapter::ElfLoadAdapter::get_filtered_load_input_stream)
/// before the real interface is ported. The adapter only ever passes the loadable through, so no
/// members are needed yet; the real interface is implemented by `ElfSectionHeader` and
/// `ElfProgramHeader`.
pub trait MemoryLoadable: Send + Sync {}

/// Placeholder for `ghidra.app.util.bin.format.elf.ElfDynamicType`, referenced by
/// [`ElfLoadAdapter::add_dynamic_types`](crate::format::elf::extend::elf_load_adapter::ElfLoadAdapter::add_dynamic_types)
/// before the real class is ported. Only used as the value type of the extension type map.
pub trait ElfDynamicType: Send + Sync {}

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

/// Placeholder for `ghidra.app.util.bin.format.elf.ElfLoadHelper`, referenced by
/// [`ElfRelocationContextBase`](crate::format::elf::relocation::elf_relocation_context::ElfRelocationContextBase)
/// before `ElfProgramBuilder` (its only implementation) is ported. Only the members the
/// relocation context needs.
pub trait ElfLoadHelper: Send + Sync {
    /// `ElfLoadHelper.getProgram()`.
    fn get_program(&self) -> std::sync::Arc<dyn crate::program::model::listing::program::Program>;

    /// `ElfLoadHelper.getElfHeader()`.
    fn get_elf_header(&self) -> std::sync::Arc<dyn ElfHeader>;

    /// `ElfLoadHelper.getLog()`.
    fn get_log(&self) -> std::sync::Arc<dyn MessageLog>;

    /// `ElfLoadHelper.log(String)`.
    fn log(&self, msg: &str);

    /// `ElfLoadHelper.log(Throwable)`.
    fn log_exception(&self, t: &dyn std::error::Error);

    /// `ElfLoadHelper.getImageBaseWordAdjustmentOffset()`.
    fn get_image_base_word_adjustment_offset(&self) -> i64;

    /// `ElfLoadHelper.getGOTValue()`, whose Java return type is the nullable `Long`.
    fn get_got_value(&self) -> Option<i64>;
}

/// Placeholder for `ghidra.app.util.bin.format.elf.ElfRelocation`, referenced by
/// [`ElfRelocationContext::process_relocation`](crate::format::elf::relocation::elf_relocation_context::ElfRelocationContext::process_relocation)
/// before the real class is ported. Only the two entry fields the dispatch reads.
pub trait ElfRelocation: Send + Sync {
    /// `ElfRelocation.getSymbolIndex()` -- the symbol table index encoded in `r_info`.
    fn get_symbol_index(&self) -> i32;

    /// `ElfRelocation.getType()` -- the relocation type ID encoded in `r_info`.
    fn get_type(&self) -> i32;
}

/// Placeholder for `ghidra.app.util.bin.format.elf.ElfRelocationTable`, referenced by
/// [`ElfRelocationContext::start_relocation_table_processing`](crate::format::elf::relocation::elf_relocation_context::ElfRelocationContext::start_relocation_table_processing)
/// before the real class is ported. Only the two members the relocation context needs.
pub trait ElfRelocationTable: Send + Sync {
    /// `ElfRelocationTable.hasAddendRelocations()` -- true for `RELA`-style tables, whose entries
    /// carry their own addend.
    fn has_addend_relocations(&self) -> bool;

    /// `ElfRelocationTable.getAssociatedSymbolTable()`, which is `null` (here `None`) when the
    /// table has no associated symbol table.
    fn get_associated_symbol_table(&self) -> Option<std::sync::Arc<dyn ElfSymbolTable>>;
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

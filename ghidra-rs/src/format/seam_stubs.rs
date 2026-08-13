//! Minimal placeholder traits for core types that a ported interface references before the real
//! Rust port of that type exists yet. Each stub exposes only the members needed by the
//! interface(s) that currently reference it, and is expected to be replaced (or grown into a
//! supertrait of) the real port once that Java class is ported. See `STUBS.tsv` for provenance.

use crate::format::pdb2::pdbreader::r#type::abstract_ms_type::AbstractMsType;

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

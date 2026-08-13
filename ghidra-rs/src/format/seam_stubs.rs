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

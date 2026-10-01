//! Minimal placeholder types for core types that a ported type references before the real
//! Rust port of that type exists yet. Each stub exposes only the members needed by the
//! interface(s) that currently reference it, and is expected to be replaced once the Java class
//! is ported. See `STUBS.tsv` for provenance.

use std::io;
use std::path::Path;

use crate::program::model::data::data_type::DataType;
use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::file::formats::android::dex::format::dex_header::DexHeader;
use crate::file::formats::android::oat::oat_class_status_enum::OatClassStatusEnum;
use crate::filesystem::gfilesystem::fsrl_root::FsrlRoot;
use crate::filesystem::gfilesystem::file_system_service::FileSystemService;
use crate::filesystem::gfilesystem::g_file_system::FsHandle;
use crate::app::util::bin::byte_provider::ByteProvider;
use crate::program::model::listing::program::Program;
use crate::util::task::TaskMonitor;

/// Placeholder for the unported Java type `StructConverterUtil`, referenced by `FieldAnnotationsItem`.
/// Concrete stub: Java class, not interface. Only methods THIS type needs are included.
/// Replace with the real port when available.
pub struct StructConverterUtil;

impl StructConverterUtil {
    pub fn to_data_type(&self, _object: &dyn std::any::Any) -> Box<dyn DataType> {
        unimplemented!("StructConverterUtil.to_data_type not yet ported")
    }

    pub fn parse_name(&self, _clazz: &dyn std::any::Any) -> String {
        unimplemented!("StructConverterUtil.parse_name not yet ported")
    }

    pub fn main(&self, _args: &[String]) {
        unimplemented!("StructConverterUtil.main not yet ported")
    }
}

/// Placeholder for the unported Java type `AnnotationSetItem`, referenced by `FieldAnnotationsItem`.
/// Concrete stub: Java class, not interface. Only methods THIS type needs are included.
/// Replace with the real port when available.
#[derive(Debug, Clone)]
pub struct AnnotationSetItem;

impl AnnotationSetItem {
    pub fn get_size(&self) -> i32 {
        unimplemented!("AnnotationSetItem.get_size not yet ported")
    }

    pub fn get_entries(&self) -> Vec<i32> {
        unimplemented!("AnnotationSetItem.get_entries not yet ported")
    }

    pub fn to_data_type(&self) -> std::io::Result<Box<dyn DataType>> {
        unimplemented!("AnnotationSetItem.to_data_type not yet ported")
    }
}

/// Placeholder for the unported Java type `ArtHeader`, referenced by `OatBundle`.
/// Concrete stub: Java class, not interface. Only methods THIS type needs are included.
/// Replace with the real port when available.
pub struct ArtHeader;

impl ArtHeader {
    pub fn get_magic(&self) -> String {
        unimplemented!("ArtHeader.get_magic not yet ported")
    }

    pub fn get_version(&self) -> String {
        unimplemented!("ArtHeader.get_version not yet ported")
    }

    pub fn get_image_begin(&self) -> i32 { 0 }
    pub fn get_image_size(&self) -> i32 { 0 }
    pub fn get_oat_checksum(&self) -> i32 { 0 }
    pub fn get_oat_file_begin(&self) -> i32 { 0 }
    pub fn get_oat_file_end(&self) -> i32 { 0 }
    pub fn get_oat_data_begin(&self) -> i32 { 0 }
    pub fn get_oat_data_end(&self) -> i32 { 0 }
    pub fn get_pointer_size(&self) -> i32 { 0 }
    pub fn get_art_method_count_for_version(&self) -> i32 { 0 }

    pub fn markup(&self, _program: &dyn std::any::Any, _monitor: &dyn TaskMonitor) -> std::io::Result<()> {
        unimplemented!("ArtHeader.markup not yet ported")
    }

    pub fn to_data_type(&self) -> std::io::Result<Box<dyn DataType>> {
        unimplemented!("ArtHeader.to_data_type not yet ported")
    }
}


/// Placeholder for the unported Java type `VdexHeader`, referenced by `OatBundle`.
/// Concrete stub: Java class, not interface. Only methods THIS type needs are included.
/// Replace with the real port when available.
pub struct VdexHeader;

impl VdexHeader {
    pub fn get_magic(&self) -> String {
        unimplemented!("VdexHeader.get_magic not yet ported")
    }

    pub fn get_version(&self) -> String {
        unimplemented!("VdexHeader.get_version not yet ported")
    }

    pub fn parse(&self, _reader: &BinaryReader, _monitor: &dyn TaskMonitor) -> std::io::Result<()> {
        unimplemented!("VdexHeader.parse not yet ported")
    }

    pub fn get_dex_start_offset(&self, _index: i32) -> i64 { 0 }
    pub fn get_verifier_deps_size(&self) -> i32 { 0 }
    pub fn get_quickening_info_size(&self) -> i32 { 0 }
    pub fn get_dex_checksums(&self) -> Vec<i32> { vec![] }
    pub fn is_dex_header_embedded_in_data_type(&self) -> bool { false }

    pub fn to_data_type(&self) -> std::io::Result<Box<dyn DataType>> {
        unimplemented!("VdexHeader.to_data_type not yet ported")
    }
}

/// Placeholder for the unported Java type `DexUtil`, referenced by `FieldAnnotationsItem`.
/// Concrete stub: Java class with static methods. Only methods THIS type needs are included.
/// Replace with the real port when available.
pub struct DexUtil;

impl DexUtil {
    pub fn to_data_type(_dtm: &dyn std::any::Any, _data_type_string: &str) -> Box<dyn DataType> {
        unimplemented!("DexUtil.to_data_type not yet ported")
    }

    pub fn adjust_offset(offset: i32, _header: &DexHeader) -> i32 {
        offset
    }

    pub fn convert_type_index_to_string(_header: &DexHeader, _type_index: i32) -> String {
        unimplemented!("DexUtil.convert_type_index_to_string not yet ported")
    }

    pub fn convert_to_string(_header: &DexHeader, _string_index: i32) -> String {
        unimplemented!("DexUtil.convert_to_string not yet ported")
    }
}

/// Placeholder for the unported Java type `TypeItem`, referenced by `ClassDefItem`.
/// Concrete stub: Java class, not interface. Only methods THIS type needs are included.
/// Replace with the real port when available.
#[derive(Debug, Clone, Copy)]
pub struct TypeItem;

impl TypeItem {
    pub fn get_type(&self) -> i16 {
        unimplemented!("TypeItem.get_type not yet ported")
    }

    pub fn to_data_type(&self) -> std::io::Result<Box<dyn DataType>> {
        unimplemented!("TypeItem.to_data_type not yet ported")
    }
}

/// Placeholder for the unported Java type `TypeList`, referenced by `ClassDefItem`.
/// Concrete stub: Java class, not interface. Only methods THIS type needs are included.
/// Replace with the real port when available.
#[derive(Debug, Clone)]
pub struct TypeList;

impl TypeList {
    pub fn get_size(&self) -> i32 {
        unimplemented!("TypeList.get_size not yet ported")
    }

    pub fn get_items(&self) -> Vec<TypeItem> {
        unimplemented!("TypeList.get_items not yet ported")
    }

    pub fn to_data_type(&self) -> std::io::Result<Box<dyn DataType>> {
        unimplemented!("TypeList.to_data_type not yet ported")
    }
}

/// Placeholder for the unported Java type `StringDataItem`, referenced by `StringIDItem`.
/// Concrete stub: Java class, not interface. Only methods THIS type needs are included.
/// Replace with the real port when available.
#[derive(Debug, Clone)]
pub struct StringDataItem {
    string: String,
}

impl StringDataItem {
    pub fn new(string: String) -> Self {
        Self { string }
    }

    pub fn get_string(&self) -> String {
        self.string.clone()
    }

    pub fn to_data_type(&self) -> Box<dyn DataType> {
        unimplemented!("StringDataItem.to_data_type not yet ported")
    }
}

/// Placeholder for the unported Java type `AnnotationsDirectoryItem`, referenced by `ClassDefItem`.
/// Concrete stub: Java class, not interface. Only methods THIS type needs are included.
/// Replace with the real port when available.
#[derive(Debug, Clone)]
pub struct AnnotationsDirectoryItem;

impl AnnotationsDirectoryItem {
    pub fn to_data_type(&self) -> std::io::Result<Box<dyn DataType>> {
        unimplemented!("AnnotationsDirectoryItem.to_data_type not yet ported")
    }
}

/// Placeholder for the unported Java type `ClassDataItem`, referenced by `ClassDefItem`.
/// Concrete stub: Java class, not interface. Only methods THIS type needs are included.
/// Replace with the real port when available.
#[derive(Debug, Clone)]
pub struct ClassDataItem;

impl ClassDataItem {
    pub fn to_data_type(&self) -> std::io::Result<Box<dyn DataType>> {
        unimplemented!("ClassDataItem.to_data_type not yet ported")
    }
}

/// Placeholder for the unported Java type `EncodedArrayItem`, referenced by `ClassDefItem`.
/// Concrete stub: Java class, not interface. Only methods THIS type needs are included.
/// Replace with the real port when available.
#[derive(Debug, Clone)]
pub struct EncodedArrayItem;

impl EncodedArrayItem {
    pub fn to_data_type(&self) -> std::io::Result<Box<dyn DataType>> {
        unimplemented!("EncodedArrayItem.to_data_type not yet ported")
    }
}

/// Placeholder standing in for the third-party `android.content.res.AXmlResourceParser`
/// (itself implementing `org.xmlpull.v1.XmlPullParser`), which
/// [`AndroidXmlConvertor::convert`](crate::file::formats::android::xml::android_xml_convertor::AndroidXmlConvertor::convert)
/// walks to render a binary Android XML document as text. Unlike every other placeholder in
/// this file, neither class is a Ghidra type awaiting its own port -- both come from a bundled
/// third-party AXMLPrinter-derived library that is not part of Ghidra's own source tree (no
/// `AXmlResourceParser.java`/`TypedValue.java` exists anywhere under `orig_src`), so there is
/// nothing to port. Like the Z3 SDK seam in `feature/seam_stubs.rs`, this defines the minimal
/// surface `AndroidXmlConvertor::convert` actually calls, as a trait a real binary-XML parser
/// (or, for now, only this crate's own tests) can implement.
pub trait AXmlResourceParser {
    /// Opens `input` for parsing. Mirrors `AXmlResourceParser.open(InputStream)`; takes the
    /// whole payload directly since every caller in this crate already has the bytes in memory.
    fn open(&mut self, input: &[u8]) -> Result<(), AXmlParseError>;

    /// Advances to, and returns, the next parse event. Mirrors `XmlPullParser.next()`.
    fn next(&mut self) -> Result<AndroidXmlEvent, AXmlParseError>;

    /// The current element's namespace prefix, if any. Mirrors `XmlPullParser.getPrefix()`.
    fn get_prefix(&self) -> Option<String>;

    /// The current element's (or, during attribute iteration, the current attribute's) local
    /// name. Mirrors `XmlPullParser.getName()`.
    fn get_name(&self) -> String;

    /// The nesting depth of the current parse event. Mirrors `XmlPullParser.getDepth()`.
    fn get_depth(&self) -> i32;

    /// The number of namespace declarations in scope at `depth`. Mirrors
    /// `XmlPullParser.getNamespaceCount(int)`.
    fn get_namespace_count(&self, depth: i32) -> i32;

    /// The prefix of the `index`-th in-scope namespace declaration. Mirrors
    /// `XmlPullParser.getNamespacePrefix(int)`.
    fn get_namespace_prefix(&self, index: i32) -> String;

    /// The URI of the `index`-th in-scope namespace declaration. Mirrors
    /// `XmlPullParser.getNamespaceUri(int)`.
    fn get_namespace_uri(&self, index: i32) -> String;

    /// The number of attributes on the current start tag. Mirrors
    /// `XmlPullParser.getAttributeCount()`.
    fn get_attribute_count(&self) -> i32;

    /// The `index`-th attribute's namespace prefix, if any. Mirrors
    /// `XmlPullParser.getAttributePrefix(int)`.
    fn get_attribute_prefix(&self, index: i32) -> Option<String>;

    /// The `index`-th attribute's local name. Mirrors `XmlPullParser.getAttributeName(int)`.
    fn get_attribute_name(&self, index: i32) -> String;

    /// The `index`-th attribute's already-formatted string value; only meaningful (and only
    /// ever called) when [`get_attribute_value_type`](Self::get_attribute_value_type) reports
    /// [`android_typed_value::TYPE_STRING`]. Mirrors `AXmlResourceParser.getAttributeValue(int)`.
    fn get_attribute_value(&self, index: i32) -> String;

    /// The `index`-th attribute's raw `TypedValue` type code (one of the `TYPE_*` constants in
    /// [`android_typed_value`]). Mirrors `AXmlResourceParser.getAttributeValueType(int)`.
    fn get_attribute_value_type(&self, index: i32) -> i32;

    /// The `index`-th attribute's raw `TypedValue` data word. Mirrors
    /// `AXmlResourceParser.getAttributeValueData(int)`.
    fn get_attribute_value_data(&self, index: i32) -> i32;

    /// The current event's text content; only meaningful for [`AndroidXmlEvent::Text`]. Mirrors
    /// `XmlPullParser.getText()`.
    fn get_text(&self) -> String;

    /// Releases any resources held by the parser. Mirrors `AXmlResourceParser.close()`.
    fn close(&mut self);
}

/// A parse event produced by [`AXmlResourceParser::next`], standing in for the subset of
/// `org.xmlpull.v1.XmlPullParser`'s integer event-type constants
/// [`AndroidXmlConvertor::convert`](crate::file::formats::android::xml::android_xml_convertor::AndroidXmlConvertor::convert)
/// switches on. [`AndroidXmlEvent::Other`] stands in for every event type Java's `switch` has no
/// case for (e.g. `COMMENT`, `PROCESSING_INSTRUCTION`), which that `switch` silently ignores.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AndroidXmlEvent {
    StartDocument,
    EndDocument,
    StartTag,
    EndTag,
    Text,
    Other,
}

/// Error produced by [`AXmlResourceParser`] methods, standing in for the
/// `XmlPullParserException`/`ArrayIndexOutOfBoundsException` pair
/// `AndroidXmlConvertor.convert`'s Java source catches identically (both wrapped into a single
/// `IOException("Failed to read AXML file", e)`).
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
#[error("{0}")]
pub struct AXmlParseError(pub String);

/// `TypedValue.TYPE_*`/`COMPLEX_UNIT_MASK` constants from the same third-party `android.util`
/// package as [`AXmlResourceParser`] -- see that trait's own doc comment for why these are
/// hand-carried constants rather than a port. Values match the standard Android SDK
/// `android.util.TypedValue` definitions.
pub mod android_typed_value {
    pub const TYPE_REFERENCE: i32 = 0x01;
    pub const TYPE_ATTRIBUTE: i32 = 0x02;
    pub const TYPE_STRING: i32 = 0x03;
    pub const TYPE_FLOAT: i32 = 0x04;
    pub const TYPE_DIMENSION: i32 = 0x05;
    pub const TYPE_FRACTION: i32 = 0x06;
    pub const TYPE_FIRST_INT: i32 = 0x10;
    pub const TYPE_INT_HEX: i32 = 0x11;
    pub const TYPE_INT_BOOLEAN: i32 = 0x12;
    pub const TYPE_FIRST_COLOR_INT: i32 = 0x1c;
    pub const TYPE_LAST_COLOR_INT: i32 = 0x1f;
    pub const TYPE_LAST_INT: i32 = 0xff;
    pub const COMPLEX_UNIT_MASK: i32 = 0xf;
}

/// Placeholder for the unported Java type `ghidra.file.formats.sevenzip.SevenZipFileSystemFactory`,
/// referenced by `ZipFileSystemFactory`.
///
/// Concrete stub: Java class, not interface. Only the static native-library check THIS type
/// needs is included; the real factory's own `create`/probe machinery is ported separately.
pub struct SevenZipFileSystemFactory;

impl SevenZipFileSystemFactory {
    /// Mirrors `SevenZipFileSystemFactory.initNativeLibraries()`. The 7-Zip JNI bindings have
    /// no Rust port, so this conservatively reports "not available", which routes
    /// `ZipFileSystemFactory::create` to the built-in zip fallback until a real binding lands.
    pub fn init_native_libraries() -> bool {
        false
    }
}

/// Placeholder for the unported Java type `ghidra.file.formats.zip.ZipFileSystem`, referenced
/// by `ZipFileSystemFactory`.
///
/// Concrete stub: Java class, not interface (a thin `SevenZipFileSystem` subclass that changes
/// only its `@FileSystemInfo` flavor to "zip"/`PRIORITY_HIGH`). Only the members
/// `ZipFileSystemFactory::create` needs are included here; the real archive-mounting behaviour
/// belongs to the already-ported `SevenZipFileSystemBase`, whose module doc already anticipates
/// this type (see `crate::file::formats::sevenzip::seven_zip_file_system`).
pub struct ZipFileSystem;


impl ZipFileSystem {
    /// Mirrors `ZipFileSystem(FSRLRoot, FileSystemService)`. The real port stores both
    /// (as `SevenZipFileSystemBase` already does); this stub has nowhere to put them yet.
    pub fn new(_fsrl: &FsrlRoot, _fs_service: &FileSystemService) -> Self {
        ZipFileSystem
    }

    /// Mirrors the inherited `SevenZipFileSystemBase::mount`. Not yet implemented: wiring this
    /// up requires an opened 7-Zip archive (see the `InArchive` seam in `seven_zip_file_system`),
    /// which this stub does not construct.
    pub fn mount(
        &mut self,
        _byte_provider: Box<dyn ByteProvider>,
        _monitor: &dyn TaskMonitor,
    ) -> io::Result<FsHandle> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "ZipFileSystem.mount not yet ported"))
    }

    /// Mirrors the inherited `AbstractSinglePayloadFileSystem::close`.
    pub fn close(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Placeholder for the unported Java type `ghidra.file.formats.zip.ZipFileSystemBuiltin`,
/// referenced by `ZipFileSystemFactory`.
///
/// Concrete stub: Java class, not interface. Only the members `ZipFileSystemFactory::create`
/// needs are included; the real port additionally implements listing, byte-provider access and
/// file attributes via `java.util.zip.ZipFile`.
pub struct ZipFileSystemBuiltin;


impl ZipFileSystemBuiltin {
    /// Mirrors `ZipFileSystemBuiltin.TEMPFILE_PREFIX`.
    pub const TEMPFILE_PREFIX: &'static str = "ghidra_tmp_zipfile";

    /// Mirrors `ZipFileSystemBuiltin(FSRLRoot, FileSystemService)`.
    pub fn new(_fsrl: &FsrlRoot, _fs_service: &FileSystemService) -> Self {
        ZipFileSystemBuiltin
    }

    /// Mirrors `mount(File, boolean, TaskMonitor)`. Not yet implemented: reading zip entries
    /// requires an in-crate zip-archive reader, which does not exist yet.
    pub fn mount(
        &mut self,
        _f: &Path,
        _delete_file_when_done: bool,
        _monitor: &dyn TaskMonitor,
    ) -> io::Result<FsHandle> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "ZipFileSystemBuiltin.mount not yet ported"))
    }

    /// Mirrors `close()`.
    pub fn close(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// ─── OAT class status/type seam, for `OatClass` ───────────────────────────────

/// Placeholder for the unported Java class
/// `ghidra.file.formats.android.oat.oatclass.OatClassStatusEnum_Invalid`, referenced by
/// `OatClass`.
///
/// Concrete stub: Java class, not interface (it implements `OatClassStatusEnum`). Java's
/// `get(short)` always returns `this` regardless of the requested value (there is no "invalid
/// within invalid" case); this stub mirrors that by ignoring the argument and cloning its own
/// stored value. Replace with the real port when available.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OatClassStatusEnumInvalid {
    value: i16,
}

impl OatClassStatusEnumInvalid {
    /// Mirrors `OatClassStatusEnum_Invalid(short)`.
    pub fn new(value: i16) -> Self {
        Self { value }
    }

    pub fn get_value(&self) -> i16 {
        self.value
    }
}

impl StructConverter for OatClassStatusEnumInvalid {
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        unimplemented!("OatClassStatusEnumInvalid.to_data_type not yet ported")
    }
}

impl OatClassStatusEnum for OatClassStatusEnumInvalid {
    fn get(&self, _value: i16) -> Option<Box<dyn OatClassStatusEnum>> {
        Some(Box::new(OatClassStatusEnumInvalid::new(self.value)))
    }
}

/// Placeholder for the unported Java enum
/// `ghidra.file.formats.android.oat.oatclass.OatClassStatusEnum_K`, referenced by `OatClass` for
/// OAT version 007 (KitKat).
///
/// Concrete stub: Java is an enum, not an interface. The real enum's `get(short)` scans its ten
/// named singletons (`kStatusError` .. `kStatusInitialized`) for a matching `getValue()`; that
/// name table is not ported, so this stub always succeeds and wraps whatever value it is asked
/// for. Replace with the real port when available.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OatClassStatusEnumK {
    value: i16,
}

impl OatClassStatusEnumK {
    pub fn new(value: i16) -> Self {
        Self { value }
    }

    /// Mirrors `getValue()`.
    pub fn get_value(&self) -> i16 {
        self.value
    }
}

impl StructConverter for OatClassStatusEnumK {
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        unimplemented!("OatClassStatusEnumK.to_data_type not yet ported")
    }
}

impl OatClassStatusEnum for OatClassStatusEnumK {
    fn get(&self, value: i16) -> Option<Box<dyn OatClassStatusEnum>> {
        Some(Box::new(OatClassStatusEnumK::new(value)))
    }
}

/// Placeholder for the unported Java enum
/// `ghidra.file.formats.android.oat.oatclass.OatClassStatusEnum_L_M_N`, referenced by `OatClass`
/// for OAT versions 039/045/051 (Lollipop), 064 (Marshmallow), 079/088 (Nougat).
///
/// Concrete stub: Java is an enum, not an interface. See [`OatClassStatusEnumK`] for the
/// simplification this stub makes. Replace with the real port when available.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OatClassStatusEnumLMN {
    value: i16,
}

impl OatClassStatusEnumLMN {
    pub fn new(value: i16) -> Self {
        Self { value }
    }

    /// Mirrors `getValue()`.
    pub fn get_value(&self) -> i16 {
        self.value
    }
}

impl StructConverter for OatClassStatusEnumLMN {
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        unimplemented!("OatClassStatusEnumLMN.to_data_type not yet ported")
    }
}

impl OatClassStatusEnum for OatClassStatusEnumLMN {
    fn get(&self, value: i16) -> Option<Box<dyn OatClassStatusEnum>> {
        Some(Box::new(OatClassStatusEnumLMN::new(value)))
    }
}

/// Placeholder for the unported Java enum
/// `ghidra.file.formats.android.oat.oatclass.OatClassStatusEnum_O`, referenced by `OatClass` for
/// OAT version 124 (Oreo).
///
/// Concrete stub: Java is an enum, not an interface. See [`OatClassStatusEnumK`] for the
/// simplification this stub makes. Replace with the real port when available.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OatClassStatusEnumO {
    value: i16,
}

impl OatClassStatusEnumO {
    pub fn new(value: i16) -> Self {
        Self { value }
    }

    /// Mirrors `getValue()`.
    pub fn get_value(&self) -> i16 {
        self.value
    }
}

impl StructConverter for OatClassStatusEnumO {
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        unimplemented!("OatClassStatusEnumO.to_data_type not yet ported")
    }
}

impl OatClassStatusEnum for OatClassStatusEnumO {
    fn get(&self, value: i16) -> Option<Box<dyn OatClassStatusEnum>> {
        Some(Box::new(OatClassStatusEnumO::new(value)))
    }
}

/// Placeholder for the unported Java enum
/// `ghidra.file.formats.android.oat.oatclass.OatClassStatusEnum_O_M2`, referenced by `OatClass`
/// for OAT version 131 (Oreo M2).
///
/// Concrete stub: Java is an enum, not an interface. See [`OatClassStatusEnumK`] for the
/// simplification this stub makes. Replace with the real port when available.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OatClassStatusEnumOM2 {
    value: i16,
}

impl OatClassStatusEnumOM2 {
    pub fn new(value: i16) -> Self {
        Self { value }
    }

    /// Mirrors `getValue()`.
    pub fn get_value(&self) -> i16 {
        self.value
    }
}

impl StructConverter for OatClassStatusEnumOM2 {
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        unimplemented!("OatClassStatusEnumOM2.to_data_type not yet ported")
    }
}

impl OatClassStatusEnum for OatClassStatusEnumOM2 {
    fn get(&self, value: i16) -> Option<Box<dyn OatClassStatusEnum>> {
        Some(Box::new(OatClassStatusEnumOM2::new(value)))
    }
}

/// Placeholder for the unported Java enum
/// `ghidra.file.formats.android.oat.oatclass.OatClassStatusEnum_P_Q`, referenced by `OatClass`
/// for OAT versions 138 (Pie) and 170 (Android 10 / Q).
///
/// Concrete stub: Java is an enum, not an interface. Its `value` field is a `byte`, unlike the
/// `short` used by the older families. See [`OatClassStatusEnumK`] for the simplification this
/// stub makes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OatClassStatusEnumPQ {
    value: i8,
}

impl OatClassStatusEnumPQ {
    pub fn new(value: i8) -> Self {
        Self { value }
    }

    /// Mirrors `getValue()`.
    pub fn get_value(&self) -> i8 {
        self.value
    }
}

impl StructConverter for OatClassStatusEnumPQ {
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        unimplemented!("OatClassStatusEnumPQ.to_data_type not yet ported")
    }
}

impl OatClassStatusEnum for OatClassStatusEnumPQ {
    fn get(&self, value: i16) -> Option<Box<dyn OatClassStatusEnum>> {
        Some(Box::new(OatClassStatusEnumPQ::new(value as i8)))
    }
}

/// Placeholder for the unported Java enum
/// `ghidra.file.formats.android.oat.oatclass.OatClassStatusEnum_R_S_T`, referenced by `OatClass`
/// for OAT versions 183/195/199 (Android 11/12), 220/223/225 (Android 13).
///
/// Concrete stub: Java is an enum, not an interface. Its `value` field is a `byte`, like
/// [`OatClassStatusEnumPQ`]. See [`OatClassStatusEnumK`] for the simplification this stub makes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OatClassStatusEnumRST {
    value: i8,
}

impl OatClassStatusEnumRST {
    pub fn new(value: i8) -> Self {
        Self { value }
    }

    /// Mirrors `getValue()`.
    pub fn get_value(&self) -> i8 {
        self.value
    }
}

impl StructConverter for OatClassStatusEnumRST {
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        unimplemented!("OatClassStatusEnumRST.to_data_type not yet ported")
    }
}

impl OatClassStatusEnum for OatClassStatusEnumRST {
    fn get(&self, value: i16) -> Option<Box<dyn OatClassStatusEnum>> {
        Some(Box::new(OatClassStatusEnumRST::new(value as i8)))
    }
}

/// Placeholder for the unported Java enum `ghidra.file.formats.android.oat.oatclass.OatClassType`,
/// referenced by `OatClass::get_type`.
///
/// Concrete stub: Java is an enum, not an interface. Only the four variants and the ordinal-based
/// lookup `OatClass.getType()` needs are included; the real `toData()` builds an `EnumDataType`
/// via reflection, which is not ported yet. Replace with the real port when available.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OatClassType {
    /// OatClass is followed by an OatMethodOffsets for each method.
    KOatClassAllCompiled,
    /// A bitmap of which OatMethodOffsets are present follows the OatClass.
    KOatClassSomeCompiled,
    /// All methods are interpreted, so no OatMethodOffsets are necessary.
    KOatClassNoneCompiled,
    /// Invalid state, mirroring `case kOatClassMax` in `oat_file.cc`.
    KOatClassMax,
}

impl OatClassType {
    /// All variants, in declaration order. Mirrors `values()`.
    pub const VALUES: [OatClassType; 4] = [
        OatClassType::KOatClassAllCompiled,
        OatClassType::KOatClassSomeCompiled,
        OatClassType::KOatClassNoneCompiled,
        OatClassType::KOatClassMax,
    ];

    /// Mirrors `ordinal()`.
    pub fn ordinal(&self) -> i16 {
        match self {
            OatClassType::KOatClassAllCompiled => 0,
            OatClassType::KOatClassSomeCompiled => 1,
            OatClassType::KOatClassNoneCompiled => 2,
            OatClassType::KOatClassMax => 3,
        }
    }

    /// Mirrors the static `toData()`.
    pub fn to_data(&self) -> Box<dyn DataType> {
        unimplemented!("OatClassType.to_data not yet ported")
    }
}

/// Placeholder for the unported Java class
/// `ghidra.file.formats.android.oat.oatmethod.OatMethodOffsets`, referenced by
/// `OatClass::methods_pointer`.
///
/// Concrete stub: Java class, not interface. Only the code offset accessor `OatClass` needs is
/// included; the real class additionally parses a `codeOffset`/`gcMapOffset` pair (present or
/// absent depending on OAT version) directly from a `BinaryReader`. Replace with the real port
/// when available.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OatMethodOffsets {
    code_offset: i32,
}

impl OatMethodOffsets {
    pub fn new(code_offset: i32) -> Self {
        Self { code_offset }
    }

    /// Mirrors `getCodeOffset()`.
    pub fn get_code_offset(&self) -> i32 {
        self.code_offset
    }

    pub fn to_data_type(&self) -> std::io::Result<Box<dyn DataType>> {
        unimplemented!("OatMethodOffsets.to_data_type not yet ported")
    }
}

/// Placeholder for the unported Java class
/// `ghidra.file.formats.android.fbpk.FBPK_Partition`, referenced by `FBPK`.
///
/// Concrete stub: Java class, not interface. Only methods THIS type needs are included.
/// Replace with the real port when available.
pub trait FBPK_Partition: Send + Sync {
    fn get_header_size(&self) -> i32;
    fn get_type(&self) -> i32;
    fn get_name(&self) -> String;
    fn get_data_start_offset(&self) -> i64;
    fn get_data_size(&self) -> i32;
    fn is_file(&self) -> bool;
    fn get_offset_to_next_partition_table(&self) -> i32;
    fn get_partition_index(&self) -> i32;
    fn markup(
        &self,
        program: &dyn Program,
        address: &crate::program::model::address::Address,
        monitor: &dyn TaskMonitor,
        log: &crate::app::util::importer::message_log::MessageLog,
    ) -> std::io::Result<()>;
}

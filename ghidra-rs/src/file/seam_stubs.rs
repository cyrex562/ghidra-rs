//! Minimal placeholder types for core types that a ported type references before the real
//! Rust port of that type exists yet. Each stub exposes only the members needed by the
//! interface(s) that currently reference it, and is expected to be replaced once the Java class
//! is ported. See `STUBS.tsv` for provenance.

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};

use crate::app::plugin::core::checksums::md5_digest_checksum_algorithm::MD5DigestChecksumAlgorithm;
use crate::program::model::data::data_type::DataType;
use crate::app::util::bin::binary_reader::BinaryReader;
use crate::filesystem::ghidra::g_binary_reader::ByteProvider;
use crate::filesystem::gfilesystem::fileinfo::file_attribute_type::FileAttributeType;
use crate::filesystem::gfilesystem::fileinfo::file_type::FileType;
use crate::filesystem::gfilesystem::fsrl::Fsrl;
use crate::filesystem::gfilesystem::g_file::GFile;
use crate::filesystem::gfilesystem::g_file_impl::{
    FsGetListing, FsrlLike as GFileFsrlLike, GFileImpl, HasFsrlRoot,
};
use crate::filesystem::seam_stubs::{FileAttributesLike, FileSystemServiceLike, FsrlRootLike, GFileSystemLike};
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

/// Placeholder for the unported Java type `DexHeader`, referenced by `FieldAnnotationsItem`.
/// Concrete stub: Java class, not interface. Only methods THIS type needs are included.
/// Replace with the real port when available.
pub struct DexHeader;

impl DexHeader {
    pub fn parse(&self, _reader: &dyn BinaryReader) -> std::io::Result<()> {
        unimplemented!("DexHeader.parse not yet ported")
    }

    pub fn is_data_offset_relative(&self) -> bool {
        unimplemented!("DexHeader.is_data_offset_relative not yet ported")
    }

    pub fn to_data_type(&self) -> std::io::Result<Box<dyn DataType>> {
        unimplemented!("DexHeader.to_data_type not yet ported")
    }

    pub fn get_magic(&self) -> Vec<i8> { vec![] }
    pub fn get_version(&self) -> Vec<i8> { vec![] }
    pub fn get_checksum(&self) -> i32 { 0 }
    pub fn get_signature(&self) -> Vec<i8> { vec![] }
    pub fn get_file_size(&self) -> i32 { 0 }
    pub fn get_header_size(&self) -> i32 { 0 }
    pub fn get_endian_tag(&self) -> i32 { 0 }
    pub fn get_string_ids_offset(&self) -> i32 { 0 }
    pub fn get_string_ids_size(&self) -> i32 { 0 }
    pub fn get_class_defs_ids_offset(&self) -> i32 { 0 }
    pub fn get_class_defs_ids_size(&self) -> i32 { 0 }
    pub fn get_data_offset(&self) -> i32 { 0 }
    pub fn get_data_size(&self) -> i32 { 0 }
    pub fn get_field_ids_offset(&self) -> i32 { 0 }
    pub fn get_field_ids_size(&self) -> i32 { 0 }
    pub fn get_method_ids_offset(&self) -> i32 { 0 }
    pub fn get_method_ids_size(&self) -> i32 { 0 }
    pub fn get_type_ids_offset(&self) -> i32 { 0 }
    pub fn get_type_ids_size(&self) -> i32 { 0 }
    pub fn get_proto_ids_offset(&self) -> i32 { 0 }
    pub fn get_proto_ids_size(&self) -> i32 { 0 }
    pub fn get_link_offset(&self) -> i32 { 0 }
    pub fn get_link_size(&self) -> i32 { 0 }
    pub fn get_map_offset(&self) -> i32 { 0 }
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

/// Placeholder for the unported Java type `AndroidXmlConvertor`, referenced by
/// `AndroidXmlFileSystem`.
/// Concrete stub: Java class, not interface. Only the members THIS type needs are included:
/// the binary-XML magic signature and the `convert` entry point that turns the binary XML
/// payload into text. Replace with the real port when available.
pub struct AndroidXmlConvertor;

impl AndroidXmlConvertor {
    /// Mirrors `AndroidXmlConvertor.ANDROID_BINARY_XML_MAGIC`.
    pub const ANDROID_BINARY_XML_MAGIC: [u8; 4] = [0x03, 0x00, 0x08, 0x00];

    /// Converts the binary Android XML bytes in `input` to text, appending the result to `out`.
    ///
    /// Java distinguishes `IOException` (which callers may recover from) from
    /// `CancelledException` (monitor cancellation); this stub collapses both into a single
    /// `io::Result` until the real converter is ported.
    pub fn convert(_input: &[u8], _out: &mut String, _monitor: &dyn TaskMonitor) -> io::Result<()> {
        unimplemented!("AndroidXmlConvertor.convert not yet ported")
    }
}

/// Placeholder for the unported Java type `ByteArrayProvider`, referenced by
/// `AndroidXmlFileSystem::get_byte_provider`.
/// Concrete stub: Java class, not interface. Wraps an in-memory byte array as a
/// [`ByteProvider`]; only the members THIS type needs are included.
pub struct ByteArrayProvider {
    bytes: Vec<u8>,
}

impl ByteArrayProvider {
    pub fn new(bytes: Vec<u8>) -> Self {
        ByteArrayProvider { bytes }
    }
}

impl ByteProvider for ByteArrayProvider {
    fn length(&mut self) -> io::Result<u64> {
        Ok(self.bytes.len() as u64)
    }

    fn is_valid_index(&mut self, index: u64) -> bool {
        (index as usize) < self.bytes.len()
    }

    fn read_byte(&mut self, index: u64) -> io::Result<u8> {
        self.bytes.get(index as usize).copied().ok_or_else(|| {
            io::Error::new(io::ErrorKind::UnexpectedEof, "index out of bounds")
        })
    }

    fn read_bytes(&mut self, index: u64, length: usize) -> io::Result<Vec<u8>> {
        let start = index as usize;
        let end = start + length;
        if end > self.bytes.len() {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "index out of bounds"));
        }
        Ok(self.bytes[start..end].to_vec())
    }

    fn write_byte(&mut self, _index: u64, _value: u8) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "ByteArrayProvider is read-only"))
    }

    fn write_bytes(&mut self, _index: u64, _values: &[u8]) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "ByteArrayProvider is read-only"))
    }

    fn get_fsrl(&self) -> Option<&dyn Fsrl> {
        None
    }

    fn get_file(&self) -> Option<PathBuf> {
        None
    }
}

/// A value carried by a [`FileAttributes`] entry.
///
/// Java's `FileAttributes.add` takes an `Object` whose class is expected to match the
/// attribute type's `getValueType()`; this enum names the small closed set of value classes
/// actually used (`String`, `FileType`, `Boolean`, `Long`, and `Date` as epoch millis).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileAttributeValue {
    Str(String),
    FileType(FileType),
    Boolean(bool),
    Long(i64),
    /// A `java.util.Date`, as epoch milliseconds.
    Date(i64),
}

impl From<&str> for FileAttributeValue {
    fn from(s: &str) -> Self {
        FileAttributeValue::Str(s.to_string())
    }
}

impl From<String> for FileAttributeValue {
    fn from(s: String) -> Self {
        FileAttributeValue::Str(s)
    }
}

impl From<FileType> for FileAttributeValue {
    fn from(t: FileType) -> Self {
        FileAttributeValue::FileType(t)
    }
}

impl From<bool> for FileAttributeValue {
    fn from(b: bool) -> Self {
        FileAttributeValue::Boolean(b)
    }
}

impl From<i64> for FileAttributeValue {
    fn from(v: i64) -> Self {
        FileAttributeValue::Long(v)
    }
}

/// Placeholder for the unported Java type `ghidra.formats.gfilesystem.fileinfo.FileAttributes`,
/// referenced by `SevenZipFileSystem::get_file_attributes`.
///
/// Concrete stub: Java class, not interface. Carries the ordered `(type, display name, value)`
/// triples that `add()` accumulates plus the lookups this type needs. The existing
/// [`FileAttributesLike`] seam only exposes the single `FILE_TYPE_ATTR` lookup that
/// `GFileSystem`'s default `getFileType()` needs, which is too narrow for a filesystem that
/// *populates* attributes, so this stub implements that seam rather than replacing it.
/// Replace with the real port when available.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FileAttributes {
    attributes: Vec<(FileAttributeType, String, FileAttributeValue)>,
}

impl FileAttributes {
    /// Creates a new, empty instance. Mirrors `new FileAttributes()`.
    pub fn new() -> Self {
        FileAttributes::default()
    }

    /// Adds a typed attribute, labelled with the type's own display name.
    ///
    /// Mirrors `add(FileAttributeType, Object)`; as in Java, a `None` value is silently
    /// skipped rather than stored.
    pub fn add(&mut self, attribute_type: FileAttributeType, value: Option<FileAttributeValue>) {
        let display_name = attribute_type.display_name().to_string();
        self.add_with_display_name(attribute_type, display_name, value);
    }

    /// Adds a custom-named attribute. Mirrors `add(String, Object)`, which records the value
    /// under `UNKNOWN_ATTRIBUTE` with `name` as its display label.
    pub fn add_named(&mut self, name: &str, value: Option<FileAttributeValue>) {
        self.add_with_display_name(
            FileAttributeType::UnknownAttribute,
            name.to_string(),
            value,
        );
    }

    /// Mirrors `add(FileAttributeType, String, Object)`.
    pub fn add_with_display_name(
        &mut self,
        attribute_type: FileAttributeType,
        display_name: String,
        value: Option<FileAttributeValue>,
    ) {
        if let Some(value) = value {
            self.attributes.push((attribute_type, display_name, value));
        }
    }

    /// The value of the first attribute of `attribute_type`, or `None`. Mirrors `get()`.
    pub fn get(&self, attribute_type: FileAttributeType) -> Option<&FileAttributeValue> {
        self.attributes
            .iter()
            .find(|(t, _, _)| *t == attribute_type)
            .map(|(_, _, v)| v)
    }

    /// The value of the first custom-named attribute labelled `name`, or `None`.
    pub fn get_named(&self, name: &str) -> Option<&FileAttributeValue> {
        self.attributes
            .iter()
            .find(|(t, n, _)| *t == FileAttributeType::UnknownAttribute && n == name)
            .map(|(_, _, v)| v)
    }

    /// `true` if an attribute of `attribute_type` is present. Mirrors `contains()`.
    pub fn contains(&self, attribute_type: FileAttributeType) -> bool {
        self.get(attribute_type).is_some()
    }

    /// All accumulated `(type, display name, value)` triples, in insertion order.
    /// Mirrors `getAttributes()`.
    pub fn get_attributes(&self) -> &[(FileAttributeType, String, FileAttributeValue)] {
        &self.attributes
    }
}

impl FileAttributesLike for FileAttributes {
    fn file_type_attr(&self) -> Option<FileType> {
        match self.get(FileAttributeType::FileTypeAttr) {
            Some(FileAttributeValue::FileType(t)) => Some(*t),
            _ => None,
        }
    }
}

/// Placeholder for the unported Java type `ghidra.formats.gfilesystem.FileCache.FileCacheEntry`,
/// referenced by `SevenZipFileSystem::get_byte_provider`.
///
/// Concrete stub: Java inner class, not interface. The real entry is a file on disk in the
/// cache directory named after its MD5; this stub keeps the bytes in memory, which is enough
/// for the three members this type needs (`getMD5`, `length`, `asByteProvider`).
/// Replace with the real port when available.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileCacheEntry {
    bytes: Vec<u8>,
    md5: String,
}

impl FileCacheEntry {
    /// The lowercase hex MD5 of the entry's contents. Mirrors `getMD5()`.
    pub fn get_md5(&self) -> &str {
        &self.md5
    }

    /// The entry's size in bytes. Mirrors `length()`.
    pub fn length(&self) -> i64 {
        self.bytes.len() as i64
    }

    /// Exposes the entry's contents as a [`ByteProvider`]. Mirrors `asByteProvider(FSRL)`.
    ///
    /// The Java method tags the returned provider with the caller's `FSRL`; [`ByteArrayProvider`]
    /// carries no FSRL (its `get_fsrl` returns `None`), so that tagging is dropped here until
    /// the real `FileCache` lands.
    pub fn as_byte_provider(&self) -> io::Result<Box<dyn ByteProvider>> {
        Ok(Box::new(ByteArrayProvider::new(self.bytes.clone())))
    }
}

/// Placeholder for the unported Java type
/// `ghidra.formats.gfilesystem.FileCache.FileCacheEntryBuilder`, referenced by
/// `SevenZipFileSystem`'s extract callback.
///
/// Concrete stub: Java inner class, not interface. Accumulates written bytes and hashes them
/// on [`finish`](Self::finish), mirroring the real builder's streaming MD5.
/// Replace with the real port when available.
#[derive(Debug, Default)]
pub struct FileCacheEntryBuilder {
    bytes: Vec<u8>,
}

impl FileCacheEntryBuilder {
    /// Creates a builder for a payload of roughly `size_hint` bytes (`-1` if unknown).
    /// Mirrors `FileSystemService.createTempFile(long)`.
    pub fn new(size_hint: i64) -> Self {
        FileCacheEntryBuilder {
            bytes: Vec::with_capacity(if size_hint > 0 { size_hint as usize } else { 0 }),
        }
    }

    /// Appends `data` to the entry being built. Mirrors `write(byte[])`.
    pub fn write(&mut self, data: &[u8]) -> io::Result<()> {
        self.bytes.extend_from_slice(data);
        Ok(())
    }

    /// The number of bytes written so far.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// `true` if nothing has been written yet.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Seals the builder into a [`FileCacheEntry`]. Mirrors `finish()`.
    pub fn finish(self) -> io::Result<FileCacheEntry> {
        let mut digest = MD5DigestChecksumAlgorithm::new();
        digest.update_checksum(&self.bytes);
        let md5 = digest
            .checksum()
            .map(|bytes| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>())
            .unwrap_or_default();
        Ok(FileCacheEntry { bytes: self.bytes, md5 })
    }
}

/// Placeholder for the unported Java type `ghidra.formats.gfilesystem.FileSystemIndexHelper`,
/// referenced by `SevenZipFileSystem` as its `fsIndex` field.
///
/// Concrete stub: Java class, not interface. Only the members THIS type needs are included --
/// the flat index by archive item number plus per-file metadata; the real helper additionally
/// maintains a directory tree, path lookups, symlink resolution and case-insensitive matching.
/// Replace with the real port when available.
pub struct FileSystemIndexHelper<FS, Fsrl, M> {
    filesystem: FS,
    root_dir: GFileImpl<FS, Fsrl>,
    entries: Vec<IndexEntry<FS, Fsrl, M>>,
    by_file_index: HashMap<i64, usize>,
}

struct IndexEntry<FS, Fsrl, M> {
    /// The normalized path this entry was stored under; kept separately so a later
    /// [`FileSystemIndexHelper::update_fsrl`] cannot break lookups.
    path: String,
    file: GFileImpl<FS, Fsrl>,
    metadata: M,
}

impl<FS, Fsrl, M> FileSystemIndexHelper<FS, Fsrl, M>
where
    FS: Clone + HasFsrlRoot<Fsrl> + FsGetListing<FS, Fsrl> + 'static,
    Fsrl: GFileFsrlLike + 'static,
{
    /// Creates an index rooted at `root_fsrl`. Mirrors
    /// `FileSystemIndexHelper(GFileSystem, FSRLRoot)`.
    pub fn new(filesystem: FS, root_fsrl: Fsrl) -> Self {
        let root_dir = GFileImpl::from_fsrl(filesystem.clone(), None, root_fsrl, true, -1);
        FileSystemIndexHelper {
            filesystem,
            root_dir,
            entries: Vec::new(),
            by_file_index: HashMap::new(),
        }
    }

    /// Indexes a file at `path`, keyed by the archive's own `file_index`.
    /// Mirrors `storeFile(String, long, boolean, long, METADATATYPE)`.
    pub fn store_file(
        &mut self,
        path: &str,
        file_index: i64,
        is_directory: bool,
        length: i64,
        metadata: M,
    ) -> &GFileImpl<FS, Fsrl> {
        let file = GFileImpl::from_path_string(
            self.filesystem.clone(),
            path,
            None,
            is_directory,
            length,
        );
        let stored_path = file.get_path().to_string();
        self.by_file_index.insert(file_index, self.entries.len());
        self.entries.push(IndexEntry { path: stored_path, file, metadata });
        &self.entries[self.entries.len() - 1].file
    }

    /// Replaces the FSRL of an already-indexed file. Mirrors `updateFSRL(GFile, FSRL)`.
    pub fn update_fsrl(&mut self, file: &GFileImpl<FS, Fsrl>, new_fsrl: Fsrl) {
        let path = file.get_path().to_string();
        if let Some(entry) = self.entries.iter_mut().find(|e| e.path == path) {
            let is_directory = entry.file.is_directory();
            let length = entry.file.get_length();
            entry.file = GFileImpl::from_fsrl(
                self.filesystem.clone(),
                None,
                new_fsrl,
                is_directory,
                length,
            );
        }
    }
}

impl<FS, Fsrl, M> FileSystemIndexHelper<FS, Fsrl, M>
where
    FS: FsGetListing<FS, Fsrl>,
{
    /// The synthetic root directory. Mirrors `getRootDir()`.
    pub fn get_root_dir(&self) -> &GFileImpl<FS, Fsrl> {
        &self.root_dir
    }

    /// The file stored under archive item number `file_index`, or `None`.
    /// Mirrors `getFileByIndex(long)`.
    pub fn get_file_by_index(&self, file_index: i64) -> Option<&GFileImpl<FS, Fsrl>> {
        self.by_file_index
            .get(&file_index)
            .map(|&i| &self.entries[i].file)
    }

    /// The metadata stored alongside `file`, or `None`. Mirrors `getMetadata(GFile)`.
    pub fn get_metadata(&self, file: &GFileImpl<FS, Fsrl>) -> Option<&M> {
        let path = file.get_path();
        self.entries
            .iter()
            .find(|e| e.path == path)
            .map(|e| &e.metadata)
    }

    /// Number of indexed files. Mirrors `getFileCount()` (which also counts the root dir).
    pub fn get_file_count(&self) -> i32 {
        self.entries.len() as i32 + 1
    }

    /// Forgets every indexed file, keeping the root directory. Mirrors `clear()`.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.by_file_index.clear();
    }
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

impl GFileSystemLike for ZipFileSystem {}

impl ZipFileSystem {
    /// Mirrors `ZipFileSystem(FSRLRoot, FileSystemService)`. The real port stores both
    /// (as `SevenZipFileSystemBase` already does); this stub has nowhere to put them yet.
    pub fn new(_fsrl: &dyn FsrlRootLike, _fs_service: &dyn FileSystemServiceLike) -> Self {
        ZipFileSystem
    }

    /// Mirrors the inherited `SevenZipFileSystemBase::mount`. Not yet implemented: wiring this
    /// up requires an opened 7-Zip archive (see the `InArchive` seam in `seven_zip_file_system`),
    /// which this stub does not construct.
    pub fn mount(
        &mut self,
        _byte_provider: Box<dyn ByteProvider>,
        _monitor: &dyn TaskMonitor,
    ) -> io::Result<()> {
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

impl GFileSystemLike for ZipFileSystemBuiltin {}

impl ZipFileSystemBuiltin {
    /// Mirrors `ZipFileSystemBuiltin.TEMPFILE_PREFIX`.
    pub const TEMPFILE_PREFIX: &'static str = "ghidra_tmp_zipfile";

    /// Mirrors `ZipFileSystemBuiltin(FSRLRoot, FileSystemService)`.
    pub fn new(_fsrl: &dyn FsrlRootLike, _fs_service: &dyn FileSystemServiceLike) -> Self {
        ZipFileSystemBuiltin
    }

    /// Mirrors `mount(File, boolean, TaskMonitor)`. Not yet implemented: reading zip entries
    /// requires an in-crate zip-archive reader, which does not exist yet.
    pub fn mount(
        &mut self,
        _f: &Path,
        _delete_file_when_done: bool,
        _monitor: &dyn TaskMonitor,
    ) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "ZipFileSystemBuiltin.mount not yet ported"))
    }

    /// Mirrors `close()`.
    pub fn close(&mut self) -> io::Result<()> {
        Ok(())
    }
}

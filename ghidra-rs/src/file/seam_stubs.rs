//! Minimal placeholder types for core types that a ported type references before the real
//! Rust port of that type exists yet. Each stub exposes only the members needed by the
//! interface(s) that currently reference it, and is expected to be replaced once the Java class
//! is ported. See `STUBS.tsv` for provenance.

use std::cell::RefCell;
use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use crate::app::plugin::core::checksums::md5_digest_checksum_algorithm::MD5DigestChecksumAlgorithm;
use crate::program::model::data::data_type::DataType;
use crate::app::util::bin::binary_reader::BinaryReader;
use crate::file::formats::ios::dyldcache::dyld_cache_entry::DyldCacheEntry;
use crate::filesystem::ghidra::g_binary_reader::ByteProvider;
use crate::filesystem::gfilesystem::fileinfo::file_attribute_type::FileAttributeType;
use crate::filesystem::gfilesystem::fileinfo::file_type::FileType;
use crate::filesystem::gfilesystem::fsrl::Fsrl;
use crate::filesystem::gfilesystem::g_file::GFile;
use crate::filesystem::gfilesystem::g_file_impl::{
    FsGetListing, FsrlLike as GFileFsrlLike, GFileImpl, HasFsrlRoot,
};
use crate::filesystem::seam_stubs::{FileAttributesLike, FileSystemServiceLike, FsrlRootLike, GFileSystemLike};
use crate::format::macho::commands::chained::dyld_chained_fixups_command::DyldChainedFixupsCommand;
use crate::format::macho::dyld::dyld_cache_image::DyldCacheImage;
use crate::format::macho::dyld::dyld_fixup::DyldFixup;
use crate::format::macho::mach_exception::MachException;
use crate::util::exception::CancelledException;
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

    /// The file stored at `path`, or `None`. Mirrors `lookup(String)`.
    pub fn lookup(&self, path: &str) -> Option<&GFileImpl<FS, Fsrl>> {
        self.entries.iter().find(|e| e.path == path).map(|e| &e.file)
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

// ─── DYLD cache seam, for `DyldCacheFileSystem` ───────────────────────────────

/// Placeholder for `ghidra.app.util.bin.format.macho.dyld.DyldCacheMappingInfo`, referenced by
/// `DyldCacheFileSystem`.
///
/// Concrete stub: Java class, not interface. Only the address/size accessors THIS type needs
/// are included; the real class additionally parses file offset and protection flags from a
/// `dyld_cache_mapping_info` structure. Replace with the real port when available.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DyldCacheMappingInfo {
    address: i64,
    size: i64,
}

impl DyldCacheMappingInfo {
    pub fn new(address: i64, size: i64) -> Self {
        DyldCacheMappingInfo { address, size }
    }

    /// Mirrors `getAddress()`.
    pub fn address(&self) -> i64 {
        self.address
    }

    /// Mirrors `getSize()`.
    pub fn size(&self) -> i64 {
        self.size
    }

    /// Mirrors `contains(long, boolean)`, restricted to the `isAddr = true` case (the only one
    /// `DyldCacheUtils.getImageRecords` uses).
    pub fn contains(&self, addr: i64) -> bool {
        addr >= self.address && addr < self.address + self.size
    }
}

/// Placeholder for `ghidra.app.util.bin.format.macho.dyld.DyldCacheMappingAndSlideInfo`,
/// referenced by `DyldCacheFileSystem`.
///
/// Concrete stub: Java class, not interface. Only the address/size/flags surface THIS type
/// needs is included, with the real `DYLD_CACHE_MAPPING_*`/`DYLD_CACHE_*_DATA` flag bit tests
/// ported faithfully; the real class additionally parses file/slide-info offsets and
/// protection flags. Replace with the real port when available.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DyldCacheMappingAndSlideInfo {
    address: i64,
    size: i64,
    flags: i64,
}

impl DyldCacheMappingAndSlideInfo {
    pub const DYLD_CACHE_MAPPING_AUTH_DATA: i64 = 0x1;
    pub const DYLD_CACHE_MAPPING_DIRTY_DATA: i64 = 0x2;
    pub const DYLD_CACHE_MAPPING_CONST_DATA: i64 = 0x4;
    pub const DYLD_CACHE_MAPPING_TEXT_STUBS: i64 = 0x8;
    pub const DYLD_CACHE_DYNAMIC_CONFIG_DATA: i64 = 0x10;
    pub const DYLD_CACHE_READ_ONLY_DATA: i64 = 0x20;
    pub const DYLD_CACHE_MAPPING_CONST_TPRO_DATA: i64 = 0x40;

    pub fn new(address: i64, size: i64, flags: i64) -> Self {
        DyldCacheMappingAndSlideInfo { address, size, flags }
    }

    /// Mirrors `getAddress()`.
    pub fn address(&self) -> i64 {
        self.address
    }

    /// Mirrors `getSize()`.
    pub fn size(&self) -> i64 {
        self.size
    }

    /// Mirrors `getFlags()`.
    pub fn flags(&self) -> i64 {
        self.flags
    }

    /// Mirrors `isAuthData()`.
    pub fn is_auth_data(&self) -> bool {
        self.flags & Self::DYLD_CACHE_MAPPING_AUTH_DATA != 0
    }

    /// Mirrors `isDirtyData()`.
    pub fn is_dirty_data(&self) -> bool {
        self.flags & Self::DYLD_CACHE_MAPPING_DIRTY_DATA != 0
    }

    /// Mirrors `isConstData()`.
    pub fn is_const_data(&self) -> bool {
        self.flags & Self::DYLD_CACHE_MAPPING_CONST_DATA != 0
    }

    /// Mirrors `isTextStubs()`.
    pub fn is_text_stubs(&self) -> bool {
        self.flags & Self::DYLD_CACHE_MAPPING_TEXT_STUBS != 0
    }

    /// Mirrors `isConfigData()`.
    pub fn is_config_data(&self) -> bool {
        self.flags & Self::DYLD_CACHE_DYNAMIC_CONFIG_DATA != 0
    }

    /// Mirrors `isReadOnlyData()`.
    pub fn is_read_only_data(&self) -> bool {
        self.flags & Self::DYLD_CACHE_READ_ONLY_DATA != 0
    }

    /// Mirrors `isConstTproData()`.
    pub fn is_const_tpro_data(&self) -> bool {
        self.flags & Self::DYLD_CACHE_MAPPING_CONST_TPRO_DATA != 0
    }
}

/// Placeholder for `ghidra.app.util.bin.format.macho.commands.SegmentCommand`, referenced by
/// `DyldCacheFileSystem::mount` and `MachoFileSetFileSystem`.
///
/// Concrete stub: Java class, not interface. Only the fields the current consumers need are
/// included (address/size for `DyldCacheFileSystem`; name, file range and protection/flags for
/// `MachoFileSetFileSystem`); the real class additionally parses section tables from a
/// `LC_SEGMENT[_64]` load command. Replace with the real port when available.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentCommand {
    vm_address: i64,
    vm_size: i64,
    segment_name: String,
    file_offset: i64,
    file_size: i64,
    max_protection: i32,
    init_protection: i32,
    flags: i32,
}

impl SegmentCommand {
    /// Mirrors the load-address/size-only construction used by `DyldCacheFileSystem`. The
    /// remaining fields (unused by that caller) default to empty/zero.
    pub fn new(vm_address: i64, vm_size: i64) -> Self {
        SegmentCommand {
            vm_address,
            vm_size,
            segment_name: String::new(),
            file_offset: 0,
            file_size: 0,
            max_protection: 0,
            init_protection: 0,
            flags: 0,
        }
    }

    /// Mirrors `getVMaddress()`.
    pub fn vm_address(&self) -> i64 {
        self.vm_address
    }

    /// Mirrors `getVMsize()`.
    pub fn vm_size(&self) -> i64 {
        self.vm_size
    }

    /// Mirrors `getSegmentName()`.
    pub fn segment_name(&self) -> &str {
        &self.segment_name
    }

    /// Mirrors `getFileOffset()`.
    pub fn file_offset(&self) -> i64 {
        self.file_offset
    }

    /// Mirrors `getFileSize()`.
    pub fn file_size(&self) -> i64 {
        self.file_size
    }

    /// Mirrors `getMaxProtection()`.
    pub fn max_protection(&self) -> i32 {
        self.max_protection
    }

    /// Mirrors `getInitProtection()`.
    pub fn init_protection(&self) -> i32 {
        self.init_protection
    }

    /// Mirrors `getFlags()`.
    pub fn flags(&self) -> i32 {
        self.flags
    }

    /// Mirrors the static `size(int magic)`: the on-disk size of a segment load command (with no
    /// sections), which differs between 32- and 64-bit Mach-O.
    pub fn size(magic: i32) -> i32 {
        const MH_MAGIC_64: i32 = 0xfeedfacfu32 as i32;
        const MH_CIGAM_64: i32 = 0xcffaedfeu32 as i32;
        if magic == MH_MAGIC_64 || magic == MH_CIGAM_64 { 0x48 } else { 0x38 }
    }
}

/// Placeholder for `ghidra.app.util.bin.format.macho.MachHeader`, referenced by
/// `DyldCacheFileSystem::mount` via `SplitDyldCache::macho`.
///
/// Concrete stub: Java class, not interface. `MachHeader(ByteProvider, long, boolean)`
/// constructs the header at a byte offset without parsing it (this class's caller invokes
/// `parseSegments()` directly, never `parse()`); parsing the Mach-O load commands to recover
/// the real segment table is not yet ported, so `parse_segments` always reports an empty list
/// until it is. Replace with the real port when available.
pub struct MachHeader {
    provider: Rc<RefCell<dyn ByteProvider>>,
    offset: i64,
    little_endian: bool,
}

impl MachHeader {
    /// Mirrors `MachHeader(ByteProvider, long, boolean)`, restricted to the `isRelative = false`
    /// case (the only one `SplitDyldCache.getMacho` uses).
    pub fn new(provider: Rc<RefCell<dyn ByteProvider>>, offset: i64) -> Self {
        MachHeader { provider, offset, little_endian: true }
    }

    /// Mirrors `MachHeader(ByteProvider)`, i.e. `MachHeader(provider, 0)`.
    pub fn from_provider(provider: Rc<RefCell<dyn ByteProvider>>) -> Self {
        MachHeader::new(provider, 0)
    }

    /// Mirrors `parseSegments()`. Not yet implemented (see type docs): always reports no
    /// segments.
    pub fn parse_segments(&self) -> io::Result<Vec<SegmentCommand>> {
        Ok(Vec::new())
    }

    /// Mirrors `parse()`, restricted to what can be determined without a real load-command
    /// parser: reads and validates the 4-byte magic at [`offset`](Self::offset) so
    /// [`is_little_endian`](Self::is_little_endian) reports a real answer. Load commands are not
    /// parsed (see type docs), so [`get_segment`](Self::get_segment),
    /// [`file_set_entry_commands`](Self::file_set_entry_commands) and
    /// [`dyld_chained_fixups_commands`](Self::dyld_chained_fixups_commands) always report empty
    /// until that lands. Replace with the real port when available.
    pub fn parse(&mut self) -> Result<(), MachException> {
        const MH_MAGIC: u32 = 0xfeedface;
        const MH_MAGIC_64: u32 = 0xfeedfacf;
        const MH_CIGAM: u32 = 0xcefaedfe;
        const MH_CIGAM_64: u32 = 0xcffaedfe;

        let bytes = self
            .provider
            .borrow_mut()
            .read_bytes(self.offset as u64, 4)
            .map_err(MachException::from_cause)?;
        let magic = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if magic != MH_MAGIC && magic != MH_MAGIC_64 && magic != MH_CIGAM && magic != MH_CIGAM_64 {
            return Err(MachException::new(format!("Invalid Mach-O magic: 0x{magic:x}")));
        }
        self.little_endian = magic == MH_CIGAM || magic == MH_CIGAM_64;
        Ok(())
    }

    /// Mirrors `isLittleEndian()`. Only meaningful after [`parse`](Self::parse) has run; `true`
    /// beforehand (this stub's default, matching the common case for iOS/arm64e binaries).
    pub fn is_little_endian(&self) -> bool {
        self.little_endian
    }

    /// Mirrors `getSegment(String)`. Not yet implemented (see type docs): always reports no
    /// matching segment, since the load-command table is not parsed.
    pub fn get_segment(&self, _segment_name: &str) -> Option<SegmentCommand> {
        None
    }

    /// Mirrors `getLoadCommands(FileSetEntryCommand.class)`. Not yet implemented (see type
    /// docs): always empty.
    pub fn file_set_entry_commands(&self) -> Vec<FileSetEntryCommand> {
        Vec::new()
    }

    /// Mirrors `getLoadCommands(DyldChainedFixupsCommand.class)`. Not yet implemented (see type
    /// docs): always empty.
    pub fn dyld_chained_fixups_commands(&self) -> Vec<DyldChainedFixupsCommand> {
        Vec::new()
    }
}

/// Placeholder for `ghidra.app.util.bin.format.macho.commands.FileSetEntryCommand`, referenced
/// by `MachoFileSetFileSystem::mount`.
///
/// Concrete stub: Java class, not interface. `getFileSetEntryId()`'s `LoadCommandString` return
/// type is collapsed directly to its resolved `String` (mirroring
/// `LoadCommandString::get_string()`), since no consumer needs the intermediate type yet.
/// Replace with the real port when available.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileSetEntryCommand {
    v_maddress: i64,
    file_offset: i64,
    file_set_entry_id: String,
}

impl FileSetEntryCommand {
    pub fn new(v_maddress: i64, file_offset: i64, file_set_entry_id: impl Into<String>) -> Self {
        FileSetEntryCommand { v_maddress, file_offset, file_set_entry_id: file_set_entry_id.into() }
    }

    /// Mirrors `getVMaddress()`.
    pub fn get_v_maddress(&self) -> i64 {
        self.v_maddress
    }

    /// Mirrors `getFileOffset()`.
    pub fn get_file_offset(&self) -> i64 {
        self.file_offset
    }

    /// Mirrors `getFileSetEntryId().getString()`.
    pub fn get_file_set_entry_id(&self) -> &str {
        &self.file_set_entry_id
    }
}

/// Placeholder for `ghidra.file.formats.ios.fileset.MachoFileSetEntry`, referenced by
/// `MachoFileSetFileSystem`.
///
/// Concrete stub: Java record, not interface. Mirrors all three record components (the full
/// public surface of a record); modeled here rather than in its own file only because
/// `MachoFileSetEntry.java` has not had its own port turn yet.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MachoFileSetEntry {
    id: String,
    offset: i64,
    is_branch_segment: bool,
}

impl MachoFileSetEntry {
    /// Mirrors the record constructor `MachoFileSetEntry(String, long, boolean)`.
    pub fn new(id: impl Into<String>, offset: i64, is_branch_segment: bool) -> Self {
        MachoFileSetEntry { id: id.into(), offset, is_branch_segment }
    }

    /// Mirrors the record accessor `id()`.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Mirrors the record accessor `offset()`.
    pub fn offset(&self) -> i64 {
        self.offset
    }

    /// Mirrors the record accessor `isBranchSegment()`.
    pub fn is_branch_segment(&self) -> bool {
        self.is_branch_segment
    }
}

/// Placeholder for `ghidra.file.formats.ios.ExtractedMacho`, referenced by
/// `MachoFileSetFileSystem::mount`.
///
/// Concrete stub: Java class, not interface. Only the static `toBytes` utility THIS type needs
/// is included, implemented faithfully (little-endian encoding of a 4- or 8-byte value); the
/// real class additionally packs a Mach-O's segments down and produces a `ByteProvider` for the
/// packed result, neither of which is ported yet. Replace with the real port when available.
pub struct ExtractedMacho;

impl ExtractedMacho {
    /// Mirrors the static `toBytes(long, int)`.
    pub fn to_bytes(value: i64, size: i32) -> io::Result<Vec<u8>> {
        match size {
            4 => Ok((value as i32).to_le_bytes().to_vec()),
            8 => Ok(value.to_le_bytes().to_vec()),
            _ => Err(io::Error::new(io::ErrorKind::InvalidInput, format!("Invalid size: {size}"))),
        }
    }
}

/// Placeholder for `ghidra.file.formats.ios.fileset.MachoFileSetExtractor`, referenced by
/// `MachoFileSetFileSystem::get_byte_provider`.
///
/// Concrete stub: Java class, not interface. Extraction depends on Mach-O header/segment
/// creation (`MachHeader::create`, `SegmentCommand::create`) and packing (`ExtractedMacho.pack`),
/// none of which is ported yet, so both entry points report "not yet implemented". Replace with
/// the real port when available (at which point `MachoFileSetExtractor.java` gets its own port
/// turn).
pub struct MachoFileSetExtractor;

impl MachoFileSetExtractor {
    /// Mirrors `extractFileSetEntry(ByteProvider, long, FSRL, TaskMonitor)`. Not yet implemented
    /// (see type docs).
    pub fn extract_file_set_entry(
        _provider: Rc<RefCell<dyn ByteProvider>>,
        _provider_offset: i64,
        _fsrl_path: &str,
        _monitor: &dyn TaskMonitor,
    ) -> io::Result<Box<dyn ByteProvider>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "MachoFileSetExtractor.extract_file_set_entry not yet ported",
        ))
    }

    /// Mirrors `extractSegment(ByteProvider, SegmentCommand, FSRL, TaskMonitor)`. Not yet
    /// implemented (see type docs).
    pub fn extract_segment(
        _provider: Rc<RefCell<dyn ByteProvider>>,
        _segment: &SegmentCommand,
        _fsrl_path: &str,
        _monitor: &dyn TaskMonitor,
    ) -> io::Result<Box<dyn ByteProvider>> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "MachoFileSetExtractor.extract_segment not yet ported"))
    }
}

/// Placeholder for `ghidra.app.util.importer.MessageLog`, referenced by
/// `MachoFileSetFileSystem::mount` (via `DyldChainedFixupsCommand::get_chained_fixups`).
///
/// Concrete stub, per the decided convention (there is nothing to dispatch over): a real, if
/// minimal, in-memory log rather than an `unimplemented!()` placeholder. Also implements
/// [`crate::format::seam_stubs::MessageLog`] so it interoperates with already-ported callers
/// (like `DyldChainedFixupsCommand::get_chained_fixups`) that still take `&dyn MessageLog`
/// against that older trait-based seam. Replace with the real port when available.
#[derive(Debug, Default)]
pub struct MessageLog {
    messages: std::sync::Mutex<Vec<String>>,
    status: std::sync::Mutex<Option<String>>,
}

impl MessageLog {
    /// Mirrors `new MessageLog()`.
    pub fn new() -> Self {
        MessageLog::default()
    }
}

impl crate::format::seam_stubs::MessageLog for MessageLog {
    fn copy_from(&self, _log: &dyn crate::format::seam_stubs::MessageLog) {
        // Not implemented: the seam trait only exposes `to_string()`, not structured access to
        // another log's messages, so there is nothing meaningful to copy through it.
    }

    fn append_msg(&self, message: &str) {
        self.messages.lock().unwrap().push(message.to_string());
    }

    fn append_exception(&self, _t: &dyn crate::format::seam_stubs::Throwable) {
        self.messages.lock().unwrap().push("exception".to_string());
    }

    fn error(&self, originator: &str, message: &str) {
        self.messages.lock().unwrap().push(format!("{originator}: {message}"));
    }

    fn has_messages(&self) -> bool {
        !self.messages.lock().unwrap().is_empty()
    }

    fn clear(&self) {
        self.messages.lock().unwrap().clear();
    }

    fn set_status(&self, status: &str) {
        *self.status.lock().unwrap() = Some(status.to_string());
    }

    fn clear_status(&self) {
        *self.status.lock().unwrap() = None;
    }

    fn get_status(&self) -> String {
        self.status.lock().unwrap().clone().unwrap_or_default()
    }

    fn to_string(&self) -> String {
        self.messages.lock().unwrap().join("\n")
    }

    fn write(&self, _owner: &dyn crate::format::seam_stubs::Class, message_header: &str) {
        self.messages.lock().unwrap().push(message_header.to_string());
    }
}

/// Placeholder for `ghidra.app.util.opinion.DyldCacheUtils.DyldCacheImageRecord`, referenced by
/// `DyldCacheFileSystem::mount` via `SplitDyldCache::image_records`.
///
/// Concrete stub: Java record, not interface.
#[derive(Clone)]
pub struct DyldCacheImageRecord {
    image: Rc<dyn DyldCacheImage>,
    split_cache_index: i32,
}

impl DyldCacheImageRecord {
    /// Mirrors the record accessor `image()`.
    pub fn image(&self) -> &dyn DyldCacheImage {
        self.image.as_ref()
    }

    /// Mirrors the record accessor `splitCacheIndex()`.
    pub fn split_cache_index(&self) -> i32 {
        self.split_cache_index
    }
}

/// Placeholder for `ghidra.app.util.bin.format.macho.dyld.DyldCacheHeader`'s mapping/image
/// table surface, referenced by `DyldCacheFileSystem::mount` via `SplitDyldCache`.
///
/// Scoped narrower than -- and independent of -- the magic/architecture-only placeholder at
/// [`crate::app::seam_stubs::DyldCacheHeader`] (added for `DyldCacheLoader`'s probe path, which
/// never needs mapping data): this one wraps that placeholder for identity parsing and adds the
/// mapping/image tables `DyldCacheFileSystem` reads. Real `DyldCacheHeader` parsing of those
/// tables is not yet ported, so they are always empty here -- a mounted `DyldCacheFileSystem`
/// therefore indexes zero files until that parsing lands. Replace with the real port when
/// available (at which point both placeholders should be retired together).
pub struct DyldCacheHeader {
    #[allow(dead_code)]
    inner: crate::app::seam_stubs::DyldCacheHeader,
}

impl DyldCacheHeader {
    /// Mirrors the magic-parsing prefix of `new DyldCacheHeader(BinaryReader)`, called from
    /// `SplitDyldCache`'s constructor.
    pub fn parse_from_file(
        reader: &mut crate::filesystem::ghidra::g_binary_reader::GBinaryReader,
    ) -> io::Result<Self> {
        Ok(DyldCacheHeader { inner: crate::app::seam_stubs::DyldCacheHeader::new(reader)? })
    }

    /// Mirrors `getMappingInfos()`. Not yet implemented (see type docs): always empty.
    pub fn mapping_infos(&self) -> &[DyldCacheMappingInfo] {
        &[]
    }

    /// Mirrors `getCacheMappingAndSlideInfos()`. Not yet implemented (see type docs): always
    /// empty.
    pub fn cache_mapping_and_slide_infos(&self) -> &[DyldCacheMappingAndSlideInfo] {
        &[]
    }

    /// Mirrors `getImageInfos()`. Not yet implemented (see type docs): always empty.
    pub fn image_infos(&self) -> &[Rc<dyn DyldCacheImage>] {
        &[]
    }

    /// Mirrors `getBaseAddress()`, delegating to the wrapped magic/architecture placeholder.
    pub fn base_address(&self) -> i64 {
        self.inner.base_address
    }

    /// Mirrors `parseLocalSymbolsInfo(boolean, MessageLog, TaskMonitor)`. Not yet implemented
    /// (see type docs): a no-op.
    pub fn parse_local_symbols_info(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// The failure modes of [`SplitDyldCache::new`], mirroring Java's `throws IOException,
/// CancelledException`.
#[derive(Debug)]
pub enum SplitDyldCacheError {
    Io(io::Error),
    Cancelled(CancelledException),
}

/// Placeholder for `ghidra.app.util.opinion.DyldCacheUtils.SplitDyldCache`, referenced by
/// `DyldCacheFileSystem::mount`.
///
/// Concrete stub: Java class, not interface. Only the single-file constructor path
/// `DyldCacheFileSystem` drives is modeled: the real class additionally locates and validates
/// sibling ".1", ".2", ".symbols" subcache files alongside the base file via
/// `FileSystemService`/`GFileSystem` filesystem probing, neither of which this narrow,
/// `ByteProvider`-only constructor has access to, so this stub always reports a single-file,
/// non-split cache. Replace with the real port when available.
pub struct SplitDyldCache {
    providers: Vec<Rc<RefCell<dyn ByteProvider>>>,
    headers: Vec<DyldCacheHeader>,
    names: Vec<String>,
}

impl SplitDyldCache {
    /// Mirrors the base-provider-only `SplitDyldCache(ByteProvider, boolean, MessageLog,
    /// TaskMonitor)` constructor; see the type docs for how this narrows it.
    pub fn new(
        base_provider: Rc<RefCell<dyn ByteProvider>>,
        _should_process_local_symbols: bool,
        monitor: &dyn TaskMonitor,
    ) -> Result<Self, SplitDyldCacheError> {
        monitor.check_cancelled().map_err(SplitDyldCacheError::Cancelled)?;
        let name = base_provider
            .borrow()
            .get_file()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
            .unwrap_or_default();
        monitor.set_message(&format!("Parsing {name} headers..."));
        let mut reader = crate::filesystem::ghidra::g_binary_reader::GBinaryReader::new(
            Rc::clone(&base_provider),
            true,
        );
        let header = DyldCacheHeader::parse_from_file(&mut reader).map_err(SplitDyldCacheError::Io)?;
        Ok(SplitDyldCache { providers: vec![base_provider], headers: vec![header], names: vec![name] })
    }

    /// Mirrors `getDyldCacheHeader(int)`.
    pub fn dyld_cache_header(&self, i: usize) -> &DyldCacheHeader {
        &self.headers[i]
    }

    /// Mutable counterpart of [`dyld_cache_header`](Self::dyld_cache_header), needed for
    /// `parseLocalSymbolsInfo`.
    pub fn dyld_cache_header_mut(&mut self, i: usize) -> &mut DyldCacheHeader {
        &mut self.headers[i]
    }

    /// Mirrors `getName(int)`.
    pub fn name(&self, i: usize) -> &str {
        &self.names[i]
    }

    /// Mirrors `size()`.
    pub fn size(&self) -> usize {
        self.providers.len()
    }

    /// Mirrors `getImageRecords()`, i.e. `DyldCacheUtils.getImageRecords(headers)`. Always empty
    /// while [`DyldCacheHeader::image_infos`]/[`DyldCacheHeader::mapping_infos`] are (see their
    /// docs), but implemented against the real algorithm so it starts working the moment those
    /// tables are ported.
    pub fn image_records(&self) -> Vec<DyldCacheImageRecord> {
        let mut seen = std::collections::HashSet::new();
        let mut records = Vec::new();
        for (split_cache_index, header) in self.headers.iter().enumerate() {
            for image in header.image_infos() {
                let addr = image.address();
                if seen.contains(&addr) {
                    continue;
                }
                for h in &self.headers {
                    if h.mapping_infos().iter().any(|m| m.contains(addr as i64)) {
                        records.push(DyldCacheImageRecord {
                            image: Rc::clone(image),
                            split_cache_index: split_cache_index as i32,
                        });
                        seen.insert(addr);
                        break;
                    }
                }
            }
        }
        records
    }

    /// Mirrors `getMacho(DyldCacheImageRecord)`.
    pub fn macho(&self, image_record: &DyldCacheImageRecord) -> Result<MachHeader, MachException> {
        let i = image_record.split_cache_index as usize;
        let provider = self.providers.get(i).ok_or_else(|| {
            MachException::new(format!("No such split cache index: {i}"))
        })?;
        let base_address = self.headers.get(i).map(DyldCacheHeader::base_address).unwrap_or(0);
        let offset = image_record.image.address() as i64 - base_address;
        Ok(MachHeader::new(Rc::clone(provider), offset))
    }

    /// Mirrors `close()`: "Assume someone else is responsible for closing the base provider[s]
    /// that was passed in at construction" -- the base provider (index 0) is owned by
    /// `DyldCacheFileSystem` and released there; only split-file providers (never populated by
    /// this single-file stub) would need releasing here.
    pub fn close(&mut self) {}
}

/// Placeholder for `ghidra.file.formats.ios.dyldcache.DyldCacheExtractor`, referenced by
/// `DyldCacheFileSystem::get_byte_provider`.
///
/// Concrete stub: Java class, not interface. Extraction depends on Mach-O load-command parsing
/// ([`MachHeader::parse_segments`]) and DYLD slide-info parsing, neither of which is ported yet
/// (the `DyldCacheSlideInfo*` classes have no port either), so both extraction entry points
/// report "not yet implemented" rather than guess at extracted bytes; the slide-fixup collector
/// reports no fixups, which is a safe (if incomplete) default. Replace with the real port when
/// available.
pub struct DyldCacheExtractor;

/// The slide-fixup map type threaded from [`DyldCacheExtractor::get_slide_fixups`] into
/// [`DyldCacheExtractor::extract_dylib`]/[`extract_mapping`](DyldCacheExtractor::extract_mapping).
/// Mirrors `Map<DyldCacheMappingInfo, Map<Long, DyldFixup>>`.
pub type SlideFixupMap = HashMap<DyldCacheMappingInfo, HashMap<i64, DyldFixup>>;

impl DyldCacheExtractor {
    /// Mirrors `getSlideFixups(SplitDyldCache, TaskMonitor)`. Not yet implemented (see type
    /// docs): always reports no fixups.
    pub fn get_slide_fixups(
        _split_dyld_cache: &SplitDyldCache,
        _monitor: &dyn TaskMonitor,
    ) -> io::Result<SlideFixupMap> {
        Ok(HashMap::new())
    }

    /// Mirrors `extractDylib(DyldCacheEntry, SplitDyldCache, Map, FSRL, TaskMonitor)`. Not yet
    /// implemented (see type docs). The `FSRL` Java uses to tag the returned provider's identity
    /// is dropped, matching how [`ByteArrayProvider`] elsewhere in this file carries no FSRL.
    pub fn extract_dylib(
        _entry: &DyldCacheEntry,
        _split_dyld_cache: &SplitDyldCache,
        _slide_fixup_map: &SlideFixupMap,
        _monitor: &dyn TaskMonitor,
    ) -> io::Result<Box<dyn ByteProvider>> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "DyldCacheExtractor.extract_dylib not yet ported"))
    }

    /// Mirrors `extractMapping(DyldCacheEntry, String, SplitDyldCache, Map, FSRL, TaskMonitor)`.
    /// Not yet implemented (see type docs); the `FSRL` parameter is dropped for the same reason
    /// as [`extract_dylib`](Self::extract_dylib).
    pub fn extract_mapping(
        _entry: &DyldCacheEntry,
        _segment_name: &str,
        _split_dyld_cache: &SplitDyldCache,
        _slide_fixup_map: &SlideFixupMap,
        _monitor: &dyn TaskMonitor,
    ) -> io::Result<Box<dyn ByteProvider>> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "DyldCacheExtractor.extract_mapping not yet ported"))
    }
}

//! Minimal placeholder types for core types that a ported type references before the real
//! Rust port of that type exists yet. Each stub exposes only the members needed by the
//! interface(s) that currently reference it, and is expected to be replaced once the Java class
//! is ported. See `STUBS.tsv` for provenance.

use std::io;
use std::path::PathBuf;

use crate::program::model::data::data_type::DataType;
use crate::app::util::bin::binary_reader::BinaryReader;
use crate::filesystem::ghidra::g_binary_reader::ByteProvider;
use crate::filesystem::gfilesystem::fsrl::Fsrl;
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

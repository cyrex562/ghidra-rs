//! Minimal placeholder types for core types that a ported type references before the real
//! Rust port of that type exists yet. Each stub exposes only the members needed by the
//! interface(s) that currently reference it, and is expected to be replaced once the Java class
//! is ported. See `STUBS.tsv` for provenance.

use crate::program::model::data::data_type::DataType;
use crate::app::util::bin::binary_reader::BinaryReader;

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

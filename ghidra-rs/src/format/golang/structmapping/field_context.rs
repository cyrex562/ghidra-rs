//! Port of `ghidra.app.util.bin.format.golang.structmapping.FieldContext`.

use std::io;
use std::sync::Arc;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::program::model::address::Address;
use crate::program::model::data::data_type::DataType;

use super::field_mapping_info::{DtcInfo, FieldMappingInfo};
use super::structure_context::StructureContext;
use super::structure_mapped::{FieldValueKind, StructureMapped};

/// Context of an individual field that is being deserialized, or being marked up.
///
/// Java's record carries the `StructureContext`, the `FieldMappingInfo`, the Ghidra structure
/// field and an optional reader positioned at the field. In this port the context also borrows
/// the structure instance (`getStructureInstance()`), because the instance owns its
/// `StructureContext` rather than the other way around.
pub struct FieldContext<'a, T: 'static> {
    structure_context: &'a StructureContext<T>,
    instance: &'a T,
    field_info: &'a FieldMappingInfo<T>,
    dtc: DtcInfo,
    reader: Option<Box<dyn BinaryReader>>,
}

impl<'a, T: StructureMapped> FieldContext<'a, T> {
    /// Creates a field context (the record's canonical constructor).
    pub fn new(
        structure_context: &'a StructureContext<T>,
        instance: &'a T,
        field_info: &'a FieldMappingInfo<T>,
        dtc: DtcInfo,
        reader: Option<Box<dyn BinaryReader>>,
    ) -> Self {
        FieldContext { structure_context, instance, field_info, dtc, reader }
    }

    /// `structureContext()`.
    pub fn structure_context(&self) -> &'a StructureContext<T> {
        self.structure_context
    }

    /// `fieldInfo()`.
    pub fn field_info(&self) -> &'a FieldMappingInfo<T> {
        self.field_info
    }

    /// `dtc()`.
    pub fn dtc(&self) -> &DtcInfo {
        &self.dtc
    }

    /// The Ghidra data type of the structure field (`dtc().getDataType()`).
    pub fn dtc_data_type(&self) -> Option<Arc<dyn DataType>> {
        Some(self.dtc.data_type.clone())
    }

    /// `reader()`: the reader positioned at the field, present only while deserializing.
    pub fn reader(&self) -> Option<&dyn BinaryReader> {
        self.reader.as_deref()
    }

    /// The field reader, mutably; an error when the context was created without one (Java
    /// would throw a `NullPointerException`).
    pub fn reader_mut(&mut self) -> io::Result<&mut dyn BinaryReader> {
        match self.reader.as_deref_mut() {
            Some(r) => Ok(r),
            None => Err(io::Error::other(format!(
                "No reader for field {} (context created without a reader)",
                self.field_info.get_field().name
            ))),
        }
    }

    /// Returns the structure instance that contains this field.
    pub fn get_structure_instance(&self) -> &'a T {
        self.instance
    }

    /// Returns the address of this structure field.
    pub fn get_address(&self) -> Address {
        self.structure_context.get_field_address(self.dtc.offset as i64)
    }

    /// The kind of value the field holds; used in place of Java's `getValue(Class<R>)`
    /// type test.
    pub fn value_kind(&self) -> FieldValueKind {
        self.field_info.get_field().kind
    }
}

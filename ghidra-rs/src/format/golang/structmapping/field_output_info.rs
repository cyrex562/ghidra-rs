//! Port of `ghidra.app.util.bin.format.golang.structmapping.FieldOutputInfo`.

use std::io;

use crate::program::model::data::data_type::DataType;
use crate::program::model::data::structure::Structure;

use super::data_type_mapper::DataTypeMapper;
use super::field_mapping_info::FieldMappingInfo;
use super::reflection_helper;
use super::structure_context::StructureContext;
use super::structure_mapped::{
    FieldDescriptor, FieldOutputFn, FieldValueKind, OutputDataType, OutputGetterFn, StructureMapped,
};
use super::structure_mapping_info::struct_length;

/// How a `@FieldOutput` field is added to a structure (`FieldOutputInfo.outputFunc`), chosen
/// the way `setOutputFuncClass` chooses.
enum OutputFunc<T: 'static> {
    /// `@FieldOutput(fieldOutputFunc = ..)`.
    Custom(FieldOutputFn<T>),
    /// `@FieldOutput(getter = ..)` (`outputFuncWithGetter`).
    Getter(OutputGetterFn<T>),
    /// `@FieldOutput(dataTypeName = ..)` (`dataTypeNameOutputFunc`).
    DataTypeName,
    /// A primitive field (`primitiveOutputFunc`).
    Primitive,
    /// A primitive array field (`arrayOutputFunc`).
    Array,
    /// A nested structure mapped field (`nestedStructureOutputFunc`).
    Nested,
}

/// Immutable information needed to create fields in a Ghidra structure data type, using
/// information from a structure mapped type.
pub struct FieldOutputInfo<T: 'static> {
    field_index: usize,
    descriptor: &'static FieldDescriptor<T>,
    data_type_name: &'static str,
    field_offset: i32,
    is_variable_length: bool,
    ordinal: i32,
    output_func: OutputFunc<T>,
}

impl<T: StructureMapped> FieldOutputInfo<T> {
    /// Port of the constructor plus `setOutputFuncClass`. `field_index` is the index of the
    /// field's [`FieldMappingInfo`] in its `StructureMappingInfo`'s field list.
    ///
    /// # Errors
    /// `Invalid FieldOutput <field>` (Java's `IllegalArgumentException`) when no way to output
    /// the field applies.
    pub fn new(
        field_index: usize,
        descriptor: &'static FieldDescriptor<T>,
        data_type_name: &'static str,
        is_variable_length: bool,
        ordinal: i32,
        field_offset: i32,
    ) -> Result<Self, String> {
        let attr = descriptor.output.as_ref();
        let output_func = if let Some(f) = attr.and_then(|a| a.output_func) {
            OutputFunc::Custom(f)
        }
        else if let Some(g) = attr.and_then(|a| a.getter) {
            OutputFunc::Getter(g)
        }
        else if !data_type_name.trim().is_empty() {
            OutputFunc::DataTypeName
        }
        else {
            match descriptor.kind {
                FieldValueKind::Primitive(_) => OutputFunc::Primitive,
                FieldValueKind::PrimitiveArray(_) => OutputFunc::Array,
                FieldValueKind::StructureMapped if descriptor.nested_data_type.is_some() => OutputFunc::Nested,
                FieldValueKind::StructureMapped => {
                    return Err(format!("Invalid FieldOutput {}", descriptor.name));
                }
            }
        };
        Ok(FieldOutputInfo {
            field_index,
            descriptor,
            data_type_name,
            field_offset,
            is_variable_length,
            ordinal,
            output_func,
        })
    }

    /// `getField()`.
    pub fn get_field(&self) -> &'static FieldDescriptor<T> {
        self.descriptor
    }

    /// `getOrdinal()`.
    pub fn get_ordinal(&self) -> i32 {
        self.ordinal
    }

    /// `isVariableLength()`.
    pub fn is_variable_length(&self) -> bool {
        self.is_variable_length
    }

    /// The `@FieldOutput(offset)`, `-1` when unspecified.
    pub fn get_field_offset(&self) -> i32 {
        self.field_offset
    }

    fn fmi<'a>(&self, context: &'a StructureContext<T>) -> &'a FieldMappingInfo<T> {
        &context.get_mapping_info().get_fields()[self.field_index]
    }

    /// Adds this field to `structure` (`getOutputFunc().addFieldToStructure(...)`).
    pub fn add_field_to_structure(
        &self,
        context: &StructureContext<T>,
        instance: &T,
        mapper: &DataTypeMapper,
        structure: &mut dyn Structure,
    ) -> io::Result<()> {
        let fmi = self.fmi(context);
        match &self.output_func {
            OutputFunc::Custom(f) => f(context, instance, mapper, structure, self),
            OutputFunc::Getter(g) => match g(instance)? {
                None => Ok(()),
                Some(OutputDataType::DataType(dt)) => {
                    self.pre_add_field(structure)?;
                    add(structure, dt, None, fmi)
                }
                Some(OutputDataType::Instance(dt, len)) => {
                    self.pre_add_field(structure)?;
                    add(structure, dt, Some(len), fmi)
                }
            },
            OutputFunc::DataTypeName => {
                let dt = mapper.get_data_type(self.data_type_name).ok_or_else(|| {
                    io::Error::other(format!(
                        "Missing data type {} for field {}",
                        self.data_type_name,
                        fmi.get_field_name()
                    ))
                })?;
                self.pre_add_field(structure)?;
                if dt.is_dynamic_type() {
                    return Err(io::Error::other(format!(
                        "Invalid dynamic sized data type {} for field {}",
                        dt.get_name(),
                        fmi.get_field_name()
                    )));
                }
                add(structure, dt, None, fmi)
            }
            OutputFunc::Primitive => {
                let FieldValueKind::Primitive(kind) = self.descriptor.kind else {
                    unreachable!("primitive output func chosen for a primitive field")
                };
                let dt = reflection_helper::get_primitive_output_data_type(
                    kind,
                    fmi.get_length(),
                    fmi.get_signedness(),
                    mapper,
                )?;
                self.pre_add_field(structure)?;
                add(structure, dt, None, fmi)
            }
            OutputFunc::Array => {
                let FieldValueKind::PrimitiveArray(kind) = self.descriptor.kind else {
                    unreachable!("array output func chosen for an array field")
                };
                // only outputs array of primitive value
                let len = self.descriptor.array_len.map_or(0, |f| f(instance));
                let dt = reflection_helper::get_array_output_data_type(
                    len,
                    kind,
                    fmi.get_length(),
                    fmi.get_signedness(),
                    mapper,
                )?;
                self.pre_add_field(structure)?;
                add(structure, dt, None, fmi)
            }
            OutputFunc::Nested => {
                let nested = self.descriptor.nested_data_type.expect("nested output func has a nested fn");
                let Some(nested_dt) = nested(instance, mapper)? else {
                    return Ok(());
                };
                self.pre_add_field(structure)?;
                // Java adds the shared data type object itself; `Structure.add` takes ownership
                // here, so hand it a clone bound to the mapper's data type manager.
                let dtm = mapper.get_dtm().ok_or_else(|| {
                    io::Error::other("Program has no data type manager to clone a nested structure into")
                })?;
                add(structure, nested_dt.clone_data_type(dtm.as_ref()), None, fmi)
            }
        }
    }

    /// Port of `preAddField(Structure)`: pads the structure with undefined bytes up to the
    /// field's explicit `offset`.
    ///
    /// # Errors
    /// When the structure is already past the offset (as Java), or when padding is needed: the
    /// padding type comes from `Undefined.getUndefinedDataType(int)`, whose concrete
    /// `Undefined1DataType`..`Undefined8DataType` classes exist in this port only as traits.
    fn pre_add_field(&self, structure: &dyn Structure) -> io::Result<()> {
        if self.field_offset >= 0 {
            let current_offset = struct_length(structure);
            if current_offset > self.field_offset {
                return Err(io::Error::other(format!(
                    "Invalid field offset {}, structure is already {}",
                    self.field_offset, current_offset
                )));
            }
            if current_offset < self.field_offset {
                return Err(io::Error::other(format!(
                    "Cannot pad structure to field offset {}: Undefined.getUndefinedDataType is not ported",
                    self.field_offset
                )));
            }
        }
        Ok(())
    }
}

fn add<T: StructureMapped>(
    structure: &mut dyn Structure,
    dt: Box<dyn DataType>,
    length: Option<i32>,
    fmi: &FieldMappingInfo<T>,
) -> io::Result<()> {
    let name = Some(fmi.get_field_name().to_string());
    let result = match length {
        Some(len) => structure.add_with_length_and_name(dt, len, name, None),
        None => structure.add_with_name(dt, name, None),
    };
    result.map(|_| ()).map_err(io::Error::other)
}

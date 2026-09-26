//! Port of `ghidra.app.util.bin.format.golang.structmapping.StructureMappingInfo`.

use std::collections::HashMap;
use std::io;
use std::sync::Arc;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::structure::Structure;
use crate::program::model::data::structure_data_type::StructureDataTypeImpl;
use crate::program::model::listing::CommentType;

use super::data_type_mapper::DataTypeMapper;
use super::data_type_mapper_context::DataTypeMapperContext;
use super::field_mapping_info::{DtcInfo, FieldMappingInfo};
use super::field_output_info::FieldOutputInfo;
use super::markup_session::MarkupSession;
use super::signedness::Signedness;
use super::structure_context::StructureContext;
use super::structure_mapped::{FieldDescriptor, MarkupGetterFn, StructureMapped, StructureMappingDescriptor};

/// One `StructureMarkupFunction` of a structure mapped type, in the order Java adds them:
/// every `@Markup` getter, then the type-level `@PlateComment`.
#[derive(Clone, Copy)]
pub enum StructureMarkupFunc<T: 'static> {
    /// A `@Markup` getter (`createMarkupFuncFromGetter`).
    MarkupGetter(MarkupGetterFn<T>),
    /// A type-level `@PlateComment` (`addPlateCommentMarkupFuncs`).
    PlateComment(fn(&T) -> io::Result<Option<String>>),
}

/// Contains immutable information about a structure mapped type needed to deserialize a new
/// object from the data found in a Ghidra program.
pub struct StructureMappingInfo<T: 'static> {
    descriptor: &'static StructureMappingDescriptor<T>,
    structure_name: String,
    structure_data_type: Option<Arc<dyn DataType>>,
    field_name_lookup: HashMap<String, DtcInfo>,
    fields: Vec<FieldMappingInfo<T>>,
    output_fields: Vec<FieldOutputInfo<T>>,
    markup_funcs: Vec<StructureMarkupFunc<T>>,
    use_field_mapping_info: bool,
}

impl<T: StructureMapped> StructureMappingInfo<T> {
    /// Returns the mapping info for a type, using the attributes found on that type.
    ///
    /// Port of `StructureMappingInfo.fromClass(Class, Structure, DataTypeMapperContext)`.
    /// `struct_data_type` is the Ghidra structure defining the binary layout of the mapped
    /// fields, or `None` for a self-reading (`StructureReader`) type.
    ///
    /// # Errors
    /// The message Java's `IllegalArgumentException` carries, when a required structure field
    /// is missing.
    pub fn from_type(
        struct_data_type: Option<Arc<dyn DataType>>,
        context: &dyn DataTypeMapperContext,
    ) -> Result<Self, String> {
        let descriptor = T::descriptor();
        let structure_name = match &struct_data_type {
            Some(dt) => dt.get_name(),
            None => descriptor
                .structure_names
                .first()
                .map(|s| s.to_string())
                .ok_or_else(|| format!("Missing @StructureMapping annotation on {}", descriptor.type_name))?,
        };
        let mut info = StructureMappingInfo {
            descriptor,
            structure_name,
            field_name_lookup: HashMap::new(),
            structure_data_type: struct_data_type,
            fields: Vec::new(),
            output_fields: Vec::new(),
            markup_funcs: Vec::new(),
            use_field_mapping_info: !descriptor.is_structure_reader,
        };
        info.field_name_lookup = info.index_struct_fields();
        info.read_field_info(context)?;
        // stable sort, as Java's Collections.sort
        info.output_fields.sort_by_key(|foi| foi.get_ordinal());
        for getter in descriptor.markup_getters {
            info.markup_funcs.push(StructureMarkupFunc::MarkupGetter(*getter));
        }
        if let Some(pc) = descriptor.plate_comment {
            info.markup_funcs.push(StructureMarkupFunc::PlateComment(pc));
        }
        Ok(info)
    }

    /// `getDescription()`: `TypeName-structurename`.
    pub fn get_description(&self) -> String {
        format!("{}-{}", self.descriptor.type_name, self.structure_name)
    }

    /// `getStructureDataType()`: `None` for a variable length structure.
    pub fn get_structure_data_type(&self) -> Option<&Arc<dyn DataType>> {
        self.structure_data_type.as_ref()
    }

    /// `getStructureName()`.
    pub fn get_structure_name(&self) -> &str {
        &self.structure_name
    }

    /// `getStructureLength()`.
    ///
    /// # Panics
    /// Like Java's `IllegalArgumentException`, when the structure is variable length.
    pub fn get_structure_length(&self) -> i32 {
        self.structure_data_type
            .as_ref()
            .map(|dt| dt.get_length())
            .expect("IllegalArgumentException: variable length structure has no fixed length")
    }

    /// The static annotation table (`getTargetClass()`).
    pub fn get_descriptor(&self) -> &'static StructureMappingDescriptor<T> {
        self.descriptor
    }

    /// `getFields()`.
    pub fn get_fields(&self) -> &[FieldMappingInfo<T>] {
        &self.fields
    }

    /// The `@FieldOutput` fields, sorted by ordinal.
    pub fn get_output_fields(&self) -> &[FieldOutputInfo<T>] {
        &self.output_fields
    }

    /// `getFieldInfo(String)`: the mapping of the Rust field `field_name`.
    pub fn get_field_info(&self, field_name: &str) -> io::Result<&FieldMappingInfo<T>> {
        self.fields
            .iter()
            .find(|fmi| fmi.get_field().name == field_name)
            .ok_or_else(|| io::Error::other(format!("Java field name not found: {field_name}")))
    }

    /// `getMarkupFuncs()`.
    pub fn get_markup_funcs(&self) -> &[StructureMarkupFunc<T>] {
        &self.markup_funcs
    }

    /// Deserializes a structure mapped instance by assigning values to its mapped fields.
    ///
    /// Port of `readStructure(StructureContext)`. A `StructureReader` type reads itself;
    /// otherwise each field is read from a reader positioned at its structure field and
    /// assigned, and `reader` is moved to the end of the structure. A `StructureVerifier` type
    /// is then checked.
    pub fn read_structure(
        &self,
        context: &StructureContext<T>,
        instance: &mut T,
        mapper: &DataTypeMapper,
        reader: &mut dyn BinaryReader,
    ) -> io::Result<()> {
        if let Some(read_self) = self.descriptor.read_structure {
            read_self(instance, reader, mapper)?;
        }
        else {
            for field_info in &self.fields {
                if !field_info.has_reader_func() {
                    return Err(io::Error::other(format!(
                        "Missing read info for field: {}",
                        field_info.get_field().name
                    )));
                }
                let value = {
                    let mut field_context =
                        context.create_field_context(instance, field_info, Some(&*reader))?;
                    field_info.read_value(&mut field_context, mapper)?
                };
                field_info.assign_field(instance, value)?;
            }
            reader.set_pointer_index(context.get_structure_end() as u64);
        }
        if let Some(is_valid) = self.descriptor.is_valid {
            if !is_valid(instance) {
                return Err(io::Error::other(format!(
                    "Invalid data for struct @0x{:x}",
                    context.get_structure_start()
                )));
            }
        }
        Ok(())
    }

    /// Creates a new customized structure data type for a variable length structure mapped
    /// instance, named after the sizes of its variable length fields.
    ///
    /// Port of `createStructureDataType(StructureContext)`.
    pub fn create_structure_data_type(
        &self,
        context: &StructureContext<T>,
        instance: &T,
        mapper: &DataTypeMapper,
    ) -> io::Result<Box<dyn DataType>> {
        let mut new_struct = StructureDataTypeImpl::new_in_category(
            mapper.get_default_variable_length_struct_category_path().clone(),
            self.structure_name.clone(),
            0,
        );
        let mut name_suffix = String::new();
        for foi in &self.output_fields {
            let size_before = struct_length(&new_struct);
            foi.add_field_to_structure(context, instance, mapper, &mut new_struct)?;
            let size_delta = struct_length(&new_struct) - size_before;
            if foi.is_variable_length() {
                name_suffix.push_str(&format!("_{size_delta}"));
            }
        }
        if !name_suffix.is_empty() {
            new_struct
                .set_name(&format!("{}{}", self.structure_name, name_suffix))
                .map_err(|e| io::Error::other(e.to_string()))?;
        }
        Ok(Box::new(new_struct))
    }

    /// Runs one structure markup function (the lambdas Java builds in
    /// `createMarkupFuncFromGetter` and `addPlateCommentMarkupFuncs`).
    pub fn run_markup_func(
        &self,
        func: &StructureMarkupFunc<T>,
        context: &StructureContext<T>,
        instance: &T,
        session: &mut MarkupSession<'_>,
    ) -> io::Result<()> {
        match func {
            StructureMarkupFunc::MarkupGetter(f) => f(instance, session),
            StructureMarkupFunc::PlateComment(f) => {
                if let Some(text) = f(instance)? {
                    session.append_comment_at_structure(context, CommentType::Plate, None, &text, "\n")?;
                }
                Ok(())
            }
        }
    }

    fn read_field_info(&mut self, context: &dyn DataTypeMapperContext) -> Result<(), String> {
        let descriptor = self.descriptor;
        for fd in descriptor.fields {
            let Some(fmi) = self.read_field_mapping_info(fd, context)? else {
                // was marked optional / not present, just skip
                continue;
            };
            let field_index = self.fields.len();
            self.fields.push(fmi);
            if let Some(foa) = &fd.output {
                let foi = FieldOutputInfo::new(
                    field_index,
                    fd,
                    foa.data_type_name,
                    foa.is_variable_length,
                    foa.ordinal,
                    foa.offset,
                )?;
                self.output_fields.push(foi);
            }
        }
        Ok(())
    }

    fn read_field_mapping_info(
        &self,
        fd: &'static FieldDescriptor<T>,
        context: &dyn DataTypeMapperContext,
    ) -> Result<Option<FieldMappingInfo<T>>, String> {
        if let Some(fma) = &fd.mapping {
            if !context.is_field_present(fma.present_when) {
                // skip if this field was marked as not present
                return Ok(None);
            }
        }
        let field_names = self.get_field_names_to_search_for(fd);
        let dtc = self.get_first_matching_field(&field_names);
        if self.use_field_mapping_info && dtc.is_none() {
            if fd.mapping.is_some_and(|fma| fma.optional) {
                return Ok(None);
            }
            return Err(format!(
                "Missing structure field: {}.{:?} for {}.{}",
                self.structure_name, field_names, self.descriptor.type_name, fd.name
            ));
        }
        let signedness = fd.mapping.map_or(Signedness::Unspecified, |fma| fma.signedness);
        let length = fd.mapping.map_or(-1, |fma| fma.length);
        let mut fmi = match (self.use_field_mapping_info, dtc) {
            (true, Some(dtc)) => FieldMappingInfo::create_early_binding(fd, dtc, signedness, length),
            _ => FieldMappingInfo::create_late_binding(fd, field_names[0], signedness, length),
        };
        fmi.set_field_value_deserialization_info();
        fmi.add_markup_nested_funcs();
        fmi.add_comment_markup_funcs();
        fmi.add_markup_reference_func();
        Ok(Some(fmi))
    }

    fn get_field_names_to_search_for(&self, fd: &'static FieldDescriptor<T>) -> Vec<&'static str> {
        match &fd.mapping {
            Some(fma) if !fma.field_names.is_empty() && !fma.field_names[0].trim().is_empty() => {
                fma.field_names.to_vec()
            }
            _ => vec![fd.search_name],
        }
    }

    fn get_first_matching_field(&self, field_names: &[&str]) -> Option<DtcInfo> {
        field_names
            .iter()
            .find_map(|name| self.field_name_lookup.get(&name.to_lowercase()).cloned())
    }

    fn index_struct_fields(&self) -> HashMap<String, DtcInfo> {
        let mut result = HashMap::new();
        if let Some(structure) = self.structure_data_type.as_ref().and_then(|dt| dt.as_structure()) {
            for dtc in structure.get_defined_components() {
                if let Some(field_name) = dtc.get_field_name() {
                    result.insert(field_name.to_lowercase(), DtcInfo::from_component(dtc.as_ref()));
                }
            }
        }
        result
    }
}

/// `getStructLength(Structure)`: a zero-length structure counts as length 0.
pub(crate) fn struct_length(structure: &dyn Structure) -> i32 {
    if structure.is_zero_length() {
        0
    }
    else {
        structure.get_length()
    }
}

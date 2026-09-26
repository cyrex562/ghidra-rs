//! Port of `ghidra.app.util.bin.format.golang.structmapping.StructureContext`.

use std::io;
use std::sync::{Arc, OnceLock};

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::program::model::address::{Address, AddressSpace};
use crate::program::model::data::data_type::DataType;

use super::data_type_mapper::DataTypeMapper;
use super::field_context::FieldContext;
use super::field_mapping_info::FieldMappingInfo;
use super::structure_mapped::StructureMapped;
use super::structure_mapping_info::StructureMappingInfo;

/// Information about an instance of a structure that has been read from the memory of a Ghidra
/// program.
///
/// All structure mapped types own their `StructureContext<Self>` (a `#[context_field]`), which
/// records where the instance was read from and how it was mapped. Unlike the Java class, the
/// context neither owns nor points back at the instance, and does not hold the
/// `DataTypeMapper`:
///
/// * [`get_structure_instance`](Self::get_structure_instance) is gone: callers already hold the
///   instance (that is how they reached its context).
/// * Operations that need the mapper ([`get_reader`](Self::get_reader),
///   [`get_field_reader`](Self::get_field_reader),
///   [`get_structure_data_type`](Self::get_structure_data_type)) take it as an argument.
///   `getReader()` returned the reader the structure was read with, which in every Ghidra use is
///   the mapper's program reader; here it is re-created from the mapper at the structure's
///   start.
/// * The structure's address is resolved once, at creation, from the mapper's data address space
///   (Java re-resolves `dataTypeMapper.getDataAddress(structureStart)` on every call; the
///   mapper's space never changes).
pub struct StructureContext<T: 'static> {
    mapping_info: Arc<StructureMappingInfo<T>>,
    containing_field_data_type: Option<Arc<dyn DataType>>,
    structure_start: i64,
    data_space: Arc<AddressSpace>,
    structure_data_type: OnceLock<Arc<dyn DataType>>,
}

impl<T: StructureMapped> Clone for StructureContext<T> {
    fn clone(&self) -> Self {
        StructureContext {
            mapping_info: self.mapping_info.clone(),
            containing_field_data_type: self.containing_field_data_type.clone(),
            structure_start: self.structure_start,
            data_space: self.data_space.clone(),
            structure_data_type: self.structure_data_type.clone(),
        }
    }
}

impl<T: StructureMapped> StructureContext<T> {
    /// Creates an instance of a `StructureContext`.
    ///
    /// Port of `StructureContext(DataTypeMapper, StructureMappingInfo, DataType, BinaryReader)`:
    /// the structure starts at the reader's current position, or at `-1` for an artificial
    /// context created without a reader.
    pub fn new(
        data_type_mapper: &DataTypeMapper,
        mapping_info: Arc<StructureMappingInfo<T>>,
        containing_field_data_type: Option<Arc<dyn DataType>>,
        reader: Option<&dyn BinaryReader>,
    ) -> Self {
        let structure_start = reader.map_or(-1, |r| r.get_pointer_index() as i64);
        let structure_data_type = OnceLock::new();
        if let Some(dt) = mapping_info.get_structure_data_type() {
            let _ = structure_data_type.set(dt.clone());
        }
        StructureContext {
            mapping_info,
            containing_field_data_type,
            structure_start,
            data_space: data_type_mapper.get_data_space().clone(),
            structure_data_type,
        }
    }

    /// Port of `StructureContext.readNewInstance()`: creates an instance of `T` and deserializes
    /// it from `reader`.
    ///
    /// The instance is created with its own copy of this context (`@ContextField` injection),
    /// its fields are read (`StructureMappingInfo.readStructure`), and its
    /// `@AfterStructureRead` methods run. `reader` is left positioned at the end of the
    /// structure, as Java leaves the reader the context was created with.
    pub fn read_new_instance(
        &self,
        mapper: &DataTypeMapper,
        reader: &mut dyn BinaryReader,
    ) -> io::Result<T> {
        let mut instance = T::create_instance(self.clone(), mapper)?;
        self.mapping_info.read_structure(self, &mut instance, mapper, reader)?;
        for after in T::descriptor().after_read {
            after(&mut instance)?;
        }
        Ok(instance)
    }

    /// `getMappingInfo()`.
    pub fn get_mapping_info(&self) -> &Arc<StructureMappingInfo<T>> {
        &self.mapping_info
    }

    /// `getContainingFieldDataType()`: the data type of the field that contained this structure
    /// when it was read as a nested field, `None` otherwise.
    pub fn get_containing_field_data_type(&self) -> Option<&Arc<dyn DataType>> {
        self.containing_field_data_type.as_ref()
    }

    /// `getStructureAddress()`.
    pub fn get_structure_address(&self) -> Address {
        self.data_space.address(self.structure_start)
    }

    /// `getFieldAddress(long)`.
    pub fn get_field_address(&self, field_offset: i64) -> Address {
        self.get_structure_address().add_wrap(field_offset)
    }

    /// `getFieldLocation(long)`: the stream location of a field.
    pub fn get_field_location(&self, field_offset: i64) -> i64 {
        self.structure_start + field_offset
    }

    /// `getStructureStart()`.
    pub fn get_structure_start(&self) -> i64 {
        self.structure_start
    }

    /// `getStructureEnd()`.
    pub fn get_structure_end(&self) -> i64 {
        self.structure_start + self.get_structure_length() as i64
    }

    /// `getStructureLength()`: the structure data type's length, `0` when the structure is
    /// variable length and its data type has not been created yet.
    pub fn get_structure_length(&self) -> i32 {
        self.structure_data_type.get().map_or(0, |dt| dt.get_length())
    }

    /// `getReader()`: a reader positioned at the start of the structure.
    pub fn get_reader(&self, mapper: &DataTypeMapper) -> io::Result<Box<dyn BinaryReader>> {
        mapper.get_reader(self.structure_start)
    }

    /// `getFieldReader(long)`: a reader positioned at a field of the structure.
    pub fn get_field_reader(&self, mapper: &DataTypeMapper, field_offset: i64) -> io::Result<Box<dyn BinaryReader>> {
        mapper.get_reader(self.structure_start + field_offset)
    }

    /// Port of `createFieldContext(FieldMappingInfo, boolean)`.
    ///
    /// `reader` is the reader the structure is being read with (Java's `this.reader`); when
    /// given, the field context gets a clone of it positioned at the field.
    ///
    /// # Errors
    /// When the field cannot be located in the structure data type (Java would throw a
    /// `NullPointerException` on the missing `DataTypeComponent`).
    pub fn create_field_context<'a>(
        &'a self,
        instance: &'a T,
        fmi: &'a FieldMappingInfo<T>,
        reader: Option<&dyn BinaryReader>,
    ) -> io::Result<FieldContext<'a, T>> {
        let structure = self.structure_data_type.get();
        let dtc = fmi
            .get_dtc_in(structure.and_then(|dt| dt.as_structure()))
            .ok_or_else(|| {
                io::Error::other(format!(
                    "Missing structure field {} in {}",
                    fmi.get_field_name(),
                    self.mapping_info.get_structure_name()
                ))
            })?;
        let field_reader =
            reader.map(|r| r.clone_at((self.structure_start + dtc.offset as i64) as u64));
        Ok(FieldContext::new(self, instance, fmi, dtc, field_reader))
    }

    /// Port of `getStructureDataType()`: the structure's Ghidra data type, creating a custom one
    /// on first use for a variable length structure (`StructureMappingInfo.createStructureDataType`).
    pub fn get_structure_data_type_for(&self, instance: &T, mapper: &DataTypeMapper) -> io::Result<Arc<dyn DataType>> {
        if let Some(dt) = self.structure_data_type.get() {
            return Ok(dt.clone());
        }
        let created: Arc<dyn DataType> =
            Arc::from(self.mapping_info.create_structure_data_type(self, instance, mapper)?);
        Ok(self.structure_data_type.get_or_init(|| created).clone())
    }

    /// The structure's Ghidra data type when it is already known (a fixed-length structure, or
    /// a variable length one whose type was created earlier). A variable length structure's type
    /// needs the instance; see [`get_structure_data_type_for`](Self::get_structure_data_type_for).
    pub fn get_structure_data_type(&self, _mapper: &DataTypeMapper) -> io::Result<Arc<dyn DataType>> {
        self.structure_data_type.get().cloned().ok_or_else(|| {
            io::Error::other(format!(
                "Structure data type of variable length {} not created yet",
                self.mapping_info.get_description()
            ))
        })
    }

    /// The structure data type if it is already known, without creating one.
    pub fn get_known_structure_data_type(&self) -> Option<&Arc<dyn DataType>> {
        self.structure_data_type.get()
    }
}

impl<T: StructureMapped> std::fmt::Display for StructureContext<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "StructureContext<{}> {{ offset: {:x}}}",
            T::descriptor().type_name,
            self.structure_start as u64
        )
    }
}

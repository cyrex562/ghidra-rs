//! Port of `ghidra.app.util.bin.format.golang.structmapping.DataTypeMapper`.

use std::any::{Any, TypeId};
use std::cell::RefCell;
use std::collections::HashMap;
use std::io;
use std::rc::Rc;
use std::sync::Arc;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::format::elf::info::elf_info_item::ProviderBinaryReader;
use crate::format::seam_stubs::MemoryByteProvider;
use crate::program::model::address::{Address, AddressSpace};
use crate::program::model::data::category_path::{CategoryPath, ROOT};
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_conflict_handler::ConflictResolutionPolicy;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::listing::Program;
use crate::util::task::TaskMonitor;

use super::data_type_mapper_context::DataTypeMapperContext;
use super::markup_session::MarkupSession;
use super::structure_context::StructureContext;
use super::structure_mapped::StructureMapped;
use super::structure_mapping_info::StructureMappingInfo;

/// Information about structure mapped types and their metadata.
///
/// To use the full might and majesty of the structure mapping system, derive
/// `StructureMapped` on the types to be mapped, register them with
/// [`register_structure`](Self::register_structure), and read instances with
/// [`read_structure`](Self::read_structure) and friends.
///
/// Java keys the registry by `Class<?>`; this port keys it by [`TypeId`] and stores each
/// type's [`StructureMappingInfo`] type-erased. Java subclasses `DataTypeMapper` (as
/// `GoRttiMapper` does); here the specialised mapper composes one, and publishes whatever its
/// mapped types inject through `@ContextField` with [`set_context_value`](Self::set_context_value).
///
/// Differences from the Java class, all at its edges:
///
/// * The archive `.gdt` is passed in already opened (Java opens `archiveGDT` itself with
///   `FileDataTypeManager.openFileArchive`), and is dropped with the mapper (`close()`).
/// * Java's final lookup fallback is the `BuiltInDataTypeManager` singleton, which is not ported;
///   callers that have a built-in data type manager supply it with
///   [`set_built_in_data_type_manager`](Self::set_built_in_data_type_manager).
/// * Archive types are resolved into the program's data type manager with the `UseExisting`
///   conflict policy; Java uses `DWARFDataTypeConflictHandler.INSTANCE`, which is not ported.
pub struct DataTypeMapper {
    program: Arc<dyn Program>,
    archive_dtm: Option<Box<dyn DataTypeManager>>,
    built_in_dtm: Option<Box<dyn DataTypeManager>>,
    program_search_cps: Vec<CategoryPath>,
    archive_search_cps: Vec<CategoryPath>,
    mapping_info: HashMap<TypeId, Arc<dyn Any + Send + Sync>>,
    context_values: HashMap<TypeId, Box<dyn Any>>,
    data_space: Arc<AddressSpace>,
    default_variable_length_struct_category_path: CategoryPath,
}

impl DataTypeMapper {
    /// Creates and initializes a `DataTypeMapper` for `program`, with an optional archive of
    /// data types to search after the program's own (`DataTypeMapper(Program, ResourceFile)`).
    ///
    /// Addresses are created in the address space of the program's image base, as Java's
    /// `program.getImageBase().getNewAddress(offset)` does. A program that does not report an
    /// image base uses its default address space.
    ///
    /// # Errors
    /// When the program has neither an image base nor a default address space.
    pub fn new(program: Arc<dyn Program>, archive_dtm: Option<Box<dyn DataTypeManager>>) -> io::Result<Self> {
        let data_space = match program.get_image_base() {
            Some(base) => base.space().clone(),
            None => program
                .get_address_factory()
                .and_then(|f| f.get_default_address_space())
                .ok_or_else(|| io::Error::other("Program has no image base or default address space"))?,
        };
        Ok(DataTypeMapper {
            program,
            archive_dtm,
            built_in_dtm: None,
            program_search_cps: Vec::new(),
            archive_search_cps: Vec::new(),
            mapping_info: HashMap::new(),
            context_values: HashMap::new(),
            data_space,
            default_variable_length_struct_category_path: ROOT.clone(),
        })
    }

    /// Supplies the built-in data type manager searched last by [`get_data_type`](Self::get_data_type)
    /// (Java's `BuiltInDataTypeManager.getDataTypeManager()`).
    pub fn set_built_in_data_type_manager(&mut self, dtm: Box<dyn DataTypeManager>) {
        self.built_in_dtm = Some(dtm);
    }

    /// `getDefaultVariableLengthStructCategoryPath()`: the category of the custom structure
    /// data types created for variable length structures.
    pub fn get_default_variable_length_struct_category_path(&self) -> &CategoryPath {
        &self.default_variable_length_struct_category_path
    }

    /// Changes the category used for variable length structures (the value Java subclasses
    /// return from their `getDefaultVariableLengthStructCategoryPath` override).
    pub fn set_default_variable_length_struct_category_path(&mut self, path: CategoryPath) {
        self.default_variable_length_struct_category_path = path;
    }

    /// `getProgram()`.
    pub fn get_program(&self) -> &Arc<dyn Program> {
        &self.program
    }

    /// `createMarkupSession(TaskMonitor)`.
    pub fn create_markup_session<'a>(&'a self, monitor: &'a dyn TaskMonitor) -> MarkupSession<'a> {
        MarkupSession::new(self, monitor)
    }

    /// Whether the program's memory is big endian (`getDataConverter()`'s choice).
    pub fn is_big_endian(&self) -> bool {
        self.program.get_memory().is_some_and(|m| m.is_big_endian())
    }

    /// `addProgramSearchCategoryPath(CategoryPath...)`.
    pub fn add_program_search_category_path(&mut self, paths: &[CategoryPath]) {
        self.program_search_cps.extend_from_slice(paths);
    }

    /// `addArchiveSearchCategoryPath(CategoryPath...)`.
    pub fn add_archive_search_category_path(&mut self, paths: &[CategoryPath]) {
        self.archive_search_cps.extend_from_slice(paths);
    }

    /// Publishes a value that structure mapped types receive through a `#[context_field]` of
    /// type `C` (Java assigns any `@ContextField` whose type the mapper is an instance of).
    pub fn set_context_value<C: Clone + 'static>(&mut self, value: C) {
        self.context_values.insert(TypeId::of::<C>(), Box::new(value));
    }

    /// The `#[context_field]` value of type `C`; used by the derived constructors.
    ///
    /// # Errors
    /// `Unsupported context field` (as Java's `assignContextFieldValues`) when no value of that
    /// type was published.
    pub fn get_context_value<C: Clone + 'static>(&self, type_name: &str, field_name: &str) -> io::Result<C> {
        self.context_values
            .get(&TypeId::of::<C>())
            .and_then(|v| v.downcast_ref::<C>())
            .cloned()
            .ok_or_else(|| {
                io::Error::other(format!(
                    "Unsupported context field: {type_name}.{field_name}: {}",
                    std::any::type_name::<C>()
                ))
            })
    }

    /// Registers a structure mapped type, binding it to the first of its `structure_name`s found
    /// in the program (or archive) data types.
    ///
    /// Port of `registerStructure(Class, DataTypeMapperContext)`.
    ///
    /// # Errors
    /// When the structure is not found (and the type is not a `StructureReader` with exactly one
    /// structure name), or a mapped structure field is missing.
    pub fn register_structure<T: StructureMapped>(&mut self, context: &dyn DataTypeMapperContext) -> io::Result<()> {
        let descriptor = T::descriptor();
        let struct_names = descriptor.structure_names;
        let struct_dt = self.get_structure_type(struct_names);
        if struct_dt.is_none() {
            let dt_name = if struct_names.is_empty() { "<missing>".to_string() } else { struct_names.join("|") };
            if !descriptor.is_structure_reader {
                return Err(io::Error::other(format!(
                    "Missing struct definition for class {}, structure name: [{dt_name}]",
                    descriptor.type_name
                )));
            }
            if struct_names.len() != 1 {
                return Err(io::Error::other(format!(
                    "Bad StructMapping,StructureReader definition for class {}, structure name: [{dt_name}]",
                    descriptor.type_name
                )));
            }
        }
        let info = StructureMappingInfo::<T>::from_type(struct_dt.map(Arc::from), context)
            .map_err(io::Error::other)?;
        self.mapping_info.insert(TypeId::of::<T>(), Arc::new(info));
        Ok(())
    }

    /// `getStructureMappingInfo(Class)`: the mapping info of a registered type.
    pub fn get_structure_mapping_info<T: StructureMapped>(&self) -> Option<Arc<StructureMappingInfo<T>>> {
        self.mapping_info
            .get(&TypeId::of::<T>())
            .cloned()
            .and_then(|a| a.downcast::<StructureMappingInfo<T>>().ok())
    }

    /// `getStructureDataType(Class)`.
    pub fn get_structure_data_type<T: StructureMapped>(&self) -> Option<Arc<dyn DataType>> {
        self.get_structure_mapping_info::<T>()
            .and_then(|smi| smi.get_structure_data_type().cloned())
    }

    /// `getStructureDataTypeName(Class)`.
    pub fn get_structure_data_type_name<T: StructureMapped>(&self) -> Option<String> {
        self.get_structure_mapping_info::<T>().map(|smi| smi.get_structure_name().to_string())
    }

    /// Returns a named data type, searching the program's data types (in the registered
    /// program category paths), then the archive's (resolving a hit into the program), then the
    /// built-in data types' root category.
    ///
    /// Port of `getType(String, Class)` with `DataType.class`.
    pub fn get_data_type(&self, name: &str) -> Option<Box<dyn DataType>> {
        let program_dtm = self.program.get_data_type_manager();
        let mut data_type =
            program_dtm.as_deref().and_then(|dtm| find_type(name, &self.program_search_cps, dtm));
        if data_type.is_none() {
            if let Some(archive_dtm) = self.archive_dtm.as_deref() {
                data_type = find_type(name, &self.archive_search_cps, archive_dtm);
                if let (Some(dt), Some(mut dtm)) = (data_type.take(), self.program.get_data_type_manager()) {
                    data_type = Some(dtm.resolve(dt, ConflictResolutionPolicy::UseExisting.get_handler()));
                }
            }
        }
        if data_type.is_none() {
            data_type = self
                .built_in_dtm
                .as_deref()
                .and_then(|dtm| dtm.get_data_type_in_category(&ROOT, name));
        }
        data_type
    }

    /// `getType(List<String>, Structure.class)`: the first of `names` that names a structure.
    pub fn get_structure_type(&self, names: &[&str]) -> Option<Box<dyn DataType>> {
        names
            .iter()
            .filter(|n| !n.trim().is_empty())
            .find_map(|n| self.get_data_type(n).filter(|dt| dt.as_structure().is_some()))
    }

    /// `getTypeOrDefault(String, Class, T)`.
    pub fn get_type_or_default(&self, name: &str, default_value: Box<dyn DataType>) -> Box<dyn DataType> {
        self.get_data_type(name).unwrap_or(default_value)
    }

    /// `getDTM()`: the program's data type manager.
    pub fn get_dtm(&self) -> Option<Box<dyn DataTypeManager>> {
        self.program.get_data_type_manager()
    }

    /// `getAddressOfStructure(T)`: the address the instance was read from, `None` when the type
    /// keeps no `StructureContext`.
    pub fn get_address_of_structure<T: StructureMapped>(&self, structure_instance: &T) -> Option<Address> {
        structure_instance.structure_context().map(|c| c.get_structure_address())
    }

    /// `getMaxAddressOfStructure(T)`: the address of the instance's last byte.
    pub fn get_max_address_of_structure<T: StructureMapped>(&self, structure_instance: &T) -> Option<Address> {
        structure_instance
            .structure_context()
            .map(|c| c.get_structure_address().add_wrap(c.get_structure_length() as i64 - 1))
    }

    /// Attempts to convert an instance of an object (that represents a chunk of memory in the
    /// program) into its [`StructureContext`] (`getStructureContextOfInstance(T)`).
    pub fn get_structure_context_of_instance<'a, T: StructureMapped>(
        &self,
        structure_instance: &'a T,
    ) -> Option<&'a StructureContext<T>> {
        structure_instance.structure_context()
    }

    /// Reads a structure mapped object from the current position of `reader`, which is left
    /// positioned at the end of the structure (`readStructure(Class, BinaryReader)`).
    pub fn read_structure<T: StructureMapped>(&self, struct_reader: &mut dyn BinaryReader) -> io::Result<T> {
        self.read_structure_with::<T>(None, struct_reader)
    }

    /// Reads a structure mapped object that is a field of a containing structure whose field
    /// data type was `containing_field_data_type`
    /// (`readStructure(Class, DataType, BinaryReader)`).
    pub fn read_structure_with<T: StructureMapped>(
        &self,
        containing_field_data_type: Option<Arc<dyn DataType>>,
        struct_reader: &mut dyn BinaryReader,
    ) -> io::Result<T> {
        let context = self.create_structure_context::<T>(containing_field_data_type, Some(&*struct_reader))?;
        context.read_new_instance(self, struct_reader)
    }

    /// Reads a structure mapped object from the specified position of the program
    /// (`readStructure(Class, long)`).
    pub fn read_structure_at<T: StructureMapped>(&self, position: i64) -> io::Result<T> {
        let mut reader = self.get_reader(position)?;
        self.read_structure::<T>(reader.as_mut())
    }

    /// Reads a structure mapped object from the specified address of the program
    /// (`readStructure(Class, Address)`).
    pub fn read_structure_at_address<T: StructureMapped>(&self, address: &Address) -> io::Result<T> {
        self.read_structure_at::<T>(address.offset())
    }

    /// Creates a reader over the program's memory positioned at `position` (`getReader(long)`).
    pub fn get_reader(&self, position: i64) -> io::Result<Box<dyn BinaryReader>> {
        let mut reader = self.create_program_reader()?;
        reader.set_pointer_index(position as u64);
        Ok(reader)
    }

    /// The address space data and code addresses are created in.
    pub fn get_data_space(&self) -> &Arc<AddressSpace> {
        &self.data_space
    }

    /// Converts a stream offset into an `Address` for data (`getDataAddress(long)`).
    pub fn get_data_address(&self, offset: i64) -> Address {
        self.data_space.address(offset)
    }

    /// Converts a stream offset into an `Address` for code (`getCodeAddress(long)`).
    pub fn get_code_address(&self, offset: i64) -> Address {
        self.data_space.address(offset)
    }

    /// `createProgramReader()`: a reader over the program's memory in the data address space,
    /// using the memory's endianness.
    fn create_program_reader(&self) -> io::Result<Box<dyn BinaryReader>> {
        let memory = self
            .program
            .get_memory()
            .ok_or_else(|| io::Error::other("Program has no memory to read structures from"))?;
        let little_endian = !memory.is_big_endian();
        let bp = MemoryByteProvider::new(memory, &self.data_space);
        Ok(Box::new(ProviderBinaryReader::new(Rc::new(RefCell::new(bp)), little_endian)))
    }

    /// `createArtificialStructureContext(Class)`: a context for an instance that was not read
    /// from the program.
    ///
    /// # Errors
    /// `Unknown structure mapped class` when `T` is not registered.
    pub fn create_artificial_structure_context<T: StructureMapped>(&self) -> io::Result<StructureContext<T>> {
        self.create_structure_context::<T>(None, None)
    }

    fn create_structure_context<T: StructureMapped>(
        &self,
        containing_field_data_type: Option<Arc<dyn DataType>>,
        reader: Option<&dyn BinaryReader>,
    ) -> io::Result<StructureContext<T>> {
        let smi = self.get_structure_mapping_info::<T>().ok_or_else(|| {
            io::Error::other(format!("Unknown structure mapped class: {}", T::descriptor().type_name))
        })?;
        Ok(StructureContext::new(self, smi, containing_field_data_type, reader))
    }
}

impl std::fmt::Display for DataTypeMapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DataTypeMapper {{ program: {} }}", Program::get_name(self.program.as_ref()))
    }
}

/// `findType(String, List<CategoryPath>, DataTypeManager)`.
fn find_type(name: &str, search_list: &[CategoryPath], dtm: &dyn DataTypeManager) -> Option<Box<dyn DataType>> {
    search_list.iter().find_map(|cp| dtm.get_data_type_in_category(cp, name))
}

use crate::program::model::address::{Address, AddressSet};
use crate::program::model::data::composite::Composite;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::data::packing_type::PackingType;
use crate::program::model::data::structure::Structure;
use crate::program::model::lang::data_type_provider_context::DataTypeProviderContext;
use crate::program::model::listing::program::Program;

/// Default name assigned to a newly created structure when no explicit name is requested.
///
/// Port of `StructureFactory.DEFAULT_STRUCTURE_NAME`.
pub const DEFAULT_STRUCTURE_NAME: &str = "struct";

/// Creates and initializes [`Structure`] instances.
///
/// Port of `ghidra.program.model.data.StructureFactory`.
///
/// The Java type is a collection of `static` factory methods with no instance state, which made
/// it a convenient cycle cut-point: several call sites reach it only to build a `Structure` from a
/// `Program`/`Address` selection. Modeled here as a trait (rather than free functions) so an
/// implementation can be swapped in as a trait object (`Box<dyn StructureFactory>`) at any such
/// call site, breaking the direct dependency on this module.
///
/// Two collaborators the Java methods construct directly are not yet ported as concrete types:
/// `StructureDataType` (`ghidra.program.model.data.StructureDataType`) and the two
/// `DataTypeProviderContext` implementations `ProgramProviderContext`/`ProgramStructureProviderContext`
/// (`ghidra.app.plugin.core.data`, outside `ghidra.program.model` entirely). Rather than adding
/// placeholder types for them, their construction is exposed as required trait methods
/// ([`StructureFactory::new_structure`], [`StructureFactory::new_program_context`],
/// [`StructureFactory::new_program_structure_context`]) returning the already-ported
/// [`Structure`]/[`DataTypeProviderContext`] trait objects: this keeps the trait object-safe and
/// lets a concrete implementation supply real instances once those classes are ported, without
/// this module needing to know their shape.
pub trait StructureFactory {
    /// Creates a [`Structure`] instance based upon the information provided. The instance will
    /// not be placed in memory.
    ///
    /// This is a pass-through to
    /// [`create_structure_data_type_named`](Self::create_structure_data_type_named) using
    /// [`DEFAULT_STRUCTURE_NAME`] and `make_unique_name = true`.
    ///
    /// # Errors
    /// See [`create_structure_data_type_named`](Self::create_structure_data_type_named).
    fn create_structure_data_type(
        &self,
        program: &mut dyn Program,
        address: &Address,
        data_length: i32,
    ) -> Result<Box<dyn Structure>, String> {
        self.create_structure_data_type_named(
            program,
            address,
            data_length,
            DEFAULT_STRUCTURE_NAME,
            true,
        )
    }

    /// Creates a [`Structure`] instance based upon the information provided. The instance will
    /// not be placed in memory.
    ///
    /// # Errors
    /// Returns `Err` for the following conditions (mirroring `IllegalArgumentException`):
    /// * `data_length` is not greater than zero
    /// * the number of components to add exceeds the available address space
    /// * there are any instructions in the provided address range
    /// * there are no data components to add to the structure
    fn create_structure_data_type_named(
        &self,
        program: &mut dyn Program,
        address: &Address,
        data_length: i32,
        structure_name: &str,
        make_unique_name: bool,
    ) -> Result<Box<dyn Structure>, String> {
        if data_length <= 0 {
            return Err(format!(
                "IllegalArgumentException: Structure length must be positive, not {data_length}"
            ));
        }

        let end_address = address.add_no_wrap((data_length - 1) as i64).map_err(|_| {
            format!(
                "IllegalArgumentException: Can't create structure because length exceeds address space{data_length}"
            )
        })?;

        if let Some(listing) = program.get_listing() {
            let range = AddressSet::from_start_end(address.clone(), end_address);
            if listing.get_instructions_in(&range, true).next().is_some() {
                return Err(
                    "IllegalArgumentException: Can't create structure because the current selection contains instructions"
                        .to_string(),
                );
            }
        }

        let context = self.new_program_context(program, address);

        let name = if make_unique_name {
            context.get_unique_name(structure_name)
        } else {
            structure_name.to_string()
        };

        let dtm = program.get_listing().map(|listing| listing.get_data_type_manager());
        let mut new_structure = self.new_structure(&name, dtm);

        initialize_structure_from_context(new_structure.as_mut(), context.as_ref(), data_length)?;

        Ok(new_structure)
    }

    /// Creates a [`Structure`] instance, which is inside of another structure, based upon the
    /// information provided. The instance will not be placed in memory.
    ///
    /// This is a pass-through to
    /// [`create_structure_data_type_in_structure_named`](Self::create_structure_data_type_in_structure_named)
    /// using [`DEFAULT_STRUCTURE_NAME`] and `make_unique_name = true`.
    ///
    /// # Errors
    /// See
    /// [`create_structure_data_type_in_structure_named`](Self::create_structure_data_type_in_structure_named).
    fn create_structure_data_type_in_structure(
        &self,
        program: &mut dyn Program,
        address: &Address,
        from_path: &[i32],
        to_path: &[i32],
    ) -> Result<Box<dyn Structure>, String> {
        self.create_structure_data_type_in_structure_named(
            program,
            address,
            from_path,
            to_path,
            DEFAULT_STRUCTURE_NAME,
            true,
        )
    }

    /// Creates a [`Structure`] instance, which is inside of another structure, based upon the
    /// information provided. The instance will not be placed in memory.
    ///
    /// # Errors
    /// Returns `Err` for the following conditions (mirroring `IllegalArgumentException`):
    /// * the component at `from_path` or the component at `to_path` are missing
    /// * there is no data to add to the structure
    /// * the parent data type is not a structure
    fn create_structure_data_type_in_structure_named(
        &self,
        program: &mut dyn Program,
        address: &Address,
        from_path: &[i32],
        to_path: &[i32],
        structure_name: &str,
        make_unique_name: bool,
    ) -> Result<Box<dyn Structure>, String> {
        let listing = program
            .get_listing()
            .ok_or_else(|| "IllegalArgumentException: program has no listing".to_string())?;

        let data = listing
            .get_data_containing(address)
            .ok_or_else(|| "IllegalArgumentException: Invalid selection".to_string())?;

        let comp1 = data
            .get_component_by_path(from_path)
            .ok_or_else(|| "IllegalArgumentException: Invalid selection".to_string())?;
        let comp2 = data
            .get_component_by_path(to_path)
            .ok_or_else(|| "IllegalArgumentException: Invalid selection".to_string())?;

        let data_length =
            (comp2.get_parent_offset() + comp2.get_length()) - comp1.get_parent_offset();
        if data_length <= 0 {
            return Err(format!(
                "IllegalArgumentException: Data length must be positive, not {data_length}"
            ));
        }

        // make sure there is a valid parent structure
        let first_component = data
            .get_component_by_path(from_path)
            .ok_or_else(|| "IllegalArgumentException: Invalid selection".to_string())?;
        let parent_data_type = first_component
            .get_parent()
            .ok_or_else(|| {
                "IllegalArgumentException: New structure is not in a structure".to_string()
            })?
            .get_base_data_type();
        if !parent_data_type.is_structure() {
            return Err("IllegalArgumentException: New structure is not in a structure".to_string());
        }

        let min_address = data.get_min_address();
        let context =
            self.new_program_structure_context(program, &min_address, comp1.get_parent_offset());

        let name = if make_unique_name {
            context.get_unique_name(structure_name)
        } else {
            structure_name.to_string()
        };

        let dtm = program
            .get_listing()
            .map(|listing| listing.get_data_type_manager());
        let mut new_structure = self.new_structure(&name, dtm);

        initialize_structure_from_context(new_structure.as_mut(), context.as_ref(), data_length)?;

        Ok(new_structure)
    }

    /// Builds a new, empty structure named `name`, associated with `dtm` if present.
    ///
    /// Required hook standing in for `new StructureDataType(name, 0, dtm)`, since
    /// `ghidra.program.model.data.StructureDataType` is not yet ported.
    fn new_structure(&self, name: &str, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn Structure>;

    /// Builds the provider context used to enumerate the data type components for a new
    /// top-level structure at `address` within `program`.
    ///
    /// Required hook standing in for `new ProgramProviderContext(program, address)`, since
    /// `ghidra.app.plugin.core.data.ProgramProviderContext` is not yet ported.
    fn new_program_context(
        &self,
        program: &dyn Program,
        address: &Address,
    ) -> Box<dyn DataTypeProviderContext>;

    /// Builds the provider context used to enumerate the data type components for a new
    /// structure nested inside an existing parent structure, starting at `parent_offset` bytes
    /// into the parent (whose containing [`Data`](crate::program::model::listing::data::Data)
    /// starts at `min_address`).
    ///
    /// Required hook standing in for `new ProgramStructureProviderContext(program, minAddress,
    /// parentStructure, parentOffset)`, since
    /// `ghidra.app.plugin.core.data.ProgramStructureProviderContext` is not yet ported.
    fn new_program_structure_context(
        &self,
        program: &dyn Program,
        min_address: &Address,
        parent_offset: i32,
    ) -> Box<dyn DataTypeProviderContext>;
}

/// Uses the provided context to initialize the provided structure with `data_length` bytes worth
/// of components.
///
/// Port of the private static `StructureFactory.initializeStructureFromContext`.
///
/// # Errors
/// Returns `Err` if no data type components are found in `context` for `0..data_length - 1`
/// (mirrors `IllegalArgumentException`), or if adding a component fails.
fn initialize_structure_from_context(
    structure: &mut dyn Structure,
    context: &dyn DataTypeProviderContext,
    data_length: i32,
) -> Result<(), String> {
    let data_comps = context.get_data_type_components(0, data_length - 1);

    if data_comps.is_empty() {
        return Err("IllegalArgumentException: No data type components found".to_string());
    }

    // adopt pack settings from parent - things could move as a result
    let parent = data_comps[0].get_parent();
    if let Some(composite) = parent.into_composite() {
        structure.set_packing_enabled(composite.is_packing_enabled());
        if composite.get_packing_type() == PackingType::Explicit {
            structure.set_explicit_packing_value(composite.get_explicit_packing_value())?;
        }
    }

    for data_comp in &data_comps {
        structure.add_with_length_and_name(
            data_comp.get_data_type(),
            data_comp.get_length(),
            data_comp.get_field_name(),
            data_comp.get_comment(),
        )?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::data::data_type_component::DataTypeComponent;
    use crate::program::model::listing::code_unit::CodeUnit;
    use crate::program::model::listing::instruction::Instruction;
    use crate::program::model::listing::data::Data;
    use crate::program::model::listing::listing::Listing;
    use crate::program::model::mem::MemoryAccessException;
    use crate::program::model::scalar::Scalar;
    use crate::program::model::symbol::{
        EmptyReferenceIterator, ExternalReference, RefType as SymRefType, Reference as SymReference,
        ReferenceIterator, SourceType, Symbol,
    };
    use crate::program::seam_stubs::{InstructionIterator, RefType, Reference};
use crate::program::model::mem::MemBuffer;
use crate::program::model::listing::CommentType;
    use std::any::{Any, TypeId};
    use std::sync::{Arc, Mutex};

    fn mock_address(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    // --- DataType / DataTypeComponent / DataTypeProviderContext mocks -------------------------

    struct MockDataType {
        name: String,
    }
    impl DataType for MockDataType {
        fn get_name(&self) -> String {
            self.name.clone()
        }
    }

    struct MockComponent {
        name: &'static str,
        length: i32,
    }
    impl DataTypeComponent for MockComponent {
        fn get_data_type(&self) -> Box<dyn DataType> {
            Box::new(MockDataType {
                name: self.name.to_string(),
            })
        }
        fn get_length(&self) -> i32 {
            self.length
        }
        fn get_field_name(&self) -> Option<String> {
            Some(self.name.to_string())
        }
    }

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    struct MockProviderContext {
        components: Vec<(&'static str, i32)>,
    }
    impl DataTypeProviderContext for MockProviderContext {
        fn get_unique_name(&self, base_name: &str) -> String {
            format!("{base_name}_unique")
        }
        fn get_data_type_component(
            &self,
            _offset: i32,
        ) -> Result<Option<Box<dyn DataTypeComponent>>, String> {
            Ok(None)
        }
        fn get_data_type_components(&self, _start: i32, _end: i32) -> Vec<Box<dyn DataTypeComponent>> {
            self.components
                .iter()
                .map(|(name, length)| -> Box<dyn DataTypeComponent> {
                    Box::new(MockComponent {
                        name,
                        length: *length,
                    })
                })
                .collect()
        }
    }

    /// A [`Structure`] that actually records added components, so the trait's default
    /// orchestration logic can be exercised end-to-end (not just type-checked). The recorded log
    /// is shared (via `Arc<Mutex<_>>`) with the factory that created it, so tests can inspect it
    /// after the trait object is consumed.
    struct RecordingStructure {
        name: String,
        added: Arc<Mutex<Vec<(String, i32, Option<String>)>>>,
    }
    impl DataType for RecordingStructure {
        fn get_name(&self) -> String {
            self.name.clone()
        }
        fn is_structure(&self) -> bool {
            true
        }
    }
    impl Composite for RecordingStructure {
        fn add_with_length_and_name(
            &mut self,
            data_type: Box<dyn DataType>,
            length: i32,
            component_name: Option<String>,
            _comment: Option<String>,
        ) -> Result<Box<dyn DataTypeComponent>, String> {
            self.added
                .lock()
                .unwrap()
                .push((data_type.get_name(), length, component_name));
            Ok(Box::new(MockComponent {
                name: "added",
                length,
            }))
        }
    }
    impl Structure for RecordingStructure {}

    /// Exercises every required hook with real (non-placeholder) behavior: builds a
    /// [`RecordingStructure`] and mock provider contexts whose components are set per-test.
    struct MockStructureFactory {
        log: Arc<Mutex<Vec<(String, i32, Option<String>)>>>,
        top_components: Vec<(&'static str, i32)>,
        nested_components: Vec<(&'static str, i32)>,
    }
    impl MockStructureFactory {
        fn new(top_components: Vec<(&'static str, i32)>, nested_components: Vec<(&'static str, i32)>) -> Self {
            Self {
                log: Arc::new(Mutex::new(Vec::new())),
                top_components,
                nested_components,
            }
        }
    }
    impl StructureFactory for MockStructureFactory {
        fn new_structure(&self, name: &str, _dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn Structure> {
            Box::new(RecordingStructure {
                name: name.to_string(),
                added: Arc::clone(&self.log),
            })
        }
        fn new_program_context(
            &self,
            _program: &dyn Program,
            _address: &Address,
        ) -> Box<dyn DataTypeProviderContext> {
            Box::new(MockProviderContext {
                components: self.top_components.clone(),
            })
        }
        fn new_program_structure_context(
            &self,
            _program: &dyn Program,
            _min_address: &Address,
            _parent_offset: i32,
        ) -> Box<dyn DataTypeProviderContext> {
            Box::new(MockProviderContext {
                components: self.nested_components.clone(),
            })
        }
    }

    // --- Program / Listing / Data mocks --------------------------------------------------------

    struct NoInstructions;
    impl Iterator for NoInstructions {
        type Item = Arc<dyn Instruction>;
        fn next(&mut self) -> Option<Self::Item> {
            None
        }
    }
    impl InstructionIterator for NoInstructions {}

    struct MockListing {
        data_type_manager_calls: std::sync::atomic::AtomicI32,
        parent_is_structure: bool,
    }
    impl Listing for MockListing {
        fn get_code_unit_at(&self, _addr: &Address) -> Option<Arc<dyn CodeUnit>> {
            None
        }
        fn get_code_unit_containing(&self, _addr: &Address) -> Option<Arc<dyn CodeUnit>> {
            None
        }
        fn get_code_unit_after(&self, _addr: &Address) -> Option<Arc<dyn CodeUnit>> {
            None
        }
        fn get_code_unit_before(&self, _addr: &Address) -> Option<Arc<dyn CodeUnit>> {
            None
        }
        fn get_code_unit_iterator(
            &self,
            _property: &str,
            _forward: bool,
        ) -> Box<dyn crate::program::seam_stubs::CodeUnitIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_code_unit_iterator_from(
            &self,
            _property: &str,
            _addr: &Address,
            _forward: bool,
        ) -> Box<dyn crate::program::seam_stubs::CodeUnitIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_code_unit_iterator_in(
            &self,
            _property: &str,
            _addr_set: &dyn crate::program::model::address::AddressSetView,
            _forward: bool,
        ) -> Box<dyn crate::program::seam_stubs::CodeUnitIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_comment_code_unit_iterator(
            &self,
            _comment_type: CommentType,
            _addr_set: &dyn crate::program::model::address::AddressSetView,
        ) -> Box<dyn crate::program::seam_stubs::CodeUnitIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_comment_address_iterator(
            &self,
            _comment_type: CommentType,
            _addr_set: &dyn crate::program::model::address::AddressSetView,
            _forward: bool,
        ) -> crate::program::model::address::BoxedAddressIterator {
            unimplemented!("not needed for this smoke test")
        }
        fn get_any_comment_address_iterator(
            &self,
            _addr_set: &dyn crate::program::model::address::AddressSetView,
            _forward: bool,
        ) -> crate::program::model::address::BoxedAddressIterator {
            unimplemented!("not needed for this smoke test")
        }
        fn get_comment(&self, _comment_type: CommentType, _address: &Address) -> Option<String> {
            None
        }
        fn get_all_comments(
            &self,
            _address: &Address,
        ) -> Box<dyn crate::program::seam_stubs::CodeUnitComments> {
            struct MockComments;
            impl crate::program::seam_stubs::CodeUnitComments for MockComments {}
            Box::new(MockComments)
        }
        fn set_comment(&mut self, _address: &Address, _comment_type: CommentType, _comment: Option<String>) {}
        fn get_code_units(&self, _forward: bool) -> Box<dyn crate::program::seam_stubs::CodeUnitIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_code_units_from(
            &self,
            _addr: &Address,
            _forward: bool,
        ) -> Box<dyn crate::program::seam_stubs::CodeUnitIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_code_units_in(
            &self,
            _addr_set: &dyn crate::program::model::address::AddressSetView,
            _forward: bool,
        ) -> Box<dyn crate::program::seam_stubs::CodeUnitIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_instruction_at(
            &self,
            _addr: &Address,
        ) -> Option<Arc<dyn crate::program::model::listing::instruction::Instruction>> {
            None
        }
        fn get_instruction_containing(
            &self,
            _addr: &Address,
        ) -> Option<Arc<dyn crate::program::model::listing::instruction::Instruction>> {
            None
        }
        fn get_instruction_after(
            &self,
            _addr: &Address,
        ) -> Option<Arc<dyn crate::program::model::listing::instruction::Instruction>> {
            None
        }
        fn get_instruction_before(
            &self,
            _addr: &Address,
        ) -> Option<Arc<dyn crate::program::model::listing::instruction::Instruction>> {
            None
        }
        fn get_instructions(
            &self,
            _forward: bool,
        ) -> Box<dyn crate::program::seam_stubs::InstructionIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_instructions_from(
            &self,
            _addr: &Address,
            _forward: bool,
        ) -> Box<dyn crate::program::seam_stubs::InstructionIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_instructions_in(
            &self,
            _addr_set: &dyn crate::program::model::address::AddressSetView,
            _forward: bool,
        ) -> Box<dyn crate::program::seam_stubs::InstructionIterator> {
            Box::new(NoInstructions)
        }
        fn get_data_at(&self, _addr: &Address) -> Option<Arc<dyn Data>> {
            None
        }
        fn get_data_containing(&self, addr: &Address) -> Option<Arc<dyn Data>> {
            Some(Arc::new(MockData::top(addr.clone(), self.parent_is_structure)))
        }
        fn get_data_after(&self, _addr: &Address) -> Option<Arc<dyn Data>> {
            None
        }
        fn get_data_before(&self, _addr: &Address) -> Option<Arc<dyn Data>> {
            None
        }
        fn get_data(&self, _forward: bool) -> Box<dyn crate::program::seam_stubs::DataIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_data_from(
            &self,
            _addr: &Address,
            _forward: bool,
        ) -> Box<dyn crate::program::seam_stubs::DataIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_data_in(
            &self,
            _addr_set: &dyn crate::program::model::address::AddressSetView,
            _forward: bool,
        ) -> Box<dyn crate::program::seam_stubs::DataIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_defined_data_at(&self, _addr: &Address) -> Option<Arc<dyn Data>> {
            None
        }
        fn get_defined_data_containing(&self, _addr: &Address) -> Option<Arc<dyn Data>> {
            None
        }
        fn get_defined_data_after(&self, _addr: &Address) -> Option<Arc<dyn Data>> {
            None
        }
        fn get_defined_data_before(&self, _addr: &Address) -> Option<Arc<dyn Data>> {
            None
        }
        fn get_defined_data(&self, _forward: bool) -> Box<dyn crate::program::seam_stubs::DataIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_defined_data_from(
            &self,
            _addr: &Address,
            _forward: bool,
        ) -> Box<dyn crate::program::seam_stubs::DataIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_defined_data_in(
            &self,
            _addr_set: &dyn crate::program::model::address::AddressSetView,
            _forward: bool,
        ) -> Box<dyn crate::program::seam_stubs::DataIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_undefined_data_at(&self, _addr: &Address) -> Option<Arc<dyn Data>> {
            None
        }
        fn get_undefined_data_after(
            &self,
            _addr: &Address,
            _monitor: &dyn crate::util::task::TaskMonitor,
        ) -> Option<Arc<dyn Data>> {
            None
        }
        fn get_first_undefined_data(
            &self,
            _set: &dyn crate::program::model::address::AddressSetView,
            _monitor: &dyn crate::util::task::TaskMonitor,
        ) -> Option<Arc<dyn Data>> {
            None
        }
        fn get_undefined_data_before(
            &self,
            _addr: &Address,
            _monitor: &dyn crate::util::task::TaskMonitor,
        ) -> Option<Arc<dyn Data>> {
            None
        }
        fn get_undefined_ranges(
            &self,
            _set: &dyn crate::program::model::address::AddressSetView,
            _initialized_memory_only: bool,
            _monitor: &dyn crate::util::task::TaskMonitor,
        ) -> Result<
            Box<dyn crate::program::model::address::AddressSetView>,
            crate::util::exception::CancelledException,
        > {
            unimplemented!("not needed for this smoke test")
        }
        fn get_defined_code_unit_after(&self, _addr: &Address) -> Option<Arc<dyn CodeUnit>> {
            None
        }
        fn get_defined_code_unit_before(&self, _addr: &Address) -> Option<Arc<dyn CodeUnit>> {
            None
        }
        fn get_user_defined_properties(&self) -> Vec<String> {
            Vec::new()
        }
        fn remove_user_defined_property(&mut self, _property_name: &str) {}
        fn get_property_map(
            &self,
            _property_name: &str,
        ) -> Option<Box<dyn crate::program::model::util::PropertyMap>> {
            None
        }
        fn create_instruction(
            &mut self,
            _addr: Address,
            _prototype: Arc<
                dyn crate::program::model::lang::instruction_prototype::InstructionPrototype,
            >,
            _mem_buf: &dyn MemBuffer,
            _context: &dyn crate::program::model::lang::ProcessorContextView,
            _length: i32,
        ) -> Result<
            Arc<dyn crate::program::model::listing::instruction::Instruction>,
            crate::program::util::CodeUnitInsertionException,
        > {
            unimplemented!("not needed for this smoke test")
        }
        fn add_instructions(
            &mut self,
            _instruction_set: &dyn crate::program::seam_stubs::InstructionSet,
            _overwrite: bool,
        ) -> Result<
            Box<dyn crate::program::model::address::AddressSetView>,
            crate::program::util::CodeUnitInsertionException,
        > {
            unimplemented!("not needed for this smoke test")
        }
        fn create_data_sized(
            &mut self,
            _addr: Address,
            _data_type: Box<dyn DataType>,
            _length: i32,
        ) -> Result<Arc<dyn Data>, crate::program::util::CodeUnitInsertionException> {
            unimplemented!("not needed for this smoke test")
        }
        fn create_data(
            &mut self,
            _addr: Address,
            _data_type: Box<dyn DataType>,
        ) -> Result<Arc<dyn Data>, crate::program::util::CodeUnitInsertionException> {
            unimplemented!("not needed for this smoke test")
        }
        fn clear_code_units(&mut self, _start_addr: &Address, _end_addr: &Address, _clear_context: bool) {}
        fn clear_code_units_with_monitor(
            &mut self,
            _start_addr: &Address,
            _end_addr: &Address,
            _clear_context: bool,
            _monitor: &dyn crate::util::task::TaskMonitor,
        ) -> Result<(), crate::util::exception::CancelledException> {
            Ok(())
        }
        fn is_undefined(&self, _start: &Address, _end: &Address) -> bool {
            true
        }
        fn clear_comments(&mut self, _start_addr: &Address, _end_addr: &Address) {}
        fn clear_properties(
            &mut self,
            _start_addr: &Address,
            _end_addr: &Address,
            _monitor: &dyn crate::util::task::TaskMonitor,
        ) -> Result<(), crate::util::exception::CancelledException> {
            Ok(())
        }
        fn clear_all(&mut self, _clear_context: bool, _monitor: &dyn crate::util::task::TaskMonitor) {}
        fn get_fragment(
            &self,
            _tree_name: &str,
            _addr: &Address,
        ) -> Option<Arc<dyn crate::program::model::listing::program_fragment::ProgramFragment>> {
            None
        }
        fn get_module(
            &self,
            _tree_name: &str,
            _name: &str,
        ) -> Option<Arc<dyn crate::program::model::listing::program_module::ProgramModule>> {
            None
        }
        fn get_fragment_by_name(
            &self,
            _tree_name: &str,
            _name: &str,
        ) -> Option<Arc<dyn crate::program::model::listing::program_fragment::ProgramFragment>> {
            None
        }
        fn create_root_module(
            &mut self,
            _tree_name: &str,
        ) -> Result<
            Arc<dyn crate::program::model::listing::program_module::ProgramModule>,
            crate::util::exception::DuplicateNameException,
        > {
            unimplemented!("not needed for this smoke test")
        }
        fn get_root_module(
            &self,
            _tree_name: &str,
        ) -> Option<Arc<dyn crate::program::model::listing::program_module::ProgramModule>> {
            None
        }
        fn get_root_module_by_id(
            &self,
            _tree_id: i64,
        ) -> Option<Arc<dyn crate::program::model::listing::program_module::ProgramModule>> {
            None
        }
        fn get_default_root_module(
            &self,
        ) -> Arc<dyn crate::program::model::listing::program_module::ProgramModule> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_tree_names(&self) -> Vec<String> {
            Vec::new()
        }
        fn remove_tree(&mut self, _tree_name: &str) -> bool {
            false
        }
        fn rename_tree(
            &mut self,
            _old_name: &str,
            _new_name: &str,
        ) -> Result<(), crate::util::exception::DuplicateNameException> {
            Ok(())
        }
        fn get_num_code_units(&self) -> i64 {
            0
        }
        fn get_num_defined_data(&self) -> i64 {
            0
        }
        fn get_num_instructions(&self) -> i64 {
            0
        }
        fn get_data_type_manager(&self) -> Box<dyn DataTypeManager> {
            self.data_type_manager_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::new(MockDataTypeManager)
        }
        fn create_function(
            &mut self,
            _name: &str,
            _entry_point: Address,
            _body: &dyn crate::program::model::address::AddressSetView,
            _source: SourceType,
        ) -> Result<
            Arc<dyn crate::program::model::listing::function::Function>,
            crate::program::model::listing::listing::CreateFunctionError,
        > {
            unimplemented!("not needed for this smoke test")
        }
        fn create_function_in_namespace(
            &mut self,
            _name: &str,
            _name_space: Arc<dyn crate::program::model::symbol::Namespace>,
            _entry_point: Address,
            _body: &dyn crate::program::model::address::AddressSetView,
            _source: SourceType,
        ) -> Result<
            Arc<dyn crate::program::model::listing::function::Function>,
            crate::program::model::listing::listing::CreateFunctionError,
        > {
            unimplemented!("not needed for this smoke test")
        }
        fn remove_function(&mut self, _entry_point: &Address) {}
        fn get_function_at(
            &self,
            _entry_point: &Address,
        ) -> Option<Arc<dyn crate::program::model::listing::function::Function>> {
            None
        }
        fn get_global_functions(
            &self,
            _name: &str,
        ) -> Vec<Arc<dyn crate::program::model::listing::function::Function>> {
            Vec::new()
        }
        fn get_functions_by_name(
            &self,
            _namespace: Option<&str>,
            _name: &str,
        ) -> Vec<Arc<dyn crate::program::model::listing::function::Function>> {
            Vec::new()
        }
        fn get_function_containing(
            &self,
            _addr: &Address,
        ) -> Option<Arc<dyn crate::program::model::listing::function::Function>> {
            None
        }
        fn get_external_functions(&self) -> Box<dyn crate::program::seam_stubs::FunctionIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_functions(&self, _forward: bool) -> Box<dyn crate::program::seam_stubs::FunctionIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_functions_from(
            &self,
            _start: &Address,
            _forward: bool,
        ) -> Box<dyn crate::program::seam_stubs::FunctionIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_functions_in(
            &self,
            _asv: &dyn crate::program::model::address::AddressSetView,
            _forward: bool,
        ) -> Box<dyn crate::program::seam_stubs::FunctionIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn is_in_function(&self, _addr: &Address) -> bool {
            false
        }
        fn get_comment_history(
            &self,
            _addr: &Address,
            _comment_type: CommentType,
        ) -> Vec<Box<dyn crate::program::seam_stubs::CommentHistory>> {
            Vec::new()
        }
        fn get_comment_address_count(&self) -> i64 {
            0
        }
    }

    struct MockProgram {
        listing: MockListing,
    }
    impl crate::framework::model::DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock.bin".to_string()
        }
        fn get_language_id(&self) -> String {
            "test:LE:32:default".to_string()
        }
        fn get_listing(&mut self) -> Option<&mut dyn Listing> {
            Some(&mut self.listing)
        }
    }

    fn mock_program(parent_is_structure: bool) -> MockProgram {
        MockProgram {
            listing: MockListing {
                data_type_manager_calls: std::sync::atomic::AtomicI32::new(0),
                parent_is_structure,
            },
        }
    }

    fn empty_program() -> Arc<dyn Program> {
        struct EmptyProgram;
        impl crate::framework::model::DomainObject for EmptyProgram {}
        impl Program for EmptyProgram {
            fn get_name(&self) -> String {
                "mock.bin".to_string()
            }
            fn get_language_id(&self) -> String {
                "test:LE:32:default".to_string()
            }
        }
        Arc::new(EmptyProgram)
    }

    /// A single [`Data`] implementation used both as a top-level "structure being edited" object
    /// (via [`MockData::top`]) and as a component reached through
    /// [`Data::get_component_by_path`] (via [`MockData::component`]). `component_path[0] == 0`
    /// selects the low end of the selection (offset 0), any other value selects the high end
    /// (offset 4, length 4) -- giving a combined selection length of 8, mirroring the
    /// `data_length` used by the top-level test.
    struct MockData {
        min_address: Address,
        parent_offset: i32,
        length: i32,
        is_structure: bool,
        is_component: bool,
    }
    impl MockData {
        fn top(min_address: Address, is_structure: bool) -> Self {
            MockData {
                min_address,
                parent_offset: 0,
                length: 8,
                is_structure,
                is_component: false,
            }
        }
        fn component(min_address: Address, is_structure: bool, parent_offset: i32, length: i32) -> Self {
            MockData {
                min_address,
                parent_offset,
                length,
                is_structure,
                is_component: true,
            }
        }
    }
    impl MemBuffer for MockData {
        fn get_byte(&self, _offset: i32) -> Result<u8, crate::program::model::mem::MemoryAccessException> {
            unimplemented!("not exercised by these tests")
        }
        fn get_bytes(&self, _buf: &mut [u8], _offset: i32) -> usize {
            unimplemented!("not exercised by these tests")
        }
        fn is_big_endian(&self) -> bool {
            unimplemented!("not exercised by these tests")
        }
        fn get_address(&self) -> Address {
            self.min_address.clone()
        }
    }
    impl crate::program::model::util::PropertySet for MockData {}
    impl CodeUnit for MockData {
        fn get_address_string(&self, _show_block_name: bool, _pad: bool) -> String {
            String::new()
        }
        fn get_label(&self) -> Option<String> {
            None
        }
        fn get_symbols(&self) -> Vec<Arc<dyn Symbol>> {
            Vec::new()
        }
        fn get_primary_symbol(&self) -> Option<Arc<dyn Symbol>> {
            None
        }
        fn get_min_address(&self) -> Address {
            self.min_address.clone()
        }
        fn get_max_address(&self) -> Address {
            self.min_address.clone()
        }
        fn get_mnemonic_string(&self) -> String {
            String::new()
        }
        fn get_comment(&self, _comment_type: CommentType) -> Option<String> {
            None
        }
        fn get_comment_as_array(&self, _comment_type: CommentType) -> Vec<String> {
            Vec::new()
        }
        fn set_comment(&mut self, _comment_type: CommentType, _comment: Option<String>) {}
        fn set_comment_as_array(&mut self, _comment_type: CommentType, _comment: &[String]) {}
        fn get_length(&self) -> i32 {
            self.length
        }
        fn get_bytes(&self) -> Result<Vec<u8>, MemoryAccessException> {
            Ok(Vec::new())
        }
        fn get_bytes_in_code_unit(
            &self,
            _buffer: &mut [u8],
            _buffer_offset: i32,
        ) -> Result<(), MemoryAccessException> {
            Ok(())
        }
        fn contains(&self, _test_addr: &Address) -> bool {
            false
        }
        fn compare_to(&self, _addr: &Address) -> i32 {
            0
        }
        fn add_mnemonic_reference(
            &mut self,
            _ref_addr: Address,
            _ref_type: SymRefType,
            _source_type: SourceType,
        ) {
        }
        fn remove_mnemonic_reference(&mut self, _ref_addr: &Address) {}
        fn get_mnemonic_references(&self) -> Vec<Arc<dyn SymReference>> {
            Vec::new()
        }
        fn get_operand_references(&self, _index: i32) -> Vec<Arc<dyn SymReference>> {
            Vec::new()
        }
        fn get_primary_reference(&self, _index: i32) -> Option<Arc<dyn SymReference>> {
            None
        }
        fn add_operand_reference(
            &mut self,
            _index: i32,
            _ref_addr: Address,
            _ref_type: SymRefType,
            _source_type: SourceType,
        ) {
        }
        fn remove_operand_reference(&mut self, _index: i32, _ref_addr: &Address) {}
        fn get_references_from(&self) -> Vec<Arc<dyn SymReference>> {
            Vec::new()
        }
        fn get_reference_iterator_to(&self) -> Box<dyn ReferenceIterator> {
            Box::new(EmptyReferenceIterator)
        }
        fn get_program(&self) -> Arc<dyn Program> {
            empty_program()
        }
        fn get_external_reference(&self, _op_index: i32) -> Option<Arc<dyn ExternalReference>> {
            None
        }
        fn remove_external_reference(&mut self, _op_index: i32) {}
        fn set_primary_memory_reference(&mut self, _reference: Arc<dyn SymReference>) {}
        fn set_stack_reference(
            &mut self,
            _op_index: i32,
            _offset: i32,
            _source_type: SourceType,
            _ref_type: SymRefType,
        ) {
        }
        fn set_register_reference(
            &mut self,
            _op_index: i32,
            _reg: &crate::program::model::lang::register::Register,
            _source_type: SourceType,
            _ref_type: SymRefType,
        ) {
        }
        fn get_num_operands(&self) -> i32 {
            1
        }
        fn get_address(&self, _op_index: i32) -> Option<Address> {
            None
        }
        fn get_scalar(&self, _op_index: i32) -> Option<Scalar> {
            None
        }
    }
    impl crate::docking::settings::settings::Settings for MockData {}
    impl Data for MockData {
        fn get_value(&self) -> Option<Box<dyn Any>> {
            None
        }
        fn get_value_class(&self) -> Option<TypeId> {
            None
        }
        fn has_string_value(&self) -> bool {
            false
        }
        fn is_constant(&self) -> bool {
            false
        }
        fn is_writable(&self) -> bool {
            true
        }
        fn is_volatile(&self) -> bool {
            false
        }
        fn is_defined(&self) -> bool {
            true
        }
        fn get_data_type(&self) -> Box<dyn DataType> {
            Box::new(MockDataType {
                name: "mock".to_string(),
            })
        }
        fn get_base_data_type(&self) -> Box<dyn DataType> {
            struct BaseDataType(bool);
            impl DataType for BaseDataType {
                fn is_structure(&self) -> bool {
                    self.0
                }
            }
            Box::new(BaseDataType(self.is_structure))
        }
        fn get_value_references(&self) -> Vec<Box<dyn Reference>> {
            Vec::new()
        }
        fn add_value_reference(&mut self, _ref_addr: Address, _ref_type: Box<dyn RefType>) {}
        fn remove_value_reference(&mut self, _ref_addr: Address) {}
        fn get_field_name(&self) -> Option<String> {
            None
        }
        fn get_path_name(&self) -> String {
            String::new()
        }
        fn get_component_path_name(&self) -> String {
            String::new()
        }
        fn is_pointer(&self) -> bool {
            false
        }
        fn is_union(&self) -> bool {
            false
        }
        fn is_structure(&self) -> bool {
            self.is_structure
        }
        fn is_array(&self) -> bool {
            false
        }
        fn is_dynamic(&self) -> bool {
            false
        }
        fn get_parent(&self) -> Option<Box<dyn Data>> {
            if self.is_component {
                Some(Box::new(MockData::top(self.min_address.clone(), self.is_structure)))
            } else {
                None
            }
        }
        fn get_root(&self) -> Box<dyn Data> {
            Box::new(MockData::top(self.min_address.clone(), self.is_structure))
        }
        fn get_root_offset(&self) -> i32 {
            self.parent_offset
        }
        fn get_parent_offset(&self) -> i32 {
            self.parent_offset
        }
        fn get_component(&self, _index: i32) -> Option<Box<dyn Data>> {
            None
        }
        fn get_component_by_path(&self, component_path: &[i32]) -> Option<Box<dyn Data>> {
            if self.is_component || component_path.is_empty() {
                return None;
            }
            let (offset, length) = if component_path[0] == 0 { (0, 0) } else { (4, 4) };
            Some(Box::new(MockData::component(
                self.min_address.clone(),
                self.is_structure,
                offset,
                length,
            )))
        }
        fn get_component_path(&self) -> Vec<i32> {
            Vec::new()
        }
        fn get_num_components(&self) -> i32 {
            2
        }
        #[allow(deprecated)]
        fn get_component_at(&self, _offset: i32) -> Option<Box<dyn Data>> {
            None
        }
        fn get_component_containing(&self, _offset: i32) -> Option<Box<dyn Data>> {
            None
        }
        fn get_components_containing(&self, _offset: i32) -> Option<Vec<Box<dyn Data>>> {
            None
        }
        fn get_primitive_at(&self, _offset: i32) -> Option<Box<dyn Data>> {
            None
        }
        fn get_component_index(&self) -> i32 {
            -1
        }
        fn get_component_level(&self) -> i32 {
            0
        }
        fn get_default_value_representation(&self) -> String {
            String::new()
        }
        fn get_default_label_prefix(
            &self,
            _options: &dyn crate::program::model::data::data_type_display_options::DataTypeDisplayOptions,
        ) -> Option<String> {
            None
        }
    }

    // --- tests ----------------------------------------------------------------------------------

    #[test]
    fn create_structure_data_type_populates_components_and_unique_name() {
        let factory = MockStructureFactory::new(vec![("alpha", 4), ("beta", 4)], vec![]);
        let mut program = mock_program(true);
        let address = mock_address(0x100);

        let structure = factory
            .create_structure_data_type(&mut program, &address, 8)
            .expect("structure creation should succeed");

        assert_eq!(structure.get_name(), "struct_unique");
        assert_eq!(
            *factory.log.lock().unwrap(),
            vec![
                ("alpha".to_string(), 4, Some("alpha".to_string())),
                ("beta".to_string(), 4, Some("beta".to_string())),
            ]
        );
        assert_eq!(
            program
                .listing
                .data_type_manager_calls
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );
    }

    #[test]
    fn create_structure_data_type_named_respects_make_unique_name_false() {
        let factory = MockStructureFactory::new(vec![("alpha", 4)], vec![]);
        let mut program = mock_program(true);
        let address = mock_address(0x100);

        let structure = factory
            .create_structure_data_type_named(&mut program, &address, 4, "my_struct", false)
            .expect("structure creation should succeed");

        assert_eq!(structure.get_name(), "my_struct");
    }

    #[test]
    fn create_structure_data_type_rejects_non_positive_length() {
        let factory = MockStructureFactory::new(vec![], vec![]);
        let mut program = mock_program(true);
        let address = mock_address(0x100);

        let err = factory
            .create_structure_data_type(&mut program, &address, 0)
            .err()
            .expect("expected an error");
        assert!(err.contains("IllegalArgumentException"));
    }

    #[test]
    fn create_structure_data_type_rejects_empty_component_list() {
        let factory = MockStructureFactory::new(vec![], vec![]);
        let mut program = mock_program(true);
        let address = mock_address(0x100);

        let err = factory
            .create_structure_data_type(&mut program, &address, 4)
            .err()
            .expect("expected an error");
        assert!(err.contains("No data type components found"));
    }

    #[test]
    fn create_structure_data_type_in_structure_uses_structure_context() {
        let factory = MockStructureFactory::new(vec![], vec![("gamma", 2)]);
        let mut program = mock_program(true);
        let address = mock_address(0x100);

        let structure = factory
            .create_structure_data_type_in_structure(&mut program, &address, &[0], &[1])
            .expect("structure creation should succeed");

        assert_eq!(structure.get_name(), "struct_unique");
        assert_eq!(
            *factory.log.lock().unwrap(),
            vec![("gamma".to_string(), 2, Some("gamma".to_string()))]
        );
    }

    #[test]
    fn create_structure_data_type_in_structure_rejects_non_structure_parent() {
        let factory = MockStructureFactory::new(vec![], vec![("gamma", 2)]);
        let mut program = mock_program(false);
        let address = mock_address(0x100);

        let err = factory
            .create_structure_data_type_in_structure(&mut program, &address, &[0], &[1])
            .err()
            .expect("expected an error");
        assert!(err.contains("New structure is not in a structure"));
    }

    #[test]
    fn create_structure_data_type_in_structure_rejects_invalid_selection() {
        let factory = MockStructureFactory::new(vec![], vec![]);
        let mut program = mock_program(true);
        let address = mock_address(0x100);

        // An empty path fails to resolve to a component (`get_component_by_path` returns `None`).
        let err = factory
            .create_structure_data_type_in_structure(&mut program, &address, &[], &[1])
            .err()
            .expect("expected an error");
        assert!(err.contains("Invalid selection"));
    }
}

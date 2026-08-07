use std::sync::Arc;

use crate::program::model::block::subroutine_block_model::SubroutineBlockModel;
use crate::program::model::listing::listing::Listing;

/// Display name for this block model.
///
/// Stands in for `PartitionCodeSubModel.NAME`.
pub const NAME: &str = "Partitioned Code";

/// Model-P: defines subroutines which do not share code with other subroutines and may have one
/// or more entry points.
///
/// Entry points represent any one of a variety of flow entries, including a source, called,
/// jump or fall-through entry point.
///
/// MODEL-P is the answer to those who always want to be able to know what subroutine a given
/// instruction is in, but also do not want the subroutine to have multiple entry points. When a
/// model-M subroutine has multiple entry points, that set of code will necessarily consist of
/// several model-P subroutines. When a model-M subroutine has a single entry point, it will
/// consist of a single model-P subroutine which has the same address set and entry point.
///
/// Port of `ghidra.program.model.block.PartitionCodeSubModel`. The address-set-partitioning
/// algorithm (`createBlockGraph`/`partitionGraph`/`fromGraphToSubs`) and the block cache it relies
/// on are private implementation details of the Java class rather than part of its public API, so
/// they are not modeled here; only the public surface (plus the inherited
/// [`SubroutineBlockModel`]/`CodeBlockModel` contract) is captured.
pub trait PartitionCodeSubModel: SubroutineBlockModel {
    /// Returns the listing associated with this block model.
    fn get_listing(&self) -> Arc<dyn Listing>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::database::function::OverlappingFunctionException;
    use crate::program::model::address::{Address, BoxedAddressIterator, AddressSetView};
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::data::data_type_manager::DataTypeManager;
    use crate::program::model::lang::instruction_prototype::InstructionPrototype;
    use crate::program::model::lang::ProcessorContextView;
    use crate::program::model::listing::code_unit::CodeUnit;
    use crate::program::model::listing::data::Data;
    use crate::program::model::listing::function::Function;
    use crate::program::model::listing::instruction::Instruction;
    use crate::program::model::listing::listing::CreateFunctionError;
    use crate::program::model::listing::program_fragment::ProgramFragment;
    use crate::program::model::listing::program_module::ProgramModule;
    use crate::program::model::symbol::Namespace;
    use crate::program::model::symbol::SourceType;
    use crate::program::model::util::PropertyMap;
    use crate::program::model::block::code_block_model::CodeBlockModel;
    use crate::program::seam_stubs::{CodeUnitComments, CodeUnitIterator, CommentHistory, DataIterator, FunctionIterator, InstructionIterator, InstructionSet, MemBuffer};
use crate::program::model::listing::CommentType;
    use crate::program::util::CodeUnitInsertionException;
    use crate::util::exception::{CancelledException, DuplicateNameException};
    use crate::util::task::TaskMonitor;
    use std::cell::Cell;
    use std::rc::Rc;

    /// A minimal [`Listing`] whose only meaningfully-implemented member is
    /// [`get_num_code_units`](Listing::get_num_code_units), which reports a caller-chosen sentinel
    /// so tests can prove a specific listing instance flowed all the way through
    /// [`PartitionCodeSubModel::get_listing`] rather than some other placeholder. Every other
    /// member is unreachable from this test and panics if called.
    struct TaggedListing {
        code_unit_count: i64,
    }

    impl Listing for TaggedListing {
        fn get_code_unit_at(&self, _: &Address) -> Option<Arc<dyn CodeUnit>> {
            unimplemented!()
        }
        fn get_code_unit_containing(&self, _: &Address) -> Option<Arc<dyn CodeUnit>> {
            unimplemented!()
        }
        fn get_code_unit_after(&self, _: &Address) -> Option<Arc<dyn CodeUnit>> {
            unimplemented!()
        }
        fn get_code_unit_before(&self, _: &Address) -> Option<Arc<dyn CodeUnit>> {
            unimplemented!()
        }
        fn get_code_unit_iterator(&self, _: &str, _: bool) -> Box<dyn CodeUnitIterator> {
            unimplemented!()
        }
        fn get_code_unit_iterator_from(
            &self,
            _: &str,
            _: &Address,
            _: bool,
        ) -> Box<dyn CodeUnitIterator> {
            unimplemented!()
        }
        fn get_code_unit_iterator_in(
            &self,
            _: &str,
            _: &dyn AddressSetView,
            _: bool,
        ) -> Box<dyn CodeUnitIterator> {
            unimplemented!()
        }
        fn get_comment_code_unit_iterator(
            &self,
            _: CommentType,
            _: &dyn AddressSetView,
        ) -> Box<dyn CodeUnitIterator> {
            unimplemented!()
        }
        fn get_comment_address_iterator(
            &self,
            _: CommentType,
            _: &dyn AddressSetView,
            _: bool,
        ) -> BoxedAddressIterator {
            unimplemented!()
        }
        fn get_any_comment_address_iterator(
            &self,
            _: &dyn AddressSetView,
            _: bool,
        ) -> BoxedAddressIterator {
            unimplemented!()
        }
        fn get_comment(&self, _: CommentType, _: &Address) -> Option<String> {
            unimplemented!()
        }
        fn get_all_comments(&self, _: &Address) -> Box<dyn CodeUnitComments> {
            unimplemented!()
        }
        fn set_comment(&mut self, _: &Address, _: CommentType, _: Option<String>) {
            unimplemented!()
        }
        fn get_code_units(&self, _: bool) -> Box<dyn CodeUnitIterator> {
            unimplemented!()
        }
        fn get_code_units_from(&self, _: &Address, _: bool) -> Box<dyn CodeUnitIterator> {
            unimplemented!()
        }
        fn get_code_units_in(
            &self,
            _: &dyn AddressSetView,
            _: bool,
        ) -> Box<dyn CodeUnitIterator> {
            unimplemented!()
        }
        fn get_instruction_at(&self, _: &Address) -> Option<Arc<dyn Instruction>> {
            unimplemented!()
        }
        fn get_instruction_containing(&self, _: &Address) -> Option<Arc<dyn Instruction>> {
            unimplemented!()
        }
        fn get_instruction_after(&self, _: &Address) -> Option<Arc<dyn Instruction>> {
            unimplemented!()
        }
        fn get_instruction_before(&self, _: &Address) -> Option<Arc<dyn Instruction>> {
            unimplemented!()
        }
        fn get_instructions(&self, _: bool) -> Box<dyn InstructionIterator> {
            unimplemented!()
        }
        fn get_instructions_from(&self, _: &Address, _: bool) -> Box<dyn InstructionIterator> {
            unimplemented!()
        }
        fn get_instructions_in(
            &self,
            _: &dyn AddressSetView,
            _: bool,
        ) -> Box<dyn InstructionIterator> {
            unimplemented!()
        }
        fn get_data_at(&self, _: &Address) -> Option<Arc<dyn Data>> {
            unimplemented!()
        }
        fn get_data_containing(&self, _: &Address) -> Option<Arc<dyn Data>> {
            unimplemented!()
        }
        fn get_data_after(&self, _: &Address) -> Option<Arc<dyn Data>> {
            unimplemented!()
        }
        fn get_data_before(&self, _: &Address) -> Option<Arc<dyn Data>> {
            unimplemented!()
        }
        fn get_data(&self, _: bool) -> Box<dyn DataIterator> {
            unimplemented!()
        }
        fn get_data_from(&self, _: &Address, _: bool) -> Box<dyn DataIterator> {
            unimplemented!()
        }
        fn get_data_in(&self, _: &dyn AddressSetView, _: bool) -> Box<dyn DataIterator> {
            unimplemented!()
        }
        fn get_defined_data_at(&self, _: &Address) -> Option<Arc<dyn Data>> {
            unimplemented!()
        }
        fn get_defined_data_containing(&self, _: &Address) -> Option<Arc<dyn Data>> {
            unimplemented!()
        }
        fn get_defined_data_after(&self, _: &Address) -> Option<Arc<dyn Data>> {
            unimplemented!()
        }
        fn get_defined_data_before(&self, _: &Address) -> Option<Arc<dyn Data>> {
            unimplemented!()
        }
        fn get_defined_data(&self, _: bool) -> Box<dyn DataIterator> {
            unimplemented!()
        }
        fn get_defined_data_from(&self, _: &Address, _: bool) -> Box<dyn DataIterator> {
            unimplemented!()
        }
        fn get_defined_data_in(
            &self,
            _: &dyn AddressSetView,
            _: bool,
        ) -> Box<dyn DataIterator> {
            unimplemented!()
        }
        fn get_undefined_data_at(&self, _: &Address) -> Option<Arc<dyn Data>> {
            unimplemented!()
        }
        fn get_undefined_data_after(
            &self,
            _: &Address,
            _: &dyn TaskMonitor,
        ) -> Option<Arc<dyn Data>> {
            unimplemented!()
        }
        fn get_first_undefined_data(
            &self,
            _: &dyn AddressSetView,
            _: &dyn TaskMonitor,
        ) -> Option<Arc<dyn Data>> {
            unimplemented!()
        }
        fn get_undefined_data_before(
            &self,
            _: &Address,
            _: &dyn TaskMonitor,
        ) -> Option<Arc<dyn Data>> {
            unimplemented!()
        }
        fn get_undefined_ranges(
            &self,
            _: &dyn AddressSetView,
            _: bool,
            _: &dyn TaskMonitor,
        ) -> Result<Box<dyn AddressSetView>, CancelledException> {
            unimplemented!()
        }
        fn get_defined_code_unit_after(&self, _: &Address) -> Option<Arc<dyn CodeUnit>> {
            unimplemented!()
        }
        fn get_defined_code_unit_before(&self, _: &Address) -> Option<Arc<dyn CodeUnit>> {
            unimplemented!()
        }
        fn get_user_defined_properties(&self) -> Vec<String> {
            unimplemented!()
        }
        fn remove_user_defined_property(&mut self, _: &str) {
            unimplemented!()
        }
        fn get_property_map(&self, _: &str) -> Option<Box<dyn PropertyMap>> {
            unimplemented!()
        }
        fn create_instruction(
            &mut self,
            _: Address,
            _: Arc<dyn InstructionPrototype>,
            _: &dyn MemBuffer,
            _: &dyn ProcessorContextView,
            _: i32,
        ) -> Result<Arc<dyn Instruction>, CodeUnitInsertionException> {
            unimplemented!()
        }
        fn add_instructions(
            &mut self,
            _: &dyn InstructionSet,
            _: bool,
        ) -> Result<Box<dyn AddressSetView>, CodeUnitInsertionException> {
            unimplemented!()
        }
        fn create_data_sized(
            &mut self,
            _: Address,
            _: Box<dyn DataType>,
            _: i32,
        ) -> Result<Arc<dyn Data>, CodeUnitInsertionException> {
            unimplemented!()
        }
        fn create_data(
            &mut self,
            _: Address,
            _: Box<dyn DataType>,
        ) -> Result<Arc<dyn Data>, CodeUnitInsertionException> {
            unimplemented!()
        }
        fn clear_code_units(&mut self, _: &Address, _: &Address, _: bool) {
            unimplemented!()
        }
        fn clear_code_units_with_monitor(
            &mut self,
            _: &Address,
            _: &Address,
            _: bool,
            _: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            unimplemented!()
        }
        fn is_undefined(&self, _: &Address, _: &Address) -> bool {
            unimplemented!()
        }
        fn clear_comments(&mut self, _: &Address, _: &Address) {
            unimplemented!()
        }
        fn clear_properties(
            &mut self,
            _: &Address,
            _: &Address,
            _: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            unimplemented!()
        }
        fn clear_all(&mut self, _: bool, _: &dyn TaskMonitor) {
            unimplemented!()
        }
        fn get_fragment(&self, _: &str, _: &Address) -> Option<Arc<dyn ProgramFragment>> {
            unimplemented!()
        }
        fn get_module(&self, _: &str, _: &str) -> Option<Arc<dyn ProgramModule>> {
            unimplemented!()
        }
        fn get_fragment_by_name(&self, _: &str, _: &str) -> Option<Arc<dyn ProgramFragment>> {
            unimplemented!()
        }
        fn create_root_module(
            &mut self,
            _: &str,
        ) -> Result<Arc<dyn ProgramModule>, DuplicateNameException> {
            unimplemented!()
        }
        fn get_root_module(&self, _: &str) -> Option<Arc<dyn ProgramModule>> {
            unimplemented!()
        }
        fn get_root_module_by_id(&self, _: i64) -> Option<Arc<dyn ProgramModule>> {
            unimplemented!()
        }
        fn get_default_root_module(&self) -> Arc<dyn ProgramModule> {
            unimplemented!()
        }
        fn get_tree_names(&self) -> Vec<String> {
            unimplemented!()
        }
        fn remove_tree(&mut self, _: &str) -> bool {
            unimplemented!()
        }
        fn rename_tree(
            &mut self,
            _: &str,
            _: &str,
        ) -> Result<(), DuplicateNameException> {
            unimplemented!()
        }
        fn get_num_code_units(&self) -> i64 {
            self.code_unit_count
        }
        fn get_num_defined_data(&self) -> i64 {
            unimplemented!()
        }
        fn get_num_instructions(&self) -> i64 {
            unimplemented!()
        }
        fn get_data_type_manager(&self) -> Box<dyn DataTypeManager> {
            unimplemented!()
        }
        fn create_function(
            &mut self,
            _: &str,
            _: Address,
            _: &dyn AddressSetView,
            _: SourceType,
        ) -> Result<Arc<dyn Function>, CreateFunctionError> {
            unimplemented!()
        }
        fn create_function_in_namespace(
            &mut self,
            _: &str,
            _: Arc<dyn Namespace>,
            _: Address,
            _: &dyn AddressSetView,
            _: SourceType,
        ) -> Result<Arc<dyn Function>, CreateFunctionError> {
            unimplemented!()
        }
        fn remove_function(&mut self, _: &Address) {
            unimplemented!()
        }
        fn get_function_at(&self, _: &Address) -> Option<Arc<dyn Function>> {
            unimplemented!()
        }
        fn get_global_functions(&self, _: &str) -> Vec<Arc<dyn Function>> {
            unimplemented!()
        }
        fn get_functions_by_name(&self, _: Option<&str>, _: &str) -> Vec<Arc<dyn Function>> {
            unimplemented!()
        }
        fn get_function_containing(&self, _: &Address) -> Option<Arc<dyn Function>> {
            unimplemented!()
        }
        fn get_external_functions(&self) -> Box<dyn FunctionIterator> {
            unimplemented!()
        }
        fn get_functions(&self, _: bool) -> Box<dyn FunctionIterator> {
            unimplemented!()
        }
        fn get_functions_from(&self, _: &Address, _: bool) -> Box<dyn FunctionIterator> {
            unimplemented!()
        }
        fn get_functions_in(&self, _: &dyn AddressSetView, _: bool) -> Box<dyn FunctionIterator> {
            unimplemented!()
        }
        fn is_in_function(&self, _: &Address) -> bool {
            unimplemented!()
        }
        fn get_comment_history(&self, _: &Address, _: CommentType) -> Vec<Box<dyn CommentHistory>> {
            unimplemented!()
        }
        fn get_comment_address_count(&self) -> i64 {
            unimplemented!()
        }
    }

    /// A base model (e.g. the M-Model) that reports a fresh instance of itself as its own base on
    /// every call, mirroring `SubroutineBlockModel`'s "if there is no base model, this subroutine
    /// model is returned" contract. Each call bumps a shared counter, and `get_listing` hands back
    /// a [`TaggedListing`] carrying its own `code_unit_count`, so the test below can prove that
    /// calling through a `Box<dyn PartitionCodeSubModel>` actually dispatches to this
    /// implementation's own state rather than just type-checking.
    struct MModel {
        base_calls: Rc<Cell<u32>>,
        code_unit_count: i64,
    }

    impl CodeBlockModel for MModel {
        fn get_name(&self) -> String {
            unimplemented!()
        }
        fn get_code_block_at(
            &self,
            _addr: &Address,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Option<Box<dyn crate::program::model::block::CodeBlock>>, CancelledException> {
            unimplemented!()
        }
        fn get_first_code_block_containing(
            &self,
            _addr: &Address,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Option<Box<dyn crate::program::model::block::CodeBlock>>, CancelledException> {
            unimplemented!()
        }
        fn get_code_blocks(
            &self,
            _monitor: &dyn TaskMonitor,
        ) -> Result<
            Box<dyn crate::program::model::block::code_block_iterator::CodeBlockIterator>,
            CancelledException,
        > {
            unimplemented!()
        }
        fn get_basic_block_model(&self) -> Box<dyn CodeBlockModel> {
            unimplemented!()
        }
        fn get_code_blocks_containing(
            &self,
            _block: &dyn crate::program::model::block::CodeBlock,
            _monitor: &dyn TaskMonitor,
        ) -> Result<
            Box<dyn crate::program::model::block::code_block_iterator::CodeBlockIterator>,
            CancelledException,
        > {
            unimplemented!()
        }
        fn get_sources(
            &self,
            _block: &dyn crate::program::model::block::CodeBlock,
            _monitor: &dyn TaskMonitor,
        ) -> Result<
            Box<dyn crate::program::model::block::code_block_reference_iterator::CodeBlockReferenceIterator>,
            CancelledException,
        > {
            unimplemented!()
        }
        fn get_num_sources(
            &self,
            _block: &dyn crate::program::model::block::CodeBlock,
            _monitor: &dyn TaskMonitor,
        ) -> Result<i32, CancelledException> {
            unimplemented!()
        }
        fn get_destinations(
            &self,
            _block: &dyn crate::program::model::block::CodeBlock,
            _monitor: &dyn TaskMonitor,
        ) -> Result<
            Box<dyn crate::program::model::block::code_block_reference_iterator::CodeBlockReferenceIterator>,
            CancelledException,
        > {
            unimplemented!()
        }
        fn get_num_destinations(
            &self,
            _block: &dyn crate::program::model::block::CodeBlock,
            _monitor: &dyn TaskMonitor,
        ) -> Result<i32, CancelledException> {
            unimplemented!()
        }
        fn get_flow_type(
            &self,
            _block: &dyn crate::program::model::block::CodeBlock,
        ) -> Box<dyn crate::program::seam_stubs::FlowType> {
            unimplemented!()
        }
        fn get_block_name(&self, _block: &dyn crate::program::model::block::CodeBlock) -> String {
            unimplemented!()
        }
        fn get_program(&self) -> Arc<dyn crate::program::model::listing::Program> {
            unimplemented!()
        }
    }

    impl SubroutineBlockModel for MModel {
        fn get_base_subroutine_model(&self) -> Box<dyn SubroutineBlockModel> {
            self.base_calls.set(self.base_calls.get() + 1);
            Box::new(MModel {
                base_calls: self.base_calls.clone(),
                code_unit_count: self.code_unit_count,
            })
        }
    }

    impl PartitionCodeSubModel for MModel {
        fn get_listing(&self) -> Arc<dyn Listing> {
            Arc::new(TaggedListing {
                code_unit_count: self.code_unit_count,
            })
        }
    }

    #[test]
    fn get_listing_returns_this_models_own_listing_through_trait_object() {
        let model: Box<dyn PartitionCodeSubModel> = Box::new(MModel {
            base_calls: Rc::new(Cell::new(0)),
            code_unit_count: 42,
        });

        let listing = model.get_listing();
        assert_eq!(listing.get_num_code_units(), 42);
    }

    #[test]
    fn base_subroutine_model_delegates_and_bumps_shared_counter() {
        let base_calls = Rc::new(Cell::new(0));
        let model: Box<dyn PartitionCodeSubModel> = Box::new(MModel {
            base_calls: base_calls.clone(),
            code_unit_count: 7,
        });

        let base = model.get_base_subroutine_model();
        assert_eq!(base_calls.get(), 1);

        // The base model is itself a distinct SubroutineBlockModel that can keep delegating.
        let _base_of_base = base.get_base_subroutine_model();
        assert_eq!(base_calls.get(), 2);
    }

    #[test]
    fn name_constant_matches_java_display_name() {
        assert_eq!(NAME, "Partitioned Code");
    }
}

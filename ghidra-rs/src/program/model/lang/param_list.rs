use std::sync::Arc;

use crate::program::model::address::{Address, AddressSpace};
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::lang::compiler_spec::CompilerSpec;
use crate::program::model::lang::language::Language;
use crate::program::model::listing::program::Program;
use crate::program::seam_stubs::{Encoder, ParameterPieces, PrototypePieces, VariableStorage};
use crate::util::xml::xml_parse_exception::XmlParseException;
use crate::util::xml::xml_pull_parser::XmlPullParser;

/// Object for passing back a possible parameter's slot and slot-size.
///
/// Port of `ghidra.program.model.lang.ParamList.WithSlotRec`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct WithSlotRec {
    pub slot: i32,
    pub slotsize: i32,
}

/// A group of `ParamEntry` that form a complete set for passing parameters (in one direction).
///
/// Port of `ghidra.program.model.lang.ParamList`.
pub trait ParamList {
    /// Given a list of datatypes, calculate the storage locations used for passing those
    /// data-types.
    ///
    /// # Parameters
    /// - `proto`: the list of datatypes
    /// - `dt_manage`: the data-type manager
    /// - `res`: the vector for holding the storage locations and other parameter properties
    /// - `add_auto_params`: if true add/process auto-parameters
    fn assign_map(
        &self,
        proto: &PrototypePieces,
        dt_manage: &dyn DataTypeManager,
        res: &mut Vec<ParameterPieces>,
        add_auto_params: bool,
    );

    /// Encode this param list's configuration to the stream.
    ///
    /// # Errors
    /// Returns an error for problems writing to the underlying stream.
    fn encode(&self, encoder: &mut dyn Encoder, is_input: bool) -> std::io::Result<()>;

    /// Restore this param list from an XML stream.
    ///
    /// Generic over the parser implementation (rather than a trait object) because
    /// [`XmlPullParser`] is not object-safe; this keeps [`ParamList`] itself dyn-compatible for
    /// every other method.
    ///
    /// # Errors
    /// Returns an error for badly formed XML.
    fn restore_xml<P: XmlPullParser>(
        &mut self,
        parser: &mut P,
        cspec: &dyn CompilerSpec,
    ) -> Result<(), XmlParseException>
    where
        Self: Sized;

    /// Get a list of all parameter storage locations consisting of a single register.
    fn get_potential_register_storage(&self, prog: &dyn Program) -> Vec<Box<dyn VariableStorage>>;

    /// Return the amount of alignment used for parameters passed on the stack, or -1 if there
    /// are no stack params.
    fn get_stack_parameter_alignment(&self) -> i32;

    /// Find the boundary offset that separates parameters on the stack from other local
    /// variables. This is usually the address of the first stack parameter, but if the stack
    /// grows positive, this is the first address after the parameters on the stack. Returns
    /// `None` if there are no stack parameters.
    fn get_stack_parameter_offset(&self) -> Option<i64>;

    /// Determine if a particular address range is a possible parameter, and if so what slot(s)
    /// it occupies.
    ///
    /// # Parameters
    /// - `loc`: the starting address of the range
    /// - `size`: the size of the range in bytes
    /// - `res`: holds the resulting slot and slot-size
    fn possible_param_with_slot(&self, loc: &Address, size: i32, res: &mut WithSlotRec) -> bool;

    /// Returns the associated `Language`.
    fn get_language(&self) -> Box<dyn Language>;

    /// Get the address space associated with any stack based parameters in this list. Returns
    /// the stack address space if this models parameters passed on the stack, `None` otherwise.
    fn get_spacebase(&self) -> Option<Arc<AddressSpace>>;

    /// Return true if the this pointer occurs before an indirect return pointer.
    ///
    /// The automatic parameters, this parameter and the hidden return value pointer, both tend
    /// to be allocated from the initial general purpose registers reserved for parameter
    /// passing. This method returns true if the this parameter is allocated first.
    fn is_this_before_ret_pointer(&self) -> bool;

    /// Determine if this `ParamList` is equivalent to another instance.
    fn is_equivalent(&self, other: &dyn ParamList) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    struct MockCompilerSpec;
    impl CompilerSpec for MockCompilerSpec {
        fn get_language(&self) -> Box<dyn Language> {
            unimplemented!()
        }
        fn get_compiler_spec_description(
            &self,
        ) -> Box<dyn crate::program::model::lang::compiler_spec_description::CompilerSpecDescription>
        {
            unimplemented!()
        }
        fn get_compiler_spec_id(&self) -> crate::program::seam_stubs::CompilerSpecID {
            unimplemented!()
        }
        fn get_stack_pointer(&self) -> Option<crate::program::model::lang::register::RegisterRef> {
            None
        }
        fn is_stack_right_justified(&self) -> bool {
            false
        }
        fn get_address_space(&self, _space_name: &str) -> Option<Arc<AddressSpace>> {
            None
        }
        fn get_stack_space(&self) -> Arc<AddressSpace> {
            unimplemented!()
        }
        fn get_stack_base_space(&self) -> Arc<AddressSpace> {
            unimplemented!()
        }
        fn stack_grows_negative(&self) -> bool {
            true
        }
        fn apply_context_settings(
            &self,
            _ctx: &mut dyn crate::program::model::listing::default_program_context::DefaultProgramContext,
        ) {
        }
        fn get_calling_conventions(
            &self,
        ) -> Vec<Box<dyn crate::program::seam_stubs::PrototypeModel>> {
            Vec::new()
        }
        fn get_calling_convention(
            &self,
            _name: &str,
        ) -> Option<Box<dyn crate::program::seam_stubs::PrototypeModel>> {
            None
        }
        fn get_all_models(&self) -> Vec<Box<dyn crate::program::seam_stubs::PrototypeModel>> {
            Vec::new()
        }
        fn get_default_calling_convention(
            &self,
        ) -> Option<Box<dyn crate::program::seam_stubs::PrototypeModel>> {
            None
        }
        fn get_decompiler_output_language(
            &self,
        ) -> crate::program::model::lang::decompiler_language::DecompilerLanguage {
            unimplemented!()
        }
    }

    struct MockEncoder;
    impl Encoder for MockEncoder {}

    struct MockParamList {
        stack_alignment: i32,
    }

    impl ParamList for MockParamList {
        fn assign_map(
            &self,
            _proto: &PrototypePieces,
            _dt_manage: &dyn DataTypeManager,
            res: &mut Vec<ParameterPieces>,
            _add_auto_params: bool,
        ) {
            res.push(ParameterPieces::default());
        }

        fn encode(&self, _encoder: &mut dyn Encoder, _is_input: bool) -> std::io::Result<()> {
            Ok(())
        }

        fn restore_xml<P: XmlPullParser>(
            &mut self,
            _parser: &mut P,
            _cspec: &dyn CompilerSpec,
        ) -> Result<(), XmlParseException>
        where
            Self: Sized,
        {
            Ok(())
        }

        fn get_potential_register_storage(
            &self,
            _prog: &dyn Program,
        ) -> Vec<Box<dyn VariableStorage>> {
            Vec::new()
        }

        fn get_stack_parameter_alignment(&self) -> i32 {
            self.stack_alignment
        }

        fn get_stack_parameter_offset(&self) -> Option<i64> {
            None
        }

        fn possible_param_with_slot(&self, _loc: &Address, size: i32, res: &mut WithSlotRec) -> bool {
            res.slot = 0;
            res.slotsize = size;
            true
        }

        fn get_language(&self) -> Box<dyn Language> {
            unimplemented!()
        }

        fn get_spacebase(&self) -> Option<Arc<AddressSpace>> {
            None
        }

        fn is_this_before_ret_pointer(&self) -> bool {
            false
        }

        fn is_equivalent(&self, other: &dyn ParamList) -> bool {
            self.get_stack_parameter_alignment() == other.get_stack_parameter_alignment()
        }
    }

    #[test]
    fn usable_as_trait_object() {
        let list: Box<dyn ParamList> = Box::new(MockParamList { stack_alignment: 4 });

        let mut res = Vec::new();
        list.assign_map(
            &PrototypePieces::default(),
            &MockDataTypeManager,
            &mut res,
            false,
        );
        assert_eq!(res.len(), 1);

        assert_eq!(list.get_stack_parameter_alignment(), 4);
        assert_eq!(list.get_stack_parameter_offset(), None);
        assert!(list.get_spacebase().is_none());
        assert!(!list.is_this_before_ret_pointer());

        let mut slot_rec = WithSlotRec::default();
        let space = AddressSpace::new(
            "ram",
            32,
            1,
            crate::program::model::address::AddressSpaceType::Ram,
            0,
        );
        let loc = Address::new(space, 0);
        assert!(list.possible_param_with_slot(&loc, 4, &mut slot_rec));
        assert_eq!(slot_rec.slotsize, 4);

        assert!(list.encode(&mut MockEncoder, true).is_ok());

        let other: Box<dyn ParamList> = Box::new(MockParamList { stack_alignment: 4 });
        assert!(list.is_equivalent(other.as_ref()));

        let _cspec = MockCompilerSpec;
    }
}

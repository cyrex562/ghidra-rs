//! Port of `ghidra.program.model.lang.PrototypeModel`.
//!
//! A function calling convention model: the formal specification of how a compiler passes
//! arguments between functions.
//!
//! `PrototypeModel` is referenced from
//! [`DataTypeManager`](crate::program::model::data::data_type_manager::DataTypeManager),
//! [`CompilerSpec`](crate::program::model::lang::compiler_spec::CompilerSpec), and
//! [`Function`](crate::program::model::listing::function::Function) (among others) long before
//! its concrete decompiler-side collaborators -- `ParamList`'s resource-list allocation
//! algorithm, `PcodeInjectLibrary`, and XML restore -- are ported, so it was selected as a
//! dependency-cycle cut-point and its public API is modeled as a trait rather than a concrete
//! struct. Every accessor defaults to the value the Java no-arg constructor produces
//! (`UNKNOWN_EXTRAPOP`, `-1`, empty lists, `false`), so a bare `impl PrototypeModel for Foo {}`
//! behaves like an as-yet-unconfigured model, matching pre-existing placeholder usage across the
//! crate.

use std::sync::Arc;

use crate::program::model::address::Address;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::lang::input_list_type::InputListType;
use crate::program::model::lang::param_list::WithSlotRec;
use crate::program::model::listing::program::Program;
use crate::program::model::pcode::{Encoder, Varnode};
use crate::program::seam_stubs::{ParameterPieces, PcodeInjectLibrary, PrototypePieces};
    use crate::program::model::listing::variable_storage::VariableStorage;

/// Special [`PrototypeModel::get_extrapop`] value indicating the number of extra bytes popped
/// from the stack on return is unknown.
///
/// Port of `PrototypeModel.UNKNOWN_EXTRAPOP`.
pub const UNKNOWN_EXTRAPOP: i32 = 0x8000;

/// A function calling convention model.
///
/// Port of `ghidra.program.model.lang.PrototypeModel`.
pub trait PrototypeModel {
    /// The formal name of the model, or `None` for an unnamed/default-constructed model.
    ///
    /// Port of `PrototypeModel.getName()`.
    fn get_name(&self) -> Option<String> {
        None
    }

    /// List of registers unaffected by called functions.
    ///
    /// Port of `PrototypeModel.getUnaffectedList()`.
    fn get_unaffected_list(&self) -> Vec<Varnode> {
        Vec::new()
    }

    /// List of registers definitely affected by called functions.
    ///
    /// Port of `PrototypeModel.getKilledByCallList()`.
    fn get_killed_by_call_list(&self) -> Vec<Varnode> {
        Vec::new()
    }

    /// List of registers whose input value is likely meaningless.
    ///
    /// Port of `PrototypeModel.getLikelyTrash()`.
    fn get_likely_trash(&self) -> Vec<Varnode> {
        Vec::new()
    }

    /// List of registers used to store internal compiler constants.
    ///
    /// Port of `PrototypeModel.getInternalStorage()`.
    fn get_internal_storage(&self) -> Vec<Varnode> {
        Vec::new()
    }

    /// List of registers/memory used to store the return address, or `None` if not recorded.
    ///
    /// Port of `PrototypeModel.getReturnAddress()`.
    fn get_return_address(&self) -> Option<Vec<Varnode>> {
        None
    }

    /// True if this model is an artificial merge of other models. A merged model can be used as
    /// part of the analysis process when attempting to distinguish between different possible
    /// models for an unknown function.
    ///
    /// Port of `PrototypeModel.isMerged()`.
    fn is_merged(&self) -> bool {
        false
    }

    /// True if this model is a Program specific extension to the `CompilerSpec`.
    ///
    /// Port of `PrototypeModel.isProgramExtension()`.
    fn is_program_extension(&self) -> bool {
        false
    }

    /// The number of extra bytes popped from the stack when a function that uses this model
    /// returns to its caller, or [`UNKNOWN_EXTRAPOP`] if unknown.
    ///
    /// Port of `PrototypeModel.getExtrapop()`.
    fn get_extrapop(&self) -> i32 {
        UNKNOWN_EXTRAPOP
    }

    /// The number of bytes on the stack used, by this model, to store the return value.
    ///
    /// Port of `PrototypeModel.getStackshift()`.
    fn get_stackshift(&self) -> i32 {
        -1
    }

    /// True if this model has an implied "this" parameter for referencing class data.
    ///
    /// Port of `PrototypeModel.hasThisPointer()`.
    fn has_this_pointer(&self) -> bool {
        false
    }

    /// True if this model is used specifically for class constructors.
    ///
    /// Port of `PrototypeModel.isConstructor()`.
    fn is_constructor(&self) -> bool {
        false
    }

    /// The allocation strategy for this model.
    ///
    /// Port of `PrototypeModel.getInputListType()`.
    fn get_input_list_type(&self) -> InputListType {
        InputListType::Standard
    }

    /// True if this model has specific p-code injections associated with it (either an
    /// "uponentry" or "uponreturn" payload), which are used to decompile functions with this
    /// model.
    ///
    /// Port of `PrototypeModel.hasInjection()`.
    fn has_injection(&self) -> bool {
        false
    }

    /// Calculate input and output storage locations given a function prototype.
    ///
    /// The data-types of the function prototype are passed in via `proto`. Based on this model,
    /// a location is selected for each (input and output) parameter and passed back via `res`,
    /// ordered with the output storage as the first entry, followed by the input storage
    /// locations. The model has the option of inserting a hidden return value pointer in the
    /// input storage locations.
    ///
    /// Port of
    /// `PrototypeModel.assignParameterStorage(PrototypePieces, DataTypeManager, ArrayList, boolean)`.
    fn assign_parameter_storage(
        &self,
        proto: &PrototypePieces,
        dt_manager: &dyn DataTypeManager,
        res: &mut Vec<ParameterPieces>,
        add_auto_params: bool,
    ) {
        let _ = (proto, dt_manager, res, add_auto_params);
    }

    /// Compute the variable storage for a given array of return/parameter datatypes.
    ///
    /// The first element of `data_types` is always the return datatype, followed by any input
    /// parameter datatypes in order. If `add_auto_params` is true, pointer datatypes will
    /// automatically be inserted for "this" or "hidden return" input parameters, if needed. The
    /// returned locations are ordered by ordinal, with the first element corresponding to return
    /// storage.
    ///
    /// Port of
    /// `PrototypeModel.getStorageLocations(Program, DataType[], boolean, boolean)`.
    fn get_storage_locations(
        &self,
        program: &dyn Program,
        data_types: &[Arc<dyn DataType>],
        add_auto_params: bool,
        is_var_args: bool,
    ) -> Vec<Box<dyn VariableStorage>> {
        let _ = (program, data_types, add_auto_params, is_var_args);
        Vec::new()
    }

    /// If this is an alias of another model, return that model. Otherwise `None`.
    ///
    /// Port of `PrototypeModel.getAliasParent()`.
    fn get_alias_parent(&self) -> Option<Arc<dyn PrototypeModel>> {
        None
    }

    /// If a `PrototypeModel` fails to parse (from XML) a substitute model may be provided, in
    /// which case this method returns true. In all other cases this method returns false.
    ///
    /// Port of `PrototypeModel.isErrorPlaceholder()`.
    fn is_error_placeholder(&self) -> bool {
        false
    }

    /// Encode this object to an output stream.
    ///
    /// # Errors
    /// Returns an error for problems writing to the underlying stream.
    ///
    /// Port of `PrototypeModel.encode(Encoder, PcodeInjectLibrary)`.
    fn encode(
        &self,
        encoder: &mut dyn Encoder,
        inject_library: &dyn PcodeInjectLibrary,
    ) -> std::io::Result<()> {
        let _ = (encoder, inject_library);
        Ok(())
    }

    /// Determine if the given address range is possible input parameter storage for this model.
    /// If it is, `true` is returned, and additional information about the parameter's position
    /// is passed back in `res`.
    ///
    /// Port of `PrototypeModel.possibleInputParamWithSlot(Address, int, ParamList.WithSlotRec)`.
    fn possible_input_param_with_slot(
        &self,
        loc: &Address,
        size: i32,
        res: &mut WithSlotRec,
    ) -> bool {
        let _ = (loc, size, res);
        false
    }

    /// Determine if the given address range is possible return value storage for this model. If
    /// it is, `true` is returned, and additional information about the storage position is
    /// passed back in `res`.
    ///
    /// Port of `PrototypeModel.possibleOutputParamWithSlot(Address, int, ParamList.WithSlotRec)`.
    fn possible_output_param_with_slot(
        &self,
        loc: &Address,
        size: i32,
        res: &mut WithSlotRec,
    ) -> bool {
        let _ = (loc, size, res);
        false
    }

    /// Assuming the model allows open ended storage of parameters on the stack, the byte
    /// alignment required for individual stack parameters, or -1 if there are none.
    ///
    /// Port of `PrototypeModel.getStackParameterAlignment()`.
    fn get_stack_parameter_alignment(&self) -> i32 {
        -1
    }

    /// The byte offset where the first input parameter on the stack is allocated, relative to
    /// the incoming stack pointer of the called function, or `None` if there are no stack
    /// parameters.
    ///
    /// Port of `PrototypeModel.getStackParameterOffset()`.
    fn get_stack_parameter_offset(&self) -> Option<i64> {
        None
    }

    /// A list of all input storage locations consisting of a single register.
    ///
    /// Port of `PrototypeModel.getPotentialInputRegisterStorage(Program)`.
    fn get_potential_input_register_storage(&self, prog: &dyn Program) -> Vec<Box<dyn VariableStorage>> {
        let _ = prog;
        Vec::new()
    }

    /// Determine if this `PrototypeModel` is equivalent to another instance.
    ///
    /// Port of `PrototypeModel.isEquivalent(PrototypeModel)`.
    fn is_equivalent(&self, other: &dyn PrototypeModel) -> bool {
        let _ = other;
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    fn mock_address(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    /// A minimal `__stdcall`-like model: fixed extrapop, no `this` pointer, a couple of
    /// unaffected registers.
    struct StdCallModel {
        name: String,
        extrapop: i32,
        unaffected: Vec<Varnode>,
    }

    impl PrototypeModel for StdCallModel {
        fn get_name(&self) -> Option<String> {
            Some(self.name.clone())
        }

        fn get_extrapop(&self) -> i32 {
            self.extrapop
        }

        fn get_unaffected_list(&self) -> Vec<Varnode> {
            self.unaffected.clone()
        }

        fn is_equivalent(&self, other: &dyn PrototypeModel) -> bool {
            self.get_name() == other.get_name() && self.get_extrapop() == other.get_extrapop()
        }
    }

    /// A `__thiscall`-like alias, mirroring the Java alias constructor's `hasThis` override.
    struct ThisCallModel;

    impl PrototypeModel for ThisCallModel {
        fn get_name(&self) -> Option<String> {
            Some("__thiscall".to_string())
        }

        fn has_this_pointer(&self) -> bool {
            true
        }
    }

    #[test]
    fn overridden_accessors_report_configured_values() {
        let model = StdCallModel {
            name: "__stdcall".to_string(),
            extrapop: 4,
            unaffected: vec![Varnode::new(mock_address(0x1000), 4)],
        };

        assert_eq!(model.get_name(), Some("__stdcall".to_string()));
        assert_eq!(model.get_extrapop(), 4);
        assert_eq!(model.get_unaffected_list().len(), 1);
        assert_eq!(model.get_unaffected_list()[0].get_address(), &mock_address(0x1000));
    }

    #[test]
    fn unconfigured_default_constructed_model_matches_java_defaults() {
        struct EmptyModel;
        impl PrototypeModel for EmptyModel {}

        let model = EmptyModel;
        assert_eq!(model.get_name(), None);
        assert_eq!(model.get_extrapop(), UNKNOWN_EXTRAPOP);
        assert_eq!(model.get_stackshift(), -1);
        assert!(model.get_unaffected_list().is_empty());
        assert!(!model.has_this_pointer());
        assert!(!model.is_constructor());
        assert!(!model.has_injection());
        assert_eq!(model.get_stack_parameter_alignment(), -1);
        assert_eq!(model.get_stack_parameter_offset(), None);
        assert!(model.get_alias_parent().is_none());
    }

    #[test]
    fn is_equivalent_distinguishes_by_name_and_extrapop() {
        let stdcall_a = StdCallModel {
            name: "__stdcall".to_string(),
            extrapop: 4,
            unaffected: Vec::new(),
        };
        let stdcall_b = StdCallModel {
            name: "__stdcall".to_string(),
            extrapop: 4,
            unaffected: Vec::new(),
        };
        let cdecl = StdCallModel {
            name: "__cdecl".to_string(),
            extrapop: 4,
            unaffected: Vec::new(),
        };

        assert!(stdcall_a.is_equivalent(&stdcall_b));
        assert!(!stdcall_a.is_equivalent(&cdecl));
    }

    #[test]
    fn usable_as_trait_object() {
        let models: Vec<Box<dyn PrototypeModel>> =
            vec![Box::new(ThisCallModel), Box::new(StdCallModel {
                name: "__stdcall".to_string(),
                extrapop: 4,
                unaffected: Vec::new(),
            })];

        assert!(models[0].has_this_pointer());
        assert!(!models[1].has_this_pointer());
        assert_eq!(models[0].get_name(), Some("__thiscall".to_string()));
    }
}

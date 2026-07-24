//! Port of `ghidra.program.model.pcode.HighParamID`.
//!
//! High-level abstraction associated with a low-level function made up of assembly instructions,
//! based on information the decompiler has produced after working on a function (parameter/return
//! storage measurements).
//!
//! The Java class `extends PcodeSyntaxTree`, whose real port does not exist yet, so it was
//! selected as a dependency-cycle cut-point and promoted to a trait rather than a concrete
//! struct. `PcodeSyntaxTree` itself is not modeled here (not even as a placeholder): none of
//! `HighParamID`'s own methods call any inherited `PcodeSyntaxTree` member directly except via
//! `this` being passed where a `PcodeFactory` is expected (see below) and via the private
//! `buildStorage(Varnode)` helper used by [`HighParamID::store_return_to_database`] and
//! [`HighParamID::store_parameters_to_database`] -- both left as required methods for the reasons
//! documented on them.
//!
//! [`ParamMeasure`](crate::program::seam_stubs::ParamMeasure) is a new minimal placeholder in
//! `seam_stubs.rs`, exposing only `isEmpty`/`getVarnode`/`getDataType`/`getRank` -- the members
//! `HighParamID` itself calls; see `STUBS.tsv`.
//!
//! Not ported here:
//! - The constructor (`HighParamID(Function, Language, CompilerSpec, PcodeDataTypeManager)`), a
//!   construction-time detail for a concrete implementation, not part of the dynamic-dispatch
//!   surface this trait exists to cut the cycle for (the same convention already followed by
//!   [`FunctionPrototype`](crate::program::model::pcode::function_prototype::FunctionPrototype)).
//! - The public static `getErrorHandler(Object, String)` factory, which builds an
//!   `org.xml.sax.ErrorHandler` around `Msg` logging. It has no receiver to dispatch on (it is not
//!   an instance method of `HighParamID`) and its SAX-based error-handling machinery is unrelated
//!   to the core p-code/decompiler data this trait exists to expose, so it is left out rather than
//!   pulling in an unrelated SAX-adapter placeholder.
//! - The private `decodeParamMeasure(Decoder, List<ParamMeasure>)` helper and `paramStorageMatches`
//!   helper, neither of which is part of the public API.
//!
//! [`HighParamID::decode`], [`HighParamID::store_return_to_database`], and
//! [`HighParamID::store_parameters_to_database`] are declared with the real Java signatures but
//! left as required methods with no default body: their Java bodies call the not-yet-ported
//! `AddressXML` utility, `ParamMeasure.decode(Decoder, PcodeFactory)` (which itself needs a
//! `PcodeDataTypeManager.decodeDataType` and the not-yet-ported `ELEM_PARAMMEASURES`/`ELEM_PROTO`/
//! `ATTRIB_MODEL`/`ATTRIB_EXTRAPOP` ids and a `Decoder.readSignedIntegerExpectString` this crate's
//! [`Decoder`] trait does not have yet), and `PcodeSyntaxTree.buildStorage`, which reads a private
//! `joinToStorage` map with no public getter. A concrete implementor has direct access to its own
//! fields and collaborators and can implement these precisely once ported; synthesizing a generic
//! default here would require guessing at unported behavior (the same convention already followed
//! by [`FunctionPrototype::decode_prototype`]).

use std::sync::Arc;

use crate::program::model::address::Address;
use crate::program::model::listing::Function;
use crate::program::model::pcode::decoder::Decoder;
use crate::program::model::pcode::decoder_exception::DecoderException;
use crate::program::model::lang::prototype_model::UNKNOWN_EXTRAPOP;
use crate::program::model::symbol::SourceType;
use crate::program::seam_stubs::ParamMeasure;

/// Port of `HighParamID.DECOMPILER_TAG_MAP`.
pub const DECOMPILER_TAG_MAP: &str = "decompiler_tags";

/// High-level abstraction associated with a low-level function made up of assembly instructions,
/// based on information the decompiler has produced after working on a function.
///
/// Port of `ghidra.program.model.pcode.HighParamID`. See the module docs for what was
/// intentionally left out of this trait.
pub trait HighParamID {
    /// The name of the function, or `None` before [`HighParamID::decode`] has populated it.
    ///
    /// Port of `HighParamID.getFunctionName()`.
    fn get_function_name(&self) -> Option<String> {
        None
    }

    /// The address of the function, or `None` before [`HighParamID::decode`] has populated it.
    ///
    /// Port of `HighParamID.getFunctionAddress()`.
    fn get_function_address(&self) -> Option<Address> {
        None
    }

    /// The name of the prototype model, or `None` before [`HighParamID::decode`] has populated
    /// it.
    ///
    /// Port of `HighParamID.getModelName()`.
    fn get_model_name(&self) -> Option<String> {
        None
    }

    /// The prototype's extra-pop, or [`UNKNOWN_EXTRAPOP`] before [`HighParamID::decode`] has
    /// populated it (mirroring the value the Java constructor assigns up front).
    ///
    /// Port of `HighParamID.getProtoExtraPop()`.
    fn get_proto_extra_pop(&self) -> i32 {
        UNKNOWN_EXTRAPOP
    }

    /// The associated low-level function. Always set (the Java constructor requires a non-null
    /// `Function`), so unlike the other accessors this has no meaningful default.
    ///
    /// Port of `HighParamID.getFunction()`.
    fn get_function(&self) -> Arc<dyn Function>;

    /// The number of inputs for function params.
    ///
    /// Port of `HighParamID.getNumInputs()`.
    fn get_num_inputs(&self) -> i32 {
        0
    }

    /// The specific input at index `i`, or `None` if out of range (the Java signature throws
    /// `IndexOutOfBoundsException` instead; returning `Option` is the safer Rust idiom, matching
    /// [`FunctionPrototype::get_param`](crate::program::model::pcode::function_prototype::FunctionPrototype::get_param)).
    ///
    /// Port of `HighParamID.getInput(int)`.
    fn get_input(&self, i: i32) -> Option<Box<dyn ParamMeasure>> {
        let _ = i;
        None
    }

    /// The number of outputs for function params.
    ///
    /// Port of `HighParamID.getNumOutputs()`.
    fn get_num_outputs(&self) -> i32 {
        0
    }

    /// The specific output at index `i`, or `None` if out of range (see [`HighParamID::get_input`]
    /// for why this differs from the Java signature).
    ///
    /// Port of `HighParamID.getOutput(int)`.
    fn get_output(&self, i: i32) -> Option<Box<dyn ParamMeasure>> {
        let _ = i;
        None
    }

    /// Decode this `HighParamID` from a stream. See the module docs for why this has no default
    /// body.
    ///
    /// Port of `HighParamID.decode(Decoder)`.
    ///
    /// # Errors
    /// Returns an error for invalid encodings, or a function name/address/entry-point mismatch.
    fn decode(&mut self, decoder: &dyn Decoder) -> Result<(), DecoderException>;

    /// Update the return parameter for this function from the parameters defined in this map.
    /// See the module docs for why this has no default body.
    ///
    /// `store_data_types` is true if data-types are getting stored. `srctype` is the function
    /// signature source (unused in the Java body, which hardcodes `SourceType.ANALYSIS` for the
    /// actual `Function.setReturn` call -- kept here only for signature fidelity).
    ///
    /// Port of `HighParamID.storeReturnToDatabase(boolean, SourceType)`.
    fn store_return_to_database(&mut self, store_data_types: bool, srctype: SourceType);

    /// Update the parameters for this function from the parameters defined in this map. See the
    /// module docs for why this has no default body.
    ///
    /// `store_data_types` is true if data-types are being stored. `srctype` is the function
    /// signature source.
    ///
    /// Port of `HighParamID.storeParametersToDatabase(boolean, SourceType)`.
    fn store_parameters_to_database(&mut self, store_data_types: bool, srctype: SourceType);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSetView, AddressSpace, AddressSpaceType};
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::lang::prototype_model::PrototypeModel;
    use crate::program::model::listing::function::{FunctionEditError, SetFunctionNameError};
    use crate::program::model::listing::{FunctionSignature, FunctionTag, Parameter, Variable};
    use crate::program::model::symbol::{ExternalLocation, Namespace, Symbol, SymbolType};
    use crate::program::model::pcode::Varnode;
    use crate::program::seam_stubs::{StackFrame, VariableFilter, VariableStorage};
    use crate::program::database::function::OverlappingFunctionException;
    use crate::program::model::listing::Program;
    use crate::util::exception::InvalidInputException;
    use crate::util::task::TaskMonitor;

    fn ram_address(offset: i64) -> Address {
        let space = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 0);
        Address::new(space, offset)
    }

    struct MockSymbol;

    impl Symbol for MockSymbol {
        fn get_address(&self) -> Address {
            ram_address(0x1000)
        }
        fn get_name(&self) -> &str {
            "test_function"
        }
        fn get_symbol_type(&self) -> SymbolType {
            SymbolType::Function
        }
        fn get_source(&self) -> SourceType {
            SourceType::UserDefined
        }
        fn is_primary(&self) -> bool {
            true
        }
        fn get_id(&self) -> i64 {
            1
        }
        fn get_parent_id(&self) -> i64 {
            0
        }
    }

    /// Minimal [`Function`] mock -- only `get_name`/`get_entry_point` are given real bodies since
    /// those are the only members the smoke test below actually reads through
    /// [`HighParamID::get_function`].
    struct MockFunction;

    impl Namespace for MockFunction {
        fn get_symbol(&self) -> Arc<dyn Symbol> {
            Arc::new(MockSymbol)
        }
        fn get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
            None
        }
    }

    impl Function for MockFunction {
        fn get_name(&self) -> String {
            "test_function".to_string()
        }
        fn set_name(&mut self, _name: &str, _source: SourceType) -> Result<(), SetFunctionNameError> {
            unimplemented!()
        }
        fn set_call_fixup(&mut self, _name: Option<&str>) {}
        fn get_call_fixup(&self) -> Option<String> {
            None
        }
        fn get_program(&self) -> Arc<dyn Program> {
            unimplemented!()
        }
        fn get_comment(&self) -> Option<String> {
            None
        }
        fn get_comment_as_array(&self) -> Vec<String> {
            Vec::new()
        }
        fn set_comment(&mut self, _comment: Option<&str>) {}
        fn get_repeatable_comment(&self) -> Option<String> {
            None
        }
        fn get_repeatable_comment_as_array(&self) -> Vec<String> {
            Vec::new()
        }
        fn set_repeatable_comment(&mut self, _comment: Option<&str>) {}
        fn get_entry_point(&self) -> Address {
            ram_address(0x1000)
        }
        fn get_return_type(&self) -> Option<Box<dyn DataType>> {
            None
        }
        fn set_return_type(
            &mut self,
            _data_type: Box<dyn DataType>,
            _source: SourceType,
        ) -> Result<(), InvalidInputException> {
            unimplemented!()
        }
        fn get_return(&self) -> Box<dyn Parameter> {
            unimplemented!()
        }
        fn set_return(
            &mut self,
            _data_type: Box<dyn DataType>,
            _storage: Box<dyn VariableStorage>,
            _source: SourceType,
        ) -> Result<(), InvalidInputException> {
            unimplemented!()
        }
        fn get_signature_formal(&self, _formal_signature: bool) -> Box<dyn FunctionSignature> {
            unimplemented!()
        }
        fn get_prototype_string(&self, _formal_signature: bool, _include_calling_convention: bool) -> String {
            unimplemented!()
        }
        fn get_signature_source(&self) -> SourceType {
            SourceType::Default
        }
        fn set_signature_source(&mut self, _signature_source: SourceType) {}
        fn get_stack_frame(&self) -> Box<dyn StackFrame> {
            unimplemented!()
        }
        fn get_stack_purge_size(&self) -> i32 {
            0
        }
        fn get_tags(&self) -> Vec<Box<dyn FunctionTag>> {
            Vec::new()
        }
        fn add_tag(&mut self, _name: &str) -> bool {
            false
        }
        fn remove_tag(&mut self, _name: &str) {}
        fn set_stack_purge_size(&mut self, _purge_size: i32) {}
        fn is_stack_purge_size_valid(&self) -> bool {
            true
        }
        #[allow(deprecated)]
        fn add_parameter(
            &mut self,
            _var: Box<dyn Variable>,
            _source: SourceType,
        ) -> Result<Box<dyn Parameter>, FunctionEditError> {
            unimplemented!()
        }
        #[allow(deprecated)]
        fn insert_parameter(
            &mut self,
            _ordinal: i32,
            _var: Box<dyn Variable>,
            _source: SourceType,
        ) -> Result<Box<dyn Parameter>, FunctionEditError> {
            unimplemented!()
        }
        fn replace_parameters(
            &mut self,
            _params: Vec<Box<dyn Variable>>,
            _update_type: crate::program::model::listing::FunctionUpdateType,
            _force: bool,
            _source: SourceType,
        ) -> Result<(), FunctionEditError> {
            unimplemented!()
        }
        fn update_function(
            &mut self,
            _calling_convention: Option<&str>,
            _return_value: Option<Box<dyn Variable>>,
            _new_params: Vec<Box<dyn Variable>>,
            _update_type: crate::program::model::listing::FunctionUpdateType,
            _force: bool,
            _source: SourceType,
        ) -> Result<(), FunctionEditError> {
            unimplemented!()
        }
        fn get_parameter(&self, _ordinal: i32) -> Option<Box<dyn Parameter>> {
            None
        }
        #[allow(deprecated)]
        fn remove_parameter(&mut self, _ordinal: i32) {}
        #[allow(deprecated)]
        fn move_parameter(
            &mut self,
            _from_ordinal: i32,
            _to_ordinal: i32,
        ) -> Result<Box<dyn Parameter>, InvalidInputException> {
            unimplemented!()
        }
        fn get_parameter_count(&self) -> i32 {
            0
        }
        fn get_auto_parameter_count(&self) -> i32 {
            0
        }
        fn get_parameters(&self) -> Vec<Box<dyn Parameter>> {
            Vec::new()
        }
        fn get_parameters_filtered(&self, _filter: Option<&dyn VariableFilter>) -> Vec<Box<dyn Parameter>> {
            Vec::new()
        }
        fn get_local_variables(&self) -> Vec<Box<dyn Variable>> {
            Vec::new()
        }
        fn get_local_variables_filtered(&self, _filter: Option<&dyn VariableFilter>) -> Vec<Box<dyn Variable>> {
            Vec::new()
        }
        fn get_variables_filtered(&self, _filter: Option<&dyn VariableFilter>) -> Vec<Box<dyn Variable>> {
            Vec::new()
        }
        fn get_all_variables(&self) -> Vec<Box<dyn Variable>> {
            Vec::new()
        }
        fn add_local_variable(
            &mut self,
            _var: Box<dyn Variable>,
            _source: SourceType,
        ) -> Result<Box<dyn Variable>, FunctionEditError> {
            unimplemented!()
        }
        fn remove_variable(&mut self, _var: &dyn Variable) {}
        fn set_body(&mut self, _new_body: &dyn AddressSetView) -> Result<(), OverlappingFunctionException> {
            Ok(())
        }
        fn has_var_args(&self) -> bool {
            false
        }
        fn set_var_args(&mut self, _has_var_args: bool) {}
        fn is_inline(&self) -> bool {
            false
        }
        fn set_inline(&mut self, _is_inline: bool) {}
        fn has_no_return(&self) -> bool {
            false
        }
        fn set_no_return(&mut self, _has_no_return: bool) {}
        fn has_custom_variable_storage(&self) -> bool {
            false
        }
        fn set_custom_variable_storage(&mut self, _has_custom_variable_storage: bool) {}
        fn get_calling_convention(&self) -> Option<Box<dyn PrototypeModel>> {
            None
        }
        fn get_calling_convention_name(&self) -> String {
            "unknown".to_string()
        }
        fn set_calling_convention(&mut self, _name: &str) -> Result<(), InvalidInputException> {
            Ok(())
        }
        fn is_thunk(&self) -> bool {
            false
        }
        fn get_thunked_function(&self, _recursive: bool) -> Option<Arc<dyn Function>> {
            None
        }
        fn get_function_thunk_addresses(&self, _recursive: bool) -> Option<Vec<Address>> {
            None
        }
        fn set_thunked_function(&mut self, _thunked_function: Option<Arc<dyn Function>>) -> Result<(), String> {
            Ok(())
        }
        fn is_external(&self) -> bool {
            false
        }
        fn get_external_location(&self) -> Option<Box<dyn ExternalLocation>> {
            None
        }
        fn get_calling_functions(&self, _monitor: &dyn TaskMonitor) -> Vec<Arc<dyn Function>> {
            Vec::new()
        }
        fn get_called_functions(&self, _monitor: &dyn TaskMonitor) -> Vec<Arc<dyn Function>> {
            Vec::new()
        }
        fn promote_local_user_labels_to_global(&mut self) {}
        fn is_deleted(&self) -> bool {
            false
        }
    }

    /// A [`Decoder`] that is never actually read from: [`MockHighParamId::decode`] just flips a
    /// flag, so every method here is unreachable.
    struct UnreachableDecoder;

    impl Decoder for UnreachableDecoder {
        fn get_address_factory(&self) -> Arc<dyn crate::program::model::address::AddressFactory> {
            unimplemented!()
        }
        fn set_address_factory(&self, _factory: Arc<dyn crate::program::model::address::AddressFactory>) {
            unimplemented!()
        }
        fn peek_element(&self) -> Result<i32, crate::program::model::pcode::decoder::DecoderError> {
            unimplemented!()
        }
        fn open_element(&self) -> Result<i32, crate::program::model::pcode::decoder::DecoderError> {
            unimplemented!()
        }
        fn open_element_with_id(
            &self,
            _elem_id: crate::program::model::pcode::ElementId,
        ) -> Result<i32, crate::program::model::pcode::decoder::DecoderError> {
            unimplemented!()
        }
        fn close_element(&self, _id: i32) -> Result<(), crate::program::model::pcode::decoder::DecoderError> {
            unimplemented!()
        }
        fn close_element_skipping(
            &self,
            _id: i32,
        ) -> Result<(), crate::program::model::pcode::decoder::DecoderError> {
            unimplemented!()
        }
        fn get_next_attribute_id(&self) -> Result<i32, crate::program::model::pcode::decoder::DecoderError> {
            unimplemented!()
        }
        fn rewind_attributes(&self) {
            unimplemented!()
        }
        fn read_bool(&self) -> Result<bool, crate::program::model::pcode::decoder::DecoderError> {
            unimplemented!()
        }
        fn read_bool_with_id(
            &self,
            _attrib_id: crate::program::model::pcode::AttributeId,
        ) -> Result<bool, crate::program::model::pcode::decoder::DecoderError> {
            unimplemented!()
        }
        fn read_signed_integer(&self) -> Result<i64, crate::program::model::pcode::decoder::DecoderError> {
            unimplemented!()
        }
        fn read_signed_integer_with_id(
            &self,
            _attrib_id: crate::program::model::pcode::AttributeId,
        ) -> Result<i64, crate::program::model::pcode::decoder::DecoderError> {
            unimplemented!()
        }
        fn read_unsigned_integer(&self) -> Result<u64, crate::program::model::pcode::decoder::DecoderError> {
            unimplemented!()
        }
        fn read_unsigned_integer_with_id(
            &self,
            _attrib_id: crate::program::model::pcode::AttributeId,
        ) -> Result<u64, crate::program::model::pcode::decoder::DecoderError> {
            unimplemented!()
        }
        fn read_string(&self) -> Result<String, crate::program::model::pcode::decoder::DecoderError> {
            unimplemented!()
        }
        fn read_string_with_id(
            &self,
            _attrib_id: crate::program::model::pcode::AttributeId,
        ) -> Result<String, crate::program::model::pcode::decoder::DecoderError> {
            unimplemented!()
        }
        fn read_space(
            &self,
        ) -> Result<Arc<crate::program::model::address::AddressSpace>, crate::program::model::pcode::decoder::DecoderError>
        {
            unimplemented!()
        }
        fn read_space_with_id(
            &self,
            _attrib_id: crate::program::model::pcode::AttributeId,
        ) -> Result<Arc<crate::program::model::address::AddressSpace>, crate::program::model::pcode::decoder::DecoderError>
        {
            unimplemented!()
        }
    }

    struct MockParamMeasure {
        vn: Varnode,
        rank: i32,
    }

    impl ParamMeasure for MockParamMeasure {
        fn is_empty(&self) -> bool {
            false
        }
        fn get_varnode(&self) -> Option<Varnode> {
            Some(self.vn.clone())
        }
        fn get_data_type(&self) -> Option<Box<dyn DataType>> {
            None
        }
        fn get_rank(&self) -> Option<i32> {
            Some(self.rank)
        }
    }

    /// [`HighParamID`] implementation backing the smoke test: real `Vec` storage for
    /// inputs/outputs (proving [`HighParamID::get_num_inputs`]/[`HighParamID::get_input`] and
    /// their output counterparts are not just trivially-true defaults once overridden), plus a
    /// `decode` override so we can verify the trait is usable behind `Box<dyn HighParamID>`.
    struct MockHighParamId {
        function: Arc<MockFunction>,
        model_name: Option<String>,
        inputs: Vec<Varnode>,
        outputs: Vec<Varnode>,
        decoded: bool,
    }

    impl HighParamID for MockHighParamId {
        fn get_function_name(&self) -> Option<String> {
            Some(Function::get_name(self.function.as_ref()))
        }

        fn get_function_address(&self) -> Option<Address> {
            Some(self.function.get_entry_point())
        }

        fn get_model_name(&self) -> Option<String> {
            self.model_name.clone()
        }

        fn get_function(&self) -> Arc<dyn Function> {
            self.function.clone()
        }

        fn get_num_inputs(&self) -> i32 {
            self.inputs.len() as i32
        }

        fn get_input(&self, i: i32) -> Option<Box<dyn ParamMeasure>> {
            self.inputs.get(i as usize).map(|vn| {
                Box::new(MockParamMeasure { vn: vn.clone(), rank: i }) as Box<dyn ParamMeasure>
            })
        }

        fn get_num_outputs(&self) -> i32 {
            self.outputs.len() as i32
        }

        fn get_output(&self, i: i32) -> Option<Box<dyn ParamMeasure>> {
            self.outputs.get(i as usize).map(|vn| {
                Box::new(MockParamMeasure { vn: vn.clone(), rank: i }) as Box<dyn ParamMeasure>
            })
        }

        fn decode(&mut self, _decoder: &dyn Decoder) -> Result<(), DecoderException> {
            self.decoded = true;
            Ok(())
        }

        fn store_return_to_database(&mut self, _store_data_types: bool, _srctype: SourceType) {}

        fn store_parameters_to_database(&mut self, _store_data_types: bool, _srctype: SourceType) {}
    }

    #[test]
    fn defaults_mirror_freshly_constructed_java_state() {
        struct Bare {
            function: Arc<MockFunction>,
        }
        impl HighParamID for Bare {
            fn get_function(&self) -> Arc<dyn Function> {
                self.function.clone()
            }
            fn decode(&mut self, _decoder: &dyn Decoder) -> Result<(), DecoderException> {
                unimplemented!()
            }
            fn store_return_to_database(&mut self, _store_data_types: bool, _srctype: SourceType) {}
            fn store_parameters_to_database(&mut self, _store_data_types: bool, _srctype: SourceType) {}
        }

        let bare = Bare { function: Arc::new(MockFunction) };
        assert_eq!(bare.get_function_name(), None);
        assert_eq!(bare.get_function_address(), None);
        assert_eq!(bare.get_model_name(), None);
        assert_eq!(bare.get_proto_extra_pop(), UNKNOWN_EXTRAPOP);
        assert_eq!(bare.get_num_inputs(), 0);
        assert!(bare.get_input(0).is_none());
        assert_eq!(bare.get_num_outputs(), 0);
        assert!(bare.get_output(0).is_none());
    }

    #[test]
    fn tracks_inputs_and_outputs_through_a_trait_object() {
        let space = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 0);
        let vn0 = Varnode::new(Address::new(space.clone(), 0x100), 4);
        let vn1 = Varnode::new(Address::new(space, 0x104), 8);

        let mut high_param_id: Box<dyn HighParamID> = Box::new(MockHighParamId {
            function: Arc::new(MockFunction),
            model_name: Some("__stdcall".to_string()),
            inputs: vec![vn0.clone(), vn1.clone()],
            outputs: vec![vn1.clone()],
            decoded: false,
        });

        assert_eq!(high_param_id.get_function_name(), Some("test_function".to_string()));
        assert_eq!(high_param_id.get_model_name(), Some("__stdcall".to_string()));

        assert_eq!(high_param_id.get_num_inputs(), 2);
        let input0 = high_param_id.get_input(0).expect("input 0 present");
        assert!(!input0.is_empty());
        assert_eq!(input0.get_varnode().unwrap().get_offset(), 0x100);
        let input1 = high_param_id.get_input(1).expect("input 1 present");
        assert_eq!(input1.get_varnode().unwrap().get_offset(), 0x104);
        assert!(high_param_id.get_input(2).is_none());

        assert_eq!(high_param_id.get_num_outputs(), 1);
        let output0 = high_param_id.get_output(0).expect("output 0 present");
        assert_eq!(output0.get_rank(), Some(0));
        assert!(high_param_id.get_output(1).is_none());

        high_param_id.decode(&UnreachableDecoder).unwrap();
    }
}

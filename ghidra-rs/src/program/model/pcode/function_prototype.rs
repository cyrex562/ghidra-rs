//! Port of `ghidra.program.model.pcode.FunctionPrototype`.
//!
//! High-level prototype of a function based on Varnodes, describing the inputs and outputs of
//! this function.
//!
//! `FunctionPrototype` is referenced from
//! [`HighFunction`](crate::program::model::pcode::high_function::HighFunction)
//! long before its serialization collaborators -- `PcodeDataTypeManager` and `PcodeFactory` (and,
//! transitively, `AddressXML`) -- are ported, so it was selected as a dependency-cycle cut-point
//! and its public API is modeled as a trait rather than a concrete struct. This promotes the
//! minimal placeholder that used to live in `seam_stubs.rs` (see `STUBS.tsv`); every pure query
//! accessor defaults to the value the Java partial-initialization constructor
//! (`FunctionPrototype(LocalSymbolMap, Function)`) produces before `grabFromFunction`/
//! `readPrototypeXML` fill in the rest, so a bare `impl FunctionPrototype for Foo {}` behaves like
//! a freshly constructed, not-yet-populated prototype.
//!
//! [`encode_prototype`](FunctionPrototype::encode_prototype) and
//! [`decode_prototype`](FunctionPrototype::decode_prototype) are declared with the real Java
//! signatures (`PcodeDataTypeManager` is now its own real trait -- see
//! `pcode_data_type_manager` -- while `PcodeFactory` remains a placeholder below) but left as
//! required methods with no default body: the real algorithm reads/writes several private fields
//! (`modellock`, `voidinputlock`, `outputlock`, `custom`, `injectname`) that have no public Java
//! getter, and also calls the not-yet-ported `AddressXML` utility to (de)serialize storage
//! varnodes. A concrete implementor has direct access to its own fields and can implement these
//! precisely once its collaborators are ported; synthesizing a generic default here would require
//! guessing at `AddressXML`'s behavior.

use std::io;
use std::sync::Arc;

use crate::program::model::data::data_type::DataType;
use crate::program::model::data::parameter_definition::ParameterDefinition;
use crate::program::model::lang::prototype_model::UNKNOWN_EXTRAPOP;
use crate::program::model::pcode::decoder::Decoder;
use crate::program::model::pcode::decoder_exception::DecoderException;
use crate::program::model::pcode::encoder::Encoder;
use crate::program::model::pcode::pcode_data_type_manager::PcodeDataTypeManager;
use crate::program::seam_stubs::{HighSymbol, PcodeFactory, PlaceholderVariableStorage};
    use crate::program::model::listing::variable_storage::VariableStorage;

/// High-level prototype of a function based on Varnodes, describing the inputs and outputs of
/// this function.
///
/// Port of `ghidra.program.model.pcode.FunctionPrototype`.
pub trait FunctionPrototype {
    /// The number of defined parameters for this function prototype.
    ///
    /// Port of `FunctionPrototype.getNumParams()`.
    fn get_num_params(&self) -> i32 {
        0
    }

    /// The `i`'th `HighSymbol` parameter to this function prototype, or `None` if this prototype
    /// is not backed by a `LocalSymbolMap`.
    ///
    /// Port of `FunctionPrototype.getParam(int)`.
    fn get_param(&self, index: i32) -> Option<Arc<dyn HighSymbol>> {
        let _ = index;
        None
    }

    /// Parameter definitions if this prototype was produced from a `FunctionSignature`, or `None`
    /// if backed by a `LocalSymbolMap`.
    ///
    /// Port of `FunctionPrototype.getParameterDefinitions()`.
    fn get_parameter_definitions(&self) -> Option<Vec<Box<dyn ParameterDefinition>>> {
        None
    }

    /// True if this prototype is backed by a `LocalSymbolMap`, or false if generated from a
    /// `FunctionSignature`.
    ///
    /// Port of `FunctionPrototype.isBackedByLocalSymbolMap()`.
    fn is_backed_by_local_symbol_map(&self) -> bool {
        false
    }

    /// The return type for the function.
    ///
    /// Port of `FunctionPrototype.getReturnType()`.
    fn get_return_type(&self) -> Option<Box<dyn DataType>> {
        None
    }

    /// The return storage for the function.
    ///
    /// Port of `FunctionPrototype.getReturnStorage()`.
    fn get_return_storage(&self) -> Box<dyn VariableStorage> {
        Box::new(PlaceholderVariableStorage)
    }

    /// The number of extra bytes popped off by this function's return, or [`UNKNOWN_EXTRAPOP`] if
    /// unknown.
    ///
    /// Port of `FunctionPrototype.getExtraPop()`.
    fn get_extra_pop(&self) -> i32 {
        UNKNOWN_EXTRAPOP
    }

    /// True if this function has variable arguments.
    ///
    /// Port of `FunctionPrototype.isVarArg()`.
    fn is_var_arg(&self) -> bool {
        false
    }

    /// True if this function should be inlined by the decompiler.
    ///
    /// Port of `FunctionPrototype.isInline()`.
    fn is_inline(&self) -> bool {
        false
    }

    /// True if calls to this function do not return.
    ///
    /// Port of `FunctionPrototype.hasNoReturn()`.
    fn has_no_return(&self) -> bool {
        false
    }

    /// True if this function is a method taking a 'this' pointer as a parameter.
    ///
    /// Port of `FunctionPrototype.hasThisPointer()`.
    fn has_this_pointer(&self) -> bool {
        false
    }

    /// True if this function is an (object-oriented) constructor.
    ///
    /// Port of `FunctionPrototype.isConstructor()`.
    fn is_constructor(&self) -> bool {
        false
    }

    /// True if this function is an (object-oriented) destructor.
    ///
    /// Port of `FunctionPrototype.isDestructor()`.
    fn is_destructor(&self) -> bool {
        false
    }

    /// Calling convention model name specific to the associated compiler spec.
    ///
    /// Port of `FunctionPrototype.getModelName()`.
    fn get_model_name(&self) -> Option<String> {
        None
    }

    /// Encode this function prototype to a stream.
    ///
    /// `dtmanage` is the `PcodeDataTypeManager` for building type reference tags; `first_var_arg`
    /// is the index of the first variable argument, or -1.
    ///
    /// Port of `FunctionPrototype.encodePrototype(Encoder, PcodeDataTypeManager, int)`.
    ///
    /// # Errors
    /// Returns an error for problems writing to the underlying stream.
    fn encode_prototype(
        &self,
        encoder: &mut dyn Encoder,
        dtmanage: &dyn PcodeDataTypeManager,
        first_var_arg: i32,
    ) -> io::Result<()>;

    /// Decode the function prototype from a `<prototype>` element in the stream.
    ///
    /// `pcode_factory` is used to resolve data-type and address space references.
    ///
    /// Port of `FunctionPrototype.decodePrototype(Decoder, PcodeFactory)`.
    ///
    /// # Errors
    /// Returns an error for invalid encodings.
    fn decode_prototype(
        &mut self,
        decoder: &dyn Decoder,
        pcode_factory: &dyn PcodeFactory,
    ) -> Result<(), DecoderException>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockDataType;
    impl DataType for MockDataType {}

    struct MockParameterDefinition {
        ordinal: i32,
    }

    impl ParameterDefinition for MockParameterDefinition {
        fn get_ordinal(&self) -> i32 {
            self.ordinal
        }

        fn get_data_type(&self) -> Box<dyn DataType> {
            Box::new(MockDataType)
        }

        fn set_data_type(&mut self, _data_type: Box<dyn DataType>) -> Result<(), String> {
            Ok(())
        }

        fn get_name(&self) -> Option<String> {
            None
        }

        fn get_length(&self) -> i32 {
            4
        }

        fn set_name(&mut self, _name: Option<String>) {}

        fn get_comment(&self) -> Option<String> {
            None
        }

        fn set_comment(&mut self, _comment: Option<String>) {}

        fn is_equivalent_variable(&self, _variable: &dyn crate::program::model::listing::Variable) -> bool {
            false
        }

        fn is_equivalent_parameter(&self, parm: &dyn ParameterDefinition) -> bool {
            self.ordinal == parm.get_ordinal()
        }

        fn compare_to(&self, other: &dyn ParameterDefinition) -> std::cmp::Ordering {
            self.ordinal.cmp(&other.get_ordinal())
        }
    }

    /// Mirrors a prototype built from a `FunctionSignature` (internally backed by
    /// `ParameterDefinition`s rather than a `LocalSymbolMap`), matching the
    /// `FunctionPrototype(FunctionSignature, CompilerSpec, boolean)` constructor.
    struct MockFunctionPrototype {
        params: Vec<i32>,
        dotdotdot: bool,
        extrapop: i32,
        model_name: Option<String>,
    }

    impl FunctionPrototype for MockFunctionPrototype {
        fn get_num_params(&self) -> i32 {
            self.params.len() as i32
        }

        fn get_parameter_definitions(&self) -> Option<Vec<Box<dyn ParameterDefinition>>> {
            Some(
                self.params
                    .iter()
                    .map(|&ordinal| Box::new(MockParameterDefinition { ordinal }) as Box<dyn ParameterDefinition>)
                    .collect(),
            )
        }

        fn is_backed_by_local_symbol_map(&self) -> bool {
            false
        }

        fn get_extra_pop(&self) -> i32 {
            self.extrapop
        }

        fn is_var_arg(&self) -> bool {
            self.dotdotdot
        }

        fn get_model_name(&self) -> Option<String> {
            self.model_name.clone()
        }

        fn encode_prototype(
            &self,
            _encoder: &mut dyn Encoder,
            _dtmanage: &dyn PcodeDataTypeManager,
            _first_var_arg: i32,
        ) -> io::Result<()> {
            Ok(())
        }

        fn decode_prototype(
            &mut self,
            _decoder: &dyn Decoder,
            _pcode_factory: &dyn PcodeFactory,
        ) -> Result<(), DecoderException> {
            Ok(())
        }
    }

    #[test]
    fn trait_object_usage_is_object_safe() {
        let proto: Box<dyn FunctionPrototype> = Box::new(MockFunctionPrototype {
            params: vec![0, 1],
            dotdotdot: true,
            extrapop: 4,
            model_name: Some("__stdcall".to_string()),
        });

        assert_eq!(proto.get_num_params(), 2);
        assert!(!proto.is_backed_by_local_symbol_map());
        assert!(proto.get_param(0).is_none());
        assert!(proto.is_var_arg());
        assert_eq!(proto.get_extra_pop(), 4);
        assert_eq!(proto.get_model_name(), Some("__stdcall".to_string()));

        let defs = proto.get_parameter_definitions().expect("internally backed");
        assert_eq!(defs.len(), 2);
        assert_eq!(defs[1].get_ordinal(), 1);
    }

    #[test]
    fn unconfigured_prototype_matches_partial_constructor_defaults() {
        struct Unconfigured;
        impl FunctionPrototype for Unconfigured {
            fn encode_prototype(
                &self,
                _encoder: &mut dyn Encoder,
                _dtmanage: &dyn PcodeDataTypeManager,
                _first_var_arg: i32,
            ) -> io::Result<()> {
                Ok(())
            }

            fn decode_prototype(
                &mut self,
                _decoder: &dyn Decoder,
                _pcode_factory: &dyn PcodeFactory,
            ) -> Result<(), DecoderException> {
                Ok(())
            }
        }

        let proto = Unconfigured;
        assert_eq!(proto.get_num_params(), 0);
        assert_eq!(proto.get_extra_pop(), UNKNOWN_EXTRAPOP);
        assert!(!proto.is_var_arg());
        assert!(!proto.has_this_pointer());
        assert!(!proto.is_constructor());
        assert!(!proto.is_destructor());
        assert!(proto.get_return_type().is_none());
        assert!(proto.get_model_name().is_none());
    }
}

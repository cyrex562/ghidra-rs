//! Port of `ghidra.app.decompiler.signature.DebugSignature`.
//!
//! A feature extracted from a function, with an additional description of what information is
//! incorporated into the feature. The feature may incorporate data-flow and/or control-flow
//! information from the function. Internally, the feature is a 32-bit hash of this information,
//! but derived types incorporate more detailed information about how the hash was formed.

use crate::program::model::lang::language::Language;
use crate::program::model::listing::function::Function;
use crate::program::model::pcode::decoder::{Decoder, DecoderError};
use crate::program::model::pcode::decoder_exception::DecoderException;
use crate::program::model::pcode::ids::{ELEM_BLOCKSIG, ELEM_COPYSIG, ELEM_VARSIG};

/// The shared state of a `DebugSignature`: the underlying 32-bit hash of the feature.
///
/// Java's `DebugSignature` is an abstract class carrying a single public field, `hash`, plus two
/// abstract methods. Rust has no field inheritance, so each concrete signature type (in-repo:
/// `BlockSignature`, `CopySignature`, `VarnodeSignature` -- not yet ported, see
/// [`crate::app::seam_stubs`]) embeds this struct and implements [`DebugSignature`] for the two
/// methods Java leaves abstract.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DebugSignatureBase {
    /// The underlying 32-bit hash of the feature.
    pub hash: i32,
}

impl DebugSignatureBase {
    /// Creates a new base with a zeroed hash, matching Java's implicit `hash = 0` default.
    pub fn new() -> Self {
        Self { hash: 0 }
    }
}

/// The abstract operations a concrete debug signature must still supply.
///
/// Port of the abstract part of `ghidra.app.decompiler.signature.DebugSignature`. The shared
/// `hash` field lives on [`DebugSignatureBase`], which concrete implementors embed.
pub trait DebugSignature: Send + Sync {
    /// Decode the feature from a stream.
    ///
    /// Port of `DebugSignature.decode(Decoder)`.
    fn decode(&mut self, decoder: &dyn Decoder) -> Result<(), DecoderException>;

    /// Write a brief description of this feature to the given buffer.
    ///
    /// Port of `DebugSignature.printRaw(Language, StringBuffer)`; Java's `StringBuffer` maps to
    /// an appended-to `String` here.
    ///
    /// # Arguments
    /// * `language` - the underlying language of the function
    /// * `buf` - the buffer to append the description to
    fn print_raw(&self, language: &dyn Language, buf: &mut String);
}

/// Decode an array of features from the stream. Collectively, the features make up a "feature
/// vector" for a specific function. Each feature is returned as a separate descriptive object.
///
/// Port of the static `DebugSignature.decodeSignatures(Decoder, Function)`. `func` is accepted
/// but unused, matching the Java source (the parameter is not read anywhere in the method body).
///
/// # Errors
/// Returns a [`DecoderException`] for problems reading the stream, or if the stream contains an
/// unrecognized debug signature element.
pub fn decode_signatures(
    decoder: &dyn Decoder,
    _func: &dyn Function,
) -> Result<Vec<Box<dyn DebugSignature>>, DecoderException> {
    let mut res: Vec<Box<dyn DebugSignature>> = Vec::new();
    let el = decoder.open_element().map_err(decode_err)?;
    let mut subel = decoder.peek_element().map_err(decode_err)?;
    while subel != 0 {
        let mut sig: Box<dyn DebugSignature> = if subel == ELEM_VARSIG.id {
            Box::new(crate::app::seam_stubs::VarnodeSignature::new())
        } else if subel == ELEM_BLOCKSIG.id {
            Box::new(crate::app::seam_stubs::BlockSignature::new())
        } else if subel == ELEM_COPYSIG.id {
            Box::new(crate::app::seam_stubs::CopySignature::new())
        } else {
            return Err(DecoderException::new("Unknown debug signature element"));
        };
        sig.decode(decoder)?;
        res.push(sig);
        subel = decoder.peek_element().map_err(decode_err)?;
    }
    decoder.close_element(el).map_err(decode_err)?;
    Ok(res)
}

fn decode_err(e: DecoderError) -> DecoderException {
    DecoderException::with_cause("failed to decode DebugSignature", e)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressFactory, AddressSpace};
    use crate::program::model::pcode::ids::{AttributeId, ElementId};
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    /// A `Decoder` double that drives `decode_signatures`'s loop by yielding queued element ids
    /// from `peek_element`, one per call. Real stream decoders leave `peek_element`
    /// non-consuming and rely on a subelement's own `decode` to advance the cursor, but since the
    /// concrete signature types are not yet ported (`seam_stubs`'s placeholders leave `decode` a
    /// no-op), this double instead advances on `peek_element` to isolate `decode_signatures`'s
    /// own dispatch/error logic from those unported types.
    struct QueueDecoder {
        queue: Mutex<VecDeque<i32>>,
    }

    impl QueueDecoder {
        fn new(ids: Vec<i32>) -> Self {
            Self { queue: Mutex::new(ids.into_iter().collect()) }
        }
    }

    impl Decoder for QueueDecoder {
        fn get_address_factory(&self) -> Arc<dyn AddressFactory> {
            unimplemented!()
        }
        fn set_address_factory(&self, _factory: Arc<dyn AddressFactory>) {}
        fn peek_element(&self) -> Result<i32, DecoderError> {
            Ok(self.queue.lock().unwrap().pop_front().unwrap_or(0))
        }
        fn open_element(&self) -> Result<i32, DecoderError> {
            Ok(0)
        }
        fn open_element_with_id(&self, _elem_id: ElementId) -> Result<i32, DecoderError> {
            Ok(0)
        }
        fn close_element(&self, _id: i32) -> Result<(), DecoderError> {
            Ok(())
        }
        fn close_element_skipping(&self, _id: i32) -> Result<(), DecoderError> {
            unimplemented!()
        }
        fn get_next_attribute_id(&self) -> Result<i32, DecoderError> {
            unimplemented!()
        }
        fn rewind_attributes(&self) {}
        fn read_bool(&self) -> Result<bool, DecoderError> {
            unimplemented!()
        }
        fn read_bool_with_id(&self, _attrib_id: AttributeId) -> Result<bool, DecoderError> {
            unimplemented!()
        }
        fn read_signed_integer(&self) -> Result<i64, DecoderError> {
            unimplemented!()
        }
        fn read_signed_integer_with_id(&self, _attrib_id: AttributeId) -> Result<i64, DecoderError> {
            unimplemented!()
        }
        fn read_unsigned_integer(&self) -> Result<u64, DecoderError> {
            unimplemented!()
        }
        fn read_unsigned_integer_with_id(
            &self,
            _attrib_id: AttributeId,
        ) -> Result<u64, DecoderError> {
            unimplemented!()
        }
        fn read_string(&self) -> Result<String, DecoderError> {
            unimplemented!()
        }
        fn read_string_with_id(&self, _attrib_id: AttributeId) -> Result<String, DecoderError> {
            unimplemented!()
        }
        fn read_space(&self) -> Result<Arc<AddressSpace>, DecoderError> {
            unimplemented!()
        }
        fn read_space_with_id(
            &self,
            _attrib_id: AttributeId,
        ) -> Result<Arc<AddressSpace>, DecoderError> {
            unimplemented!()
        }
    }

    /// A `Function` double satisfying the trait's full (mostly non-default) surface with
    /// `unimplemented!()` bodies. `decode_signatures` never reads its `func` parameter (matching
    /// the Java source, which never reads it either), so none of these are ever called.
    struct UnusedFunction;

    impl crate::program::model::symbol::Namespace for UnusedFunction {
        fn get_symbol(&self) -> Arc<dyn crate::program::model::symbol::Symbol> {
            unimplemented!("not exercised by these tests")
        }
        fn get_parent_namespace(
            &self,
        ) -> Option<Arc<dyn crate::program::model::symbol::Namespace>> {
            unimplemented!("not exercised by these tests")
        }
    }

    impl Function for UnusedFunction {
        fn get_name(&self) -> String {
            unimplemented!("not exercised by these tests")
        }
        fn set_name(
            &mut self,
            _name: &str,
            _source: crate::program::model::symbol::SourceType,
        ) -> Result<(), crate::program::model::listing::function::SetFunctionNameError> {
            unimplemented!("not exercised by these tests")
        }
        fn set_call_fixup(&mut self, _name: Option<&str>) {
            unimplemented!("not exercised by these tests")
        }
        fn get_call_fixup(&self) -> Option<String> {
            unimplemented!("not exercised by these tests")
        }
        fn get_program(&self) -> Arc<dyn crate::program::model::listing::Program> {
            unimplemented!("not exercised by these tests")
        }
        fn get_comment(&self) -> Option<String> {
            unimplemented!("not exercised by these tests")
        }
        fn get_comment_as_array(&self) -> Vec<String> {
            unimplemented!("not exercised by these tests")
        }
        fn set_comment(&mut self, _comment: Option<&str>) {
            unimplemented!("not exercised by these tests")
        }
        fn get_repeatable_comment(&self) -> Option<String> {
            unimplemented!("not exercised by these tests")
        }
        fn get_repeatable_comment_as_array(&self) -> Vec<String> {
            unimplemented!("not exercised by these tests")
        }
        fn set_repeatable_comment(&mut self, _comment: Option<&str>) {
            unimplemented!("not exercised by these tests")
        }
        fn get_entry_point(&self) -> crate::program::model::address::Address {
            unimplemented!("not exercised by these tests")
        }
        fn get_return_type(&self) -> Option<Box<dyn crate::program::model::data::data_type::DataType>> {
            unimplemented!("not exercised by these tests")
        }
        fn set_return_type(
            &mut self,
            _data_type: Box<dyn crate::program::model::data::data_type::DataType>,
            _source: crate::program::model::symbol::SourceType,
        ) -> Result<(), crate::util::exception::InvalidInputException> {
            unimplemented!("not exercised by these tests")
        }
        fn get_return(&self) -> Box<dyn crate::program::model::listing::Parameter> {
            unimplemented!("not exercised by these tests")
        }
        fn set_return(
            &mut self,
            _data_type: Box<dyn crate::program::model::data::data_type::DataType>,
            _storage: Box<dyn crate::program::model::listing::variable_storage::VariableStorage>,
            _source: crate::program::model::symbol::SourceType,
        ) -> Result<(), crate::util::exception::InvalidInputException> {
            unimplemented!("not exercised by these tests")
        }
        fn get_signature_formal(
            &self,
            _formal_signature: bool,
        ) -> Box<dyn crate::program::model::listing::FunctionSignature> {
            unimplemented!("not exercised by these tests")
        }
        fn get_prototype_string(
            &self,
            _formal_signature: bool,
            _include_calling_convention: bool,
        ) -> String {
            unimplemented!("not exercised by these tests")
        }
        fn get_signature_source(&self) -> crate::program::model::symbol::SourceType {
            unimplemented!("not exercised by these tests")
        }
        fn set_signature_source(&mut self, _signature_source: crate::program::model::symbol::SourceType) {
            unimplemented!("not exercised by these tests")
        }
        fn get_stack_frame(&self) -> Box<dyn crate::program::seam_stubs::StackFrame> {
            unimplemented!("not exercised by these tests")
        }
        fn get_stack_purge_size(&self) -> i32 {
            unimplemented!("not exercised by these tests")
        }
        fn get_tags(&self) -> Vec<Box<dyn crate::program::model::listing::FunctionTag>> {
            unimplemented!("not exercised by these tests")
        }
        fn add_tag(&mut self, _name: &str) -> bool {
            unimplemented!("not exercised by these tests")
        }
        fn remove_tag(&mut self, _name: &str) {
            unimplemented!("not exercised by these tests")
        }
        fn set_stack_purge_size(&mut self, _purge_size: i32) {
            unimplemented!("not exercised by these tests")
        }
        fn is_stack_purge_size_valid(&self) -> bool {
            unimplemented!("not exercised by these tests")
        }
        #[allow(deprecated)]
        fn add_parameter(
            &mut self,
            _var: Box<dyn crate::program::model::listing::Variable>,
            _source: crate::program::model::symbol::SourceType,
        ) -> Result<
            Box<dyn crate::program::model::listing::Parameter>,
            crate::program::model::listing::function::FunctionEditError,
        > {
            unimplemented!("not exercised by these tests")
        }
        #[allow(deprecated)]
        fn insert_parameter(
            &mut self,
            _ordinal: i32,
            _var: Box<dyn crate::program::model::listing::Variable>,
            _source: crate::program::model::symbol::SourceType,
        ) -> Result<
            Box<dyn crate::program::model::listing::Parameter>,
            crate::program::model::listing::function::FunctionEditError,
        > {
            unimplemented!("not exercised by these tests")
        }
        fn replace_parameters(
            &mut self,
            _params: Vec<Box<dyn crate::program::model::listing::Variable>>,
            _update_type: crate::program::model::listing::function::FunctionUpdateType,
            _force: bool,
            _source: crate::program::model::symbol::SourceType,
        ) -> Result<(), crate::program::model::listing::function::FunctionEditError> {
            unimplemented!("not exercised by these tests")
        }
        fn update_function(
            &mut self,
            _calling_convention: Option<&str>,
            _return_value: Option<Box<dyn crate::program::model::listing::Variable>>,
            _new_params: Vec<Box<dyn crate::program::model::listing::Variable>>,
            _update_type: crate::program::model::listing::function::FunctionUpdateType,
            _force: bool,
            _source: crate::program::model::symbol::SourceType,
        ) -> Result<(), crate::program::model::listing::function::FunctionEditError> {
            unimplemented!("not exercised by these tests")
        }
        fn get_parameter(&self, _ordinal: i32) -> Option<Box<dyn crate::program::model::listing::Parameter>> {
            unimplemented!("not exercised by these tests")
        }
        #[allow(deprecated)]
        fn remove_parameter(&mut self, _ordinal: i32) {
            unimplemented!("not exercised by these tests")
        }
        #[allow(deprecated)]
        fn move_parameter(
            &mut self,
            _from_ordinal: i32,
            _to_ordinal: i32,
        ) -> Result<Box<dyn crate::program::model::listing::Parameter>, crate::util::exception::InvalidInputException>
        {
            unimplemented!("not exercised by these tests")
        }
        fn get_parameter_count(&self) -> i32 {
            unimplemented!("not exercised by these tests")
        }
        fn get_auto_parameter_count(&self) -> i32 {
            unimplemented!("not exercised by these tests")
        }
        fn get_parameters(&self) -> Vec<Box<dyn crate::program::model::listing::Parameter>> {
            unimplemented!("not exercised by these tests")
        }
        fn get_parameters_filtered(
            &self,
            _filter: Option<&dyn crate::program::seam_stubs::VariableFilter>,
        ) -> Vec<Box<dyn crate::program::model::listing::Parameter>> {
            unimplemented!("not exercised by these tests")
        }
        fn get_local_variables(&self) -> Vec<Box<dyn crate::program::model::listing::Variable>> {
            unimplemented!("not exercised by these tests")
        }
        fn get_local_variables_filtered(
            &self,
            _filter: Option<&dyn crate::program::seam_stubs::VariableFilter>,
        ) -> Vec<Box<dyn crate::program::model::listing::Variable>> {
            unimplemented!("not exercised by these tests")
        }
        fn get_variables_filtered(
            &self,
            _filter: Option<&dyn crate::program::seam_stubs::VariableFilter>,
        ) -> Vec<Box<dyn crate::program::model::listing::Variable>> {
            unimplemented!("not exercised by these tests")
        }
        fn get_all_variables(&self) -> Vec<Box<dyn crate::program::model::listing::Variable>> {
            unimplemented!("not exercised by these tests")
        }
        fn add_local_variable(
            &mut self,
            _var: Box<dyn crate::program::model::listing::Variable>,
            _source: crate::program::model::symbol::SourceType,
        ) -> Result<
            Box<dyn crate::program::model::listing::Variable>,
            crate::program::model::listing::function::FunctionEditError,
        > {
            unimplemented!("not exercised by these tests")
        }
        fn remove_variable(&mut self, _var: &dyn crate::program::model::listing::Variable) {
            unimplemented!("not exercised by these tests")
        }
        fn set_body(
            &mut self,
            _new_body: &dyn crate::program::model::address::AddressSetView,
        ) -> Result<(), crate::program::database::function::OverlappingFunctionException> {
            unimplemented!("not exercised by these tests")
        }
        fn has_var_args(&self) -> bool {
            unimplemented!("not exercised by these tests")
        }
        fn set_var_args(&mut self, _has_var_args: bool) {
            unimplemented!("not exercised by these tests")
        }
        fn is_inline(&self) -> bool {
            unimplemented!("not exercised by these tests")
        }
        fn set_inline(&mut self, _is_inline: bool) {
            unimplemented!("not exercised by these tests")
        }
        fn has_no_return(&self) -> bool {
            unimplemented!("not exercised by these tests")
        }
        fn set_no_return(&mut self, _has_no_return: bool) {
            unimplemented!("not exercised by these tests")
        }
        fn has_custom_variable_storage(&self) -> bool {
            unimplemented!("not exercised by these tests")
        }
        fn set_custom_variable_storage(&mut self, _has_custom_variable_storage: bool) {
            unimplemented!("not exercised by these tests")
        }
        fn get_calling_convention(
            &self,
        ) -> Option<Box<dyn crate::program::model::lang::prototype_model::PrototypeModel>> {
            unimplemented!("not exercised by these tests")
        }
        fn get_calling_convention_name(&self) -> String {
            unimplemented!("not exercised by these tests")
        }
        fn set_calling_convention(
            &mut self,
            _name: &str,
        ) -> Result<(), crate::util::exception::InvalidInputException> {
            unimplemented!("not exercised by these tests")
        }
        fn is_thunk(&self) -> bool {
            unimplemented!("not exercised by these tests")
        }
        fn get_thunked_function(&self, _recursive: bool) -> Option<Arc<dyn Function>> {
            unimplemented!("not exercised by these tests")
        }
        fn get_function_thunk_addresses(
            &self,
            _recursive: bool,
        ) -> Option<Vec<crate::program::model::address::Address>> {
            unimplemented!("not exercised by these tests")
        }
        fn set_thunked_function(
            &mut self,
            _thunked_function: Option<Arc<dyn Function>>,
        ) -> Result<(), String> {
            unimplemented!("not exercised by these tests")
        }
        fn is_external(&self) -> bool {
            unimplemented!("not exercised by these tests")
        }
        fn get_external_location(
            &self,
        ) -> Option<Box<dyn crate::program::model::symbol::ExternalLocation>> {
            unimplemented!("not exercised by these tests")
        }
        fn get_calling_functions(
            &self,
            _monitor: &dyn crate::util::task::TaskMonitor,
        ) -> Vec<Arc<dyn Function>> {
            unimplemented!("not exercised by these tests")
        }
        fn get_called_functions(
            &self,
            _monitor: &dyn crate::util::task::TaskMonitor,
        ) -> Vec<Arc<dyn Function>> {
            unimplemented!("not exercised by these tests")
        }
        fn promote_local_user_labels_to_global(&mut self) {
            unimplemented!("not exercised by these tests")
        }
        fn is_deleted(&self) -> bool {
            unimplemented!("not exercised by these tests")
        }
    }

    #[test]
    fn base_new_has_zeroed_hash() {
        assert_eq!(DebugSignatureBase::new().hash, 0);
        assert_eq!(DebugSignatureBase::default().hash, 0);
    }

    #[test]
    fn decode_signatures_dispatches_each_known_element_in_order() {
        let decoder = QueueDecoder::new(vec![ELEM_VARSIG.id, ELEM_BLOCKSIG.id, ELEM_COPYSIG.id]);
        let sigs = decode_signatures(&decoder, &UnusedFunction).unwrap();
        assert_eq!(sigs.len(), 3);
    }

    #[test]
    fn decode_signatures_empty_stream_yields_no_signatures() {
        let decoder = QueueDecoder::new(vec![]);
        let sigs = decode_signatures(&decoder, &UnusedFunction).unwrap();
        assert!(sigs.is_empty());
    }

    #[test]
    fn decode_signatures_rejects_unknown_element() {
        let decoder = QueueDecoder::new(vec![9999]);
        match decode_signatures(&decoder, &UnusedFunction) {
            Err(e) => assert!(e.to_string().contains("Unknown debug signature element")),
            Ok(_) => panic!("expected an error for an unrecognized element id"),
        }
    }
}

//! Port of `ghidra.program.model.lang.InjectPayloadCallfixupError`.
//!
//! A substitute for a callfixup that did not successfully parse: it wraps an
//! [`InjectPayloadCallfixupImpl`] built from a dummy p-code sequence
//! ([`get_dummy_pcode`](crate::program::model::lang::inject_payload_sleigh::get_dummy_pcode)),
//! standing in for either a partial clone of the failed payload or a bare named placeholder, and
//! reports [`is_error_placeholder`](InjectPayload::is_error_placeholder) as `true`.

use crate::program::model::address::factory::AddressFactory;
use crate::program::model::lang::inject_context::InjectContext;
use crate::program::model::lang::inject_payload::{InjectParameter, InjectPayload, InjectPayloadError};
use crate::program::model::lang::inject_payload_callfixup::{
    InjectPayloadCallfixup, InjectPayloadCallfixupImpl,
};
use crate::program::model::lang::inject_payload_sleigh::{get_dummy_pcode, InjectPayloadSleigh};
use crate::program::model::lang::sleigh::template::ConstructTpl;
use crate::program::model::lang::sleigh::SleighLanguage;
use crate::program::model::pcode::Encoder;
use crate::util::xml::xml_parse_exception::XmlParseException;
use crate::util::xml::xml_pull_parser::XmlPullParser;

/// A substitute for a callfixup that did not successfully parse.
///
/// Port of `ghidra.program.model.lang.InjectPayloadCallfixupError`.
#[derive(Clone)]
pub struct InjectPayloadCallfixupError {
    inner: InjectPayloadCallfixupImpl,
}

impl InjectPayloadCallfixupError {
    /// Constructor for use if the p-code template did not parse -- makes a partial clone of
    /// `failed_payload`, substituting dummy p-code.
    ///
    /// Port of `InjectPayloadCallfixupError(AddressFactory, InjectPayloadCallfixup)`.
    pub fn new_from_failed(
        addr_factory: &dyn AddressFactory,
        failed_payload: &InjectPayloadCallfixupImpl,
    ) -> Self {
        InjectPayloadCallfixupError {
            inner: InjectPayloadCallfixupImpl::new_partial_clone(
                get_dummy_pcode(addr_factory),
                failed_payload,
            ),
        }
    }

    /// Port of `InjectPayloadCallfixupError(AddressFactory, String)`.
    pub fn new_named(addr_factory: &dyn AddressFactory, nm: impl Into<String>) -> Self {
        InjectPayloadCallfixupError {
            inner: InjectPayloadCallfixupImpl::new_dummy(get_dummy_pcode(addr_factory), nm),
        }
    }
}

impl InjectPayload for InjectPayloadCallfixupError {
    fn get_name(&self) -> String {
        self.inner.get_name()
    }
    fn get_type(&self) -> i32 {
        self.inner.get_type()
    }
    fn get_source(&self) -> String {
        self.inner.get_source()
    }
    fn get_param_shift(&self) -> i32 {
        self.inner.get_param_shift()
    }
    fn get_input(&self) -> Vec<InjectParameter> {
        self.inner.get_input()
    }
    fn get_output(&self) -> Vec<InjectParameter> {
        self.inner.get_output()
    }

    /// Port of `InjectPayloadCallfixupError.isErrorPlaceholder()`: always `true`.
    fn is_error_placeholder(&self) -> bool {
        true
    }

    fn inject(
        &self,
        context: &InjectContext,
        emit: &mut dyn crate::app::plugin::processors::sleigh::pcode_emit::PcodeEmit,
    ) -> Result<(), InjectPayloadError> {
        self.inner.inject(context, emit)
    }
    fn get_pcode(
        &self,
        program: &dyn crate::program::model::listing::program::Program,
        context: &InjectContext,
    ) -> Result<Vec<crate::program::model::pcode::PcodeOp>, InjectPayloadError> {
        self.inner.get_pcode(program, context)
    }
    fn is_fall_thru(&self) -> bool {
        self.inner.is_fall_thru()
    }
    fn is_incidental_copy(&self) -> bool {
        self.inner.is_incidental_copy()
    }
    fn encode(&self, encoder: &mut dyn Encoder) -> std::io::Result<()> {
        self.inner.encode(encoder)
    }
    fn restore_xml<P: XmlPullParser>(
        &mut self,
        parser: &mut P,
        _language: &SleighLanguage,
    ) -> Result<(), XmlParseException>
    where
        Self: Sized,
    {
        self.inner.restore_xml(parser)
    }
    fn is_equivalent(&self, other: &dyn InjectPayload) -> bool {
        self.get_name() == other.get_name()
            && self.is_error_placeholder() == other.is_error_placeholder()
            && self.get_input() == other.get_input()
            && self.get_output() == other.get_output()
    }
}

impl InjectPayloadSleigh for InjectPayloadCallfixupError {
    fn release_parse_string(&mut self) -> Option<String> {
        self.inner.release_parse_string()
    }
    fn set_template(&mut self, template: ConstructTpl) {
        self.inner.set_template(template)
    }
}

impl InjectPayloadCallfixup for InjectPayloadCallfixupError {
    fn get_targets(&self) -> Vec<String> {
        self.inner.get_targets()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::factory::DefaultAddressFactory;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::lang::inject_payload::CALLFIXUP_TYPE;

    fn factory() -> DefaultAddressFactory {
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        let unique = AddressSpace::new("unique", 32, 1, AddressSpaceType::Unique, 2);
        let constant = AddressSpace::new("const", 32, 1, AddressSpaceType::Constant, 3);
        DefaultAddressFactory::new(vec![ram, unique, constant])
    }

    #[test]
    fn is_error_placeholder_is_always_true() {
        let err = InjectPayloadCallfixupError::new_named(&factory(), "myFixup_ERROR");
        assert!(err.is_error_placeholder());
        assert_eq!(err.get_name(), "myFixup_ERROR");
        assert!(err.is_fall_thru()); // dummy pcode's single INT_ADD op falls through
    }

    #[test]
    fn partial_clone_preserves_failed_payload_targets_and_source_suffix() {
        // `InjectPayloadCallfixupImpl::new` only assigns `source` (mirroring Java's public
        // `InjectPayloadCallfixup(String sourceName)`, which never touches `name`).
        let failed = InjectPayloadCallfixupImpl::new("realFixup.pspec");
        assert!(failed.get_targets().is_empty());

        let err = InjectPayloadCallfixupError::new_from_failed(&factory(), &failed);
        assert_eq!(err.get_type(), CALLFIXUP_TYPE);
        assert!(err.is_error_placeholder());
        assert_eq!(err.get_targets(), Vec::<String>::new());

        // Source gets the "_FAILED" suffix, mirroring InjectPayloadSleigh's partial-clone ctor.
        assert_eq!(err.get_source(), "realFixup.pspec_FAILED");
    }

    #[test]
    fn usable_as_trait_object() {
        let payload: Box<dyn InjectPayload> =
            Box::new(InjectPayloadCallfixupError::new_named(&factory(), "p_ERROR"));
        assert!(payload.is_error_placeholder());
        // `new_dummy` (invoked via `new_named`) always assigns `CALLFIXUP_TYPE`.
        assert_eq!(payload.get_type(), CALLFIXUP_TYPE);
    }
}

//! Port of `ghidra.program.model.lang.InjectPayloadCallfixup`.
//!
//! `InjectPayloadCallfixup` was selected as a dependency-cycle cut-point: `CallFixupAnalyzer`
//! (not yet ported) downcasts a `PcodeInjectLibrary`-provided `InjectPayloadSleigh` to
//! `InjectPayloadCallfixup` purely to call `getTargets()`, while `ProgramCompilerSpec` and
//! `SpecExtension` (not yet ported) construct and pattern-match on the concrete class when
//! wiring `<callfixup>` XML into a `PcodeInjectLibrary`. Modeling it as a trait over
//! [`InjectPayloadSleigh`] lets those consumers depend on the trait object instead of the
//! concrete class, breaking the cycle.
//!
//! The extra constructors (partial clone of a failed payload, dummy payload) are Java
//! construction patterns rather than API surface, so -- consistent with
//! [`InjectPayloadSleigh`](super::inject_payload_sleigh) -- they are left out of the trait.
//! Likewise `encode`, `restoreXml`, and `isEquivalent` are overrides of methods already declared
//! on [`InjectPayload`], not new API surface, so they are not redeclared here.

use crate::program::model::lang::inject_payload_sleigh::InjectPayloadSleigh;

/// A call fixup: a payload of p-code that substitutes for a subroutine call to specific target
/// symbols (see [`InjectPayloadSleigh`]).
///
/// Port of `ghidra.program.model.lang.InjectPayloadCallfixup`.
pub trait InjectPayloadCallfixup: InjectPayloadSleigh {
    /// Returns the names of symbols that trigger this call fixup when called.
    ///
    /// Port of `InjectPayloadCallfixup.getTargets()`.
    fn get_targets(&self) -> Vec<String>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::lang::inject_payload::{
        InjectParameter, InjectPayload, InjectPayloadError, CALLFIXUP_TYPE,
    };
    use crate::program::model::lang::inject_payload_sleigh::compute_fall_thru;
    use crate::program::model::lang::sleigh::template::ConstructTpl;
    use crate::program::model::lang::sleigh::SleighLanguage;
    use crate::program::model::listing::program::Program;
    use crate::program::model::pcode::{Encoder, PcodeOp};
    use crate::app::plugin::processors::sleigh::pcode_emit::PcodeEmit;
    use crate::program::seam_stubs::InjectContext;
    use crate::util::xml::xml_parse_exception::XmlParseException;
    use crate::util::xml::xml_pull_parser::XmlPullParser;

    struct MockCallfixup {
        name: String,
        targets: Vec<String>,
        parse_string: Option<String>,
        is_fallthru: bool,
    }

    impl InjectPayload for MockCallfixup {
        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn get_type(&self) -> i32 {
            CALLFIXUP_TYPE
        }

        fn get_source(&self) -> String {
            "mock".to_string()
        }

        fn get_param_shift(&self) -> i32 {
            0
        }

        fn get_input(&self) -> Vec<InjectParameter> {
            Vec::new()
        }

        fn get_output(&self) -> Vec<InjectParameter> {
            Vec::new()
        }

        fn is_error_placeholder(&self) -> bool {
            false
        }

        fn inject(
            &self,
            _context: &dyn InjectContext,
            _emit: &mut dyn PcodeEmit,
        ) -> Result<(), InjectPayloadError> {
            Ok(())
        }

        fn get_pcode(
            &self,
            _program: &dyn Program,
            _context: &dyn InjectContext,
        ) -> Result<Vec<PcodeOp>, InjectPayloadError> {
            Ok(Vec::new())
        }

        fn is_fall_thru(&self) -> bool {
            self.is_fallthru
        }

        fn is_incidental_copy(&self) -> bool {
            false
        }

        fn encode(&self, _encoder: &mut dyn Encoder) -> std::io::Result<()> {
            Ok(())
        }

        fn restore_xml<P: XmlPullParser>(
            &mut self,
            _parser: &mut P,
            _language: &SleighLanguage,
        ) -> Result<(), XmlParseException>
        where
            Self: Sized,
        {
            Ok(())
        }

        fn is_equivalent(&self, other: &dyn InjectPayload) -> bool {
            self.name == other.get_name()
        }
    }

    impl InjectPayloadSleigh for MockCallfixup {
        fn release_parse_string(&mut self) -> Option<String> {
            self.parse_string.take()
        }

        fn set_template(&mut self, template: ConstructTpl) {
            self.is_fallthru = compute_fall_thru(&template.vec);
        }
    }

    impl InjectPayloadCallfixup for MockCallfixup {
        fn get_targets(&self) -> Vec<String> {
            self.targets.clone()
        }
    }

    #[test]
    fn usable_as_trait_object_and_exposes_targets() {
        let mut payload: Box<dyn InjectPayloadCallfixup> = Box::new(MockCallfixup {
            name: "memcpy_fixup".to_string(),
            targets: vec!["memcpy".to_string(), "__memcpy_chk".to_string()],
            parse_string: Some("local tmp:1 = 0;".to_string()),
            is_fallthru: false,
        });

        assert_eq!(payload.get_name(), "memcpy_fixup");
        assert_eq!(
            payload.get_targets(),
            vec!["memcpy".to_string(), "__memcpy_chk".to_string()]
        );

        assert!(payload.release_parse_string().is_some());
        assert!(payload.release_parse_string().is_none());
    }
}

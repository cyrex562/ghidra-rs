//! Port of `ghidra.program.model.lang.InjectPayloadSleigh`.
//!
//! `InjectPayloadSleigh` was selected as a dependency-cycle cut-point: in Java,
//! `SleighLanguage` holds a `List<InjectPayloadSleigh>` and constructs concrete subclasses
//! (`InjectPayloadCallfixup`, `InjectPayloadCallother`, `InjectPayloadJumpAssist`,
//! `InjectPayloadSegment` -- none yet ported) polymorphically as `InjectPayloadSleigh`, while
//! `InjectPayloadSleigh.restoreXml` itself takes a `SleighLanguage` parameter. `PcodeInjectLibrary`
//! (not yet ported) also depends on the base class alone, driving compilation of the sleigh source
//! text via `releaseParseString`/`setTemplate` without caring which subclass it holds. Modeling
//! `InjectPayloadSleigh` as a trait over [`InjectPayload`] lets those consumers depend on the
//! trait object instead of the concrete class, breaking the cycle.
//!
//! The private/internal helpers (`checkParameterRestrictions`, `setupParameters`,
//! `orderParameters`, `setInputParameters`/`setOutputParameters`) are left out of the trait since
//! they are only ever called from within the base class's own `inject`/`restoreXml`
//! implementations, never by subclasses or other classes.

use crate::decompiler::opcodes::OpCode;
use crate::program::model::address::factory::AddressFactory;
use crate::program::model::lang::inject_payload::InjectPayload;
use crate::program::model::lang::sleigh::template::{
    ConstTpl, ConstTplType, ConstructTpl, OpTpl, VarnodeTpl,
};

/// A payload of p-code defined via a string passed to the sleigh compiler.
///
/// Port of `ghidra.program.model.lang.InjectPayloadSleigh`.
pub trait InjectPayloadSleigh: InjectPayload {
    /// Takes (and clears) the raw p-code source text parsed from this payload's XML `<body>`, so
    /// the sleigh compiler can compile it into a [`ConstructTpl`]. Returns `None` once already
    /// taken, or if this payload has no `<body>` (a dynamic payload).
    ///
    /// Port of the package-private `InjectPayloadSleigh.releaseParseString()`.
    fn release_parse_string(&mut self) -> Option<String>;

    /// Installs the compiled p-code template for this payload -- typically the result of
    /// compiling the text returned by [`release_parse_string`](Self::release_parse_string) --
    /// and recomputes whether the payload falls through (see [`compute_fall_thru`]).
    ///
    /// Port of the protected `InjectPayloadSleigh.setTemplate(ConstructTpl)`.
    fn set_template(&mut self, template: ConstructTpl);
}

/// Determines whether p-code ending in `op_vec`'s final operation falls through, i.e. does not
/// end in an unconditional branch, indirect branch, or return.
///
/// Port of the private `InjectPayloadSleigh.computeFallThru()`, extracted as a free function so
/// any [`InjectPayloadSleigh`] implementation can reuse it from
/// [`InjectPayloadSleigh::set_template`].
pub fn compute_fall_thru(op_vec: &[OpTpl]) -> bool {
    match op_vec.last() {
        None => true,
        Some(op) => !matches!(
            op.get_opcode(),
            OpCode::CpuiBranch | OpCode::CpuiBranchind | OpCode::CpuiReturn
        ),
    }
}

/// Builds a dummy p-code sequence to use in place of a normal parsed payload whose p-code failed
/// to parse. The sequence is non-empty, consisting of a single operation: `tmp = tmp + 0;`
///
/// Port of the static `InjectPayloadSleigh.getDummyPcode(AddressFactory)`.
pub fn get_dummy_pcode(addr_factory: &dyn AddressFactory) -> ConstructTpl {
    let unique_space = ConstTpl {
        tp: ConstTplType::SpaceId,
        value_real: 0,
        value_spaceid: addr_factory.get_unique_space(),
        handle_index: 0,
        select: None,
    };
    let const_space = ConstTpl {
        tp: ConstTplType::SpaceId,
        value_real: 0,
        value_spaceid: addr_factory.get_constant_space(),
        handle_index: 0,
        select: None,
    };
    let tmp_offset = ConstTpl {
        tp: ConstTplType::Real,
        value_real: 0x100,
        value_spaceid: None,
        handle_index: 0,
        select: None,
    };
    let const_zero = ConstTpl::new();
    let size = ConstTpl {
        tp: ConstTplType::Real,
        value_real: 4,
        value_spaceid: None,
        handle_index: 0,
        select: None,
    };

    let temp = VarnodeTpl {
        space: unique_space,
        offset: tmp_offset,
        size: size.clone(),
    };
    let zero = VarnodeTpl {
        space: const_space,
        offset: const_zero,
        size,
    };

    let mut op = OpTpl::with_opcode(OpCode::CpuiIntAdd);
    op.set_output(temp.clone());
    op.add_input(temp);
    op.add_input(zero);

    ConstructTpl {
        num_labels: 0,
        vec: vec![op],
        result: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::factory::DefaultAddressFactory;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::lang::inject_payload::{
        InjectParameter, InjectPayloadError, CALLFIXUP_TYPE,
    };
    use crate::program::model::lang::sleigh::SleighLanguage;
    use crate::program::model::listing::program::Program;
    use crate::program::model::pcode::{Encoder, PcodeOp};
    use crate::app::plugin::processors::sleigh::pcode_emit::PcodeEmit;
    use crate::program::seam_stubs::InjectContext;
    use crate::util::xml::xml_parse_exception::XmlParseException;
    use crate::util::xml::xml_pull_parser::XmlPullParser;

    struct MockInjectPayloadSleigh {
        name: String,
        parse_string: Option<String>,
        template: Option<ConstructTpl>,
        is_fallthru: bool,
    }

    impl InjectPayload for MockInjectPayloadSleigh {
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

    impl InjectPayloadSleigh for MockInjectPayloadSleigh {
        fn release_parse_string(&mut self) -> Option<String> {
            self.parse_string.take()
        }

        fn set_template(&mut self, template: ConstructTpl) {
            self.is_fallthru = compute_fall_thru(&template.vec);
            self.template = Some(template);
        }
    }

    fn factory() -> DefaultAddressFactory {
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        let unique = AddressSpace::new("unique", 32, 1, AddressSpaceType::Unique, 2);
        let constant = AddressSpace::new("const", 32, 1, AddressSpaceType::Constant, 3);
        DefaultAddressFactory::new(vec![ram, unique, constant])
    }

    #[test]
    fn usable_as_trait_object_and_drives_release_and_set_template() {
        let mut payload: Box<dyn InjectPayloadSleigh> = Box::new(MockInjectPayloadSleigh {
            name: "myInject".to_string(),
            parse_string: Some(" local tmp:1 = 0; ".to_string()),
            template: None,
            is_fallthru: false,
        });

        assert_eq!(payload.get_name(), "myInject");
        assert!(!payload.is_fall_thru());

        let text = payload.release_parse_string();
        assert_eq!(text.as_deref(), Some(" local tmp:1 = 0; "));
        assert_eq!(payload.release_parse_string(), None);

        let dummy = get_dummy_pcode(&factory());
        payload.set_template(dummy);
        assert!(payload.is_fall_thru());
    }

    #[test]
    fn get_dummy_pcode_builds_single_int_add_op() {
        let template = get_dummy_pcode(&factory());
        assert_eq!(template.vec.len(), 1);
        let op = &template.vec[0];
        assert_eq!(op.get_opcode(), OpCode::CpuiIntAdd);
        assert!(op.get_out().is_some());
        assert_eq!(op.num_input(), 2);
        assert!(compute_fall_thru(&template.vec));
    }

    #[test]
    fn compute_fall_thru_detects_terminal_control_flow() {
        assert!(compute_fall_thru(&[]));

        let falls_through = vec![OpTpl::with_opcode(OpCode::CpuiIntAdd)];
        assert!(compute_fall_thru(&falls_through));

        for opc in [OpCode::CpuiBranch, OpCode::CpuiBranchind, OpCode::CpuiReturn] {
            let terminated = vec![OpTpl::with_opcode(OpCode::CpuiIntAdd), OpTpl::with_opcode(opc)];
            assert!(!compute_fall_thru(&terminated));
        }
    }
}

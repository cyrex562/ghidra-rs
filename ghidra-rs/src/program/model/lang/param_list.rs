//! Port of `ghidra.program.model.lang.ParamList`.

use std::sync::Arc;

use crate::program::model::address::{Address, AddressSpace};
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::lang::compiler_spec::CompilerSpec;
use crate::program::model::lang::language::Language;
use crate::program::model::lang::param_list_register_out::ParamListRegisterOut;
use crate::program::model::lang::param_list_standard::ParamListStandard;
use crate::program::model::lang::param_list_standard_out::ParamListStandardOut;
use crate::program::model::lang::program_architecture::ProgramArchitecture;
use crate::program::model::listing::variable_storage::VariableStorage;
use crate::program::model::pcode::Encoder;
use crate::program::seam_stubs::{ParameterPieces, PrototypePieces};
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
/// Java's `ParamList` is an interface whose only implementors are the `ParamListStandard`
/// chain: `ParamListStandard`, `ParamListStandardOut extends ParamListStandard`, and
/// `ParamListRegisterOut extends ParamListStandardOut`. They differ only in `assignMap`, so the
/// interface is an enum over the three concrete lists; every other operation is the shared
/// [`ParamListStandard`] behaviour.
///
/// Port of `ghidra.program.model.lang.ParamList`.
pub enum ParamList {
    /// Input (or plain) resource list: `ParamListStandard`.
    Standard(ParamListStandard),
    /// Output list that falls back to a hidden return pointer: `ParamListStandardOut`.
    StandardOut(ParamListStandardOut),
    /// Output list with first-fit register assignment only: `ParamListRegisterOut`.
    RegisterOut(ParamListRegisterOut),
}

impl ParamList {
    /// The shared resource list behind every variant.
    pub fn standard(&self) -> &ParamListStandard {
        match self {
            ParamList::Standard(list) => list,
            ParamList::StandardOut(list) => list.base(),
            ParamList::RegisterOut(list) => list.standard(),
        }
    }

    /// Given a list of data-types, calculate the storage locations used for passing them.
    ///
    /// Port of `ParamList.assignMap`.
    pub fn assign_map(
        &self,
        proto: &PrototypePieces,
        dt_manager: &dyn DataTypeManager,
        res: &mut Vec<ParameterPieces>,
        add_auto_params: bool,
    ) {
        match self {
            ParamList::Standard(list) => list.assign_map(proto, dt_manager, res, add_auto_params),
            ParamList::StandardOut(list) => list.assign_map(proto, dt_manager, res, add_auto_params),
            ParamList::RegisterOut(list) => list.assign_map(proto, dt_manager, res, add_auto_params),
        }
    }

    /// Encode this list's configuration as an `<input>` or `<output>` element.
    ///
    /// Port of `ParamList.encode`.
    ///
    /// # Errors
    /// Returns an error for problems writing to the underlying stream.
    pub fn encode(&self, encoder: &mut dyn Encoder, is_input: bool) -> std::io::Result<()> {
        self.standard().encode(encoder, is_input)
    }

    /// Restore this list from an `<input>` or `<output>` element.
    ///
    /// Port of `ParamList.restoreXml`.
    ///
    /// # Errors
    /// Returns an error for badly formed XML.
    pub(crate) fn restore_xml<P: XmlPullParser>(
        &mut self,
        parser: &mut P,
        cspec: &dyn CompilerSpec,
    ) -> Result<(), XmlParseException> {
        match self {
            ParamList::Standard(list) => list.restore_xml(parser, cspec),
            ParamList::StandardOut(list) => list.restore_xml(parser, cspec),
            ParamList::RegisterOut(list) => list.restore_xml(parser, cspec),
        }
    }

    /// All parameter storage locations consisting of a single register.
    ///
    /// Port of `ParamList.getPotentialRegisterStorage(Program)`.
    pub fn get_potential_register_storage(&self, prog: Arc<dyn ProgramArchitecture>) -> Vec<Box<dyn VariableStorage>> {
        self.standard().get_potential_register_storage(prog)
    }

    /// The alignment of parameters passed on the stack, or -1 if there are no stack params.
    ///
    /// Port of `ParamList.getStackParameterAlignment`.
    pub fn get_stack_parameter_alignment(&self) -> i32 {
        self.standard().get_stack_parameter_alignment()
    }

    /// The boundary offset separating stack parameters from other local variables, or `None`.
    ///
    /// Port of `ParamList.getStackParameterOffset`.
    pub fn get_stack_parameter_offset(&self) -> Option<i64> {
        self.standard().get_stack_parameter_offset()
    }

    /// Determine if a memory range is a possible parameter, and if so what slot(s) it occupies.
    ///
    /// Port of `ParamList.possibleParamWithSlot`.
    pub fn possible_param_with_slot(&self, loc: &Address, size: i32, res: &mut WithSlotRec) -> bool {
        self.standard().possible_param_with_slot(loc, size, res)
    }

    /// The associated language.
    ///
    /// Port of `ParamList.getLanguage`.
    pub fn get_language(&self) -> Option<Arc<dyn Language + Send + Sync>> {
        self.standard().get_language()
    }

    /// The address space of stack-based parameters in this list, if any.
    ///
    /// Port of `ParamList.getSpacebase`.
    pub fn get_spacebase(&self) -> Option<Arc<AddressSpace>> {
        self.standard().get_spacebase()
    }

    /// True if the `this` pointer occurs before an indirect return pointer.
    ///
    /// Port of `ParamList.isThisBeforeRetPointer`.
    pub fn is_this_before_ret_pointer(&self) -> bool {
        self.standard().is_this_before_ret_pointer()
    }

    /// Determine if this list is equivalent to another: same concrete kind (Java's
    /// `getClass()` check) and identical configuration.
    ///
    /// Port of `ParamList.isEquivalent`.
    pub fn is_equivalent(&self, other: &ParamList) -> bool {
        std::mem::discriminant(self) == std::mem::discriminant(other) && self.standard().is_equivalent(other.standard())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::lang::cspec_test_support::{
        int_type, parser, TestCompilerSpec, TestDataTypeManager, SYSV_INPUT, SYSV_OUTPUT,
    };

    fn restored(mut list: ParamList, xml: &str) -> ParamList {
        list.restore_xml(&mut parser(xml), &TestCompilerSpec::x86_64()).unwrap();
        list
    }

    #[test]
    fn variants_dispatch_assign_map() {
        let input = restored(ParamList::Standard(ParamListStandard::new()), SYSV_INPUT);
        let output = restored(ParamList::StandardOut(ParamListStandardOut::new()), SYSV_OUTPUT);
        let register_out = restored(ParamList::RegisterOut(ParamListRegisterOut::new()), SYSV_OUTPUT);

        let proto = PrototypePieces { outtype: Some(int_type(64)), intypes: vec![int_type(4)], ..Default::default() };
        let mut res = Vec::new();
        output.assign_map(&proto, &TestDataTypeManager, &mut res, true);
        assert_eq!(res.len(), 2); // hidden return pointer requested
        input.assign_map(&proto, &TestDataTypeManager, &mut res, true);
        assert_eq!(res.len(), 3);
        // The hidden return pointer takes RDI, the first real parameter RSI.
        assert_eq!(res[1].address.as_ref().unwrap().offset(), 0x38);
        assert_eq!(res[2].address.as_ref().unwrap().offset(), 0x30);

        let mut res = Vec::new();
        register_out.assign_map(&proto, &TestDataTypeManager, &mut res, true);
        assert_eq!(res.len(), 1);
    }

    #[test]
    fn is_equivalent_requires_same_kind() {
        let a = restored(ParamList::StandardOut(ParamListStandardOut::new()), SYSV_OUTPUT);
        let b = restored(ParamList::StandardOut(ParamListStandardOut::new()), SYSV_OUTPUT);
        let c = restored(ParamList::RegisterOut(ParamListRegisterOut::new()), SYSV_OUTPUT);
        assert!(a.is_equivalent(&b));
        assert!(!a.is_equivalent(&c));
        assert_eq!(a.get_stack_parameter_alignment(), -1);
        assert_eq!(a.get_stack_parameter_offset(), None);
        assert!(a.get_spacebase().is_none());
        assert!(!a.is_this_before_ret_pointer());
    }
}

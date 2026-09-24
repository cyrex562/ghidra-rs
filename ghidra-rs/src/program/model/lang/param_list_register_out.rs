//! Port of `ghidra.program.model.lang.ParamListRegisterOut`.

use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::lang::compiler_spec::CompilerSpec;
use crate::program::model::lang::param_list_standard::ParamListStandard;
use crate::program::model::lang::param_list_standard_out::ParamListStandardOut;
use crate::program::seam_stubs::{is_void_data_type, ParameterPieces, PrototypePieces};
use crate::util::xml::xml_parse_exception::XmlParseException;
use crate::util::xml::xml_pull_parser::XmlPullParser;

/// A list of resources describing possible storage locations for a function's return value,
/// whose strategy is to take the first storage location in the list that fits the return
/// data-type -- with no fallback to a hidden return pointer.
///
/// Java's `extends ParamListStandardOut` is composition here: the embedded
/// [`ParamListStandardOut`] carries the resource list, and only `assignMap` differs.
///
/// Port of `ghidra.program.model.lang.ParamListRegisterOut`.
#[derive(Default)]
pub struct ParamListRegisterOut {
    base: ParamListStandardOut,
}

impl ParamListRegisterOut {
    /// An empty, unconfigured list, ready for [`restore_xml`](Self::restore_xml).
    pub fn new() -> Self {
        ParamListRegisterOut { base: ParamListStandardOut::new() }
    }

    /// The embedded `ParamListStandardOut` (the Java superclass).
    pub fn base(&self) -> &ParamListStandardOut {
        &self.base
    }

    /// The underlying resource list.
    pub fn standard(&self) -> &ParamListStandard {
        self.base.base()
    }

    /// Restore the resource list from an `<output>` element.
    ///
    /// Port of the inherited `ParamListStandard.restoreXml`.
    ///
    /// # Errors
    /// Returns an error for badly formed or inconsistent XML.
    pub(crate) fn restore_xml<P: XmlPullParser>(
        &mut self,
        parser: &mut P,
        cspec: &dyn CompilerSpec,
    ) -> Result<(), XmlParseException> {
        self.base.restore_xml(parser, cspec)
    }

    /// Compute storage for the return value and push it onto `res`. `add_auto_params` is unused:
    /// this strategy never creates a hidden return parameter.
    ///
    /// Port of `ParamListRegisterOut.assignMap`.
    pub fn assign_map(
        &self,
        proto: &PrototypePieces,
        dt_manager: &dyn DataTypeManager,
        res: &mut Vec<ParameterPieces>,
        _add_auto_params: bool,
    ) {
        let list = self.standard();
        let mut status = vec![0i32; list.num_group().max(0) as usize];
        let mut store = ParameterPieces::default();
        if is_void_data_type(proto.outtype.as_deref()) {
            store.data_type = proto.outtype.clone();
            res.push(store); // Don't assign storage for VOID
            return;
        }
        if let Some(outtype) = proto.outtype.as_ref() {
            list.assign_address(outtype, proto, -1, dt_manager, &mut status, &mut store);
        }
        res.push(store);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::lang::cspec_test_support::{
        int_type, parser, void_type, TestCompilerSpec, TestDataTypeManager, SYSV_OUTPUT,
    };

    fn register_out() -> ParamListRegisterOut {
        let mut list = ParamListRegisterOut::new();
        list.restore_xml(&mut parser(SYSV_OUTPUT), &TestCompilerSpec::x86_64()).unwrap();
        list
    }

    fn assign(outtype: std::sync::Arc<dyn crate::program::model::data::data_type::DataType>) -> Vec<ParameterPieces> {
        let proto = PrototypePieces { outtype: Some(outtype), ..Default::default() };
        let mut res = Vec::new();
        register_out().assign_map(&proto, &TestDataTypeManager, &mut res, true);
        res
    }

    #[test]
    fn fitting_return_gets_direct_storage() {
        let res = assign(int_type(4));
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].address.as_ref().unwrap().offset(), 0); // RAX
        assert!(!res[0].is_indirect);
        assert!(register_out().standard().is_standard_out());
    }

    #[test]
    fn void_return_gets_no_storage() {
        let res = assign(void_type());
        assert_eq!(res.len(), 1);
        assert!(res[0].address.is_none());
        assert!(res[0].data_type.is_some());
    }

    #[test]
    fn oversized_return_is_unassigned_without_hidden_pointer() {
        // Unlike ParamListStandardOut, no fallback to a hidden return pointer.
        let res = assign(int_type(64));
        assert_eq!(res.len(), 1);
        assert!(res[0].address.is_none());
        assert!(!res[0].is_indirect);
    }
}

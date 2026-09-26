//! Port of `ghidra.program.model.lang.ParamListStandardOut`.

use std::sync::Arc;

use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::lang::compiler_spec::CompilerSpec;
use crate::program::model::lang::param_list_standard::ParamListStandard;
use crate::program::model::lang::protorules::assign_action;
use crate::program::seam_stubs::{is_void_data_type, ParameterPieces, PrototypePieces};
use crate::util::xml::xml_parse_exception::XmlParseException;
use crate::util::xml::xml_pull_parser::XmlPullParser;

/// A list of resources describing possible storage locations for a function's return value, and
/// a strategy for selecting a storage location based on the return data-type.
///
/// Like [`ParamListStandard`], the first entry that matches the data-type is chosen; but if none
/// fits (because the return value is too big), the data-type is converted to a pointer and
/// storage is assigned for that pointer instead. If configured, this also signals that a hidden
/// input parameter is required to fully model where the large return value is stored.
///
/// Java's `extends ParamListStandard` is composition here: the resource list is the embedded
/// [`base`](Self::base), and only `assignMap` differs.
///
/// Port of `ghidra.program.model.lang.ParamListStandardOut`.
pub struct ParamListStandardOut {
    base: ParamListStandard,
}

impl Default for ParamListStandardOut {
    fn default() -> Self {
        Self::new()
    }
}

impl ParamListStandardOut {
    /// An empty, unconfigured list, ready for [`restore_xml`](Self::restore_xml).
    pub fn new() -> Self {
        Self::from_base(ParamListStandard::new())
    }

    /// Wrap an already-built resource list as an output list.
    pub fn from_base(mut base: ParamListStandard) -> Self {
        base.set_standard_out(true);
        ParamListStandardOut { base }
    }

    /// The underlying resource list (the Java superclass state).
    pub fn base(&self) -> &ParamListStandard {
        &self.base
    }

    /// Mutable access to the underlying resource list.
    pub fn base_mut(&mut self) -> &mut ParamListStandard {
        &mut self.base
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

    /// Compute storage for the return value `proto.outtype` and push it onto `res` (always the
    /// first element). If it does not fit, the return is converted to a pointer; with
    /// `add_auto_params` a hidden-return-pointer input parameter is pushed after it.
    ///
    /// Port of `ParamListStandardOut.assignMap`.
    pub fn assign_map(
        &self,
        proto: &PrototypePieces,
        dt_manager: &dyn DataTypeManager,
        res: &mut Vec<ParameterPieces>,
        add_auto_params: bool,
    ) {
        let base = &self.base;
        let mut status = vec![0i32; base.num_group().max(0) as usize];
        let mut store = ParameterPieces::default();

        if is_void_data_type(proto.outtype.as_deref()) {
            store.data_type = proto.outtype.clone();
            res.push(store); // Don't assign storage for VOID
            return;
        }
        let mut response_code = match proto.outtype.as_ref() {
            Some(outtype) => base.assign_address(outtype, proto, -1, dt_manager, &mut status, &mut store),
            None => assign_action::FAIL,
        };
        if response_code == assign_action::FAIL {
            // Invoke default hidden return input assignment action
            response_code = assign_action::HIDDENRET_PTRPARAM;
        }
        let mut hidden_ret = None;
        if response_code == assign_action::HIDDENRET_PTRPARAM
            || response_code == assign_action::HIDDENRET_SPECIALREG
            || response_code == assign_action::HIDDENRET_SPECIALREG_VOID
        {
            // If the storage is not assigned (because the datatype is too big) create a hidden
            // input parameter
            let sz = base.get_spacebase().map_or(-1, |space| space.pointer_size());
            let pointer_type: Option<Arc<dyn DataType>> = proto.outtype.as_ref().map(|outtype| {
                let ptr: Box<dyn DataType> = dt_manager.get_pointer_with_size(outtype.as_ref(), sz);
                Arc::from(ptr)
            });
            if response_code == assign_action::HIDDENRET_SPECIALREG_VOID {
                // Java stores the `VoidDataType.dataType` singleton, which has no concrete port
                // yet; `None` is what `ParameterPieces` treats as "no data-type".
                store.data_type = None;
            } else {
                store.data_type = pointer_type.clone();
                if let Some(pointer_type) = &pointer_type {
                    base.assign_address(pointer_type, proto, -1, dt_manager, &mut status, &mut store);
                }
            }
            store.is_indirect = true; // Signal that there is a hidden return
            if add_auto_params {
                let mut hidden_ret_pieces = ParameterPieces::default();
                hidden_ret_pieces.data_type = pointer_type;
                // Encode whether or not hidden return should be drawn from TYPECLASS_HIDDENRET
                hidden_ret_pieces.hidden_return_ptr = response_code == assign_action::HIDDENRET_SPECIALREG
                    || response_code == assign_action::HIDDENRET_SPECIALREG_VOID;
                hidden_ret = Some(hidden_ret_pieces); // will get replaced during input storage assignments
            }
        }
        res.push(store);
        if let Some(hidden_ret_pieces) = hidden_ret {
            res.push(hidden_ret_pieces);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::AddressSpaceType;
    use crate::program::model::lang::cspec_test_support::{
        float_type, int_type, parser, void_type, TestCompilerSpec, TestDataTypeManager, SYSV_OUTPUT,
    };

    fn sysv_output() -> ParamListStandardOut {
        let mut list = ParamListStandardOut::new();
        list.restore_xml(&mut parser(SYSV_OUTPUT), &TestCompilerSpec::x86_64()).unwrap();
        list
    }

    fn assign(list: &ParamListStandardOut, outtype: Arc<dyn DataType>, auto: bool) -> Vec<ParameterPieces> {
        let proto = PrototypePieces { outtype: Some(outtype), ..Default::default() };
        let mut res = Vec::new();
        list.assign_map(&proto, &TestDataTypeManager, &mut res, auto);
        res
    }

    #[test]
    fn restored_output_list_is_standard_out() {
        let list = sysv_output();
        assert!(list.base().is_standard_out());
        assert_eq!(list.base().get_num_param_entry(), 3);
        // The join entry overlaps RAX (group 1) only; RDX is not in this list.
        assert_eq!(list.base().get_entry(2).unwrap().get_all_groups(), &[1]);
    }

    #[test]
    fn void_return_gets_no_storage() {
        let res = assign(&sysv_output(), void_type(), true);
        assert_eq!(res.len(), 1);
        assert!(res[0].address.is_none());
        assert!(res[0].data_type.as_ref().unwrap().is_void_type());
        assert!(!res[0].is_indirect);
    }

    #[test]
    fn integer_and_float_returns_use_rax_and_xmm0() {
        let res = assign(&sysv_output(), int_type(8), true);
        assert_eq!(res.len(), 1);
        let addr = res[0].address.as_ref().unwrap();
        assert_eq!(addr.space().space_type(), AddressSpaceType::Register);
        assert_eq!(addr.offset(), 0);
        let res = assign(&sysv_output(), float_type(8), true);
        assert_eq!(res[0].address.as_ref().unwrap().offset(), 0x1200);
    }

    #[test]
    fn sixteen_byte_return_uses_rdx_rax_join() {
        let res = assign(&sysv_output(), int_type(16), true);
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].address.as_ref().unwrap().space().space_type(), AddressSpaceType::Join);
        let pieces = res[0].join_pieces.as_ref().unwrap();
        assert_eq!(pieces.len(), 2);
        assert_eq!(pieces[0].get_offset(), 0x10); // RDX, most significant
        assert_eq!(pieces[1].get_offset(), 0x0); // RAX
    }

    #[test]
    fn oversized_return_becomes_hidden_return_pointer() {
        let res = assign(&sysv_output(), int_type(64), true);
        assert_eq!(res.len(), 2);
        assert!(res[0].is_indirect);
        assert!(res[0].data_type.as_ref().unwrap().is_pointer());
        // The pointer itself is returned in RAX.
        assert_eq!(res[0].address.as_ref().unwrap().offset(), 0);
        assert!(res[1].data_type.as_ref().unwrap().is_pointer());
        assert!(!res[1].hidden_return_ptr);
        assert!(res[1].address.is_none());

        let res = assign(&sysv_output(), int_type(64), false);
        assert_eq!(res.len(), 1);
        assert!(res[0].is_indirect);
    }
}

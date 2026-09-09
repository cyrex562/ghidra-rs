//! Port of `ghidra.program.model.lang.PrototypePieces`.
//!
//! Raw components of a function prototype (obtained from parsing source code).
//!
//! This was originally a placeholder concrete struct living in `seam_stubs.rs` (only the
//! `outtype`/`intypes`/`first_var_arg_slot` fields were modeled, since those were the only
//! members its early consumers -- [`ParamList`](super::param_list::ParamList),
//! [`ParamListStandardOut`](super::param_list_standard_out::ParamListStandardOut),
//! [`ParamListStandard`](super::param_list_standard::ParamListStandard), and the `protorules`
//! qualifier filters -- read). It has since grown into the direct dependency of the entire
//! `protorules` `AssignAction`/`DatatypeFilter`/`QualifierFilter` cluster
//! ([`AssignAction::assign_address`](super::protorules::assign_action::AssignAction::assign_address)
//! takes `proto: &PrototypePieces` as one of its core parameters). This file graduates it to a
//! real, faithful port, adding the previously-omitted `model` field and both of Java's real
//! constructors. `seam_stubs.rs` re-exports [`PrototypePieces`] under its old path so none of
//! those existing call sites need to change, following this crate's established precedent for
//! graduating a seam-stub type in place (e.g. `DataTypePath`, `Mask`, `StackFrame`,
//! `VariableFilter`).
//!
//! `Debug` is intentionally not derived since `DataType` has no `Debug` supertrait yet.

use std::sync::Arc;

use crate::program::model::data::data_type::DataType;
use crate::program::model::lang::prototype_model::PrototypeModel;

/// Raw components of a function prototype (obtained from parsing source code).
///
/// Port of `ghidra.program.model.lang.PrototypePieces`.
#[derive(Clone)]
pub struct PrototypePieces {
    /// (Optional) model on which the prototype is based (`PrototypePieces.model`).
    pub model: Option<Arc<dyn PrototypeModel>>,
    /// Return data-type of the prototype (`PrototypePieces.outtype`).
    pub outtype: Option<Arc<dyn DataType>>,
    /// Input data-types of the prototype, in parameter order (`PrototypePieces.intypes`).
    pub intypes: Vec<Arc<dyn DataType>>,
    /// First position of a variable argument, or -1 if not vararg
    /// (`PrototypePieces.firstVarArgSlot`).
    pub first_var_arg_slot: i32,
}

impl PrototypePieces {
    /// Populate pieces from an old-style array of data-types: `old_list[0]` is the return
    /// data-type and the remainder are the input data-types, with `injected_this` (if present)
    /// inserted as the first input data-type.
    ///
    /// Port of `PrototypePieces(PrototypeModel model, DataType[] oldList, DataType
    /// injectedThis)`.
    ///
    /// Java indexes `oldList[0]` unconditionally (an empty array throws
    /// `ArrayIndexOutOfBoundsException`); this port instead takes `outtype` as `None` for an
    /// empty `old_list`, matching the `Option`-based field already established here rather than
    /// panicking.
    pub fn from_old_list(
        model: Option<Arc<dyn PrototypeModel>>,
        old_list: &[Arc<dyn DataType>],
        injected_this: Option<Arc<dyn DataType>>,
    ) -> Self {
        let mut intypes = Vec::new();
        if let Some(this_type) = injected_this {
            intypes.push(this_type);
        }
        if old_list.len() > 1 {
            intypes.extend(old_list[1..].iter().cloned());
        }
        PrototypePieces {
            model,
            outtype: old_list.first().cloned(),
            intypes,
            first_var_arg_slot: -1,
        }
    }

    /// Create a prototype with the given output data-type and empty/unspecified input
    /// data-types.
    ///
    /// Port of `PrototypePieces(PrototypeModel model, DataType outType)`.
    pub fn with_out_type(
        model: Option<Arc<dyn PrototypeModel>>,
        out_type: Option<Arc<dyn DataType>>,
    ) -> Self {
        PrototypePieces {
            model,
            outtype: out_type,
            intypes: Vec::new(),
            first_var_arg_slot: -1,
        }
    }
}

impl Default for PrototypePieces {
    /// Mirrors both Java constructors, which always set `firstVarArgSlot = -1` (there is no
    /// Java default-constructor to derive a blanket `#[derive(Default)]` from; `i32::default()`
    /// would wrongly produce `0`, which `VarargsFilter` would treat as "vararg starting at
    /// parameter 0" instead of "not vararg").
    fn default() -> Self {
        PrototypePieces {
            model: None,
            outtype: None,
            intypes: Vec::new(),
            first_var_arg_slot: -1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, Copy)]
    struct MockDataType {
        name: &'static str,
        length: i32,
    }

    impl DataType for MockDataType {
        fn get_name(&self) -> String {
            self.name.to_string()
        }

        fn get_length(&self) -> i32 {
            self.length
        }
    }

    fn dt(name: &'static str, length: i32) -> Arc<dyn DataType> {
        Arc::new(MockDataType { name, length })
    }

    #[test]
    fn default_matches_both_java_constructors_first_var_arg_slot() {
        let pieces = PrototypePieces::default();
        assert_eq!(pieces.first_var_arg_slot, -1);
        assert!(pieces.model.is_none());
        assert!(pieces.outtype.is_none());
        assert!(pieces.intypes.is_empty());
    }

    #[test]
    fn with_out_type_sets_outtype_and_empty_intypes() {
        let out = dt("undefined4", 4);
        let pieces = PrototypePieces::with_out_type(None, Some(out.clone()));
        assert_eq!(pieces.outtype.unwrap().get_name(), out.get_name());
        assert!(pieces.intypes.is_empty());
        assert_eq!(pieces.first_var_arg_slot, -1);
    }

    #[test]
    fn from_old_list_splits_first_element_as_outtype() {
        let old_list = vec![dt("out", 4), dt("in0", 4), dt("in1", 8)];
        let pieces = PrototypePieces::from_old_list(None, &old_list, None);
        assert_eq!(pieces.outtype.unwrap().get_name(), "out");
        assert_eq!(pieces.intypes.len(), 2);
        assert_eq!(pieces.intypes[0].get_name(), "in0");
        assert_eq!(pieces.intypes[1].get_name(), "in1");
        assert_eq!(pieces.first_var_arg_slot, -1);
    }

    #[test]
    fn from_old_list_injects_this_pointer_first() {
        let old_list = vec![dt("out", 4), dt("in0", 4)];
        let injected_this = dt("thisptr", 4);
        let pieces = PrototypePieces::from_old_list(None, &old_list, Some(injected_this.clone()));
        assert_eq!(pieces.intypes.len(), 2);
        assert_eq!(pieces.intypes[0].get_name(), "thisptr");
        assert_eq!(pieces.intypes[1].get_name(), "in0");
    }

    #[test]
    fn from_old_list_with_only_outtype_produces_empty_intypes() {
        let old_list = vec![dt("out", 4)];
        let pieces = PrototypePieces::from_old_list(None, &old_list, None);
        assert_eq!(pieces.outtype.unwrap().get_name(), "out");
        assert!(pieces.intypes.is_empty());
    }

    #[test]
    fn from_old_list_with_empty_slice_has_no_outtype() {
        let old_list: Vec<Arc<dyn DataType>> = Vec::new();
        let pieces = PrototypePieces::from_old_list(None, &old_list, None);
        assert!(pieces.outtype.is_none());
        assert!(pieces.intypes.is_empty());
    }

    #[test]
    fn clone_is_a_deep_field_copy_sharing_arcs() {
        let old_list = vec![dt("out", 4), dt("in0", 4)];
        let pieces = PrototypePieces::from_old_list(None, &old_list, None);
        let cloned = pieces.clone();
        assert_eq!(cloned.outtype.unwrap().get_name(), "out");
        assert_eq!(cloned.intypes.len(), 1);
    }
}

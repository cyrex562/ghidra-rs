use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::seam_stubs::{
    is_void_data_type, ParamListStandardLike, ParameterPieces, PrototypePieces,
};

/// A list of resources describing possible storage locations for a function's return value,
/// and a strategy for selecting a storage location based on data-types in a function signature.
///
/// The assignment strategy for this class is to take the first storage location in the list
/// that fits for the given function signature's return data-type.
///
/// In Java, `ParamListRegisterOut` is a concrete subclass of `ParamListStandardOut` that
/// overrides `assignMap` with a simpler strategy: no fallback to a hidden-return-pointer if the
/// first attempt fails to find storage, and no auto-parameter handling.
///
/// `ParamListStandard` is not yet ported (see [`ParamListStandardLike`]), so this is expressed
/// as an extension trait: implementors supply the inherited `numgroup`/`assignAddress` behavior
/// via [`ParamListStandardLike`], and get [`assign_map_register_out`](Self::assign_map_register_out)
/// as a provided method built on top of them.
///
/// Port of `ghidra.program.model.lang.ParamListRegisterOut`.
pub trait ParamListRegisterOut: ParamListStandardLike {
    /// Port of `ParamListRegisterOut.assignMap`.
    ///
    /// # Parameters
    /// - `proto`: the list of datatypes, including the return data-type being assigned storage
    /// - `dt_manager`: the data-type manager
    /// - `res`: the vector for holding the storage locations and other parameter properties;
    ///   the return storage is always appended first
    /// - `add_auto_params`: unused by this strategy (kept for API parity with the Java override)
    fn assign_map_register_out(
        &self,
        proto: &PrototypePieces,
        dt_manager: &dyn DataTypeManager,
        res: &mut Vec<ParameterPieces>,
        add_auto_params: bool,
    ) {
        let _ = add_auto_params;
        let mut status = vec![0i32; self.num_group().max(0) as usize];
        let mut store = ParameterPieces::default();

        if is_void_data_type(proto.outtype.as_deref()) {
            store.data_type = proto.outtype.clone();
            res.push(store); // Don't assign storage for VOID
            return;
        }

        if let Some(outtype) = proto.outtype.as_ref() {
            self.assign_address(outtype, proto, -1, dt_manager, &mut status, &mut store);
        }
        res.push(store);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::lang::protorules::assign_action;
    use std::sync::Arc;

    struct MockVoidDataType;
    impl DataType for MockVoidDataType {
        fn is_void_type(&self) -> bool {
            true
        }
    }

    struct MockIntDataType {
        length: i32,
    }
    impl DataType for MockIntDataType {
        fn get_length(&self) -> i32 {
            self.length
        }
    }

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    /// A resource list with a single group that only finds storage for data-types up to 4 bytes.
    struct FirstFitOnly;

    impl ParamListStandardLike for FirstFitOnly {
        fn num_group(&self) -> i32 {
            1
        }

        fn assign_address(
            &self,
            dt: &Arc<dyn DataType>,
            _proto: &PrototypePieces,
            _pos: i32,
            _dt_manager: &dyn DataTypeManager,
            status: &mut [i32],
            res: &mut ParameterPieces,
        ) -> i32 {
            status[0] += 1;
            if dt.get_length() <= 4 {
                res.data_type = Some(dt.clone());
                return assign_action::SUCCESS;
            }
            assign_action::FAIL
        }
    }

    impl ParamListRegisterOut for FirstFitOnly {}

    #[test]
    fn void_return_type_gets_no_storage() {
        let list = FirstFitOnly;
        let proto = PrototypePieces {
            outtype: Some(Arc::new(MockVoidDataType)),
        };
        let mut res = Vec::new();

        list.assign_map_register_out(&proto, &MockDataTypeManager, &mut res, true);

        assert_eq!(res.len(), 1);
        assert!(res[0].data_type.is_some());
        assert!(!res[0].is_indirect);
    }

    #[test]
    fn fitting_return_type_gets_direct_storage() {
        let list = FirstFitOnly;
        let proto = PrototypePieces {
            outtype: Some(Arc::new(MockIntDataType { length: 4 })),
        };
        let mut res = Vec::new();

        list.assign_map_register_out(&proto, &MockDataTypeManager, &mut res, true);

        assert_eq!(res.len(), 1);
        assert!(res[0].data_type.is_some());
        assert!(!res[0].is_indirect);
    }

    #[test]
    fn oversized_return_type_is_not_assigned_and_no_hidden_return_fallback() {
        // Unlike ParamListStandardOut, ParamListRegisterOut never falls back to a
        // hidden-return-pointer strategy: a failed direct assignment just leaves the
        // single result entry with no storage.
        let list = FirstFitOnly;
        let proto = PrototypePieces {
            outtype: Some(Arc::new(MockIntDataType { length: 64 })),
        };
        let mut res = Vec::new();

        list.assign_map_register_out(&proto, &MockDataTypeManager, &mut res, true);

        assert_eq!(res.len(), 1);
        assert!(res[0].data_type.is_none());
        assert!(!res[0].is_indirect);
    }

    #[test]
    fn usable_as_trait_object() {
        let list: Box<dyn ParamListRegisterOut> = Box::new(FirstFitOnly);
        let proto = PrototypePieces {
            outtype: Some(Arc::new(MockIntDataType { length: 4 })),
        };
        let mut res = Vec::new();

        list.assign_map_register_out(&proto, &MockDataTypeManager, &mut res, true);
        assert_eq!(res.len(), 1);
        assert!(res[0].data_type.is_some());
    }
}

use std::sync::Arc;

use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::data::pointer::Pointer;
use crate::program::model::lang::protorules::assign_action;
use crate::program::seam_stubs::{
    is_void_data_type, ParamListStandardLike, ParameterPieces, PrototypePieces,
};

/// Adapts a `Box<dyn Pointer>` so it can be stored/passed as `Arc<dyn DataType>`.
///
/// `Pointer: DataType` in the Java sense (`Pointer` is an interface extending `DataType`), but
/// `Pointer` itself declares no `DataType` overrides, so wrapping and using the default `DataType`
/// behavior here is equivalent to what a real upcast would observe.
struct PointerAsDataType(Box<dyn Pointer>);

impl DataType for PointerAsDataType {
    fn is_pointer(&self) -> bool {
        true
    }
}

/// A list of resources describing possible storage locations for a function's return value, and
/// a strategy for selecting a storage location based on data-types in a function signature.
///
/// In Java, `ParamListStandardOut` is a concrete subclass of `ParamListStandard` that overrides
/// `assignMap`: like the parent class, the first entry that matches the data-type is chosen, but
/// if this instance fails to find a match (because the return value data-type is too big) the
/// data-type is converted to a pointer and storage is assigned based on that pointer. If
/// configured, this also signals that a hidden input parameter is required to fully model where
/// the large return value is stored.
///
/// `ParamListStandard` is not yet ported (see [`ParamListStandardLike`]), so this is expressed as
/// an extension trait: implementors supply the inherited `numgroup`/`spacebase`/`assignAddress`
/// behavior via [`ParamListStandardLike`], and get [`assign_map_out`](Self::assign_map_out) as a
/// provided method built on top of them.
///
/// Port of `ghidra.program.model.lang.ParamListStandardOut`.
pub trait ParamListStandardOut: ParamListStandardLike {
    /// Port of `ParamListStandardOut.assignMap`.
    ///
    /// # Parameters
    /// - `proto`: the list of datatypes, including the return data-type being assigned storage
    /// - `dt_manager`: the data-type manager
    /// - `res`: the vector for holding the storage locations and other parameter properties;
    ///   the return storage is always appended first, followed by a hidden-return-pointer
    ///   parameter if one was required and `add_auto_params` is set
    /// - `add_auto_params`: if true add/process auto-parameters
    fn assign_map_out(
        &self,
        proto: &PrototypePieces,
        dt_manager: &dyn DataTypeManager,
        res: &mut Vec<ParameterPieces>,
        add_auto_params: bool,
    ) {
        let mut status = vec![0i32; self.num_group().max(0) as usize];
        let mut store = ParameterPieces::default();

        if is_void_data_type(proto.outtype.as_deref()) {
            store.data_type = proto.outtype.clone();
            res.push(store); // Don't assign storage for VOID
            return;
        }

        let mut response_code = match proto.outtype.as_ref() {
            Some(outtype) => {
                self.assign_address(outtype, proto, -1, dt_manager, &mut status, &mut store)
            }
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
            let sz = self.spacebase().map_or(-1, |space| space.pointer_size());
            let pointer_type: Option<Arc<dyn DataType>> = proto.outtype.as_ref().map(|outtype| {
                let ptr = dt_manager.get_pointer_with_size(outtype.as_ref(), sz);
                Arc::new(PointerAsDataType(ptr)) as Arc<dyn DataType>
            });

            if response_code == assign_action::HIDDENRET_SPECIALREG_VOID {
                // Stand-in for the Java `VoidDataType.dataType` singleton, not yet ported.
                store.data_type = None;
            } else {
                store.data_type = pointer_type.clone();
                if let Some(pointer_type) = &pointer_type {
                    self.assign_address(pointer_type, proto, -1, dt_manager, &mut status, &mut store);
                }
            }

            store.is_indirect = true; // Signal that there is a hidden return
            if add_auto_params {
                let mut hidden_ret_pieces = ParameterPieces::default();
                hidden_ret_pieces.data_type = pointer_type;
                // Encode whether or not hidden return should be drawn from TYPECLASS_HIDDENRET
                hidden_ret_pieces.hidden_return_ptr = response_code
                    == assign_action::HIDDENRET_SPECIALREG
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
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

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

    /// A resource list with two groups that always fails to place the return value directly
    /// (forcing the hidden-return-pointer path), unless the datatype under consideration is
    /// already a pointer (the second `assign_address` call `assign_map_out` makes once it has
    /// converted the return type to a pointer).
    struct AlwaysHiddenReturn {
        spacebase: Arc<AddressSpace>,
    }

    impl ParamListStandardLike for AlwaysHiddenReturn {
        fn num_group(&self) -> i32 {
            2
        }

        fn spacebase(&self) -> Option<Arc<AddressSpace>> {
            Some(self.spacebase.clone())
        }

        fn assign_address(
            &self,
            dt: &Arc<dyn DataType>,
            _proto: &PrototypePieces,
            pos: i32,
            _dt_manager: &dyn DataTypeManager,
            status: &mut [i32],
            res: &mut ParameterPieces,
        ) -> i32 {
            status[0] += 1;
            if dt.is_pointer() {
                res.data_type = Some(dt.clone());
                return assign_action::SUCCESS;
            }
            let _ = pos;
            assign_action::FAIL
        }
    }

    impl ParamListStandardOut for AlwaysHiddenReturn {}

    fn stack_space() -> Arc<AddressSpace> {
        AddressSpace::new("stack", 32, 1, AddressSpaceType::Ram, 0)
    }

    #[test]
    fn void_return_type_gets_no_storage() {
        let list = AlwaysHiddenReturn {
            spacebase: stack_space(),
        };
        let proto = PrototypePieces {
            outtype: Some(Arc::new(MockVoidDataType)),
        };
        let mut res = Vec::new();

        list.assign_map_out(&proto, &MockDataTypeManager, &mut res, true);

        assert_eq!(res.len(), 1);
        assert!(res[0].data_type.is_some());
        assert!(!res[0].is_indirect);
    }

    #[test]
    fn oversized_return_type_converts_to_hidden_return_pointer() {
        let list = AlwaysHiddenReturn {
            spacebase: stack_space(),
        };
        let proto = PrototypePieces {
            outtype: Some(Arc::new(MockIntDataType { length: 64 })),
        };
        let mut res = Vec::new();

        list.assign_map_out(&proto, &MockDataTypeManager, &mut res, true);

        assert_eq!(res.len(), 2);
        assert!(res[0].is_indirect);
        assert!(res[0].data_type.as_ref().is_some_and(|dt| dt.is_pointer()));
        assert!(res[1].data_type.is_some());
        assert!(!res[1].hidden_return_ptr);
    }

    #[test]
    fn oversized_return_type_without_auto_params_skips_hidden_return() {
        let list = AlwaysHiddenReturn {
            spacebase: stack_space(),
        };
        let proto = PrototypePieces {
            outtype: Some(Arc::new(MockIntDataType { length: 64 })),
        };
        let mut res = Vec::new();

        list.assign_map_out(&proto, &MockDataTypeManager, &mut res, false);

        assert_eq!(res.len(), 1);
        assert!(res[0].is_indirect);
    }

    #[test]
    fn usable_as_trait_object() {
        let list: Box<dyn ParamListStandardOut> = Box::new(AlwaysHiddenReturn {
            spacebase: stack_space(),
        });
        let proto = PrototypePieces {
            outtype: Some(Arc::new(MockIntDataType { length: 4 })),
        };
        let mut res = Vec::new();

        list.assign_map_out(&proto, &MockDataTypeManager, &mut res, true);
        assert_eq!(res.len(), 2);
    }
}

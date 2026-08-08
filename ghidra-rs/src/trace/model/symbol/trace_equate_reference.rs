use crate::program::database::symbol::equate_store::EquateReference;
use crate::program::model::pcode::Varnode;
use crate::trace::model::lifespan::Lifespan;
use crate::trace::seam_stubs::TraceThread;

/// A reference from an operand (or dynamic hash) to an equate, scoped to a lifespan and
/// (optionally) a thread, within a trace.
///
/// Port of `ghidra.trace.model.symbol.TraceEquateReference`.
///
/// It was selected as a dependency-cycle cut-point.
///
/// The Java interface `extends EquateReference`. The ported [`EquateReference`] is a plain data
/// struct (address/operand-index/dynamic-hash fields, no methods) rather than a trait, so it
/// cannot be used as a Rust supertrait; instead, [`Self::equate_reference`] hands back that data
/// verbatim, mirroring the inherited `getAddress()`/`getOpIndex()`/`getDynamicHashValue()` as a
/// single accessor.
pub trait TraceEquateReference {
    /// The address/operand-index/dynamic-hash data inherited from `EquateReference`.
    fn equate_reference(&self) -> EquateReference;

    /// Get the lifespan for which this reference is effective.
    fn get_lifespan(&self) -> Lifespan;

    /// Get the thread of the referring operand, applicable when the operand is (or resolves to)
    /// a register varnode.
    fn get_thread(&self) -> Box<dyn TraceThread>;

    /// Get the varnode being referred to, which is expected to be constant.
    fn get_varnode(&self) -> Varnode;

    /// Delete this reference.
    fn delete(&mut self);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};



    struct MockThread;

    impl TraceThread for MockThread {}

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    struct MockTraceEquateReference {
        address: Address,
        op_index: Option<i16>,
        start_snap: i64,
        varnode: Varnode,
        deleted: bool,
    }

    impl TraceEquateReference for MockTraceEquateReference {
        fn equate_reference(&self) -> EquateReference {
            EquateReference {
                address: self.address.clone(),
                op_index: self.op_index,
                dynamic_hash: None,
            }
        }

        fn get_lifespan(&self) -> Lifespan {
            Lifespan::span(self.start_snap, i64::MAX)
        }

        fn get_thread(&self) -> Box<dyn TraceThread> {
            Box::new(MockThread)
        }

        fn get_varnode(&self) -> Varnode {
            self.varnode.clone()
        }

        fn delete(&mut self) {
            self.deleted = true;
        }
    }

    fn make_ref() -> MockTraceEquateReference {
        MockTraceEquateReference {
            address: addr(0x400),
            op_index: Some(0),
            start_snap: 5,
            varnode: Varnode::new(addr(0x2000), 4),
            deleted: false,
        }
    }

    #[test]
    fn equate_reference_carries_address_and_op_index() {
        let r = make_ref();
        let er = r.equate_reference();
        assert_eq!(er.address, addr(0x400));
        assert_eq!(er.op_index, Some(0));
    }

    #[test]
    fn mutators_and_object_safety_via_trait_object() {
        let mut r = make_ref();
        assert!(!r.deleted);

        let mut boxed: Box<dyn TraceEquateReference> = Box::new(r);

        assert_eq!(boxed.get_lifespan().lmin(), 5);
        assert_eq!(boxed.get_varnode().get_address(), &addr(0x2000));
        let _thread = boxed.get_thread();

        boxed.delete();
    }
}

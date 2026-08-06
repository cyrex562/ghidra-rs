use crate::program::model::symbol::ShiftedReference;
use crate::trace::model::symbol::trace_reference::TraceReference;

/// Port of `ghidra.trace.model.symbol.TraceShiftedReference`, a
/// [`TraceReference`] whose destination is computed from a base value left
/// shifted by a shift amount.
///
/// It was selected as a dependency-cycle cut-point. It introduces no new
/// methods beyond its two supertraits, so its contract is captured entirely
/// by requiring both as bounds -- every type implementing both
/// [`TraceReference`] and [`ShiftedReference`] automatically satisfies this
/// trait via the blanket impl below, mirroring how any
/// `TraceShiftedReference` instance in Java is usable wherever a
/// `TraceReference` or `ShiftedReference` is expected.
///
/// The Java interface overrides one `Reference` default -- `isShiftedReference()`
/// always returns `true` -- which implementations of this trait's
/// supertraits must reproduce directly (Rust has no notion of re-overriding
/// an inherited abstract method).
pub trait TraceShiftedReference: TraceReference + ShiftedReference {}

impl<T: TraceReference + ShiftedReference + ?Sized> TraceShiftedReference for T {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressRange, AddressSpace, AddressSpaceType};
    use crate::program::model::symbol::{RefType, Reference, SourceType, Symbol};
    use crate::trace::model::lifespan::Lifespan;
    use crate::trace::model::trace::Trace;
    use std::sync::Arc;

    struct MockTraceShiftedReference {
        value: i64,
        shift: i32,
    }

    impl TraceReference for MockTraceShiftedReference {
        fn get_trace(&self) -> Box<dyn Trace> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_lifespan(&self) -> Box<dyn Lifespan> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_start_snap(&self) -> i64 {
            0
        }

        fn get_to_range(&self) -> AddressRange {
            let to = self.to_address();
            AddressRange::new(to.clone(), to)
        }

        fn set_primary(&mut self, _primary: bool) {}

        fn set_reference_type(&mut self, _ref_type: RefType) {}

        fn set_associated_symbol(&mut self, _symbol: Arc<dyn Symbol>) {}

        fn clear_associated_symbol(&mut self) {}

        fn delete(&mut self) {}
    }

    impl ShiftedReference for MockTraceShiftedReference {
        fn shift(&self) -> i32 {
            self.shift
        }

        fn value(&self) -> i64 {
            self.value
        }
    }

    impl Reference for MockTraceShiftedReference {
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }

        fn from_address(&self) -> Address {
            addr(0x400)
        }

        fn to_address(&self) -> Address {
            addr(self.value << self.shift)
        }

        fn is_primary(&self) -> bool {
            true
        }

        fn symbol_id(&self) -> i64 {
            -1
        }

        fn reference_type(&self) -> RefType {
            RefType::Data
        }

        fn operand_index(&self) -> i32 {
            0
        }

        fn is_mnemonic_reference(&self) -> bool {
            false
        }

        fn is_operand_reference(&self) -> bool {
            true
        }

        fn is_stack_reference(&self) -> bool {
            false
        }

        fn is_external_reference(&self) -> bool {
            false
        }

        fn is_entry_point_reference(&self) -> bool {
            false
        }

        fn is_memory_reference(&self) -> bool {
            true
        }

        fn is_register_reference(&self) -> bool {
            false
        }

        fn is_offset_reference(&self) -> bool {
            false
        }

        fn is_shifted_reference(&self) -> bool {
            // Mirrors the Java override: always true for TraceShiftedReference.
            true
        }

        fn source(&self) -> SourceType {
            SourceType::Default
        }
    }

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    #[test]
    fn usable_as_trait_object_via_blanket_impl_and_reports_shift_and_value() {
        let reference: Box<dyn TraceShiftedReference> = Box::new(MockTraceShiftedReference {
            value: 0x1234,
            shift: 4,
        });

        assert!(reference.is_shifted_reference());
        assert_eq!(reference.value(), 0x1234);
        assert_eq!(reference.shift(), 4);
        assert_eq!(reference.to_address(), addr(0x1234 << 4));
    }
}

use crate::program::model::symbol::OffsetReference;
use crate::trace::model::symbol::trace_reference::TraceReference;

/// Port of `ghidra.trace.model.symbol.TraceOffsetReference`, a
/// [`TraceReference`] whose destination is computed as a base address plus an
/// offset.
///
/// It was selected as a dependency-cycle cut-point. It introduces no new
/// methods beyond its two supertraits, so its contract is captured entirely
/// by requiring both as bounds -- every type implementing both
/// [`TraceReference`] and [`OffsetReference`] automatically satisfies this
/// trait via the blanket impl below, mirroring how any
/// `TraceOffsetReference` instance in Java is usable wherever a
/// `TraceReference` or `OffsetReference` is expected.
///
/// The Java interface overrides two `Reference` defaults, which
/// implementations of this trait's supertraits must reproduce directly
/// (Rust has no notion of re-overriding an inherited abstract method):
/// - `isOffsetReference()` always returns `true`.
/// - `getToAddress()` delegates to `TraceReference`'s default (the minimum
///   address of the reference's "to" range), not `OffsetReference`'s
///   base-plus-offset formula. The base/offset pair remains available via
///   `OffsetReference::base_address`/`offset` for callers that want the
///   computed address instead of the recorded range.
pub trait TraceOffsetReference: TraceReference + OffsetReference {}

impl<T: TraceReference + OffsetReference + ?Sized> TraceOffsetReference for T {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressRange, AddressSpace, AddressSpaceType};
    use crate::program::model::symbol::{RefType, Reference, SourceType, Symbol};
    use crate::trace::model::lifespan::Lifespan;
    use crate::trace::model::trace::Trace;
    use std::sync::Arc;

    struct MockTraceOffsetReference {
        to_range_min: Address,
        base_address: Address,
        offset: i64,
    }

    impl TraceReference for MockTraceOffsetReference {
        fn get_trace(&self) -> Box<dyn Trace> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_lifespan(&self) -> Lifespan {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_start_snap(&self) -> i64 {
            0
        }

        fn get_to_range(&self) -> AddressRange {
            AddressRange::new(self.to_range_min.clone(), self.to_range_min.clone())
        }

        fn set_primary(&mut self, _primary: bool) {}

        fn set_reference_type(&mut self, _ref_type: RefType) {}

        fn set_associated_symbol(&mut self, _symbol: Arc<dyn Symbol>) {}

        fn clear_associated_symbol(&mut self) {}

        fn delete(&mut self) {}
    }

    impl OffsetReference for MockTraceOffsetReference {
        fn offset(&self) -> i64 {
            self.offset
        }

        fn base_address(&self) -> Address {
            self.base_address.clone()
        }
    }

    impl Reference for MockTraceOffsetReference {
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }

        fn from_address(&self) -> Address {
            addr(0x400)
        }

        fn to_address(&self) -> Address {
            // Mirrors the Java override: delegates to the recorded "to" range,
            // not `base_address() + offset()`.
            self.to_range_min.clone()
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
            // Mirrors the Java override: always true for TraceOffsetReference.
            true
        }

        fn is_shifted_reference(&self) -> bool {
            false
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
    fn usable_as_trait_object_via_blanket_impl_and_to_address_uses_range_not_offset() {
        let reference: Box<dyn TraceOffsetReference> = Box::new(MockTraceOffsetReference {
            to_range_min: addr(0x2000),
            base_address: addr(0x1000),
            offset: 0x20,
        });

        assert!(reference.is_offset_reference());
        assert_eq!(reference.base_address(), addr(0x1000));
        assert_eq!(reference.offset(), 0x20);
        // The recorded "to" range wins over the base+offset formula, per the
        // Java `TraceOffsetReference.getToAddress()` override.
        assert_eq!(reference.to_address(), addr(0x2000));
        assert_ne!(reference.to_address(), reference.base_address().add(reference.offset()).unwrap());
    }
}

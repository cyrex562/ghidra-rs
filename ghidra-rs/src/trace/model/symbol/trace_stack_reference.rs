use crate::program::model::symbol::StackReference;
use crate::trace::seam_stubs::TraceReference;

/// Port of `ghidra.trace.model.symbol.TraceStackReference`, a
/// [`TraceReference`] pointing to a stack location.
///
/// It was selected as a dependency-cycle cut-point. It introduces no new
/// methods beyond its two supertraits, so its contract is captured entirely
/// by requiring both as bounds -- every type implementing both
/// [`TraceReference`] and [`StackReference`] automatically satisfies this
/// trait via the blanket impl below, mirroring how any `TraceStackReference`
/// instance in Java is usable wherever a `TraceReference` or `StackReference`
/// is expected.
///
/// The Java interface overrides two inherited members, which implementations
/// of this trait's supertraits must reproduce directly (Rust has no notion of
/// re-overriding an inherited abstract method):
/// - `getStackOffset()` is computed as `(int) getToAddress().getOffset()`
///   rather than a stored field.
/// - `isStackReference()` always returns `true`.
pub trait TraceStackReference: TraceReference + StackReference {}

impl<T: TraceReference + StackReference + ?Sized> TraceStackReference for T {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::symbol::{RefType, Reference, SourceType};

    struct MockTraceStackReference {
        to_address: Address,
    }

    impl TraceReference for MockTraceStackReference {}

    impl StackReference for MockTraceStackReference {
        fn stack_offset(&self) -> i32 {
            // Mirrors the Java override: computed from getToAddress().getOffset(),
            // not a stored field.
            self.to_address.offset() as i32
        }
    }

    impl Reference for MockTraceStackReference {
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }

        fn from_address(&self) -> Address {
            addr(0x400)
        }

        fn to_address(&self) -> Address {
            self.to_address.clone()
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
            // Mirrors the Java override: always true for TraceStackReference.
            true
        }

        fn is_external_reference(&self) -> bool {
            false
        }

        fn is_entry_point_reference(&self) -> bool {
            false
        }

        fn is_memory_reference(&self) -> bool {
            false
        }

        fn is_register_reference(&self) -> bool {
            false
        }

        fn is_offset_reference(&self) -> bool {
            false
        }

        fn is_shifted_reference(&self) -> bool {
            false
        }

        fn source(&self) -> SourceType {
            SourceType::Default
        }
    }

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("stack", 32, 1, AddressSpaceType::Stack, 1);
        Address::new(space, offset)
    }

    #[test]
    fn usable_as_trait_object_via_blanket_impl_and_stack_offset_tracks_to_address() {
        let reference: Box<dyn TraceStackReference> = Box::new(MockTraceStackReference {
            to_address: addr(-0x20),
        });

        assert!(reference.is_stack_reference());
        assert_eq!(reference.stack_offset(), -0x20);
        assert_eq!(reference.to_address(), addr(-0x20));
    }
}

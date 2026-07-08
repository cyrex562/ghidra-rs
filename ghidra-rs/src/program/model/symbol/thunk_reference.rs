use std::any::Any;
use crate::program::model::address::Address;
use crate::program::model::symbol::{DynamicReference, RefType, Reference, SourceType};
use std::cmp::Ordering;

const OPINDEX: i32 = RefType::OTHER;

/// Dynamic reference inferred from a thunk function to its thunked function.
#[derive(Debug, Clone, Eq)]
pub struct ThunkReference {
    from_address: Address,
    to_address: Address,
}

impl ThunkReference {
    /// Creates a thunk reference from the thunk function address to the
    /// thunked function address.
    pub fn new(thunk_address: Address, thunked_address: Address) -> Self {
        Self {
            from_address: thunk_address,
            to_address: thunked_address,
        }
    }

    /// Compares this reference to any `Reference`, matching Java's
    /// `ThunkReference.compareTo` ordering.
    pub fn compare_to_reference(&self, reference: &dyn Reference) -> Ordering {
        self.from_address()
            .cmp(&reference.from_address())
            .then(OPINDEX.cmp(&reference.operand_index()))
            .then(self.to_address().cmp(&reference.to_address()))
    }

    /// Returns true when another reference has the same Java-observable thunk
    /// identity.
    pub fn equals_reference(&self, reference: &dyn Reference) -> bool {
        reference.reference_type() == RefType::Thunk
            && self.from_address == reference.from_address()
            && self.to_address == reference.to_address()
    }
}

impl Reference for ThunkReference {
    fn from_address(&self) -> Address {
        self.from_address.clone()
    }

    fn to_address(&self) -> Address {
        self.to_address.clone()
    }

    fn is_primary(&self) -> bool {
        false
    }

    fn symbol_id(&self) -> i64 {
        -1
    }

    fn reference_type(&self) -> RefType {
        RefType::Thunk
    }

    fn operand_index(&self) -> i32 {
        OPINDEX
    }

    fn is_mnemonic_reference(&self) -> bool {
        true
    }

    fn is_operand_reference(&self) -> bool {
        false
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

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl DynamicReference for ThunkReference {}

impl PartialEq for ThunkReference {
    fn eq(&self, other: &Self) -> bool {
        self.from_address == other.from_address && self.to_address == other.to_address
    }
}

impl PartialOrd for ThunkReference {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ThunkReference {
    fn cmp(&self, other: &Self) -> Ordering {
        self.from_address
            .cmp(&other.from_address)
            .then(OPINDEX.cmp(&OPINDEX))
            .then(self.to_address.cmp(&other.to_address))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use std::sync::Arc;

    #[test]
    fn thunk_reference_matches_java_contract() {
        let reference = ThunkReference::new(addr(0x1000), addr(0x2000));

        assert_eq!(reference.from_address(), addr(0x1000));
        assert_eq!(reference.to_address(), addr(0x2000));
        assert!(!reference.is_primary());
        assert_eq!(reference.symbol_id(), -1);
        assert_eq!(reference.reference_type(), RefType::Thunk);
        assert_eq!(reference.operand_index(), RefType::OTHER);
        assert!(reference.is_mnemonic_reference());
        assert!(!reference.is_operand_reference());
        assert_eq!(reference.source(), SourceType::Default);
    }

    #[test]
    fn thunk_reference_classifiers_are_false() {
        let reference = ThunkReference::new(addr(0x1000), addr(0x2000));

        assert!(!reference.is_stack_reference());
        assert!(!reference.is_external_reference());
        assert!(!reference.is_entry_point_reference());
        assert!(!reference.is_memory_reference());
        assert!(!reference.is_register_reference());
        assert!(!reference.is_offset_reference());
        assert!(!reference.is_shifted_reference());
    }

    #[test]
    fn thunk_reference_equality_requires_thunk_type_and_matching_addresses() {
        let reference = ThunkReference::new(addr(0x1000), addr(0x2000));
        let same = ThunkReference::new(addr(0x1000), addr(0x2000));
        let different_to = ThunkReference::new(addr(0x1000), addr(0x3000));
        let non_thunk = TestReference::new(addr(0x1000), addr(0x2000), RefType::Data, OPINDEX);

        assert_eq!(reference, same);
        assert_ne!(reference, different_to);
        assert!(reference.equals_reference(&same));
        assert!(!reference.equals_reference(&different_to));
        assert!(!reference.equals_reference(&non_thunk));
    }

    #[test]
    fn thunk_reference_order_matches_java_compare_to() {
        let reference = ThunkReference::new(addr(0x1000), addr(0x2000));
        let earlier_from = TestReference::new(addr(0x0fff), addr(0x2000), RefType::Thunk, OPINDEX);
        let later_from = TestReference::new(addr(0x1001), addr(0x2000), RefType::Thunk, OPINDEX);
        let earlier_operand = TestReference::new(addr(0x1000), addr(0x2000), RefType::Thunk, -1);
        let later_operand = TestReference::new(addr(0x1000), addr(0x2000), RefType::Thunk, -3);
        let later_to = TestReference::new(addr(0x1000), addr(0x3000), RefType::Thunk, OPINDEX);

        assert_eq!(
            reference.compare_to_reference(&earlier_from),
            Ordering::Greater
        );
        assert_eq!(reference.compare_to_reference(&later_from), Ordering::Less);
        assert_eq!(
            reference.compare_to_reference(&earlier_operand),
            Ordering::Less
        );
        assert_eq!(
            reference.compare_to_reference(&later_operand),
            Ordering::Greater
        );
        assert_eq!(reference.compare_to_reference(&later_to), Ordering::Less);

        let mut refs = vec![
            ThunkReference::new(addr(0x1000), addr(0x3000)),
            ThunkReference::new(addr(0x0fff), addr(0x2000)),
            reference.clone(),
        ];
        refs.sort();

        assert_eq!(refs[0].from_address(), addr(0x0fff));
        assert_eq!(refs[1], reference);
        assert_eq!(refs[2].to_address(), addr(0x3000));
    }

    fn addr(offset: i64) -> Address {
        Address::new(space(), offset)
    }

    fn space() -> Arc<AddressSpace> {
        AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 1)
    }

    struct TestReference {
        from_address: Address,
        to_address: Address,
        reference_type: RefType,
        operand_index: i32,
    }

    impl TestReference {
        fn new(
            from_address: Address,
            to_address: Address,
            reference_type: RefType,
            operand_index: i32,
        ) -> Self {
            Self {
                from_address,
                to_address,
                reference_type,
                operand_index,
            }
        }
    }

    impl Reference for TestReference {
        fn from_address(&self) -> Address {
            self.from_address.clone()
        }

        fn to_address(&self) -> Address {
            self.to_address.clone()
        }

        fn is_primary(&self) -> bool {
            false
        }

        fn symbol_id(&self) -> i64 {
            -1
        }

        fn reference_type(&self) -> RefType {
            self.reference_type
        }

        fn operand_index(&self) -> i32 {
            self.operand_index
        }

        fn is_mnemonic_reference(&self) -> bool {
            self.operand_index == RefType::MNEMONIC
        }

        fn is_operand_reference(&self) -> bool {
            self.operand_index >= 0
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
}

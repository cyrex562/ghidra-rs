use std::any::Any;
use crate::program::model::address::Address;
use crate::program::model::symbol::{RefType, Reference, SourceType};
use std::cmp::Ordering;

/// Basic memory reference implementation not associated with a program.
///
/// This mirrors Ghidra's `MemReferenceImpl`.
#[derive(Debug, Clone, Eq)]
pub struct MemReferenceImpl {
    from_address: Address,
    to_address: Address,
    reference_type: RefType,
    operand_index: i32,
    source_type: SourceType,
    symbol_id: i64,
    primary: bool,
}

impl MemReferenceImpl {
    /// Creates a memory reference.
    pub fn new(
        from_address: Address,
        to_address: Address,
        reference_type: RefType,
        source_type: SourceType,
        operand_index: i32,
        primary: bool,
    ) -> Self {
        Self {
            from_address,
            to_address,
            reference_type,
            operand_index,
            source_type,
            symbol_id: -1,
            primary,
        }
    }

    /// Sets the source type for this reference.
    pub fn set_source(&mut self, source_type: SourceType) {
        self.source_type = source_type;
    }

    /// Compares this reference to any `Reference`, matching Java's
    /// `MemReferenceImpl.compareTo` ordering.
    pub fn compare_to_reference(&self, reference: &dyn Reference) -> Ordering {
        self.from_address()
            .cmp(&reference.from_address())
            .then(self.operand_index.cmp(&reference.operand_index()))
            .then(self.to_address().cmp(&reference.to_address()))
    }

    /// Returns true when another reference has the same Java-observable memory
    /// reference identity.
    pub fn equals_reference(&self, reference: &dyn Reference) -> bool {
        self.is_memory_reference()
            && reference.is_memory_reference()
            && self.from_address == reference.from_address()
            && self.to_address == reference.to_address()
            && self.operand_index == reference.operand_index()
            && self.symbol_id == reference.symbol_id()
            && self.primary == reference.is_primary()
            && self.source_type == reference.source()
            && self.reference_type == reference.reference_type()
            && self.is_shifted_reference() == reference.is_shifted_reference()
            && self.is_offset_reference() == reference.is_offset_reference()
    }
}

impl Reference for MemReferenceImpl {
    fn from_address(&self) -> Address {
        self.from_address.clone()
    }

    fn to_address(&self) -> Address {
        self.to_address.clone()
    }

    fn is_primary(&self) -> bool {
        self.primary
    }

    fn symbol_id(&self) -> i64 {
        self.symbol_id
    }

    fn reference_type(&self) -> RefType {
        self.reference_type
    }

    fn operand_index(&self) -> i32 {
        self.operand_index
    }

    fn is_mnemonic_reference(&self) -> bool {
        !self.is_operand_reference()
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
        true
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
        self.source_type
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl PartialEq for MemReferenceImpl {
    fn eq(&self, other: &Self) -> bool {
        self.equals_reference(other)
    }
}

impl PartialOrd for MemReferenceImpl {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for MemReferenceImpl {
    fn cmp(&self, other: &Self) -> Ordering {
        self.from_address
            .cmp(&other.from_address)
            .then(self.operand_index.cmp(&other.operand_index))
            .then(self.to_address.cmp(&other.to_address))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::symbol::ThunkReference;

    #[test]
    fn mem_reference_stores_constructor_values() {
        let reference = MemReferenceImpl::new(
            addr(0x1000),
            addr(0x2000),
            RefType::Read,
            SourceType::Analysis,
            1,
            true,
        );

        assert_eq!(reference.from_address(), addr(0x1000));
        assert_eq!(reference.to_address(), addr(0x2000));
        assert_eq!(reference.reference_type(), RefType::Read);
        assert_eq!(reference.source(), SourceType::Analysis);
        assert_eq!(reference.operand_index(), 1);
        assert!(reference.is_primary());
        assert_eq!(reference.symbol_id(), -1);
    }

    #[test]
    fn mem_reference_classifiers_match_java_defaults() {
        let operand_reference = reference_with_operand(0);
        let mnemonic_reference = reference_with_operand(-1);

        assert!(operand_reference.is_operand_reference());
        assert!(!operand_reference.is_mnemonic_reference());
        assert!(!mnemonic_reference.is_operand_reference());
        assert!(mnemonic_reference.is_mnemonic_reference());

        assert!(operand_reference.is_memory_reference());
        assert!(!operand_reference.is_stack_reference());
        assert!(!operand_reference.is_external_reference());
        assert!(!operand_reference.is_entry_point_reference());
        assert!(!operand_reference.is_register_reference());
        assert!(!operand_reference.is_offset_reference());
        assert!(!operand_reference.is_shifted_reference());
    }

    #[test]
    fn set_source_updates_reference_source() {
        let mut reference = reference_with_operand(0);

        assert_eq!(reference.source(), SourceType::Default);
        reference.set_source(SourceType::UserDefined);
        assert_eq!(reference.source(), SourceType::UserDefined);
    }

    #[test]
    fn mem_reference_equality_matches_java_fields() {
        let reference = MemReferenceImpl::new(
            addr(0x1000),
            addr(0x2000),
            RefType::Read,
            SourceType::Analysis,
            1,
            true,
        );
        let same = MemReferenceImpl::new(
            addr(0x1000),
            addr(0x2000),
            RefType::Read,
            SourceType::Analysis,
            1,
            true,
        );
        let different_primary = MemReferenceImpl::new(
            addr(0x1000),
            addr(0x2000),
            RefType::Read,
            SourceType::Analysis,
            1,
            false,
        );
        let non_memory = ThunkReference::new(addr(0x1000), addr(0x2000));

        assert_eq!(reference, same);
        assert!(reference.equals_reference(&same));
        assert_ne!(reference, different_primary);
        assert!(!reference.equals_reference(&different_primary));
        assert!(!reference.equals_reference(&non_memory));
    }

    #[test]
    fn mem_reference_order_matches_java_compare_to() {
        let reference = MemReferenceImpl::new(
            addr(0x1000),
            addr(0x2000),
            RefType::Read,
            SourceType::Default,
            1,
            false,
        );
        let earlier_from = MemReferenceImpl::new(
            addr(0x0fff),
            addr(0x2000),
            RefType::Read,
            SourceType::Default,
            1,
            false,
        );
        let later_operand = MemReferenceImpl::new(
            addr(0x1000),
            addr(0x2000),
            RefType::Read,
            SourceType::Default,
            2,
            false,
        );
        let later_to = MemReferenceImpl::new(
            addr(0x1000),
            addr(0x3000),
            RefType::Read,
            SourceType::Default,
            1,
            false,
        );

        assert_eq!(
            reference.compare_to_reference(&earlier_from),
            Ordering::Greater
        );
        assert_eq!(
            reference.compare_to_reference(&later_operand),
            Ordering::Less
        );
        assert_eq!(reference.compare_to_reference(&later_to), Ordering::Less);

        let mut refs = vec![later_to, earlier_from, reference.clone()];
        refs.sort();

        assert_eq!(refs[0].from_address(), addr(0x0fff));
        assert_eq!(refs[1], reference);
        assert_eq!(refs[2].to_address(), addr(0x3000));
    }

    fn reference_with_operand(operand_index: i32) -> MemReferenceImpl {
        MemReferenceImpl::new(
            addr(0x1000),
            addr(0x2000),
            RefType::Read,
            SourceType::Default,
            operand_index,
            false,
        )
    }

    fn addr(offset: i64) -> Address {
        use crate::program::model::address::{AddressSpace, AddressSpaceType};

        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }
}

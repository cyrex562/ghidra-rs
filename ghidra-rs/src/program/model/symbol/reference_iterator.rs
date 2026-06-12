use crate::program::model::symbol::Reference;
use std::sync::Arc;

/// Iterator that returns references.
///
/// This mirrors Ghidra's `ReferenceIterator`, using `Option` in place of
/// Java's null return when no reference is available.
pub trait ReferenceIterator {
    /// Returns true when another reference is available.
    fn has_next(&self) -> bool;

    /// Returns the next reference, or `None` when no reference is available.
    fn next_reference(&mut self) -> Option<Arc<dyn Reference>>;
}

/// Empty reference iterator.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct EmptyReferenceIterator;

impl ReferenceIterator for EmptyReferenceIterator {
    fn has_next(&self) -> bool {
        false
    }

    fn next_reference(&mut self) -> Option<Arc<dyn Reference>> {
        None
    }
}

/// Adapter from a vector of references to a `ReferenceIterator`.
pub struct ReferenceIteratorAdapter {
    references: Vec<Arc<dyn Reference>>,
    index: usize,
}

impl ReferenceIteratorAdapter {
    /// Creates an adapter over the supplied references.
    pub fn new(references: Vec<Arc<dyn Reference>>) -> Self {
        Self {
            references,
            index: 0,
        }
    }
}

impl ReferenceIterator for ReferenceIteratorAdapter {
    fn has_next(&self) -> bool {
        self.index < self.references.len()
    }

    fn next_reference(&mut self) -> Option<Arc<dyn Reference>> {
        if !self.has_next() {
            return None;
        }
        let reference = self.references[self.index].clone();
        self.index += 1;
        Some(reference)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::symbol::{RefType, SourceType};

    #[test]
    fn empty_iterator_has_no_references() {
        let mut iterator = EmptyReferenceIterator;

        assert!(!iterator.has_next());
        assert!(iterator.next_reference().is_none());
    }

    #[test]
    fn adapter_iterates_references_and_then_returns_none() {
        let references: Vec<Arc<dyn Reference>> = vec![
            Arc::new(TestReference::new(0x1000)),
            Arc::new(TestReference::new(0x1001)),
        ];
        let mut iterator = ReferenceIteratorAdapter::new(references);

        assert!(iterator.has_next());
        assert_eq!(
            iterator.next_reference().unwrap().from_address(),
            addr(0x1000)
        );
        assert!(iterator.has_next());
        assert_eq!(
            iterator.next_reference().unwrap().from_address(),
            addr(0x1001)
        );
        assert!(!iterator.has_next());
        assert!(iterator.next_reference().is_none());
    }

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    struct TestReference {
        from_address: Address,
    }

    impl TestReference {
        fn new(offset: i64) -> Self {
            Self {
                from_address: addr(offset),
            }
        }
    }

    impl Reference for TestReference {
        fn from_address(&self) -> Address {
            self.from_address.clone()
        }

        fn to_address(&self) -> Address {
            addr(0x2000)
        }

        fn is_primary(&self) -> bool {
            false
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
            false
        }

        fn source(&self) -> SourceType {
            SourceType::Default
        }
    }
}

//! Test stub for reference iteration.
//!
//! Port of `ghidra.program.model.ReferenceIteratorTestStub`.

use crate::program::model::symbol::Reference;
use std::sync::Arc;

/// A simple test stub implementation of `ReferenceIterator` for testing purposes.
///
/// This wraps a collection of references and provides iteration access,
/// similar to the original Java `ReferenceIteratorTestStub`.
pub struct ReferenceIteratorTestStub {
    references: Vec<Arc<dyn Reference>>,
    index: usize,
}

impl ReferenceIteratorTestStub {
    /// Creates a test stub iterator from a collection of references.
    pub fn new(references: Vec<Arc<dyn Reference>>) -> Self {
        Self {
            references,
            index: 0,
        }
    }
}

use crate::program::model::symbol::ReferenceIterator;

impl ReferenceIterator for ReferenceIteratorTestStub {
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

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    #[test]
    fn empty_stub_has_no_references() {
        let mut stub = ReferenceIteratorTestStub::new(vec![]);

        assert!(!stub.has_next());
        assert!(stub.next_reference().is_none());
    }

    #[test]
    fn stub_iterates_references_in_order() {
        let references: Vec<Arc<dyn Reference>> = vec![
            Arc::new(TestReference::new(0x1000)),
            Arc::new(TestReference::new(0x1001)),
            Arc::new(TestReference::new(0x1002)),
        ];
        let mut stub = ReferenceIteratorTestStub::new(references);

        assert!(stub.has_next());
        assert_eq!(
            stub.next_reference().unwrap().from_address(),
            addr(0x1000)
        );
        assert!(stub.has_next());
        assert_eq!(
            stub.next_reference().unwrap().from_address(),
            addr(0x1001)
        );
        assert!(stub.has_next());
        assert_eq!(
            stub.next_reference().unwrap().from_address(),
            addr(0x1002)
        );
        assert!(!stub.has_next());
        assert!(stub.next_reference().is_none());
    }

    #[test]
    fn stub_returns_none_after_exhausted() {
        let references: Vec<Arc<dyn Reference>> =
            vec![Arc::new(TestReference::new(0x1000))];
        let mut stub = ReferenceIteratorTestStub::new(references);

        assert!(stub.has_next());
        stub.next_reference();
        assert!(!stub.has_next());
        assert!(stub.next_reference().is_none());
        assert!(stub.next_reference().is_none());
    }
}

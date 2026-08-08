use crate::program::model::symbol::Reference;
use std::sync::Arc;

/// Iterator that returns references.
///
/// Mirrors Ghidra's `ReferenceIterator`, which extends `java.util.Iterator<Reference>`.
///
/// A marker supertrait over [`Iterator`] rather than a hand-rolled `has_next`/`next_reference`
/// pair: with one cursor-advancing operation, `for`/`while let` cannot express the
/// double-advance that dropped every other element in the regression recorded in AGENTS.md.
pub trait ReferenceIterator: Iterator<Item = Arc<dyn Reference>> {}

/// Empty reference iterator.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct EmptyReferenceIterator;

impl Iterator for EmptyReferenceIterator {
    type Item = Arc<dyn Reference>;

    fn next(&mut self) -> Option<Self::Item> {
        None
    }
}

impl ReferenceIterator for EmptyReferenceIterator {}

/// Adapter from a vector of references to a `ReferenceIterator`.
pub struct ReferenceIteratorAdapter {
    iter: std::vec::IntoIter<Arc<dyn Reference>>,
}

impl ReferenceIteratorAdapter {
    /// Creates an adapter over the supplied references.
    pub fn new(references: Vec<Arc<dyn Reference>>) -> Self {
        Self {
            iter: references.into_iter(),
        }
    }
}

impl Iterator for ReferenceIteratorAdapter {
    type Item = Arc<dyn Reference>;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
    }
}

impl ReferenceIterator for ReferenceIteratorAdapter {}

/// Adapter that wraps any iterator of references.
///
/// This is the Rust equivalent of Java's `ReferenceIteratorAdapter`, providing
/// a convenient way to wrap a boxed iterator to implement the `ReferenceIterator` trait.
pub struct ReferenceAdapter {
    iter: Box<dyn Iterator<Item = Arc<dyn Reference>>>,
}

impl ReferenceAdapter {
    /// Creates an adapter from a boxed iterator of references.
    ///
    /// # Arguments
    ///
    /// * `iter` - A boxed iterator that yields references
    pub fn new(iter: Box<dyn Iterator<Item = Arc<dyn Reference>>>) -> Self {
        Self { iter }
    }
}

impl Iterator for ReferenceAdapter {
    type Item = Arc<dyn Reference>;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
    }
}

impl ReferenceIterator for ReferenceAdapter {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::symbol::{RefType, SourceType};

    #[test]
    fn empty_iterator_has_no_references() {
        let mut iterator = EmptyReferenceIterator;

        assert!(iterator.next().is_none());
    }

    #[test]
    fn vector_adapter_iterates_references_and_then_returns_none() {
        let references: Vec<Arc<dyn Reference>> = vec![
            Arc::new(TestReference::new(0x1000)),
            Arc::new(TestReference::new(0x1001)),
        ];
        let mut iterator = ReferenceIteratorAdapter::new(references);
        assert_eq!(
            iterator.next().unwrap().from_address(),
            addr(0x1000)
        );
        assert_eq!(
            iterator.next().unwrap().from_address(),
            addr(0x1001)
        );
        assert!(iterator.next().is_none());
    }

    #[test]
    fn adapter_yields_every_reference_when_driven_by_a_for_loop() {
        // The regression this shape exists to prevent. With a has_next/next_reference pair a
        // caller could write `while it.has_next() { v.push(it.next_reference()) }`, advance the
        // cursor twice per turn and silently keep only every other reference -- it compiled, and
        // it is recorded in AGENTS.md under "Compiling is not evidence". Under `Iterator` there
        // is one cursor-advancing operation and the loop cannot express it.
        let references: Vec<Arc<dyn Reference>> = (0..6)
            .map(|i| Arc::new(TestReference::new(0x1000 + i)) as Arc<dyn Reference>)
            .collect();

        let seen: Vec<i64> = ReferenceIteratorAdapter::new(references)
            .map(|r| r.from_address().offset())
            .collect();

        assert_eq!(seen, vec![0x1000, 0x1001, 0x1002, 0x1003, 0x1004, 0x1005]);
    }

    #[test]
    fn boxed_adapter_iterates_from_boxed_iterator() {
        let references: Vec<Arc<dyn Reference>> = vec![
            Arc::new(TestReference::new(0x1000)),
            Arc::new(TestReference::new(0x1001)),
            Arc::new(TestReference::new(0x1002)),
        ];
        let boxed_iter: Box<dyn Iterator<Item = Arc<dyn Reference>>> =
            Box::new(references.into_iter());
        let mut adapter = ReferenceAdapter::new(boxed_iter);
        assert_eq!(
            adapter.next().unwrap().from_address(),
            addr(0x1000)
        );
        assert_eq!(
            adapter.next().unwrap().from_address(),
            addr(0x1001)
        );
        assert_eq!(
            adapter.next().unwrap().from_address(),
            addr(0x1002)
        );
        assert!(adapter.next().is_none());
    }

    #[test]
    fn boxed_adapter_with_empty_iterator_returns_none() {
        let references: Vec<Arc<dyn Reference>> = vec![];
        let boxed_iter: Box<dyn Iterator<Item = Arc<dyn Reference>>> =
            Box::new(references.into_iter());
        let mut adapter = ReferenceAdapter::new(boxed_iter);

        assert!(adapter.next().is_none());
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
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }

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

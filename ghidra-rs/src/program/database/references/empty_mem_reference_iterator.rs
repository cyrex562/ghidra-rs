//! Empty memory reference iterator.
//!
//! Port of `ghidra.program.database.references.EmptyMemReferenceIterator`.

use crate::program::model::symbol::{Reference, ReferenceIterator};
use std::sync::Arc;

/// Empty memory reference iterator.
///
/// A reference iterator that never yields any references. Used in contexts
/// where no references are available.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct EmptyMemReferenceIterator;

impl ReferenceIterator for EmptyMemReferenceIterator {
    fn has_next(&self) -> bool {
        false
    }

    fn next_reference(&mut self) -> Option<Arc<dyn Reference>> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_iterator_never_yields_references() {
        let mut iter = EmptyMemReferenceIterator;
        assert!(!iter.has_next());
        assert!(iter.next_reference().is_none());
        assert!(!iter.has_next());
        assert!(iter.next_reference().is_none());
    }

    #[test]
    fn empty_iterator_is_copy() {
        let iter1 = EmptyMemReferenceIterator;
        let iter2 = iter1;
        assert_eq!(iter1, iter2);
    }

    #[test]
    fn empty_iterator_is_default_constructible() {
        let iter = EmptyMemReferenceIterator::default();
        assert!(!iter.has_next());
    }

    #[test]
    fn multiple_calls_remain_consistent() {
        let mut iter = EmptyMemReferenceIterator;
        for _ in 0..10 {
            assert!(!iter.has_next());
            assert!(iter.next_reference().is_none());
        }
    }
}

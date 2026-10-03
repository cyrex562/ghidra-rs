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

impl Iterator for EmptyMemReferenceIterator {
    type Item = Arc<dyn Reference>;

    fn next(&mut self) -> Option<Self::Item> {
        None
    }
}

impl ReferenceIterator for EmptyMemReferenceIterator {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_iterator_never_yields_references() {
        let mut iter = EmptyMemReferenceIterator;
        assert!(iter.next().is_none());
        assert!(iter.next().is_none());
    }

    #[test]
    fn empty_iterator_is_copy() {
        let iter1 = EmptyMemReferenceIterator;
        let iter2 = iter1;
        assert_eq!(iter1, iter2);
    }

    #[test]
    fn empty_iterator_is_default_constructible() {
        let mut iter = EmptyMemReferenceIterator::default();
        assert!(iter.next().is_none());
    }

    #[test]
    fn multiple_calls_remain_consistent() {
        let mut iter = EmptyMemReferenceIterator;
        for _ in 0..10 {
            assert!(iter.next().is_none());
        }
    }
}

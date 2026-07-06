use crate::program::model::listing::FunctionIterator;
use std::sync::Arc;
use crate::program::model::listing::Function;

/// An empty function iterator that yields no items.
///
/// Analogous to Java's `ghidra.trace.util.EmptyFunctionIterator`. This provides
/// a singleton-like empty iterator for use in trace utilities when no functions
/// are available.
#[derive(Debug, Clone, Copy)]
pub struct EmptyFunctionIterator;

impl Iterator for EmptyFunctionIterator {
    type Item = Arc<dyn Function>;

    fn next(&mut self) -> Option<Self::Item> {
        None
    }
}

impl FunctionIterator for EmptyFunctionIterator {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_iterator_returns_none() {
        let mut iterator = EmptyFunctionIterator;
        assert!(iterator.next().is_none());
    }

    #[test]
    fn empty_iterator_multiple_calls_return_none() {
        let mut iterator = EmptyFunctionIterator;
        assert!(iterator.next().is_none());
        assert!(iterator.next().is_none());
        assert!(iterator.next().is_none());
    }

    #[test]
    fn empty_iterator_is_copyable() {
        let iter1 = EmptyFunctionIterator;
        let iter2 = iter1;
        let mut iter3 = iter2;
        assert!(iter3.next().is_none());
    }
}

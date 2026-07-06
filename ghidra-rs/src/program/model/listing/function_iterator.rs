use crate::program::model::listing::Function;
use std::sync::Arc;

/// Iterator that returns functions.
///
/// This trait mirrors Ghidra's `FunctionIterator`, which combines the behavior of both
/// Iterator and Iterable in Java. Implementations should provide efficient iteration
/// over Function elements.
pub trait FunctionIterator: Iterator<Item = Arc<dyn Function>> {}

/// Empty function iterator with no items.
#[derive(Debug, Clone, Copy)]
pub struct EmptyFunctionIterator;

impl Iterator for EmptyFunctionIterator {
    type Item = Arc<dyn Function>;

    fn next(&mut self) -> Option<Self::Item> {
        None
    }
}

impl FunctionIterator for EmptyFunctionIterator {}

/// List-based function iterator.
///
/// Wraps a vector of Function items and iterates over them by consuming ownership.
pub struct ListFunctionIterator {
    iter: std::vec::IntoIter<Arc<dyn Function>>,
}

impl ListFunctionIterator {
    /// Creates a new iterator over the supplied function items.
    pub fn new(items: Vec<Arc<dyn Function>>) -> Self {
        Self {
            iter: items.into_iter(),
        }
    }
}

impl Iterator for ListFunctionIterator {
    type Item = Arc<dyn Function>;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
    }
}

impl FunctionIterator for ListFunctionIterator {}

/// Creates an empty function iterator.
pub fn empty() -> Box<dyn FunctionIterator> {
    Box::new(EmptyFunctionIterator)
}

/// Creates a function iterator from a vector of function items.
pub fn of(items: Vec<Arc<dyn Function>>) -> Box<dyn FunctionIterator> {
    Box::new(ListFunctionIterator::new(items))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockFunction;

    impl crate::program::seam_stubs::Namespace for MockFunction {}

    impl Function for MockFunction {}

    #[test]
    fn empty_iterator_returns_none() {
        let mut iterator = EmptyFunctionIterator;
        assert!(iterator.next().is_none());
    }

    #[test]
    fn empty_from_factory_returns_none() {
        let mut iterator = empty();
        assert!(iterator.next().is_none());
    }

    #[test]
    fn list_iterator_yields_items() {
        let items: Vec<Arc<dyn Function>> =
            vec![Arc::new(MockFunction), Arc::new(MockFunction)];
        let mut iterator = ListFunctionIterator::new(items);

        assert!(iterator.next().is_some());
        assert!(iterator.next().is_some());
        assert!(iterator.next().is_none());
    }

    #[test]
    fn list_from_factory_yields_items() {
        let items: Vec<Arc<dyn Function>> =
            vec![Arc::new(MockFunction), Arc::new(MockFunction)];
        let mut iterator = of(items);

        assert!(iterator.next().is_some());
        assert!(iterator.next().is_some());
        assert!(iterator.next().is_none());
    }

    #[test]
    fn list_iterator_empty_list() {
        let items: Vec<Arc<dyn Function>> = vec![];
        let mut iterator = ListFunctionIterator::new(items);

        assert!(iterator.next().is_none());
    }
}

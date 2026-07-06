use crate::program::seam_stubs::CodeUnitIterator;

/// Wraps an iterator to implement the [`CodeUnitIterator`] interface.
///
/// Analogous to Java's `ghidra.trace.util.WrappingCodeUnitIterator`. This provides
/// a generic wrapper for any iterator, allowing it to be used as a [`CodeUnitIterator`].
pub struct WrappingCodeUnitIterator<I: Iterator> {
    iter: I,
}

impl<I: Iterator> WrappingCodeUnitIterator<I> {
    /// Creates a new wrapping iterator.
    ///
    /// # Arguments
    /// * `iter` - The iterator to wrap
    pub fn new(iter: I) -> Self {
        Self { iter }
    }
}

impl<I: Iterator> Iterator for WrappingCodeUnitIterator<I> {
    type Item = I::Item;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
    }
}

impl<I: Iterator> CodeUnitIterator for WrappingCodeUnitIterator<I> {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wraps_iterator_delegates_to_inner() {
        let mut it = WrappingCodeUnitIterator::new(vec![1, 2, 3].into_iter());
        assert_eq!(it.next(), Some(1));
        assert_eq!(it.next(), Some(2));
        assert_eq!(it.next(), Some(3));
        assert_eq!(it.next(), None);
    }

    #[test]
    fn wraps_empty_iterator() {
        let mut it = WrappingCodeUnitIterator::new(std::iter::empty::<i32>());
        assert_eq!(it.next(), None);
    }

    #[test]
    fn wraps_iterator_returns_none_after_exhaustion() {
        let mut it = WrappingCodeUnitIterator::new(vec![42].into_iter());
        assert_eq!(it.next(), Some(42));
        assert_eq!(it.next(), None);
        assert_eq!(it.next(), None);
    }

    #[test]
    fn wraps_iterator_with_generic_type() {
        let vec = vec!["a", "b", "c"];
        let mut it = WrappingCodeUnitIterator::new(vec.into_iter());
        assert_eq!(it.next(), Some("a"));
        assert_eq!(it.next(), Some("b"));
        assert_eq!(it.next(), Some("c"));
        assert_eq!(it.next(), None);
    }
}

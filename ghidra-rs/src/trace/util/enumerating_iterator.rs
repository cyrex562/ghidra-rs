/// An iterator that also reports the index of the most recently returned element.
///
/// Analogous to Java's `ghidra.trace.util.EnumeratingIterator`. The index starts
/// at -1 and advances by one for each element successfully returned by
/// [`Iterator::next`].
pub trait EnumeratingIterator: Iterator {
    /// Returns the index of the last element returned by [`Iterator::next`].
    ///
    /// Returns -1 if [`Iterator::next`] has not yet been called.
    fn index(&self) -> i32;
}

/// Wraps any [`Iterator`] to add index tracking via [`EnumeratingIterator`].
///
/// Analogous to Java's `EnumeratingIterator.WrappingEnumeratingIterator`.
pub struct WrappingEnumeratingIterator<I: Iterator> {
    iter: I,
    current_index: i32,
}

impl<I: Iterator> WrappingEnumeratingIterator<I> {
    /// Creates a new wrapping iterator. The index starts at -1.
    pub fn new(iter: I) -> Self {
        Self {
            iter,
            current_index: -1,
        }
    }
}

impl<I: Iterator> Iterator for WrappingEnumeratingIterator<I> {
    type Item = I::Item;

    fn next(&mut self) -> Option<Self::Item> {
        let result = self.iter.next();
        if result.is_some() {
            self.current_index += 1;
        }
        result
    }
}

impl<I: Iterator> EnumeratingIterator for WrappingEnumeratingIterator<I> {
    fn index(&self) -> i32 {
        self.current_index
    }
}

/// Wraps `iter` in a [`WrappingEnumeratingIterator`].
///
/// Mirrors `EnumeratingIterator.castOrWrap`. The Rust version always wraps
/// because runtime trait-object identity checks are not idiomatic here.
pub fn wrap<I: Iterator>(iter: I) -> WrappingEnumeratingIterator<I> {
    WrappingEnumeratingIterator::new(iter)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_index_is_minus_one() {
        let it = wrap(vec![1, 2, 3].into_iter());
        assert_eq!(it.index(), -1);
    }

    #[test]
    fn index_increments_on_next() {
        let mut it = wrap(vec![10, 20, 30].into_iter());
        assert_eq!(it.index(), -1);
        assert_eq!(it.next(), Some(10));
        assert_eq!(it.index(), 0);
        assert_eq!(it.next(), Some(20));
        assert_eq!(it.index(), 1);
        assert_eq!(it.next(), Some(30));
        assert_eq!(it.index(), 2);
    }

    #[test]
    fn index_does_not_change_after_exhaustion() {
        let mut it = wrap(vec![42].into_iter());
        it.next();
        assert_eq!(it.index(), 0);
        assert_eq!(it.next(), None);
        assert_eq!(it.index(), 0);
    }

    #[test]
    fn empty_iterator_stays_at_minus_one() {
        let mut it = wrap(std::iter::empty::<i32>());
        assert_eq!(it.next(), None);
        assert_eq!(it.index(), -1);
    }
}

//! Port of `ghidra.util.DistinctIterator`.
//!
//! Java implements this as a hand-rolled `PeekableIterator<T>` (`extends
//! AbstractPeekableIterator<T>`), since Java has no native lazy-adaptor story for `Iterator`. Rust
//! does, so this ports directly onto Rust's native [`Iterator`] trait rather than reproducing the
//! `Peekable`/`seekNext()` machinery: `DistinctIterator` here simply wraps any `I: Iterator` (via
//! `std::iter::Peekable`, the same underlying idea Java's `PeekableIterators.castOrWrap` provides)
//! and is itself an `Iterator`.
//!
//! Crucially, this preserves Java's documented (deliberately weak) behavior: **only immediate
//! repeats are removed**, exactly like the Unix `uniq` command. If the wrapped iterator does not
//! visit elements in sorted order, non-adjacent duplicates are *not* removed -- this is Java's
//! documented behavior, not a bug, and is exercised directly in the tests below.

/// A filtering iterator which removes repeated *adjacent* elements (immediate repeats only).
///
/// To obtain a truly distinct iteration, the wrapped iterator must visit elements in sorted
/// order.
///
/// Port of `ghidra.util.DistinctIterator`.
pub struct DistinctIterator<I: Iterator> {
    wrapped: std::iter::Peekable<I>,
}

impl<I: Iterator> DistinctIterator<I> {
    /// Wraps `iter`, removing immediately-repeated elements as it is consumed.
    pub fn new(iter: I) -> Self {
        DistinctIterator {
            wrapped: iter.peekable(),
        }
    }
}

impl<I> Iterator for DistinctIterator<I>
where
    I: Iterator,
    I::Item: PartialEq,
{
    type Item = I::Item;

    fn next(&mut self) -> Option<Self::Item> {
        let item = self.wrapped.next()?;
        // Skip any further elements immediately equal to `item` (matches Java's `seekNext()`
        // loop: `while wrapped.hasNext() && Objects.equals(last, wrapped.peek())`).
        while self.wrapped.peek().is_some_and(|next| *next == item) {
            self.wrapped.next();
        }
        Some(item)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removes_only_immediately_adjacent_duplicates() {
        // Non-adjacent repeats of `1` are NOT removed -- this is the documented Java behavior
        // ("only removes immediate repeats ... similar to uniq"), not a bug: [1,1,2,1,1,3,3]
        // becomes [1,2,1,3], not [1,2,3].
        let input = vec![1, 1, 2, 1, 1, 3, 3];
        let result: Vec<i32> = DistinctIterator::new(input.into_iter()).collect();
        assert_eq!(result, vec![1, 2, 1, 3]);
    }

    #[test]
    fn sorted_input_yields_a_truly_distinct_sequence() {
        let input = vec![1, 1, 1, 2, 2, 3, 4, 4, 4, 4];
        let result: Vec<i32> = DistinctIterator::new(input.into_iter()).collect();
        assert_eq!(result, vec![1, 2, 3, 4]);
    }

    #[test]
    fn empty_input_yields_nothing() {
        let input: Vec<i32> = vec![];
        let result: Vec<i32> = DistinctIterator::new(input.into_iter()).collect();
        assert!(result.is_empty());
    }

    #[test]
    fn no_duplicates_passes_through_unchanged() {
        let input = vec![1, 2, 3, 4];
        let result: Vec<i32> = DistinctIterator::new(input.into_iter()).collect();
        assert_eq!(result, vec![1, 2, 3, 4]);
    }

    #[test]
    fn single_run_of_all_equal_elements_collapses_to_one() {
        let input = vec!["a", "a", "a", "a"];
        let result: Vec<&str> = DistinctIterator::new(input.into_iter()).collect();
        assert_eq!(result, vec!["a"]);
    }

    #[test]
    fn works_with_strings_via_partial_eq() {
        let input = vec!["x".to_string(), "x".to_string(), "y".to_string()];
        let result: Vec<String> = DistinctIterator::new(input.into_iter()).collect();
        assert_eq!(result, vec!["x".to_string(), "y".to_string()]);
    }
}

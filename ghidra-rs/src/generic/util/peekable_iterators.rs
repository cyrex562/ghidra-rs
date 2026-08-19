#[cfg(test)]
use super::peekable_iterator::PeekableIterator;

/// Mirrors `generic.util.PeekableIterators`, a static-only Java utility class (an enum with
/// no variants) exposing a single factory method that ensures an iterator is peekable.
///
/// Ported as an extension trait, blanket-implemented for every [`Iterator`], rather than as
/// a polymorphic instance interface -- the Java original has no state or instances, only a
/// static factory method. Java's `castOrWrap` uses `instanceof` to return an already-peekable
/// iterator as-is, falling back to wrapping it in `WrappingPeekableIterator` otherwise. Rust
/// has no generic runtime equivalent of that check, so `cast_or_wrap` always wraps via
/// [`std::iter::Peekable`], which already implements [`PeekableIterator`] (see
/// `peekable_iterator.rs`) and is the idiomatic Rust analogue of Java's hand-rolled wrapper
/// class -- so no placeholder for `WrappingPeekableIterator` is needed here.
pub trait PeekableIterators: Iterator + Sized {
    /// Ensures that this iterator is peekable, wrapping it if necessary.
    ///
    /// Corresponds to Java's `PeekableIterators.castOrWrap`.
    fn cast_or_wrap(self) -> std::iter::Peekable<Self> {
        self.peekable()
    }
}

impl<I: Iterator> PeekableIterators for I {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Trivial mock iterator standing in for an arbitrary Java `Iterator<E>` implementor,
    /// proving `PeekableIterators` is usable by any type that implements `Iterator` and not
    /// just `std` adapters.
    struct CountdownIterator {
        remaining: u8,
    }

    impl Iterator for CountdownIterator {
        type Item = u8;

        fn next(&mut self) -> Option<u8> {
            if self.remaining == 0 {
                return None;
            }
            self.remaining -= 1;
            Some(self.remaining)
        }
    }

    #[test]
    fn cast_or_wrap_wraps_a_custom_iterator() {
        let mut it = CountdownIterator { remaining: 2 }.cast_or_wrap();
        assert_eq!(PeekableIterator::peek(&mut it), Some(&1));
        assert_eq!(it.next(), Some(1));
        assert_eq!(it.next(), Some(0));
        assert_eq!(it.next(), None);
    }

    #[test]
    fn cast_or_wrap_produces_peekable_iterator() {
        let mut it = vec![1, 2, 3].into_iter().cast_or_wrap();
        assert_eq!(PeekableIterator::peek(&mut it), Some(&1));
        assert_eq!(it.next(), Some(1));
    }

    #[test]
    fn cast_or_wrap_on_empty_iterator() {
        let mut it = std::iter::empty::<i32>().cast_or_wrap();
        assert_eq!(PeekableIterator::peek(&mut it), None);
        assert_eq!(it.next(), None);
    }

    #[test]
    fn cast_or_wrap_over_existing_peekable_iterator() {
        let mut it = vec![10, 20].into_iter().peekable().cast_or_wrap();
        assert_eq!(PeekableIterator::peek(&mut it), Some(&10));
        assert_eq!(it.next(), Some(10));
        assert_eq!(it.next(), Some(20));
    }
}

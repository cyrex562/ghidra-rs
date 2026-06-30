/// An iterator that allows you to peek at the next item without consuming it.
///
/// Mirrors `generic.util.PeekableIterator` from Ghidra. In Java this is an interface
/// extending `Iterator<T>` with one extra method — `peek()` — that returns the next
/// element without advancing the iterator, throwing `NoSuchElementException` when
/// exhausted.
///
/// [`std::iter::Peekable`] satisfies this trait automatically via the blanket impl
/// below.
pub trait PeekableIterator: Iterator {
    /// Returns a reference to the next item without advancing the iterator, or `None`
    /// when the iterator is exhausted.
    ///
    /// Corresponds to Java's `peek()`, which throws `NoSuchElementException` on
    /// exhaustion; this version returns `None` instead.
    fn peek(&mut self) -> Option<&Self::Item>;
}

impl<I: Iterator> PeekableIterator for std::iter::Peekable<I> {
    fn peek(&mut self) -> Option<&Self::Item> {
        std::iter::Peekable::peek(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call_peek<P: PeekableIterator>(it: &mut P) -> Option<&P::Item> {
        it.peek()
    }

    #[test]
    fn peek_does_not_consume_item() {
        let mut it = vec![1, 2, 3].into_iter().peekable();
        assert_eq!(call_peek(&mut it), Some(&1));
        assert_eq!(call_peek(&mut it), Some(&1));
        assert_eq!(it.next(), Some(1));
    }

    #[test]
    fn peek_tracks_iterator_position() {
        let mut it = vec![10, 20, 30].into_iter().peekable();
        assert_eq!(call_peek(&mut it), Some(&10));
        it.next();
        assert_eq!(call_peek(&mut it), Some(&20));
        it.next();
        assert_eq!(call_peek(&mut it), Some(&30));
    }

    #[test]
    fn peek_returns_none_when_exhausted() {
        let mut it = std::iter::empty::<i32>().peekable();
        assert_eq!(call_peek(&mut it), None);
    }

    #[test]
    fn repeated_peeks_without_advance_return_same_item() {
        let mut it = vec![42].into_iter().peekable();
        for _ in 0..5 {
            assert_eq!(call_peek(&mut it), Some(&42));
        }
        assert_eq!(it.next(), Some(42));
        assert_eq!(call_peek(&mut it), None);
    }

    #[test]
    fn peek_after_last_element_is_none() {
        let mut it = vec![1, 2].into_iter().peekable();
        it.next();
        it.next();
        assert_eq!(call_peek(&mut it), None);
        assert_eq!(it.next(), None);
    }
}

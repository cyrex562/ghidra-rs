use super::peekable_iterator::PeekableIterator;

/// An implementation of `PeekableIterator` that only requires implementing a seeker function
/// to find the next element. This allows lazy evaluation of the next element until it's needed.
///
/// The seeker function is called only once per element and the result is cached until
/// the element is consumed via `next()`. This matches the behavior of the Java class
/// `AbstractPeekableIterator<T>`.
///
/// # Example
/// ```ignore
/// let mut iter = AbstractPeekableIterator::new(|| Some(42));
/// assert_eq!(iter.next(), Some(42));
/// assert_eq!(iter.peek(), None);
/// ```
pub struct AbstractPeekableIterator<T, F>
where
    F: FnMut() -> Option<T>,
{
    seeker: F,
    next: Option<T>,
    sought_next: bool,
}

impl<T, F> AbstractPeekableIterator<T, F>
where
    F: FnMut() -> Option<T>,
{
    /// Creates a new `AbstractPeekableIterator` with the given seeker function.
    ///
    /// The seeker function should return `Some(item)` to provide the next element,
    /// or `None` when there are no more elements.
    pub fn new(seeker: F) -> Self {
        Self {
            seeker,
            next: None,
            sought_next: false,
        }
    }

    /// Ensures the next element has been sought from the seeker, caching it for use.
    fn check_seek_next(&mut self) {
        if !self.sought_next {
            self.sought_next = true;
            self.next = (self.seeker)();
        }
    }

    /// Returns whether there is a next element available.
    ///
    /// This will trigger the seeker if it hasn't been called yet.
    pub fn has_next(&mut self) -> bool {
        self.check_seek_next();
        self.next.is_some()
    }
}

impl<T, F> Iterator for AbstractPeekableIterator<T, F>
where
    F: FnMut() -> Option<T>,
{
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        self.check_seek_next();
        self.sought_next = false;
        self.next.take()
    }
}

impl<T, F> PeekableIterator for AbstractPeekableIterator<T, F>
where
    F: FnMut() -> Option<T>,
{
    fn peek(&mut self) -> Option<&T> {
        self.check_seek_next();
        self.next.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_has_next_with_value() {
        let mut iter = AbstractPeekableIterator::new(|| Some(1));
        assert!(iter.has_next());
    }

    #[test]
    fn test_has_next_when_exhausted() {
        let mut iter: AbstractPeekableIterator<i32, _> = AbstractPeekableIterator::new(|| None);
        assert!(!iter.has_next());
    }

    #[test]
    fn test_next_returns_value() {
        let mut iter = AbstractPeekableIterator::new(|| Some(42));
        assert_eq!(iter.next(), Some(42));
    }

    #[test]
    fn test_next_after_exhaustion_returns_none() {
        let mut iter = AbstractPeekableIterator::new(|| Some(1));
        assert_eq!(iter.next(), Some(1));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_peek_does_not_advance() {
        let mut iter = AbstractPeekableIterator::new(|| Some(99));
        assert_eq!(iter.peek(), Some(&99));
        assert_eq!(iter.peek(), Some(&99));
    }

    #[test]
    fn test_peek_then_next() {
        let mut iter = AbstractPeekableIterator::new(|| Some(42));
        assert_eq!(iter.peek(), Some(&42));
        assert_eq!(iter.next(), Some(42));
        assert_eq!(iter.peek(), None);
    }

    #[test]
    fn test_peek_after_exhaustion_returns_none() {
        let mut iter: AbstractPeekableIterator<i32, _> = AbstractPeekableIterator::new(|| None);
        assert_eq!(iter.peek(), None);
    }

    #[test]
    fn test_seeker_called_once_per_element() {
        let mut call_count = 0;
        {
            let mut iter = AbstractPeekableIterator::new(|| {
                call_count += 1;
                if call_count <= 2 {
                    Some(call_count)
                } else {
                    None
                }
            });
            assert_eq!(iter.next(), Some(1));
            assert_eq!(iter.next(), Some(2));
            assert_eq!(iter.next(), None);
        }
        assert_eq!(call_count, 3);
    }

    #[test]
    fn test_peek_caches_element() {
        let mut call_count = 0;
        let mut iter = AbstractPeekableIterator::new(|| {
            call_count += 1;
            Some(call_count)
        });
        assert_eq!(iter.peek(), Some(&1));
        assert_eq!(iter.peek(), Some(&1));
        assert_eq!(call_count, 1);
    }

    #[test]
    fn test_alternating_peek_and_next() {
        let mut values_iter = vec![1, 2, 3].into_iter();
        let mut iter = AbstractPeekableIterator::new(|| values_iter.next());

        assert_eq!(iter.peek(), Some(&1));
        assert_eq!(iter.next(), Some(1));
        assert_eq!(iter.peek(), Some(&2));
        assert_eq!(iter.next(), Some(2));
        assert_eq!(iter.peek(), Some(&3));
        assert_eq!(iter.next(), Some(3));
        assert_eq!(iter.peek(), None);
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_multiple_peeks_before_next() {
        let mut iter = AbstractPeekableIterator::new(|| Some(100));
        for _ in 0..5 {
            assert_eq!(iter.peek(), Some(&100));
        }
        assert_eq!(iter.next(), Some(100));
    }

    #[test]
    fn test_empty_iterator() {
        let mut iter: AbstractPeekableIterator<i32, _> = AbstractPeekableIterator::new(|| None);
        assert!(!iter.has_next());
        assert_eq!(iter.peek(), None);
        assert_eq!(iter.next(), None);
        assert_eq!(iter.next(), None);
    }
}

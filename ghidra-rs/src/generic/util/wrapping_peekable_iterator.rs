use super::abstract_peekable_iterator::AbstractPeekableIterator;
use super::peekable_iterator::PeekableIterator;

/// An implementation of [`PeekableIterator`] that wraps an arbitrary [`Iterator`] to give it
/// peeking behavior.
///
/// Port of `generic.util.WrappingPeekableIterator<T>`, which `extends
/// AbstractPeekableIterator<T>`. Following this crate's composition-over-inheritance convention,
/// that `extends` becomes a `base: AbstractPeekableIterator<..>` field rather than a re-derived
/// hierarchy; `AbstractPeekableIterator` (see `abstract_peekable_iterator.rs`) already implements
/// all of `PeekableIterator`'s caching behavior given a `seekNext()`-shaped closure, so this type
/// only needs to supply that closure -- pulling values from the wrapped iterator one at a time --
/// exactly as Java's `seekNext()` override does.
///
/// The wrapped iterator's `Item` type and the closure itself aren't nameable at the type level,
/// so the closure is boxed (`Box<dyn FnMut() -> Option<T>>`, which itself implements `FnMut()
/// -> Option<T>`).
///
/// Java's `remove()` override unconditionally throws `UnsupportedOperationException`; Rust's
/// `Iterator` trait has no `remove` method to override, so there is nothing to port for it.
pub struct WrappingPeekableIterator<T> {
    base: AbstractPeekableIterator<T, Box<dyn FnMut() -> Option<T>>>,
}

impl<T: 'static> WrappingPeekableIterator<T> {
    /// Wrap the given iterator.
    ///
    /// Port of `WrappingPeekableIterator(Iterator<T>)`.
    pub fn new<I>(iterator: I) -> Self
    where
        I: Iterator<Item = T> + 'static,
    {
        let mut iterator = iterator;
        let seeker: Box<dyn FnMut() -> Option<T>> = Box::new(move || iterator.next());
        Self {
            base: AbstractPeekableIterator::new(seeker),
        }
    }
}

impl<T> Iterator for WrappingPeekableIterator<T> {
    type Item = T;

    fn next(&mut self) -> Option<T> {
        self.base.next()
    }
}

impl<T> PeekableIterator for WrappingPeekableIterator<T> {
    fn peek(&mut self) -> Option<&T> {
        self.base.peek()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wraps_a_plain_vec_iterator() {
        let mut it = WrappingPeekableIterator::new(vec![1, 2, 3].into_iter());
        assert_eq!(it.next(), Some(1));
        assert_eq!(it.next(), Some(2));
        assert_eq!(it.next(), Some(3));
        assert_eq!(it.next(), None);
    }

    #[test]
    fn peek_does_not_consume() {
        let mut it = WrappingPeekableIterator::new(vec!["a", "b"].into_iter());
        assert_eq!(it.peek(), Some(&"a"));
        assert_eq!(it.peek(), Some(&"a"));
        assert_eq!(it.next(), Some("a"));
        assert_eq!(it.peek(), Some(&"b"));
    }

    #[test]
    fn peek_after_exhaustion_is_none() {
        let mut it = WrappingPeekableIterator::new(std::iter::empty::<i32>());
        assert_eq!(it.peek(), None);
        assert_eq!(it.next(), None);
    }

    #[test]
    fn wraps_an_arbitrary_custom_iterator_not_just_std_adapters() {
        struct Countdown(u8);
        impl Iterator for Countdown {
            type Item = u8;
            fn next(&mut self) -> Option<u8> {
                if self.0 == 0 {
                    return None;
                }
                self.0 -= 1;
                Some(self.0)
            }
        }

        let mut it = WrappingPeekableIterator::new(Countdown(2));
        assert_eq!(it.peek(), Some(&1));
        assert_eq!(it.next(), Some(1));
        assert_eq!(it.next(), Some(0));
        assert_eq!(it.next(), None);
    }

    #[test]
    fn underlying_iterator_is_pulled_lazily_one_item_at_a_time() {
        use std::cell::Cell;
        use std::rc::Rc;

        // `WrappingPeekableIterator::new` requires `I: Iterator<Item = T> + 'static` (it boxes
        // the seeker closure), so the wrapped iterator can't just borrow these counters -- they
        // need to be moved into it, with a shared handle kept outside to observe them.
        let pull_count = Rc::new(Cell::new(0));
        let pull_count_handle = pull_count.clone();
        let mut values = vec![1, 2, 3].into_iter();
        let mut it = WrappingPeekableIterator::new(std::iter::from_fn(move || {
            pull_count_handle.set(pull_count_handle.get() + 1);
            values.next()
        }));

        assert_eq!(pull_count.get(), 0);
        assert_eq!(it.peek(), Some(&1));
        assert_eq!(pull_count.get(), 1);
        assert_eq!(it.peek(), Some(&1));
        assert_eq!(pull_count.get(), 1, "peek must not re-pull once cached");
        // `it.next()` here returns the value already cached by the `peek()` calls above without
        // pulling again -- `AbstractPeekableIterator::next` only re-invokes the seeker when
        // `sought_next` is false, and peeking already set it true.
        assert_eq!(it.next(), Some(1));
        assert_eq!(pull_count.get(), 1, "next() must reuse the value peek() already cached, not re-pull");
        // This second `next()` has no cached value to reuse, so it pulls exactly once more.
        assert_eq!(it.next(), Some(2));
        assert_eq!(pull_count.get(), 2);
    }
}

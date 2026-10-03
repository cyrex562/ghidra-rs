use super::iterator_stl::IteratorStl;

/// This wrapper class is used to detect cases where code is modifying iterators that shouldn't
/// change.
///
/// Port of `generic.stl.UnmodifiableListIteratorSTL<T>`.
///
/// Java's `UnmodifiableListIteratorSTL` `extends ListIterator<T>`, copying another
/// `ListIterator`'s `list`/`root`/`node` fields via its constructor, then overriding every
/// mutating method (`assign`, `decrement`, `decrement(int)`, `delete`, `delete(int)`,
/// `increment`, `increment(int)`, `insert`, `set`) to throw `UnsupportedOperationException`,
/// while leaving the read-only methods (`get`, `isBegin`, `isEnd`) inherited unchanged. As with
/// [`ReverseListIterator`](super::reverse_list_iterator::ReverseListIterator), this crate has no
/// concrete node-based `ListIterator`/`ListSTL<T>` to wrap (see that type's doc comment for why),
/// so this wraps any `Box<dyn IteratorStl<T>>` instead, blocking exactly the same set of mutating
/// operations that trait exposes. Java's `delete`/`delete(int)` are `ListIterator`-specific
/// convenience methods with no equivalent on the [`IteratorStl`] trait this crate ported, so they
/// have no counterpart here.
pub struct UnmodifiableListIteratorStl<T> {
    inner: Box<dyn IteratorStl<T>>,
}

impl<T: 'static> UnmodifiableListIteratorStl<T> {
    /// Wraps `iterator`, blocking every mutating operation.
    ///
    /// Mirrors `UnmodifiableListIteratorSTL(ListIterator<T> iterator)`.
    pub fn new(iterator: Box<dyn IteratorStl<T>>) -> Self {
        Self { inner: iterator }
    }
}

impl<T: 'static> IteratorStl<T> for UnmodifiableListIteratorStl<T> {
    /// Mirrors the inherited (not overridden) `ListIterator.get()`.
    fn get(&self) -> &T {
        self.inner.get()
    }

    /// Mirrors the overridden `set(Object)`, which unconditionally throws
    /// `UnsupportedOperationException("Cannot modify this iterator!")`.
    fn set(&mut self, _value: T) {
        panic!("Cannot modify this iterator!");
    }

    /// Mirrors the overridden `increment()`.
    fn increment(&mut self) {
        panic!("Cannot modify this iterator!");
    }

    /// Mirrors the overridden `increment(int n)`.
    fn increment_by(&mut self, _n: usize) {
        panic!("Cannot modify this iterator!");
    }

    /// Mirrors the overridden `decrement()`.
    fn decrement(&mut self) {
        panic!("Cannot modify this iterator!");
    }

    /// Mirrors the overridden `decrement(int n)`.
    fn decrement_by(&mut self, _n: usize) {
        panic!("Cannot modify this iterator!");
    }

    /// Mirrors the inherited (not overridden) `ListIterator.isBegin()`.
    fn is_begin(&self) -> bool {
        self.inner.is_begin()
    }

    /// Mirrors the inherited (not overridden) `ListIterator.isEnd()`.
    fn is_end(&self) -> bool {
        self.inner.is_end()
    }

    /// Mirrors the overridden `insert(T)`.
    fn insert(&mut self, _value: T) {
        panic!("Cannot modify this iterator!");
    }

    /// Mirrors the inherited (**not** overridden) `ListIterator.copy()`.
    ///
    /// This reproduces a real quirk: `UnmodifiableListIteratorSTL` does not override `copy()`, so
    /// copying an unmodifiable iterator in Java yields a plain, fully mutable `ListIterator` --
    /// silently escaping the protection this wrapper exists to provide. This port reproduces that
    /// exactly: it returns the wrapped cursor's own copy directly, *not* wrapped in another
    /// `UnmodifiableListIteratorStl`. See the `copy_of_an_unmodifiable_iterator_is_modifiable`
    /// test below.
    fn copy_iter(&self) -> Box<dyn IteratorStl<T>> {
        self.inner.copy_iter()
    }

    /// Mirrors the overridden `assign(IteratorSTL<T>)`.
    fn assign(&mut self, _other: &dyn IteratorStl<T>) {
        panic!("Cannot modify this iterator!");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct VecCursor {
        data: Vec<i32>,
        pos: usize,
    }

    impl IteratorStl<i32> for VecCursor {
        fn get(&self) -> &i32 {
            &self.data[self.pos]
        }
        fn set(&mut self, value: i32) {
            self.data[self.pos] = value;
        }
        fn increment(&mut self) {
            self.pos += 1;
        }
        fn increment_by(&mut self, n: usize) {
            self.pos += n;
        }
        fn decrement(&mut self) {
            self.pos -= 1;
        }
        fn decrement_by(&mut self, n: usize) {
            self.pos -= n;
        }
        fn is_begin(&self) -> bool {
            self.pos == 0 && !self.data.is_empty()
        }
        fn is_end(&self) -> bool {
            self.pos >= self.data.len()
        }
        fn insert(&mut self, value: i32) {
            self.data.insert(self.pos, value);
        }
        fn copy_iter(&self) -> Box<dyn IteratorStl<i32>> {
            Box::new(VecCursor {
                data: self.data.clone(),
                pos: self.pos,
            })
        }
        fn assign(&mut self, other: &dyn IteratorStl<i32>) {
            if other.is_end() {
                self.pos = self.data.len();
            } else if other.is_begin() {
                self.pos = 0;
            }
        }
    }

    fn wrapped(data: Vec<i32>, pos: usize) -> UnmodifiableListIteratorStl<i32> {
        UnmodifiableListIteratorStl::new(Box::new(VecCursor { data, pos }))
    }

    #[test]
    fn get_reads_through_to_the_wrapped_cursor() {
        let it = wrapped(vec![10, 20, 30], 1);
        assert_eq!(*it.get(), 20);
    }

    #[test]
    fn is_begin_and_is_end_read_through_unchanged() {
        let begin = wrapped(vec![10, 20, 30], 0);
        assert!(begin.is_begin());
        assert!(!begin.is_end());

        let end = wrapped(vec![10, 20, 30], 3);
        assert!(!end.is_begin());
        assert!(end.is_end());
    }

    #[test]
    #[should_panic(expected = "Cannot modify this iterator!")]
    fn set_panics() {
        let mut it = wrapped(vec![10, 20, 30], 0);
        it.set(99);
    }

    #[test]
    #[should_panic(expected = "Cannot modify this iterator!")]
    fn increment_panics() {
        let mut it = wrapped(vec![10, 20, 30], 0);
        it.increment();
    }

    #[test]
    #[should_panic(expected = "Cannot modify this iterator!")]
    fn increment_by_panics() {
        let mut it = wrapped(vec![10, 20, 30], 0);
        it.increment_by(2);
    }

    #[test]
    #[should_panic(expected = "Cannot modify this iterator!")]
    fn decrement_panics() {
        let mut it = wrapped(vec![10, 20, 30], 1);
        it.decrement();
    }

    #[test]
    #[should_panic(expected = "Cannot modify this iterator!")]
    fn decrement_by_panics() {
        let mut it = wrapped(vec![10, 20, 30], 2);
        it.decrement_by(1);
    }

    #[test]
    #[should_panic(expected = "Cannot modify this iterator!")]
    fn insert_panics() {
        let mut it = wrapped(vec![10, 20, 30], 0);
        it.insert(99);
    }

    #[test]
    #[should_panic(expected = "Cannot modify this iterator!")]
    fn assign_panics() {
        let mut it = wrapped(vec![10, 20, 30], 0);
        let other = wrapped(vec![1, 2], 0);
        it.assign(&other);
    }

    #[test]
    fn copy_of_an_unmodifiable_iterator_is_modifiable() {
        // Real Java quirk: `UnmodifiableListIteratorSTL` never overrides `copy()`, so copying one
        // produces a plain, mutable `ListIterator` -- the copy is NOT itself unmodifiable. This
        // port reproduces that: `copy_iter()` hands back the wrapped cursor's own copy, whose
        // concrete type is `VecCursor` here, not `UnmodifiableListIteratorStl`.
        let it = wrapped(vec![10, 20, 30], 1);
        let mut copy = it.copy_iter();

        // The original remains protected...
        assert_eq!(*it.get(), 20);

        // ...but the copy freely mutates, proving it escaped the wrapper.
        copy.set(999);
        assert_eq!(*copy.get(), 999);
        copy.increment();
        assert_eq!(*copy.get(), 30);
    }

    #[test]
    fn is_object_safe_as_boxed_trait() {
        let it: Box<dyn IteratorStl<i32>> = Box::new(wrapped(vec![1, 2, 3], 0));
        assert_eq!(*it.get(), 1);
    }
}

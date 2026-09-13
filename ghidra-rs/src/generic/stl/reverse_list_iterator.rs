use super::iterator_stl::IteratorStl;

/// A bidirectional cursor that walks a sequential list back-to-front.
///
/// Port of `generic.stl.ReverseListIterator<T>`.
///
/// Java's `ReverseListIterator` `extends ListIterator<T>`, reusing its parent's package-private
/// `list`/`root`/`node` fields (raw `ListNodeSTL<T>` pointers into a circular doubly-linked list)
/// and overriding `increment`/`decrement`/`insert`/`isBegin`/`copy` to walk and splice in the
/// opposite direction. Neither `ListIterator` nor the concrete node-based `ListSTL<T>` storage it
/// requires has been ported to this crate: `ListStl` (see `list_stl.rs`) was deliberately cut to a
/// trait driven purely through the already-ported [`IteratorStl`] cursor interface, specifically
/// to avoid depending on a concrete node representation. This port continues that decision:
/// instead of holding raw node pointers (which would require `unsafe`, unlike every other type in
/// this module), [`ReverseListIterator`] wraps *any* forward-walking `Box<dyn IteratorStl<T>>` --
/// positioned at the same conceptual node Java's `node` field would reference -- and reverses the
/// direction of traversal purely through that trait's public surface.
///
/// This does mean one Java quirk can't be reproduced: the base `ListIterator.increment()`
/// (`node = node.prev`, called unconditionally by `ReverseListIterator.increment()`) has no bounds
/// check at all in Java. Driven past its natural bound, it doesn't throw -- it silently walks onto
/// the sentinel `root` node (a defined, if unhelpful, "reverse end" state) and, driven even
/// further, wraps back around the circular list forever. Reproducing that requires the exact
/// circular sentinel-node representation this trait-based port deliberately doesn't have; instead,
/// per the panic-at-bound convention already established by every other [`IteratorStl`] implementor
/// in this crate (see `vector_iterator.rs`, `reverse_vector_iterator.rs`, and the trait's own test
/// mock), [`ReverseListIterator::increment`] panics when driven past its bound rather than
/// wrapping around.
pub struct ReverseListIterator<T> {
    inner: Box<dyn IteratorStl<T>>,
}

impl<T: 'static> ReverseListIterator<T> {
    /// Wraps `inner` (a forward-walking cursor positioned at the node this reverse iterator
    /// should start from) to traverse it in reverse.
    ///
    /// Mirrors `ReverseListIterator(ListSTL<T>, ListNodeSTL<T>, ListNodeSTL<T>)`.
    pub fn new(inner: Box<dyn IteratorStl<T>>) -> Self {
        Self { inner }
    }
}

impl<T: 'static> IteratorStl<T> for ReverseListIterator<T> {
    /// Mirrors the inherited (not overridden by `ReverseListIterator`) `ListIterator.get()`.
    fn get(&self) -> &T {
        self.inner.get()
    }

    /// Mirrors the inherited `ListIterator.set(T)`.
    fn set(&mut self, value: T) {
        self.inner.set(value);
    }

    /// Moves toward the front of the underlying (forward-ordered) list -- i.e. deeper into
    /// reverse traversal.
    ///
    /// Mirrors `ReverseListIterator.increment()` (`node = node.prev`), adapted to panic at the
    /// bound instead of reproducing Java's unguarded wraparound; see the type-level doc comment.
    fn increment(&mut self) {
        if self.inner.is_begin() {
            panic!("ReverseListIterator cannot increment past the end");
        }
        self.inner.decrement();
    }

    fn increment_by(&mut self, n: usize) {
        for _ in 0..n {
            self.increment();
        }
    }

    /// Moves toward the back of the underlying (forward-ordered) list -- i.e. back toward where
    /// reverse traversal started.
    ///
    /// Mirrors `ReverseListIterator.decrement()`, which guards with `if (node.prev == root) throw`
    /// before moving via `node = node.next`.
    ///
    /// This reproduces a real, surprising Java quirk: that guard is copied verbatim from the
    /// *forward* `ListIterator.decrement()` (which guards its own, differently-directed
    /// `node = node.prev` move) without being updated for this override's reversed movement.
    /// `node.prev == root` is true exactly when the underlying forward cursor sits on the
    /// *first* forward element -- the *deepest* point reverse traversal can reach, not reverse
    /// -begin. So decrementing throws specifically from that one position, even though every
    /// other position -- including reverse-begin itself, where `node.next` legally reaches the
    /// sentinel `root` (this crate's `is_end()`) -- decrements without incident. See
    /// `decrement_from_the_forward_first_element_panics_a_real_java_quirk` and
    /// `decrement_at_reverse_begin_reaches_the_end_state` below.
    fn decrement(&mut self) {
        if self.inner.is_begin() {
            panic!("ReverseListIterator cannot decrement past the beginning");
        }
        self.inner.increment();
    }

    fn decrement_by(&mut self, n: usize) {
        for _ in 0..n {
            self.decrement();
        }
    }

    /// True when this is the last reverse position, i.e. the underlying forward cursor sits on
    /// the final real element (one step from the forward-list's end).
    ///
    /// Mirrors `ReverseListIterator.isBegin()` (`node == root.prev`), translated into the
    /// [`IteratorStl`] surface: "one more forward step would reach the end" rather than a direct
    /// node/sentinel comparison.
    fn is_begin(&self) -> bool {
        let mut probe = self.inner.copy_iter();
        if probe.is_end() {
            return false;
        }
        probe.increment();
        probe.is_end()
    }

    /// Mirrors the inherited (not overridden by `ReverseListIterator`) `ListIterator.isEnd()`
    /// (`node == root`). The sentinel position is the same regardless of traversal direction, so
    /// no adaptation is needed.
    fn is_end(&self) -> bool {
        self.inner.is_end()
    }

    /// Inserts `value` immediately *after* the current position (between it and the next forward
    /// element), landing the cursor on the new element.
    ///
    /// Mirrors `ReverseListIterator.insert(T)`, which splices a new node between `node` and
    /// `node.next` and moves `node` onto it. Advancing the forward cursor by one and then
    /// inserting there (forward `insert` splices *before* the current position) lands the new
    /// element in exactly that spot.
    fn insert(&mut self, value: T) {
        self.inner.increment();
        self.inner.insert(value);
    }

    /// Mirrors `ReverseListIterator.copy()`, which returns another `ReverseListIterator` (not a
    /// plain `ListIterator`) over the same node.
    fn copy_iter(&self) -> Box<dyn IteratorStl<T>> {
        Box::new(ReverseListIterator {
            inner: self.inner.copy_iter(),
        })
    }

    /// Mirrors the inherited `ListIterator.assign(IteratorSTL<T>)`, which downcasts `other` and
    /// copies its `list`/`root`/`node` fields verbatim -- impossible without downcasting a Rust
    /// trait object. As with [`crate::generic::stl::vector_iterator::VectorIterator::assign`] and
    /// its reverse counterpart, this only synchronizes begin/end cursor state exposed through
    /// [`IteratorStl`], by delegating to the wrapped cursor's own `assign`.
    fn assign(&mut self, other: &dyn IteratorStl<T>) {
        self.inner.assign(other);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `Vec`-backed forward cursor standing in for a Java `ListIterator` positioned by raw node
    /// pointers -- sufficient to exercise `ReverseListIterator` purely through [`IteratorStl`].
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
            assert!(self.pos < self.data.len(), "increment past end");
            self.pos += 1;
        }
        fn increment_by(&mut self, n: usize) {
            self.pos += n;
        }
        fn decrement(&mut self) {
            assert!(self.pos > 0, "decrement past beginning");
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

    fn cursor_at(data: Vec<i32>, pos: usize) -> Box<dyn IteratorStl<i32>> {
        Box::new(VecCursor { data, pos })
    }

    /// Reverse-begin: positioned on the last real element ([10, 20, 30] -> index 2).
    fn reverse_begin(data: Vec<i32>) -> ReverseListIterator<i32> {
        let len = data.len();
        ReverseListIterator::new(cursor_at(data, len - 1))
    }

    #[test]
    fn get_reads_the_current_reverse_element() {
        let it = reverse_begin(vec![10, 20, 30]);
        assert_eq!(*it.get(), 30);
    }

    #[test]
    fn set_replaces_the_current_element() {
        let mut it = reverse_begin(vec![10, 20, 30]);
        it.set(99);
        assert_eq!(*it.get(), 99);
    }

    #[test]
    fn increment_walks_backward_through_the_underlying_list() {
        let mut it = reverse_begin(vec![10, 20, 30]);
        assert_eq!(*it.get(), 30);
        it.increment();
        assert_eq!(*it.get(), 20);
        it.increment();
        assert_eq!(*it.get(), 10);
    }

    #[test]
    #[should_panic(expected = "cannot increment past the end")]
    fn increment_panics_once_the_underlying_list_is_exhausted() {
        let mut it = reverse_begin(vec![10, 20, 30]);
        it.increment();
        it.increment();
        it.increment();
    }

    #[test]
    fn decrement_walks_forward_back_toward_reverse_begin() {
        // [10, 20, 30, 40]; from 20 (not the forward-first element, 10), decrement should walk
        // normally back toward reverse-begin (40). See the dedicated quirk tests below for what
        // happens when decrementing *from* the forward-first element instead.
        let mut it = reverse_begin(vec![10, 20, 30, 40]);
        it.increment(); // 40 -> 30
        it.increment(); // 30 -> 20
        assert_eq!(*it.get(), 20);
        it.decrement();
        assert_eq!(*it.get(), 30);
        it.decrement();
        assert_eq!(*it.get(), 40);
    }

    #[test]
    fn decrement_at_reverse_begin_reaches_the_end_state() {
        // Decrementing right at reverse-begin doesn't panic: `node.next` from the *last* forward
        // element is the sentinel `root`, landing on the same `is_end()` state forward
        // exhaustion reaches.
        let mut it = reverse_begin(vec![10, 20, 30]);
        it.decrement();
        assert!(it.is_end());
    }

    #[test]
    #[should_panic(expected = "cannot decrement past the beginning")]
    fn decrement_from_the_forward_first_element_panics_a_real_java_quirk() {
        // See the doc comment on `IteratorStl::decrement` for `ReverseListIterator` above: the
        // Java guard is copied from the *forward* decrement's bounds check without being updated
        // for this override's reversed movement, so it fires specifically when the cursor sits on
        // the forward-first element (here, "10", the deepest point reverse traversal reaches) --
        // not at any point that's actually a reverse-iteration bound.
        let mut it = reverse_begin(vec![10, 20, 30]);
        it.increment(); // 30 -> 20
        it.increment(); // 20 -> 10 (the forward-first element)
        it.decrement(); // panics, per the real Java quirk
    }

    #[test]
    fn is_begin_true_only_at_the_last_underlying_element() {
        let mut it = reverse_begin(vec![10, 20, 30]);
        assert!(it.is_begin());
        it.increment();
        assert!(!it.is_begin());
    }

    #[test]
    fn is_end_matches_the_underlying_cursors_end() {
        let it = ReverseListIterator::new(cursor_at(vec![10, 20, 30], 3));
        assert!(it.is_end());
        let not_end = reverse_begin(vec![10, 20, 30]);
        assert!(!not_end.is_end());
    }

    #[test]
    fn insert_places_the_new_value_after_the_current_position() {
        // Reverse cursor at the middle element (20 of [10, 20, 30]); inserting 99 should splice
        // it in immediately after 20 in forward order (between 20 and 30), landing the cursor on
        // 99. Resulting forward order: [10, 20, 99, 30].
        let mut it = ReverseListIterator::new(cursor_at(vec![10, 20, 30], 1));
        it.insert(99);
        assert_eq!(*it.get(), 99);

        // Decrementing a reverse cursor moves forward in underlying-list terms, so it should
        // reach 99's forward successor, 30.
        it.decrement();
        assert_eq!(*it.get(), 30);

        // Incrementing a reverse cursor moves backward in underlying-list terms (deeper into
        // reverse traversal), so from 99 it should reach 99's forward predecessor, 20.
        let mut it2 = ReverseListIterator::new(cursor_at(vec![10, 20, 99, 30], 2));
        assert_eq!(*it2.get(), 99);
        it2.increment();
        assert_eq!(*it2.get(), 20);
    }

    #[test]
    fn copy_iter_produces_an_independent_reverse_iterator() {
        let it = reverse_begin(vec![10, 20, 30]);
        let mut copy = it.copy_iter();
        copy.set(999);
        assert_eq!(*it.get(), 30);
        assert_eq!(*copy.get(), 999);
    }

    #[test]
    fn copy_iter_preserves_reverse_traversal_direction() {
        let it = reverse_begin(vec![10, 20, 30]);
        let mut copy = it.copy_iter();
        copy.increment();
        assert_eq!(*copy.get(), 20);
    }

    #[test]
    fn assign_syncs_to_end_position() {
        let mut it = reverse_begin(vec![10, 20, 30]);
        let end = ReverseListIterator::new(cursor_at(vec![10, 20, 30], 3));
        it.assign(&end);
        assert!(it.is_end());
    }

    #[test]
    fn assign_syncs_to_begin_position() {
        let mut it = ReverseListIterator::new(cursor_at(vec![10, 20, 30], 3));
        let begin = reverse_begin(vec![10, 20, 30]);
        it.assign(&begin);
        assert!(!it.is_end());
    }

    #[test]
    fn is_object_safe_as_boxed_trait() {
        let it: Box<dyn IteratorStl<i32>> = reverse_begin(vec![1, 2, 3]).copy_iter();
        assert_eq!(*it.get(), 3);
    }
}

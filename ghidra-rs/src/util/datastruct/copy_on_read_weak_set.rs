use crate::util::seam_stubs::WeakSet;

/// A copy-on-read set that snapshots its storage for iteration operations.
///
/// Port of `ghidra.util.datastruct.CopyOnReadWeakSet`, cut to a trait to break a dependency
/// cycle: the original class extends `WeakSet<T>`, an abstract class not yet ported (see the
/// [`WeakSet`] placeholder trait). Copy-on-read semantics let clients mutate the set while a
/// previously taken snapshot is still being read, avoiding the concurrent-modification hazards
/// a live iterator would have.
///
/// The Java class's `iterator()` and `stream()` overrides both build on the same internal
/// `createCopy()` helper as `values()`; Rust has no shared `Iterator`/`Stream` return type to
/// abstract over here, so all three collapse into [`values`][Self::values] — callers derive an
/// iterator or process the returned `Vec` directly.
pub trait CopyOnReadWeakSet<T>: WeakSet<T> {
    /// Adds `t`, returning `true` if it was not already present.
    fn add(&self, t: T) -> bool;

    /// Removes `t`, returning `true` if it was present.
    fn remove(&self, t: &T) -> bool;

    /// Removes every element.
    fn clear(&self);

    /// Returns `true` if this set holds no elements.
    fn is_empty(&self) -> bool;

    /// Returns the number of elements held.
    fn size(&self) -> usize;

    /// Returns `true` if `t` is present.
    fn contains(&self, t: &T) -> bool;

    /// Returns a snapshot copy of the current elements, safe to read while this set is
    /// mutated concurrently. Stands in for the Java class's `values()`, `iterator()`, and
    /// `stream()` overrides, which all build the same snapshot.
    fn values(&self) -> Vec<T>;

    /// Adds every element of `items`, returning `true` if any were newly added.
    fn add_all(&self, items: Vec<T>) -> bool;

    /// Removes every element not present in `items`, returning `true` if this set changed.
    fn retain_all(&self, items: &[T]) -> bool
    where
        T: PartialEq;

    /// Removes every element present in `items`, returning `true` if this set changed.
    fn remove_all(&self, items: &[T]) -> bool
    where
        T: PartialEq;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Trivial mock proving `CopyOnReadWeakSet` is object-safe and usable behind
    /// `Box<dyn CopyOnReadWeakSet<T>>`.
    struct MockCopyOnReadWeakSet {
        items: Mutex<Vec<i32>>,
    }

    impl WeakSet<i32> for MockCopyOnReadWeakSet {}

    impl CopyOnReadWeakSet<i32> for MockCopyOnReadWeakSet {
        fn add(&self, t: i32) -> bool {
            let mut items = self.items.lock().unwrap();
            if items.contains(&t) {
                return false;
            }
            items.push(t);
            true
        }

        fn remove(&self, t: &i32) -> bool {
            let mut items = self.items.lock().unwrap();
            let len_before = items.len();
            items.retain(|x| x != t);
            items.len() != len_before
        }

        fn clear(&self) {
            self.items.lock().unwrap().clear();
        }

        fn is_empty(&self) -> bool {
            self.items.lock().unwrap().is_empty()
        }

        fn size(&self) -> usize {
            self.items.lock().unwrap().len()
        }

        fn contains(&self, t: &i32) -> bool {
            self.items.lock().unwrap().contains(t)
        }

        fn values(&self) -> Vec<i32> {
            self.items.lock().unwrap().clone()
        }

        fn add_all(&self, items: Vec<i32>) -> bool {
            let mut changed = false;
            for item in items {
                changed |= self.add(item);
            }
            changed
        }

        fn retain_all(&self, items: &[i32]) -> bool {
            let mut store = self.items.lock().unwrap();
            let len_before = store.len();
            store.retain(|x| items.contains(x));
            store.len() != len_before
        }

        fn remove_all(&self, items: &[i32]) -> bool {
            let mut store = self.items.lock().unwrap();
            let len_before = store.len();
            store.retain(|x| !items.contains(x));
            store.len() != len_before
        }
    }

    #[test]
    fn add_read_remove_behind_trait_object() {
        let set: Box<dyn CopyOnReadWeakSet<i32>> = Box::new(MockCopyOnReadWeakSet {
            items: Mutex::new(Vec::new()),
        });

        assert!(set.is_empty());
        assert!(set.add(1));
        assert!(!set.add(1));
        assert!(set.add(2));
        assert_eq!(set.size(), 2);
        assert!(set.contains(&1));

        let snapshot = set.values();
        assert_eq!(snapshot.len(), 2);

        assert!(set.remove(&1));
        assert_eq!(set.size(), 1);

        assert!(set.add_all(vec![3, 4]));
        assert_eq!(set.size(), 3);

        assert!(set.retain_all(&[2, 3]));
        assert_eq!(set.size(), 2);

        assert!(set.remove_all(&[2]));
        assert_eq!(set.size(), 1);

        set.clear();
        assert!(set.is_empty());
    }
}

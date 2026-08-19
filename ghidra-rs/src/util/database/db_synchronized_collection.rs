use super::db_synchronized_iterator::RemovableIterator;

/// Mirrors the subset of `java.util.Collection<E>` operations that
/// [`DBSynchronizedCollection`] delegates to.
pub trait Collection<E> {
    /// The collection's iterator type. An associated type rather than
    /// `Box<dyn RemovableIterator<E>>`: the implementer knows its own iterator, so there is
    /// nothing to erase, and static dispatch keeps `Iterator`'s adaptors usable.
    type Iter: RemovableIterator<Item = E>;

    /// Returns the number of elements.
    fn size(&self) -> usize;
    /// Returns `true` if there are no elements.
    fn is_empty(&self) -> bool;
    /// Returns `true` if this collection contains the given element.
    fn contains(&self, o: &E) -> bool;
    /// Returns an iterator over the elements.
    fn iterator(&self) -> Self::Iter;
    /// Returns all elements as a `Vec`, corresponding to Java's `toArray()`/`toArray(T[])`.
    fn to_vec(&self) -> Vec<E>;
    /// Adds an element, returning `true` if the collection changed as a result.
    fn add(&mut self, e: E) -> bool;
    /// Removes an element, returning `true` if the collection changed as a result.
    fn remove(&mut self, o: &E) -> bool;
    /// Returns `true` if this collection contains every element of `c`.
    fn contains_all(&self, c: &[E]) -> bool;
    /// Adds every element of `c`, returning `true` if the collection changed as a result.
    fn add_all(&mut self, c: Vec<E>) -> bool;
    /// Removes every element that is also in `c`, returning `true` if the collection changed.
    fn remove_all(&mut self, c: &[E]) -> bool;
    /// Retains only the elements that are also in `c`, returning `true` if the collection changed.
    fn retain_all(&mut self, c: &[E]) -> bool;
    /// Removes all elements.
    fn clear(&mut self);
}

/// `DBSynchronizedCollection` (Java: `ghidra.util.database.DBSynchronizedCollection`) is
/// deliberately absent; see [`RemovableIterator`]'s module for the full reasoning.
///
/// The Java class wraps a collection plus the database's `ReadWriteLock`, taking the read lock
/// around queries and the write lock around mutations. Translated literally it became a struct
/// holding `Arc<RwLock<()>>` -- a lock over no data -- while owning its delegate by value, so
/// it guarded nothing that `&self`/`&mut self` did not already guard. Worse, its mutating half
/// was unusable: sharing the wrapper across threads needs `Arc<..>`, which makes every
/// `&mut self` method (`add`, `remove`, `clear`, ...) unreachable.
///
/// In Rust, a synchronized collection is `Arc<RwLock<C>>`: the lock holds the data, mutation
/// happens through the write guard, and the borrow checker enforces the discipline the Java
/// class had to document. [`Collection`] remains as the delegate abstraction.

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, RwLock};

    struct VecIter<T> {
        items: Vec<T>,
        pos: usize,
    }

    impl<T: Clone> Iterator for VecIter<T> {
        type Item = T;

        fn next(&mut self) -> Option<T> {
            let item = self.items.get(self.pos)?.clone();
            self.pos += 1;
            Some(item)
        }
    }

    impl<T: Clone> RemovableIterator for VecIter<T> {
        fn remove(&mut self) {
            self.pos -= 1;
            self.items.remove(self.pos);
        }
    }

    #[derive(Clone)]
    struct VecCollection<T> {
        items: Vec<T>,
    }

    impl<T> VecCollection<T> {
        fn new(items: Vec<T>) -> Self {
            Self { items }
        }
    }

    impl<T: Clone + PartialEq + 'static> Collection<T> for VecCollection<T> {
        type Iter = VecIter<T>;

        fn size(&self) -> usize {
            self.items.len()
        }

        fn is_empty(&self) -> bool {
            self.items.is_empty()
        }

        fn contains(&self, o: &T) -> bool {
            self.items.contains(o)
        }

        fn iterator(&self) -> Self::Iter {
            VecIter {
                items: self.items.clone(),
                pos: 0,
            }
        }

        fn to_vec(&self) -> Vec<T> {
            self.items.clone()
        }

        fn add(&mut self, e: T) -> bool {
            self.items.push(e);
            true
        }

        fn remove(&mut self, o: &T) -> bool {
            if let Some(idx) = self.items.iter().position(|x| x == o) {
                self.items.remove(idx);
                true
            } else {
                false
            }
        }

        fn contains_all(&self, c: &[T]) -> bool {
            c.iter().all(|o| self.items.contains(o))
        }

        fn add_all(&mut self, c: Vec<T>) -> bool {
            let changed = !c.is_empty();
            self.items.extend(c);
            changed
        }

        fn remove_all(&mut self, c: &[T]) -> bool {
            let before = self.items.len();
            self.items.retain(|x| !c.contains(x));
            self.items.len() != before
        }

        fn retain_all(&mut self, c: &[T]) -> bool {
            let before = self.items.len();
            self.items.retain(|x| c.contains(x));
            self.items.len() != before
        }

        fn clear(&mut self) {
            self.items.clear();
        }
    }

    fn collection(items: Vec<i32>) -> VecCollection<i32> {
        VecCollection::new(items)
    }

    #[test]
    fn iterator_yields_all_elements() {
        let out: Vec<i32> = collection(vec![10, 20, 30]).iterator().collect();
        assert_eq!(out, vec![10, 20, 30]);
    }

    #[test]
    fn removable_iterator_removes_through_the_collection_iterator() {
        let mut iter = collection(vec![1, 2, 3]).iterator();
        assert_eq!(iter.next(), Some(1));
        iter.remove();
        assert_eq!(iter.collect::<Vec<_>>(), vec![2, 3]);
    }

    #[test]
    fn to_vec_returns_all_elements() {
        assert_eq!(collection(vec![1, 2, 3]).to_vec(), vec![1, 2, 3]);
    }

    #[test]
    fn add_and_remove_report_whether_the_collection_changed() {
        let mut c = collection(vec![1, 2]);
        assert!(c.add(3));
        assert!(c.remove(&1));
        assert!(!c.remove(&99));
        assert_eq!(c.to_vec(), vec![2, 3]);
    }

    #[test]
    fn retain_all_and_clear() {
        let mut c = collection(vec![1, 2, 3, 4]);
        assert!(c.retain_all(&[2, 4]));
        assert_eq!(c.to_vec(), vec![2, 4]);
        c.clear();
        assert!(c.is_empty());
    }

    /// The replacement for `DBSynchronizedCollection`: put the collection behind the lock,
    /// not a lock beside it. This is the case the removed wrapper could not serve at all --
    /// sharing it required `Arc`, which made every `&mut self` method unreachable, so a
    /// concurrent `add` was impossible. Here two threads mutate the same collection.
    #[test]
    fn arc_rwlock_gives_the_shared_mutation_the_wrapper_promised() {
        let shared = Arc::new(RwLock::new(collection(vec![])));
        let handles: Vec<_> = (0..4)
            .map(|n| {
                let shared = Arc::clone(&shared);
                std::thread::spawn(move || {
                    shared.write().unwrap().add(n);
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }

        let mut got = shared.read().unwrap().to_vec();
        got.sort();
        assert_eq!(got, vec![0, 1, 2, 3]);
    }

    #[test]
    fn read_guard_allows_concurrent_readers() {
        let shared = Arc::new(RwLock::new(collection(vec![1, 2, 3])));
        let first = shared.read().unwrap();
        let second = shared.read().unwrap();
        assert_eq!(first.size(), 3);
        assert_eq!(second.size(), 3);
    }
}

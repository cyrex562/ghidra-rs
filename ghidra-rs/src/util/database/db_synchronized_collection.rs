use std::marker::PhantomData;
use std::sync::Arc;
use std::sync::RwLock;

use super::db_synchronized_iterator::{DBSynchronizedIterator, RemovableIterator};

/// Mirrors the subset of `java.util.Collection<E>` operations that
/// [`DBSynchronizedCollection`] delegates to.
pub trait Collection<E> {
    /// Returns the number of elements.
    fn size(&self) -> usize;
    /// Returns `true` if there are no elements.
    fn is_empty(&self) -> bool;
    /// Returns `true` if this collection contains the given element.
    fn contains(&self, o: &E) -> bool;
    /// Returns a boxed iterator over the elements.
    fn iterator(&self) -> Box<dyn RemovableIterator<E>>;
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

/// A thread-safe wrapper around a [`Collection`] that synchronizes access using a
/// read-write lock.
///
/// Read-only operations (`size`, `is_empty`, `contains`, `iterator`, `to_vec`,
/// `contains_all`) acquire the read lock, while mutating operations (`add`, `remove`,
/// `add_all`, `remove_all`, `retain_all`, `clear`) acquire the write lock. Iterators
/// returned by [`iterator`][Self::iterator] share the same lock and re-acquire the read
/// lock (or write lock, for removal) on each operation, mirroring
/// [`DBSynchronizedIterator`].
///
/// Port of `ghidra.util.database.DBSynchronizedCollection`.
pub struct DBSynchronizedCollection<E, C: Collection<E>> {
    delegate: C,
    lock: Arc<RwLock<()>>,
    _marker: PhantomData<E>,
}

impl<E, C: Collection<E>> DBSynchronizedCollection<E, C> {
    /// Creates a new `DBSynchronizedCollection` wrapping `delegate` and protecting it with
    /// `lock`.
    pub fn new(delegate: C, lock: Arc<RwLock<()>>) -> Self {
        Self {
            delegate,
            lock,
            _marker: PhantomData,
        }
    }

    /// Returns the number of elements.
    ///
    /// This operation acquires the read lock.
    pub fn size(&self) -> usize {
        let _guard = self.lock.read().unwrap();
        self.delegate.size()
    }

    /// Returns `true` if there are no elements.
    ///
    /// This operation acquires the read lock.
    pub fn is_empty(&self) -> bool {
        let _guard = self.lock.read().unwrap();
        self.delegate.is_empty()
    }

    /// Returns `true` if this collection contains the given element.
    ///
    /// This operation acquires the read lock.
    pub fn contains(&self, o: &E) -> bool {
        let _guard = self.lock.read().unwrap();
        self.delegate.contains(o)
    }

    /// Returns a synchronized iterator over the elements.
    ///
    /// Obtaining the delegate's iterator acquires the read lock; the returned
    /// [`DBSynchronizedIterator`] shares this collection's lock and acquires it again on
    /// each subsequent operation.
    pub fn iterator(&self) -> DBSynchronizedIterator<E> {
        let iter = {
            let _guard = self.lock.read().unwrap();
            self.delegate.iterator()
        };
        DBSynchronizedIterator::new(iter, Arc::clone(&self.lock))
    }

    /// Returns all elements as a `Vec`, corresponding to Java's `toArray()`/`toArray(T[])`.
    ///
    /// This operation acquires the read lock.
    pub fn to_vec(&self) -> Vec<E> {
        let _guard = self.lock.read().unwrap();
        self.delegate.to_vec()
    }

    /// Adds an element, returning `true` if the collection changed as a result.
    ///
    /// This operation acquires the write lock.
    pub fn add(&mut self, e: E) -> bool {
        let _guard = self.lock.write().unwrap();
        self.delegate.add(e)
    }

    /// Removes an element, returning `true` if the collection changed as a result.
    ///
    /// This operation acquires the write lock.
    pub fn remove(&mut self, o: &E) -> bool {
        let _guard = self.lock.write().unwrap();
        self.delegate.remove(o)
    }

    /// Returns `true` if this collection contains every element of `c`.
    ///
    /// This operation acquires the read lock.
    pub fn contains_all(&self, c: &[E]) -> bool {
        let _guard = self.lock.read().unwrap();
        self.delegate.contains_all(c)
    }

    /// Adds every element of `c`, returning `true` if the collection changed as a result.
    ///
    /// This operation acquires the write lock.
    pub fn add_all(&mut self, c: Vec<E>) -> bool {
        let _guard = self.lock.write().unwrap();
        self.delegate.add_all(c)
    }

    /// Removes every element that is also in `c`, returning `true` if the collection changed.
    ///
    /// This operation acquires the write lock.
    pub fn remove_all(&mut self, c: &[E]) -> bool {
        let _guard = self.lock.write().unwrap();
        self.delegate.remove_all(c)
    }

    /// Retains only the elements that are also in `c`, returning `true` if the collection
    /// changed.
    ///
    /// This operation acquires the write lock.
    pub fn retain_all(&mut self, c: &[E]) -> bool {
        let _guard = self.lock.write().unwrap();
        self.delegate.retain_all(c)
    }

    /// Removes all elements.
    ///
    /// This operation acquires the write lock.
    pub fn clear(&mut self) {
        let _guard = self.lock.write().unwrap();
        self.delegate.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct VecIter<T> {
        items: Vec<T>,
        pos: usize,
    }

    impl<T: Clone> RemovableIterator<T> for VecIter<T> {
        fn has_next(&mut self) -> bool {
            self.pos < self.items.len()
        }

        fn next(&mut self) -> T {
            let item = self.items[self.pos].clone();
            self.pos += 1;
            item
        }

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
        fn size(&self) -> usize {
            self.items.len()
        }

        fn is_empty(&self) -> bool {
            self.items.is_empty()
        }

        fn contains(&self, o: &T) -> bool {
            self.items.contains(o)
        }

        fn iterator(&self) -> Box<dyn RemovableIterator<T>> {
            Box::new(VecIter {
                items: self.items.clone(),
                pos: 0,
            })
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

    fn make(items: Vec<i32>) -> DBSynchronizedCollection<i32, VecCollection<i32>> {
        DBSynchronizedCollection::new(VecCollection::new(items), Arc::new(RwLock::new(())))
    }

    #[test]
    fn size_reports_element_count() {
        let c = make(vec![1, 2, 3]);
        assert_eq!(c.size(), 3);
    }

    #[test]
    fn is_empty_true_for_empty_collection() {
        let c = make(vec![]);
        assert!(c.is_empty());
    }

    #[test]
    fn is_empty_false_for_nonempty_collection() {
        let c = make(vec![1]);
        assert!(!c.is_empty());
    }

    #[test]
    fn contains_finds_present_element() {
        let c = make(vec![1, 2, 3]);
        assert!(c.contains(&2));
        assert!(!c.contains(&9));
    }

    #[test]
    fn iterator_yields_all_elements() {
        let c = make(vec![10, 20, 30]);
        let mut iter = c.iterator();
        let mut out = vec![];
        while iter.has_next() {
            out.push(iter.next());
        }
        assert_eq!(out, vec![10, 20, 30]);
    }

    #[test]
    fn to_vec_returns_all_elements() {
        let c = make(vec![1, 2, 3]);
        assert_eq!(c.to_vec(), vec![1, 2, 3]);
    }

    #[test]
    fn add_appends_element_and_reports_change() {
        let mut c = make(vec![1]);
        assert!(c.add(2));
        assert_eq!(c.to_vec(), vec![1, 2]);
    }

    #[test]
    fn remove_deletes_element_and_reports_change() {
        let mut c = make(vec![1, 2, 3]);
        assert!(c.remove(&2));
        assert_eq!(c.to_vec(), vec![1, 3]);
        assert!(!c.remove(&99));
    }

    #[test]
    fn contains_all_checks_every_element() {
        let c = make(vec![1, 2, 3]);
        assert!(c.contains_all(&[1, 3]));
        assert!(!c.contains_all(&[1, 9]));
    }

    #[test]
    fn add_all_extends_and_reports_change() {
        let mut c = make(vec![1]);
        assert!(c.add_all(vec![2, 3]));
        assert_eq!(c.to_vec(), vec![1, 2, 3]);
        assert!(!c.add_all(vec![]));
    }

    #[test]
    fn remove_all_deletes_matching_and_reports_change() {
        let mut c = make(vec![1, 2, 3, 4]);
        assert!(c.remove_all(&[2, 4]));
        assert_eq!(c.to_vec(), vec![1, 3]);
        assert!(!c.remove_all(&[99]));
    }

    #[test]
    fn retain_all_keeps_only_matching_and_reports_change() {
        let mut c = make(vec![1, 2, 3, 4]);
        assert!(c.retain_all(&[2, 4]));
        assert_eq!(c.to_vec(), vec![2, 4]);
        assert!(!c.retain_all(&[2, 4]));
    }

    #[test]
    fn clear_removes_all_elements() {
        let mut c = make(vec![1, 2, 3]);
        c.clear();
        assert!(c.is_empty());
    }

    #[test]
    fn read_lock_released_after_size() {
        let lock = Arc::new(RwLock::new(()));
        let c = DBSynchronizedCollection::new(VecCollection::new(vec![1, 2]), lock.clone());
        c.size();
        assert!(
            lock.try_write().is_ok(),
            "write lock should be acquirable after size() returns"
        );
    }

    #[test]
    fn write_lock_released_after_add() {
        let lock = Arc::new(RwLock::new(()));
        let mut c = DBSynchronizedCollection::new(VecCollection::new(vec![1]), lock.clone());
        c.add(2);
        assert!(
            lock.try_write().is_ok(),
            "write lock should be acquirable after add() returns"
        );
    }

    #[test]
    fn returned_iterator_shares_collection_lock() {
        let lock = Arc::new(RwLock::new(()));
        let c = DBSynchronizedCollection::new(VecCollection::new(vec![1, 2]), lock.clone());
        let mut iter = c.iterator();
        iter.has_next();
        assert!(
            lock.try_write().is_ok(),
            "write lock should be acquirable after the iterator's has_next() returns"
        );
    }
}

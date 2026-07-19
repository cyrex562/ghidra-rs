use thiserror::Error;

use crate::util::graph::keyed_object::KeyedObject;

/// Raised by [`GraphIterator::next`] when the backing set has been modified since the
/// iterator was created.
///
/// Port of `java.util.ConcurrentModificationException` as used by
/// `ghidra.util.graph.GraphIterator#next()`.
#[derive(Error, Debug, Clone, PartialEq)]
#[error("Backing set modified since iterator was created")]
pub struct ConcurrentModificationError;

/// Interface for `VertexSet` and `EdgeSet` iterators.
///
/// Port of `ghidra.util.graph.GraphIterator` (deprecated since Ghidra 10.2).
#[deprecated(note = "Deprecated since Ghidra 10.2")]
pub trait GraphIterator<T: KeyedObject> {
    /// Returns true if the iterator has more elements.
    fn has_next(&self) -> bool;

    /// Returns the next element in the iteration.
    ///
    /// Returns [`ConcurrentModificationError`] if the backing set has been modified since
    /// the iterator was created.
    fn next(&mut self) -> Result<T, ConcurrentModificationError>;

    /// Removes the object from the backing set safely.
    fn remove(&mut self) -> bool;
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;

    struct MockKeyedObject {
        key: i64,
    }

    impl KeyedObject for MockKeyedObject {
        fn key(&self) -> i64 {
            self.key
        }
    }

    struct MockIterator {
        remaining: Vec<i64>,
        pos: usize,
        modified: bool,
    }

    impl GraphIterator<MockKeyedObject> for MockIterator {
        fn has_next(&self) -> bool {
            self.pos < self.remaining.len()
        }

        fn next(&mut self) -> Result<MockKeyedObject, ConcurrentModificationError> {
            if self.modified {
                return Err(ConcurrentModificationError);
            }
            let key = self.remaining[self.pos];
            self.pos += 1;
            Ok(MockKeyedObject { key })
        }

        fn remove(&mut self) -> bool {
            if self.pos == 0 {
                return false;
            }
            self.remaining.remove(self.pos - 1);
            self.pos -= 1;
            true
        }
    }

    #[test]
    fn boxed_trait_object_is_usable() {
        let mut it: Box<dyn GraphIterator<MockKeyedObject>> =
            Box::new(MockIterator { remaining: vec![1, 2, 3], pos: 0, modified: false });

        assert!(it.has_next());
        assert_eq!(it.next().unwrap().key, 1);
        assert_eq!(it.next().unwrap().key, 2);
        assert!(it.remove());
        assert_eq!(it.next().unwrap().key, 3);
        assert!(!it.has_next());
    }

    #[test]
    fn next_reports_concurrent_modification() {
        let mut it = MockIterator { remaining: vec![1], pos: 0, modified: true };
        assert_eq!(it.next(), Err(ConcurrentModificationError));
    }
}

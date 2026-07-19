use crate::util::graph::keyed_object::KeyedObject;
use crate::util::seam_stubs::GraphIteratorLike;

/// Interface for sets of graph objects which have keys, such as vertices and edges.
///
/// Port of `ghidra.util.graph.KeyIndexableSet` (deprecated since Ghidra 10.2), cut to a trait to
/// break a dependency cycle at this node in the port graph. `ghidra.util.graph.GraphIterator` is
/// not yet ported, so [`iterator`](KeyIndexableSet::iterator) returns a boxed
/// [`GraphIteratorLike`] placeholder from `seam_stubs` instead.
#[deprecated(note = "Deprecated since Ghidra 10.2")]
pub trait KeyIndexableSet<T: KeyedObject> {
    /// Returns the number of changes this `KeyIndexableSet` has undergone since its creation.
    fn modification_number(&self) -> i64;

    /// Returns the number of `KeyedObject`s in this set.
    fn size(&self) -> usize;

    /// Returns the number of `KeyedObject`s this set can hold without growing.
    fn capacity(&self) -> usize;

    /// Adds a `KeyedObject` to this set, growing capacity if needed.
    ///
    /// Returns true if the object was successfully added; false if it was already present in
    /// the set or addition otherwise failed.
    fn add(&mut self, obj: T) -> bool;

    /// Removes a `KeyedObject` from this set. Returns true if it was present and removed.
    fn remove(&mut self, obj: &T) -> bool;

    /// Returns true if this set contains the given `KeyedObject`.
    fn contains(&self, obj: &T) -> bool;

    /// Returns an iterator over this set.
    fn iterator(&self) -> Box<dyn GraphIteratorLike<T> + '_>;

    /// Returns the elements of this set as a vector of references.
    fn to_array(&self) -> Vec<&T>;

    /// Returns the `KeyedObject` with the given key, or `None` if this set contains no object
    /// with that key.
    fn get_keyed_object(&self, key: i64) -> Option<&T>;
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

    struct MockIterator<'a> {
        remaining: std::slice::Iter<'a, MockKeyedObject>,
    }

    impl<'a> GraphIteratorLike<MockKeyedObject> for MockIterator<'a> {
        fn has_next(&self) -> bool {
            self.remaining.clone().next().is_some()
        }

        fn next(&mut self) -> Option<MockKeyedObject> {
            self.remaining.next().map(|o| MockKeyedObject { key: o.key })
        }

        fn remove(&mut self) -> bool {
            false
        }
    }

    struct MockSet {
        objects: Vec<MockKeyedObject>,
        modification_number: i64,
    }

    impl KeyIndexableSet<MockKeyedObject> for MockSet {
        fn modification_number(&self) -> i64 {
            self.modification_number
        }

        fn size(&self) -> usize {
            self.objects.len()
        }

        fn capacity(&self) -> usize {
            self.objects.capacity()
        }

        fn add(&mut self, obj: MockKeyedObject) -> bool {
            if self.contains(&obj) {
                return false;
            }
            self.objects.push(obj);
            self.modification_number += 1;
            true
        }

        fn remove(&mut self, obj: &MockKeyedObject) -> bool {
            let before = self.objects.len();
            self.objects.retain(|o| o.key != obj.key);
            let removed = self.objects.len() != before;
            if removed {
                self.modification_number += 1;
            }
            removed
        }

        fn contains(&self, obj: &MockKeyedObject) -> bool {
            self.objects.iter().any(|o| o.key == obj.key)
        }

        fn iterator(&self) -> Box<dyn GraphIteratorLike<MockKeyedObject> + '_> {
            Box::new(MockIterator { remaining: self.objects.iter() })
        }

        fn to_array(&self) -> Vec<&MockKeyedObject> {
            self.objects.iter().collect()
        }

        fn get_keyed_object(&self, key: i64) -> Option<&MockKeyedObject> {
            self.objects.iter().find(|o| o.key == key)
        }
    }

    #[test]
    fn boxed_trait_object_is_usable() {
        let mut set: Box<dyn KeyIndexableSet<MockKeyedObject>> =
            Box::new(MockSet { objects: Vec::new(), modification_number: 0 });

        assert!(set.add(MockKeyedObject { key: 1 }));
        assert!(!set.add(MockKeyedObject { key: 1 }));
        assert_eq!(set.size(), 1);
        assert!(set.contains(&MockKeyedObject { key: 1 }));
        assert_eq!(set.get_keyed_object(1).map(|o| o.key), Some(1));
        assert_eq!(set.modification_number(), 1);

        let mut iter = set.iterator();
        assert!(iter.has_next());
        assert_eq!(iter.next().map(|o| o.key), Some(1));

        assert!(set.remove(&MockKeyedObject { key: 1 }));
        assert_eq!(set.size(), 0);
        assert_eq!(set.modification_number(), 2);
    }
}

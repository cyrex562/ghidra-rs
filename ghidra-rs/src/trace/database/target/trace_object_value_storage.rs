//! Storage backing shared by a value entry and its wrapper.
//!
//! Java source: `ghidra.trace.database.target.TraceObjectValueStorage`.
//!
//! Ported as a trait because it was selected as a cycle cut-point: it references
//! [`DBTraceObject`], [`DBTraceObjectManager`], and [`DBTraceObjectValue`], each of which (once
//! ported) will in turn reference storage/value types back. Those three are not yet ported, so
//! they are represented here by minimal placeholder traits in
//! [`crate::trace::seam_stubs`].
use crate::trace::model::lifespan::Lifespan;
use crate::trace::seam_stubs::{DBTraceObject, DBTraceObjectManager, DBTraceObjectValue};

/// Storage backing shared by a value entry ([`DBTraceObjectValue`]) and its wrapper.
///
/// Port of `ghidra.trace.database.target.TraceObjectValueStorage`.
pub trait TraceObjectValueStorage: Send + Sync {
    /// Get the manager that owns this storage's object database.
    fn get_manager(&self) -> Box<dyn DBTraceObjectManager>;

    /// Get the value entry that wraps this storage.
    fn get_wrapper(&self) -> Box<dyn DBTraceObjectValue>;

    /// Get the parent object of this entry.
    fn get_parent(&self) -> Box<dyn DBTraceObject>;

    /// Get the key identifying this child to its parent.
    fn get_entry_key(&self) -> String;

    /// Just set the lifespan, no notifications.
    ///
    /// The wrapper will notify the parent and child, if necessary.
    fn do_set_lifespan(&mut self, lifespan: &dyn Lifespan);

    /// Get the lifespan.
    fn get_lifespan(&self) -> Box<dyn Lifespan>;

    /// Get the child object, or `None` if this entry's value is not an object.
    fn get_child_or_null(&self) -> Option<Box<dyn DBTraceObject>>;

    /// Get the value.
    fn get_value(&self) -> Box<dyn std::any::Any + Send + Sync>;

    /// Check if this entry has been deleted.
    fn is_deleted(&self) -> bool;

    /// Delete this entry, no notifications.
    fn do_delete(&mut self);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct MockLifespan {
        min: i64,
        max: i64,
    }

    impl Lifespan for MockLifespan {
        fn lmin(&self) -> i64 {
            self.min
        }

        fn lmax(&self) -> i64 {
            self.max
        }

        fn contains(&self, n: i64) -> bool {
            self.min <= n && n <= self.max
        }

        fn with_min(&self, min: i64) -> Box<dyn Lifespan> {
            Box::new(MockLifespan { min, max: self.max })
        }

        fn with_max(&self, max: i64) -> Box<dyn Lifespan> {
            Box::new(MockLifespan { min: self.min, max })
        }

        fn iter(&self) -> Box<dyn Iterator<Item = i64> + '_> {
            Box::new(self.min..=self.max)
        }
    }

    struct MockManager;
    impl DBTraceObjectManager for MockManager {}

    struct MockValue;
    impl DBTraceObjectValue for MockValue {}

    struct MockObject;
    impl DBTraceObject for MockObject {}

    struct MockStorage {
        lifespan: MockLifespan,
        value: i64,
        deleted: bool,
        has_child: bool,
    }

    impl TraceObjectValueStorage for MockStorage {
        fn get_manager(&self) -> Box<dyn DBTraceObjectManager> {
            Box::new(MockManager)
        }

        fn get_wrapper(&self) -> Box<dyn DBTraceObjectValue> {
            Box::new(MockValue)
        }

        fn get_parent(&self) -> Box<dyn DBTraceObject> {
            Box::new(MockObject)
        }

        fn get_entry_key(&self) -> String {
            "key1".to_string()
        }

        fn do_set_lifespan(&mut self, lifespan: &dyn Lifespan) {
            self.lifespan = MockLifespan {
                min: lifespan.lmin(),
                max: lifespan.lmax(),
            };
        }

        fn get_lifespan(&self) -> Box<dyn Lifespan> {
            Box::new(self.lifespan)
        }

        fn get_child_or_null(&self) -> Option<Box<dyn DBTraceObject>> {
            if self.has_child {
                Some(Box::new(MockObject))
            } else {
                None
            }
        }

        fn get_value(&self) -> Box<dyn std::any::Any + Send + Sync> {
            Box::new(self.value)
        }

        fn is_deleted(&self) -> bool {
            self.deleted
        }

        fn do_delete(&mut self) {
            self.deleted = true;
        }
    }

    fn make_storage() -> MockStorage {
        MockStorage {
            lifespan: MockLifespan { min: 0, max: 10 },
            value: 42,
            deleted: false,
            has_child: false,
        }
    }

    #[test]
    fn do_set_lifespan_replaces_span() {
        let mut storage = make_storage();
        assert_eq!(storage.get_lifespan().lmin(), 0);
        assert_eq!(storage.get_lifespan().lmax(), 10);

        storage.do_set_lifespan(&MockLifespan { min: 5, max: 20 });

        assert_eq!(storage.get_lifespan().lmin(), 5);
        assert_eq!(storage.get_lifespan().lmax(), 20);
    }

    #[test]
    fn do_delete_marks_deleted() {
        let mut storage = make_storage();
        assert!(!storage.is_deleted());
        storage.do_delete();
        assert!(storage.is_deleted());
    }

    #[test]
    fn get_child_or_null_reflects_object_presence() {
        let with_child = MockStorage {
            has_child: true,
            ..make_storage()
        };
        assert!(with_child.get_child_or_null().is_some());

        let without_child = make_storage();
        assert!(without_child.get_child_or_null().is_none());
    }

    #[test]
    fn get_value_downcasts_to_original_type() {
        let storage = make_storage();
        let value = storage.get_value();
        assert_eq!(*value.downcast_ref::<i64>().unwrap(), 42);
    }

    #[test]
    fn entry_key_and_parent_are_accessible() {
        let storage = make_storage();
        assert_eq!(storage.get_entry_key(), "key1");
        let _parent = storage.get_parent();
        let _manager = storage.get_manager();
        let _wrapper = storage.get_wrapper();
    }

    #[test]
    fn dyn_trait_object_is_usable() {
        let boxed: Box<dyn TraceObjectValueStorage> = Box::new(make_storage());
        assert_eq!(boxed.get_entry_key(), "key1");
        assert!(!boxed.is_deleted());
    }
}

//! Storage backing shared by a value entry and its wrapper.
//!
//! Java source: `ghidra.trace.database.target.TraceObjectValueStorage`.
//!
//! Ported as a trait because it was selected as a cycle cut-point: it references
//! [`DBTraceObject`], [`DBTraceObjectManager`], and [`DBTraceObjectValue`], each of which (once
//! ported) will in turn reference storage/value types back. The first two are not yet ported, so
//! they are represented here by minimal placeholder traits in [`crate::trace::seam_stubs`];
//! [`DBTraceObjectValue`] now *is* ported, so [`Self::get_wrapper`] names the real struct.
use std::sync::Arc;

use crate::trace::database::target::db_trace_object_value::DBTraceObjectValue;
use crate::trace::model::lifespan::Lifespan;
use crate::trace::seam_stubs::{DBTraceObject, DBTraceObjectManager};

/// Storage backing shared by a value entry ([`DBTraceObjectValue`]) and its wrapper.
///
/// Port of `ghidra.trace.database.target.TraceObjectValueStorage`.
pub trait TraceObjectValueStorage: Send + Sync {
    /// Get the manager that owns this storage's object database.
    fn get_manager(&self) -> Box<dyn DBTraceObjectManager>;

    /// Get the value entry that wraps this storage, or `None` if none has been installed yet.
    ///
    /// Java's `getWrapper()` never returns null: `DBTraceObjectValueData` lazily constructs
    /// `new DBTraceObjectValue(manager, this)` and caches it in a `wrapper` field. That is an
    /// ownership cycle in Rust -- the wrapper owns the storage and the storage would own the
    /// wrapper -- so the back-pointer is a shared handle that is `None` until something installs
    /// it, matching the Java field's own initial state.
    fn get_wrapper(&self) -> Option<Arc<DBTraceObjectValue>>;

    /// Get the parent object of this entry, or `None` if this is the root value.
    ///
    /// Java declares this `DBTraceObject getParent()`, but it is null for the root value --
    /// `DBTraceObjectValue.doGetCanonicalPath`, `doIsCanonical`, `delete` and `truncateOrDelete`
    /// all branch on exactly that -- so it is `Option` here.
    fn get_parent(&self) -> Option<Box<dyn DBTraceObject>>;

    /// Get the key identifying this child to its parent.
    fn get_entry_key(&self) -> String;

    /// Just set the lifespan, no notifications.
    ///
    /// The wrapper will notify the parent and child, if necessary.
    fn do_set_lifespan(&mut self, lifespan: Lifespan);

    /// Get the lifespan.
    fn get_lifespan(&self) -> Lifespan;

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



    use crate::debug::api::tracermi::SchemaName;
    use crate::trace::model::target::path::key_path::KeyPath;
    use crate::trace::seam_stubs::{LifeSet, ObjectKey, TraceObjectSchema};
    use crate::trace::model::target::trace_object::TraceObject;

    struct MockManager;
    impl DBTraceObjectManager for MockManager {}

    struct MockObject;

    impl crate::trace::model::trace_unique_object::TraceUniqueObject for MockObject {
        fn get_object_key(&self) -> Box<dyn ObjectKey> {
            unimplemented!("not exercised by this smoke test")
        }

        fn is_deleted(&self) -> bool {
            false
        }
    }

    impl TraceObject for MockObject {
        fn get_schema(&self) -> Box<dyn TraceObjectSchema> {
            struct S;
            impl TraceObjectSchema for S {
                fn get_name(&self) -> SchemaName {
                    SchemaName::new("Mock")
                }
                fn to_string(&self) -> String {
                    "Mock".to_string()
                }
            }
            Box::new(S)
        }


        fn get_life(&self) -> Box<dyn LifeSet> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_canonical_path(&self) -> KeyPath {
            KeyPath::root()
        }

        crate::trace::model::target::trace_object::unimplemented_trace_object_members!();
    }

    impl DBTraceObject for MockObject {}

    struct MockStorage {
        lifespan: Lifespan,
        value: i64,
        deleted: bool,
        has_child: bool,
    }

    impl TraceObjectValueStorage for MockStorage {
        fn get_manager(&self) -> Box<dyn DBTraceObjectManager> {
            Box::new(MockManager)
        }

        fn get_wrapper(&self) -> Option<Arc<DBTraceObjectValue>> {
            None
        }

        fn get_parent(&self) -> Option<Box<dyn DBTraceObject>> {
            Some(Box::new(MockObject))
        }

        fn get_entry_key(&self) -> String {
            "key1".to_string()
        }

        fn do_set_lifespan(&mut self, lifespan: Lifespan) {
            self.lifespan = Lifespan::span(lifespan.lmin(), lifespan.lmax());
        }

        fn get_lifespan(&self) -> Lifespan {
            self.lifespan
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
            lifespan: Lifespan::span(0, 10),
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

        storage.do_set_lifespan(Lifespan::span(5, 20));

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
        assert!(storage.get_parent().is_some());
        let _manager = storage.get_manager();
        // No wrapper is installed until one is created around this storage.
        assert!(storage.get_wrapper().is_none());
    }

    #[test]
    fn dyn_trait_object_is_usable() {
        let boxed: Box<dyn TraceObjectValueStorage> = Box::new(make_storage());
        assert_eq!(boxed.get_entry_key(), "key1");
        assert!(!boxed.is_deleted());
    }
}

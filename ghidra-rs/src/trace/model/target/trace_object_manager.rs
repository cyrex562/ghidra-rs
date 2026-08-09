//! A store of objects observed over time in a trace.
//!
//! Java source: `ghidra.trace.model.target.TraceObjectManager`.
//!
//! Ported as a trait because it was selected as a cycle cut-point: `TraceObjectManager` and
//! `TraceObject`/`TraceObjectValue` (the trace object graph) reference each other, so the manager
//! cannot be a concrete struct until the whole object graph exists.
use crate::program::model::address::range::AddressRange;
use crate::trace::model::lifespan::Lifespan;
use crate::trace::model::target::path::key_path::KeyPath;
use crate::trace::model::target::path::PathFilter;
use crate::trace::model::target::trace_object_val_path::TraceObjectValPath;
use crate::trace::model::target::trace_object_value::TraceObjectValue;
use crate::trace::model::trace::Trace;
use crate::trace::model::target::iface::TraceObjectInterface;
use crate::trace::seam_stubs::TraceObjectSchema;
use crate::trace::model::target::trace_object::TraceObject;

/// A handle to automatically re-enable the write cache.
///
/// Port of the nested `ghidra.trace.model.target.TraceObjectManager.BypassWriteCache` interface.
/// Java's `AutoCloseable.close()` is ported as an explicit `close(&mut self)`, mirroring the same
/// convention used elsewhere in this crate (e.g. `TransactionCoalescer`'s `CoalescedTx`).
pub trait BypassWriteCache {
    /// Re-enables the write cache. Mirrors `BypassWriteCache.close()`.
    fn close(&mut self);
}

/// A store of objects observed over time in a trace.
///
/// Port of `ghidra.trace.model.target.TraceObjectManager`.
pub trait TraceObjectManager: Send + Sync {
    /// Get the trace to which the object manager belongs.
    fn get_trace(&self) -> Box<dyn Trace>;

    /// Creates the root object of the model, fixing its schema.
    ///
    /// Note the schema cannot be changed once the root object is created. The only means to
    /// "change" the schema is to delete the root object (and thus the entire tree) then re-create
    /// the root object with the new schema.
    fn create_root_object(&mut self, schema: Box<dyn TraceObjectSchema>) -> Box<dyn TraceObjectValue>;

    /// Create (or get) an object with the given canonical path.
    fn create_object(&mut self, path: &KeyPath) -> Box<dyn TraceObject>;

    /// Get the schema of the root object, or `None` if no root object exists.
    fn get_root_schema(&self) -> Option<Box<dyn TraceObjectSchema>>;

    /// Get the schema of the root object, failing if no root object exists.
    fn require_root_schema(&self) -> Box<dyn TraceObjectSchema> {
        self.get_root_schema()
            .expect("requireRootSchema() requires a root object, mirroring the Java exception")
    }

    /// Get the root object, if it has been created.
    fn get_root_object(&self) -> Option<Box<dyn TraceObject>>;

    /// Get the object with the given database key, if it exists.
    fn get_object_by_id(&self, key: i64) -> Option<Box<dyn TraceObject>>;

    /// Get the object in the database having the given canonical path.
    fn get_object_by_canonical_path(&self, path: &KeyPath) -> Option<Box<dyn TraceObject>>;

    /// Get objects in the database having the given path intersecting the given span.
    fn get_objects_by_path(&self, span: Lifespan, path: &KeyPath) -> Vec<Box<dyn TraceObject>>;

    /// Get value entries in the database matching the given predicates intersecting the given
    /// span.
    ///
    /// While the manager does not maintain integrity wrt. child lifespans and that of their
    /// parents, nor even the connectivity of objects to their canonical parents, this search
    /// depends on that consistency. An object may not be discovered unless it is properly
    /// connected to the root object. Furthermore, it will not be discovered unless it and its
    /// ancestors' lifespans all intersect the given span.
    fn get_value_paths(
        &self,
        span: Lifespan,
        predicates: &dyn PathFilter,
    ) -> Vec<Box<dyn TraceObjectValPath>>;

    /// Get all the objects in the database.
    fn get_all_objects(&self) -> Vec<Box<dyn TraceObject>>;

    /// Get the number of objects in the database.
    fn get_object_count(&self) -> i32;

    /// Get all the values (edges) in the database.
    fn get_all_values(&self) -> Vec<Box<dyn TraceObjectValue>>;

    /// Get all address-ranged values intersecting the given span and address range.
    ///
    /// `entry_key`, if given, restricts the match to a single entry key.
    fn get_values_intersecting(
        &self,
        span: Lifespan,
        range: &AddressRange,
        entry_key: Option<&str>,
    ) -> Vec<Box<dyn TraceObjectValue>>;

    /// Get all interfaces of the given type in the database.
    ///
    /// The Java `Class<I>` parameter is reified via the Rust type parameter `I` instead of being
    /// passed explicitly. This keeps `dyn TraceObjectManager` object-safe (the same trade-off
    /// documented on `ProgressService::execute_with_future`), so it is unavailable through a
    /// trait object -- callers need a concrete (or otherwise `Sized`) manager type.
    fn query_all_interface<I: TraceObjectInterface>(&self, span: Lifespan) -> Vec<I>
    where
        Self: Sized;

    /// For maintenance, remove all disconnected objects.
    ///
    /// An object is disconnected if it is neither the child nor parent of any value for any span.
    /// In other words, it's unused.
    fn cull_disconnected_objects(&mut self);

    /// Delete the *entire* object model, including the schema.
    ///
    /// This is the only mechanism to modify the schema. This should almost never be necessary,
    /// because a connector should provide its immutable schema immediately. Nevertheless, the
    /// database permits schema modification, but requires that the entire model be replaced.
    fn clear(&mut self);

    /// Bypass the write cache, usually for an import operation.
    ///
    /// For live sessions, we typically want to complete object writes as promptly as possible, so
    /// we don't tie up the connection and/or the remote debugger. However, for import operations,
    /// we'd rather just have object writes go straight to the database. The importer will want to
    /// save, which requires flushing the cache anyway. Disabling the cache gives more honest
    /// progress reporting and assures any crashes or diagnostics occur during the import rather
    /// than during the flush.
    fn without_write_cache(&mut self) -> Box<dyn BypassWriteCache>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace};
    use crate::trace::seam_stubs::{ObjectKey, TraceObjectSchema as SchemaTrait};



    struct MockBypassWriteCache {
        closed: bool,
    }

    impl BypassWriteCache for MockBypassWriteCache {
        fn close(&mut self) {
            self.closed = true;
        }
    }

    struct MockObjectKey(i32);

    impl ObjectKey for MockObjectKey {
        fn equals(&self, obj: &dyn std::any::Any) -> bool {
            obj.downcast_ref::<MockObjectKey>()
                .is_some_and(|other| other.0 == self.0)
        }

        fn hash_code(&self) -> i32 {
            self.0
        }

        fn compare_to(&self, that: &dyn ObjectKey) -> i32 {
            self.hash_code() - that.hash_code()
        }
    }

    struct MockLifeSet;

    impl crate::trace::seam_stubs::LifeSet for MockLifeSet {
        fn is_empty(&self) -> bool {
            false
        }
    }

    struct MockSchema;

    impl SchemaTrait for MockSchema {
        fn get_name(&self) -> crate::debug::api::tracermi::SchemaName {
            crate::debug::api::tracermi::SchemaName::new("Root")
        }

        fn to_string(&self) -> String {
            "Root".to_string()
        }
    }

    struct MockObject;

    impl crate::trace::model::trace_unique_object::TraceUniqueObject for MockObject {
        fn get_object_key(&self) -> Box<dyn ObjectKey> {
            Box::new(MockObjectKey(0))
        }

        fn is_deleted(&self) -> bool {
            false
        }
    }

    impl TraceObject for MockObject {
        fn get_schema(&self) -> Box<dyn SchemaTrait> {
            Box::new(MockSchema)
        }


        fn get_life(&self) -> Box<dyn crate::trace::seam_stubs::LifeSet> {
            Box::new(MockLifeSet)
        }

        fn get_canonical_path(&self) -> crate::trace::model::target::path::key_path::KeyPath {
            crate::trace::model::target::path::key_path::KeyPath::root()
        }

        crate::trace::model::target::trace_object::unimplemented_trace_object_members!();
    }

    struct MockManager {
        root: Option<()>,
        object_count: i32,
    }

    impl TraceObjectManager for MockManager {
        fn get_trace(&self) -> Box<dyn Trace> {
            unimplemented!("not exercised by this smoke test")
        }

        fn create_root_object(
            &mut self,
            _schema: Box<dyn SchemaTrait>,
        ) -> Box<dyn TraceObjectValue> {
            unimplemented!("not exercised by this smoke test")
        }

        fn create_object(&mut self, _path: &KeyPath) -> Box<dyn TraceObject> {
            self.object_count += 1;
            Box::new(MockObject)
        }

        fn get_root_schema(&self) -> Option<Box<dyn SchemaTrait>> {
            if self.root.is_some() {
                Some(Box::new(MockSchema))
            } else {
                None
            }
        }

        fn get_root_object(&self) -> Option<Box<dyn TraceObject>> {
            self.root.map(|_| Box::new(MockObject) as Box<dyn TraceObject>)
        }

        fn get_object_by_id(&self, _key: i64) -> Option<Box<dyn TraceObject>> {
            None
        }

        fn get_object_by_canonical_path(&self, _path: &KeyPath) -> Option<Box<dyn TraceObject>> {
            None
        }

        fn get_objects_by_path(&self, _span: Lifespan, _path: &KeyPath) -> Vec<Box<dyn TraceObject>> {
            Vec::new()
        }

        fn get_value_paths(
            &self,
            _span: Lifespan,
            _predicates: &dyn PathFilter,
        ) -> Vec<Box<dyn TraceObjectValPath>> {
            Vec::new()
        }

        fn get_all_objects(&self) -> Vec<Box<dyn TraceObject>> {
            Vec::new()
        }

        fn get_object_count(&self) -> i32 {
            self.object_count
        }

        fn get_all_values(&self) -> Vec<Box<dyn TraceObjectValue>> {
            Vec::new()
        }

        fn get_values_intersecting(
            &self,
            _span: Lifespan,
            _range: &AddressRange,
            _entry_key: Option<&str>,
        ) -> Vec<Box<dyn TraceObjectValue>> {
            Vec::new()
        }

        fn query_all_interface<I: TraceObjectInterface>(&self, _span: Lifespan) -> Vec<I>
        where
            Self: Sized,
        {
            Vec::new()
        }

        fn cull_disconnected_objects(&mut self) {}

        fn clear(&mut self) {
            self.root = None;
            self.object_count = 0;
        }

        fn without_write_cache(&mut self) -> Box<dyn BypassWriteCache> {
            Box::new(MockBypassWriteCache { closed: false })
        }
    }

    fn make_address(offset: i64) -> Address {
        let space = AddressSpace::new(
            "ram",
            32,
            1,
            crate::program::model::address::AddressSpaceType::Ram,
            0,
        );
        Address::new(space, offset)
    }

    #[test]
    fn require_root_schema_panics_without_root() {
        let manager = MockManager { root: None, object_count: 0 };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            manager.require_root_schema()
        }));
        assert!(result.is_err());
    }

    #[test]
    fn require_root_schema_returns_schema_with_root() {
        let manager = MockManager { root: Some(()), object_count: 0 };
        let schema = manager.require_root_schema();
        assert_eq!(schema.to_string(), "Root");
    }

    #[test]
    fn create_object_increments_object_count() {
        let mut manager = MockManager { root: None, object_count: 0 };
        assert_eq!(manager.get_object_count(), 0);
        manager.create_object(&KeyPath::root());
        assert_eq!(manager.get_object_count(), 1);
    }

    #[test]
    fn clear_resets_root_and_count() {
        let mut manager = MockManager { root: Some(()), object_count: 3 };
        manager.clear();
        assert!(manager.get_root_object().is_none());
        assert_eq!(manager.get_object_count(), 0);
    }

    #[test]
    fn without_write_cache_returns_closable_handle() {
        let mut manager = MockManager { root: None, object_count: 0 };
        let mut handle = manager.without_write_cache();
        handle.close();
    }

    #[test]
    fn trait_object_usage_is_object_safe() {
        let mut manager: Box<dyn TraceObjectManager> =
            Box::new(MockManager { root: None, object_count: 0 });
        let range = AddressRange::new(make_address(0), make_address(0x10));
        let span = Lifespan::span(0, 10);
        assert!(manager.get_values_intersecting(span, &range, None).is_empty());
        manager.clear();
    }
}

//! A path of values leading from one object to another.
//!
//! Java source: `ghidra.trace.model.target.TraceObjectValPath`.
//!
//! Ported as a trait: the interface has 10 abstract methods, and while
//! [`DBTraceObjectValPath`](crate::trace::database::target::db_trace_object_val_path::DBTraceObjectValPath)
//! is the only in-repo implementor so far, Java code elsewhere in the tree (the
//! `ghidra.trace.database.target.visitors.*` classes and `DBTraceObject.doGetSuccessors`, not yet
//! ported) holds values of the interface type and calls `append`/`prepend` on them polymorphically,
//! so this is a genuine open extension point rather than a single-implementor seam.
//!
//! `getSource`/`getDestinationValue`/`getDestination`/`compareTo` are given default bodies here,
//! even though the Java interface declares all ten methods abstract: each body is expressible
//! purely in terms of the other (still-abstract) trait methods, and is identical for every
//! implementor (compare
//! [`DBTraceObjectValPath`](crate::trace::database::target::db_trace_object_val_path::DBTraceObjectValPath)'s
//! own implementation), so defaults avoid making every future implementor re-derive the same logic.
use std::any::Any;
use std::cmp::Ordering;
use std::sync::Arc;

use crate::trace::model::target::path::key_path::KeyPath;
use crate::trace::model::target::trace_object_value::TraceObjectValue;
use crate::trace::seam_stubs::TraceObject;

/// A path of values leading from one object to another, ordered from source to destination.
///
/// Often, the source object is the root. These are often returned in streams where the search
/// involves a desired "span". The path satisfies that requirement, i.e., "the path intersects the
/// span" if the cumulative intersection of all values' lifespans along the path and the given span
/// is non-empty. Paths may also be empty, implying the source is the destination. Empty paths
/// "intersect" any given span.
///
/// Port of `ghidra.trace.model.target.TraceObjectValPath`. The interface's static `of()` factory
/// for the empty path has no natural home on a trait; use
/// [`DBTraceObjectValPath::empty`](crate::trace::database::target::db_trace_object_val_path::DBTraceObjectValPath::empty)
/// directly, mirroring the Java default's delegation to `DBTraceObjectValPath.of()`.
pub trait TraceObjectValPath: Send + Sync {
    /// The values in the path, ordered from source to destination. Mirrors `getEntryList()`.
    fn get_entry_list(&self) -> Vec<Arc<dyn TraceObjectValue>>;

    /// The keys in the path, ordered from source to destination.
    ///
    /// The returned path is suited for testing with `PathFilter` or other path-manipulation
    /// methods. Mirrors `getPath()`.
    fn get_path(&self) -> KeyPath;

    /// Check if a given value appears on this path. Mirrors `contains(TraceObjectValue)`.
    fn contains(&self, entry: &dyn TraceObjectValue) -> bool;

    /// The first entry, i.e., the one adjacent to the source object, or `None` if the path is
    /// empty. Mirrors `getFirstEntry()`.
    fn get_first_entry(&self) -> Option<Arc<dyn TraceObjectValue>>;

    /// The last entry, i.e., the one adjacent to the destination object, or `None` if the path is
    /// empty. Mirrors `getLastEntry()`.
    fn get_last_entry(&self) -> Option<Arc<dyn TraceObjectValue>>;

    /// Append the entry to this path, generating a new path.
    ///
    /// This performs no validation. The parent of the given entry should be the child of the last
    /// entry in this path. Mirrors `append(TraceObjectValue)`.
    fn append(&self, entry: Arc<dyn TraceObjectValue>) -> Box<dyn TraceObjectValPath>;

    /// Prepend the entry to this path, generating a new path.
    ///
    /// This performs no validation. The child of the given entry should be the parent of the
    /// first entry in this path. Mirrors `prepend(TraceObjectValue)`.
    fn prepend(&self, entry: Arc<dyn TraceObjectValue>) -> Box<dyn TraceObjectValPath>;

    /// The source object.
    ///
    /// This returns the parent object of the first entry of the path, unless the path is empty.
    /// If the path is empty, then this returns `if_empty`, which is presumably the destination
    /// object. Mirrors `getSource(TraceObject)`.
    fn get_source(&self, if_empty: Box<dyn TraceObject>) -> Box<dyn TraceObject> {
        match self.get_first_entry() {
            None => if_empty,
            Some(first) => first
                .get_parent()
                .expect("the first entry of a non-empty path always has a parent"),
        }
    }

    /// The destination value.
    ///
    /// This returns the value of the last entry of the path, unless the path is empty. If the
    /// path is empty, then this returns `if_empty`, which is presumably the source value. Note
    /// that values may be primitive, so the destination is not always an object; see
    /// [`Self::get_destination`] to assume the destination is an object. Mirrors
    /// `getDestinationValue(Object)`.
    fn get_destination_value(
        &self,
        if_empty: Box<dyn Any + Send + Sync>,
    ) -> Box<dyn Any + Send + Sync> {
        match self.get_last_entry() {
            None => if_empty,
            Some(last) => last.get_value(),
        }
    }

    /// The destination object.
    ///
    /// This returns the child object of the last entry of the path, unless the path is empty. If
    /// the path is empty, then this returns `if_empty`, which is presumably the source object.
    /// Mirrors `getDestination(TraceObject)`.
    ///
    /// # Panics
    /// Panics if the destination value is not an object, mirroring the Java `ClassCastException`
    /// (see [`TraceObjectValue::get_child`]).
    fn get_destination(&self, if_empty: Box<dyn TraceObject>) -> Box<dyn TraceObject> {
        match self.get_last_entry() {
            None => if_empty,
            Some(last) => last.get_child(),
        }
    }

    /// Order paths by [`KeyPath`]'s keyed ordering. Mirrors `compareTo(TraceObjectValPath)`.
    fn compare_to(&self, that: &dyn TraceObjectValPath) -> Ordering {
        self.get_path().cmp(&that.get_path())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::model::lifespan::Lifespan;
    use crate::trace::model::target::duplicate_key_exception::DuplicateKeyException;
    use crate::trace::model::target::trace_object_value::TruncateOrDelete;
    use crate::trace::model::trace::Trace;
    use crate::trace::seam_stubs::{ConflictResolution, LifeSet, ObjectKey, TraceObjectSchema};

    struct MockObjectKey;
    impl ObjectKey for MockObjectKey {
        fn equals(&self, _obj: &dyn Any) -> bool {
            true
        }
        fn hash_code(&self) -> i32 {
            0
        }
        fn compare_to(&self, _that: &dyn ObjectKey) -> i32 {
            0
        }
    }

    struct MockLifeSet;
    impl LifeSet for MockLifeSet {
        fn is_empty(&self) -> bool {
            false
        }
    }

    struct MockSchema;
    impl TraceObjectSchema for MockSchema {
        fn get_name(&self) -> crate::debug::api::tracermi::SchemaName {
            crate::debug::api::tracermi::SchemaName::new("Test")
        }
        fn to_string(&self) -> String {
            "Test".to_string()
        }
    }

    struct MockObject {
        path: KeyPath,
    }

    impl TraceObject for MockObject {
        fn get_schema(&self) -> Box<dyn TraceObjectSchema> {
            Box::new(MockSchema)
        }
        fn get_object_key(&self) -> Box<dyn ObjectKey> {
            Box::new(MockObjectKey)
        }
        fn get_life(&self) -> Box<dyn LifeSet> {
            Box::new(MockLifeSet)
        }
        fn get_canonical_path(&self) -> KeyPath {
            self.path.clone()
        }
    }

    /// A value entry `key`, whose parent's canonical path is `parent_path` and whose child's
    /// canonical path is `parent_path` extended by `key`.
    struct MockValue {
        key: &'static str,
        parent_path: &'static str,
        value: i64,
    }

    impl TraceObjectValue for MockValue {
        fn get_trace(&self) -> Box<dyn Trace> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_parent(&self) -> Option<Box<dyn TraceObject>> {
            Some(Box::new(MockObject { path: KeyPath::parse(self.parent_path).unwrap() }))
        }
        fn get_entry_key(&self) -> String {
            self.key.to_string()
        }
        fn get_canonical_path(&self) -> KeyPath {
            KeyPath::parse(self.parent_path).unwrap().with_key(self.key)
        }
        fn get_value(&self) -> Box<dyn Any + Send + Sync> {
            Box::new(self.value)
        }
        fn get_child(&self) -> Box<dyn TraceObject> {
            Box::new(MockObject { path: self.get_canonical_path() })
        }
        fn is_object(&self) -> bool {
            true
        }
        fn is_canonical(&self) -> bool {
            true
        }
        fn set_lifespan(&mut self, _lifespan: Lifespan) {}
        fn set_lifespan_with_resolution(
            &mut self,
            _span: Lifespan,
            _resolution: ConflictResolution,
        ) -> Result<(), DuplicateKeyException> {
            Ok(())
        }
        fn get_lifespan(&self) -> Lifespan {
            Lifespan::span(0, 10)
        }
        fn set_min_snap(&mut self, _min_snap: i64) {}
        fn get_min_snap(&self) -> i64 {
            0
        }
        fn set_max_snap(&mut self, _max_snap: i64) {}
        fn get_max_snap(&self) -> i64 {
            10
        }
        fn delete(&mut self) {}
        fn is_deleted(&self) -> bool {
            false
        }
        fn truncate_or_delete(&mut self, _span: Lifespan) -> TruncateOrDelete {
            TruncateOrDelete::Unchanged
        }
    }

    /// A minimal implementor exercising the trait's default methods via dynamic dispatch, the way
    /// `DBTraceObjectValPath` does for real.
    #[derive(Clone)]
    struct MockPath {
        entries: Vec<Arc<dyn TraceObjectValue>>,
    }

    impl TraceObjectValPath for MockPath {
        fn get_entry_list(&self) -> Vec<Arc<dyn TraceObjectValue>> {
            self.entries.clone()
        }
        fn get_path(&self) -> KeyPath {
            KeyPath::of_iter(self.entries.iter().map(|e| e.get_entry_key()))
        }
        fn contains(&self, entry: &dyn TraceObjectValue) -> bool {
            // Compare the data address only (`as *const ()` strips the vtable pointer): see
            // `DBTraceObjectValPath::contains` for why comparing the fat pointers directly is
            // unreliable.
            let entry_ptr = entry as *const dyn TraceObjectValue as *const ();
            self.entries.iter().any(|e| {
                (e.as_ref() as *const dyn TraceObjectValue as *const ()) == entry_ptr
            })
        }
        fn get_first_entry(&self) -> Option<Arc<dyn TraceObjectValue>> {
            self.entries.first().cloned()
        }
        fn get_last_entry(&self) -> Option<Arc<dyn TraceObjectValue>> {
            self.entries.last().cloned()
        }
        fn append(&self, entry: Arc<dyn TraceObjectValue>) -> Box<dyn TraceObjectValPath> {
            let mut entries = self.entries.clone();
            entries.push(entry);
            Box::new(MockPath { entries })
        }
        fn prepend(&self, entry: Arc<dyn TraceObjectValue>) -> Box<dyn TraceObjectValPath> {
            let mut entries = Vec::with_capacity(1 + self.entries.len());
            entries.push(entry);
            entries.extend(self.entries.iter().cloned());
            Box::new(MockPath { entries })
        }
    }

    fn make_value(key: &'static str, parent_path: &'static str, value: i64) -> Arc<dyn TraceObjectValue> {
        Arc::new(MockValue { key, parent_path, value })
    }

    #[test]
    fn empty_path_source_and_destination_fall_back_to_if_empty() {
        // Java: TraceObjectValPath.getSource/getDestination/getDestinationValue on an empty path
        // return the ifEmpty argument unchanged.
        let path: Box<dyn TraceObjectValPath> = Box::new(MockPath { entries: Vec::new() });

        let fallback = MockObject { path: KeyPath::parse("Session").unwrap() };
        let fallback_key = fallback.get_canonical_path();
        let source = path.get_source(Box::new(fallback));
        assert_eq!(source.get_canonical_path(), fallback_key);

        let fallback2 = MockObject { path: KeyPath::parse("Session").unwrap() };
        let dest = path.get_destination(Box::new(fallback2));
        assert_eq!(dest.get_canonical_path(), fallback_key);

        let fallback_value: Box<dyn Any + Send + Sync> = Box::new(7i64);
        let dest_value = path.get_destination_value(fallback_value);
        assert_eq!(*dest_value.downcast::<i64>().unwrap(), 7);
    }

    #[test]
    fn non_empty_path_source_is_first_entrys_parent_and_destination_is_last_entrys_child() {
        let a = make_value("Threads", "Process[1]", 1);
        let b = make_value("[0]", "Process[1].Threads", 2);
        let path: Box<dyn TraceObjectValPath> = Box::new(MockPath { entries: vec![a, b] });

        let fallback = MockObject { path: KeyPath::root() };
        let source = path.get_source(Box::new(fallback));
        assert_eq!(source.get_canonical_path(), KeyPath::parse("Process[1]").unwrap());

        let fallback2 = MockObject { path: KeyPath::root() };
        let dest = path.get_destination(Box::new(fallback2));
        assert_eq!(dest.get_canonical_path(), KeyPath::parse("Process[1].Threads[0]").unwrap());

        let dest_value =
            path.get_destination_value(Box::new(0i64) as Box<dyn Any + Send + Sync>);
        assert_eq!(*dest_value.downcast::<i64>().unwrap(), 2);
    }

    #[test]
    fn compare_to_orders_by_keyed_path() {
        let a: Box<dyn TraceObjectValPath> =
            Box::new(MockPath { entries: vec![make_value("Alpha", "Process[1]", 0)] });
        let b: Box<dyn TraceObjectValPath> =
            Box::new(MockPath { entries: vec![make_value("Beta", "Process[1]", 0)] });
        assert_eq!(a.compare_to(b.as_ref()), Ordering::Less);
        assert_eq!(b.compare_to(a.as_ref()), Ordering::Greater);
        assert_eq!(a.compare_to(a.as_ref()), Ordering::Equal);
    }

    #[test]
    fn append_and_prepend_build_new_paths_without_mutating_the_original() {
        let a = make_value("Threads", "Process[1]", 1);
        let base: Box<dyn TraceObjectValPath> = Box::new(MockPath { entries: vec![a] });

        let b = make_value("[0]", "Process[1].Threads", 2);
        let appended = base.append(b);
        assert_eq!(appended.get_entry_list().len(), 2);
        assert_eq!(appended.get_path(), KeyPath::parse("Threads[0]").unwrap());
        assert_eq!(base.get_entry_list().len(), 1);

        let c = make_value("Process", "Session", 0);
        let prepended = appended.prepend(c);
        assert_eq!(prepended.get_entry_list().len(), 3);
        assert_eq!(prepended.get_path(), KeyPath::parse("Process.Threads[0]").unwrap());
    }

    #[test]
    fn contains_checks_entry_identity_not_equality() {
        let a = make_value("Threads", "Process[1]", 1);
        let b = make_value("[0]", "Process[1].Threads", 2);
        let path: Box<dyn TraceObjectValPath> = Box::new(MockPath { entries: vec![Arc::clone(&a)] });
        assert!(path.contains(a.as_ref()));
        assert!(!path.contains(b.as_ref()));
    }
}

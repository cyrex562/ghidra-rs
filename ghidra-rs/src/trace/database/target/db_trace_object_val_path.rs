//! A path of values leading from one object to another.
//!
//! Java source: `ghidra.trace.database.target.DBTraceObjectValPath`, a concrete
//! `class DBTraceObjectValPath implements TraceObjectValPath`, so this is a `struct` implementing
//! the already-stubbed [`TraceObjectValPath`] marker trait.
//!
//! # Cycle
//!
//! `TraceObjectValPath` (the Java interface) references this class back (its static `of()`
//! delegates to `DBTraceObjectValPath.of()`), so the interface is still only the empty marker
//! [`TraceObjectValPath`] placeholder in `seam_stubs.rs`; there is nothing further to cut here.
//!
//! # Sharing
//!
//! Java's `entryList` holds direct `DBTraceObjectValue` references, and `prepend`/`append` build a
//! new immutable list that reuses the *same* entry objects rather than copying them. Since
//! [`DBTraceObjectValue`] holds a lock and is not [`Clone`], entries are kept as `Arc` so a path
//! and its `prepend`/`append` derivatives can share entries the way the Java lists do.
//!
//! # Not reproduced
//!
//! - The `entry.getTrace() != entryList.get(0).getTrace()` same-trace sanity check in `prepend`
//!   and `append`. Each call to [`DBTraceObjectValue::get_trace`] hands back a freshly boxed `dyn
//!   Trace`, which has no reliable identity comparison across calls, so the check cannot be
//!   reproduced without a trace-identity accessor that does not exist yet.
//! - The `instanceof DBTraceObjectValue` cast (and its `IllegalArgumentException` on failure) in
//!   `prepend` and `append`. [`Self::prepend`]/[`Self::append`] take `Arc<DBTraceObjectValue>`
//!   directly, so the check is enforced at compile time instead.

use std::sync::{Arc, OnceLock};

use crate::trace::database::target::db_trace_object_value::DBTraceObjectValue;
use crate::trace::model::target::path::key_path::KeyPath;
use crate::trace::model::target::trace_object_value::TraceObjectValue;
use crate::trace::seam_stubs::TraceObjectValPath;

/// A path of values leading from one object to another, ordered from source to destination.
///
/// Port of `ghidra.trace.database.target.DBTraceObjectValPath`.
pub struct DBTraceObjectValPath {
    entry_list: Vec<Arc<DBTraceObjectValue>>,
    /// Mirrors the lazily-computed `KeyPath path` field.
    path: OnceLock<KeyPath>,
}

impl DBTraceObjectValPath {
    fn new(entry_list: Vec<Arc<DBTraceObjectValue>>) -> Self {
        Self { entry_list, path: OnceLock::new() }
    }

    /// The zero-length path. Mirrors `DBTraceObjectValPath.of()` / the `EMPTY` constant.
    pub fn empty() -> Self {
        Self::new(Vec::new())
    }

    /// Build a path from an explicit list of entries. Mirrors `of(Collection)` / `of(DBTraceObjectValue...)`.
    pub fn of(entries: Vec<Arc<DBTraceObjectValue>>) -> Self {
        Self::new(entries)
    }

    /// Mirrors `protected KeyPath computePath()`.
    fn compute_path(&self) -> KeyPath {
        KeyPath::of_iter(self.entry_list.iter().map(|e| e.get_entry_key()))
    }

    /// The values in the path, ordered from source to destination. Mirrors `getEntryList()`.
    pub fn get_entry_list(&self) -> &[Arc<DBTraceObjectValue>] {
        &self.entry_list
    }

    /// The keys in the path, ordered from source to destination. Mirrors `getPath()`.
    pub fn get_path(&self) -> KeyPath {
        self.path.get_or_init(|| self.compute_path()).clone()
    }

    /// Order paths by [`KeyPath`]'s keyed ordering. Mirrors `compareTo(TraceObjectValPath)`.
    pub fn compare_to(&self, that: &DBTraceObjectValPath) -> std::cmp::Ordering {
        self.get_path().cmp(&that.get_path())
    }

    /// Check if a given value appears on this path. Mirrors `contains(TraceObjectValue)`.
    ///
    /// Java compares by (default, identity) `equals`; this compares by pointer identity of the
    /// entry itself.
    pub fn contains(&self, entry: &DBTraceObjectValue) -> bool {
        self.entry_list.iter().any(|e| std::ptr::eq(e.as_ref(), entry))
    }

    /// Prepend the entry to this path, generating a new path. Mirrors `prepend(TraceObjectValue)`.
    ///
    /// This performs no validation. The child of the given entry should be the parent of the
    /// first entry in this path.
    pub fn prepend(&self, entry: Arc<DBTraceObjectValue>) -> DBTraceObjectValPath {
        let mut entries = Vec::with_capacity(1 + self.entry_list.len());
        entries.push(entry);
        entries.extend(self.entry_list.iter().cloned());
        DBTraceObjectValPath::new(entries)
    }

    /// Append the entry to this path, generating a new path. Mirrors `append(TraceObjectValue)`.
    ///
    /// This performs no validation. The parent of the given entry should be the child of the last
    /// entry in this path.
    pub fn append(&self, entry: Arc<DBTraceObjectValue>) -> DBTraceObjectValPath {
        let mut entries = self.entry_list.clone();
        entries.push(entry);
        DBTraceObjectValPath::new(entries)
    }

    /// The first entry, i.e., the one adjacent to the source object. Mirrors `getFirstEntry()`.
    pub fn get_first_entry(&self) -> Option<Arc<DBTraceObjectValue>> {
        self.entry_list.first().cloned()
    }

    /// The last entry, i.e., the one adjacent to the destination object. Mirrors `getLastEntry()`.
    pub fn get_last_entry(&self) -> Option<Arc<DBTraceObjectValue>> {
        self.entry_list.last().cloned()
    }

    /// The source object: the parent of the first entry, or `if_empty` when the path is empty.
    /// Mirrors `getSource(TraceObject)`.
    pub fn get_source(
        &self,
        if_empty: Box<dyn crate::trace::seam_stubs::TraceObject>,
    ) -> Box<dyn crate::trace::seam_stubs::TraceObject> {
        match self.get_first_entry() {
            None => if_empty,
            Some(first) => first
                .get_parent_object()
                .map(|p| p as Box<dyn crate::trace::seam_stubs::TraceObject>)
                .expect("the first entry of a non-empty path always has a parent"),
        }
    }

    /// The destination value: the value of the last entry, or `if_empty` when the path is empty.
    /// Mirrors `getDestinationValue(Object)`.
    pub fn get_destination_value(
        &self,
        if_empty: Box<dyn std::any::Any + Send + Sync>,
    ) -> Box<dyn std::any::Any + Send + Sync> {
        match self.get_last_entry() {
            None => if_empty,
            Some(last) => last.get_value(),
        }
    }

    /// The destination object: the child of the last entry, or `if_empty` when the path is empty.
    /// Mirrors `getDestination(TraceObject)`.
    ///
    /// # Panics
    /// Panics if the last entry's value is not an object, mirroring the Java `ClassCastException`.
    pub fn get_destination(
        &self,
        if_empty: Box<dyn crate::trace::seam_stubs::TraceObject>,
    ) -> Box<dyn crate::trace::seam_stubs::TraceObject> {
        match self.get_last_entry() {
            None => if_empty,
            Some(last) => last.get_child_object() as Box<dyn crate::trace::seam_stubs::TraceObject>,
        }
    }
}

impl TraceObjectValPath for DBTraceObjectValPath {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::database::target::trace_object_value_storage::TraceObjectValueStorage;
    use crate::trace::model::lifespan::Lifespan;
    use crate::trace::seam_stubs::{DBTraceObject, DBTraceObjectManager, TraceObject};

    struct MockManager;
    impl DBTraceObjectManager for MockManager {}

    struct MockObject {
        path: KeyPath,
    }

    impl TraceObject for MockObject {
        fn get_schema(&self) -> Box<dyn crate::trace::seam_stubs::TraceObjectSchema> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_object_key(&self) -> Box<dyn crate::trace::seam_stubs::ObjectKey> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_life(&self) -> Box<dyn crate::trace::seam_stubs::LifeSet> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_canonical_path(&self) -> KeyPath {
            self.path.clone()
        }
    }

    impl DBTraceObject for MockObject {
        fn notify_value_created(&self, _value: &DBTraceObjectValue) {}
        fn notify_value_deleted(&self, _value: &DBTraceObjectValue) {}
        fn notify_parent_value_created(&self, _value: &DBTraceObjectValue) {}
        fn notify_parent_value_deleted(&self, _value: &DBTraceObjectValue) {}
    }

    /// A value entry `key` under a parent whose canonical path is `parent_path`, live over
    /// `[0,10]`, holding no object as its value.
    struct MockStorage {
        parent_path: &'static str,
        entry_key: &'static str,
    }

    impl TraceObjectValueStorage for MockStorage {
        fn get_manager(&self) -> Box<dyn DBTraceObjectManager> {
            Box::new(MockManager)
        }
        fn get_wrapper(&self) -> Option<Arc<DBTraceObjectValue>> {
            None
        }
        fn get_parent(&self) -> Option<Box<dyn DBTraceObject>> {
            Some(Box::new(MockObject { path: KeyPath::parse(self.parent_path).unwrap() }))
        }
        fn get_entry_key(&self) -> String {
            self.entry_key.to_string()
        }
        fn do_set_lifespan(&mut self, _lifespan: Lifespan) {}
        fn get_lifespan(&self) -> Lifespan {
            Lifespan::span(0, 10)
        }
        fn get_child_or_null(&self) -> Option<Box<dyn DBTraceObject>> {
            None
        }
        fn get_value(&self) -> Box<dyn std::any::Any + Send + Sync> {
            Box::new(42i64)
        }
        fn is_deleted(&self) -> bool {
            false
        }
        fn do_delete(&mut self) {}
    }

    fn make_entry(parent_path: &'static str, entry_key: &'static str) -> Arc<DBTraceObjectValue> {
        Arc::new(DBTraceObjectValue::new(
            Arc::new(MockManager),
            Box::new(MockStorage { parent_path, entry_key }),
        ))
    }

    #[test]
    fn empty_path_has_the_root_key_path() {
        // Java: KeyPath.of(Stream.empty()) -> the root path.
        let path = DBTraceObjectValPath::empty();
        assert_eq!(path.get_path(), KeyPath::root());
        assert!(path.get_first_entry().is_none());
        assert!(path.get_last_entry().is_none());
    }

    #[test]
    fn path_key_is_the_concatenation_of_entry_keys() {
        let a = make_entry("Process[1]", "Threads");
        let b = make_entry("Process[1].Threads", "[0]");
        let path = DBTraceObjectValPath::of(vec![a, b]);
        // Java: KeyPath.of(entryList.stream().map(TraceObjectValue::getEntryKey))
        assert_eq!(path.get_path(), KeyPath::parse("Threads[0]").unwrap());
    }

    #[test]
    fn append_and_prepend_build_new_paths_without_mutating_the_original() {
        let a = make_entry("Process[1]", "Threads");
        let b = make_entry("Process[1].Threads", "[0]");
        let base = DBTraceObjectValPath::of(vec![Arc::clone(&a)]);

        let appended = base.append(Arc::clone(&b));
        assert_eq!(appended.get_entry_list().len(), 2);
        assert_eq!(appended.get_path(), KeyPath::parse("Threads[0]").unwrap());
        // The original path is untouched.
        assert_eq!(base.get_entry_list().len(), 1);

        let prepended = appended.prepend(make_entry("Session", "Process"));
        assert_eq!(prepended.get_entry_list().len(), 3);
        assert_eq!(prepended.get_path(), KeyPath::parse("Process.Threads[0]").unwrap());
    }

    #[test]
    fn contains_checks_entry_identity_not_equality() {
        let a = make_entry("Process[1]", "Threads");
        let b = make_entry("Process[1].Threads", "[0]");
        let path = DBTraceObjectValPath::of(vec![Arc::clone(&a)]);
        assert!(path.contains(&a));
        assert!(!path.contains(&b));
    }

    #[test]
    fn compare_to_orders_by_keyed_path() {
        let a = DBTraceObjectValPath::of(vec![make_entry("Process[1]", "Alpha")]);
        let b = DBTraceObjectValPath::of(vec![make_entry("Process[1]", "Beta")]);
        assert_eq!(a.compare_to(&b), std::cmp::Ordering::Less);
        assert_eq!(b.compare_to(&a), std::cmp::Ordering::Greater);
        assert_eq!(a.compare_to(&a), std::cmp::Ordering::Equal);
    }

    #[test]
    fn source_and_destination_fall_back_to_if_empty_on_the_empty_path() {
        let path = DBTraceObjectValPath::empty();
        let fallback = MockObject { path: KeyPath::parse("Session").unwrap() };
        let fallback_key = fallback.get_canonical_path();
        let source = path.get_source(Box::new(fallback));
        assert_eq!(source.get_canonical_path(), fallback_key);

        let fallback2 = MockObject { path: KeyPath::parse("Session").unwrap() };
        let dest = path.get_destination(Box::new(fallback2));
        assert_eq!(dest.get_canonical_path(), fallback_key);

        let fallback_value: Box<dyn std::any::Any + Send + Sync> = Box::new(7i64);
        let dest_value = path.get_destination_value(fallback_value);
        assert_eq!(*dest_value.downcast::<i64>().unwrap(), 7);
    }

    #[test]
    fn source_is_the_first_entrys_parent() {
        let a = make_entry("Process[1]", "Threads");
        let path = DBTraceObjectValPath::of(vec![a]);
        let fallback = MockObject { path: KeyPath::root() };
        let source = path.get_source(Box::new(fallback));
        assert_eq!(source.get_canonical_path(), KeyPath::parse("Process[1]").unwrap());
    }
}

//! A single value entry (attribute or element) in the trace object database.
//!
//! Java source: `ghidra.trace.database.target.DBTraceObjectValue`, a concrete
//! `class DBTraceObjectValue implements TraceObjectValue`, so this is a `struct` implementing the
//! already-ported [`TraceObjectValue`] trait.
//!
//! The class is a thin, lock-taking *wrapper* around a [`TraceObjectValueStorage`]: the storage
//! holds the record (parent, key, value, lifespan) and the wrapper adds the trace lock, the
//! canonical-path logic, and the change notifications. Java swaps the storage out under the
//! wrapper (`setWrapped`) when an entry moves between the R*-tree table and the primitive-value
//! table, which is why the field is `volatile` and why it is behind an [`RwLock`] here.
//!
//! # Cycle
//!
//! This type sits on the object/value cycle: a value's parent and child are `DBTraceObject`s,
//! and an object's values are `DBTraceObjectValue`s. `DBTraceObject` is not ported yet, so it
//! stays behind the [`DBTraceObject`] placeholder, which this port grows with the
//! package-private members the wrapper calls (`emitEvents`, the four `notifyXxx` hooks,
//! `doCheckConflicts`, `doAdjust`, `doCreateValue`) and re-declares as a subtrait of
//! [`TraceObject`] -- which the Java class is -- so that parents and children can be widened for
//! the [`TraceObjectValue`] impl.
//!
//! # Locking
//!
//! Java takes `manager.lock` (the domain object's shared `ReadWriteLock`) around every storage
//! access, and `manager.trace.lockRead()`/`getTrace().lockWrite()` -- the same lock -- in a few
//! places. Following
//! [`DBTraceTimeManager`](crate::trace::database::time::db_trace_time_manager), which took the
//! same parameter and made it the lock around the data it guards, that lock becomes the
//! [`RwLock`] around `wrapped`: `LockHold.lock(manager.lock.readLock())` maps to
//! `self.wrapped.read()` and the write lock to `self.wrapped.write()`. As there, guards are
//! released *before* any `notifyXxx`/`emitEvents` callback runs, since those call back out into
//! the object and thence the trace.
//!
//! # Not reproduced
//!
//! - The nested `static abstract class ValueLifespanSetter`, and with it the coalescing half of
//!   `setLifespan(Lifespan, ConflictResolution)`. It is a
//!   [`RangeMapSetter`](crate::generic::range_map_setter::RangeMapSetter) whose value type is
//!   Java's `Object` with an array-aware `valuesEqual`; the ported `RangeMapSetter` requires
//!   `V: PartialEq + Clone`, which the `Box<dyn Any + Send + Sync>` this port uses for an
//!   unconstrained value type (see
//!   [`TraceObjectValue::get_value`]) is not, and its `getIntersecting`/`create` hooks need
//!   `DBTraceObject.streamValuesR`/`doCreateValue` over a real object table. What remains is the
//!   part that does not depend on the setter: the conflict-resolution prologue, the lifespan
//!   write plus its `VALUE_LIFESPAN_CHANGED` event, and the child's `OBJECT_LIFE_CHANGED` event
//!   -- which is exactly what the setter reduces to when no other entry intersects.
//! - `protected Stream<? extends TraceObjectValPath> doStreamVisitor(Lifespan, Visitor)`. Its
//!   whole body is `TreeTraversal.INSTANCE.walkValue(...)`, a call on a *static singleton* of the
//!   unported `TreeTraversal`. Rust cannot call through to a static-like member of a placeholder
//!   trait without already knowing a concrete implementor -- the same omission
//!   [`DBTraceObjectInterface`](crate::trace::database::target::db_trace_object_interface)
//!   documents for `DBTraceObject.spaceForValue`.
//! - `TraceEvents.VALUE_LIFESPAN_CHANGED` / `VALUE_DELETED` / `OBJECT_LIFE_CHANGED`. The generic
//!   event table is unported, so, as in `DBTraceTimeManager`, the three constants become the
//!   local [`ValueEvent`] enum, built into a real
//!   [`TraceChangeRecord`](crate::trace::util::trace_change_record::TraceChangeRecord) by
//!   [`value_change_record`].

use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, RwLock};

use once_cell::sync::Lazy;

use crate::framework::model::{DomainObjectEventIdGenerator, EventType};
use crate::trace::database::target::trace_object_value_storage::TraceObjectValueStorage;
use crate::trace::model::lifespan::Lifespan;
use crate::trace::model::target::duplicate_key_exception::DuplicateKeyException;
use crate::trace::model::target::path::key_path::KeyPath;
use crate::trace::model::target::trace_object_value::{TraceObjectValue, TruncateOrDelete};
use crate::trace::model::trace::Trace;
use crate::trace::seam_stubs::{DBTraceObject, DBTraceObjectManager};
use crate::trace::model::target::trace_object::{ConflictResolution, TraceObject};
use crate::trace::util::trace_change_record::TraceChangeRecord;

/// Which value event a [`value_change_record`] carries.
///
/// Stands in for the `TraceEvents.VALUE_LIFESPAN_CHANGED` / `VALUE_DELETED` /
/// `OBJECT_LIFE_CHANGED` constants, which live in the unported `TraceEvents`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ValueEvent {
    /// `TraceEvents.VALUE_LIFESPAN_CHANGED`: a value entry's lifespan was rewritten.
    LifespanChanged,
    /// `TraceEvents.VALUE_DELETED`: a value entry was removed.
    Deleted,
    /// `TraceEvents.OBJECT_LIFE_CHANGED`: a canonical value entry's lifespan change altered the
    /// child object's life.
    ObjectLifeChanged,
}

static VALUE_EVENT_IDS: Lazy<HashMap<ValueEvent, i32>> = Lazy::new(|| {
    [ValueEvent::LifespanChanged, ValueEvent::Deleted, ValueEvent::ObjectLifeChanged]
        .into_iter()
        .map(|event| (event, DomainObjectEventIdGenerator::next()))
        .collect()
});

impl EventType for ValueEvent {
    fn get_id(&self) -> i32 {
        VALUE_EVENT_IDS.get(self).copied().expect("ValueEvent variant should have an id")
    }
}

/// Builds the [`TraceChangeRecord`] mirroring `new TraceChangeRecord<>(TraceEvents.XXX, null,
/// value, old, new)`.
///
/// The affected entry's key stands in for the record's affected-object reference, which cannot
/// be a `&DBTraceObjectValue` without tying the record to the entry's lifetime. `old_lifespan` /
/// `new_lifespan` are only known together (for [`ValueEvent::LifespanChanged`]); otherwise the
/// record carries no old/new value, mirroring the 3-argument `TraceChangeRecord` constructor.
fn value_change_record(
    event: ValueEvent,
    entry_key: String,
    old_lifespan: Option<Lifespan>,
    new_lifespan: Option<Lifespan>,
) -> TraceChangeRecord {
    let affected_object = Some(Box::new(entry_key) as Box<dyn Any + Send + Sync>);
    match (old_lifespan, new_lifespan) {
        (Some(old), Some(new)) => TraceChangeRecord::new(
            Box::new(event),
            None,
            affected_object,
            Some(Box::new(old) as Box<dyn Any + Send + Sync>),
            Some(Box::new(new) as Box<dyn Any + Send + Sync>),
        ),
        _ => TraceChangeRecord::without_values(Box::new(event), None, affected_object),
    }
}

/// A single value entry (attribute or element) attached to a `DBTraceObject`.
///
/// Port of `ghidra.trace.database.target.DBTraceObjectValue`. See the module docs for the
/// cycle-cutting, locking, and omissions.
pub struct DBTraceObjectValue {
    manager: Arc<dyn DBTraceObjectManager>,
    /// Mirrors the `volatile TraceObjectValueStorage wrapped` field. See the module docs for why
    /// the trace lock became this [`RwLock`].
    wrapped: RwLock<Box<dyn TraceObjectValueStorage>>,
}

impl DBTraceObjectValue {
    /// Wrap `wrapped` as a value entry of `manager`'s object database.
    ///
    /// Mirrors `DBTraceObjectValue(DBTraceObjectManager, TraceObjectValueStorage)`.
    pub fn new(
        manager: Arc<dyn DBTraceObjectManager>,
        wrapped: Box<dyn TraceObjectValueStorage>,
    ) -> Self {
        Self { manager, wrapped: RwLock::new(wrapped) }
    }

    /// Swap in a new storage record for this entry.
    ///
    /// Mirrors the package-private `setWrapped(TraceObjectValueStorage)`, minus its
    /// `data.setWrapper(this)` back-pointer: `TraceObjectValueStorage::get_wrapper` is
    /// `Option<Arc<DBTraceObjectValue>>` precisely because that back-pointer is an ownership
    /// cycle, and a `&self` method has no `Arc<Self>` to install. A caller that holds the entry
    /// as an `Arc` should pair this with the storage's own wrapper setter once one exists.
    pub(crate) fn set_wrapped(&self, wrapped: Box<dyn TraceObjectValueStorage>) {
        *self.wrapped.write().expect("value storage lock poisoned") = wrapped;
    }

    /// Run `f` against this entry's storage record.
    ///
    /// Mirrors `public TraceObjectValueStorage getWrapped()`. Java hands out the reference
    /// itself; here the record lives behind the [`RwLock`] that replaced the trace lock, so it is
    /// borrowed for the duration of a closure instead.
    pub fn with_wrapped<R>(&self, f: impl FnOnce(&dyn TraceObjectValueStorage) -> R) -> R {
        f(&**self.wrapped.read().expect("value storage lock poisoned"))
    }

    /// This entry's parent object, or `None` if this is the root value.
    ///
    /// Mirrors `getParent()`, which is covariant on `DBTraceObject` where [`TraceObjectValue`]
    /// only promises `TraceObject`.
    pub fn get_parent_object(&self) -> Option<Box<dyn DBTraceObject>> {
        self.wrapped.read().expect("value storage lock poisoned").get_parent()
    }

    /// This entry's value as an object.
    ///
    /// Mirrors `getChild()`, which is covariant on `DBTraceObject`.
    ///
    /// # Panics
    /// Panics if the value is not an object, mirroring the Java `ClassCastException` from
    /// `(DBTraceObject) wrapped.getValue()`.
    pub fn get_child_object(&self) -> Box<dyn DBTraceObject> {
        self.wrapped
            .read()
            .expect("value storage lock poisoned")
            .get_child_or_null()
            .expect("value is not an object")
    }

    /// The parent's canonical path extended by this entry's key, or the root path if this is the
    /// root value.
    ///
    /// Mirrors `protected KeyPath doGetCanonicalPath()`; the caller is expected to hold the lock.
    pub fn do_get_canonical_path(&self) -> KeyPath {
        let (parent, entry_key) = {
            let wrapped = self.wrapped.read().expect("value storage lock poisoned");
            (wrapped.get_parent(), wrapped.get_entry_key())
        };
        match parent {
            None => KeyPath::root(),
            Some(parent) => parent.get_canonical_path().extend_keys(&[&entry_key]),
        }
    }

    /// Whether this entry names its child's canonical location.
    ///
    /// Mirrors `protected boolean doIsCanonical()`.
    pub fn do_is_canonical(&self) -> bool {
        let child = {
            let wrapped = self.wrapped.read().expect("value storage lock poisoned");
            match wrapped.get_child_or_null() {
                None => return false,
                // The root value has no parent, and is canonical by definition.
                Some(_) if wrapped.get_parent().is_none() => return true,
                Some(child) => child,
            }
        };
        self.do_get_canonical_path() == child.get_canonical_path()
    }

    /// Rewrite this entry's lifespan and announce it.
    ///
    /// Mirrors the package-private `doSetLifespanAndEmit(Lifespan)`.
    pub(crate) fn do_set_lifespan_and_emit(&self, lifespan: Lifespan) {
        let old_lifespan = self.do_get_lifespan();
        self.do_set_lifespan(lifespan);
        self.emit_to_parent(value_change_record(
            ValueEvent::LifespanChanged,
            self.do_get_entry_key(),
            Some(old_lifespan),
            Some(lifespan),
        ));
    }

    /// Rewrite this entry's lifespan, re-keying the parent's and child's caches around the write.
    ///
    /// Mirrors the package-private `doSetLifespan(Lifespan)`. A no-op if the lifespan is
    /// unchanged, as in Java.
    pub(crate) fn do_set_lifespan(&self, lifespan: Lifespan) {
        let (parent, child) = {
            let wrapped = self.wrapped.read().expect("value storage lock poisoned");
            if wrapped.get_lifespan() == lifespan {
                return;
            }
            (wrapped.get_parent(), wrapped.get_child_or_null())
        };
        let parent = parent.expect("cannot set the lifespan of the root value");

        parent.notify_value_deleted(self);
        if let Some(child) = &child {
            child.notify_parent_value_deleted(self);
        }
        self.wrapped.write().expect("value storage lock poisoned").do_set_lifespan(lifespan);
        parent.notify_value_created(self);
        if let Some(child) = &child {
            child.notify_parent_value_created(self);
        }
    }

    /// Remove this entry from its parent's and child's caches and from storage, without
    /// announcing it.
    ///
    /// Mirrors the package-private `doDelete()`.
    pub(crate) fn do_delete(&self) {
        let (parent, child) = {
            let wrapped = self.wrapped.read().expect("value storage lock poisoned");
            (wrapped.get_parent(), wrapped.get_child_or_null())
        };
        let parent = parent.expect("cannot delete the root value");

        parent.notify_value_deleted(self);
        if let Some(child) = &child {
            child.notify_parent_value_deleted(self);
        }
        self.wrapped.write().expect("value storage lock poisoned").do_delete();
    }

    /// Delete this entry and announce it.
    ///
    /// Mirrors the package-private `doDeleteAndEmit()`.
    pub(crate) fn do_delete_and_emit(&self) {
        let entry_key = self.do_get_entry_key();
        let parent = self.get_parent_object().expect("cannot delete the root value");
        self.do_delete();
        parent.emit_events(&value_change_record(ValueEvent::Deleted, entry_key, None, None));
    }

    /// Clear `span` out of this entry's lifespan, announcing the child object's life change if
    /// this entry is canonical.
    ///
    /// Mirrors the package-private `doTruncateOrDeleteAndEmitLifeChange(Lifespan)`.
    pub(crate) fn do_truncate_or_delete_and_emit_life_change(
        &self,
        span: Lifespan,
    ) -> TruncateOrDelete {
        if !self.do_is_canonical() {
            return self.do_truncate_or_delete(span);
        }
        let child = self.get_child_object();
        let result = self.do_truncate_or_delete(span);
        child.emit_events(&value_change_record(
            ValueEvent::ObjectLifeChanged,
            self.do_get_entry_key(),
            None,
            None,
        ));
        result
    }

    /// Clear `span` out of this entry's lifespan, deleting the entry if nothing is left and
    /// splitting it in two if `span` falls strictly inside it.
    ///
    /// Mirrors the package-private `doTruncateOrDelete(Lifespan)`. Its three Java returns --
    /// `null`, `this`, and a freshly created entry -- map onto the three
    /// [`TruncateOrDelete`] variants.
    pub(crate) fn do_truncate_or_delete(&self, span: Lifespan) -> TruncateOrDelete {
        let removed = self.do_get_lifespan().subtract(span);
        let Some(first) = removed.first().copied() else {
            self.do_delete_and_emit();
            return TruncateOrDelete::Deleted;
        };
        self.do_set_lifespan_and_emit(first);
        match removed.get(1).copied() {
            None => TruncateOrDelete::Unchanged,
            Some(second) => {
                let (entry_key, value) = {
                    let wrapped = self.wrapped.read().expect("value storage lock poisoned");
                    (wrapped.get_entry_key(), wrapped.get_value())
                };
                let parent = self
                    .get_parent_object()
                    .expect("cannot truncate or delete the root value");
                TruncateOrDelete::Split(parent.do_create_value(second, &entry_key, value))
            }
        }
    }

    /// Set this entry's lifespan under the given conflict-resolution strategy.
    ///
    /// Mirrors `setLifespan(Lifespan, ConflictResolution)`, minus the `ValueLifespanSetter`
    /// coalescing pass (see the module docs).
    ///
    /// # Panics
    /// Panics if this is the root value, mirroring the Java `IllegalArgumentException`.
    pub fn do_set_lifespan_with_resolution(
        &self,
        lifespan: Lifespan,
        resolution: ConflictResolution,
    ) -> Result<(), DuplicateKeyException> {
        let (entry_key, value) = {
            let wrapped = self.wrapped.read().expect("value storage lock poisoned");
            (wrapped.get_entry_key(), wrapped.get_value())
        };
        let parent =
            self.get_parent_object().expect("cannot set the lifespan of the root value");

        let lifespan = match resolution {
            ConflictResolution::Deny => {
                parent.do_check_conflicts(lifespan, &entry_key, &*value)?;
                lifespan
            }
            ConflictResolution::Adjust => parent.do_adjust(lifespan, &entry_key, &*value),
            ConflictResolution::Truncate => lifespan,
        };

        self.do_set_lifespan_and_emit(lifespan);

        if self.do_is_object() {
            let child = self.get_child_object();
            child.emit_events(&value_change_record(
                ValueEvent::ObjectLifeChanged,
                entry_key,
                None,
                None,
            ));
        }
        Ok(())
    }

    /// The storage record's lifespan, read under the lock. The body of `getLifespan()`.
    fn do_get_lifespan(&self) -> Lifespan {
        self.wrapped.read().expect("value storage lock poisoned").get_lifespan()
    }

    /// The storage record's key, read under the lock. The body of `getEntryKey()`.
    fn do_get_entry_key(&self) -> String {
        self.wrapped.read().expect("value storage lock poisoned").get_entry_key()
    }

    /// Whether the storage record's value is an object. The body of `isObject()`.
    fn do_is_object(&self) -> bool {
        self.wrapped.read().expect("value storage lock poisoned").get_child_or_null().is_some()
    }

    /// Hand `record` to the parent object, if there is one. The root value has no parent to
    /// notify; Java would throw an NPE, but every caller here reaches this only for a non-root
    /// entry.
    fn emit_to_parent(&self, record: TraceChangeRecord) {
        if let Some(parent) = self.get_parent_object() {
            parent.emit_events(&record);
        }
    }
}

impl fmt::Display for DBTraceObjectValue {
    /// Java's `toString()` returns `wrapped.toString()`, which is the `DBAnnotatedObject`
    /// record dump of the storage row. [`TraceObjectValueStorage`] has no such member (Java
    /// declares none either -- the text comes from the DB record superclass), so this renders the
    /// fields the storage does expose.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let wrapped = self.wrapped.read().expect("value storage lock poisoned");
        write!(f, "{}@{}", wrapped.get_entry_key(), wrapped.get_lifespan())?;
        if wrapped.is_deleted() {
            f.write_str(" (deleted)")?;
        }
        Ok(())
    }
}

impl fmt::Debug for DBTraceObjectValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DBTraceObjectValue({self})")
    }
}

impl TraceObjectValue for DBTraceObjectValue {
    fn get_trace(&self) -> Box<dyn Trace> {
        self.manager.get_trace()
    }

    fn get_parent(&self) -> Option<Box<dyn TraceObject>> {
        self.get_parent_object().map(|p| p as Box<dyn TraceObject>)
    }

    fn get_entry_key(&self) -> String {
        self.do_get_entry_key()
    }

    fn get_canonical_path(&self) -> KeyPath {
        self.do_get_canonical_path()
    }

    fn get_value(&self) -> Box<dyn Any + Send + Sync> {
        self.wrapped.read().expect("value storage lock poisoned").get_value()
    }

    fn get_child(&self) -> Box<dyn TraceObject> {
        self.get_child_object()
    }

    fn is_object(&self) -> bool {
        self.do_is_object()
    }

    fn is_canonical(&self) -> bool {
        self.do_is_canonical()
    }

    fn set_lifespan(&mut self, lifespan: Lifespan) {
        self.do_set_lifespan_with_resolution(lifespan, ConflictResolution::Truncate)
            .expect("TRUNCATE resolution never reports a duplicate key");
    }

    fn set_lifespan_with_resolution(
        &mut self,
        span: Lifespan,
        resolution: ConflictResolution,
    ) -> Result<(), DuplicateKeyException> {
        self.do_set_lifespan_with_resolution(span, resolution)
    }

    fn get_lifespan(&self) -> Lifespan {
        self.do_get_lifespan()
    }

    fn set_min_snap(&mut self, min_snap: i64) {
        let lifespan = Lifespan::span(min_snap, self.do_get_lifespan().lmax());
        self.set_lifespan(lifespan);
    }

    fn get_min_snap(&self) -> i64 {
        self.do_get_lifespan().lmin()
    }

    fn set_max_snap(&mut self, max_snap: i64) {
        let lifespan = Lifespan::span(self.do_get_lifespan().lmin(), max_snap);
        self.set_lifespan(lifespan);
    }

    fn get_max_snap(&self) -> i64 {
        self.do_get_lifespan().lmax()
    }

    fn delete(&mut self) {
        assert!(self.get_parent_object().is_some(), "Cannot delete root value");
        self.do_delete_and_emit();
    }

    fn is_deleted(&self) -> bool {
        self.wrapped.read().expect("value storage lock poisoned").is_deleted()
    }

    fn truncate_or_delete(&mut self, span: Lifespan) -> TruncateOrDelete {
        assert!(
            self.get_parent_object().is_some(),
            "Cannot truncate or delete root value"
        );
        self.do_truncate_or_delete_and_emit_life_change(span)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::debug::api::tracermi::SchemaName;
    use crate::trace::seam_stubs::{LifeSet, ObjectKey, TraceObjectSchema};
    use std::sync::Mutex;

    /// Everything the mock object graph shares: the value record's mutable state plus a log of
    /// the notifications and events the wrapper made.
    #[derive(Default)]
    struct Shared {
        lifespan: Option<Lifespan>,
        deleted: bool,
        log: Vec<String>,
        created: Vec<(Lifespan, String)>,
    }

    struct Fixture {
        shared: Mutex<Shared>,
        /// The canonical path the mock parent reports, mirroring `DBTraceObject.getCanonicalPath`.
        /// `None` models the root value, whose record has no parent.
        parent_path: Option<KeyPath>,
        /// The canonical path the mock child reports, or `None` for a non-object value.
        child_path: Option<KeyPath>,
        entry_key: String,
    }

    impl Fixture {
        /// A record for `entry_key` under `parent_path`, live over `[0,10]`.
        fn new(parent_path: Option<&str>, entry_key: &str, child_path: Option<&str>) -> Arc<Self> {
            Arc::new(Fixture {
                shared: Mutex::new(Shared {
                    lifespan: Some(Lifespan::span(0, 10)),
                    ..Shared::default()
                }),
                parent_path: parent_path.map(|p| KeyPath::parse(p).unwrap()),
                child_path: child_path.map(|p| KeyPath::parse(p).unwrap()),
                entry_key: entry_key.to_string(),
            })
        }

        fn log(&self, entry: impl Into<String>) {
            self.shared.lock().unwrap().log.push(entry.into());
        }

        fn lifespan(&self) -> Lifespan {
            self.shared.lock().unwrap().lifespan.expect("no lifespan set")
        }

        fn take_log(&self) -> Vec<String> {
            std::mem::take(&mut self.shared.lock().unwrap().log)
        }
    }

    struct MockSchema;
    impl TraceObjectSchema for MockSchema {
        fn get_name(&self) -> SchemaName {
            SchemaName::new("Mock")
        }
        fn to_string(&self) -> String {
            "Mock".to_string()
        }
    }

    struct MockKey(i32);
    impl ObjectKey for MockKey {
        fn equals(&self, obj: &dyn Any) -> bool {
            obj.downcast_ref::<MockKey>().is_some_and(|o| o.0 == self.0)
        }
        fn hash_code(&self) -> i32 {
            self.0
        }
        fn compare_to(&self, that: &dyn ObjectKey) -> i32 {
            self.0 - that.hash_code()
        }
    }

    struct MockLife;
    impl LifeSet for MockLife {
        fn is_empty(&self) -> bool {
            false
        }
    }

    /// A mock `DBTraceObject` standing in for either the parent or the child of the entry under
    /// test. `role` distinguishes the two in the notification log.
    struct MockObject {
        fixture: Arc<Fixture>,
        role: &'static str,
        path: KeyPath,
    }

    impl crate::trace::model::trace_unique_object::TraceUniqueObject for MockObject {
        fn get_object_key(&self) -> Box<dyn ObjectKey> {
            Box::new(MockKey(0))
        }

        fn is_deleted(&self) -> bool {
            false
        }
    }

    impl TraceObject for MockObject {
        fn get_schema(&self) -> Box<dyn TraceObjectSchema> {
            Box::new(MockSchema)
        }
        fn get_life(&self) -> Box<dyn LifeSet> {
            Box::new(MockLife)
        }
        fn get_canonical_path(&self) -> KeyPath {
            self.path.clone()
        }

        crate::trace::model::target::trace_object::unimplemented_trace_object_members!();
    }

    impl DBTraceObject for MockObject {
        fn emit_events(&self, record: &TraceChangeRecord) {
            let _ = record;
            self.fixture.log(format!("{}:emit", self.role));
        }
        fn notify_value_created(&self, _value: &DBTraceObjectValue) {
            self.fixture.log(format!("{}:valueCreated", self.role));
        }
        fn notify_value_deleted(&self, _value: &DBTraceObjectValue) {
            self.fixture.log(format!("{}:valueDeleted", self.role));
        }
        fn notify_parent_value_created(&self, _value: &DBTraceObjectValue) {
            self.fixture.log(format!("{}:parentValueCreated", self.role));
        }
        fn notify_parent_value_deleted(&self, _value: &DBTraceObjectValue) {
            self.fixture.log(format!("{}:parentValueDeleted", self.role));
        }
        fn do_check_conflicts(
            &self,
            _lifespan: Lifespan,
            key: &str,
            _value: &(dyn Any + Send + Sync),
        ) -> Result<(), DuplicateKeyException> {
            // The mock parent always reports a conflict, so DENY can be observed.
            Err(DuplicateKeyException::new(key))
        }
        fn do_adjust(
            &self,
            lifespan: Lifespan,
            _key: &str,
            _value: &(dyn Any + Send + Sync),
        ) -> Lifespan {
            // The mock parent has room only up to snap 8.
            Lifespan::span(lifespan.lmin(), lifespan.lmax().min(8))
        }
        fn do_create_value(
            &self,
            lifespan: Lifespan,
            key: &str,
            _value: Box<dyn Any + Send + Sync>,
        ) -> Box<DBTraceObjectValue> {
            self.fixture.shared.lock().unwrap().created.push((lifespan, key.to_string()));
            let created = Fixture::new(Some("Process[1]"), key, None);
            created.shared.lock().unwrap().lifespan = Some(lifespan);
            Box::new(make_value(created))
        }
    }

    struct MockManager;
    impl DBTraceObjectManager for MockManager {}

    struct MockStorage(Arc<Fixture>);

    impl TraceObjectValueStorage for MockStorage {
        fn get_manager(&self) -> Box<dyn DBTraceObjectManager> {
            Box::new(MockManager)
        }
        fn get_wrapper(&self) -> Option<Arc<DBTraceObjectValue>> {
            None
        }
        fn get_parent(&self) -> Option<Box<dyn DBTraceObject>> {
            self.0.parent_path.clone().map(|path| {
                Box::new(MockObject { fixture: Arc::clone(&self.0), role: "parent", path })
                    as Box<dyn DBTraceObject>
            })
        }
        fn get_entry_key(&self) -> String {
            self.0.entry_key.clone()
        }
        fn do_set_lifespan(&mut self, lifespan: Lifespan) {
            self.0.shared.lock().unwrap().lifespan = Some(lifespan);
        }
        fn get_lifespan(&self) -> Lifespan {
            self.0.lifespan()
        }
        fn get_child_or_null(&self) -> Option<Box<dyn DBTraceObject>> {
            self.0.child_path.clone().map(|path| {
                Box::new(MockObject { fixture: Arc::clone(&self.0), role: "child", path })
                    as Box<dyn DBTraceObject>
            })
        }
        fn get_value(&self) -> Box<dyn Any + Send + Sync> {
            Box::new(42i64)
        }
        fn is_deleted(&self) -> bool {
            self.0.shared.lock().unwrap().deleted
        }
        fn do_delete(&mut self) {
            self.0.shared.lock().unwrap().deleted = true;
        }
    }

    fn make_value(fixture: Arc<Fixture>) -> DBTraceObjectValue {
        DBTraceObjectValue::new(Arc::new(MockManager), Box::new(MockStorage(fixture)))
    }

    /// A plain (non-object) attribute `Process[1].State` over snaps 0..=10.
    fn attribute_fixture() -> Arc<Fixture> {
        Fixture::new(Some("Process[1]"), "State", None)
    }

    #[test]
    fn canonical_path_extends_the_parents_path_with_the_entry_key() {
        let value = make_value(attribute_fixture());
        // Java: parent.getCanonicalPath().extend(wrapped.getEntryKey())
        assert_eq!(value.get_canonical_path(), KeyPath::parse("Process[1].State").unwrap());
    }

    #[test]
    fn root_value_has_the_root_canonical_path() {
        let value = make_value(Fixture::new(None, "", None));
        // Java: parent == null -> KeyPath.of()
        assert_eq!(value.get_canonical_path(), KeyPath::root());
        assert!(value.get_parent().is_none());
    }

    #[test]
    fn a_non_object_value_is_neither_object_nor_canonical() {
        let value = make_value(attribute_fixture());
        assert!(!value.is_object());
        assert!(!value.is_canonical());
        assert_eq!(*value.get_value().downcast::<i64>().unwrap(), 42);
    }

    #[test]
    fn a_value_is_canonical_only_when_it_names_the_childs_own_path() {
        // `Process[1].Threads[0]` holding the thread whose canonical path that is.
        let canonical =
            Fixture::new(Some("Process[1].Threads"), "[0]", Some("Process[1].Threads[0]"));
        assert!(make_value(canonical).is_canonical());

        // A link: the same slot, but the child's canonical path lives elsewhere in the tree.
        let link = Fixture::new(Some("Process[1].Threads"), "[0]", Some("Session.Threads[7]"));
        assert!(!make_value(link).is_canonical());
    }

    #[test]
    fn the_root_value_is_canonical_when_it_holds_an_object() {
        // Java doIsCanonical: `if (wrapped.getParent() == null) return true;` -- we're the root.
        let root = Fixture::new(None, "", Some("Session.Anything"));
        assert!(make_value(root).is_canonical());
    }

    #[test]
    fn snap_accessors_read_the_storage_lifespan() {
        let value = make_value(attribute_fixture());
        assert_eq!(value.get_min_snap(), 0);
        assert_eq!(value.get_max_snap(), 10);
        assert_eq!(value.get_lifespan(), Lifespan::span(0, 10));
    }

    #[test]
    fn set_min_snap_rewrites_the_lower_bound_and_emits() {
        let fixture = attribute_fixture();
        let mut value = make_value(Arc::clone(&fixture));
        value.set_min_snap(3);
        assert_eq!(value.get_lifespan(), Lifespan::span(3, 10));
        // Java doSetLifespan re-keys the parent's cache around the write, then
        // doSetLifespanAndEmit fires VALUE_LIFESPAN_CHANGED at the parent.
        assert_eq!(
            fixture.take_log(),
            vec!["parent:valueDeleted", "parent:valueCreated", "parent:emit"]
        );
    }

    #[test]
    fn set_max_snap_rewrites_the_upper_bound() {
        let mut value = make_value(attribute_fixture());
        value.set_max_snap(4);
        assert_eq!(value.get_lifespan(), Lifespan::span(0, 4));
    }

    #[test]
    fn setting_an_unchanged_lifespan_notifies_nobody() {
        let fixture = attribute_fixture();
        let value = make_value(Arc::clone(&fixture));
        value.do_set_lifespan(Lifespan::span(0, 10));
        // Java: `if (wrapped.getLifespan().equals(lifespan)) return;`
        assert!(fixture.take_log().is_empty());
    }

    #[test]
    fn deny_resolution_reports_the_parents_conflict_and_leaves_the_lifespan_alone() {
        let fixture = attribute_fixture();
        let mut value = make_value(Arc::clone(&fixture));
        let err = value
            .set_lifespan_with_resolution(Lifespan::span(0, 20), ConflictResolution::Deny)
            .unwrap_err();
        assert_eq!(err.key(), "State");
        assert_eq!(value.get_lifespan(), Lifespan::span(0, 10));
    }

    #[test]
    fn adjust_resolution_uses_the_span_the_parent_grants() {
        let mut value = make_value(attribute_fixture());
        value
            .set_lifespan_with_resolution(Lifespan::span(0, 20), ConflictResolution::Adjust)
            .unwrap();
        // The mock parent has room only through snap 8.
        assert_eq!(value.get_lifespan(), Lifespan::span(0, 8));
    }

    #[test]
    fn delete_unhooks_the_entry_and_emits_value_deleted() {
        let fixture = attribute_fixture();
        let mut value = make_value(Arc::clone(&fixture));
        assert!(!value.is_deleted());
        value.delete();
        assert!(value.is_deleted());
        assert_eq!(fixture.take_log(), vec!["parent:valueDeleted", "parent:emit"]);
    }

    #[test]
    #[should_panic(expected = "Cannot delete root value")]
    fn deleting_the_root_value_is_rejected() {
        let mut value = make_value(Fixture::new(None, "", None));
        value.delete();
    }

    #[test]
    fn truncate_or_delete_removes_the_entry_when_the_span_covers_it() {
        let fixture = attribute_fixture();
        let mut value = make_value(Arc::clone(&fixture));
        // Java: getLifespan().subtract(span) is empty -> doDeleteAndEmit(), return null.
        assert!(matches!(
            value.truncate_or_delete(Lifespan::span(-5, 15)),
            TruncateOrDelete::Deleted
        ));
        assert!(value.is_deleted());
    }

    #[test]
    fn truncate_or_delete_shrinks_the_entry_when_the_span_clips_one_end() {
        let mut value = make_value(attribute_fixture());
        // Java: removed == [[0,4]] -> doSetLifespanAndEmit([0,4]), return this.
        assert!(matches!(
            value.truncate_or_delete(Lifespan::span(5, 20)),
            TruncateOrDelete::Unchanged
        ));
        assert_eq!(value.get_lifespan(), Lifespan::span(0, 4));
        assert!(!value.is_deleted());
    }

    #[test]
    fn truncate_or_delete_splits_the_entry_when_the_span_falls_inside_it() {
        let fixture = attribute_fixture();
        let mut value = make_value(Arc::clone(&fixture));
        // Java: removed == [[0,3], [7,10]] -> keep [0,3], create a second entry for [7,10].
        let TruncateOrDelete::Split(created) = value.truncate_or_delete(Lifespan::span(4, 6))
        else {
            panic!("expected a split");
        };
        assert_eq!(value.get_lifespan(), Lifespan::span(0, 3));
        assert_eq!(created.get_lifespan(), Lifespan::span(7, 10));
        assert_eq!(created.get_entry_key(), "State");
        assert_eq!(
            fixture.shared.lock().unwrap().created,
            vec![(Lifespan::span(7, 10), "State".to_string())]
        );
    }

    #[test]
    fn display_names_the_key_and_lifespan() {
        let value = make_value(attribute_fixture());
        assert_eq!(value.to_string(), "State@[0,10]");
    }

    #[test]
    fn set_wrapped_swaps_the_storage_record_under_the_same_entry() {
        // Java setWrapped is how the manager moves an entry between the R*-tree table and the
        // primitive-value table without the wrapper's identity changing.
        let value = make_value(attribute_fixture());
        assert_eq!(value.get_entry_key(), "State");

        let moved = Fixture::new(Some("Process[1]"), "State", None);
        moved.shared.lock().unwrap().lifespan = Some(Lifespan::span(2, 4));
        value.set_wrapped(Box::new(MockStorage(moved)));

        assert_eq!(value.get_lifespan(), Lifespan::span(2, 4));
        assert_eq!(value.with_wrapped(|w| w.get_entry_key()), "State");
    }
}

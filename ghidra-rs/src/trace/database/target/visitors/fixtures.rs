//! Shared test fixtures for this module's `*Visitor` ports.
//!
//! An in-memory, arena-indexed object/value graph flexible enough to give every one of this
//! module's visitors (which walk both up towards ancestors and down towards successors) a real
//! [`TraceObject`]/[`TraceObjectValue`] implementation to exercise, including an object with more
//! than one parent (needed by [`super::AllPathsVisitor`]'s tests) -- something a plain
//! single-parent tree cannot express.
//!
//! Test-only (`#![cfg(test)]`): compiled solely for `cargo test`, and visible to sibling test
//! modules in this directory via `super::fixtures::...`.
#![cfg(test)]

use std::any::Any;
use std::sync::Arc;

use crate::trace::model::lifespan::Lifespan;
use crate::trace::model::target::duplicate_key_exception::DuplicateKeyException;
use crate::trace::model::target::info::trace_object_info::TraceObjectInfo;
use crate::trace::model::target::path::key_path::KeyPath;
use crate::trace::model::target::trace_object::{ConflictResolution, ObjectValue, TraceObject};
use crate::trace::model::target::trace_object_val_path::TraceObjectValPath;
use crate::trace::model::target::trace_object_value::{TraceObjectValue, TruncateOrDelete};
use crate::trace::model::trace::Trace;
use crate::trace::model::trace_unique_object::TraceUniqueObject;
use crate::trace::seam_stubs::{LifeSet, ObjectKey, TraceObjectSchema};

struct ObjSpec {
    path: KeyPath,
    is_root: bool,
    /// Outgoing value edges owned by this object (its own attributes/elements).
    children: Vec<usize>,
    /// Incoming value edges whose child is this object -- i.e. what `get_parents` returns.
    parents: Vec<usize>,
}

struct ValSpec {
    key: &'static str,
    lifespan: Lifespan,
    is_canonical: bool,
    /// The object that owns this value entry (`TraceObjectValue::get_parent()`). `None` models
    /// the edge case Java allows via a nullable `getParent()` -- a value with no parent -- which
    /// no wired-up value in this fixture's graph ever has, but a test may still construct a lone
    /// [`FixtureValue`] with `parent_obj: None` to exercise that branch directly.
    parent_obj: Option<usize>,
    /// The object this value's edge points to, if this value is object-valued.
    child_obj: Option<usize>,
}

/// The backing arena for a [`Builder`]-constructed fixture graph.
pub(crate) struct Arena {
    objects: Vec<ObjSpec>,
    values: Vec<ValSpec>,
}

/// Builds an [`Arena`] incrementally: objects and values are added in dependency order (a value's
/// parent/child object indices must already exist).
pub(crate) struct Builder {
    objects: Vec<ObjSpec>,
    values: Vec<ValSpec>,
}

impl Builder {
    pub(crate) fn new() -> Self {
        Builder { objects: Vec::new(), values: Vec::new() }
    }

    /// Adds an object at `path` (parsed via [`KeyPath::parse`]; pass `""` for the root),
    /// returning its index.
    pub(crate) fn object(&mut self, path: &str, is_root: bool) -> usize {
        let path = if path.is_empty() { KeyPath::root() } else { KeyPath::parse(path).unwrap() };
        self.objects.push(ObjSpec { path, is_root, children: Vec::new(), parents: Vec::new() });
        self.objects.len() - 1
    }

    /// Adds a value entry with entry key `key`, owned by `parent_obj` (or parentless, if `None`;
    /// see [`ValSpec::parent_obj`]) and, if `child_obj` is `Some`, pointing to that object.
    /// Returns the new value's index, and wires it into both objects' `children`/`parents` lists.
    pub(crate) fn value(
        &mut self,
        parent_obj: Option<usize>,
        key: &'static str,
        lifespan: Lifespan,
        is_canonical: bool,
        child_obj: Option<usize>,
    ) -> usize {
        let idx = self.values.len();
        self.values.push(ValSpec { key, lifespan, is_canonical, parent_obj, child_obj });
        if let Some(p) = parent_obj {
            self.objects[p].children.push(idx);
        }
        if let Some(c) = child_obj {
            self.objects[c].parents.push(idx);
        }
        idx
    }

    pub(crate) fn build(self) -> Arc<Arena> {
        Arc::new(Arena { objects: self.objects, values: self.values })
    }
}

struct FixtureSchema;
impl TraceObjectSchema for FixtureSchema {
    fn get_name(&self) -> crate::debug::api::tracermi::SchemaName {
        crate::debug::api::tracermi::SchemaName::new("Fixture")
    }
    fn to_string(&self) -> String {
        "Fixture".to_string()
    }
}

struct FixtureLifeSet;
impl LifeSet for FixtureLifeSet {
    fn is_empty(&self) -> bool {
        false
    }
}

struct FixtureObjectKey(usize);
impl ObjectKey for FixtureObjectKey {
    fn equals(&self, obj: &dyn Any) -> bool {
        obj.downcast_ref::<FixtureObjectKey>().is_some_and(|o| o.0 == self.0)
    }
    fn hash_code(&self) -> i32 {
        self.0 as i32
    }
    fn compare_to(&self, that: &dyn ObjectKey) -> i32 {
        self.hash_code() - that.hash_code()
    }
}

/// A [`TraceObject`] backed by an [`Arena`] slot.
#[derive(Clone)]
pub(crate) struct FixtureObject {
    arena: Arc<Arena>,
    idx: usize,
}

impl FixtureObject {
    pub(crate) fn new(arena: Arc<Arena>, idx: usize) -> Self {
        FixtureObject { arena, idx }
    }

    fn spec(&self) -> &ObjSpec {
        &self.arena.objects[self.idx]
    }

    fn value_at(&self, idx: usize) -> Box<dyn TraceObjectValue> {
        Box::new(FixtureValue::new(self.arena.clone(), idx))
    }
}

impl TraceUniqueObject for FixtureObject {
    fn get_object_key(&self) -> Box<dyn ObjectKey> {
        Box::new(FixtureObjectKey(self.idx))
    }
    fn is_deleted(&self) -> bool {
        false
    }
}

impl TraceObject for FixtureObject {
    fn get_schema(&self) -> Box<dyn TraceObjectSchema> {
        Box::new(FixtureSchema)
    }
    fn get_life(&self) -> Box<dyn LifeSet> {
        Box::new(FixtureLifeSet)
    }
    fn get_canonical_path(&self) -> KeyPath {
        self.spec().path.clone()
    }
    fn is_root(&self) -> bool {
        self.spec().is_root
    }

    fn get_parents(&self, span: Lifespan) -> Vec<Box<dyn TraceObjectValue>> {
        self.spec()
            .parents
            .iter()
            .filter(|&&vidx| !self.arena.values[vidx].lifespan.intersect(span).is_empty())
            .map(|&vidx| self.value_at(vidx))
            .collect()
    }

    fn get_values(&self, span: Lifespan) -> Vec<Box<dyn TraceObjectValue>> {
        self.spec()
            .children
            .iter()
            .filter(|&&vidx| !self.arena.values[vidx].lifespan.intersect(span).is_empty())
            .map(|&vidx| self.value_at(vidx))
            .collect()
    }

    fn get_values_by_key(&self, span: Lifespan, key: &str) -> Vec<Box<dyn TraceObjectValue>> {
        self.get_values(span).into_iter().filter(|v| v.get_entry_key() == key).collect()
    }

    fn get_ordered_values(
        &self,
        span: Lifespan,
        key: &str,
        forward: bool,
    ) -> Vec<Box<dyn TraceObjectValue>> {
        let mut values = self.get_values_by_key(span, key);
        values.sort_by_key(|v| v.get_min_snap());
        if !forward {
            values.reverse();
        }
        values
    }

    fn get_elements(&self, span: Lifespan) -> Vec<Box<dyn TraceObjectValue>> {
        self.get_values(span).into_iter().filter(|v| KeyPath::is_index(&v.get_entry_key())).collect()
    }

    fn get_attributes(&self, span: Lifespan) -> Vec<Box<dyn TraceObjectValue>> {
        self.get_values(span).into_iter().filter(|v| KeyPath::is_name(&v.get_entry_key())).collect()
    }

    fn get_interfaces(&self) -> Vec<TraceObjectInfo> {
        Vec::new()
    }

    // --- Unused by these fixture tests below. ---

    fn get_trace(&self) -> Box<dyn Trace> {
        unimplemented!("not exercised by these fixture tests")
    }
    fn get_key(&self) -> i64 {
        unimplemented!("not exercised by these fixture tests")
    }
    fn get_root(&self) -> Box<dyn TraceObject> {
        unimplemented!("not exercised by these fixture tests")
    }
    fn is_alive(&self, _snap: i64) -> bool {
        unimplemented!("not exercised by these fixture tests")
    }
    fn is_alive_span(&self, _span: Lifespan) -> bool {
        unimplemented!("not exercised by these fixture tests")
    }
    fn insert(
        &mut self,
        _lifespan: Lifespan,
        _resolution: ConflictResolution,
    ) -> Box<dyn TraceObjectValPath> {
        unimplemented!("not exercised by these fixture tests")
    }
    fn remove(&mut self, _span: Lifespan) {
        unimplemented!("not exercised by these fixture tests")
    }
    fn remove_tree(&mut self, _span: Lifespan) {
        unimplemented!("not exercised by these fixture tests")
    }
    fn get_canonical_parent(&self, _snap: i64) -> Option<Box<dyn TraceObjectValue>> {
        unimplemented!("not exercised by these fixture tests")
    }
    fn get_canonical_parents(&self, _lifespan: Lifespan) -> Vec<Box<dyn TraceObjectValue>> {
        unimplemented!("not exercised by these fixture tests")
    }
    fn get_all_paths(&self, _span: Lifespan) -> Vec<Box<dyn TraceObjectValPath>> {
        unimplemented!("not exercised by these fixture tests")
    }
    fn query_interface<I: crate::trace::model::target::iface::TraceObjectInterface>(
        &self,
    ) -> Option<I>
    where
        Self: Sized,
    {
        unimplemented!("not exercised by these fixture tests")
    }
    fn get_value(&self, _snap: i64, _key: &str) -> Option<Box<dyn TraceObjectValue>> {
        unimplemented!("not exercised by these fixture tests")
    }
    fn get_ancestors_root(
        &self,
        _span: Lifespan,
        _root_filter: &dyn crate::trace::model::target::path::PathFilter,
    ) -> Vec<Box<dyn TraceObjectValPath>> {
        unimplemented!("not exercised by these fixture tests")
    }
    fn get_ancestors(
        &self,
        _span: Lifespan,
        _relative_filter: &dyn crate::trace::model::target::path::PathFilter,
    ) -> Vec<Box<dyn TraceObjectValPath>> {
        unimplemented!("not exercised by these fixture tests")
    }
    fn get_successors(
        &self,
        _span: Lifespan,
        _relative_filter: &dyn crate::trace::model::target::path::PathFilter,
    ) -> Vec<Box<dyn TraceObjectValPath>> {
        unimplemented!("not exercised by these fixture tests")
    }
    fn get_ordered_successors(
        &self,
        _span: Lifespan,
        _relative_path: &KeyPath,
        _forward: bool,
    ) -> Vec<Box<dyn TraceObjectValPath>> {
        unimplemented!("not exercised by these fixture tests")
    }
    fn get_canonical_successors(
        &self,
        _relative_filter: &dyn crate::trace::model::target::path::PathFilter,
    ) -> Vec<Box<dyn TraceObjectValPath>> {
        unimplemented!("not exercised by these fixture tests")
    }
    fn set_value_with_resolution(
        &mut self,
        _lifespan: Lifespan,
        _key: &str,
        _value: Option<ObjectValue>,
        _resolution: ConflictResolution,
    ) -> Result<Option<Box<dyn TraceObjectValue>>, DuplicateKeyException> {
        unimplemented!("not exercised by these fixture tests")
    }
    fn find_ancestors_interface(
        &self,
        _span: Lifespan,
        _iface: &TraceObjectInfo,
    ) -> Vec<Box<dyn TraceObjectValPath>> {
        unimplemented!("not exercised by these fixture tests")
    }
    fn query_ancestors_interface<I: crate::trace::model::target::iface::TraceObjectInterface>(
        &self,
        _span: Lifespan,
    ) -> Vec<I>
    where
        Self: Sized,
    {
        unimplemented!("not exercised by these fixture tests")
    }
    fn find_canonical_ancestors_interface(
        &self,
        _iface: &TraceObjectInfo,
    ) -> Vec<Box<dyn TraceObject>> {
        unimplemented!("not exercised by these fixture tests")
    }
    fn query_canonical_ancestors_interface<
        I: crate::trace::model::target::iface::TraceObjectInterface,
    >(
        &self,
    ) -> Vec<I>
    where
        Self: Sized,
    {
        unimplemented!("not exercised by these fixture tests")
    }
    fn find_successors_interface(
        &self,
        _span: Lifespan,
        _iface: &TraceObjectInfo,
        _require_canonical: bool,
    ) -> Vec<Box<dyn TraceObjectValPath>> {
        unimplemented!("not exercised by these fixture tests")
    }
    fn query_successors_interface<I: crate::trace::model::target::iface::TraceObjectInterface>(
        &self,
        _span: Lifespan,
        _require_canonical: bool,
    ) -> Vec<I>
    where
        Self: Sized,
    {
        unimplemented!("not exercised by these fixture tests")
    }
    fn delete(&mut self) {
        unimplemented!("not exercised by these fixture tests")
    }
}

/// A [`TraceObjectValue`] backed by an [`Arena`] slot.
#[derive(Clone)]
pub(crate) struct FixtureValue {
    arena: Arc<Arena>,
    idx: usize,
}

impl FixtureValue {
    pub(crate) fn new(arena: Arc<Arena>, idx: usize) -> Self {
        FixtureValue { arena, idx }
    }

    fn spec(&self) -> &ValSpec {
        &self.arena.values[self.idx]
    }
}

impl TraceObjectValue for FixtureValue {
    fn get_trace(&self) -> Box<dyn Trace> {
        unimplemented!("not exercised by these fixture tests")
    }

    fn get_parent(&self) -> Option<Box<dyn TraceObject>> {
        self.spec().parent_obj.map(|p| Box::new(FixtureObject::new(self.arena.clone(), p)) as Box<dyn TraceObject>)
    }

    fn get_entry_key(&self) -> String {
        self.spec().key.to_string()
    }

    fn get_canonical_path(&self) -> KeyPath {
        let parent = self.spec().parent_obj.expect(
            "get_canonical_path is only meaningful for a value with a parent; this fixture's \
             tests never call it on a deliberately-parentless value",
        );
        self.arena.objects[parent].path.with_key(self.spec().key)
    }

    fn get_value(&self) -> Box<dyn Any + Send + Sync> {
        Box::new(self.idx as i64)
    }

    fn get_child(&self) -> Box<dyn TraceObject> {
        let child = self.spec().child_obj.expect("get_child called on a non-object fixture value");
        Box::new(FixtureObject::new(self.arena.clone(), child))
    }

    fn is_object(&self) -> bool {
        self.spec().child_obj.is_some()
    }

    fn is_canonical(&self) -> bool {
        self.spec().is_canonical
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
        self.spec().lifespan
    }

    fn set_min_snap(&mut self, _min_snap: i64) {}

    fn get_min_snap(&self) -> i64 {
        self.spec().lifespan.lmin()
    }

    fn set_max_snap(&mut self, _max_snap: i64) {}

    fn get_max_snap(&self) -> i64 {
        self.spec().lifespan.lmax()
    }

    fn delete(&mut self) {}

    fn is_deleted(&self) -> bool {
        false
    }

    fn truncate_or_delete(&mut self, _span: Lifespan) -> TruncateOrDelete {
        TruncateOrDelete::Unchanged
    }
}

/// A minimal [`TraceObjectValPath`] implementor, generic over any `Arc<dyn TraceObjectValue>`.
///
/// Mirrors `MockPath` in
/// [`tree_traversal`](super::tree_traversal)'s own tests.
#[derive(Clone)]
pub(crate) struct FixturePath {
    entries: Vec<Arc<dyn TraceObjectValue>>,
}

impl FixturePath {
    pub(crate) fn empty() -> Self {
        FixturePath { entries: Vec::new() }
    }
}

impl TraceObjectValPath for FixturePath {
    fn get_entry_list(&self) -> Vec<Arc<dyn TraceObjectValue>> {
        self.entries.clone()
    }
    fn get_path(&self) -> KeyPath {
        KeyPath::of_iter(self.entries.iter().map(|e| e.get_entry_key()))
    }
    fn contains(&self, entry: &dyn TraceObjectValue) -> bool {
        let entry_ptr = entry as *const dyn TraceObjectValue as *const ();
        self.entries.iter().any(|e| (e.as_ref() as *const dyn TraceObjectValue as *const ()) == entry_ptr)
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
        Box::new(FixturePath { entries })
    }
    fn prepend(&self, entry: Arc<dyn TraceObjectValue>) -> Box<dyn TraceObjectValPath> {
        let mut entries = Vec::with_capacity(1 + self.entries.len());
        entries.push(entry);
        entries.extend(self.entries.iter().cloned());
        Box::new(FixturePath { entries })
    }
}

/// Extracts the keys of a walked path, for easy comparison in assertions.
pub(crate) fn path_keys(path: &dyn TraceObjectValPath) -> Vec<String> {
    path.get_entry_list().iter().map(|e| e.get_entry_key()).collect()
}

/// A ready-made object/value graph shared by this module's visitor tests:
///
/// ```text
/// Session (root)
///  |-- "Processes" --> ProcsContainer
///  |                    |-- "[0]" --> ProcA
///  |                    |             |-- "Threads" --> ThreadsContainerA
///  |                    |             |                  |-- "[0]" --> ThreadA0  (span [0,10])
///  |                    |             |                  |-- "[1]" --> ThreadA1  (span [5,20])
///  |                    |             |-- "Comment" --> (primitive leaf, non-canonical)
///  |                    |-- "[1]" --> ProcB
///  |                                   |-- "Threads" --> ThreadsContainerB (no children)
///  |-- "Alias" --> ProcA  (non-canonical second parent of ProcA)
/// ```
///
/// The `"Alias"` edge gives `ProcA` two distinct parents (`ProcsContainer`'s `"[0]"` and
/// `Session`'s `"Alias"`), needed by [`super::AllPathsVisitor`]'s tests; the `"Comment"` attribute
/// and `"[0]"`/`"[1]"` elements exercise the attribute/element/wildcard-key distinctions the
/// successor visitors filter on.
pub(crate) struct Fixture {
    pub(crate) arena: Arc<Arena>,
    pub(crate) session: usize,
    pub(crate) procs_container: usize,
    pub(crate) proc_a: usize,
    pub(crate) proc_b: usize,
    pub(crate) threads_container_a: usize,
    pub(crate) threads_container_b: usize,
    pub(crate) thread_a0: usize,
    pub(crate) thread_a1: usize,
}

impl Fixture {
    /// The [`FixtureObject`] at `idx` (one of this struct's own index fields).
    pub(crate) fn object(&self, idx: usize) -> FixtureObject {
        FixtureObject::new(self.arena.clone(), idx)
    }
}

pub(crate) fn build_process_thread_fixture() -> Fixture {
    let mut b = Builder::new();
    let session = b.object("", true);
    let procs_container = b.object("Processes", false);
    let proc_a = b.object("Processes[0]", false);
    let proc_b = b.object("Processes[1]", false);
    let threads_container_a = b.object("Processes[0].Threads", false);
    let threads_container_b = b.object("Processes[1].Threads", false);
    let thread_a0 = b.object("Processes[0].Threads[0]", false);
    let thread_a1 = b.object("Processes[0].Threads[1]", false);

    b.value(Some(session), "Processes", Lifespan::ALL, true, Some(procs_container));
    b.value(Some(procs_container), "[0]", Lifespan::ALL, true, Some(proc_a));
    b.value(Some(procs_container), "[1]", Lifespan::ALL, true, Some(proc_b));
    // A second, non-canonical edge into `proc_a`, giving it two parents.
    b.value(Some(session), "Alias", Lifespan::ALL, false, Some(proc_a));
    b.value(Some(proc_a), "Threads", Lifespan::ALL, true, Some(threads_container_a));
    b.value(Some(proc_b), "Threads", Lifespan::ALL, true, Some(threads_container_b));
    b.value(Some(threads_container_a), "[0]", Lifespan::span(0, 10), true, Some(thread_a0));
    b.value(Some(threads_container_a), "[1]", Lifespan::span(5, 20), true, Some(thread_a1));
    // A primitive (non-object) attribute, to exercise attribute-vs-element filtering.
    b.value(Some(proc_a), "Comment", Lifespan::ALL, false, None);

    Fixture {
        arena: b.build(),
        session,
        procs_container,
        proc_a,
        proc_b,
        threads_container_a,
        threads_container_b,
        thread_a0,
        thread_a1,
    }
}

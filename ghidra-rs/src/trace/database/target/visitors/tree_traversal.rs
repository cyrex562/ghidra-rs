//! Support for traversing a trace's object tree.
//!
//! Java source: `ghidra.trace.database.target.visitors.TreeTraversal`.
//!
//! Many traversals are already built into the object/value interfaces; this is for the rare
//! customized traversal that needs to prune subtrees in a way no built-in traversal provides.
//!
//! # Shape
//!
//! Java's `enum TreeTraversal { INSTANCE; ... }` is a stateless singleton whose two instance
//! methods (`walkValue`/`walkObject`) never read any enum-specific state. Following this crate's
//! established translation of that idiom (see e.g.
//! [`DataTypeComparator::INSTANCE`](crate::program::model::data::data_type_comparator::DataTypeComparator::INSTANCE)),
//! it becomes a unit struct with an `INSTANCE` constant.
//!
//! `Stream<? extends TraceObjectValPath>` becomes `Vec<Box<dyn TraceObjectValPath>>`: every other
//! stream-typed method in this package that has already been ported returns an
//! eagerly-collected `Vec` rather than a lazy iterator (see
//! [`CachePerDBTraceObject`](crate::trace::database::target::cache_per_db_trace_object::CachePerDBTraceObject)'s
//! module docs for the same choice).
//!
//! `TreeTraversal.SpanIntersectingVisitor extends Visitor`, overriding `composeSpan` with a
//! default body. Rust does not let a subtrait's default method satisfy a supertrait's required
//! method (see
//! [`DisassemblerContextAdapter`](crate::program::model::lang::disassembler_context_adapter::DisassemblerContextAdapter)
//! for the same situation elsewhere in this port), so [`SpanIntersectingVisitor`] is a genuinely
//! separate trait: a type wanting both must implement [`Visitor`] directly, with `compose_span`
//! delegating to `<Self as SpanIntersectingVisitor>::compose_span(self, pre, value)`.

use std::sync::Arc;

use crate::trace::model::lifespan::Lifespan;
use crate::trace::model::target::trace_object::TraceObject;
use crate::trace::model::target::trace_object_val_path::TraceObjectValPath;
use crate::trace::model::target::trace_object_value::TraceObjectValue;

/// A result directing the traversal how to proceed.
///
/// Port of `TreeTraversal.VisitResult`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VisitResult {
    /// Include the value that was just traversed, and descend.
    IncludeDescend,
    /// Include the value that was just traversed, but prune its subtree.
    IncludePrune,
    /// Exclude the value that was just traversed, but descend.
    ExcludeDescend,
    /// Exclude the value that was just traversed, and prune its subtree.
    ExcludePrune,
}

impl VisitResult {
    /// Get the result that indicates the given inclusion and continuation.
    ///
    /// Port of `VisitResult.result(boolean, boolean)`.
    ///
    /// # Arguments
    /// * `include` - `true` to include the value just traversed, `false` to exclude.
    /// * `cont` - `true` to continue traversal, `false` to terminate.
    pub fn result(include: bool, cont: bool) -> VisitResult {
        match (include, cont) {
            (true, true) => VisitResult::IncludeDescend,
            (true, false) => VisitResult::IncludePrune,
            (false, true) => VisitResult::ExcludeDescend,
            (false, false) => VisitResult::ExcludePrune,
        }
    }
}

/// An object-tree visitor.
///
/// Traversal starts at a seed object or value (node or edge, respectively) and proceeds in
/// alternating fashion from object to value to object and so on via
/// [`Visitor::continue_object`]/[`Visitor::continue_values`]. Filtering is performed on values via
/// [`Visitor::visit_value`]. As traversal descends, paths and spans are composed to inform
/// filtering and construct the final result. Note that some traversals start at a seed and
/// "descend" along the ancestry.
///
/// Port of `TreeTraversal.Visitor`.
pub trait Visitor {
    /// When descending in a value, what span to consider in the subtree.
    ///
    /// Usually this is intersection; see [`SpanIntersectingVisitor`].
    ///
    /// `pre` is the span composed from values from seed to but excluding the current value;
    /// `value` is the current value. Returns the span composed from values from seed to and
    /// including the current value, or `None` to prune (Java: `null`).
    ///
    /// Port of `Visitor.composeSpan(Lifespan, TraceObjectValue)`.
    fn compose_span(&self, pre: Lifespan, value: &dyn TraceObjectValue) -> Option<Lifespan>;

    /// When descending in a value, what path leads to the value.
    ///
    /// This is usually [`TraceObjectValPath::append`] or [`TraceObjectValPath::prepend`].
    ///
    /// `pre` is the path from seed to but excluding the current value. Returns the path from seed
    /// to and including the current value, or `None` to prune (Java: `null`).
    ///
    /// Port of `Visitor.composePath(TraceObjectValPath, TraceObjectValue)`.
    fn compose_path(
        &self,
        pre: &dyn TraceObjectValPath,
        value: Arc<dyn TraceObjectValue>,
    ) -> Option<Box<dyn TraceObjectValPath>>;

    /// Visit a value.
    ///
    /// Note that `path` is the composed path, so it will likely have the current value at its
    /// beginning or end.
    ///
    /// Port of `Visitor.visitValue(TraceObjectValue, TraceObjectValPath)`.
    fn visit_value(&self, value: &dyn TraceObjectValue, path: &dyn TraceObjectValPath) -> VisitResult;

    /// When descending in a value, the object to consider next.
    ///
    /// This is usually `value.get_child()` or `value.get_parent()`.
    ///
    /// Port of `Visitor.continueObject(TraceObjectValue)`.
    fn continue_object(&self, value: &dyn TraceObjectValue) -> Box<dyn TraceObject>;

    /// When descending in an object, the values to consider next.
    ///
    /// `span` is the composed span of values from seed to the current object; `path` is the path
    /// from seed to the current object.
    ///
    /// Port of `Visitor.continueValues(TraceObject, Lifespan, TraceObjectValPath)`.
    fn continue_values(
        &self,
        object: &dyn TraceObject,
        span: Lifespan,
        path: &dyn TraceObjectValPath,
    ) -> Vec<Arc<dyn TraceObjectValue>>;
}

/// A [`Visitor`] whose [`Visitor::compose_span`] intersects spans while descending.
///
/// Port of `TreeTraversal.SpanIntersectingVisitor`. See the module docs for why this cannot be a
/// plain `Visitor` subtrait providing `compose_span`'s default directly.
pub trait SpanIntersectingVisitor: Visitor {
    /// The descended-into span is the intersection of `pre` and `value`'s own lifespan, or `None`
    /// if that intersection is empty.
    ///
    /// Port of `SpanIntersectingVisitor.composeSpan(Lifespan, TraceObjectValue)`.
    fn compose_span(&self, pre: Lifespan, value: &dyn TraceObjectValue) -> Option<Lifespan> {
        let span = pre.intersect(value.get_lifespan());
        if span.is_empty() {
            None
        } else {
            Some(span)
        }
    }
}

/// Support for traversing a trace's object tree.
///
/// Port of `ghidra.trace.database.target.visitors.TreeTraversal`. See the module docs for why
/// this is a unit struct rather than an enum.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TreeTraversal;

impl TreeTraversal {
    /// The singleton instance, mirroring Java's `TreeTraversal.INSTANCE`.
    pub const INSTANCE: TreeTraversal = TreeTraversal;

    /// Walk a value and possibly its subtree.
    ///
    /// `span` is the composed span from seed to but excluding the current value; `path` is the
    /// path from seed to but excluding the current value. Returns the result of the value and
    /// subtree walked.
    ///
    /// Port of `TreeTraversal.walkValue(Visitor, TraceObjectValue, Lifespan, TraceObjectValPath)`.
    pub fn walk_value(
        &self,
        visitor: &dyn Visitor,
        value: Arc<dyn TraceObjectValue>,
        span: Lifespan,
        path: &dyn TraceObjectValPath,
    ) -> Vec<Box<dyn TraceObjectValPath>> {
        let Some(comp_span) = visitor.compose_span(span, value.as_ref()) else {
            return Vec::new();
        };
        let Some(comp_path) = visitor.compose_path(path, Arc::clone(&value)) else {
            return Vec::new();
        };

        match visitor.visit_value(value.as_ref(), comp_path.as_ref()) {
            VisitResult::IncludePrune => vec![comp_path],
            VisitResult::ExcludePrune => Vec::new(),
            VisitResult::IncludeDescend => {
                let object = visitor.continue_object(value.as_ref());
                let mut rest =
                    self.walk_object(visitor, object.as_ref(), comp_span, comp_path.as_ref());
                let mut result = Vec::with_capacity(1 + rest.len());
                result.push(comp_path);
                result.append(&mut rest);
                result
            }
            VisitResult::ExcludeDescend => {
                let object = visitor.continue_object(value.as_ref());
                self.walk_object(visitor, object.as_ref(), comp_span, comp_path.as_ref())
            }
        }
    }

    /// Walk an object and its subtree.
    ///
    /// `span` is the composed span from seed to the current object; `path` is the path from seed
    /// to the current object. Returns the result of the object and subtree walked.
    ///
    /// Port of `TreeTraversal.walkObject(Visitor, TraceObject, Lifespan, TraceObjectValPath)`.
    pub fn walk_object(
        &self,
        visitor: &dyn Visitor,
        object: &dyn TraceObject,
        span: Lifespan,
        path: &dyn TraceObjectValPath,
    ) -> Vec<Box<dyn TraceObjectValPath>> {
        let mut result = Vec::new();
        for v in visitor.continue_values(object, span, path) {
            result.extend(self.walk_value(visitor, v, span, path));
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::model::target::duplicate_key_exception::DuplicateKeyException;
    use crate::trace::model::target::path::key_path::KeyPath;
    use crate::trace::model::target::trace_object::ConflictResolution;
    use crate::trace::model::target::trace_object_value::TruncateOrDelete;
    use crate::trace::model::trace::Trace;
    use crate::trace::model::trace_unique_object::TraceUniqueObject;
    use crate::trace::seam_stubs::{LifeSet, ObjectKey};
    use crate::trace::model::target::schema::trace_object_schema::TraceObjectSchema;
    use std::any::Any;

    // --- A tiny in-memory object/value graph, just enough to exercise the traversal. ---

    /// A node in the test fixture's object tree: a value with the given key/lifespan, whose
    /// child object in turn has these `children`.
    #[derive(Clone)]
    struct Node {
        key: &'static str,
        lifespan: Lifespan,
        children: Vec<Node>,
    }

    fn node(key: &'static str, lifespan: Lifespan, children: Vec<Node>) -> Node {
        Node { key, lifespan, children }
    }

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


    /// A mock object node, carrying just enough state (its canonical path, and its own children)
    /// to answer [`TraceObject::get_values`].
    struct MockObject {
        path: KeyPath,
        children: Vec<Node>,
    }

    impl TraceUniqueObject for MockObject {
        fn get_object_key(&self) -> Box<dyn ObjectKey> {
            Box::new(MockObjectKey)
        }
        fn is_deleted(&self) -> bool {
            false
        }
    }

    impl TraceObject for MockObject {
        fn get_schema(&self) -> Box<dyn TraceObjectSchema> {
            Box::new(crate::trace::model::target::schema::schema_builder::plain_schema("Test"))
        }
        fn get_life(&self) -> Box<dyn LifeSet> {
            Box::new(MockLifeSet)
        }
        fn get_canonical_path(&self) -> KeyPath {
            self.path.clone()
        }
        fn get_values(&self, _span: Lifespan) -> Vec<Box<dyn TraceObjectValue>> {
            self.children
                .iter()
                .map(|n| {
                    Box::new(MockValue {
                        key: n.key,
                        lifespan: n.lifespan,
                        parent_path: self.path.clone(),
                        children: n.children.clone(),
                    }) as Box<dyn TraceObjectValue>
                })
                .collect()
        }

        // Everything below is unused by this test (matches
        // `trace_object::unimplemented_trace_object_members!()`, inlined by hand since that
        // macro also stubs `get_values`, which this impl overrides for real above -- and Rust
        // does not allow a manual method definition to coexist with one a macro invocation in
        // the same `impl` block also generates).
        fn get_trace(&self) -> Box<dyn crate::trace::model::trace::Trace> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_key(&self) -> i64 {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_root(&self) -> Box<dyn crate::trace::model::target::trace_object::TraceObject> {
            unimplemented!("not exercised by this smoke test")
        }

        fn is_alive(&self, _snap: i64) -> bool {
            unimplemented!("not exercised by this smoke test")
        }

        fn is_alive_span(&self, _span: crate::trace::model::lifespan::Lifespan) -> bool {
            unimplemented!("not exercised by this smoke test")
        }

        fn insert(
            &mut self,
            _lifespan: crate::trace::model::lifespan::Lifespan,
            _resolution: crate::trace::model::target::trace_object::ConflictResolution,
        ) -> Box<dyn crate::trace::model::target::trace_object_val_path::TraceObjectValPath> {
            unimplemented!("not exercised by this smoke test")
        }

        fn remove(&mut self, _span: crate::trace::model::lifespan::Lifespan) {
            unimplemented!("not exercised by this smoke test")
        }

        fn remove_tree(&mut self, _span: crate::trace::model::lifespan::Lifespan) {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_canonical_parent(
            &self,
            _snap: i64,
        ) -> Option<Box<dyn crate::trace::model::target::trace_object_value::TraceObjectValue>>
        {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_canonical_parents(
            &self,
            _lifespan: crate::trace::model::lifespan::Lifespan,
        ) -> Vec<Box<dyn crate::trace::model::target::trace_object_value::TraceObjectValue>> {
            unimplemented!("not exercised by this smoke test")
        }

        fn is_root(&self) -> bool {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_all_paths(
            &self,
            _span: crate::trace::model::lifespan::Lifespan,
        ) -> Vec<Box<dyn crate::trace::model::target::trace_object_val_path::TraceObjectValPath>>
        {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_interfaces(
            &self,
        ) -> Vec<crate::trace::model::target::info::trace_object_info::TraceObjectInfo> {
            Vec::new()
        }

        fn query_interface<I: crate::trace::model::target::iface::TraceObjectInterface>(&self) -> Option<I>
        where
            Self: Sized,
        {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_parents(
            &self,
            _span: crate::trace::model::lifespan::Lifespan,
        ) -> Vec<Box<dyn crate::trace::model::target::trace_object_value::TraceObjectValue>> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_values_by_key(
            &self,
            _span: crate::trace::model::lifespan::Lifespan,
            _key: &str,
        ) -> Vec<Box<dyn crate::trace::model::target::trace_object_value::TraceObjectValue>> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_ordered_values(
            &self,
            _span: crate::trace::model::lifespan::Lifespan,
            _key: &str,
            _forward: bool,
        ) -> Vec<Box<dyn crate::trace::model::target::trace_object_value::TraceObjectValue>> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_elements(
            &self,
            _span: crate::trace::model::lifespan::Lifespan,
        ) -> Vec<Box<dyn crate::trace::model::target::trace_object_value::TraceObjectValue>> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_attributes(
            &self,
            _span: crate::trace::model::lifespan::Lifespan,
        ) -> Vec<Box<dyn crate::trace::model::target::trace_object_value::TraceObjectValue>> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_value(
            &self,
            _snap: i64,
            _key: &str,
        ) -> Option<Box<dyn crate::trace::model::target::trace_object_value::TraceObjectValue>>
        {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_ancestors_root(
            &self,
            _span: crate::trace::model::lifespan::Lifespan,
            _root_filter: &dyn crate::trace::model::target::path::PathFilter,
        ) -> Vec<Box<dyn crate::trace::model::target::trace_object_val_path::TraceObjectValPath>>
        {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_ancestors(
            &self,
            _span: crate::trace::model::lifespan::Lifespan,
            _relative_filter: &dyn crate::trace::model::target::path::PathFilter,
        ) -> Vec<Box<dyn crate::trace::model::target::trace_object_val_path::TraceObjectValPath>>
        {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_successors(
            &self,
            _span: crate::trace::model::lifespan::Lifespan,
            _relative_filter: &dyn crate::trace::model::target::path::PathFilter,
        ) -> Vec<Box<dyn crate::trace::model::target::trace_object_val_path::TraceObjectValPath>>
        {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_ordered_successors(
            &self,
            _span: crate::trace::model::lifespan::Lifespan,
            _relative_path: &crate::trace::model::target::path::key_path::KeyPath,
            _forward: bool,
        ) -> Vec<Box<dyn crate::trace::model::target::trace_object_val_path::TraceObjectValPath>>
        {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_canonical_successors(
            &self,
            _relative_filter: &dyn crate::trace::model::target::path::PathFilter,
        ) -> Vec<Box<dyn crate::trace::model::target::trace_object_val_path::TraceObjectValPath>>
        {
            unimplemented!("not exercised by this smoke test")
        }

        fn set_value_with_resolution(
            &mut self,
            _lifespan: crate::trace::model::lifespan::Lifespan,
            _key: &str,
            _value: Option<crate::trace::model::target::trace_object::ObjectValue>,
            _resolution: crate::trace::model::target::trace_object::ConflictResolution,
        ) -> Result<
            Option<Box<dyn crate::trace::model::target::trace_object_value::TraceObjectValue>>,
            crate::trace::model::target::duplicate_key_exception::DuplicateKeyException,
        > {
            unimplemented!("not exercised by this smoke test")
        }

        fn find_ancestors_interface(
            &self,
            _span: crate::trace::model::lifespan::Lifespan,
            _iface: &crate::trace::model::target::info::trace_object_info::TraceObjectInfo,
        ) -> Vec<Box<dyn crate::trace::model::target::trace_object_val_path::TraceObjectValPath>>
        {
            unimplemented!("not exercised by this smoke test")
        }

        fn query_ancestors_interface<I: crate::trace::model::target::iface::TraceObjectInterface>(
            &self,
            _span: crate::trace::model::lifespan::Lifespan,
        ) -> Vec<I>
        where
            Self: Sized,
        {
            unimplemented!("not exercised by this smoke test")
        }

        fn find_canonical_ancestors_interface(
            &self,
            _iface: &crate::trace::model::target::info::trace_object_info::TraceObjectInfo,
        ) -> Vec<Box<dyn crate::trace::model::target::trace_object::TraceObject>> {
            unimplemented!("not exercised by this smoke test")
        }

        fn query_canonical_ancestors_interface<
            I: crate::trace::model::target::iface::TraceObjectInterface,
        >(
            &self,
        ) -> Vec<I>
        where
            Self: Sized,
        {
            unimplemented!("not exercised by this smoke test")
        }

        fn find_successors_interface(
            &self,
            _span: crate::trace::model::lifespan::Lifespan,
            _iface: &crate::trace::model::target::info::trace_object_info::TraceObjectInfo,
            _require_canonical: bool,
        ) -> Vec<Box<dyn crate::trace::model::target::trace_object_val_path::TraceObjectValPath>>
        {
            unimplemented!("not exercised by this smoke test")
        }

        fn query_successors_interface<I: crate::trace::model::target::iface::TraceObjectInterface>(
            &self,
            _span: crate::trace::model::lifespan::Lifespan,
            _require_canonical: bool,
        ) -> Vec<I>
        where
            Self: Sized,
        {
            unimplemented!("not exercised by this smoke test")
        }

        fn delete(&mut self) {
            unimplemented!("not exercised by this smoke test")
        }
    }

    /// A mock value entry, carrying its key, lifespan, and (for [`TraceObjectValue::get_child`])
    /// the grandchildren under its own child object.
    struct MockValue {
        key: &'static str,
        lifespan: Lifespan,
        parent_path: KeyPath,
        children: Vec<Node>,
    }

    impl TraceObjectValue for MockValue {
        fn get_trace(&self) -> Box<dyn Trace> {
            unimplemented!("not exercised by this traversal test")
        }
        fn get_parent(&self) -> Option<Box<dyn TraceObject>> {
            None
        }
        fn get_entry_key(&self) -> String {
            self.key.to_string()
        }
        fn get_canonical_path(&self) -> KeyPath {
            self.parent_path.with_key(self.key)
        }
        fn get_value(&self) -> Box<dyn Any + Send + Sync> {
            Box::new(0i64)
        }
        fn get_child(&self) -> Box<dyn TraceObject> {
            Box::new(MockObject { path: self.get_canonical_path(), children: self.children.clone() })
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
            self.lifespan
        }
        fn set_min_snap(&mut self, _min_snap: i64) {}
        fn get_min_snap(&self) -> i64 {
            self.lifespan.lmin()
        }
        fn set_max_snap(&mut self, _max_snap: i64) {}
        fn get_max_snap(&self) -> i64 {
            self.lifespan.lmax()
        }
        fn delete(&mut self) {}
        fn is_deleted(&self) -> bool {
            false
        }
        fn truncate_or_delete(&mut self, _span: Lifespan) -> TruncateOrDelete {
            TruncateOrDelete::Unchanged
        }
    }

    fn root(children: Vec<Node>) -> MockObject {
        MockObject { path: KeyPath::root(), children }
    }

    /// A minimal [`TraceObjectValPath`] implementor, generic over any `Arc<dyn TraceObjectValue>`
    /// (unlike [`DBTraceObjectValPath`](crate::trace::database::target::db_trace_object_val_path::DBTraceObjectValPath),
    /// which panics unless the entry downcasts to the concrete `DBTraceObjectValue` this test's
    /// [`MockValue`] is not).
    #[derive(Clone)]
    struct MockPath {
        entries: Vec<Arc<dyn TraceObjectValue>>,
    }

    impl MockPath {
        fn empty() -> Self {
            MockPath { entries: Vec::new() }
        }
    }

    impl TraceObjectValPath for MockPath {
        fn get_entry_list(&self) -> Vec<Arc<dyn TraceObjectValue>> {
            self.entries.clone()
        }
        fn get_path(&self) -> KeyPath {
            KeyPath::of_iter(self.entries.iter().map(|e| e.get_entry_key()))
        }
        fn contains(&self, entry: &dyn TraceObjectValue) -> bool {
            let entry_ptr = entry as *const dyn TraceObjectValue as *const ();
            self.entries
                .iter()
                .any(|e| (e.as_ref() as *const dyn TraceObjectValue as *const ()) == entry_ptr)
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

    /// Extracts the keys of a walked path, for easy comparison.
    fn keys(path: &dyn TraceObjectValPath) -> Vec<String> {
        path.get_entry_list().iter().map(|e| e.get_entry_key()).collect()
    }

    // --- Visitors ---

    /// Includes and descends into every value, ignoring span filtering.
    struct IncludeAll;
    impl Visitor for IncludeAll {
        fn compose_span(&self, pre: Lifespan, _value: &dyn TraceObjectValue) -> Option<Lifespan> {
            Some(pre)
        }
        fn compose_path(
            &self,
            pre: &dyn TraceObjectValPath,
            value: Arc<dyn TraceObjectValue>,
        ) -> Option<Box<dyn TraceObjectValPath>> {
            Some(pre.append(value))
        }
        fn visit_value(&self, _value: &dyn TraceObjectValue, _path: &dyn TraceObjectValPath) -> VisitResult {
            VisitResult::IncludeDescend
        }
        fn continue_object(&self, value: &dyn TraceObjectValue) -> Box<dyn TraceObject> {
            value.get_child()
        }
        fn continue_values(
            &self,
            object: &dyn TraceObject,
            span: Lifespan,
            _path: &dyn TraceObjectValPath,
        ) -> Vec<Arc<dyn TraceObjectValue>> {
            object.get_values(span).into_iter().map(Arc::from).collect()
        }
    }

    /// Like [`IncludeAll`], but excludes (without pruning) any value whose key is in `excluded`,
    /// and prunes the subtree under any value whose key is in `pruned`.
    struct SelectiveVisitor {
        excluded: Vec<&'static str>,
        pruned: Vec<&'static str>,
    }
    impl Visitor for SelectiveVisitor {
        fn compose_span(&self, pre: Lifespan, _value: &dyn TraceObjectValue) -> Option<Lifespan> {
            Some(pre)
        }
        fn compose_path(
            &self,
            pre: &dyn TraceObjectValPath,
            value: Arc<dyn TraceObjectValue>,
        ) -> Option<Box<dyn TraceObjectValPath>> {
            Some(pre.append(value))
        }
        fn visit_value(&self, value: &dyn TraceObjectValue, _path: &dyn TraceObjectValPath) -> VisitResult {
            let key = value.get_entry_key();
            let include = !self.excluded.contains(&key.as_str());
            let descend = !self.pruned.contains(&key.as_str());
            VisitResult::result(include, descend)
        }
        fn continue_object(&self, value: &dyn TraceObjectValue) -> Box<dyn TraceObject> {
            value.get_child()
        }
        fn continue_values(
            &self,
            object: &dyn TraceObject,
            span: Lifespan,
            _path: &dyn TraceObjectValPath,
        ) -> Vec<Arc<dyn TraceObjectValue>> {
            object.get_values(span).into_iter().map(Arc::from).collect()
        }
    }

    /// A [`SpanIntersectingVisitor`] that includes and descends into everything whose composed
    /// span survives intersection.
    struct SpanFiltering;
    impl Visitor for SpanFiltering {
        fn compose_span(&self, pre: Lifespan, value: &dyn TraceObjectValue) -> Option<Lifespan> {
            <Self as SpanIntersectingVisitor>::compose_span(self, pre, value)
        }
        fn compose_path(
            &self,
            pre: &dyn TraceObjectValPath,
            value: Arc<dyn TraceObjectValue>,
        ) -> Option<Box<dyn TraceObjectValPath>> {
            Some(pre.append(value))
        }
        fn visit_value(&self, _value: &dyn TraceObjectValue, _path: &dyn TraceObjectValPath) -> VisitResult {
            VisitResult::IncludeDescend
        }
        fn continue_object(&self, value: &dyn TraceObjectValue) -> Box<dyn TraceObject> {
            value.get_child()
        }
        fn continue_values(
            &self,
            object: &dyn TraceObject,
            span: Lifespan,
            _path: &dyn TraceObjectValPath,
        ) -> Vec<Arc<dyn TraceObjectValue>> {
            object.get_values(span).into_iter().map(Arc::from).collect()
        }
    }
    impl SpanIntersectingVisitor for SpanFiltering {}

    /// A visitor whose `compose_path` refuses to build a path longer than one entry, exercising
    /// `walk_value`'s second early-return branch (a `None` from `compose_path`, distinct from a
    /// `None` from `compose_span`).
    struct PathLengthLimited;
    impl Visitor for PathLengthLimited {
        fn compose_span(&self, pre: Lifespan, _value: &dyn TraceObjectValue) -> Option<Lifespan> {
            Some(pre)
        }
        fn compose_path(
            &self,
            pre: &dyn TraceObjectValPath,
            value: Arc<dyn TraceObjectValue>,
        ) -> Option<Box<dyn TraceObjectValPath>> {
            if pre.get_entry_list().len() >= 1 {
                return None;
            }
            Some(pre.append(value))
        }
        fn visit_value(&self, _value: &dyn TraceObjectValue, _path: &dyn TraceObjectValPath) -> VisitResult {
            VisitResult::IncludeDescend
        }
        fn continue_object(&self, value: &dyn TraceObjectValue) -> Box<dyn TraceObject> {
            value.get_child()
        }
        fn continue_values(
            &self,
            object: &dyn TraceObject,
            span: Lifespan,
            _path: &dyn TraceObjectValPath,
        ) -> Vec<Arc<dyn TraceObjectValue>> {
            object.get_values(span).into_iter().map(Arc::from).collect()
        }
    }

    /// The fixture tree used by most tests:
    /// ```text
    /// Root --A[0,10]--> ObjA --B[0,10]--> ObjAB --C[0,10]--> ObjABC (leaf)
    /// ```
    fn fixture() -> MockObject {
        root(vec![node(
            "A",
            Lifespan::span(0, 10),
            vec![node("B", Lifespan::span(0, 10), vec![node("C", Lifespan::span(0, 10), vec![])])],
        )])
    }

    #[test]
    fn visit_result_result_maps_include_and_continue_flags() {
        assert_eq!(VisitResult::result(true, true), VisitResult::IncludeDescend);
        assert_eq!(VisitResult::result(true, false), VisitResult::IncludePrune);
        assert_eq!(VisitResult::result(false, true), VisitResult::ExcludeDescend);
        assert_eq!(VisitResult::result(false, false), VisitResult::ExcludePrune);
    }

    #[test]
    fn walk_object_includes_every_value_in_a_full_traversal() {
        let tree = fixture();
        let results = TreeTraversal::INSTANCE.walk_object(
            &IncludeAll,
            &tree,
            Lifespan::ALL,
            &MockPath::empty(),
        );
        let paths: Vec<Vec<String>> = results.iter().map(|p| keys(p.as_ref())).collect();
        assert_eq!(
            paths,
            vec![
                vec!["A".to_string()],
                vec!["A".to_string(), "B".to_string()],
                vec!["A".to_string(), "B".to_string(), "C".to_string()],
            ]
        );
    }

    #[test]
    fn walk_value_include_prune_stops_the_paren_but_keeps_the_result() {
        let tree = fixture();
        let visitor = SelectiveVisitor { excluded: vec![], pruned: vec!["B"] };
        let results = TreeTraversal::INSTANCE.walk_object(&visitor, &tree, Lifespan::ALL, &MockPath::empty());
        let paths: Vec<Vec<String>> = results.iter().map(|p| keys(p.as_ref())).collect();
        // "B" is included (its path appears) but pruned, so "C" underneath it never appears.
        assert_eq!(paths, vec![vec!["A".to_string()], vec!["A".to_string(), "B".to_string()]]);
    }

    #[test]
    fn walk_value_exclude_descend_omits_the_value_but_keeps_descending() {
        let tree = fixture();
        let visitor = SelectiveVisitor { excluded: vec!["B"], pruned: vec![] };
        let results = TreeTraversal::INSTANCE.walk_object(&visitor, &tree, Lifespan::ALL, &MockPath::empty());
        let paths: Vec<Vec<String>> = results.iter().map(|p| keys(p.as_ref())).collect();
        // "B" itself is excluded, but "C" beneath it is still reached.
        assert_eq!(
            paths,
            vec![vec!["A".to_string()], vec!["A".to_string(), "B".to_string(), "C".to_string()]]
        );
    }

    #[test]
    fn walk_value_exclude_prune_drops_the_value_and_its_subtree() {
        let tree = fixture();
        let visitor = SelectiveVisitor { excluded: vec!["B"], pruned: vec!["B"] };
        let results = TreeTraversal::INSTANCE.walk_object(&visitor, &tree, Lifespan::ALL, &MockPath::empty());
        let paths: Vec<Vec<String>> = results.iter().map(|p| keys(p.as_ref())).collect();
        assert_eq!(paths, vec![vec!["A".to_string()]]);
    }

    #[test]
    fn span_intersecting_visitor_prunes_when_intersection_is_empty() {
        // "A" only lives on [0, 10]; querying [20, 30] leaves nothing for compose_span to work
        // with once it tries to intersect with "A"'s lifespan, so the whole traversal is empty.
        let tree = fixture();
        let results = TreeTraversal::INSTANCE.walk_object(
            &SpanFiltering,
            &tree,
            Lifespan::span(20, 30),
            &MockPath::empty(),
        );
        assert!(results.is_empty());
    }

    #[test]
    fn span_intersecting_visitor_narrows_the_span_while_descending() {
        // "A" lives on [0, 10], "B" only on... reuse fixture's [0,10] for all, but query a
        // sub-range: the composed span narrows to the query range throughout, and every value
        // (all sharing [0, 10]) still intersects it, so the full traversal succeeds.
        let tree = fixture();
        let results = TreeTraversal::INSTANCE.walk_object(
            &SpanFiltering,
            &tree,
            Lifespan::span(5, 8),
            &MockPath::empty(),
        );
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn compose_path_returning_none_prunes_independently_of_compose_span() {
        let tree = fixture();
        let results = TreeTraversal::INSTANCE.walk_object(
            &PathLengthLimited,
            &tree,
            Lifespan::ALL,
            &MockPath::empty(),
        );
        // The path length cap of 1 lets "A" through (path would be length 1) but refuses to
        // extend it to "A.B" (length 2), so only "A" is ever collected.
        let paths: Vec<Vec<String>> = results.iter().map(|p| keys(p.as_ref())).collect();
        assert_eq!(paths, vec![vec!["A".to_string()]]);
    }

    #[test]
    fn walk_value_on_a_leaf_returns_just_its_own_path() {
        let leaf = MockObject { path: KeyPath::root(), children: vec![] };
        let results = TreeTraversal::INSTANCE.walk_object(&IncludeAll, &leaf, Lifespan::ALL, &MockPath::empty());
        assert!(results.is_empty());
    }

    #[test]
    fn instance_is_a_stable_singleton_value() {
        assert_eq!(TreeTraversal::INSTANCE, TreeTraversal);
    }
}

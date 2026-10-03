//! Enumerates every ancestor path from an object back to the tree's root.
//!
//! Java source: `ghidra.trace.database.target.visitors.AllPathsVisitor`.
//!
//! # Shape
//!
//! Java's `enum AllPathsVisitor { INSTANCE; ... }` is a stateless singleton, exactly like
//! `TreeTraversal` itself (see [`TreeTraversal`](super::TreeTraversal)'s module docs for the
//! established translation of that idiom): a unit struct with an `INSTANCE` constant.
//!
//! Ascends via [`Visitor::continue_object`] following `TraceObjectValue::get_parent` (not
//! `get_child`, as the successor-oriented visitors in this module do), and composes paths with
//! [`TraceObjectValPath::prepend`] so the returned paths read root-to-destination even though the
//! walk itself proceeds destination-to-root.
use std::sync::Arc;

use crate::trace::database::target::visitors::tree_traversal::{
    SpanIntersectingVisitor, VisitResult, Visitor,
};
use crate::trace::model::lifespan::Lifespan;
use crate::trace::model::target::trace_object::TraceObject;
use crate::trace::model::target::trace_object_val_path::TraceObjectValPath;
use crate::trace::model::target::trace_object_value::TraceObjectValue;

/// Enumerates every path from an object back to the tree's root, including paths through objects
/// with more than one parent.
///
/// Port of `ghidra.trace.database.target.visitors.AllPathsVisitor`. See the module docs for why
/// this is a unit struct rather than an enum.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct AllPathsVisitor;

impl AllPathsVisitor {
    /// The singleton instance, mirroring Java's `AllPathsVisitor.INSTANCE`.
    pub const INSTANCE: AllPathsVisitor = AllPathsVisitor;
}

impl Visitor for AllPathsVisitor {
    fn compose_span(&self, pre: Lifespan, value: &dyn TraceObjectValue) -> Option<Lifespan> {
        <Self as SpanIntersectingVisitor>::compose_span(self, pre, value)
    }

    fn compose_path(
        &self,
        pre: &dyn TraceObjectValPath,
        value: Arc<dyn TraceObjectValue>,
    ) -> Option<Box<dyn TraceObjectValPath>> {
        Some(pre.prepend(value))
    }

    fn visit_value(
        &self,
        value: &dyn TraceObjectValue,
        _path: &dyn TraceObjectValPath,
    ) -> VisitResult {
        match value.get_parent() {
            None => VisitResult::ExcludePrune,
            Some(parent) => {
                if parent.is_root() {
                    // It may have other parents.
                    VisitResult::IncludeDescend
                } else {
                    VisitResult::ExcludeDescend
                }
            }
        }
    }

    fn continue_object(&self, value: &dyn TraceObjectValue) -> Box<dyn TraceObject> {
        value.get_parent().expect(
            "continue_object is only reached for a Descend result, and visit_value already \
             returned ExcludePrune for the case where value.get_parent() is None",
        )
    }

    fn continue_values(
        &self,
        object: &dyn TraceObject,
        span: Lifespan,
        path: &dyn TraceObjectValPath,
    ) -> Vec<Arc<dyn TraceObjectValue>> {
        object
            .get_parents(span)
            .into_iter()
            .filter(|v| !path.contains(v.as_ref()))
            .map(Arc::from)
            .collect()
    }
}

impl SpanIntersectingVisitor for AllPathsVisitor {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::database::target::visitors::fixtures::{
        build_process_thread_fixture, path_keys, Builder, FixturePath, FixtureValue,
    };
    use crate::trace::database::target::visitors::tree_traversal::TreeTraversal;

    #[test]
    fn discovers_every_path_to_a_multiply_parented_object() {
        // `proc_a` has two distinct parent edges in the fixture: the canonical
        // "Processes[0]" and the non-canonical "Alias" straight off the root. AllPathsVisitor
        // must find both.
        let fx = build_process_thread_fixture();
        let proc_a = fx.object(fx.proc_a);

        let results = TreeTraversal::INSTANCE.walk_object(
            &AllPathsVisitor::INSTANCE,
            &proc_a,
            Lifespan::ALL,
            &FixturePath::empty(),
        );
        let mut paths: Vec<Vec<String>> = results.iter().map(|p| path_keys(p.as_ref())).collect();
        paths.sort();

        let mut expected =
            vec![vec!["Processes".to_string(), "[0]".to_string()], vec!["Alias".to_string()]];
        expected.sort();
        assert_eq!(paths, expected);
    }

    #[test]
    fn a_value_with_no_parent_is_excluded_and_pruned() {
        // Faithful to the Java null check: `value.getParent() == null` returns EXCLUDE_PRUNE. No
        // value produced by `build_process_thread_fixture` has a null parent, so this builds one
        // directly, in a scratch arena, to exercise the branch.
        let mut b = Builder::new();
        let target = b.object("Target", false);
        let orphan_idx = b.value(None, "Orphan", Lifespan::ALL, false, Some(target));
        let arena = b.build();
        let orphan: Arc<dyn TraceObjectValue> = Arc::new(FixtureValue::new(arena, orphan_idx));

        let results = TreeTraversal::INSTANCE.walk_value(
            &AllPathsVisitor::INSTANCE,
            orphan,
            Lifespan::ALL,
            &FixturePath::empty(),
        );
        assert!(results.is_empty());
    }

    #[test]
    fn instance_is_a_stable_singleton_value() {
        assert_eq!(AllPathsVisitor::INSTANCE, AllPathsVisitor);
    }
}

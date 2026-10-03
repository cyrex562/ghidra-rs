//! Finds ancestor values whose *absolute* (canonical) path matches a root filter.
//!
//! Java source: `ghidra.trace.database.target.visitors.AncestorsRootVisitor`.
//!
//! # Shape
//!
//! See [`AncestorsRelativeVisitor`](super::AncestorsRelativeVisitor)'s module docs for why the
//! constructor accepts anything implementing
//! [`HasPatterns`](crate::trace::model::target::path::path_matcher::HasPatterns) and folds it into
//! an owned [`PathMatcher`], rather than a `PathFilter` trait object.
//!
//! # A faithfully-preserved quirk
//!
//! Unlike every other visitor in this module, [`Visitor::visit_value`] here always requests
//! continued descent (`VisitResult::result(_, true)`), regardless of whether the value's parent
//! matched the filter -- Java: `VisitResult.result(filter.matches(...), true)`. Traversal is
//! instead terminated independently, by [`Visitor::continue_values`] checking
//! [`TraceObject::is_root`]. So a match does not prune the walk; it merely marks that value's path
//! for inclusion in the result while ascent continues regardless, all the way to the true root
//! (see `ancestry_keeps_ascending_past_a_match_all_the_way_to_the_true_root` below).
use std::sync::Arc;

use crate::trace::database::target::visitors::tree_traversal::{
    SpanIntersectingVisitor, VisitResult, Visitor,
};
use crate::trace::model::lifespan::Lifespan;
use crate::trace::model::target::path::path_matcher::HasPatterns;
use crate::trace::model::target::path::PathMatcher;
use crate::trace::model::target::trace_object::TraceObject;
use crate::trace::model::target::trace_object_val_path::TraceObjectValPath;
use crate::trace::model::target::trace_object_value::TraceObjectValue;

/// Finds ancestor values of an object whose parent's *canonical* (absolute) path matches a root
/// filter. See [`AncestorsRelativeVisitor`](super::AncestorsRelativeVisitor) for the
/// relative-path counterpart.
///
/// Port of `ghidra.trace.database.target.visitors.AncestorsRootVisitor`.
pub struct AncestorsRootVisitor {
    filter: PathMatcher,
}

impl AncestorsRootVisitor {
    /// Constructs a visitor matching ancestors against `filter`.
    ///
    /// Port of `AncestorsRootVisitor(PathFilter)`.
    pub fn new(filter: impl HasPatterns) -> Self {
        let filter = PathMatcher::any_of_filters(std::iter::once(&filter as &dyn HasPatterns));
        AncestorsRootVisitor { filter }
    }
}

impl Visitor for AncestorsRootVisitor {
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
        let parent = value.get_parent().expect(
            "visit_value is only reached for values obtained from get_parents(), which always \
             have a non-null parent",
        );
        VisitResult::result(self.filter.matches(&parent.get_canonical_path()), true)
    }

    fn continue_object(&self, value: &dyn TraceObjectValue) -> Box<dyn TraceObject> {
        value.get_parent().expect(
            "continue_object is only reached for values obtained from get_parents(), which \
             always have a non-null parent",
        )
    }

    fn continue_values(
        &self,
        object: &dyn TraceObject,
        span: Lifespan,
        path: &dyn TraceObjectValPath,
    ) -> Vec<Arc<dyn TraceObjectValue>> {
        if object.is_root() {
            return Vec::new();
        }
        // Can't really use filter for parent values here. The filter does not match relative
        // paths, but canonical paths.
        object
            .get_parents(span)
            .into_iter()
            .filter(|v| !path.contains(v.as_ref()))
            .map(Arc::from)
            .collect()
    }
}

impl SpanIntersectingVisitor for AncestorsRootVisitor {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::database::target::visitors::fixtures::{
        build_process_thread_fixture, path_keys, FixturePath,
    };
    use crate::trace::database::target::visitors::tree_traversal::TreeTraversal;
    use crate::trace::model::target::path::PathPattern;
    use crate::trace::model::target::path::key_path::KeyPath;

    #[test]
    fn ancestry_keeps_ascending_past_a_match_all_the_way_to_the_true_root() {
        // A root filter matching only the session's own (empty) canonical path. `proc_a` has two
        // parents (see `build_process_thread_fixture`'s docs), so ascending from `thread_a0`
        // forks once it reaches `proc_a`, yielding two distinct included paths -- both of which
        // only get included once the walk actually reaches the session object, several hops past
        // where the fork happened, since `visit_value` never prunes on its own.
        let fx = build_process_thread_fixture();
        let thread = fx.object(fx.thread_a0);
        let root_filter = PathPattern::new(KeyPath::root());
        let visitor = AncestorsRootVisitor::new(root_filter);

        let mut results = TreeTraversal::INSTANCE.walk_object(
            &visitor,
            &thread,
            Lifespan::ALL,
            &FixturePath::empty(),
        );
        let mut paths: Vec<Vec<String>> =
            results.drain(..).map(|p| path_keys(p.as_ref())).collect();
        paths.sort();

        let mut expected = vec![
            vec![
                "Processes".to_string(),
                "[0]".to_string(),
                "Threads".to_string(),
                "[0]".to_string(),
            ],
            vec!["Alias".to_string(), "Threads".to_string(), "[0]".to_string()],
        ];
        expected.sort();
        assert_eq!(paths, expected);
    }

    #[test]
    fn a_filter_that_never_matches_still_terminates_at_the_true_root_with_no_included_paths() {
        let fx = build_process_thread_fixture();
        let thread = fx.object(fx.thread_a0);
        let pattern = PathPattern::parse("NeverMatches").unwrap();
        let visitor = AncestorsRootVisitor::new(pattern);

        let results = TreeTraversal::INSTANCE.walk_object(
            &visitor,
            &thread,
            Lifespan::ALL,
            &FixturePath::empty(),
        );
        assert!(results.is_empty());
    }
}

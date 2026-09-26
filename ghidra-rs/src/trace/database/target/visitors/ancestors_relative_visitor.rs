//! Finds ancestor values matching a *relative* path filter.
//!
//! Java source: `ghidra.trace.database.target.visitors.AncestorsRelativeVisitor`.
//!
//! # Shape
//!
//! Java's field is declared `PathFilter filter` -- the ~15-member Java interface implemented by
//! both `PathPattern` and `PathMatcher`. This crate's
//! [`PathFilter`](crate::trace::model::target::path::PathFilter) trait is deliberately kept
//! minimal (see its docs, and [`PathMatcher`](crate::trace::model::target::path::PathMatcher)'s
//! own docs for why `PathMatcher` doesn't implement it), so there is no single Rust trait object
//! exposing every operation this visitor needs (`matches`, `ancestorCouldMatchRight`,
//! `getPrevKeys`). Instead, the constructor accepts anything implementing
//! [`HasPatterns`](crate::trace::model::target::path::path_matcher::HasPatterns) (satisfied by
//! both `PathPattern` and `PathMatcher`, mirroring Java's polymorphic parameter) and immediately
//! folds it into an owned [`PathMatcher`], whose inherent methods cover this visitor's full needs.
use std::collections::HashSet;
use std::sync::Arc;

use crate::trace::database::target::visitors::tree_traversal::{
    SpanIntersectingVisitor, VisitResult, Visitor,
};
use crate::trace::model::lifespan::Lifespan;
use crate::trace::model::target::path::key_matches;
use crate::trace::model::target::path::path_matcher::HasPatterns;
use crate::trace::model::target::path::PathMatcher;
use crate::trace::model::target::trace_object::TraceObject;
use crate::trace::model::target::trace_object_val_path::TraceObjectValPath;
use crate::trace::model::target::trace_object_value::TraceObjectValue;

/// Port of `PathFilter.anyMatches(Set<String>, String)`.
fn any_matches(pats: &HashSet<String>, key: &str) -> bool {
    pats.iter().any(|p| key_matches(p, key))
}

/// Finds ancestor values of an object matching a *relative* path filter, i.e. one describing the
/// path from the matched ancestor down to the seed object -- not the ancestor's absolute
/// (canonical) location. See [`AncestorsRootVisitor`](super::AncestorsRootVisitor) for the
/// absolute-path counterpart.
///
/// Port of `ghidra.trace.database.target.visitors.AncestorsRelativeVisitor`.
pub struct AncestorsRelativeVisitor {
    filter: PathMatcher,
}

impl AncestorsRelativeVisitor {
    /// Constructs a visitor matching ancestors against `filter`.
    ///
    /// Port of `AncestorsRelativeVisitor(PathFilter)`. See the module docs for why this accepts
    /// anything [`HasPatterns`](crate::trace::model::target::path::path_matcher::HasPatterns)
    /// rather than a `PathFilter` trait object.
    pub fn new(filter: impl HasPatterns) -> Self {
        let filter = PathMatcher::any_of_filters(std::iter::once(&filter as &dyn HasPatterns));
        AncestorsRelativeVisitor { filter }
    }
}

impl Visitor for AncestorsRelativeVisitor {
    fn compose_span(&self, pre: Lifespan, value: &dyn TraceObjectValue) -> Option<Lifespan> {
        <Self as SpanIntersectingVisitor>::compose_span(self, pre, value)
    }

    fn compose_path(
        &self,
        pre: &dyn TraceObjectValPath,
        value: Arc<dyn TraceObjectValue>,
    ) -> Option<Box<dyn TraceObjectValPath>> {
        // Java: `pre == null ? TraceObjectValPath.of() : pre.prepend(value)`. `pre` is never null
        // in this port (see `tree_traversal`'s module docs on `Stream` returns and seed paths), so
        // the null branch is unconditionally unreachable here, matching how every other already-
        // ported `Visitor` in this module handles the same guard.
        Some(pre.prepend(value))
    }

    fn visit_value(
        &self,
        value: &dyn TraceObjectValue,
        val_path: &dyn TraceObjectValPath,
    ) -> VisitResult {
        let path = val_path.get_path();
        VisitResult::result(
            self.filter.matches(&path),
            self.filter.ancestor_could_match_right(&path, true) && value.is_object(),
        )
    }

    fn continue_object(&self, value: &dyn TraceObjectValue) -> Box<dyn TraceObject> {
        value.get_parent().expect(
            "continue_object is only reached for values TreeTraversal obtained from \
             get_parents(), which always have a non-null parent",
        )
    }

    fn continue_values(
        &self,
        object: &dyn TraceObject,
        span: Lifespan,
        pre: &dyn TraceObjectValPath,
    ) -> Vec<Arc<dyn TraceObjectValue>> {
        let prev_keys = self.filter.get_prev_keys(&pre.get_path());
        if prev_keys.is_empty() {
            return Vec::new();
        }
        object
            .get_parents(span)
            .into_iter()
            .filter(|v| any_matches(&prev_keys, &v.get_entry_key()))
            .map(Arc::from)
            .collect()
    }
}

impl SpanIntersectingVisitor for AncestorsRelativeVisitor {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::database::target::visitors::fixtures::{
        build_process_thread_fixture, path_keys, FixturePath,
    };
    use crate::trace::database::target::visitors::tree_traversal::TreeTraversal;
    use crate::trace::model::target::path::PathPattern;

    #[test]
    fn finds_the_single_matching_ancestor_path_by_ascending_hop_by_hop() {
        let fx = build_process_thread_fixture();
        let thread = fx.object(fx.thread_a0);
        let pattern = PathPattern::parse("Processes[0].Threads[0]").unwrap();
        let visitor = AncestorsRelativeVisitor::new(pattern);

        let results = TreeTraversal::INSTANCE.walk_object(
            &visitor,
            &thread,
            Lifespan::ALL,
            &FixturePath::empty(),
        );
        let paths: Vec<Vec<String>> = results.iter().map(|p| path_keys(p.as_ref())).collect();
        assert_eq!(
            paths,
            vec![vec![
                "Processes".to_string(),
                "[0]".to_string(),
                "Threads".to_string(),
                "[0]".to_string(),
            ]]
        );
    }

    #[test]
    fn a_pattern_matching_nothing_along_the_ancestry_yields_no_results() {
        let fx = build_process_thread_fixture();
        let thread = fx.object(fx.thread_a0);
        let pattern = PathPattern::parse("Bogus").unwrap();
        let visitor = AncestorsRelativeVisitor::new(pattern);

        let results = TreeTraversal::INSTANCE.walk_object(
            &visitor,
            &thread,
            Lifespan::ALL,
            &FixturePath::empty(),
        );
        assert!(results.is_empty());
    }
}

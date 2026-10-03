//! Finds successor values matching a relative path filter.
//!
//! Java source: `ghidra.trace.database.target.visitors.SuccessorsRelativeVisitor`.
//!
//! # Shape
//!
//! See [`AncestorsRelativeVisitor`](super::AncestorsRelativeVisitor)'s module docs for why the
//! constructor accepts anything implementing
//! [`HasPatterns`](crate::trace::model::target::path::path_matcher::HasPatterns) and folds it into
//! an owned [`PathMatcher`], rather than a `PathFilter` trait object.
//!
//! Unlike [`CanonicalSuccessorsRelativeVisitor`](super::CanonicalSuccessorsRelativeVisitor), every
//! matching value is included regardless of [`TraceObjectValue::is_canonical`], and named
//! (non-wildcard) keys are resolved via `object.get_values_by_key` (potentially several values per
//! key) rather than the single canonical one.
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

/// Finds successor values of an object matching a relative path filter.
///
/// Port of `ghidra.trace.database.target.visitors.SuccessorsRelativeVisitor`.
pub struct SuccessorsRelativeVisitor {
    filter: PathMatcher,
}

impl SuccessorsRelativeVisitor {
    /// Constructs a visitor matching successors against `filter`.
    ///
    /// Port of `SuccessorsRelativeVisitor(PathFilter)`.
    pub fn new(filter: impl HasPatterns) -> Self {
        let filter = PathMatcher::any_of_filters(std::iter::once(&filter as &dyn HasPatterns));
        SuccessorsRelativeVisitor { filter }
    }
}

impl Visitor for SuccessorsRelativeVisitor {
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

    fn visit_value(
        &self,
        value: &dyn TraceObjectValue,
        val_path: &dyn TraceObjectValPath,
    ) -> VisitResult {
        let path = val_path.get_path();
        VisitResult::result(
            self.filter.matches(&path),
            self.filter.successor_could_match(&path, true) && value.is_object(),
        )
    }

    fn continue_object(&self, value: &dyn TraceObjectValue) -> Box<dyn TraceObject> {
        // Java: `value.isObject() ? value.getChild() : null`. Only reached after `visit_value`
        // requested descent, which already required `value.is_object()`.
        value.get_child()
    }

    fn continue_values(
        &self,
        object: &dyn TraceObject,
        span: Lifespan,
        pre: &dyn TraceObjectValPath,
    ) -> Vec<Arc<dyn TraceObjectValue>> {
        let next_keys = self.filter.get_next_keys(&pre.get_path());
        if next_keys.is_empty() {
            return Vec::new();
        }

        let mut result: Vec<Arc<dyn TraceObjectValue>> = Vec::new();
        if next_keys.contains("") {
            result.extend(object.get_attributes(span).into_iter().map(Arc::from));
        }
        if next_keys.contains("[]") {
            result.extend(object.get_elements(span).into_iter().map(Arc::from));
        }
        for k in next_keys.iter().filter(|k| !k.is_empty() && k.as_str() != "[]") {
            result.extend(object.get_values_by_key(span, k).into_iter().map(Arc::from));
        }
        result
    }
}

impl SpanIntersectingVisitor for SuccessorsRelativeVisitor {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::database::target::visitors::fixtures::{
        build_process_thread_fixture, path_keys, FixturePath,
    };
    use crate::trace::database::target::visitors::tree_traversal::TreeTraversal;
    use crate::trace::model::target::path::key_path::KeyPath;
    use crate::trace::model::target::path::PathPattern;

    #[test]
    fn a_name_wildcard_matches_every_attribute() {
        let fx = build_process_thread_fixture();
        let proc_a = fx.object(fx.proc_a);
        let pattern = PathPattern::new(KeyPath::of(&[""]));
        let visitor = SuccessorsRelativeVisitor::new(pattern);

        let results = TreeTraversal::INSTANCE.walk_object(
            &visitor,
            &proc_a,
            Lifespan::ALL,
            &FixturePath::empty(),
        );
        let paths: Vec<Vec<String>> = results.iter().map(|p| path_keys(p.as_ref())).collect();
        assert_eq!(paths, vec![vec!["Threads".to_string()], vec!["Comment".to_string()]]);
    }

    #[test]
    fn an_index_wildcard_matches_every_element() {
        let fx = build_process_thread_fixture();
        let threads = fx.object(fx.threads_container_a);
        let pattern = PathPattern::new(KeyPath::of(&["[]"]));
        let visitor = SuccessorsRelativeVisitor::new(pattern);

        let results = TreeTraversal::INSTANCE.walk_object(
            &visitor,
            &threads,
            Lifespan::ALL,
            &FixturePath::empty(),
        );
        let paths: Vec<Vec<String>> = results.iter().map(|p| path_keys(p.as_ref())).collect();
        assert_eq!(paths, vec![vec!["[0]".to_string()], vec!["[1]".to_string()]]);
    }

    #[test]
    fn a_non_canonical_named_key_is_still_included() {
        // Unlike CanonicalSuccessorsRelativeVisitor, this visitor doesn't filter by
        // `is_canonical()`: "Comment" (non-canonical in the fixture) is still found.
        let fx = build_process_thread_fixture();
        let proc_a = fx.object(fx.proc_a);
        let pattern = PathPattern::parse("Comment").unwrap();
        let visitor = SuccessorsRelativeVisitor::new(pattern);

        let results = TreeTraversal::INSTANCE.walk_object(
            &visitor,
            &proc_a,
            Lifespan::ALL,
            &FixturePath::empty(),
        );
        let paths: Vec<Vec<String>> = results.iter().map(|p| path_keys(p.as_ref())).collect();
        assert_eq!(paths, vec![vec!["Comment".to_string()]]);
    }
}

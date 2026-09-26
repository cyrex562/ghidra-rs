//! Finds *canonical* successor values matching a relative path filter.
//!
//! Java source: `ghidra.trace.database.target.visitors.CanonicalSuccessorsRelativeVisitor`.
//!
//! # Shape
//!
//! See [`AncestorsRelativeVisitor`](super::AncestorsRelativeVisitor)'s module docs for why the
//! constructor accepts anything implementing
//! [`HasPatterns`](crate::trace::model::target::path::path_matcher::HasPatterns) and folds it into
//! an owned [`PathMatcher`], rather than a `PathFilter` trait object.
//!
//! # Faithfully-preserved quirks
//!
//! * `compose_span` (Java: `composeSpan`) unconditionally returns `Lifespan::ALL`, ignoring both
//!   its `pre` and `value` arguments entirely. This class implements the plain `Visitor` interface
//!   rather than `SpanIntersectingVisitor` for exactly this reason: real span intersection is
//!   skipped, since canonical relationships are defined without regard to time (a value is
//!   canonical or not independent of when it existed).
//! * Java declares `protected final Set<TraceObject> seen = new HashSet<>();` but never reads or
//!   writes it anywhere in the class -- a genuine dead field, kept here as `seen` for fidelity (see
//!   `the_seen_field_is_declared_but_never_populated` below) rather than dropped.
use std::sync::Arc;

use crate::trace::database::target::visitors::tree_traversal::{VisitResult, Visitor};
use crate::trace::model::lifespan::Lifespan;
use crate::trace::model::target::path::path_matcher::HasPatterns;
use crate::trace::model::target::path::PathMatcher;
use crate::trace::model::target::trace_object::TraceObject;
use crate::trace::model::target::trace_object_val_path::TraceObjectValPath;
use crate::trace::model::target::trace_object_value::TraceObjectValue;

/// Finds *canonical* successor values of an object matching a relative path filter -- i.e. only
/// values for which [`TraceObjectValue::is_canonical`] holds, unlike
/// [`SuccessorsRelativeVisitor`](super::SuccessorsRelativeVisitor), which includes every matching
/// value regardless.
///
/// Port of `ghidra.trace.database.target.visitors.CanonicalSuccessorsRelativeVisitor`.
pub struct CanonicalSuccessorsRelativeVisitor {
    filter: PathMatcher,
    /// Port of the Java field `seen`. See this module's docs: real Java code neither reads nor
    /// writes this field beyond its own initialization, so it stays empty for the visitor's
    /// entire lifetime; this port preserves that (inert) shape rather than silently dropping it.
    seen: Vec<Box<dyn TraceObject>>,
}

impl CanonicalSuccessorsRelativeVisitor {
    /// Constructs a visitor matching canonical successors against `filter`.
    ///
    /// Port of `CanonicalSuccessorsRelativeVisitor(PathFilter)`.
    pub fn new(filter: impl HasPatterns) -> Self {
        let filter = PathMatcher::any_of_filters(std::iter::once(&filter as &dyn HasPatterns));
        CanonicalSuccessorsRelativeVisitor { filter, seen: Vec::new() }
    }
}

impl Visitor for CanonicalSuccessorsRelativeVisitor {
    fn compose_span(&self, _pre: Lifespan, _value: &dyn TraceObjectValue) -> Option<Lifespan> {
        // Faithful to the Java quirk: always `Lifespan.ALL`, ignoring `pre`/`value` entirely. See
        // this module's docs.
        Some(Lifespan::ALL)
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
        // Java: `value.isObject() ? value.getChild() : null`. `continue_object` is only reached
        // after `visit_value` requested descent, and its `cont` flag already required
        // `value.is_object()`, so the child is always present here.
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
            result.extend(
                object.get_attributes(span).into_iter().filter(|v| v.is_canonical()).map(Arc::from),
            );
        }
        if next_keys.contains("[]") {
            result.extend(
                object.get_elements(span).into_iter().filter(|v| v.is_canonical()).map(Arc::from),
            );
        }
        for k in next_keys.iter().filter(|k| !k.is_empty() && k.as_str() != "[]") {
            if let Some(v) = Self::get_canonical_value(object, k) {
                result.push(Arc::from(v));
            }
        }
        result
    }
}

impl CanonicalSuccessorsRelativeVisitor {
    /// Port of the protected helper `getCanonicalValue(TraceObject, String)`.
    fn get_canonical_value(parent: &dyn TraceObject, key: &str) -> Option<Box<dyn TraceObjectValue>> {
        parent
            .get_ordered_values(Lifespan::ALL, key, true)
            .into_iter()
            .find(|v| v.is_canonical())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::database::target::visitors::fixtures::{
        build_process_thread_fixture, path_keys, FixturePath,
    };
    use crate::trace::database::target::visitors::tree_traversal::TreeTraversal;
    use crate::trace::model::target::path::PathPattern;

    #[test]
    fn finds_only_canonical_matches_under_an_element_wildcard() {
        let fx = build_process_thread_fixture();
        let proc_a = fx.object(fx.proc_a);
        // "Threads[0]" and "Threads[1]" are both canonical in the fixture.
        let pattern = PathPattern::parse("Threads[]").unwrap();
        let visitor = CanonicalSuccessorsRelativeVisitor::new(pattern);

        let results = TreeTraversal::INSTANCE.walk_object(
            &visitor,
            &proc_a,
            Lifespan::ALL,
            &FixturePath::empty(),
        );
        let paths: Vec<Vec<String>> = results.iter().map(|p| path_keys(p.as_ref())).collect();
        assert_eq!(
            paths,
            vec![
                vec!["Threads".to_string(), "[0]".to_string()],
                vec!["Threads".to_string(), "[1]".to_string()],
            ]
        );
    }

    #[test]
    fn a_non_canonical_named_key_is_excluded() {
        // Unlike SuccessorsRelativeVisitor, a match on a non-canonical value ("Comment", in the
        // fixture) never appears in the results: `getCanonicalValue` filters it out before it is
        // ever visited.
        let fx = build_process_thread_fixture();
        let proc_a = fx.object(fx.proc_a);
        let pattern = PathPattern::parse("Comment").unwrap();
        let visitor = CanonicalSuccessorsRelativeVisitor::new(pattern);

        let results = TreeTraversal::INSTANCE.walk_object(
            &visitor,
            &proc_a,
            Lifespan::ALL,
            &FixturePath::empty(),
        );
        assert!(results.is_empty());
    }

    #[test]
    fn the_seen_field_is_declared_but_never_populated() {
        // See this module's docs: `seen` mirrors a genuinely dead Java field. Run a real
        // traversal, then confirm it is still empty -- nothing in this visitor ever writes to it.
        let fx = build_process_thread_fixture();
        let proc_a = fx.object(fx.proc_a);
        let pattern = PathPattern::parse("Threads[]").unwrap();
        let visitor = CanonicalSuccessorsRelativeVisitor::new(pattern);
        let _ = TreeTraversal::INSTANCE.walk_object(
            &visitor,
            &proc_a,
            Lifespan::ALL,
            &FixturePath::empty(),
        );
        assert!(visitor.seen.is_empty());
    }
}

//! Walks down a single, fully-concrete relative path, fetching each hop's values in time order.
//!
//! Java source: `ghidra.trace.database.target.visitors.OrderedSuccessorsVisitor`.
//!
//! # Shape
//!
//! Unlike the other filter-taking visitors in this module, Java's constructor here always builds
//! its own filter internally (`this.filter = new PathPattern(path)`), never accepting an arbitrary
//! caller-supplied `PathFilter`. So this port stores a concrete
//! [`PathPattern`](crate::trace::model::target::path::PathPattern) directly rather than folding
//! into a [`PathMatcher`] (contrast
//! [`AncestorsRelativeVisitor`](super::AncestorsRelativeVisitor), which does need that).
use std::sync::Arc;

use crate::trace::database::target::visitors::tree_traversal::{
    SpanIntersectingVisitor, VisitResult, Visitor,
};
use crate::trace::model::lifespan::Lifespan;
use crate::trace::model::target::path::key_path::KeyPath;
use crate::trace::model::target::path::{PathFilter, PathPattern};
use crate::trace::model::target::trace_object::TraceObject;
use crate::trace::model::target::trace_object_val_path::TraceObjectValPath;
use crate::trace::model::target::trace_object_value::TraceObjectValue;

/// Walks down a single, fully-concrete relative `path` (no wildcards), fetching each hop's values
/// via [`TraceObject::get_ordered_values`] (time-ordered, `forward` or reverse) rather than the
/// unordered `get_values`/`get_values_by_key`.
///
/// Port of `ghidra.trace.database.target.visitors.OrderedSuccessorsVisitor`.
pub struct OrderedSuccessorsVisitor {
    filter: PathPattern,
    forward: bool,
}

impl OrderedSuccessorsVisitor {
    /// Constructs a visitor walking down `path` (a fully-concrete relative path -- no wildcard
    /// keys), fetching each hop's values ordered from least- to most-recent if `forward`, or the
    /// reverse otherwise.
    ///
    /// Port of `OrderedSuccessorsVisitor(KeyPath, boolean)`.
    pub fn new(path: KeyPath, forward: bool) -> Self {
        OrderedSuccessorsVisitor { filter: PathPattern::new(path), forward }
    }
}

impl Visitor for OrderedSuccessorsVisitor {
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
        if self.filter.matches(&path) {
            // Singleton path, so if I match, no successor can.
            return VisitResult::IncludePrune;
        }
        if !value.is_object() || !self.filter.successor_could_match(&path, true) {
            return VisitResult::ExcludePrune;
        }
        VisitResult::ExcludeDescend
    }

    fn continue_object(&self, value: &dyn TraceObjectValue) -> Box<dyn TraceObject> {
        // Java: `value.isObject() ? value.getChild() : null`. Only reached for the ExcludeDescend
        // result above, which already required `value.is_object()`.
        value.get_child()
    }

    fn continue_values(
        &self,
        object: &dyn TraceObject,
        span: Lifespan,
        val_path: &dyn TraceObjectValPath,
    ) -> Vec<Arc<dyn TraceObjectValue>> {
        let next_keys = self.filter.get_next_keys(&val_path.get_path());
        if next_keys.is_empty() {
            return Vec::new();
        }
        if next_keys.len() != 1 {
            // Dead in practice for a plain `PathPattern` (its `getNextKeys` never returns more
            // than one key), but kept faithful to Java's defensive check.
            panic!("predicates must be a singleton");
        }
        let next = next_keys.iter().next().expect("checked len() == 1 above");
        if PathPattern::is_wildcard(next) {
            panic!("predicates must be a singleton");
        }
        object.get_ordered_values(span, next, self.forward).into_iter().map(Arc::from).collect()
    }
}

impl SpanIntersectingVisitor for OrderedSuccessorsVisitor {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::database::target::visitors::fixtures::{
        build_process_thread_fixture, path_keys, Builder, FixtureObject, FixturePath,
    };
    use crate::trace::database::target::visitors::tree_traversal::TreeTraversal;

    #[test]
    fn walks_down_a_fully_concrete_path_hop_by_hop() {
        let fx = build_process_thread_fixture();
        let proc_a = fx.object(fx.proc_a);
        let visitor = OrderedSuccessorsVisitor::new(KeyPath::of(&["Threads", "[0]"]), true);

        let results = TreeTraversal::INSTANCE.walk_object(
            &visitor,
            &proc_a,
            Lifespan::ALL,
            &FixturePath::empty(),
        );
        let paths: Vec<Vec<String>> = results.iter().map(|p| path_keys(p.as_ref())).collect();
        assert_eq!(paths, vec![vec!["Threads".to_string(), "[0]".to_string()]]);
    }

    #[test]
    #[should_panic(expected = "predicates must be a singleton")]
    fn a_wildcard_next_key_panics() {
        let fx = build_process_thread_fixture();
        let proc_a = fx.object(fx.proc_a);
        let visitor = OrderedSuccessorsVisitor::new(KeyPath::of(&["[]"]), true);

        let _ = TreeTraversal::INSTANCE.walk_object(
            &visitor,
            &proc_a,
            Lifespan::ALL,
            &FixturePath::empty(),
        );
    }

    #[test]
    fn continue_values_orders_by_time_according_to_the_forward_flag() {
        // Two entries sharing the key "State" at different times, to observe `forward`'s effect
        // directly (a full walk can't distinguish them: both produce the same key-path "State").
        let mut b = Builder::new();
        let root = b.object("", true);
        b.value(Some(root), "State", Lifespan::span(10, 15), false, None);
        b.value(Some(root), "State", Lifespan::span(0, 5), false, None);
        let arena = b.build();
        let obj = FixtureObject::new(arena, root);

        let forward_visitor = OrderedSuccessorsVisitor::new(KeyPath::of(&["State"]), true);
        let forward = forward_visitor.continue_values(&obj, Lifespan::ALL, &FixturePath::empty());
        let forward_spans: Vec<i64> = forward.iter().map(|v| v.get_min_snap()).collect();
        assert_eq!(forward_spans, vec![0, 10]);

        let backward_visitor = OrderedSuccessorsVisitor::new(KeyPath::of(&["State"]), false);
        let backward =
            backward_visitor.continue_values(&obj, Lifespan::ALL, &FixturePath::empty());
        let backward_spans: Vec<i64> = backward.iter().map(|v| v.get_min_snap()).collect();
        assert_eq!(backward_spans, vec![10, 0]);
    }
}

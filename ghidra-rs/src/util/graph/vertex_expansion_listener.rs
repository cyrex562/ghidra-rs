//! Rust port of `ghidra.base.graph.VertexExpansionListener`.
//!
//! `ghidra.base.*` maps to `util/` (AGENTS.md layout table), so this sits beside the
//! `ghidra.util.graph` ports.

use crate::graph::seam_stubs::VisualVertex;

/// A listener to know when a vertex has been told to expand.
///
/// An open extension point (a Java `interface` with no in-repo implementers), so it is a
/// trait; the vertex is taken as `&dyn VisualVertex` because `VisualVertex` itself is an open
/// interface with many implementers.
pub trait VertexExpansionListener {
    /// Show or hide those vertices that are on incoming edges to `v`.
    ///
    /// Mirrors `toggleIncomingVertices(VisualVertex)`.
    fn toggle_incoming_vertices(&self, v: &dyn VisualVertex);

    /// Show or hide those vertices that are on outgoing edges to `v`.
    ///
    /// Mirrors `toggleOutgoingVertices(VisualVertex)`.
    fn toggle_outgoing_vertices(&self, v: &dyn VisualVertex);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::any::Any;
    use std::cell::RefCell;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct TestVertex {
        id: &'static str,
        selected: AtomicBool,
    }

    impl VisualVertex for TestVertex {
        fn get_component(&self) -> Box<dyn Any> {
            Box::new(self.id)
        }
        fn set_focused(&self, _focused: bool) {}
        fn is_focused(&self) -> bool {
            false
        }
        fn set_selected(&self, selected: bool) {
            self.selected.store(selected, Ordering::SeqCst);
        }
        fn is_selected(&self) -> bool {
            self.selected.load(Ordering::SeqCst)
        }
        fn set_hovered(&self, _hovered: bool) {}
        fn is_hovered(&self) -> bool {
            false
        }
        fn set_location(&self, _p: &dyn Any) {}
        fn get_location(&self) -> Box<dyn Any> {
            Box::new(())
        }
        fn is_grabbable(&self, _c: &dyn Any) -> bool {
            true
        }
        fn dispose(&self) {}
        fn set_emphasis(&self, _emphasis_level: f64) {}
        fn get_emphasis(&self) -> f64 {
            0.0
        }
        fn set_alpha(&self, _alpha: f64) {}
        fn get_alpha(&self) -> f64 {
            1.0
        }
    }

    /// Records every toggle request, the way a graph provider would queue an expand/collapse.
    #[derive(Default)]
    struct RecordingListener {
        events: RefCell<Vec<(String, &'static str)>>,
    }

    fn vertex_id(v: &dyn VisualVertex) -> &'static str {
        *v.get_component().downcast::<&'static str>().unwrap()
    }

    impl VertexExpansionListener for RecordingListener {
        fn toggle_incoming_vertices(&self, v: &dyn VisualVertex) {
            self.events.borrow_mut().push(("incoming".to_string(), vertex_id(v)));
        }
        fn toggle_outgoing_vertices(&self, v: &dyn VisualVertex) {
            self.events.borrow_mut().push(("outgoing".to_string(), vertex_id(v)));
        }
    }

    #[test]
    fn listener_receives_toggles_for_the_given_vertex() {
        let a = TestVertex { id: "a", selected: AtomicBool::new(false) };
        let b = TestVertex { id: "b", selected: AtomicBool::new(true) };
        let listener = RecordingListener::default();
        let dyn_listener: &dyn VertexExpansionListener = &listener;

        dyn_listener.toggle_incoming_vertices(&a);
        dyn_listener.toggle_outgoing_vertices(&b);
        dyn_listener.toggle_outgoing_vertices(&a);

        assert_eq!(
            *listener.events.borrow(),
            vec![
                ("incoming".to_string(), "a"),
                ("outgoing".to_string(), "b"),
                ("outgoing".to_string(), "a"),
            ]
        );
        assert!(b.is_selected());
    }
}

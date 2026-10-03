//! Port of `ghidra.graph.viewer.actions.VisualGraphVertexActionContext`.

use crate::graph::seam_stubs::VisualVertex;
use crate::graph::viewer::actions::visual_graph_action_context::VisualGraphActionContext;

/// Context for a visual graph when a vertex is selected.
///
/// Port of `ghidra.graph.viewer.actions.VisualGraphVertexActionContext<V extends VisualVertex>`.
/// Like its parent [`VisualGraphActionContext`], the Java interface carries no docking
/// dependency of its own; the docking action contexts that implement it mix it in.
///
/// Java's type parameter `V` is fixed once per implementing class, so it becomes the associated
/// type [`Vertex`](Self::Vertex).
///
/// # Satellite actions
///
/// The Java interface overrides the inherited default of `shouldShowSatelliteActions()` to
/// return `false` ("no satellite viewer actions when on a vertex"). A Rust subtrait cannot
/// replace a supertrait's default method, and a blanket `VisualGraphActionContext` impl would
/// stop implementors re-overriding it as Java's `DegContext` does (`getVertex() == null`). The
/// vertex-context default is therefore provided as
/// [`vertex_should_show_satellite_actions`](Self::vertex_should_show_satellite_actions), which
/// implementors return from their [`VisualGraphActionContext::should_show_satellite_actions`]
/// unless they need different behaviour.
pub trait VisualGraphVertexActionContext: VisualGraphActionContext {
    /// The vertex type of the graph (Java's `V`).
    type Vertex: VisualVertex + ?Sized;

    /// Returns the vertex this context is for.
    ///
    /// Port of `getVertex()`.
    fn get_vertex(&self) -> &Self::Vertex;

    /// The vertex-context default for
    /// [`VisualGraphActionContext::should_show_satellite_actions`]: satellite viewer actions are
    /// not shown when on a vertex.
    ///
    /// Port of `VisualGraphVertexActionContext.shouldShowSatelliteActions()`'s default body.
    fn vertex_should_show_satellite_actions(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::any::Any;

    struct TestVertex(&'static str);

    impl VisualVertex for TestVertex {
        fn get_component(&self) -> Box<dyn Any> {
            Box::new(())
        }
        fn set_focused(&self, _focused: bool) {}
        fn is_focused(&self) -> bool {
            false
        }
        fn set_selected(&self, _selected: bool) {}
        fn is_selected(&self) -> bool {
            false
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
            false
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

    /// Mirrors Java's `VgVertexContext`: takes the vertex-context default.
    struct VertexContext(TestVertex);

    impl VisualGraphActionContext for VertexContext {
        fn should_show_satellite_actions(&self) -> bool {
            self.vertex_should_show_satellite_actions()
        }
    }

    impl VisualGraphVertexActionContext for VertexContext {
        type Vertex = TestVertex;
        fn get_vertex(&self) -> &TestVertex {
            &self.0
        }
    }

    /// Mirrors Java's `DegContext`, which re-overrides to `getVertex() == null`.
    struct OptionalVertexContext(Option<TestVertex>, TestVertex);

    impl VisualGraphActionContext for OptionalVertexContext {
        fn should_show_satellite_actions(&self) -> bool {
            self.0.is_none()
        }
    }

    impl VisualGraphVertexActionContext for OptionalVertexContext {
        type Vertex = TestVertex;
        fn get_vertex(&self) -> &TestVertex {
            self.0.as_ref().unwrap_or(&self.1)
        }
    }

    fn satellite(ctx: &impl VisualGraphActionContext) -> bool {
        ctx.should_show_satellite_actions()
    }

    #[test]
    fn vertex_contexts_hide_satellite_actions_by_default() {
        let ctx = VertexContext(TestVertex("a"));
        assert!(!ctx.vertex_should_show_satellite_actions());
        assert!(!satellite(&ctx));
        assert_eq!(ctx.get_vertex().0, "a");
    }

    #[test]
    fn implementors_may_reoverride_satellite_behaviour() {
        let over = OptionalVertexContext(Some(TestVertex("v")), TestVertex("fallback"));
        assert!(!satellite(&over));
        let empty = OptionalVertexContext(None, TestVertex("fallback"));
        assert!(satellite(&empty));
    }

    #[test]
    fn usable_through_a_trait_object_with_a_dyn_vertex() {
        struct DynContext(Box<dyn VisualVertex>);
        impl VisualGraphActionContext for DynContext {}
        impl VisualGraphVertexActionContext for DynContext {
            type Vertex = dyn VisualVertex;
            fn get_vertex(&self) -> &Self::Vertex {
                self.0.as_ref()
            }
        }
        let ctx: &dyn VisualGraphVertexActionContext<Vertex = dyn VisualVertex> =
            &DynContext(Box::new(TestVertex("d")));
        assert_eq!(ctx.get_vertex().get_alpha(), 1.0);
        // Supertrait default still applies when the implementor does not override it.
        assert!(ctx.should_show_satellite_actions());
        assert!(!ctx.vertex_should_show_satellite_actions());
    }
}

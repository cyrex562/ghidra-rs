use super::seam_stubs::FcgVertex;

/// A listener to know when a vertex has been told to expand.
pub trait FcgVertexExpansionListener: Send + Sync {
    /// Show or hide those vertices that are on incoming edges to v.
    fn toggle_incoming_vertices(&self, v: &dyn FcgVertex);

    /// Show or hide those vertices that are on outgoing edges to v.
    fn toggle_outgoing_vertices(&self, v: &dyn FcgVertex);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockVertex;
    impl FcgVertex for MockVertex {
        fn clone_vertex(&self, _new_listener: &dyn std::any::Any) -> Box<dyn FcgVertex> {
            Box::new(MockVertex)
        }
        fn get_function(&self) -> Box<dyn std::any::Any> {
            Box::new(())
        }
        fn get_address(&self) -> Box<dyn std::any::Any> {
            Box::new(())
        }
        fn get_options(&self) -> Box<dyn std::any::Any> {
            Box::new(())
        }
        fn get_level(&self) -> Box<dyn std::any::Any> {
            Box::new(())
        }
        fn get_degree(&self) -> i32 {
            0
        }
        fn get_direction(&self) -> Box<dyn std::any::Any> {
            Box::new(())
        }
        fn set_hovered(&self, _hovered: bool) {}
        fn get_incoming_toggle_button(&self) -> Box<dyn std::any::Any> {
            Box::new(())
        }
        fn get_outgoing_toggle_button(&self) -> Box<dyn std::any::Any> {
            Box::new(())
        }
        fn set_has_incoming_references(&self, _has_incoming: bool) {}
        fn set_has_outgoing_references(&self, _has_outgoing: bool) {}
        fn set_too_many_incoming_references(&self, _too_many: bool) {}
        fn set_too_many_outgoing_references(&self, _too_many: bool) {}
        fn has_too_many_incoming_references(&self) -> bool {
            false
        }
        fn has_too_many_outgoing_references(&self) -> bool {
            false
        }
        fn is_incoming_expanded(&self) -> bool {
            false
        }
        fn is_outgoing_expanded(&self) -> bool {
            false
        }
        fn is_expanded(&self) -> bool {
            false
        }
        fn can_expand(&self) -> bool {
            false
        }
        fn can_expand_incoming_references(&self) -> bool {
            false
        }
        fn can_expand_outgoing_references(&self) -> bool {
            false
        }
        fn set_incoming_expanded(&self, _set_expanded: bool) {}
        fn set_outgoing_expanded(&self, _set_expanded: bool) {}
        fn to_string(&self) -> String {
            "MockVertex".to_string()
        }
        fn hash_code(&self) -> i32 {
            42
        }
        fn equals(&self, _obj: &dyn std::any::Any) -> bool {
            true
        }
        fn dispose(&self) {}
    }

    struct MockListener;

    impl FcgVertexExpansionListener for MockListener {
        fn toggle_incoming_vertices(&self, _v: &dyn FcgVertex) {}

        fn toggle_outgoing_vertices(&self, _v: &dyn FcgVertex) {}
    }

    #[test]
    fn test_listener_implements_trait() {
        let listener = MockListener;
        let vertex = MockVertex;

        listener.toggle_incoming_vertices(&vertex);
        listener.toggle_outgoing_vertices(&vertex);
    }

    #[test]
    fn test_listener_as_trait_object() {
        let listener: Box<dyn FcgVertexExpansionListener> = Box::new(MockListener);
        let vertex = MockVertex;

        listener.toggle_incoming_vertices(&vertex);
        listener.toggle_outgoing_vertices(&vertex);
    }
}

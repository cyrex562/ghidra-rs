use super::GraphType;

/// Default GraphType implementation that has no vertex or edge types defined
pub fn empty_graph_type() -> GraphType {
    GraphType::new(
        "Empty Graph Type".to_string(),
        "Graph type with no defined vertex or edge types".to_string(),
        Vec::new(),
        Vec::new(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_graph_type_has_correct_name() {
        let gt = empty_graph_type();
        assert_eq!(gt.get_name(), "Empty Graph Type");
    }

    #[test]
    fn empty_graph_type_has_correct_description() {
        let gt = empty_graph_type();
        assert_eq!(
            gt.get_description(),
            "Graph type with no defined vertex or edge types"
        );
    }

    #[test]
    fn empty_graph_type_has_empty_vertex_types() {
        let gt = empty_graph_type();
        assert_eq!(gt.get_vertex_types(), Vec::<String>::new());
    }

    #[test]
    fn empty_graph_type_has_empty_edge_types() {
        let gt = empty_graph_type();
        assert_eq!(gt.get_edge_types(), Vec::<String>::new());
    }

    #[test]
    fn empty_graph_type_contains_no_vertex_types() {
        let gt = empty_graph_type();
        assert!(!gt.contains_vertex_type("anything"));
    }

    #[test]
    fn empty_graph_type_contains_no_edge_types() {
        let gt = empty_graph_type();
        assert!(!gt.contains_edge_type("anything"));
    }
}

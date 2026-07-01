use crate::service::graph::GraphType;

/// The [`GraphType`] for PCode data flow graphs.
///
/// Mirrors `ghidra.app.plugin.core.decompile.actions.PCodeDfgGraphType`.
pub struct PCodeDfgGraphType {
    graph_type: GraphType,
}

// Vertex types
pub const DEFAULT_VERTEX: &str = "Default";
pub const CONSTANT: &str = "Constant";
pub const REGISTER: &str = "Register";
pub const UNIQUE: &str = "Unique";
pub const PERSISTENT: &str = "Persistent";
pub const ADDRESS_TIED: &str = "Address Tied";
pub const OP: &str = "Op";

// Edge types
pub const DEFAULT_EDGE: &str = "Default";
pub const WITHIN_BLOCK: &str = "Within Block";
pub const BETWEEN_BLOCKS: &str = "Between Blocks";

fn vertex_types() -> Vec<String> {
    [
        DEFAULT_VERTEX,
        CONSTANT,
        REGISTER,
        UNIQUE,
        PERSISTENT,
        ADDRESS_TIED,
        OP,
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

fn edge_types() -> Vec<String> {
    [DEFAULT_EDGE, WITHIN_BLOCK, BETWEEN_BLOCKS]
        .iter()
        .map(|s| s.to_string())
        .collect()
}

impl PCodeDfgGraphType {
    /// Constructs a new `PCodeDfgGraphType`.
    pub fn new() -> Self {
        Self {
            graph_type: GraphType::new(
                "AST Graph".to_string(),
                "Displays an AST graph for the current function".to_string(),
                vertex_types(),
                edge_types(),
            ),
        }
    }
}

impl Default for PCodeDfgGraphType {
    fn default() -> Self {
        Self::new()
    }
}

impl std::ops::Deref for PCodeDfgGraphType {
    type Target = GraphType;

    fn deref(&self) -> &Self::Target {
        &self.graph_type
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_and_description_match_java() {
        let gt = PCodeDfgGraphType::new();
        assert_eq!(gt.get_name(), "AST Graph");
        assert_eq!(
            gt.get_description(),
            "Displays an AST graph for the current function"
        );
    }

    #[test]
    fn get_vertex_and_edge_types_preserve_order() {
        let gt = PCodeDfgGraphType::new();
        let vt = gt.get_vertex_types();
        let et = gt.get_edge_types();

        assert_eq!(
            vt,
            vec![
                "Default",
                "Constant",
                "Register",
                "Unique",
                "Persistent",
                "Address Tied",
                "Op"
            ]
        );
        assert_eq!(
            et,
            vec!["Default", "Within Block", "Between Blocks"]
        );
    }

    #[test]
    fn contains_all_vertex_types() {
        let gt = PCodeDfgGraphType::new();
        assert!(gt.contains_vertex_type(DEFAULT_VERTEX));
        assert!(gt.contains_vertex_type(CONSTANT));
        assert!(gt.contains_vertex_type(REGISTER));
        assert!(gt.contains_vertex_type(UNIQUE));
        assert!(gt.contains_vertex_type(PERSISTENT));
        assert!(gt.contains_vertex_type(ADDRESS_TIED));
        assert!(gt.contains_vertex_type(OP));
        assert!(!gt.contains_vertex_type("InvalidVertex"));
    }

    #[test]
    fn contains_all_edge_types() {
        let gt = PCodeDfgGraphType::new();
        assert!(gt.contains_edge_type(DEFAULT_EDGE));
        assert!(gt.contains_edge_type(WITHIN_BLOCK));
        assert!(gt.contains_edge_type(BETWEEN_BLOCKS));
        assert!(!gt.contains_edge_type("InvalidEdge"));
    }

    #[test]
    fn vertex_and_edge_type_counts_match_java() {
        let gt = PCodeDfgGraphType::new();
        assert_eq!(gt.get_vertex_types().len(), 7);
        assert_eq!(gt.get_edge_types().len(), 3);
    }

    #[test]
    fn default_constructs_same_as_new() {
        let a = PCodeDfgGraphType::default();
        let b = PCodeDfgGraphType::new();
        assert_eq!(a.get_name(), b.get_name());
        assert_eq!(a.get_description(), b.get_description());
        assert_eq!(a.get_vertex_types(), b.get_vertex_types());
        assert_eq!(a.get_edge_types(), b.get_edge_types());
    }

    #[test]
    fn public_constants_have_expected_values() {
        assert_eq!(DEFAULT_VERTEX, "Default");
        assert_eq!(CONSTANT, "Constant");
        assert_eq!(REGISTER, "Register");
        assert_eq!(UNIQUE, "Unique");
        assert_eq!(PERSISTENT, "Persistent");
        assert_eq!(ADDRESS_TIED, "Address Tied");
        assert_eq!(OP, "Op");

        assert_eq!(DEFAULT_EDGE, "Default");
        assert_eq!(WITHIN_BLOCK, "Within Block");
        assert_eq!(BETWEEN_BLOCKS, "Between Blocks");
    }
}

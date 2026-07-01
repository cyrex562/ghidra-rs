use crate::service::graph::GraphType;

/// The [`GraphType`] for BSim Feature Graphs.
///
/// Mirrors `ghidra.bsfv.BSimFeatureGraphType`.
pub struct BSimFeatureGraphType {
    graph_type: GraphType,
}

// Dataflow vertex types.
pub const DEFAULT_VERTEX: &str = "Default";
pub const CONSTANT_VERTEX: &str = "Constant";
pub const VARNODE_ADDRESS: &str = "Address Varnode";
pub const BASE_VARNODE_VERTEX: &str = "Base Varnode";
pub const SECONDARY_BASE_VARNODE_VERTEX: &str = "Secondary Base Varnode";
pub const FUNCTION_INPUT: &str = "Function Input";
pub const CONSTANT_FUNCTION_INPUT: &str = "Constant Function Input";
pub const PCODE_OP_VERTEX: &str = "Pcode Op";
pub const VOID_BASE: &str = "void";
pub const COLLAPSED_VARNODE: &str = "Collapsed Varnode";
pub const COLLAPSED_OP: &str = "Collapsed Op";

// Dataflow vertex attributes.
pub const OP_ADDRESS: &str = "Address";
pub const PCODE_OUTPUT: &str = "Pcode Output";
pub const SIZE: &str = "Size";

// Dataflow edge types.
pub const DATAFLOW_IN: &str = "Input";
pub const DATAFLOW_OUT: &str = "Output";
pub const COLLAPSED_IN: &str = "Collapsed Input";
pub const COLLAPSED_OUT: &str = "Collapsed Output";

// Control flow vertex types.
pub const BASE_BLOCK_VERTEX: &str = "Base Block";
pub const PARENT_BLOCK_VERTEX: &str = "Parent Block";
pub const GRANDPARENT_BLOCK_VERTEX: &str = "Grandparent Block";
pub const CHILD_BLOCK_VERTEX: &str = "Child Block";
pub const SIBLING_BLOCK_VERTEX: &str = "Sibling Block";
pub const NULL_BLOCK_VERTEX: &str = "Null Block";

/// For blocks that can't be categorized cleanly within a bsim neighborhood using
/// ancestor/descendant relations.
pub const BSIM_NEIGHBOR_VERTEX: &str = "BSim Neighbor Block";

// Control flow vertex attributes.
pub const BLOCK_START: &str = "Block Start";
pub const BLOCK_STOP: &str = "Block Stop";
pub const CALL_STRING: &str = "Call String";
pub const EMPTY_CALL_STRING: &str = "(empty)";

// Control flow edge types.
pub const TRUE_EDGE: &str = "True";
pub const FALSE_EDGE: &str = "False";
pub const CONTROL_FLOW_DEFAULT_EDGE: &str = "Default";

// Copy signature attributes.
pub const COPY_SIGNATURE: &str = "Copy Signature";

pub const DATAFLOW_WINDOW_SIZE: i32 = 3;
pub const DATAFLOW_PREFIX: &str = "df";
pub const CONTROL_FLOW_PREFIX: &str = "cf";
pub const COPY_PREFIX: &str = "copy";

pub const OPTIONS_NAME: &str = "BSim Feature Graph";

fn vertex_types() -> Vec<String> {
    [
        DEFAULT_VERTEX,
        CONSTANT_VERTEX,
        VARNODE_ADDRESS,
        BASE_VARNODE_VERTEX,
        SECONDARY_BASE_VARNODE_VERTEX,
        FUNCTION_INPUT,
        CONSTANT_FUNCTION_INPUT,
        PCODE_OP_VERTEX,
        VOID_BASE,
        COLLAPSED_VARNODE,
        COLLAPSED_OP,
        BASE_BLOCK_VERTEX,
        PARENT_BLOCK_VERTEX,
        GRANDPARENT_BLOCK_VERTEX,
        CHILD_BLOCK_VERTEX,
        SIBLING_BLOCK_VERTEX,
        NULL_BLOCK_VERTEX,
        BSIM_NEIGHBOR_VERTEX,
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

fn edge_types() -> Vec<String> {
    [
        DATAFLOW_IN,
        DATAFLOW_OUT,
        COLLAPSED_IN,
        COLLAPSED_OUT,
        TRUE_EDGE,
        FALSE_EDGE,
        CONTROL_FLOW_DEFAULT_EDGE,
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

impl BSimFeatureGraphType {
    /// Constructs a new `BSimFeatureGraphType`.
    pub fn new() -> Self {
        Self {
            graph_type: GraphType::new(
                "BSim Feature Graph".to_string(),
                "BSim Feature Graph".to_string(),
                vertex_types(),
                edge_types(),
            ),
        }
    }

    /// Returns the options display name for this graph type.
    pub fn get_options_name(&self) -> &'static str {
        OPTIONS_NAME
    }
}

impl Default for BSimFeatureGraphType {
    fn default() -> Self {
        Self::new()
    }
}

impl std::ops::Deref for BSimFeatureGraphType {
    type Target = GraphType;

    fn deref(&self) -> &Self::Target {
        &self.graph_type
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_options_name_matches_java_constant() {
        let gt = BSimFeatureGraphType::new();
        assert_eq!(gt.get_options_name(), "BSim Feature Graph");
    }

    #[test]
    fn name_and_description_match_java() {
        let gt = BSimFeatureGraphType::new();
        assert_eq!(gt.get_name(), "BSim Feature Graph");
        assert_eq!(gt.get_description(), "BSim Feature Graph");
    }

    #[test]
    fn contains_all_vertex_types() {
        let gt = BSimFeatureGraphType::new();
        for v in vertex_types() {
            assert!(gt.contains_vertex_type(&v), "missing vertex type {v}");
        }
        assert!(!gt.contains_vertex_type("Not A Vertex Type"));
    }

    #[test]
    fn contains_all_edge_types() {
        let gt = BSimFeatureGraphType::new();
        for e in edge_types() {
            assert!(gt.contains_edge_type(&e), "missing edge type {e}");
        }
        assert!(!gt.contains_edge_type("Not An Edge Type"));
    }

    #[test]
    fn vertex_and_edge_type_counts_match_java_static_initializer() {
        let gt = BSimFeatureGraphType::new();
        assert_eq!(gt.get_vertex_types().len(), 18);
        assert_eq!(gt.get_edge_types().len(), 7);
    }

    #[test]
    fn default_constructs_same_as_new() {
        let a = BSimFeatureGraphType::default();
        let b = BSimFeatureGraphType::new();
        assert_eq!(a.get_name(), b.get_name());
        assert_eq!(a.get_vertex_types(), b.get_vertex_types());
        assert_eq!(a.get_edge_types(), b.get_edge_types());
    }
}

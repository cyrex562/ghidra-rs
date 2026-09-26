//! Port of `ghidra.graph.BlockFlowGraphType`.
//!
//! Java models this as a one-line subclass of `ProgramGraphType` whose constructor just supplies
//! a fixed name/description to `super(...)`:
//!
//! ```java
//! public class BlockFlowGraphType extends ProgramGraphType {
//!     public BlockFlowGraphType() {
//!         super("Block Flow Graph", "Shows program basic block flow");
//!     }
//! }
//! ```
//!
//! Unlike its sibling [`CodeFlowGraphType`](crate::graph::CodeFlowGraphType) (whose real Java
//! description string has a "veretx" typo, faithfully preserved there), this class's description
//! string is a plain, correctly-spelled sentence with no copy-paste artifacts.
//!
//! Per this crate's composition-over-inheritance convention (see
//! [`ProgramGraphType`](crate::graph::ProgramGraphType)'s own module docs), [`BlockFlowGraphType`]
//! is a thin wrapper struct around [`ProgramGraphType`] rather than a subclass, [`Deref`]ing to it
//! (and transitively to `GraphType`) so callers get the exact same vertex/edge type set and
//! behavior.

use std::ops::Deref;

use crate::graph::ProgramGraphType;

/// Port of `ghidra.graph.BlockFlowGraphType`.
pub struct BlockFlowGraphType {
    program_graph_type: ProgramGraphType,
}

impl BlockFlowGraphType {
    /// `BlockFlowGraphType()`.
    pub fn new() -> Self {
        Self {
            program_graph_type: ProgramGraphType::new(
                "Block Flow Graph",
                "Shows program basic block flow",
            ),
        }
    }
}

impl Default for BlockFlowGraphType {
    fn default() -> Self {
        Self::new()
    }
}

impl Deref for BlockFlowGraphType {
    type Target = ProgramGraphType;

    fn deref(&self) -> &Self::Target {
        &self.program_graph_type
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::program_graph_type::{BODY, READ};

    #[test]
    fn new_has_the_expected_name_and_description() {
        let gt = BlockFlowGraphType::new();
        assert_eq!(gt.get_name(), "Block Flow Graph");
        assert_eq!(gt.get_description(), "Shows program basic block flow");
    }

    #[test]
    fn default_matches_new() {
        let a = BlockFlowGraphType::default();
        let b = BlockFlowGraphType::new();
        assert_eq!(a.get_name(), b.get_name());
        assert_eq!(a.get_description(), b.get_description());
    }

    #[test]
    fn deref_exposes_the_wrapped_program_graph_type() {
        let gt = BlockFlowGraphType::new();
        assert!(gt.contains_vertex_type(BODY));
        assert!(gt.contains_edge_type(READ));
        assert_eq!(gt.get_options_name(), "Program Graph Display Options");
    }
}

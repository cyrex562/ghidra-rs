//! Port of `ghidra.graph.DataFlowGraphType`.
//!
//! Java models this as a one-line subclass of `ProgramGraphType` whose constructor just supplies
//! a fixed name/description to `super(...)`:
//!
//! ```java
//! public class DataFlowGraphType extends ProgramGraphType {
//!     public DataFlowGraphType() {
//!         super("Data Flow Graph", "Shows program data relationships");
//!     }
//! }
//! ```
//!
//! Per this crate's composition-over-inheritance convention (see
//! [`ProgramGraphType`](crate::graph::ProgramGraphType)'s own module docs), [`DataFlowGraphType`]
//! is a thin wrapper struct around [`ProgramGraphType`] rather than a subclass, [`Deref`]ing to it
//! (and transitively to `GraphType`) so callers get the exact same vertex/edge type set and
//! behavior.

use std::ops::Deref;

use crate::graph::ProgramGraphType;

/// Port of `ghidra.graph.DataFlowGraphType`.
pub struct DataFlowGraphType {
    program_graph_type: ProgramGraphType,
}

impl DataFlowGraphType {
    /// `DataFlowGraphType()`.
    pub fn new() -> Self {
        Self {
            program_graph_type: ProgramGraphType::new(
                "Data Flow Graph",
                "Shows program data relationships",
            ),
        }
    }
}

impl Default for DataFlowGraphType {
    fn default() -> Self {
        Self::new()
    }
}

impl Deref for DataFlowGraphType {
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
        let gt = DataFlowGraphType::new();
        assert_eq!(gt.get_name(), "Data Flow Graph");
        assert_eq!(gt.get_description(), "Shows program data relationships");
    }

    #[test]
    fn default_matches_new() {
        let a = DataFlowGraphType::default();
        let b = DataFlowGraphType::new();
        assert_eq!(a.get_name(), b.get_name());
        assert_eq!(a.get_description(), b.get_description());
    }

    #[test]
    fn deref_exposes_the_wrapped_program_graph_type() {
        let gt = DataFlowGraphType::new();
        assert!(gt.contains_vertex_type(BODY));
        assert!(gt.contains_edge_type(READ));
        assert_eq!(gt.get_options_name(), "Program Graph Display Options");
    }
}

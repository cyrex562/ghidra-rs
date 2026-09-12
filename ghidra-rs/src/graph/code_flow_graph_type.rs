//! Port of `ghidra.graph.CodeFlowGraphType`.
//!
//! Java models this as a one-line subclass of `ProgramGraphType` whose constructor just supplies
//! a fixed name/description to `super(...)`:
//!
//! ```java
//! public class CodeFlowGraphType extends ProgramGraphType {
//!     public CodeFlowGraphType() {
//!         super("Code Flow Graph",
//!             "Shows code block flow (similar to Block Flow graph type, but shows the code in each veretx)");
//!     }
//! }
//! ```
//!
//! Note the misspelling of "vertex" as "veretx" in the real Java description string
//! (`CodeFlowGraphType.java:22`) -- faithfully reproduced verbatim below rather than corrected.
//!
//! Per this crate's composition-over-inheritance convention (see
//! [`ProgramGraphType`](crate::graph::ProgramGraphType)'s own module docs), [`CodeFlowGraphType`]
//! is a thin wrapper struct around [`ProgramGraphType`] rather than a subclass, [`Deref`]ing to it
//! (and transitively to `GraphType`) so callers get the exact same vertex/edge type set and
//! behavior.

use std::ops::Deref;

use crate::graph::ProgramGraphType;

/// Port of `ghidra.graph.CodeFlowGraphType`.
pub struct CodeFlowGraphType {
    program_graph_type: ProgramGraphType,
}

impl CodeFlowGraphType {
    /// `CodeFlowGraphType()`.
    pub fn new() -> Self {
        Self {
            program_graph_type: ProgramGraphType::new(
                "Code Flow Graph",
                "Shows code block flow (similar to Block Flow graph type, but shows the code in each veretx)",
            ),
        }
    }
}

impl Default for CodeFlowGraphType {
    fn default() -> Self {
        Self::new()
    }
}

impl Deref for CodeFlowGraphType {
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
        let gt = CodeFlowGraphType::new();
        assert_eq!(gt.get_name(), "Code Flow Graph");
        // Faithful reproduction of the real Java typo ("veretx" instead of "vertex") --
        // see the module docs and CodeFlowGraphType.java:22.
        assert_eq!(
            gt.get_description(),
            "Shows code block flow (similar to Block Flow graph type, but shows the code in each veretx)"
        );
        assert!(gt.get_description().contains("veretx"));
        assert!(!gt.get_description().contains("vertex"));
    }

    #[test]
    fn default_matches_new() {
        let a = CodeFlowGraphType::default();
        let b = CodeFlowGraphType::new();
        assert_eq!(a.get_name(), b.get_name());
        assert_eq!(a.get_description(), b.get_description());
    }

    #[test]
    fn deref_exposes_the_wrapped_program_graph_type() {
        let gt = CodeFlowGraphType::new();
        assert!(gt.contains_vertex_type(BODY));
        assert!(gt.contains_edge_type(READ));
        assert_eq!(gt.get_options_name(), "Program Graph Display Options");
    }
}

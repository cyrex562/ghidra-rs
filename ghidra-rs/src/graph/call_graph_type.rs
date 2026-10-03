//! Port of `ghidra.graph.CallGraphType`.
//!
//! Java models this as a one-line subclass of `ProgramGraphType` whose constructor just supplies
//! a fixed name/description to `super(...)`:
//!
//! ```java
//! public class CallGraphType extends ProgramGraphType {
//!     public CallGraphType() {
//!         super("Call Graph", "Shows relationships between functions");
//!     }
//! }
//! ```
//!
//! Per this crate's composition-over-inheritance convention (see
//! [`ProgramGraphType`](crate::graph::ProgramGraphType)'s own module docs), [`CallGraphType`] is a
//! thin wrapper struct around [`ProgramGraphType`] rather than a subclass, [`Deref`]ing to it (and
//! transitively to `GraphType`) so callers get the exact same vertex/edge type set and behavior.

use std::ops::Deref;

use crate::graph::ProgramGraphType;

/// Port of `ghidra.graph.CallGraphType`.
pub struct CallGraphType {
    program_graph_type: ProgramGraphType,
}

impl CallGraphType {
    /// `CallGraphType()`.
    pub fn new() -> Self {
        Self {
            program_graph_type: ProgramGraphType::new(
                "Call Graph",
                "Shows relationships between functions",
            ),
        }
    }
}

impl Default for CallGraphType {
    fn default() -> Self {
        Self::new()
    }
}

impl Deref for CallGraphType {
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
        let gt = CallGraphType::new();
        assert_eq!(gt.get_name(), "Call Graph");
        assert_eq!(gt.get_description(), "Shows relationships between functions");
    }

    #[test]
    fn default_matches_new() {
        let a = CallGraphType::default();
        let b = CallGraphType::new();
        assert_eq!(a.get_name(), b.get_name());
        assert_eq!(a.get_description(), b.get_description());
    }

    #[test]
    fn deref_exposes_the_wrapped_program_graph_type() {
        let gt = CallGraphType::new();
        assert!(gt.contains_vertex_type(BODY));
        assert!(gt.contains_edge_type(READ));
        assert_eq!(gt.get_options_name(), "Program Graph Display Options");
    }
}

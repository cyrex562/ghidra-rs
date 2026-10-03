//! Port of `ghidra.app.plugin.core.decompile.actions.PCodeCfgGraphType`.
//!
//! Java models this as a one-line subclass of `ProgramGraphType`:
//!
//! ```java
//! public class PCodeCfgGraphType extends ProgramGraphType {
//!     protected PCodeCfgGraphType() {
//!         super("Pcode", "Graph to show pcode for function");
//!     }
//! }
//! ```
//!
//! Per this crate's composition-over-inheritance convention (see
//! [`ProgramGraphType`](crate::graph::ProgramGraphType)'s own module docs, and the already-ported
//! sibling [`BlockFlowGraphType`](crate::graph::BlockFlowGraphType) for the identical shape),
//! [`PCodeCfgGraphType`] is a thin wrapper struct around [`ProgramGraphType`] rather than a
//! subclass, [`Deref`]ing to it (and transitively to `GraphType`) so callers get the exact same
//! vertex/edge type set and behavior.
//!
//! Placed alongside [`PCodeDfgGraphType`](super::p_code_dfg_graph_type::PCodeDfgGraphType), its
//! sibling in the same Java package (`ghidra.app.plugin.core.decompile.actions`), matching the
//! module layout that class already established in this crate.
//!
//! Java's constructor is `protected` (package/subclass visibility only); its one real-code caller
//! (`PCodeCfgGraphTask`, not yet ported) lives in that same package. This crate has no exact
//! equivalent narrower than `pub(crate)`, used here to preserve "not part of the public API".

use std::ops::Deref;

use crate::graph::ProgramGraphType;

/// Port of `ghidra.app.plugin.core.decompile.actions.PCodeCfgGraphType`.
pub struct PCodeCfgGraphType {
    program_graph_type: ProgramGraphType,
}

impl PCodeCfgGraphType {
    /// `PCodeCfgGraphType()`.
    pub(crate) fn new() -> Self {
        Self {
            program_graph_type: ProgramGraphType::new("Pcode", "Graph to show pcode for function"),
        }
    }
}

impl Default for PCodeCfgGraphType {
    fn default() -> Self {
        Self::new()
    }
}

impl Deref for PCodeCfgGraphType {
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
        let gt = PCodeCfgGraphType::new();
        assert_eq!(gt.get_name(), "Pcode");
        assert_eq!(gt.get_description(), "Graph to show pcode for function");
    }

    #[test]
    fn default_matches_new() {
        let a = PCodeCfgGraphType::default();
        let b = PCodeCfgGraphType::new();
        assert_eq!(a.get_name(), b.get_name());
        assert_eq!(a.get_description(), b.get_description());
    }

    #[test]
    fn deref_exposes_the_wrapped_program_graph_type() {
        let gt = PCodeCfgGraphType::new();
        assert!(gt.contains_vertex_type(BODY));
        assert!(gt.contains_edge_type(READ));
        assert_eq!(gt.get_options_name(), "Program Graph Display Options");
    }
}

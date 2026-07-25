//! Minimal placeholder traits for core types not yet ported, used to break
//! dependency cycles. Each placeholder is replaced by the real port later.

use super::g_edge::GEdge;

/// Placeholder for `ghidra.graph.GDirectedGraph`, needed by
/// [`crate::graph::GImplicitDirectedGraph::copy`].
///
/// `copy()` only ever hands the caller an explicit snapshot of the implicit graph; nothing
/// in `GImplicitDirectedGraph` itself calls a method on the result, so this is a marker
/// trait until the real explicit graph type is ported.
pub trait GDirectedGraph<V, E: GEdge<V>> {}

//! Minimal placeholder traits for core types not yet ported, used to break
//! dependency cycles. Each placeholder is replaced by the real port later.

/// Placeholder for `ghidra.service.graph.GraphDisplayOptions`, referenced by
/// [`GraphDisplay`](crate::service::graph::graph_display::GraphDisplay) before the real class is
/// ported. `GraphDisplay` only ever passes this type through as a parameter, so no members are
/// needed yet.
pub trait GraphDisplayOptions: Send + Sync {}

// Re-export GraphDisplayListener from its canonical location
pub use super::graph::graph_display_listener::GraphDisplayListener;

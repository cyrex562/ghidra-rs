//! Minimal placeholder types for `datagraph.data.graph` types not yet ported, used to break
//! dependency cycles. Each placeholder is replaced by the real port later.

/// Placeholder for the unported Java type `DegVertex`, referenced by
/// [`DegEdge`](super::deg_edge::DegEdge). `DegVertex` is a concrete class in Java (not an
/// interface), so it is modeled here as a plain struct rather than a `dyn` trait object.
/// `DegEdge` itself never calls a `DegVertex` method directly (it only stores start/end and
/// clones itself), so no members are declared yet.
pub struct DegVertex;

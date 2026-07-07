use std::ops::{Deref, DerefMut};

use super::Attributed;

const EDGE_TYPE_KEY: &str = "EdgeType";

/// Generic directed graph edge implementation.
///
/// Mirrors `ghidra.service.graph.AttributedEdge`.
#[derive(Debug)]
pub struct AttributedEdge {
    attributed: Attributed,
    id: String,
}

impl AttributedEdge {
    /// Constructs a new `AttributedEdge`.
    ///
    /// `id` is the unique id for the edge.
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            attributed: Attributed::new(),
            id: id.into(),
        }
    }

    /// Returns the id for this edge.
    pub fn get_id(&self) -> &str {
        &self.id
    }

    /// Returns the edge type for this edge.
    pub fn get_edge_type(&self) -> Option<&String> {
        self.get_attribute(EDGE_TYPE_KEY)
    }

    /// Sets the edge type for this edge. Should be a value defined by the `GraphType` for
    /// this graph, but there is no enforcement for this. If the value is not defined in
    /// `GraphType`, it will be rendered using the default edge color for `GraphType`.
    pub fn set_edge_type(&mut self, edge_type: impl Into<String>) {
        self.set_attribute(EDGE_TYPE_KEY.to_string(), edge_type.into());
    }
}

impl Deref for AttributedEdge {
    type Target = Attributed;

    fn deref(&self) -> &Self::Target {
        &self.attributed
    }
}

impl DerefMut for AttributedEdge {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.attributed
    }
}

impl std::fmt::Display for AttributedEdge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.id)
    }
}

impl PartialEq for AttributedEdge {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for AttributedEdge {}

impl std::hash::Hash for AttributedEdge {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_sets_id() {
        let e = AttributedEdge::new("e1");
        assert_eq!(e.get_id(), "e1");
    }

    #[test]
    fn display_returns_id() {
        let e = AttributedEdge::new("e1");
        assert_eq!(e.to_string(), "e1");
    }

    #[test]
    fn get_edge_type_defaults_to_none() {
        let e = AttributedEdge::new("e1");
        assert!(e.get_edge_type().is_none());
    }

    #[test]
    fn set_and_get_edge_type() {
        let mut e = AttributedEdge::new("e1");
        e.set_edge_type("Fallthrough");
        assert_eq!(e.get_edge_type(), Some(&"Fallthrough".to_string()));
    }

    #[test]
    fn equality_based_on_id_only() {
        let mut a = AttributedEdge::new("same");
        let b = AttributedEdge::new("same");
        a.set_edge_type("Foo");
        assert_eq!(a, b);
    }

    #[test]
    fn inequality_for_different_ids() {
        let a = AttributedEdge::new("a");
        let b = AttributedEdge::new("b");
        assert_ne!(a, b);
    }

    #[test]
    fn deref_exposes_attributed_methods() {
        let mut e = AttributedEdge::new("e1");
        e.set_attribute("key".to_string(), "value".to_string());
        assert_eq!(e.get_attribute("key"), Some(&"value".to_string()));
    }

    #[test]
    fn hash_matches_for_equal_ids() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(AttributedEdge::new("x"));
        assert!(set.contains(&AttributedEdge::new("x")));
    }
}

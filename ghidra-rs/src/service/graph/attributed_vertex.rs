use std::ops::{Deref, DerefMut};

use super::Attributed;

const NAME_KEY: &str = "Name";
const VERTEX_TYPE_KEY: &str = "VertexType";

/// Graph vertex with attributes.
///
/// Mirrors `ghidra.service.graph.AttributedVertex`.
#[derive(Debug)]
pub struct AttributedVertex {
    attributed: Attributed,
    id: String,
}

impl AttributedVertex {
    /// Constructs a new `AttributedVertex` with the given id and name.
    pub fn new(id: impl Into<String>, name: impl Into<String>) -> Self {
        let mut vertex = Self {
            attributed: Attributed::new(),
            id: id.into(),
        };
        vertex.set_name(name);
        vertex
    }

    /// Constructs a new `AttributedVertex` with the given id, using the id as the name.
    pub fn with_id(id: impl Into<String>) -> Self {
        let id = id.into();
        Self::new(id.clone(), id)
    }

    /// Sets the name on the vertex.
    pub fn set_name(&mut self, name: impl Into<String>) {
        self.set_attribute(NAME_KEY.to_string(), name.into());
    }

    /// Returns the id for this vertex.
    pub fn get_id(&self) -> &str {
        &self.id
    }

    /// Returns the name of the vertex.
    pub fn get_name(&self) -> Option<&String> {
        self.get_attribute(NAME_KEY)
    }

    /// Returns the vertex type for this vertex.
    pub fn get_vertex_type(&self) -> Option<&String> {
        self.get_attribute(VERTEX_TYPE_KEY)
    }

    /// Sets the vertex type for this vertex. Should be a value defined by the `GraphType` for
    /// this graph, but there is no enforcement for this. If the value is not defined in
    /// `GraphType`, it will be rendered using the default vertex shape and color for the
    /// `GraphType`.
    pub fn set_vertex_type(&mut self, vertex_type: impl Into<String>) {
        self.set_attribute(VERTEX_TYPE_KEY.to_string(), vertex_type.into());
    }
}

impl Deref for AttributedVertex {
    type Target = Attributed;

    fn deref(&self) -> &Self::Target {
        &self.attributed
    }
}

impl DerefMut for AttributedVertex {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.attributed
    }
}

impl std::fmt::Display for AttributedVertex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = self.get_name().map(String::as_str).unwrap_or("");
        write!(f, "{} ({})", name, self.id)
    }
}

impl PartialEq for AttributedVertex {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for AttributedVertex {}

impl std::hash::Hash for AttributedVertex {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_sets_id_and_name() {
        let v = AttributedVertex::new("v1", "Vertex One");
        assert_eq!(v.get_id(), "v1");
        assert_eq!(v.get_name(), Some(&"Vertex One".to_string()));
    }

    #[test]
    fn with_id_uses_id_as_name() {
        let v = AttributedVertex::with_id("v1");
        assert_eq!(v.get_id(), "v1");
        assert_eq!(v.get_name(), Some(&"v1".to_string()));
    }

    #[test]
    fn set_name_updates_name_attribute() {
        let mut v = AttributedVertex::with_id("v1");
        v.set_name("New Name");
        assert_eq!(v.get_name(), Some(&"New Name".to_string()));
    }

    #[test]
    fn display_returns_name_and_id() {
        let v = AttributedVertex::new("v1", "Vertex One");
        assert_eq!(v.to_string(), "Vertex One (v1)");
    }

    #[test]
    fn get_vertex_type_defaults_to_none() {
        let v = AttributedVertex::with_id("v1");
        assert!(v.get_vertex_type().is_none());
    }

    #[test]
    fn set_and_get_vertex_type() {
        let mut v = AttributedVertex::with_id("v1");
        v.set_vertex_type("Entry");
        assert_eq!(v.get_vertex_type(), Some(&"Entry".to_string()));
    }

    #[test]
    fn equality_based_on_id_only() {
        let mut a = AttributedVertex::with_id("same");
        let b = AttributedVertex::with_id("same");
        a.set_name("Different Name");
        assert_eq!(a, b);
    }

    #[test]
    fn inequality_for_different_ids() {
        let a = AttributedVertex::with_id("a");
        let b = AttributedVertex::with_id("b");
        assert_ne!(a, b);
    }

    #[test]
    fn deref_exposes_attributed_methods() {
        let mut v = AttributedVertex::with_id("v1");
        v.set_attribute("key".to_string(), "value".to_string());
        assert_eq!(v.get_attribute("key"), Some(&"value".to_string()));
    }

    #[test]
    fn hash_matches_for_equal_ids() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(AttributedVertex::with_id("x"));
        assert!(set.contains(&AttributedVertex::with_id("x")));
    }
}

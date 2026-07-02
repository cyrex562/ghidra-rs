use std::collections::HashSet;
use std::ops::{Deref, DerefMut};

use crate::service::graph::AttributedVertex;

const MAX_IDS_TO_COMBINE: usize = 6;

/// A vertex passed to [`GroupVertex::group_vertices`] or [`GroupVertex::flatten`].
///
/// Rust has no subtyping, so this enum stands in for the runtime `instanceof GroupVertex`
/// check the Java implementation uses to detect nested groups in a vertex collection.
pub enum GroupableVertex {
    Vertex(AttributedVertex),
    Group(GroupVertex),
}

/// `AttributedVertex` class to represent a group of "collapsed nodes".
///
/// Mirrors `ghidra.graph.visualization.GroupVertex`.
pub struct GroupVertex {
    vertex: AttributedVertex,
    children: HashSet<AttributedVertex>,
    first_id: String,
}

impl GroupVertex {
    /// Creates a new `GroupVertex` that represents the grouping of the given vertices.
    ///
    /// Panics if `vertices` is empty, mirroring the Java implementation's
    /// `IndexOutOfBoundsException` for an empty collection.
    pub fn group_vertices(vertices: impl IntoIterator<Item = GroupableVertex>) -> GroupVertex {
        // the set of vertices given may include group nodes, we only want "real nodes"
        let set = Self::flatten(vertices);
        let mut list: Vec<&AttributedVertex> = set.iter().collect();
        list.sort_by(|a, b| a.get_name().cmp(&b.get_name()));

        let id = Self::get_unique_id(&list);
        let first_id = list[0].get_id().to_string();
        drop(list);

        let mut vertex = AttributedVertex::with_id(id);
        vertex.set_vertex_type("Collapsed Group");
        GroupVertex {
            vertex,
            children: set,
            first_id,
        }
    }

    /// Returns a set of vertices such that all non-group nodes in the given vertices are
    /// included and any group nodes in the given vertices are replaced with their contained
    /// vertices.
    pub fn flatten(vertices: impl IntoIterator<Item = GroupableVertex>) -> HashSet<AttributedVertex> {
        let mut set = HashSet::new();
        for vertex in vertices {
            match vertex {
                GroupableVertex::Group(group) => set.extend(group.children),
                GroupableVertex::Vertex(vertex) => {
                    set.insert(vertex);
                }
            }
        }
        set
    }

    fn get_unique_id(vertex_list: &[&AttributedVertex]) -> String {
        if vertex_list.len() > MAX_IDS_TO_COMBINE {
            let ids_not_shown_count = vertex_list.len() - MAX_IDS_TO_COMBINE;
            return format!(
                "{}\n...\n + {} Others",
                Self::combine_ids(&vertex_list[0..MAX_IDS_TO_COMBINE]),
                ids_not_shown_count
            );
        }
        Self::combine_ids(vertex_list)
    }

    fn combine_ids(vertices: &[&AttributedVertex]) -> String {
        vertices
            .iter()
            .map(|vertex| vertex.get_name().map(String::as_str).unwrap_or(""))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Returns the set of flattened nodes contained in this node. In other words, any group
    /// nodes that were given to this group node would have been swapped for the nodes that the
    /// group node contained.
    pub fn get_contained_vertices(&self) -> &HashSet<AttributedVertex> {
        &self.children
    }

    /// Returns the node that is first, with first being currently defined to be the one that is
    /// first when sorted by id alphabetically.
    pub fn get_first(&self) -> &AttributedVertex {
        self.children
            .iter()
            .find(|vertex| vertex.get_id() == self.first_id)
            .expect("first vertex is always present among children")
    }
}

impl Deref for GroupVertex {
    type Target = AttributedVertex;

    fn deref(&self) -> &Self::Target {
        &self.vertex
    }
}

impl DerefMut for GroupVertex {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.vertex
    }
}

impl std::fmt::Display for GroupVertex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.vertex, f)
    }
}

impl PartialEq for GroupVertex {
    fn eq(&self, other: &Self) -> bool {
        self.vertex == other.vertex
    }
}

impl Eq for GroupVertex {}

impl std::hash::Hash for GroupVertex {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.vertex.hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vertex(id: &str) -> AttributedVertex {
        AttributedVertex::with_id(id)
    }

    #[test]
    fn group_vertices_combines_plain_vertices() {
        let group = GroupVertex::group_vertices(vec![
            GroupableVertex::Vertex(vertex("b")),
            GroupableVertex::Vertex(vertex("a")),
        ]);
        assert_eq!(group.get_id(), "a\nb");
        assert_eq!(group.get_vertex_type(), Some(&"Collapsed Group".to_string()));
        assert_eq!(group.get_contained_vertices().len(), 2);
    }

    #[test]
    fn group_vertices_first_is_alphabetically_first() {
        let group = GroupVertex::group_vertices(vec![
            GroupableVertex::Vertex(vertex("zeta")),
            GroupableVertex::Vertex(vertex("alpha")),
        ]);
        assert_eq!(group.get_first().get_id(), "alpha");
    }

    #[test]
    fn flatten_replaces_nested_groups_with_their_children() {
        let inner = GroupVertex::group_vertices(vec![
            GroupableVertex::Vertex(vertex("a")),
            GroupableVertex::Vertex(vertex("b")),
        ]);
        let set = GroupVertex::flatten(vec![
            GroupableVertex::Group(inner),
            GroupableVertex::Vertex(vertex("c")),
        ]);
        let mut ids: Vec<&str> = set.iter().map(|v| v.get_id()).collect();
        ids.sort();
        assert_eq!(ids, vec!["a", "b", "c"]);
    }

    #[test]
    fn group_vertices_nested_group_flattens_grandchildren() {
        let inner = GroupVertex::group_vertices(vec![
            GroupableVertex::Vertex(vertex("a")),
            GroupableVertex::Vertex(vertex("b")),
        ]);
        let outer = GroupVertex::group_vertices(vec![
            GroupableVertex::Group(inner),
            GroupableVertex::Vertex(vertex("c")),
        ]);
        assert_eq!(outer.get_contained_vertices().len(), 3);
        assert_eq!(outer.get_first().get_id(), "a");
    }

    #[test]
    fn get_unique_id_combines_many_ids_with_ellipsis() {
        let vertices: Vec<GroupableVertex> = (0..8)
            .map(|i| GroupableVertex::Vertex(vertex(&format!("v{}", i))))
            .collect();
        let group = GroupVertex::group_vertices(vertices);
        assert!(group.get_id().contains("...\n + 2 Others"));
    }

    #[test]
    fn deref_exposes_attributed_vertex_methods() {
        let mut group = GroupVertex::group_vertices(vec![GroupableVertex::Vertex(vertex("a"))]);
        group.set_attribute("key".to_string(), "value".to_string());
        assert_eq!(group.get_attribute("key"), Some(&"value".to_string()));
    }

    #[test]
    fn equality_based_on_id_only() {
        let a = GroupVertex::group_vertices(vec![GroupableVertex::Vertex(vertex("a"))]);
        let b = GroupVertex::group_vertices(vec![GroupableVertex::Vertex(vertex("a"))]);
        assert_eq!(a, b);
    }

    #[test]
    #[should_panic]
    fn group_vertices_empty_panics() {
        GroupVertex::group_vertices(Vec::new());
    }
}

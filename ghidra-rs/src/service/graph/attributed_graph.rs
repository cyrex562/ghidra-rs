use std::collections::HashMap;

use super::{AttributedEdge, AttributedVertex, GraphType};

struct EdgeEntry {
    edge: AttributedEdge,
    source_id: String,
    target_id: String,
}

/// Basic graph implementation for a directed graph whose vertices and edges support
/// attributes.
///
/// The graph can be configured as to how to handle multiple edges with the same source and
/// destination vertices. One option is to simply allow multiple edges. The second option is
/// to collapse duplicate edges such that there is only ever one edge with the same source and
/// destination. In this case, each additional duplicate edge added will cause the edge to
/// have a "Weight" attribute that will be the total number of edges that were added to the
/// same source/destination vertex pair.
///
/// Mirrors `ghidra.service.graph.AttributedGraph`.
pub struct AttributedGraph {
    name: String,
    graph_type: GraphType,
    description: String,
    collapse_duplicate_edges: bool,
    vertices: HashMap<String, AttributedVertex>,
    edges: HashMap<String, EdgeEntry>,
    next_vertex_id: u64,
    next_edge_id: u64,
}

impl AttributedGraph {
    /// The attribute key used to record the number of duplicate edges collapsed into one.
    pub const WEIGHT: &'static str = "Weight";

    /// Creates a new empty `AttributedGraph` that automatically collapses duplicate edges.
    pub fn new(name: impl Into<String>, graph_type: GraphType) -> Self {
        let name = name.into();
        Self::with_options(name.clone(), graph_type, name, true)
    }

    /// Creates a new empty `AttributedGraph` that automatically collapses duplicate edges.
    pub fn with_description(
        name: impl Into<String>,
        graph_type: GraphType,
        description: impl Into<String>,
    ) -> Self {
        Self::with_options(name, graph_type, description, true)
    }

    /// Creates a new empty `AttributedGraph`.
    ///
    /// If `collapse_duplicate_edges` is true, duplicate edges will be collapsed into a single
    /// edge with a "Weight" attribute whose value is the number of edges that have been added
    /// between those vertices.
    pub fn with_options(
        name: impl Into<String>,
        graph_type: GraphType,
        description: impl Into<String>,
        collapse_duplicate_edges: bool,
    ) -> Self {
        Self {
            name: name.into(),
            graph_type,
            description: description.into(),
            collapse_duplicate_edges,
            vertices: HashMap::new(),
            edges: HashMap::new(),
            next_vertex_id: 1,
            next_edge_id: 1,
        }
    }

    /// Returns the name of the graph.
    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// Returns a description of the graph.
    pub fn get_description(&self) -> &str {
        &self.description
    }

    /// Returns the `GraphType` for this graph.
    pub fn get_graph_type(&self) -> &GraphType {
        &self.graph_type
    }

    /// Adds a new vertex with the given id. The vertex's name will be the same as the id. If
    /// a vertex already exists with that id, then that vertex will be returned.
    pub fn add_vertex(&mut self, id: impl Into<String>) -> &AttributedVertex {
        let id = id.into();
        self.add_vertex_with_name(id.clone(), id)
    }

    /// Adds a new vertex with the given id and name. If a vertex already exists with that id,
    /// then that vertex will be returned, but with its name changed to the given name.
    pub fn add_vertex_with_name(
        &mut self,
        id: impl Into<String>,
        vertex_name: impl Into<String>,
    ) -> &AttributedVertex {
        let id = id.into();
        match self.vertices.get_mut(&id) {
            Some(existing) => existing.set_name(vertex_name),
            None => {
                self.vertices
                    .insert(id.clone(), AttributedVertex::new(id.clone(), vertex_name));
            }
        }
        self.vertices.get(&id).expect("vertex was just inserted")
    }

    /// Adds a new vertex with an automatically generated id, using a simple one-up numbering
    /// scheme.
    pub fn add_generated_vertex(&mut self) -> &AttributedVertex {
        let id = self.next_vertex_id.to_string();
        self.next_vertex_id += 1;
        let vertex = AttributedVertex::with_id(id.clone());
        self.vertices.insert(id.clone(), vertex);
        self.vertices.get(&id).expect("vertex was just inserted")
    }

    /// Adds the given vertex to the graph. Returns `true` if the vertex was added, or `false`
    /// if a vertex with that id already existed, in which case the existing vertex is left
    /// unchanged.
    pub fn insert_vertex(&mut self, vertex: AttributedVertex) -> bool {
        let id = vertex.get_id().to_string();
        if self.vertices.contains_key(&id) {
            return false;
        }
        self.vertices.insert(id, vertex);
        true
    }

    /// Creates and adds a new directed edge with the given id between the given source and
    /// target vertex ids. If the graph is set to collapse duplicate edges and an edge for that
    /// source and target already exists, the existing edge is returned with its "Weight"
    /// attribute set to the total number of edges that have been added between the source and
    /// target vertices; the given `edge_id` is not used in that case.
    pub fn add_edge(
        &mut self,
        source_id: &str,
        target_id: &str,
        edge_id: impl Into<String>,
    ) -> &AttributedEdge {
        let edge = AttributedEdge::new(edge_id);
        let id = self.insert_edge_internal(source_id, target_id, edge);
        &self.edges.get(&id).expect("edge was just inserted").edge
    }

    /// Adds the given edge object between the given source and target vertex ids. If the
    /// graph is set to collapse duplicate edges and an edge for that source and target
    /// already exists, the existing edge's "Weight" attribute is updated instead and the
    /// given edge object is discarded. Returns `true` if the edge was added (this always
    /// returns `true`, matching the collapsing behavior of the graph).
    pub fn insert_edge(&mut self, source_id: &str, target_id: &str, edge: AttributedEdge) -> bool {
        self.insert_edge_internal(source_id, target_id, edge);
        true
    }

    /// Creates and adds a new directed edge with an automatically generated id between the
    /// given source and target vertex ids. If the graph is set to collapse duplicate edges
    /// and an edge for that source and target already exists, the existing edge is returned
    /// with its "Weight" attribute set accordingly.
    pub fn add_generated_edge(&mut self, source_id: &str, target_id: &str) -> &AttributedEdge {
        let edge_id = self.next_edge_id.to_string();
        self.next_edge_id += 1;
        let edge = AttributedEdge::new(edge_id);
        let id = self.insert_edge_internal(source_id, target_id, edge);
        &self.edges.get(&id).expect("edge was just inserted").edge
    }

    /// Returns the total number of edges in the graph.
    pub fn get_edge_count(&self) -> usize {
        self.edges.len()
    }

    /// Returns the total number of vertices in the graph.
    pub fn get_vertex_count(&self) -> usize {
        self.vertices.len()
    }

    /// Returns the vertex with the given vertex id, or `None` if none found.
    pub fn get_vertex(&self, vertex_id: &str) -> Option<&AttributedVertex> {
        self.vertices.get(vertex_id)
    }

    fn insert_edge_internal(
        &mut self,
        source_id: &str,
        target_id: &str,
        edge: AttributedEdge,
    ) -> String {
        self.ensure_in_graph(source_id);
        self.ensure_in_graph(target_id);
        if self.collapse_duplicate_edges {
            if let Some(existing_id) = self.find_edge_id(source_id, target_id) {
                Self::increment_weight_property(&mut self.edges.get_mut(&existing_id).unwrap().edge);
                return existing_id;
            }
        }
        let id = edge.get_id().to_string();
        self.edges.insert(
            id.clone(),
            EdgeEntry {
                edge,
                source_id: source_id.to_string(),
                target_id: target_id.to_string(),
            },
        );
        id
    }

    fn find_edge_id(&self, source_id: &str, target_id: &str) -> Option<String> {
        self.edges
            .iter()
            .find(|(_, entry)| entry.source_id == source_id && entry.target_id == target_id)
            .map(|(id, _)| id.clone())
    }

    fn ensure_in_graph(&mut self, vertex_id: &str) {
        if !self.vertices.contains_key(vertex_id) {
            self.insert_vertex(AttributedVertex::with_id(vertex_id.to_string()));
        }
    }

    fn increment_weight_property(edge: &mut AttributedEdge) {
        let next = match edge.get_attribute(Self::WEIGHT) {
            Some(weight_string) => Self::increment_weight_string_value(weight_string),
            None => "2".to_string(),
        };
        edge.set_attribute(Self::WEIGHT.to_string(), next);
    }

    fn increment_weight_string_value(value: &str) -> String {
        let weight: i64 = value.parse().expect("Weight attribute should be an integer");
        (weight + 1).to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::graph::empty_graph_type;

    #[test]
    fn new_sets_name_type_and_description_to_name() {
        let g = AttributedGraph::new("MyGraph", empty_graph_type());
        assert_eq!(g.get_name(), "MyGraph");
        assert_eq!(g.get_description(), "MyGraph");
        assert_eq!(g.get_graph_type().get_name(), "Empty Graph Type");
    }

    #[test]
    fn with_description_sets_distinct_description() {
        let g = AttributedGraph::with_description("MyGraph", empty_graph_type(), "A description");
        assert_eq!(g.get_name(), "MyGraph");
        assert_eq!(g.get_description(), "A description");
    }

    #[test]
    fn new_graph_is_empty() {
        let g = AttributedGraph::new("G", empty_graph_type());
        assert_eq!(g.get_vertex_count(), 0);
        assert_eq!(g.get_edge_count(), 0);
    }

    #[test]
    fn add_vertex_creates_vertex_with_id_as_name() {
        let mut g = AttributedGraph::new("G", empty_graph_type());
        let v = g.add_vertex("v1");
        assert_eq!(v.get_id(), "v1");
        assert_eq!(v.get_name(), Some(&"v1".to_string()));
        assert_eq!(g.get_vertex_count(), 1);
    }

    #[test]
    fn add_vertex_twice_resets_name_to_id() {
        let mut g = AttributedGraph::new("G", empty_graph_type());
        g.add_vertex_with_name("v1", "Custom Name");
        let v = g.add_vertex("v1");
        assert_eq!(v.get_name(), Some(&"v1".to_string()));
        assert_eq!(g.get_vertex_count(), 1);
    }

    #[test]
    fn add_vertex_with_name_updates_existing_vertex_name() {
        let mut g = AttributedGraph::new("G", empty_graph_type());
        g.add_vertex("v1");
        let v = g.add_vertex_with_name("v1", "New Name");
        assert_eq!(v.get_id(), "v1");
        assert_eq!(v.get_name(), Some(&"New Name".to_string()));
        assert_eq!(g.get_vertex_count(), 1);
    }

    #[test]
    fn add_generated_vertex_uses_one_up_ids() {
        let mut g = AttributedGraph::new("G", empty_graph_type());
        let id1 = g.add_generated_vertex().get_id().to_string();
        let id2 = g.add_generated_vertex().get_id().to_string();
        assert_eq!(id1, "1");
        assert_eq!(id2, "2");
        assert_eq!(g.get_vertex_count(), 2);
    }

    #[test]
    fn insert_vertex_returns_true_when_new() {
        let mut g = AttributedGraph::new("G", empty_graph_type());
        let added = g.insert_vertex(AttributedVertex::with_id("v1"));
        assert!(added);
        assert_eq!(g.get_vertex_count(), 1);
    }

    #[test]
    fn insert_vertex_returns_false_and_keeps_existing_when_duplicate() {
        let mut g = AttributedGraph::new("G", empty_graph_type());
        g.add_vertex_with_name("v1", "Original");
        let added = g.insert_vertex(AttributedVertex::new("v1", "Ignored"));
        assert!(!added);
        assert_eq!(
            g.get_vertex("v1").unwrap().get_name(),
            Some(&"Original".to_string())
        );
    }

    #[test]
    fn get_vertex_returns_none_for_missing_id() {
        let g = AttributedGraph::new("G", empty_graph_type());
        assert!(g.get_vertex("missing").is_none());
    }

    #[test]
    fn add_edge_creates_edge_and_registers_vertices() {
        let mut g = AttributedGraph::new("G", empty_graph_type());
        let edge = g.add_edge("a", "b", "e1");
        assert_eq!(edge.get_id(), "e1");
        assert_eq!(g.get_edge_count(), 1);
        assert_eq!(g.get_vertex_count(), 2);
        assert!(g.get_vertex("a").is_some());
        assert!(g.get_vertex("b").is_some());
    }

    #[test]
    fn add_edge_collapses_duplicate_and_sets_weight() {
        let mut g = AttributedGraph::new("G", empty_graph_type());
        g.add_edge("a", "b", "e1");
        let edge2 = g.add_edge("a", "b", "e2");
        assert_eq!(edge2.get_id(), "e1");
        assert_eq!(edge2.get_attribute(AttributedGraph::WEIGHT), Some(&"2".to_string()));
        assert_eq!(g.get_edge_count(), 1);
    }

    #[test]
    fn add_edge_collapse_increments_weight_on_repeated_duplicates() {
        let mut g = AttributedGraph::new("G", empty_graph_type());
        g.add_edge("a", "b", "e1");
        g.add_edge("a", "b", "e2");
        let edge3 = g.add_edge("a", "b", "e3");
        assert_eq!(edge3.get_attribute(AttributedGraph::WEIGHT), Some(&"3".to_string()));
        assert_eq!(g.get_edge_count(), 1);
    }

    #[test]
    fn add_edge_without_collapse_allows_multiple_edges() {
        let mut g = AttributedGraph::with_options("G", empty_graph_type(), "G", false);
        g.add_edge("a", "b", "e1");
        g.add_edge("a", "b", "e2");
        assert_eq!(g.get_edge_count(), 2);
    }

    #[test]
    fn add_generated_edge_uses_one_up_ids() {
        let mut g = AttributedGraph::with_options("G", empty_graph_type(), "G", false);
        let id1 = g.add_generated_edge("a", "b").get_id().to_string();
        let id2 = g.add_generated_edge("a", "b").get_id().to_string();
        assert_eq!(id1, "1");
        assert_eq!(id2, "2");
        assert_eq!(g.get_edge_count(), 2);
    }

    #[test]
    fn insert_edge_collapses_when_configured() {
        let mut g = AttributedGraph::new("G", empty_graph_type());
        g.add_edge("a", "b", "e1");
        let added = g.insert_edge("a", "b", AttributedEdge::new("e2"));
        assert!(added);
        assert_eq!(g.get_edge_count(), 1);
        assert_eq!(
            g.get_vertex("a").is_some() && g.get_vertex("b").is_some(),
            true
        );
    }

    #[test]
    fn weight_constant_matches_java_value() {
        assert_eq!(AttributedGraph::WEIGHT, "Weight");
    }

    #[test]
    fn add_generated_vertex_is_retrievable_by_id() {
        let mut g = AttributedGraph::new("G", empty_graph_type());
        let id = g.add_generated_vertex().get_id().to_string();
        assert!(g.get_vertex(&id).is_some());
        assert_eq!(g.get_vertex_count(), 1);
    }

    #[test]
    fn add_vertex_with_name_creates_new_vertex_with_given_name() {
        let mut g = AttributedGraph::new("G", empty_graph_type());
        let v = g.add_vertex_with_name("A", "Bob");
        assert_eq!(v.get_id(), "A");
        assert_eq!(v.get_name(), Some(&"Bob".to_string()));
        assert_eq!(g.get_vertex_count(), 1);
    }

    #[test]
    fn add_vertex_called_twice_with_same_id_keeps_single_vertex() {
        let mut g = AttributedGraph::new("G", empty_graph_type());
        g.add_vertex("A");
        let v2 = g.add_vertex("A");
        assert_eq!(v2.get_id(), "A");
        assert_eq!(g.get_vertex_count(), 1);
    }

    #[test]
    fn get_vertex_works_for_all_vertex_creation_methods() {
        let mut g = AttributedGraph::new("G", empty_graph_type());
        g.add_vertex("A");
        g.add_vertex_with_name("B", "NAME");
        let generated_id = g.add_generated_vertex().get_id().to_string();
        g.insert_vertex(AttributedVertex::with_id("C"));

        assert_eq!(g.get_vertex_count(), 4);
        assert!(g.get_vertex("A").is_some());
        assert!(g.get_vertex("B").is_some());
        assert!(g.get_vertex(&generated_id).is_some());
        assert!(g.get_vertex("C").is_some());
    }

    #[test]
    fn insert_edge_then_add_edge_collapses_preserving_original_id() {
        let mut g = AttributedGraph::new("G", empty_graph_type());
        let added = g.insert_edge("a", "b", AttributedEdge::new("E1"));
        assert!(added);
        assert_eq!(g.get_edge_count(), 1);

        let edge = g.add_edge("a", "b", "ignored");
        assert_eq!(edge.get_id(), "E1");
        assert_eq!(g.get_edge_count(), 1);
    }

    #[test]
    fn collapse_duplicate_edges_with_supplied_edges_preserves_first_id() {
        let mut g = AttributedGraph::new("G", empty_graph_type());
        g.insert_edge("a", "b", AttributedEdge::new("1"));
        g.insert_edge("a", "b", AttributedEdge::new("2"));
        let edge = g.add_edge("a", "b", "3");
        let edge_id = edge.get_id().to_string();
        let edge_weight = edge.get_attribute(AttributedGraph::WEIGHT).cloned();

        assert_eq!(g.get_edge_count(), 1);
        assert_eq!(edge_id, "1");
        assert_eq!(edge_weight, Some("3".to_string()));
    }

    #[test]
    fn reverse_direction_edges_do_not_collapse() {
        let mut g = AttributedGraph::new("G", empty_graph_type());
        g.add_edge("a", "b", "e1");
        g.add_edge("b", "a", "e2");
        assert_eq!(g.get_edge_count(), 2);
    }
}

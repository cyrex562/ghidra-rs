use std::collections::{HashMap, HashSet};

use crate::service::graph::AttributedVertex;

use super::group_vertex::{GroupVertex, GroupableVertex};

/// Minimal view onto a graph viewer's vertex/edge selection state.
///
/// Stands in for jungrapht-visualization's `VisualizationServer` and `MutableSelectedState`,
/// which back the Java `vv` field and have no Rust port. Callers wire this trait to whatever
/// owns the actual rendering/selection state.
pub trait GraphSelectionView {
    /// Returns the ids of the vertices currently selected in the view.
    fn selected_vertex_ids(&self) -> HashSet<String>;

    /// Clears the current vertex selection.
    fn clear_vertex_selection(&mut self);

    /// Clears the current edge selection.
    fn clear_edge_selection(&mut self);

    /// Selects the vertex with the given id.
    fn select_vertex(&mut self, vertex_id: &str);
}

/// Handles collapsing graph nodes.
///
/// Mirrors `ghidra.graph.visualization.GhidraGraphCollapser`. The Java class subclasses
/// jungrapht-visualization's `VisualGraphCollapser` to get its `collapse`/`expand`/
/// `findOwnerOf` machinery and a `graph` field tracking which vertices are currently visible;
/// that base class is a third-party UI library type with no Rust port, so this struct owns
/// the equivalent grouping/ownership bookkeeping directly.
pub struct GhidraGraphCollapser {
    /// Vertices currently visible at the top level of the graph, keyed by id.
    live: HashMap<String, GroupableVertex>,
    /// Maps the id of a vertex that has been collapsed away to the id of the vertex that
    /// currently, directly owns/replaces it.
    owners: HashMap<String, String>,
}

impl GhidraGraphCollapser {
    /// Creates a new collapser seeded with the given top-level vertices from the graph.
    pub fn new(vertices: impl IntoIterator<Item = AttributedVertex>) -> Self {
        let live = vertices
            .into_iter()
            .map(|v| (v.get_id().to_string(), GroupableVertex::Vertex(v)))
            .collect();
        GhidraGraphCollapser {
            live,
            owners: HashMap::new(),
        }
    }

    /// Returns `true` if a vertex with the given id is currently visible at the top level of
    /// the graph (i.e. it is not collapsed into a group).
    pub fn contains_vertex(&self, vertex_id: &str) -> bool {
        self.live.contains_key(vertex_id)
    }

    /// Returns the group vertex with the given id, if one is currently live.
    pub fn get_group(&self, vertex_id: &str) -> Option<&GroupVertex> {
        match self.live.get(vertex_id) {
            Some(GroupableVertex::Group(group)) => Some(group),
            _ => None,
        }
    }

    /// Ungroups any GroupVertices that are selected.
    pub fn ungroup_selected_vertices(&mut self, view: &mut impl GraphSelectionView) {
        let selected = view.selected_vertex_ids();
        self.expand(&selected);
    }

    /// Groups the selected vertices into one vertex that represents them all.
    ///
    /// Returns `None` if fewer than two vertices are selected.
    pub fn group_selected_vertices(
        &mut self,
        view: &mut impl GraphSelectionView,
    ) -> Option<&GroupVertex> {
        let selected = view.selected_vertex_ids();
        if selected.len() <= 1 {
            return None;
        }

        let group_id = self.collapse(&selected);
        view.clear_vertex_selection();
        view.clear_edge_selection();
        view.select_vertex(&group_id);
        self.get_group(&group_id)
    }

    /// Converts the given set of vertices to the set of ids of their outermost containing
    /// groups (or their own id, if not grouped).
    pub fn convert_to_outermost_vertices(
        &self,
        vertices: &HashSet<AttributedVertex>,
    ) -> HashSet<String> {
        vertices.iter().map(|v| self.get_outermost_vertex(v)).collect()
    }

    /// Returns the id of the outermost group vertex containing the given vertex, or the
    /// vertex's own id if it is not in a group.
    pub fn get_outermost_vertex(&self, vertex: &AttributedVertex) -> String {
        let mut current = vertex.get_id();
        while let Some(owner) = self.owners.get(current) {
            current = owner.as_str();
        }
        current.to_string()
    }

    /// Collapses the vertices with the given ids into one new group vertex, returning its id.
    fn collapse(&mut self, ids: &HashSet<String>) -> String {
        let groupable: Vec<GroupableVertex> =
            ids.iter().filter_map(|id| self.live.remove(id)).collect();
        let group = GroupVertex::group_vertices(groupable);
        let group_id = group.get_id().to_string();

        for id in ids {
            self.owners.insert(id.clone(), group_id.clone());
        }
        self.owners.remove(&group_id);
        self.live.insert(group_id.clone(), GroupableVertex::Group(group));
        group_id
    }

    /// Expands any of the given ids that are currently live group vertices, restoring their
    /// contained vertices to the top level of the graph.
    fn expand(&mut self, ids: &HashSet<String>) {
        for id in ids {
            let is_group = matches!(self.live.get(id), Some(GroupableVertex::Group(_)));
            if !is_group {
                continue;
            }
            if let Some(GroupableVertex::Group(group)) = self.live.remove(id) {
                for child in group.get_contained_vertices() {
                    let child_id = child.get_id().to_string();
                    self.owners.remove(&child_id);
                    self.live
                        .insert(child_id, GroupableVertex::Vertex(Self::copy_vertex(child)));
                }
            }
        }
    }

    /// Copies a vertex's id and attributes into a fresh `AttributedVertex`.
    ///
    /// Used to restore vertices that were moved into a `GroupVertex`'s private contained-vertex
    /// set back onto the top level of the graph when expanding.
    fn copy_vertex(vertex: &AttributedVertex) -> AttributedVertex {
        let mut copy = AttributedVertex::with_id(vertex.get_id());
        copy.put_attributes(vertex.get_attributes().clone());
        copy
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockView {
        selected: HashSet<String>,
        vertex_selection_cleared: bool,
        edge_selection_cleared: bool,
    }

    impl MockView {
        fn with_selection(ids: &[&str]) -> Self {
            MockView {
                selected: ids.iter().map(|s| s.to_string()).collect(),
                vertex_selection_cleared: false,
                edge_selection_cleared: false,
            }
        }
    }

    impl GraphSelectionView for MockView {
        fn selected_vertex_ids(&self) -> HashSet<String> {
            self.selected.clone()
        }

        fn clear_vertex_selection(&mut self) {
            self.vertex_selection_cleared = true;
            self.selected.clear();
        }

        fn clear_edge_selection(&mut self) {
            self.edge_selection_cleared = true;
        }

        fn select_vertex(&mut self, vertex_id: &str) {
            self.selected.insert(vertex_id.to_string());
        }
    }

    fn vertex(id: &str) -> AttributedVertex {
        AttributedVertex::with_id(id)
    }

    #[test]
    fn group_selected_vertices_requires_more_than_one() {
        let mut collapser = GhidraGraphCollapser::new(vec![vertex("a")]);
        let mut view = MockView::with_selection(&["a"]);
        assert!(collapser.group_selected_vertices(&mut view).is_none());
    }

    #[test]
    fn group_selected_vertices_creates_group_and_updates_selection() {
        let mut collapser = GhidraGraphCollapser::new(vec![vertex("a"), vertex("b")]);
        let mut view = MockView::with_selection(&["a", "b"]);

        let group_id = collapser
            .group_selected_vertices(&mut view)
            .expect("group should be created")
            .get_id()
            .to_string();

        assert_eq!(group_id, "a\nb");
        assert!(view.vertex_selection_cleared);
        assert!(view.edge_selection_cleared);
        assert_eq!(view.selected, [group_id.clone()].into_iter().collect());

        assert!(!collapser.contains_vertex("a"));
        assert!(!collapser.contains_vertex("b"));
        assert!(collapser.contains_vertex(&group_id));
        assert_eq!(
            collapser.get_group(&group_id).unwrap().get_contained_vertices().len(),
            2
        );
    }

    #[test]
    fn get_outermost_vertex_returns_self_when_ungrouped() {
        let collapser = GhidraGraphCollapser::new(vec![vertex("a")]);
        assert_eq!(collapser.get_outermost_vertex(&vertex("a")), "a");
    }

    #[test]
    fn get_outermost_vertex_returns_group_after_grouping() {
        let mut collapser = GhidraGraphCollapser::new(vec![vertex("a"), vertex("b")]);
        let mut view = MockView::with_selection(&["a", "b"]);
        let group_id = collapser
            .group_selected_vertices(&mut view)
            .unwrap()
            .get_id()
            .to_string();

        assert_eq!(collapser.get_outermost_vertex(&vertex("a")), group_id);
        assert_eq!(collapser.get_outermost_vertex(&vertex("b")), group_id);
    }

    #[test]
    fn get_outermost_vertex_walks_nested_groups() {
        let mut collapser =
            GhidraGraphCollapser::new(vec![vertex("a"), vertex("b"), vertex("c")]);

        let mut view1 = MockView::with_selection(&["a", "b"]);
        let g1 = collapser
            .group_selected_vertices(&mut view1)
            .unwrap()
            .get_id()
            .to_string();

        let mut view2 = MockView::with_selection(&[g1.as_str(), "c"]);
        let g2 = collapser
            .group_selected_vertices(&mut view2)
            .unwrap()
            .get_id()
            .to_string();

        assert_eq!(collapser.get_outermost_vertex(&vertex("a")), g2);
        assert_eq!(collapser.get_outermost_vertex(&vertex("c")), g2);
        assert!(!collapser.contains_vertex(&g1));
        assert_eq!(collapser.get_group(&g2).unwrap().get_contained_vertices().len(), 3);
    }

    #[test]
    fn convert_to_outermost_vertices_dedups_grouped_vertices() {
        let mut collapser = GhidraGraphCollapser::new(vec![vertex("a"), vertex("b"), vertex("c")]);
        let mut view = MockView::with_selection(&["a", "b"]);
        let group_id = collapser
            .group_selected_vertices(&mut view)
            .unwrap()
            .get_id()
            .to_string();

        let converted = collapser
            .convert_to_outermost_vertices(&[vertex("a"), vertex("b"), vertex("c")].into_iter().collect());

        let expected: HashSet<String> = [group_id, "c".to_string()].into_iter().collect();
        assert_eq!(converted, expected);
    }

    #[test]
    fn ungroup_selected_vertices_restores_children() {
        let mut collapser = GhidraGraphCollapser::new(vec![vertex("a"), vertex("b")]);
        let mut group_view = MockView::with_selection(&["a", "b"]);
        let group_id = collapser
            .group_selected_vertices(&mut group_view)
            .unwrap()
            .get_id()
            .to_string();

        let mut ungroup_view = MockView::with_selection(&[group_id.as_str()]);
        collapser.ungroup_selected_vertices(&mut ungroup_view);

        assert!(!collapser.contains_vertex(&group_id));
        assert!(collapser.contains_vertex("a"));
        assert!(collapser.contains_vertex("b"));
        assert_eq!(collapser.get_outermost_vertex(&vertex("a")), "a");
        assert_eq!(collapser.get_outermost_vertex(&vertex("b")), "b");
    }

    #[test]
    fn ungroup_selected_vertices_is_noop_for_non_group_vertex() {
        let mut collapser = GhidraGraphCollapser::new(vec![vertex("a")]);
        let mut view = MockView::with_selection(&["a"]);
        collapser.ungroup_selected_vertices(&mut view);
        assert!(collapser.contains_vertex("a"));
    }

    #[test]
    fn copy_vertex_preserves_attributes_on_expand() {
        let mut a = vertex("a");
        a.set_vertex_type("Custom Type");
        let mut collapser = GhidraGraphCollapser::new(vec![a, vertex("b")]);

        let mut group_view = MockView::with_selection(&["a", "b"]);
        let group_id = collapser
            .group_selected_vertices(&mut group_view)
            .unwrap()
            .get_id()
            .to_string();

        let mut ungroup_view = MockView::with_selection(&[group_id.as_str()]);
        collapser.ungroup_selected_vertices(&mut ungroup_view);

        match collapser.live.get("a") {
            Some(GroupableVertex::Vertex(v)) => {
                assert_eq!(v.get_vertex_type(), Some(&"Custom Type".to_string()))
            }
            _ => panic!("expected vertex a to be restored as a plain vertex"),
        }
    }
}

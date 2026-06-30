use std::collections::HashSet;

/// Defines a graph type by specifying the set of valid vertex and edge type names.
pub struct GraphType {
    name: String,
    description: String,
    vertex_types: Vec<String>,
    edge_types: Vec<String>,
}

fn deduplicate_ordered(items: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        if seen.insert(item.clone()) {
            out.push(item);
        }
    }
    out
}

impl GraphType {
    /// Constructs a new `GraphType`.
    ///
    /// Duplicate entries in `vertex_types` or `edge_types` are silently removed while
    /// preserving first-seen insertion order, matching Java's `LinkedHashSet` semantics.
    pub fn new(
        name: String,
        description: String,
        vertex_types: Vec<String>,
        edge_types: Vec<String>,
    ) -> Self {
        Self {
            name,
            description,
            vertex_types: deduplicate_ordered(vertex_types),
            edge_types: deduplicate_ordered(edge_types),
        }
    }

    /// Returns the name of this graph type.
    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// Returns the description of this graph type.
    pub fn get_description(&self) -> &str {
        &self.description
    }

    /// Returns the ordered list of valid vertex type names for graphs of this type.
    pub fn get_vertex_types(&self) -> Vec<String> {
        self.vertex_types.clone()
    }

    /// Returns the ordered list of valid edge type names for graphs of this type.
    pub fn get_edge_types(&self) -> Vec<String> {
        self.edge_types.clone()
    }

    /// Returns `true` if `vertex_type` is a valid vertex type for this graph type.
    pub fn contains_vertex_type(&self, vertex_type: &str) -> bool {
        self.vertex_types.iter().any(|v| v == vertex_type)
    }

    /// Returns `true` if `edge_type` is a valid edge type for this graph type.
    pub fn contains_edge_type(&self, edge_type: &str) -> bool {
        self.edge_types.iter().any(|e| e == edge_type)
    }

    /// Returns the options display name for this graph type (e.g. `"Call Graph Graph Type"`).
    pub fn get_options_name(&self) -> String {
        format!("{} Graph Type", self.name)
    }
}

impl PartialEq for GraphType {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
            && self.description == other.description
            && self.vertex_types == other.vertex_types
            && self.edge_types == other.edge_types
    }
}

impl Eq for GraphType {}

impl std::hash::Hash for GraphType {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.name.hash(state);
        self.description.hash(state);
        self.vertex_types.hash(state);
        self.edge_types.hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_gt(name: &str, desc: &str, vt: &[&str], et: &[&str]) -> GraphType {
        GraphType::new(
            name.to_string(),
            desc.to_string(),
            vt.iter().map(|s| s.to_string()).collect(),
            et.iter().map(|s| s.to_string()).collect(),
        )
    }

    #[test]
    fn get_name_and_description() {
        let gt = make_gt("Call Graph", "A call graph", &[], &[]);
        assert_eq!(gt.get_name(), "Call Graph");
        assert_eq!(gt.get_description(), "A call graph");
    }

    #[test]
    fn get_vertex_and_edge_types_preserve_order() {
        let gt = make_gt("G", "d", &["A", "B", "C"], &["X", "Y"]);
        assert_eq!(gt.get_vertex_types(), vec!["A", "B", "C"]);
        assert_eq!(gt.get_edge_types(), vec!["X", "Y"]);
    }

    #[test]
    fn duplicates_are_removed_preserving_first_occurrence() {
        let gt = make_gt("G", "d", &["A", "B", "A", "C"], &["X", "X", "Y"]);
        assert_eq!(gt.get_vertex_types(), vec!["A", "B", "C"]);
        assert_eq!(gt.get_edge_types(), vec!["X", "Y"]);
    }

    #[test]
    fn contains_vertex_type() {
        let gt = make_gt("G", "d", &["Foo", "Bar"], &[]);
        assert!(gt.contains_vertex_type("Foo"));
        assert!(gt.contains_vertex_type("Bar"));
        assert!(!gt.contains_vertex_type("Baz"));
    }

    #[test]
    fn contains_edge_type() {
        let gt = make_gt("G", "d", &[], &["Calls", "Returns"]);
        assert!(gt.contains_edge_type("Calls"));
        assert!(gt.contains_edge_type("Returns"));
        assert!(!gt.contains_edge_type("Unknown"));
    }

    #[test]
    fn get_options_name() {
        let gt = make_gt("Call Graph", "d", &[], &[]);
        assert_eq!(gt.get_options_name(), "Call Graph Graph Type");
    }

    #[test]
    fn equality_requires_all_fields() {
        let a = make_gt("G", "d", &["V1"], &["E1"]);
        let b = make_gt("G", "d", &["V1"], &["E1"]);
        let c = make_gt("H", "d", &["V1"], &["E1"]);
        let d = make_gt("G", "x", &["V1"], &["E1"]);
        let e = make_gt("G", "d", &["V2"], &["E1"]);
        let f = make_gt("G", "d", &["V1"], &["E2"]);
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, d);
        assert_ne!(a, e);
        assert_ne!(a, f);
    }

    #[test]
    fn vertex_order_matters_for_equality() {
        let a = make_gt("G", "d", &["A", "B"], &[]);
        let b = make_gt("G", "d", &["B", "A"], &[]);
        assert_ne!(a, b);
    }

    #[test]
    fn empty_vertex_and_edge_types() {
        let gt = make_gt("G", "d", &[], &[]);
        assert_eq!(gt.get_vertex_types(), Vec::<String>::new());
        assert_eq!(gt.get_edge_types(), Vec::<String>::new());
        assert!(!gt.contains_vertex_type("anything"));
        assert!(!gt.contains_edge_type("anything"));
    }
}

use super::GraphType;

/// Builder class for constructing new `GraphType`s.
pub struct GraphTypeBuilder {
    name: String,
    description: String,
    vertex_types: Vec<String>,
    edge_types: Vec<String>,
}

impl GraphTypeBuilder {
    /// Creates a new builder with the given name.
    ///
    /// The description is initially set to the same value as the name.
    pub fn new(name: String) -> Self {
        let description = name.clone();
        Self {
            name,
            description,
            vertex_types: Vec::new(),
            edge_types: Vec::new(),
        }
    }

    /// Sets the description for the `GraphType`.
    ///
    /// Returns `self` to allow method chaining.
    pub fn description(mut self, text: String) -> Self {
        self.description = text;
        self
    }

    /// Defines a new vertex type.
    ///
    /// Returns `self` to allow method chaining.
    pub fn vertex_type(mut self, vertex_type: String) -> Self {
        self.vertex_types.push(vertex_type);
        self
    }

    /// Defines a new edge type.
    ///
    /// Returns `self` to allow method chaining.
    pub fn edge_type(mut self, edge_type: String) -> Self {
        self.edge_types.push(edge_type);
        self
    }

    /// Builds and returns a new `GraphType`.
    pub fn build(self) -> GraphType {
        GraphType::new(self.name, self.description, self.vertex_types, self.edge_types)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_with_name_only() {
        let gt = GraphTypeBuilder::new("TestGraph".to_string()).build();
        assert_eq!(gt.get_name(), "TestGraph");
        assert_eq!(gt.get_description(), "TestGraph");
        assert_eq!(gt.get_vertex_types(), Vec::<String>::new());
        assert_eq!(gt.get_edge_types(), Vec::<String>::new());
    }

    #[test]
    fn builder_with_description() {
        let gt = GraphTypeBuilder::new("CallGraph".to_string())
            .description("A graph showing function calls".to_string())
            .build();
        assert_eq!(gt.get_name(), "CallGraph");
        assert_eq!(gt.get_description(), "A graph showing function calls");
    }

    #[test]
    fn builder_with_single_vertex_type() {
        let gt = GraphTypeBuilder::new("Graph".to_string())
            .vertex_type("Function".to_string())
            .build();
        assert_eq!(gt.get_vertex_types(), vec!["Function"]);
        assert!(gt.contains_vertex_type("Function"));
    }

    #[test]
    fn builder_with_multiple_vertex_types() {
        let gt = GraphTypeBuilder::new("Graph".to_string())
            .vertex_type("Function".to_string())
            .vertex_type("Variable".to_string())
            .vertex_type("Block".to_string())
            .build();
        assert_eq!(
            gt.get_vertex_types(),
            vec!["Function", "Variable", "Block"]
        );
    }

    #[test]
    fn builder_with_single_edge_type() {
        let gt = GraphTypeBuilder::new("Graph".to_string())
            .edge_type("Calls".to_string())
            .build();
        assert_eq!(gt.get_edge_types(), vec!["Calls"]);
        assert!(gt.contains_edge_type("Calls"));
    }

    #[test]
    fn builder_with_multiple_edge_types() {
        let gt = GraphTypeBuilder::new("Graph".to_string())
            .edge_type("Calls".to_string())
            .edge_type("References".to_string())
            .build();
        assert_eq!(gt.get_edge_types(), vec!["Calls", "References"]);
    }

    #[test]
    fn builder_with_all_fields() {
        let gt = GraphTypeBuilder::new("CallGraph".to_string())
            .description("Complete call graph".to_string())
            .vertex_type("Function".to_string())
            .vertex_type("Module".to_string())
            .edge_type("Calls".to_string())
            .edge_type("Returns".to_string())
            .build();
        assert_eq!(gt.get_name(), "CallGraph");
        assert_eq!(gt.get_description(), "Complete call graph");
        assert_eq!(gt.get_vertex_types(), vec!["Function", "Module"]);
        assert_eq!(gt.get_edge_types(), vec!["Calls", "Returns"]);
    }

    #[test]
    fn builder_chaining() {
        let builder = GraphTypeBuilder::new("Graph".to_string());
        let gt = builder
            .description("Description".to_string())
            .vertex_type("V1".to_string())
            .vertex_type("V2".to_string())
            .edge_type("E1".to_string())
            .build();
        assert_eq!(gt.get_vertex_types(), vec!["V1", "V2"]);
        assert_eq!(gt.get_edge_types(), vec!["E1"]);
    }

    #[test]
    fn builder_with_duplicate_vertex_types() {
        let gt = GraphTypeBuilder::new("Graph".to_string())
            .vertex_type("Func".to_string())
            .vertex_type("Func".to_string())
            .vertex_type("Block".to_string())
            .build();
        assert_eq!(gt.get_vertex_types(), vec!["Func", "Block"]);
    }

    #[test]
    fn builder_with_duplicate_edge_types() {
        let gt = GraphTypeBuilder::new("Graph".to_string())
            .edge_type("Call".to_string())
            .edge_type("Call".to_string())
            .build();
        assert_eq!(gt.get_edge_types(), vec!["Call"]);
    }
}

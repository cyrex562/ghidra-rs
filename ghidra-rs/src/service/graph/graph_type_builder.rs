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
    fn test_name() {
        let graph_type = GraphTypeBuilder::new("Test".to_string()).build();
        assert_eq!("Test", graph_type.get_name());
    }

    #[test]
    fn test_description() {
        let graph_type = GraphTypeBuilder::new("Test".to_string())
            .description("abc".to_string())
            .build();
        assert_eq!("abc", graph_type.get_description());
    }

    #[test]
    fn test_no_description_uses_name() {
        let graph_type = GraphTypeBuilder::new("Test".to_string()).build();
        assert_eq!("Test", graph_type.get_description());
    }

    #[test]
    fn test_vertex_type() {
        let graph_type = GraphTypeBuilder::new("Test".to_string())
            .vertex_type("V1".to_string())
            .vertex_type("V2".to_string())
            .build();

        let vertex_types = graph_type.get_vertex_types();
        assert_eq!(2, vertex_types.len());
        assert_eq!("V1", vertex_types.get(0).unwrap());
        assert_eq!("V2", vertex_types.get(1).unwrap());
    }

    #[test]
    fn test_edge_type() {
        let graph_type = GraphTypeBuilder::new("Test".to_string())
            .edge_type("E1".to_string())
            .edge_type("E2".to_string())
            .build();

        let edge_types = graph_type.get_edge_types();
        assert_eq!(2, edge_types.len());
        assert_eq!("E1", edge_types.get(0).unwrap());
        assert_eq!("E2", edge_types.get(1).unwrap());
    }
}

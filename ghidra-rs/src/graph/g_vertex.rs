/// A vertex in a (usually directed) graph.
pub trait GVertex {}

#[cfg(test)]
mod tests {
    use super::*;

    struct SimpleVertex {
        id: u32,
    }

    impl GVertex for SimpleVertex {}

    struct StringVertex(String);

    impl GVertex for StringVertex {}

    #[test]
    fn test_simple_vertex_implementation() {
        let vertex = SimpleVertex { id: 1u32 };
        let _: &dyn GVertex = &vertex;
    }

    #[test]
    fn test_string_vertex_implementation() {
        let vertex = StringVertex("test".to_string());
        let _: &dyn GVertex = &vertex;
    }

    #[test]
    fn test_multiple_vertex_types() {
        let v1 = SimpleVertex { id: 1 };
        let v2 = StringVertex("node".to_string());

        let _vertices: Vec<Box<dyn GVertex>> =
            vec![Box::new(v1), Box::new(v2)];
    }

    #[test]
    fn test_vertex_in_collection() {
        let vertices: Vec<SimpleVertex> = vec![
            SimpleVertex { id: 1 },
            SimpleVertex { id: 2 },
            SimpleVertex { id: 3 },
        ];

        for vertex in vertices {
            let _: &dyn GVertex = &vertex;
        }
    }
}

use std::io;
use std::path::Path;

use crate::util::classfinder::ExtensionPoint;

use super::AttributedGraph;

/// Interface for exporting `AttributedGraph`s.
///
/// Implementations of this trait are responsible for exporting an `AttributedGraph` to a
/// specified file path. Implementers must decide on a file format and extension.
///
/// Port of `ghidra.service.graph.AttributedGraphExporter`.
pub trait AttributedGraphExporter: ExtensionPoint {
    /// Exports the given graph to the specified file.
    ///
    /// # Arguments
    ///
    /// * `graph` - The `AttributedGraph` to export
    /// * `path` - The file path to export to
    ///
    /// # Errors
    ///
    /// Returns an `io::Error` if there is an error writing to the file or if the export fails.
    fn export_graph(&self, graph: &AttributedGraph, path: &Path) -> io::Result<()>;

    /// Returns the suggested file extension to use for this exporter.
    ///
    /// This should typically be a string like `"dot"` or `"graphml"` without the leading dot.
    fn get_file_extension(&self) -> String;

    /// Returns the name of this exporter.
    fn get_name(&self) -> String;

    /// Returns a description of this exporter.
    fn get_description(&self) -> String;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockExporter {
        name: String,
        extension: String,
        description: String,
    }

    impl ExtensionPoint for MockExporter {}

    impl AttributedGraphExporter for MockExporter {
        fn export_graph(&self, _graph: &AttributedGraph, _path: &Path) -> io::Result<()> {
            Ok(())
        }

        fn get_file_extension(&self) -> String {
            self.extension.clone()
        }

        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn get_description(&self) -> String {
            self.description.clone()
        }
    }

    #[test]
    fn trait_is_implementable() {
        let exporter = MockExporter {
            name: "Test Exporter".to_string(),
            extension: "txt".to_string(),
            description: "A test exporter".to_string(),
        };

        assert_eq!(exporter.get_name(), "Test Exporter");
        assert_eq!(exporter.get_file_extension(), "txt");
        assert_eq!(exporter.get_description(), "A test exporter");
    }

    #[test]
    fn export_graph_can_be_called() {
        let exporter = MockExporter {
            name: "Test".to_string(),
            extension: "txt".to_string(),
            description: "Test".to_string(),
        };
        let graph_type =
            crate::service::graph::GraphType::new("test".to_string(), "test".to_string(), vec![], vec![]);
        let graph = AttributedGraph::new("test", graph_type);
        let path = Path::new("/tmp/test.txt");

        let result = exporter.export_graph(&graph, path);
        assert!(result.is_ok());
    }

    #[test]
    fn trait_is_object_safe() {
        let exporter: Box<dyn AttributedGraphExporter> = Box::new(MockExporter {
            name: "Test".to_string(),
            extension: "txt".to_string(),
            description: "Test".to_string(),
        });
        let _ = exporter.get_name();
    }
}

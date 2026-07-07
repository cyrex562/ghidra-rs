/// Allows components used as a column in the byteviewer to specify a more descriptive
/// name to use for the header above the format's column.
pub trait ByteViewerComponentNamer {
    /// Returns the name to display in the byte viewer column header.
    fn get_byte_viewer_component_name(&self) -> String;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct NamedComponent {
        name: String,
    }

    impl ByteViewerComponentNamer for NamedComponent {
        fn get_byte_viewer_component_name(&self) -> String {
            self.name.clone()
        }
    }

    #[test]
    fn test_returns_configured_name() {
        let c = NamedComponent { name: "Hex".to_string() };
        assert_eq!(c.get_byte_viewer_component_name(), "Hex");
    }

    #[test]
    fn test_returns_empty_name() {
        let c = NamedComponent { name: String::new() };
        assert_eq!(c.get_byte_viewer_component_name(), "");
    }

    #[test]
    fn test_returns_multiword_name() {
        let c = NamedComponent { name: "Octal Dump".to_string() };
        assert_eq!(c.get_byte_viewer_component_name(), "Octal Dump");
    }
}

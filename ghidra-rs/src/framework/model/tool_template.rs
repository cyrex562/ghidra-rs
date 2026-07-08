use crate::framework::seam_stubs::{ImageIcon, JdomElement, PluginTool, Project, ToolIconURL};

/// XML element name used when a tool template is written to/read from XML.
///
/// Port of `ToolTemplate.TOOL_XML_NAME`.
pub const TOOL_XML_NAME: &str = "TOOL";

/// XML attribute name for a tool template's tool name.
///
/// Port of `ToolTemplate.TOOL_NAME_XML_NAME`.
pub const TOOL_NAME_XML_NAME: &str = "TOOL_NAME";

/// XML attribute name for a tool template's instance name.
///
/// Port of `ToolTemplate.TOOL_INSTANCE_NAME_XML_NAME`.
pub const TOOL_INSTANCE_NAME_XML_NAME: &str = "INSTANCE_NAME";

/// Configuration of a tool that knows how to create tools.
///
/// Port of `ghidra.framework.model.ToolTemplate`.
///
/// `Class<?>[] getSupportedDataTypes()` is represented as `Vec<String>` of fully-qualified type
/// names rather than `Class` objects or trait objects, matching how this crate already represents
/// `Class<?>` annotation elements elsewhere (see
/// [`PluginInfo`](crate::framework::plugintool::PluginInfo)).
pub trait ToolTemplate {
    /// Get the name for the tool.
    fn get_name(&self) -> String;

    /// Returns the path from whence this tool template came; may be `None` if the tool was not
    /// loaded from the filesystem.
    fn get_path(&self) -> Option<String>;

    /// Set the name for the tool template.
    fn set_name(&mut self, name: &str);

    /// Get the icon URL for this tool template.
    fn get_icon_url(&self) -> Box<dyn ToolIconURL>;

    /// Get the icon for this tool template. This is equivalent to calling
    /// `get_icon_url().get_icon()` in the Java original.
    fn get_icon(&self) -> Box<dyn ImageIcon>;

    /// Get the classes of the data types that this tool supports, i.e., what data types can be
    /// dropped onto this tool.
    fn get_supported_data_types(&self) -> Vec<String>;

    /// Save this object to an XML element.
    fn save_to_xml(&self) -> Box<dyn JdomElement>;

    /// Restore this object from a saved XML element.
    fn restore_from_xml(&mut self, root: &dyn JdomElement);

    /// Creates a tool like only this template knows how.
    ///
    /// # Arguments
    /// * `project` - the project in which the tool will be living.
    fn create_tool(&self, project: &dyn Project) -> Box<dyn PluginTool>;

    /// Returns the XML element that represents the tool part of the overall XML hierarchy.
    fn get_tool_element(&self) -> Box<dyn JdomElement>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockToolIconURL;
    impl ToolIconURL for MockToolIconURL {}

    struct MockImageIcon;
    impl ImageIcon for MockImageIcon {}

    struct MockJdomElement;
    impl JdomElement for MockJdomElement {}

    struct MockPluginTool;
    impl PluginTool for MockPluginTool {}

    struct MockProject;
    impl Project for MockProject {}

    struct SimpleToolTemplate {
        name: String,
        path: Option<String>,
    }

    impl ToolTemplate for SimpleToolTemplate {
        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn get_path(&self) -> Option<String> {
            self.path.clone()
        }

        fn set_name(&mut self, name: &str) {
            self.name = name.to_string();
        }

        fn get_icon_url(&self) -> Box<dyn ToolIconURL> {
            Box::new(MockToolIconURL)
        }

        fn get_icon(&self) -> Box<dyn ImageIcon> {
            Box::new(MockImageIcon)
        }

        fn get_supported_data_types(&self) -> Vec<String> {
            Vec::new()
        }

        fn save_to_xml(&self) -> Box<dyn JdomElement> {
            Box::new(MockJdomElement)
        }

        fn restore_from_xml(&mut self, _root: &dyn JdomElement) {}

        fn create_tool(&self, _project: &dyn Project) -> Box<dyn PluginTool> {
            Box::new(MockPluginTool)
        }

        fn get_tool_element(&self) -> Box<dyn JdomElement> {
            Box::new(MockJdomElement)
        }
    }

    #[test]
    fn usable_as_trait_object() {
        let mut template =
            SimpleToolTemplate { name: "CodeBrowser".to_string(), path: Some("/tools/cb".to_string()) };
        let dyn_template: &mut dyn ToolTemplate = &mut template;

        assert_eq!(dyn_template.get_name(), "CodeBrowser");
        assert_eq!(dyn_template.get_path(), Some("/tools/cb".to_string()));

        dyn_template.set_name("Renamed");
        assert_eq!(dyn_template.get_name(), "Renamed");

        assert!(dyn_template.get_supported_data_types().is_empty());

        let project = MockProject;
        let _tool = dyn_template.create_tool(&project);
        dyn_template.restore_from_xml(&MockJdomElement);
        let _saved = dyn_template.save_to_xml();
        let _element = dyn_template.get_tool_element();
        let _icon_url = dyn_template.get_icon_url();
        let _icon = dyn_template.get_icon();
    }

    #[test]
    fn path_is_none_when_not_loaded_from_filesystem() {
        let template = SimpleToolTemplate { name: "Unsaved".to_string(), path: None };
        assert_eq!(template.get_path(), None);
    }
}

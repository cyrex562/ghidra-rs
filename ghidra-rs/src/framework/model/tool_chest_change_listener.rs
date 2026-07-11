use crate::framework::model::{ToolSet, ToolTemplate};

/// Listener that is notified when a ToolTemplate is added or removed from a
/// project.
///
/// NOTE: notification callbacks are not guaranteed to occur on the main thread.
pub trait ToolChestChangeListener {
    /// ToolTemplate was added to the project toolchest.
    fn tool_template_added(&mut self, tool: &dyn ToolTemplate);

    /// ToolSet was added to the project toolchest.
    fn tool_set_added(&mut self, toolset: &dyn ToolSet);

    /// Tool was removed from the project toolchest.
    fn tool_removed(&mut self, tool_name: &str);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockToolTemplate {
        name: String,
    }

    impl ToolTemplate for MockToolTemplate {
        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn get_path(&self) -> Option<String> {
            None
        }

        fn set_name(&mut self, name: &str) {
            self.name = name.to_string();
        }

        fn get_icon_url(&self) -> Box<dyn crate::framework::seam_stubs::ToolIconURL> {
            struct Stub;
            impl crate::framework::seam_stubs::ToolIconURL for Stub {}
            Box::new(Stub)
        }

        fn get_icon(&self) -> Box<dyn crate::framework::seam_stubs::ImageIcon> {
            struct Stub;
            impl crate::framework::seam_stubs::ImageIcon for Stub {}
            Box::new(Stub)
        }

        fn get_supported_data_types(&self) -> Vec<String> {
            Vec::new()
        }

        fn save_to_xml(&self) -> Box<dyn crate::framework::seam_stubs::JdomElement> {
            struct Stub;
            impl crate::framework::seam_stubs::JdomElement for Stub {}
            Box::new(Stub)
        }

        fn restore_from_xml(&mut self, _root: &dyn crate::framework::seam_stubs::JdomElement) {}

        fn create_tool(&self, _project: &dyn crate::framework::model::Project) -> Box<dyn crate::framework::seam_stubs::PluginTool> {
            struct Stub;
            impl crate::framework::seam_stubs::PluginTool for Stub {}
            Box::new(Stub)
        }

        fn get_tool_element(&self) -> Box<dyn crate::framework::seam_stubs::JdomElement> {
            struct Stub;
            impl crate::framework::seam_stubs::JdomElement for Stub {}
            Box::new(Stub)
        }
    }

    struct MockToolSet {
        name: String,
        description: String,
    }

    impl ToolSet for MockToolSet {
        fn name(&self) -> &str {
            &self.name
        }

        fn set_name(&mut self, name: &str) {
            self.name = name.to_string();
        }

        fn description(&self) -> &str {
            &self.description
        }
    }

    struct RecordingListener {
        templates_added: Vec<String>,
        toolsets_added: Vec<String>,
        tools_removed: Vec<String>,
    }

    impl RecordingListener {
        fn new() -> Self {
            RecordingListener {
                templates_added: Vec::new(),
                toolsets_added: Vec::new(),
                tools_removed: Vec::new(),
            }
        }
    }

    impl ToolChestChangeListener for RecordingListener {
        fn tool_template_added(&mut self, tool: &dyn ToolTemplate) {
            self.templates_added.push(tool.get_name());
        }

        fn tool_set_added(&mut self, toolset: &dyn ToolSet) {
            self.toolsets_added.push(toolset.name().to_string());
        }

        fn tool_removed(&mut self, tool_name: &str) {
            self.tools_removed.push(tool_name.to_string());
        }
    }

    #[test]
    fn test_tool_template_added() {
        let mut listener = RecordingListener::new();
        let tool = MockToolTemplate { name: "CodeBrowser".to_string() };
        listener.tool_template_added(&tool);
        assert_eq!(listener.templates_added, vec!["CodeBrowser"]);
        assert!(listener.toolsets_added.is_empty());
        assert!(listener.tools_removed.is_empty());
    }

    #[test]
    fn test_tool_set_added() {
        let mut listener = RecordingListener::new();
        let toolset = MockToolSet {
            name: "MyToolSet".to_string(),
            description: "A set of tools".to_string(),
        };
        listener.tool_set_added(&toolset);
        assert!(listener.templates_added.is_empty());
        assert_eq!(listener.toolsets_added, vec!["MyToolSet"]);
        assert!(listener.tools_removed.is_empty());
    }

    #[test]
    fn test_tool_removed() {
        let mut listener = RecordingListener::new();
        listener.tool_removed("CodeBrowser");
        assert!(listener.templates_added.is_empty());
        assert!(listener.toolsets_added.is_empty());
        assert_eq!(listener.tools_removed, vec!["CodeBrowser"]);
    }

    #[test]
    fn test_all_events_together() {
        let mut listener = RecordingListener::new();
        let tool1 = MockToolTemplate { name: "Tool1".to_string() };
        let tool2 = MockToolTemplate { name: "Tool2".to_string() };
        let toolset = MockToolSet {
            name: "MySet".to_string(),
            description: "Description".to_string(),
        };

        listener.tool_template_added(&tool1);
        listener.tool_set_added(&toolset);
        listener.tool_template_added(&tool2);
        listener.tool_removed("Tool1");

        assert_eq!(listener.templates_added, vec!["Tool1", "Tool2"]);
        assert_eq!(listener.toolsets_added, vec!["MySet"]);
        assert_eq!(listener.tools_removed, vec!["Tool1"]);
    }

    #[test]
    fn test_multiple_removals() {
        let mut listener = RecordingListener::new();
        listener.tool_removed("Tool1");
        listener.tool_removed("Tool2");
        listener.tool_removed("Tool3");
        assert_eq!(listener.tools_removed, vec!["Tool1", "Tool2", "Tool3"]);
    }
}

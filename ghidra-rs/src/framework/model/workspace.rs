use crate::framework::model::ToolTemplate;
use crate::framework::seam_stubs::PluginTool;
use crate::util::exception::DuplicateNameException;

/// Defines methods for accessing a workspace; a workspace is simply a group of running tools and
/// their templates.
///
/// Port of `ghidra.framework.model.Workspace`.
pub trait Workspace {
    /// Get the workspace name.
    fn get_name(&self) -> String;

    /// Get the running tools in the workspace.
    ///
    /// Returns an empty vector if there are no tools in the workspace.
    fn get_tools(&self) -> Vec<Box<dyn PluginTool>>;

    /// Launch an empty tool.
    ///
    /// Returns the empty tool that is launched.
    fn create_tool(&mut self) -> Box<dyn PluginTool>;

    /// Run the tool specified by the tool template object.
    ///
    /// Returns the launched tool that is now running.
    fn run_tool(&mut self, template: &dyn ToolTemplate) -> Box<dyn PluginTool>;

    /// Rename this workspace.
    ///
    /// # Errors
    /// Returns `DuplicateNameException` if `new_name` is already the name of a workspace.
    fn set_name(&mut self, new_name: &str) -> Result<(), DuplicateNameException>;

    /// Set this workspace to be the active workspace, i.e., all tools become visible. The
    /// currently active workspace becomes inactive, and this workspace becomes active.
    fn set_active(&mut self);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockPluginTool;
    impl PluginTool for MockPluginTool {}

    struct MockToolTemplate;
    impl ToolTemplate for MockToolTemplate {
        fn get_name(&self) -> String {
            "MockTool".to_string()
        }

        fn get_path(&self) -> Option<String> {
            None
        }

        fn set_name(&mut self, _name: &str) {}

        fn get_icon_url(&self) -> Box<dyn crate::framework::seam_stubs::ToolIconURL> {
            struct MockToolIconURL;
            impl crate::framework::seam_stubs::ToolIconURL for MockToolIconURL {}
            Box::new(MockToolIconURL)
        }

        fn get_icon(&self) -> Box<dyn crate::framework::seam_stubs::ImageIcon> {
            struct MockImageIcon;
            impl crate::framework::seam_stubs::ImageIcon for MockImageIcon {}
            Box::new(MockImageIcon)
        }

        fn get_supported_data_types(&self) -> Vec<String> {
            Vec::new()
        }

        fn save_to_xml(&self) -> Box<dyn crate::framework::seam_stubs::JdomElement> {
            struct MockJdomElement;
            impl crate::framework::seam_stubs::JdomElement for MockJdomElement {}
            Box::new(MockJdomElement)
        }

        fn restore_from_xml(&mut self, _root: &dyn crate::framework::seam_stubs::JdomElement) {}

        fn create_tool(
            &self,
            _project: &dyn crate::framework::seam_stubs::Project,
        ) -> Box<dyn PluginTool> {
            Box::new(MockPluginTool)
        }

        fn get_tool_element(&self) -> Box<dyn crate::framework::seam_stubs::JdomElement> {
            struct MockJdomElement;
            impl crate::framework::seam_stubs::JdomElement for MockJdomElement {}
            Box::new(MockJdomElement)
        }
    }

    struct SimpleWorkspace {
        name: String,
        active: bool,
    }

    impl Workspace for SimpleWorkspace {
        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn get_tools(&self) -> Vec<Box<dyn PluginTool>> {
            Vec::new()
        }

        fn create_tool(&mut self) -> Box<dyn PluginTool> {
            Box::new(MockPluginTool)
        }

        fn run_tool(&mut self, _template: &dyn ToolTemplate) -> Box<dyn PluginTool> {
            Box::new(MockPluginTool)
        }

        fn set_name(&mut self, new_name: &str) -> Result<(), DuplicateNameException> {
            if new_name == self.name {
                return Err(DuplicateNameException::new());
            }
            self.name = new_name.to_string();
            Ok(())
        }

        fn set_active(&mut self) {
            self.active = true;
        }
    }

    #[test]
    fn usable_as_trait_object() {
        let mut workspace: Box<dyn Workspace> =
            Box::new(SimpleWorkspace { name: "Workspace".to_string(), active: false });

        assert_eq!(workspace.get_name(), "Workspace");
        assert!(workspace.get_tools().is_empty());

        let _tool = workspace.create_tool();
        let template = MockToolTemplate;
        let _tool = workspace.run_tool(&template);

        workspace.set_active();

        assert!(workspace.set_name("Workspace").is_err());
        assert!(workspace.set_name("Renamed").is_ok());
        assert_eq!(workspace.get_name(), "Renamed");
    }
}

use crate::framework::model::ToolServices;

/// A simplified interface for stand-alone applications.
///
/// Mirrors `ghidra.framework.plugintool.GenericStandAloneApplication`.
///
/// Provides a minimal contract for stand-alone applications that need to interact with
/// the framework's tool services and handle application exit.
pub trait GenericStandAloneApplication {
    /// Returns the tool services available to this application.
    fn get_tool_services(&self) -> Box<dyn ToolServices>;

    /// Notifies the application to exit.
    fn exit(&mut self);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::any::TypeId;
    use std::io;
    use std::path::PathBuf;

    struct MockPluginTool;
    struct MockToolChest;
    struct MockToolAssociationInfo;
    struct MockDomainFile;
    struct MockToolTemplate;

    impl crate::framework::seam_stubs::PluginTool for MockPluginTool {}
    impl crate::framework::seam_stubs::ToolChest for MockToolChest {}
    impl crate::framework::seam_stubs::ToolAssociationInfo for MockToolAssociationInfo {}
    impl crate::framework::model::DomainFile for MockDomainFile {
        fn get_shared_project_url(&self) -> Option<&str> {
            None
        }
    }
    impl crate::framework::model::ToolTemplate for MockToolTemplate {}

    struct MockToolServices;

    impl ToolServices for MockToolServices {
        fn close_tool(&mut self, _tool: &dyn crate::framework::seam_stubs::PluginTool) {}

        fn save_tool(&mut self, _tool: &dyn crate::framework::seam_stubs::PluginTool) {}

        fn export_tool(&self, _tool: &dyn crate::framework::model::ToolTemplate) -> io::Result<PathBuf> {
            Ok(PathBuf::from("/tmp/tool.tcd"))
        }

        fn get_tool_chest(&self) -> Box<dyn crate::framework::seam_stubs::ToolChest> {
            Box::new(MockToolChest)
        }

        fn get_default_tool_template_for_file(
            &self,
            _domain_file: &dyn crate::framework::model::DomainFile,
        ) -> Option<Box<dyn crate::framework::model::ToolTemplate>> {
            None
        }

        fn get_default_tool_template_for_content_type(
            &self,
            _content_type: &str,
        ) -> Option<Box<dyn crate::framework::model::ToolTemplate>> {
            None
        }

        fn get_compatible_tools(&self, _domain_class: TypeId) -> Vec<Box<dyn crate::framework::model::ToolTemplate>> {
            Vec::new()
        }

        fn get_content_type_tool_associations(&self) -> Vec<Box<dyn crate::framework::seam_stubs::ToolAssociationInfo>> {
            vec![Box::new(MockToolAssociationInfo)]
        }

        fn set_content_type_tool_associations(&mut self, _infos: Vec<Box<dyn crate::framework::seam_stubs::ToolAssociationInfo>>) {}

        fn launch_default_tool(
            &mut self,
            _domain_files: &[&dyn crate::framework::model::DomainFile],
        ) -> Option<Box<dyn crate::framework::seam_stubs::PluginTool>> {
            None
        }

        fn launch_tool(
            &mut self,
            _tool_name: &str,
            _domain_files: &[&dyn crate::framework::model::DomainFile],
        ) -> Option<Box<dyn crate::framework::seam_stubs::PluginTool>> {
            None
        }

        fn launch_default_tool_with_url(&mut self, _ghidra_url: &str) -> Option<Box<dyn crate::framework::seam_stubs::PluginTool>> {
            None
        }

        fn launch_tool_with_url(
            &mut self,
            _tool_name: &str,
            _ghidra_url: &str,
        ) -> Option<Box<dyn crate::framework::seam_stubs::PluginTool>> {
            None
        }

        fn get_running_tools(&self) -> Vec<Box<dyn crate::framework::seam_stubs::PluginTool>> {
            vec![Box::new(MockPluginTool)]
        }

        fn can_auto_save(&self, _tool: &dyn crate::framework::seam_stubs::PluginTool) -> bool {
            true
        }
    }

    struct TestApplication {
        exited: bool,
    }

    impl GenericStandAloneApplication for TestApplication {
        fn get_tool_services(&self) -> Box<dyn ToolServices> {
            Box::new(MockToolServices)
        }

        fn exit(&mut self) {
            self.exited = true;
        }
    }

    #[test]
    fn can_implement_generic_stand_alone_application() {
        let mut app = TestApplication { exited: false };
        assert!(!app.exited);

        app.exit();
        assert!(app.exited);
    }

    #[test]
    fn can_get_tool_services() {
        let app = TestApplication { exited: false };
        let _services = app.get_tool_services();
    }

    #[test]
    fn trait_is_object_safe() {
        let app = TestApplication { exited: false };
        let _: &dyn GenericStandAloneApplication = &app;
    }
}

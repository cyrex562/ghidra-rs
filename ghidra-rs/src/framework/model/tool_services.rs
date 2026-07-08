use std::any::TypeId;
use std::io;
use std::path::PathBuf;

use crate::framework::model::{DomainFile, ToolTemplate};
use crate::framework::seam_stubs::{PluginTool, ToolAssociationInfo, ToolChest};

/// The default tool name for Ghidra.
///
/// Port of `ToolServices.DEFAULT_TOOLNAME`.
pub const DEFAULT_TOOLNAME: &str = "DefaultTool";

/// Services that the Tool uses.
///
/// Port of `ghidra.framework.model.ToolServices`.
///
/// `java.net.URL` parameters are represented as `&str`, matching how this crate already
/// represents Ghidra URLs elsewhere (see
/// [`DomainFile::get_shared_project_url`](crate::framework::model::DomainFile::get_shared_project_url)).
pub trait ToolServices {
    /// Notify the framework that the tool is closing.
    fn close_tool(&mut self, tool: &dyn PluginTool);

    /// Saves the tool's configuration in the standard tool location.
    fn save_tool(&mut self, tool: &dyn PluginTool);

    /// Save the tool to the given location on the local file system.
    ///
    /// Returns the file to which the tool was saved.
    fn export_tool(&self, tool: &dyn ToolTemplate) -> io::Result<PathBuf>;

    /// Get the tool chest for the project.
    fn get_tool_chest(&self) -> Box<dyn ToolChest>;

    /// Returns the default/preferred tool template which should be used to open the specified
    /// domain file, whether defined by the user or the system default. Returns `None` if none
    /// found.
    fn get_default_tool_template_for_file(
        &self,
        domain_file: &dyn DomainFile,
    ) -> Option<Box<dyn ToolTemplate>>;

    /// Returns the default/preferred tool template which should be used to open the specified
    /// domain file content type, whether defined by the user or the system default. Returns
    /// `None` if none found.
    fn get_default_tool_template_for_content_type(
        &self,
        content_type: &str,
    ) -> Option<Box<dyn ToolTemplate>>;

    /// Returns the tools that can open the given domain file class.
    fn get_compatible_tools(&self, domain_class: TypeId) -> Vec<Box<dyn ToolTemplate>>;

    /// Returns the associations, which describe content types and the tools used to open them,
    /// for all content types known to the system.
    ///
    /// See [`set_content_type_tool_associations`](ToolServices::set_content_type_tool_associations).
    fn get_content_type_tool_associations(&self) -> Vec<Box<dyn ToolAssociationInfo>>;

    /// Sets the associations, which describe content types and the tools used to open them, for
    /// the system.
    ///
    /// See [`get_content_type_tool_associations`](ToolServices::get_content_type_tool_associations).
    fn set_content_type_tool_associations(&mut self, infos: Vec<Box<dyn ToolAssociationInfo>>);

    /// Launch the default tool and open the specified domain files. NOTE: running tool reuse is
    /// implementation dependent.
    ///
    /// A `None` or empty list of `domain_files` results in an immediate return of `None`.
    ///
    /// Returns the launched tool, or `None` if a suitable default tool for the file content type
    /// was not found or failed to launch.
    fn launch_default_tool(&mut self, domain_files: &[&dyn DomainFile]) -> Option<Box<dyn PluginTool>>;

    /// Launch the tool with the given name and open the specified domain files. Only those
    /// domain files with a content type supported by the specified tool will be opened. NOTE:
    /// running tool reuse is implementation dependent.
    ///
    /// Returns the resulting tool, or `None` if the specified tool was not found or failed to
    /// launch.
    fn launch_tool(
        &mut self,
        tool_name: &str,
        domain_files: &[&dyn DomainFile],
    ) -> Option<Box<dyn PluginTool>>;

    /// Launch the default tool and open the specified Ghidra URL resource. The tool chosen will
    /// be based upon the content type of the specified resource. NOTE: running tool re-use is
    /// implementation dependent.
    ///
    /// Returns the launched tool, or `None` if a failure occurs while accessing the specified
    /// resource or a suitable default tool for the file content type was not found.
    ///
    /// # Panics / errors
    /// Implementations should reject unsupported URL protocols; currently only the `ghidra`
    /// protocol is supported.
    fn launch_default_tool_with_url(&mut self, ghidra_url: &str) -> Option<Box<dyn PluginTool>>;

    /// Launch the tool with the given name and attempt to open the specified Ghidra URL
    /// resource.
    ///
    /// Returns the requested tool, or `None` if the specified tool was not found.
    ///
    /// Implementations should reject unsupported URL protocols; currently only the `ghidra`
    /// protocol is supported.
    fn launch_tool_with_url(
        &mut self,
        tool_name: &str,
        ghidra_url: &str,
    ) -> Option<Box<dyn PluginTool>>;

    /// Return the list of running tools.
    fn get_running_tools(&self) -> Vec<Box<dyn PluginTool>>;

    /// Returns true if this tool should be saved based on the state of other running instances
    /// of the same tool.
    fn can_auto_save(&self, tool: &dyn PluginTool) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockPluginTool;
    impl PluginTool for MockPluginTool {}

    struct MockToolChest;
    impl ToolChest for MockToolChest {}

    struct MockToolAssociationInfo;
    impl ToolAssociationInfo for MockToolAssociationInfo {}

    struct NoopToolServices;

    impl ToolServices for NoopToolServices {
        fn close_tool(&mut self, _tool: &dyn PluginTool) {}

        fn save_tool(&mut self, _tool: &dyn PluginTool) {}

        fn export_tool(&self, _tool: &dyn ToolTemplate) -> io::Result<PathBuf> {
            Ok(PathBuf::from("/tmp/tool.tcd"))
        }

        fn get_tool_chest(&self) -> Box<dyn ToolChest> {
            Box::new(MockToolChest)
        }

        fn get_default_tool_template_for_file(
            &self,
            _domain_file: &dyn DomainFile,
        ) -> Option<Box<dyn ToolTemplate>> {
            None
        }

        fn get_default_tool_template_for_content_type(
            &self,
            _content_type: &str,
        ) -> Option<Box<dyn ToolTemplate>> {
            None
        }

        fn get_compatible_tools(&self, _domain_class: TypeId) -> Vec<Box<dyn ToolTemplate>> {
            Vec::new()
        }

        fn get_content_type_tool_associations(&self) -> Vec<Box<dyn ToolAssociationInfo>> {
            vec![Box::new(MockToolAssociationInfo)]
        }

        fn set_content_type_tool_associations(&mut self, _infos: Vec<Box<dyn ToolAssociationInfo>>) {}

        fn launch_default_tool(
            &mut self,
            _domain_files: &[&dyn DomainFile],
        ) -> Option<Box<dyn PluginTool>> {
            None
        }

        fn launch_tool(
            &mut self,
            _tool_name: &str,
            _domain_files: &[&dyn DomainFile],
        ) -> Option<Box<dyn PluginTool>> {
            None
        }

        fn launch_default_tool_with_url(&mut self, _ghidra_url: &str) -> Option<Box<dyn PluginTool>> {
            None
        }

        fn launch_tool_with_url(
            &mut self,
            _tool_name: &str,
            _ghidra_url: &str,
        ) -> Option<Box<dyn PluginTool>> {
            None
        }

        fn get_running_tools(&self) -> Vec<Box<dyn PluginTool>> {
            vec![Box::new(MockPluginTool)]
        }

        fn can_auto_save(&self, _tool: &dyn PluginTool) -> bool {
            true
        }
    }

    #[test]
    fn noop_tool_services_is_object_safe_and_usable() {
        let mut services: Box<dyn ToolServices> = Box::new(NoopToolServices);
        let tool = MockPluginTool;

        services.close_tool(&tool);
        services.save_tool(&tool);
        assert!(services.can_auto_save(&tool));
        assert_eq!(services.get_running_tools().len(), 1);
        assert_eq!(services.get_content_type_tool_associations().len(), 1);
        assert!(services.launch_default_tool(&[]).is_none());
    }
}

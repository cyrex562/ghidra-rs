use std::any::TypeId;
use std::io;
use std::path::PathBuf;

use crate::framework::client::RepositoryAdapter;
use crate::framework::model::domain_file::DomainFile;
use crate::framework::model::domain_object::DomainObjectConsumer;
use crate::framework::model::project_data::ProjectData;
use crate::framework::model::project_manager::{OpenProjectError, ProjectManager};
use crate::framework::model::project_view_listener::ProjectViewListener;
use crate::framework::model::server_info::ServerInfo;
use crate::framework::model::tool_chest::ToolChest;
use crate::framework::model::tool_chest_change_listener::ToolChestChangeListener;
use crate::framework::model::tool_connection::ToolConnection;
use crate::framework::model::tool_manager::ToolManager;
use crate::framework::model::tool_services::ToolServices;
use crate::framework::model::tool_template::ToolTemplate;
use crate::framework::model::workspace::Workspace;
use crate::framework::seam_stubs::{
    PluginTool, ProjectLocator, RepositoryServerAdapter, SaveState, ToolAssociationInfo,
    ToolChest as StubToolChest, WorkspaceChangeListener,
};
use crate::util::exception::DuplicateNameException;

/// Interface to define methods to manage data and tools for users working on a particular
/// effort. `Project` represents the container object for users, data, and tools to work
/// together.
///
/// Port of `ghidra.framework.model.Project`.
///
/// This trait was promoted from a minimal placeholder (see
/// [`seam_stubs`](crate::framework::seam_stubs)) that declared no methods, so there is nothing to
/// retain as a superset here. Every method is given a default so that existing bare
/// `impl Project for MockProject {}` blocks (scattered across code that only needed an opaque
/// `Project` to pass around) keep compiling unmodified. The defaults describe a non-existent,
/// closed project with nothing open, mirroring the style used for
/// [`ProjectData`](crate::framework::model::ProjectData) and
/// [`DomainFolder`](crate::framework::model::DomainFolder).
///
/// The Java interface extends `Iterable<DomainFile>`, whose default `iterator()` delegates to
/// `getProjectData().iterator()`; [`iter_files`](Self::iter_files) stands in for that so the
/// trait remains object-safe (`dyn Project` cannot itself implement `Iterator`).
///
/// The two `getProjectData` overloads (by [`ProjectLocator`] and by URL) become distinct
/// `_for_locator`/`_for_url` methods since Rust has no method overloading. `java.net.URL`
/// parameters are represented as `&str`, matching how this crate already represents Ghidra URLs
/// elsewhere (see
/// [`DomainFolder::get_shared_project_url`](crate::framework::model::DomainFolder::get_shared_project_url)).
pub trait Project {
    /// Get the name of this project.
    fn get_name(&self) -> String {
        String::new()
    }

    /// Get the project locator for this project.
    fn get_project_locator(&self) -> Box<dyn ProjectLocator> {
        Box::new(FallbackProjectLocator)
    }

    /// Get the project manager of this project.
    fn get_project_manager(&self) -> Box<dyn ProjectManager> {
        Box::new(FallbackProjectManager)
    }

    /// Get the tool manager for this project.
    fn get_tool_manager(&self) -> Box<dyn ToolManager> {
        Box::new(FallbackToolManager)
    }

    /// Get the tool services for this project.
    fn get_tool_services(&self) -> Box<dyn ToolServices> {
        Box::new(FallbackToolServices)
    }

    /// Returns whether the project configuration has changed.
    fn has_changed(&self) -> bool {
        false
    }

    /// Returns whether this project instance has been closed.
    fn is_closed(&self) -> bool {
        false
    }

    /// Get the local tool chest for the user logged in.
    fn get_local_tool_chest(&self) -> Box<dyn ToolChest> {
        Box::new(FallbackToolChest)
    }

    /// Get the repository that this project is associated with.
    ///
    /// Returns `None` if the project is not associated with a remote repository.
    fn get_repository(&self) -> Option<Box<dyn RepositoryAdapter>> {
        None
    }

    /// Add the given project URL to this project's list of project views. The project view
    /// allows users to look at data files from another project. If the URL corresponds to this
    /// project its `ProjectData` will be returned.
    ///
    /// # Arguments
    /// * `project_url` - identifier for the project view (ghidra protocol only)
    /// * `visible` - true if project may be made visible or false if hidden
    ///
    /// # Errors
    /// Returns `Err` if this project is closed, an invalid URL is specified, or failed to
    /// open/connect to the project/repository.
    fn add_project_view(
        &mut self,
        project_url: &str,
        visible: bool,
    ) -> io::Result<Box<dyn ProjectData>> {
        let _ = (project_url, visible);
        Err(io::Error::new(io::ErrorKind::Unsupported, "project views are not supported"))
    }

    /// Remove the project view from this project.
    fn remove_project_view(&mut self, project_url: &str) {
        let _ = project_url;
    }

    /// Get the list of visible project views in this project.
    fn get_project_views(&self) -> Vec<Box<dyn ProjectLocator>> {
        Vec::new()
    }

    /// Close the project.
    fn close(&mut self) {}

    /// Save the project and the list of project views.
    fn save(&mut self) {}

    /// Saves any tools that are associated with the opened project when the project is closed.
    ///
    /// Returns true if the save was not cancelled.
    fn save_session_tools(&mut self) -> bool {
        true
    }

    /// Restore this project's state.
    fn restore(&mut self) {}

    /// Save the given tool template as part of the project.
    fn save_tool_template(&mut self, tag: &str, template: &dyn ToolTemplate) {
        let _ = (tag, template);
    }

    /// Get the tool template with the given tag.
    fn get_tool_template(&self, tag: &str) -> Option<Box<dyn ToolTemplate>> {
        let _ = tag;
        None
    }

    /// Allows the user to store data related to the project. See
    /// [`get_saveable_data`](Self::get_saveable_data) for future retrieval of data.
    fn set_saveable_data(&mut self, key: &str, save_state: Box<dyn SaveState>) {
        let _ = (key, save_state);
    }

    /// Get the user data previously stored to the project. See
    /// [`set_saveable_data`](Self::set_saveable_data).
    fn get_saveable_data(&self, key: &str) -> Option<Box<dyn SaveState>> {
        let _ = key;
        None
    }

    /// Get list of domain files that are open.
    fn get_open_data(&self) -> Vec<Box<dyn DomainFile>> {
        Vec::new()
    }

    /// Get the root domain data folder in the project.
    fn get_project_data(&self) -> Box<dyn ProjectData> {
        Box::new(FallbackProjectData)
    }

    /// Returns the project data for the given project locator. The project locator must be
    /// either the current active project or a currently open project view. The returned view may
    /// not be visible.
    fn get_project_data_for_locator(&self, project_locator: &dyn ProjectLocator) -> Box<dyn ProjectData> {
        let _ = project_locator;
        Box::new(FallbackProjectData)
    }

    /// Returns the project data for the given project URL. The project URL must be either the
    /// current active project or a currently open project view. The returned view may not be
    /// visible. Returns `None` if there is no such project data.
    fn get_project_data_for_url(&self, project_url: &str) -> Option<Box<dyn ProjectData>> {
        let _ = project_url;
        None
    }

    /// Get the project data for visible viewed projects that are managed by this project.
    ///
    /// Returns an empty vector if there are no visible viewed projects open.
    fn get_viewed_project_data(&self) -> Vec<Box<dyn ProjectData>> {
        Vec::new()
    }

    /// Releases all `DomainObject`s used by the given consumer.
    fn release_files(&mut self, consumer: DomainObjectConsumer) {
        let _ = consumer;
    }

    /// Add a listener to be notified when a visible project view is added or removed.
    fn add_project_view_listener(&mut self, listener: Box<dyn ProjectViewListener>) {
        let _ = listener;
    }

    /// Remove a project view listener previously added.
    fn remove_project_view_listener(&mut self, listener: &dyn ProjectViewListener) {
        let _ = listener;
    }

    /// Return an iterator over all non-link files within this project's data store. Stands in
    /// for the Java `Iterable<DomainFile>` default `iterator()`.
    fn iter_files(&self) -> Vec<Box<dyn DomainFile>> {
        self.get_project_data().iter_files()
    }
}

/// Trivial fallback used by [`Project::get_project_locator`]'s default implementation before a
/// real project location is available.
struct FallbackProjectLocator;
impl ProjectLocator for FallbackProjectLocator {}

/// Trivial fallback used by [`Project::get_project_data`] and friends' default implementations:
/// an empty, non-existent project data store.
struct FallbackProjectData;
impl ProjectData for FallbackProjectData {}

/// Trivial fallback used by [`Project::get_local_tool_chest`]'s (and other traits') default
/// implementations: a tool chest with no templates.
struct FallbackToolChest;
impl ToolChest for FallbackToolChest {
    fn get_tool_template(&self, tool_name: &str) -> Option<Box<dyn ToolTemplate>> {
        let _ = tool_name;
        None
    }

    fn get_tool_templates(&self) -> Vec<Box<dyn ToolTemplate>> {
        Vec::new()
    }

    fn add_tool_chest_change_listener(&mut self, listener: Box<dyn ToolChestChangeListener>) {
        let _ = listener;
    }

    fn remove_tool_chest_change_listener(&mut self, listener: Box<dyn ToolChestChangeListener>) {
        let _ = listener;
    }

    fn add_tool_template(&mut self, template: &mut dyn ToolTemplate) -> bool {
        let _ = template;
        false
    }

    fn remove(&mut self, tool_name: &str) -> bool {
        let _ = tool_name;
        false
    }

    fn get_tool_count(&self) -> i32 {
        0
    }

    fn replace_tool_template(&mut self, template: &mut dyn ToolTemplate) -> bool {
        let _ = template;
        false
    }
}

/// Trivial fallback used by [`Project::get_project_manager`]'s default implementation: a manager
/// with no known projects.
struct FallbackProjectManager;
impl ProjectManager for FallbackProjectManager {
    fn create_project(
        &mut self,
        project_locator: &dyn ProjectLocator,
        rep_adapter: Option<&dyn RepositoryAdapter>,
        remember: bool,
    ) -> io::Result<Box<dyn Project>> {
        let _ = (project_locator, rep_adapter, remember);
        Err(io::Error::new(io::ErrorKind::Unsupported, "no project manager available"))
    }

    fn get_recent_projects(&self) -> Vec<Box<dyn ProjectLocator>> {
        Vec::new()
    }

    fn get_recent_viewed_projects(&self) -> Vec<String> {
        Vec::new()
    }

    fn get_active_project(&self) -> Option<Box<dyn Project>> {
        None
    }

    fn get_last_opened_project(&self) -> Option<Box<dyn ProjectLocator>> {
        None
    }

    fn set_last_opened_project(&mut self, project_locator: Option<&dyn ProjectLocator>) {
        let _ = project_locator;
    }

    fn remember_project(&mut self, project_locator: &dyn ProjectLocator) {
        let _ = project_locator;
    }

    fn remember_viewed_project(&mut self, url: &str) {
        let _ = url;
    }

    fn forget_viewed_project(&mut self, url: &str) {
        let _ = url;
    }

    fn open_project(
        &mut self,
        project_locator: &dyn ProjectLocator,
        do_restore: bool,
        reset_owner: bool,
    ) -> Result<Box<dyn Project>, OpenProjectError> {
        let _ = (project_locator, do_restore, reset_owner);
        Err(OpenProjectError::Io(io::Error::new(
            io::ErrorKind::Unsupported,
            "no project manager available",
        )))
    }

    fn delete_project(&mut self, project_locator: &dyn ProjectLocator) -> bool {
        let _ = project_locator;
        false
    }

    fn project_exists(&self, project_locator: &dyn ProjectLocator) -> bool {
        let _ = project_locator;
        false
    }

    fn get_repository_server_adapter(
        &mut self,
        host: &str,
        port_number: i32,
        force_connect: bool,
    ) -> Box<dyn RepositoryServerAdapter> {
        let _ = (host, port_number, force_connect);
        Box::new(FallbackRepositoryServerAdapter)
    }

    fn get_most_recent_server_info(&self) -> Option<ServerInfo> {
        None
    }

    fn get_user_tool_chest(&self) -> Box<dyn StubToolChest> {
        Box::new(FallbackStubToolChest)
    }
}

/// Trivial fallback for `ghidra.framework.model.ToolChest` as seen through the still-unpromoted
/// [`seam_stubs::ToolChest`](crate::framework::seam_stubs::ToolChest) marker used by
/// [`ProjectManager::get_user_tool_chest`] and [`ToolServices::get_tool_chest`], distinct from the
/// real, already-ported [`ToolChest`] used by [`Project::get_local_tool_chest`].
struct FallbackStubToolChest;
impl StubToolChest for FallbackStubToolChest {}

/// Trivial fallback used by [`FallbackProjectManager::get_repository_server_adapter`]'s
/// implementation before a real class is available.
struct FallbackRepositoryServerAdapter;
impl RepositoryServerAdapter for FallbackRepositoryServerAdapter {}

/// Trivial fallback used by several defaults in this module before a real `PluginTool` is
/// available.
struct FallbackPluginTool;
impl PluginTool for FallbackPluginTool {}

/// Trivial fallback used by [`Project::get_tool_manager`]'s default implementation: a manager
/// with no running tools or workspaces.
struct FallbackToolManager;
impl ToolManager for FallbackToolManager {
    fn get_connection(
        &self,
        producer: &dyn PluginTool,
        consumer: &dyn PluginTool,
    ) -> Box<dyn ToolConnection> {
        let _ = (producer, consumer);
        Box::new(FallbackToolConnection { tool: FallbackPluginTool })
    }

    fn get_producer_tools(&self) -> Vec<Box<dyn PluginTool>> {
        Vec::new()
    }

    fn get_consumer_tools(&self) -> Vec<Box<dyn PluginTool>> {
        Vec::new()
    }

    fn get_running_tools(&self) -> Vec<Box<dyn PluginTool>> {
        Vec::new()
    }

    fn create_workspace(
        &mut self,
        name: &str,
    ) -> Result<Box<dyn Workspace>, DuplicateNameException> {
        let _ = name;
        Ok(Box::new(FallbackWorkspace))
    }

    fn remove_workspace(&mut self, ws: &dyn Workspace) {
        let _ = ws;
    }

    fn get_workspaces(&self) -> Vec<Box<dyn Workspace>> {
        Vec::new()
    }

    fn get_active_workspace(&self) -> Box<dyn Workspace> {
        Box::new(FallbackWorkspace)
    }

    fn add_workspace_change_listener(&mut self, listener: Box<dyn WorkspaceChangeListener>) {
        let _ = listener;
    }

    fn remove_workspace_change_listener(&mut self, listener: Box<dyn WorkspaceChangeListener>) {
        let _ = listener;
    }

    fn disconnect_tool(&mut self, tool: &dyn PluginTool) {
        let _ = tool;
    }

    fn tool_changed(&mut self, tool: &dyn PluginTool) {
        let _ = tool;
    }
}

/// Trivial fallback used by [`FallbackToolManager::get_connection`]'s implementation before a
/// real tool connection is available.
struct FallbackToolConnection {
    tool: FallbackPluginTool,
}
impl ToolConnection for FallbackToolConnection {
    fn get_producer(&self) -> &dyn PluginTool {
        &self.tool
    }

    fn get_consumer(&self) -> &dyn PluginTool {
        &self.tool
    }

    fn get_events(&self) -> Vec<String> {
        Vec::new()
    }

    fn connect(&mut self, event_name: &str) -> Result<(), String> {
        Err(format!("no tool manager available to connect event: {event_name}"))
    }

    fn disconnect(&mut self, event_name: &str) -> Result<(), String> {
        Err(format!("no tool manager available to disconnect event: {event_name}"))
    }

    fn is_connected(&self, event_name: &str) -> bool {
        let _ = event_name;
        false
    }
}

/// Trivial fallback used by [`FallbackToolManager::create_workspace`]/`get_active_workspace`'s
/// implementations before a real workspace is available.
struct FallbackWorkspace;
impl Workspace for FallbackWorkspace {
    fn get_name(&self) -> String {
        String::new()
    }

    fn get_tools(&self) -> Vec<Box<dyn PluginTool>> {
        Vec::new()
    }

    fn create_tool(&mut self) -> Box<dyn PluginTool> {
        Box::new(FallbackPluginTool)
    }

    fn run_tool(&mut self, template: &dyn ToolTemplate) -> Box<dyn PluginTool> {
        let _ = template;
        Box::new(FallbackPluginTool)
    }

    fn set_name(&mut self, new_name: &str) -> Result<(), DuplicateNameException> {
        let _ = new_name;
        Ok(())
    }

    fn set_active(&mut self) {}
}

/// Trivial fallback used by [`Project::get_tool_services`]'s default implementation: services
/// with no compatible tools or running tools.
struct FallbackToolServices;
impl ToolServices for FallbackToolServices {
    fn close_tool(&mut self, tool: &dyn PluginTool) {
        let _ = tool;
    }

    fn save_tool(&mut self, tool: &dyn PluginTool) {
        let _ = tool;
    }

    fn export_tool(&self, tool: &dyn ToolTemplate) -> io::Result<PathBuf> {
        let _ = tool;
        Err(io::Error::new(io::ErrorKind::Unsupported, "no tool services available"))
    }

    fn get_tool_chest(&self) -> Box<dyn StubToolChest> {
        Box::new(FallbackStubToolChest)
    }

    fn get_default_tool_template_for_file(
        &self,
        domain_file: &dyn DomainFile,
    ) -> Option<Box<dyn ToolTemplate>> {
        let _ = domain_file;
        None
    }

    fn get_default_tool_template_for_content_type(
        &self,
        content_type: &str,
    ) -> Option<Box<dyn ToolTemplate>> {
        let _ = content_type;
        None
    }

    fn get_compatible_tools(&self, domain_class: TypeId) -> Vec<Box<dyn ToolTemplate>> {
        let _ = domain_class;
        Vec::new()
    }

    fn get_content_type_tool_associations(&self) -> Vec<Box<dyn ToolAssociationInfo>> {
        Vec::new()
    }

    fn set_content_type_tool_associations(&mut self, infos: Vec<Box<dyn ToolAssociationInfo>>) {
        let _ = infos;
    }

    fn launch_default_tool(&mut self, domain_files: &[&dyn DomainFile]) -> Option<Box<dyn PluginTool>> {
        let _ = domain_files;
        None
    }

    fn launch_tool(
        &mut self,
        tool_name: &str,
        domain_files: &[&dyn DomainFile],
    ) -> Option<Box<dyn PluginTool>> {
        let _ = (tool_name, domain_files);
        None
    }

    fn launch_default_tool_with_url(&mut self, ghidra_url: &str) -> Option<Box<dyn PluginTool>> {
        let _ = ghidra_url;
        None
    }

    fn launch_tool_with_url(
        &mut self,
        tool_name: &str,
        ghidra_url: &str,
    ) -> Option<Box<dyn PluginTool>> {
        let _ = (tool_name, ghidra_url);
        None
    }

    fn get_running_tools(&self) -> Vec<Box<dyn PluginTool>> {
        Vec::new()
    }

    fn can_auto_save(&self, tool: &dyn PluginTool) -> bool {
        let _ = tool;
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_default_impl_compiles_and_behaves_like_a_closed_project() {
        struct BareProject;
        impl Project for BareProject {}

        let mut project = BareProject;
        assert_eq!(project.get_name(), "");
        assert!(!project.has_changed());
        assert!(!project.is_closed());
        assert!(project.get_open_data().is_empty());
        assert!(project.get_project_views().is_empty());
        assert!(project.iter_files().is_empty());
        assert!(project.get_tool_template("CodeBrowser").is_none());
        assert!(project.get_saveable_data("key").is_none());
        assert!(project.save_session_tools());

        project.save();
        project.restore();
        project.close();

        assert!(project.add_project_view("ghidra://localhost/repo", true).is_err());
    }

    #[derive(Default)]
    struct SimpleProject {
        name: String,
        changed: bool,
        closed: bool,
    }

    impl Project for SimpleProject {
        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn has_changed(&self) -> bool {
            self.changed
        }

        fn is_closed(&self) -> bool {
            self.closed
        }

        fn close(&mut self) {
            self.closed = true;
        }
    }

    #[test]
    fn usable_as_trait_object() {
        let mut project = SimpleProject { name: "MyProject".to_string(), ..Default::default() };
        let dyn_project: &mut dyn Project = &mut project;

        assert_eq!(dyn_project.get_name(), "MyProject");
        assert!(!dyn_project.has_changed());
        assert!(!dyn_project.is_closed());

        dyn_project.close();
        assert!(dyn_project.is_closed());

        let _locator = dyn_project.get_project_locator();
        let _manager = dyn_project.get_project_manager();
        let _tool_manager = dyn_project.get_tool_manager();
        let _tool_services = dyn_project.get_tool_services();
        let _tool_chest = dyn_project.get_local_tool_chest();
        let _data = dyn_project.get_project_data();
        assert!(dyn_project.get_repository().is_none());
    }
}

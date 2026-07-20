use std::io;

use thiserror::Error;

use crate::framework::client::{RepositoryAdapter, RepositoryServerAdapter};
use crate::framework::model::Project;
use crate::framework::seam_stubs::{ProjectLocator, ToolChest};
use crate::framework::store::LockException;
use crate::framework::model::server_info::ServerInfo;
use crate::util::exception::{NotFoundException, NotOwnerException};

/// Default extension for tool config files.
///
/// Port of `ProjectManager.APPLICATION_TOOL_EXTENSION`.
pub const APPLICATION_TOOL_EXTENSION: &str = ".tcd";

/// Tools directory name.
///
/// Port of `ProjectManager.APPLICATION_TOOLS_DIR_NAME`.
pub const APPLICATION_TOOLS_DIR_NAME: &str = "tools";

/// Combines the checked exceptions declared on
/// `ProjectManager.openProject(ProjectLocator, boolean, boolean)`.
#[derive(Error, Debug)]
pub enum OpenProjectError {
    #[error(transparent)]
    NotFound(#[from] NotFoundException),
    #[error(transparent)]
    NotOwner(#[from] NotOwnerException),
    #[error(transparent)]
    Lock(#[from] LockException),
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Interface for methods to create, open, and delete projects; maintains a list of known project
/// views that the user opened. It has a handle to the currently opened project. A project can be
/// opened by one user at a time.
///
/// Port of `ghidra.framework.model.ProjectManager`.
///
/// `java.net.URL` parameters/returns are represented as `String`, matching how this crate already
/// represents project view URLs elsewhere (see
/// [`DomainFolder::get_shared_project_url`](crate::framework::model::DomainFolder::get_shared_project_url)).
pub trait ProjectManager {
    /// Create a project on the local filesystem.
    ///
    /// # Arguments
    /// * `project_locator` - location for where the project should be created
    /// * `rep_adapter` - repository adapter if this project is to be a shared project; `None` if
    ///   the project is not shared.
    /// * `remember` - if false the new project should not be remembered (i.e., recently opened,
    ///   etc.)
    fn create_project(
        &mut self,
        project_locator: &dyn ProjectLocator,
        rep_adapter: Option<&dyn RepositoryAdapter>,
        remember: bool,
    ) -> io::Result<Box<dyn Project>>;

    /// Get list of projects that user most recently opened.
    fn get_recent_projects(&self) -> Vec<Box<dyn ProjectLocator>>;

    /// Get list of projects that user most recently viewed.
    fn get_recent_viewed_projects(&self) -> Vec<String>;

    /// Get the project that is currently open, or `None` if there is no project opened.
    fn get_active_project(&self) -> Option<Box<dyn Project>>;

    /// Get the last opened (active) project; returns `None` if a project was never opened OR the
    /// last opened project is no longer valid.
    fn get_last_opened_project(&self) -> Option<Box<dyn ProjectLocator>>;

    /// Set the project locator of last opened (active) project; this project locator is returned
    /// by [`get_last_opened_project`](ProjectManager::get_last_opened_project). `None` signals
    /// that the user closed the project.
    fn set_last_opened_project(&mut self, project_locator: Option<&dyn ProjectLocator>);

    /// Keep the project locator on the list of known projects.
    fn remember_project(&mut self, project_locator: &dyn ProjectLocator);

    /// Keep the url on the list of known projects.
    fn remember_viewed_project(&mut self, url: &str);

    /// Remove the project url from the list of known viewed projects.
    fn forget_viewed_project(&mut self, url: &str);

    /// Open a project from the file system. Add the project url to the list of known projects.
    ///
    /// # Arguments
    /// * `project_locator` - project location
    /// * `do_restore` - true if the project should be restored
    /// * `reset_owner` - if true, the owner of the project will be changed to the current user.
    fn open_project(
        &mut self,
        project_locator: &dyn ProjectLocator,
        do_restore: bool,
        reset_owner: bool,
    ) -> Result<Box<dyn Project>, OpenProjectError>;

    /// Delete the project in the given location. Returns false if no project was deleted.
    fn delete_project(&mut self, project_locator: &dyn ProjectLocator) -> bool;

    /// Returns true if a project with the given project locator exists.
    fn project_exists(&self, project_locator: &dyn ProjectLocator) -> bool;

    /// Establish a connection to the given host and port number.
    ///
    /// # Arguments
    /// * `host` - server name or IP address
    /// * `port_number` - server port or 0 for default
    /// * `force_connect` - if true and currently not connected, an attempt will be made to
    ///   connect
    fn get_repository_server_adapter(
        &mut self,
        host: &str,
        port_number: i32,
        force_connect: bool,
    ) -> Box<dyn RepositoryServerAdapter>;

    /// Returns the information that was last used to access a repository managed by a Ghidra
    /// server, or `None` if a repository has never been accessed.
    fn get_most_recent_server_info(&self) -> Option<ServerInfo>;

    /// Returns the user's ToolChest.
    fn get_user_tool_chest(&self) -> Box<dyn ToolChest>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockProjectLocator;
    impl ProjectLocator for MockProjectLocator {}

    struct MockRepositoryAdapter;
    impl RepositoryAdapter for MockRepositoryAdapter {}

    struct MockRepositoryServerAdapter;
    impl RepositoryServerAdapter for MockRepositoryServerAdapter {}

    struct MockProject;
    impl Project for MockProject {}

    struct MockToolChest;
    impl ToolChest for MockToolChest {}

    struct SimpleProjectManager {
        active: Option<()>,
        last_opened: Option<()>,
        recent: Vec<()>,
    }

    impl ProjectManager for SimpleProjectManager {
        fn create_project(
            &mut self,
            _project_locator: &dyn ProjectLocator,
            _rep_adapter: Option<&dyn RepositoryAdapter>,
            remember: bool,
        ) -> io::Result<Box<dyn Project>> {
            if remember {
                self.recent.push(());
            }
            Ok(Box::new(MockProject))
        }

        fn get_recent_projects(&self) -> Vec<Box<dyn ProjectLocator>> {
            self.recent.iter().map(|_| Box::new(MockProjectLocator) as Box<dyn ProjectLocator>).collect()
        }

        fn get_recent_viewed_projects(&self) -> Vec<String> {
            Vec::new()
        }

        fn get_active_project(&self) -> Option<Box<dyn Project>> {
            self.active.map(|_| Box::new(MockProject) as Box<dyn Project>)
        }

        fn get_last_opened_project(&self) -> Option<Box<dyn ProjectLocator>> {
            self.last_opened.map(|_| Box::new(MockProjectLocator) as Box<dyn ProjectLocator>)
        }

        fn set_last_opened_project(&mut self, project_locator: Option<&dyn ProjectLocator>) {
            self.last_opened = project_locator.map(|_| ());
        }

        fn remember_project(&mut self, _project_locator: &dyn ProjectLocator) {
            self.recent.push(());
        }

        fn remember_viewed_project(&mut self, _url: &str) {}

        fn forget_viewed_project(&mut self, _url: &str) {}

        fn open_project(
            &mut self,
            _project_locator: &dyn ProjectLocator,
            _do_restore: bool,
            _reset_owner: bool,
        ) -> Result<Box<dyn Project>, OpenProjectError> {
            self.active = Some(());
            Ok(Box::new(MockProject))
        }

        fn delete_project(&mut self, _project_locator: &dyn ProjectLocator) -> bool {
            false
        }

        fn project_exists(&self, _project_locator: &dyn ProjectLocator) -> bool {
            false
        }

        fn get_repository_server_adapter(
            &mut self,
            _host: &str,
            _port_number: i32,
            _force_connect: bool,
        ) -> Box<dyn RepositoryServerAdapter> {
            Box::new(MockRepositoryServerAdapter)
        }

        fn get_most_recent_server_info(&self) -> Option<ServerInfo> {
            None
        }

        fn get_user_tool_chest(&self) -> Box<dyn ToolChest> {
            Box::new(MockToolChest)
        }
    }

    #[test]
    fn usable_as_trait_object() {
        let mut mgr = SimpleProjectManager { active: None, last_opened: None, recent: Vec::new() };
        let dyn_mgr: &mut dyn ProjectManager = &mut mgr;

        assert!(dyn_mgr.get_active_project().is_none());
        assert!(dyn_mgr.get_last_opened_project().is_none());
        assert!(dyn_mgr.get_recent_projects().is_empty());
        assert!(dyn_mgr.get_recent_viewed_projects().is_empty());
        assert!(dyn_mgr.get_most_recent_server_info().is_none());

        let locator = MockProjectLocator;
        let created = dyn_mgr.create_project(&locator, None, true).expect("create succeeds");
        let _: Box<dyn Project> = created;
        assert_eq!(dyn_mgr.get_recent_projects().len(), 1);

        dyn_mgr.set_last_opened_project(Some(&locator));
        assert!(dyn_mgr.get_last_opened_project().is_some());
        dyn_mgr.set_last_opened_project(None);
        assert!(dyn_mgr.get_last_opened_project().is_none());

        dyn_mgr.remember_project(&locator);
        dyn_mgr.remember_viewed_project("ghidra://localhost/repo");
        dyn_mgr.forget_viewed_project("ghidra://localhost/repo");

        let opened = dyn_mgr.open_project(&locator, true, false).expect("open succeeds");
        let _: Box<dyn Project> = opened;
        assert!(dyn_mgr.get_active_project().is_some());

        assert!(!dyn_mgr.delete_project(&locator));
        assert!(!dyn_mgr.project_exists(&locator));

        let _rsh = dyn_mgr.get_repository_server_adapter("localhost", 13100, true);
        let _chest = dyn_mgr.get_user_tool_chest();
    }

    #[test]
    fn open_project_error_variants_convert_via_from() {
        let _e: OpenProjectError = NotFoundException::new().into();
        let _e: OpenProjectError = NotOwnerException::new().into();
        let _e: OpenProjectError = LockException::new("locked").into();
        let _e: OpenProjectError = io::Error::new(io::ErrorKind::Other, "io failure").into();
    }
}

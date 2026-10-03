//! Port of `ghidra.pyghidra.PyGhidraProjectManager`.

use std::io;
use std::rc::Rc;

use crate::framework::client::{RepositoryAdapter, RepositoryServerAdapter};
use crate::framework::model::{
    OpenProjectError, Project, ProjectLocator, ProjectManager, ServerInfo, ToolChest,
};
use crate::framework::project::default_project_manager::{
    DefaultProjectManager, DefaultProjectManagerBase,
};
use crate::framework::protocol::ghidra::GhidraURL;
use crate::framework::seam_stubs::{
    AppInfo, ClientUtil, DefaultProjectFactory, PreferencesLike, TransientDataManager,
};

/// A [`DefaultProjectManager`] for use by PyGhidra.
///
/// Port of `ghidra.pyghidra.PyGhidraProjectManager`. In Java, this class exists solely to expose
/// `DefaultProjectManager`'s otherwise-`protected` constructor to the `ghidra.pyghidra` package --
/// it adds no members of its own. Per this crate's composition-over-inheritance convention (and
/// exactly as anticipated by [`DefaultProjectManagerBase`]'s own module docs: "a subclass is a
/// struct that embeds this one and forwards `ProjectManager` to it"), this embeds a
/// [`DefaultProjectManagerBase`] and forwards every [`ProjectManager`]/[`DefaultProjectManager`]
/// member to it.
pub struct PyGhidraProjectManager {
    base: DefaultProjectManagerBase,
}

impl PyGhidraProjectManager {
    /// Constructs the manager, reading the known projects and last used server back out of the
    /// given preferences.
    ///
    /// Port of `public PyGhidraProjectManager()`, which (as the class's only member) calls the
    /// inherited `protected DefaultProjectManager()` constructor with no arguments of its own; the
    /// seams that constructor needs are threaded through here instead, matching
    /// [`DefaultProjectManagerBase::new`].
    pub fn new(
        preferences: Rc<dyn PreferencesLike>,
        ghidra_url: Rc<dyn GhidraURL>,
        client_util: Rc<dyn ClientUtil>,
        app_info: Rc<dyn AppInfo>,
        transient_data: Rc<dyn TransientDataManager>,
        project_factory: Rc<dyn DefaultProjectFactory>,
        user_tool_chest: Box<dyn ToolChest>,
    ) -> Self {
        Self {
            base: DefaultProjectManagerBase::new(
                preferences,
                ghidra_url,
                client_util,
                app_info,
                transient_data,
                project_factory,
                user_tool_chest,
            ),
        }
    }
}

impl DefaultProjectManager for PyGhidraProjectManager {}

impl ProjectManager for PyGhidraProjectManager {
    fn create_project(
        &mut self,
        project_locator: &dyn ProjectLocator,
        rep_adapter: Option<&dyn RepositoryAdapter>,
        remember: bool,
    ) -> io::Result<Box<dyn Project>> {
        self.base.create_project(project_locator, rep_adapter, remember)
    }

    fn get_recent_projects(&self) -> Vec<Box<dyn ProjectLocator>> {
        self.base.get_recent_projects()
    }

    fn get_recent_viewed_projects(&self) -> Vec<String> {
        self.base.get_recent_viewed_projects()
    }

    fn get_active_project(&self) -> Option<Box<dyn Project>> {
        self.base.get_active_project()
    }

    fn get_last_opened_project(&self) -> Option<Box<dyn ProjectLocator>> {
        self.base.get_last_opened_project()
    }

    fn set_last_opened_project(&mut self, project_locator: Option<&dyn ProjectLocator>) {
        self.base.set_last_opened_project(project_locator)
    }

    fn remember_project(&mut self, project_locator: &dyn ProjectLocator) {
        self.base.remember_project(project_locator)
    }

    fn remember_viewed_project(&mut self, url: &str) {
        self.base.remember_viewed_project(url)
    }

    fn forget_viewed_project(&mut self, url: &str) {
        self.base.forget_viewed_project(url)
    }

    fn open_project(
        &mut self,
        project_locator: &dyn ProjectLocator,
        do_restore: bool,
        reset_owner: bool,
    ) -> Result<Box<dyn Project>, OpenProjectError> {
        self.base.open_project(project_locator, do_restore, reset_owner)
    }

    fn delete_project(&mut self, project_locator: &dyn ProjectLocator) -> bool {
        self.base.delete_project(project_locator)
    }

    fn project_exists(&self, project_locator: &dyn ProjectLocator) -> bool {
        self.base.project_exists(project_locator)
    }

    fn get_repository_server_adapter(
        &mut self,
        host: &str,
        port_number: i32,
        force_connect: bool,
    ) -> Box<dyn RepositoryServerAdapter> {
        self.base.get_repository_server_adapter(host, port_number, force_connect)
    }

    fn get_most_recent_server_info(&self) -> Option<ServerInfo> {
        self.base.get_most_recent_server_info()
    }

    fn get_user_tool_chest(&self) -> Box<dyn ToolChest> {
        self.base.get_user_tool_chest()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::seam_stubs::{
        CreateProjectError, DefaultProject, GhidraUrlHandlerLike, ToolChestImpl,
    };
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};

    /// Project locator over a real directory: `<location>/<name>.gpr` marker file next to a
    /// `<location>/<name>.rep` project directory.
    struct TestLocator {
        name: String,
        location: PathBuf,
    }

    impl TestLocator {
        fn new(location: &Path, name: &str) -> Self {
            Self { name: name.to_string(), location: location.to_path_buf() }
        }

        fn create_storage(&self) {
            std::fs::create_dir_all(self.get_project_dir()).unwrap();
            std::fs::write(self.get_marker_file(), "").unwrap();
        }
    }

    impl ProjectLocator for TestLocator {
        fn url(&self) -> String {
            format!("ghidra://{}/{}", self.location.display(), self.name)
        }

        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn get_location(&self) -> String {
            self.location.display().to_string()
        }

        fn get_project_dir(&self) -> PathBuf {
            self.location.join(format!("{}.rep", self.name))
        }

        fn get_marker_file(&self) -> PathBuf {
            self.location.join(format!("{}.gpr", self.name))
        }
    }

    /// `GhidraURL` double understanding the `ghidra://<location>/<name>` URLs [`TestLocator`]
    /// produces, answering `localProjectExists` from the filesystem -- exercised whenever a
    /// remembered/last-opened project's URL is resolved back into a locator (e.g.
    /// `get_recent_projects`/`get_last_opened_project`), which several of these tests do reach
    /// once a project has been created/opened/remembered. `handler`/`make_project_locator` are
    /// not reached by any of these tests.
    struct TestGhidraUrl;

    impl TestGhidraUrl {
        fn locator_of(url: &str) -> Option<TestLocator> {
            let rest = url.strip_prefix("ghidra://")?;
            let (location, name) = rest.rsplit_once('/')?;
            Some(TestLocator::new(Path::new(location), name))
        }
    }

    impl GhidraURL for TestGhidraUrl {
        fn make_project_locator(&self, _dir_path: &str, _project_name: &str) -> Box<dyn ProjectLocator> {
            unimplemented!("not exercised by these tests")
        }
        fn handler(&self) -> Box<dyn GhidraUrlHandlerLike> {
            unimplemented!("not exercised by these tests")
        }
        fn to_url(&self, project_path_or_url: &str) -> io::Result<String> {
            if Self::locator_of(project_path_or_url).is_some() {
                return Ok(project_path_or_url.to_string());
            }
            Err(io::Error::new(io::ErrorKind::InvalidInput, format!("not a project path: {project_path_or_url}")))
        }
        fn is_local_url(&self, str: &str) -> bool {
            str.starts_with("ghidra://")
        }
        fn local_project_exists(&self, url: &str) -> bool {
            Self::locator_of(url).is_some_and(|locator| locator.get_project_dir().exists())
        }
        fn get_project_storage_locator(
            &self,
            local_project_url: &str,
        ) -> io::Result<Option<Box<dyn ProjectLocator>>> {
            Ok(Self::locator_of(local_project_url).map(|locator| Box::new(locator) as Box<dyn ProjectLocator>))
        }
    }

    #[derive(Default)]
    struct TestPreferences {
        properties: RefCell<HashMap<String, String>>,
    }

    impl PreferencesLike for TestPreferences {
        fn get_property(
            &self,
            name: &str,
            default_value: Option<&str>,
            _use_historical_value: bool,
        ) -> Option<String> {
            self.properties.borrow().get(name).cloned().or_else(|| default_value.map(str::to_string))
        }

        fn set_property(&self, name: &str, value: &str) {
            self.properties.borrow_mut().insert(name.to_string(), value.to_string());
        }

        fn store(&self) -> bool {
            true
        }
    }

    struct TestClientUtil;
    struct TestServerAdapter {
        server_info: ServerInfo,
    }
    impl RepositoryServerAdapter for TestServerAdapter {
        fn get_server_info(&self) -> Option<ServerInfo> {
            Some(self.server_info.clone())
        }
    }
    impl ClientUtil for TestClientUtil {
        fn get_repository_server(
            &self,
            host: &str,
            port: i32,
            _force_connect: bool,
        ) -> Box<dyn RepositoryServerAdapter> {
            Box::new(TestServerAdapter { server_info: ServerInfo::new(host, port as u16) })
        }
    }

    #[derive(Default)]
    struct TestAppInfo {
        activated: RefCell<Vec<String>>,
    }
    impl AppInfo for TestAppInfo {
        fn set_active_project(&self, project: &dyn Project) {
            self.activated.borrow_mut().push(project.get_name());
        }
    }

    #[derive(Default)]
    struct TestTransientDataManager;
    impl TransientDataManager for TestTransientDataManager {
        fn clear_all(&self) {}
    }

    struct TestProject {
        name: String,
    }
    impl Project for TestProject {
        fn get_name(&self) -> String {
            self.name.clone()
        }
    }
    impl DefaultProject for TestProject {}

    #[derive(Default)]
    struct TestProjectFactory;
    impl DefaultProjectFactory for TestProjectFactory {
        fn create(
            &self,
            project_locator: &dyn ProjectLocator,
            _repository: Option<&dyn RepositoryAdapter>,
        ) -> Result<Box<dyn DefaultProject>, CreateProjectError> {
            Ok(Box::new(TestProject { name: project_locator.get_name() }))
        }

        fn open(
            &self,
            project_locator: &dyn ProjectLocator,
            _reset_owner: bool,
        ) -> Result<Box<dyn DefaultProject>, OpenProjectError> {
            Ok(Box::new(TestProject { name: project_locator.get_name() }))
        }
    }

    fn manager() -> PyGhidraProjectManager {
        PyGhidraProjectManager::new(
            Rc::new(TestPreferences::default()),
            Rc::new(TestGhidraUrl),
            Rc::new(TestClientUtil),
            Rc::new(TestAppInfo::default()),
            Rc::new(TestTransientDataManager),
            Rc::new(TestProjectFactory),
            Box::new(ToolChestImpl::new()),
        )
    }

    #[test]
    fn constructs_with_empty_state() {
        let mgr = manager();
        assert!(mgr.get_active_project().is_none());
        assert!(mgr.get_recent_projects().is_empty());
        assert!(mgr.get_recent_viewed_projects().is_empty());
        assert!(mgr.get_most_recent_server_info().is_none());
    }

    #[test]
    fn user_tool_chest_forwards_to_the_embedded_base() {
        let mgr = manager();
        assert_eq!(mgr.get_user_tool_chest().get_tool_count(), 0);
    }

    #[test]
    fn creating_a_project_delegates_and_activates_it() {
        let dir = tempfile::tempdir().unwrap();
        let locator = TestLocator::new(dir.path(), "Alpha");
        locator.create_storage();
        let mut mgr = manager();

        let project = mgr.create_project(&locator, None, true).expect("create succeeds");
        assert_eq!(project.get_name(), "Alpha");
        assert_eq!(mgr.get_active_project().map(|p| p.get_name()), Some("Alpha".to_string()));
        assert_eq!(mgr.get_recent_projects().len(), 1);

        // A second concurrent create is refused, exactly as `DefaultProjectManagerBase` refuses
        // it -- proving the forward reaches the real, stateful base rather than a fresh copy.
        let second = TestLocator::new(dir.path(), "Beta");
        second.create_storage();
        assert!(mgr.create_project(&second, None, true).is_err());
    }

    #[test]
    fn opening_a_project_delegates_and_remembers_it() {
        let dir = tempfile::tempdir().unwrap();
        let locator = TestLocator::new(dir.path(), "Gamma");
        locator.create_storage();
        let mut mgr = manager();

        let project = mgr.open_project(&locator, false, false).expect("open succeeds");
        assert_eq!(project.get_name(), "Gamma");
        assert_eq!(
            mgr.get_recent_projects().iter().map(|l| l.get_name()).collect::<Vec<_>>(),
            vec!["Gamma".to_string()]
        );
    }

    #[test]
    fn connecting_to_a_server_records_it_via_the_base() {
        let mut mgr = manager();
        let _rsh = mgr.get_repository_server_adapter("myhost", 13100, true);
        assert_eq!(mgr.get_most_recent_server_info(), Some(ServerInfo::new("myhost", 13100)));
    }

    #[test]
    fn remember_and_forget_viewed_projects_delegate_to_the_base() {
        let mut mgr = manager();
        mgr.remember_viewed_project("ghidra://localhost/repo");
        assert_eq!(mgr.get_recent_viewed_projects(), vec!["ghidra://localhost/repo".to_string()]);
        mgr.forget_viewed_project("ghidra://localhost/repo");
        assert!(mgr.get_recent_viewed_projects().is_empty());
    }

    #[test]
    fn set_and_get_last_opened_project_delegate_to_the_base() {
        let dir = tempfile::tempdir().unwrap();
        let locator = TestLocator::new(dir.path(), "Delta");
        locator.create_storage();
        let mut mgr = manager();

        mgr.set_last_opened_project(Some(&locator));
        assert_eq!(mgr.get_last_opened_project().map(|l| l.get_name()), Some("Delta".to_string()));

        mgr.set_last_opened_project(None);
        assert!(mgr.get_last_opened_project().is_none());
    }

    #[test]
    fn project_exists_and_delete_project_delegate_to_the_base() {
        let dir = tempfile::tempdir().unwrap();
        let locator = TestLocator::new(dir.path(), "Epsilon");
        locator.create_storage();
        let mut mgr = manager();

        assert!(mgr.project_exists(&locator));
        assert!(mgr.delete_project(&locator));
        assert!(!mgr.project_exists(&locator));
    }

    #[test]
    fn usable_as_a_project_manager_trait_object() {
        let mut mgr = manager();
        let dyn_mgr: &mut dyn ProjectManager = &mut mgr;
        assert!(dyn_mgr.get_active_project().is_none());
        let _chest = dyn_mgr.get_user_tool_chest();
    }
}

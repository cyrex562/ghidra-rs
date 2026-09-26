//! Port of `ghidra.framework.project.DefaultProjectManager`.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use crate::framework::client::{RepositoryAdapter, RepositoryServerAdapter};
use crate::framework::generic_run_info::GenericRunInfo;
use crate::framework::model::{
    OpenProjectError, Project, ProjectLocator, ProjectManager, ServerInfo, ToolChest,
    ToolChestChangeListener, ToolTemplate, APPLICATION_TOOLS_DIR_NAME, APPLICATION_TOOL_EXTENSION,
};
use crate::framework::protocol::ghidra::GhidraURL;
use crate::framework::seam_stubs::{
    AppInfo, ClientUtil, DefaultProject, DefaultProjectFactory, PreferencesLike, ToolChestImpl,
    ToolUtils, TransientDataManager,
};
use crate::util::msg::Msg;

/// Preference name for the last opened project.
///
/// Port of the private `DefaultProjectManager.LAST_OPENED_PROJECT`.
pub const LAST_OPENED_PROJECT: &str = "LastOpenedProject";

/// Preference name holding the recently opened projects.
const RECENT_PROJECTS: &str = "RecentProjects";

/// Preference name holding the recently viewed (read-only) projects.
const VIEWED_PROJECTS: &str = "ViewedProjects";

/// Preference name holding the most recently used Ghidra server.
const SERVER_INFO: &str = "ServerInfo";

/// How many entries the recently-opened and recently-viewed lists hold.
const RECENT_PROJECTS_LIMIT: usize = 6;

/// Value written to the [`LAST_OPENED_PROJECT`] preference once the user closes a project without
/// opening another one.
const PROJECT_CLOSED_BY_USER_VALUE: &str = "PROJECT_CLOSED;NO_PROJECT_OPEN";

/// Separator between project paths within a single preference value.
const PROJECT_PATH_SEPARATOR: &str = ";";

/// Originator passed to [`Msg`], standing in for Java's
/// `LogManager.getLogger(DefaultProjectManager.class)`.
const LOG: &str = "DefaultProjectManager";

/// A live handle to the tool chest owned by a [`DefaultProjectManagerBase`].
///
/// [`ProjectManager::get_user_tool_chest`] hands the chest back as an owned `Box<dyn ToolChest>`
/// where Java hands back the field itself, so the manager keeps its chest behind a shared
/// [`Rc`]/[`RefCell`] and boxes these handles: adding a tool through a handle adds it to the
/// manager's chest, as it does in Java.
#[derive(Clone)]
pub struct ToolChestHandle(Rc<RefCell<Box<dyn ToolChest>>>);

impl ToolChest for ToolChestHandle {
    fn get_tool_template(&self, tool_name: &str) -> Option<Box<dyn ToolTemplate>> {
        self.0.borrow().get_tool_template(tool_name)
    }

    fn get_tool_templates(&self) -> Vec<Box<dyn ToolTemplate>> {
        self.0.borrow().get_tool_templates()
    }

    fn add_tool_chest_change_listener(&mut self, listener: Box<dyn ToolChestChangeListener>) {
        self.0.borrow_mut().add_tool_chest_change_listener(listener);
    }

    fn remove_tool_chest_change_listener(&mut self, listener: Box<dyn ToolChestChangeListener>) {
        self.0.borrow_mut().remove_tool_chest_change_listener(listener);
    }

    fn add_tool_template(&mut self, template: &mut dyn ToolTemplate) -> bool {
        self.0.borrow_mut().add_tool_template(template)
    }

    fn remove(&mut self, tool_name: &str) -> bool {
        self.0.borrow_mut().remove(tool_name)
    }

    fn get_tool_count(&self) -> i32 {
        self.0.borrow().get_tool_count()
    }

    fn replace_tool_template(&mut self, template: &mut dyn ToolTemplate) -> bool {
        self.0.borrow_mut().replace_tool_template(template)
    }
}

/// A live handle to the project a [`DefaultProjectManagerBase`] currently has open.
///
/// Like [`ToolChestHandle`], this exists because [`ProjectManager::get_active_project`] hands the
/// project back as an owned `Box<dyn Project>` where Java hands back the field. Members that only
/// read or drive the project itself are delegated; the rest keep [`Project`]'s own "nothing here"
/// defaults, since the [`DefaultProject`] seam cannot answer them yet.
#[derive(Clone)]
pub struct ProjectHandle(Rc<RefCell<Box<dyn DefaultProject>>>);

impl ProjectHandle {
    /// Whether this handle and `other` refer to the same open project.
    pub fn is_same_project(&self, other: &ProjectHandle) -> bool {
        Rc::ptr_eq(&self.0, &other.0)
    }
}

impl Project for ProjectHandle {
    fn get_name(&self) -> String {
        self.0.borrow().get_name()
    }

    fn get_project_locator(&self) -> Box<dyn ProjectLocator> {
        self.0.borrow().get_project_locator()
    }

    fn has_changed(&self) -> bool {
        self.0.borrow().has_changed()
    }

    fn is_closed(&self) -> bool {
        self.0.borrow().is_closed()
    }

    fn close(&mut self) {
        self.0.borrow_mut().close();
    }

    fn save(&mut self) {
        self.0.borrow_mut().save();
    }

    fn save_session_tools(&mut self) -> bool {
        self.0.borrow_mut().save_session_tools()
    }

    fn restore(&mut self) {
        self.0.borrow_mut().restore();
    }
}

/// The state shared by every project manager: the recently opened/viewed lists, the user's tool
/// chest, the last used server, and the project that is currently open.
///
/// Port of `ghidra.framework.project.DefaultProjectManager`. The Java class is concrete but is
/// only ever used through one of the four subclasses that exist solely to expose its `protected`
/// constructor (`GhidraRun.GhidraProjectManager`, `HeadlessAnalyzer.HeadlessGhidraProjectManager`,
/// `GhidraProject.GhidraProjectManager`, `PyGhidraProjectManager`, plus the test-only
/// `TestProjectManager`), so the state and the concrete behaviour live here and the one
/// overridable member lives on [`DefaultProjectManager`]. A subclass is a struct that embeds this
/// one and forwards [`ProjectManager`] to it.
///
/// Four shapes differ from the Java class:
///
/// * **The statics it calls are injected.** `Preferences`, `GhidraURL`, `ClientUtil`, `AppInfo`
///   and `TransientDataManager` are static Java utilities but traits here, so the manager holds
///   one of each. `ToolUtils` and [`GenericRunInfo`] are passed to the tool-chest members that
///   need them instead of being held, since those members run once, before the manager exists.
/// * **`DefaultProject` is constructed through a factory.** Java calls `new DefaultProject(this,
///   ..)`, handing the project a back-reference to its manager; that back-reference is the
///   dependency cycle this port sits on, so project construction goes through
///   [`DefaultProjectFactory`] and the projects it returns do not know their manager.
/// * **Project locators are held as their URLs.** Java keeps `ProjectLocator` objects in both
///   lists; [`ProjectLocator`] is a trait here (identity defined by
///   [`url`](ProjectLocator::url), see its own docs) and trait objects cannot be cloned out of a
///   `&dyn` argument, so the lists hold the URL strings that Java writes to the preferences
///   anyway, and [`get_recent_projects`](ProjectManager::get_recent_projects) rebuilds locators
///   from them through [`GhidraURL`].
/// * **`createProject`/`getLastOpenedProject` cannot return `null`.** Java returns `null` from
///   `createProject` when a project is already open; [`ProjectManager::create_project`] returns
///   `io::Result`, so that case becomes an error carrying the same message it logs.
pub struct DefaultProjectManagerBase {
    preferences: Rc<dyn PreferencesLike>,
    ghidra_url: Rc<dyn GhidraURL>,
    client_util: Rc<dyn ClientUtil>,
    app_info: Rc<dyn AppInfo>,
    transient_data: Rc<dyn TransientDataManager>,
    project_factory: Rc<dyn DefaultProjectFactory>,

    /// URLs of the projects the user most recently opened, most recent first.
    recently_opened_projects: Vec<String>,
    /// URLs of the projects the user most recently viewed, most recent first.
    recently_viewed_projects: Vec<String>,

    user_tool_chest: Rc<RefCell<Box<dyn ToolChest>>>,
    server_info: Option<ServerInfo>,
    last_opened_project: Option<String>,
    current_project: Option<ProjectHandle>,
}

impl DefaultProjectManagerBase {
    /// Constructs the manager, reading the known projects and the last used server back out of
    /// the preferences.
    ///
    /// Port of `protected DefaultProjectManager()`. The tool chest is a parameter rather than a
    /// `createUserToolChest()` call because Java's constructor calls that overridable member on a
    /// half-built object, which Rust cannot do: a concrete manager calls
    /// [`DefaultProjectManager::create_user_tool_chest`] first and hands the result here.
    pub fn new(
        preferences: Rc<dyn PreferencesLike>,
        ghidra_url: Rc<dyn GhidraURL>,
        client_util: Rc<dyn ClientUtil>,
        app_info: Rc<dyn AppInfo>,
        transient_data: Rc<dyn TransientDataManager>,
        project_factory: Rc<dyn DefaultProjectFactory>,
        user_tool_chest: Box<dyn ToolChest>,
    ) -> Self {
        let mut manager = Self {
            preferences,
            ghidra_url,
            client_util,
            app_info,
            transient_data,
            project_factory,
            recently_opened_projects: Vec::new(),
            recently_viewed_projects: Vec::new(),
            user_tool_chest: Rc::new(RefCell::new(user_tool_chest)),
            server_info: None,
            last_opened_project: None,
            current_project: None,
        };

        // get locator for last opened project
        manager.last_opened_project = manager.get_last_opened_project().map(|l| l.url());
        // read known projects from ghidra preferences...
        manager.populate_project_locator_list(RECENT_PROJECTS);
        manager.populate_project_url_list(VIEWED_PROJECTS);
        manager.update_preferences();
        manager.server_info = parse_server_info(
            manager.preferences.get_property(SERVER_INFO, None, false).as_deref(),
        );
        manager
    }

    /// The user's tool chest, as a handle that shares the manager's chest.
    ///
    /// Port of `getUserToolChest()` for callers that would rather not go through the
    /// [`ProjectManager`] trait object.
    pub fn user_tool_chest(&self) -> ToolChestHandle {
        ToolChestHandle(Rc::clone(&self.user_tool_chest))
    }

    /// Notifies the manager that one of its projects closed; if it is the active one, the manager
    /// no longer has an active project.
    ///
    /// Port of the package-private `projectClosed(DefaultProject)`.
    pub(crate) fn project_closed(&mut self, project: &ProjectHandle) {
        if self.current_project.as_ref().is_some_and(|open| open.is_same_project(project)) {
            self.current_project = None;
        }
        self.transient_data.clear_all();
    }

    /// Updates the preferences file with the list of known projects, the last used server, and the
    /// last opened project.
    ///
    /// Port of the package-private `updatePreferences()`.
    pub(crate) fn update_preferences(&self) {
        self.set_project_list_property(&self.recently_opened_projects, RECENT_PROJECTS);
        self.set_project_list_property(&self.recently_viewed_projects, VIEWED_PROJECTS);
        if let Some(server_info) = &self.server_info {
            self.preferences.set_property(
                SERVER_INFO,
                &format!("{}:{}", server_info.server_name(), server_info.port_number()),
            );
        }

        let value = self.last_opened_project.as_deref().unwrap_or(PROJECT_CLOSED_BY_USER_VALUE);
        self.preferences.set_property(LAST_OPENED_PROJECT, value);

        self.preferences.store();
    }

    /// Adds the default tools to the given tool chest. Unlike the tool chest built by
    /// [`create_default_user_tool_chest`](Self::create_default_user_tool_chest), this does not
    /// attempt to merge the user's previous tools.
    ///
    /// Port of `addDefaultTools(ToolChest)`; an associated function since the Java method reads no
    /// instance state, only the `ToolUtils` statics that are a parameter here.
    pub fn add_default_tools(tool_utils: &dyn ToolUtils, tool_chest: &mut dyn ToolChest) {
        let tools = tool_utils.get_default_application_tools();
        if tools.is_empty() {
            Msg::show_error(
                LOG,
                "Default Tools Not Found",
                &"Could not find default tools for project.",
            );
            return;
        }

        for mut template in tools {
            Self::add_default_tool(tool_chest, template.as_mut());
        }
    }

    /// Builds the user's tool chest, installing the default tools (merged with any tools found in
    /// the user's previous settings directory) when it comes up empty.
    ///
    /// Port of `protected ToolChest createUserToolChest()`; the default body of
    /// [`DefaultProjectManager::create_user_tool_chest`].
    pub fn create_default_user_tool_chest(
        tool_utils: &dyn ToolUtils,
        run_info: &dyn GenericRunInfo,
    ) -> Box<dyn ToolChest> {
        let mut tool_chest: Box<dyn ToolChest> = Box::new(ToolChestImpl::new());
        if tool_chest.get_tool_count() == 0 {
            Self::install_tools(tool_utils, run_info, tool_chest.as_mut());
        }
        tool_chest
    }

    /// Port of the private `installTools(ToolChest)`.
    fn install_tools(
        tool_utils: &dyn ToolUtils,
        run_info: &dyn GenericRunInfo,
        tool_chest: &mut dyn ToolChest,
    ) {
        Msg::debug(LOG, &"No tools found; Installing default tools");

        let Some(recovery_directory) = Self::most_recent_valid_project_directory(run_info) else {
            Msg::debug(LOG, &"\tno recent project directories found");
            Self::add_default_tools(tool_utils, tool_chest);
            return;
        };

        // get old tools
        let tools = tool_utils.get_default_application_tools();
        if tools.is_empty() {
            Msg::show_error(
                LOG,
                "Default Tools Not Found",
                &"Could not find default tools for project.",
            );
            return;
        }

        // get the user's existing tools, adding any default tools they don't have
        let pre_existing = Self::pre_existing_user_tools(tool_utils, Some(&recovery_directory));
        for mut template in Self::merge_default_tools_into_existing(tools, pre_existing) {
            Self::add_default_tool(tool_chest, template.as_mut());
        }
    }

    /// Port of the private `getMostRecentValidProjectDirectory()`.
    fn most_recent_valid_project_directory(run_info: &dyn GenericRunInfo) -> Option<PathBuf> {
        // get the tools from the most recent projects first
        for user_dir in run_info.get_previous_application_settings_dirs_by_time() {
            let Ok(entries) = fs::read_dir(&user_dir) else {
                continue; // empty ghidra dir
            };
            for entry in entries.flatten() {
                if entry.file_name() == APPLICATION_TOOLS_DIR_NAME {
                    return Some(user_dir); // found a tools dir; move on
                }
            }
        }
        None
    }

    /// Port of the private `mergeDefaultToolsIntoExisting(Set, Set)`. Java merges through a
    /// `HashMap` keyed by tool name; a [`BTreeMap`] is used instead so the resulting order is
    /// stable.
    fn merge_default_tools_into_existing(
        default_tools: Vec<Box<dyn ToolTemplate>>,
        user_tools: Vec<Box<dyn ToolTemplate>>,
    ) -> Vec<Box<dyn ToolTemplate>> {
        if user_tools.is_empty() {
            // no previous tools--use default tools
            return default_tools;
        }

        let mut all_tools: BTreeMap<String, Box<dyn ToolTemplate>> = BTreeMap::new();
        for template in default_tools {
            all_tools.insert(template.get_name(), template);
        }
        // user tools last, overwriting the defaults; they are preferred
        for template in user_tools {
            all_tools.insert(template.get_name(), template);
        }

        all_tools.into_values().collect()
    }

    /// Port of the private `saveTool(ToolTemplate)`. Java turns the written file into a `URL`;
    /// the path itself is returned here, matching how the rest of this crate carries file
    /// locations.
    fn save_tool(tool_utils: &dyn ToolUtils, template: &dyn ToolTemplate) -> Option<PathBuf> {
        if !tool_utils.write_tool_template(template) {
            return None;
        }
        tool_utils.get_tool_file(&template.get_name())
    }

    /// Gets the tools from the user's last project.
    ///
    /// Port of the private `getPreExistingUserTools(File)`.
    fn pre_existing_user_tools(
        tool_utils: &dyn ToolUtils,
        previous_user_dir: Option<&Path>,
    ) -> Vec<Box<dyn ToolTemplate>> {
        let Some(previous_user_dir) = previous_user_dir else {
            return Vec::new();
        };

        let tool_dirs: Vec<PathBuf> = read_dir_sorted(previous_user_dir)
            .into_iter()
            .filter(|path| path.is_dir() && ends_with_name(path, APPLICATION_TOOLS_DIR_NAME))
            .collect();
        if tool_dirs.len() != 1 {
            Msg::debug(LOG, &format!("No user tools found in '{}'", previous_user_dir.display()));
            return Vec::new();
        }

        let tools_dir = &tool_dirs[0];
        let mut tools = Vec::new();
        for tool_file in read_dir_sorted(tools_dir)
            .into_iter()
            .filter(|path| path.to_string_lossy().ends_with(APPLICATION_TOOL_EXTENSION))
        {
            if let Some(template) = tool_utils.read_tool_template(&tool_file) {
                Self::scrub_user_tool(tool_utils, template.as_ref());
                tools.push(template);
            }
        }

        tools
    }

    /// Port of the private `scrubUserTool(ToolTemplate)`. Java wraps the save in a `try`/`catch`
    /// that logs whatever the save threw; nothing in the [`ToolUtils`] seam can fail that way, so
    /// there is no counterpart to the catch block.
    fn scrub_user_tool(tool_utils: &dyn ToolUtils, template: &dyn ToolTemplate) {
        tool_utils.remove_invalid_plugins(template);
        Self::save_tool(tool_utils, template);
    }

    /// Port of the private `addDefaultTool(ToolChest, ToolTemplate)`.
    fn add_default_tool(tool_chest: &mut dyn ToolChest, template: &mut dyn ToolTemplate) {
        let name = template.get_name();

        // this implies that there exist multiple *default* tools with the same name, which
        // is an error condition.
        if tool_chest.get_tool_template(&name).is_some() {
            Msg::show_warn(
                LOG,
                "Error Adding Tool",
                &format!(
                    "Found multiple default tools with the same name: {name}.\nCheck the \
                     classpath for entries that contain tools that share the same tool name"
                ),
            );
        }

        // Note: we call replace here and not add, since we know that we want to put a new tool
        //       in by the given name.  At this point we can assume there are not yet any
        //       tools to overwrite, since this method is only called when no tools existed and
        //       we are adding the default set.
        tool_chest.replace_tool_template(template);
    }

    /// Removes the project from the list of known projects.
    ///
    /// Port of the private `forgetProject(ProjectLocator)`; the Java null check is expressed by
    /// the caller having a URL to pass at all.
    fn forget_project(&mut self, project_url: &str) {
        if self.last_opened_project.as_deref() == Some(project_url) {
            self.last_opened_project = None;
        }
        self.recently_opened_projects.retain(|url| url != project_url);
        self.update_preferences();
    }

    /// Adds the project to the given list; most recently accessed projects are first in the list.
    ///
    /// Port of the private `addProjectToList(List, ProjectLocator)`.
    fn add_project_to_list(list: &mut Vec<String>, project_locator: &dyn ProjectLocator) -> bool {
        if !project_locator.get_marker_file().exists() {
            return false;
        }
        if !project_locator.get_project_dir().exists() {
            return false;
        }
        let url = project_locator.url();
        list.retain(|known| *known != url);
        list.insert(0, url);
        if list.len() > RECENT_PROJECTS_LIMIT {
            list.pop();
        }
        true
    }

    /// Port of the private `populateProjectLocatorList(List, String)`.
    fn populate_project_locator_list(&mut self, property_name: &str) {
        let Some(project_names) = self.preferences.get_property(property_name, None, true) else {
            return;
        };

        // TODO: fixed pathSeparator should be used to allow preferences to be more portable
        // between platforms
        for path in project_names.split(PROJECT_PATH_SEPARATOR).filter(|s| !s.is_empty()) {
            if let Some(project_locator) = self.get_locator_from_project_path(path) {
                self.recently_opened_projects.push(project_locator.url());
                if self.recently_opened_projects.len() == RECENT_PROJECTS_LIMIT {
                    break;
                }
            }
        }
    }

    /// Port of the private `getLocatorFromProjectPath(String)`.
    fn get_locator_from_project_path(&self, path: &str) -> Option<Box<dyn ProjectLocator>> {
        match self.ghidra_url.to_url(path) {
            Ok(url) => {
                if self.ghidra_url.local_project_exists(&url) {
                    return self.ghidra_url.get_project_storage_locator(&url).ok().flatten();
                }
                None
            }
            Err(e) => {
                Msg::error_with_error(LOG, &format!("Invalid project path: {path}"), &e);
                None
            }
        }
    }

    /// Port of the private `populateProjectURLList(List, String)`.
    fn populate_project_url_list(&mut self, property_name: &str) {
        let Some(project_names) = self.preferences.get_property(property_name, None, true) else {
            return;
        };

        for url_str in project_names.split(PROJECT_PATH_SEPARATOR).filter(|s| !s.is_empty()) {
            match self.ghidra_url.to_url(url_str) {
                Ok(url) => {
                    if self.ghidra_url.is_local_url(&url)
                        && !self.ghidra_url.local_project_exists(&url)
                    {
                        continue;
                    }
                    self.recently_viewed_projects.push(url);
                    if self.recently_viewed_projects.len() == RECENT_PROJECTS_LIMIT {
                        break;
                    }
                }
                Err(_) => {
                    Msg::error(LOG, &format!("Invalid project path/URL: {url_str}"));
                }
            }
        }
    }

    /// Port of the private `setProjectLocatorProperty`/`setProjectURLProperty` pair, which differ
    /// in Java only by whether they call `ProjectLocator.toString()` or `URL.toExternalForm()` on
    /// each entry; both lists already hold those strings here.
    fn set_project_list_property(&self, list: &[String], property_name: &str) {
        self.preferences.set_property(property_name, &list.join(PROJECT_PATH_SEPARATOR));
    }
}

/// The behaviour a concrete project manager may still override.
///
/// Port of the overridable part of `ghidra.framework.project.DefaultProjectManager`: the shared
/// state and every concrete member live on [`DefaultProjectManagerBase`], which an implementor
/// embeds and forwards [`ProjectManager`] to.
pub trait DefaultProjectManager: ProjectManager {
    /// Builds the tool chest this manager hands out as the user's tool chest.
    ///
    /// Port of `protected ToolChest createUserToolChest()`. Java calls this from the constructor,
    /// before the manager exists, so this is an associated function taking the two seams the
    /// default body needs rather than a `&self` member. The default body is Java's:
    /// [`DefaultProjectManagerBase::create_default_user_tool_chest`].
    fn create_user_tool_chest(
        tool_utils: &dyn ToolUtils,
        run_info: &dyn GenericRunInfo,
    ) -> Box<dyn ToolChest>
    where
        Self: Sized,
    {
        DefaultProjectManagerBase::create_default_user_tool_chest(tool_utils, run_info)
    }
}

impl DefaultProjectManager for DefaultProjectManagerBase {}

impl ProjectManager for DefaultProjectManagerBase {
    fn create_project(
        &mut self,
        project_locator: &dyn ProjectLocator,
        rep_adapter: Option<&dyn RepositoryAdapter>,
        remember: bool,
    ) -> io::Result<Box<dyn Project>> {
        if self.current_project.is_some() {
            let msg = "Current project must be closed before establishing a new active project";
            Msg::error(LOG, &msg);
            // Java returns null here; `io::Result` has no such value, so the logged message is
            // handed back as the error instead.
            return Err(io::Error::new(io::ErrorKind::Other, msg));
        }

        let marker_file = project_locator.get_marker_file();
        let marker_parent = marker_file.parent().map(Path::to_path_buf).unwrap_or_default();
        if !marker_parent.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("Directory not found: {}", marker_parent.display()),
            ));
        }

        let project = self
            .project_factory
            .create(project_locator, rep_adapter)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        let handle = ProjectHandle(Rc::new(RefCell::new(project)));
        self.current_project = Some(handle.clone());

        if remember {
            Self::add_project_to_list(&mut self.recently_opened_projects, project_locator);
            self.last_opened_project = Some(project_locator.url());
            self.update_preferences();
        }

        self.app_info.set_active_project(&handle);
        Ok(Box::new(handle))
    }

    fn get_recent_projects(&self) -> Vec<Box<dyn ProjectLocator>> {
        self.recently_opened_projects
            .iter()
            .filter_map(|url| self.get_locator_from_project_path(url))
            .collect()
    }

    fn get_recent_viewed_projects(&self) -> Vec<String> {
        self.recently_viewed_projects.clone()
    }

    fn get_active_project(&self) -> Option<Box<dyn Project>> {
        self.current_project.clone().map(|handle| Box::new(handle) as Box<dyn Project>)
    }

    fn get_last_opened_project(&self) -> Option<Box<dyn ProjectLocator>> {
        let project_path = self.preferences.get_property(LAST_OPENED_PROJECT, None, true)?;
        if project_path.trim().is_empty() {
            return None;
        }

        if project_path == PROJECT_CLOSED_BY_USER_VALUE {
            return None;
        }

        self.get_locator_from_project_path(&project_path)
    }

    fn set_last_opened_project(&mut self, project_locator: Option<&dyn ProjectLocator>) {
        let value = project_locator
            .map(|locator| locator.url())
            .unwrap_or_else(|| PROJECT_CLOSED_BY_USER_VALUE.to_string());

        self.preferences.set_property(LAST_OPENED_PROJECT, &value);
        self.preferences.store();
    }

    fn remember_project(&mut self, project_locator: &dyn ProjectLocator) {
        if !self.recently_opened_projects.contains(&project_locator.url()) {
            Self::add_project_to_list(&mut self.recently_opened_projects, project_locator);
            self.update_preferences();
        }
    }

    fn remember_viewed_project(&mut self, url: &str) {
        if !self.recently_viewed_projects.iter().any(|known| known == url) {
            self.recently_viewed_projects.insert(0, url.to_string());
            if self.recently_viewed_projects.len() > RECENT_PROJECTS_LIMIT {
                self.recently_viewed_projects.pop();
            }
            self.update_preferences();
        }
    }

    fn forget_viewed_project(&mut self, url: &str) {
        self.recently_viewed_projects.retain(|known| known != url);
        self.update_preferences();
    }

    fn open_project(
        &mut self,
        project_locator: &dyn ProjectLocator,
        do_restore: bool,
        reset_owner: bool,
    ) -> Result<Box<dyn Project>, OpenProjectError> {
        if self.current_project.is_some() {
            let msg = "Current project must be closed before establishing a new active project";
            Msg::error(LOG, &msg);
            return Err(OpenProjectError::Lock(
                crate::framework::store::LockException::new(msg),
            ));
        }

        let project = match self.project_factory.open(project_locator, reset_owner) {
            Ok(project) => project,
            Err(e) => {
                // Java's `ReadOnlyException` branch has no counterpart: it is an `IOException`
                // subclass, and `OpenProjectError` folds every `IOException` into one variant.
                if let OpenProjectError::Io(io_error) = &e {
                    Msg::show_error_with_error(
                        LOG,
                        "Open Project Failed!",
                        &format!(
                            "Could not open project {}\n \nCAUSE: {io_error}",
                            project_locator.url()
                        ),
                        io_error,
                    );
                }
                // Java's `finally` block: the project never opened, so forget it if its
                // directory is gone.
                let dir_file = project_locator.get_project_dir();
                if !dir_file.exists() || !dir_file.is_dir() {
                    self.forget_project(&project_locator.url());
                }
                return Err(e);
            }
        };

        let mut handle = ProjectHandle(Rc::new(RefCell::new(project)));
        self.current_project = Some(handle.clone());
        self.app_info.set_active_project(&handle);
        if do_restore {
            handle.restore();
        }
        // success
        Self::add_project_to_list(&mut self.recently_opened_projects, project_locator);
        self.last_opened_project = Some(project_locator.url());
        self.update_preferences();
        Ok(Box::new(handle))
    }

    /// Deletes the project in the given location and removes it from the list of known projects;
    /// returns false if no project was deleted.
    ///
    /// # Panics
    /// Panics when the project directory does not exist, standing in for the unchecked
    /// `RuntimeException` the Java method throws in that case.
    fn delete_project(&mut self, project_locator: &dyn ProjectLocator) -> bool {
        let dir = project_locator.get_project_dir();
        let file = project_locator.get_marker_file();
        if !dir.exists() {
            panic!("{} does not exist", file.display());
        }
        if !dir.is_dir() {
            return false;
        }

        let did_delete = fs::remove_dir_all(&dir).is_ok()
            && (!file.exists() || fs::remove_file(&file).is_ok());
        self.forget_project(&project_locator.url());
        did_delete
    }

    fn project_exists(&self, project_locator: &dyn ProjectLocator) -> bool {
        project_locator.get_project_dir().exists()
    }

    fn get_repository_server_adapter(
        &mut self,
        host: &str,
        port_number: i32,
        force_connect: bool,
    ) -> Box<dyn RepositoryServerAdapter> {
        let rsh = self.client_util.get_repository_server(host, port_number, force_connect);
        self.server_info = rsh.get_server_info();
        self.update_preferences();
        rsh
    }

    fn get_most_recent_server_info(&self) -> Option<ServerInfo> {
        self.server_info.clone()
    }

    fn get_user_tool_chest(&self) -> Box<dyn ToolChest> {
        Box::new(self.user_tool_chest())
    }
}

/// Port of the private `getServerInfo(String)`: splits `host:port` and returns `None` for anything
/// that does not parse.
fn parse_server_info(str: Option<&str>) -> Option<ServerInfo> {
    let str = str?;
    let mut host = None;
    let mut port_str = None;

    for token in str.split(':').filter(|token| !token.is_empty()) {
        if host.is_none() {
            host = Some(token);
        } else {
            port_str = Some(token);
        }
    }

    match (host, port_str) {
        (Some(host), Some(port_str)) => {
            // Java catches NumberFormatException and returns null; an out-of-range port is
            // rejected the same way here.
            port_str.parse::<u16>().ok().map(|port| ServerInfo::new(host, port))
        }
        _ => None,
    }
}

/// The entries of `dir` in name order, or nothing at all when it cannot be read -- standing in for
/// the `File[]` (possibly `null`) that `File.listFiles()` hands back.
fn read_dir_sorted(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut paths: Vec<PathBuf> = entries.flatten().map(|entry| entry.path()).collect();
    paths.sort();
    paths
}

fn ends_with_name(path: &Path, name: &str) -> bool {
    path.file_name().is_some_and(|file_name| file_name == name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::seam_stubs::GhidraUrlHandlerLike;
    use std::collections::HashMap;

    /// Project locator over a real directory: `<location>/<name>.gpr` marker file next to a
    /// `<location>/<name>.rep` project directory, which is the layout
    /// [`ProjectLocator`] describes.
    struct TestLocator {
        name: String,
        location: PathBuf,
    }

    impl TestLocator {
        fn new(location: &Path, name: &str) -> Self {
            Self { name: name.to_string(), location: location.to_path_buf() }
        }

        /// Creates the marker file and project directory on disk.
        fn create_storage(&self) {
            fs::create_dir_all(self.get_project_dir()).unwrap();
            fs::write(self.get_marker_file(), "").unwrap();
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

    /// `GhidraURL` double that understands the `ghidra://<location>/<name>` URLs [`TestLocator`]
    /// produces, and answers `localProjectExists` from the filesystem.
    struct TestGhidraUrl;

    impl TestGhidraUrl {
        fn locator_of(url: &str) -> Option<TestLocator> {
            let rest = url.strip_prefix("ghidra://")?;
            let (location, name) = rest.rsplit_once('/')?;
            Some(TestLocator::new(Path::new(location), name))
        }
    }

    impl GhidraURL for TestGhidraUrl {
        fn make_project_locator(&self, dir_path: &str, project_name: &str) -> Box<dyn ProjectLocator> {
            Box::new(TestLocator::new(Path::new(dir_path), project_name))
        }

        fn handler(&self) -> Box<dyn GhidraUrlHandlerLike> {
            unimplemented!("no URL handler is needed by these tests")
        }

        fn to_url(&self, project_path_or_url: &str) -> io::Result<String> {
            if Self::locator_of(project_path_or_url).is_some() {
                return Ok(project_path_or_url.to_string());
            }
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("not a project path: {project_path_or_url}"),
            ))
        }

        fn is_local_url(&self, str: &str) -> bool {
            str.starts_with("ghidra://")
        }

        fn local_project_exists(&self, url: &str) -> bool {
            Self::locator_of(url).is_some_and(|locator| locator.exists())
        }

        fn get_project_storage_locator(
            &self,
            local_project_url: &str,
        ) -> io::Result<Option<Box<dyn ProjectLocator>>> {
            Ok(Self::locator_of(local_project_url)
                .map(|locator| Box::new(locator) as Box<dyn ProjectLocator>))
        }
    }

    /// In-memory `Preferences` that also counts the flushes, standing in for the properties file.
    #[derive(Default)]
    struct TestPreferences {
        properties: RefCell<HashMap<String, String>>,
        stores: RefCell<u32>,
    }

    impl TestPreferences {
        fn with(entries: &[(&str, &str)]) -> Rc<Self> {
            let prefs = Self::default();
            for (name, value) in entries {
                prefs.properties.borrow_mut().insert(name.to_string(), value.to_string());
            }
            Rc::new(prefs)
        }

        fn get(&self, name: &str) -> Option<String> {
            self.properties.borrow().get(name).cloned()
        }
    }

    impl PreferencesLike for TestPreferences {
        fn get_property(
            &self,
            name: &str,
            default_value: Option<&str>,
            _use_historical_value: bool,
        ) -> Option<String> {
            self.properties
                .borrow()
                .get(name)
                .cloned()
                .or_else(|| default_value.map(str::to_string))
        }

        fn set_property(&self, name: &str, value: &str) {
            self.properties.borrow_mut().insert(name.to_string(), value.to_string());
        }

        fn store(&self) -> bool {
            *self.stores.borrow_mut() += 1;
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

    /// Records the projects handed to `AppInfo.setActiveProject`.
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
    struct TestTransientDataManager {
        cleared: RefCell<u32>,
    }

    impl TransientDataManager for TestTransientDataManager {
        fn clear_all(&self) {
            *self.cleared.borrow_mut() += 1;
        }
    }

    struct TestProject {
        name: String,
        restores: Rc<std::cell::Cell<u32>>,
    }

    impl Project for TestProject {
        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn restore(&mut self) {
            self.restores.set(self.restores.get() + 1);
        }
    }

    impl DefaultProject for TestProject {}

    /// Project factory whose `open` can be told to fail, standing in for the two `DefaultProject`
    /// constructors.
    #[derive(Default)]
    struct TestProjectFactory {
        open_failure: Option<io::ErrorKind>,
        restores: Rc<std::cell::Cell<u32>>,
    }

    impl DefaultProjectFactory for TestProjectFactory {
        fn create(
            &self,
            project_locator: &dyn ProjectLocator,
            _repository: Option<&dyn RepositoryAdapter>,
        ) -> Result<Box<dyn DefaultProject>, crate::framework::seam_stubs::CreateProjectError>
        {
            Ok(Box::new(TestProject {
                name: project_locator.get_name(),
                restores: Rc::clone(&self.restores),
            }))
        }

        fn open(
            &self,
            project_locator: &dyn ProjectLocator,
            _reset_owner: bool,
        ) -> Result<Box<dyn DefaultProject>, OpenProjectError> {
            match self.open_failure {
                Some(kind) => {
                    Err(OpenProjectError::Io(io::Error::new(kind, "cannot open project")))
                }
                None => Ok(Box::new(TestProject {
                    name: project_locator.get_name(),
                    restores: Rc::clone(&self.restores),
                })),
            }
        }
    }

    struct TestToolTemplate {
        name: String,
    }

    impl ToolTemplate for TestToolTemplate {
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
            unimplemented!("icons are not exercised by these tests")
        }

        fn get_icon(&self) -> Box<dyn crate::framework::seam_stubs::ImageIcon> {
            unimplemented!("icons are not exercised by these tests")
        }

        fn get_supported_data_types(&self) -> Vec<String> {
            Vec::new()
        }

        fn save_to_xml(&self) -> Box<dyn crate::framework::seam_stubs::JdomElement> {
            unimplemented!("XML is not exercised by these tests")
        }

        fn restore_from_xml(&mut self, _root: &dyn crate::framework::seam_stubs::JdomElement) {}

        fn create_tool(
            &self,
            _project: &dyn Project,
        ) -> Box<dyn crate::framework::seam_stubs::PluginTool> {
            unimplemented!("tools are not exercised by these tests")
        }

        fn get_tool_element(&self) -> Box<dyn crate::framework::seam_stubs::JdomElement> {
            unimplemented!("XML is not exercised by these tests")
        }
    }

    struct TestToolUtils {
        default_tool_names: Vec<String>,
    }

    impl ToolUtils for TestToolUtils {
        fn get_default_application_tools(&self) -> Vec<Box<dyn ToolTemplate>> {
            self.default_tool_names
                .iter()
                .map(|name| {
                    Box::new(TestToolTemplate { name: name.clone() }) as Box<dyn ToolTemplate>
                })
                .collect()
        }

        fn remove_invalid_plugins(&self, _template: &dyn ToolTemplate) {}

        fn write_tool_template(&self, _template: &dyn ToolTemplate) -> bool {
            true
        }

        fn read_tool_template(&self, _tool_file: &Path) -> Option<Box<dyn ToolTemplate>> {
            None
        }

        fn get_tool_file(&self, name: &str) -> Option<PathBuf> {
            Some(PathBuf::from(format!("/tools/{name}.tcd")))
        }
    }

    struct Fixture {
        preferences: Rc<TestPreferences>,
        app_info: Rc<TestAppInfo>,
        transient_data: Rc<TestTransientDataManager>,
        restores: Rc<std::cell::Cell<u32>>,
        manager: DefaultProjectManagerBase,
    }

    fn fixture(preferences: Rc<TestPreferences>, factory: TestProjectFactory) -> Fixture {
        let app_info = Rc::new(TestAppInfo::default());
        let transient_data = Rc::new(TestTransientDataManager::default());
        let restores = Rc::clone(&factory.restores);
        let manager = DefaultProjectManagerBase::new(
            Rc::clone(&preferences) as Rc<dyn PreferencesLike>,
            Rc::new(TestGhidraUrl),
            Rc::new(TestClientUtil),
            Rc::clone(&app_info) as Rc<dyn AppInfo>,
            Rc::clone(&transient_data) as Rc<dyn TransientDataManager>,
            Rc::new(factory),
            Box::new(ToolChestImpl::new()),
        );
        Fixture { preferences, app_info, transient_data, restores, manager }
    }

    #[test]
    fn constructor_reads_known_projects_back_out_of_preferences() {
        let dir = tempfile::tempdir().unwrap();
        let alpha = TestLocator::new(dir.path(), "Alpha");
        let beta = TestLocator::new(dir.path(), "Beta");
        alpha.create_storage();
        beta.create_storage();
        let gone = TestLocator::new(dir.path(), "Gone");

        let recent = [alpha.url(), gone.url(), beta.url()].join(";");
        let prefs = TestPreferences::with(&[
            (RECENT_PROJECTS, recent.as_str()),
            (VIEWED_PROJECTS, recent.as_str()),
            (LAST_OPENED_PROJECT, alpha.url().as_str()),
        ]);

        let f = fixture(prefs, TestProjectFactory::default());

        // A project whose storage is gone is dropped from the recent list, as
        // getLocatorFromProjectPath's localProjectExists check does in Java...
        let names: Vec<String> =
            f.manager.get_recent_projects().iter().map(|l| l.get_name()).collect();
        assert_eq!(names, vec!["Alpha".to_string(), "Beta".to_string()]);

        // ...but the viewed list keeps non-local URLs and only drops local ones that are gone.
        assert_eq!(f.manager.get_recent_viewed_projects(), vec![alpha.url(), beta.url()]);

        assert_eq!(f.manager.get_last_opened_project().map(|l| l.get_name()), Some("Alpha".into()));

        // The constructor rewrites the preferences with the pruned lists.
        assert_eq!(
            f.preferences.get(RECENT_PROJECTS),
            Some([alpha.url(), beta.url()].join(";"))
        );
    }

    #[test]
    fn remembering_projects_keeps_the_six_most_recent_newest_first() {
        let dir = tempfile::tempdir().unwrap();
        let f = &mut fixture(TestPreferences::with(&[]), TestProjectFactory::default());

        let locators: Vec<TestLocator> = (0..8)
            .map(|i| {
                let locator = TestLocator::new(dir.path(), &format!("P{i}"));
                locator.create_storage();
                locator
            })
            .collect();
        for locator in &locators {
            f.manager.remember_project(locator);
        }

        let names: Vec<String> =
            f.manager.get_recent_projects().iter().map(|l| l.get_name()).collect();
        assert_eq!(names, vec!["P7", "P6", "P5", "P4", "P3", "P2"]);

        // Re-remembering a known project is a no-op, matching the Java contains() guard.
        f.manager.remember_project(&locators[7]);
        assert_eq!(f.manager.get_recent_projects().len(), 6);
    }

    #[test]
    fn projects_without_storage_are_not_remembered() {
        let dir = tempfile::tempdir().unwrap();
        let f = &mut fixture(TestPreferences::with(&[]), TestProjectFactory::default());

        // addProjectToList requires both the marker file and the project directory to exist.
        let no_storage = TestLocator::new(dir.path(), "Missing");
        f.manager.remember_project(&no_storage);
        assert!(f.manager.get_recent_projects().is_empty());

        fs::write(no_storage.get_marker_file(), "").unwrap();
        f.manager.remember_project(&no_storage);
        assert!(f.manager.get_recent_projects().is_empty());
    }

    #[test]
    fn set_last_opened_project_records_the_closed_marker_for_none() {
        let dir = tempfile::tempdir().unwrap();
        let locator = TestLocator::new(dir.path(), "Alpha");
        locator.create_storage();
        let f = &mut fixture(TestPreferences::with(&[]), TestProjectFactory::default());

        f.manager.set_last_opened_project(Some(&locator));
        assert_eq!(f.preferences.get(LAST_OPENED_PROJECT), Some(locator.url()));
        assert_eq!(f.manager.get_last_opened_project().map(|l| l.get_name()), Some("Alpha".into()));

        f.manager.set_last_opened_project(None);
        assert_eq!(
            f.preferences.get(LAST_OPENED_PROJECT),
            Some(PROJECT_CLOSED_BY_USER_VALUE.to_string())
        );
        assert!(f.manager.get_last_opened_project().is_none());
    }

    #[test]
    fn most_recent_server_info_is_parsed_from_the_preference() {
        let f = fixture(
            TestPreferences::with(&[(SERVER_INFO, "ghidra-server.example.com:13100")]),
            TestProjectFactory::default(),
        );
        assert_eq!(
            f.manager.get_most_recent_server_info(),
            Some(ServerInfo::new("ghidra-server.example.com", 13100))
        );

        // A value without a port, or with an unparsable one, yields no server info at all.
        for bad in ["localhost", "localhost:not-a-port", "localhost:99999"] {
            let f = fixture(
                TestPreferences::with(&[(SERVER_INFO, bad)]),
                TestProjectFactory::default(),
            );
            assert!(f.manager.get_most_recent_server_info().is_none(), "{bad} should not parse");
        }
    }

    #[test]
    fn connecting_to_a_server_records_it_in_the_preferences() {
        let f = &mut fixture(TestPreferences::with(&[]), TestProjectFactory::default());

        let _rsh = f.manager.get_repository_server_adapter("myhost", 13100, true);

        assert_eq!(f.manager.get_most_recent_server_info(), Some(ServerInfo::new("myhost", 13100)));
        assert_eq!(f.preferences.get(SERVER_INFO), Some("myhost:13100".to_string()));
    }

    #[test]
    fn viewed_projects_cap_at_six_and_can_be_forgotten() {
        let f = &mut fixture(TestPreferences::with(&[]), TestProjectFactory::default());

        for i in 0..7 {
            f.manager.remember_viewed_project(&format!("ghidra://server/repo{i}"));
        }

        assert_eq!(
            f.manager.get_recent_viewed_projects(),
            (1..7).rev().map(|i| format!("ghidra://server/repo{i}")).collect::<Vec<_>>()
        );
        assert_eq!(
            f.preferences.get(VIEWED_PROJECTS),
            Some(f.manager.get_recent_viewed_projects().join(";"))
        );

        f.manager.forget_viewed_project("ghidra://server/repo6");
        assert!(!f
            .manager
            .get_recent_viewed_projects()
            .contains(&"ghidra://server/repo6".to_string()));
    }

    #[test]
    fn creating_a_project_activates_it_and_blocks_a_second_one() {
        let dir = tempfile::tempdir().unwrap();
        let locator = TestLocator::new(dir.path(), "Alpha");
        locator.create_storage();
        let f = &mut fixture(TestPreferences::with(&[]), TestProjectFactory::default());

        let project = f.manager.create_project(&locator, None, true).expect("create succeeds");
        assert_eq!(project.get_name(), "Alpha");
        assert_eq!(f.app_info.activated.borrow().as_slice(), ["Alpha".to_string()]);
        assert_eq!(f.manager.get_active_project().map(|p| p.get_name()), Some("Alpha".into()));
        assert_eq!(f.preferences.get(LAST_OPENED_PROJECT), Some(locator.url()));
        assert_eq!(f.restores.get(), 0, "createProject never restores");

        // Java logs and returns null when a project is already open.
        let second = TestLocator::new(dir.path(), "Beta");
        second.create_storage();
        let Err(err) = f.manager.create_project(&second, None, true) else {
            panic!("a second project must not be created while one is open");
        };
        assert!(err.to_string().contains("must be closed"), "{err}");
    }

    #[test]
    fn creating_a_project_requires_the_parent_directory_to_exist() {
        let dir = tempfile::tempdir().unwrap();
        let locator = TestLocator::new(&dir.path().join("no-such-dir"), "Alpha");
        let f = &mut fixture(TestPreferences::with(&[]), TestProjectFactory::default());

        let Err(err) = f.manager.create_project(&locator, None, true) else {
            panic!("a project cannot be created under a missing directory");
        };
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        assert!(err.to_string().starts_with("Directory not found: "), "{err}");
    }

    #[test]
    fn opening_a_project_restores_it_and_remembers_it() {
        let dir = tempfile::tempdir().unwrap();
        let locator = TestLocator::new(dir.path(), "Alpha");
        locator.create_storage();
        let f = &mut fixture(TestPreferences::with(&[]), TestProjectFactory::default());

        let project = f.manager.open_project(&locator, true, false).expect("open succeeds");
        assert_eq!(project.get_name(), "Alpha");
        assert_eq!(f.restores.get(), 1, "doRestore=true restores the project");
        assert_eq!(f.app_info.activated.borrow().as_slice(), ["Alpha".to_string()]);
        assert_eq!(
            f.manager.get_recent_projects().iter().map(|l| l.get_name()).collect::<Vec<_>>(),
            vec!["Alpha".to_string()]
        );
        assert_eq!(f.preferences.get(LAST_OPENED_PROJECT), Some(locator.url()));
    }

    #[test]
    fn a_failed_open_forgets_a_project_whose_directory_is_gone() {
        let dir = tempfile::tempdir().unwrap();
        let locator = TestLocator::new(dir.path(), "Alpha");
        locator.create_storage();

        let prefs = TestPreferences::with(&[(RECENT_PROJECTS, locator.url().as_str())]);
        let f = &mut fixture(
            prefs,
            TestProjectFactory {
                open_failure: Some(io::ErrorKind::PermissionDenied),
                ..TestProjectFactory::default()
            },
        );
        assert_eq!(f.manager.get_recent_projects().len(), 1);

        // Storage still present: the project stays on the recent list.
        let Err(err) = f.manager.open_project(&locator, false, false) else {
            panic!("the factory was told to fail");
        };
        assert!(matches!(err, OpenProjectError::Io(_)), "{err}");
        assert_eq!(f.manager.get_recent_projects().len(), 1);

        // Storage gone: the failed open forgets it.
        fs::remove_dir_all(locator.get_project_dir()).unwrap();
        assert!(f.manager.open_project(&locator, false, false).is_err());
        assert!(f.manager.get_recent_projects().is_empty());
        assert_eq!(f.preferences.get(RECENT_PROJECTS), Some(String::new()));
    }

    #[test]
    fn deleting_a_project_removes_its_storage_and_forgets_it() {
        let dir = tempfile::tempdir().unwrap();
        let locator = TestLocator::new(dir.path(), "Alpha");
        locator.create_storage();
        let prefs = TestPreferences::with(&[
            (RECENT_PROJECTS, locator.url().as_str()),
            (LAST_OPENED_PROJECT, locator.url().as_str()),
        ]);
        let f = &mut fixture(prefs, TestProjectFactory::default());

        assert!(f.manager.project_exists(&locator));
        assert!(f.manager.delete_project(&locator));

        assert!(!locator.get_project_dir().exists());
        assert!(!locator.get_marker_file().exists());
        assert!(!f.manager.project_exists(&locator));
        assert!(f.manager.get_recent_projects().is_empty());
        assert_eq!(
            f.preferences.get(LAST_OPENED_PROJECT),
            Some(PROJECT_CLOSED_BY_USER_VALUE.to_string())
        );
    }

    #[test]
    #[should_panic(expected = "does not exist")]
    fn deleting_a_project_that_is_not_there_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let locator = TestLocator::new(dir.path(), "Nope");
        let f = &mut fixture(TestPreferences::with(&[]), TestProjectFactory::default());
        f.manager.delete_project(&locator);
    }

    #[test]
    fn closing_the_active_project_clears_it_and_the_transient_files() {
        let dir = tempfile::tempdir().unwrap();
        let locator = TestLocator::new(dir.path(), "Alpha");
        locator.create_storage();
        let f = &mut fixture(TestPreferences::with(&[]), TestProjectFactory::default());
        f.manager.create_project(&locator, None, true).expect("create succeeds");

        let active = f.manager.current_project.clone().expect("a project is open");
        f.manager.project_closed(&active);

        assert!(f.manager.get_active_project().is_none());
        assert_eq!(*f.transient_data.cleared.borrow(), 1);
    }

    #[test]
    fn default_tools_are_installed_into_an_empty_chest() {
        let tool_utils =
            TestToolUtils { default_tool_names: vec!["CodeBrowser".into(), "Debugger".into()] };
        let mut chest = ToolChestImpl::new();

        DefaultProjectManagerBase::add_default_tools(&tool_utils, &mut chest);

        assert_eq!(chest.get_tool_count(), 2);
        assert_eq!(chest.tool_names(), ["CodeBrowser".to_string(), "Debugger".to_string()]);
        assert!(chest.get_tool_template("CodeBrowser").is_some());

        // addDefaultTool replaces rather than adds, so a second pass does not duplicate anything.
        DefaultProjectManagerBase::add_default_tools(&tool_utils, &mut chest);
        assert_eq!(chest.get_tool_count(), 2);
    }

    #[test]
    fn the_user_tool_chest_is_shared_with_the_manager() {
        let f = &mut fixture(TestPreferences::with(&[]), TestProjectFactory::default());
        let tool_utils = TestToolUtils { default_tool_names: vec!["CodeBrowser".into()] };

        let mut chest = f.manager.get_user_tool_chest();
        assert_eq!(chest.get_tool_count(), 0);
        DefaultProjectManagerBase::add_default_tools(&tool_utils, chest.as_mut());

        // The handle wrote through to the manager's chest, as the Java field reference does.
        assert_eq!(f.manager.get_user_tool_chest().get_tool_count(), 1);
    }
}

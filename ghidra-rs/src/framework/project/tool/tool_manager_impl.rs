//! Port of `ghidra.framework.project.tool.ToolManagerImpl`.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::rc::Rc;
use std::sync::Arc;

use crate::framework::model::tool_manager::{DEFAULT_WORKSPACE_NAME, WORKSPACE_NAME_PROPERTY};
use crate::framework::model::{
    Project, ToolChest, ToolConnection, ToolManager, ToolTemplate, Workspace,
    WorkspaceChangeListener,
};
use crate::framework::seam_stubs::{
    GhidraTool, JdomElement, PluginTool, PropertyChangeEvent, SharedPluginTool, ToolConnectionImpl,
    WorkspaceImpl,
};
use crate::util::exception::DuplicateNameException;
use crate::util::msg::Msg;

/// Property name fired by `PluginTool` when its tool name changes
/// (`PluginTool.TOOL_NAME_PROPERTY`).
pub const TOOL_NAME_PROPERTY: &str = "ToolName";

/// Property name fired by `PluginTool` when a plugin is added to or removed from it
/// (`PluginTool.PLUGIN_COUNT_PROPERTY_NAME`).
pub const PLUGIN_COUNT_PROPERTY_NAME: &str = "PluginCount";

/// Whether saving a tool of a given name still happens silently, or has to be confirmed because
/// several instances of that tool are running and have diverged. Port of the private
/// `ToolManagerImpl.ToolSaveStatus` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ToolSaveStatus {
    AutoSaveMode,
    AskSaveMode,
}

/// What to do with a set of changed tools that share a tool name, as decided by whoever stands in
/// for Java's `SelectChangedToolDialog`.
///
/// Java pops that dialog on the front-end tool from inside `saveToolSet`; there is no UI at this
/// layer in Rust, so [`ToolManagerImpl::set_changed_tool_chooser`] injects the decision instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangedToolChoice {
    /// The user cancelled: `saveSessionTools` reports failure and the project is not closed.
    Cancelled,
    /// The user chose not to save any of the changed tools.
    SaveNone,
    /// Save the changed tool at this index in the slice handed to the chooser.
    Save(usize),
}

/// A live handle to one of a [`ToolManagerImpl`]'s workspaces.
///
/// [`ToolManager`] hands workspaces back as owned `Box<dyn Workspace>` where Java hands back the
/// workspace object itself, so the manager keeps its workspaces in `Rc<RefCell<..>>` and boxes
/// these handles: mutating through a handle mutates the manager's workspace, as it does in Java.
pub struct WorkspaceHandle(Rc<RefCell<WorkspaceImpl>>);

impl WorkspaceHandle {
    fn new(workspace: &Rc<RefCell<WorkspaceImpl>>) -> Self {
        Self(Rc::clone(workspace))
    }

    /// A handle to a workspace that belongs to no manager, used where Java would return `null`.
    fn detached(name: &str) -> Self {
        Self(Rc::new(RefCell::new(WorkspaceImpl::new(name))))
    }
}

impl Workspace for WorkspaceHandle {
    fn get_name(&self) -> String {
        self.0.borrow().name().to_string()
    }

    fn get_tools(&self) -> Vec<Box<dyn PluginTool>> {
        self.0.borrow().get_tools()
    }

    fn create_tool(&mut self) -> Box<dyn PluginTool> {
        self.0.borrow_mut().create_tool()
    }

    fn run_tool(&mut self, template: &dyn ToolTemplate) -> Box<dyn PluginTool> {
        self.0.borrow_mut().run_tool(template)
    }

    fn set_name(&mut self, new_name: &str) -> Result<(), DuplicateNameException> {
        self.0.borrow_mut().set_name(new_name)
    }

    fn set_active(&mut self) {
        self.0.borrow_mut().set_active();
    }
}

/// The event handed to [`WorkspaceChangeListener::property_change`]. `PropertyChangeEvent` is
/// still an opaque seam stub, so listeners cannot read these fields yet; they are carried anyway
/// so the data is already right when the stub grows accessors.
struct ToolManagerPropertyChange {
    #[allow(dead_code)]
    property_name: String,
    #[allow(dead_code)]
    old_value: Option<String>,
    #[allow(dead_code)]
    new_value: Option<String>,
}

impl PropertyChangeEvent for ToolManagerPropertyChange {}

/// Tool manager that knows about all the running tools for each workspace in the project; the
/// tool manager is responsible for launching new tools, and managing connections among tools.
///
/// Port of `ghidra.framework.project.tool.ToolManagerImpl`. Three shapes differ from the Java
/// class, all of them consequences of the `ToolManagerImpl` ⇄ `WorkspaceImpl`/`PluginTool`
/// dependency cycle that this type sits on:
///
/// * **The back-references are inverted.** Java's `WorkspaceImpl` holds its `ToolManagerImpl` and
///   calls up into it (`setActive`, `closeRunningTool`, `setName`), and a closing `PluginTool`
///   reaches the manager the same way. The [`WorkspaceImpl`] seam placeholder carries no such
///   back-reference, so the manager drives those transitions itself:
///   [`set_active_workspace`](Self::set_active_workspace), [`close_tool`](Self::close_tool) and
///   [`set_workspace_name`](Self::set_workspace_name) perform both halves.
/// * **The project is passed in, not held.** Java stores the `Project` that owns this manager;
///   holding it here would be a reference cycle, so the two members that need it
///   ([`get_tool`](Self::get_tool), [`get_tool_from_template`](Self::get_tool_from_template)) take
///   it as an argument.
/// * **`ToolServicesImpl` is not ported yet.** Java routes tool saving and the tool-chest lookup
///   through the `ToolServicesImpl` it constructs; until that class exists this manager holds the
///   project's [`ToolChest`] directly and saves tools through [`PluginTool::save_tool`], which is
///   what `ToolServicesImpl.saveTool` ultimately does. `getToolServices()` therefore has no
///   counterpart yet; [`tool_chest`](Self::tool_chest) exposes what it was used for.
///
/// Java's `wsMap` (workspace name → workspace) is dropped as well: it is a lookup cache over the
/// same handful of workspaces already in `workspaces`, and keeping both in sync through renames
/// buys nothing at this size.
pub struct ToolManagerImpl {
    tool_chest: Box<dyn ToolChest>,

    /// The workspaces in the project, in creation order.
    workspaces: Vec<Rc<RefCell<WorkspaceImpl>>>,
    /// Names of the workspaces that have added or removed a tool since the last save.
    changed_workspaces: BTreeSet<String>,

    /// Maps `producerName+consumerName` to the connection between that pair. Behind a `RefCell`
    /// because [`ToolManager::get_connection`] takes `&self` but creates the connection on first
    /// request, as Java's does.
    connect_map: RefCell<BTreeMap<String, ToolConnectionImpl>>,

    /// Maps a generic tool name to every running instance of that tool.
    names_map: HashMap<String, Vec<Arc<dyn PluginTool>>>,

    /// Name of the active workspace, made inactive when another workspace is made active.
    active_workspace: Option<String>,
    change_listeners: Vec<Box<dyn WorkspaceChangeListener>>,
    active_workspace_changed: bool,
    in_restore_mode: bool,

    tool_status_map: HashMap<String, ToolSaveStatus>,

    #[allow(clippy::type_complexity)]
    changed_tool_chooser: Option<Box<dyn FnMut(&[Arc<dyn PluginTool>]) -> ChangedToolChoice>>,
}

impl ToolManagerImpl {
    /// Creates a tool manager for the given project, taking the project's local tool chest.
    pub fn new(project: &dyn Project) -> Self {
        Self::with_tool_chest(project.get_local_tool_chest())
    }

    /// Creates a tool manager over an explicit tool chest. Java has no such constructor; it is the
    /// seam that lets a manager be built without a whole project, and is what
    /// [`new`](Self::new) delegates to.
    pub fn with_tool_chest(tool_chest: Box<dyn ToolChest>) -> Self {
        Self {
            tool_chest,
            workspaces: Vec::new(),
            changed_workspaces: BTreeSet::new(),
            connect_map: RefCell::new(BTreeMap::new()),
            names_map: HashMap::new(),
            active_workspace: None,
            change_listeners: Vec::new(),
            active_workspace_changed: false,
            in_restore_mode: false,
            tool_status_map: HashMap::new(),
            changed_tool_chooser: None,
        }
    }

    /// The tool chest this manager launches tools from.
    pub fn tool_chest(&self) -> &dyn ToolChest {
        self.tool_chest.as_ref()
    }

    /// Installs the callback that decides which of several changed instances of one tool to save;
    /// see [`ChangedToolChoice`]. With no chooser installed, that case saves nothing and reports
    /// success, since there is nobody to ask.
    pub fn set_changed_tool_chooser(
        &mut self,
        chooser: impl FnMut(&[Arc<dyn PluginTool>]) -> ChangedToolChoice + 'static,
    ) {
        self.changed_tool_chooser = Some(Box::new(chooser));
    }

    // ------------------------------------------------------------------
    // tool registration
    // ------------------------------------------------------------------

    /// Registers a new instance of a tool under `tool_name` and gives it a unique instance name.
    ///
    /// Java additionally registers the manager itself as the tool's `PropertyChangeListener`; here
    /// the tool cannot hold that back-reference, so callers report changes by calling
    /// [`property_change`](Self::property_change) directly.
    pub fn register_tool(&mut self, tool_name: &str, tool: Arc<dyn PluginTool>) {
        let list = self.names_map.entry(tool_name.to_string()).or_default();
        list.push(Arc::clone(&tool));

        if list.len() == 1 {
            // first tool, set the default status
            self.tool_status_map.insert(tool_name.to_string(), ToolSaveStatus::AutoSaveMode);
        }

        // make sure tools have unique names
        let instance_name = Self::generate_instance_name(&self.names_map[tool_name]);
        tool.put_instance_name(&instance_name);
    }

    /// Forgets a running instance of `tool_name`.
    pub fn deregister_tool(&mut self, tool_name: &str, tool: &Arc<dyn PluginTool>) {
        let Some(list) = self.names_map.get_mut(tool_name) else {
            Msg::error(
                "ToolManagerImpl",
                &format!("Attempted to remove tool that's not there: {tool_name}"),
            );
            return;
        };
        list.retain(|t| !Arc::ptr_eq(t, tool));
        if list.is_empty() {
            self.names_map.remove(tool_name);
            self.tool_status_map.remove(tool_name);
        }
    }

    /// Generates the one-up instance name for the tool just appended to `list`: empty for the
    /// first instance, `"2"` for the second, and one more than the previous instance after that.
    fn generate_instance_name(list: &[Arc<dyn PluginTool>]) -> String {
        if list.len() <= 1 {
            return String::new();
        }

        // the last one is the one that was just added
        let last_tool = &list[list.len() - 2];
        let instance_name = last_tool.get_instance_name();
        if instance_name.is_empty() {
            return "2".to_string();
        }
        match instance_name.parse::<i32>() {
            Ok(n) => (n + 1).to_string(),
            Err(_) => "2".to_string(),
        }
    }

    /// Every running instance of every tool, across all workspaces.
    pub fn running_tools(&self) -> Vec<Arc<dyn PluginTool>> {
        self.workspaces
            .iter()
            .flat_map(|ws| ws.borrow().tools().to_vec())
            .collect()
    }

    fn boxed(tools: Vec<Arc<dyn PluginTool>>) -> Vec<Box<dyn PluginTool>> {
        tools
            .into_iter()
            .map(|t| Box::new(SharedPluginTool::new(t)) as Box<dyn PluginTool>)
            .collect()
    }

    /// Looks up the shared handle for a tool this manager registered, matching on the tool's
    /// display name (the unique name [`register_tool`](Self::register_tool) establishes, and the
    /// same identity Java's connection keys use).
    fn find_tool(&self, name: &str) -> Option<Arc<dyn PluginTool>> {
        self.names_map
            .values()
            .flatten()
            .find(|t| t.get_name() == name)
            .map(Arc::clone)
    }

    /// Resolves a borrowed tool to a shared handle. Tools this manager never registered get a
    /// name-only stand-in, so a connection can still be described but carries no events.
    fn resolve_tool(&self, tool: &dyn PluginTool) -> Arc<dyn PluginTool> {
        if let Some(found) = self.find_tool(&tool.get_name()) {
            return found;
        }
        let stand_in = GhidraTool::new(tool.get_tool_name());
        stand_in.put_instance_name(&tool.get_instance_name());
        Arc::new(stand_in)
    }

    // ------------------------------------------------------------------
    // workspaces
    // ------------------------------------------------------------------

    /// The active workspace, or `None` when the project has none yet (Java returns `null`).
    pub fn active_workspace(&self) -> Option<WorkspaceHandle> {
        let name = self.active_workspace.as_deref()?;
        self.workspace(name)
    }

    /// A handle to the workspace with the given name, if one exists. Port of the package-level
    /// `getWorkspace(String)`.
    pub fn workspace(&self, name: &str) -> Option<WorkspaceHandle> {
        self.workspace_index(name).map(|i| WorkspaceHandle::new(&self.workspaces[i]))
    }

    fn workspace_index(&self, name: &str) -> Option<usize> {
        self.workspaces.iter().position(|ws| ws.borrow().name() == name)
    }

    /// Makes the named workspace the active one, hiding the previously active workspace. Port of
    /// the package-level `setActiveWorkspace(WorkspaceImpl)` together with the `setVisible(true)`
    /// that `WorkspaceImpl.setActive()` performs on the way in.
    ///
    /// Returns whether a workspace with that name exists.
    pub fn set_active_workspace(&mut self, name: &str) -> bool {
        let Some(index) = self.workspace_index(name) else {
            return false;
        };
        if self.active_workspace.as_deref() == Some(name) {
            return true;
        }

        // if we're in the process of being restored, don't set the change flag
        if !self.in_restore_mode {
            self.active_workspace_changed = true;
        }

        // set the current active workspace to inactive first; since only one workspace can be
        // active at a time, we don't have to set each one in the list inactive
        if let Some(previous) = self.active_workspace.as_deref().and_then(|n| self.workspace_index(n))
        {
            self.workspaces[previous].borrow_mut().set_visible(false);
        }

        self.active_workspace = Some(name.to_string());
        self.workspaces[index].borrow_mut().set_visible(true);

        let handle = WorkspaceHandle::new(&self.workspaces[index]);
        for listener in &mut self.change_listeners {
            listener.workspace_set_active(&handle);
        }
        true
    }

    /// Marks a workspace as having added or removed a tool. Port of the package-level
    /// `setWorkspaceChanged(WorkspaceImpl)`.
    pub fn set_workspace_changed(&mut self, name: &str) {
        self.changed_workspaces.insert(name.to_string());
    }

    /// Renames a workspace and fires the [`WORKSPACE_NAME_PROPERTY`] change event. Port of the
    /// package-level `setWorkspaceName(Workspace, String)`, which Java's `WorkspaceImpl.setName`
    /// calls back into.
    ///
    /// # Errors
    /// Returns [`DuplicateNameException`] if a workspace named `new_name` already exists.
    pub fn set_workspace_name(
        &mut self,
        current_name: &str,
        new_name: &str,
    ) -> Result<(), DuplicateNameException> {
        if self.workspace_index(new_name).is_some() {
            return Err(DuplicateNameException::with_message(format!(
                "Workspace named {new_name} already exists"
            )));
        }
        let Some(index) = self.workspace_index(current_name) else {
            return Ok(());
        };
        self.workspaces[index].borrow_mut().rename(new_name);
        if self.active_workspace.as_deref() == Some(current_name) {
            self.active_workspace = Some(new_name.to_string());
        }

        let event = ToolManagerPropertyChange {
            property_name: WORKSPACE_NAME_PROPERTY.to_string(),
            old_value: Some(current_name.to_string()),
            new_value: Some(new_name.to_string()),
        };
        for listener in &mut self.change_listeners {
            listener.property_change(&event);
        }
        Ok(())
    }

    fn is_default_workspace_name(name: &str) -> bool {
        name == DEFAULT_WORKSPACE_NAME
            || name.starts_with(&format!("{DEFAULT_WORKSPACE_NAME} ("))
    }

    fn unique_workspace_name(&self) -> String {
        let mut name = DEFAULT_WORKSPACE_NAME.to_string();
        let mut count = 0;
        while self.workspace_index(&name).is_some() {
            count += 1;
            name = format!("{DEFAULT_WORKSPACE_NAME} ({count})");
        }
        name
    }

    /// Notifies the workspace listeners that a tool was added to a workspace. Port of the
    /// package-level `fireToolAddedEvent(Workspace, PluginTool)`.
    pub fn fire_tool_added_event(&mut self, workspace_name: &str, tool: &Arc<dyn PluginTool>) {
        let Some(index) = self.workspace_index(workspace_name) else {
            return;
        };
        let handle = WorkspaceHandle::new(&self.workspaces[index]);
        let tool = SharedPluginTool::new(Arc::clone(tool));
        for listener in &mut self.change_listeners {
            listener.tool_added(&handle, &tool);
        }
    }

    /// Deregisters and disconnects a tool the given workspace has dropped, then notifies the
    /// workspace listeners. Port of the package-level `toolRemoved(Workspace, PluginTool)`.
    pub fn tool_removed(&mut self, workspace_name: &str, tool: &Arc<dyn PluginTool>) {
        self.deregister_tool(&tool.get_tool_name(), tool);
        self.disconnect_tool(tool.as_ref());

        let Some(index) = self.workspace_index(workspace_name) else {
            return;
        };
        let handle = WorkspaceHandle::new(&self.workspaces[index]);
        let shared = SharedPluginTool::new(Arc::clone(tool));
        for listener in &mut self.change_listeners {
            listener.tool_removed(&handle, &shared);
        }
    }

    /// Removes a closed tool from whichever workspace was running it. Port of the package-level
    /// `closeTool(PluginTool)` plus the `WorkspaceImpl.closeRunningTool` half it delegates to,
    /// which the workspace placeholder cannot perform on its own.
    pub fn close_tool(&mut self, tool: &Arc<dyn PluginTool>) {
        let Some(index) =
            self.workspaces.iter().position(|ws| ws.borrow().tools().iter().any(|t| Arc::ptr_eq(t, tool)))
        else {
            return;
        };
        self.workspaces[index].borrow_mut().remove_tool(tool);
        let name = self.workspaces[index].borrow().name().to_string();
        self.set_workspace_changed(&name);
        self.tool_removed(&name, tool);
    }

    // ------------------------------------------------------------------
    // tools
    // ------------------------------------------------------------------

    /// Creates and registers the tool with the given name from the tool chest, as
    /// `WorkspaceImpl` does when restoring its state. Returns `None` if the tool chest has no
    /// template by that name.
    pub fn get_tool(
        &mut self,
        project: &dyn Project,
        tool_name: &str,
    ) -> Option<Arc<dyn PluginTool>> {
        let template = self.tool_chest.get_tool_template(tool_name)?;
        let tool: Arc<dyn PluginTool> = Arc::from(template.create_tool(project));
        self.register_tool(tool_name, Arc::clone(&tool));
        Some(tool)
    }

    /// Creates and registers a tool from a template, setting its instance name. Port of the
    /// package-level `getTool(Workspace, ToolTemplate)`, whose workspace argument is unused.
    pub fn get_tool_from_template(
        &mut self,
        project: &dyn Project,
        template: &dyn ToolTemplate,
    ) -> Arc<dyn PluginTool> {
        let tool: Arc<dyn PluginTool> = Arc::from(template.create_tool(project));
        self.register_tool(&tool.get_tool_name(), Arc::clone(&tool));
        tool
    }

    /// Creates and registers an empty, untitled tool. Port of the package-level
    /// `createEmptyTool()`.
    pub fn create_empty_tool(&mut self) -> Arc<dyn PluginTool> {
        let tool: Arc<dyn PluginTool> = Arc::new(GhidraTool::new("Untitled"));
        tool.set_tool_name("Untitled");
        self.register_tool("Untitled", Arc::clone(&tool));
        tool
    }

    // ------------------------------------------------------------------
    // connections
    // ------------------------------------------------------------------

    fn connection_key(producer: &dyn PluginTool, consumer: &dyn PluginTool) -> String {
        format!("{}+{}", producer.get_name(), consumer.get_name())
    }

    /// Rekeys and refreshes every connection involving `tool`, after the tool was renamed or had
    /// its plugins changed. Port of the private `updateConnectMap(PluginTool)`.
    fn update_connect_map(&mut self, tool: &dyn PluginTool) {
        let tool_name = tool.get_name();
        let mut map = self.connect_map.borrow_mut();
        let old = std::mem::take(&mut *map);
        for (key, connection) in old {
            let involved = connection.producer().get_name() == tool_name
                || connection.consumer().get_name() == tool_name;
            if involved {
                connection.update_event_list();
                let new_key = Self::connection_key(
                    connection.producer().as_ref(),
                    connection.consumer().as_ref(),
                );
                map.insert(new_key, connection);
            } else {
                map.insert(key, connection);
            }
        }
    }

    /// Reports a property change on a running tool. Port of
    /// `propertyChange(PropertyChangeEvent)`; the event is unpacked into arguments because the
    /// manager cannot register itself as a listener on a tool it does not own.
    pub fn property_change(
        &mut self,
        tool: &Arc<dyn PluginTool>,
        property_name: &str,
        old_value: Option<&str>,
        new_value: Option<&str>,
    ) {
        if property_name == PLUGIN_COUNT_PROPERTY_NAME {
            self.update_connect_map(tool.as_ref());
            self.fire_property_change_event(property_name, old_value, new_value);
        }

        if property_name != TOOL_NAME_PROPERTY {
            return;
        }

        let (Some(old_name), Some(new_name)) = (old_value, new_value) else {
            return;
        };
        self.deregister_tool(old_name, tool);
        self.register_tool(new_name, Arc::clone(tool));

        self.update_connect_map(tool.as_ref());

        self.fire_property_change_event(property_name, old_value, new_value);
    }

    fn fire_property_change_event(
        &mut self,
        property_name: &str,
        old_value: Option<&str>,
        new_value: Option<&str>,
    ) {
        let event = ToolManagerPropertyChange {
            property_name: property_name.to_string(),
            old_value: old_value.map(str::to_string),
            new_value: new_value.map(str::to_string),
        };
        for listener in &mut self.change_listeners {
            listener.property_change(&event);
        }
    }

    /// Logs the current connections. Port of `dumpConnectionList()`.
    pub fn dump_connection_list(&self) {
        for (key, connection) in self.connect_map.borrow().iter() {
            Msg::debug("ToolManagerImpl", &format!("{key}==> "));
            for event in connection.get_events() {
                Msg::debug(
                    "ToolManagerImpl",
                    &format!(
                        "\t isConnected for {event}? = {}",
                        connection.is_connected(&event)
                    ),
                );
            }
        }
    }

    // ------------------------------------------------------------------
    // project state
    // ------------------------------------------------------------------

    /// Whether any connection changed, or any tool was added to or removed from a workspace, or
    /// the active workspace changed. Port of `hasChanged()`.
    pub fn has_changed(&self) -> bool {
        if self.connect_map.borrow().values().any(ToolConnectionImpl::has_changed) {
            return true;
        }
        !self.changed_workspaces.is_empty() || self.active_workspace_changed
    }

    /// Clears the flag that would prompt the user to save the project; it is set when a workspace
    /// is created, and a workspace is created when a new project is created. Port of
    /// `clearWorkspaceChanged()`.
    pub fn clear_workspace_changed(&mut self) {
        self.active_workspace_changed = false;
    }

    /// Writes the manager's workspaces and connections into `root`, which the caller creates as a
    /// `TOOL_MANAGER` element (Java's `saveToXml()` creates and returns it, but element creation
    /// goes through a parent in the [`JdomElement`] seam). Resets the changed state.
    pub fn save_to_xml(&mut self, root: &mut dyn JdomElement) {
        if let Some(active) = self.active_workspace.clone() {
            root.set_attribute("ACTIVE_WORKSPACE", &active);
        }
        for workspace in &self.workspaces {
            let element = workspace.borrow().save_to_xml(root);
            root.add_content(element);
        }
        for connection in self.connect_map.borrow().values() {
            let element = connection.save_to_xml(root);
            root.add_content(element);
            connection.clear_changed();
        }

        // reset the changed state back to "unchanged"
        self.changed_workspaces.clear();
        self.active_workspace_changed = false;
    }

    /// Restores the workspaces and connections saved by [`save_to_xml`](Self::save_to_xml). Port
    /// of `restoreFromXml(Element)`.
    pub fn restore_from_xml(&mut self, root: &dyn JdomElement) {
        self.in_restore_mode = true;

        let active_ws_name = root.attribute_value("ACTIVE_WORKSPACE");
        let mut make_me_active: Option<String> = None;
        let mut tool_map: HashMap<String, Arc<dyn PluginTool>> = HashMap::new();

        for element in root.children("WORKSPACE") {
            let mut workspace = WorkspaceImpl::new("TEMP");
            workspace.restore_from_xml(element);
            let name = workspace.name().to_string();
            for tool in workspace.tools() {
                tool_map.insert(tool.get_name(), Arc::clone(tool));
            }
            self.workspaces.push(Rc::new(RefCell::new(workspace)));
            if Some(&name) == active_ws_name.as_ref() {
                make_me_active = Some(name);
            }
        }
        if let Some(name) = make_me_active {
            self.set_active_workspace(&name);
        }

        for element in root.children("CONNECTION") {
            let (Some(producer_name), Some(consumer_name)) =
                (element.attribute_value("PRODUCER"), element.attribute_value("CONSUMER"))
            else {
                continue;
            };
            let (Some(producer), Some(consumer)) =
                (tool_map.get(&producer_name), tool_map.get(&consumer_name))
            else {
                continue;
            };
            let connection = ToolConnectionImpl::new(Arc::clone(producer), Arc::clone(consumer));
            connection.restore_from_xml(element);
            self.connect_map
                .borrow_mut()
                .insert(format!("{producer_name}+{consumer_name}"), connection);
        }

        self.in_restore_mode = false;
    }

    /// Saves the tools that are open and changed, so they come back up when the project is
    /// reopened. Port of `saveSessionTools()`; returns whether the session was saved (`false`
    /// only when the user cancelled out of choosing among several changed instances of one tool).
    pub fn save_session_tools(&mut self) -> bool {
        let tool_names: Vec<String> = self.names_map.keys().cloned().collect();
        for tool_name in tool_names {
            let tools = self.names_map[&tool_name].clone();
            if tools.len() == 1 {
                let tool = &tools[0];
                if tool.should_save() {
                    tool.save_tool();
                }
            } else if !self.save_tool_set(&tools) {
                return false;
            }
        }
        true
    }

    fn save_tool_set(&mut self, tools: &[Arc<dyn PluginTool>]) -> bool {
        let changed_tools: Vec<Arc<dyn PluginTool>> =
            tools.iter().filter(|t| t.has_config_changed()).map(Arc::clone).collect();
        if changed_tools.is_empty() {
            return true;
        }

        if changed_tools.len() == 1 {
            let changed_tool = &changed_tools[0];
            if changed_tool.should_save() {
                changed_tool.save_tool();
            }
            // we don't care if they save or not here; it is not a cancel
            return true;
        }

        let Some(chooser) = self.changed_tool_chooser.as_mut() else {
            return true;
        };
        match chooser(&changed_tools) {
            ChangedToolChoice::Cancelled => false,
            ChangedToolChoice::SaveNone => true,
            ChangedToolChoice::Save(index) => {
                if let Some(tool) = changed_tools.get(index) {
                    tool.save_tool();
                }
                true
            }
        }
    }

    /// Closes every tool in every workspace. Port of `dispose()`.
    pub fn dispose(&mut self) {
        for workspace in &self.workspaces {
            workspace.borrow_mut().dispose();
        }
    }

    // ------------------------------------------------------------------
    // save status
    // ------------------------------------------------------------------

    /// Whether the given tool can be saved without asking the user first. Port of
    /// `canAutoSave(PluginTool)`; takes `&mut self` because Java lazily updates the tool's save
    /// status here.
    pub fn can_auto_save(&mut self, tool: &dyn PluginTool) -> bool {
        let tool_name = tool.get_tool_name();
        let mut status = self.tool_status_map.get(&tool_name).copied();
        if status == Some(ToolSaveStatus::AskSaveMode) {
            return false;
        }

        // we are in auto mode...if there is only one tool, then we can auto save
        if self.tool_instance_count(tool) <= 1 {
            return true;
        }

        // otherwise, lazy update the status...things may have changed
        if tool.has_config_changed() {
            status = Some(ToolSaveStatus::AskSaveMode);
            self.tool_status_map.insert(tool_name, ToolSaveStatus::AskSaveMode);
        }

        status == Some(ToolSaveStatus::AutoSaveMode)
    }

    /// Records that a tool was saved, resetting or tightening its save status. Port of
    /// `toolSaved(PluginTool, boolean)`.
    pub fn tool_saved(&mut self, tool: &dyn PluginTool, tool_changed: bool) {
        let tool_name = tool.get_tool_name();
        if self.tool_instance_count(tool) == 1 {
            // saving with only one instance open resets the status
            self.tool_status_map.insert(tool_name, ToolSaveStatus::AutoSaveMode);
        } else if tool_changed {
            // if there is more than one tool open and a changed tool is saved, go into ask mode
            self.tool_status_map.insert(tool_name, ToolSaveStatus::AskSaveMode);
        }
    }

    fn tool_instance_count(&self, tool: &dyn PluginTool) -> usize {
        self.names_map.get(&tool.get_tool_name()).map_or(0, Vec::len)
    }
}

impl ToolManager for ToolManagerImpl {
    fn get_connection(
        &self,
        producer: &dyn PluginTool,
        consumer: &dyn PluginTool,
    ) -> Box<dyn ToolConnection> {
        let key = Self::connection_key(producer, consumer);
        let mut map = self.connect_map.borrow_mut();
        let connection = map.entry(key).or_insert_with(|| {
            ToolConnectionImpl::new(self.resolve_tool(producer), self.resolve_tool(consumer))
        });
        Box::new(connection.clone())
    }

    fn get_producer_tools(&self) -> Vec<Box<dyn PluginTool>> {
        Self::boxed(
            self.running_tools()
                .into_iter()
                .filter(|t| !t.get_tool_event_names().is_empty())
                .collect(),
        )
    }

    fn get_consumer_tools(&self) -> Vec<Box<dyn PluginTool>> {
        Self::boxed(
            self.running_tools()
                .into_iter()
                .filter(|t| !t.get_consumed_tool_event_names().is_empty())
                .collect(),
        )
    }

    fn get_running_tools(&self) -> Vec<Box<dyn PluginTool>> {
        Self::boxed(self.running_tools())
    }

    fn create_workspace(&mut self, name: &str) -> Result<Box<dyn Workspace>, DuplicateNameException> {
        // if passed the default "untitled" name, or no name at all, then bump up the name with
        // the "one-up" number to create a new one
        let mut name = if name.is_empty() { DEFAULT_WORKSPACE_NAME.to_string() } else { name.to_string() };
        if Self::is_default_workspace_name(&name) {
            name = self.unique_workspace_name();
        }

        // duplicate workspaces are not allowed in the same project
        if self.workspace_index(&name).is_some() {
            return Err(DuplicateNameException::with_message(format!(
                "Duplicate workspace requested: {name}"
            )));
        }

        // create the new workspace and add it to the list of managed workspaces
        let workspace = Rc::new(RefCell::new(WorkspaceImpl::new(name.clone())));
        self.workspaces.push(Rc::clone(&workspace));

        // notify listeners of added workspace
        let handle = WorkspaceHandle::new(&workspace);
        for listener in &mut self.change_listeners {
            listener.workspace_added(&handle);
        }

        // makes the others inactive
        self.set_active_workspace(&name);

        Ok(Box::new(WorkspaceHandle::new(&workspace)))
    }

    fn remove_workspace(&mut self, ws: &dyn Workspace) {
        let name = ws.get_name();
        let Some(index) = self.workspace_index(&name) else {
            // this is a programming error if it occurs
            Msg::show_error(
                "ToolManagerImpl",
                "Remove Workspace",
                &format!("unknown/stale workspace reference: {name}"),
            );
            return;
        };

        // first close all the tools running in the workspace; if data has changed in a tool, the
        // front end takes care of asking to save it. Java relies on each closing tool calling back
        // into closeTool; the placeholder tools cannot, so drive both halves here.
        let running_tools = self.workspaces[index].borrow().tools().to_vec();
        for tool in &running_tools {
            tool.close();
            self.close_tool(tool);
        }

        // if any of the tools didn't close, don't remove the workspace
        if !self.workspaces[index].borrow().tools().is_empty() {
            return;
        }

        // remove workspace from the list of workspaces
        let workspace = self.workspaces.remove(index);
        if self.active_workspace.as_deref() == Some(name.as_str()) {
            self.active_workspace = None;
        }
        self.changed_workspaces.remove(&name);

        // notify listeners of removed workspace
        let handle = WorkspaceHandle::new(&workspace);
        for listener in &mut self.change_listeners {
            listener.workspace_removed(&handle);
        }

        // set the oldest workspace to now be the active workspace; if this was the last workspace,
        // create a new "empty" workspace which is the project default
        if self.workspaces.is_empty() {
            if let Err(e) = self.create_workspace(DEFAULT_WORKSPACE_NAME) {
                Msg::show_error(
                    "ToolManagerImpl",
                    "Duplicate Name",
                    &format!("Error Creating Default Workspace: {e}"),
                );
            }
        } else {
            let first = self.workspaces[0].borrow().name().to_string();
            self.set_active_workspace(&first);
        }
    }

    fn get_workspaces(&self) -> Vec<Box<dyn Workspace>> {
        self.workspaces
            .iter()
            .map(|ws| Box::new(WorkspaceHandle::new(ws)) as Box<dyn Workspace>)
            .collect()
    }

    fn get_active_workspace(&self) -> Box<dyn Workspace> {
        match self.active_workspace() {
            Some(handle) => Box::new(handle),
            // Java returns null here; hand back a detached, empty workspace instead
            None => Box::new(WorkspaceHandle::detached("")),
        }
    }

    fn add_workspace_change_listener(&mut self, listener: Box<dyn WorkspaceChangeListener>) {
        self.change_listeners.push(listener);
    }

    fn remove_workspace_change_listener(&mut self, listener: Box<dyn WorkspaceChangeListener>) {
        let target = std::ptr::addr_of!(*listener).cast::<()>();
        self.change_listeners
            .retain(|l| !std::ptr::eq(std::ptr::addr_of!(**l).cast::<()>(), target));
    }

    fn disconnect_tool(&mut self, tool: &dyn PluginTool) {
        let tool_name = tool.get_name();
        let mut map = self.connect_map.borrow_mut();
        let keys: Vec<String> = map
            .iter()
            .filter(|(_, c)| {
                c.producer().get_name() == tool_name || c.consumer().get_name() == tool_name
            })
            .map(|(key, _)| key.clone())
            .collect();
        for key in keys {
            let Some(connection) = map.remove(&key) else {
                continue;
            };
            connection.producer().remove_tool_listener(&connection);
        }
    }

    fn tool_changed(&mut self, tool: &dyn PluginTool) {
        self.update_connect_map(tool);
    }
}

impl fmt::Debug for ToolManagerImpl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ToolManagerImpl")
            .field("workspaces", &self.workspaces.iter().map(|w| w.borrow().name().to_string()).collect::<Vec<_>>())
            .field("active_workspace", &self.active_workspace)
            .field("connections", &self.connect_map.borrow().keys().cloned().collect::<Vec<_>>())
            .field("tool_names", &self.names_map.keys().cloned().collect::<Vec<_>>())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::ToolChestChangeListener;
    use std::cell::Cell;

    /// A tool chest with no templates, standing in for the project's local chest.
    struct EmptyToolChest;

    impl ToolChest for EmptyToolChest {
        fn get_tool_template(&self, _tool_name: &str) -> Option<Box<dyn ToolTemplate>> {
            None
        }

        fn get_tool_templates(&self) -> Vec<Box<dyn ToolTemplate>> {
            Vec::new()
        }

        fn add_tool_chest_change_listener(&mut self, _listener: Box<dyn ToolChestChangeListener>) {}

        fn remove_tool_chest_change_listener(
            &mut self,
            _listener: Box<dyn ToolChestChangeListener>,
        ) {
        }

        fn add_tool_template(&mut self, _template: &mut dyn ToolTemplate) -> bool {
            false
        }

        fn remove(&mut self, _tool_name: &str) -> bool {
            false
        }

        fn get_tool_count(&self) -> i32 {
            0
        }

        fn replace_tool_template(&mut self, _template: &mut dyn ToolTemplate) -> bool {
            false
        }
    }

    /// A tool that produces and consumes a fixed set of events.
    struct EventTool {
        inner: GhidraTool,
        produced: Vec<String>,
        consumed: Vec<String>,
    }

    impl EventTool {
        fn new(tool_name: &str, produced: &[&str], consumed: &[&str]) -> Arc<Self> {
            Arc::new(Self {
                inner: GhidraTool::new(tool_name),
                produced: produced.iter().map(|s| s.to_string()).collect(),
                consumed: consumed.iter().map(|s| s.to_string()).collect(),
            })
        }
    }

    impl PluginTool for EventTool {
        fn get_tool_name(&self) -> String {
            self.inner.get_tool_name()
        }

        fn set_tool_name(&self, name: &str) {
            self.inner.set_tool_name(name);
        }

        fn get_instance_name(&self) -> String {
            self.inner.get_instance_name()
        }

        fn put_instance_name(&self, instance_name: &str) {
            self.inner.put_instance_name(instance_name);
        }

        fn get_tool_event_names(&self) -> Vec<String> {
            self.produced.clone()
        }

        fn get_consumed_tool_event_names(&self) -> Vec<String> {
            self.consumed.clone()
        }

        fn has_config_changed(&self) -> bool {
            self.inner.has_config_changed()
        }

        fn should_save(&self) -> bool {
            self.inner.should_save()
        }

        fn save_tool(&self) {
            self.inner.save_tool();
        }

        fn close(&self) {
            self.inner.close();
        }
    }

    /// A `JdomElement` with real state, so the save/restore round trip can be exercised.
    #[derive(Default)]
    struct TestElement {
        name: String,
        attributes: Vec<(String, String)>,
        children: Vec<Box<TestElement>>,
    }

    impl TestElement {
        fn new(name: &str) -> Self {
            Self { name: name.to_string(), ..Default::default() }
        }
    }

    impl JdomElement for TestElement {
        fn new_child(&self, name: &str) -> Box<dyn JdomElement> {
            Box::new(TestElement::new(name))
        }

        fn tag_name(&self) -> String {
            self.name.clone()
        }

        fn set_attribute(&mut self, name: &str, value: &str) {
            self.attributes.retain(|(n, _)| n != name);
            self.attributes.push((name.to_string(), value.to_string()));
        }

        fn attribute_value(&self, name: &str) -> Option<String> {
            self.attributes.iter().find(|(n, _)| n == name).map(|(_, v)| v.clone())
        }

        fn add_content(&mut self, child: Box<dyn JdomElement>) {
            let mut copy = TestElement::new(&child.tag_name());
            for name in ["NAME", "ACTIVE", "PRODUCER", "CONSUMER", "TOOL_NAME"] {
                if let Some(value) = child.attribute_value(name) {
                    copy.set_attribute(name, &value);
                }
            }
            self.children.push(Box::new(copy));
        }

        fn children(&self, name: &str) -> Vec<&dyn JdomElement> {
            self.children
                .iter()
                .filter(|c| c.name == name)
                .map(|c| c.as_ref() as &dyn JdomElement)
                .collect()
        }
    }

    /// Counts the workspace events the manager fires.
    #[derive(Default)]
    struct CountingListener {
        added: Rc<Cell<usize>>,
        removed: Rc<Cell<usize>>,
        activated: Rc<Cell<usize>>,
    }

    impl WorkspaceChangeListener for CountingListener {
        fn tool_added(&mut self, _ws: &dyn Workspace, _tool: &dyn PluginTool) {}

        fn tool_removed(&mut self, _ws: &dyn Workspace, _tool: &dyn PluginTool) {}

        fn workspace_added(&mut self, _ws: &dyn Workspace) {
            self.added.set(self.added.get() + 1);
        }

        fn workspace_removed(&mut self, _ws: &dyn Workspace) {
            self.removed.set(self.removed.get() + 1);
        }

        fn workspace_set_active(&mut self, _ws: &dyn Workspace) {
            self.activated.set(self.activated.get() + 1);
        }

        fn property_change(&mut self, _event: &dyn PropertyChangeEvent) {}
    }

    fn manager() -> ToolManagerImpl {
        ToolManagerImpl::with_tool_chest(Box::new(EmptyToolChest))
    }

    /// Erases a test tool to the shared handle the manager stores, for the members that take
    /// `&Arc<dyn PluginTool>` (where an unsized coercion cannot happen implicitly).
    fn shared(tool: &Arc<EventTool>) -> Arc<dyn PluginTool> {
        Arc::clone(tool) as Arc<dyn PluginTool>
    }

    #[test]
    fn default_workspace_names_get_one_up_suffixes() {
        let mut tm = manager();

        // an empty name, the default name, and any "Workspace (n)" name all get bumped
        assert_eq!(tm.create_workspace("").unwrap().get_name(), "Workspace");
        assert_eq!(tm.create_workspace("Workspace").unwrap().get_name(), "Workspace (1)");
        assert_eq!(tm.create_workspace("Workspace (5)").unwrap().get_name(), "Workspace (2)");

        // a non-default name is taken as-is, and may not be duplicated
        assert_eq!(tm.create_workspace("Reversing").unwrap().get_name(), "Reversing");
        assert!(tm.create_workspace("Reversing").is_err());

        assert_eq!(tm.get_workspaces().len(), 4);
        // the last workspace created is the active one, and only it is visible
        assert_eq!(tm.get_active_workspace().get_name(), "Reversing");
        assert!(!tm.workspace("Workspace").unwrap().0.borrow().is_visible());
        assert!(tm.workspace("Reversing").unwrap().0.borrow().is_visible());
        assert!(tm.has_changed());
    }

    #[test]
    fn workspace_listeners_see_add_activate_and_remove() {
        let mut tm = manager();
        let added = Rc::new(Cell::new(0));
        let removed = Rc::new(Cell::new(0));
        let activated = Rc::new(Cell::new(0));
        tm.add_workspace_change_listener(Box::new(CountingListener {
            added: Rc::clone(&added),
            removed: Rc::clone(&removed),
            activated: Rc::clone(&activated),
        }));

        tm.create_workspace("A").unwrap();
        tm.create_workspace("B").unwrap();
        assert_eq!((added.get(), activated.get()), (2, 2));

        let b = tm.workspace("B").unwrap();
        tm.remove_workspace(&b);
        assert_eq!(removed.get(), 1);
        // "A" is the oldest remaining workspace, so it becomes active again
        assert_eq!(tm.get_active_workspace().get_name(), "A");

        // removing the last workspace re-creates the project default
        let a = tm.workspace("A").unwrap();
        tm.remove_workspace(&a);
        assert_eq!(removed.get(), 2);
        assert_eq!(tm.get_workspaces().len(), 1);
        assert_eq!(tm.get_active_workspace().get_name(), "Workspace");
    }

    #[test]
    fn instance_names_are_one_up_per_tool_name() {
        let mut tm = manager();
        let first = EventTool::new("CodeBrowser", &[], &[]);
        let second = EventTool::new("CodeBrowser", &[], &[]);
        let third = EventTool::new("CodeBrowser", &[], &[]);
        let other = EventTool::new("Debugger", &[], &[]);

        for tool in [&first, &second, &third, &other] {
            tm.register_tool(&tool.get_tool_name(), shared(tool));
        }

        assert_eq!(first.get_instance_name(), "");
        assert_eq!(second.get_instance_name(), "2");
        assert_eq!(third.get_instance_name(), "3");
        assert_eq!(other.get_instance_name(), "");

        // getName() folds the instance name in, which is what connection keys are built from
        assert_eq!(first.get_name(), "CodeBrowser");
        assert_eq!(third.get_name(), "CodeBrowser(3)");

        // the third instance leaving does not renumber the others
        tm.deregister_tool("CodeBrowser", &shared(&third));
        assert_eq!(second.get_instance_name(), "2");
    }

    #[test]
    fn connection_covers_only_the_shared_events() {
        let mut tm = manager();
        let producer = EventTool::new("Producer", &["Location", "Selection"], &[]);
        let consumer = EventTool::new("Consumer", &[], &["Selection", "Highlight"]);
        tm.register_tool("Producer", shared(&producer));
        tm.register_tool("Consumer", shared(&consumer));

        let mut connection = tm.get_connection(producer.as_ref(), consumer.as_ref());
        assert_eq!(connection.get_events(), vec!["Selection".to_string()]);
        assert!(connection.connect("Location").is_err());

        connection.connect("Selection").unwrap();
        assert!(connection.is_connected("Selection"));
        // the connection was cached, so the manager sees the same one the caller mutated
        assert!(tm.get_connection(producer.as_ref(), consumer.as_ref()).is_connected("Selection"));
        assert!(tm.has_changed());

        // disconnecting the producer drops every connection it takes part in
        tm.disconnect_tool(producer.as_ref());
        assert!(!tm.get_connection(producer.as_ref(), consumer.as_ref()).is_connected("Selection"));
    }

    #[test]
    fn renaming_a_tool_rekeys_its_connections() {
        let mut tm = manager();
        let producer = EventTool::new("Producer", &["Location"], &[]);
        let consumer = EventTool::new("Consumer", &[], &["Location"]);
        tm.register_tool("Producer", shared(&producer));
        tm.register_tool("Consumer", shared(&consumer));
        tm.get_connection(producer.as_ref(), consumer.as_ref());
        assert!(tm.connect_map.borrow().contains_key("Producer+Consumer"));

        producer.set_tool_name("Renamed");
        tm.property_change(&shared(&producer), TOOL_NAME_PROPERTY, Some("Producer"), Some("Renamed"));

        assert!(tm.connect_map.borrow().contains_key("Renamed+Consumer"));
        assert!(!tm.connect_map.borrow().contains_key("Producer+Consumer"));
        // the tool is now registered under its new name only
        assert!(tm.names_map.contains_key("Renamed"));
        assert!(!tm.names_map.contains_key("Producer"));
    }

    #[test]
    fn auto_save_turns_into_ask_save_for_diverged_instances() {
        let mut tm = manager();
        let first = EventTool::new("CodeBrowser", &[], &[]);
        tm.register_tool("CodeBrowser", shared(&first));

        // one instance always auto-saves, changed or not
        assert!(tm.can_auto_save(first.as_ref()));

        let second = EventTool::new("CodeBrowser", &[], &[]);
        tm.register_tool("CodeBrowser", shared(&second));

        // two unchanged instances still auto-save
        assert!(tm.can_auto_save(first.as_ref()));

        // ...but once one of them has diverged, saving has to be confirmed
        first.inner.set_config_changed(true);
        assert!(!tm.can_auto_save(first.as_ref()));
        assert!(!tm.can_auto_save(second.as_ref()));

        // saving with several instances open keeps it in ask mode
        tm.tool_saved(first.as_ref(), true);
        assert!(!tm.can_auto_save(second.as_ref()));

        // ...and saving the last remaining instance resets it
        tm.deregister_tool("CodeBrowser", &shared(&second));
        tm.tool_saved(first.as_ref(), true);
        assert!(tm.can_auto_save(first.as_ref()));
    }

    #[test]
    fn save_session_tools_asks_about_several_changed_instances() {
        let mut tm = manager();
        let lone = EventTool::new("Debugger", &[], &[]);
        lone.set_tool_name("Debugger");
        tm.register_tool("Debugger", shared(&lone));

        let first = EventTool::new("CodeBrowser", &[], &[]);
        let second = EventTool::new("CodeBrowser", &[], &[]);
        tm.register_tool("CodeBrowser", shared(&first));
        tm.register_tool("CodeBrowser", shared(&second));
        first.inner.set_config_changed(true);
        second.inner.set_config_changed(true);

        // a lone changed tool is saved without asking
        lone.inner.set_config_changed(true);

        tm.set_changed_tool_chooser(|_changed| ChangedToolChoice::Cancelled);
        assert!(!tm.save_session_tools(), "a cancelled choice must fail the session save");

        tm.set_changed_tool_chooser(|_changed| ChangedToolChoice::Save(1));
        assert!(tm.save_session_tools());
        assert!(lone.inner.was_saved());
        assert!(!first.inner.was_saved());
        assert!(second.inner.was_saved());
    }

    #[test]
    fn xml_round_trip_restores_workspaces_and_active_one() {
        let mut tm = manager();
        tm.create_workspace("Alpha").unwrap();
        tm.create_workspace("Beta").unwrap();
        assert_eq!(tm.get_active_workspace().get_name(), "Beta");

        let mut root = TestElement::new("TOOL_MANAGER");
        tm.save_to_xml(&mut root);

        assert_eq!(root.attribute_value("ACTIVE_WORKSPACE").as_deref(), Some("Beta"));
        assert_eq!(root.children("WORKSPACE").len(), 2);
        // saving resets the "needs saving" state
        assert!(!tm.has_changed());

        let mut restored = manager();
        restored.restore_from_xml(&root);
        let names: Vec<String> =
            restored.get_workspaces().iter().map(|ws| ws.get_name()).collect();
        assert_eq!(names, vec!["Alpha".to_string(), "Beta".to_string()]);
        assert_eq!(restored.get_active_workspace().get_name(), "Beta");
        // restoring is not a user change
        assert!(!restored.has_changed());
    }

    #[test]
    fn closing_a_tool_removes_it_from_its_workspace() {
        let mut tm = manager();
        tm.create_workspace("Alpha").unwrap();
        let tool = EventTool::new("CodeBrowser", &[], &[]);
        tm.register_tool("CodeBrowser", shared(&tool));
        tm.workspace("Alpha").unwrap().0.borrow_mut().add_tool(shared(&tool));

        assert_eq!(tm.get_running_tools().len(), 1);
        assert_eq!(tm.get_running_tools()[0].get_name(), "CodeBrowser");

        tm.close_tool(&shared(&tool));

        assert!(tm.get_running_tools().is_empty());
        assert!(!tm.names_map.contains_key("CodeBrowser"));
        assert!(tm.has_changed());
    }

    #[test]
    fn producer_and_consumer_tools_are_filtered_by_their_events() {
        let mut tm = manager();
        tm.create_workspace("Alpha").unwrap();
        let producer = EventTool::new("Producer", &["Location"], &[]);
        let consumer = EventTool::new("Consumer", &[], &["Location"]);
        let quiet = EventTool::new("Quiet", &[], &[]);
        {
            let ws = tm.workspace("Alpha").unwrap();
            for tool in [&producer, &consumer, &quiet] {
                ws.0.borrow_mut().add_tool(shared(tool));
            }
        }

        let producers: Vec<String> =
            tm.get_producer_tools().iter().map(|t| t.get_name()).collect();
        let consumers: Vec<String> =
            tm.get_consumer_tools().iter().map(|t| t.get_name()).collect();

        assert_eq!(producers, vec!["Producer".to_string()]);
        assert_eq!(consumers, vec!["Consumer".to_string()]);
        assert_eq!(tm.get_running_tools().len(), 3);
    }
}

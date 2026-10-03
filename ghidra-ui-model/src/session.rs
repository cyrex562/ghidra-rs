//! The root UI-session object every renderer talks to.

use std::collections::BTreeMap;

use ghidra_rs::docking::{ComponentProvider, DockingTool, ProviderId};

use crate::events::{UiEvent, UiEventQueue, WakeHandle};
use crate::view_models::{FormModel, TableModel, TextModel, TreeModel};

/// The model behind one provider's generic view.
pub enum ViewModelBox {
    /// A table pane.
    Table(Box<dyn TableModel>),
    /// A tree pane.
    Tree(Box<dyn TreeModel>),
    /// A text pane.
    Text(Box<dyn TextModel>),
    /// A form pane.
    Form(Box<dyn FormModel>),
    /// A listing pane.
    /// The listing's state is shared with its navigation actions.
    Listing(crate::listing_controller::ListingHandle),
}

/// The application-wide UI session: the root object a renderer is handed at
/// startup. Owns the tool (providers, actions, layout), each provider's view
/// model, and the event queue.
pub struct UiSession {
    app_name: String,
    version: String,
    tool: DockingTool,
    models: BTreeMap<ProviderId, ViewModelBox>,
    events: UiEventQueue,
    wake: Option<WakeHandle>,
    central: Option<ProviderId>,
    icons: Option<Box<dyn crate::icons::IconResolver>>,
    goto_target: Option<ProviderId>,
    config_states: Vec<(String, Box<dyn ConfigState>)>,
    dialog_panes: BTreeMap<u64, PaneViewIds>,
}

/// The view-model ids of an open dialog's panes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PaneViewIds {
    /// Tree pane.
    pub tree: ProviderId,
    /// Form pane.
    pub form: ProviderId,
    /// Table pane, if the dialog has one.
    pub table: Option<ProviderId>,
}

/// First view-model id used for dialog panes (tool providers count up from 1).
pub const DIALOG_VIEW_BASE: u64 = 1 << 62;

/// Per-plugin state saved with the tool configuration (Java
/// `Plugin.writeConfigState`/`readConfigState`).
pub trait ConfigState: Send {
    /// Writes the state.
    fn write_config_state(&self, state: &mut ghidra_rs::framework::options::SaveState);
    /// Restores it.
    fn read_config_state(&mut self, state: &ghidra_rs::framework::options::SaveState);
    /// Restore order: lower first. Tool options are 0 so plugins (1) read
    /// their state under the restored option values, as in Java.
    fn phase(&self) -> u8 {
        1
    }
}

impl UiSession {
    /// Creates the session for this build of ghidra-rs, with an empty tool.
    pub fn new() -> Self {
        let (events, wake) = UiEventQueue::new();
        Self {
            app_name: "Ghidra-rs".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            tool: DockingTool::new("Ghidra-rs"),
            models: BTreeMap::new(),
            events,
            wake: Some(wake),
            central: None,
            icons: None,
            goto_target: None,
            config_states: Vec::new(),
            dialog_panes: BTreeMap::new(),
        }
    }

    /// Application name shown to users.
    pub fn app_name(&self) -> &str {
        &self.app_name
    }

    /// Application version (the crate version).
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Main-window title, e.g. `"Ghidra-rs 0.1.0"`.
    pub fn title(&self) -> String {
        format!("{} {}", self.app_name, self.version)
    }

    /// The tool.
    pub fn tool(&self) -> &DockingTool {
        &self.tool
    }

    /// Mutable tool.
    pub fn tool_mut(&mut self) -> &mut DockingTool {
        &mut self.tool
    }

    /// Adds a provider with its view model.
    pub fn add_provider(&mut self, provider: Box<dyn ComponentProvider>, model: Option<ViewModelBox>, show: bool) -> ProviderId {
        let id = self.tool.add_provider(provider, show);
        if let Some(m) = model {
            self.models.insert(id, m);
        }
        id
    }

    /// The provider's view model.
    pub fn model(&self, id: ProviderId) -> Option<&ViewModelBox> {
        self.models.get(&id)
    }

    /// Mutable view model.
    pub fn model_mut(&mut self, id: ProviderId) -> Option<&mut ViewModelBox> {
        self.models.get_mut(&id)
    }

    /// The event queue (clone it to post from actions or tasks).
    pub fn events(&self) -> &UiEventQueue {
        &self.events
    }

    /// Writes the tool configuration (layout + renderer geometry) as
    /// `SaveState` XML, creating parent directories.
    pub fn save_tool_config(&self, path: &std::path::Path) -> std::io::Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let mut state = self.tool.save_layout();
        for (name, contributor) in &self.config_states {
            let mut own = ghidra_rs::framework::options::SaveState::new();
            contributor.write_config_state(&mut own);
            state.put_xml_element(name, own.save_to_xml());
        }
        let xml = state.save_to_xml().output_string();
        std::fs::write(path, xml)
    }

    /// Restores a tool configuration written by [`Self::save_tool_config`].
    /// `Ok(false)` if the file does not exist (defaults kept); `Err` if it
    /// exists but cannot be read or parsed (defaults kept).
    pub fn load_tool_config(&mut self, path: &std::path::Path) -> std::io::Result<bool> {
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(e),
        };
        let element = ghidra_rs::util::xml::element::Element::parse_bytes(&bytes)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{}: {e:?}", path.display())))?;
        let state = ghidra_rs::framework::options::SaveState::from_xml(&element);
        self.tool.restore_layout(&state);
        let mut order: Vec<usize> = (0..self.config_states.len()).collect();
        order.sort_by_key(|&i| self.config_states[i].1.phase());
        for i in order {
            let (name, contributor) = &mut self.config_states[i];
            if let Some(e) = state.get_xml_element(name) {
                contributor.read_config_state(&ghidra_rs::framework::options::SaveState::from_xml(e));
            }
        }
        self.apply_tool_requests(); // restored key bindings re-bind their actions
        Ok(true)
    }

    /// Makes `id` the tool's root component: it fills the space the docked
    /// providers leave (Ghidra's CodeBrowser listing). Only one; later calls win.
    pub fn set_central_provider(&mut self, id: ProviderId) {
        self.central = Some(id);
    }

    /// The root component, if any.
    pub fn central_provider(&self) -> Option<ProviderId> {
        self.central
    }

    /// Applies provider show requests made by the action just performed
    /// (Window menu entries) and tells the renderer about each.
    pub fn apply_tool_requests(&mut self) {
        // Java ShowAllComponentsAction focuses only the first provider.
        for (i, id) in self.tool.apply_requests().into_iter().enumerate() {
            self.events.post(UiEvent::ProviderShown { id: id.0, focus: i == 0 });
        }
    }

    /// Makes listing provider `id` the target of [`Self::go_to`] (Java's
    /// default navigatable for the GoToService).
    pub fn set_goto_target(&mut self, id: ProviderId) {
        self.goto_target = Some(id);
    }

    /// Goes to `address` in the go-to target listing (history recorded) and
    /// tells the renderer.
    pub fn go_to(&mut self, address: u64) -> Result<(), String> {
        let target = self.goto_target.ok_or_else(|| "no listing to go to".to_string())?;
        let Some(ViewModelBox::Listing(h)) = self.models.get(&target) else {
            return Err(format!("go-to target {} is not a listing", target.0));
        };
        crate::listing_controller::lock(h).goto_address(address)?;
        self.events.post(UiEvent::ViewChanged(target.0));
        self.events.post(UiEvent::ActionsChanged);
        Ok(())
    }

    /// A table row was activated (double-click, Java `GhidraTable.navigate`):
    /// go to its location; a failure becomes a status message.
    pub fn table_activate(&mut self, table: ProviderId, row: usize, column: usize) -> Result<(), String> {
        let location = match self.models.get(&table) {
            Some(ViewModelBox::Table(t)) => t.location(row, column),
            Some(_) => return Err(format!("provider {} is not a table", table.0)),
            None => return Err(format!("no view model for provider {}", table.0)),
        };
        if let Some(address) = location {
            if let Err(message) = self.go_to(address) {
                self.events.post(UiEvent::Status(message));
            }
        }
        Ok(())
    }

    /// Saves `state` with the tool configuration under `name` (a plugin name).
    pub fn add_config_state(&mut self, name: &str, state: Box<dyn ConfigState>) {
        self.config_states.push((name.to_owned(), state));
    }

    /// The view-model ids of dialog `id`'s tree and form panes, registered in
    /// this session's model registry on first use (ids from
    /// [`DIALOG_VIEW_BASE`], never a tool provider's).
    pub fn dialog_pane_ids(&mut self, id: u64) -> Result<PaneViewIds, String> {
        if let Some(ids) = self.dialog_panes.get(&id) {
            return Ok(*ids);
        }
        let panes = self.events.dialog_panes(id)?.ok_or_else(|| format!("dialog {id} has no panes"))?;
        let base = DIALOG_VIEW_BASE + 3 * id;
        let ids = PaneViewIds {
            tree: ProviderId(base),
            form: ProviderId(base + 1),
            table: panes.table.is_some().then_some(ProviderId(base + 2)),
        };
        self.models.insert(ids.tree, ViewModelBox::Tree(panes.tree));
        self.models.insert(ids.form, ViewModelBox::Form(panes.form));
        if let (Some(t), Some(table)) = (ids.table, panes.table) {
            self.models.insert(t, ViewModelBox::Table(table));
        }
        self.dialog_panes.insert(id, ids);
        Ok(ids)
    }

    /// Drops dialog `id`'s pane view models (after it closed).
    pub fn release_dialog(&mut self, id: u64) {
        if let Some(ids) = self.dialog_panes.remove(&id) {
            self.models.remove(&ids.tree);
            self.models.remove(&ids.form);
            if let Some(t) = ids.table {
                self.models.remove(&t);
            }
        }
    }

    /// A tree node was activated (double-click): go to its location.
    pub fn tree_activate(&mut self, tree: ProviderId, node: crate::view_models::NodeId) -> Result<(), String> {
        let location = match self.models.get(&tree) {
            Some(ViewModelBox::Tree(t)) => t.location(node),
            Some(_) => return Err(format!("provider {} is not a tree", tree.0)),
            None => return Err(format!("no view model for provider {}", tree.0)),
        };
        if let Some(address) = location {
            if let Err(message) = self.go_to(address) {
                self.events.post(UiEvent::Status(message));
            }
        }
        Ok(())
    }

    /// Installs the theme icon resolver.
    pub fn set_icon_resolver(&mut self, resolver: Box<dyn crate::icons::IconResolver>) {
        self.icons = Some(resolver);
    }

    /// The image file for theme icon `id`, if any.
    pub fn icon_path(&self, id: &str) -> Option<std::path::PathBuf> {
        self.icons.as_ref()?.resolve(id)
    }

    /// The renderer's wake handle (taken once).
    pub fn take_wake_handle(&mut self) -> Option<WakeHandle> {
        self.wake.take()
    }
}

impl Default for UiSession {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn title_is_app_name_then_version() {
        let s = UiSession::new();
        assert_eq!(s.title(), format!("Ghidra-rs {}", env!("CARGO_PKG_VERSION")));
    }

    #[test]
    fn tool_config_round_trips_layout_through_a_file() {
        let dir = std::env::temp_dir().join(format!("ghidra-ui-model-cfg-{}", std::process::id()));
        let path = dir.join("tool.xml");
        let mut a = crate::demo_tool::build_demo_session();
        a.tool_mut().layout_mut().set_geometry(Some(vec![7, 7, 7]));
        a.save_tool_config(&path).unwrap();
        let mut b = crate::demo_tool::build_demo_session();
        assert!(b.load_tool_config(&path).unwrap());
        assert_eq!(b.tool().layout().geometry(), Some(&[7u8, 7, 7][..]));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_or_corrupt_tool_config_keeps_defaults() {
        let mut s = crate::demo_tool::build_demo_session();
        assert!(!s.load_tool_config(std::path::Path::new("/nonexistent/ghidra-rs/tool.xml")).unwrap());
        let bad = std::env::temp_dir().join(format!("ghidra-ui-model-bad-{}.xml", std::process::id()));
        std::fs::write(&bad, "<not xml").unwrap();
        assert!(s.load_tool_config(&bad).is_err());
        assert_eq!(s.tool().provider_ids().count(), 5);
        let _ = std::fs::remove_file(&bad);
    }

    #[test]
    fn version_is_the_crate_version() {
        assert_eq!(UiSession::default().version(), env!("CARGO_PKG_VERSION"));
        assert_eq!(UiSession::default().app_name(), "Ghidra-rs");
    }

    #[test]
    fn a_window_menu_entry_shows_a_hidden_provider_and_tells_the_renderer() {
        use ghidra_rs::docking::show_component_action::DOCKING_WINDOWS_OWNER;
        let mut s = crate::demo_tool::build_demo_session();
        let symbols = s.tool().find_provider("Demo", "Symbols").unwrap();
        s.tool_mut().show_provider(symbols, false);
        let entry = s
            .tool()
            .actions()
            .global_actions()
            .find(|&id| {
                s.tool().actions().get(id).is_some_and(|a| {
                    a.state().owner() == DOCKING_WINDOWS_OWNER
                        && a.state().menu_bar_data().is_some_and(|m| m.menu_path().last().map(String::as_str) == Some("Symbols"))
                })
            })
            .expect("Window > Symbols");
        let ctx = ghidra_rs::docking::DefaultActionContext::new();
        s.tool_mut().actions_mut().get_mut(entry).unwrap().action_performed(&ctx);
        s.events().drain();
        s.apply_tool_requests();
        assert!(s.tool().provider(symbols).unwrap().state().is_visible());
        assert_eq!(s.events().drain(), vec![crate::events::UiEvent::ProviderShown { id: symbols.0, focus: true }]);
    }

    fn listing_at(s: &UiSession) -> Option<u128> {
        let id = s.tool().find_provider("Demo", "Listing").unwrap();
        match s.model(id) {
            Some(ViewModelBox::Listing(h)) => crate::listing_controller::lock(h).cursor().map(|c| c.index),
            _ => None,
        }
    }

    #[test]
    fn go_to_moves_the_target_listing_and_tells_the_renderer() {
        let mut s = crate::demo_tool::build_demo_session();
        let listing = s.tool().find_provider("Demo", "Listing").unwrap();
        s.events().drain();
        s.go_to(0x402000).unwrap();
        assert_eq!(listing_at(&s), Some(12));
        let events = s.events().drain();
        assert!(events.contains(&UiEvent::ViewChanged(listing.0)) && events.contains(&UiEvent::ActionsChanged));
        assert!(s.go_to(0x401800).unwrap_err().contains("401800"));
    }

    #[test]
    fn activating_a_symbol_row_navigates_the_listing() {
        let mut s = crate::demo_tool::build_demo_session();
        let symbols = s.tool().find_provider("Demo", "Symbols").unwrap();
        // demo rows: main 401000, _start 400f00 (unmapped), printf 402000, helper 401100
        s.table_activate(symbols, 2, 0).unwrap();
        assert_eq!(listing_at(&s), Some(12));
        s.events().drain();
        s.table_activate(symbols, 1, 0).unwrap();
        assert_eq!(listing_at(&s), Some(12));
        assert_eq!(s.events().drain(), vec![UiEvent::Status("Address not found: 400f00".into())]);
        assert!(s.table_activate(symbols, 99, 0).is_ok()); // no row: nothing to do
    }

    #[test]
    fn dialog_panes_get_dialog_scoped_view_ids_until_released() {
        use crate::options_dialog::{OptionsDialog, OptionsDialogState};
        use ghidra_rs::framework::options::option_type::OptionValue;
        let o = std::sync::Arc::new(ghidra_rs::framework::options::ToolOptions::new("Tool"));
        o.register_option("A.X", Some(OptionValue::Int(1)), None, "x").unwrap();
        o.register_option("B.Y", Some(OptionValue::Boolean(true)), None, "y").unwrap();
        let mut s = UiSession::new();
        let id = s.events().open_dialog(Box::new(OptionsDialog(OptionsDialogState::shared("T", vec![o]))));
        let ids = s.dialog_pane_ids(id).unwrap();
        let (tree, form) = (ids.tree, ids.form);
        assert!(tree.0 >= DIALOG_VIEW_BASE && form.0 >= DIALOG_VIEW_BASE && tree != form);
        assert_eq!(ids.table, None);
        assert_eq!(s.dialog_pane_ids(id).unwrap(), ids, "registered once");
        let b = match s.model_mut(tree) {
            Some(ViewModelBox::Tree(t)) => {
                let b = t.child(t.root(), 1);
                t.select(b);
                b
            }
            _ => panic!("tree pane"),
        };
        assert_eq!(b.0, 2);
        match s.model(form) {
            Some(ViewModelBox::Form(f)) => assert_eq!(f.fields()[0].label, "Y"),
            _ => panic!("form pane"),
        }
        s.release_dialog(id);
        assert!(s.model(tree).is_none() && s.model(form).is_none());
        assert!(UiSession::new().dialog_pane_ids(42).is_err());
    }

    #[test]
    fn double_clicking_a_program_tree_fragment_goes_to_its_start() {
        let mut s = crate::demo_tool::build_demo_session();
        let tree = s.tool().find_provider("Demo", "Program Tree").unwrap();
        let node = |s: &UiSession, name: &str| match s.model(tree) {
            Some(ViewModelBox::Tree(t)) => {
                let root = t.root();
                if name.is_empty() {
                    return root;
                }
                (0..t.child_count(root)).map(|i| t.child(root, i)).find(|&n| t.label(n) == name).unwrap()
            }
            _ => panic!("tree"),
        };
        let data = node(&s, ".data");
        s.tree_activate(tree, data).unwrap();
        assert_eq!(listing_at(&s), Some(12));
        let bss = node(&s, ".bss");
        s.tree_activate(tree, bss).unwrap(); // no memory behind it: nothing happens
        assert_eq!(listing_at(&s), Some(12));
        let root = node(&s, "");
        s.tree_activate(tree, root).unwrap();
        assert_eq!(listing_at(&s), Some(0));
    }
}
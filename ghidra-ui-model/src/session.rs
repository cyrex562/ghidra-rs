//! The root UI-session object every renderer talks to.

use std::collections::BTreeMap;

use ghidra_rs::docking::{ComponentProvider, DockingTool, ProviderId};

use crate::events::{UiEventQueue, WakeHandle};
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
    Listing(Box<dyn crate::listing::ListingViewModel>),
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
        let xml = self.tool.save_layout().save_to_xml().output_string();
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
        Ok(true)
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
        assert_eq!(s.tool().provider_ids().count(), 4);
        let _ = std::fs::remove_file(&bad);
    }

    #[test]
    fn version_is_the_crate_version() {
        assert_eq!(UiSession::default().version(), env!("CARGO_PKG_VERSION"));
        assert_eq!(UiSession::default().app_name(), "Ghidra-rs");
    }
}

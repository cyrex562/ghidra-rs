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
    fn version_is_the_crate_version() {
        assert_eq!(UiSession::default().version(), env!("CARGO_PKG_VERSION"));
        assert_eq!(UiSession::default().app_name(), "Ghidra-rs");
    }
}

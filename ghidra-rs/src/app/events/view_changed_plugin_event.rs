use crate::framework::plugintool::PluginEvent;
use crate::program::model::address::AddressSet;

const NAME: &str = "ViewChanged";

/// Event for notifying plugins when the program view changes (what the
/// Code Browser shows in the listing window).
///
/// Mirrors `ghidra.app.events.ViewChangedPluginEvent`.
pub struct ViewChangedPluginEvent {
    event: PluginEvent,
    tree_name: String,
    view_set: AddressSet,
}

impl ViewChangedPluginEvent {
    /// Creates a new view changed event.
    ///
    /// # Arguments
    ///
    /// * `source` - Name of the plugin that created this event
    /// * `tree_name` - Name of the tree in the program
    /// * `view_set` - Set of addresses in the view
    pub fn new(
        source: impl Into<String>,
        tree_name: impl Into<String>,
        view_set: AddressSet,
    ) -> Self {
        Self {
            event: PluginEvent::new(source, NAME),
            tree_name: tree_name.into(),
            view_set,
        }
    }

    /// Returns the name of the tree where the view is from.
    ///
    /// Mirrors `getTreeName()`.
    pub fn get_tree_name(&self) -> &str {
        &self.tree_name
    }

    /// Returns the address set in the view.
    ///
    /// Mirrors `getView()`.
    pub fn get_view(&self) -> &AddressSet {
        &self.view_set
    }

    /// Returns a reference to the underlying `PluginEvent`.
    pub fn event(&self) -> &PluginEvent {
        &self.event
    }

    /// Returns a mutable reference to the underlying `PluginEvent`.
    pub fn event_mut(&mut self) -> &mut PluginEvent {
        &mut self.event
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_stores_source() {
        let view_set = AddressSet::new();
        let event = ViewChangedPluginEvent::new("TestPlugin", "DefaultTree", view_set);

        assert_eq!(event.event().source_name(), "TestPlugin");
    }

    #[test]
    fn new_stores_tree_name() {
        let view_set = AddressSet::new();
        let event = ViewChangedPluginEvent::new("TestPlugin", "MyTree", view_set);

        assert_eq!(event.get_tree_name(), "MyTree");
    }

    #[test]
    fn new_stores_view_set() {
        let view_set = AddressSet::new();
        let event = ViewChangedPluginEvent::new("TestPlugin", "DefaultTree", view_set.clone());

        assert_eq!(event.get_view(), &view_set);
    }

    #[test]
    fn event_name_is_correct() {
        let view_set = AddressSet::new();
        let event = ViewChangedPluginEvent::new("TestPlugin", "DefaultTree", view_set);

        assert_eq!(event.event().event_name(), "ViewChanged");
    }

    #[test]
    fn get_tree_name_returns_stored_name() {
        let view_set = AddressSet::new();
        let tree_name = "ImportantTree";
        let event = ViewChangedPluginEvent::new("TestPlugin", tree_name, view_set);

        assert_eq!(event.get_tree_name(), tree_name);
    }

    #[test]
    fn get_view_returns_stored_set() {
        let view_set = AddressSet::new();
        let event = ViewChangedPluginEvent::new("TestPlugin", "DefaultTree", view_set.clone());

        assert_eq!(event.get_view(), &view_set);
    }

    #[test]
    fn event_mut_allows_modification() {
        let view_set = AddressSet::new();
        let mut event = ViewChangedPluginEvent::new("TestPlugin", "DefaultTree", view_set);

        event.event_mut().set_source_name("NewSource");
        assert_eq!(event.event().source_name(), "NewSource");
    }

    #[test]
    fn name_constant_is_correct() {
        assert_eq!(NAME, "ViewChanged");
    }

    #[test]
    fn accepts_owned_strings() {
        let view_set = AddressSet::new();
        let source = String::from("PluginA");
        let tree = String::from("Tree1");
        let event = ViewChangedPluginEvent::new(source, tree, view_set);

        assert_eq!(event.event().source_name(), "PluginA");
        assert_eq!(event.get_tree_name(), "Tree1");
    }

    #[test]
    fn accepts_string_slices() {
        let view_set = AddressSet::new();
        let event = ViewChangedPluginEvent::new("PluginB", "Tree2", view_set);

        assert_eq!(event.event().source_name(), "PluginB");
        assert_eq!(event.get_tree_name(), "Tree2");
    }
}

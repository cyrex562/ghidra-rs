//! Port of `docking.ComponentProvider`, toolkit-neutral.
//!
//! The provider's state (name, owner, titles, placement, view kind) is a
//! shared-state struct (R11); behaviour hooks are on the [`ComponentProvider`]
//! trait. Java's `getComponent()` (a Swing `JComponent`) is replaced by a
//! [`ProviderViewKind`]: the renderer builds the matching generic view (Qt6
//! UI spec §2, §4). Title changes are recorded as [`ProviderChange`]s instead
//! of calling back into the tool.

use crate::docking::action_context::ActionContext;
use crate::docking::{DefaultActionContext, IconId, ProviderId, WindowPosition};

/// `ComponentProvider.DEFAULT_WINDOW_GROUP`
pub const DEFAULT_WINDOW_GROUP: &str = "Default";

/// The kind of generic view a provider shows (the renderer contract's
/// `ViewKind`, kept in `ghidra-rs` so this crate never depends on the UI crate).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ProviderViewKind {
    /// Sortable, filterable rows and columns.
    Table,
    /// Hierarchical nodes.
    Tree,
    /// Styled lines with hyperlinks (decompiler, console).
    Text,
    /// Option / edit fields.
    Form,
    /// The code listing.
    Listing,
    /// A bespoke renderer widget, by id (e.g. `"graph"`).
    Custom(String),
}

/// What changed on a provider (the tool used to be called back for these).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProviderChange {
    /// `title` changed.
    Title,
    /// `subTitle` changed.
    SubTitle,
    /// `tabText` changed.
    TabText,
    /// The icon changed.
    Icon,
    /// Visibility changed.
    Visible,
}

/// Shared state of a component provider.
#[derive(Debug, Clone)]
pub struct ComponentProviderState {
    id: Option<ProviderId>,
    name: String,
    owner: String,
    title: String,
    sub_title: Option<String>,
    tab_text: Option<String>,
    custom_title: Option<String>,
    custom_sub_title: Option<String>,
    custom_tab_text: Option<String>,
    icon: Option<IconId>,
    window_menu_group: Option<String>,
    group: String,
    default_position: WindowPosition,
    intra_group_position: WindowPosition,
    visible: bool,
    is_transient: bool,
    help_location: Option<String>,
    view_kind: ProviderViewKind,
    pending: Vec<ProviderChange>,
}

impl ComponentProviderState {
    /// `new ComponentProvider(tool, name, owner)`: title defaults to the name,
    /// placement to a separate window, stacked within its group.
    pub fn new(name: impl Into<String>, owner: impl Into<String>, view_kind: ProviderViewKind) -> Self {
        let name = name.into();
        Self {
            id: None,
            title: name.clone(),
            name,
            owner: owner.into(),
            sub_title: None,
            tab_text: None,
            custom_title: None,
            custom_sub_title: None,
            custom_tab_text: None,
            icon: None,
            window_menu_group: None,
            group: DEFAULT_WINDOW_GROUP.to_owned(),
            default_position: WindowPosition::Window,
            intra_group_position: WindowPosition::Stack,
            visible: false,
            is_transient: false,
            help_location: None,
            view_kind,
            pending: Vec::new(),
        }
    }

    fn changed(&mut self, c: ProviderChange) {
        if !self.pending.contains(&c) {
            self.pending.push(c);
        }
    }

    /// Drains recorded changes.
    pub fn take_changes(&mut self) -> Vec<ProviderChange> {
        std::mem::take(&mut self.pending)
    }

    /// The id assigned by the tool (`None` until added).
    pub fn id(&self) -> Option<ProviderId> {
        self.id
    }

    /// Set by the tool when the provider is added.
    pub fn set_id(&mut self, id: ProviderId) {
        self.id = Some(id);
    }

    /// `getName()`
    pub fn name(&self) -> &str {
        &self.name
    }

    /// `getOwner()`
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// Layout/persistence key: `"<owner>.<name>"`.
    pub fn layout_key(&self) -> String {
        format!("{}.{}", self.owner, self.name)
    }

    /// `getTitle()`
    pub fn title(&self) -> &str {
        &self.title
    }

    /// `setTitle`: ignored once a custom title is set.
    pub fn set_title(&mut self, title: impl Into<String>) {
        if self.custom_title.is_some() {
            return;
        }
        let t = title.into();
        if t != self.title {
            self.title = t;
            self.changed(ProviderChange::Title);
        }
    }

    /// `setCustomTitle`: locks the title against later `set_title` calls.
    pub fn set_custom_title(&mut self, title: impl Into<String>) {
        let t = title.into();
        self.custom_title = Some(t.clone());
        if t != self.title {
            self.title = t;
            self.changed(ProviderChange::Title);
        }
    }

    /// `getSubTitle()`
    pub fn sub_title(&self) -> Option<&str> {
        self.sub_title.as_deref()
    }

    /// `setSubTitle`: ignored once a custom sub-title is set.
    pub fn set_sub_title(&mut self, sub_title: Option<String>) {
        if self.custom_sub_title.is_some() {
            return;
        }
        if sub_title != self.sub_title {
            self.sub_title = sub_title;
            self.changed(ProviderChange::SubTitle);
        }
    }

    /// `setCustomSubTitle`
    pub fn set_custom_sub_title(&mut self, sub_title: impl Into<String>) {
        let s = sub_title.into();
        self.custom_sub_title = Some(s.clone());
        if self.sub_title.as_deref() != Some(s.as_str()) {
            self.sub_title = Some(s);
            self.changed(ProviderChange::SubTitle);
        }
    }

    /// `getTabText()`
    pub fn tab_text(&self) -> Option<&str> {
        self.tab_text.as_deref()
    }

    /// `setTabText`: ignored once custom tab text is set.
    pub fn set_tab_text(&mut self, tab_text: Option<String>) {
        if self.custom_tab_text.is_some() {
            return;
        }
        if tab_text != self.tab_text {
            self.tab_text = tab_text;
            self.changed(ProviderChange::TabText);
        }
    }

    /// `setCustomTabText`
    pub fn set_custom_tab_text(&mut self, tab_text: impl Into<String>) {
        let t = tab_text.into();
        self.custom_tab_text = Some(t.clone());
        if self.tab_text.as_deref() != Some(t.as_str()) {
            self.tab_text = Some(t);
            self.changed(ProviderChange::TabText);
        }
    }

    /// `getIcon()`
    pub fn icon(&self) -> Option<&IconId> {
        self.icon.as_ref()
    }

    /// `setIcon`
    pub fn set_icon(&mut self, icon: Option<IconId>) {
        if icon != self.icon {
            self.icon = icon;
            self.changed(ProviderChange::Icon);
        }
    }

    /// `getWindowMenuGroup()`
    pub fn window_menu_group(&self) -> Option<&str> {
        self.window_menu_group.as_deref()
    }

    /// `setWindowMenuGroup`
    pub fn set_window_menu_group(&mut self, group: Option<String>) {
        self.window_menu_group = group;
    }

    /// `getWindowGroup()`
    pub fn window_group(&self) -> &str {
        &self.group
    }

    /// `setWindowGroup`
    pub fn set_window_group(&mut self, group: impl Into<String>) {
        self.group = group.into();
    }

    /// `getDefaultWindowPosition()`
    pub fn default_position(&self) -> WindowPosition {
        self.default_position
    }

    /// `setDefaultWindowPosition`
    pub fn set_default_position(&mut self, position: WindowPosition) {
        self.default_position = position;
    }

    /// `getIntraGroupPosition()`
    pub fn intra_group_position(&self) -> WindowPosition {
        self.intra_group_position
    }

    /// `setIntraGroupPosition`
    pub fn set_intra_group_position(&mut self, position: WindowPosition) {
        self.intra_group_position = position;
    }

    /// `isVisible()`
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    /// Visibility as tracked by the tool (Java `setVisible` routes through the tool).
    pub fn set_visible(&mut self, visible: bool) {
        if visible != self.visible {
            self.visible = visible;
            self.changed(ProviderChange::Visible);
        }
    }

    /// `isTransient()`
    pub fn is_transient(&self) -> bool {
        self.is_transient
    }

    /// `setTransient()`: transient providers are not saved in the layout.
    pub fn set_transient(&mut self) {
        self.is_transient = true;
    }

    /// `getHelpLocation()` (as a help-location string).
    pub fn help_location(&self) -> Option<&str> {
        self.help_location.as_deref()
    }

    /// `setHelpLocation`
    pub fn set_help_location(&mut self, location: Option<String>) {
        self.help_location = location;
    }

    /// The generic view this provider shows.
    pub fn view_kind(&self) -> &ProviderViewKind {
        &self.view_kind
    }
}

/// A dockable component provider: state plus behaviour hooks.
pub trait ComponentProvider: Send {
    /// The provider's shared state.
    fn state(&self) -> &ComponentProviderState;

    /// Mutable access to the provider's shared state.
    fn state_mut(&mut self) -> &mut ComponentProviderState;

    /// `getActionContext(null)`: by default a context naming this provider.
    fn action_context(&self) -> Box<dyn ActionContext> {
        Box::new(DefaultActionContext::new().with_provider(self.state().id()))
    }

    /// `componentShown()`
    fn component_shown(&mut self) {}

    /// `componentHidden()`
    fn component_hidden(&mut self) {}

    /// `componentActivated()`
    fn component_activated(&mut self) {}

    /// `componentDeactived()`
    fn component_deactivated(&mut self) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    struct P(ComponentProviderState);
    impl ComponentProvider for P {
        fn state(&self) -> &ComponentProviderState {
            &self.0
        }
        fn state_mut(&mut self) -> &mut ComponentProviderState {
            &mut self.0
        }
    }

    fn provider() -> P {
        P(ComponentProviderState::new("Listing", "CodeBrowserPlugin", ProviderViewKind::Listing))
    }

    #[test]
    fn defaults_match_java() {
        let p = provider();
        assert_eq!(p.state().title(), "Listing"); // title defaults to name
        assert_eq!(p.state().tab_text(), None);
        assert_eq!(p.state().default_position(), WindowPosition::Window);
        assert_eq!(p.state().intra_group_position(), WindowPosition::Stack);
        assert_eq!(p.state().window_group(), DEFAULT_WINDOW_GROUP);
        assert!(!p.state().is_visible());
        assert_eq!(p.state().layout_key(), "CodeBrowserPlugin.Listing");
    }

    #[test]
    fn title_change_is_recorded_once() {
        let mut p = provider();
        p.state_mut().set_title("Listing: a.out");
        p.state_mut().set_title("Listing: a.out");
        assert_eq!(p.state_mut().take_changes(), vec![ProviderChange::Title]);
    }

    #[test]
    fn custom_title_locks_out_set_title() {
        let mut p = provider();
        p.state_mut().set_custom_title("Mine");
        p.state_mut().set_title("Theirs");
        assert_eq!(p.state().title(), "Mine");
        p.state_mut().set_custom_tab_text("T");
        p.state_mut().set_tab_text(Some("X".into()));
        assert_eq!(p.state().tab_text(), Some("T"));
    }

    #[test]
    fn default_action_context_names_the_provider() {
        let mut p = provider();
        p.state_mut().set_id(ProviderId(7));
        let ctx = p.action_context();
        assert_eq!(ctx.component_provider(), Some(ProviderId(7)));
    }
}

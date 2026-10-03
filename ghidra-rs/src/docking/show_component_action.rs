//! Port of `docking.ShowComponentAction` and `ShowAllComponentsAction`: the
//! auto-generated Window menu entries that bring a provider (or every
//! provider of a window sub-menu) back on screen.
//!
//! Java's actions hold the `DockingWindowManager`; here an action cannot
//! reach the tool that owns it, so it records a request in the tool's
//! [`ToolRequests`] queue and the tool applies it after the action ran
//! ([`crate::docking::DockingTool::apply_requests`]).

use std::sync::{Arc, Mutex, PoisonError};

use crate::docking::action::{DockingAction, DockingActionIf, KeyBindingType, MenuData};
use crate::framework::options::action_trigger::ActionTrigger;
use crate::docking::{ActionContext, ProviderId};

/// Owner name of the generated actions (Java `DOCKING_WINDOWS_OWNER`).
pub const DOCKING_WINDOWS_OWNER: &str = "DockingWindows";
/// The Window menu (Java `COMPONENT_MENU_NAME`).
pub const MENU_WINDOW: &str = "&Window";
const MAX_LENGTH: usize = 40;

/// A change an action or listener asks of the tool that owns it.
#[derive(Clone)]
pub enum ToolRequest {
    /// Show this provider.
    Show(ProviderId),
    /// The key-binding option `full_name` changed (Java `ToolActions.optionsChanged`).
    SetActionTrigger(String, Option<ActionTrigger>),
}

/// Requests made by actions and option listeners, applied by the tool.
#[derive(Clone, Default)]
pub struct ToolRequests(Arc<Mutex<Vec<ToolRequest>>>);

impl ToolRequests {
    /// Asks the tool to show `id`.
    pub fn request_show(&self, id: ProviderId) {
        self.push(ToolRequest::Show(id));
    }

    /// Queues a request.
    pub fn push(&self, request: ToolRequest) {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).push(request);
    }

    /// Takes the pending requests in order.
    pub fn take(&self) -> Vec<ToolRequest> {
        std::mem::take(&mut *self.0.lock().unwrap_or_else(PoisonError::into_inner))
    }
}

/// Java `truncateTitleAsNeeded`.
pub fn truncate_title(title: &str) -> String {
    if title.chars().count() <= MAX_LENGTH {
        return title.to_owned();
    }
    let head: String = title.chars().take(MAX_LENGTH - 3).collect();
    format!("{head}...")
}

/// A Window menu entry showing one provider, or all of a sub-menu's.
pub struct ShowComponentAction {
    state: DockingAction,
    targets: Vec<ProviderId>,
    requests: ToolRequests,
}

impl ShowComponentAction {
    /// The entry for one provider: `Window > title`, or
    /// `Window > sub_menu > full_title` inside a window sub-menu.
    pub fn for_provider(
        name: &str,
        title: &str,
        full_title: &str,
        sub_menu: Option<&str>,
        id: ProviderId,
        requests: ToolRequests,
    ) -> Self {
        // Java createKeyBindingType: SHARED (with the provider's show action)
        let mut state = DockingAction::with_key_binding_type(name, DOCKING_WINDOWS_OWNER, KeyBindingType::Shared);
        let path: Vec<&str> = match sub_menu {
            Some(sub) => vec![MENU_WINDOW, sub, "temporary_placeholder"],
            None => vec![MENU_WINDOW, "temporary_placeholder"],
        };
        let mut menu = MenuData::full(&path, None, Some("Permanent"), None, None).expect("non-empty path");
        // Plain: provider titles are not parsed for '&' mnemonics.
        menu.set_menu_item_name_plain(&if sub_menu.is_some() { full_title.to_owned() } else { truncate_title(title) });
        state.set_menu_bar_data(Some(menu));
        Self { state, targets: vec![id], requests }
    }

    /// `Window > sub_menu > Show All` (Java `ShowAllComponentsAction`, group "Z").
    pub fn show_all(sub_menu: &str, ids: Vec<ProviderId>, requests: ToolRequests) -> Self {
        let mut state = DockingAction::with_key_binding_type("Show All", DOCKING_WINDOWS_OWNER, KeyBindingType::Unsupported);
        state.set_menu_bar_data(MenuData::full(&[MENU_WINDOW, sub_menu, "Show All"], None, Some("Z"), None, None).ok());
        Self { state, targets: ids, requests }
    }

    /// The providers this entry shows.
    pub fn targets(&self) -> &[ProviderId] {
        &self.targets
    }
}

impl DockingActionIf for ShowComponentAction {
    fn state(&self) -> &DockingAction {
        &self.state
    }
    fn state_mut(&mut self) -> &mut DockingAction {
        &mut self.state
    }
    fn action_performed(&mut self, _context: &dyn ActionContext) {
        for &id in &self.targets {
            self.requests.request_show(id);
        }
    }
    fn is_enabled_for_context(&self, _context: &dyn ActionContext) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn long_titles_are_truncated_like_java() {
        assert_eq!(truncate_title("short"), "short");
        let long = "x".repeat(45);
        assert_eq!(truncate_title(&long), format!("{}...", "x".repeat(37)));
        assert_eq!(truncate_title(&"y".repeat(40)), "y".repeat(40));
    }

    #[test]
    fn menu_paths_follow_sub_menus() {
        let r = ToolRequests::default();
        let top = ShowComponentAction::for_provider("Symbols", "Symbols", "Symbols - main", None, ProviderId(1), r.clone());
        let md = top.state().menu_bar_data().unwrap();
        assert_eq!(md.menu_path(), &["&Window".to_string(), "Symbols".to_string()]);
        assert_eq!(md.menu_group(), Some("Permanent"));
        let sub = ShowComponentAction::for_provider("Bytes", "Bytes", "Bytes - ls", Some("Byte Viewers"), ProviderId(2), r.clone());
        assert_eq!(sub.state().menu_bar_data().unwrap().menu_path(), &["&Window", "Byte Viewers", "Bytes - ls"].map(String::from));
        let all = ShowComponentAction::show_all("Byte Viewers", vec![ProviderId(2), ProviderId(3)], r.clone());
        assert_eq!(all.state().menu_bar_data().unwrap().menu_path(), &["&Window", "Byte Viewers", "Show All"].map(String::from));
        assert_eq!(all.state().menu_bar_data().unwrap().menu_group(), Some("Z"));
        assert_eq!(all.state().owner(), DOCKING_WINDOWS_OWNER);
    }

    #[test]
    fn performing_requests_its_providers() {
        let r = ToolRequests::default();
        let mut all = ShowComponentAction::show_all("G", vec![ProviderId(2), ProviderId(3)], r.clone());
        all.action_performed(&crate::docking::DefaultActionContext::new());
        let shown: Vec<ProviderId> = r.take().into_iter().filter_map(|q| if let ToolRequest::Show(p) = q { Some(p) } else { None }).collect();
        assert_eq!(shown, vec![ProviderId(2), ProviderId(3)]);
        assert!(r.take().is_empty());
    }
}

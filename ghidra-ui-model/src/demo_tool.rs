//! The demo tool the Qt shell runs until real plugins exist (U1b): one
//! provider per fixed view kind plus a handful of actions that exercise
//! menus, toolbars, popups and context-sensitive key dispatch.

use ghidra_rs::docking::action::{ClosureAction, DockingAction, DockingActionIf, KeyBindingData, MenuData, ToggleDockingActionIf, ToggleState, ToolBarData};
use ghidra_rs::docking::{ActionContext, ComponentProvider, DockingTool, ProviderId, ComponentProviderState, IconId, ProviderViewKind, WindowPosition};
use ghidra_rs::util::awt::key_stroke::{vk, ALT_DOWN_MASK, CTRL_DOWN_MASK};
use ghidra_rs::util::awt::KeyStroke;

use crate::demo::{LinesText, MapForm, StaticTree, VecTable};
use crate::events::{UiEvent, UiEventQueue};
use crate::listing::{MemoryBlockSnapshot, MemoryListing};
use crate::listing_controller::{parse_address, ListingController, ListingHandle};
use crate::session::{UiSession, ViewModelBox};
use crate::view_models::{CellValue, FormField};

const OWNER: &str = "Demo";

struct DemoProvider(ComponentProviderState);

impl ComponentProvider for DemoProvider {
    fn state(&self) -> &ComponentProviderState {
        &self.0
    }
    fn state_mut(&mut self) -> &mut ComponentProviderState {
        &mut self.0
    }
}

fn provider(name: &str, kind: ProviderViewKind, pos: WindowPosition) -> Box<dyn ComponentProvider> {
    let mut s = ComponentProviderState::new(name, OWNER, kind);
    s.set_default_position(pos);
    Box::new(DemoProvider(s))
}

/// An action that reports itself in the status bar when performed.
struct StatusAction {
    state: DockingAction,
    events: UiEventQueue,
}

impl DockingActionIf for StatusAction {
    fn state(&self) -> &DockingAction {
        &self.state
    }
    fn state_mut(&mut self) -> &mut DockingAction {
        &mut self.state
    }
    fn action_performed(&mut self, _context: &dyn ActionContext) {
        self.events.post(UiEvent::Status(self.state.name().to_owned()));
    }
}

struct WrapAction {
    state: DockingAction,
    toggle: ToggleState,
    events: UiEventQueue,
}

impl DockingActionIf for WrapAction {
    fn state(&self) -> &DockingAction {
        &self.state
    }
    fn state_mut(&mut self) -> &mut DockingAction {
        &mut self.state
    }
    fn as_toggle(&self) -> Option<&dyn ToggleDockingActionIf> {
        Some(self)
    }
    fn action_performed(&mut self, _context: &dyn ActionContext) {
        let on = !self.is_selected();
        self.set_selected(on);
        self.events.post(UiEvent::Status(format!("Wrap Lines: {}", if on { "on" } else { "off" })));
    }
}

impl ToggleDockingActionIf for WrapAction {
    fn is_selected(&self) -> bool {
        self.toggle.is_selected()
    }
    fn set_selected(&mut self, v: bool) {
        if let Some(c) = self.toggle.set_selected(v) {
            self.state.record_change(c);
        }
    }
}

fn status_action(name: &str, events: &UiEventQueue) -> StatusAction {
    StatusAction { state: DockingAction::new(name, OWNER), events: events.clone() }
}

fn ctrl(code: i32) -> KeyBindingData {
    KeyBindingData::new(KeyStroke::new(code, CTRL_DOWN_MASK))
}

/// Builds the demo session: Symbols (table, left), Program Tree (tree, left),
/// Decompiler (text, right), Options (form, bottom) and their actions.
pub fn build_demo_session() -> UiSession {
    let mut s = UiSession::new();
    let events = s.events().clone();

    let symbols = s.add_provider(
        provider("Symbols", ProviderViewKind::Table, WindowPosition::Left),
        Some(ViewModelBox::Table(Box::new(VecTable::new(
            vec!["Name".into(), "Address".into(), "Size".into()],
            vec![
                vec![CellValue::Text("main".into()), CellValue::Address(0x401000), CellValue::Int(120)],
                vec![CellValue::Text("_start".into()), CellValue::Address(0x400f00), CellValue::Int(42)],
                vec![CellValue::Text("printf".into()), CellValue::Address(0x402000), CellValue::Int(8)],
                vec![CellValue::Text("helper".into()), CellValue::Address(0x401100), CellValue::Int(64)],
            ],
        )))),
        true,
    );
    s.add_provider(
        provider("Program Tree", ProviderViewKind::Tree, WindowPosition::Left),
        Some(ViewModelBox::Tree(Box::new(StaticTree::from_paths(&[
            "a.out/.text",
            "a.out/.data",
            "a.out/.bss",
            "a.out/.rodata",
        ])))),
        true,
    );
    let decompiler = s.add_provider(
        provider("Decompiler", ProviderViewKind::Text, WindowPosition::Right),
        Some(ViewModelBox::Text(Box::new(LinesText::new(vec![
            "int main(int argc, char **argv)".into(),
            "{".into(),
            "  helper(argc);".into(),
            "  printf(\"done\\n\");".into(),
            "  return 0;".into(),
            "}".into(),
        ])))),
        true,
    );
    s.add_provider(
        provider("Options", ProviderViewKind::Form, WindowPosition::Bottom),
        Some(ViewModelBox::Form(Box::new(MapForm::new(vec![
            FormField::text("font", "Listing Font", "Monospaced 12"),
            FormField::int("max_depth", "Max Call Depth", 5),
            FormField::bool("show_bytes", "Show Bytes", true),
        ])))),
        true,
    );

    // The code listing over a small synthetic memory image (a real imported
    // program replaces this once the ELF loader lands).
    let listing = ListingController::handle(Box::new(MemoryListing::new(
            32,
            vec![
                MemoryBlockSnapshot {
                    start: 0x0040_1000,
                    bytes: vec![0x55, 0x48, 0x89, 0xe5, 0x89, 0x7d, 0xfc, 0x8b, 0x45, 0xfc, 0x5d, 0xc3],
                },
                MemoryBlockSnapshot { start: 0x0040_2000, bytes: b"done\n\0".to_vec() },
            ],
    )));
    let listing_id = s.add_provider(
        provider("Listing", ProviderViewKind::Listing, WindowPosition::Stack),
        Some(ViewModelBox::Listing(listing.clone())),
        true,
    );

    // Test hook: a provider an older saved layout has never seen.
    if std::env::var_os("GHIDRA_RS_DEMO_EXTRA_PROVIDER").is_some() {
        s.add_provider(
            provider("Extra", ProviderViewKind::Table, WindowPosition::Right),
            Some(ViewModelBox::Table(Box::new(VecTable::new(vec!["Value".into()], vec![vec![CellValue::Int(1)]])))),
            true,
        );
    }

    let tool = s.tool_mut();
    tool.set_menu_group(&["&File"], Some("0"), None);
    tool.set_menu_group(&["&Edit"], Some("1"), None);
    tool.set_menu_group(&["&Search"], Some("3"), None);
    let mut exit = status_action("Exit", &events);
    exit.state.set_menu_bar_data(MenuData::full(&["&File", "E&xit"], None, Some("Z"), None, None).ok());
    tool.add_action(Box::new(exit));

    let mut copy = status_action("Copy", &events);
    copy.state.set_menu_bar_data(MenuData::full(&["&Edit", "&Copy"], None, Some("Clipboard"), None, None).ok());
    copy.state.set_key_binding_data(Some(ctrl(vk::C)));
    tool.add_action(Box::new(copy));

    let mut find = status_action("Find", &events);
    find.state.set_menu_bar_data(MenuData::new(&["&Search", "&Find..."]).ok());
    find.state.set_tool_bar_data(Some(ToolBarData::new(IconId::new("icon.search"), Some("Search"), None)));
    find.state.set_key_binding_data(Some(ctrl(vk::F)));
    tool.add_action(Box::new(find));

    let mut find_local = status_action("Find in Table", &events);
    find_local.state.set_popup_menu_data(MenuData::new(&["Find in Table"]).ok());
    find_local.state.set_key_binding_data(Some(ctrl(vk::F)));
    tool.add_local_action(symbols, Box::new(find_local));

    let mut wrap = WrapAction { state: DockingAction::new("Wrap Lines", OWNER), toggle: ToggleState::default(), events: events.clone() };
    wrap.state.set_popup_menu_data(MenuData::new(&["Wrap Lines"]).ok());
    tool.add_local_action(decompiler, Box::new(wrap));

    add_navigation_actions(s.tool_mut(), &events, listing, listing_id);
    s
}

/// Go To (`G`) and Previous/Next Location (Alt-Left/Alt-Right) over the
/// listing (Java `GoToAddressLabelPlugin`, `NavigationHistoryPlugin`).
fn add_navigation_actions(tool: &mut DockingTool, events: &UiEventQueue, listing: ListingHandle, listing_id: ProviderId) {
    tool.set_menu_group(&["&Navigation"], Some("2"), None);
    let (ev, h) = (events.clone(), listing.clone());
    let mut go_to = ClosureAction::new("Go To Address/Label", OWNER, move |_| {
        let (ev2, h2) = (ev.clone(), h.clone());
        ev.prompt(
            "Go To ...",
            "Enter an address:",
            "",
            Box::new(move |answer| {
                let Some(text) = answer else { return Ok(()) };
                let address = parse_address(&text)?;
                h2.lock().map_err(|_| "listing state poisoned".to_string())?.goto_address(address)?;
                ev2.post(UiEvent::ViewChanged(listing_id.0));
                ev2.post(UiEvent::ActionsChanged);
                Ok(())
            }),
        );
    });
    go_to.state_mut().set_menu_bar_data(MenuData::new(&["&Navigation", "&Go To..."]).ok());
    go_to.state_mut().set_key_binding_data(Some(KeyBindingData::new(KeyStroke::new(vk::G, 0))));
    tool.add_action(Box::new(go_to));

    for (name, key, icon, sub_group, forward) in [
        ("Previous Location", vk::LEFT, "icon.left", "1", false),
        ("Next Location", vk::RIGHT, "icon.right", "2", true),
    ] {
        let (ev, h, enabled) = (events.clone(), listing.clone(), listing.clone());
        let mut a = ClosureAction::new(name, OWNER, move |_| {
            let moved = h.lock().map(|mut c| if forward { c.forward() } else { c.back() }).unwrap_or(false);
            if moved {
                ev.post(UiEvent::ViewChanged(listing_id.0));
                ev.post(UiEvent::ActionsChanged);
            }
        });
        a.state_mut().enabled_when(Box::new(move |_| {
            enabled.lock().map(|c| if forward { c.can_go_forward() } else { c.can_go_back() }).unwrap_or(false)
        }));
        a.state_mut().set_tool_bar_data(Some(ToolBarData::new(IconId::new(icon), Some("Navigation"), Some(sub_group))));
        a.state_mut().set_key_binding_data(Some(KeyBindingData::new(KeyStroke::new(key, ALT_DOWN_MASK))));
        tool.add_action(Box::new(a));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_rs::docking::action::DispatchResult;
    use ghidra_rs::util::awt::key_stroke::{vk, CTRL_DOWN_MASK};
    use ghidra_rs::util::awt::KeyStroke;

    #[test]
    fn demo_has_one_provider_per_fixed_view_kind() {
        let s = build_demo_session();
        let kinds: Vec<_> = s
            .tool()
            .provider_ids()
            .map(|id| s.tool().provider(id).unwrap().state().view_kind().clone())
            .collect();
        for k in [ProviderViewKind::Table, ProviderViewKind::Tree, ProviderViewKind::Text, ProviderViewKind::Form] {
            assert!(kinds.contains(&k), "{k:?}");
        }
        for id in s.tool().provider_ids() {
            assert!(s.model(id).is_some(), "provider {id:?} has a model");
        }
    }


    fn listing(s: &UiSession) -> (ProviderId, crate::listing_controller::ListingHandle) {
        let id = s.tool().find_provider("Demo", "Listing").unwrap();
        match s.model(id) {
            Some(ViewModelBox::Listing(h)) => (id, h.clone()),
            _ => panic!("listing model"),
        }
    }

    fn take_prompt(s: &UiSession) -> u64 {
        s.events()
            .drain()
            .into_iter()
            .find_map(|e| match e {
                UiEvent::Prompt { id, .. } => Some(id),
                _ => None,
            })
            .expect("a prompt")
    }

    #[test]
    fn previous_location_precedes_next_on_the_toolbar() {
        let s = build_demo_session();
        let ctx = ghidra_rs::docking::DefaultActionContext::new();
        let tips: Vec<String> = crate::menus::tool_bar(s.tool(), &ctx)
            .into_iter()
            .filter_map(|e| match e {
                crate::menus::ToolBarEntry::Button { tooltip, .. } => Some(tooltip),
                _ => None,
            })
            .filter(|t| t.ends_with("Location"))
            .collect();
        assert_eq!(tips, vec!["Previous Location", "Next Location"]);
    }

    #[test]
    fn g_prompts_for_an_address_and_goes_there() {
        let mut s = build_demo_session();
        let (id, h) = listing(&s);
        h.lock().unwrap().set_viewport(100);
        assert!(matches!(s.tool_mut().dispatch_key(KeyStroke::new(vk::G, 0), Some(id)), DispatchResult::Performed(_)));
        let prompt = take_prompt(&s);
        s.events().answer_prompt(prompt, Some("0x402000".into())).unwrap();
        assert_eq!(h.lock().unwrap().cursor().map(|c| c.index), Some(12));
        assert!(s.events().drain().contains(&UiEvent::ViewChanged(id.0)));
    }

    #[test]
    fn a_bad_go_to_reports_and_leaves_the_listing_alone() {
        let mut s = build_demo_session();
        let (id, h) = listing(&s);
        s.tool_mut().dispatch_key(KeyStroke::new(vk::G, 0), Some(id));
        let prompt = take_prompt(&s);
        s.events().answer_prompt(prompt, Some("401800".into())).unwrap();
        assert_eq!(s.events().drain(), vec![UiEvent::Status("Address not found: 401800".into())]);
        assert_eq!(h.lock().unwrap().cursor(), None);
        s.tool_mut().dispatch_key(KeyStroke::new(vk::G, 0), Some(id));
        let cancelled = take_prompt(&s);
        s.events().answer_prompt(cancelled, None).unwrap();
        assert!(s.events().drain().is_empty());
    }

    #[test]
    fn alt_arrows_walk_the_history_and_follow_enablement() {
        let mut s = build_demo_session();
        let (id, h) = listing(&s);
        let back = KeyStroke::new(vk::LEFT, ALT_DOWN_MASK);
        let fwd = KeyStroke::new(vk::RIGHT, ALT_DOWN_MASK);
        assert!(!matches!(s.tool_mut().dispatch_key(back, Some(id)), DispatchResult::Performed(_)));
        h.lock().unwrap().key(crate::listing::Move::Down, false);
        h.lock().unwrap().goto_address(0x402000).unwrap();
        assert!(matches!(s.tool_mut().dispatch_key(back, Some(id)), DispatchResult::Performed(_)));
        assert_eq!(h.lock().unwrap().cursor().map(|c| c.index), Some(1));
        assert!(matches!(s.tool_mut().dispatch_key(fwd, Some(id)), DispatchResult::Performed(_)));
        assert_eq!(h.lock().unwrap().cursor().map(|c| c.index), Some(12));
    }

    #[test]
    fn ctrl_f_is_local_in_symbols_and_global_elsewhere() {
        let mut s = build_demo_session();
        let symbols = s.tool().find_provider("Demo", "Symbols").unwrap();
        let tree = s.tool().find_provider("Demo", "Program Tree").unwrap();
        let ctrl_f = KeyStroke::new(vk::F, CTRL_DOWN_MASK);
        let local = s.tool_mut().dispatch_key(ctrl_f, Some(symbols));
        let global = s.tool_mut().dispatch_key(ctrl_f, Some(tree));
        match (local, global) {
            (DispatchResult::Performed(a), DispatchResult::Performed(b)) => assert_ne!(a, b),
            other => panic!("{other:?}"),
        }
        let statuses: Vec<String> = s
            .events()
            .drain()
            .into_iter()
            .filter_map(|e| match e {
                UiEvent::Status(m) => Some(m),
                _ => None,
            })
            .collect();
        assert_eq!(statuses, vec!["Find in Table".to_string(), "Find".to_string()]);
    }
}

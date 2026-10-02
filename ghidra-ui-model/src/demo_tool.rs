//! The demo tool the Qt shell runs until real plugins exist (U1b): one
//! provider per fixed view kind plus a handful of actions that exercise
//! menus, toolbars, popups and context-sensitive key dispatch.

use ghidra_rs::docking::action::{DockingAction, DockingActionIf, KeyBindingData, MenuData, ToggleDockingActionIf, ToggleState, ToolBarData};
use ghidra_rs::docking::{ActionContext, ComponentProvider, ComponentProviderState, IconId, ProviderViewKind, WindowPosition};
use ghidra_rs::util::awt::key_stroke::{vk, CTRL_DOWN_MASK};
use ghidra_rs::util::awt::KeyStroke;

use crate::demo::{LinesText, MapForm, StaticTree, VecTable};
use crate::events::{UiEvent, UiEventQueue};
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

    let tool = s.tool_mut();
    tool.set_menu_group(&["&File"], Some("0"), None);
    tool.set_menu_group(&["&Edit"], Some("1"), None);
    tool.set_menu_group(&["&Search"], Some("2"), None);
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

    let mut wrap = WrapAction { state: DockingAction::new("Wrap Lines", OWNER), toggle: ToggleState::default(), events };
    wrap.state.set_popup_menu_data(MenuData::new(&["Wrap Lines"]).ok());
    tool.add_local_action(decompiler, Box::new(wrap));

    s
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

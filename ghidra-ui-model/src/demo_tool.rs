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
use crate::go_to_dialog::{GoToAddressLabelDialog, QueryData, SharedGoToDialog};
use crate::options_dialog::{OptionsDialog, OptionsDialogState};
use ghidra_rs::framework::options::option_type::OptionValue;
use ghidra_rs::framework::options::options_change_listener::OptionsChangeListener;
use ghidra_rs::framework::options::{SharedOptionsListener, ToolOptions};
use crate::program_import::ImportedProgram;
use crate::session::ConfigState;
use std::sync::{Arc, Mutex};
use crate::listing_controller::{lock, parse_address, ListingController, ListingHandle};
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
    build_session_for(None)
}

/// The demo tool showing `program` (`ghidra-qt --open`) in place of the
/// synthetic image: its memory in the Listing and its blocks in the Program
/// Tree; Symbols stays empty until ELF symbols are loaded.
pub fn build_session_for(program: Option<&ImportedProgram>) -> UiSession {
    let mut s = UiSession::new();
    let events = s.events().clone();

    let symbols = s.add_provider(
        provider("Symbols", ProviderViewKind::Table, WindowPosition::Left),
        Some(ViewModelBox::Table(Box::new(VecTable::new(
            vec!["Name".into(), "Address".into(), "Size".into()],
            if program.is_some() {
                Vec::new() // ELF symbols arrive with ElfProgramBuilder phase 2
            } else {
                vec![
                    vec![CellValue::Text("main".into()), CellValue::Address(0x401000), CellValue::Int(120)],
                    vec![CellValue::Text("_start".into()), CellValue::Address(0x400f00), CellValue::Int(42)],
                    vec![CellValue::Text("printf".into()), CellValue::Address(0x402000), CellValue::Int(8)],
                    vec![CellValue::Text("helper".into()), CellValue::Address(0x401100), CellValue::Int(64)],
                ]
            },
        )))),
        true,
    );
    s.add_provider(
        provider("Program Tree", ProviderViewKind::Tree, WindowPosition::Left),
        Some(ViewModelBox::Tree(Box::new(match program {
            Some(p) => {
                // '/' separates tree levels; block names never nest
                let paths: Vec<String> = p.block_names.iter().map(|b| format!("{}/{}", p.name, b.replace('/', "\u{2215}"))).collect();
                let located: Vec<(&str, Option<u64>)> =
                    paths.iter().map(String::as_str).zip(p.block_starts.iter().map(|&a| Some(a))).collect();
                StaticTree::with_locations(&located)
            }
            None => StaticTree::with_locations(&[
                ("a.out/.text", Some(0x0040_1000)),
                ("a.out/.data", Some(0x0040_2000)),
                ("a.out/.bss", None),
                ("a.out/.rodata", None),
            ]),
        }))),
        true,
    );
    let decompiler = s.add_provider(
        provider("Decompiler", ProviderViewKind::Text, WindowPosition::Right),
        Some(ViewModelBox::Text(Box::new(LinesText::new(if program.is_some() {
            vec!["// The decompiler is not ported yet.".into()]
        } else {
            vec![
                "int main(int argc, char **argv)".into(),
                "{".into(),
                "  helper(argc);".into(),
                "  printf(\"done\\n\");".into(),
                "  return 0;".into(),
                "}".into(),
            ]
        })))),
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
    let memory = match program {
        Some(p) => MemoryListing::new(p.address_bits, p.blocks.clone()),
        None => MemoryListing::new(
            32,
            vec![
                MemoryBlockSnapshot::initialized(0x0040_1000, vec![0x55, 0x48, 0x89, 0xe5, 0x89, 0x7d, 0xfc, 0x8b, 0x45, 0xfc, 0x5d, 0xc3]),
                MemoryBlockSnapshot::initialized(0x0040_2000, b"done\n\0".to_vec()),
            ],
        ),
    };
    let listing = ListingController::handle(Box::new(memory));
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

    s.set_central_provider(listing_id);
    s.set_goto_target(listing_id);
    if let Some(theme) = crate::icons::load_default_theme() {
        s.set_icon_resolver(theme);
    }
    let mut config = Vec::new();
    let go_to = add_navigation_actions(s.tool_mut(), &events, listing, listing_id, &mut config);
    add_tool_options(s.tool_mut(), &events, go_to, &mut config);
    for (name, state) in config {
        s.add_config_state(&name, state);
    }
    s
}

/// Go To (`G`) and Previous/Next Location (Alt-Left/Alt-Right) over the
/// listing (Java `GoToAddressLabelPlugin`, `NavigationHistoryPlugin`).
fn add_navigation_actions(
    tool: &mut DockingTool,
    events: &UiEventQueue,
    listing: ListingHandle,
    listing_id: ProviderId,
    config: &mut Vec<(String, Box<dyn ConfigState>)>,
) -> SharedGoToDialog {
    tool.set_menu_group(&["&Navigation"], Some("2"), None);
    // GoToService.goToQuery for the listing: addresses only until symbols land
    // (a label finds nothing, as Ghidra reports for an unknown label).
    let (ev, h) = (events.clone(), listing.clone());
    let dialog = SharedGoToDialog(Arc::new(Mutex::new(GoToAddressLabelDialog::new(Box::new(move |q: &QueryData| {
        let Ok(address) = parse_address(&q.query) else { return Ok(false) };
        if lock(&h).goto_address(address).is_err() {
            return Ok(false);
        }
        ev.post(UiEvent::ViewChanged(listing_id.0));
        ev.post(UiEvent::ActionsChanged);
        Ok(true)
    })))));
    config.push(("GoToAddressLabelPlugin".to_owned(), Box::new(dialog.clone())));
    let shared_dialog = dialog.clone();
    let ev = events.clone();
    let mut go_to = ClosureAction::new("Go To Address/Label", OWNER, move |_| {
        ev.open_dialog(Box::new(dialog.clone()));
    });
    go_to.state_mut().set_menu_bar_data(MenuData::new(&["&Navigation", "&Go To..."]).ok());
    go_to.state_mut().set_key_binding_data(Some(KeyBindingData::new(KeyStroke::new(vk::G, 0))));
    tool.add_action(Box::new(go_to));

    for (name, key, icon, sub_group, forward) in [
        ("Previous Location", vk::LEFT, "icon.plugin.navigation.location.previous", "1", false),
        ("Next Location", vk::RIGHT, "icon.plugin.navigation.location.next", "2", true),
    ] {
        let (ev, h, enabled) = (events.clone(), listing.clone(), listing.clone());
        let mut a = ClosureAction::new(name, OWNER, move |_| {
            let moved = {
                let mut c = lock(&h);
                if forward { c.forward() } else { c.back() }
            };
            if moved {
                ev.post(UiEvent::ViewChanged(listing_id.0));
                ev.post(UiEvent::ActionsChanged);
            }
        });
        a.state_mut().enabled_when(Box::new(move |_| {
            let c = lock(&enabled);
            if forward { c.can_go_forward() } else { c.can_go_back() }
        }));
        a.state_mut().set_tool_bar_data(Some(ToolBarData::new(IconId::new(icon), Some("Navigation"), Some(sub_group))));
        a.state_mut().set_key_binding_data(Some(KeyBindingData::new(KeyStroke::new(key, ALT_DOWN_MASK))));
        tool.add_action(Box::new(a));
    }
    shared_dialog
}

/// Java `GhidraOptions.OPTION_MAX_GO_TO_ENTRIES`.
const MAX_GOTO_ENTRIES: &str = "Max Goto Entries";

/// The tool's "Tool" options (Java `ToolConstants.TOOL_OPTIONS`) and
/// `Edit > Tool Options` (Java `PluginTool.addOptionsAction`).
fn add_tool_options(
    tool: &mut DockingTool,
    events: &UiEventQueue,
    go_to: SharedGoToDialog,
    config: &mut Vec<(String, Box<dyn ConfigState>)>,
) {
    let options = Arc::new(ToolOptions::new("Tool"));
    // GoToAddressLabelPlugin.initOptions
    let _ = options.register_option(
        MAX_GOTO_ENTRIES,
        Some(OptionValue::Int(crate::go_to_dialog::DEFAULT_MAX_GOTO_ENTRIES as i32)),
        None,
        "Max number of entries remembered in the go to list.",
    );
    let listener: SharedOptionsListener = Arc::new(Mutex::new(MaxGotoListener(go_to)));
    options.add_options_change_listener(&listener);
    config.push(("OPTIONS".to_owned(), Box::new(ToolOptionsState { options: options.clone(), _listener: listener })));

    let (ev, tool_name) = (events.clone(), tool.name().to_owned());
    let mut edit = ClosureAction::new("Edit Options", OWNER, move |_| {
        ev.open_dialog(Box::new(OptionsDialog(OptionsDialogState::shared(&tool_name, vec![options.clone()]))));
    });
    edit.state_mut().set_menu_bar_data(MenuData::full(&["&Edit", "&Tool Options"], None, Some("AOptions"), None, Some("AOptions")).ok());
    tool.add_action(Box::new(edit));
}

/// GoToAddressLabelPlugin.optionsChanged: the history follows Max Goto Entries.
struct MaxGotoListener(SharedGoToDialog);

impl OptionsChangeListener for MaxGotoListener {
    fn options_changed(
        &mut self,
        _options: &dyn ghidra_rs::framework::seam_stubs::ToolOptions,
        option_name: &str,
        _old_value: Option<&dyn std::any::Any>,
        new_value: Option<&dyn std::any::Any>,
    ) -> Result<(), Box<dyn ghidra_rs::framework::seam_stubs::OptionsVetoException>> {
        if option_name == MAX_GOTO_ENTRIES {
            if let Some(OptionValue::Int(n)) = new_value.and_then(|v| v.downcast_ref::<OptionValue>()) {
                self.0 .0.lock().unwrap_or_else(std::sync::PoisonError::into_inner).set_max_entries((*n).max(0) as usize);
            }
        }
        Ok(())
    }
}

/// The options saved with the tool config; also keeps their listener alive
/// (ToolOptions holds listeners weakly, as Java's WeakSet).
struct ToolOptionsState {
    options: Arc<ToolOptions>,
    _listener: SharedOptionsListener,
}

impl ConfigState for ToolOptionsState {
    fn write_config_state(&self, state: &mut ghidra_rs::framework::options::SaveState) {
        state.put_xml_element(&self.options.get_name(), self.options.get_xml_root(false));
    }
    fn read_config_state(&mut self, state: &ghidra_rs::framework::options::SaveState) {
        let Some(e) = state.get_xml_element(&self.options.get_name()) else { return };
        let saved = ToolOptions::from_xml(e);
        for name in saved.get_option_names() {
            if let (Some(_), Ok(Some(value))) = (self.options.find_option(&name), saved.get_object(&name, None)) {
                let _ = self.options.put_object(&name, Some(value)); // listeners see the restored value
            }
        }
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

    fn take_dialog(s: &UiSession) -> u64 {
        s.events()
            .drain()
            .into_iter()
            .find_map(|e| match e {
                UiEvent::Dialog(id) => Some(id),
                _ => None,
            })
            .expect("a dialog")
    }

    #[test]
    fn a_session_for_an_imported_program_shows_its_memory_and_blocks() {
        let program = ImportedProgram {
            name: "ls".into(),
            language: "x86:LE:64:default".into(),
            address_bits: 64,
            blocks: vec![MemoryBlockSnapshot::initialized(0x10_0000, vec![0x7f, 0x45]), MemoryBlockSnapshot::uninitialized(0x12_0000, 3)],
            block_names: vec!["segment_1".into(), ".bss".into()],
            block_starts: vec![0x10_0000, 0x12_0000],
        };
        let s = build_session_for(Some(&program));
        let (_, h) = listing(&s);
        let frame = {
            let mut c = lock(&h);
            c.set_viewport(1000);
            c.frame()
        };
        assert_eq!(frame.rows.len(), 5);
        assert_eq!(frame.rows[0].row.runs[0].text, "0000000000100000");
        let tree = s.tool().find_provider("Demo", "Program Tree").unwrap();
        let Some(ViewModelBox::Tree(t)) = s.model(tree) else { panic!("tree") };
        let root = t.root();
        assert_eq!(t.label(root), "ls");
        assert_eq!((0..t.child_count(root)).map(|i| t.label(t.child(root, i))).collect::<Vec<_>>(), vec!["segment_1", ".bss"]);
        let symbols = s.tool().find_provider("Demo", "Symbols").unwrap();
        let Some(ViewModelBox::Table(sym)) = s.model(symbols) else { panic!("table") };
        assert_eq!(sym.row_count(), 0);
        let dec = s.tool().find_provider("Demo", "Decompiler").unwrap();
        let Some(ViewModelBox::Text(text)) = s.model(dec) else { panic!("text") };
        assert!(text.line_count() > 0);
        assert!(!(0..text.line_count()).any(|i| text.line(i).iter().any(|r| r.text.contains("main"))));
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

    fn edit_options_dialog(s: &mut UiSession) -> u64 {
        let action = s
            .tool()
            .actions()
            .global_actions()
            .find(|&id| s.tool().actions().get(id).is_some_and(|a| a.state().name() == "Edit Options"))
            .expect("Edit Options action");
        let ctx = ghidra_rs::docking::DefaultActionContext::new();
        s.tool_mut().actions_mut().get_mut(action).unwrap().action_performed(&ctx);
        take_dialog(s)
    }

    fn set_max_goto_entries(s: &mut UiSession, n: &str) {
        let d = edit_options_dialog(s);
        let (_, form) = s.dialog_pane_ids(d).unwrap();
        let Some(ViewModelBox::Form(f)) = s.model_mut(form) else { panic!("form") };
        let key = f.fields().into_iter().find(|f| f.label == "Max Goto Entries").expect("field").key;
        f.set(&key, n).unwrap();
        assert_eq!(s.events().dialog_ok(d, "", &[]).unwrap(), crate::dialogs::DialogReply::Close);
        s.release_dialog(d);
    }

    #[test]
    fn edit_options_lives_in_the_edit_menu_and_shows_tool_options() {
        let mut s = build_demo_session();
        let action = s.tool().actions().global_actions().find(|&id| s.tool().actions().get(id).is_some_and(|a| a.state().name() == "Edit Options")).unwrap();
        let md = s.tool().actions().get(action).unwrap().state().menu_bar_data().unwrap().clone();
        assert_eq!(md.menu_path(), &["&Edit".to_string(), "Tool Options".to_string()]);
        let d = edit_options_dialog(&mut s);
        assert_eq!(s.events().dialog_spec(d).unwrap().title, "Options for Ghidra-rs");
        let (_, form) = s.dialog_pane_ids(d).unwrap();
        let Some(ViewModelBox::Form(f)) = s.model(form) else { panic!("form") };
        let goto = f.fields().into_iter().find(|f| f.label == "Max Goto Entries").expect("Max Goto Entries");
        assert_eq!(goto.value, "10");
        assert!(!goto.tooltip.is_empty());
    }

    #[test]
    fn max_goto_entries_truncates_the_go_to_history() {
        let mut s = build_demo_session();
        let (id, _) = listing(&s);
        for a in ["401000", "401001", "401002"] {
            s.tool_mut().dispatch_key(KeyStroke::new(vk::G, 0), Some(id));
            let d = take_dialog(&s);
            s.events().dialog_ok(d, a, &[]).unwrap();
        }
        set_max_goto_entries(&mut s, "2");
        s.tool_mut().dispatch_key(KeyStroke::new(vk::G, 0), Some(id));
        let d = take_dialog(&s);
        assert_eq!(s.events().dialog_spec(d).unwrap().combo.unwrap().items, vec!["401002", "401001"]);
    }

    #[test]
    fn tool_options_are_saved_with_the_tool_config() {
        let dir = std::env::temp_dir().join(format!("ghidra-ui-model-opts-{}", std::process::id()));
        let path = dir.join("tool.xml");
        let mut s = build_demo_session();
        set_max_goto_entries(&mut s, "25");
        s.save_tool_config(&path).unwrap();
        let mut s2 = build_demo_session();
        s2.load_tool_config(&path).unwrap();
        let d = edit_options_dialog(&mut s2);
        let (_, form) = s2.dialog_pane_ids(d).unwrap();
        let Some(ViewModelBox::Form(f)) = s2.model(form) else { panic!("form") };
        assert_eq!(f.fields().into_iter().find(|f| f.label == "Max Goto Entries").unwrap().value, "25");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn g_opens_the_go_to_dialog_and_goes_there() {
        let mut s = build_demo_session();
        let (id, h) = listing(&s);
        lock(&h).set_viewport(100);
        assert!(matches!(s.tool_mut().dispatch_key(KeyStroke::new(vk::G, 0), Some(id)), DispatchResult::Performed(_)));
        let dialog = take_dialog(&s);
        assert_eq!(s.events().dialog_spec(dialog).unwrap().title, "Go To ...");
        assert_eq!(s.events().dialog_ok(dialog, "0x402000", &[]).unwrap(), crate::dialogs::DialogReply::Close);
        assert_eq!(lock(&h).cursor().map(|c| c.index), Some(12));
        assert!(s.events().drain().contains(&UiEvent::ViewChanged(id.0)));
        // the next opening offers the history
        s.tool_mut().dispatch_key(KeyStroke::new(vk::G, 0), Some(id));
        let again = take_dialog(&s);
        assert_eq!(s.events().dialog_spec(again).unwrap().combo.unwrap().items, vec!["0x402000"]);
    }

    #[test]
    fn a_go_to_with_no_results_stays_open_and_leaves_the_listing_alone() {
        let mut s = build_demo_session();
        let (id, h) = listing(&s);
        s.tool_mut().dispatch_key(KeyStroke::new(vk::G, 0), Some(id));
        let dialog = take_dialog(&s);
        for bad in ["401800", "zz"] {
            match s.events().dialog_ok(dialog, bad, &[]).unwrap() {
                crate::dialogs::DialogReply::Stay(spec) => assert_eq!(spec.status, format!("No results for {bad}")),
                other => panic!("{other:?}"),
            }
        }
        assert_eq!(lock(&h).cursor(), None);
        s.events().dialog_cancel(dialog).unwrap();
    }

    #[test]
    fn go_to_history_is_saved_with_the_tool_config() {
        let dir = std::env::temp_dir().join(format!("ghidra-ui-model-goto-{}", std::process::id()));
        let path = dir.join("tool.xml");
        let mut s = build_demo_session();
        let (id, _) = listing(&s);
        s.tool_mut().dispatch_key(KeyStroke::new(vk::G, 0), Some(id));
        let d = take_dialog(&s);
        s.events().dialog_ok(d, "402001", &[]).unwrap();
        s.save_tool_config(&path).unwrap();
        let mut s2 = build_demo_session();
        assert!(s2.load_tool_config(&path).unwrap());
        s2.tool_mut().dispatch_key(KeyStroke::new(vk::G, 0), Some(id));
        let d2 = take_dialog(&s2);
        assert_eq!(s2.events().dialog_spec(d2).unwrap().combo.unwrap().items, vec!["402001"]);
        let _ = std::fs::remove_dir_all(&dir);
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

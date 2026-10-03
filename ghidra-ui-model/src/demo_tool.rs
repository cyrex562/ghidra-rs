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
use crate::theme::{ChangeThemeDialog, SharedTheme, ThemeConfig, ThemedIcons, UiTheme};
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
        Some(ViewModelBox::Table(Box::new(match program {
            // Java SymbolTablePlugin columns (Namespace, reference counts: later)
            Some(p) => VecTable::new(
                vec!["Name".into(), "Location".into(), "Type".into(), "Source".into()],
                p.symbols
                    .iter()
                    .map(|s| {
                        vec![
                            CellValue::Text(s.name.clone()),
                            CellValue::Address(s.address),
                            CellValue::Text(s.kind.clone()),
                            CellValue::Text(s.source.clone()),
                        ]
                    })
                    .collect(),
            ),
            None => VecTable::new(
            vec!["Name".into(), "Address".into(), "Size".into()],
            {
                vec![
                    vec![CellValue::Text("main".into()), CellValue::Address(0x401000), CellValue::Int(120)],
                    vec![CellValue::Text("_start".into()), CellValue::Address(0x400f00), CellValue::Int(42)],
                    vec![CellValue::Text("printf".into()), CellValue::Address(0x402000), CellValue::Int(8)],
                    vec![CellValue::Text("helper".into()), CellValue::Address(0x401100), CellValue::Int(64)],
                ]
            },
            ),
        }))),
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
    let memory: Box<dyn crate::listing::ListingViewModel> = match program {
        // code units + the program's symbols as label rows
        Some(p) => Box::new(code_unit_listing(p, p.instructions.clone())),
        None => Box::new(MemoryListing::new(
            32,
            vec![
                MemoryBlockSnapshot::initialized(0x0040_1000, vec![0x55, 0x48, 0x89, 0xe5, 0x89, 0x7d, 0xfc, 0x8b, 0x45, 0xfc, 0x5d, 0xc3]),
                MemoryBlockSnapshot::initialized(0x0040_2000, b"done\n\0".to_vec()),
            ],
        )),
    };
    let listing = ListingController::handle(memory);
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

    // Java ClipboardPlugin "Copy": the focused provider's clipboard content —
    // the listing's selection (or cursor field); the demo panes just report.
    let (ev, copy_listing) = (events.clone(), listing.clone());
    let mut copy = ClosureAction::new("Copy", OWNER, move |context| {
        if context.component_provider() != Some(listing_id) {
            ev.post(UiEvent::Status("Copy".into()));
            return;
        }
        let copied = lock(&copy_listing).copy_text();
        match copied {
            Ok(Some(text)) => ev.post(UiEvent::Clipboard(text)),
            Ok(None) => {}
            Err(message) => ev.post(UiEvent::Status(message)),
        }
    });
    copy.state_mut().set_menu_bar_data(MenuData::full(&["&Edit", "&Copy"], None, Some("Clipboard"), None, None).ok());
    copy.state_mut().set_key_binding_data(Some(ctrl(vk::C)));
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
    // Theme (Java ThemeManagerPlugin): Flat Light by default; icons follow it.
    let theme: SharedTheme = Arc::new(Mutex::new(UiTheme::FlatLight));
    if let Some(icons) = crate::icons::default_theme_root().and_then(|root| ThemedIcons::load(&root, theme.clone()).ok()) {
        s.set_icon_resolver(Box::new(icons));
    }
    s.add_config_state("THEME", Box::new(ThemeConfig { theme: theme.clone(), events: s.events().clone() }));
    // The renderer starts in whatever the platform gives it: say which theme
    // is current so it matches the chooser (a saved one follows on load).
    s.events().post(UiEvent::ThemeChanged { dark: false });
    let ev = s.events().clone();
    let mut switch = ClosureAction::new("Switch Theme", OWNER, move |_| {
        ev.open_dialog(Box::new(ChangeThemeDialog::new(theme.clone(), ev.clone())));
    });
    switch.state_mut().set_menu_bar_data(MenuData::full(&["&Edit", "Theme", "Switch..."], None, Some("theme"), None, Some("1")).ok());
    s.tool_mut().add_action(Box::new(switch));
    let mut config = Vec::new();
    if let Some(p) = program.filter(|p| p.live.is_some()) {
        add_disassemble_action(s.tool_mut(), &events, listing.clone(), listing_id, p);
    }
    let go_to = add_navigation_actions(s.tool_mut(), &events, listing, listing_id, &mut config);
    add_tool_options(s.tool_mut(), &events, go_to, &mut config);
    for (name, state) in config {
        s.add_config_state(&name, state);
    }
    s
}

/// The code listing of `p` with `instructions` (labels and headers as imported).
fn code_unit_listing(p: &ImportedProgram, instructions: Vec<crate::code_unit_listing::InstructionSnapshot>) -> crate::code_unit_listing::CodeUnitListing {
    crate::code_unit_listing::CodeUnitListing::with_headers(
        p.address_bits,
        p.blocks.clone(),
        instructions,
        p.symbols
            .iter()
            .map(|s| crate::code_unit_listing::LabelSnapshot { address: s.address, name: s.name.clone(), primary: s.primary })
            .collect(),
        p.block_headers.clone(),
    )
}

/// Merges `new` (sorted) into `existing` (sorted); a new instruction replaces
/// an old one at the same start. Linear: a disassembly only adds its ranges.
fn merge_instructions(
    existing: Vec<crate::code_unit_listing::InstructionSnapshot>,
    new: Vec<crate::code_unit_listing::InstructionSnapshot>,
) -> Vec<crate::code_unit_listing::InstructionSnapshot> {
    let mut out = Vec::with_capacity(existing.len() + new.len());
    let (mut old, mut new) = (existing.into_iter().peekable(), new.into_iter().peekable());
    loop {
        match (old.peek(), new.peek()) {
            (Some(o), Some(n)) if o.start < n.start => out.extend(old.next()),
            (Some(o), Some(n)) if o.start == n.start => {
                old.next();
                out.extend(new.next());
            }
            (_, Some(_)) => out.extend(new.next()),
            (Some(_), None) => out.extend(old.next()),
            (None, None) => return out,
        }
    }
}

/// Java `DisassemblerPlugin` "Disassemble" (`D`, listing popup): disassembles
/// from the selection, else the cursor, following flows, then re-reads the
/// program's code units into the listing.
fn add_disassemble_action(tool: &mut DockingTool, events: &UiEventQueue, listing: ListingHandle, listing_id: ProviderId, p: &ImportedProgram) {
    use ghidra_rs::app::cmd::disassemble::disassemble_command::DisassembleCommand;
    use ghidra_rs::framework::cmd::background_command::BackgroundCommand;
    use ghidra_rs::program::model::address::{Address, AddressSet};
    use ghidra_rs::program::model::lang::language::Language;
    use ghidra_rs::util::task::DummyMonitor;

    let Some(live) = p.live.clone() else { return };
    let space = live.program().get_language().get_default_space();
    let at = move |offset: u64| Address::new(space.clone(), offset as i64);
    // What the listing is rebuilt from: blocks share their bytes, and only the
    // disassembled ranges are re-read from the program.
    let base = ImportedProgram { instructions: Vec::new(), live: None, ..p.clone() };
    let instructions = Arc::new(Mutex::new(p.instructions.clone()));
    let (ev, h, enabled, enabled_live, enabled_at) = (events.clone(), listing.clone(), listing, live.clone(), at.clone());
    let mut a = ClosureAction::new("Disassemble", "DisassemblerPlugin", move |_| {
        let program = live.program();
        let (cursor, ranges) = {
            let c = lock(&h);
            let m = c.model();
            let cursor = c.cursor().and_then(|cur| m.address_of(cur.index));
            let ranges: Vec<(u64, u64)> =
                c.selection().ranges().iter().filter_map(|&(lo, hi)| Some((m.address_of(lo)?, m.address_of(hi)?))).collect();
            (cursor, ranges)
        };
        let mut cmd = if ranges.is_empty() {
            let Some(cursor) = cursor else { return };
            // DisassemblerPlugin.disassembleCallback
            let initialized = base.blocks.iter().any(|b| cursor >= b.start && b.byte(cursor - b.start).is_some());
            if !initialized {
                ev.post(UiEvent::Status("Can't disassemble uninitialized memory!".into()));
                return;
            }
            DisassembleCommand::new(at(cursor), None, true)
        } else {
            let mut set = AddressSet::new();
            for (lo, hi) in ranges {
                set.add_range(&at(lo), &at(hi));
            }
            DisassembleCommand::with_start_set(set, None, true)
        };
        let applied = cmd.apply(program, &DummyMonitor);
        let done = cmd.get_disassembled_address_set().to_list();
        if !applied || done.is_empty() {
            ev.post(UiEvent::Status(cmd.get_status_msg().unwrap_or_else(|| "Disassembly failed".into())));
            return;
        }
        if let Some(msg) = cmd.get_status_msg() {
            ev.post(UiEvent::Status(msg));
        }
        let mut added: Vec<_> = done
            .iter()
            .flat_map(|r| crate::program_import::instructions_in(program, r.min_address(), r.max_address()))
            .collect();
        added.sort_by_key(|i| i.start);
        let merged = {
            let mut current = instructions.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            *current = merge_instructions(std::mem::take(&mut *current), added);
            current.clone()
        };
        lock(&h).replace_model(Box::new(code_unit_listing(&base, merged)));
        ev.post(UiEvent::ViewChanged(listing_id.0));
        ev.post(UiEvent::ActionsChanged);
    });
    // DisassemblerPlugin.checkDisassemblyEnabled: a selection, or a cursor not
    // inside an instruction
    a.state_mut().enabled_when(Box::new(move |context| {
        if context.component_provider() != Some(listing_id) {
            return false;
        }
        let (cursor, selected) = {
            let c = lock(&enabled);
            (c.cursor().and_then(|cur| c.model().address_of(cur.index)), !c.selection().is_empty())
        };
        if selected {
            return true;
        }
        let Some(cursor) = cursor else { return false };
        let store = enabled_live.program().get_listing_store();
        let store = store.read().unwrap_or_else(std::sync::PoisonError::into_inner);
        store.instruction_containing(&enabled_at(cursor)).is_none()
    }));
    a.state_mut().set_popup_menu_data(MenuData::full(&["Disassemble"], None, Some("Disassembly"), None, None).ok());
    a.state_mut().set_key_binding_data(Some(KeyBindingData::new(KeyStroke::new(vk::D, 0))));
    tool.add_action(Box::new(a));
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
    config.push(("OPTIONS".to_owned(), Box::new(ToolOptionsState { options: options.clone(), _listener: Some(listener) })));
    // Key Bindings (DockingToolConstants.KEY_BINDINGS): the tool keeps the
    // options in sync with its actions; the dialog edits them as a table.
    let key_bindings = tool.key_binding_options().clone();
    key_bindings.register_options_editor("", crate::options_dialog::KEY_BINDINGS_EDITOR);
    config.push(("KEY_BINDINGS".to_owned(), Box::new(ToolOptionsState { options: key_bindings.clone(), _listener: None })));

    let (ev, tool_name) = (events.clone(), tool.name().to_owned());
    let mut edit = ClosureAction::new("Edit Options", OWNER, move |_| {
        ev.open_dialog(Box::new(OptionsDialog(OptionsDialogState::shared(&tool_name, vec![key_bindings.clone(), options.clone()]))));
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
                if *n <= 0 {
                    // Java: OptionsVetoException("Search limit must be greater than 0")
                    return Err(Box::new(SearchLimitVeto));
                }
                self.0 .0.lock().unwrap_or_else(std::sync::PoisonError::into_inner).set_max_entries(*n as usize);
            }
        }
        Ok(())
    }
}

/// "Search limit must be greater than 0".
struct SearchLimitVeto;
impl ghidra_rs::framework::seam_stubs::OptionsVetoException for SearchLimitVeto {}

/// The options saved with the tool config; also keeps their listener alive
/// (ToolOptions holds listeners weakly, as Java's WeakSet).
struct ToolOptionsState {
    options: Arc<ToolOptions>,
    _listener: Option<SharedOptionsListener>,
}

impl ConfigState for ToolOptionsState {
    fn phase(&self) -> u8 {
        0
    }
    fn write_config_state(&self, state: &mut ghidra_rs::framework::options::SaveState) {
        state.put_xml_element(&self.options.get_name(), self.options.get_xml_root(false));
    }
    fn read_config_state(&mut self, state: &ghidra_rs::framework::options::SaveState) {
        let Some(e) = state.get_xml_element(&self.options.get_name()) else { return };
        let saved = ToolOptions::from_xml(e);
        // Every saved value, cleared ones and ones whose owner registers later
        // included (Java rebuilds the options from XML); listeners see each.
        for name in saved.get_option_names() {
            let Ok(value) = saved.get_object(&name, None) else { continue };
            let is_trigger = matches!(value, Some(OptionValue::ActionTrigger(_)))
                || saved.find_option(&name).is_some_and(|o| o.option_type() == ghidra_rs::framework::options::option_type::OptionType::ActionTrigger);
            let _ = if is_trigger {
                let trigger = match value {
                    Some(OptionValue::ActionTrigger(t)) => Some(t),
                    _ => None,
                };
                self.options.set_action_trigger(&name, trigger)
            } else {
                self.options.put_object(&name, value)
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_rs::docking::action::DispatchResult;
    use crate::listing::CursorPos;
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
            symbols: vec![
                crate::program_import::ImportedSymbol { name: "_start".into(), address: 0x10_0001, kind: "Label".into(), source: "Imported".into(), primary: true },
                crate::program_import::ImportedSymbol { name: "free".into(), address: 0x12_0002, kind: "Label".into(), source: "Imported".into(), primary: true },
            ],
            block_headers: vec![crate::code_unit_listing::BlockHeader {
                start: 0x10_0000,
                name: "segment_1".into(),
                comment: String::new(),
                space: "ram".into(),
            }],
            instructions: vec![],
            live: None,
        };
        let s = build_session_for(Some(&program));
        let (_, h) = listing(&s);
        let frame = {
            let mut c = lock(&h);
            c.set_viewport(1000);
            c.frame()
        };
        assert_eq!(frame.rows.len(), 11, "4 header rows + 5 bytes + 2 label rows");
        assert_eq!(frame.rows[1].row.runs[0].text, "// segment_1", "block header first");
        assert_eq!(frame.rows[4].row.runs[0].text, "0000000000100000");
        assert_eq!(frame.rows[5].row.runs[0].text, "_start", "label row above its address");
        assert_eq!(frame.rows[6].row.runs[0].text, "0000000000100001");
        let tree = s.tool().find_provider("Demo", "Program Tree").unwrap();
        let Some(ViewModelBox::Tree(t)) = s.model(tree) else { panic!("tree") };
        let root = t.root();
        assert_eq!(t.label(root), "ls");
        assert_eq!((0..t.child_count(root)).map(|i| t.label(t.child(root, i))).collect::<Vec<_>>(), vec!["segment_1", ".bss"]);
        let symbols = s.tool().find_provider("Demo", "Symbols").unwrap();
        let Some(ViewModelBox::Table(sym)) = s.model(symbols) else { panic!("table") };
        assert_eq!((0..sym.column_count()).map(|c| sym.column_name(c)).collect::<Vec<_>>(), vec!["Name", "Location", "Type", "Source"]);
        assert_eq!(sym.row_count(), 2);
        assert_eq!(sym.cell(1, 0), CellValue::Text("free".into()));
        assert_eq!(sym.location(1, 0), Some(0x12_0002));
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

    /// Selects the top-level options node `label` in the open options dialog.
    fn select_options(s: &mut UiSession, d: u64, label: &str) {
        let tree = s.dialog_pane_ids(d).unwrap().tree;
        let Some(ViewModelBox::Tree(t)) = s.model_mut(tree) else { panic!("tree") };
        let root = t.root();
        let n = (0..t.child_count(root)).map(|i| t.child(root, i)).find(|&n| t.label(n) == label).expect(label);
        t.select(n);
    }

    fn set_max_goto_entries(s: &mut UiSession, n: &str) {
        let d = edit_options_dialog(s);
        select_options(s, d, "Tool");
        let form = s.dialog_pane_ids(d).unwrap().form;
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
        select_options(&mut s, d, "Tool");
        let form = s.dialog_pane_ids(d).unwrap().form;
        let Some(ViewModelBox::Form(f)) = s.model(form) else { panic!("form") };
        let goto = f.fields().into_iter().find(|f| f.label == "Max Goto Entries").expect("Max Goto Entries");
        assert_eq!(goto.value, "10");
        assert!(!goto.tooltip.is_empty());
    }

    #[test]
    fn a_restored_max_goto_entries_applies_before_the_go_to_history_loads() {
        let dir = std::env::temp_dir().join(format!("ghidra-ui-model-order-{}", std::process::id()));
        let path = dir.join("tool.xml");
        let mut s = build_demo_session();
        let (id, _) = listing(&s);
        set_max_goto_entries(&mut s, "25");
        for i in 0..20 {
            s.tool_mut().dispatch_key(KeyStroke::new(vk::G, 0), Some(id));
            let d = take_dialog(&s);
            s.events().dialog_ok(d, &format!("{:x}", 0x401000 + i % 12), &[]).unwrap();
            if i >= 12 {
                continue;
            }
        }
        s.save_tool_config(&path).unwrap();
        let before = {
            s.tool_mut().dispatch_key(KeyStroke::new(vk::G, 0), Some(id));
            let d = take_dialog(&s);
            s.events().dialog_spec(d).unwrap().combo.unwrap().items.len()
        };
        let mut s2 = build_demo_session();
        s2.load_tool_config(&path).unwrap();
        s2.tool_mut().dispatch_key(KeyStroke::new(vk::G, 0), Some(id));
        let d = take_dialog(&s2);
        assert_eq!(s2.events().dialog_spec(d).unwrap().combo.unwrap().items.len(), before);
        assert!(before > 10, "{before}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn max_goto_entries_must_be_positive() {
        let mut s = build_demo_session();
        let (id, _) = listing(&s);
        s.tool_mut().dispatch_key(KeyStroke::new(vk::G, 0), Some(id));
        let d = take_dialog(&s);
        s.events().dialog_ok(d, "401000", &[]).unwrap();
        let opts = edit_options_dialog(&mut s);
        select_options(&mut s, opts, "Tool");
        let form = s.dialog_pane_ids(opts).unwrap().form;
        let Some(ViewModelBox::Form(f)) = s.model_mut(form) else { panic!("form") };
        let key = f.fields().into_iter().find(|f| f.label == "Max Goto Entries").unwrap().key;
        f.set(&key, "0").unwrap();
        match s.events().dialog_ok(opts, "", &[]).unwrap() {
            crate::dialogs::DialogReply::Stay(spec) => assert!(spec.status.to_lowercase().contains("veto"), "{}", spec.status),
            other => panic!("{other:?}"),
        }
        s.events().dialog_cancel(opts).unwrap();
        s.tool_mut().dispatch_key(KeyStroke::new(vk::G, 0), Some(id));
        let again = take_dialog(&s);
        assert_eq!(s.events().dialog_spec(again).unwrap().combo.unwrap().items, vec!["401000"]);
    }

    fn rebind_go_to(s: &mut UiSession, key: &str) {
        let d = edit_options_dialog(s);
        select_options(s, d, "Key Bindings");
        assert_eq!(s.events().dialog_spec(d).unwrap().pane_kind, 1);
        let table = s.dialog_pane_ids(d).unwrap().table.expect("key bindings table");
        let Some(ViewModelBox::Table(t)) = s.model_mut(table) else { panic!("table") };
        let row = (0..t.row_count()).find(|&r| t.cell(r, 0) == crate::view_models::CellValue::Text("Go To Address/Label".into())).expect("Go To row");
        t.edit(row, 1, key).unwrap();
        assert_eq!(s.events().dialog_ok(d, "", &[]).unwrap(), crate::dialogs::DialogReply::Close);
        s.release_dialog(d);
        s.apply_tool_requests(); // the bridge does this after every dialog OK
    }

    fn g_like(s: &mut UiSession, ks: KeyStroke) -> bool {
        let (id, _) = listing(s);
        s.events().drain();
        s.tool_mut().dispatch_key(ks, Some(id));
        s.events().drain().iter().any(|e| matches!(e, UiEvent::Dialog(_)))
    }

    #[test]
    fn rebinding_go_to_in_the_key_bindings_table_changes_its_key() {
        let mut s = build_demo_session();
        rebind_go_to(&mut s, "ctrl J");
        assert!(g_like(&mut s, KeyStroke::new(vk::J, CTRL_DOWN_MASK)), "Ctrl-J opens Go To");
        assert!(!g_like(&mut s, KeyStroke::new(vk::G, 0)), "G no longer does");
    }

    #[test]
    fn key_bindings_are_saved_with_the_tool_config() {
        let dir = std::env::temp_dir().join(format!("ghidra-ui-model-kb-{}", std::process::id()));
        let path = dir.join("tool.xml");
        let mut s = build_demo_session();
        rebind_go_to(&mut s, "ctrl J");
        s.save_tool_config(&path).unwrap();
        let mut s2 = build_demo_session();
        s2.load_tool_config(&path).unwrap();
        assert!(g_like(&mut s2, KeyStroke::new(vk::J, CTRL_DOWN_MASK)));
        assert!(!g_like(&mut s2, KeyStroke::new(vk::G, 0)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_cleared_key_binding_stays_cleared_after_a_restart() {
        let dir = std::env::temp_dir().join(format!("ghidra-ui-model-kbclear-{}", std::process::id()));
        let path = dir.join("tool.xml");
        let mut s = build_demo_session();
        rebind_go_to(&mut s, "");
        assert!(!g_like(&mut s, KeyStroke::new(vk::G, 0)));
        s.save_tool_config(&path).unwrap();
        let mut s2 = build_demo_session();
        s2.load_tool_config(&path).unwrap();
        assert!(!g_like(&mut s2, KeyStroke::new(vk::G, 0)), "G must stay unbound");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_saved_binding_reaches_an_action_registered_after_loading() {
        use ghidra_rs::framework::options::action_trigger::ActionTrigger;
        let dir = std::env::temp_dir().join(format!("ghidra-ui-model-kblate-{}", std::process::id()));
        let path = dir.join("tool.xml");
        let s = build_demo_session();
        s.tool()
            .key_binding_options()
            .set_action_trigger("Later (Demo)", ActionTrigger::new(Some(KeyStroke::new(vk::K, CTRL_DOWN_MASK)), None).ok())
            .unwrap();
        s.save_tool_config(&path).unwrap();
        let mut s2 = build_demo_session();
        s2.load_tool_config(&path).unwrap();
        let mut later = ClosureAction::new("Later", OWNER, |_| {});
        later.state_mut().set_key_binding_data(Some(KeyBindingData::new(KeyStroke::new(vk::L, CTRL_DOWN_MASK))));
        let id = s2.tool_mut().add_action(Box::new(later));
        let key = s2.tool().actions().get(id).unwrap().state().key_binding_data().and_then(|k| k.key_binding());
        assert_eq!(key, Some(KeyStroke::new(vk::K, CTRL_DOWN_MASK)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rebinding_refreshes_menus() {
        let mut s = build_demo_session();
        let d = edit_options_dialog(&mut s);
        select_options(&mut s, d, "Key Bindings");
        let table = s.dialog_pane_ids(d).unwrap().table.unwrap();
        let Some(ViewModelBox::Table(t)) = s.model_mut(table) else { panic!("table") };
        let row = (0..t.row_count()).find(|&r| t.cell(r, 0) == crate::view_models::CellValue::Text("Go To Address/Label".into())).unwrap();
        t.edit(row, 1, "ctrl J").unwrap();
        s.events().dialog_button(d, "apply").unwrap();
        s.events().drain();
        s.apply_tool_requests();
        assert!(s.events().drain().contains(&UiEvent::ActionsChanged), "menus show the new shortcut");
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
        select_options(&mut s2, d, "Tool");
        let form = s2.dialog_pane_ids(d).unwrap().form;
        let Some(ViewModelBox::Form(f)) = s2.model(form) else { panic!("form") };
        assert_eq!(f.fields().into_iter().find(|f| f.label == "Max Goto Entries").unwrap().value, "25");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ctrl_c_in_the_listing_copies_the_selection_and_elsewhere_reports() {
        let mut s = build_demo_session();
        let (id, h) = listing(&s);
        {
            let mut c = lock(&h);
            c.set_viewport(200);
            c.key(crate::listing::Move::Down, true); // rows 0..=1
        }
        s.events().drain();
        s.tool_mut().dispatch_key(KeyStroke::new(vk::C, CTRL_DOWN_MASK), Some(id));
        let copied: Vec<String> = s
            .events()
            .drain()
            .into_iter()
            .filter_map(|e| if let UiEvent::Clipboard(t) = e { Some(t) } else { None })
            .collect();
        assert_eq!(copied.len(), 1);
        assert!(copied[0].starts_with("00401000  55") && copied[0].lines().count() == 2, "{copied:?}");
        let symbols = s.tool().find_provider("Demo", "Symbols").unwrap();
        s.tool_mut().dispatch_key(KeyStroke::new(vk::C, CTRL_DOWN_MASK), Some(symbols));
        assert_eq!(s.events().drain(), vec![UiEvent::Status("Copy".into())]);
    }

    /// `/bin/ls` imported, and the first start of `.fini`/`.plt.sec`/`.plt`/`.init`
    /// that the import did not disassemble.
    fn bin_ls_with_undefined_code() -> Option<(ImportedProgram, u64)> {
        let dist = crate::program_import::default_ghidra_dist()?;
        let bytes = std::fs::read("/bin/ls").ok()?;
        if bytes.len() < 64 || bytes[..4] != *b"\x7fELF" || bytes[4] != 2 || bytes[18] != 62 {
            return None;
        }
        let p = crate::program_import::import_elf(std::path::Path::new("/bin/ls"), &dist).ok()?;
        let target = [".fini", ".plt.sec", ".plt", ".init"].iter().find_map(|name| {
            let i = p.block_names.iter().position(|n| n == name)?;
            let a = p.block_starts[i];
            (!p.instructions.iter().any(|ins| ins.start <= a && a < ins.start + u64::from(ins.len))).then_some(a)
        })?;
        Some((p, target))
    }

    #[test]
    fn disassemble_at_the_cursor_decodes_there_and_keeps_the_cursor() {
        let Some((program, target)) = bin_ls_with_undefined_code() else { return };
        let mut s = build_session_for(Some(&program));
        let (id, h) = listing(&s);
        {
            let mut c = lock(&h);
            c.set_viewport(400);
            c.goto_address(target).unwrap();
        }
        let before = lock(&h).model().index_count();
        s.events().drain();
        let r = s.tool_mut().dispatch_key(KeyStroke::new(vk::D, 0), Some(id));
        assert!(matches!(r, DispatchResult::Performed(_)), "D performs Disassemble");
        let c = lock(&h);
        let cursor = c.cursor().unwrap();
        assert_eq!(c.model().address_of(cursor.index), Some(target), "cursor stays at the address");
        assert!(c.model().index_count() < before, "decoded bytes merge into instruction rows");
        let mut row = cursor.index;
        while c.model().field_text(CursorPos { index: row, field: 0, col: 0 }).is_some_and(|t| !t.chars().all(|ch| ch.is_ascii_hexdigit())) {
            row += 1; // past label rows
        }
        let mnemonic = c.model().field_text(CursorPos { index: row, field: 2, col: 0 }).unwrap_or_default();
        assert!(!mnemonic.is_empty() && mnemonic != "??", "an instruction at {target:x}: {mnemonic:?}");
        drop(c);
        assert!(s.events().drain().contains(&UiEvent::ViewChanged(id.0)));
    }

    #[test]
    fn disassembling_uninitialized_memory_reports_and_leaves_the_listing() {
        let Some((program, _)) = bin_ls_with_undefined_code() else { return };
        let Some(bss) = program.block_names.iter().position(|n| n == ".bss").map(|i| program.block_starts[i]) else { return };
        let mut s = build_session_for(Some(&program));
        let (id, h) = listing(&s);
        let (cursor, top) = {
            let mut c = lock(&h);
            c.set_viewport(400);
            c.goto_address(bss + 8).unwrap();
            c.key(crate::listing::Move::Down, false); // not the first row at its address
            (c.cursor(), c.top())
        };
        let before = lock(&h).model().index_count();
        s.events().drain();
        s.tool_mut().dispatch_key(KeyStroke::new(vk::D, 0), Some(id));
        let c = lock(&h);
        assert_eq!((c.model().index_count(), c.cursor(), c.top()), (before, cursor, top), "nothing changed");
        drop(c);
        // DisassemblerPlugin.disassembleCallback
        assert_eq!(s.events().drain(), vec![UiEvent::Status("Can't disassemble uninitialized memory!".into())]);
    }

    #[test]
    fn disassemble_is_disabled_where_an_instruction_already_is() {
        let Some((program, _)) = bin_ls_with_undefined_code() else { return };
        let Some(insn) = program.instructions.iter().find(|i| i.len > 1).cloned() else { return };
        let mut s = build_session_for(Some(&program));
        let (id, h) = listing(&s);
        lock(&h).goto_address(insn.start + 1).unwrap(); // inside it
        let r = s.tool_mut().dispatch_key(KeyStroke::new(vk::D, 0), Some(id));
        assert!(matches!(r, DispatchResult::Disabled(_)), "checkDisassemblyEnabled");
    }

    #[test]
    fn new_instructions_merge_into_the_sorted_snapshot() {
        use crate::code_unit_listing::InstructionSnapshot;
        let i = |start: u64| InstructionSnapshot { start, len: 1, mnemonic: format!("I{start}"), operands: String::new() };
        let merged = merge_instructions(vec![i(1), i(5), i(9)], vec![i(3), i(5), i(10)]);
        assert_eq!(merged.iter().map(|x| x.start).collect::<Vec<_>>(), vec![1, 3, 5, 9, 10]);
    }

    #[test]
    fn disassemble_needs_a_live_program_and_the_listing() {
        let s = build_demo_session();
        let names: Vec<String> = s.tool().actions().global_actions().filter_map(|id| s.tool().actions().get(id).map(|a| a.state().name().to_owned())).collect();
        assert!(!names.iter().any(|n| n == "Disassemble"), "the fixture listing has no program to disassemble");
    }

    #[test]
    fn the_startup_theme_is_announced_so_the_renderer_matches_the_chooser() {
        let s = build_demo_session();
        assert!(s.events().drain().contains(&UiEvent::ThemeChanged { dark: false }));
    }

    #[test]
    fn switch_theme_turns_the_tool_dark_and_persists() {
        let dir = std::env::temp_dir().join(format!("ghidra-ui-model-theme-{}", std::process::id()));
        let path = dir.join("tool.xml");
        let mut s = build_demo_session();
        let action = s.tool().actions().global_actions().find(|&id| s.tool().actions().get(id).is_some_and(|a| a.state().name() == "Switch Theme")).unwrap();
        let md = s.tool().actions().get(action).unwrap().state().menu_bar_data().unwrap().clone();
        assert_eq!(md.menu_path(), &["&Edit".to_string(), "Theme".to_string(), "Switch...".to_string()]);
        let ctx = ghidra_rs::docking::DefaultActionContext::new();
        s.tool_mut().actions_mut().get_mut(action).unwrap().action_performed(&ctx);
        let d = take_dialog(&s);
        assert_eq!(s.events().dialog_ok(d, "Flat Dark Theme", &[]).unwrap(), crate::dialogs::DialogReply::Close);
        assert!(s.events().drain().contains(&UiEvent::ThemeChanged { dark: true }));
        if crate::icons::default_theme_root().is_some() {
            assert!(s.icon_path("icon.plugin.symboltree.node.namespace").unwrap().ends_with("Namespace.dark.gif"));
        }
        s.save_tool_config(&path).unwrap();
        let mut s2 = build_demo_session();
        s2.events().drain();
        s2.load_tool_config(&path).unwrap();
        assert!(s2.events().drain().contains(&UiEvent::ThemeChanged { dark: true }));
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

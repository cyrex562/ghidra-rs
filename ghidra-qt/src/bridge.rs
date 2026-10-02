//! The cxx bridge between the C++ Qt shell and the Rust UI model.
//! Rules (spec §3): C++ calls Rust for data only; Rust never calls back into
//! C++ widgets; every `extern "Rust"` function returns through `guard`.
//!
//! The session lives in a process-wide slot ([`install`]); the C++ shell is
//! single-threaded, the mutex only guards against misuse. Provider ids cross
//! the bridge as `u64`; "no provider" is `-1` in `i64` parameters.

use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};

use ghidra_rs::docking::action::{ActionId, DispatchResult};
use ghidra_rs::docking::{ProviderId, ProviderViewKind, WindowPosition};
use ghidra_ui_model::menus::{self, MenuEntry, ToolBarEntry};
use ghidra_ui_model::{FormFieldKind, NodeId, UiEvent, UiSession as ModelSession, ViewModelBox, WakeHandle};

use crate::guard::guard;
use crate::keys::qt_to_key_stroke;

/// Bridge-local handle for the UI session. cxx requires opaque Rust types to be
/// defined in this crate (orphan rule); C++ sees it as `ghidra_qt::UiSession`.
pub struct UiSession(String);

impl UiSession {
    /// A handle carrying the window title of the installed session.
    pub fn new(title: String) -> Self {
        Self(title)
    }
}

static SESSION: OnceLock<Mutex<ModelSession>> = OnceLock::new();
static WAKE: OnceLock<WakeHandle> = OnceLock::new();

/// Installs the session the shell renders (call once, before `run_app`).
pub fn install(mut session: ModelSession) -> UiSession {
    let title = session.title();
    if let Some(w) = session.take_wake_handle() {
        let _ = WAKE.set(w);
    }
    let _ = SESSION.set(Mutex::new(session));
    UiSession::new(title)
}

fn session() -> MutexGuard<'static, ModelSession> {
    #[cfg(test)]
    let slot = SESSION.get_or_init(|| {
        let mut s = ghidra_ui_model::demo_tool::build_demo_session();
        if let Some(w) = s.take_wake_handle() {
            let _ = WAKE.set(w);
        }
        Mutex::new(s)
    });
    #[cfg(not(test))]
    let slot = SESSION.get().expect("ghidra-qt: session not installed");
    slot.lock().unwrap_or_else(PoisonError::into_inner)
}

fn with<T>(what: &str, f: impl FnOnce(&mut ModelSession) -> Result<T, String>) -> Result<T, String> {
    guard(what, || f(&mut session())).and_then(|r| r)
}

fn focused(pid: i64) -> Option<ProviderId> {
    (pid >= 0).then(|| ProviderId(pid as u64))
}

fn kind_code(k: &ProviderViewKind) -> (u8, String) {
    match k {
        ProviderViewKind::Table => (0, String::new()),
        ProviderViewKind::Tree => (1, String::new()),
        ProviderViewKind::Text => (2, String::new()),
        ProviderViewKind::Form => (3, String::new()),
        ProviderViewKind::Listing => (4, String::new()),
        ProviderViewKind::Custom(id) => (5, id.clone()),
    }
}

fn position_code(p: WindowPosition) -> u8 {
    match p {
        WindowPosition::Top => 0,
        WindowPosition::Bottom => 1,
        WindowPosition::Left => 2,
        WindowPosition::Right => 3,
        WindowPosition::Window => 4,
        WindowPosition::Stack => 5,
    }
}

#[cxx::bridge(namespace = "ghidra_qt")]
pub mod ffi {
    /// Startup options passed from `main` to the C++ shell.
    pub struct AppOptions {
        /// PNG path for the auto-quit screenshot; empty = none.
        pub screenshot_path: String,
        /// Auto-quit delay in ms; 0 = interactive.
        pub quit_after_ms: u32,
        /// Print one line per dock and exit (smoke tests).
        pub dump_docks: bool,
        /// Print the built menu bar and exit (smoke tests).
        pub dump_menus: bool,
        /// Geometry file to restore before showing (smoke tests); empty = none.
        pub restore_geometry: String,
        /// Synthetic key press "Ctrl-F"-style to send after showing; empty = none.
        pub press: String,
        /// Title of the dock to focus before `press`.
        pub focus: String,
        /// Invoke a non-existent action from a slot (error-path smoke test).
        pub invoke_missing_action: bool,
        /// Rebuild actions N times and print child counts (leak test); 0 = off.
        pub count_after_rebuilds: u32,
    }

    /// A provider as the shell needs it.
    pub struct ProviderInfo {
        pub id: u64,
        pub title: String,
        pub tab_text: String,
        /// 0 table, 1 tree, 2 text, 3 form, 4 listing, 5 custom
        pub kind: u8,
        pub custom_kind: String,
        /// 0 top, 1 bottom, 2 left, 3 right, 4 window, 5 stack
        pub position: u8,
        pub visible: bool,
    }

    /// A styled text run.
    pub struct RunInfo {
        pub text: String,
        pub color_id: String,
        pub bold: bool,
        pub italic: bool,
        pub link: String,
    }

    /// A form field.
    pub struct FieldInfo {
        pub key: String,
        pub label: String,
        /// 0 text, 1 int, 2 bool, 3 choice
        pub kind: u8,
        pub value: String,
        pub choices: Vec<String>,
    }

    /// A flattened (depth-first) menu entry.
    pub struct MenuItemInfo {
        pub depth: u32,
        /// 0 submenu, 1 item, 2 separator
        pub kind: u8,
        pub text: String,
        /// mnemonic character as a code point, 0 = none
        pub mnemonic: u32,
        pub action: u64,
        pub key_text: String,
        pub enabled: bool,
        pub checkable: bool,
        pub checked: bool,
    }

    /// A toolbar entry.
    pub struct ToolBarInfo {
        /// 0 button, 1 separator
        pub kind: u8,
        pub action: u64,
        pub icon: String,
        pub tooltip: String,
        pub enabled: bool,
    }

    /// Result of a key dispatch.
    pub struct KeyResult {
        /// 0 performed, 1 disabled, 2 ambiguous, 3 not handled
        pub code: u8,
        /// candidate actions when ambiguous
        pub candidates: Vec<u64>,
    }

    /// A drained UI event.
    pub struct EventInfo {
        /// 0 status, 1 task progress, 2 task done, 3 actions changed, 4 domain changed, 5 other
        pub kind: u8,
        pub text: String,
        pub task: u64,
        pub progress: u64,
        pub maximum: u64,
    }

    extern "Rust" {
        type UiSession;
        fn session_title(session: &UiSession) -> Result<String>;

        fn provider_ids() -> Result<Vec<u64>>;
        fn provider_info(pid: u64) -> Result<ProviderInfo>;

        fn table_column_count(pid: u64) -> Result<usize>;
        fn table_column_name(pid: u64, column: usize) -> Result<String>;
        fn table_row_count(pid: u64) -> Result<usize>;
        fn table_cell(pid: u64, row: usize, column: usize) -> Result<String>;
        fn table_sort(pid: u64, column: usize, ascending: bool) -> Result<()>;
        fn table_filter(pid: u64, text: &str) -> Result<()>;
        fn table_editable(pid: u64, row: usize, column: usize) -> Result<bool>;
        fn table_edit(pid: u64, row: usize, column: usize, value: &str) -> Result<()>;

        fn tree_root(pid: u64) -> Result<u64>;
        fn tree_child_count(pid: u64, node: u64) -> Result<usize>;
        fn tree_child(pid: u64, node: u64, index: usize) -> Result<u64>;
        fn tree_parent(pid: u64, node: u64) -> Result<i64>;
        fn tree_label(pid: u64, node: u64) -> Result<String>;

        fn text_line_count(pid: u64) -> Result<usize>;
        fn text_line(pid: u64, index: usize) -> Result<Vec<RunInfo>>;

        fn form_fields(pid: u64) -> Result<Vec<FieldInfo>>;
        fn form_set(pid: u64, key: &str, value: &str) -> Result<()>;

        fn menu_bar(focused_pid: i64) -> Result<Vec<MenuItemInfo>>;
        fn popup_menu(pid: u64) -> Result<Vec<MenuItemInfo>>;
        fn tool_bar(focused_pid: i64) -> Result<Vec<ToolBarInfo>>;

        fn invoke_action(action: u64, focused_pid: i64) -> Result<()>;
        fn action_name(action: u64) -> Result<String>;
        fn dispatch_key(qt_key: i32, qt_modifiers: u32, focused_pid: i64) -> Result<KeyResult>;

        fn layout_geometry() -> Result<Vec<u8>>;
        fn set_layout_geometry(bytes: &[u8]) -> Result<()>;

        fn load_tool_config() -> Result<bool>;
        fn save_tool_config() -> Result<()>;

        fn wake_fd() -> Result<i32>;
        fn drain_events() -> Result<Vec<EventInfo>>;
    }

    unsafe extern "C++" {
        include!("ghidra-qt/cpp/app.h");
        fn run_app(session: &UiSession, options: &AppOptions) -> i32;
    }
}

use ffi::{EventInfo, FieldInfo, KeyResult, MenuItemInfo, ProviderInfo, RunInfo, ToolBarInfo};

fn session_title(session: &UiSession) -> Result<String, String> {
    guard("session_title", || session.0.clone())
}

fn provider_ids() -> Result<Vec<u64>, String> {
    with("provider_ids", |s| Ok(s.tool().provider_ids().map(|p| p.0).collect()))
}

fn provider_info(pid: u64) -> Result<ProviderInfo, String> {
    with("provider_info", |s| {
        let p = s.tool().provider(ProviderId(pid)).ok_or_else(|| format!("no provider {pid}"))?;
        let st = p.state();
        let (kind, custom_kind) = kind_code(st.view_kind());
        let position = s.tool().layout().entry(&st.layout_key()).map(|e| e.position).unwrap_or(st.default_position());
        Ok(ProviderInfo {
            id: pid,
            title: st.title().to_owned(),
            tab_text: st.tab_text().unwrap_or("").to_owned(),
            kind,
            custom_kind,
            position: position_code(position),
            visible: st.is_visible(),
        })
    })
}

macro_rules! model {
    ($s:expr, $pid:expr, $variant:ident, $what:literal) => {
        match $s.model_mut(ProviderId($pid)) {
            Some(ViewModelBox::$variant(m)) => m,
            Some(_) => return Err(format!("provider {} is not a {}", $pid, $what)),
            None => return Err(format!("no view model for provider {}", $pid)),
        }
    };
}

fn table_column_count(pid: u64) -> Result<usize, String> {
    with("table_column_count", |s| Ok(model!(s, pid, Table, "table").column_count()))
}

fn table_column_name(pid: u64, column: usize) -> Result<String, String> {
    with("table_column_name", |s| Ok(model!(s, pid, Table, "table").column_name(column)))
}

fn table_row_count(pid: u64) -> Result<usize, String> {
    with("table_row_count", |s| Ok(model!(s, pid, Table, "table").row_count()))
}

fn table_cell(pid: u64, row: usize, column: usize) -> Result<String, String> {
    with("table_cell", |s| Ok(model!(s, pid, Table, "table").cell(row, column).to_string()))
}

fn table_sort(pid: u64, column: usize, ascending: bool) -> Result<(), String> {
    with("table_sort", |s| {
        model!(s, pid, Table, "table").sort(column, ascending);
        Ok(())
    })
}

fn table_filter(pid: u64, text: &str) -> Result<(), String> {
    with("table_filter", |s| {
        model!(s, pid, Table, "table").set_filter(text);
        Ok(())
    })
}

fn table_editable(pid: u64, row: usize, column: usize) -> Result<bool, String> {
    with("table_editable", |s| Ok(model!(s, pid, Table, "table").is_editable(row, column)))
}

fn table_edit(pid: u64, row: usize, column: usize, value: &str) -> Result<(), String> {
    with("table_edit", |s| model!(s, pid, Table, "table").edit(row, column, value))
}

fn tree_root(pid: u64) -> Result<u64, String> {
    with("tree_root", |s| Ok(model!(s, pid, Tree, "tree").root().0))
}

fn tree_child_count(pid: u64, node: u64) -> Result<usize, String> {
    with("tree_child_count", |s| Ok(model!(s, pid, Tree, "tree").child_count(NodeId(node))))
}

fn tree_child(pid: u64, node: u64, index: usize) -> Result<u64, String> {
    with("tree_child", |s| {
        let t = model!(s, pid, Tree, "tree");
        if index >= t.child_count(NodeId(node)) {
            return Err(format!("node {node} has no child {index}"));
        }
        Ok(t.child(NodeId(node), index).0)
    })
}

fn tree_parent(pid: u64, node: u64) -> Result<i64, String> {
    with("tree_parent", |s| Ok(model!(s, pid, Tree, "tree").parent(NodeId(node)).map_or(-1, |p| p.0 as i64)))
}

fn tree_label(pid: u64, node: u64) -> Result<String, String> {
    with("tree_label", |s| Ok(model!(s, pid, Tree, "tree").label(NodeId(node))))
}

fn text_line_count(pid: u64) -> Result<usize, String> {
    with("text_line_count", |s| Ok(model!(s, pid, Text, "text view").line_count()))
}

fn text_line(pid: u64, index: usize) -> Result<Vec<RunInfo>, String> {
    with("text_line", |s| {
        Ok(model!(s, pid, Text, "text view")
            .line(index)
            .into_iter()
            .map(|r| RunInfo {
                text: r.text,
                color_id: r.color_id.unwrap_or_default(),
                bold: r.bold,
                italic: r.italic,
                link: r.link.unwrap_or_default(),
            })
            .collect())
    })
}

fn form_fields(pid: u64) -> Result<Vec<FieldInfo>, String> {
    with("form_fields", |s| {
        Ok(model!(s, pid, Form, "form")
            .fields()
            .into_iter()
            .map(|f| {
                let (kind, choices) = match f.kind {
                    FormFieldKind::Text => (0, Vec::new()),
                    FormFieldKind::Int => (1, Vec::new()),
                    FormFieldKind::Bool => (2, Vec::new()),
                    FormFieldKind::Choice(c) => (3, c),
                };
                FieldInfo { key: f.key, label: f.label, kind, value: f.value, choices }
            })
            .collect())
    })
}

fn form_set(pid: u64, key: &str, value: &str) -> Result<(), String> {
    with("form_set", |s| model!(s, pid, Form, "form").set(key, value))
}

fn flatten(entries: &[MenuEntry], depth: u32, out: &mut Vec<MenuItemInfo>) {
    for e in entries {
        match e {
            MenuEntry::Submenu { title, mnemonic, children } => {
                out.push(MenuItemInfo {
                    depth,
                    kind: 0,
                    text: title.clone(),
                    mnemonic: mnemonic.map_or(0, u32::from),
                    action: 0,
                    key_text: String::new(),
                    enabled: true,
                    checkable: false,
                    checked: false,
                });
                flatten(children, depth + 1, out);
            }
            MenuEntry::Item { action, text, mnemonic, key_text, enabled, checkable, checked } => out.push(MenuItemInfo {
                depth,
                kind: 1,
                text: text.clone(),
                mnemonic: mnemonic.map_or(0, u32::from),
                action: action.0,
                key_text: key_text.clone(),
                enabled: *enabled,
                checkable: *checkable,
                checked: *checked,
            }),
            MenuEntry::Separator => out.push(MenuItemInfo {
                depth,
                kind: 2,
                text: String::new(),
                mnemonic: 0,
                action: 0,
                key_text: String::new(),
                enabled: false,
                checkable: false,
                checked: false,
            }),
        }
    }
}

fn menu_bar(focused_pid: i64) -> Result<Vec<MenuItemInfo>, String> {
    with("menu_bar", |s| {
        let ctx = s.tool().action_context(focused(focused_pid));
        let mut out = Vec::new();
        flatten(&menus::menu_bar(s.tool(), ctx.as_ref()), 0, &mut out);
        Ok(out)
    })
}

fn popup_menu(pid: u64) -> Result<Vec<MenuItemInfo>, String> {
    with("popup_menu", |s| {
        let ctx = s.tool().action_context(Some(ProviderId(pid)));
        let mut out = Vec::new();
        flatten(&menus::popup(s.tool(), Some(ProviderId(pid)), ctx.as_ref()), 0, &mut out);
        Ok(out)
    })
}

fn tool_bar(focused_pid: i64) -> Result<Vec<ToolBarInfo>, String> {
    with("tool_bar", |s| {
        let ctx = s.tool().action_context(focused(focused_pid));
        Ok(menus::tool_bar(s.tool(), ctx.as_ref())
            .into_iter()
            .map(|e| match e {
                ToolBarEntry::Button { action, icon, tooltip, enabled } => {
                    ToolBarInfo { kind: 0, action: action.0, icon, tooltip, enabled }
                }
                ToolBarEntry::Separator => {
                    ToolBarInfo { kind: 1, action: 0, icon: String::new(), tooltip: String::new(), enabled: false }
                }
            })
            .collect())
    })
}

fn invoke_action(action: u64, focused_pid: i64) -> Result<(), String> {
    with("invoke_action", |s| {
        let ctx = s.tool().action_context(focused(focused_pid));
        let a = s.tool_mut().actions_mut().get_mut(ActionId(action)).ok_or_else(|| format!("no action {action}"))?;
        if !(a.is_valid_context(ctx.as_ref()) && a.is_enabled_for_context(ctx.as_ref())) {
            return Err(format!("action {} is not enabled here", a.full_name()));
        }
        a.action_performed(ctx.as_ref());
        Ok(())
    })
}

fn action_name(action: u64) -> Result<String, String> {
    with("action_name", |s| {
        s.tool().actions().get(ActionId(action)).map(|a| a.name().to_owned()).ok_or_else(|| format!("no action {action}"))
    })
}

fn dispatch_key(qt_key: i32, qt_modifiers: u32, focused_pid: i64) -> Result<KeyResult, String> {
    with("dispatch_key", |s| {
        let Some(ks) = qt_to_key_stroke(qt_key, qt_modifiers) else {
            return Ok(KeyResult { code: 3, candidates: Vec::new() });
        };
        Ok(match s.tool_mut().dispatch_key(ks, focused(focused_pid)) {
            DispatchResult::Performed(_) => KeyResult { code: 0, candidates: Vec::new() },
            DispatchResult::Disabled(_) => KeyResult { code: 1, candidates: Vec::new() },
            DispatchResult::Ambiguous(ids) => KeyResult { code: 2, candidates: ids.into_iter().map(|i| i.0).collect() },
            DispatchResult::NotHandled => KeyResult { code: 3, candidates: Vec::new() },
        })
    })
}

fn layout_geometry() -> Result<Vec<u8>, String> {
    with("layout_geometry", |s| Ok(s.tool().layout().geometry().map(<[u8]>::to_vec).unwrap_or_default()))
}

fn set_layout_geometry(bytes: &[u8]) -> Result<(), String> {
    with("set_layout_geometry", |s| {
        s.tool_mut().layout_mut().set_geometry((!bytes.is_empty()).then(|| bytes.to_vec()));
        Ok(())
    })
}

/// `$GHIDRA_RS_CONFIG_DIR`, else `$XDG_CONFIG_HOME/ghidra-rs`, else
/// `~/.config/ghidra-rs`; the tool config is `<dir>/tools/<tool>.xml`.
fn tool_config_path(tool_name: &str) -> Result<std::path::PathBuf, String> {
    let base = std::env::var_os("GHIDRA_RS_CONFIG_DIR")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("XDG_CONFIG_HOME").map(|d| std::path::PathBuf::from(d).join("ghidra-rs")))
        .or_else(|| std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".config").join("ghidra-rs")))
        .ok_or_else(|| "no config directory (set GHIDRA_RS_CONFIG_DIR or HOME)".to_owned())?;
    Ok(base.join("tools").join(format!("{tool_name}.xml")))
}

fn load_tool_config() -> Result<bool, String> {
    with("load_tool_config", |s| {
        let path = tool_config_path(s.tool().name())?;
        s.load_tool_config(&path).map_err(|e| format!("could not load tool config: {e}"))
    })
}

fn save_tool_config() -> Result<(), String> {
    with("save_tool_config", |s| {
        let path = tool_config_path(s.tool().name())?;
        s.save_tool_config(&path).map_err(|e| format!("could not save tool config {}: {e}", path.display()))
    })
}

fn wake_fd() -> Result<i32, String> {
    drop(session()); // ensure installed (and, in tests, initialised)
    #[cfg(unix)]
    {
        WAKE.get().map(WakeHandle::raw_fd).ok_or_else(|| "wake handle already taken".to_owned())
    }
    #[cfg(not(unix))]
    {
        Err("no wake fd on this platform".to_owned())
    }
}

fn drain_events() -> Result<Vec<EventInfo>, String> {
    with("drain_events", |s| {
        // consume wake bytes BEFORE draining (see WakeHandle::clear)
        if let Some(w) = WAKE.get() {
            w.clear();
        }
        Ok(s.events()
            .drain()
            .into_iter()
            .map(|e| {
                let mut i = EventInfo { kind: 5, text: String::new(), task: 0, progress: 0, maximum: 0 };
                match e {
                    UiEvent::Status(m) => {
                        i.kind = 0;
                        i.text = m;
                    }
                    UiEvent::TaskProgress { task, message, progress, maximum } => {
                        i = EventInfo { kind: 1, text: message, task, progress, maximum };
                    }
                    UiEvent::TaskDone { task, cancelled, error } => {
                        i = EventInfo {
                            kind: 2,
                            text: error.unwrap_or_else(|| if cancelled { "cancelled".into() } else { String::new() }),
                            task,
                            progress: 0,
                            maximum: 0,
                        };
                    }
                    UiEvent::ActionsChanged => i.kind = 3,
                    UiEvent::DomainChanged { object, .. } => {
                        i.kind = 4;
                        i.task = object;
                    }
                    _ => {}
                }
                i
            })
            .collect())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pid(title: &str) -> u64 {
        provider_ids().unwrap().into_iter().find(|p| provider_info(*p).unwrap().title == title).unwrap()
    }

    #[test]
    fn demo_providers_are_visible_through_the_bridge() {
        assert_eq!(provider_ids().unwrap().len(), 4);
        let symbols = provider_info(pid("Symbols")).unwrap();
        assert_eq!((symbols.kind, symbols.position), (0, 2));
        assert_eq!(provider_info(pid("Options")).unwrap().position, 1);
    }

    #[test]
    fn table_reads_and_out_of_range_is_empty() {
        let p = pid("Symbols");
        assert_eq!(table_column_count(p).unwrap(), 3);
        assert_eq!(table_column_name(p, 0).unwrap(), "Name");
        assert_eq!(table_cell(p, 999, 0).unwrap(), "");
        assert!(table_edit(p, 0, 0, "x").unwrap_err().contains("not editable"));
    }

    #[test]
    fn wrong_view_kind_is_an_error_not_a_panic() {
        let tree = pid("Program Tree");
        assert!(table_row_count(tree).unwrap_err().contains("not a table"));
        assert!(tree_child(tree, tree_root(tree).unwrap(), 99).is_err());
    }

    #[test]
    fn form_set_validates() {
        let p = pid("Options");
        assert!(form_set(p, "max_depth", "deep").is_err());
        assert!(form_set(p, "max_depth", "7").is_ok());
    }

    #[test]
    fn ctrl_f_in_symbols_performs_and_menus_flatten() {
        let r = dispatch_key(0x46 /*Key_F*/, 0x0400_0000 /*Ctrl*/, pid("Symbols") as i64).unwrap();
        assert_eq!(r.code, 0);
        let menu = menu_bar(-1).unwrap();
        let tops: Vec<&str> = menu.iter().filter(|m| m.depth == 0).map(|m| m.text.as_str()).collect();
        assert_eq!(tops, vec!["File", "Edit", "Search"]);
        let copy = menu.iter().find(|m| m.text == "Copy").unwrap();
        assert_eq!(copy.key_text, "Ctrl-C");
        assert!(invoke_action(9_999_999, -1).is_err());
    }
}

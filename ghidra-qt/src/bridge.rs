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
        /// Print the first N listing rows the view would paint; 0 = off.
        pub dump_listing: u32,
        /// Scroll, change the listing font, print the first row before/after.
        pub listing_font_change: bool,
        /// Auto-answer prompts with `prompt_answer` (smoke tests).
        pub has_prompt_answer: bool,
        pub prompt_answer: String,
        /// Print the Listing's state line at quit.
        pub print_listing_state: bool,
        /// Float this dock before pressing keys; empty = none.
        pub float_dock: String,
        /// Trigger the menu-bar item with this text; empty = none.
        pub invoke_menu: String,
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
        /// The tool's root component (ADS central widget, Ghidra's main listing).
        pub central: bool,
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
        pub tooltip: String,
        pub read_only: bool,
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
        /// Resolved image file for `icon`; empty = show the tooltip text.
        pub icon_path: String,
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

    /// Listing font metrics from the renderer.
    pub struct MetricsInfo {
        pub char_width: i32,
        pub bold_char_width: i32,
        pub ascent: i32,
        pub descent: i32,
        pub leading: i32,
    }

    /// A positioned run on a listing row.
    pub struct RunPosInfo {
        pub x: i32,
        pub text: String,
        pub color_id: String,
        pub bold: bool,
    }

    /// A highlighted span on a listing row.
    pub struct SpanInfo {
        pub x: i32,
        pub width: i32,
    }

    /// A painted listing row; `index` is a decimal u128.
    pub struct FrameRowInfo {
        pub index: String,
        pub y: i32,
        pub height: i32,
        pub runs: Vec<RunPosInfo>,
        pub selected: bool,
        /// Cursor bar x; -1 = the cursor is not on this row.
        pub cursor_x: i32,
        pub highlights: Vec<SpanInfo>,
    }

    /// Everything the listing view paints; `top` is a decimal u128.
    pub struct FrameInfo {
        pub top: String,
        pub rows: Vec<FrameRowInfo>,
        pub scroll_max: i32,
        pub scroll_page: i32,
        pub scroll_value: i32,
        pub location: String,
    }

    /// A dialog check box.
    pub struct CheckInfo {
        pub key: String,
        pub label: String,
        pub tooltip: String,
        pub checked: bool,
    }

    /// An extra dialog button; empty `confirm` = no confirmation.
    pub struct ButtonInfo {
        pub key: String,
        pub label: String,
        pub confirm: String,
    }

    /// View-model ids of a dialog's tree and form panes.
    pub struct PaneIds {
        pub tree: u64,
        pub form: u64,
    }

    /// A Rust-described dialog.
    pub struct DialogInfo {
        pub title: String,
        pub message: String,
        pub has_combo: bool,
        pub combo_text: String,
        pub combo_items: Vec<String>,
        pub checks: Vec<CheckInfo>,
        pub status: String,
        pub buttons: Vec<ButtonInfo>,
        pub has_panes: bool,
    }

    /// A drained UI event.
    pub struct EventInfo {
        /// 0 status, 1 task progress, 2 task done, 3 actions changed, 4 domain changed, 5 other,
        /// 6 prompt (task = prompt id, text = title), 7 view changed (task = provider id),
        /// 8 provider shown (task = provider id, progress = 1 to focus it),
        /// 9 dialog (task = dialog id)
        pub kind: u8,
        pub text: String,
        pub task: u64,
        pub progress: u64,
        pub maximum: u64,
        /// Prompt field label.
        pub label: String,
        /// Prompt initial text.
        pub initial: String,
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
        /// Double-click: navigate to the row's location (Java GhidraTable.navigate).
        fn table_activate(pid: u64, row: usize, column: usize) -> Result<()>;

        fn tree_root(pid: u64) -> Result<u64>;
        fn tree_child_count(pid: u64, node: u64) -> Result<usize>;
        fn tree_child(pid: u64, node: u64, index: usize) -> Result<u64>;
        fn tree_parent(pid: u64, node: u64) -> Result<i64>;
        fn tree_label(pid: u64, node: u64) -> Result<String>;

        fn text_line_count(pid: u64) -> Result<usize>;
        fn text_line(pid: u64, index: usize) -> Result<Vec<RunInfo>>;

        fn form_fields(pid: u64) -> Result<Vec<FieldInfo>>;
        fn form_set(pid: u64, key: &str, value: &str) -> Result<()>;

        fn listing_set_metrics(pid: u64, metrics: MetricsInfo) -> Result<()>;
        fn listing_set_viewport(pid: u64, viewport_px: i32) -> Result<()>;
        /// kind: 0 key (a = direction), 1 click (a, b = x, y), 2 middle click,
        /// 3 wheel (a = rows), 4 scrollbar value (a), 5 drag (a, b = x, y); `extend` = shift.
        fn listing_intent(pid: u64, kind: u8, a: i64, b: i64, extend: bool) -> Result<()>;
        fn listing_frame(pid: u64) -> Result<FrameInfo>;
        fn prompt_reply(id: u64, accepted: bool, text: &str) -> Result<()>;
        fn dialog_spec(id: u64) -> Result<DialogInfo>;
        /// OK; true when the dialog is done (else re-read its spec).
        fn dialog_ok(id: u64, text: &str, checks: Vec<CheckInfo>) -> Result<bool>;
        fn dialog_cancel(id: u64) -> Result<()>;
        /// An extra button; true when the dialog is done.
        fn dialog_button(id: u64, key: &str) -> Result<bool>;
        fn dialog_panes(id: u64) -> Result<PaneIds>;
        /// The renderer selected a tree node (single selection).
        fn tree_select(pid: u64, node: u64) -> Result<()>;
        /// Double-click: navigate to the node's location (Java ProgramTreePlugin.doubleClick).
        fn tree_activate(pid: u64, node: u64) -> Result<()>;

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

use ffi::{ButtonInfo, CheckInfo, DialogInfo, EventInfo, FieldInfo, PaneIds, FrameInfo, FrameRowInfo, KeyResult, MenuItemInfo, MetricsInfo, ProviderInfo, RunInfo, RunPosInfo, SpanInfo, ToolBarInfo};
use ghidra_ui_model::listing::{FontMetrics, Move};
use ghidra_ui_model::listing_controller::ListingController;

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
            central: s.central_provider() == Some(ProviderId(pid)),
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
                FieldInfo { key: f.key, label: f.label, kind, value: f.value, choices, tooltip: f.tooltip, read_only: f.read_only }
            })
            .collect())
    })
}

fn table_activate(pid: u64, row: usize, column: usize) -> Result<(), String> {
    with("table_activate", |s| s.table_activate(ProviderId(pid), row, column))
}

fn form_set(pid: u64, key: &str, value: &str) -> Result<(), String> {
    with("form_set", |s| model!(s, pid, Form, "form").set(key, value))
}

/// Locks provider `pid`'s listing controller and runs `f` on it.
fn with_listing<T>(what: &str, pid: u64, f: impl FnOnce(&mut ListingController) -> Result<T, String>) -> Result<T, String> {
    with(what, |s| {
        let handle = model!(s, pid, Listing, "listing").clone();
        let mut c = ghidra_ui_model::listing_controller::lock(&handle);
        f(&mut c)
    })
}

fn listing_set_metrics(pid: u64, m: MetricsInfo) -> Result<(), String> {
    with_listing("listing_set_metrics", pid, |c| {
        c.set_metrics(FontMetrics {
            char_width: m.char_width,
            bold_char_width: m.bold_char_width,
            ascent: m.ascent,
            descent: m.descent,
            leading: m.leading,
        });
        Ok(())
    })
}

fn listing_set_viewport(pid: u64, viewport_px: i32) -> Result<(), String> {
    with_listing("listing_set_viewport", pid, |c| {
        c.set_viewport(viewport_px);
        Ok(())
    })
}

fn direction(d: i64) -> Result<Move, String> {
    Ok(match d {
        0 => Move::Up,
        1 => Move::Down,
        2 => Move::Left,
        3 => Move::Right,
        4 => Move::PageUp,
        5 => Move::PageDown,
        6 => Move::Home,
        7 => Move::End,
        d => return Err(format!("bad cursor direction {d}")),
    })
}

fn listing_intent(pid: u64, kind: u8, a: i64, b: i64, extend: bool) -> Result<(), String> {
    with_listing("listing_intent", pid, |c| {
        let px = |v: i64| v.clamp(i32::MIN as i64, i32::MAX as i64) as i32;
        match kind {
            0 => c.key(direction(a)?, extend),
            1 => c.click(px(a), px(b), extend),
            2 => c.middle_click(px(a), px(b)),
            3 => c.wheel(a),
            4 => c.set_scroll_value(px(a)),
            5 => c.drag(px(a), px(b)),
            k => return Err(format!("bad listing intent {k}")),
        }
        Ok(())
    })
}

fn listing_frame(pid: u64) -> Result<FrameInfo, String> {
    with_listing("listing_frame", pid, |c| {
        let f = c.frame();
        Ok(FrameInfo {
            top: f.top.to_string(),
            rows: f
                .rows
                .into_iter()
                .map(|r| FrameRowInfo {
                    index: r.row.index.to_string(),
                    y: r.row.y,
                    height: r.row.height,
                    runs: r
                        .row
                        .runs
                        .into_iter()
                        .map(|p| RunPosInfo { x: p.x, text: p.text, color_id: p.color_id.unwrap_or_default(), bold: p.bold })
                        .collect(),
                    selected: r.selected,
                    cursor_x: r.cursor_x.unwrap_or(-1),
                    highlights: r.highlights.into_iter().map(|(x, width)| SpanInfo { x, width }).collect(),
                })
                .collect(),
            scroll_max: f.scroll_max,
            scroll_page: f.scroll_page,
            scroll_value: f.scroll_value,
            location: f.location,
        })
    })
}

fn dialog_spec(id: u64) -> Result<DialogInfo, String> {
    with("dialog_spec", |s| {
        let d = s.events().dialog_spec(id)?;
        let (has_combo, combo_text, combo_items) = match d.combo {
            Some(c) => (true, c.text, c.items),
            None => (false, String::new(), Vec::new()),
        };
        Ok(DialogInfo {
            title: d.title,
            message: d.message,
            has_combo,
            combo_text,
            combo_items,
            checks: d.checks.into_iter().map(|c| CheckInfo { key: c.key, label: c.label, tooltip: c.tooltip, checked: c.checked }).collect(),
            status: d.status,
            buttons: d
                .buttons
                .into_iter()
                .map(|b| ButtonInfo { key: b.key, label: b.label, confirm: b.confirm.unwrap_or_default() })
                .collect(),
            has_panes: d.has_panes,
        })
    })
}

fn dialog_ok(id: u64, text: &str, checks: Vec<CheckInfo>) -> Result<bool, String> {
    with("dialog_ok", |s| {
        let checks: Vec<(String, bool)> = checks.into_iter().map(|c| (c.key, c.checked)).collect();
        let done = s.events().dialog_ok(id, text, &checks)? == ghidra_ui_model::dialogs::DialogReply::Close;
        if done {
            s.release_dialog(id);
        }
        Ok(done)
    })
}

fn dialog_cancel(id: u64) -> Result<(), String> {
    with("dialog_cancel", |s| {
        let r = s.events().dialog_cancel(id);
        s.release_dialog(id);
        r
    })
}

fn dialog_button(id: u64, key: &str) -> Result<bool, String> {
    with("dialog_button", |s| {
        let done = s.events().dialog_button(id, key)? == ghidra_ui_model::dialogs::DialogReply::Close;
        if done {
            s.release_dialog(id);
        }
        Ok(done)
    })
}

fn dialog_panes(id: u64) -> Result<PaneIds, String> {
    with("dialog_panes", |s| {
        let (tree, form) = s.dialog_pane_ids(id)?;
        Ok(PaneIds { tree: tree.0, form: form.0 })
    })
}

fn tree_activate(pid: u64, node: u64) -> Result<(), String> {
    with("tree_activate", |s| s.tree_activate(ProviderId(pid), NodeId(node)))
}

fn tree_select(pid: u64, node: u64) -> Result<(), String> {
    with("tree_select", |s| {
        model!(s, pid, Tree, "tree").select(NodeId(node));
        Ok(())
    })
}

fn prompt_reply(id: u64, accepted: bool, text: &str) -> Result<(), String> {
    with("prompt_reply", |s| s.events().answer_prompt(id, accepted.then(|| text.to_owned())))
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
                    let icon_path = s.icon_path(&icon).map(|p| p.display().to_string()).unwrap_or_default();
                    ToolBarInfo { kind: 0, action: action.0, icon, icon_path, tooltip, enabled }
                }
                ToolBarEntry::Separator => ToolBarInfo {
                    kind: 1,
                    action: 0,
                    icon: String::new(),
                    icon_path: String::new(),
                    tooltip: String::new(),
                    enabled: false,
                },
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
        s.apply_tool_requests();
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
        let result = s.tool_mut().dispatch_key(ks, focused(focused_pid));
        s.apply_tool_requests();
        Ok(match result {
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
                let mut i = EventInfo {
                    kind: 5,
                    text: String::new(),
                    task: 0,
                    progress: 0,
                    maximum: 0,
                    label: String::new(),
                    initial: String::new(),
                };
                match e {
                    UiEvent::Status(m) => {
                        i.kind = 0;
                        i.text = m;
                    }
                    UiEvent::TaskProgress { task, message, progress, maximum } => {
                        (i.kind, i.text, i.task, i.progress, i.maximum) = (1, message, task, progress, maximum);
                    }
                    UiEvent::TaskDone { task, cancelled, error } => {
                        i.kind = 2;
                        i.text = error.unwrap_or_else(|| if cancelled { "cancelled".into() } else { String::new() });
                        i.task = task;
                    }
                    UiEvent::ActionsChanged => i.kind = 3,
                    UiEvent::DomainChanged { object, .. } => {
                        i.kind = 4;
                        i.task = object;
                    }
                    UiEvent::Prompt { id, title, label, initial } => {
                        (i.kind, i.task, i.text, i.label, i.initial) = (6, id, title, label, initial);
                    }
                    UiEvent::Dialog(id) => {
                        i.kind = 9;
                        i.task = id;
                    }
                    UiEvent::ViewChanged(pid) => {
                        i.kind = 7;
                        i.task = pid;
                    }
                    UiEvent::ProviderShown { id, focus } => {
                        i.kind = 8;
                        i.task = id;
                        i.progress = u64::from(focus);
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

    /// Tests share one session: the demo listing and the single event queue
    /// (a drain in one test would steal another's events). Every test that
    /// drives the listing, posts/drains events or dispatches actions holds it.
    static SESSION_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn pid(title: &str) -> u64 {
        provider_ids().unwrap().into_iter().find(|p| provider_info(*p).unwrap().title == title).unwrap()
    }

    fn frame_text(p: u64) -> Vec<String> {
        listing_frame(p).unwrap().rows.iter().map(|r| r.runs.iter().map(|x| x.text.clone()).collect::<Vec<_>>().join(" ")).collect()
    }

    /// Bridge tests share one global session: each uses its own fresh
    /// listing state by resetting through intents (Home, no selection).
    fn fresh(p: u64, rows: i32) -> i64 {
        listing_set_metrics(p, MetricsInfo { char_width: 7, bold_char_width: 7, ascent: 11, descent: 3, leading: 0 }).unwrap();
        listing_set_viewport(p, rows * 14).unwrap();
        listing_intent(p, 0, 6, 0, false).unwrap(); // Home
        listing_intent(p, 4, 0, 0, false).unwrap(); // scrollbar to 0
        14
    }

    #[test]
    fn listing_frames_and_intents_through_the_bridge() {
        let _g = SESSION_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let p = pid("Listing");
        let h = fresh(p, 5);
        assert_eq!(frame_text(p)[0], "00401000 55 ?? 55h");
        let f = listing_frame(p).unwrap();
        assert_eq!((f.scroll_max, f.scroll_page, f.top.as_str()), (13, 5, "0"));
        listing_intent(p, 3, 100, 0, false).unwrap(); // wheel past the end
        assert_eq!(listing_frame(p).unwrap().top, "13");
        listing_intent(p, 1, 0, 2 * h + 1, false).unwrap(); // click row 15
        listing_intent(p, 0, 1, 0, true).unwrap(); // shift-down
        let f = listing_frame(p).unwrap();
        let selected: Vec<&str> = f.rows.iter().filter(|r| r.selected).map(|r| r.index.as_str()).collect();
        assert_eq!(selected, vec!["15", "16"]);
        assert_eq!(f.location, "00402004");
        assert!(f.rows.iter().any(|r| r.index == "16" && r.cursor_x == 0));
        assert!(listing_intent(p, 9, 0, 0, false).is_err());
        assert!(listing_intent(p, 0, 42, 0, false).is_err());
    }

    #[test]
    fn go_to_dialog_round_trips_through_the_bridge() {
        let _g = SESSION_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let p = pid("Listing");
        fresh(p, 5);
        drain_events().unwrap();
        assert_eq!(dispatch_key(0x47 /*Key_G*/, 0, p as i64).unwrap().code, 0);
        let dialog = drain_events().unwrap().into_iter().find(|e| e.kind == 9).expect("dialog event");
        let spec = dialog_spec(dialog.task).unwrap();
        assert_eq!((spec.title.as_str(), spec.has_combo, spec.checks.len()), ("Go To ...", true, 2));
        assert!(!dialog_ok(dialog.task, "401800", spec.checks).unwrap());
        assert_eq!(dialog_spec(dialog.task).unwrap().status, "No results for 401800");
        assert!(dialog_ok(dialog.task, "402000", Vec::new()).unwrap());
        assert!(drain_events().unwrap().iter().any(|e| e.kind == 7 && e.task == p));
        assert_eq!(listing_frame(p).unwrap().location, "00402000");
        assert!(dialog_spec(dialog.task).is_err());
    }

    #[test]
    fn window_menu_entries_reshow_hidden_providers() {
        let _g = SESSION_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let decompiler = pid("Decompiler");
        with("test", |s| {
            s.tool_mut().show_provider(ProviderId(decompiler), false);
            Ok(())
        })
        .unwrap();
        let menu = menu_bar(-1).unwrap();
        let entry = menu.iter().find(|m| m.depth == 1 && m.text == "Decompiler").expect("Window > Decompiler");
        drain_events().unwrap();
        invoke_action(entry.action, -1).unwrap();
        assert!(provider_info(decompiler).unwrap().visible);
        assert!(drain_events().unwrap().iter().any(|e| e.kind == 8 && e.task == decompiler && e.progress == 1));
    }

    #[test]
    fn toolbar_entries_carry_resolved_theme_icon_files() {
        if ghidra_ui_model::icons::default_theme_root().is_none() {
            return;
        }
        let bar = tool_bar(-1).unwrap();
        let prev = bar.iter().find(|t| t.tooltip == "Previous Location").expect("Previous Location button");
        assert!(prev.icon_path.ends_with("images/left.png"), "{}", prev.icon_path);
    }

    #[test]
    fn double_clicking_a_symbol_navigates_the_listing() {
        let _g = SESSION_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let symbols = pid("Symbols");
        let row = (0..table_row_count(symbols).unwrap()).find(|&r| table_cell(symbols, r, 0).unwrap() == "printf").unwrap();
        drain_events().unwrap();
        table_activate(symbols, row, 0).unwrap();
        assert_eq!(listing_frame(pid("Listing")).unwrap().location, "00402000");
        assert!(drain_events().unwrap().iter().any(|e| e.kind == 7 && e.task == pid("Listing")));
    }

    #[test]
    fn the_options_dialog_has_panes_buttons_and_releases_them() {
        let _g = SESSION_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        drain_events().unwrap();
        let menu = menu_bar(-1).unwrap();
        let entry = menu.iter().find(|m| m.text == "Tool Options").expect("Edit > Tool Options");
        invoke_action(entry.action, -1).unwrap();
        let dialog = drain_events().unwrap().into_iter().find(|e| e.kind == 9).expect("dialog").task;
        let spec = dialog_spec(dialog).unwrap();
        assert!(spec.has_panes);
        assert_eq!(spec.buttons.iter().map(|b| b.label.as_str()).collect::<Vec<_>>(), vec!["Apply", "Restore Defaults"]);
        assert!(spec.buttons[1].confirm.contains("Restore"));
        let panes = dialog_panes(dialog).unwrap();
        assert_eq!(tree_label(panes.tree, tree_root(panes.tree).unwrap()).unwrap(), "Tool");
        tree_select(panes.tree, tree_root(panes.tree).unwrap()).unwrap();
        let fields = form_fields(panes.form).unwrap();
        let goto = fields.iter().find(|f| f.label == "Max Goto Entries").unwrap();
        assert!(!goto.tooltip.is_empty() && !goto.read_only);
        assert!(!dialog_button(dialog, "apply").unwrap());
        dialog_cancel(dialog).unwrap();
        assert!(form_fields(panes.form).is_err(), "panes released with the dialog");
    }

    #[test]
    fn double_clicking_a_program_tree_fragment_navigates_the_listing() {
        let _g = SESSION_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tree = pid("Program Tree");
        let root = tree_root(tree).unwrap();
        let data = (0..tree_child_count(tree, root).unwrap())
            .map(|i| tree_child(tree, root, i).unwrap())
            .find(|&n| tree_label(tree, n).unwrap() == ".data")
            .unwrap();
        tree_activate(tree, data).unwrap();
        assert_eq!(listing_frame(pid("Listing")).unwrap().location, "00402000");
        assert!(tree_activate(pid("Symbols"), 0).is_err());
    }

    #[test]
    fn the_listing_is_the_central_provider() {
        assert!(provider_info(pid("Listing")).unwrap().central);
        assert!(!provider_info(pid("Symbols")).unwrap().central);
    }

    #[test]
    fn demo_providers_are_visible_through_the_bridge() {
        assert_eq!(provider_ids().unwrap().len(), 5);
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
        let _g = SESSION_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let r = dispatch_key(0x46 /*Key_F*/, 0x0400_0000 /*Ctrl*/, pid("Symbols") as i64).unwrap();
        assert_eq!(r.code, 0);
        let menu = menu_bar(-1).unwrap();
        let tops: Vec<&str> = menu.iter().filter(|m| m.depth == 0).map(|m| m.text.as_str()).collect();
        assert_eq!(tops, vec!["File", "Edit", "Navigation", "Search", "Window"]);
        let copy = menu.iter().find(|m| m.text == "Copy").unwrap();
        assert_eq!(copy.key_text, "Ctrl-C");
        assert!(invoke_action(9_999_999, -1).is_err());
    }
}

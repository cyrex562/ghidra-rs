//! The Tool Options dialog's model (Java `docking.options.editor.OptionsDialog`
//! + `OptionsPanel` + `OptionsManager.editOptions`): a category tree over one
//! or more [`ToolOptions`], the selected category's options as a form, edits
//! staged until Apply/OK, and Restore Defaults for the selected subtree.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};

use ghidra_rs::framework::options::option_type::OptionType;
use ghidra_rs::util::awt::KeyStroke;
use ghidra_rs::framework::options::ToolOptions;

use crate::view_models::{FormField, FormFieldKind, FormModel, NodeId, TreeModel};

/// Java `OptionsRootTreeNode` name when several options are shown.
pub const ROOT_NAME: &str = "Options";

#[derive(Debug, Clone)]
struct Node {
    label: String,
    /// Index into `options`; `None` for the multi-options root.
    options: Option<usize>,
    /// Category path inside those options ("" = their top level).
    path: String,
    parent: Option<usize>,
    children: Vec<usize>,
}

/// Dialog state shared by its tree, its form and the dialog model.
pub struct OptionsDialogState {
    tool_name: String,
    options: Vec<Arc<ToolOptions>>,
    nodes: Vec<Node>,
    selected: usize,
    /// (options index, full option name) → staged value text.
    staged: BTreeMap<(usize, String), String>,
    /// Rejected edits (what was typed, why): shown, and they block Apply/OK.
    invalid: BTreeMap<(usize, String), (String, String)>,
    status: String,
}

/// The state behind its adapters.
pub type SharedOptionsDialog = Arc<Mutex<OptionsDialogState>>;

impl OptionsDialogState {
    /// The dialog for `tool_name` over `options` (one becomes the root itself,
    /// several hang under "Options"); the root starts selected.
    pub fn new(tool_name: &str, options: Vec<Arc<ToolOptions>>) -> Self {
        let mut nodes = Vec::new();
        if options.len() == 1 {
            nodes.push(Node { label: options[0].get_name(), options: Some(0), path: String::new(), parent: None, children: Vec::new() });
            if !is_table_set(&options[0]) {
                add_categories(&mut nodes, &options[0], 0, "", 0);
            }
        } else {
            nodes.push(Node { label: ROOT_NAME.to_owned(), options: None, path: String::new(), parent: None, children: Vec::new() });
            for (i, o) in options.iter().enumerate() {
                let id = nodes.len();
                nodes.push(Node { label: o.get_name(), options: Some(i), path: String::new(), parent: Some(0), children: Vec::new() });
                nodes[0].children.push(id);
                if !is_table_set(o) {
                    add_categories(&mut nodes, o, i, "", id); // action names may contain '.'
                }
            }
        }
        Self {
            tool_name: tool_name.to_owned(),
            options,
            nodes,
            selected: 0,
            staged: BTreeMap::new(),
            invalid: BTreeMap::new(),
            status: String::new(),
        }
    }

    /// [`Self::new`] behind a shared handle.
    pub fn shared(tool_name: &str, options: Vec<Arc<ToolOptions>>) -> SharedOptionsDialog {
        Arc::new(Mutex::new(Self::new(tool_name, options)))
    }

    /// "Options for <tool>".
    pub fn title(&self) -> String {
        format!("Options for {}", self.tool_name)
    }

    /// Selects a category node (out-of-range ids are ignored).
    pub fn select(&mut self, node: NodeId) {
        if (node.0 as usize) < self.nodes.len() {
            self.selected = node.0 as usize;
        }
    }

    /// The selected node.
    pub fn selected(&self) -> NodeId {
        NodeId(self.selected as u64)
    }

    /// The selected category's options, staged values shown.
    pub fn fields(&self) -> Vec<FormField> {
        let node = &self.nodes[self.selected];
        let Some(i) = node.options else { return Vec::new() };
        if self.selected_shows_table() {
            return Vec::new();
        }
        self.options[i]
            .leaf_option_names(&node.path)
            .iter()
            .filter_map(|leaf| self.field(i, &join(&node.path, leaf)))
            .collect()
    }

    /// Stages an edit of field `key` (validated against the option's type).
    pub fn stage(&mut self, key: &str, value: &str) -> Result<(), String> {
        let (i, name) = parse_key(key).ok_or_else(|| format!("unknown option {key}"))?;
        let field = self.field(i, &name).ok_or_else(|| format!("unknown option {key}"))?;
        if field.read_only {
            return Err(format!("{} is read-only", field.label));
        }
        let ty = self.options[i].find_option(&name).map(|o| o.option_type());
        let checked = field.validate(value).and_then(|()| match ty {
            Some(OptionType::DoubleType | OptionType::FloatType) if value.trim().parse::<f64>().is_err() => {
                Err(format!("{}: not a number", field.label))
            }
            _ => Ok(()),
        });
        if let Err(e) = checked {
            // Keep it: the user sees what they typed, and OK can't silently drop it.
            self.staged.remove(&(i, name.clone()));
            self.invalid.insert((i, name), (value.to_owned(), e.clone()));
            self.status = e.clone();
            return Err(e);
        }
        self.invalid.remove(&(i, name.clone()));
        self.staged.insert((i, name), value.to_owned());
        self.status.clear();
        Ok(())
    }

    /// Whether edits are staged.
    pub fn has_changes(&self) -> bool {
        !self.staged.is_empty() || !self.invalid.is_empty()
    }

    /// Writes every staged edit; on the first failure the status says why and
    /// the failed edit stays staged.
    pub fn apply(&mut self) -> Result<(), String> {
        if let Some((_, error)) = self.invalid.values().next() {
            self.status = error.clone();
            return Err(error.clone());
        }
        let staged = std::mem::take(&mut self.staged);
        let mut failed: Option<String> = None;
        for ((i, name), value) in staged {
            if failed.is_some() {
                self.staged.insert((i, name), value);
                continue;
            }
            if let Err(e) = write_option(&self.options[i], &name, &value) {
                failed = Some(format!("{name}: {e}"));
                self.staged.insert((i, name), value);
            }
        }
        match failed {
            Some(msg) => {
                self.status = msg.clone();
                Err(msg)
            }
            None => {
                self.status.clear();
                Ok(())
            }
        }
    }

    /// Drops staged edits (Cancel).
    pub fn discard(&mut self) {
        self.staged.clear();
        self.invalid.clear();
        self.status.clear();
    }

    /// Restores defaults for every option under the selected node, immediately
    /// (Java `restoreDefaultOptionsForCurrentEditor`); its staged edits go too.
    pub fn restore_defaults(&mut self) -> Result<(), String> {
        let node = self.nodes[self.selected].clone();
        let targets: Vec<(usize, String)> = match node.options {
            Some(i) => vec![(i, node.path.clone())],
            None => (0..self.options.len()).map(|i| (i, String::new())).collect(),
        };
        for (i, path) in targets {
            for rel in self.options[i].option_names_in_category(&path) {
                let full = join(&path, &rel);
                self.options[i].restore_default_value(&full).map_err(|e| format!("{full}: {e:?}"))?;
                self.staged.remove(&(i, full.clone()));
                self.invalid.remove(&(i, full));
            }
        }
        self.status.clear();
        Ok(())
    }

    /// The Restore Defaults confirmation text for the selected node.
    pub fn restore_confirm_text(&self) -> String {
        format!("Restore {} to default option values and erase current settings?", self.nodes[self.selected].label)
    }

    /// The status line.
    pub fn status(&self) -> &str {
        &self.status
    }

    /// Whether any shown options set uses the key-bindings table editor.
    pub fn has_table_editor(&self) -> bool {
        self.options.iter().any(|o| o.get_options_editor("").as_deref() == Some(KEY_BINDINGS_EDITOR))
    }

    /// Whether the selected node's options are edited as a table.
    pub fn selected_shows_table(&self) -> bool {
        let node = &self.nodes[self.selected];
        node.options.is_some_and(|i| node.path.is_empty() && is_table_set(&self.options[i]))
    }

    /// The key-binding rows of the selected table set: (options index, full option name).
    fn key_binding_rows(&self) -> Vec<(usize, String)> {
        let node = &self.nodes[self.selected];
        let Some(i) = node.options.filter(|_| self.selected_shows_table()) else { return Vec::new() };
        let mut names: Vec<String> = self.options[i]
            .get_option_names()
            .into_iter()
            .filter(|n| self.options[i].find_option(n).is_some_and(|e| e.is_registered() && e.option_type() == OptionType::ActionTrigger))
            .collect();
        names.sort_by(|a, b| split_full_name(a).0.cmp(split_full_name(b).0).then(a.cmp(b)));
        names.into_iter().map(|n| (i, n)).collect()
    }

    /// The key text shown for a key-binding option (typed, staged or stored).
    fn key_text(&self, i: usize, name: &str) -> String {
        let k = (i, name.to_owned());
        if let Some((typed, _)) = self.invalid.get(&k) {
            return typed.clone();
        }
        if let Some(v) = self.staged.get(&k) {
            return v.clone();
        }
        trigger_text(self.options[i].get_object(name, None).ok().flatten().as_ref())
    }

    /// Stages a key-binding edit: "" clears; otherwise a key stroke
    /// (`Ctrl-J`, `ctrl J`). Notes other actions already using it.
    fn stage_key_binding(&mut self, i: usize, name: &str, text: &str) -> Result<(), String> {
        let k = (i, name.to_owned());
        let text = text.trim();
        let parsed = if text.is_empty() { None } else { Some(KeyStroke::parse(text)) };
        if let Some(None) = parsed {
            let e = format!("Invalid key binding: {text}");
            self.staged.remove(&k);
            self.invalid.insert(k, (text.to_owned(), e.clone()));
            self.status = e.clone();
            return Err(e);
        }
        let canonical = parsed.flatten().map(|ks| ks.to_ghidra_string()).unwrap_or_default();
        self.invalid.remove(&k);
        self.staged.insert(k, canonical.clone());
        let others: Vec<String> = self
            .key_binding_rows()
            .into_iter()
            .filter(|(j, n)| !(*j == i && n == name) && !canonical.is_empty() && self.key_text(*j, n) == canonical)
            .map(|(_, n)| n)
            .collect();
        self.status = if canonical.is_empty() {
            format!("Key binding for {name} will be removed")
        } else if others.is_empty() {
            format!("Key binding for {name} will be {canonical}")
        } else {
            format!("Key binding {canonical} is also used by: {}", others.join(", "))
        };
        Ok(())
    }

    /// The form field for option `name` of options `i`.
    fn field(&self, i: usize, name: &str) -> Option<FormField> {
        let entry = self.options.get(i)?.find_option(name)?;
        let leaf = name.rsplit('.').next().unwrap_or(name);
        let key = format!("{i}:{name}");
        let k = (i, name.to_owned());
        let value = match (self.invalid.get(&k), self.staged.get(&k)) {
            (Some((typed, _)), _) => typed.clone(),
            (None, Some(v)) => v.clone(),
            (None, None) => self.options[i].get_value_as_string(name).ok().flatten().unwrap_or_default(),
        };
        let (kind, read_only) = match entry.option_type() {
            OptionType::IntType | OptionType::LongType => (FormFieldKind::Int, false),
            OptionType::BooleanType => (FormFieldKind::Bool, false),
            OptionType::StringType | OptionType::DoubleType | OptionType::FloatType | OptionType::EnumType | OptionType::FileType => {
                (FormFieldKind::Text, false)
            }
            _ => (FormFieldKind::Text, true),
        };
        let field = FormField { key, label: leaf.to_owned(), kind, value, tooltip: entry.description().to_owned(), read_only };
        Some(field)
    }
}

/// Whether an options set is edited as the key-bindings table.
fn is_table_set(options: &ToolOptions) -> bool {
    options.get_options_editor("").as_deref() == Some(KEY_BINDINGS_EDITOR)
}

/// "Go To (Demo)" → ("Go To", "Demo") (Java `ActionBindingsDescriptor`).
fn split_full_name(full: &str) -> (&str, &str) {
    match full.rfind(" (") {
        Some(p) if full.ends_with(')') => (&full[..p], &full[p + 2..full.len() - 1]),
        _ => (full, ""),
    }
}

/// An action trigger's key as Ghidra prints it ("" for none).
fn trigger_text(value: Option<&ghidra_rs::framework::options::option_type::OptionValue>) -> String {
    match value {
        Some(ghidra_rs::framework::options::option_type::OptionValue::ActionTrigger(t)) => {
            t.key_stroke().map(|k| k.to_ghidra_string()).unwrap_or_default()
        }
        _ => String::new(),
    }
}

fn join(path: &str, leaf: &str) -> String {
    if path.is_empty() { leaf.to_owned() } else { format!("{path}.{leaf}") }
}

fn parse_key(key: &str) -> Option<(usize, String)> {
    let (i, name) = key.split_once(':')?;
    Some((i.parse().ok()?, name.to_owned()))
}

fn add_categories(nodes: &mut Vec<Node>, options: &ToolOptions, index: usize, path: &str, parent: usize) {
    for child in options.child_categories(path) {
        let full = join(path, &child);
        let id = nodes.len();
        nodes.push(Node { label: child, options: Some(index), path: full.clone(), parent: Some(parent), children: Vec::new() });
        nodes[parent].children.push(id);
        add_categories(nodes, options, index, &full, id);
    }
}

/// Writes `value` with the setter for the option's registered type.
fn write_option(options: &ToolOptions, name: &str, value: &str) -> Result<(), String> {
    use ghidra_rs::framework::options::option_type::{EnumOptionValue, OptionValue};
    let entry = options.find_option(name).ok_or("not registered")?;
    let v = value.trim();
    let r = match entry.option_type() {
        OptionType::IntType => options.set_int(name, v.parse().map_err(|_| "not a 32-bit integer")?),
        OptionType::LongType => options.set_long(name, v.parse().map_err(|_| "not a 64-bit integer")?),
        OptionType::BooleanType => options.set_boolean(name, v.parse().map_err(|_| "expected true or false")?),
        OptionType::DoubleType => options.set_double(name, v.parse().map_err(|_| "not a number")?),
        OptionType::FloatType => options.set_float(name, v.parse().map_err(|_| "not a number")?),
        OptionType::StringType => options.set_string(name, Some(value)),
        OptionType::EnumType => {
            let class_name = match entry.current_value().or(entry.default_value()) {
                Some(OptionValue::Enum(e)) => e.class_name.clone(),
                _ => return Err("enum class unknown".into()),
            };
            options.set_enum(name, Some(EnumOptionValue { class_name, name: v.to_owned() }))
        }
        OptionType::FileType => options.put_object(name, Some(OptionValue::File(v.into()))),
        OptionType::ActionTrigger => {
            use ghidra_rs::framework::options::action_trigger::ActionTrigger;
            // Only the key stroke is edited; a mouse binding is kept (Java KeyBindingData.update).
            let mouse = match options.get_object(name, None) {
                Ok(Some(OptionValue::ActionTrigger(t))) => t.mouse_binding(),
                _ => None,
            };
            let ks = if v.is_empty() { None } else { Some(KeyStroke::parse(v).ok_or("not a key stroke")?) };
            options.set_action_trigger(name, ActionTrigger::new(ks, mouse).ok())
        }
        other => return Err(format!("{other:?} options are read-only here")),
    };
    r.map_err(|e| format!("{e:?}"))
}

/// Editor id an options set registers (at its root) to be edited as the
/// key-bindings table (Java's custom `KeyBindingsPanel` editor).
pub const KEY_BINDINGS_EDITOR: &str = "key-bindings";

/// The key-bindings table pane: Action Name | Key Binding | Owner (Java
/// `KeyBindingsPanel.KeyBindingsTableModel`), over the selected options set's
/// `ActionTrigger` options.
pub struct KeyBindingsTable(pub SharedOptionsDialog);

impl crate::view_models::TableModel for KeyBindingsTable {
    fn column_count(&self) -> usize {
        3
    }
    fn column_name(&self, column: usize) -> String {
        ["Action Name", "Key Binding", "Owner"].get(column).map(|s| s.to_string()).unwrap_or_default()
    }
    fn row_count(&self) -> usize {
        lock(&self.0).key_binding_rows().len()
    }
    fn cell(&self, row: usize, column: usize) -> crate::view_models::CellValue {
        let s = lock(&self.0);
        let Some((i, name)) = s.key_binding_rows().into_iter().nth(row) else { return crate::view_models::CellValue::Text(String::new()) };
        let (action, owner) = split_full_name(&name);
        crate::view_models::CellValue::Text(match column {
            0 => action.to_owned(),
            1 => s.key_text(i, &name),
            2 => owner.to_owned(),
            _ => String::new(),
        })
    }
    fn is_editable(&self, _row: usize, column: usize) -> bool {
        column == 1
    }
    fn edit(&mut self, row: usize, column: usize, value: &str) -> Result<(), String> {
        if column != 1 {
            return Err("only the key binding is editable".into());
        }
        let mut s = lock(&self.0);
        let (i, name) = s.key_binding_rows().into_iter().nth(row).ok_or_else(|| format!("no row {row}"))?;
        s.stage_key_binding(i, &name, value)
    }
}

/// The category tree pane.
pub struct OptionsTree(pub SharedOptionsDialog);
/// The selected-category form pane.
pub struct OptionsForm(pub SharedOptionsDialog);

fn lock(s: &SharedOptionsDialog) -> std::sync::MutexGuard<'_, OptionsDialogState> {
    s.lock().unwrap_or_else(PoisonError::into_inner)
}

impl TreeModel for OptionsTree {
    fn root(&self) -> NodeId {
        NodeId(0)
    }
    fn child_count(&self, node: NodeId) -> usize {
        lock(&self.0).nodes.get(node.0 as usize).map_or(0, |n| n.children.len())
    }
    fn child(&self, node: NodeId, index: usize) -> NodeId {
        NodeId(lock(&self.0).nodes.get(node.0 as usize).and_then(|n| n.children.get(index)).copied().unwrap_or(0) as u64)
    }
    fn parent(&self, node: NodeId) -> Option<NodeId> {
        lock(&self.0).nodes.get(node.0 as usize).and_then(|n| n.parent).map(|p| NodeId(p as u64))
    }
    fn label(&self, node: NodeId) -> String {
        lock(&self.0).nodes.get(node.0 as usize).map(|n| n.label.clone()).unwrap_or_default()
    }
    fn select(&mut self, node: NodeId) {
        lock(&self.0).select(node);
    }
}

impl FormModel for OptionsForm {
    fn fields(&self) -> Vec<FormField> {
        lock(&self.0).fields()
    }
    fn set(&mut self, key: &str, value: &str) -> Result<(), String> {
        lock(&self.0).stage(key, value)
    }
}

/// The Tool Options dialog behind the dialog seam.
#[derive(Clone)]
pub struct OptionsDialog(pub SharedOptionsDialog);

impl crate::dialogs::DialogModel for OptionsDialog {
    fn spec(&self) -> crate::dialogs::DialogSpec {
        let s = lock(&self.0);
        crate::dialogs::DialogSpec {
            title: s.title(),
            status: s.status().to_owned(),
            buttons: vec![
                crate::dialogs::ButtonSpec { key: "apply".into(), label: "Apply".into(), confirm: None },
                crate::dialogs::ButtonSpec {
                    key: "restore".into(),
                    label: "Restore Defaults".into(),
                    confirm: Some(s.restore_confirm_text()),
                },
            ],
            has_panes: true,
            pane_kind: u8::from(s.selected_shows_table()),
            ..Default::default()
        }
    }
    /// OK: apply, then close; a failed apply keeps it open with the status.
    fn ok(&mut self, _text: &str, _checks: &[(String, bool)]) -> crate::dialogs::DialogReply {
        let applied = lock(&self.0).apply();
        match applied {
            Ok(()) => crate::dialogs::DialogReply::Close,
            Err(_) => crate::dialogs::DialogReply::Stay(self.spec()),
        }
    }
    fn cancel(&mut self) {
        lock(&self.0).discard();
    }
    fn button(&mut self, key: &str) -> crate::dialogs::DialogReply {
        {
            let mut s = lock(&self.0);
            let r = match key {
                "apply" => s.apply(),
                "restore" => s.restore_defaults(),
                _ => Ok(()),
            };
            if let Err(e) = r {
                s.status = e; // apply sets it already; restore reports here
            }
        }
        crate::dialogs::DialogReply::Stay(self.spec())
    }
    fn panes(&self) -> Option<crate::dialogs::DialogPanes> {
        let has_table = lock(&self.0).has_table_editor();
        Some(crate::dialogs::DialogPanes {
            tree: Box::new(OptionsTree(self.0.clone())),
            form: Box::new(OptionsForm(self.0.clone())),
            table: has_table.then(|| Box::new(KeyBindingsTable(self.0.clone())) as Box<dyn crate::view_models::TableModel>),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_rs::framework::options::option_type::OptionValue;

    fn tool_options() -> Arc<ToolOptions> {
        let o = ToolOptions::new("Tool");
        o.register_option("Max Goto Entries", Some(OptionValue::Int(10)), None, "Max number of entries in the Go To history")
            .unwrap();
        o.register_option("Show Tooltips", Some(OptionValue::Boolean(true)), None, "Show tooltips").unwrap();
        o.register_option("Mouse Wheel.Lines", Some(OptionValue::Int(3)), None, "Rows per wheel notch").unwrap();
        o.register_option("Mouse Wheel.Invert", Some(OptionValue::Boolean(false)), None, "Invert scrolling").unwrap();
        o.register_option("Fonts.Listing", Some(OptionValue::String("Monospaced".into())), None, "Listing font").unwrap();
        Arc::new(o)
    }

    fn labels(d: &OptionsDialogState) -> Vec<(String, String)> {
        d.fields().into_iter().map(|f| (f.label, f.value)).collect()
    }

    fn node(d: &SharedOptionsDialog, label: &str) -> NodeId {
        let t = OptionsTree(d.clone());
        let mut stack = vec![t.root()];
        while let Some(n) = stack.pop() {
            if t.label(n) == label {
                return n;
            }
            stack.extend((0..t.child_count(n)).map(|i| t.child(n, i)));
        }
        panic!("no node {label}")
    }

    #[test]
    fn one_options_is_the_root_and_its_categories_are_children() {
        let d = OptionsDialogState::shared("CodeBrowser", vec![tool_options()]);
        assert_eq!(lock(&d).title(), "Options for CodeBrowser");
        let t = OptionsTree(d.clone());
        assert_eq!(t.label(t.root()), "Tool");
        let kids: Vec<String> = (0..t.child_count(t.root())).map(|i| t.label(t.child(t.root(), i))).collect();
        assert_eq!(kids, vec!["Fonts", "Mouse Wheel"]);
        assert_eq!(lock(&d).selected(), t.root());
        assert_eq!(labels(&lock(&d)), vec![("Max Goto Entries".into(), "10".into()), ("Show Tooltips".into(), "true".into())]);
    }

    #[test]
    fn several_options_hang_under_the_options_root() {
        let other = Arc::new(ToolOptions::new("Listing Fields"));
        other.register_option("Address Field.Show Block Name", Some(OptionValue::Boolean(false)), None, "").unwrap();
        let d = OptionsDialogState::shared("T", vec![tool_options(), other]);
        let t = OptionsTree(d.clone());
        assert_eq!(t.label(t.root()), ROOT_NAME);
        assert_eq!(t.child_count(t.root()), 2);
        assert!(labels(&lock(&d)).is_empty()); // the root has no options of its own
        let addr = node(&d, "Address Field");
        OptionsTree(d.clone()).select(addr);
        assert_eq!(labels(&lock(&d)), vec![("Show Block Name".into(), "false".into())]);
    }

    #[test]
    fn selecting_a_category_shows_its_options_with_kinds_and_descriptions() {
        let d = OptionsDialogState::shared("T", vec![tool_options()]);
        let mouse = node(&d, "Mouse Wheel"); // bind first: the guard would be held while node() locks
        lock(&d).select(mouse);
        let f = lock(&d).fields();
        assert_eq!(f.iter().map(|f| (f.label.as_str(), &f.kind)).collect::<Vec<_>>(), vec![("Invert", &FormFieldKind::Bool), ("Lines", &FormFieldKind::Int)]);
        assert_eq!(f[1].tooltip, "Rows per wheel notch");
        assert!(!f[1].read_only);
    }

    #[test]
    fn edits_are_staged_until_apply_and_invalid_values_never_reach_the_options() {
        let o = tool_options();
        let d = OptionsDialogState::shared("T", vec![o.clone()]);
        let key = lock(&d).fields()[0].key.clone(); // Max Goto Entries
        assert!(lock(&d).stage(&key, "abc").unwrap_err().contains("not an integer"));
        lock(&d).stage(&key, "25").unwrap();
        assert_eq!(lock(&d).fields()[0].value, "25");
        assert_eq!(o.get_int("Max Goto Entries", 0).unwrap(), 10, "staged, not applied");
        lock(&d).apply().unwrap();
        assert_eq!(o.get_int("Max Goto Entries", 0).unwrap(), 25);
        assert!(!lock(&d).has_changes());
    }

    #[test]
    fn an_out_of_range_int_fails_apply_with_a_status_and_stays_staged() {
        let o = tool_options();
        let d = OptionsDialogState::shared("T", vec![o.clone()]);
        let key = lock(&d).fields()[0].key.clone();
        lock(&d).stage(&key, "99999999999").unwrap(); // valid i64, not an i32
        assert!(lock(&d).apply().is_err());
        assert!(lock(&d).status().contains("Max Goto Entries"), "{}", lock(&d).status());
        assert!(lock(&d).has_changes());
        assert_eq!(o.get_int("Max Goto Entries", 0).unwrap(), 10);
    }

    #[test]
    fn an_invalid_edit_stays_visible_and_blocks_ok() {
        use crate::dialogs::{DialogModel, DialogReply};
        let o = tool_options();
        let d = OptionsDialogState::shared("T", vec![o.clone()]);
        let mut dialog = OptionsDialog(d.clone());
        let key = lock(&d).fields()[0].key.clone(); // Max Goto Entries
        assert!(lock(&d).stage(&key, "abc").is_err());
        assert_eq!(lock(&d).fields()[0].value, "abc", "what the user typed stays visible");
        match dialog.ok("", &[]) {
            DialogReply::Stay(s) => assert!(s.status.contains("not an integer"), "{}", s.status),
            other => panic!("{other:?}"),
        }
        assert_eq!(o.get_int("Max Goto Entries", 0).unwrap(), 10);
        lock(&d).stage(&key, "12").unwrap();
        assert_eq!(dialog.ok("", &[]), DialogReply::Close);
        assert_eq!(o.get_int("Max Goto Entries", 0).unwrap(), 12);
    }

    #[test]
    fn cancel_discards_staged_edits() {
        let o = tool_options();
        let d = OptionsDialogState::shared("T", vec![o.clone()]);
        let key = lock(&d).fields()[1].key.clone(); // Show Tooltips
        lock(&d).stage(&key, "false").unwrap();
        lock(&d).discard();
        assert_eq!(lock(&d).fields()[1].value, "true");
        assert!(o.get_boolean("Show Tooltips", false).unwrap());
    }

    #[test]
    fn restore_defaults_touches_only_the_selected_subtree() {
        let o = tool_options();
        o.set_int("Max Goto Entries", 30).unwrap();
        o.set_int("Mouse Wheel.Lines", 7).unwrap();
        let d = OptionsDialogState::shared("T", vec![o.clone()]);
        let mouse = node(&d, "Mouse Wheel"); // bind first: the guard would be held while node() locks
        lock(&d).select(mouse);
        assert_eq!(lock(&d).restore_confirm_text(), "Restore Mouse Wheel to default option values and erase current settings?");
        lock(&d).restore_defaults().unwrap();
        assert_eq!(o.get_int("Mouse Wheel.Lines", 0).unwrap(), 3);
        assert_eq!(o.get_int("Max Goto Entries", 0).unwrap(), 30);
    }

    #[test]
    fn types_the_form_cannot_edit_are_read_only() {
        let o = Arc::new(ToolOptions::new("Tool"));
        o.register_option("Bytes", Some(OptionValue::ByteArray(vec![1, 2])), None, "raw").unwrap();
        let d = OptionsDialogState::shared("T", vec![o]);
        let f = lock(&d).fields();
        assert!(f[0].read_only);
        assert!(lock(&d).stage(&f[0].key, "x").is_err());
    }

    #[test]
    fn the_dialog_offers_apply_and_a_confirmed_restore_defaults() {
        use crate::dialogs::{DialogModel, DialogReply};
        let o = tool_options();
        let d = OptionsDialogState::shared("CodeBrowser", vec![o.clone()]);
        let mut dialog = OptionsDialog(d.clone());
        let spec = dialog.spec();
        assert_eq!(spec.title, "Options for CodeBrowser");
        assert!(spec.has_panes && spec.combo.is_none());
        let keys: Vec<(&str, &str, bool)> = spec.buttons.iter().map(|b| (b.key.as_str(), b.label.as_str(), b.confirm.is_some())).collect();
        assert_eq!(keys, vec![("apply", "Apply", false), ("restore", "Restore Defaults", true)]);
        let key = lock(&d).fields()[0].key.clone();
        lock(&d).stage(&key, "12").unwrap();
        assert!(matches!(dialog.button("apply"), DialogReply::Stay(_)));
        assert_eq!(o.get_int("Max Goto Entries", 0).unwrap(), 12);
        assert!(matches!(dialog.button("restore"), DialogReply::Stay(_)));
        assert_eq!(o.get_int("Max Goto Entries", 0).unwrap(), 10);
        lock(&d).stage(&key, "99999999999").unwrap();
        match dialog.ok("", &[]) {
            DialogReply::Stay(s) => assert!(s.status.contains("Max Goto Entries"), "{}", s.status),
            other => panic!("{other:?}"),
        }
        lock(&d).stage(&key, "15").unwrap();
        assert_eq!(dialog.ok("", &[]), DialogReply::Close);
        assert_eq!(o.get_int("Max Goto Entries", 0).unwrap(), 15);
    }

    fn key_bindings() -> Arc<ToolOptions> {
        use ghidra_rs::framework::options::action_trigger::ActionTrigger;
        use ghidra_rs::util::awt::KeyStroke;
        let o = ToolOptions::new("Key Bindings");
        for (name, key) in [("Go To (Demo)", "G"), ("Find (Demo)", "ctrl F")] {
            let t = ActionTrigger::new(KeyStroke::parse(key), None).unwrap();
            o.register_option_with_type(name, OptionType::ActionTrigger, Some(OptionValue::ActionTrigger(t)), None, Some(&format!("Key Binding for {name}")), None)
                .unwrap();
        }
        o.register_options_editor("", KEY_BINDINGS_EDITOR);
        Arc::new(o)
    }

    #[test]
    fn a_key_bindings_options_set_is_edited_as_a_table() {
        use crate::dialogs::{DialogModel, DialogReply};
        use crate::view_models::{CellValue, TableModel};
        let kb = key_bindings();
        let d = OptionsDialogState::shared("T", vec![kb.clone(), tool_options()]);
        let mut dialog = OptionsDialog(d.clone());
        let kb_node = node(&d, "Key Bindings");
        lock(&d).select(kb_node);
        assert_eq!(dialog.spec().pane_kind, 1);
        let mut t = KeyBindingsTable(d.clone());
        let rows: Vec<(String, String, String)> = (0..t.row_count())
            .map(|r| {
                let txt = |c| match t.cell(r, c) {
                    CellValue::Text(s) => s,
                    other => format!("{other:?}"),
                };
                (txt(0), txt(1), txt(2))
            })
            .collect();
        assert_eq!(
            rows,
            vec![("Find".into(), "Ctrl-F".into(), "Demo".into()), ("Go To".into(), "G".into(), "Demo".into())]
        );
        t.edit(1, 1, "ctrl J").unwrap();
        assert!(lock(&d).status().contains("Go To"), "staged edits are noted: {}", lock(&d).status());
        t.edit(0, 1, "").unwrap(); // clear Find
        assert!(t.edit(0, 1, "not a key").is_err());
        assert!(matches!(dialog.ok("", &[]), DialogReply::Stay(_)), "invalid key text blocks OK");
        t.edit(0, 1, "").unwrap();
        assert_eq!(dialog.ok("", &[]), DialogReply::Close);
        let key = |name: &str| match kb.get_object(name, None).unwrap() {
            Some(OptionValue::ActionTrigger(t)) => t.key_stroke().map(|k| k.to_ghidra_string()),
            _ => None,
        };
        assert_eq!(key("Go To (Demo)").as_deref(), Some("Ctrl-J"));
        assert_eq!(key("Find (Demo)"), None);
        let tool = node(&d, "Tool");
        lock(&d).select(tool);
        assert_eq!(dialog.spec().pane_kind, 0);
    }

    #[test]
    fn a_shared_key_binding_is_reported() {
        use crate::view_models::TableModel;
        let d = OptionsDialogState::shared("T", vec![key_bindings()]);
        let mut t = KeyBindingsTable(d.clone());
        t.edit(1, 1, "ctrl F").unwrap(); // Go To := Find's key
        assert!(lock(&d).status().contains("Find (Demo)"), "{}", lock(&d).status());
    }

    #[test]
    fn bad_keys_and_node_ids_are_errors_not_panics() {
        let d = OptionsDialogState::shared("T", vec![tool_options()]);
        assert!(lock(&d).stage("nonsense", "1").is_err());
        assert!(lock(&d).stage("9:Max Goto Entries", "1").is_err());
        lock(&d).select(NodeId(999));
        assert_eq!(lock(&d).selected(), NodeId(0));
        let _ = OptionType::IntType;
    }
}

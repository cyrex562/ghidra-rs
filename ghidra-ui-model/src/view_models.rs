//! Generic view-model traits the renderer has one widget for each of (Qt6 UI
//! spec §2). Every method is a cheap snapshot read on the UI thread — no I/O,
//! no transaction locks (spec §3).

use std::fmt;

/// One table cell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CellValue {
    /// Plain text.
    Text(String),
    /// An integer (sorted numerically).
    Int(i64),
    /// An address (rendered as hex, sorted numerically).
    Address(u64),
    /// A checkbox value.
    Bool(bool),
    /// No value.
    Empty,
}

impl fmt::Display for CellValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CellValue::Text(s) => f.write_str(s),
            CellValue::Int(i) => write!(f, "{i}"),
            CellValue::Address(a) => write!(f, "{a:08x}"),
            CellValue::Bool(b) => write!(f, "{b}"),
            CellValue::Empty => Ok(()),
        }
    }
}

/// Rows and columns.
pub trait TableModel: Send {
    /// Number of columns.
    fn column_count(&self) -> usize;
    /// Header text of a column.
    fn column_name(&self, column: usize) -> String;
    /// Number of (visible, filtered) rows.
    fn row_count(&self) -> usize;
    /// The cell; [`CellValue::Empty`] when out of range.
    fn cell(&self, row: usize, column: usize) -> CellValue;
    /// Sorts by a column.
    fn sort(&mut self, _column: usize, _ascending: bool) {}
    /// The address a row navigates to (Java `ProgramTableModel.getProgramLocation`):
    /// by default the clicked cell's address, else the row's first address cell.
    fn location(&self, row: usize, column: usize) -> Option<u64> {
        if row >= self.row_count() {
            return None;
        }
        let address = |c: usize| match self.cell(row, c) {
            CellValue::Address(a) => Some(a),
            _ => None,
        };
        address(column).or_else(|| (0..self.column_count()).find_map(address))
    }
    /// Filters rows by text (empty = no filter).
    fn set_filter(&mut self, _text: &str) {}
    /// Whether a cell is editable.
    fn is_editable(&self, _row: usize, _column: usize) -> bool {
        false
    }
    /// Commits an edit.
    fn edit(&mut self, _row: usize, _column: usize, _value: &str) -> Result<(), String> {
        Err("not editable".to_owned())
    }
}

/// A tree node handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeId(pub u64);

/// A hierarchy of labelled nodes.
pub trait TreeModel: Send {
    /// The root node.
    fn root(&self) -> NodeId;
    /// Number of children.
    fn child_count(&self, node: NodeId) -> usize;
    /// The `index`th child.
    fn child(&self, node: NodeId, index: usize) -> NodeId;
    /// The parent, or `None` for the root.
    fn parent(&self, node: NodeId) -> Option<NodeId>;
    /// Display label.
    fn label(&self, node: NodeId) -> String;
    /// Theme icon id.
    fn icon(&self, _node: NodeId) -> Option<String> {
        None
    }
    /// The renderer selected `node` (single selection); default: ignored.
    fn select(&mut self, _node: NodeId) {}
    /// Whether the node has no children.
    fn is_leaf(&self, node: NodeId) -> bool {
        self.child_count(node) == 0
    }
}

/// A styled run of text within a line.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StyledRun {
    /// The text.
    pub text: String,
    /// Theme color id (`GColor` id), if styled.
    pub color_id: Option<String>,
    /// Bold.
    pub bold: bool,
    /// Italic.
    pub italic: bool,
    /// Hyperlink target, if any.
    pub link: Option<String>,
}

impl StyledRun {
    /// An unstyled run.
    pub fn plain(text: impl Into<String>) -> Self {
        Self { text: text.into(), ..Self::default() }
    }
}

/// Lines of styled text.
pub trait TextModel: Send {
    /// Number of lines.
    fn line_count(&self) -> usize;
    /// The runs of a line (empty when out of range).
    fn line(&self, index: usize) -> Vec<StyledRun>;
}

/// What a form field edits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FormFieldKind {
    /// Free text.
    Text,
    /// An integer.
    Int,
    /// A checkbox.
    Bool,
    /// One of a fixed set of choices.
    Choice(Vec<String>),
}

/// One editable field of a form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormField {
    /// Stable key.
    pub key: String,
    /// Label shown to the user.
    pub label: String,
    /// Kind of value.
    pub kind: FormFieldKind,
    /// Current value, as text.
    pub value: String,
    /// Tooltip (an option's description); empty for none.
    pub tooltip: String,
    /// Shown but not editable.
    pub read_only: bool,
}

impl FormField {
    /// A text field.
    pub fn text(key: &str, label: &str, value: &str) -> Self {
        Self { key: key.into(), label: label.into(), kind: FormFieldKind::Text, value: value.into(), tooltip: String::new(), read_only: false }
    }

    /// An integer field.
    pub fn int(key: &str, label: &str, value: i64) -> Self {
        Self { key: key.into(), label: label.into(), kind: FormFieldKind::Int, value: value.to_string(), tooltip: String::new(), read_only: false }
    }

    /// A checkbox field.
    pub fn bool(key: &str, label: &str, value: bool) -> Self {
        Self { key: key.into(), label: label.into(), kind: FormFieldKind::Bool, value: value.to_string(), tooltip: String::new(), read_only: false }
    }

    /// With a tooltip.
    pub fn with_tooltip(mut self, tooltip: &str) -> Self {
        self.tooltip = tooltip.to_owned();
        self
    }

    /// Shown but not editable.
    pub fn read_only(mut self) -> Self {
        self.read_only = true;
        self
    }

    /// Validates a candidate value for this field's kind.
    pub fn validate(&self, value: &str) -> Result<(), String> {
        match &self.kind {
            FormFieldKind::Text => Ok(()),
            FormFieldKind::Int => value.trim().parse::<i64>().map(|_| ()).map_err(|_| format!("{}: not an integer", self.label)),
            FormFieldKind::Bool => match value {
                "true" | "false" => Ok(()),
                _ => Err(format!("{}: expected true or false", self.label)),
            },
            FormFieldKind::Choice(c) if c.iter().any(|x| x == value) => Ok(()),
            FormFieldKind::Choice(_) => Err(format!("{}: not one of the choices", self.label)),
        }
    }
}

/// Option / edit fields.
pub trait FormModel: Send {
    /// The fields, in display order.
    fn fields(&self) -> Vec<FormField>;
    /// Sets a field's value (validated).
    fn set(&mut self, key: &str, value: &str) -> Result<(), String>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::demo::*;

    #[test]
    fn vec_table_sorts_and_filters() {
        let mut t = VecTable::new(
            vec!["Name".into(), "Size".into()],
            vec![
                vec![CellValue::Text("b".into()), CellValue::Int(2)],
                vec![CellValue::Text("a".into()), CellValue::Int(10)],
                vec![CellValue::Text("c".into()), CellValue::Int(1)],
            ],
        );
        t.sort(1, true);
        assert_eq!(t.cell(0, 0), CellValue::Text("c".into()));
        t.sort(1, false);
        assert_eq!(t.cell(0, 0), CellValue::Text("a".into()));
        t.set_filter("a");
        assert_eq!(t.row_count(), 1);
        t.set_filter("");
        assert_eq!(t.row_count(), 3);
    }

    #[test]
    fn out_of_range_cells_are_empty_not_panics() {
        let t = VecTable::new(vec!["A".into()], vec![vec![CellValue::Int(1)]]);
        assert_eq!(t.cell(5, 0), CellValue::Empty);
        assert_eq!(t.cell(0, 9), CellValue::Empty);
    }

    #[test]
    fn static_tree_navigation() {
        let t = StaticTree::from_paths(&["root/a/x", "root/a/y", "root/b"]);
        let r = t.root();
        assert_eq!(t.label(r), "root");
        assert_eq!(t.child_count(r), 2);
        let a = t.child(r, 0);
        assert_eq!(t.label(a), "a");
        assert_eq!(t.child_count(a), 2);
        assert_eq!(t.parent(a), Some(r));
        assert_eq!(t.parent(r), None);
        assert!(t.is_leaf(t.child(r, 1)));
    }

    #[test]
    fn map_form_validates_int_fields() {
        let mut f = MapForm::new(vec![FormField::int("depth", "Depth", 3)]);
        assert!(f.set("depth", "12").is_ok());
        assert!(f.set("depth", "twelve").is_err());
        assert!(f.set("missing", "1").is_err());
        assert_eq!(f.fields()[0].value, "12");
    }

    #[test]
    fn lines_text_returns_runs() {
        let t = LinesText::new(vec!["int main() {".into(), "}".into()]);
        assert_eq!(t.line_count(), 2);
        assert_eq!(t.line(0)[0].text, "int main() {");
        assert!(t.line(7).is_empty());
    }
}

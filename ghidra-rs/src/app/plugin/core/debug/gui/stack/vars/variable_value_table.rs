use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex};

use super::{RowKey, VariableValueRow};

/// A table for display in a variable value hover.
///
/// At most one row of each [`RowKey`] type may be present; adding a row whose key already
/// exists replaces the previous row.  All operations are internally synchronised, so the
/// table may be shared across threads.
///
/// Rows are always iterated in [`RowKey`] declaration order (enforced by [`BTreeMap`]).
///
/// Ported from `ghidra.app.plugin.core.debug.gui.stack.vars.VariableValueTable`.
pub struct VariableValueTable {
    rows: Mutex<BTreeMap<RowKey, Arc<dyn VariableValueRow>>>,
}

impl VariableValueTable {
    pub fn new() -> Self {
        Self {
            rows: Mutex::new(BTreeMap::new()),
        }
    }

    /// Inserts `row`, replacing any existing row with the same [`RowKey`].
    pub fn add(&self, row: Arc<dyn VariableValueRow>) {
        let key = row.key();
        self.rows.lock().unwrap().insert(key, row);
    }

    /// Returns the row for `key`, or `None` if absent.
    pub fn get(&self, key: RowKey) -> Option<Arc<dyn VariableValueRow>> {
        self.rows.lock().unwrap().get(&key).cloned()
    }

    /// Removes the row for `key`, if present.
    pub fn remove(&self, key: RowKey) {
        self.rows.lock().unwrap().remove(&key);
    }

    /// Returns the number of rows currently in the table.
    pub fn get_num_rows(&self) -> usize {
        self.rows.lock().unwrap().len()
    }

    /// Renders the table as an HTML `<table>` element; rows appear in [`RowKey`] order.
    pub fn to_html(&self) -> String {
        let rows = self.rows.lock().unwrap();
        let inner: Vec<String> = rows.values().map(|r| r.to_html()).collect();
        format!("<table>\n  {}\n</table>\n", inner.join("\n"))
    }

    /// Calls [`VariableValueRow::report_details`] on every row in the table.
    pub fn report_details(&self) {
        let rows = self.rows.lock().unwrap();
        for row in rows.values() {
            row.report_details();
        }
    }
}

impl Default for VariableValueTable {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for VariableValueTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let rows = self.rows.lock().unwrap();
        let inner: Vec<String> = rows.values().map(|r| r.to_simple_string()).collect();
        write!(f, "<VariableValueTable:\n  {}\n>\n", inner.join("\n  "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::RowKey;

    struct SimpleRow {
        key: RowKey,
        value: String,
    }

    impl VariableValueRow for SimpleRow {
        fn key(&self) -> RowKey {
            self.key
        }
        fn value_to_simple_string(&self) -> String {
            self.value.clone()
        }
        fn value_to_html(&self) -> String {
            self.value.clone()
        }
    }

    fn row(key: RowKey, value: &str) -> Arc<dyn VariableValueRow> {
        Arc::new(SimpleRow { key, value: value.to_string() })
    }

    #[test]
    fn new_table_is_empty() {
        let t = VariableValueTable::new();
        assert_eq!(t.get_num_rows(), 0);
    }

    #[test]
    fn default_creates_empty_table() {
        let t = VariableValueTable::default();
        assert_eq!(t.get_num_rows(), 0);
    }

    #[test]
    fn add_and_get_row() {
        let t = VariableValueTable::new();
        t.add(row(RowKey::Name, "foo"));
        let r = t.get(RowKey::Name).unwrap();
        assert_eq!(r.value_to_simple_string(), "foo");
    }

    #[test]
    fn get_absent_key_returns_none() {
        let t = VariableValueTable::new();
        assert!(t.get(RowKey::Name).is_none());
    }

    #[test]
    fn add_replaces_existing_row_of_same_key() {
        let t = VariableValueTable::new();
        t.add(row(RowKey::Name, "first"));
        t.add(row(RowKey::Name, "second"));
        assert_eq!(t.get_num_rows(), 1);
        assert_eq!(t.get(RowKey::Name).unwrap().value_to_simple_string(), "second");
    }

    #[test]
    fn remove_row() {
        let t = VariableValueTable::new();
        t.add(row(RowKey::Status, "computing"));
        t.remove(RowKey::Status);
        assert!(t.get(RowKey::Status).is_none());
        assert_eq!(t.get_num_rows(), 0);
    }

    #[test]
    fn remove_absent_key_is_no_op() {
        let t = VariableValueTable::new();
        t.remove(RowKey::Error);
        assert_eq!(t.get_num_rows(), 0);
    }

    #[test]
    fn get_num_rows_counts_distinct_keys() {
        let t = VariableValueTable::new();
        t.add(row(RowKey::Name, "v"));
        t.add(row(RowKey::Status, "s"));
        t.add(row(RowKey::Error, "e"));
        assert_eq!(t.get_num_rows(), 3);
    }

    #[test]
    fn to_html_wraps_in_table_tag() {
        let t = VariableValueTable::new();
        t.add(row(RowKey::Status, "ok"));
        let html = t.to_html();
        assert!(html.contains("<table>"));
        assert!(html.contains("</table>"));
        assert!(html.contains("<tr>"));
    }

    #[test]
    fn to_html_empty_table() {
        let t = VariableValueTable::new();
        let html = t.to_html();
        assert!(html.contains("<table>"));
        assert!(html.contains("</table>"));
    }

    #[test]
    fn rows_ordered_by_row_key_in_html() {
        let t = VariableValueTable::new();
        t.add(row(RowKey::Error, "err_val"));
        t.add(row(RowKey::Name, "name_val"));
        let html = t.to_html();
        let name_pos = html.find("name_val").unwrap();
        let err_pos = html.find("err_val").unwrap();
        assert!(name_pos < err_pos, "Name must appear before Error in output");
    }

    #[test]
    fn display_contains_table_name_and_row_values() {
        let t = VariableValueTable::new();
        t.add(row(RowKey::Name, "my_var"));
        let s = t.to_string();
        assert!(s.contains("VariableValueTable"));
        assert!(s.contains("my_var"));
    }

    #[test]
    fn row_key_ordering_matches_declaration_order() {
        assert!(RowKey::Name < RowKey::Frame);
        assert!(RowKey::Frame < RowKey::Storage);
        assert!(RowKey::Bytes < RowKey::Integer);
        assert!(RowKey::Integer < RowKey::Value);
        assert!(RowKey::Warnings < RowKey::Error);
        assert!(RowKey::Name < RowKey::Error);
    }

    #[test]
    fn row_key_to_html_escapes_special_chars() {
        let r = SimpleRow { key: RowKey::Name, value: String::new() };
        let html = r.key_to_html();
        assert!(html.ends_with(':'), "key_to_html should append a colon");
        assert!(!html.contains('<'), "key_to_html should not contain raw '<'");
    }

    #[test]
    fn row_default_to_html_contains_key_and_value() {
        let r = SimpleRow { key: RowKey::Status, value: "pending".to_string() };
        let html = r.to_html();
        assert!(html.contains("Status:"));
        assert!(html.contains("pending"));
        assert!(html.starts_with("<tr>"));
    }

    #[test]
    fn row_default_to_simple_string() {
        let r = SimpleRow { key: RowKey::Value, value: "42".to_string() };
        assert_eq!(r.to_simple_string(), "Value: 42");
    }
}

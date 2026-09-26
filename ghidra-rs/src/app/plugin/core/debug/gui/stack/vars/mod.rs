pub mod variable_value_table;
pub use variable_value_table::VariableValueTable;

/// Key identifying a row type within a [`VariableValueTable`].
///
/// Variants appear in the natural display order; the derived [`Ord`] ensures a
/// [`std::collections::BTreeMap`] keyed on `RowKey` always iterates in this order.
///
/// Ported from `ghidra.app.plugin.core.debug.gui.stack.vars.VariableValueRow.RowKey`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RowKey {
    Name,
    Frame,
    Storage,
    Type,
    Instruction,
    Location,
    Bytes,
    Integer,
    Value,
    Status,
    Warnings,
    Error,
}

impl std::fmt::Display for RowKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            RowKey::Name => "Name",
            RowKey::Frame => "Frame",
            RowKey::Storage => "Storage",
            RowKey::Type => "Type",
            RowKey::Instruction => "Instruction",
            RowKey::Location => "Location",
            RowKey::Bytes => "Bytes",
            RowKey::Integer => "Integer",
            RowKey::Value => "Value",
            RowKey::Status => "Status",
            RowKey::Warnings => "Warnings",
            RowKey::Error => "Error",
        };
        write!(f, "{s}")
    }
}

/// A row to be displayed in a variable value hover's table.
///
/// Implementors supply a [`RowKey`], a plain-text value, and an HTML value.
/// The remaining rendering methods have default implementations that compose those.
///
/// Ported from `ghidra.app.plugin.core.debug.gui.stack.vars.VariableValueRow`.
pub trait VariableValueRow: Send + Sync {
    /// Returns the key that identifies this row's type.
    fn key(&self) -> RowKey;

    /// Renders the row value for diagnostic display (plain text).
    fn value_to_simple_string(&self) -> String;

    /// Renders the row value as an HTML fragment for table display.
    fn value_to_html(&self) -> String;

    /// Renders the key for diagnostic display.
    fn key_to_simple_string(&self) -> String {
        self.key().to_string()
    }

    /// Renders the key as an HTML-escaped string with a trailing colon.
    fn key_to_html(&self) -> String {
        html_escape(&format!("{}:", self.key()))
    }

    /// Renders the complete row for diagnostic display (`"Key: value"`).
    fn to_simple_string(&self) -> String {
        format!("{}: {}", self.key_to_simple_string(), self.value_to_simple_string())
    }

    /// Renders the complete row as an HTML `<tr>` element.
    fn to_html(&self) -> String {
        format!(
            "<tr><td valign='top'><b>{}</b></td><td><tt>{}</tt></td></tr>",
            self.key_to_html(),
            self.value_to_html()
        )
    }

    /// Reports any additional diagnostic details; no-op by default.
    fn report_details(&self) {}
}

fn html_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            _ => out.push(c),
        }
    }
    out
}

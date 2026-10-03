//! Port of `ghidra.feature.vt.api.db.TableColumn`.

use std::fmt;

use crate::framework::db::Field;

/// Describes one column of a database table: its storage [`Field`] type, whether it is indexed,
/// and (once assigned by whatever builds the table's schema) its display name and ordinal
/// position.
///
/// Port of `ghidra.feature.vt.api.db.TableColumn`. `name`/`ordinal` are set after construction --
/// mirroring Java's package-private `setName`/`setOrdinal`, called by `TableDescriptor` (not yet
/// ported) once it knows where in the schema this column landed -- so both start unset:
/// [`name`](Self::name) mirrors Java's `null` as `None` until [`set_name`](Self::set_name) is
/// called, and [`column`](Self::column) starts at `0` (Java's default `int` field value) until
/// [`set_ordinal`](Self::set_ordinal) is called.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableColumn {
    column_field: Field,
    indexed: bool,
    ordinal: i32,
    name: Option<String>,
}

impl TableColumn {
    /// Construct a non-indexed column of the given storage type.
    ///
    /// Mirrors `TableColumn(Field columnField)`, which delegates to the two-argument constructor
    /// with `isIndexed = false`.
    pub fn new(column_field: Field) -> Self {
        Self::with_indexed(column_field, false)
    }

    /// Construct a column of the given storage type, optionally indexed.
    ///
    /// Mirrors `TableColumn(Field columnField, boolean isIndexed)`.
    pub fn with_indexed(column_field: Field, is_indexed: bool) -> Self {
        Self { column_field, indexed: is_indexed, ordinal: 0, name: None }
    }

    /// Set this column's display name.
    ///
    /// Mirrors the package-private `TableColumn.setName(String)`.
    pub fn set_name(&mut self, name: impl Into<String>) {
        self.name = Some(name.into());
    }

    /// Set this column's ordinal position within the table.
    ///
    /// Mirrors the package-private `TableColumn.setOrdinal(int)`.
    pub fn set_ordinal(&mut self, ordinal: i32) {
        self.ordinal = ordinal;
    }

    /// Whether this column is indexed.
    ///
    /// Mirrors `TableColumn.isIndexed()`.
    pub fn is_indexed(&self) -> bool {
        self.indexed
    }

    /// This column's storage [`Field`] type.
    ///
    /// Mirrors `TableColumn.getColumnField()`.
    pub fn get_column_field(&self) -> &Field {
        &self.column_field
    }

    /// This column's display name, if [`set_name`](Self::set_name) has been called.
    ///
    /// Mirrors `TableColumn.name()`, which returns `null` before `setName` is ever called; that
    /// case is modeled here as `None`.
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// This column's ordinal position, or `0` if [`set_ordinal`](Self::set_ordinal) has not been
    /// called yet.
    ///
    /// Mirrors `TableColumn.column()`.
    pub fn column(&self) -> i32 {
        self.ordinal
    }
}

impl fmt::Display for TableColumn {
    /// Mirrors `TableColumn.toString()`: `"<name>(<ordinal>)"`.
    ///
    /// Java's `name() + "(" + ordinal + ")"` string concatenation renders a `null` name (i.e.
    /// before `setName` is ever called) as the literal text `"null"`, per `String.valueOf(null)`.
    /// That quirk is reproduced here rather than, say, an empty string.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = self.name.as_deref().unwrap_or("null");
        write!(f, "{name}({})", self.ordinal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Java: `new TableColumn(columnField)` defaults `indexed` to `false`.
    #[test]
    fn new_defaults_to_not_indexed() {
        let col = TableColumn::new(Field::Long(None));
        assert!(!col.is_indexed());
    }

    /// Java: `new TableColumn(columnField, true)` stores the given indexed flag.
    #[test]
    fn with_indexed_stores_the_flag() {
        let col = TableColumn::with_indexed(Field::String(None), true);
        assert!(col.is_indexed());
    }

    #[test]
    fn get_column_field_returns_the_constructor_argument() {
        let col = TableColumn::new(Field::Int(Some(4)));
        assert_eq!(col.get_column_field(), &Field::Int(Some(4)));
    }

    /// Java: `name()` returns `null` and `column()` returns `0` before `setName`/`setOrdinal` are
    /// ever called (the default value of a `String` field and an `int` field, respectively).
    #[test]
    fn name_and_column_default_before_being_set() {
        let col = TableColumn::new(Field::Long(None));
        assert_eq!(col.name(), None);
        assert_eq!(col.column(), 0);
    }

    #[test]
    fn set_name_and_set_ordinal_round_trip() {
        let mut col = TableColumn::new(Field::Long(None));
        col.set_name("SOURCE_ADDRESS_COL");
        col.set_ordinal(3);
        assert_eq!(col.name(), Some("SOURCE_ADDRESS_COL"));
        assert_eq!(col.column(), 3);
    }

    /// Java: `toString()` is `name() + "(" + ordinal + ")"`.
    #[test]
    fn display_formats_name_and_ordinal() {
        let mut col = TableColumn::new(Field::Long(None));
        col.set_name("VOTE_COUNT_COL");
        col.set_ordinal(5);
        assert_eq!(col.to_string(), "VOTE_COUNT_COL(5)");
    }

    /// Java quirk, reproduced faithfully: before `setName` is called, `name()` is `null`, and
    /// `toString()`'s `+` concatenation renders that `null` as the literal text `"null"` (per
    /// `String.valueOf(null)`), not an empty string.
    #[test]
    fn display_before_set_name_renders_java_null_concatenation_quirk() {
        let mut col = TableColumn::new(Field::Long(None));
        col.set_ordinal(2);
        assert_eq!(col.to_string(), "null(2)");
    }

    #[test]
    fn display_before_any_setter_is_called() {
        let col = TableColumn::new(Field::Long(None));
        assert_eq!(col.to_string(), "null(0)");
    }
}

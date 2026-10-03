//! Port of `ghidra.feature.vt.api.db.TableDescriptor`.

use crate::feature::vt::api::db::table_column::TableColumn;
use crate::framework::db::Field;

/// Returns a fresh, empty [`Field`] of the same variant as `field`, discarding whatever value (if
/// any) `field` currently holds.
///
/// Mirrors `db.Field.newField()`: in Java, each concrete `Field` subclass (`LongField`,
/// `StringField`, ...) is both a type descriptor *and* a value holder, and `newField()` produces a
/// brand-new, empty instance of that same concrete type. Since [`Field`] is a Rust enum rather than
/// a class hierarchy, "same concrete type" becomes "same variant, with a `None` payload".
fn new_field_of_same_type(field: &Field) -> Field {
    match field {
        Field::Byte(_) => Field::Byte(None),
        Field::Short(_) => Field::Short(None),
        Field::Int(_) => Field::Int(None),
        Field::Long(_) => Field::Long(None),
        Field::String(_) => Field::String(None),
        Field::Binary(_) => Field::Binary(None),
        Field::Boolean(_) => Field::Boolean(None),
        Field::Fixed(_) => Field::Fixed(None),
    }
}

/// Describes the ordered set of [`TableColumn`]s that make up a database table's schema.
///
/// Port of `ghidra.feature.vt.api.db.TableDescriptor`. In Java, a concrete `TableDescriptor`
/// subclass declares its columns as `public static final TableColumn` fields (e.g. `public static
/// final TableColumn ADDRESS_COL = ...`), and the protected constructor's private
/// `discoverTableColumns()` helper uses `getClass().getFields()` reflection to find them (in
/// declaration order among that class's public fields, skipping any public field that isn't a
/// `TableColumn`), assigning each discovered column's name (the field's own name) and ordinal (its
/// position among the *discovered* fields, 0-based) via the package-private
/// `TableColumn.setName`/`setOrdinal`.
///
/// Rust has no field reflection, so [`TableDescriptor::new`] takes that same `(name, TableColumn)`
/// sequence explicitly, in the order the columns should be discovered -- standing in for the
/// reflected fields, in declaration order. Every other part of `discoverTableColumns()`'s behavior
/// is reproduced: each column's name/ordinal are (re)assigned unconditionally on construction (even
/// if the caller passes in a [`TableColumn`] that already has a name/ordinal set, mirroring
/// `discoverTableColumns()` overwriting them every time a `TableDescriptor` is constructed), and the
/// resulting order backs [`get_indexed_columns`](Self::get_indexed_columns)/
/// [`get_column_names`](Self::get_column_names)/[`get_column_fields`](Self::get_column_fields)
/// exactly as declared.
///
/// # Deviation from Java
///
/// * **No `IllegalAccessException`/"skip non-`TableColumn` field" path.** Java's reflective
///   `field.get(null)` can throw `IllegalAccessException` for a non-public-static field (logged via
///   `Msg.showError` and then silently skipped), and non-`TableColumn`-typed public fields are
///   skipped outright. Since the Rust caller supplies only `TableColumn` values directly (not
///   reflected field accesses), neither failure mode can occur and neither has a Rust equivalent.
pub struct TableDescriptor {
    columns: Vec<TableColumn>,
}

impl TableDescriptor {
    /// Mirrors the protected `TableDescriptor()` constructor plus its private
    /// `discoverTableColumns()` helper. `columns` stands in for the reflected `public static final
    /// TableColumn` fields of a concrete subclass, supplied in declaration order; each column's
    /// name and ordinal (0-based, in the order given) are (re)assigned here exactly as
    /// `discoverTableColumns()` would.
    pub fn new(columns: impl IntoIterator<Item = (&'static str, TableColumn)>) -> Self {
        let columns = columns
            .into_iter()
            .enumerate()
            .map(|(ordinal, (name, mut column))| {
                column.set_name(name);
                column.set_ordinal(ordinal as i32);
                column
            })
            .collect();
        Self { columns }
    }

    /// Mirrors `TableDescriptor.getIndexedColumns()`: the ordinal of every indexed column, in
    /// declaration order.
    pub fn get_indexed_columns(&self) -> Vec<i32> {
        self.columns.iter().filter(|column| column.is_indexed()).map(|column| column.column()).collect()
    }

    /// Mirrors `TableDescriptor.getColumnNames()`.
    pub fn get_column_names(&self) -> Vec<String> {
        self.columns.iter().map(|column| column.name().unwrap_or_default().to_string()).collect()
    }

    /// Mirrors `TableDescriptor.getColumnFields()`: a fresh, empty [`Field`] of each column's
    /// storage type, in declaration order.
    pub fn get_column_fields(&self) -> Vec<Field> {
        self.columns.iter().map(|column| new_field_of_same_type(column.get_column_field())).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn schema() -> TableDescriptor {
        TableDescriptor::new([
            ("KEY_COL", TableColumn::with_indexed(Field::Long(None), true)),
            ("NAME_COL", TableColumn::new(Field::String(None))),
            ("VOTE_COUNT_COL", TableColumn::with_indexed(Field::Int(None), true)),
        ])
    }

    /// Java: `discoverTableColumns()` assigns each column's ordinal as its position among the
    /// discovered fields, 0-based, in declaration order.
    #[test]
    fn new_assigns_ordinals_in_declaration_order() {
        let descriptor = schema();
        assert_eq!(descriptor.get_column_names(), vec!["KEY_COL", "NAME_COL", "VOTE_COUNT_COL"]);
    }

    /// Java: `discoverTableColumns()` assigns each column's name from its field's own name.
    #[test]
    fn new_assigns_names_from_declaration() {
        let descriptor = TableDescriptor::new([("ONLY_COL", TableColumn::new(Field::Long(None)))]);
        assert_eq!(descriptor.get_column_names(), vec!["ONLY_COL"]);
    }

    /// Java: names/ordinals are reassigned unconditionally, even overwriting values a caller
    /// already set beforehand.
    #[test]
    fn new_overwrites_a_preexisting_name_and_ordinal() {
        let mut pre_named = TableColumn::new(Field::Long(None));
        pre_named.set_name("STALE_NAME");
        pre_named.set_ordinal(99);
        let descriptor = TableDescriptor::new([("FRESH_NAME", pre_named)]);
        assert_eq!(descriptor.get_column_names(), vec!["FRESH_NAME"]);
        assert_eq!(descriptor.get_indexed_columns(), Vec::<i32>::new());
    }

    /// Java: `getIndexedColumns()` returns only the ordinals of indexed columns, in declaration
    /// order, skipping non-indexed columns entirely.
    #[test]
    fn get_indexed_columns_returns_only_indexed_ordinals() {
        let descriptor = schema();
        assert_eq!(descriptor.get_indexed_columns(), vec![0, 2]);
    }

    #[test]
    fn get_indexed_columns_is_empty_when_no_column_is_indexed() {
        let descriptor = TableDescriptor::new([("PLAIN_COL", TableColumn::new(Field::Long(None)))]);
        assert!(descriptor.get_indexed_columns().is_empty());
    }

    /// Java: `getColumnFields()` returns a fresh `newField()` of each column's storage type -- the
    /// same variant, but with a null/empty value even if the original `TableColumn`'s stored
    /// `Field` somehow carried one.
    #[test]
    fn get_column_fields_returns_empty_fields_of_the_declared_types() {
        let descriptor = schema();
        assert_eq!(
            descriptor.get_column_fields(),
            vec![Field::Long(None), Field::String(None), Field::Int(None)]
        );
    }

    #[test]
    fn get_column_fields_discards_a_preexisting_value() {
        let descriptor =
            TableDescriptor::new([("VALUE_COL", TableColumn::new(Field::Int(Some(42))))]);
        assert_eq!(descriptor.get_column_fields(), vec![Field::Int(None)]);
    }

    #[test]
    fn empty_descriptor_has_no_columns() {
        let descriptor = TableDescriptor::new([]);
        assert!(descriptor.get_column_names().is_empty());
        assert!(descriptor.get_indexed_columns().is_empty());
        assert!(descriptor.get_column_fields().is_empty());
    }
}

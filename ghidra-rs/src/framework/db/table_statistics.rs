/// Table statistics data.
///
/// Port of `db.TableStatistics`, a plain public-field data class with no methods beyond the
/// implicit default constructor. Java's `indexColumn` field defaults to `-1` (all other numeric
/// fields default to `0`, and `name` defaults to `null`); this port mirrors those defaults via
/// [`Default`], using an empty string in place of Java's `null` `name` (Rust has no equivalent of
/// an absent/uninitialized `String`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TableStatistics {
    /// Name of table (same name used by both primary table and related index tables).
    pub name: String,

    /// For index tables, this indicates the indexed column within the primary table. For primary
    /// tables, this value is -1 and does not apply.
    pub index_column: i32,

    /// Total number of table nodes.
    pub buffer_count: i32,

    /// Total size of table.
    pub size: i32,

    /// Total number of interior nodes.
    pub interior_node_cnt: i32,

    /// Total number of leaf/record nodes.
    pub record_node_cnt: i32,

    /// Total number of buffers used within chained DBBuffers for record storage.
    pub chained_buffer_cnt: i32,
}

impl TableStatistics {
    /// Construct a new `TableStatistics` with Java's default field values: `index_column` is
    /// `-1` (indicating a primary, non-index table), all other numeric fields are `0`, and
    /// `name` is an empty string (standing in for Java's default `null`).
    pub fn new() -> Self {
        Self { index_column: -1, ..Default::default() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_defaults_match_java_field_initializers() {
        let stats = TableStatistics::new();
        assert_eq!(stats.name, "");
        assert_eq!(stats.index_column, -1);
        assert_eq!(stats.buffer_count, 0);
        assert_eq!(stats.size, 0);
        assert_eq!(stats.interior_node_cnt, 0);
        assert_eq!(stats.record_node_cnt, 0);
        assert_eq!(stats.chained_buffer_cnt, 0);
    }

    #[test]
    fn test_fields_are_publicly_mutable() {
        let mut stats = TableStatistics::new();
        stats.name = "MyTable".to_string();
        stats.index_column = 2;
        stats.buffer_count = 5;
        stats.size = 1024;
        stats.interior_node_cnt = 3;
        stats.record_node_cnt = 10;
        stats.chained_buffer_cnt = 7;

        assert_eq!(stats.name, "MyTable");
        assert_eq!(stats.index_column, 2);
        assert_eq!(stats.buffer_count, 5);
        assert_eq!(stats.size, 1024);
        assert_eq!(stats.interior_node_cnt, 3);
        assert_eq!(stats.record_node_cnt, 10);
        assert_eq!(stats.chained_buffer_cnt, 7);
    }

    #[test]
    fn test_clone_and_eq() {
        let a = TableStatistics::new();
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn test_bare_default_differs_from_new_index_column() {
        // `#[derive(Default)]` zero-initializes every field, including `index_column` (unlike
        // Java's explicit `= -1` field initializer). `TableStatistics::new()` applies that
        // initializer; the bare `Default::default()` does not. This distinction matters because
        // Java's `TableStatistics` relies on `-1` meaning "not an index table" wherever an
        // instance is constructed via `new TableStatistics()`.
        let bare_default = TableStatistics::default();
        assert_eq!(bare_default.index_column, 0);
        assert_eq!(TableStatistics::new().index_column, -1);
    }
}

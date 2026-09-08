use crate::framework::db::DBRecord;

/// Query interface used to test a record for some condition.
///
/// Port of `ghidra.program.database.util.Query`.
pub trait Query {
    /// Returns true if the given record matches the query's condition.
    fn matches(&self, record: &DBRecord) -> bool;
}

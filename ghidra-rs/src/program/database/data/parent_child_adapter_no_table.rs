//! Port of `ghidra.program.database.data.ParentChildDBAdapterNoTable`.
//!
//! Pre-table version of the adapter for the Parent Child database table, used when the
//! underlying database predates this table's existence.

use std::collections::HashSet;
use std::io;

use crate::framework::db::DBHandle;
use crate::program::database::data::parent_child_adapter::ParentChildAdapter;

/// Pre-table adapter for the Parent Child database table.
///
/// Port of `ghidra.program.database.data.ParentChildDBAdapterNoTable`.
#[derive(Debug, Default)]
pub struct ParentChildDBAdapterNoTable;

impl ParentChildDBAdapterNoTable {
    /// Gets a pre-table version of the adapter for the Parent Child database table.
    ///
    /// `_handle` is the handle to the database which doesn't contain the table (unused: no table
    /// is required).
    pub fn new(_handle: &DBHandle) -> Self {
        ParentChildDBAdapterNoTable
    }
}

impl ParentChildAdapter for ParentChildDBAdapterNoTable {
    fn needs_initializing(&self) -> bool {
        false
    }

    fn create_record(&mut self, _parent_id: i64, _child_id: i64) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "no parent/child table exists",
        ))
    }

    fn remove_record(&mut self, _parent_id: i64, _child_id: i64) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "no parent/child table exists",
        ))
    }

    fn get_child_ids(&self, _parent_id: i64) -> io::Result<HashSet<i64>> {
        Ok(HashSet::new())
    }

    fn get_parent_ids(&self, _child_id: i64) -> io::Result<HashSet<i64>> {
        Ok(HashSet::new())
    }

    fn has_parent(&self, _child_id: i64) -> io::Result<bool> {
        Ok(false)
    }

    fn remove_all_records_for_parent(&mut self, _parent_id: i64) -> io::Result<()> {
        Ok(())
    }

    fn remove_all_records_for_child(&mut self, _child_id: i64) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_remove_record_are_unsupported() {
        let mut adapter = ParentChildDBAdapterNoTable::new(&DBHandle::new().unwrap());
        assert_eq!(
            adapter.create_record(1, 2).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        assert_eq!(
            adapter.remove_record(1, 2).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
    }

    #[test]
    fn lookups_are_always_empty() {
        let adapter = ParentChildDBAdapterNoTable::new(&DBHandle::new().unwrap());
        assert!(adapter.get_child_ids(1).unwrap().is_empty());
        assert!(adapter.get_parent_ids(1).unwrap().is_empty());
        assert!(!adapter.has_parent(1).unwrap());
        assert!(!adapter.needs_initializing());
    }

    #[test]
    fn bulk_removal_stubs_succeed() {
        let mut adapter = ParentChildDBAdapterNoTable::new(&DBHandle::new().unwrap());
        adapter.remove_all_records_for_parent(1).unwrap();
        adapter.remove_all_records_for_child(2).unwrap();
    }

    #[test]
    fn behaves_as_trait_object() {
        let adapter: Box<dyn ParentChildAdapter> =
            Box::new(ParentChildDBAdapterNoTable::new(&DBHandle::new().unwrap()));
        assert!(!adapter.needs_initializing());
    }
}

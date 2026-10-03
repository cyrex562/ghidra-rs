//! Port of `ghidra.program.database.data.CallingConventionDBAdapterNoTable`.
//!
//! Adapter used when no Calling Convention table exists (e.g. a read-only data type manager
//! opened against a database predating this table, with no upgrade requested).

use std::collections::HashSet;
use std::io;

use crate::program::database::data::calling_convention_db_adapter::CallingConventionDBAdapter;

/// Adapter when no Calling Convention table exists.
///
/// Port of `ghidra.program.database.data.CallingConventionDBAdapterNoTable`.
#[derive(Debug, Default)]
pub struct CallingConventionDBAdapterNoTable;

impl CallingConventionDBAdapterNoTable {
    /// Gets a no-table adapter for the calling convention database table.
    pub fn new() -> Self {
        CallingConventionDBAdapterNoTable
    }
}

impl CallingConventionDBAdapter for CallingConventionDBAdapterNoTable {
    fn get_calling_convention_id(
        &mut self,
        _name: Option<&str>,
        _convention_added: &mut dyn FnMut(&str),
    ) -> io::Result<u8> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "no calling convention table exists",
        ))
    }

    fn get_calling_convention_name(&self, _id: u8) -> io::Result<Option<String>> {
        Ok(None)
    }

    fn invalidate_cache(&mut self) {
        // do nothing
    }

    fn get_calling_convention_names(&self) -> io::Result<HashSet<String>> {
        Ok(HashSet::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_calling_convention_id_is_unsupported() {
        let mut adapter = CallingConventionDBAdapterNoTable::new();
        let err = adapter
            .get_calling_convention_id(Some("__stdcall"), &mut |_| {
                panic!("should not be called")
            })
            .expect_err("no-table adapter must not assign new calling convention ids");
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn get_calling_convention_name_is_always_none() {
        let adapter = CallingConventionDBAdapterNoTable::new();
        assert_eq!(adapter.get_calling_convention_name(0).unwrap(), None);
        assert_eq!(adapter.get_calling_convention_name(5).unwrap(), None);
    }

    #[test]
    fn get_calling_convention_names_is_empty() {
        let adapter = CallingConventionDBAdapterNoTable::new();
        assert!(adapter.get_calling_convention_names().unwrap().is_empty());
    }

    #[test]
    fn invalidate_cache_is_a_no_op() {
        let mut adapter = CallingConventionDBAdapterNoTable::new();
        adapter.invalidate_cache();
    }

    #[test]
    fn behaves_as_trait_object() {
        let adapter: Box<dyn CallingConventionDBAdapter> =
            Box::new(CallingConventionDBAdapterNoTable::new());
        assert_eq!(adapter.get_calling_convention_name(1).unwrap(), None);
    }
}

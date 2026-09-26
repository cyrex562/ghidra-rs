//! Port of `ghidra.program.database.module.FragmentDBAdapterV0`.
//!
//! Version 0 (current, and so far only) implementation for accessing a program tree's Fragment
//! database table, backed by a live, writable [`Table`]. One table exists per program tree, named
//! via [`get_table_name`].
//!
//! `create_fragment_record` mirrors Java's odd `long key = fragmentTable.getKey(); if (key == 0)
//! key = 1;` quirk: the table's peeked next key is used directly, except that key `0` is skipped
//! in favor of `1` (key `0` is reserved elsewhere, e.g. for the tree's root module). This is
//! preserved rather than "fixed" since it matches observed Java behavior.

use std::io;
use std::sync::{Arc, RwLock};

use crate::framework::db::{DBHandle, DBRecord, Field, FieldType, Schema, Table};
use crate::program::database::module::fragment_db_adapter::{
    get_table_name, FragmentDBAdapter, FRAGMENT_COMMENTS_COL, FRAGMENT_NAME_COL,
};
use crate::util::exception::VersionException;

fn schema() -> Arc<Schema> {
    Arc::new(Schema::new(
        0,
        FieldType::Long,
        "Key".to_string(),
        vec![FieldType::String, FieldType::String],
        vec!["Name".to_string(), "Comments".to_string()],
        vec![],
    ))
}

/// Version 0 (current) implementation for accessing a program tree's Fragment database table.
///
/// Port of `ghidra.program.database.module.FragmentDBAdapterV0`.
pub struct FragmentDBAdapterV0 {
    table: Arc<RwLock<Table>>,
}

impl FragmentDBAdapterV0 {
    /// Schema version implemented by this adapter.
    pub const VERSION: i32 = 0;

    /// Gets a version 0 adapter for the program tree fragment database table.
    ///
    /// If `create` is true, the table is created; otherwise an existing table is opened.
    pub fn new(
        handle: &mut DBHandle,
        create: bool,
        tree_id: i64,
    ) -> Result<Self, VersionException> {
        let table_name = get_table_name(tree_id);
        let table = if create {
            handle
                .create_table(table_name, schema())
                .map_err(|e| VersionException::with_message(e.to_string()))?
        } else {
            let table = handle.get_table(&table_name).ok_or_else(|| {
                VersionException::with_message(format!("Missing Table: {table_name}"))
            })?;
            let version = table.read().unwrap().get_schema().get_version();
            if version != Self::VERSION {
                return Err(VersionException::with_upgradeable(false));
            }
            table
        };
        Ok(FragmentDBAdapterV0 { table })
    }
}

impl FragmentDBAdapter for FragmentDBAdapterV0 {
    fn create_fragment_record(
        &mut self,
        _parent_module_id: i64,
        name: &str,
    ) -> io::Result<DBRecord> {
        let mut table = self.table.write().unwrap();
        let mut key = table.peek_next_key();
        if key == 0 {
            key = 1;
        }
        let mut record = DBRecord::new(schema(), Field::Long(Some(key)));
        record.set_field(FRAGMENT_NAME_COL, Field::String(Some(name.to_string())));
        table.put_record(record.clone())?;
        table.ensure_next_key_at_least(key);
        Ok(record)
    }

    fn get_fragment_record(&self, key: i64) -> io::Result<Option<DBRecord>> {
        self.table
            .read()
            .unwrap()
            .get_record(&Field::Long(Some(key)))
    }

    fn get_fragment_record_by_name(&self, name: &str) -> io::Result<Option<DBRecord>> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut found: Option<DBRecord> = None;
        let mut count = 0;
        while let Some(rec) = iter.next()? {
            if matches!(rec.get_field(FRAGMENT_NAME_COL), Field::String(Some(v)) if v == name) {
                count += 1;
                if found.is_none() {
                    found = Some(rec);
                }
            }
        }
        if count > 1 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Found {count} fragments named {name}"),
            ));
        }
        Ok(found)
    }

    fn update_fragment_record(&mut self, record: &DBRecord) -> io::Result<()> {
        self.table.write().unwrap().put_record(record.clone())
    }

    fn remove_fragment_record(&mut self, child_id: i64) -> io::Result<bool> {
        self.table
            .write()
            .unwrap()
            .delete_record(&Field::Long(Some(child_id)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_handle() -> DBHandle {
        DBHandle::new().unwrap()
    }

    #[test]
    fn missing_table_without_create_is_an_error() {
        let mut handle = make_handle();
        assert!(FragmentDBAdapterV0::new(&mut handle, false, 0).is_err());
    }

    #[test]
    fn create_fragment_record_skips_key_zero() {
        let mut handle = make_handle();
        let mut adapter = FragmentDBAdapterV0::new(&mut handle, true, 0).unwrap();

        let rec = adapter.create_fragment_record(0, ".text").unwrap();
        assert_eq!(rec.get_key(), &Field::Long(Some(1)));

        let rec2 = adapter.create_fragment_record(0, ".data").unwrap();
        assert_eq!(rec2.get_key(), &Field::Long(Some(2)));
    }

    #[test]
    fn get_fragment_record_by_key_and_name() {
        let mut handle = make_handle();
        let mut adapter = FragmentDBAdapterV0::new(&mut handle, true, 0).unwrap();
        let rec = adapter.create_fragment_record(0, ".text").unwrap();
        let key = match rec.get_key() {
            Field::Long(Some(v)) => *v,
            _ => panic!("expected long key"),
        };

        assert!(adapter.get_fragment_record(key).unwrap().is_some());
        assert!(adapter.get_fragment_record(999).unwrap().is_none());
        assert!(adapter
            .get_fragment_record_by_name(".text")
            .unwrap()
            .is_some());
        assert!(adapter
            .get_fragment_record_by_name(".missing")
            .unwrap()
            .is_none());
    }

    #[test]
    fn get_fragment_record_by_name_errors_on_duplicates() {
        let mut handle = make_handle();
        let mut adapter = FragmentDBAdapterV0::new(&mut handle, true, 0).unwrap();
        adapter.create_fragment_record(0, "dup").unwrap();
        adapter.create_fragment_record(0, "dup").unwrap();

        assert!(adapter.get_fragment_record_by_name("dup").is_err());
    }

    #[test]
    fn update_and_remove_fragment_record() {
        let mut handle = make_handle();
        let mut adapter = FragmentDBAdapterV0::new(&mut handle, true, 0).unwrap();
        let mut rec = adapter.create_fragment_record(0, ".text").unwrap();
        let key = match rec.get_key() {
            Field::Long(Some(v)) => *v,
            _ => panic!("expected long key"),
        };

        rec.set_string(FRAGMENT_COMMENTS_COL, Some("a comment".to_string()));
        adapter.update_fragment_record(&rec).unwrap();
        let fetched = adapter.get_fragment_record(key).unwrap().unwrap();
        assert_eq!(
            fetched.get_field(FRAGMENT_COMMENTS_COL),
            &Field::String(Some("a comment".to_string()))
        );

        assert!(adapter.remove_fragment_record(key).unwrap());
        assert!(adapter.get_fragment_record(key).unwrap().is_none());
        assert!(!adapter.remove_fragment_record(key).unwrap());
    }

    #[test]
    fn per_tree_table_names_do_not_collide() {
        let mut handle = make_handle();
        let mut a0 = FragmentDBAdapterV0::new(&mut handle, true, 0).unwrap();
        let mut a1 = FragmentDBAdapterV0::new(&mut handle, true, 1).unwrap();
        a0.create_fragment_record(0, "only-in-tree-0").unwrap();
        assert!(a1
            .get_fragment_record_by_name("only-in-tree-0")
            .unwrap()
            .is_none());
        a1.create_fragment_record(0, "only-in-tree-1").unwrap();
        assert!(a0
            .get_fragment_record_by_name("only-in-tree-1")
            .unwrap()
            .is_none());
    }

    #[test]
    fn behaves_as_trait_object() {
        let mut handle = make_handle();
        let adapter: Box<dyn FragmentDBAdapter> =
            Box::new(FragmentDBAdapterV0::new(&mut handle, true, 0).unwrap());
        assert!(adapter.get_fragment_record(1).unwrap().is_none());
    }
}

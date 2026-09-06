//! Port of `ghidra.program.database.data.CategoryDBAdapterV0`.
//!
//! Version 0 (current, and so far only) implementation for accessing the Category database
//! table, backed by a live, writable [`Table`]. The root category always occupies key `0`
//! (reserved: [`create_category`](CategoryDBAdapter::create_category) skips it), with parent ID
//! `-1`; seeding that root record is the caller's responsibility (mirroring the Java adapter,
//! which does not seed it in its constructor either), typically via
//! [`update_record`](CategoryDBAdapter::update_record).

use std::io;
use std::sync::{Arc, RwLock};

use crate::framework::db::{DBHandle, DBRecord, Field, FieldType, Schema, Table};
use crate::program::database::data::category_db_adapter::{
    CategoryDBAdapter, CATEGORY_NAME_COL, CATEGORY_PARENT_COL,
};
use crate::util::exception::VersionException;

/// Name of the database table used to store category records.
pub const CATEGORY_TABLE_NAME: &str = "Categories";

/// Schema version implemented by the current (and, so far, only) `CategoryDBAdapterV0` table
/// layout.
pub const CURRENT_VERSION: i32 = 0;

/// Build the category table schema, as defined by `CategoryDBAdapterV0.V0_SCHEMA`. Exposed as a
/// function (rather than a `Schema` constant) since `Schema` construction is not `const`.
pub fn schema() -> Arc<Schema> {
    Arc::new(Schema::new(
        CURRENT_VERSION,
        FieldType::Long,
        "Category ID".to_string(),
        vec![FieldType::String, FieldType::Long],
        vec!["Name".to_string(), "Parent ID".to_string()],
        vec![],
    ))
}

/// Version 0 (current) implementation for accessing the Category database table.
///
/// Port of `ghidra.program.database.data.CategoryDBAdapterV0`.
pub struct CategoryDBAdapterV0 {
    table: Arc<RwLock<Table>>,
}

impl CategoryDBAdapterV0 {
    /// Schema version implemented by this adapter.
    pub const VERSION: i32 = CURRENT_VERSION;

    /// Gets a version 0 adapter for the Category database table.
    ///
    /// `table_prefix` is the prefix to be used with the default table name; if `create` is
    /// `true`, the table is created, otherwise an existing table is opened.
    pub fn new(
        handle: &mut DBHandle,
        table_prefix: &str,
        create: bool,
    ) -> Result<Self, VersionException> {
        let table_name = format!("{table_prefix}{CATEGORY_TABLE_NAME}");
        let table = if create {
            handle
                .create_table(table_name, schema())
                .map_err(|e| VersionException::with_message(e.to_string()))?
        } else {
            let table = handle.get_table(&table_name).ok_or_else(|| {
                VersionException::with_message(format!("Missing Table: {table_name}"))
            })?;
            if table.read().unwrap().get_schema().get_version() != Self::VERSION {
                return Err(VersionException::with_upgradeable(false));
            }
            table
        };
        Ok(CategoryDBAdapterV0 { table })
    }
}

impl CategoryDBAdapter for CategoryDBAdapterV0 {
    fn get_record(&self, category_id: i64) -> io::Result<Option<DBRecord>> {
        self.table
            .read()
            .unwrap()
            .get_record(&Field::Long(Some(category_id)))
    }

    fn update_record(
        &mut self,
        category_id: i64,
        parent_category_id: i64,
        name: &str,
    ) -> io::Result<()> {
        let mut rec = DBRecord::new(schema(), Field::Long(Some(category_id)));
        rec.set_field(CATEGORY_NAME_COL, Field::String(Some(name.to_string())));
        rec.set_field(CATEGORY_PARENT_COL, Field::Long(Some(parent_category_id)));
        self.table.write().unwrap().put_record(rec)
    }

    fn get_record_ids_with_parent(&self, category_id: i64) -> io::Result<Vec<Field>> {
        // The Java adapter uses an indexed lookup (`table.findRecords`) on this column; this
        // port's `Table` has no secondary-index support, so this scans linearly instead. Same
        // observable result, just O(n) rather than indexed.
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut ids = Vec::new();
        while let Some(rec) = iter.next()? {
            if matches!(rec.get_field(CATEGORY_PARENT_COL), Field::Long(Some(v)) if *v == category_id)
            {
                ids.push(rec.get_key().clone());
            }
        }
        Ok(ids)
    }

    fn create_category(&mut self, name: &str, parent_id: i64) -> io::Result<DBRecord> {
        let mut table = self.table.write().unwrap();
        let mut key = table.get_next_key();
        if key == 0 {
            // Key 0 is reserved for the root category.
            key = 1;
        }
        table.ensure_next_key_at_least(key);
        let mut rec = DBRecord::new(schema(), Field::Long(Some(key)));
        rec.set_field(CATEGORY_NAME_COL, Field::String(Some(name.to_string())));
        rec.set_field(CATEGORY_PARENT_COL, Field::Long(Some(parent_id)));
        table.put_record(rec.clone())?;
        Ok(rec)
    }

    fn remove_category(&mut self, category_id: i64) -> io::Result<bool> {
        self.table
            .write()
            .unwrap()
            .delete_record(&Field::Long(Some(category_id)))
    }

    fn get_root_record(&self) -> io::Result<DBRecord> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut found = Vec::new();
        while let Some(rec) = iter.next()? {
            if matches!(rec.get_field(CATEGORY_PARENT_COL), Field::Long(Some(-1))) {
                found.push(rec);
            }
        }
        if found.len() != 1 {
            return Err(io::Error::other(format!(
                "Found {} entries for root category",
                found.len()
            )));
        }
        Ok(found.remove(0))
    }

    fn put_record(&mut self, record: &DBRecord) -> io::Result<()> {
        self.table.write().unwrap().put_record(record.clone())
    }

    fn get_record_count(&self) -> i32 {
        self.table.read().unwrap().get_record_count() as i32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn adapter_with_root(handle: &mut DBHandle) -> CategoryDBAdapterV0 {
        let mut adapter = CategoryDBAdapterV0::new(handle, "", true).unwrap();
        adapter.update_record(0, -1, "").unwrap();
        adapter
    }

    #[test]
    fn opening_missing_table_without_create_is_an_error() {
        let mut handle = DBHandle::new().unwrap();
        assert!(CategoryDBAdapterV0::new(&mut handle, "", false).is_err());
    }

    #[test]
    fn get_root_record_requires_exactly_one_seeded_root() {
        let mut handle = DBHandle::new().unwrap();
        let adapter = CategoryDBAdapterV0::new(&mut handle, "", true).unwrap();
        // No root seeded yet: an error, matching the Java "Found 0 entries" case.
        assert!(adapter.get_root_record().is_err());
    }

    #[test]
    fn create_table_and_round_trip_records() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = adapter_with_root(&mut handle);

        let root = adapter.get_root_record().unwrap();
        assert_eq!(root.get_key(), &Field::Long(Some(0)));

        let child = adapter.create_category("child1", 0).unwrap();
        assert_eq!(child.get_key(), &Field::Long(Some(1)));
        assert_eq!(adapter.get_record_count(), 2);

        let fetched = adapter.get_record(1).unwrap().expect("record should exist");
        assert_eq!(
            fetched.get_field(CATEGORY_NAME_COL),
            &Field::String(Some("child1".to_string()))
        );
    }

    #[test]
    fn get_record_ids_with_parent_filters_by_parent() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = adapter_with_root(&mut handle);
        adapter.create_category("a", 0).unwrap();
        adapter.create_category("b", 0).unwrap();

        let children = adapter.get_record_ids_with_parent(0).unwrap();
        assert_eq!(children.len(), 2);
    }

    #[test]
    fn update_and_remove_record() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = adapter_with_root(&mut handle);
        let child = adapter.create_category("a", 0).unwrap();
        let key = child.get_key().get_long_value();

        adapter.update_record(key, 0, "renamed").unwrap();
        let renamed = adapter.get_record(key).unwrap().unwrap();
        assert_eq!(
            renamed.get_field(CATEGORY_NAME_COL),
            &Field::String(Some("renamed".to_string()))
        );

        let removed = adapter.remove_category(key).unwrap();
        assert!(removed);
        assert!(adapter.get_record(key).unwrap().is_none());
    }

    #[test]
    fn opening_an_existing_table_reuses_records() {
        let mut handle = DBHandle::new().unwrap();
        {
            let mut adapter = adapter_with_root(&mut handle);
            adapter.create_category("a", 0).unwrap();
        }
        let adapter = CategoryDBAdapterV0::new(&mut handle, "", false).unwrap();
        assert_eq!(adapter.get_record_count(), 2);
    }

    #[test]
    fn behaves_as_trait_object() {
        let mut handle = DBHandle::new().unwrap();
        let adapter: Box<dyn CategoryDBAdapter> = Box::new(adapter_with_root(&mut handle));
        assert_eq!(adapter.get_record_count(), 1);
    }
}

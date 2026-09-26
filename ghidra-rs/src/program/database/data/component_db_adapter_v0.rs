//! Port of `ghidra.program.database.data.ComponentDBAdapterV0`.
//!
//! Version 0 (current, and so far only) implementation for accessing the Component database
//! table, backed by a live, writable [`Table`].
//!
//! The Java `createRecord` computes its key via `DataTypeManagerDB.createKey(COMPONENT,
//! componentTable.getKey())`, tagging the raw table key with a datatype-kind bit pattern. That
//! key-tagging scheme is a `DataTypeManagerDB`-wide invariant (not specific to this table) and
//! `DataTypeManagerDB` has not been ported with that scheme yet, so this port uses the table's
//! own next-key sequence directly instead (same deviation as `PointerDBAdapterV2`).

use std::io;
use std::sync::{Arc, RwLock};

use crate::framework::db::{DBHandle, DBRecord, Field, Table};
use crate::program::database::data::component_db_adapter::{
    ComponentDBAdapter, COMPONENT_COMMENT_COL, COMPONENT_DT_ID_COL, COMPONENT_FIELD_NAME_COL,
    COMPONENT_OFFSET_COL, COMPONENT_ORDINAL_COL, COMPONENT_PARENT_ID_COL, COMPONENT_SIZE_COL,
};
use crate::program::model::data::internal_data_type_component::cleanup_field_name;
use crate::util::exception::VersionException;

/// Name of the database table used to store composite data type components.
pub const COMPONENT_TABLE_NAME: &str = "Components";

/// Schema version implemented by the current (and, so far, only) `ComponentDBAdapterV0` table
/// layout.
pub const CURRENT_VERSION: i32 = 0;

/// Build the component table schema, as defined by `ComponentDBAdapterV0.V0_COMPONENT_SCHEMA`
/// (aliased as `ComponentDBAdapter.COMPONENT_SCHEMA`). Exposed as a function (rather than a
/// `Schema` constant) since `Schema` construction is not `const`.
pub fn schema() -> Arc<crate::framework::db::Schema> {
    use crate::framework::db::{FieldType, Schema};
    Arc::new(Schema::new(
        CURRENT_VERSION,
        FieldType::Long,
        "Data Type ID".to_string(),
        vec![
            FieldType::Long,
            FieldType::Int,
            FieldType::Long,
            FieldType::String,
            FieldType::String,
            FieldType::Int,
            FieldType::Int,
        ],
        vec![
            "Parent".to_string(),
            "Offset".to_string(),
            "Data Type ID".to_string(),
            "Field Name".to_string(),
            "Comment".to_string(),
            "Component Size".to_string(),
            "Ordinal".to_string(),
        ],
        vec![],
    ))
}

/// Version 0 (current) implementation for accessing the Component database table.
///
/// Port of `ghidra.program.database.data.ComponentDBAdapterV0`.
pub struct ComponentDBAdapterV0 {
    component_table: Arc<RwLock<Table>>,
}

impl ComponentDBAdapterV0 {
    /// Schema version implemented by this adapter.
    pub const VERSION: i32 = CURRENT_VERSION;

    /// Gets a version 0 adapter for the Component database table.
    ///
    /// `table_prefix` is the prefix to be used with the default table name; if `create` is
    /// `true`, the table is created, otherwise an existing table is opened.
    pub fn new(
        handle: &mut DBHandle,
        table_prefix: &str,
        create: bool,
    ) -> Result<Self, VersionException> {
        let table_name = format!("{table_prefix}{COMPONENT_TABLE_NAME}");
        let component_table = if create {
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
        Ok(ComponentDBAdapterV0 { component_table })
    }
}

impl ComponentDBAdapter for ComponentDBAdapterV0 {
    fn create_record(
        &mut self,
        data_type_id: i64,
        parent_id: i64,
        length: i32,
        ordinal: i32,
        offset: i32,
        field_name: Option<&str>,
        comment: Option<&str>,
    ) -> io::Result<DBRecord> {
        let comment = comment.filter(|s| !s.trim().is_empty());
        let field_name = cleanup_field_name(field_name);

        let mut table = self.component_table.write().unwrap();
        let key = table.get_next_key();
        let mut record = DBRecord::new(schema(), Field::Long(Some(key)));
        record.set_field(COMPONENT_PARENT_ID_COL, Field::Long(Some(parent_id)));
        record.set_field(COMPONENT_OFFSET_COL, Field::Int(Some(offset)));
        record.set_field(COMPONENT_DT_ID_COL, Field::Long(Some(data_type_id)));
        record.set_field(COMPONENT_FIELD_NAME_COL, Field::String(field_name));
        record.set_field(
            COMPONENT_COMMENT_COL,
            Field::String(comment.map(str::to_string)),
        );
        record.set_field(COMPONENT_SIZE_COL, Field::Int(Some(length)));
        record.set_field(COMPONENT_ORDINAL_COL, Field::Int(Some(ordinal)));
        table.put_record(record.clone())?;
        Ok(record)
    }

    fn get_record(&self, component_id: i64) -> io::Result<Option<DBRecord>> {
        self.component_table
            .read()
            .unwrap()
            .get_record(&Field::Long(Some(component_id)))
    }

    fn remove_record(&mut self, component_id: i64) -> io::Result<bool> {
        self.component_table
            .write()
            .unwrap()
            .delete_record(&Field::Long(Some(component_id)))
    }

    fn update_record(&mut self, record: &DBRecord) -> io::Result<()> {
        self.component_table
            .write()
            .unwrap()
            .put_record(record.clone())
    }

    fn get_component_ids_in_composite(&self, composite_id: i64) -> io::Result<Vec<Field>> {
        // The Java adapter uses an indexed lookup (`table.findRecords`) on this column; this
        // port's `Table` has no secondary-index support, so this scans linearly instead. Same
        // observable result, just O(n) rather than indexed.
        let table = self.component_table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut ids = Vec::new();
        while let Some(rec) = iter.next()? {
            if matches!(rec.get_field(COMPONENT_PARENT_ID_COL), Field::Long(Some(v)) if *v == composite_id)
            {
                ids.push(rec.get_key().clone());
            }
        }
        Ok(ids)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_table_and_round_trip_record() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = ComponentDBAdapterV0::new(&mut handle, "", true).unwrap();

        let rec = adapter
            .create_record(42, 7, 4, 0, 0, Some("  field 0  "), Some("   "))
            .unwrap();
        assert_eq!(
            rec.get_field(COMPONENT_FIELD_NAME_COL),
            &Field::String(Some("field_0".to_string()))
        );
        // A blank comment is normalized to None, matching StringUtils.isBlank(comment).
        assert_eq!(rec.get_field(COMPONENT_COMMENT_COL), &Field::String(None));

        let fetched = adapter
            .get_record(rec.get_key().get_long_value())
            .unwrap()
            .expect("record should exist");
        assert_eq!(fetched.get_field(COMPONENT_DT_ID_COL), &Field::Long(Some(42)));
    }

    #[test]
    fn opening_an_existing_table_reuses_records() {
        let mut handle = DBHandle::new().unwrap();
        {
            let mut adapter = ComponentDBAdapterV0::new(&mut handle, "", true).unwrap();
            adapter.create_record(1, 1, 4, 0, 0, None, None).unwrap();
        }
        let adapter = ComponentDBAdapterV0::new(&mut handle, "", false).unwrap();
        assert!(adapter.get_component_ids_in_composite(1).unwrap().len() == 1);
    }

    #[test]
    fn opening_missing_table_without_create_is_an_error() {
        let mut handle = DBHandle::new().unwrap();
        assert!(ComponentDBAdapterV0::new(&mut handle, "", false).is_err());
    }

    #[test]
    fn update_and_remove_record() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = ComponentDBAdapterV0::new(&mut handle, "", true).unwrap();
        let mut rec = adapter.create_record(1, 1, 4, 0, 0, None, None).unwrap();

        rec.set_field(COMPONENT_SIZE_COL, Field::Int(Some(8)));
        adapter.update_record(&rec).unwrap();
        let refetched = adapter
            .get_record(rec.get_key().get_long_value())
            .unwrap()
            .unwrap();
        assert_eq!(refetched.get_field(COMPONENT_SIZE_COL), &Field::Int(Some(8)));

        let removed = adapter.remove_record(rec.get_key().get_long_value()).unwrap();
        assert!(removed);
        assert!(adapter
            .get_record(rec.get_key().get_long_value())
            .unwrap()
            .is_none());
    }

    #[test]
    fn get_component_ids_in_composite_filters_by_parent() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = ComponentDBAdapterV0::new(&mut handle, "", true).unwrap();
        adapter.create_record(1, 7, 4, 0, 0, None, None).unwrap();
        adapter.create_record(2, 7, 4, 1, 4, None, None).unwrap();
        adapter.create_record(3, 8, 4, 0, 0, None, None).unwrap();

        assert_eq!(adapter.get_component_ids_in_composite(7).unwrap().len(), 2);
        assert_eq!(adapter.get_component_ids_in_composite(8).unwrap().len(), 1);
    }

    #[test]
    fn behaves_as_trait_object() {
        let mut handle = DBHandle::new().unwrap();
        let adapter: Box<dyn ComponentDBAdapter> =
            Box::new(ComponentDBAdapterV0::new(&mut handle, "", true).unwrap());
        assert!(adapter.get_component_ids_in_composite(0).unwrap().is_empty());
    }
}

//! Port of `ghidra.program.database.data.FunctionDefinitionDBAdapterV1`.
//!
//! Version 1 (read-only) implementation for accessing the Function Signature Definition
//! database table. This version's on-disk records have no dedicated Call Conv ID column;
//! instead, bits 1..4 of the Flags column hold an old `GenericCallingConvention` ordinal.
//! [`translate_record`] extracts that ordinal, clears those flag bits, and resolves a current
//! Call Conv ID from it:
//!
//! - If no calling-convention adapter was supplied (typical read-only use), the raw generic
//!   ordinal is reused directly as the Call Conv ID (matching Java's `usesGenericCallingConventionId()
//!   == true` path) -- callers must consult [`FunctionDefinitionDBAdapter::uses_generic_calling_convention_id`]
//!   and [`get_generic_calling_convention_name`] to interpret it correctly.
//! - If a calling-convention adapter *was* supplied (the upgrade path), the generic ordinal is
//!   resolved to a name via [`get_generic_calling_convention_name`] and then to a real Call Conv
//!   ID via that adapter, registering a new convention if needed. Any I/O error along this path
//!   is swallowed and the unknown convention ID is used instead, matching Java's
//!   `catch (IOException e) { /* ignore */ }`.
//!
//! [`translate_record`]: RecordTranslator::translate_record
//! [`get_generic_calling_convention_name`]: super::function_definition_db_adapter::get_generic_calling_convention_name
//!
//! `translate_record` takes `&self` (per [`RecordTranslator`]), but resolving a calling
//! convention ID through the optional adapter requires `&mut` access to it; the adapter is
//! therefore held behind a `RefCell`.
//!
//! Also unlike every other read-only V0/V1 adapter in this porting batch,
//! [`get_record_with_ids`](FunctionDefinitionDBAdapter::get_record_with_ids) here returns the
//! **raw, untranslated** V1-schema record on a match rather than calling `translate_record` --
//! this matches Java's `FunctionDefinitionDBAdapterV1.getRecordWithIDs`, which does `return
//! record;` instead of `return translateRecord(record);`. That looks like a latent bug in the
//! original (the returned record's column layout won't line up with the current schema's column
//! constants), but this port mirrors the observed behavior rather than "fixing" it.

use std::cell::RefCell;
use std::io;
use std::sync::{Arc, RwLock};

use crate::framework::db::{DBHandle, DBRecord, Field, RecordIterator, RecordTranslator, Table};
use crate::program::database::data::calling_convention_db_adapter::{
    CallingConventionDBAdapter, UNKNOWN_CALLING_CONVENTION_ID,
};
use crate::program::database::data::function_definition_db_adapter::{
    self, get_generic_calling_convention_name, FunctionDefinitionDBAdapter,
    FUNCTION_DEF_CALLCONV_COL, FUNCTION_DEF_CAT_ID_COL, FUNCTION_DEF_COMMENT_COL,
    FUNCTION_DEF_FLAGS_COL, FUNCTION_DEF_LAST_CHANGE_TIME_COL, FUNCTION_DEF_NAME_COL,
    FUNCTION_DEF_RETURN_ID_COL, FUNCTION_DEF_SOURCE_ARCHIVE_ID_COL, FUNCTION_DEF_SOURCE_DT_ID_COL,
    FUNCTION_DEF_SOURCE_SYNC_TIME_COL, FUNCTION_DEF_TABLE_NAME,
};
use crate::program::model::data::data_type::{NO_LAST_CHANGE_TIME, NO_SOURCE_SYNC_TIME};
use crate::program::model::data::data_type_manager::LOCAL_ARCHIVE_KEY;
use crate::program::util::DBRecordAdapter;
use crate::util::exception::VersionException;
use crate::util::universal_id_generator::next_id;
use crate::util::UniversalID;

/// Column index of the function definition's name, as defined by `FunctionDefinitionDBAdapterV1`.
pub const V1_FUNCTION_DEF_NAME_COL: usize = 0;

/// Column index of the function definition's comment, as defined by
/// `FunctionDefinitionDBAdapterV1`.
pub const V1_FUNCTION_DEF_COMMENT_COL: usize = 1;

/// Column index of the function definition's category ID, as defined by
/// `FunctionDefinitionDBAdapterV1`.
pub const V1_FUNCTION_DEF_CAT_ID_COL: usize = 2;

/// Column index of the function definition's return data type ID, as defined by
/// `FunctionDefinitionDBAdapterV1`.
pub const V1_FUNCTION_DEF_RETURN_ID_COL: usize = 3;

/// Column index of the function definition's flags (which also carry the old generic calling
/// convention ordinal in bits 1..4), as defined by `FunctionDefinitionDBAdapterV1`.
pub const V1_FUNCTION_DEF_FLAGS_COL: usize = 4;

/// Column index of the function definition's source archive ID, as defined by
/// `FunctionDefinitionDBAdapterV1`.
pub const V1_FUNCTION_DEF_SOURCE_ARCHIVE_ID_COL: usize = 5;

/// Column index of the function definition's universal data type ID, as defined by
/// `FunctionDefinitionDBAdapterV1`.
pub const V1_FUNCTION_DEF_UNIVERSAL_DT_ID_COL: usize = 6;

/// Column index of the function definition's source sync time, as defined by
/// `FunctionDefinitionDBAdapterV1`.
pub const V1_FUNCTION_DEF_SOURCE_SYNC_TIME_COL: usize = 7;

/// Column index of the function definition's last change time, as defined by
/// `FunctionDefinitionDBAdapterV1`.
pub const V1_FUNCTION_DEF_LAST_CHANGE_TIME_COL: usize = 8;

/// Mask (pre-shift) for the 4 generic-calling-convention-ordinal bits packed into the Flags
/// column.
const GENERIC_CALLING_CONVENTION_FLAG_MASK: u8 = 0xf;

/// Bit position of the generic-calling-convention-ordinal field within the Flags column.
const GENERIC_CALLING_CONVENTION_FLAG_SHIFT: u32 = 1;

/// A `RecordIterator` over an eagerly-collected, already-translated set of records.
struct VecRecordIterator {
    records: std::vec::IntoIter<DBRecord>,
}

impl RecordIterator for VecRecordIterator {
    fn next(&mut self) -> io::Result<Option<DBRecord>> {
        Ok(self.records.next())
    }

    fn has_next(&self) -> bool {
        self.records.len() > 0
    }
}

/// Version 1 (read-only) implementation for accessing the Function Signature Definition
/// database table.
///
/// Port of `ghidra.program.database.data.FunctionDefinitionDBAdapterV1`.
pub struct FunctionDefinitionDBAdapterV1 {
    table: Arc<RwLock<Table>>,
    /// Calling convention table adapter suitable for adding new conventions (used during an
    /// upgrade operation). `None` if not performing an upgrade, in which case calling
    /// convention IDs reflect raw generic convention ordinals. Held behind a `RefCell` since
    /// [`RecordTranslator::translate_record`] takes `&self` but resolving a convention name to
    /// an ID requires `&mut` access to this adapter.
    call_conv_adapter: RefCell<Option<Box<dyn CallingConventionDBAdapter>>>,
}

impl FunctionDefinitionDBAdapterV1 {
    /// Schema version implemented by this adapter.
    pub const VERSION: i32 = 1;

    /// Gets a version 1 read-only adapter for the Function Definition database table.
    ///
    /// `call_conv_adapter` should be `None` if not performing an upgrade, in which case calling
    /// convention IDs will reflect generic convention ordinals.
    pub fn new(
        handle: &DBHandle,
        table_prefix: &str,
        call_conv_adapter: Option<Box<dyn CallingConventionDBAdapter>>,
    ) -> Result<Self, VersionException> {
        let table_name = format!("{table_prefix}{FUNCTION_DEF_TABLE_NAME}");
        let table = handle
            .get_table(&table_name)
            .ok_or_else(|| VersionException::with_upgradeable(true))?;
        let version = table.read().unwrap().get_schema().get_version();
        if version != Self::VERSION {
            return Err(VersionException::with_upgradeable(version < Self::VERSION));
        }
        Ok(FunctionDefinitionDBAdapterV1 {
            table,
            call_conv_adapter: RefCell::new(call_conv_adapter),
        })
    }
}

impl RecordTranslator for FunctionDefinitionDBAdapterV1 {
    fn translate_record(&self, old_record: DBRecord) -> io::Result<DBRecord> {
        let mut rec = DBRecord::new(
            function_definition_db_adapter::schema(),
            old_record.get_key().clone(),
        );
        rec.set_field(
            FUNCTION_DEF_NAME_COL,
            old_record.get_field(V1_FUNCTION_DEF_NAME_COL).clone(),
        );
        rec.set_field(
            FUNCTION_DEF_COMMENT_COL,
            old_record.get_field(V1_FUNCTION_DEF_COMMENT_COL).clone(),
        );
        rec.set_field(
            FUNCTION_DEF_CAT_ID_COL,
            old_record.get_field(V1_FUNCTION_DEF_CAT_ID_COL).clone(),
        );
        rec.set_field(
            FUNCTION_DEF_RETURN_ID_COL,
            old_record.get_field(V1_FUNCTION_DEF_RETURN_ID_COL).clone(),
        );

        let raw_flags = match old_record.get_field(V1_FUNCTION_DEF_FLAGS_COL) {
            Field::Byte(Some(v)) => *v as u8,
            _ => 0,
        };
        let mask = GENERIC_CALLING_CONVENTION_FLAG_MASK << GENERIC_CALLING_CONVENTION_FLAG_SHIFT;
        let generic_call_conv_id = (raw_flags & mask) >> GENERIC_CALLING_CONVENTION_FLAG_SHIFT;
        let flags = raw_flags & !mask;

        let mut call_conv_adapter = self.call_conv_adapter.borrow_mut();
        let calling_convention_id = match call_conv_adapter.as_mut() {
            None => generic_call_conv_id,
            Some(adapter) => {
                let name = get_generic_calling_convention_name(generic_call_conv_id as i32);
                adapter
                    .get_calling_convention_id(Some(&name), &mut |_| {})
                    .unwrap_or(UNKNOWN_CALLING_CONVENTION_ID)
            }
        };

        rec.set_field(FUNCTION_DEF_FLAGS_COL, Field::Byte(Some(flags as i8)));
        rec.set_field(
            FUNCTION_DEF_CALLCONV_COL,
            Field::Byte(Some(calling_convention_id as i8)),
        );
        rec.set_field(
            FUNCTION_DEF_SOURCE_ARCHIVE_ID_COL,
            Field::Long(Some(LOCAL_ARCHIVE_KEY)),
        );
        rec.set_field(
            FUNCTION_DEF_SOURCE_DT_ID_COL,
            Field::Long(Some(next_id().value())),
        );
        rec.set_field(
            FUNCTION_DEF_SOURCE_SYNC_TIME_COL,
            Field::Long(Some(NO_SOURCE_SYNC_TIME)),
        );
        rec.set_field(
            FUNCTION_DEF_LAST_CHANGE_TIME_COL,
            Field::Long(Some(NO_LAST_CHANGE_TIME)),
        );
        Ok(rec)
    }
}

impl DBRecordAdapter for FunctionDefinitionDBAdapterV1 {
    fn get_records(&self) -> io::Result<Box<dyn RecordIterator + '_>> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut translated = Vec::new();
        while let Some(rec) = iter.next()? {
            translated.push(self.translate_record(rec)?);
        }
        Ok(Box::new(VecRecordIterator {
            records: translated.into_iter(),
        }))
    }

    fn get_record_count(&self) -> usize {
        self.table.read().unwrap().get_record_count()
    }
}

impl FunctionDefinitionDBAdapter for FunctionDefinitionDBAdapterV1 {
    #[allow(clippy::too_many_arguments)]
    fn create_record(
        &mut self,
        _name: &str,
        _comments: Option<&str>,
        _category_id: i64,
        _return_dt_id: i64,
        _has_no_return: bool,
        _has_var_args: bool,
        _calling_convention_id: u8,
        _source_archive_id: i64,
        _source_data_type_id: i64,
        _last_change_time: i64,
    ) -> io::Result<DBRecord> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Cannot create records in Version 1",
        ))
    }

    fn get_record(&self, function_def_id: i64) -> io::Result<Option<DBRecord>> {
        let old = self
            .table
            .read()
            .unwrap()
            .get_record(&Field::Long(Some(function_def_id)))?;
        match old {
            Some(rec) => Ok(Some(self.translate_record(rec)?)),
            None => Ok(None),
        }
    }

    fn remove_record(&mut self, _function_def_id: i64) -> io::Result<bool> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Cannot remove records in Version 1",
        ))
    }

    fn update_record(&mut self, _record: &DBRecord, _set_last_change_time: bool) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Cannot update records in Version 1",
        ))
    }

    fn delete_table(&mut self, handle: &mut DBHandle) -> io::Result<()> {
        let name = self.table.read().unwrap().get_name().to_string();
        handle.delete_table(&name);
        Ok(())
    }

    fn get_record_ids_in_category(&self, category_id: i64) -> io::Result<Vec<Field>> {
        // The Java adapter uses an indexed lookup (`table.findRecords`) on this column; this
        // port's `Table` has no secondary-index support, so this scans linearly instead. Same
        // observable result, just O(n) rather than indexed.
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut ids = Vec::new();
        while let Some(rec) = iter.next()? {
            if matches!(rec.get_field(V1_FUNCTION_DEF_CAT_ID_COL), Field::Long(Some(v)) if *v == category_id)
            {
                ids.push(rec.get_key().clone());
            }
        }
        Ok(ids)
    }

    fn get_record_ids_for_source_archive(&self, archive_id: i64) -> io::Result<Vec<Field>> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut ids = Vec::new();
        while let Some(rec) = iter.next()? {
            if matches!(rec.get_field(V1_FUNCTION_DEF_SOURCE_ARCHIVE_ID_COL), Field::Long(Some(v)) if *v == archive_id)
            {
                ids.push(rec.get_key().clone());
            }
        }
        Ok(ids)
    }

    fn get_record_with_ids(
        &self,
        source_id: UniversalID,
        datatype_id: UniversalID,
    ) -> io::Result<Option<DBRecord>> {
        // NOTE: returns the raw (untranslated) V1-schema record, matching Java's observed
        // behavior -- see module docs.
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        while let Some(rec) = iter.next()? {
            if matches!(rec.get_field(V1_FUNCTION_DEF_UNIVERSAL_DT_ID_COL), Field::Long(Some(v)) if *v == datatype_id.value())
                && matches!(rec.get_field(V1_FUNCTION_DEF_SOURCE_ARCHIVE_ID_COL), Field::Long(Some(v)) if *v == source_id.value())
            {
                return Ok(Some(rec));
            }
        }
        Ok(None)
    }

    fn uses_generic_calling_convention_id(&self) -> bool {
        self.call_conv_adapter.borrow().is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::{FieldType, Schema};
    use std::collections::HashSet;

    fn v1_schema() -> Arc<Schema> {
        Arc::new(Schema::new(
            1,
            FieldType::Long,
            "Data Type ID".to_string(),
            vec![
                FieldType::String,
                FieldType::String,
                FieldType::Long,
                FieldType::Long,
                FieldType::Byte,
                FieldType::Long,
                FieldType::Long,
                FieldType::Long,
                FieldType::Long,
            ],
            vec![
                "Name".to_string(),
                "Comment".to_string(),
                "Category ID".to_string(),
                "Return Type ID".to_string(),
                "Flags".to_string(),
                "Source Archive ID".to_string(),
                "Source Data Type ID".to_string(),
                "Source Sync Time".to_string(),
                "Last Change Time".to_string(),
            ],
            vec![],
        ))
    }

    /// Generic calling convention ordinal 2 == `__cdecl`, packed into flags bits 1..4, with the
    /// vararg bit (bit 0) also set.
    const CDECL_ORDINAL: u8 = 2;

    fn make_handle_with_v1_table() -> DBHandle {
        let mut handle = DBHandle::new().unwrap();
        let table = handle
            .create_table(FUNCTION_DEF_TABLE_NAME.to_string(), v1_schema())
            .unwrap();
        let mut t = table.write().unwrap();
        let packed_flags = 0x1u8 | (CDECL_ORDINAL << GENERIC_CALLING_CONVENTION_FLAG_SHIFT);
        for (name, cat, source_archive, universal_dt) in
            [("foo", 5i64, 10i64, 20i64), ("bar", 5, 11, 21), ("baz", 6, 10, 22)]
        {
            let key = t.get_next_key();
            let mut rec = DBRecord::new(v1_schema(), Field::Long(Some(key)));
            rec.set_field(V1_FUNCTION_DEF_NAME_COL, Field::String(Some(name.to_string())));
            rec.set_field(V1_FUNCTION_DEF_COMMENT_COL, Field::String(None));
            rec.set_field(V1_FUNCTION_DEF_CAT_ID_COL, Field::Long(Some(cat)));
            rec.set_field(V1_FUNCTION_DEF_RETURN_ID_COL, Field::Long(Some(42)));
            rec.set_field(V1_FUNCTION_DEF_FLAGS_COL, Field::Byte(Some(packed_flags as i8)));
            rec.set_field(
                V1_FUNCTION_DEF_SOURCE_ARCHIVE_ID_COL,
                Field::Long(Some(source_archive)),
            );
            rec.set_field(
                V1_FUNCTION_DEF_UNIVERSAL_DT_ID_COL,
                Field::Long(Some(universal_dt)),
            );
            rec.set_field(V1_FUNCTION_DEF_SOURCE_SYNC_TIME_COL, Field::Long(Some(0)));
            rec.set_field(V1_FUNCTION_DEF_LAST_CHANGE_TIME_COL, Field::Long(Some(0)));
            t.put_record(rec).unwrap();
        }
        drop(t);
        handle
    }

    #[test]
    fn missing_table_is_a_version_exception() {
        let handle = DBHandle::new().unwrap();
        assert!(FunctionDefinitionDBAdapterV1::new(&handle, "", None).is_err());
    }

    #[test]
    fn without_a_calling_convention_adapter_uses_raw_generic_ordinal() {
        let handle = make_handle_with_v1_table();
        let adapter = FunctionDefinitionDBAdapterV1::new(&handle, "", None).unwrap();
        assert!(adapter.uses_generic_calling_convention_id());

        let rec = adapter.get_record(0).unwrap().expect("record should exist");
        assert_eq!(
            rec.get_field(FUNCTION_DEF_CALLCONV_COL),
            &Field::Byte(Some(CDECL_ORDINAL as i8))
        );
        // Vararg bit (bit 0) should survive the flag-clearing.
        assert_eq!(
            rec.get_field(FUNCTION_DEF_FLAGS_COL),
            &Field::Byte(Some(0x1))
        );
        assert_eq!(
            rec.get_field(FUNCTION_DEF_SOURCE_ARCHIVE_ID_COL),
            &Field::Long(Some(LOCAL_ARCHIVE_KEY))
        );
    }

    struct MockCallingConventionDBAdapter {
        next_id: u8,
        ids_by_name: std::collections::HashMap<String, u8>,
    }

    impl CallingConventionDBAdapter for MockCallingConventionDBAdapter {
        fn get_calling_convention_id(
            &mut self,
            name: Option<&str>,
            convention_added: &mut dyn FnMut(&str),
        ) -> io::Result<u8> {
            let name = match name {
                Some(n) if !n.is_empty() => n,
                _ => return Ok(UNKNOWN_CALLING_CONVENTION_ID),
            };
            if let Some(id) = self.ids_by_name.get(name) {
                return Ok(*id);
            }
            let id = self.next_id;
            self.next_id += 1;
            self.ids_by_name.insert(name.to_string(), id);
            convention_added(name);
            Ok(id)
        }

        fn get_calling_convention_name(&self, id: u8) -> io::Result<Option<String>> {
            Ok(self
                .ids_by_name
                .iter()
                .find(|(_, v)| **v == id)
                .map(|(k, _)| k.clone()))
        }

        fn invalidate_cache(&mut self) {}

        fn get_calling_convention_names(&self) -> io::Result<HashSet<String>> {
            Ok(self.ids_by_name.keys().cloned().collect())
        }
    }

    #[test]
    fn with_a_calling_convention_adapter_resolves_a_real_id() {
        let handle = make_handle_with_v1_table();
        let call_conv_adapter = MockCallingConventionDBAdapter {
            next_id: 2,
            ids_by_name: std::collections::HashMap::new(),
        };
        let adapter =
            FunctionDefinitionDBAdapterV1::new(&handle, "", Some(Box::new(call_conv_adapter)))
                .unwrap();
        assert!(!adapter.uses_generic_calling_convention_id());

        let rec = adapter.get_record(0).unwrap().expect("record should exist");
        // Should have resolved "__cdecl" to a real (non-generic-ordinal) ID via the mock.
        assert_eq!(rec.get_field(FUNCTION_DEF_CALLCONV_COL), &Field::Byte(Some(2)));
    }

    #[test]
    fn get_record_ids_in_category_and_for_source_archive() {
        let handle = make_handle_with_v1_table();
        let adapter = FunctionDefinitionDBAdapterV1::new(&handle, "", None).unwrap();

        assert_eq!(adapter.get_record_ids_in_category(5).unwrap().len(), 2);
        assert_eq!(
            adapter.get_record_ids_for_source_archive(10).unwrap().len(),
            2
        );
    }

    #[test]
    fn get_record_with_ids_returns_raw_untranslated_record() {
        let handle = make_handle_with_v1_table();
        let adapter = FunctionDefinitionDBAdapterV1::new(&handle, "", None).unwrap();

        let found = adapter
            .get_record_with_ids(UniversalID::new(11), UniversalID::new(21))
            .unwrap()
            .expect("record should exist");
        // Raw V1-schema record: name is still at V1's name column index (same as current, 0).
        assert_eq!(
            found.get_field(V1_FUNCTION_DEF_NAME_COL),
            &Field::String(Some("bar".to_string()))
        );
        assert!(adapter
            .get_record_with_ids(UniversalID::new(999), UniversalID::new(999))
            .unwrap()
            .is_none());
    }

    #[test]
    fn mutating_operations_are_unsupported() {
        let handle = make_handle_with_v1_table();
        let mut adapter = FunctionDefinitionDBAdapterV1::new(&handle, "", None).unwrap();

        assert_eq!(
            adapter
                .create_record("x", None, 5, 1, false, false, 0, 0, 0, 0)
                .unwrap_err()
                .kind(),
            io::ErrorKind::Unsupported
        );
        let existing = adapter.get_record(0).unwrap().unwrap();
        assert_eq!(
            adapter
                .update_record(&existing, false)
                .unwrap_err()
                .kind(),
            io::ErrorKind::Unsupported
        );
        assert_eq!(
            adapter.remove_record(0).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
    }

    #[test]
    fn behaves_as_trait_object() {
        let handle = make_handle_with_v1_table();
        let adapter: Box<dyn FunctionDefinitionDBAdapter> =
            Box::new(FunctionDefinitionDBAdapterV1::new(&handle, "", None).unwrap());
        assert_eq!(adapter.get_record_count(), 3);
    }
}

//! Port of `ghidra.program.database.reloc.RelocationDBAdapterV6`.
//!
//! The live, current-schema implementation: a single [`Table`] whose primary key is a plain
//! one-up ID (Java: key name `"Index"`), with the relocation's address stored in the indexed
//! [`ADDR_COL`] field rather than encoded into the key itself (unlike `V1`..`V4`, which use the
//! address-encoded key directly as their primary key -- see those versions' own module docs).
//!
//! **No secondary-index support.** Java leans on `Table.indexKeyIterator`/
//! `AddressIndexPrimaryKeyIterator` for `ADDR_COL`-ordered iteration. This port's
//! [`Table`](crate::framework::db::Table) has no secondary-index support at all, so
//! [`RelocationDbAdapterV6::collect_records`] instead uses the real
//! [`AddressIndexPrimaryKeyIterator`] utility (which itself falls back to an eager linear
//! scan/sort under the hood -- see that type's own module docs) to gather the matching primary
//! keys, then looks up each full record, all before ever handing back a [`RecordIterator`] --
//! matching the "no secondary-index support -> eager linear scan" convention already established
//! by `BookmarkDBAdapterV3`/`SymbolDatabaseAdapterV5` and others in this DB-adapter family.
//!
//! **`adaptRecord` always panics.** Java's `RelocationDBAdapterV6.adaptRecord` unconditionally
//! throws `UnsupportedOperationException("Don't know how to adapt to the new version")` -- there
//! is, by definition, no newer schema for the *current* version to translate into. Since
//! [`RelocationDBAdapter::adapt_record`] is an infallible `DBRecord -> DBRecord` signature (no
//! `Result` to propagate an error through), this port mirrors that unconditional throw with an
//! unconditional `panic!`, the same convention already used elsewhere in this port for methods
//! whose *only* Java behavior is to throw (see `SymbolDatabaseAdapterV2`'s module docs for the
//! analogous mutating-method precedent).

use std::io;
use std::sync::{Arc, RwLock};

use crate::framework::db::{DBFieldIterator, DBHandle, DBRecord, Field, RecordIterator, Schema, Table};
use crate::program::database::map::{AddressIndexPrimaryKeyIterator, AddressMap};
use crate::program::database::reloc::relocation_db_adapter::{
    encode_binary_coded_longs, RelocationDBAdapter, VecRelocationRecordIterator, ADDR_COL,
    BYTES_COL, FLAGS_COL, SYMBOL_NAME_COL, TABLE_NAME, TYPE_COL, VALUE_COL,
};
use crate::program::model::address::{Address, AddressSetView};
use crate::util::exception::VersionException;

/// Schema version implemented by this adapter. Port of `RelocationDBAdapterV6.VERSION`.
pub const VERSION: i32 = 6;

/// Builds the current relocation table schema. Port of `RelocationDBAdapter.SCHEMA`, which in
/// Java lives on the shared abstract base class (referencing `RelocationDBAdapterV6.VERSION` for
/// its version number) rather than on this concrete type; this port puts the two together here
/// since [`VERSION`] already lives in this module.
pub fn schema() -> Arc<Schema> {
    use crate::framework::db::FieldType;
    Arc::new(Schema::new(
        VERSION,
        FieldType::Long,
        "Index".to_string(),
        vec![
            FieldType::Long,
            FieldType::Byte,
            FieldType::Int,
            FieldType::Binary,
            FieldType::Binary,
            FieldType::String,
        ],
        vec![
            "Address".to_string(),
            "Status".to_string(),
            "Type".to_string(),
            "Values".to_string(),
            "Bytes".to_string(),
            "Symbol Name".to_string(),
        ],
        vec![],
    ))
}

/// The live, table-backed implementation of the relocations database adapter (current schema).
///
/// Port of `ghidra.program.database.reloc.RelocationDBAdapterV6`.
pub struct RelocationDbAdapterV6 {
    reloc_table: Arc<RwLock<Table>>,
    addr_map: Arc<dyn AddressMap>,
}

impl RelocationDbAdapterV6 {
    /// Constructs the V6 relocation adapter: creates (`create = true`) or opens (`create =
    /// false`) the relocations table.
    ///
    /// Port of `RelocationDBAdapterV6(DBHandle, AddressMap, boolean)`.
    ///
    /// # Errors
    /// When opening (`create = false`): returns an upgradeable [`VersionException`] if no
    /// relocations table exists yet, or one whose upgradeability reflects whether the stored
    /// schema is older or newer than [`VERSION`] if the table exists at a different version.
    pub fn new(
        handle: &mut DBHandle,
        addr_map: Arc<dyn AddressMap>,
        create: bool,
    ) -> Result<Self, VersionException> {
        let reloc_table = if create {
            handle
                .create_table(TABLE_NAME.to_string(), schema())
                .map_err(|e| VersionException::with_message(e.to_string()))?
        } else {
            let table = handle
                .get_table(TABLE_NAME)
                .ok_or_else(|| VersionException::with_upgradeable(true))?;
            let version = table.read().unwrap().get_schema().get_version();
            if version != VERSION {
                return Err(VersionException::with_upgradeable(version < VERSION));
            }
            table
        };
        Ok(RelocationDbAdapterV6 { reloc_table, addr_map })
    }

    /// Adds or updates the given relocation record verbatim, keeping its existing key. Port of
    /// the package-private `RelocationDBAdapterV6.put(DBRecord)`; used by the `upgrade()` factory
    /// helper (see `relocation_db_adapter.rs`) to copy already-V6-shaped records straight into
    /// the real table without re-allocating keys via [`RelocationDBAdapter::add`].
    ///
    /// Unlike Java's real B-tree `Table` (whose `getKey()` always derives the next key from
    /// whatever keys are actually present), this port's [`Table::get_next_key`] is a separate
    /// explicit counter that `put_record` alone does not advance -- so this also calls
    /// [`Table::ensure_next_key_at_least`] after inserting, keeping that counter in sync with the
    /// externally-chosen key just written. Without this, a subsequent [`RelocationDBAdapter::add`]
    /// could allocate a colliding key and silently overwrite this record instead of adding a new
    /// one (see `BookmarkDBAdapterV3::create_bookmark`'s module docs for the same fix applied to
    /// an analogous situation).
    pub(crate) fn put(&mut self, rec: DBRecord) -> io::Result<()> {
        let key = rec.get_key().get_long_value();
        let mut table = self.reloc_table.write().unwrap();
        table.put_record(rec)?;
        table.ensure_next_key_at_least(key);
        Ok(())
    }

    /// Gathers every record whose [`ADDR_COL`] falls within `set` (or all records, if `set` is
    /// `None`), optionally positioned at `start`, in ascending address-then-key order. Backs all
    /// three [`RelocationDBAdapter`] iterator methods. See the module docs for why this collects
    /// eagerly rather than returning a live cursor.
    fn collect_records(
        &self,
        set: Option<&dyn AddressSetView>,
        start: Option<&Address>,
    ) -> io::Result<Vec<DBRecord>> {
        let mut it = match start {
            Some(start) => AddressIndexPrimaryKeyIterator::new_at(
                &self.reloc_table,
                ADDR_COL,
                self.addr_map.as_ref(),
                start,
                true,
            )?,
            None => AddressIndexPrimaryKeyIterator::new_over_set(
                &self.reloc_table,
                ADDR_COL,
                self.addr_map.as_ref(),
                set,
                true,
            )?,
        };
        let mut records = Vec::new();
        while it.has_next()? {
            if let Some(key) = it.next()? {
                let table = self.reloc_table.read().unwrap();
                if let Some(rec) = table.get_record(&key)? {
                    records.push(rec);
                }
            }
        }
        Ok(records)
    }
}

impl RelocationDBAdapter for RelocationDbAdapterV6 {
    fn add(
        &mut self,
        addr: &Address,
        flags: u8,
        type_: i32,
        values: &[i64],
        bytes: Option<&[u8]>,
        symbol_name: Option<&str>,
    ) -> io::Result<()> {
        let mut table = self.reloc_table.write().unwrap();
        let key = table.get_next_key();
        let mut rec = DBRecord::new(schema(), Field::Long(Some(key)));
        rec.set_field(ADDR_COL, Field::Long(Some(self.addr_map.get_key(addr, true))));
        rec.set_field(FLAGS_COL, Field::Byte(Some(flags as i8)));
        rec.set_field(TYPE_COL, Field::Int(Some(type_)));
        rec.set_field(VALUE_COL, Field::Binary(Some(encode_binary_coded_longs(values))));
        rec.set_field(BYTES_COL, Field::Binary(bytes.map(|b| b.to_vec())));
        rec.set_field(
            SYMBOL_NAME_COL,
            Field::String(symbol_name.map(|s| s.to_string())),
        );
        table.put_record(rec)
    }

    fn iterator(&self) -> io::Result<Box<dyn RecordIterator + '_>> {
        let records = self.collect_records(None, None)?;
        Ok(Box::new(VecRelocationRecordIterator::new(records)))
    }

    fn iterator_in_set(&self, set: &dyn AddressSetView) -> io::Result<Box<dyn RecordIterator + '_>> {
        let records = self.collect_records(Some(set), None)?;
        Ok(Box::new(VecRelocationRecordIterator::new(records)))
    }

    fn iterator_from(&self, start: &Address) -> io::Result<Box<dyn RecordIterator + '_>> {
        let records = self.collect_records(None, Some(start))?;
        Ok(Box::new(VecRelocationRecordIterator::new(records)))
    }

    fn get_record_count(&self) -> i32 {
        self.reloc_table.read().unwrap().get_record_count() as i32
    }

    fn adapt_record(&self, _rec: DBRecord) -> DBRecord {
        // See the module docs: Java's V6.adaptRecord always throws -- there is no newer schema to
        // translate into.
        panic!("RelocationDBAdapterV6.adaptRecord: don't know how to adapt to the new version");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::database::reloc::relocation_db_adapter::{get_flags, get_status};
    use crate::program::database::reloc::test_support::IdentityAddressMap;
    use crate::program::model::address::{AddressSet, AddressSpace, AddressSpaceType};
    use crate::program::model::reloc::relocation::RelocationStatus;

    fn space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn addr_map() -> Arc<dyn AddressMap> {
        Arc::new(IdentityAddressMap::new(space()))
    }

    fn create_adapter(handle: &mut DBHandle) -> RelocationDbAdapterV6 {
        RelocationDbAdapterV6::new(handle, addr_map(), true).unwrap()
    }

    #[test]
    fn add_and_iterate_round_trips_all_columns() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = create_adapter(&mut handle);
        let s = space();

        let flags = get_flags(RelocationStatus::Applied, 0);
        adapter
            .add(&s.address(0x2000), flags, 5, &[1, 2, 3], Some(&[0xde, 0xad]), Some("main"))
            .unwrap();
        adapter
            .add(&s.address(0x1000), get_flags(RelocationStatus::Unknown, 4), 9, &[], None, None)
            .unwrap();

        assert_eq!(adapter.get_record_count(), 2);

        let mut it = adapter.iterator().unwrap();
        let first = it.next().unwrap().unwrap();
        // Ordered by address, so 0x1000 comes first even though it was added second.
        assert_eq!(first.get_field(ADDR_COL), &Field::Long(Some(0x1000)));
        assert_eq!(first.get_field(TYPE_COL), &Field::Int(Some(9)));
        assert_eq!(first.get_field(BYTES_COL), &Field::Binary(None));

        let second = it.next().unwrap().unwrap();
        assert_eq!(second.get_field(ADDR_COL), &Field::Long(Some(0x2000)));
        assert_eq!(second.get_string(SYMBOL_NAME_COL), Some("main"));
        let stored_flags = match second.get_field(FLAGS_COL) {
            Field::Byte(Some(b)) => *b as u8,
            _ => panic!("expected byte field"),
        };
        assert_eq!(get_status(stored_flags), RelocationStatus::Applied);

        assert!(it.next().unwrap().is_none());
    }

    #[test]
    fn iterator_in_set_filters_by_address() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = create_adapter(&mut handle);
        let s = space();
        adapter.add(&s.address(0x100), 0, 0, &[], None, None).unwrap();
        adapter.add(&s.address(0x200), 0, 0, &[], None, None).unwrap();
        adapter.add(&s.address(0x300), 0, 0, &[], None, None).unwrap();

        let set = AddressSet::from_start_end(s.address(0x150), s.address(0x250));
        let mut it = adapter.iterator_in_set(&set).unwrap();
        let rec = it.next().unwrap().unwrap();
        assert_eq!(rec.get_field(ADDR_COL), &Field::Long(Some(0x200)));
        assert!(it.next().unwrap().is_none());
    }

    #[test]
    fn iterator_from_starts_at_and_includes_given_address() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter = create_adapter(&mut handle);
        let s = space();
        adapter.add(&s.address(0x100), 0, 0, &[], None, None).unwrap();
        adapter.add(&s.address(0x200), 0, 0, &[], None, None).unwrap();

        let mut it = adapter.iterator_from(&s.address(0x200)).unwrap();
        let rec = it.next().unwrap().unwrap();
        assert_eq!(rec.get_field(ADDR_COL), &Field::Long(Some(0x200)));
        assert!(it.next().unwrap().is_none());
    }

    #[test]
    fn open_mode_rejects_missing_table_as_upgradeable() {
        let mut handle = DBHandle::new().unwrap();
        match RelocationDbAdapterV6::new(&mut handle, addr_map(), false) {
            Err(e) => assert!(e.is_upgradable()),
            Ok(_) => panic!("expected VersionException"),
        }
    }

    #[test]
    fn open_mode_reopens_previously_created_table() {
        let mut handle = DBHandle::new().unwrap();
        {
            let mut adapter = create_adapter(&mut handle);
            adapter.add(&space().address(0x10), 0, 0, &[], None, None).unwrap();
        }
        let reopened = RelocationDbAdapterV6::new(&mut handle, addr_map(), false).unwrap();
        assert_eq!(reopened.get_record_count(), 1);
    }

    #[test]
    #[should_panic(expected = "don't know how to adapt")]
    fn adapt_record_always_panics() {
        let mut handle = DBHandle::new().unwrap();
        let adapter = create_adapter(&mut handle);
        let rec = DBRecord::new(schema(), Field::Long(Some(0)));
        adapter.adapt_record(rec);
    }

    #[test]
    fn behaves_as_trait_object() {
        let mut handle = DBHandle::new().unwrap();
        let mut adapter: Box<dyn RelocationDBAdapter> = Box::new(create_adapter(&mut handle));
        adapter.add(&space().address(0x10), 0, 0, &[], None, None).unwrap();
        assert_eq!(adapter.get_record_count(), 1);
    }
}

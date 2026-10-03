//! Port of `ghidra.program.database.symbol.SymbolDatabaseAdapterV5`.
//!
//! Version 5 (current) implementation for accessing the symbol database table, backed by a live,
//! writable [`Table`]. Version 5 added additional sparse columns to store optional data specific
//! to certain symbol types (datatype ID, variable offset, external import name/address, comment,
//! library path/ordinal); the ad-hoc string data column used by earlier versions was eliminated.
//!
//! Also re-declares the `SymbolDatabaseAdapter.SYMBOL_TABLE_NAME`/`SYMBOL_SCHEMA`/column-index
//! constants locally, since
//! [`SymbolDatabaseAdapter`](crate::program::database::symbol::SymbolDatabaseAdapter)'s own port
//! intentionally left the table-layout constants out.
//!
//! Deviation from Java: this struct holds the real `Arc<dyn AddressMap>` it was constructed with
//! (matching the Java field exactly), used to translate between `Address` and the raw database-key
//! encoding stored in `SYMBOL_ADDR_COL`/`SYMBOL_PRIMARY_COL`. Where Java uses indexed lookups
//! (`Table.indexIterator`/`Table.findRecords`/`AddressIndexPrimaryKeyIterator`/
//! `AddressIndexKeyIterator`/`AddressRecordDeleter`) against `Table`'s secondary indexes, this
//! port's [`Table`] has no secondary-index support, so every such lookup scans linearly instead --
//! decoding each candidate record's address through the real `AddressMap` and filtering/sorting in
//! memory. Same observable result, just O(n) rather than indexed (matching the convention already
//! established by `EquateRefDBAdapterV1`/`LabelHistoryAdapterV0`/`CompositeDBAdapterV5V6` and
//! others in this DB-adapter family).

use std::collections::BTreeSet;
use std::io;
use std::sync::{Arc, RwLock};

use crate::framework::db::{DBHandle, DBRecord, Field, FieldType, RecordIterator, Schema, Table};
use crate::program::database::map::{AddressMap, INVALID_ADDRESS_KEY};
use crate::program::database::symbol::symbol_database_adapter::{
    compute_locator_hash, get_source_type_flags_bits, SymbolDatabaseAdapter,
    SymbolDeleteAddressRangeError, SYMBOL_PINNED_FLAG,
};
use crate::program::model::address::{Address, AddressSetView, AddressSpace};
use crate::program::model::symbol::{SourceType, SymbolType};
use crate::util::exception::VersionException;
use crate::util::task::TaskMonitor;

/// Name of the symbol database table. Mirrors `SymbolDatabaseAdapter.SYMBOL_TABLE_NAME`.
pub const SYMBOL_TABLE_NAME: &str = "Symbols";

/// Column index of the symbol name. Mirrors `SymbolDatabaseAdapter.SYMBOL_NAME_COL`.
pub const SYMBOL_NAME_COL: usize = 0;
/// Column index of the symbol's address (database-key encoding). Mirrors
/// `SymbolDatabaseAdapter.SYMBOL_ADDR_COL`.
pub const SYMBOL_ADDR_COL: usize = 1;
/// Column index of the symbol's containing namespace ID. Mirrors
/// `SymbolDatabaseAdapter.SYMBOL_PARENT_ID_COL`.
pub const SYMBOL_PARENT_ID_COL: usize = 2;
/// Column index of the symbol's [`SymbolType`] ID. Mirrors
/// `SymbolDatabaseAdapter.SYMBOL_TYPE_COL`.
pub const SYMBOL_TYPE_COL: usize = 3;
/// Column index of the symbol's flags byte. Mirrors `SymbolDatabaseAdapter.SYMBOL_FLAGS_COL`.
pub const SYMBOL_FLAGS_COL: usize = 4;
/// Column index of the name/namespace/address locator hash (sparse). Mirrors
/// `SymbolDatabaseAdapter.SYMBOL_HASH_COL`.
pub const SYMBOL_HASH_COL: usize = 5;
/// Column index of the primary-symbol marker (sparse; duplicates the address key when primary).
/// Mirrors `SymbolDatabaseAdapter.SYMBOL_PRIMARY_COL`.
pub const SYMBOL_PRIMARY_COL: usize = 6;
/// Column index of the associated data type ID (sparse). Mirrors
/// `SymbolDatabaseAdapter.SYMBOL_DATATYPE_COL`.
pub const SYMBOL_DATATYPE_COL: usize = 7;
/// Column index of the variable ordinal/first-use offset (sparse). Mirrors
/// `SymbolDatabaseAdapter.SYMBOL_VAROFFSET_COL`.
pub const SYMBOL_VAROFFSET_COL: usize = 8;
/// Column index of the external symbol's original imported name (sparse). Mirrors
/// `SymbolDatabaseAdapter.SYMBOL_ORIGINAL_IMPORTED_NAME_COL`.
pub const SYMBOL_ORIGINAL_IMPORTED_NAME_COL: usize = 9;
/// Column index of the external symbol's program address, stored as a string (sparse). Mirrors
/// `SymbolDatabaseAdapter.SYMBOL_EXTERNAL_PROG_ADDR_COL`.
pub const SYMBOL_EXTERNAL_PROG_ADDR_COL: usize = 10;
/// Column index of the symbol comment (sparse). Mirrors
/// `SymbolDatabaseAdapter.SYMBOL_COMMENT_COL`.
pub const SYMBOL_COMMENT_COL: usize = 11;
/// Column index of the external library path (sparse). Mirrors
/// `SymbolDatabaseAdapter.SYMBOL_LIBPATH_COL`.
pub const SYMBOL_LIBPATH_COL: usize = 12;
/// Column index of the external library ordinal (sparse). Mirrors
/// `SymbolDatabaseAdapter.SYMBOL_LIB_ORDINAL_COL`.
pub const SYMBOL_LIB_ORDINAL_COL: usize = 13;

/// Schema version implemented by this adapter.
pub const CURRENT_VERSION: i32 = 5;

// Used to create a range when searching symbols by name/namespace but don't care about address.
const MIN_ADDRESS_OFFSET: i64 = 0;
const MAX_ADDRESS_OFFSET: i64 = -1;

/// Build the current symbol table schema, as defined by
/// `SymbolDatabaseAdapterV5.V5_SYMBOL_SCHEMA`.
pub fn schema() -> Arc<Schema> {
    Arc::new(Schema::new(
        CURRENT_VERSION,
        FieldType::Long,
        "Key".to_string(),
        vec![
            FieldType::String,
            FieldType::Long,
            FieldType::Long,
            FieldType::Byte,
            FieldType::Byte,
            FieldType::Long,
            FieldType::Long,
            FieldType::Long,
            FieldType::Int,
            FieldType::String,
            FieldType::String,
            FieldType::String,
            FieldType::String,
            FieldType::Int,
        ],
        vec![
            "Name".to_string(),
            "Address".to_string(),
            "Namespace".to_string(),
            "Symbol Type".to_string(),
            "Flags".to_string(),
            "Locator Hash".to_string(),
            "Primary".to_string(),
            "Datatype".to_string(),
            "Variable Offset".to_string(),
            "ExtOrigImportName".to_string(),
            "ExtProgAddr".to_string(),
            "Comment".to_string(),
            "LibPath".to_string(),
            "LibOrdinal".to_string(),
        ],
        vec![
            SYMBOL_HASH_COL,
            SYMBOL_PRIMARY_COL,
            SYMBOL_DATATYPE_COL,
            SYMBOL_VAROFFSET_COL,
            SYMBOL_ORIGINAL_IMPORTED_NAME_COL,
            SYMBOL_EXTERNAL_PROG_ADDR_COL,
            SYMBOL_COMMENT_COL,
            SYMBOL_LIBPATH_COL,
            SYMBOL_LIB_ORDINAL_COL,
        ],
    ))
}

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

fn empty_iterator() -> Box<dyn RecordIterator + 'static> {
    Box::new(VecRecordIterator {
        records: Vec::new().into_iter(),
    })
}

/// Version 5 (current) implementation for accessing the symbol database table.
///
/// Port of `ghidra.program.database.symbol.SymbolDatabaseAdapterV5`.
pub struct SymbolDatabaseAdapterV5 {
    table: Arc<RwLock<Table>>,
    addr_map: Arc<dyn AddressMap>,
}

impl SymbolDatabaseAdapterV5 {
    /// Gets a version 5 adapter for the symbol database table. If `create` is `true`, the table is
    /// created, otherwise an existing table is opened.
    ///
    /// # Errors
    ///
    /// Returns a [`VersionException`] if opening an existing table that is missing or whose schema
    /// version does not match [`CURRENT_VERSION`].
    pub fn new(
        handle: &mut DBHandle,
        addr_map: Arc<dyn AddressMap>,
        create: bool,
    ) -> Result<Self, VersionException> {
        let table = if create {
            handle
                .create_table(SYMBOL_TABLE_NAME.to_string(), schema())
                .map_err(|e| VersionException::with_message(e.to_string()))?
        } else {
            let table = handle.get_table(SYMBOL_TABLE_NAME).ok_or_else(|| {
                VersionException::with_message(format!("Missing Table: {SYMBOL_TABLE_NAME}"))
            })?;
            let version = table.read().unwrap().get_schema().get_version();
            if version != CURRENT_VERSION {
                return Err(VersionException::with_upgradeable(version < CURRENT_VERSION));
            }
            table
        };
        Ok(SymbolDatabaseAdapterV5 { table, addr_map })
    }

    /// Collects, decodes, and address-sorts every record for which `filter` returns `true`.
    /// Backs the several by-address/range/set iteration methods below.
    fn collect_sorted_by_address(
        &self,
        forward: bool,
        filter: impl Fn(&DBRecord, &Address) -> bool,
    ) -> io::Result<Box<dyn RecordIterator + '_>> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut entries: Vec<(Address, DBRecord)> = Vec::new();
        while let Some(rec) = iter.next()? {
            if let Some(key) = rec.get_long(SYMBOL_ADDR_COL) {
                let addr = self.addr_map.decode_address(key);
                if filter(&rec, &addr) {
                    entries.push((addr, rec));
                }
            }
        }
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        if !forward {
            entries.reverse();
        }
        Ok(Box::new(VecRecordIterator {
            records: entries.into_iter().map(|(_, rec)| rec).collect::<Vec<_>>().into_iter(),
        }))
    }

    /// Deletes all symbol records with addresses within `[start, end]`, unconditionally (no
    /// pinned-symbol exemption). Stands in for `SymbolDatabaseAdapterV5.deleteExternalEntries`.
    /// Not part of the [`SymbolDatabaseAdapter`] trait -- like Java's package-private method of
    /// the same name, this is called only by whichever symbol manager ends up owning external
    /// symbol cleanup.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    pub fn delete_external_entries(&mut self, start: &Address, end: &Address) -> io::Result<()> {
        let mut table = self.table.write().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut to_delete = Vec::new();
        while let Some(rec) = iter.next()? {
            if let Some(key) = rec.get_long(SYMBOL_ADDR_COL) {
                let addr = self.addr_map.decode_address(key);
                if &addr >= start && &addr <= end {
                    to_delete.push(rec.get_key().clone());
                }
            }
        }
        drop(iter);
        for key in to_delete {
            table.delete_record(&key)?;
        }
        Ok(())
    }
}

impl SymbolDatabaseAdapter for SymbolDatabaseAdapterV5 {
    fn create_symbol_record(
        &self,
        name: &str,
        namespace_id: i64,
        address: &Address,
        symbol_type: SymbolType,
        is_primary: bool,
        source: SourceType,
    ) -> DBRecord {
        // Avoid key 0, as it is reserved for the global namespace. Deviation from Java: Java's
        // `Table.getKey()` derives its answer from the table's current max stored key, so calling
        // it repeatedly without an intervening `putRecord` keeps returning the same value --
        // meaning Java's `if (nextID == 0) nextID++` is a pure local bump that costs nothing.
        // This port's `Table::get_next_key` instead advances a real, always-consumed counter on
        // every call (see `VariableStorageDBAdapterV2::get_next_storage_id` for the established
        // convention), so a local-only bump here would silently reuse key 1 for the *next* symbol
        // too. Drawing a second real key instead avoids that collision.
        let mut next_id = self.table.write().unwrap().get_next_key();
        if next_id == 0 {
            next_id = self.table.write().unwrap().get_next_key();
        }

        let address_key = self.addr_map.get_key(address, true);

        let mut rec = DBRecord::new(schema(), Field::Long(Some(next_id)));
        rec.set_string(SYMBOL_NAME_COL, Some(name.to_string()));
        rec.set_long(SYMBOL_ADDR_COL, address_key);
        rec.set_long(SYMBOL_PARENT_ID_COL, namespace_id);
        rec.set_byte(SYMBOL_TYPE_COL, symbol_type.get_id() as i8);
        let flags = get_source_type_flags_bits(source)
            .unwrap_or_else(|e| panic!("{e}")); // assume non-pinned
        rec.set_byte(SYMBOL_FLAGS_COL, flags as i8);

        // Sparse columns -- these columns don't apply to all symbols. They default to null
        // unless specifically set. Null values don't consume space.

        if let Some(hash) = compute_locator_hash(name, namespace_id, address_key) {
            rec.set_field(SYMBOL_HASH_COL, Field::Long(Some(hash)));
        }

        if is_primary {
            rec.set_long(SYMBOL_PRIMARY_COL, address_key);
        }

        rec
    }

    fn get_symbol_record(&self, symbol_id: i64) -> io::Result<Option<DBRecord>> {
        self.table.read().unwrap().get_record(&Field::Long(Some(symbol_id)))
    }

    fn remove_symbol(&mut self, symbol_id: i64) -> io::Result<()> {
        self.table.write().unwrap().delete_record(&Field::Long(Some(symbol_id)))?;
        Ok(())
    }

    fn has_symbol(&self, addr: &Address) -> io::Result<bool> {
        let key = self.addr_map.get_key(addr, false);
        if key == INVALID_ADDRESS_KEY {
            return Ok(false);
        }
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        while let Some(rec) = iter.next()? {
            if rec.get_long(SYMBOL_ADDR_COL) == Some(key) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn get_symbol_ids(&self, addr: &Address) -> io::Result<Vec<Field>> {
        let key = self.addr_map.get_key(addr, false);
        if key == INVALID_ADDRESS_KEY {
            return Ok(Vec::new());
        }
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut ids = Vec::new();
        while let Some(rec) = iter.next()? {
            if rec.get_long(SYMBOL_ADDR_COL) == Some(key) {
                ids.push(rec.get_key().clone());
            }
        }
        Ok(ids)
    }

    fn get_symbol_count(&self) -> i32 {
        self.table.read().unwrap().get_record_count() as i32
    }

    fn get_symbols_by_address(&self, forward: bool) -> io::Result<Box<dyn RecordIterator + '_>> {
        self.collect_sorted_by_address(forward, |_, _| true)
    }

    fn get_symbols_by_address_from(
        &self,
        start_addr: &Address,
        forward: bool,
    ) -> io::Result<Box<dyn RecordIterator + '_>> {
        let start = start_addr.clone();
        self.collect_sorted_by_address(forward, move |_, addr| {
            if forward {
                addr >= &start
            } else {
                addr <= &start
            }
        })
    }

    fn update_symbol_record(&mut self, record: &DBRecord) -> io::Result<()> {
        // Make sure the hash is updated to reflect the current name and namespace.
        let mut record = record.clone();
        let name = record.get_string(SYMBOL_NAME_COL).unwrap_or("").to_string();
        let namespace_id = record.get_long(SYMBOL_PARENT_ID_COL).unwrap_or(0);
        let address_key = record.get_long(SYMBOL_ADDR_COL).unwrap_or(0);
        let hash_field = match compute_locator_hash(&name, namespace_id, address_key) {
            Some(hash) => Field::Long(Some(hash)),
            None => Field::Long(None),
        };
        record.set_field(SYMBOL_HASH_COL, hash_field);
        self.table.write().unwrap().put_record(record)
    }

    fn get_symbols(&self) -> io::Result<Box<dyn RecordIterator + '_>> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut records = Vec::new();
        while let Some(rec) = iter.next()? {
            records.push(rec);
        }
        Ok(Box::new(VecRecordIterator {
            records: records.into_iter(),
        }))
    }

    fn get_symbols_in_range(
        &self,
        start: &Address,
        end: &Address,
        forward: bool,
    ) -> io::Result<Box<dyn RecordIterator + '_>> {
        let (start, end) = (start.clone(), end.clone());
        self.collect_sorted_by_address(forward, move |_, addr| addr >= &start && addr <= &end)
    }

    fn get_symbols_in_set(
        &self,
        set: &dyn AddressSetView,
        forward: bool,
    ) -> io::Result<Box<dyn RecordIterator + '_>> {
        self.collect_sorted_by_address(forward, |_, addr| set.contains(addr))
    }

    fn get_primary_symbols(
        &self,
        set: &dyn AddressSetView,
        forward: bool,
    ) -> io::Result<Box<dyn RecordIterator + '_>> {
        self.collect_sorted_by_address(forward, |rec, addr| {
            !rec.get_field(SYMBOL_PRIMARY_COL).is_null() && set.contains(addr)
        })
    }

    fn get_primary_symbol(&self, address: &Address) -> io::Result<Option<DBRecord>> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        while let Some(rec) = iter.next()? {
            if let Field::Long(Some(v)) = rec.get_field(SYMBOL_PRIMARY_COL) {
                if &self.addr_map.decode_address(*v) == address {
                    return Ok(Some(rec));
                }
            }
        }
        Ok(None)
    }

    fn move_address(&mut self, old_addr: &Address, new_addr: &Address) -> io::Result<()> {
        let old_key = self.addr_map.get_key(old_addr, false);
        let new_key = self.addr_map.get_key(new_addr, true);
        let mut table = self.table.write().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut to_update = Vec::new();
        while let Some(mut rec) = iter.next()? {
            if rec.get_long(SYMBOL_ADDR_COL) == Some(old_key) {
                rec.set_long(SYMBOL_ADDR_COL, new_key);
                to_update.push(rec);
            }
        }
        drop(iter);
        for rec in to_update {
            table.put_record(rec)?;
        }
        Ok(())
    }

    fn delete_address_range(
        &mut self,
        start_addr: &Address,
        end_addr: &Address,
        monitor: &dyn TaskMonitor,
    ) -> Result<BTreeSet<Address>, SymbolDeleteAddressRangeError> {
        monitor.check_cancelled()?;

        let mut anchored = BTreeSet::new();
        let mut table = self.table.write().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut to_delete = Vec::new();
        while let Some(rec) = iter.next()? {
            let Some(key) = rec.get_long(SYMBOL_ADDR_COL) else {
                continue;
            };
            let addr = self.addr_map.decode_address(key);
            if &addr < start_addr || &addr > end_addr {
                continue;
            }
            let flags = rec.get_byte(SYMBOL_FLAGS_COL).unwrap_or(0) as u8;
            let pinned = flags & SYMBOL_PINNED_FLAG != 0;
            if pinned {
                // Only move/delete symbols whose anchor (pinned) flag is not set.
                anchored.insert(addr);
            } else {
                to_delete.push(rec.get_key().clone());
            }
        }
        drop(iter);
        for key in to_delete {
            table.delete_record(&key)?;
        }
        Ok(anchored)
    }

    fn get_symbols_by_namespace(&self, id: i64) -> io::Result<Box<dyn RecordIterator + '_>> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut records = Vec::new();
        while let Some(rec) = iter.next()? {
            if rec.get_long(SYMBOL_PARENT_ID_COL) == Some(id) {
                records.push(rec);
            }
        }
        Ok(Box::new(VecRecordIterator {
            records: records.into_iter(),
        }))
    }

    fn get_symbols_by_name(&self, name: &str) -> io::Result<Box<dyn RecordIterator + '_>> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut records = Vec::new();
        while let Some(rec) = iter.next()? {
            if rec.get_string(SYMBOL_NAME_COL) == Some(name) {
                records.push(rec);
            }
        }
        Ok(Box::new(VecRecordIterator {
            records: records.into_iter(),
        }))
    }

    fn scan_symbols_by_name(&self, start_name: &str) -> io::Result<Box<dyn RecordIterator + '_>> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut records = Vec::new();
        while let Some(rec) = iter.next()? {
            if rec.get_string(SYMBOL_NAME_COL).unwrap_or("") >= start_name {
                records.push(rec);
            }
        }
        records.sort_by(|a, b| {
            a.get_string(SYMBOL_NAME_COL)
                .unwrap_or("")
                .cmp(b.get_string(SYMBOL_NAME_COL).unwrap_or(""))
        });
        Ok(Box::new(VecRecordIterator {
            records: records.into_iter(),
        }))
    }

    fn get_external_symbols_by_original_import_name(
        &self,
        ext_label: &str,
    ) -> io::Result<Box<dyn RecordIterator + '_>> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut records = Vec::new();
        while let Some(rec) = iter.next()? {
            if rec.get_string(SYMBOL_ORIGINAL_IMPORTED_NAME_COL) == Some(ext_label) {
                records.push(rec);
            }
        }
        Ok(Box::new(VecRecordIterator {
            records: records.into_iter(),
        }))
    }

    fn get_external_symbols_by_memory_address(
        &self,
        ext_prog_addr: &Address,
    ) -> io::Result<Box<dyn RecordIterator + '_>> {
        let target = ext_prog_addr.to_string();
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut records = Vec::new();
        while let Some(rec) = iter.next()? {
            if rec.get_string(SYMBOL_EXTERNAL_PROG_ADDR_COL) == Some(target.as_str()) {
                records.push(rec);
            }
        }
        Ok(Box::new(VecRecordIterator {
            records: records.into_iter(),
        }))
    }

    fn get_symbols_by_name_and_namespace(
        &self,
        name: &str,
        id: i64,
    ) -> io::Result<Box<dyn RecordIterator + '_>> {
        // Java forms a hash range [computeLocatorHash(name, id, MIN_ADDRESS_OFFSET),
        // computeLocatorHash(name, id, MAX_ADDRESS_OFFSET)] and scans the hash index; since this
        // port's `Table` has no secondary-index support, this filters directly on name+namespace
        // instead. Same observable result. `computeLocatorHash` returns `None` for an empty name,
        // in which case Java returns `EmptyRecordIterator.INSTANCE`.
        let _ = (
            compute_locator_hash(name, id, MIN_ADDRESS_OFFSET),
            MAX_ADDRESS_OFFSET,
        );
        if name.is_empty() {
            return Ok(empty_iterator());
        }
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut records = Vec::new();
        while let Some(rec) = iter.next()? {
            if rec.get_string(SYMBOL_NAME_COL) == Some(name)
                && rec.get_long(SYMBOL_PARENT_ID_COL) == Some(id)
            {
                records.push(rec);
            }
        }
        Ok(Box::new(VecRecordIterator {
            records: records.into_iter(),
        }))
    }

    fn get_symbol_record_by_address_name_namespace(
        &self,
        address: &Address,
        name: &str,
        namespace_id: i64,
    ) -> io::Result<Option<DBRecord>> {
        let address_key = self.addr_map.get_key(address, false);
        if compute_locator_hash(name, namespace_id, address_key).is_none() {
            return Ok(None);
        }
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        while let Some(rec) = iter.next()? {
            if rec.get_string(SYMBOL_NAME_COL) == Some(name)
                && rec.get_long(SYMBOL_PARENT_ID_COL) == Some(namespace_id)
                && rec.get_long(SYMBOL_ADDR_COL) == Some(address_key)
            {
                return Ok(Some(rec));
            }
        }
        Ok(None)
    }

    fn get_max_symbol_address(&self, space: &AddressSpace) -> io::Result<Option<Address>> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut max: Option<Address> = None;
        while let Some(rec) = iter.next()? {
            if let Some(key) = rec.get_long(SYMBOL_ADDR_COL) {
                let addr = self.addr_map.decode_address(key);
                if addr.space().as_ref() != space {
                    continue;
                }
                if max.as_ref().is_none_or(|m| addr > *m) {
                    max = Some(addr);
                }
            }
        }
        Ok(max)
    }

    fn get_table(&self) -> Arc<RwLock<Table>> {
        self.table.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressFactory, AddressSpaceType, KeyRange};
    use crate::util::task::DummyMonitor;

    struct TestAddressMap {
        space: Arc<AddressSpace>,
    }

    impl AddressMap for TestAddressMap {
        fn get_key(&self, addr: &Address, _create: bool) -> i64 {
            addr.offset()
        }

        fn get_absolute_encoding(&self, addr: &Address, _create: bool) -> i64 {
            addr.offset()
        }

        fn find_key_range(&self, _key_range_list: &[KeyRange], _addr: Option<&Address>) -> i32 {
            -1
        }

        fn decode_address(&self, value: i64) -> Address {
            self.space.address(value)
        }

        fn get_address_factory(&self) -> Option<Arc<dyn AddressFactory>> {
            None
        }

        fn get_key_ranges_absolute(
            &self,
            _start: &Address,
            _end: &Address,
            _absolute: bool,
            _create: bool,
        ) -> Vec<KeyRange> {
            Vec::new()
        }

        fn get_key_ranges_for_set_absolute(
            &self,
            _set: Option<&dyn AddressSetView>,
            _absolute: bool,
            _create: bool,
        ) -> Vec<KeyRange> {
            Vec::new()
        }

        fn get_old_address_map(&self) -> Box<dyn AddressMap> {
            Box::new(TestAddressMap {
                space: self.space.clone(),
            })
        }

        fn is_upgraded(&self) -> bool {
            false
        }

        fn get_image_base(&self) -> Address {
            self.space.address(0)
        }
    }

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    fn addr_map() -> Arc<dyn AddressMap> {
        Arc::new(TestAddressMap { space: ram_space() })
    }

    fn addr(offset: i64) -> Address {
        ram_space().address(offset)
    }

    fn new_adapter() -> (DBHandle, SymbolDatabaseAdapterV5) {
        let mut handle = DBHandle::new().unwrap();
        let adapter = SymbolDatabaseAdapterV5::new(&mut handle, addr_map(), true).unwrap();
        (handle, adapter)
    }

    #[test]
    fn create_update_and_lookup_round_trip() {
        let (_h, mut adapter) = new_adapter();
        let a = addr(0x1000);
        let rec = adapter.create_symbol_record(
            "foo",
            0,
            &a,
            SymbolType::Label,
            true,
            SourceType::UserDefined,
        );
        let key = rec.get_key().get_long_value();
        adapter.update_symbol_record(&rec).unwrap();

        assert_eq!(adapter.get_symbol_count(), 1);
        assert!(adapter.has_symbol(&a).unwrap());

        let ids = adapter.get_symbol_ids(&a).unwrap();
        assert_eq!(ids.len(), 1);

        let fetched = adapter.get_symbol_record(key).unwrap().expect("present");
        assert_eq!(fetched.get_string(SYMBOL_NAME_COL), Some("foo"));
        // update_symbol_record must (re)compute the locator hash.
        assert!(!fetched.get_field(SYMBOL_HASH_COL).is_null());
        // is_primary => primary col duplicates the address key.
        assert_eq!(fetched.get_long(SYMBOL_PRIMARY_COL), Some(0x1000));

        adapter.remove_symbol(key).unwrap();
        assert_eq!(adapter.get_symbol_count(), 0);
        assert!(!adapter.has_symbol(&a).unwrap());
    }

    #[test]
    fn create_symbol_record_skips_key_zero() {
        let (_h, adapter) = new_adapter();
        let rec = adapter.create_symbol_record(
            "first",
            0,
            &addr(0x1000),
            SymbolType::Label,
            false,
            SourceType::UserDefined,
        );
        // Key 0 is reserved for the global namespace; the very first allocated key must be 1.
        assert_eq!(rec.get_key().get_long_value(), 1);
    }

    #[test]
    fn get_symbols_by_address_orders_ascending_and_descending() {
        let (_h, mut adapter) = new_adapter();
        for (name, off) in [("c", 0x300), ("a", 0x100), ("b", 0x200)] {
            let rec = adapter.create_symbol_record(
                name,
                0,
                &addr(off),
                SymbolType::Label,
                false,
                SourceType::UserDefined,
            );
            adapter.update_symbol_record(&rec).unwrap();
        }

        let mut iter = adapter.get_symbols_by_address(true).unwrap();
        let mut names = Vec::new();
        while let Some(rec) = iter.next().unwrap() {
            names.push(rec.get_string(SYMBOL_NAME_COL).unwrap().to_string());
        }
        assert_eq!(names, vec!["a", "b", "c"]);

        let mut iter = adapter.get_symbols_by_address(false).unwrap();
        let mut names = Vec::new();
        while let Some(rec) = iter.next().unwrap() {
            names.push(rec.get_string(SYMBOL_NAME_COL).unwrap().to_string());
        }
        assert_eq!(names, vec!["c", "b", "a"]);
    }

    #[test]
    fn get_symbols_by_address_from_and_in_range() {
        let (_h, mut adapter) = new_adapter();
        for (name, off) in [("a", 0x100), ("b", 0x200), ("c", 0x300)] {
            let rec = adapter.create_symbol_record(
                name,
                0,
                &addr(off),
                SymbolType::Label,
                false,
                SourceType::UserDefined,
            );
            adapter.update_symbol_record(&rec).unwrap();
        }

        let mut iter = adapter
            .get_symbols_by_address_from(&addr(0x150), true)
            .unwrap();
        let mut names = Vec::new();
        while let Some(rec) = iter.next().unwrap() {
            names.push(rec.get_string(SYMBOL_NAME_COL).unwrap().to_string());
        }
        assert_eq!(names, vec!["b", "c"]);

        let mut iter = adapter
            .get_symbols_in_range(&addr(0x150), &addr(0x250), true)
            .unwrap();
        let mut names = Vec::new();
        while let Some(rec) = iter.next().unwrap() {
            names.push(rec.get_string(SYMBOL_NAME_COL).unwrap().to_string());
        }
        assert_eq!(names, vec!["b"]);
    }

    #[test]
    fn get_symbols_by_namespace_and_by_name() {
        let (_h, mut adapter) = new_adapter();
        let rec1 = adapter.create_symbol_record(
            "foo",
            5,
            &addr(0x100),
            SymbolType::Label,
            false,
            SourceType::UserDefined,
        );
        adapter.update_symbol_record(&rec1).unwrap();
        let rec2 = adapter.create_symbol_record(
            "bar",
            5,
            &addr(0x200),
            SymbolType::Label,
            false,
            SourceType::UserDefined,
        );
        adapter.update_symbol_record(&rec2).unwrap();
        let rec3 = adapter.create_symbol_record(
            "foo",
            6,
            &addr(0x300),
            SymbolType::Label,
            false,
            SourceType::UserDefined,
        );
        adapter.update_symbol_record(&rec3).unwrap();

        let mut ns5 = adapter.get_symbols_by_namespace(5).unwrap();
        let mut count = 0;
        while ns5.next().unwrap().is_some() {
            count += 1;
        }
        assert_eq!(count, 2);

        let mut by_name = adapter.get_symbols_by_name("foo").unwrap();
        let mut count = 0;
        while by_name.next().unwrap().is_some() {
            count += 1;
        }
        assert_eq!(count, 2);

        let mut by_both = adapter.get_symbols_by_name_and_namespace("foo", 5).unwrap();
        let first = by_both.next().unwrap().expect("one match");
        assert_eq!(first.get_long(SYMBOL_PARENT_ID_COL), Some(5));
        assert!(by_both.next().unwrap().is_none());

        // Empty name short-circuits to an empty iterator, matching Java's
        // `computeLocatorHash` -> `null` -> `EmptyRecordIterator.INSTANCE` path.
        let mut empty = adapter.get_symbols_by_name_and_namespace("", 5).unwrap();
        assert!(empty.next().unwrap().is_none());
    }

    #[test]
    fn scan_symbols_by_name_returns_sorted_suffix() {
        let (_h, mut adapter) = new_adapter();
        for name in ["alpha", "beta", "gamma", "delta"] {
            let rec = adapter.create_symbol_record(
                name,
                0,
                &addr(0x100),
                SymbolType::Label,
                false,
                SourceType::UserDefined,
            );
            adapter.update_symbol_record(&rec).unwrap();
        }
        let mut iter = adapter.scan_symbols_by_name("beta").unwrap();
        let mut names = Vec::new();
        while let Some(rec) = iter.next().unwrap() {
            names.push(rec.get_string(SYMBOL_NAME_COL).unwrap().to_string());
        }
        assert_eq!(names, vec!["beta", "delta", "gamma"]);
    }

    #[test]
    fn get_symbol_record_by_address_name_namespace_matches_exactly() {
        let (_h, mut adapter) = new_adapter();
        let rec = adapter.create_symbol_record(
            "foo",
            5,
            &addr(0x1000),
            SymbolType::Label,
            false,
            SourceType::UserDefined,
        );
        adapter.update_symbol_record(&rec).unwrap();

        let found = adapter
            .get_symbol_record_by_address_name_namespace(&addr(0x1000), "foo", 5)
            .unwrap();
        assert!(found.is_some());

        assert!(adapter
            .get_symbol_record_by_address_name_namespace(&addr(0x1000), "foo", 6)
            .unwrap()
            .is_none());
        assert!(adapter
            .get_symbol_record_by_address_name_namespace(&addr(0x1000), "", 5)
            .unwrap()
            .is_none());
    }

    #[test]
    fn primary_symbol_lookup() {
        let (_h, mut adapter) = new_adapter();
        let primary = adapter.create_symbol_record(
            "main",
            0,
            &addr(0x1000),
            SymbolType::Function,
            true,
            SourceType::UserDefined,
        );
        adapter.update_symbol_record(&primary).unwrap();
        let secondary = adapter.create_symbol_record(
            "alias",
            0,
            &addr(0x1000),
            SymbolType::Label,
            false,
            SourceType::UserDefined,
        );
        adapter.update_symbol_record(&secondary).unwrap();

        let found = adapter
            .get_primary_symbol(&addr(0x1000))
            .unwrap()
            .expect("primary symbol present");
        assert_eq!(found.get_string(SYMBOL_NAME_COL), Some("main"));

        let mut set = crate::program::model::address::AddressSet::new();
        set.add_range(&addr(0x0), &addr(0x2000));
        let mut iter = adapter.get_primary_symbols(&set, true).unwrap();
        let first = iter.next().unwrap().expect("one primary symbol");
        assert_eq!(first.get_string(SYMBOL_NAME_COL), Some("main"));
        assert!(iter.next().unwrap().is_none());
    }

    #[test]
    fn move_address_relocates_matching_symbols() {
        let (_h, mut adapter) = new_adapter();
        let rec = adapter.create_symbol_record(
            "foo",
            0,
            &addr(0x1000),
            SymbolType::Label,
            false,
            SourceType::UserDefined,
        );
        adapter.update_symbol_record(&rec).unwrap();

        adapter.move_address(&addr(0x1000), &addr(0x2000)).unwrap();
        assert!(!adapter.has_symbol(&addr(0x1000)).unwrap());
        assert!(adapter.has_symbol(&addr(0x2000)).unwrap());
    }

    #[test]
    fn delete_address_range_respects_pinned_flag() {
        let (_h, mut adapter) = new_adapter();
        let mut pinned = adapter.create_symbol_record(
            "pinned",
            0,
            &addr(0x1000),
            SymbolType::Label,
            false,
            SourceType::UserDefined,
        );
        pinned.set_byte(SYMBOL_FLAGS_COL, SYMBOL_PINNED_FLAG as i8);
        adapter.update_symbol_record(&pinned).unwrap();

        let free = adapter.create_symbol_record(
            "free",
            0,
            &addr(0x1010),
            SymbolType::Label,
            false,
            SourceType::UserDefined,
        );
        adapter.update_symbol_record(&free).unwrap();

        let anchored = adapter
            .delete_address_range(&addr(0x1000), &addr(0x2000), &DummyMonitor)
            .unwrap();

        assert_eq!(anchored, BTreeSet::from([addr(0x1000)]));
        assert!(adapter.has_symbol(&addr(0x1000)).unwrap());
        assert!(!adapter.has_symbol(&addr(0x1010)).unwrap());
        assert_eq!(adapter.get_symbol_count(), 1);
    }

    #[test]
    fn get_max_symbol_address_filters_by_space() {
        let (_h, mut adapter) = new_adapter();
        for off in [0x100, 0x300, 0x200] {
            let rec = adapter.create_symbol_record(
                "s",
                0,
                &addr(off),
                SymbolType::Label,
                false,
                SourceType::UserDefined,
            );
            adapter.update_symbol_record(&rec).unwrap();
        }
        let max = adapter
            .get_max_symbol_address(&ram_space())
            .unwrap()
            .expect("some symbol");
        assert_eq!(max, addr(0x300));

        let other_space = AddressSpace::new("other", 32, 1, AddressSpaceType::Ram, 2);
        assert!(adapter.get_max_symbol_address(&other_space).unwrap().is_none());
    }

    #[test]
    fn external_symbol_lookups() {
        let (_h, mut adapter) = new_adapter();
        let mut rec = adapter.create_symbol_record(
            "ext_func",
            0,
            &addr(0x1000),
            SymbolType::Label,
            false,
            SourceType::Imported,
        );
        rec.set_string(SYMBOL_ORIGINAL_IMPORTED_NAME_COL, Some("_ext_func".to_string()));
        rec.set_string(SYMBOL_EXTERNAL_PROG_ADDR_COL, Some(addr(0x5000).to_string()));
        adapter.update_symbol_record(&rec).unwrap();

        let mut by_import = adapter
            .get_external_symbols_by_original_import_name("_ext_func")
            .unwrap();
        assert!(by_import.next().unwrap().is_some());

        let mut by_addr = adapter
            .get_external_symbols_by_memory_address(&addr(0x5000))
            .unwrap();
        assert!(by_addr.next().unwrap().is_some());

        assert!(adapter
            .get_external_symbols_by_original_import_name("nope")
            .unwrap()
            .next()
            .unwrap()
            .is_none());
    }

    #[test]
    fn delete_external_entries_removes_unconditionally() {
        let (_h, mut adapter) = new_adapter();
        let mut pinned = adapter.create_symbol_record(
            "pinned",
            0,
            &addr(0x1000),
            SymbolType::Label,
            false,
            SourceType::UserDefined,
        );
        pinned.set_byte(SYMBOL_FLAGS_COL, SYMBOL_PINNED_FLAG as i8);
        adapter.update_symbol_record(&pinned).unwrap();

        adapter
            .delete_external_entries(&addr(0x0), &addr(0x2000))
            .unwrap();
        assert_eq!(adapter.get_symbol_count(), 0);
    }

    #[test]
    fn opening_missing_table_without_create_is_an_error() {
        let mut handle = DBHandle::new().unwrap();
        assert!(SymbolDatabaseAdapterV5::new(&mut handle, addr_map(), false).is_err());
    }

    #[test]
    fn opening_an_existing_table_reuses_records() {
        let mut handle = DBHandle::new().unwrap();
        {
            let mut adapter =
                SymbolDatabaseAdapterV5::new(&mut handle, addr_map(), true).unwrap();
            let rec = adapter.create_symbol_record(
                "x",
                0,
                &addr(0x1000),
                SymbolType::Label,
                false,
                SourceType::UserDefined,
            );
            adapter.update_symbol_record(&rec).unwrap();
        }
        let adapter = SymbolDatabaseAdapterV5::new(&mut handle, addr_map(), false).unwrap();
        assert_eq!(adapter.get_symbol_count(), 1);
    }

    #[test]
    fn wrong_schema_version_is_an_error() {
        let mut handle = DBHandle::new().unwrap();
        let old_schema = Arc::new(Schema::new(
            1,
            FieldType::Long,
            "Key".to_string(),
            vec![FieldType::String],
            vec!["Name".to_string()],
            vec![],
        ));
        handle
            .create_table(SYMBOL_TABLE_NAME.to_string(), old_schema)
            .unwrap();
        assert!(SymbolDatabaseAdapterV5::new(&mut handle, addr_map(), false).is_err());
    }

    #[test]
    fn behaves_as_trait_object() {
        let mut handle = DBHandle::new().unwrap();
        let adapter: Box<dyn SymbolDatabaseAdapter> =
            Box::new(SymbolDatabaseAdapterV5::new(&mut handle, addr_map(), true).unwrap());
        assert_eq!(adapter.get_symbol_count(), 0);
    }
}

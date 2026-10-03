//! Port of `ghidra.program.database.symbol.SymbolDatabaseAdapterV3`.
//!
//! This version introduced fast symbol lookup by namespace and name and the use of sparse table
//! columns for storing optional symbol data (hash, primary, datatype ID, variable offset) --
//! created in June 2021 with ProgramDB version 24, first in effect starting at Ghidra 10.1. Unlike
//! [`SymbolDatabaseAdapterV1`](crate::program::database::symbol::SymbolDatabaseAdapterV1)/
//! [`SymbolDatabaseAdapterV2`](crate::program::database::symbol::SymbolDatabaseAdapterV2), V3's raw
//! schema already carries real `HASH`/`PRIMARY`/`DATATYPE`/`VAROFFSET` sparse columns (matching the
//! current V5 layout's equivalents field-for-field), so [`Self::convert_v3_record`] copies them
//! straight across rather than re-deriving them from a packed "data2" column.
//!
//! Like V1/V2, this is a read-only, upgrade-path-only adapter: mutating operations
//! (`create_symbol_record`/`remove_symbol`/`update_symbol_record`/`move_address`/
//! `delete_address_range`) all panic, mirroring Java's `throw new
//! UnsupportedOperationException()`. `getExternalSymbolsByOriginalImportName`/
//! `getExternalSymbolsByMemoryAddress`, unlike V2's (which does not support import-name lookup at
//! all), are both real here, decoding V3's ad-hoc `[address][,importName]` string column via the
//! shared
//! [`convert_symbol_string_data`](crate::program::database::symbol::symbol_database_adapter_v1::convert_symbol_string_data)
//! helper.
//!
//! Java's `getSymbolsByNameAndNamespace`/`getSymbolRecord(Address, String, long)` search via a hash
//! index (`V3_SYMBOL_HASH_COL`) and then apply an exact-match filter over the candidates the hash
//! range yields; since this port's [`Table`] has no secondary-index support, this adapter instead
//! filters directly on name/namespace/address (or all three), the same "no index" convention
//! already established by `SymbolDatabaseAdapterV1`/`V5`. `getMaxSymbolAddress` is a real linear
//! scan for the same reason.

use std::io;
use std::sync::Arc;

use crate::framework::db::{DBHandle, DBRecord, Field, FieldType, RecordIterator, Schema, Table};
use crate::program::database::map::{AddressMap, INVALID_ADDRESS_KEY};
use crate::program::database::symbol::symbol_database_adapter::{
    SymbolDatabaseAdapter, SymbolDeleteAddressRangeError,
};
use crate::program::database::symbol::symbol_database_adapter_v1::convert_symbol_string_data;
use crate::program::database::symbol::symbol_database_adapter_v5::{
    schema as v5_schema, SYMBOL_ADDR_COL, SYMBOL_DATATYPE_COL, SYMBOL_FLAGS_COL, SYMBOL_HASH_COL,
    SYMBOL_NAME_COL, SYMBOL_PARENT_ID_COL, SYMBOL_PRIMARY_COL, SYMBOL_TABLE_NAME, SYMBOL_TYPE_COL,
    SYMBOL_VAROFFSET_COL,
};
use crate::program::model::address::{Address, AddressSetView, AddressSpace};
use crate::program::model::symbol::{SourceType, SymbolType};
use crate::util::exception::VersionException;
use crate::util::task::TaskMonitor;

/// Schema version implemented by this adapter.
pub const SYMBOL_VERSION: i32 = 3;

/// Column index of the symbol name (V3 raw schema).
pub const V3_SYMBOL_NAME_COL: usize = 0;
/// Column index of the symbol's address, database-key encoding (V3 raw schema).
pub const V3_SYMBOL_ADDR_COL: usize = 1;
/// Column index of the symbol's containing namespace ID (V3 raw schema).
pub const V3_SYMBOL_PARENT_ID_COL: usize = 2;
/// Column index of the symbol's [`SymbolType`] ID (V3 raw schema).
pub const V3_SYMBOL_TYPE_COL: usize = 3;
/// Column index of the ad-hoc string data column (removed with V4): external
/// `[address][,importName]` (V3 raw schema).
pub const V3_SYMBOL_STRING_DATA_COL: usize = 4;
/// Column index of the symbol's flags byte (V3 raw schema).
pub const V3_SYMBOL_FLAGS_COL: usize = 5;
/// Column index of the name/namespace/address locator hash (sparse; V3 raw schema).
pub const V3_SYMBOL_HASH_COL: usize = 6;
/// Column index of the primary-symbol marker (sparse; V3 raw schema).
pub const V3_SYMBOL_PRIMARY_COL: usize = 7;
/// Column index of the associated data type ID (sparse; external and variable symbol use; V3 raw
/// schema).
pub const V3_SYMBOL_DATATYPE_COL: usize = 8;
/// Column index of the variable ordinal/first-use offset (sparse; V3 raw schema).
pub const V3_SYMBOL_VAROFFSET_COL: usize = 9;

/// Build the legacy V3 symbol table schema, as shown in the commented-out
/// `SymbolDatabaseAdapterV3.V3_SYMBOL_SCHEMA` (removed from the live Java source, but preserved
/// there -- and here -- as documentation of the on-disk layout this adapter reads).
pub fn schema() -> Arc<Schema> {
    Arc::new(Schema::new(
        SYMBOL_VERSION,
        FieldType::Long,
        "Key".to_string(),
        vec![
            FieldType::String,
            FieldType::Long,
            FieldType::Long,
            FieldType::Byte,
            FieldType::String,
            FieldType::Byte,
            FieldType::Long,
            FieldType::Long,
            FieldType::Long,
            FieldType::Int,
        ],
        vec![
            "Name".to_string(),
            "Address".to_string(),
            "Namespace".to_string(),
            "Symbol Type".to_string(),
            "String Data".to_string(),
            "Flags".to_string(),
            "Locator Hash".to_string(),
            "Primary".to_string(),
            "Datatype".to_string(),
            "Variable Offset".to_string(),
        ],
        vec![
            V3_SYMBOL_HASH_COL,
            V3_SYMBOL_PRIMARY_COL,
            V3_SYMBOL_DATATYPE_COL,
            V3_SYMBOL_VAROFFSET_COL,
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

/// Read-only legacy adapter for symbol tables at schema version 3.
///
/// Port of `ghidra.program.database.symbol.SymbolDatabaseAdapterV3`.
pub struct SymbolDatabaseAdapterV3 {
    table: Arc<std::sync::RwLock<Table>>,
    addr_map: Arc<dyn AddressMap>,
}

impl SymbolDatabaseAdapterV3 {
    /// Constructs a version-3 symbol table adapter over an existing table.
    ///
    /// # Errors
    ///
    /// Returns a [`VersionException`] if the symbol table is missing or its schema version does
    /// not match [`SYMBOL_VERSION`].
    pub fn new(handle: &DBHandle, addr_map: Arc<dyn AddressMap>) -> Result<Self, VersionException> {
        let table = handle.get_table(SYMBOL_TABLE_NAME).ok_or_else(|| {
            VersionException::with_message(format!("Missing Table: {SYMBOL_TABLE_NAME}"))
        })?;
        let version = table.read().unwrap().get_schema().get_version();
        if version != SYMBOL_VERSION {
            if version < SYMBOL_VERSION {
                return Err(VersionException::with_upgradeable(true));
            }
            return Err(VersionException::with_version_indicator(
                VersionException::NEWER_VERSION,
                false,
            ));
        }
        Ok(SymbolDatabaseAdapterV3 { table, addr_map })
    }

    /// Returns a record matching the current (V5) database schema, translated from the version-3
    /// record. Stands in for `SymbolDatabaseAdapterV3.convertV3Record`.
    fn convert_v3_record(&self, record: &DBRecord) -> DBRecord {
        let mut rec = DBRecord::new(v5_schema(), record.get_key().clone());

        let symbol_name = record.get_string(V3_SYMBOL_NAME_COL).unwrap_or("").to_string();
        rec.set_string(SYMBOL_NAME_COL, Some(symbol_name));

        let symbol_addr_key = record.get_long(V3_SYMBOL_ADDR_COL).unwrap_or(0);
        rec.set_long(SYMBOL_ADDR_COL, symbol_addr_key);

        let namespace_id = record.get_long(V3_SYMBOL_PARENT_ID_COL).unwrap_or(0);
        rec.set_long(SYMBOL_PARENT_ID_COL, namespace_id);

        let symbol_type_id = record.get_byte(V3_SYMBOL_TYPE_COL).unwrap_or(0);
        rec.set_byte(SYMBOL_TYPE_COL, symbol_type_id);

        rec.set_byte(SYMBOL_FLAGS_COL, record.get_byte(V3_SYMBOL_FLAGS_COL).unwrap_or(0));

        // Convert sparse columns.
        convert_symbol_string_data(symbol_type_id, &mut rec, record.get_string(V3_SYMBOL_STRING_DATA_COL));

        let hash = record.get_field(V3_SYMBOL_HASH_COL);
        if !hash.is_null() {
            rec.set_field(SYMBOL_HASH_COL, hash.clone());
        }

        let primary_addr = record.get_field(V3_SYMBOL_PRIMARY_COL);
        if !primary_addr.is_null() {
            rec.set_field(SYMBOL_PRIMARY_COL, primary_addr.clone());
        }

        let data_type_id = record.get_field(V3_SYMBOL_DATATYPE_COL);
        if !data_type_id.is_null() {
            rec.set_field(SYMBOL_DATATYPE_COL, data_type_id.clone());
        }

        let var_offset = record.get_field(V3_SYMBOL_VAROFFSET_COL);
        if !var_offset.is_null() {
            rec.set_field(SYMBOL_VAROFFSET_COL, var_offset.clone());
        }

        rec
    }

    fn collect_sorted_by_address(
        &self,
        forward: bool,
        filter: impl Fn(&DBRecord, &Address) -> bool,
    ) -> io::Result<Box<dyn RecordIterator + '_>> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut entries: Vec<(Address, DBRecord)> = Vec::new();
        while let Some(rec) = iter.next()? {
            if let Some(key) = rec.get_long(V3_SYMBOL_ADDR_COL) {
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
        let records: Vec<DBRecord> = entries
            .into_iter()
            .map(|(_, rec)| self.convert_v3_record(&rec))
            .collect();
        Ok(Box::new(VecRecordIterator {
            records: records.into_iter(),
        }))
    }

    /// Extracts the ad-hoc string data column for a raw record when its address is external and
    /// its type is `LABEL`/`FUNCTION`. Stands in for the private `getExternalStringData(DBRecord)`.
    fn external_string_data(&self, rec: &DBRecord) -> Option<String> {
        let addr_key = rec.get_long(V3_SYMBOL_ADDR_COL)?;
        let addr = self.addr_map.decode_address(addr_key);
        if !addr.is_external_address() {
            return None;
        }
        let symbol_type_id = rec.get_byte(V3_SYMBOL_TYPE_COL)?;
        let label_id = SymbolType::Label.get_id() as i8;
        let function_id = SymbolType::Function.get_id() as i8;
        if symbol_type_id != function_id && symbol_type_id != label_id {
            return None;
        }
        rec.get_string(V3_SYMBOL_STRING_DATA_COL).map(str::to_string)
    }
}

impl SymbolDatabaseAdapter for SymbolDatabaseAdapterV3 {
    fn create_symbol_record(
        &self,
        _name: &str,
        _namespace_id: i64,
        _address: &Address,
        _symbol_type: SymbolType,
        _is_primary: bool,
        _source: SourceType,
    ) -> DBRecord {
        panic!("SymbolDatabaseAdapterV3 is read-only: create_symbol_record is not supported");
    }

    fn get_symbol_record(&self, symbol_id: i64) -> io::Result<Option<DBRecord>> {
        let raw = self.table.read().unwrap().get_record(&Field::Long(Some(symbol_id)))?;
        Ok(raw.map(|rec| self.convert_v3_record(&rec)))
    }

    fn remove_symbol(&mut self, _symbol_id: i64) -> io::Result<()> {
        panic!("SymbolDatabaseAdapterV3 is read-only: remove_symbol is not supported");
    }

    fn has_symbol(&self, addr: &Address) -> io::Result<bool> {
        let key = self.addr_map.get_key(addr, false);
        if key == INVALID_ADDRESS_KEY {
            return Ok(false);
        }
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        while let Some(rec) = iter.next()? {
            if rec.get_long(V3_SYMBOL_ADDR_COL) == Some(key) {
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
            if rec.get_long(V3_SYMBOL_ADDR_COL) == Some(key) {
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

    fn update_symbol_record(&mut self, _record: &DBRecord) -> io::Result<()> {
        panic!("SymbolDatabaseAdapterV3 is read-only: update_symbol_record is not supported");
    }

    fn get_symbols(&self) -> io::Result<Box<dyn RecordIterator + '_>> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut records = Vec::new();
        while let Some(rec) = iter.next()? {
            records.push(self.convert_v3_record(&rec));
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
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut entries: Vec<(Address, DBRecord)> = Vec::new();
        while let Some(rec) = iter.next()? {
            if let Field::Long(Some(primary_key)) = rec.get_field(V3_SYMBOL_PRIMARY_COL) {
                let addr = self.addr_map.decode_address(*primary_key);
                if set.contains(&addr) {
                    entries.push((addr, self.convert_v3_record(&rec)));
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

    fn get_primary_symbol(&self, address: &Address) -> io::Result<Option<DBRecord>> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        while let Some(rec) = iter.next()? {
            if let Field::Long(Some(v)) = rec.get_field(V3_SYMBOL_PRIMARY_COL) {
                if &self.addr_map.decode_address(*v) == address {
                    return Ok(Some(self.convert_v3_record(&rec)));
                }
            }
        }
        Ok(None)
    }

    fn move_address(&mut self, _old_addr: &Address, _new_addr: &Address) -> io::Result<()> {
        panic!("SymbolDatabaseAdapterV3 is read-only: move_address is not supported");
    }

    fn delete_address_range(
        &mut self,
        _start_addr: &Address,
        _end_addr: &Address,
        _monitor: &dyn TaskMonitor,
    ) -> Result<std::collections::BTreeSet<Address>, SymbolDeleteAddressRangeError> {
        panic!("SymbolDatabaseAdapterV3 is read-only: delete_address_range is not supported");
    }

    fn get_external_symbols_by_memory_address(
        &self,
        ext_prog_addr: &Address,
    ) -> io::Result<Box<dyn RecordIterator + '_>> {
        let match_addr_str = ext_prog_addr.to_string();
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut records = Vec::new();
        while let Some(rec) = iter.next()? {
            if let Some(str_data) = self.external_string_data(&rec) {
                let address_string = match str_data.find(',') {
                    Some(idx) => &str_data[..idx],
                    None => str_data.as_str(),
                };
                if address_string == match_addr_str {
                    records.push(self.convert_v3_record(&rec));
                }
            }
        }
        Ok(Box::new(VecRecordIterator {
            records: records.into_iter(),
        }))
    }

    fn get_external_symbols_by_original_import_name(
        &self,
        ext_label: &str,
    ) -> io::Result<Box<dyn RecordIterator + '_>> {
        if ext_label.trim().is_empty() {
            return Ok(Box::new(VecRecordIterator {
                records: Vec::new().into_iter(),
            }));
        }
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut records = Vec::new();
        while let Some(rec) = iter.next()? {
            if let Some(str_data) = self.external_string_data(&rec) {
                let original_imported_name = str_data.find(',').map(|idx| &str_data[idx + 1..]);
                if original_imported_name == Some(ext_label) {
                    records.push(self.convert_v3_record(&rec));
                }
            }
        }
        Ok(Box::new(VecRecordIterator {
            records: records.into_iter(),
        }))
    }

    fn get_symbols_by_namespace(&self, id: i64) -> io::Result<Box<dyn RecordIterator + '_>> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut records = Vec::new();
        while let Some(rec) = iter.next()? {
            if rec.get_long(V3_SYMBOL_PARENT_ID_COL) == Some(id) {
                records.push(self.convert_v3_record(&rec));
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
            if rec.get_string(V3_SYMBOL_NAME_COL) == Some(name) {
                records.push(self.convert_v3_record(&rec));
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
            if rec.get_string(V3_SYMBOL_NAME_COL).unwrap_or("") >= start_name {
                records.push(rec);
            }
        }
        records.sort_by(|a, b| {
            a.get_string(V3_SYMBOL_NAME_COL)
                .unwrap_or("")
                .cmp(b.get_string(V3_SYMBOL_NAME_COL).unwrap_or(""))
        });
        let converted: Vec<DBRecord> =
            records.iter().map(|rec| self.convert_v3_record(rec)).collect();
        Ok(Box::new(VecRecordIterator {
            records: converted.into_iter(),
        }))
    }

    fn get_symbols_by_name_and_namespace(
        &self,
        name: &str,
        id: i64,
    ) -> io::Result<Box<dyn RecordIterator + '_>> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut records = Vec::new();
        while let Some(rec) = iter.next()? {
            if rec.get_string(V3_SYMBOL_NAME_COL) == Some(name)
                && rec.get_long(V3_SYMBOL_PARENT_ID_COL) == Some(id)
            {
                records.push(self.convert_v3_record(&rec));
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
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        while let Some(rec) = iter.next()? {
            if rec.get_string(V3_SYMBOL_NAME_COL) == Some(name)
                && rec.get_long(V3_SYMBOL_PARENT_ID_COL) == Some(namespace_id)
                && rec.get_long(V3_SYMBOL_ADDR_COL) == Some(address_key)
            {
                return Ok(Some(self.convert_v3_record(&rec)));
            }
        }
        Ok(None)
    }

    fn get_max_symbol_address(&self, space: &AddressSpace) -> io::Result<Option<Address>> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut max: Option<Address> = None;
        while let Some(rec) = iter.next()? {
            if let Some(key) = rec.get_long(V3_SYMBOL_ADDR_COL) {
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

    fn get_table(&self) -> Arc<std::sync::RwLock<Table>> {
        panic!("SymbolDatabaseAdapterV3 is read-only: get_table is not supported");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressFactory, AddressSpaceType, KeyRange};

    struct TestAddressMap {
        space: Arc<AddressSpace>,
        external_space: Arc<AddressSpace>,
    }

    impl AddressMap for TestAddressMap {
        fn get_key(&self, addr: &Address, _create: bool) -> i64 {
            if addr.space().space_type() == AddressSpaceType::External {
                addr.offset() | (1i64 << 62)
            } else {
                addr.offset()
            }
        }

        fn get_absolute_encoding(&self, addr: &Address, _create: bool) -> i64 {
            addr.offset()
        }

        fn find_key_range(&self, _key_range_list: &[KeyRange], _addr: Option<&Address>) -> i32 {
            -1
        }

        fn decode_address(&self, value: i64) -> Address {
            if value & (1i64 << 62) != 0 {
                self.external_space.address(value & !(1i64 << 62))
            } else {
                self.space.address(value)
            }
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
                external_space: self.external_space.clone(),
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

    fn external_space() -> Arc<AddressSpace> {
        AddressSpace::new("EXTERNAL", 32, 1, AddressSpaceType::External, 2)
    }

    fn addr_map() -> Arc<dyn AddressMap> {
        Arc::new(TestAddressMap {
            space: ram_space(),
            external_space: external_space(),
        })
    }

    fn addr(offset: i64) -> Address {
        ram_space().address(offset)
    }

    #[allow(clippy::too_many_arguments)]
    fn make_v3_record(
        table: &mut Table,
        name: &str,
        address_key: i64,
        parent: i64,
        symbol_type: SymbolType,
        string_data: Option<&str>,
        flags: i8,
        hash: Option<i64>,
        primary: Option<i64>,
        datatype: Option<i64>,
        var_offset: Option<i32>,
    ) -> DBRecord {
        let key = table.get_next_key();
        let mut rec = DBRecord::new(schema(), Field::Long(Some(key)));
        rec.set_string(V3_SYMBOL_NAME_COL, Some(name.to_string()));
        rec.set_long(V3_SYMBOL_ADDR_COL, address_key);
        rec.set_long(V3_SYMBOL_PARENT_ID_COL, parent);
        rec.set_byte(V3_SYMBOL_TYPE_COL, symbol_type.get_id() as i8);
        rec.set_string(V3_SYMBOL_STRING_DATA_COL, string_data.map(str::to_string));
        rec.set_byte(V3_SYMBOL_FLAGS_COL, flags);
        if let Some(h) = hash {
            rec.set_long(V3_SYMBOL_HASH_COL, h);
        }
        if let Some(p) = primary {
            rec.set_long(V3_SYMBOL_PRIMARY_COL, p);
        }
        if let Some(dt) = datatype {
            rec.set_long(V3_SYMBOL_DATATYPE_COL, dt);
        }
        if let Some(vo) = var_offset {
            rec.set_int(V3_SYMBOL_VAROFFSET_COL, vo);
        }
        table.put_record(rec.clone()).unwrap();
        rec
    }

    fn new_handle_with_table() -> DBHandle {
        let mut handle = DBHandle::new().unwrap();
        handle.create_table(SYMBOL_TABLE_NAME.to_string(), schema()).unwrap();
        handle
    }

    #[test]
    fn opens_existing_v3_table() {
        let handle = new_handle_with_table();
        assert!(SymbolDatabaseAdapterV3::new(&handle, addr_map()).is_ok());
    }

    #[test]
    fn missing_table_is_an_error() {
        let handle = DBHandle::new().unwrap();
        assert!(SymbolDatabaseAdapterV3::new(&handle, addr_map()).is_err());
    }

    #[test]
    fn wrong_schema_version_is_an_error() {
        let mut handle = DBHandle::new().unwrap();
        let v5 = crate::program::database::symbol::symbol_database_adapter_v5::schema();
        handle.create_table(SYMBOL_TABLE_NAME.to_string(), v5).unwrap();
        assert!(SymbolDatabaseAdapterV3::new(&handle, addr_map()).is_err());
    }

    #[test]
    fn sparse_columns_are_copied_straight_across() {
        let mut handle = new_handle_with_table();
        {
            let table = handle.get_table(SYMBOL_TABLE_NAME).unwrap();
            let mut table = table.write().unwrap();
            make_v3_record(
                &mut table,
                "foo",
                0x1000,
                0,
                SymbolType::Label,
                None,
                0x9,
                Some(0xdead),
                Some(0x1000),
                Some(42),
                None,
            );
        }
        let adapter = SymbolDatabaseAdapterV3::new(&handle, addr_map()).unwrap();
        let mut iter = adapter.get_symbols().unwrap();
        let converted = iter.next().unwrap().expect("one record");
        assert_eq!(converted.get_byte(SYMBOL_FLAGS_COL), Some(0x9));
        assert_eq!(converted.get_long(SYMBOL_HASH_COL), Some(0xdead));
        assert_eq!(converted.get_long(SYMBOL_PRIMARY_COL), Some(0x1000));
        assert_eq!(converted.get_long(SYMBOL_DATATYPE_COL), Some(42));
        assert!(converted.get_field(SYMBOL_VAROFFSET_COL).is_null());
    }

    #[test]
    fn primary_symbol_lookup_uses_real_primary_column() {
        let mut handle = new_handle_with_table();
        {
            let table = handle.get_table(SYMBOL_TABLE_NAME).unwrap();
            let mut table = table.write().unwrap();
            make_v3_record(
                &mut table, "main", 0x1000, 0, SymbolType::Function, None, 0, None, Some(0x1000), None, None,
            );
            make_v3_record(
                &mut table, "alias", 0x1000, 0, SymbolType::Label, None, 0, None, None, None, None,
            );
        }
        let adapter = SymbolDatabaseAdapterV3::new(&handle, addr_map()).unwrap();
        let found = adapter.get_primary_symbol(&addr(0x1000)).unwrap().expect("primary present");
        assert_eq!(found.get_string(SYMBOL_NAME_COL), Some("main"));
    }

    #[test]
    fn external_symbol_lookups_parse_address_and_import_name() {
        let mut handle = new_handle_with_table();
        let ext_addr = Address::new(external_space(), 0);
        let ext_key = addr_map().get_key(&ext_addr, true);
        {
            let table = handle.get_table(SYMBOL_TABLE_NAME).unwrap();
            let mut table = table.write().unwrap();
            make_v3_record(
                &mut table,
                "ext_func",
                ext_key,
                0,
                SymbolType::Function,
                Some(format!("{},_ext_func", addr(0x1000)).as_str()),
                0,
                None,
                None,
                None,
                None,
            );
        }
        let adapter = SymbolDatabaseAdapterV3::new(&handle, addr_map()).unwrap();
        assert!(adapter
            .get_external_symbols_by_memory_address(&addr(0x1000))
            .unwrap()
            .next()
            .unwrap()
            .is_some());
        assert!(adapter
            .get_external_symbols_by_original_import_name("_ext_func")
            .unwrap()
            .next()
            .unwrap()
            .is_some());
        assert!(adapter
            .get_external_symbols_by_original_import_name("")
            .unwrap()
            .next()
            .unwrap()
            .is_none());
    }

    #[test]
    fn get_symbols_by_name_and_namespace_filters_exactly() {
        let mut handle = new_handle_with_table();
        {
            let table = handle.get_table(SYMBOL_TABLE_NAME).unwrap();
            let mut table = table.write().unwrap();
            make_v3_record(&mut table, "foo", 0x100, 5, SymbolType::Label, None, 0, None, None, None, None);
            make_v3_record(&mut table, "foo", 0x200, 6, SymbolType::Label, None, 0, None, None, None, None);
        }
        let adapter = SymbolDatabaseAdapterV3::new(&handle, addr_map()).unwrap();
        let mut iter = adapter.get_symbols_by_name_and_namespace("foo", 5).unwrap();
        let first = iter.next().unwrap().expect("one match");
        assert_eq!(first.get_long(SYMBOL_PARENT_ID_COL), Some(5));
        assert!(iter.next().unwrap().is_none());
    }

    #[test]
    fn get_max_symbol_address_filters_by_space() {
        let mut handle = new_handle_with_table();
        {
            let table = handle.get_table(SYMBOL_TABLE_NAME).unwrap();
            let mut table = table.write().unwrap();
            for off in [0x100, 0x300, 0x200] {
                make_v3_record(&mut table, "s", off, 0, SymbolType::Label, None, 0, None, None, None, None);
            }
        }
        let adapter = SymbolDatabaseAdapterV3::new(&handle, addr_map()).unwrap();
        let max = adapter.get_max_symbol_address(&ram_space()).unwrap().expect("some symbol");
        assert_eq!(max, addr(0x300));
    }

    #[test]
    #[should_panic(expected = "read-only")]
    fn create_symbol_record_panics() {
        let handle = new_handle_with_table();
        let adapter = SymbolDatabaseAdapterV3::new(&handle, addr_map()).unwrap();
        adapter.create_symbol_record(
            "x",
            0,
            &addr(0x1000),
            SymbolType::Label,
            false,
            SourceType::UserDefined,
        );
    }

    #[test]
    fn behaves_as_trait_object() {
        let handle = new_handle_with_table();
        let adapter: Box<dyn SymbolDatabaseAdapter> =
            Box::new(SymbolDatabaseAdapterV3::new(&handle, addr_map()).unwrap());
        assert_eq!(adapter.get_symbol_count(), 0);
    }
}

//! Port of `ghidra.program.database.symbol.SymbolDatabaseAdapterV1`.
//!
//! Read-only legacy adapter for symbol tables created before the V5 sparse-column layout (and
//! before namespaces were fully general). Every record it returns is translated on the fly into
//! the current (V5) [`DBRecord`] layout via [`Self::convert_v1_record`], matching the read-only,
//! upgrade-path-only convention already established for this project's other `V0`/`V1` "legacy"
//! adapters (e.g. `PointerDBAdapterV0`/`V1`). Mutating operations
//! (`create_symbol_record`/`remove_symbol`/`update_symbol_record`/`move_address`/
//! `delete_address_range`) and `get_table`/`get_max_symbol_address` all panic, mirroring Java's
//! `throw new UnsupportedOperationException()` for the same methods -- there is no sensible
//! recovery from calling them against a read-only legacy adapter, exactly as in Java.
//!
//! `SymbolDatabaseAdapterV0` (the version below this one) is *not* ported as a standalone type:
//! `V0` requires deferred, cross-manager upgrade machinery
//! (`extractLocalSymbols`/`SymbolManager.saveLocalSymbol`/`SymbolManager.programReady`) that has no
//! ported counterpart yet, and V0 predates general namespace/function-symbol support entirely
//! (its class doc: "handles symbol tables which were created prior to the addition of Namespace
//! support and Function symbols"). Left `TODO` for whichever future work ports `SymbolManager`'s
//! upgrade path.
//!
//! `SymbolDatabaseAdapterV3.convertSymbolStringData` (a static helper `V1.convertV1Record` calls
//! into) is reproduced locally as [`convert_symbol_string_data`] rather than ported onto a
//! `SymbolDatabaseAdapterV3` type, since `V3` itself has not been ported yet; whoever ports `V3`
//! should reuse this function rather than duplicating it (it is `pub(crate)` for that reason).

use std::io;
use std::sync::Arc;

use crate::framework::db::{DBHandle, DBRecord, Field, FieldType, RecordIterator, Schema, Table};
use crate::program::database::map::{AddressMap, INVALID_ADDRESS_KEY};
use crate::program::database::symbol::symbol_database_adapter::{
    compute_locator_hash, SymbolDatabaseAdapter, SymbolDeleteAddressRangeError,
};
use crate::program::database::symbol::symbol_database_adapter_v5::{
    schema as v5_schema, SYMBOL_ADDR_COL, SYMBOL_COMMENT_COL, SYMBOL_DATATYPE_COL,
    SYMBOL_EXTERNAL_PROG_ADDR_COL, SYMBOL_FLAGS_COL, SYMBOL_HASH_COL, SYMBOL_LIBPATH_COL,
    SYMBOL_NAME_COL, SYMBOL_ORIGINAL_IMPORTED_NAME_COL, SYMBOL_PARENT_ID_COL, SYMBOL_PRIMARY_COL,
    SYMBOL_TABLE_NAME, SYMBOL_TYPE_COL, SYMBOL_VAROFFSET_COL,
};
use crate::program::model::address::{Address, AddressSet, AddressSetView, AddressSpace};
use crate::program::model::symbol::symbol_utilities::{DefaultSymbolUtilities, SymbolUtilities};
use crate::program::model::symbol::{SourceType, SymbolType};
use crate::util::exception::VersionException;
use crate::util::task::TaskMonitor;

/// Schema version implemented by this adapter.
pub const SYMBOL_VERSION: i32 = 1;

/// Column index of the symbol name (V1 raw schema). Mirrors
/// `SymbolDatabaseAdapterV1.V1_SYMBOL_NAME_COL`.
pub const V1_SYMBOL_NAME_COL: usize = 0;
/// Column index of the symbol's address, database-key encoding (V1 raw schema). Mirrors
/// `SymbolDatabaseAdapterV1.V1_SYMBOL_ADDR_COL`.
pub const V1_SYMBOL_ADDR_COL: usize = 1;
/// Column index of the symbol's containing namespace ID (V1 raw schema). Mirrors
/// `SymbolDatabaseAdapterV1.V1_SYMBOL_PARENT_COL`.
pub const V1_SYMBOL_PARENT_COL: usize = 2;
/// Column index of the symbol's [`SymbolType`] ID (V1 raw schema). Mirrors
/// `SymbolDatabaseAdapterV1.V1_SYMBOL_TYPE_COL`.
pub const V1_SYMBOL_TYPE_COL: usize = 3;
/// Column index of "SymbolData1": variable datatype ID (V1 raw schema). Mirrors
/// `SymbolDatabaseAdapterV1.V1_SYMBOL_DATA1_COL`.
pub const V1_SYMBOL_DATA1_COL: usize = 4;
/// Column index of "SymbolData2": primary flag (for labels) or variable offset (V1 raw schema).
/// Mirrors `SymbolDatabaseAdapterV1.V1_SYMBOL_DATA2_COL`.
pub const V1_SYMBOL_DATA2_COL: usize = 5;
/// Column index of the ad-hoc string data column (V1 raw schema). Mirrors
/// `SymbolDatabaseAdapterV1.V1_SYMBOL_COMMENT_COL`.
pub const V1_SYMBOL_COMMENT_COL: usize = 6;

/// Build the legacy V1 symbol table schema, as shown in the commented-out
/// `SymbolDatabaseAdapterV1.SYMBOL_SCHEMA` (removed from the live Java source, but preserved there
/// -- and here -- as documentation of the on-disk layout this adapter reads).
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
            FieldType::Long,
            FieldType::Int,
            FieldType::String,
        ],
        vec![
            "Name".to_string(),
            "Address".to_string(),
            "Parent".to_string(),
            "Symbol Type".to_string(),
            "SymbolData1".to_string(),
            "SymbolData2".to_string(),
            "Comment".to_string(),
        ],
        vec![],
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

/// Distributes the V1/V3-era ad-hoc string data column into the correct V5 sparse column(s),
/// based on the symbol's type. Stands in for `SymbolDatabaseAdapterV3.convertSymbolStringData`.
///
/// Ad-hoc string field use/format:
///  - External location (label or function): `"[<addressStr>][,<originalImportedName>]"`
///  - Library: `[externalLibraryPath]`
///  - Variables (parameter/local): `[comment]`
pub(crate) fn convert_symbol_string_data(symbol_type_id: i8, record: &mut DBRecord, str: Option<&str>) {
    let Some(str) = str else {
        return;
    };
    if str.trim().is_empty() {
        return;
    }

    let label_id = SymbolType::Label.get_id() as i8;
    let function_id = SymbolType::Function.get_id() as i8;
    let local_var_id = SymbolType::LocalVar.get_id() as i8;
    let parameter_id = SymbolType::Parameter.get_id() as i8;
    let library_id = SymbolType::Library.get_id() as i8;

    if symbol_type_id == label_id || symbol_type_id == function_id {
        let (address_string, original_imported_name) = match str.find(',') {
            Some(idx) => (&str[..idx], Some(str[idx + 1..].to_string())),
            None => (str, None),
        };
        record.set_string(SYMBOL_EXTERNAL_PROG_ADDR_COL, Some(address_string.to_string()));
        record.set_string(SYMBOL_ORIGINAL_IMPORTED_NAME_COL, original_imported_name);
    } else if symbol_type_id == local_var_id || symbol_type_id == parameter_id {
        record.set_string(SYMBOL_COMMENT_COL, Some(str.to_string()));
    } else if symbol_type_id == library_id {
        record.set_string(SYMBOL_LIBPATH_COL, Some(str.to_string()));
    }
}

/// Read-only legacy adapter for symbol tables at schema version 1.
///
/// Port of `ghidra.program.database.symbol.SymbolDatabaseAdapterV1`.
pub struct SymbolDatabaseAdapterV1 {
    table: Arc<std::sync::RwLock<Table>>,
    addr_map: Arc<dyn AddressMap>,
}

impl SymbolDatabaseAdapterV1 {
    /// Constructs a version-1 symbol table adapter over an existing table.
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
        Ok(SymbolDatabaseAdapterV1 { table, addr_map })
    }

    /// Returns a record matching the current (V5) database schema, translated from the version-1
    /// record. Stands in for `SymbolDatabaseAdapterV1.convertV1Record`.
    fn convert_v1_record(&self, record: &DBRecord) -> DBRecord {
        let mut rec = DBRecord::new(v5_schema(), record.get_key().clone());

        let symbol_name = record.get_string(V1_SYMBOL_NAME_COL).unwrap_or("").to_string();
        rec.set_string(SYMBOL_NAME_COL, Some(symbol_name.clone()));

        let symbol_addr_key = record.get_long(V1_SYMBOL_ADDR_COL).unwrap_or(0);
        rec.set_long(SYMBOL_ADDR_COL, symbol_addr_key);

        let namespace_id = record.get_long(V1_SYMBOL_PARENT_COL).unwrap_or(0);
        rec.set_long(SYMBOL_PARENT_ID_COL, namespace_id);

        let symbol_type_id = record.get_byte(V1_SYMBOL_TYPE_COL).unwrap_or(0);
        rec.set_byte(SYMBOL_TYPE_COL, symbol_type_id);

        let mut source = SourceType::UserDefined;
        if symbol_type_id == SymbolType::Function.get_id() as i8 {
            let symbol_address = self.addr_map.decode_address(symbol_addr_key);
            let default_name = DefaultSymbolUtilities.get_default_function_name(&symbol_address);
            if symbol_name == default_name {
                source = SourceType::Default;
            }
        }
        // NOTE: matches real Ghidra byte-for-byte, including what looks like a latent bug: Java
        // stores the raw enum `ordinal()` here (`(byte) source.ordinal()`) instead of running it
        // through the bit-split `storageId`-based encoding that `decodeSourceTypeFromFlags`
        // expects (the scheme every V4+ record actually uses, and the one `create_symbol_record`
        // above correctly uses via `get_source_type_flags_bits`). Since `SourceType::UserDefined`
        // has ordinal 4 but storage ID 1, a V1 symbol upgraded through this path with `source ==
        // UserDefined` round-trips through `decode_source_type_from_flags` as `Analysis` instead.
        // Preserved as-is since this is what real Ghidra's upgrade path actually produces;
        // "fixing" it here would silently diverge this port from the artifact Java produces when
        // opening an ancient V1 database.
        rec.set_byte(SYMBOL_FLAGS_COL, source as i8);

        // Convert sparse columns.
        convert_symbol_string_data(
            symbol_type_id,
            &mut rec,
            record.get_string(V1_SYMBOL_COMMENT_COL),
        );

        let data_type_id = record.get_long(V1_SYMBOL_DATA1_COL).unwrap_or(-1);
        if data_type_id != -1 {
            rec.set_long(SYMBOL_DATATYPE_COL, data_type_id);
        }

        let symbol_type = SymbolType::from_id(symbol_type_id as i32);
        let data2 = record.get_int(V1_SYMBOL_DATA2_COL).unwrap_or(0);
        // The data1 field was used in two ways for label symbols: it stored a 1 for primary and 0
        // for non-primary. If the type was a parameter or variable, it stored the ordinal or
        // first-use offset respectively.
        if symbol_type == Some(SymbolType::Label) {
            if data2 == 1 {
                rec.set_long(SYMBOL_PRIMARY_COL, symbol_addr_key);
            }
        } else if symbol_type == Some(SymbolType::Parameter) || symbol_type == Some(SymbolType::LocalVar) {
            rec.set_int(SYMBOL_VAROFFSET_COL, data2);
        }

        // Also need to store primary for functions.
        if symbol_type == Some(SymbolType::Function) {
            rec.set_long(SYMBOL_PRIMARY_COL, symbol_addr_key);
        }

        let hash_field = match compute_locator_hash(&symbol_name, namespace_id, symbol_addr_key) {
            Some(hash) => Field::Long(Some(hash)),
            None => Field::Long(None),
        };
        rec.set_field(SYMBOL_HASH_COL, hash_field);

        rec
    }

    /// Collects, decodes (via the raw `V1_SYMBOL_ADDR_COL`), converts, and address-sorts every
    /// raw record for which `filter` returns `true`. Backs the several by-address/range/set
    /// iteration methods below.
    fn collect_sorted_by_address(
        &self,
        forward: bool,
        filter: impl Fn(&DBRecord, &Address) -> bool,
    ) -> io::Result<Box<dyn RecordIterator + '_>> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut entries: Vec<(Address, DBRecord)> = Vec::new();
        while let Some(rec) = iter.next()? {
            if let Some(key) = rec.get_long(V1_SYMBOL_ADDR_COL) {
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
            .map(|(_, rec)| self.convert_v1_record(&rec))
            .collect();
        Ok(Box::new(VecRecordIterator {
            records: records.into_iter(),
        }))
    }
}

impl SymbolDatabaseAdapter for SymbolDatabaseAdapterV1 {
    fn create_symbol_record(
        &self,
        _name: &str,
        _namespace_id: i64,
        _address: &Address,
        _symbol_type: SymbolType,
        _is_primary: bool,
        _source: SourceType,
    ) -> DBRecord {
        panic!("SymbolDatabaseAdapterV1 is read-only: create_symbol_record is not supported");
    }

    fn get_symbol_record(&self, symbol_id: i64) -> io::Result<Option<DBRecord>> {
        let raw = self.table.read().unwrap().get_record(&Field::Long(Some(symbol_id)))?;
        Ok(raw.map(|rec| self.convert_v1_record(&rec)))
    }

    fn remove_symbol(&mut self, _symbol_id: i64) -> io::Result<()> {
        panic!("SymbolDatabaseAdapterV1 is read-only: remove_symbol is not supported");
    }

    fn has_symbol(&self, addr: &Address) -> io::Result<bool> {
        let key = self.addr_map.get_key(addr, false);
        if key == INVALID_ADDRESS_KEY {
            return Ok(false);
        }
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        while let Some(rec) = iter.next()? {
            if rec.get_long(V1_SYMBOL_ADDR_COL) == Some(key) {
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
            if rec.get_long(V1_SYMBOL_ADDR_COL) == Some(key) {
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
        panic!("SymbolDatabaseAdapterV1 is read-only: update_symbol_record is not supported");
    }

    fn get_symbols(&self) -> io::Result<Box<dyn RecordIterator + '_>> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut records = Vec::new();
        while let Some(rec) = iter.next()? {
            records.push(self.convert_v1_record(&rec));
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
        // Filtering for "primary" must happen on the *converted* record (V1's raw schema has no
        // primary column of its own -- primary-ness is derived during conversion from the
        // "SymbolData2" flag / symbol type), so this can't reuse `collect_sorted_by_address`'s
        // filter (which only sees the raw record).
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut entries: Vec<(Address, DBRecord)> = Vec::new();
        while let Some(rec) = iter.next()? {
            if let Some(key) = rec.get_long(V1_SYMBOL_ADDR_COL) {
                let addr = self.addr_map.decode_address(key);
                if !set.contains(&addr) {
                    continue;
                }
                let converted = self.convert_v1_record(&rec);
                if !converted.get_field(SYMBOL_PRIMARY_COL).is_null() {
                    entries.push((addr, converted));
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
        let set = AddressSet::from_address(address.clone());
        let mut iter = self.get_primary_symbols(&set, true)?;
        iter.next()
    }

    fn move_address(&mut self, _old_addr: &Address, _new_addr: &Address) -> io::Result<()> {
        panic!("SymbolDatabaseAdapterV1 is read-only: move_address is not supported");
    }

    fn delete_address_range(
        &mut self,
        _start_addr: &Address,
        _end_addr: &Address,
        _monitor: &dyn TaskMonitor,
    ) -> Result<std::collections::BTreeSet<Address>, SymbolDeleteAddressRangeError> {
        panic!("SymbolDatabaseAdapterV1 is read-only: delete_address_range is not supported");
    }

    fn get_external_symbols_by_memory_address(
        &self,
        _ext_prog_addr: &Address,
    ) -> io::Result<Box<dyn RecordIterator + '_>> {
        // External symbols were not supported at schema version 1.
        Ok(Box::new(VecRecordIterator {
            records: Vec::new().into_iter(),
        }))
    }

    fn get_external_symbols_by_original_import_name(
        &self,
        _ext_label: &str,
    ) -> io::Result<Box<dyn RecordIterator + '_>> {
        // External symbols were not supported at schema version 1.
        Ok(Box::new(VecRecordIterator {
            records: Vec::new().into_iter(),
        }))
    }

    fn get_symbols_by_namespace(&self, id: i64) -> io::Result<Box<dyn RecordIterator + '_>> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut records = Vec::new();
        while let Some(rec) = iter.next()? {
            if rec.get_long(V1_SYMBOL_PARENT_COL) == Some(id) {
                records.push(self.convert_v1_record(&rec));
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
            if rec.get_string(V1_SYMBOL_NAME_COL) == Some(name) {
                records.push(self.convert_v1_record(&rec));
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
            if rec.get_string(V1_SYMBOL_NAME_COL).unwrap_or("") >= start_name {
                records.push(rec);
            }
        }
        records.sort_by(|a, b| {
            a.get_string(V1_SYMBOL_NAME_COL)
                .unwrap_or("")
                .cmp(b.get_string(V1_SYMBOL_NAME_COL).unwrap_or(""))
        });
        let converted: Vec<DBRecord> =
            records.iter().map(|rec| self.convert_v1_record(rec)).collect();
        Ok(Box::new(VecRecordIterator {
            records: converted.into_iter(),
        }))
    }

    fn get_symbols_by_name_and_namespace(
        &self,
        name: &str,
        id: i64,
    ) -> io::Result<Box<dyn RecordIterator + '_>> {
        let mut by_name = self.get_symbols_by_name(name)?;
        let mut records = Vec::new();
        while let Some(rec) = by_name.next()? {
            if rec.get_long(SYMBOL_PARENT_ID_COL) == Some(id) {
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
        let mut by_name = self.get_symbols_by_name(name)?;
        while let Some(rec) = by_name.next()? {
            if rec.get_long(SYMBOL_PARENT_ID_COL) == Some(namespace_id)
                && rec.get_long(SYMBOL_ADDR_COL) == Some(address_key)
            {
                return Ok(Some(rec));
            }
        }
        Ok(None)
    }

    fn get_max_symbol_address(&self, _space: &AddressSpace) -> io::Result<Option<Address>> {
        panic!("SymbolDatabaseAdapterV1 is read-only: get_max_symbol_address is not supported");
    }

    fn get_table(&self) -> Arc<std::sync::RwLock<Table>> {
        panic!("SymbolDatabaseAdapterV1 is read-only: get_table is not supported");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressFactory, AddressSpaceType, KeyRange};

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

    fn make_v1_record(
        table: &mut Table,
        name: &str,
        address_key: i64,
        parent: i64,
        symbol_type: SymbolType,
        data1: i64,
        data2: i32,
        comment: Option<&str>,
    ) -> DBRecord {
        let key = table.get_next_key();
        let mut rec = DBRecord::new(schema(), Field::Long(Some(key)));
        rec.set_string(V1_SYMBOL_NAME_COL, Some(name.to_string()));
        rec.set_long(V1_SYMBOL_ADDR_COL, address_key);
        rec.set_long(V1_SYMBOL_PARENT_COL, parent);
        rec.set_byte(V1_SYMBOL_TYPE_COL, symbol_type.get_id() as i8);
        rec.set_long(V1_SYMBOL_DATA1_COL, data1);
        rec.set_int(V1_SYMBOL_DATA2_COL, data2);
        rec.set_string(V1_SYMBOL_COMMENT_COL, comment.map(str::to_string));
        table.put_record(rec.clone()).unwrap();
        rec
    }

    fn new_handle_with_table() -> DBHandle {
        let mut handle = DBHandle::new().unwrap();
        handle.create_table(SYMBOL_TABLE_NAME.to_string(), schema()).unwrap();
        handle
    }

    #[test]
    fn opens_existing_v1_table() {
        let handle = new_handle_with_table();
        assert!(SymbolDatabaseAdapterV1::new(&handle, addr_map()).is_ok());
    }

    #[test]
    fn missing_table_is_an_error() {
        let handle = DBHandle::new().unwrap();
        assert!(SymbolDatabaseAdapterV1::new(&handle, addr_map()).is_err());
    }

    #[test]
    fn wrong_schema_version_is_an_error() {
        let mut handle = DBHandle::new().unwrap();
        let v5 = crate::program::database::symbol::symbol_database_adapter_v5::schema();
        handle.create_table(SYMBOL_TABLE_NAME.to_string(), v5).unwrap();
        assert!(SymbolDatabaseAdapterV1::new(&handle, addr_map()).is_err());
    }

    #[test]
    fn convert_basic_label_record() {
        let mut handle = new_handle_with_table();
        {
            let table = handle.get_table(SYMBOL_TABLE_NAME).unwrap();
            let mut table = table.write().unwrap();
            make_v1_record(&mut table, "foo", 0x1000, 0, SymbolType::Label, -1, 1, None);
        }
        let adapter = SymbolDatabaseAdapterV1::new(&handle, addr_map()).unwrap();
        assert_eq!(adapter.get_symbol_count(), 1);
        assert!(adapter.has_symbol(&addr(0x1000)).unwrap());

        let ids = adapter.get_symbol_ids(&addr(0x1000)).unwrap();
        assert_eq!(ids.len(), 1);
        let key = ids[0].get_long_value();
        let converted = adapter.get_symbol_record(key).unwrap().expect("present");
        assert_eq!(converted.get_string(SYMBOL_NAME_COL), Some("foo"));
        assert_eq!(converted.get_long(SYMBOL_ADDR_COL), Some(0x1000));
        // data2 == 1 means primary for a LABEL symbol.
        assert_eq!(converted.get_long(SYMBOL_PRIMARY_COL), Some(0x1000));
        assert!(!converted.get_field(SYMBOL_HASH_COL).is_null());
        // No datatype was set (-1 sentinel).
        assert!(converted.get_field(SYMBOL_DATATYPE_COL).is_null());
    }

    #[test]
    fn convert_non_primary_label_has_no_primary_marker() {
        let mut handle = new_handle_with_table();
        {
            let table = handle.get_table(SYMBOL_TABLE_NAME).unwrap();
            let mut table = table.write().unwrap();
            make_v1_record(&mut table, "bar", 0x2000, 0, SymbolType::Label, -1, 0, None);
        }
        let adapter = SymbolDatabaseAdapterV1::new(&handle, addr_map()).unwrap();
        let mut iter = adapter.get_symbols().unwrap();
        let converted = iter.next().unwrap().expect("one record");
        assert!(converted.get_field(SYMBOL_PRIMARY_COL).is_null());
    }

    #[test]
    fn convert_function_symbol_is_always_primary() {
        let mut handle = new_handle_with_table();
        {
            let table = handle.get_table(SYMBOL_TABLE_NAME).unwrap();
            let mut table = table.write().unwrap();
            make_v1_record(&mut table, "main", 0x1000, 0, SymbolType::Function, -1, 0, None);
        }
        let adapter = SymbolDatabaseAdapterV1::new(&handle, addr_map()).unwrap();
        let mut iter = adapter.get_symbols().unwrap();
        let converted = iter.next().unwrap().expect("one record");
        assert_eq!(converted.get_long(SYMBOL_PRIMARY_COL), Some(0x1000));
    }

    #[test]
    fn convert_variable_symbol_stores_offset_and_comment() {
        let mut handle = new_handle_with_table();
        {
            let table = handle.get_table(SYMBOL_TABLE_NAME).unwrap();
            let mut table = table.write().unwrap();
            make_v1_record(
                &mut table,
                "local_x",
                0x1000,
                7,
                SymbolType::LocalVar,
                -1,
                4,
                Some("a local variable"),
            );
        }
        let adapter = SymbolDatabaseAdapterV1::new(&handle, addr_map()).unwrap();
        let mut iter = adapter.get_symbols().unwrap();
        let converted = iter.next().unwrap().expect("one record");
        assert_eq!(converted.get_int(SYMBOL_VAROFFSET_COL), Some(4));
        assert_eq!(converted.get_string(SYMBOL_COMMENT_COL), Some("a local variable"));
        assert_eq!(converted.get_long(SYMBOL_PARENT_ID_COL), Some(7));
    }

    #[test]
    fn convert_datatype_id_is_carried_over_unless_sentinel() {
        let mut handle = new_handle_with_table();
        {
            let table = handle.get_table(SYMBOL_TABLE_NAME).unwrap();
            let mut table = table.write().unwrap();
            make_v1_record(&mut table, "typed", 0x1000, 0, SymbolType::Label, 42, 0, None);
        }
        let adapter = SymbolDatabaseAdapterV1::new(&handle, addr_map()).unwrap();
        let mut iter = adapter.get_symbols().unwrap();
        let converted = iter.next().unwrap().expect("one record");
        assert_eq!(converted.get_long(SYMBOL_DATATYPE_COL), Some(42));
    }

    #[test]
    fn convert_label_string_data_becomes_external_addr_and_import_name() {
        let mut handle = new_handle_with_table();
        {
            let table = handle.get_table(SYMBOL_TABLE_NAME).unwrap();
            let mut table = table.write().unwrap();
            make_v1_record(
                &mut table,
                "ext_sym",
                0x1000,
                0,
                SymbolType::Label,
                -1,
                0,
                Some("ram:00001000,_original"),
            );
        }
        let adapter = SymbolDatabaseAdapterV1::new(&handle, addr_map()).unwrap();
        let mut iter = adapter.get_symbols().unwrap();
        let converted = iter.next().unwrap().expect("one record");
        assert_eq!(
            converted.get_string(SYMBOL_EXTERNAL_PROG_ADDR_COL),
            Some("ram:00001000")
        );
        assert_eq!(
            converted.get_string(SYMBOL_ORIGINAL_IMPORTED_NAME_COL),
            Some("_original")
        );
    }

    #[test]
    fn convert_library_string_data_becomes_libpath() {
        let mut handle = new_handle_with_table();
        {
            let table = handle.get_table(SYMBOL_TABLE_NAME).unwrap();
            let mut table = table.write().unwrap();
            make_v1_record(
                &mut table,
                "MYLIB",
                0x0,
                0,
                SymbolType::Library,
                -1,
                0,
                Some("/usr/lib/mylib.so"),
            );
        }
        let adapter = SymbolDatabaseAdapterV1::new(&handle, addr_map()).unwrap();
        let mut iter = adapter.get_symbols().unwrap();
        let converted = iter.next().unwrap().expect("one record");
        assert_eq!(converted.get_string(SYMBOL_LIBPATH_COL), Some("/usr/lib/mylib.so"));
    }

    #[test]
    fn get_symbols_by_address_orders_and_converts() {
        let mut handle = new_handle_with_table();
        {
            let table = handle.get_table(SYMBOL_TABLE_NAME).unwrap();
            let mut table = table.write().unwrap();
            make_v1_record(&mut table, "c", 0x300, 0, SymbolType::Label, -1, 0, None);
            make_v1_record(&mut table, "a", 0x100, 0, SymbolType::Label, -1, 0, None);
            make_v1_record(&mut table, "b", 0x200, 0, SymbolType::Label, -1, 0, None);
        }
        let adapter = SymbolDatabaseAdapterV1::new(&handle, addr_map()).unwrap();
        let mut iter = adapter.get_symbols_by_address(true).unwrap();
        let mut names = Vec::new();
        while let Some(rec) = iter.next().unwrap() {
            names.push(rec.get_string(SYMBOL_NAME_COL).unwrap().to_string());
        }
        assert_eq!(names, vec!["a", "b", "c"]);
    }

    #[test]
    fn get_symbols_by_namespace_and_by_name() {
        let mut handle = new_handle_with_table();
        {
            let table = handle.get_table(SYMBOL_TABLE_NAME).unwrap();
            let mut table = table.write().unwrap();
            make_v1_record(&mut table, "foo", 0x100, 5, SymbolType::Label, -1, 0, None);
            make_v1_record(&mut table, "bar", 0x200, 5, SymbolType::Label, -1, 0, None);
            make_v1_record(&mut table, "foo", 0x300, 6, SymbolType::Label, -1, 0, None);
        }
        let adapter = SymbolDatabaseAdapterV1::new(&handle, addr_map()).unwrap();

        let mut ns5 = adapter.get_symbols_by_namespace(5).unwrap();
        let mut count = 0;
        while ns5.next().unwrap().is_some() {
            count += 1;
        }
        assert_eq!(count, 2);

        let mut by_both = adapter.get_symbols_by_name_and_namespace("foo", 5).unwrap();
        let first = by_both.next().unwrap().expect("one match");
        assert_eq!(first.get_long(SYMBOL_PARENT_ID_COL), Some(5));
        assert!(by_both.next().unwrap().is_none());
    }

    #[test]
    fn get_symbol_record_by_address_name_namespace_matches_exactly() {
        let mut handle = new_handle_with_table();
        {
            let table = handle.get_table(SYMBOL_TABLE_NAME).unwrap();
            let mut table = table.write().unwrap();
            make_v1_record(&mut table, "foo", 0x1000, 5, SymbolType::Label, -1, 0, None);
        }
        let adapter = SymbolDatabaseAdapterV1::new(&handle, addr_map()).unwrap();
        assert!(adapter
            .get_symbol_record_by_address_name_namespace(&addr(0x1000), "foo", 5)
            .unwrap()
            .is_some());
        assert!(adapter
            .get_symbol_record_by_address_name_namespace(&addr(0x1000), "foo", 6)
            .unwrap()
            .is_none());
    }

    #[test]
    fn primary_symbol_lookup() {
        let mut handle = new_handle_with_table();
        {
            let table = handle.get_table(SYMBOL_TABLE_NAME).unwrap();
            let mut table = table.write().unwrap();
            make_v1_record(&mut table, "main", 0x1000, 0, SymbolType::Function, -1, 0, None);
            make_v1_record(&mut table, "alias", 0x1000, 0, SymbolType::Label, -1, 0, None);
        }
        let adapter = SymbolDatabaseAdapterV1::new(&handle, addr_map()).unwrap();
        let found = adapter
            .get_primary_symbol(&addr(0x1000))
            .unwrap()
            .expect("primary symbol present");
        assert_eq!(found.get_string(SYMBOL_NAME_COL), Some("main"));
    }

    #[test]
    fn external_symbol_lookups_are_always_empty() {
        let handle = new_handle_with_table();
        let adapter = SymbolDatabaseAdapterV1::new(&handle, addr_map()).unwrap();
        assert!(adapter
            .get_external_symbols_by_original_import_name("x")
            .unwrap()
            .next()
            .unwrap()
            .is_none());
        assert!(adapter
            .get_external_symbols_by_memory_address(&addr(0x1000))
            .unwrap()
            .next()
            .unwrap()
            .is_none());
    }

    #[test]
    #[should_panic(expected = "read-only")]
    fn create_symbol_record_panics() {
        let handle = new_handle_with_table();
        let adapter = SymbolDatabaseAdapterV1::new(&handle, addr_map()).unwrap();
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
    #[should_panic(expected = "read-only")]
    fn get_table_panics() {
        let handle = new_handle_with_table();
        let adapter = SymbolDatabaseAdapterV1::new(&handle, addr_map()).unwrap();
        let _ = adapter.get_table();
    }

    #[test]
    fn behaves_as_trait_object() {
        let handle = new_handle_with_table();
        let adapter: Box<dyn SymbolDatabaseAdapter> =
            Box::new(SymbolDatabaseAdapterV1::new(&handle, addr_map()).unwrap());
        assert_eq!(adapter.get_symbol_count(), 0);
    }
}

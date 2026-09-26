//! Port of `ghidra.program.database.symbol.SymbolDatabaseAdapterV0`.
//!
//! Read-only legacy adapter for symbol tables created before namespace support and function
//! symbols existed at all. As in Java, `V0` is far more restrictive than
//! [`SymbolDatabaseAdapterV1`](crate::program::database::symbol::SymbolDatabaseAdapterV1): several
//! methods that V1 implements for real (`has_symbol`, `get_symbol_ids`) are `panic!`s here too,
//! mirroring Java's `throw new UnsupportedOperationException()` for those same methods on `V0`
//! specifically (not just the always-unsupported mutating operations every legacy adapter in this
//! family refuses).
//!
//! Every record this adapter returns is translated on the fly into the current (V5) [`DBRecord`]
//! layout via [`SymbolDatabaseAdapterV0::convert_v0_record`], reproducing
//! `SymbolDatabaseAdapterV0.convertV0Record`: every V0 symbol becomes a global-namespace
//! [`SymbolType::Label`] with [`SourceType::UserDefined`] source (V0 predates function symbols),
//! and inherits the same "raw ordinal instead of the bit-split encoding" quirk already documented
//! on `SymbolDatabaseAdapterV1::convert_v1_record` (`SourceType::UserDefined as i8` is stored
//! directly rather than routed through
//! [`get_source_type_flags_bits`](crate::program::database::symbol::get_source_type_flags_bits)).
//!
//! Two more real Java quirks are reproduced faithfully rather than silently fixed (each with a
//! test proving the resulting always-empty/always-`None` behavior):
//! - [`SymbolDatabaseAdapterV0::get_primary_symbols`] (and, since it delegates,
//!   `get_primary_symbol`) index on the *current*-schema `SYMBOL_ADDR_COL` (column 1) instead of
//!   this class's own `V0_SYMBOL_ADDR_COL` (column 4). In the V0 raw schema, column 1 is "Is
//!   Dynamic" (a `Boolean`), not the address (a `Long`), so the lookup can never resolve an
//!   address and always yields zero records, regardless of what primary symbols actually exist.
//! - [`SymbolDatabaseAdapterV0::get_symbol_record_by_address_name_namespace`] filters the *raw*,
//!   unconverted V0 record using the current schema's `SYMBOL_PARENT_ID_COL` (2) /
//!   `SYMBOL_ADDR_COL` (1), which in the V0 raw schema are "Is Local" / "Is Dynamic" (`Boolean`,
//!   not `Long`). The comparisons can never match, so this always returns `None`.
//!
//! [`SymbolDatabaseAdapterV0::get_symbols_by_namespace`] returns an iterator only for
//! `Namespace::GLOBAL_NAMESPACE_ID`; for any other id, real Java returns `null` (V0 predates
//! namespace support, so no non-global namespace can exist in a V0 database, and every real caller
//! in `SymbolManager` unconditionally dereferences the result). Since this trait's return type
//! isn't nullable, that branch panics instead -- the closest honest translation of an
//! unconditionally-dereferenced `null`.
//!
//! `SymbolDatabaseAdapterV0::extract_local_symbols` (stands in for the package-private
//! `SymbolDatabaseAdapterV0.extractLocalSymbols`, called only from the not-yet-ported
//! `SymbolDatabaseAdapter.upgrade`/`copyToTempAndFixupRecords`) is only partially portable: real
//! Ghidra calls `SymbolManager.saveLocalSymbol` for every local symbol it finds, and neither that
//! method nor `SymbolManager.programReady` (which later finishes the V0 upgrade using the data
//! `saveLocalSymbol` stashed away) has a Rust counterpart yet -- `symbol_manager.rs` has no
//! equivalent. This port implements everything up to that call for real (monitor progress,
//! cancellation, iteration), but returns [`ExtractLocalSymbolsError::Unported`] instead of silently
//! dropping the local symbol's data the moment one is actually encountered, so a V0 database with
//! no local symbols upgrades cleanly today while one that needs the unported machinery fails loudly
//! rather than silently losing data.

use std::io;
use std::sync::{Arc, RwLock};

use crate::framework::db::{DBHandle, DBRecord, Field, FieldType, RecordIterator, Schema, Table};
use crate::program::database::map::AddressMap;
use crate::program::database::symbol::symbol_database_adapter::{
    compute_locator_hash, SymbolDatabaseAdapter, SymbolDeleteAddressRangeError,
};
use crate::program::database::symbol::symbol_database_adapter_v5::{
    schema as v5_schema, SYMBOL_ADDR_COL, SYMBOL_FLAGS_COL, SYMBOL_HASH_COL, SYMBOL_NAME_COL,
    SYMBOL_PARENT_ID_COL, SYMBOL_PRIMARY_COL, SYMBOL_TABLE_NAME, SYMBOL_TYPE_COL,
};
use crate::program::model::address::{Address, AddressSet, AddressSetView, AddressSpace};
use crate::program::model::symbol::{SourceType, SymbolType, GLOBAL_NAMESPACE_ID};
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// Schema version implemented by this adapter.
pub const SYMBOL_VERSION: i32 = 0;

/// Column index of the symbol name (V0 raw schema). Mirrors
/// `SymbolDatabaseAdapterV0.V0_SYMBOL_NAME_COL`.
pub const V0_SYMBOL_NAME_COL: usize = 0;
/// Column index of the "is dynamic" flag (V0 raw schema). Mirrors
/// `SymbolDatabaseAdapterV0.V0_SYMBOL_IS_DYNAMIC_COL`.
pub const V0_SYMBOL_IS_DYNAMIC_COL: usize = 1;
/// Column index of the "is local" flag (V0 raw schema). Mirrors
/// `SymbolDatabaseAdapterV0.V0_SYMBOL_LOCAL_COL`.
pub const V0_SYMBOL_LOCAL_COL: usize = 2;
/// Column index of the "is primary" flag (V0 raw schema). Mirrors
/// `SymbolDatabaseAdapterV0.V0_SYMBOL_PRIMARY_COL`.
pub const V0_SYMBOL_PRIMARY_COL: usize = 3;
/// Column index of the symbol's address, database-key encoding (V0 raw schema). Mirrors
/// `SymbolDatabaseAdapterV0.V0_SYMBOL_ADDR_COL`.
pub const V0_SYMBOL_ADDR_COL: usize = 4;

/// Build the legacy V0 symbol table schema, as shown in the commented-out
/// `SymbolDatabaseAdapterV0.SYMBOL_SCHEMA` (removed from the live Java source, but preserved there
/// -- and here -- as documentation of the on-disk layout this adapter reads).
pub fn schema() -> Arc<Schema> {
    Arc::new(Schema::new(
        SYMBOL_VERSION,
        FieldType::Long,
        "Key".to_string(),
        vec![
            FieldType::String,
            FieldType::Boolean,
            FieldType::Boolean,
            FieldType::Boolean,
            FieldType::Long,
        ],
        vec![
            "Name".to_string(),
            "Is Dynamic".to_string(),
            "Is Local".to_string(),
            "Is Primary".to_string(),
            "Address".to_string(),
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

/// Error returned by [`SymbolDatabaseAdapterV0::extract_local_symbols`], mirroring the Java
/// method's `throws IOException, CancelledException`, plus an [`ExtractLocalSymbolsError::Unported`]
/// variant for the genuinely-not-yet-portable case (see the module docs).
#[derive(Debug, thiserror::Error)]
pub enum ExtractLocalSymbolsError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Cancelled(#[from] CancelledException),
    #[error(
        "cannot extract local symbol (key={key}): SymbolManager::save_local_symbol has not been \
         ported to Rust yet (see the TODO(port) in SymbolDatabaseAdapterV0::extract_local_symbols)"
    )]
    Unported { key: i64 },
}

/// Read-only legacy adapter for symbol tables at schema version 0.
///
/// Port of `ghidra.program.database.symbol.SymbolDatabaseAdapterV0`. See the module docs for the
/// real Java quirks reproduced here and the one genuinely-unported method.
pub struct SymbolDatabaseAdapterV0 {
    table: Arc<RwLock<Table>>,
    addr_map: Arc<dyn AddressMap>,
}

impl SymbolDatabaseAdapterV0 {
    /// Constructs a version-0 symbol table adapter over an existing table.
    ///
    /// # Errors
    ///
    /// Returns a [`VersionException`] if the symbol table is missing or its schema version does
    /// not match [`SYMBOL_VERSION`].
    pub fn new(
        handle: &DBHandle,
        addr_map: Arc<dyn AddressMap>,
    ) -> Result<Self, crate::util::exception::VersionException> {
        use crate::util::exception::VersionException;

        let table = handle.get_table(SYMBOL_TABLE_NAME).ok_or_else(|| {
            VersionException::with_message(format!("Missing Table: {SYMBOL_TABLE_NAME}"))
        })?;
        let version = table.read().unwrap().get_schema().get_version();
        if version != SYMBOL_VERSION {
            // Matches Java: `throw new VersionException(false);` unconditionally (V0 is the oldest
            // version, so any mismatch here isn't "upgradeable from V0's point of view").
            return Err(VersionException::with_upgradeable(false));
        }
        let old_addr_map: Arc<dyn AddressMap> = Arc::from(addr_map.get_old_address_map());
        Ok(SymbolDatabaseAdapterV0 {
            table,
            addr_map: old_addr_map,
        })
    }

    /// Stores local-symbol information (key, address, name, is-primary) so the deferred V0 upgrade
    /// can complete once cross-manager context is available. See the module docs for why this can
    /// currently only be implemented up to that point.
    ///
    /// # Errors
    ///
    /// Returns [`ExtractLocalSymbolsError::Cancelled`]/`Io` mirroring Java's `throws
    /// CancelledException, IOException`, or [`ExtractLocalSymbolsError::Unported`] if a local
    /// symbol is actually encountered (see the module docs).
    pub fn extract_local_symbols(
        &self,
        monitor: &dyn TaskMonitor,
    ) -> Result<i64, ExtractLocalSymbolsError> {
        monitor.set_message("Extracting Local Symbols...");
        let table = self.table.read().unwrap();
        monitor.initialize(table.get_record_count() as i64);
        let mut cnt: i64 = 0;
        let mut iter = table.get_record_iterator()?;
        while let Some(rec) = iter.next()? {
            monitor.check_cancelled()?;
            if rec.get_bool(V0_SYMBOL_LOCAL_COL) == Some(true) {
                // TODO(port): SymbolManager::save_local_symbol has not been ported to Rust yet
                // (symbol_manager.rs has no counterpart to
                // ghidra.program.database.symbol.SymbolManager.saveLocalSymbol/programReady). Real
                // Ghidra would persist (key, address, name, isPrimary) into a scratch table here so
                // `SymbolManager.programReady()` can finish the V0 upgrade later; until that lands,
                // surface the blocker instead of silently dropping the local symbol's data.
                let key = rec.get_key().get_long_value();
                return Err(ExtractLocalSymbolsError::Unported { key });
            }
            cnt += 1;
            monitor.set_progress(cnt);
        }
        Ok(table.peek_next_key())
    }

    /// Returns a record matching the current (V5) database schema, translated from the version-0
    /// record. Stands in for `SymbolDatabaseAdapterV0.convertV0Record`.
    ///
    /// # Panics
    ///
    /// Panics if `record` is a local or dynamic symbol, mirroring Java's `throw new
    /// AssertException("Unexpected Symbol")` -- callers are expected to have already filtered
    /// those out (as every use site in this adapter does).
    fn convert_v0_record(&self, record: &DBRecord) -> DBRecord {
        if record.get_bool(V0_SYMBOL_IS_DYNAMIC_COL) == Some(true)
            || record.get_bool(V0_SYMBOL_LOCAL_COL) == Some(true)
        {
            panic!(
                "SymbolDatabaseAdapterV0::convert_v0_record: unexpected local/dynamic symbol \
                 (mirrors Java's `throw new AssertException(\"Unexpected Symbol\")`)"
            );
        }

        let mut rec = DBRecord::new(v5_schema(), record.get_key().clone());

        let symbol_name = record.get_string(V0_SYMBOL_NAME_COL).unwrap_or("").to_string();
        rec.set_string(SYMBOL_NAME_COL, Some(symbol_name.clone()));

        let address_key = record.get_long(V0_SYMBOL_ADDR_COL).unwrap_or(0);
        rec.set_long(SYMBOL_ADDR_COL, address_key);

        rec.set_byte(SYMBOL_TYPE_COL, SymbolType::Label.get_id() as i8);

        let namespace_id = GLOBAL_NAMESPACE_ID;
        rec.set_long(SYMBOL_PARENT_ID_COL, namespace_id);

        // NOTE: matches real Ghidra byte-for-byte, including the same latent quirk documented on
        // `SymbolDatabaseAdapterV1::convert_v1_record`: Java stores the raw enum `ordinal()` here
        // (`(byte) SourceType.USER_DEFINED.ordinal()`) instead of running it through the bit-split
        // `storageId`-based encoding `decode_source_type_from_flags` expects. Preserved as-is since
        // this is what real Ghidra's upgrade path actually produces.
        rec.set_byte(SYMBOL_FLAGS_COL, SourceType::UserDefined as i8);

        // Convert sparse columns.
        let hash_field = match compute_locator_hash(&symbol_name, namespace_id, address_key) {
            Some(hash) => Field::Long(Some(hash)),
            None => Field::Long(None),
        };
        rec.set_field(SYMBOL_HASH_COL, hash_field);

        if record.get_bool(V0_SYMBOL_PRIMARY_COL) == Some(true) {
            rec.set_long(SYMBOL_PRIMARY_COL, address_key);
        }

        rec
    }

    /// Collects, decodes (via the raw `V0_SYMBOL_ADDR_COL`), converts, and address-sorts every raw
    /// record for which `filter` returns `true`, skipping local/dynamic symbols (as every use site
    /// of `V0ConvertedRecordIterator` does in Java). Backs the several by-address/range/set
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
            if rec.get_bool(V0_SYMBOL_IS_DYNAMIC_COL) == Some(true)
                || rec.get_bool(V0_SYMBOL_LOCAL_COL) == Some(true)
            {
                continue;
            }
            if let Some(key) = rec.get_long(V0_SYMBOL_ADDR_COL) {
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
            .map(|(_, rec)| self.convert_v0_record(&rec))
            .collect();
        Ok(Box::new(VecRecordIterator {
            records: records.into_iter(),
        }))
    }
}

impl SymbolDatabaseAdapter for SymbolDatabaseAdapterV0 {
    fn create_symbol_record(
        &self,
        _name: &str,
        _namespace_id: i64,
        _address: &Address,
        _symbol_type: SymbolType,
        _is_primary: bool,
        _source: SourceType,
    ) -> DBRecord {
        panic!("SymbolDatabaseAdapterV0 is read-only: create_symbol_record is not supported");
    }

    fn get_symbol_record(&self, symbol_id: i64) -> io::Result<Option<DBRecord>> {
        let raw = self.table.read().unwrap().get_record(&Field::Long(Some(symbol_id)))?;
        Ok(raw.as_ref().map(|rec| self.convert_v0_record(rec)))
    }

    fn remove_symbol(&mut self, _symbol_id: i64) -> io::Result<()> {
        panic!("SymbolDatabaseAdapterV0 is read-only: remove_symbol is not supported");
    }

    fn has_symbol(&self, _addr: &Address) -> io::Result<bool> {
        // Matches Java: `V0` throws `UnsupportedOperationException` here too (unlike `V1`, which
        // implements this for real).
        panic!("SymbolDatabaseAdapterV0: has_symbol is not supported");
    }

    fn get_symbol_ids(&self, _addr: &Address) -> io::Result<Vec<Field>> {
        // Matches Java: `V0` throws `UnsupportedOperationException` here too (unlike `V1`, which
        // implements this for real).
        panic!("SymbolDatabaseAdapterV0: get_symbol_ids is not supported");
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
        panic!("SymbolDatabaseAdapterV0 is read-only: update_symbol_record is not supported");
    }

    fn get_symbols(&self) -> io::Result<Box<dyn RecordIterator + '_>> {
        // Matches Java: `getSymbols()` wraps the raw table iterator directly (natural/key order),
        // unlike the by-address methods, which sort by decoded address.
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut records = Vec::new();
        while let Some(rec) = iter.next()? {
            if rec.get_bool(V0_SYMBOL_IS_DYNAMIC_COL) == Some(true)
                || rec.get_bool(V0_SYMBOL_LOCAL_COL) == Some(true)
            {
                continue;
            }
            records.push(self.convert_v0_record(&rec));
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
        // NOTE: matches real Ghidra's SymbolDatabaseAdapterV0.getPrimarySymbols, which passes the
        // *current*-schema `SYMBOL_ADDR_COL` (column 1) here instead of this class's own
        // `V0_SYMBOL_ADDR_COL` (column 4). In the V0 raw schema, column 1 is "Is Dynamic" (a
        // `Boolean`), not the address (a `Long`), so decoding it as an address key always fails
        // (`DBRecord::get_long` returns `None` for a non-`Long` field) and this always yields zero
        // records, regardless of what primary symbols actually exist. Reproduced as-is, not
        // "fixed" -- see `get_primary_symbols_bug_always_empty` below.
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut entries: Vec<(Address, DBRecord)> = Vec::new();
        while let Some(rec) = iter.next()? {
            let Some(key) = rec.get_long(SYMBOL_ADDR_COL) else {
                continue;
            };
            let addr = self.addr_map.decode_address(key);
            if !set.contains(&addr) {
                continue;
            }
            if rec.get_bool(V0_SYMBOL_IS_DYNAMIC_COL) == Some(true)
                || rec.get_bool(V0_SYMBOL_LOCAL_COL) == Some(true)
            {
                continue;
            }
            let converted = self.convert_v0_record(&rec);
            if converted.get_field(SYMBOL_PRIMARY_COL).is_null() {
                continue;
            }
            entries.push((addr, converted));
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
        panic!("SymbolDatabaseAdapterV0 is read-only: move_address is not supported");
    }

    fn delete_address_range(
        &mut self,
        _start_addr: &Address,
        _end_addr: &Address,
        _monitor: &dyn TaskMonitor,
    ) -> Result<std::collections::BTreeSet<Address>, SymbolDeleteAddressRangeError> {
        panic!("SymbolDatabaseAdapterV0 is read-only: delete_address_range is not supported");
    }

    fn get_external_symbols_by_memory_address(
        &self,
        _ext_prog_addr: &Address,
    ) -> io::Result<Box<dyn RecordIterator + '_>> {
        // External symbols were not supported at schema version 0.
        Ok(Box::new(VecRecordIterator {
            records: Vec::new().into_iter(),
        }))
    }

    fn get_external_symbols_by_original_import_name(
        &self,
        _ext_label: &str,
    ) -> io::Result<Box<dyn RecordIterator + '_>> {
        // External symbols were not supported at schema version 0.
        Ok(Box::new(VecRecordIterator {
            records: Vec::new().into_iter(),
        }))
    }

    fn get_symbols_by_namespace(&self, id: i64) -> io::Result<Box<dyn RecordIterator + '_>> {
        if id == GLOBAL_NAMESPACE_ID {
            return self.get_symbols();
        }
        // See module docs: real Ghidra returns `null` here (V0 predates namespace support), and
        // every real caller unconditionally dereferences the result. This is the closest honest
        // translation given this trait's `RecordIterator` return type isn't nullable.
        panic!(
            "SymbolDatabaseAdapterV0::get_symbols_by_namespace({id}): V0 has no namespace \
             support; real Ghidra returns null here, which every caller unconditionally \
             dereferences"
        );
    }

    fn get_symbols_by_name(&self, name: &str) -> io::Result<Box<dyn RecordIterator + '_>> {
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        let mut records = Vec::new();
        while let Some(rec) = iter.next()? {
            if rec.get_string(V0_SYMBOL_NAME_COL) != Some(name) {
                continue;
            }
            if rec.get_bool(V0_SYMBOL_IS_DYNAMIC_COL) == Some(true)
                || rec.get_bool(V0_SYMBOL_LOCAL_COL) == Some(true)
            {
                continue;
            }
            records.push(self.convert_v0_record(&rec));
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
            if rec.get_bool(V0_SYMBOL_IS_DYNAMIC_COL) == Some(true)
                || rec.get_bool(V0_SYMBOL_LOCAL_COL) == Some(true)
            {
                continue;
            }
            if rec.get_string(V0_SYMBOL_NAME_COL).unwrap_or("") >= start_name {
                records.push(rec);
            }
        }
        records.sort_by(|a, b| {
            a.get_string(V0_SYMBOL_NAME_COL)
                .unwrap_or("")
                .cmp(b.get_string(V0_SYMBOL_NAME_COL).unwrap_or(""))
        });
        let converted: Vec<DBRecord> =
            records.iter().map(|rec| self.convert_v0_record(rec)).collect();
        Ok(Box::new(VecRecordIterator {
            records: converted.into_iter(),
        }))
    }

    fn get_symbols_by_name_and_namespace(
        &self,
        name: &str,
        id: i64,
    ) -> io::Result<Box<dyn RecordIterator + '_>> {
        // `get_symbols_by_name` already returns *converted* (current-schema) records, so filtering
        // on `SYMBOL_PARENT_ID_COL` here is correct (unlike the raw-record bug documented on
        // `get_symbol_record_by_address_name_namespace`). Since V0 predates namespaces, every
        // symbol's converted namespace id is always `GLOBAL_NAMESPACE_ID`, so this only ever
        // matches for `id == GLOBAL_NAMESPACE_ID`.
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
        id: i64,
    ) -> io::Result<Option<DBRecord>> {
        // NOTE: matches real Ghidra's SymbolDatabaseAdapterV0.getSymbolRecord(Address, String,
        // long), which filters the *raw* (unconverted) V0 record using the current schema's
        // `SYMBOL_PARENT_ID_COL` (2) / `SYMBOL_ADDR_COL` (1). In the V0 raw schema those columns
        // are "Is Local" / "Is Dynamic" (`Boolean`, not `Long`), so `DBRecord::get_long` always
        // returns `None` for them and the comparisons can never match: this always returns `None`
        // for a real V0 database, regardless of whether a matching symbol exists. Reproduced as-is
        // -- see `get_symbol_record_by_address_name_namespace_bug_always_none` below.
        let address_key = self.addr_map.get_key(address, false);
        let table = self.table.read().unwrap();
        let mut iter = table.get_record_iterator()?;
        while let Some(rec) = iter.next()? {
            if rec.get_string(V0_SYMBOL_NAME_COL) != Some(name) {
                continue;
            }
            if rec.get_long(SYMBOL_PARENT_ID_COL) != Some(id) {
                continue;
            }
            if rec.get_long(SYMBOL_ADDR_COL) != Some(address_key) {
                continue;
            }
            return Ok(Some(rec));
        }
        Ok(None)
    }

    fn get_max_symbol_address(&self, _space: &AddressSpace) -> io::Result<Option<Address>> {
        panic!("SymbolDatabaseAdapterV0 is read-only: get_max_symbol_address is not supported");
    }

    fn get_table(&self) -> Arc<RwLock<Table>> {
        panic!("SymbolDatabaseAdapterV0 is read-only: get_table is not supported");
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

    #[allow(clippy::too_many_arguments)]
    fn make_v0_record(
        table: &mut Table,
        name: &str,
        is_dynamic: bool,
        is_local: bool,
        is_primary: bool,
        address_key: i64,
    ) -> DBRecord {
        let key = table.get_next_key();
        let mut rec = DBRecord::new(schema(), Field::Long(Some(key)));
        rec.set_string(V0_SYMBOL_NAME_COL, Some(name.to_string()));
        rec.set_bool(V0_SYMBOL_IS_DYNAMIC_COL, is_dynamic);
        rec.set_bool(V0_SYMBOL_LOCAL_COL, is_local);
        rec.set_bool(V0_SYMBOL_PRIMARY_COL, is_primary);
        rec.set_long(V0_SYMBOL_ADDR_COL, address_key);
        table.put_record(rec.clone()).unwrap();
        rec
    }

    fn new_handle_with_table() -> DBHandle {
        let mut handle = DBHandle::new().unwrap();
        handle.create_table(SYMBOL_TABLE_NAME.to_string(), schema()).unwrap();
        handle
    }

    #[test]
    fn opens_existing_v0_table() {
        let handle = new_handle_with_table();
        assert!(SymbolDatabaseAdapterV0::new(&handle, addr_map()).is_ok());
    }

    #[test]
    fn missing_table_is_an_error() {
        let handle = DBHandle::new().unwrap();
        assert!(SymbolDatabaseAdapterV0::new(&handle, addr_map()).is_err());
    }

    #[test]
    fn wrong_schema_version_is_an_error() {
        let mut handle = DBHandle::new().unwrap();
        let v5 = crate::program::database::symbol::symbol_database_adapter_v5::schema();
        handle.create_table(SYMBOL_TABLE_NAME.to_string(), v5).unwrap();
        assert!(SymbolDatabaseAdapterV0::new(&handle, addr_map()).is_err());
    }

    #[test]
    fn convert_basic_label_record() {
        let mut handle = new_handle_with_table();
        {
            let table = handle.get_table(SYMBOL_TABLE_NAME).unwrap();
            let mut table = table.write().unwrap();
            make_v0_record(&mut table, "foo", false, false, true, 0x1000);
        }
        let adapter = SymbolDatabaseAdapterV0::new(&handle, addr_map()).unwrap();
        assert_eq!(adapter.get_symbol_count(), 1);

        let mut iter = adapter.get_symbols().unwrap();
        let converted = iter.next().unwrap().expect("one record");
        assert_eq!(converted.get_string(SYMBOL_NAME_COL), Some("foo"));
        assert_eq!(converted.get_long(SYMBOL_ADDR_COL), Some(0x1000));
        assert_eq!(converted.get_byte(SYMBOL_TYPE_COL), Some(SymbolType::Label.get_id() as i8));
        assert_eq!(converted.get_long(SYMBOL_PARENT_ID_COL), Some(GLOBAL_NAMESPACE_ID));
        assert_eq!(converted.get_byte(SYMBOL_FLAGS_COL), Some(SourceType::UserDefined as i8));
        // is_primary == true means primary for a V0 symbol.
        assert_eq!(converted.get_long(SYMBOL_PRIMARY_COL), Some(0x1000));
        assert!(!converted.get_field(SYMBOL_HASH_COL).is_null());
    }

    #[test]
    fn convert_non_primary_has_no_primary_marker() {
        let mut handle = new_handle_with_table();
        {
            let table = handle.get_table(SYMBOL_TABLE_NAME).unwrap();
            let mut table = table.write().unwrap();
            make_v0_record(&mut table, "bar", false, false, false, 0x2000);
        }
        let adapter = SymbolDatabaseAdapterV0::new(&handle, addr_map()).unwrap();
        let mut iter = adapter.get_symbols().unwrap();
        let converted = iter.next().unwrap().expect("one record");
        assert!(converted.get_field(SYMBOL_PRIMARY_COL).is_null());
    }

    #[test]
    fn local_and_dynamic_symbols_are_filtered_from_get_symbols() {
        let mut handle = new_handle_with_table();
        {
            let table = handle.get_table(SYMBOL_TABLE_NAME).unwrap();
            let mut table = table.write().unwrap();
            make_v0_record(&mut table, "visible", false, false, false, 0x1000);
            make_v0_record(&mut table, "local", false, true, false, 0x2000);
            make_v0_record(&mut table, "dynamic", true, false, false, 0x3000);
        }
        let adapter = SymbolDatabaseAdapterV0::new(&handle, addr_map()).unwrap();
        assert_eq!(adapter.get_symbol_count(), 3);

        let mut names = Vec::new();
        let mut iter = adapter.get_symbols().unwrap();
        while let Some(rec) = iter.next().unwrap() {
            names.push(rec.get_string(SYMBOL_NAME_COL).unwrap().to_string());
        }
        assert_eq!(names, vec!["visible"]);
    }

    #[test]
    #[should_panic(expected = "Unexpected Symbol")]
    fn get_symbol_record_on_local_symbol_panics() {
        let mut handle = new_handle_with_table();
        let key;
        {
            let table = handle.get_table(SYMBOL_TABLE_NAME).unwrap();
            let mut table = table.write().unwrap();
            let rec = make_v0_record(&mut table, "local", false, true, false, 0x1000);
            key = rec.get_key().get_long_value();
        }
        let adapter = SymbolDatabaseAdapterV0::new(&handle, addr_map()).unwrap();
        let _ = adapter.get_symbol_record(key);
    }

    #[test]
    fn get_symbols_by_address_orders_and_converts() {
        let mut handle = new_handle_with_table();
        {
            let table = handle.get_table(SYMBOL_TABLE_NAME).unwrap();
            let mut table = table.write().unwrap();
            make_v0_record(&mut table, "c", false, false, false, 0x300);
            make_v0_record(&mut table, "a", false, false, false, 0x100);
            make_v0_record(&mut table, "b", false, false, false, 0x200);
        }
        let adapter = SymbolDatabaseAdapterV0::new(&handle, addr_map()).unwrap();

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
    fn get_symbols_natural_order_differs_from_address_order() {
        let mut handle = new_handle_with_table();
        {
            let table = handle.get_table(SYMBOL_TABLE_NAME).unwrap();
            let mut table = table.write().unwrap();
            // Inserted in descending-address order, so "natural" (key) order and address order
            // disagree.
            make_v0_record(&mut table, "high", false, false, false, 0x300);
            make_v0_record(&mut table, "low", false, false, false, 0x100);
        }
        let adapter = SymbolDatabaseAdapterV0::new(&handle, addr_map()).unwrap();

        let mut natural = Vec::new();
        let mut iter = adapter.get_symbols().unwrap();
        while let Some(rec) = iter.next().unwrap() {
            natural.push(rec.get_string(SYMBOL_NAME_COL).unwrap().to_string());
        }
        assert_eq!(natural, vec!["high", "low"]);

        let mut by_addr = Vec::new();
        let mut iter = adapter.get_symbols_by_address(true).unwrap();
        while let Some(rec) = iter.next().unwrap() {
            by_addr.push(rec.get_string(SYMBOL_NAME_COL).unwrap().to_string());
        }
        assert_eq!(by_addr, vec!["low", "high"]);
    }

    #[test]
    fn get_symbols_by_namespace_global_returns_all() {
        let mut handle = new_handle_with_table();
        {
            let table = handle.get_table(SYMBOL_TABLE_NAME).unwrap();
            let mut table = table.write().unwrap();
            make_v0_record(&mut table, "foo", false, false, false, 0x1000);
        }
        let adapter = SymbolDatabaseAdapterV0::new(&handle, addr_map()).unwrap();
        let mut iter = adapter.get_symbols_by_namespace(GLOBAL_NAMESPACE_ID).unwrap();
        assert!(iter.next().unwrap().is_some());
    }

    #[test]
    #[should_panic(expected = "no namespace support")]
    fn get_symbols_by_namespace_non_global_panics() {
        let handle = new_handle_with_table();
        let adapter = SymbolDatabaseAdapterV0::new(&handle, addr_map()).unwrap();
        let _ = adapter.get_symbols_by_namespace(42);
    }

    #[test]
    fn get_symbols_by_name_and_scan_symbols_by_name() {
        let mut handle = new_handle_with_table();
        {
            let table = handle.get_table(SYMBOL_TABLE_NAME).unwrap();
            let mut table = table.write().unwrap();
            make_v0_record(&mut table, "alpha", false, false, false, 0x100);
            make_v0_record(&mut table, "beta", false, false, false, 0x200);
            make_v0_record(&mut table, "alpha", false, false, false, 0x300);
        }
        let adapter = SymbolDatabaseAdapterV0::new(&handle, addr_map()).unwrap();

        let mut count = 0;
        let mut iter = adapter.get_symbols_by_name("alpha").unwrap();
        while iter.next().unwrap().is_some() {
            count += 1;
        }
        assert_eq!(count, 2);

        let mut names = Vec::new();
        let mut iter = adapter.scan_symbols_by_name("beta").unwrap();
        while let Some(rec) = iter.next().unwrap() {
            names.push(rec.get_string(SYMBOL_NAME_COL).unwrap().to_string());
        }
        assert_eq!(names, vec!["beta"]);
    }

    #[test]
    fn get_symbols_by_name_and_namespace_only_matches_global() {
        let mut handle = new_handle_with_table();
        {
            let table = handle.get_table(SYMBOL_TABLE_NAME).unwrap();
            let mut table = table.write().unwrap();
            make_v0_record(&mut table, "foo", false, false, false, 0x1000);
        }
        let adapter = SymbolDatabaseAdapterV0::new(&handle, addr_map()).unwrap();

        let mut matches = adapter.get_symbols_by_name_and_namespace("foo", GLOBAL_NAMESPACE_ID).unwrap();
        assert!(matches.next().unwrap().is_some());

        let mut no_matches = adapter.get_symbols_by_name_and_namespace("foo", 99).unwrap();
        assert!(no_matches.next().unwrap().is_none());
    }

    #[test]
    fn get_primary_symbols_bug_always_empty() {
        let mut handle = new_handle_with_table();
        {
            let table = handle.get_table(SYMBOL_TABLE_NAME).unwrap();
            let mut table = table.write().unwrap();
            // A real primary symbol -- if the indexing bug weren't present, this would show up.
            make_v0_record(&mut table, "main", false, false, true, 0x1000);
        }
        let adapter = SymbolDatabaseAdapterV0::new(&handle, addr_map()).unwrap();

        let whole_space = AddressSet::from_address(addr(0x1000));
        let mut iter = adapter.get_primary_symbols(&whole_space, true).unwrap();
        assert!(iter.next().unwrap().is_none());

        assert!(adapter.get_primary_symbol(&addr(0x1000)).unwrap().is_none());
    }

    #[test]
    fn get_symbol_record_by_address_name_namespace_bug_always_none() {
        let mut handle = new_handle_with_table();
        {
            let table = handle.get_table(SYMBOL_TABLE_NAME).unwrap();
            let mut table = table.write().unwrap();
            make_v0_record(&mut table, "foo", false, false, false, 0x1000);
        }
        let adapter = SymbolDatabaseAdapterV0::new(&handle, addr_map()).unwrap();
        // Exact match on address/name/namespace still returns None due to the column-index bug.
        let result = adapter
            .get_symbol_record_by_address_name_namespace(&addr(0x1000), "foo", GLOBAL_NAMESPACE_ID)
            .unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn external_symbol_lookups_are_always_empty() {
        let handle = new_handle_with_table();
        let adapter = SymbolDatabaseAdapterV0::new(&handle, addr_map()).unwrap();
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
    fn extract_local_symbols_succeeds_when_no_local_symbols() {
        let mut handle = new_handle_with_table();
        {
            let table = handle.get_table(SYMBOL_TABLE_NAME).unwrap();
            let mut table = table.write().unwrap();
            make_v0_record(&mut table, "a", false, false, false, 0x100);
            make_v0_record(&mut table, "b", false, false, false, 0x200);
        }
        let adapter = SymbolDatabaseAdapterV0::new(&handle, addr_map()).unwrap();
        let next_key = adapter.extract_local_symbols(&DummyMonitor).unwrap();
        assert_eq!(next_key, 2);
    }

    #[test]
    fn extract_local_symbols_reports_unported_blocker_for_local_symbol() {
        let mut handle = new_handle_with_table();
        {
            let table = handle.get_table(SYMBOL_TABLE_NAME).unwrap();
            let mut table = table.write().unwrap();
            make_v0_record(&mut table, "loc", false, true, false, 0x100);
        }
        let adapter = SymbolDatabaseAdapterV0::new(&handle, addr_map()).unwrap();
        let result = adapter.extract_local_symbols(&DummyMonitor);
        assert!(matches!(result, Err(ExtractLocalSymbolsError::Unported { key: 0 })));
    }

    #[test]
    #[should_panic(expected = "read-only")]
    fn create_symbol_record_panics() {
        let handle = new_handle_with_table();
        let adapter = SymbolDatabaseAdapterV0::new(&handle, addr_map()).unwrap();
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
    #[should_panic(expected = "has_symbol")]
    fn has_symbol_panics() {
        let handle = new_handle_with_table();
        let adapter = SymbolDatabaseAdapterV0::new(&handle, addr_map()).unwrap();
        let _ = adapter.has_symbol(&addr(0x1000));
    }

    #[test]
    #[should_panic(expected = "get_symbol_ids")]
    fn get_symbol_ids_panics() {
        let handle = new_handle_with_table();
        let adapter = SymbolDatabaseAdapterV0::new(&handle, addr_map()).unwrap();
        let _ = adapter.get_symbol_ids(&addr(0x1000));
    }

    #[test]
    #[should_panic(expected = "read-only")]
    fn move_address_panics() {
        let handle = new_handle_with_table();
        let mut adapter = SymbolDatabaseAdapterV0::new(&handle, addr_map()).unwrap();
        adapter.move_address(&addr(0x1000), &addr(0x2000)).unwrap();
    }

    #[test]
    #[should_panic(expected = "read-only")]
    fn delete_address_range_panics() {
        let handle = new_handle_with_table();
        let mut adapter = SymbolDatabaseAdapterV0::new(&handle, addr_map()).unwrap();
        let _ = adapter.delete_address_range(&addr(0x1000), &addr(0x2000), &DummyMonitor);
    }

    #[test]
    #[should_panic(expected = "read-only")]
    fn get_table_panics() {
        let handle = new_handle_with_table();
        let adapter = SymbolDatabaseAdapterV0::new(&handle, addr_map()).unwrap();
        let _ = adapter.get_table();
    }

    #[test]
    fn behaves_as_trait_object() {
        let handle = new_handle_with_table();
        let adapter: Box<dyn SymbolDatabaseAdapter> =
            Box::new(SymbolDatabaseAdapterV0::new(&handle, addr_map()).unwrap());
        assert_eq!(adapter.get_symbol_count(), 0);
    }
}

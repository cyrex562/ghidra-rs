//! Port of `ghidra.program.database.symbol.SymbolDatabaseAdapter`.
//!
//! The Java type is an abstract class whose static factory method (`getAdapter`, plus the
//! private `findReadOnlyAdapter` helper and the `upgrade`/`copyToTempAndFixupRecords`/
//! `copyTempToNewAdapter` migration helpers it delegates to) selects and migrates between
//! concrete version-specific implementations (`SymbolDatabaseAdapterV0`..`V5`). Those concrete
//! adapters have not been ported yet, so this port only models the abstract instance API each
//! version implements, as an object-safe trait; the version-selection/upgrade logic belongs with
//! whichever type ends up owning the concrete adapters. This follows the same convention already
//! used for
//! [`VariableStorageDBAdapter`](crate::program::database::symbol::VariableStorageDBAdapter) and
//! [`LabelHistoryAdapter`](crate::program::database::symbol::LabelHistoryAdapter). This trait was
//! itself selected as a dependency-cycle cut-point.
//!
//! Also ported: the protected static helpers [`get_source_type_flags_bits`] and
//! [`decode_source_type_from_flags`], which encode/decode a [`SourceType`]'s storage ID into the
//! split flag bits used by the V4+ on-disk symbol record layout -- real bit-packing logic rather
//! than a concrete table layout descriptor. Left out for the same reason as
//! `VARIABLE_STORAGE_TABLE_NAME` was left out of `VariableStorageDBAdapter`: the
//! `getNameAndNamespaceFilterIterator`/`getNameNamespaceAddressFilterIterator`/
//! `getPrimaryFilterRecordIterator`/`computeLocatorHash` static helpers, since they operate on
//! `db.Query`/`db.RecordIterator` machinery specific to a concrete adapter's column layout and
//! are unused by any already-ported caller; left for whichever concrete adapter is ported first.

use std::collections::BTreeSet;
use std::io;

use crate::framework::db::{DBRecord, Field, RecordIterator, Table};
use crate::program::model::address::{Address, AddressSetView, AddressSpace};
use crate::program::model::symbol::{SourceType, SymbolType};
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// Bits 0-1 of the flags byte: low bits of the [`SourceType`] storage ID. Stands in for
/// `SymbolDatabaseAdapter.SYMBOL_SOURCE_LO_BITS`.
pub const SYMBOL_SOURCE_LO_BITS: u8 = 0x3;
/// Bit 2 of the flags byte: flag for "anchored to address". Stands in for
/// `SymbolDatabaseAdapter.SYMBOL_PINNED_FLAG`.
pub const SYMBOL_PINNED_FLAG: u8 = 0x4;
/// Bit 3 of the flags byte: high bit of the [`SourceType`] storage ID. Stands in for
/// `SymbolDatabaseAdapter.SYMBOL_SOURCE_HI_BIT`.
pub const SYMBOL_SOURCE_HI_BIT: u8 = 0x8;
/// Storage mask for the [`SourceType`] storage ID within the flags byte. Stands in for
/// `SymbolDatabaseAdapter.SYMBOL_SOURCE_MASK`.
pub const SYMBOL_SOURCE_MASK: u8 = 0xB;

const SYMBOL_SOURCE_LO_BITS_SHIFT: u32 = 0;
const SYMBOL_SOURCE_HI_BIT_SHIFT: u32 = 3;

/// Value limit based upon 3-bit storage capacity. Stands in for
/// `SymbolDatabaseAdapter.MAX_SOURCE_VALUE`.
pub const MAX_SOURCE_VALUE: i32 = 7;

/// Transforms a [`SourceType`] storage ID to V4+ flag bits.
///
/// Stands in for `SymbolDatabaseAdapter.getSourceTypeFlagsBits(SourceType)`.
///
/// # Errors
///
/// Returns an error if `source`'s storage ID exceeds [`MAX_SOURCE_VALUE`] (mirrors the Java
/// method's unchecked `RuntimeException`).
pub fn get_source_type_flags_bits(source: SourceType) -> Result<u8, String> {
    let source_type_id = source.storage_id();
    if source_type_id > MAX_SOURCE_VALUE {
        return Err(format!("Unsupported SourceType storage ID: {source_type_id}"));
    }
    let lo_bits = ((source_type_id & 0x3) << SYMBOL_SOURCE_LO_BITS_SHIFT) as u8;
    let hi_bit = ((source_type_id >> 2) << SYMBOL_SOURCE_HI_BIT_SHIFT) as u8;
    Ok(hi_bit | lo_bits)
}

/// Decodes a [`SourceType`] from V4+ flags.
///
/// Stands in for `SymbolDatabaseAdapter.decodeSourceTypeFromFlags(byte)`.
///
/// # Errors
///
/// Returns an error if the decoded storage ID does not correspond to a known [`SourceType`].
pub fn decode_source_type_from_flags(flags: u8) -> Result<SourceType, String> {
    let lo_bits = (flags & SYMBOL_SOURCE_LO_BITS) >> SYMBOL_SOURCE_LO_BITS_SHIFT;
    let hi_bit = (flags & SYMBOL_SOURCE_HI_BIT) >> (SYMBOL_SOURCE_HI_BIT_SHIFT - 2);
    SourceType::get_source_type((hi_bit | lo_bits) as i32)
}

/// Error returned by [`SymbolDatabaseAdapter::delete_address_range`], mirroring the Java method's
/// `throws CancelledException, IOException`.
#[derive(Debug, thiserror::Error)]
pub enum SymbolDeleteAddressRangeError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Cancelled(#[from] CancelledException),
}

/// Adapter to access records in the symbol table.
///
/// Port of `ghidra.program.database.symbol.SymbolDatabaseAdapter`. See the module docs for what
/// was intentionally left out (the static factory, version-upgrade logic, and the query-filter
/// helpers).
pub trait SymbolDatabaseAdapter {
    /// Instantiate a new basic symbol record. Caller is responsible for updating any related
    /// optional record fields and then adding to the table via
    /// [`Self::update_symbol_record`]. `is_primary` marks the symbol record as primary (relevant
    /// for label and function symbols only).
    ///
    /// Stands in for `SymbolDatabaseAdapter.createSymbolRecord(String, long, Address, SymbolType,
    /// boolean, SourceType)`.
    fn create_symbol_record(
        &self,
        name: &str,
        namespace_id: i64,
        address: &Address,
        symbol_type: SymbolType,
        is_primary: bool,
        source: SourceType,
    ) -> DBRecord;

    /// Get the record with the given symbol ID, or `None` if there is no such record.
    ///
    /// Stands in for `SymbolDatabaseAdapter.getSymbolRecord(long)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn get_symbol_record(&self, symbol_id: i64) -> io::Result<Option<DBRecord>>;

    /// Remove the record for the given symbol ID.
    ///
    /// Stands in for `SymbolDatabaseAdapter.removeSymbol(long)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn remove_symbol(&mut self, symbol_id: i64) -> io::Result<()>;

    /// Check if the address has a symbol defined at it.
    ///
    /// Stands in for `SymbolDatabaseAdapter.hasSymbol(Address)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn has_symbol(&self, addr: &Address) -> io::Result<bool>;

    /// Get the symbol IDs at the given address.
    ///
    /// Stands in for `SymbolDatabaseAdapter.getSymbolIDs(Address)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn get_symbol_ids(&self, addr: &Address) -> io::Result<Vec<Field>>;

    /// Get the number of symbols.
    ///
    /// Stands in for `SymbolDatabaseAdapter.getSymbolCount()`.
    fn get_symbol_count(&self) -> i32;

    /// Get an iterator over all the symbols in ascending (or descending, if `forward` is `false`)
    /// address order.
    ///
    /// Stands in for `SymbolDatabaseAdapter.getSymbolsByAddress(boolean)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn get_symbols_by_address(&self, forward: bool) -> io::Result<Box<dyn RecordIterator + '_>>;

    /// Get an iterator over all the symbols starting at `start_addr`.
    ///
    /// Stands in for `SymbolDatabaseAdapter.getSymbolsByAddress(Address, boolean)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn get_symbols_by_address_from(
        &self,
        start_addr: &Address,
        forward: bool,
    ) -> io::Result<Box<dyn RecordIterator + '_>>;

    /// Update the table with the given record.
    ///
    /// Stands in for `SymbolDatabaseAdapter.updateSymbolRecord(DBRecord)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn update_symbol_record(&mut self, record: &DBRecord) -> io::Result<()>;

    /// Get all of the symbols.
    ///
    /// Stands in for `SymbolDatabaseAdapter.getSymbols()`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn get_symbols(&self) -> io::Result<Box<dyn RecordIterator + '_>>;

    /// Get symbols in the range `[start, end]`.
    ///
    /// Stands in for `SymbolDatabaseAdapter.getSymbols(Address, Address, boolean)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn get_symbols_in_range(
        &self,
        start: &Address,
        end: &Address,
        forward: bool,
    ) -> io::Result<Box<dyn RecordIterator + '_>>;

    /// Get symbols contained in the given address set.
    ///
    /// Stands in for `SymbolDatabaseAdapter.getSymbols(AddressSetView, boolean)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn get_symbols_in_set(
        &self,
        set: &dyn AddressSetView,
        forward: bool,
    ) -> io::Result<Box<dyn RecordIterator + '_>>;

    /// Returns an iterator over the primary symbols in the given range.
    ///
    /// Stands in for `SymbolDatabaseAdapter.getPrimarySymbols(AddressSetView, boolean)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn get_primary_symbols(
        &self,
        set: &dyn AddressSetView,
        forward: bool,
    ) -> io::Result<Box<dyn RecordIterator + '_>>;

    /// Returns the symbol record for the primary symbol at the given address, or `None` if no
    /// label or function exists at that address.
    ///
    /// Stands in for `SymbolDatabaseAdapter.getPrimarySymbol(Address)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn get_primary_symbol(&self, address: &Address) -> io::Result<Option<DBRecord>>;

    /// Update the address in all records to reflect the movement of a symbol address.
    ///
    /// Stands in for `SymbolDatabaseAdapter.moveAddress(Address, Address)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn move_address(&mut self, old_addr: &Address, new_addr: &Address) -> io::Result<()>;

    /// Delete all records which contain addresses within `[start_addr, end_addr]`. Returns the
    /// set of addresses where symbols were not deleted because they were anchored (pinned).
    ///
    /// Stands in for `SymbolDatabaseAdapter.deleteAddressRange(Address, Address, TaskMonitor)`.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation is cancelled or there was a problem accessing the
    /// database.
    fn delete_address_range(
        &mut self,
        start_addr: &Address,
        end_addr: &Address,
        monitor: &dyn TaskMonitor,
    ) -> Result<BTreeSet<Address>, SymbolDeleteAddressRangeError>;

    /// Get all symbols contained within the specified namespace.
    ///
    /// Stands in for `SymbolDatabaseAdapter.getSymbolsByNamespace(long)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn get_symbols_by_namespace(&self, id: i64) -> io::Result<Box<dyn RecordIterator + '_>>;

    /// Get symbols that have the specified name.
    ///
    /// Stands in for `SymbolDatabaseAdapter.getSymbolsByName(String)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn get_symbols_by_name(&self, name: &str) -> io::Result<Box<dyn RecordIterator + '_>>;

    /// Scan symbols lexicographically by name starting from the given name. Only includes
    /// memory-based stored symbols.
    ///
    /// Stands in for `SymbolDatabaseAdapter.scanSymbolsByName(String)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn scan_symbols_by_name(&self, start_name: &str) -> io::Result<Box<dyn RecordIterator + '_>>;

    /// Get symbol records which match the specified external original import name (forward
    /// iteration only, delete not supported).
    ///
    /// Stands in for `SymbolDatabaseAdapter.getExternalSymbolsByOriginalImportName(String)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn get_external_symbols_by_original_import_name(
        &self,
        ext_label: &str,
    ) -> io::Result<Box<dyn RecordIterator + '_>>;

    /// Get symbol records which match the specified external program address (forward iteration
    /// only, delete not supported).
    ///
    /// Stands in for `SymbolDatabaseAdapter.getExternalSymbolsByMemoryAddress(Address)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn get_external_symbols_by_memory_address(
        &self,
        ext_prog_addr: &Address,
    ) -> io::Result<Box<dyn RecordIterator + '_>>;

    /// Get all symbols contained in the given namespace that have the given name.
    ///
    /// Stands in for `SymbolDatabaseAdapter.getSymbolsByNameAndNamespace(String, long)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn get_symbols_by_name_and_namespace(
        &self,
        name: &str,
        id: i64,
    ) -> io::Result<Box<dyn RecordIterator + '_>>;

    /// Get the symbol record with the given address, name, and namespace ID, or `None` if there
    /// is no match.
    ///
    /// Stands in for `SymbolDatabaseAdapter.getSymbolRecord(Address, String, long)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn get_symbol_record_by_address_name_namespace(
        &self,
        address: &Address,
        name: &str,
        namespace_id: i64,
    ) -> io::Result<Option<DBRecord>>;

    /// Returns the maximum symbol address within the specified address space, or `None` if none
    /// are found. Intended for update use only.
    ///
    /// Stands in for `SymbolDatabaseAdapter.getMaxSymbolAddress(AddressSpace)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn get_max_symbol_address(&self, space: &AddressSpace) -> io::Result<Option<Address>>;

    /// Returns the underlying symbol table (for upgrade use only).
    ///
    /// Stands in for `SymbolDatabaseAdapter.getTable()`.
    fn get_table(&self) -> &Table;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::{FieldType, Schema};
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::util::task::DummyMonitor;
    use std::collections::BTreeMap;
    use std::sync::Arc;

    fn test_schema() -> Arc<Schema> {
        Arc::new(Schema::new(
            5,
            FieldType::Long,
            "Key".to_string(),
            vec![
                FieldType::String,
                FieldType::Long,
                FieldType::Long,
                FieldType::Int,
                FieldType::Byte,
            ],
            vec![
                "Name".to_string(),
                "Address".to_string(),
                "ParentID".to_string(),
                "Type".to_string(),
                "Flags".to_string(),
            ],
            vec![],
        ))
    }

    struct MockRecordIterator {
        records: std::vec::IntoIter<DBRecord>,
    }

    impl RecordIterator for MockRecordIterator {
        fn next(&mut self) -> io::Result<Option<DBRecord>> {
            Ok(self.records.next())
        }

        fn has_next(&self) -> bool {
            self.records.len() > 0
        }
    }

    struct MockSymbolDatabaseAdapter {
        schema: Arc<Schema>,
        records: BTreeMap<i64, DBRecord>,
        next_key: i64,
        table: Table,
        pinned: BTreeSet<i64>,
    }

    impl MockSymbolDatabaseAdapter {
        fn new() -> Self {
            let schema = test_schema();
            let buffer_mgr = Arc::new(std::sync::RwLock::new(crate::framework::db::BufferMgr::new(
                crate::framework::db::BufferMgr::DEFAULT_BUFFER_SIZE,
            )));
            MockSymbolDatabaseAdapter {
                schema: schema.clone(),
                records: BTreeMap::new(),
                next_key: 0,
                table: Table::new("Symbols".to_string(), schema, buffer_mgr),
                pinned: BTreeSet::new(),
            }
        }
    }

    impl SymbolDatabaseAdapter for MockSymbolDatabaseAdapter {
        fn create_symbol_record(
            &self,
            name: &str,
            namespace_id: i64,
            address: &Address,
            symbol_type: SymbolType,
            is_primary: bool,
            source: SourceType,
        ) -> DBRecord {
            let mut record = DBRecord::new(self.schema.clone(), Field::Long(None));
            record.set_string(0, Some(name.to_string()));
            record.set_long(1, address.offset());
            record.set_long(2, namespace_id);
            record.set_int(3, symbol_type.get_id());
            let flags = get_source_type_flags_bits(source).unwrap();
            record.set_byte(4, flags as i8);
            let _ = is_primary;
            record
        }

        fn get_symbol_record(&self, symbol_id: i64) -> io::Result<Option<DBRecord>> {
            Ok(self.records.get(&symbol_id).cloned())
        }

        fn remove_symbol(&mut self, symbol_id: i64) -> io::Result<()> {
            self.records.remove(&symbol_id);
            self.pinned.remove(&symbol_id);
            Ok(())
        }

        fn has_symbol(&self, addr: &Address) -> io::Result<bool> {
            Ok(self
                .records
                .values()
                .any(|r| r.get_long(1) == Some(addr.offset())))
        }

        fn get_symbol_ids(&self, addr: &Address) -> io::Result<Vec<Field>> {
            Ok(self
                .records
                .iter()
                .filter(|(_, r)| r.get_long(1) == Some(addr.offset()))
                .map(|(k, _)| Field::Long(Some(*k)))
                .collect())
        }

        fn get_symbol_count(&self) -> i32 {
            self.records.len() as i32
        }

        fn get_symbols_by_address(
            &self,
            forward: bool,
        ) -> io::Result<Box<dyn RecordIterator + '_>> {
            let mut records: Vec<DBRecord> = self.records.values().cloned().collect();
            records.sort_by_key(|r| r.get_long(1));
            if !forward {
                records.reverse();
            }
            Ok(Box::new(MockRecordIterator {
                records: records.into_iter(),
            }))
        }

        fn get_symbols_by_address_from(
            &self,
            start_addr: &Address,
            forward: bool,
        ) -> io::Result<Box<dyn RecordIterator + '_>> {
            let mut records: Vec<DBRecord> = self
                .records
                .values()
                .filter(|r| {
                    let a = r.get_long(1).unwrap_or(0);
                    if forward {
                        a >= start_addr.offset()
                    } else {
                        a <= start_addr.offset()
                    }
                })
                .cloned()
                .collect();
            records.sort_by_key(|r| r.get_long(1));
            if !forward {
                records.reverse();
            }
            Ok(Box::new(MockRecordIterator {
                records: records.into_iter(),
            }))
        }

        fn update_symbol_record(&mut self, record: &DBRecord) -> io::Result<()> {
            let mut record = record.clone();
            let key = record.get_key().get_long_value();
            let key = if key < 0 || record.get_key().is_null() {
                let k = self.next_key;
                self.next_key += 1;
                record.set_key(Field::Long(Some(k)));
                k
            } else {
                self.next_key = self.next_key.max(key + 1);
                key
            };
            self.records.insert(key, record);
            Ok(())
        }

        fn get_symbols(&self) -> io::Result<Box<dyn RecordIterator + '_>> {
            self.get_symbols_by_address(true)
        }

        fn get_symbols_in_range(
            &self,
            start: &Address,
            end: &Address,
            forward: bool,
        ) -> io::Result<Box<dyn RecordIterator + '_>> {
            let mut records: Vec<DBRecord> = self
                .records
                .values()
                .filter(|r| {
                    let a = r.get_long(1).unwrap_or(0);
                    a >= start.offset() && a <= end.offset()
                })
                .cloned()
                .collect();
            records.sort_by_key(|r| r.get_long(1));
            if !forward {
                records.reverse();
            }
            Ok(Box::new(MockRecordIterator {
                records: records.into_iter(),
            }))
        }

        fn get_symbols_in_set(
            &self,
            set: &dyn AddressSetView,
            forward: bool,
        ) -> io::Result<Box<dyn RecordIterator + '_>> {
            let mut records: Vec<DBRecord> = self
                .records
                .values()
                .filter(|r| r.get_long(1).is_some() && set.contains(&addr_of(r)))
                .cloned()
                .collect();
            records.sort_by_key(|r| r.get_long(1));
            if !forward {
                records.reverse();
            }
            Ok(Box::new(MockRecordIterator {
                records: records.into_iter(),
            }))
        }

        fn get_primary_symbols(
            &self,
            set: &dyn AddressSetView,
            forward: bool,
        ) -> io::Result<Box<dyn RecordIterator + '_>> {
            self.get_symbols_in_set(set, forward)
        }

        fn get_primary_symbol(&self, address: &Address) -> io::Result<Option<DBRecord>> {
            Ok(self
                .records
                .values()
                .find(|r| r.get_long(1) == Some(address.offset()))
                .cloned())
        }

        fn move_address(&mut self, old_addr: &Address, new_addr: &Address) -> io::Result<()> {
            for record in self.records.values_mut() {
                if record.get_long(1) == Some(old_addr.offset()) {
                    record.set_long(1, new_addr.offset());
                }
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
            let space = start_addr.space().clone();
            let mut anchored = BTreeSet::new();
            let mut to_remove = Vec::new();
            for (key, record) in &self.records {
                let a = record.get_long(1).unwrap_or(i64::MIN);
                if a >= start_addr.offset() && a <= end_addr.offset() {
                    if self.pinned.contains(key) {
                        anchored.insert(space.address(a));
                    } else {
                        to_remove.push(*key);
                    }
                }
            }
            for key in to_remove {
                self.records.remove(&key);
            }
            Ok(anchored)
        }

        fn get_symbols_by_namespace(&self, id: i64) -> io::Result<Box<dyn RecordIterator + '_>> {
            let records: Vec<DBRecord> = self
                .records
                .values()
                .filter(|r| r.get_long(2) == Some(id))
                .cloned()
                .collect();
            Ok(Box::new(MockRecordIterator {
                records: records.into_iter(),
            }))
        }

        fn get_symbols_by_name(&self, name: &str) -> io::Result<Box<dyn RecordIterator + '_>> {
            let records: Vec<DBRecord> = self
                .records
                .values()
                .filter(|r| r.get_string(0).as_deref() == Some(name))
                .cloned()
                .collect();
            Ok(Box::new(MockRecordIterator {
                records: records.into_iter(),
            }))
        }

        fn scan_symbols_by_name(
            &self,
            start_name: &str,
        ) -> io::Result<Box<dyn RecordIterator + '_>> {
            let mut records: Vec<DBRecord> = self
                .records
                .values()
                .filter(|r| r.get_string(0).as_deref().unwrap_or("") >= start_name)
                .cloned()
                .collect();
            records.sort_by(|a, b| a.get_string(0).cmp(&b.get_string(0)));
            Ok(Box::new(MockRecordIterator {
                records: records.into_iter(),
            }))
        }

        fn get_external_symbols_by_original_import_name(
            &self,
            _ext_label: &str,
        ) -> io::Result<Box<dyn RecordIterator + '_>> {
            Ok(Box::new(MockRecordIterator {
                records: Vec::new().into_iter(),
            }))
        }

        fn get_external_symbols_by_memory_address(
            &self,
            _ext_prog_addr: &Address,
        ) -> io::Result<Box<dyn RecordIterator + '_>> {
            Ok(Box::new(MockRecordIterator {
                records: Vec::new().into_iter(),
            }))
        }

        fn get_symbols_by_name_and_namespace(
            &self,
            name: &str,
            id: i64,
        ) -> io::Result<Box<dyn RecordIterator + '_>> {
            let records: Vec<DBRecord> = self
                .records
                .values()
                .filter(|r| r.get_string(0).as_deref() == Some(name) && r.get_long(2) == Some(id))
                .cloned()
                .collect();
            Ok(Box::new(MockRecordIterator {
                records: records.into_iter(),
            }))
        }

        fn get_symbol_record_by_address_name_namespace(
            &self,
            address: &Address,
            name: &str,
            namespace_id: i64,
        ) -> io::Result<Option<DBRecord>> {
            Ok(self
                .records
                .values()
                .find(|r| {
                    r.get_long(1) == Some(address.offset())
                        && r.get_string(0).as_deref() == Some(name)
                        && r.get_long(2) == Some(namespace_id)
                })
                .cloned())
        }

        fn get_max_symbol_address(&self, space: &AddressSpace) -> io::Result<Option<Address>> {
            let max = self.records.values().filter_map(|r| r.get_long(1)).max();
            Ok(max.map(|off| Arc::new(space.clone()).address(off)))
        }

        fn get_table(&self) -> &Table {
            &self.table
        }
    }

    fn addr_of(record: &DBRecord) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        space.address(record.get_long(1).unwrap_or(0))
    }

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    #[test]
    fn source_type_flags_round_trip() {
        for source in [
            SourceType::Default,
            SourceType::Analysis,
            SourceType::Imported,
            SourceType::UserDefined,
        ] {
            let flags = get_source_type_flags_bits(source).unwrap();
            assert_eq!(decode_source_type_from_flags(flags).unwrap(), source);
        }
    }

    #[test]
    fn create_update_lookup_and_delete_round_trip() {
        let space = ram_space();
        let mut adapter = MockSymbolDatabaseAdapter::new();

        let addr = space.address(0x1000);
        let record = adapter.create_symbol_record(
            "foo",
            0,
            &addr,
            SymbolType::Label,
            true,
            SourceType::UserDefined,
        );
        adapter.update_symbol_record(&record).unwrap();

        assert_eq!(adapter.get_symbol_count(), 1);
        assert!(adapter.has_symbol(&addr).unwrap());

        let ids = adapter.get_symbol_ids(&addr).unwrap();
        assert_eq!(ids.len(), 1);
        let Field::Long(Some(key)) = ids[0].clone() else {
            panic!("expected long field");
        };

        let fetched = adapter.get_symbol_record(key).unwrap().expect("present");
        assert_eq!(fetched.get_string(0), Some("foo"));

        adapter.remove_symbol(key).unwrap();
        assert_eq!(adapter.get_symbol_count(), 0);
        assert!(!adapter.has_symbol(&addr).unwrap());
    }

    #[test]
    fn object_safety_move_and_delete_range_respects_pinned() {
        let space = ram_space();
        let mut mock = MockSymbolDatabaseAdapter::new();

        let pinned_addr = space.address(0x1000);
        let free_addr = space.address(0x1010);

        let pinned_record = mock.create_symbol_record(
            "pinned",
            0,
            &pinned_addr,
            SymbolType::Label,
            true,
            SourceType::UserDefined,
        );
        mock.update_symbol_record(&pinned_record).unwrap();
        let pinned_key = mock
            .get_symbol_ids(&pinned_addr)
            .unwrap()
            .into_iter()
            .next()
            .and_then(|f| match f {
                Field::Long(Some(k)) => Some(k),
                _ => None,
            })
            .unwrap();
        mock.pinned.insert(pinned_key);

        let free_record = mock.create_symbol_record(
            "free",
            0,
            &free_addr,
            SymbolType::Label,
            true,
            SourceType::UserDefined,
        );
        mock.update_symbol_record(&free_record).unwrap();

        // Move the free symbol before boxing, to prove `move_address` works through the trait
        // object below.
        let mut adapter: Box<dyn SymbolDatabaseAdapter> = Box::new(mock);
        let moved_addr = space.address(0x2000);
        adapter.move_address(&free_addr, &moved_addr).unwrap();
        assert!(adapter.has_symbol(&moved_addr).unwrap());
        assert!(!adapter.has_symbol(&free_addr).unwrap());

        let start = space.address(0x1000);
        let end = space.address(0x3000);
        let anchored = adapter
            .delete_address_range(&start, &end, &DummyMonitor)
            .unwrap();

        // The pinned symbol survives and is reported as anchored; the moved (formerly free)
        // symbol falls within the range and is deleted.
        assert_eq!(anchored, BTreeSet::from([pinned_addr.clone()]));
        assert!(adapter.has_symbol(&pinned_addr).unwrap());
        assert!(!adapter.has_symbol(&moved_addr).unwrap());
        assert_eq!(adapter.get_symbol_count(), 1);
    }
}

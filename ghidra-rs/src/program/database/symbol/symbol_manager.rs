use crate::framework::db::record::DBRecord;
use crate::framework::db::{DBHandle, Field, FieldType, Schema};
use crate::program::database::map::AddressMapDB;
use crate::program::database::symbol::namespace_manager::NamespaceManagerDB;
use crate::program::database::symbol::symbol_db::SymbolDB;
use crate::program::database::symbol::variable_storage_manager::VariableStorageManager;
use crate::program::database::ManagerDB;
use crate::program::model::address::{Address, AddressSpace};
use crate::program::model::listing::Library;
use crate::program::model::symbol::{SetSymbolNameError, SourceType, Symbol, SymbolIterator, SymbolTable, SymbolType};
use crate::program::model::symbol::symbol_utilities::SymbolUtilities;
use crate::util::exception::{DuplicateNameException, InvalidInputException};
use crate::program::model::listing::variable_storage::VariableStorage;
use crate::program::model::address::BoxedAddressIterator;
use crate::program::model::symbol::{Namespace, SymbolIteratorAdapter};
use crate::util::user_search_utils::UserSearchUtils;
use std::collections::BTreeSet;
use std::io;
use std::sync::{Arc, RwLock};

pub struct SymbolManagerDB {
    db_handle: Arc<RwLock<DBHandle>>,
    addr_map: Arc<RwLock<AddressMapDB>>,
    namespace_mgr: Arc<RwLock<NamespaceManagerDB>>,
    /// The program's external entry points. Java keeps these as `EXTERNAL_ENTRY` references in
    /// the `ReferenceDBManager` (`SymbolManager.addExternalEntryPoint` delegates to
    /// `refManager.addExternalEntryPointRef`); `ProgramDB` has no reference manager yet, so the
    /// symbol manager holds the entry point set itself, in address order as Java's
    /// `getExternalEntryIterator` returns it.
    external_entry_points: BTreeSet<Address>,
}

impl SymbolManagerDB {
    pub const SYMBOL_TABLE_NAME: &'static str = "Symbols";

    pub const SYMBOL_NAME_COL: usize = 0;
    pub const SYMBOL_ADDR_COL: usize = 1;
    pub const SYMBOL_PARENT_ID_COL: usize = 2;
    pub const SYMBOL_TYPE_COL: usize = 3;
    pub const SYMBOL_FLAGS_COL: usize = 4;
    pub const SYMBOL_HASH_COL: usize = 5;
    pub const SYMBOL_PRIMARY_COL: usize = 6;

    pub const SYMBOL_PINNED_FLAG: u8 = 0x4;
    /// The flag bits holding the source type (`SymbolDatabaseAdapter.SYMBOL_SOURCE_MASK`).
    pub const SYMBOL_SOURCE_MASK: u8 = 0x3 | 0x8;

    pub fn new(
        db_handle: Arc<RwLock<DBHandle>>,
        addr_map: Arc<RwLock<AddressMapDB>>,
        namespace_mgr: Arc<RwLock<NamespaceManagerDB>>,
        create: bool,
    ) -> io::Result<Self> {
        if create {
            let schema = Schema::new(
                0,
                FieldType::Long,
                "ID".to_string(),
                vec![
                    FieldType::String, // Name
                    FieldType::Long,   // Address
                    FieldType::Long,   // Parent ID
                    FieldType::Byte,   // Symbol Type
                    FieldType::Byte,   // Flags
                    FieldType::Long,   // Locator Hash
                    FieldType::Long,   // Primary Address Key
                ],
                vec![
                    "Name".to_string(),
                    "Address".to_string(),
                    "Parent ID".to_string(),
                    "Type".to_string(),
                    "Flags".to_string(),
                    "Hash".to_string(),
                    "Primary".to_string(),
                ],
                vec![1, 2], // Indexed: Address, Parent ID
            );
            let mut handle = db_handle.write().unwrap();
            handle.create_table(Self::SYMBOL_TABLE_NAME.to_string(), Arc::new(schema))?;
        }
        Ok(Self {
            db_handle,
            addr_map,
            namespace_mgr,
            external_entry_points: BTreeSet::new(),
        })
    }

    pub fn create_symbol_record(
        &self,
        name: &str,
        namespace_id: i64,
        address: &Address,
        symbol_type: SymbolType,
        is_primary: bool,
        source: SourceType,
    ) -> io::Result<DBRecord> {
        let handle = self.db_handle.read().unwrap();
        let table = handle
            .get_table(Self::SYMBOL_TABLE_NAME)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Symbol table not found"))?;

        let mut table_lock = table.write().unwrap();
        let mut next_id = table_lock.get_next_key();
        while next_id <= 0 {
            // Skip 0, reserved for global namespace. Allocate past it rather than substituting 1,
            // which the table has not handed out yet and would give to the next record too.
            next_id = table_lock.get_next_key();
        }

        let address_key = self.addr_map.read().unwrap().get_key(address, true);

        let mut rec = DBRecord::new(table_lock.get_schema(), Field::Long(Some(next_id)));
        rec.set_string(Self::SYMBOL_NAME_COL, Some(name.to_string()));
        rec.set_long(Self::SYMBOL_ADDR_COL, address_key);
        rec.set_long(Self::SYMBOL_PARENT_ID_COL, namespace_id);
        rec.set_byte(Self::SYMBOL_TYPE_COL, symbol_type.get_id() as i8);
        rec.set_byte(
            Self::SYMBOL_FLAGS_COL,
            Self::get_source_type_flags_bits(source) as i8,
        );

        if let Some(hash) = Self::compute_locator_hash(name, namespace_id, address_key) {
            rec.set_long(Self::SYMBOL_HASH_COL, hash);
        }

        if is_primary {
            rec.set_long(Self::SYMBOL_PRIMARY_COL, address_key);
        }

        table_lock.put_record(rec.clone())?;

        Ok(rec)
    }

    pub fn record_to_symbol(&self, rec: DBRecord) -> io::Result<Arc<dyn Symbol>> {
        let id = rec.get_key().get_long_value();
        let name = rec
            .get_string(Self::SYMBOL_NAME_COL)
            .unwrap_or("")
            .to_string();
        let addr_key = rec.get_long(Self::SYMBOL_ADDR_COL).unwrap();
        let parent_id = rec.get_long(Self::SYMBOL_PARENT_ID_COL).unwrap();
        let type_id = rec.get_byte(Self::SYMBOL_TYPE_COL).unwrap() as i32;
        let flags = rec.get_byte(Self::SYMBOL_FLAGS_COL).unwrap() as u8;
        let primary_key = rec.get_long(Self::SYMBOL_PRIMARY_COL).unwrap_or(0);

        let symbol_type = SymbolType::get_symbol_type(type_id).unwrap_or(SymbolType::Label);
        let source = Self::get_source_type_from_flags(flags);
        let is_primary = primary_key != 0;

        let address = self.addr_map.read().unwrap().decode_address(addr_key);

        let mut symbol = SymbolDB::new(id, name, address, symbol_type, parent_id, is_primary, source);
        symbol.pinned = flags & Self::SYMBOL_PINNED_FLAG != 0;
        Ok(Arc::new(symbol))
    }

    /// Every symbol record, in table (ID) order.
    fn all_records(&self) -> io::Result<Vec<DBRecord>> {
        let handle = self.db_handle.read().unwrap();
        let mut records = Vec::new();
        if let Some(table) = handle.get_table(Self::SYMBOL_TABLE_NAME) {
            let table_lock = table.read().unwrap();
            let mut it = table_lock.get_record_iterator()?;
            while let Some(rec) = it.next()? {
                records.push(rec);
            }
        }
        Ok(records)
    }

    /// The records at `addr`, in table (ID) order.
    fn records_at(&self, addr: &Address) -> io::Result<Vec<DBRecord>> {
        let addr_key = self.addr_map.read().unwrap().get_key(addr, false);
        Ok(self
            .all_records()?
            .into_iter()
            .filter(|rec| rec.get_long(Self::SYMBOL_ADDR_COL) == Some(addr_key))
            .collect())
    }

    fn put_record(&self, rec: DBRecord) -> io::Result<()> {
        let handle = self.db_handle.read().unwrap();
        let table = handle
            .get_table(Self::SYMBOL_TABLE_NAME)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Symbol table not found"))?;
        let mut table_lock = table.write().unwrap();
        table_lock.put_record(rec)
    }

    /// Every symbol, ordered by address (ties in ID order) as Java's `getSymbolsByAddress`
    /// index orders them.
    fn symbols_by_address(&self) -> io::Result<Vec<Arc<dyn Symbol>>> {
        let mut symbols = self
            .all_records()?
            .into_iter()
            .map(|rec| self.record_to_symbol(rec))
            .collect::<io::Result<Vec<_>>>()?;
        symbols.sort_by(|a, b| a.get_address().cmp(&b.get_address()));
        Ok(symbols)
    }

    /// Mirrors `SymbolManager.createLabel(Address, String, Namespace, SourceType)` for a
    /// resolved namespace ID: an existing symbol with the same name and namespace at `addr` is
    /// returned as is; otherwise the new label is primary only when no primary symbol is at
    /// `addr` yet.
    fn create_label_with_namespace_id(
        &mut self,
        addr: &Address,
        name: &str,
        namespace_id: i64,
        source: SourceType,
    ) -> io::Result<Arc<dyn Symbol>> {
        if !addr.is_memory_address() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Invalid memory address: {addr}"),
            ));
        }
        let mut make_primary = true;
        for rec in self.records_at(addr)? {
            if rec.get_string(Self::SYMBOL_NAME_COL) == Some(name)
                && rec.get_long(Self::SYMBOL_PARENT_ID_COL) == Some(namespace_id)
            {
                return self.record_to_symbol(rec);
            }
            if rec.get_long(Self::SYMBOL_PRIMARY_COL).unwrap_or(0) != 0 {
                make_primary = false;
            }
        }
        let rec = self.create_symbol_record(name, namespace_id, addr, SymbolType::Label, make_primary, source)?;
        self.record_to_symbol(rec)
    }

    /// Computes the java `String.hashCode()` equivalent for a string.
    fn java_string_hash(s: &str) -> i32 {
        let mut hash = 0i32;
        for c in s.encode_utf16() {
            hash = hash.wrapping_mul(31).wrapping_add(c as i32);
        }
        hash
    }

    /// Computes Java's `Objects.hash(name, namespaceID)` and combines it with address key.
    pub fn compute_locator_hash(name: &str, namespace_id: i64, address_key: i64) -> Option<i64> {
        if name.is_empty() {
            return None;
        }

        let name_hash = Self::java_string_hash(name);
        let namespace_hash = (namespace_id ^ (namespace_id.wrapping_shr(32))) as i32;

        let mut hash = 1i32;
        hash = hash.wrapping_mul(31).wrapping_add(name_hash);
        hash = hash.wrapping_mul(31).wrapping_add(namespace_hash);

        let combined_hash = ((hash as i64) << 32) | (address_key & 0xFFFFFFFF);
        Some(combined_hash)
    }

    pub fn get_source_type_flags_bits(source: SourceType) -> u8 {
        let storage_id = source.storage_id() as u8;
        let mut flags = 0u8;
        flags |= storage_id & 0x3; // lower 2 bits
        flags |= (storage_id & 0x4) << 1; // 3rd bit moves to bit 3
        flags
    }

    pub fn get_source_type_from_flags(flags: u8) -> SourceType {
        let mut storage_id = flags & 0x3;
        storage_id |= (flags & 0x8) >> 1;
        SourceType::from_storage_id(storage_id as i32).unwrap_or(SourceType::Default)
    }
}

impl SymbolTable for SymbolManagerDB {
    /// Mirrors `SymbolManager.createLabel(Address, String, SourceType)` -- see
    /// [`create_label_in_namespace`](SymbolTable::create_label_in_namespace) for the primary and
    /// duplicate rules.
    fn create_label(
        &mut self,
        addr: &Address,
        name: &str,
        source: SourceType,
    ) -> io::Result<Arc<dyn Symbol>> {
        let namespace_id = self.namespace_mgr.read().unwrap().get_namespace_id(addr)?;
        self.create_label_with_namespace_id(addr, name, namespace_id, source)
    }

    /// Mirrors `SymbolManager.createLabel(Address, String, Namespace, SourceType)`: returns the
    /// existing symbol of that name and namespace at `addr` if there is one, else creates a label
    /// that is primary exactly when `addr` has no primary symbol yet.
    fn create_label_in_namespace(
        &mut self,
        addr: &Address,
        name: &str,
        namespace: Arc<dyn Namespace>,
        source: SourceType,
    ) -> io::Result<Arc<dyn Symbol>> {
        self.create_label_with_namespace_id(addr, name, namespace.get_id(), source)
    }

    /// Mirrors `SymbolManager.getAllSymbols(boolean)`. This symbol manager creates no dynamic
    /// symbols, so `include_dynamic_symbols` changes nothing.
    fn get_all_symbols(&self, include_dynamic_symbols: bool) -> Box<dyn SymbolIterator> {
        let _ = include_dynamic_symbols;
        Box::new(SymbolIteratorAdapter::new(self.symbols_by_address().unwrap_or_default()))
    }

    /// Mirrors `SymbolManager.getSymbolIterator(Address, boolean)`: the symbols at and after
    /// (`forward`) or at and before `start_addr`, in address order.
    fn get_symbol_iterator_from(&self, start_addr: &Address, forward: bool) -> Box<dyn SymbolIterator> {
        let mut symbols = self.symbols_by_address().unwrap_or_default();
        if forward {
            symbols.retain(|s| s.get_address() >= *start_addr);
        } else {
            symbols.retain(|s| s.get_address() <= *start_addr);
            symbols.reverse();
        }
        Box::new(SymbolIteratorAdapter::new(symbols))
    }

    /// Mirrors `SymbolManager.getSymbolIterator(String, boolean)`: the symbols whose whole name
    /// matches `search_str` as a `UserSearchUtils.createSearchPattern` glob (`*`, `?`).
    fn get_symbol_iterator(&self, search_str: &str, case_sensitive: bool) -> Box<dyn SymbolIterator> {
        // Java's `Matcher.matches()`: the whole name must match the glob's regex
        let regex = format!("^(?:{})$", UserSearchUtils::create_pattern_string(search_str, true));
        let Ok(pattern) = regex::RegexBuilder::new(&regex).case_insensitive(!case_sensitive).build() else {
            return Box::new(SymbolIteratorAdapter::new(Vec::new()));
        };
        let matches = |name: &str| pattern.is_match(name);
        let symbols = self
            .all_records()
            .unwrap_or_default()
            .into_iter()
            .filter(|rec| matches(rec.get_string(Self::SYMBOL_NAME_COL).unwrap_or("")))
            .filter_map(|rec| self.record_to_symbol(rec).ok())
            .collect();
        Box::new(SymbolIteratorAdapter::new(symbols))
    }

    /// Mirrors `SymbolManager.getPrimarySymbol(Address)` for memory addresses (no dynamic
    /// symbols: there is no reference manager to ask whether `addr` is referenced).
    fn get_primary_symbol(&self, addr: &Address) -> io::Result<Option<Arc<dyn Symbol>>> {
        if !addr.is_memory_address() {
            return Ok(None);
        }
        for rec in self.records_at(addr)? {
            if rec.get_long(Self::SYMBOL_PRIMARY_COL).unwrap_or(0) != 0 {
                return Ok(Some(self.record_to_symbol(rec)?));
            }
        }
        Ok(None)
    }

    /// Mirrors `CodeSymbol.setPrimary()`: false if the symbol is missing or already primary;
    /// otherwise the current primary symbol at its address stops being primary and this one
    /// becomes it.
    fn set_primary_symbol(&mut self, symbol_id: i64) -> io::Result<bool> {
        let handle = self.db_handle.read().unwrap();
        let Some(table) = handle.get_table(Self::SYMBOL_TABLE_NAME) else {
            return Ok(false);
        };
        let Some(mut rec) = table.read().unwrap().get_record(&Field::Long(Some(symbol_id)))? else {
            return Ok(false);
        };
        if rec.get_long(Self::SYMBOL_PRIMARY_COL).unwrap_or(0) != 0 {
            return Ok(false);
        }
        drop(handle);
        let addr_key = rec.get_long(Self::SYMBOL_ADDR_COL).unwrap_or(0);
        let address = self.addr_map.read().unwrap().decode_address(addr_key);
        for mut other in self.records_at(&address)? {
            if other.get_long(Self::SYMBOL_PRIMARY_COL).unwrap_or(0) != 0 {
                other.set_long(Self::SYMBOL_PRIMARY_COL, 0);
                self.put_record(other)?;
            }
        }
        rec.set_long(Self::SYMBOL_PRIMARY_COL, addr_key);
        self.put_record(rec)?;
        Ok(true)
    }

    fn add_external_entry_point(&mut self, addr: &Address) -> io::Result<()> {
        self.external_entry_points.insert(addr.clone());
        Ok(())
    }

    fn remove_external_entry_point(&mut self, addr: &Address) -> io::Result<()> {
        self.external_entry_points.remove(addr);
        Ok(())
    }

    fn is_external_entry_point(&self, addr: &Address) -> io::Result<bool> {
        Ok(self.external_entry_points.contains(addr))
    }

    fn get_external_entry_point_iterator(&self) -> BoxedAddressIterator {
        Box::new(self.external_entry_points.iter().cloned().collect::<Vec<_>>().into_iter())
    }

    fn get_symbol(&self, id: i64) -> io::Result<Option<Arc<dyn Symbol>>> {
        let handle = self.db_handle.read().unwrap();
        if let Some(table) = handle.get_table(Self::SYMBOL_TABLE_NAME) {
            if let Some(rec) = table.read().unwrap().get_record(&Field::Long(Some(id)))? {
                return Ok(Some(self.record_to_symbol(rec)?));
            }
        }
        Ok(None)
    }

    fn get_symbols(&self, addr: &Address) -> io::Result<Vec<Arc<dyn Symbol>>> {
        // This is inefficient without a secondary index iterator: every record is scanned.
        self.records_at(addr)?.into_iter().map(|rec| self.record_to_symbol(rec)).collect()
    }

    /// Mirrors `SymbolDB.setName(String, SourceType)` (`doSetNameAndNamespace` without a
    /// namespace change) for labels in memory: `CodeSymbol.validateNameSource` turns a DEFAULT
    /// source into ANALYSIS; the source must be valid for the symbol type
    /// (`SymbolManager.validateSource`) and the name pass `SymbolUtilities.validateName`; an
    /// unchanged name changes nothing (not even the source); another symbol of the new name in
    /// the same namespace at the address is a duplicate (`checkDuplicateSymbolName` -- labels
    /// elsewhere may share it). The record's name, source bits and locator hash are rewritten.
    ///
    /// Not ported: renaming other symbol types (functions, namespaces, externals), the
    /// register-name check (`checkEditOK`), dynamic symbol conversion, label history and the
    /// rename event.
    fn set_symbol_name(&mut self, symbol_id: i64, new_name: &str, source: SourceType) -> Result<(), SetSymbolNameError> {
        struct Utils;
        impl SymbolUtilities for Utils {}
        let invalid = |msg: String| SetSymbolNameError::InvalidInput(InvalidInputException::with_message(msg));
        let record = {
            let handle = self.db_handle.read().unwrap();
            let table = handle.get_table(Self::SYMBOL_TABLE_NAME).ok_or_else(|| invalid("Symbol table not found".into()))?;
            let record = table.read().unwrap().get_record(&Field::Long(Some(symbol_id)));
            record.map_err(|e| invalid(e.to_string()))?
        };
        let Some(mut rec) = record else {
            return Err(invalid(format!("Symbol {symbol_id} has been deleted")));
        };
        let type_id = rec.get_byte(Self::SYMBOL_TYPE_COL).unwrap_or(0) as i32;
        let symbol_type = SymbolType::get_symbol_type(type_id).unwrap_or(SymbolType::Label);
        let old_name = rec.get_string(Self::SYMBOL_NAME_COL).unwrap_or("").to_string();
        let addr_key = rec.get_long(Self::SYMBOL_ADDR_COL).unwrap_or(0);
        let address = self.addr_map.read().unwrap().decode_address(addr_key);
        if symbol_type != SymbolType::Label || !address.is_memory_address() {
            return Err(invalid(format!("Renaming {symbol_type:?} symbol {old_name} is not supported")));
        }
        // CodeSymbol.validateNameSource
        let source = if source == SourceType::Default { SourceType::Analysis } else { source };
        if !symbol_type.is_valid_source_type(source, &address) {
            return Err(invalid(format!(
                "Can't set source to {source:?} for symbol '{new_name}' since it is a {symbol_type:?} symbol type."
            )));
        }
        Utils.validate_name(Some(new_name)).map_err(SetSymbolNameError::InvalidInput)?;
        if old_name == new_name {
            return Ok(());
        }
        let parent_id = rec.get_long(Self::SYMBOL_PARENT_ID_COL).unwrap_or(0);
        let records = self.records_at(&address).map_err(|e| invalid(e.to_string()))?;
        if records.iter().any(|other| {
            other.get_string(Self::SYMBOL_NAME_COL) == Some(new_name)
                && other.get_long(Self::SYMBOL_PARENT_ID_COL) == Some(parent_id)
        }) {
            return Err(SetSymbolNameError::Duplicate(DuplicateNameException(format!(
                "A symbol named {new_name} already exists at this address!"
            ))));
        }
        // labels allow duplicates: no namespace-wide check
        rec.set_string(Self::SYMBOL_NAME_COL, Some(new_name.to_string()));
        let mut flags = rec.get_byte(Self::SYMBOL_FLAGS_COL).unwrap_or(0) as u8;
        flags &= !Self::SYMBOL_SOURCE_MASK;
        flags |= Self::get_source_type_flags_bits(source);
        rec.set_byte(Self::SYMBOL_FLAGS_COL, flags as i8);
        if let Some(hash) = Self::compute_locator_hash(new_name, parent_id, addr_key) {
            rec.set_long(Self::SYMBOL_HASH_COL, hash);
        }
        self.put_record(rec).map_err(|e| invalid(e.to_string()))
    }

    fn set_symbol_pinned(&mut self, symbol_id: i64, pinned: bool) -> io::Result<()> {
        let handle = self.db_handle.read().unwrap();
        if let Some(table) = handle.get_table(Self::SYMBOL_TABLE_NAME) {
            // bind the record first: an `if let` scrutinee's read guard would live through the
            // body and deadlock the `write()` below
            let record = table.read().unwrap().get_record(&Field::Long(Some(symbol_id)))?;
            if let Some(mut rec) = record {
                let mut flags = rec.get_byte(Self::SYMBOL_FLAGS_COL).unwrap_or(0) as u8;
                if pinned {
                    flags |= Self::SYMBOL_PINNED_FLAG;
                } else {
                    flags &= !Self::SYMBOL_PINNED_FLAG;
                }
                rec.set_byte(Self::SYMBOL_FLAGS_COL, flags as i8);
                table.write().unwrap().put_record(rec)?;
            }
        }
        Ok(())
    }
}

impl ManagerDB for SymbolManagerDB {
    fn invalidate_cache(&mut self, _all: bool) -> io::Result<()> {
        Ok(())
    }

    fn delete_address_range(
        &mut self,
        _start_addr: &Address,
        _end_addr: &Address,
    ) -> io::Result<()> {
        Ok(())
    }

    fn move_address_range(
        &mut self,
        _from_addr: &Address,
        _to_addr: &Address,
        _length: u64,
    ) -> io::Result<()> {
        Ok(())
    }
}

/// Port of `ghidra.program.database.symbol.SymbolManager` as a trait (cycle cut-point).
///
/// The Java class is a ~3500-line concrete `SymbolTable`/`ManagerDB` implementation that directly
/// wires together a dozen other DB-backed managers (`ReferenceDBManager`, `NamespaceManager`,
/// `VariableStorageManagerDB`, `ExternalManagerDB`, `FunctionManagerDB`, `CodeManager`,
/// `ProgramDB`, ...), several of which are themselves unported and would otherwise pull this port
/// back into a `SymbolManager`/`ProgramDB`/`NamespaceManager` cycle.
///
/// `SymbolManagerDb` captures the class's own public surface -- the parts not already covered by
/// the already-ported [`SymbolTable`] and [`ManagerDB`] interfaces it implements -- against
/// already-ported trait objects ([`VariableStorageManager`], [`Library`], [`SymbolIterator`]) so a
/// concrete implementor can be added later without reintroducing the cycle. Method names mirror
/// the corresponding `SymbolManager` Java methods (`snake_case`d).
pub trait SymbolManagerDb: SymbolTable + ManagerDB {
    /// Accessor for the backing variable storage manager (`SymbolManager.variableStorageMgr`).
    fn variable_storage_manager(&self) -> Arc<dyn VariableStorageManager + Send + Sync>;

    /// Stands in for `SymbolManager.findVariableStorageAddress(VariableStorage)`.
    fn find_variable_storage_address(
        &self,
        storage: &dyn VariableStorage,
    ) -> io::Result<Option<Address>> {
        self.variable_storage_manager()
            .get_variable_storage_address(storage, false)
    }

    /// Stands in for `SymbolManager.getLibrarySymbol(String)`.
    fn get_library_symbol(&self, name: &str) -> io::Result<Option<Arc<dyn Symbol>>>;

    /// Stands in for `SymbolManager.getMaxSymbolAddress(AddressSpace)`.
    fn get_max_symbol_address(&self, space: &AddressSpace) -> Option<Address>;

    /// Stands in for `SymbolManager.namespaceRemoved(long)`.
    fn namespace_removed(&mut self, namespace_id: i64) -> io::Result<()>;

    /// Stands in for `SymbolManager.moveSymbolsAt(Address, Address)`. Only the symbol address is
    /// changed; references must be moved separately.
    fn move_symbols_at(&mut self, old_addr: &Address, new_addr: &Address) -> io::Result<()>;

    /// Stands in for `SymbolManager.getDynamicSymbolID(Address)`.
    fn get_dynamic_symbol_id(&self, addr: &Address) -> i64;

    /// Stands in for `SymbolManager.getExternalSymbolByOriginalImportName(Library, String)`.
    /// `library` of `None` mirrors the Java overload's nullable "ignore" constraint.
    fn get_external_symbol_by_original_import_name(
        &self,
        library: Option<&dyn Library>,
        ext_label: &str,
    ) -> Box<dyn SymbolIterator>;

    /// Stands in for `SymbolManager.getExternalSymbolByMemoryAddress(Library, Address)`. `library`
    /// of `None` mirrors the Java overload's nullable "ignore" constraint.
    fn get_external_symbol_by_memory_address(
        &self,
        library: Option<&dyn Library>,
        ext_prog_addr: &Address,
    ) -> Box<dyn SymbolIterator>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType, DefaultAddressFactory};

    #[test]
    fn test_create_and_get_symbol() {
        let handle = Arc::new(RwLock::new(DBHandle::new().unwrap()));
        let space = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 0);
        let factory = Arc::new(DefaultAddressFactory::new(vec![space.clone()]));
        let addr_map = Arc::new(RwLock::new(
            AddressMapDB::new(handle.clone(), factory).unwrap(),
        ));
        let namespace_mgr = Arc::new(RwLock::new(
            NamespaceManagerDB::new(handle.clone(), addr_map.clone()).unwrap(),
        ));
        let mut manager = SymbolManagerDB::new(handle, addr_map, namespace_mgr, true).unwrap();

        let addr = Address::new(space, 0x1234);

        let sym = manager
            .create_label(&addr, "MyLabel", SourceType::UserDefined)
            .unwrap();

        assert_eq!(sym.get_name(), "MyLabel");
        assert_eq!(sym.get_address().offset(), 0x1234);

        let fetched = manager.get_symbol(sym.get_id()).unwrap().unwrap();
        assert_eq!(fetched.get_name(), "MyLabel");
    }

    struct MockVariableStorageManager {
        slot: std::sync::Mutex<Option<Address>>,
    }

    impl VariableStorageManager for MockVariableStorageManager {
        fn get_variable_storage_address(
            &self,
            _storage: &dyn VariableStorage,
            create: bool,
        ) -> io::Result<Option<Address>> {
            let mut slot = self.slot.lock().unwrap();
            if let Some(addr) = slot.clone() {
                return Ok(Some(addr));
            }
            if !create {
                return Ok(None);
            }
            let space = AddressSpace::new("const", 32, 1, AddressSpaceType::Constant, 0);
            let addr = Address::new(space, 0);
            *slot = Some(addr.clone());
            Ok(Some(addr))
        }
    }

    struct MockSymbolManagerDb {
        symbols: RwLock<Vec<Arc<dyn Symbol>>>,
        var_storage: Arc<dyn VariableStorageManager + Send + Sync>,
        removed_namespaces: RwLock<Vec<i64>>,
    }

    impl MockSymbolManagerDb {
        fn new() -> Self {
            MockSymbolManagerDb {
                symbols: RwLock::new(Vec::new()),
                var_storage: Arc::new(MockVariableStorageManager {
                    slot: std::sync::Mutex::new(None),
                }),
                removed_namespaces: RwLock::new(Vec::new()),
            }
        }
    }

    impl SymbolTable for MockSymbolManagerDb {
        fn create_label(
            &mut self,
            addr: &Address,
            name: &str,
            source: SourceType,
        ) -> io::Result<Arc<dyn Symbol>> {
            let mut symbols = self.symbols.write().unwrap();
            let id = symbols.len() as i64 + 1;
            let sym: Arc<dyn Symbol> = Arc::new(SymbolDB::new(
                id,
                name.to_string(),
                addr.clone(),
                SymbolType::Label,
                0,
                true,
                source,
            ));
            symbols.push(sym.clone());
            Ok(sym)
        }

        fn get_symbol(&self, id: i64) -> io::Result<Option<Arc<dyn Symbol>>> {
            Ok(self
                .symbols
                .read()
                .unwrap()
                .iter()
                .find(|s| s.get_id() == id)
                .cloned())
        }

        fn get_symbols(&self, addr: &Address) -> io::Result<Vec<Arc<dyn Symbol>>> {
            Ok(self
                .symbols
                .read()
                .unwrap()
                .iter()
                .filter(|s| s.get_address().offset() == addr.offset())
                .cloned()
                .collect())
        }
    }

    impl ManagerDB for MockSymbolManagerDb {
        fn invalidate_cache(&mut self, _all: bool) -> io::Result<()> {
            Ok(())
        }

        fn delete_address_range(
            &mut self,
            _start_addr: &Address,
            _end_addr: &Address,
        ) -> io::Result<()> {
            Ok(())
        }

        fn move_address_range(
            &mut self,
            _from_addr: &Address,
            _to_addr: &Address,
            _length: u64,
        ) -> io::Result<()> {
            Ok(())
        }
    }

    impl SymbolManagerDb for MockSymbolManagerDb {
        fn variable_storage_manager(&self) -> Arc<dyn VariableStorageManager + Send + Sync> {
            self.var_storage.clone()
        }

        fn get_library_symbol(&self, name: &str) -> io::Result<Option<Arc<dyn Symbol>>> {
            Ok(self
                .symbols
                .read()
                .unwrap()
                .iter()
                .find(|s| s.get_symbol_type() == SymbolType::Library && s.get_name() == name)
                .cloned())
        }

        fn get_max_symbol_address(&self, space: &AddressSpace) -> Option<Address> {
            self.symbols
                .read()
                .unwrap()
                .iter()
                .map(|s| s.get_address())
                .filter(|a| a.space().as_ref() == space)
                .max_by_key(|a| a.offset())
        }

        fn namespace_removed(&mut self, namespace_id: i64) -> io::Result<()> {
            self.symbols
                .write()
                .unwrap()
                .retain(|s| s.get_parent_id() != namespace_id);
            self.removed_namespaces.write().unwrap().push(namespace_id);
            Ok(())
        }

        fn move_symbols_at(&mut self, old_addr: &Address, new_addr: &Address) -> io::Result<()> {
            let mut symbols = self.symbols.write().unwrap();
            let moved: Vec<Arc<dyn Symbol>> = symbols
                .iter()
                .filter(|s| s.get_address().offset() == old_addr.offset())
                .map(|s| {
                    let moved_sym: Arc<dyn Symbol> = Arc::new(SymbolDB::new(
                        s.get_id(),
                        s.get_name().to_string(),
                        new_addr.clone(),
                        s.get_symbol_type(),
                        s.get_parent_id(),
                        s.is_primary(),
                        s.get_source(),
                    ));
                    moved_sym
                })
                .collect();
            symbols.retain(|s| s.get_address().offset() != old_addr.offset());
            symbols.extend(moved);
            Ok(())
        }

        fn get_dynamic_symbol_id(&self, addr: &Address) -> i64 {
            addr.offset() | (0x40i64 << 56)
        }

        fn get_external_symbol_by_original_import_name(
            &self,
            _library: Option<&dyn Library>,
            ext_label: &str,
        ) -> Box<dyn SymbolIterator> {
            let matches: Vec<Arc<dyn Symbol>> = self
                .symbols
                .read()
                .unwrap()
                .iter()
                .filter(|s| s.get_name() == ext_label)
                .cloned()
                .collect();
            Box::new(crate::program::model::symbol::SymbolIteratorAdapter::new(
                matches,
            ))
        }

        fn get_external_symbol_by_memory_address(
            &self,
            _library: Option<&dyn Library>,
            ext_prog_addr: &Address,
        ) -> Box<dyn SymbolIterator> {
            let matches: Vec<Arc<dyn Symbol>> = self
                .symbols
                .read()
                .unwrap()
                .iter()
                .filter(|s| s.get_address().offset() == ext_prog_addr.offset())
                .cloned()
                .collect();
            Box::new(crate::program::model::symbol::SymbolIteratorAdapter::new(
                matches,
            ))
        }
    }

    #[test]
    fn trait_object_usage_is_object_safe() {
        let space = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 0);
        let mut mgr: Box<dyn SymbolManagerDb> = Box::new(MockSymbolManagerDb::new());

        let addr1 = Address::new(space.clone(), 0x1000);
        let addr2 = Address::new(space.clone(), 0x2000);

        mgr.create_label(&addr1, "foo", SourceType::UserDefined)
            .unwrap();
        mgr.create_label(&addr2, "libentry", SourceType::UserDefined)
            .unwrap();

        assert_eq!(
            mgr.get_max_symbol_address(&space).unwrap().offset(),
            0x2000
        );

        mgr.move_symbols_at(&addr1, &addr2).unwrap();
        assert!(mgr.get_symbols(&addr1).unwrap().is_empty());
        assert_eq!(mgr.get_symbols(&addr2).unwrap().len(), 2);

        let mut it = mgr.get_external_symbol_by_original_import_name(None, "libentry");
        assert!(it.has_next());

        let allocated = mgr
            .variable_storage_manager()
            .get_variable_storage_address(&crate::program::seam_stubs::PlaceholderVariableStorage, true)
            .unwrap()
            .unwrap();
        let found = mgr
            .find_variable_storage_address(&crate::program::seam_stubs::PlaceholderVariableStorage)
            .unwrap()
            .unwrap();
        assert_eq!(allocated, found);

        mgr.namespace_removed(0).unwrap();
        assert!(mgr.get_symbols(&addr2).unwrap().is_empty());

        assert_eq!(mgr.get_dynamic_symbol_id(&addr1), addr1.offset() | (0x40i64 << 56));
    }
}

/// Java-derived behaviour of the concrete [`SymbolManagerDB`]: `SymbolManager.createLabel`'s
/// primary/duplicate rules, `getPrimarySymbol`, `CodeSymbol.setPrimary`, pinning, the address-
/// and name-ordered iterators and the external entry point set.
#[cfg(test)]
mod symbol_manager_db_tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType, DefaultAddressFactory};

    fn manager() -> (SymbolManagerDB, Arc<AddressSpace>) {
        let handle = Arc::new(RwLock::new(DBHandle::new().unwrap()));
        let space = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 1);
        let factory = Arc::new(DefaultAddressFactory::new(vec![space.clone()]));
        let addr_map = Arc::new(RwLock::new(AddressMapDB::new(handle.clone(), factory).unwrap()));
        let namespace_mgr =
            Arc::new(RwLock::new(NamespaceManagerDB::new(handle.clone(), addr_map.clone()).unwrap()));
        (SymbolManagerDB::new(handle, addr_map, namespace_mgr, true).unwrap(), space)
    }

    /// A namespace that only has an ID -- all `createLabel(.., Namespace, ..)` reads from it.
    struct TestNamespace(i64);

    impl crate::program::model::symbol::Namespace for TestNamespace {
        fn get_symbol(&self) -> Arc<dyn Symbol> {
            unreachable!("createLabel only needs the namespace ID")
        }
        fn get_parent_namespace(&self) -> Option<Arc<dyn crate::program::model::symbol::Namespace>> {
            None
        }
        fn get_id(&self) -> i64 {
            self.0
        }
    }

    fn names(mut it: Box<dyn SymbolIterator>) -> Vec<String> {
        let mut out = Vec::new();
        while let Some(s) = it.next_symbol() {
            out.push(s.get_name().to_string());
        }
        out
    }

    #[test]
    fn first_label_at_an_address_is_primary_and_later_ones_are_not() {
        let (mut mgr, space) = manager();
        let addr = Address::new(space, 0x100);
        let first = mgr.create_label(&addr, "first", SourceType::Imported).unwrap();
        let second = mgr.create_label(&addr, "second", SourceType::Imported).unwrap();
        assert!(first.is_primary());
        assert!(!second.is_primary());
        assert_eq!(mgr.get_primary_symbol(&addr).unwrap().unwrap().get_name(), "first");
    }

    #[test]
    fn creating_an_existing_label_returns_the_existing_symbol() {
        let (mut mgr, space) = manager();
        let addr = Address::new(space, 0x100);
        let first = mgr.create_label(&addr, "dup", SourceType::Imported).unwrap();
        let again = mgr.create_label(&addr, "dup", SourceType::Imported).unwrap();
        assert_eq!(first.get_id(), again.get_id());
        assert_eq!(mgr.get_symbols(&addr).unwrap().len(), 1);
    }

    #[test]
    fn primary_symbol_is_none_where_there_are_no_symbols() {
        let (mgr, space) = manager();
        assert!(mgr.get_primary_symbol(&Address::new(space, 0x100)).unwrap().is_none());
    }

    #[test]
    fn set_primary_moves_primary_status_from_the_old_symbol() {
        let (mut mgr, space) = manager();
        let addr = Address::new(space, 0x100);
        let first = mgr.create_label(&addr, "first", SourceType::Imported).unwrap();
        let second = mgr.create_label(&addr, "second", SourceType::Imported).unwrap();
        assert!(mgr.set_primary_symbol(second.get_id()).unwrap());
        assert_eq!(mgr.get_primary_symbol(&addr).unwrap().unwrap().get_name(), "second");
        assert!(!mgr.get_symbol(first.get_id()).unwrap().unwrap().is_primary());
        // already primary: CodeSymbol.setPrimary answers false
        assert!(!mgr.set_primary_symbol(second.get_id()).unwrap());
    }

    #[test]
    fn pinned_flag_reads_back_and_keeps_the_source() {
        let (mut mgr, space) = manager();
        let addr = Address::new(space, 0x100);
        let sym = mgr.create_label(&addr, "abs", SourceType::Imported).unwrap();
        assert!(!sym.is_pinned());
        mgr.set_symbol_pinned(sym.get_id(), true).unwrap();
        let sym = mgr.get_symbol(sym.get_id()).unwrap().unwrap();
        assert!(sym.is_pinned());
        assert_eq!(sym.get_source(), SourceType::Imported);
    }

    #[test]
    fn label_in_namespace_records_the_parent_namespace() {
        let (mut mgr, space) = manager();
        let addr = Address::new(space, 0x100);
        let ns: Arc<dyn crate::program::model::symbol::Namespace> = Arc::new(TestNamespace(42));
        let sym = mgr.create_label_in_namespace(&addr, "inner", ns, SourceType::Imported).unwrap();
        assert_eq!(sym.get_parent_id(), 42);
    }

    #[test]
    fn all_symbols_iterate_in_address_order() {
        let (mut mgr, space) = manager();
        mgr.create_label(&Address::new(space.clone(), 0x300), "c", SourceType::Imported).unwrap();
        mgr.create_label(&Address::new(space.clone(), 0x100), "a", SourceType::Imported).unwrap();
        mgr.create_label(&Address::new(space.clone(), 0x200), "b", SourceType::Imported).unwrap();
        assert_eq!(names(mgr.get_all_symbols(true)), ["a", "b", "c"]);
        assert_eq!(names(mgr.get_symbol_iterator_from(&Address::new(space.clone(), 0x200), true)), ["b", "c"]);
        assert_eq!(names(mgr.get_symbol_iterator_from(&Address::new(space, 0x200), false)), ["b", "a"]);
    }

    #[test]
    fn name_queries_match_globs_and_exact_names() {
        let (mut mgr, space) = manager();
        mgr.create_label(&Address::new(space.clone(), 0x100), "printf", SourceType::Imported).unwrap();
        mgr.create_label(&Address::new(space.clone(), 0x200), "puts", SourceType::Imported).unwrap();
        mgr.create_label(&Address::new(space, 0x300), "Puts", SourceType::Imported).unwrap();
        let mut found = names(mgr.get_symbol_iterator("p*", true));
        found.sort();
        assert_eq!(found, ["printf", "puts"]);
        let mut found = names(mgr.get_symbol_iterator("p?ts", false));
        found.sort();
        assert_eq!(found, ["Puts", "puts"]);
        let by_name = mgr.get_symbols_by_name("puts").unwrap();
        assert_eq!(by_name.len(), 1);
        assert_eq!(by_name[0].get_address().offset(), 0x200);
    }

    /// `SymbolDB.setName` for a label: the name and source change; primary and pinned stay.
    #[test]
    fn renaming_a_label_changes_its_name_and_source() {
        let (mut mgr, space) = manager();
        let addr = Address::new(space, 0x100);
        let sym = mgr.create_label(&addr, "old", SourceType::Imported).unwrap();
        mgr.set_symbol_pinned(sym.get_id(), true).unwrap();
        mgr.set_symbol_name(sym.get_id(), "new_name", SourceType::UserDefined).unwrap();
        let renamed = mgr.get_symbol(sym.get_id()).unwrap().unwrap();
        assert_eq!(renamed.get_name(), "new_name");
        assert_eq!(renamed.get_source(), SourceType::UserDefined);
        assert!(renamed.is_primary());
        assert!(renamed.is_pinned());
        assert!(mgr.get_symbols_by_name("old").unwrap().is_empty());
        assert_eq!(mgr.get_symbols_by_name("new_name").unwrap().len(), 1);
        // a stored locator hash follows the new name
        let rec = mgr.records_at(&addr).unwrap().remove(0);
        let key = rec.get_long(SymbolManagerDB::SYMBOL_ADDR_COL).unwrap();
        assert_eq!(
            rec.get_long(SymbolManagerDB::SYMBOL_HASH_COL),
            SymbolManagerDB::compute_locator_hash("new_name", sym.get_parent_id(), key)
        );
    }

    /// `CodeSymbol.validateNameSource`: a label renamed with DEFAULT source becomes ANALYSIS.
    #[test]
    fn renaming_a_label_with_default_source_records_analysis() {
        let (mut mgr, space) = manager();
        let sym = mgr.create_label(&Address::new(space, 0x100), "old", SourceType::Imported).unwrap();
        mgr.set_symbol_name(sym.get_id(), "auto", SourceType::Default).unwrap();
        assert_eq!(mgr.get_symbol(sym.get_id()).unwrap().unwrap().get_source(), SourceType::Analysis);
    }

    /// Same name: nothing changes, not even the source (Java returns early).
    #[test]
    fn renaming_a_label_to_its_own_name_changes_nothing() {
        let (mut mgr, space) = manager();
        let sym = mgr.create_label(&Address::new(space, 0x100), "same", SourceType::Imported).unwrap();
        mgr.set_symbol_name(sym.get_id(), "same", SourceType::UserDefined).unwrap();
        assert_eq!(mgr.get_symbol(sym.get_id()).unwrap().unwrap().get_source(), SourceType::Imported);
    }

    /// `SymbolManager.checkDuplicateSymbolName`: no two symbols of a name in one namespace at one
    /// address; labels elsewhere may share it.
    #[test]
    fn renaming_a_label_onto_a_name_at_its_address_is_a_duplicate() {
        let (mut mgr, space) = manager();
        let addr = Address::new(space.clone(), 0x100);
        mgr.create_label(&addr, "taken", SourceType::Imported).unwrap();
        let sym = mgr.create_label(&addr, "other", SourceType::Imported).unwrap();
        let err = mgr.set_symbol_name(sym.get_id(), "taken", SourceType::UserDefined).unwrap_err();
        assert!(matches!(err, SetSymbolNameError::Duplicate(_)), "{err:?}");
        assert_eq!(err.to_string(), "A symbol named taken already exists at this address!");
        assert_eq!(mgr.get_symbol(sym.get_id()).unwrap().unwrap().get_name(), "other");
        let elsewhere = mgr.create_label(&Address::new(space, 0x200), "x", SourceType::Imported).unwrap();
        mgr.set_symbol_name(elsewhere.get_id(), "taken", SourceType::UserDefined).unwrap();
        assert_eq!(mgr.get_symbols_by_name("taken").unwrap().len(), 2);
    }

    /// `SymbolUtilities.validateName`, and a missing symbol.
    #[test]
    fn renaming_rejects_invalid_names_and_missing_symbols() {
        let (mut mgr, space) = manager();
        let sym = mgr.create_label(&Address::new(space, 0x100), "ok", SourceType::Imported).unwrap();
        for bad in ["", "has space"] {
            let err = mgr.set_symbol_name(sym.get_id(), bad, SourceType::UserDefined).unwrap_err();
            assert!(matches!(err, SetSymbolNameError::InvalidInput(_)), "{bad:?}: {err:?}");
        }
        assert_eq!(mgr.get_symbol(sym.get_id()).unwrap().unwrap().get_name(), "ok");
        assert!(matches!(
            mgr.set_symbol_name(9999, "x", SourceType::UserDefined),
            Err(SetSymbolNameError::InvalidInput(_))
        ));
    }

    #[test]
    fn external_entry_points_are_a_sorted_address_set() {
        let (mut mgr, space) = manager();
        let a = Address::new(space.clone(), 0x200);
        let b = Address::new(space, 0x100);
        assert!(!mgr.is_external_entry_point(&a).unwrap());
        mgr.add_external_entry_point(&a).unwrap();
        mgr.add_external_entry_point(&b).unwrap();
        mgr.add_external_entry_point(&a).unwrap();
        assert!(mgr.is_external_entry_point(&a).unwrap());
        let all: Vec<i64> = mgr.get_external_entry_point_iterator().map(|x| x.offset()).collect();
        assert_eq!(all, [0x100, 0x200]);
        mgr.remove_external_entry_point(&a).unwrap();
        assert!(!mgr.is_external_entry_point(&a).unwrap());
    }
}

use crate::framework::db::record::DBRecord;
use crate::framework::db::{DBHandle, Field, FieldType, Schema};
use crate::program::database::map::AddressMapDB;
use crate::program::database::symbol::namespace_manager::NamespaceManagerDB;
use crate::program::database::symbol::symbol_db::SymbolDB;
use crate::program::database::ManagerDB;
use crate::program::model::address::Address;
use crate::program::model::symbol::{SourceType, Symbol, SymbolTable, SymbolType};
use std::io;
use std::sync::{Arc, RwLock};

pub struct SymbolManagerDB {
    db_handle: Arc<RwLock<DBHandle>>,
    addr_map: Arc<RwLock<AddressMapDB>>,
    namespace_mgr: Arc<RwLock<NamespaceManagerDB>>,
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
        if next_id <= 0 {
            next_id = 1; // Skip 0, reserved for global namespace
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

        let symbol_type = SymbolType::from_id(type_id).unwrap_or(SymbolType::Label);
        let source = Self::get_source_type_from_flags(flags);
        let is_primary = primary_key != 0;

        let address = self.addr_map.read().unwrap().decode_address(addr_key);

        Ok(Arc::new(SymbolDB::new(
            id,
            name,
            address,
            symbol_type,
            parent_id,
            is_primary,
            source,
        )))
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
    fn create_label(
        &mut self,
        addr: &Address,
        name: &str,
        source: SourceType,
    ) -> io::Result<Arc<dyn Symbol>> {
        let namespace_id = self.namespace_mgr.read().unwrap().get_namespace_id(addr)?;
        let rec =
            self.create_symbol_record(name, namespace_id, addr, SymbolType::Label, true, source)?;
        self.record_to_symbol(rec)
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
        let handle = self.db_handle.read().unwrap();
        let mut results = Vec::new();
        if let Some(table) = handle.get_table(Self::SYMBOL_TABLE_NAME) {
            let addr_key = self.addr_map.read().unwrap().get_key(addr, false);
            // This is inefficient without a secondary index iterator.
            // For now, iterate all (or use the primary index if keys match address order).
            let table_lock = table.read().unwrap();
            let mut it = table_lock.get_record_iterator()?;
            while let Some(rec) = it.next()? {
                if rec.get_long(Self::SYMBOL_ADDR_COL) == Some(addr_key) {
                    results.push(self.record_to_symbol(rec)?);
                }
            }
        }
        Ok(results)
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
}

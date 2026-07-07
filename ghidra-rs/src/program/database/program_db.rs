use crate::framework::db::DBHandle;
use crate::framework::model::DomainObject;
use crate::program::database::map::AddressMapDB;
use crate::program::database::mem::MemoryMapDB;
use crate::program::database::symbol::namespace_manager::NamespaceManagerDB;
use crate::program::database::symbol::SymbolManagerDB;
use crate::program::model::lang::sleigh::SleighLanguage;
use crate::program::model::listing::Program;
use std::io;
use std::sync::{Arc, RwLock};

pub struct ProgramDB {
    db_handle: Arc<RwLock<DBHandle>>,
    name: String,
    language: Arc<SleighLanguage>,
    addr_map: Arc<RwLock<AddressMapDB>>,
    memory: Arc<RwLock<MemoryMapDB>>,
    namespace_mgr: Arc<RwLock<NamespaceManagerDB>>,
    symbol_mgr: Arc<RwLock<SymbolManagerDB>>,
}

impl ProgramDB {
    pub fn new(name: String, language: Arc<SleighLanguage>) -> io::Result<Self> {
        let db_handle = Arc::new(RwLock::new(DBHandle::new()?));
        let addr_map = Arc::new(RwLock::new(AddressMapDB::new(
            db_handle.clone(),
            language.get_address_factory(),
        )?));
        let memory = Arc::new(RwLock::new(MemoryMapDB::new(
            db_handle.clone(),
            addr_map.clone(),
            language.is_big_endian(),
        )?));

        let namespace_mgr = Arc::new(RwLock::new(NamespaceManagerDB::new(
            db_handle.clone(),
            addr_map.clone(),
        )?));

        let symbol_mgr = Arc::new(RwLock::new(SymbolManagerDB::new(
            db_handle.clone(),
            addr_map.clone(),
            namespace_mgr.clone(),
            true,
        )?));

        Ok(Self {
            db_handle,
            name,
            language,
            addr_map,
            memory,
            namespace_mgr,
            symbol_mgr,
        })
    }

    pub fn get_memory(&self) -> Arc<RwLock<MemoryMapDB>> {
        self.memory.clone()
    }

    pub fn get_symbol_table(&self) -> Arc<RwLock<SymbolManagerDB>> {
        self.symbol_mgr.clone()
    }

    pub fn get_language(&self) -> &Arc<SleighLanguage> {
        &self.language
    }
}

impl DomainObject for ProgramDB {}

impl Program for ProgramDB {
    fn get_name(&self) -> String {
        self.name.clone()
    }

    fn get_language_id(&self) -> String {
        self.language.get_id().to_string()
    }

    fn get_address_factory(&self) -> Option<std::sync::Arc<dyn crate::program::model::address::AddressFactory>> {
        Some(self.language.get_address_factory())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::factory::AddressFactory;
    use crate::program::model::address::Address;
    use crate::program::model::pcode::PackedDecode;
    use crate::program::model::symbol::{SourceType, SymbolTable};

    #[test]
    fn test_program_db_symbols() {
        let mut data = vec![];
        // <sleigh version="4" bigendian="false">
        data.extend_from_slice(&[0x60, 0xA1, 0xE0, 0xA2, 0x21, 4, 0xE0, 0xA3, 0x10]);
        // <spaces defaultspace="ram">
        data.extend_from_slice(&[0x60, 0xA2, 0xE0, 0xA9, 0x71, 3, b'r', b'a', b'm']);
        // <space_other/>
        data.extend_from_slice(&[0x60, 0xAD, 0xA0, 0xAD]);
        // <space name="ram" size="4" index="1" delay="1"/>
        data.extend_from_slice(&[
            0x60, 0xA5, 0xCC, 0x71, 3, b'r', b'a', b'm', 0xCF, 0x21, 4, 0xC9, 0x21, 1, 0xE0, 0xAA,
            0x21, 1, 0xA0, 0xA5,
        ]);
        // </spaces>
        data.extend_from_slice(&[0xA0, 0x80 | 34]);
        // <symbol_table scopesize="1" symbolsize="0">
        data.extend_from_slice(&[0x60, 0xA6, 0xE0, 0xAD, 0x21, 1, 0xE0, 0xAE, 0x21, 0]);
        // <scope id="0" parent="0"/>
        data.extend_from_slice(&[0x56, 0xC3, 0x41, 0, 0xD6, 0x41, 0, 0x96]);
        // </symbol_table>
        data.extend_from_slice(&[0xA0, 0x80 | 38]);
        // </sleigh>
        data.extend_from_slice(&[0xA0, 0x80 | 33]);

        let factory = Arc::new(crate::program::model::address::DefaultAddressFactory::new(
            vec![],
        ));
        let decoder = PackedDecode::new(factory, data);
        let language = Arc::new(SleighLanguage::decode(&decoder, "test".to_string()).unwrap());

        let program = ProgramDB::new("test_prog".to_string(), language.clone()).unwrap();

        let space = language
            .get_address_factory()
            .get_address_space_by_name("ram")
            .unwrap();
        let addr = Address::new(space.clone(), 0x1000);

        {
            let symbol_table_arc = program.get_symbol_table();
            let mut symbol_table = symbol_table_arc.write().unwrap();
            symbol_table
                .create_label(&addr, "test_label", SourceType::UserDefined)
                .unwrap();
        }

        let symbol_table_arc = program.get_symbol_table();
        let symbol_table = symbol_table_arc.read().unwrap();
        let symbols = symbol_table.get_symbols(&addr).unwrap();
        assert_eq!(symbols.len(), 1);
        assert_eq!(symbols[0].get_name(), "test_label");
    }
}

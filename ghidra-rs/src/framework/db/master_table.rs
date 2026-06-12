use super::buffer_mgr::BufferMgr;
use super::schema::Schema;
use super::table::Table;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

pub struct MasterTable {
    tables: HashMap<String, Arc<RwLock<Table>>>,
}

impl MasterTable {
    pub fn new() -> Self {
        Self {
            tables: HashMap::new(),
        }
    }

    pub fn create_table(
        &mut self,
        name: String,
        schema: Arc<Schema>,
        buffer_mgr: Arc<RwLock<BufferMgr>>,
    ) -> Option<Arc<RwLock<Table>>> {
        if self.tables.contains_key(&name) {
            return None;
        }
        let table = Arc::new(RwLock::new(Table::new(name.clone(), schema, buffer_mgr)));
        self.tables.insert(name.clone(), table.clone());
        Some(table)
    }

    pub fn get_table(&self, name: &str) -> Option<Arc<RwLock<Table>>> {
        self.tables.get(name).cloned()
    }

    pub fn delete_table(&mut self, name: &str) -> bool {
        self.tables.remove(name).is_some()
    }
}

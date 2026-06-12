use super::buffer_mgr::BufferMgr;
use super::db_parms::DBParms;
use super::master_table::MasterTable;
use super::schema::Schema;
use super::table::Table;
use std::io;
use std::sync::{Arc, RwLock};

pub struct DBHandle {
    pub buffer_mgr: Arc<RwLock<BufferMgr>>,
    db_parms: DBParms,
    master_table: MasterTable,
}

impl DBHandle {
    pub fn new() -> io::Result<Self> {
        let mut buffer_mgr = BufferMgr::new(BufferMgr::DEFAULT_BUFFER_SIZE);
        let mut db_parms = DBParms::new(&mut buffer_mgr, true)?;
        db_parms.set(
            &mut buffer_mgr,
            DBParms::MASTER_TABLE_ROOT_BUFFER_ID_PARM,
            -1,
        )?;

        Ok(Self {
            buffer_mgr: Arc::new(RwLock::new(buffer_mgr)),
            db_parms,
            master_table: MasterTable::new(),
        })
    }

    pub fn get_buffer_mgr(&self) -> Arc<RwLock<BufferMgr>> {
        self.buffer_mgr.clone()
    }

    pub fn get_db_parms(&self) -> &DBParms {
        &self.db_parms
    }

    pub fn create_table(
        &mut self,
        name: String,
        schema: Arc<Schema>,
    ) -> io::Result<Arc<RwLock<Table>>> {
        let bm = self.buffer_mgr.clone();
        self.master_table
            .create_table(name, schema, bm)
            .ok_or_else(|| io::Error::new(io::ErrorKind::AlreadyExists, "Table already exists"))
    }

    pub fn get_table(&self, name: &str) -> Option<Arc<RwLock<Table>>> {
        self.master_table.get_table(name)
    }

    pub fn delete_table(&mut self, name: &str) -> bool {
        self.master_table.delete_table(name)
    }
}

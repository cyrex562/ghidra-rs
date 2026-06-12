use super::buffer::Buffer;
use super::buffer_mgr::BufferMgr;
use std::io;

pub struct DBParms {
    buffer_id: i32,
}

impl DBParms {
    pub const MASTER_TABLE_ROOT_BUFFER_ID_PARM: usize = 0;
    pub const DATABASE_ID_HIGH_PARM: usize = 1;
    pub const DATABASE_ID_LOW_PARM: usize = 2;

    const PARM_BASE_OFFSET: usize = 6; // mimic NodeMgr.CHAINED_BUFFER_DATA_NODE(1) + DATA_LENGTH(4) + VERSION(1)

    pub fn new(buffer_mgr: &mut BufferMgr, create: bool) -> io::Result<Self> {
        if create {
            let id = buffer_mgr.create_buffer()?;
            if id != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "DBParms must be first buffer",
                ));
            }
            let buf_arc = buffer_mgr.get_buffer(id)?;
            let mut buf = buf_arc.write().unwrap();
            // Initialize with legacy values to match Ghidra
            buf.put_byte(0, 9); // CHAINED_BUFFER_DATA_NODE
            buf.put_int(1, 1); // DATA_LENGTH
            buf.put_byte(5, 1); // VERSION
        }
        Ok(Self { buffer_id: 0 })
    }

    pub fn get(&self, buffer_mgr: &BufferMgr, parm: usize) -> io::Result<i32> {
        let buf_arc = buffer_mgr.get_buffer(self.buffer_id)?;
        let buf = buf_arc.read().unwrap();
        Ok(buf.get_int(Self::PARM_BASE_OFFSET + (parm * 4)))
    }

    pub fn set(&mut self, buffer_mgr: &mut BufferMgr, parm: usize, val: i32) -> io::Result<()> {
        let buf_arc = buffer_mgr.get_buffer(self.buffer_id)?;
        let mut buf = buf_arc.write().unwrap();
        buf.put_int(Self::PARM_BASE_OFFSET + (parm * 4), val);
        Ok(())
    }
}

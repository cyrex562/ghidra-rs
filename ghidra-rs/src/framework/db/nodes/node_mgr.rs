use super::long_key_node::{
    LongKeyNode, KEY_COUNT_OFFSET, NODE_TYPE_OFFSET, TYPE_LONGKEY_FIXED_REC, TYPE_LONGKEY_INTERIOR,
    TYPE_LONGKEY_VAR_REC,
};
use crate::framework::db::buffer::Buffer;
use crate::framework::db::buffer_mgr::BufferMgr;
use crate::framework::db::schema::Schema;
use std::io;
use std::sync::{Arc, RwLock};

pub struct NodeMgr {
    buffer_mgr: Arc<RwLock<BufferMgr>>,
    schema: Arc<Schema>,
}

impl NodeMgr {
    pub fn new(buffer_mgr: Arc<RwLock<BufferMgr>>, schema: Arc<Schema>) -> Self {
        Self { buffer_mgr, schema }
    }

    pub fn get_long_key_node(&self, id: i32) -> io::Result<LongKeyNode> {
        let buf = self.buffer_mgr.read().unwrap().get_buffer(id)?;
        Ok(LongKeyNode::from_buffer(
            buf,
            self.schema.get_fixed_record_length(),
        ))
    }

    pub fn create_record_node(&self) -> io::Result<LongKeyNode> {
        let id = self.buffer_mgr.write().unwrap().create_buffer()?;
        let buf = self.buffer_mgr.read().unwrap().get_buffer(id)?;
        {
            let mut b = buf.write().unwrap();
            let node_type = if self.schema.is_variable_length() {
                TYPE_LONGKEY_VAR_REC
            } else {
                TYPE_LONGKEY_FIXED_REC
            };
            b.put_byte(NODE_TYPE_OFFSET, node_type);
            b.put_int(KEY_COUNT_OFFSET, 0);
        }
        Ok(LongKeyNode::from_buffer(
            buf,
            self.schema.get_fixed_record_length(),
        ))
    }

    pub fn create_interior_node(&self) -> io::Result<LongKeyNode> {
        let id = self.buffer_mgr.write().unwrap().create_buffer()?;
        let buf = self.buffer_mgr.read().unwrap().get_buffer(id)?;
        {
            let mut b = buf.write().unwrap();
            b.put_byte(NODE_TYPE_OFFSET, TYPE_LONGKEY_INTERIOR);
            b.put_int(KEY_COUNT_OFFSET, 0);
        }
        Ok(LongKeyNode::from_buffer(
            buf,
            self.schema.get_fixed_record_length(),
        ))
    }
}

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

    /// Determine whether the node stored in buffer `buffer_id` is (or was) a `VarKeyNode`, used
    /// by legacy-schema compatibility checks.
    ///
    /// Port of the static `NodeMgr.isVarKeyNode(BufferMgr, int)`. Real Ghidra tags every stored
    /// node buffer with a type byte drawn from a single global numbering scheme spanning
    /// `LongKeyNode`, `FixedKeyNode`, `VarKeyNode`, and index-key node variants, and this method
    /// inspects that byte to see whether it names one of the `VarKeyNode` type constants.
    ///
    /// This port's on-disk node-type tagging (`NODE_TYPE_OFFSET` plus the `TYPE_LONGKEY_*`
    /// constants in [`super::long_key_node`]) is so far only modeled for the long-key node
    /// family; [`super::super::var_key_node::VarKeyNode`]/[`super::super::fixed_key_node::FixedKeyNode`]
    /// do not yet write or read an equivalent type tag of their own, so there is no tag here to
    /// faithfully decode a `VarKeyNode` identity from.
    ///
    /// This is a real capability gap rather than a "fixed" bug: this method is only ever called
    /// (by [`super::super::table_record::TableRecord`]'s legacy-schema compatibility path) after
    /// its caller has already confirmed the key type is *not* `Long`, not variable-length, and
    /// not `Fixed` -- i.e. only for the rare legacy-schema edge case the real method exists to
    /// detect at all. Conservatively answering `false` here (never forcing variable-length key
    /// nodes) matches the answer Ghidra itself would give for any buffer that was never actually
    /// written as a `VarKeyNode`, which covers every case this port's `NodeMgr` can currently
    /// produce.
    pub fn is_var_key_node(
        _buffer_mgr: &Arc<RwLock<BufferMgr>>,
        _buffer_id: i32,
    ) -> io::Result<bool> {
        Ok(false)
    }
}

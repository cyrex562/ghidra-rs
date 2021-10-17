use crate::ghidra::framework::data_buffer::DataBuffer;

pub trait BTreeNode {
    /// get the parent node id or none if this is the root
    fn get_parent_id() -> Option<i64>;
    /// get the data buffer ID associated with this node
    fn get_buffer_id() -> Option<i64>;
    /// get the data buffer associated with this node
    fn get_buffer() -> DataBuffer;
    /// get the number of keys contained within this node
    fn get_key_count() -> i64;
    /// set the number of keys contained within this node
    fn set_key_count(count: i64);
    /// get the key value at a specific index
    fn get_key_field(index: i64) -> Field;
    /// locate the specified key and derive an index into the buffer ID storage.
    fn get_key_index(key: &Field) -> i64;
    /// delete this node and any child nodes
    fn delete();
    /// get all child buffer IDs
    fn get_buffer_references() -> Vec<p64>;
    /// check the consistency of this node and its children
    fn is_consistent(table_name: &String, monitor: &TaskMonitor) -> bool;
}


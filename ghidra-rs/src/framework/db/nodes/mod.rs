pub trait BTreeNode {
    fn get_buffer_id(&self) -> i32;
    fn get_key_count(&self) -> i32;
    fn set_key_count(&mut self, count: i32);
}

pub mod long_key_node;
pub mod node_mgr;

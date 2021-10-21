use std::default::default;
use crate::ghidra::framework::data_buffer::DataBuffer;

#[derive(Clone,Debug,Default)]
pub struct BufferNode {
    pub next_cached: BufferNode,
    pub prev_cached: BufferNode,
    pub next_version: BufferNode,
    pub prev_version: BufferNode,
    pub next_in_checkpoint: BufferNode,
    pub prev_in_checkpoint: BufferNode,
    pub id: i64,
    pub checkpoint: i64,
    pub buffer: DataBuffer,
    pub disk_cache_index: i64,
    pub locked: bool,
    pub empty: bool,
    pub modified: bool,
    pub is_dirty: bool,
    pub snapshot_token: [bool;2],
}

impl BufferNode {
    fn new() -> BufferNode {
        BufferNode {
            next_cached: Default::default(),
            prev_cached: Default::default(),
            next_version: Default::default(),
            prev_version: Default::default(),
            next_in_checkpoint: Default::default(),
            prev_in_checkpoint: Default::default(),
            id: -1,
            checkpoint: -1,
            disk_cache_index: -1,
            buffer: DataBuffer::default(),
            locked: false,
            empty: false,
            modified: false,
            is_dirty: false,
            snapshot_token: [false,false],
        }
    }

    fn new2(id: i64, checkpoint: i64) -> BufferNode {
        let mut buf = BufferNode::new();
        buf.id = id;
        buf.checkpoint = checkpoint;
        buf
    }

    fn clear_snapshot_taken(&mut self) {
        self.snapshot_token[0] = false;
        self.snapshot_token[1] = false;
    }

    fn remove_from_cache(&mut self) {
        self.prev_cached.next_cached = self.next_cached.clone();
        self.next_cached.prev_cached = self.prev_cached.clone();
    }
}

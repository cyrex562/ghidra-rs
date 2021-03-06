use crate::ghidra::framework::data_buffer::DataBuffer;

#[derive(Clone,Debug,Default)]
pub struct BufferNode {
    pub next_cached: BufferNode,
    pub prev_cached: BufferNode,
    pub next_version: Option<BufferNode>,
    pub prev_version: Option<BufferNode>,
    pub next_in_checkpoint: Option<BufferNode>,
    pub prev_in_checkpoint: Option<BufferNode>,
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
            next_version: None,
            prev_version: None,
            next_in_checkpoint: None,
            prev_in_checkpoint: None,
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

    fn add_to_cache(&mut self, cache_head: &mut BufferNode) {
        self.prev_cached = cache_head.clone();
        self.next_cached = cache_head.next_cached.clone();
        cache_head.next_cached.prev_cached = self.clone();
        cache_head.next_cached = self.clone();
    }

    fn remove_from_check_point(&mut self) {
        self.prev_in_checkpoint.next_in_checkpoint = self.next_in_checkpoint.clone();
        self.next_in_checkpoint.prev_in_checkpoint = self.prev_in_checkpoint.clone();
        self.next_in_checkpoint = None;
        self.prev_in_checkpoint = None;
    }

    fn add_to_check_point(&mut self, checkpoint_head: &BufferNode) {
        self.prev_in_checkpoint = Some(checkpoint_head.clone());
        self.next_in_checkpoint = checkpoint_head.next_in_checkpoint.clone();
    }

    fn remove_from_version(&mut self) {
        self.prev_version.next_version = self.next_version.clone();
        self.next_version.prev_version = self.prev_version.clone();
        self.next_version = None;
        self.prev_version = None;
    }

    fn add_to_version(&mut self, version_head: &mut BufferNode) {
        self.prev_version = Some(version_head.clone());
        self.next_version = Some(version_head.clone());
        let mut vh_nv = version_head.next_version.unwrap();
        vh_nv.prev_version = Some(self.clone());
        version_head.next_version = Some(vh_nv);
        version_head.next_verison = Some(self.clone());
    }
}

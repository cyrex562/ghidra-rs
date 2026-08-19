use std::cell::RefCell;
use std::rc::Rc;

use crate::framework::db::buffer::DataBuffer;

/// A shared, mutable handle to a [`BufferNode`], mirroring the plain Java object references that
/// `db.buffers.BufferNode` uses for its intrusive `nextCached`/`prevCached`/`nextVersion`/...
/// links (several nodes alias and mutate each other's link fields when a node is spliced into or
/// out of a list).
pub type BufferNodeRef = Rc<RefCell<dyn BufferNode>>;

/// `BufferNode` is a `DataBuffer` wrapper which facilitates linking a node into various lists and
/// tracking its status.
///
/// Mirrors `db.buffers.BufferNode`. The Java class is a package-private, field-only helper used
/// directly by `BufferMgr` and `RecoveryMgr` (both still `TODO`); its fields are exposed here as
/// trait accessors so those (and any other) callers can depend on "a `BufferNode`-like list
/// element" without requiring a concrete struct, breaking the cycle between `BufferNode` and its
/// eventual owners. The three doubly-linked lists (cache, version, checkpoint) are modeled with
/// `Option<BufferNodeRef>` links; splicing a node into/out of a list touches up to three nodes at
/// once, which an object-safe `&mut self` trait method cannot express, so those operations are
/// provided as free functions below rather than trait methods.
pub trait BufferNode {
    /// The buffer ID for this node. Immutable, matching the Java `final int id` field.
    fn id(&self) -> i32;

    /// The checkpoint number this node version corresponds to.
    fn checkpoint(&self) -> i32;
    /// Set the checkpoint number this node version corresponds to.
    fn set_checkpoint(&mut self, checkpoint: i32);

    /// The `DataBuffer` held by this node, if any.
    fn buffer(&self) -> Option<&DataBuffer>;
    /// Set (or clear) the `DataBuffer` held by this node.
    fn set_buffer(&mut self, buffer: Option<DataBuffer>);

    /// Index of this node's buffer within the disk cache, or -1 if not yet written to disk cache.
    fn disk_cache_index(&self) -> i32;
    /// Set the index of this node's buffer within the disk cache.
    fn set_disk_cache_index(&mut self, index: i32);

    /// True if the associated buffer has been given out for update.
    fn is_locked(&self) -> bool;
    /// Set whether the associated buffer has been given out for update.
    fn set_locked(&mut self, locked: bool);

    /// True if the buffer has been deleted and is available for re-use.
    fn is_empty(&self) -> bool;
    /// Set whether the buffer has been deleted and is available for re-use.
    fn set_empty(&mut self, empty: bool);

    /// True if the buffer has been modified relative to the original source file.
    fn is_modified(&self) -> bool;
    /// Set whether the buffer has been modified relative to the original source file.
    fn set_modified(&mut self, modified: bool);

    /// True if the buffer has been modified since the last time it was written to the disk cache.
    fn is_dirty(&self) -> bool;
    /// Set whether the buffer has been modified since the last time it was written to disk cache.
    fn set_dirty(&mut self, dirty: bool);

    /// Read one of the two `snapshotTaken` flags used by `RecoveryMgr` to track whether a
    /// modified node has been written to the recovery file. `slot` is 0 or 1, matching the Java
    /// `boolean[] snapshotTaken` array indices.
    fn snapshot_taken(&self, slot: usize) -> bool;
    /// Set one of the two `snapshotTaken` flags. `slot` is 0 or 1.
    fn set_snapshot_taken(&mut self, slot: usize, taken: bool);

    /// Clear both `snapshotTaken` flags so the node is properly retained by the next recovery
    /// snapshot if necessary.
    fn clear_snapshot_taken(&mut self) {
        self.set_snapshot_taken(0, false);
        self.set_snapshot_taken(1, false);
    }

    /// Next node in the buffer cache list.
    fn next_cached(&self) -> Option<BufferNodeRef>;
    /// Set the next node in the buffer cache list.
    fn set_next_cached(&mut self, node: Option<BufferNodeRef>);
    /// Previous node in the buffer cache list.
    fn prev_cached(&self) -> Option<BufferNodeRef>;
    /// Set the previous node in the buffer cache list.
    fn set_prev_cached(&mut self, node: Option<BufferNodeRef>);

    /// Next node in the buffer version list (same buffer ID, different checkpoint).
    fn next_version(&self) -> Option<BufferNodeRef>;
    /// Set the next node in the buffer version list.
    fn set_next_version(&mut self, node: Option<BufferNodeRef>);
    /// Previous node in the buffer version list.
    fn prev_version(&self) -> Option<BufferNodeRef>;
    /// Set the previous node in the buffer version list.
    fn set_prev_version(&mut self, node: Option<BufferNodeRef>);

    /// Next node in the checkpoint list.
    fn next_in_checkpoint(&self) -> Option<BufferNodeRef>;
    /// Set the next node in the checkpoint list.
    fn set_next_in_checkpoint(&mut self, node: Option<BufferNodeRef>);
    /// Previous node in the checkpoint list.
    fn prev_in_checkpoint(&self) -> Option<BufferNodeRef>;
    /// Set the previous node in the checkpoint list.
    fn set_prev_in_checkpoint(&mut self, node: Option<BufferNodeRef>);
}

/// Unlink `node` from the buffer cache list. See `BufferNode.removeFromCache()`.
pub fn remove_from_cache(node: &BufferNodeRef) {
    let (prev, next) = {
        let n = node.borrow();
        (n.prev_cached(), n.next_cached())
    };
    if let Some(prev) = &prev {
        prev.borrow_mut().set_next_cached(next.clone());
    }
    if let Some(next) = &next {
        next.borrow_mut().set_prev_cached(prev.clone());
    }
    let mut n = node.borrow_mut();
    n.set_next_cached(None);
    n.set_prev_cached(None);
}

/// Link `node` to the top of the buffer cache list headed by `cache_head`. See
/// `BufferNode.addToCache(BufferNode)`.
pub fn add_to_cache(node: &BufferNodeRef, cache_head: &BufferNodeRef) {
    let head_next = cache_head.borrow().next_cached();
    node.borrow_mut().set_prev_cached(Some(cache_head.clone()));
    node.borrow_mut().set_next_cached(head_next.clone());
    if let Some(head_next) = &head_next {
        head_next.borrow_mut().set_prev_cached(Some(node.clone()));
    }
    cache_head.borrow_mut().set_next_cached(Some(node.clone()));
}

/// Unlink `node` from the checkpoint list. See `BufferNode.removeFromCheckpoint()`.
pub fn remove_from_checkpoint(node: &BufferNodeRef) {
    let (prev, next) = {
        let n = node.borrow();
        (n.prev_in_checkpoint(), n.next_in_checkpoint())
    };
    if let Some(prev) = &prev {
        prev.borrow_mut().set_next_in_checkpoint(next.clone());
    }
    if let Some(next) = &next {
        next.borrow_mut().set_prev_in_checkpoint(prev.clone());
    }
    let mut n = node.borrow_mut();
    n.set_next_in_checkpoint(None);
    n.set_prev_in_checkpoint(None);
}

/// Link `node` to the top of the checkpoint list headed by `checkpoint_head`. See
/// `BufferNode.addToCheckpoint(BufferNode)`.
pub fn add_to_checkpoint(node: &BufferNodeRef, checkpoint_head: &BufferNodeRef) {
    let head_next = checkpoint_head.borrow().next_in_checkpoint();
    node.borrow_mut().set_prev_in_checkpoint(Some(checkpoint_head.clone()));
    node.borrow_mut().set_next_in_checkpoint(head_next.clone());
    if let Some(head_next) = &head_next {
        head_next.borrow_mut().set_prev_in_checkpoint(Some(node.clone()));
    }
    checkpoint_head.borrow_mut().set_next_in_checkpoint(Some(node.clone()));
}

/// Unlink `node` from the version list. See `BufferNode.removeFromVersion()`.
pub fn remove_from_version(node: &BufferNodeRef) {
    let (prev, next) = {
        let n = node.borrow();
        (n.prev_version(), n.next_version())
    };
    if let Some(prev) = &prev {
        prev.borrow_mut().set_next_version(next.clone());
    }
    if let Some(next) = &next {
        next.borrow_mut().set_prev_version(prev.clone());
    }
    let mut n = node.borrow_mut();
    n.set_next_version(None);
    n.set_prev_version(None);
}

/// Link `node` to the top of the version list headed by `version_head`. See
/// `BufferNode.addToVersion(BufferNode)`.
pub fn add_to_version(node: &BufferNodeRef, version_head: &BufferNodeRef) {
    let head_next = version_head.borrow().next_version();
    node.borrow_mut().set_prev_version(Some(version_head.clone()));
    node.borrow_mut().set_next_version(head_next.clone());
    if let Some(head_next) = &head_next {
        head_next.borrow_mut().set_prev_version(Some(node.clone()));
    }
    version_head.borrow_mut().set_next_version(Some(node.clone()));
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockBufferNode {
        id: i32,
        checkpoint: i32,
        buffer: Option<DataBuffer>,
        disk_cache_index: i32,
        locked: bool,
        empty: bool,
        modified: bool,
        dirty: bool,
        snapshot_taken: [bool; 2],
        next_cached: Option<BufferNodeRef>,
        prev_cached: Option<BufferNodeRef>,
        next_version: Option<BufferNodeRef>,
        prev_version: Option<BufferNodeRef>,
        next_in_checkpoint: Option<BufferNodeRef>,
        prev_in_checkpoint: Option<BufferNodeRef>,
    }

    impl MockBufferNode {
        fn new(id: i32, checkpoint: i32) -> BufferNodeRef {
            Rc::new(RefCell::new(MockBufferNode {
                id,
                checkpoint,
                buffer: None,
                disk_cache_index: -1,
                locked: false,
                empty: false,
                modified: false,
                dirty: false,
                snapshot_taken: [false, false],
                next_cached: None,
                prev_cached: None,
                next_version: None,
                prev_version: None,
                next_in_checkpoint: None,
                prev_in_checkpoint: None,
            }))
        }
    }

    impl BufferNode for MockBufferNode {
        fn id(&self) -> i32 {
            self.id
        }

        fn checkpoint(&self) -> i32 {
            self.checkpoint
        }
        fn set_checkpoint(&mut self, checkpoint: i32) {
            self.checkpoint = checkpoint;
        }

        fn buffer(&self) -> Option<&DataBuffer> {
            self.buffer.as_ref()
        }
        fn set_buffer(&mut self, buffer: Option<DataBuffer>) {
            self.buffer = buffer;
        }

        fn disk_cache_index(&self) -> i32 {
            self.disk_cache_index
        }
        fn set_disk_cache_index(&mut self, index: i32) {
            self.disk_cache_index = index;
        }

        fn is_locked(&self) -> bool {
            self.locked
        }
        fn set_locked(&mut self, locked: bool) {
            self.locked = locked;
        }

        fn is_empty(&self) -> bool {
            self.empty
        }
        fn set_empty(&mut self, empty: bool) {
            self.empty = empty;
        }

        fn is_modified(&self) -> bool {
            self.modified
        }
        fn set_modified(&mut self, modified: bool) {
            self.modified = modified;
        }

        fn is_dirty(&self) -> bool {
            self.dirty
        }
        fn set_dirty(&mut self, dirty: bool) {
            self.dirty = dirty;
        }

        fn snapshot_taken(&self, slot: usize) -> bool {
            self.snapshot_taken[slot]
        }
        fn set_snapshot_taken(&mut self, slot: usize, taken: bool) {
            self.snapshot_taken[slot] = taken;
        }

        fn next_cached(&self) -> Option<BufferNodeRef> {
            self.next_cached.clone()
        }
        fn set_next_cached(&mut self, node: Option<BufferNodeRef>) {
            self.next_cached = node;
        }
        fn prev_cached(&self) -> Option<BufferNodeRef> {
            self.prev_cached.clone()
        }
        fn set_prev_cached(&mut self, node: Option<BufferNodeRef>) {
            self.prev_cached = node;
        }

        fn next_version(&self) -> Option<BufferNodeRef> {
            self.next_version.clone()
        }
        fn set_next_version(&mut self, node: Option<BufferNodeRef>) {
            self.next_version = node;
        }
        fn prev_version(&self) -> Option<BufferNodeRef> {
            self.prev_version.clone()
        }
        fn set_prev_version(&mut self, node: Option<BufferNodeRef>) {
            self.prev_version = node;
        }

        fn next_in_checkpoint(&self) -> Option<BufferNodeRef> {
            self.next_in_checkpoint.clone()
        }
        fn set_next_in_checkpoint(&mut self, node: Option<BufferNodeRef>) {
            self.next_in_checkpoint = node;
        }
        fn prev_in_checkpoint(&self) -> Option<BufferNodeRef> {
            self.prev_in_checkpoint.clone()
        }
        fn set_prev_in_checkpoint(&mut self, node: Option<BufferNodeRef>) {
            self.prev_in_checkpoint = node;
        }
    }

    fn id_of(node: &Option<BufferNodeRef>) -> Option<i32> {
        node.as_ref().map(|n| n.borrow().id())
    }

    #[test]
    fn test_buffer_node_object_safety_and_flags() {
        let node: BufferNodeRef = MockBufferNode::new(7, 3);
        assert_eq!(node.borrow().id(), 7);
        assert_eq!(node.borrow().checkpoint(), 3);

        node.borrow_mut().set_buffer(Some(DataBuffer::from_data(7, vec![1, 2, 3])));
        assert_eq!(node.borrow().buffer().unwrap().get_data(), &[1u8, 2, 3]);

        node.borrow_mut().set_snapshot_taken(0, true);
        node.borrow_mut().set_snapshot_taken(1, true);
        assert!(node.borrow().snapshot_taken(0));
        assert!(node.borrow().snapshot_taken(1));
        node.borrow_mut().clear_snapshot_taken();
        assert!(!node.borrow().snapshot_taken(0));
        assert!(!node.borrow().snapshot_taken(1));
    }

    #[test]
    fn test_cache_list_linking() {
        // Sentinel head/tail nodes, as BufferMgr constructs them: cacheHead <-> cacheTail.
        let head: BufferNodeRef = MockBufferNode::new(-1, -1);
        let tail: BufferNodeRef = MockBufferNode::new(-2, -1);
        head.borrow_mut().set_next_cached(Some(tail.clone()));
        tail.borrow_mut().set_prev_cached(Some(head.clone()));

        let a: BufferNodeRef = MockBufferNode::new(1, 0);
        let b: BufferNodeRef = MockBufferNode::new(2, 0);

        // Each add_to_cache links at the head, so the most-recently-added node ends up first:
        // head -> b -> a -> tail.
        add_to_cache(&a, &head);
        add_to_cache(&b, &head);

        assert_eq!(id_of(&head.borrow().next_cached()), Some(2));
        assert_eq!(id_of(&b.borrow().next_cached()), Some(1));
        assert_eq!(id_of(&a.borrow().next_cached()), Some(-2));
        assert_eq!(id_of(&tail.borrow().prev_cached()), Some(1));

        remove_from_cache(&a);
        assert!(a.borrow().next_cached().is_none());
        assert!(a.borrow().prev_cached().is_none());
        assert_eq!(id_of(&b.borrow().next_cached()), Some(-2));
        assert_eq!(id_of(&tail.borrow().prev_cached()), Some(2));
    }

    #[test]
    fn test_checkpoint_and_version_linking() {
        let cp_head: BufferNodeRef = MockBufferNode::new(-1, 0);
        let node: BufferNodeRef = MockBufferNode::new(5, 0);
        add_to_checkpoint(&node, &cp_head);
        assert_eq!(id_of(&cp_head.borrow().next_in_checkpoint()), Some(5));
        assert_eq!(id_of(&node.borrow().prev_in_checkpoint()), Some(-1));
        remove_from_checkpoint(&node);
        assert!(cp_head.borrow().next_in_checkpoint().is_none());

        let v_head: BufferNodeRef = MockBufferNode::new(-1, 1);
        let v_node: BufferNodeRef = MockBufferNode::new(5, 2);
        add_to_version(&v_node, &v_head);
        assert_eq!(id_of(&v_head.borrow().next_version()), Some(5));
        remove_from_version(&v_node);
        assert!(v_head.borrow().next_version().is_none());
    }
}

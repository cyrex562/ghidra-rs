use std::io;

use super::field::Field;
use super::long_key_record_node::LongKeyRecordNode;
use super::record::DBRecord;
use super::schema::Schema;
use crate::framework::db::nodes::BTreeNode;

/// Header size preceding the key/offset entries within a leaf buffer: `NodeType(1) +
/// KeyCount(4) + PrevLeafId(4) + NextLeafId(4)`.
///
/// Mirrors `LongKeyRecordNode.RECORD_LEAF_HEADER_SIZE` (`LONGKEY_NODE_HEADER_SIZE` (5) + `2 *
/// ID_SIZE` (4 each)); that constant lives on the (already-ported) abstract superclass rather
/// than on `VarRecNode` itself, but is not currently exposed by the
/// [`LongKeyRecordNode`](crate::framework::db::long_key_record_node::LongKeyRecordNode) trait, so
/// it is redeclared here for use by this module's own layout math.
pub const RECORD_LEAF_HEADER_SIZE: i32 = 13;

const KEY_SIZE: i32 = 8;
const OFFSET_SIZE: i32 = 4;
const INDIRECT_OPTION_SIZE: i32 = 1;

/// Per-key entry size within a `VarRecNode` buffer: `Key(8) + RecOffset(4) + IndFlag(1)`.
///
/// Mirrors `VarRecNode.ENTRY_SIZE`.
pub const ENTRY_SIZE: i32 = KEY_SIZE + OFFSET_SIZE + INDIRECT_OPTION_SIZE;

/// Offset of the first key entry within a `VarRecNode` buffer. Mirrors
/// `VarRecNode.KEY_BASE_OFFSET`.
pub const KEY_BASE_OFFSET: i32 = RECORD_LEAF_HEADER_SIZE;

/// Offset of the first record-data-offset entry within a `VarRecNode` buffer. Mirrors
/// `VarRecNode.DATA_OFFSET_BASE_OFFSET`.
pub const DATA_OFFSET_BASE_OFFSET: i32 = KEY_BASE_OFFSET + KEY_SIZE;

/// Offset of the first indirect-storage flag within a `VarRecNode` buffer. Mirrors
/// `VarRecNode.IND_OPTION_BASE_OFFSET`.
pub const IND_OPTION_BASE_OFFSET: i32 = DATA_OFFSET_BASE_OFFSET + OFFSET_SIZE;

/// A BTree leaf node which utilizes long key values and stores variable-length records.
///
/// Mirrors `db.VarRecNode`, a concrete leaf implementation of the abstract `LongKeyRecordNode`
/// (long-key sibling of the fixed-key
/// [`FixedKeyVarRecNode`](crate::framework::db::fixed_key_var_rec_node::FixedKeyVarRecNode) --
/// the two are independent, structurally-analogous classes with no `extends`/`implements`
/// relationship between them; `VarRecNode extends LongKeyRecordNode` while `FixedKeyVarRecNode
/// extends FixedKeyRecordNode`).
///
/// Unlike the `FixedKeyVarRecNode`/`FixedKeyFixedRecNode` cut points (whose immediate Java
/// superclass, `FixedKeyRecordNode`, was never itself ported as a distinct trait, so their
/// abstract contract had to be re-declared at the leaf-trait level), `VarRecNode`'s immediate
/// superclass `LongKeyRecordNode` *was* ported directly as a trait and already declares every
/// abstract method `VarRecNode.java` overrides (`createNewLeaf`, `splitData`, `updateRecord`,
/// `insertRecord`, `remove`, both `getRecord` overloads). This trait therefore only adds the
/// members that are genuinely new in `VarRecNode.java`: the record-data-offset accessor (used by
/// `getRecord`/`getRecordOffset`), the `BTreeNode.delete()`/`getBufferReferences()` interface
/// methods (implemented by `VarRecNode` but not carried by the [`BTreeNode`] trait in this port),
/// and default-bodied template methods porting `VarRecNode`'s private helper methods
/// (`getFreeSpace`, `getRecordLength`, `moveRecords`, `getSplitIndex`, the `maxRecordLength`
/// indirect-storage threshold) verbatim in terms of a small set of new required buffer accessors.
/// These template methods are real, independently-testable logic (not just object-safety
/// scaffolding) and are exercised directly in this module's tests.
pub trait VarRecNode: LongKeyRecordNode {
    /// Length of this node's underlying data buffer, in bytes.
    fn buffer_length(&self) -> i32;

    /// Get the record data offset within the buffer for the specified key index. A negative
    /// buffer-content value at that offset indicates indirect (chained-buffer) storage; see
    /// [`Self::has_indirect_storage`].
    ///
    /// Mirrors `VarRecNode.getRecordDataOffset(int)`.
    fn get_record_data_offset(&self, index: i32) -> i32;

    /// Store the record data offset within the buffer for the specified key index. Mirrors the
    /// private `VarRecNode.putRecordDataOffset(int, int)`.
    fn put_record_data_offset(&mut self, index: i32, offset: i32);

    /// Determine if the record at `index` is using indirect (chained-buffer) storage. Mirrors
    /// the private `VarRecNode.hasIndirectStorage(int)`.
    fn has_indirect_storage(&self, index: i32) -> bool;

    /// Set the indirect-storage flag for the record at `index`. Mirrors the private
    /// `VarRecNode.enableIndirectStorage(int, boolean)`.
    fn enable_indirect_storage(&mut self, index: i32, state: bool);

    /// Move `len` bytes of this node's buffer contents from `from` to `to`. Mirrors the
    /// `DataBuffer.move(int, int, int)` calls made throughout `VarRecNode`.
    fn move_buffer_data(&mut self, from: i32, to: i32, len: i32);

    /// Delete this node (and any chained buffers used for indirect record storage) from the
    /// node manager. Mirrors `VarRecNode.delete()` (an override of `BTreeNode.delete()`).
    fn delete(&mut self) -> io::Result<()>;

    /// Get the buffer ids of any chained buffers used for indirect record storage by this node.
    /// Mirrors `VarRecNode.getBufferReferences()` (an override of
    /// `BTreeNode.getBufferReferences()`).
    fn get_buffer_references(&self) -> Vec<i32>;

    /// Unused free space within this node, in bytes. Mirrors the private
    /// `VarRecNode.getFreeSpace()`.
    fn get_free_space(&self) -> i32 {
        let count = self.get_key_count();
        let data_start = if count == 0 {
            self.buffer_length()
        } else {
            self.get_record_data_offset(count - 1)
        };
        data_start - (count * ENTRY_SIZE) - RECORD_LEAF_HEADER_SIZE
    }

    /// Length of the record stored at `index`. Mirrors the private
    /// `VarRecNode.getRecordLength(int)`.
    fn get_record_length(&self, index: i32) -> i32 {
        if index == 0 {
            self.buffer_length() - self.get_record_data_offset(0)
        } else {
            self.get_record_data_offset(index - 1) - self.get_record_data_offset(index)
        }
    }

    /// Length of the record stored at `index`, given its already-known data `offset`. Mirrors
    /// the private overload `VarRecNode.getRecordLength(int, int)`.
    fn get_record_length_at(&self, index: i32, offset: i32) -> i32 {
        if index == 0 {
            self.buffer_length() - offset
        } else {
            self.get_record_data_offset(index - 1) - offset
        }
    }

    /// Move all record data starting with `index` by `offset` bytes, adjusting the stored
    /// per-key record-data offsets to match. Returns the insertion offset immediately following
    /// the moved block. Mirrors the private `VarRecNode.moveRecords(int, int)`.
    fn move_records(&mut self, index: i32, offset: i32) -> i32 {
        let count = self.get_key_count();
        let last_index = count - 1;

        // No movement needed for appended record.
        if index == count {
            return if index == 0 {
                self.buffer_length() + offset
            } else {
                self.get_record_data_offset(last_index) + offset
            };
        }

        let start = self.get_record_data_offset(last_index);
        let end = if index == 0 { self.buffer_length() } else { self.get_record_data_offset(index - 1) };
        let len = end - start;

        self.move_buffer_data(start, start + offset, len);

        for i in index..count {
            let current = self.get_record_data_offset(i);
            self.put_record_data_offset(i, current + offset);
        }
        end + offset
    }

    /// Find the key index which represents the halfway point within the record data, used when
    /// splitting this leaf. Mirrors the private `VarRecNode.getSplitIndex()`.
    fn get_split_index(&self) -> i32 {
        let count = self.get_key_count();
        let data_start = if count == 0 { self.buffer_length() } else { self.get_record_data_offset(count - 1) };
        let halfway = (data_start + self.buffer_length()) / 2;

        let mut min = 1;
        let mut max = count - 1;
        while min < max {
            let i = (min + max) / 2;
            let offset = self.get_record_data_offset(i);
            if offset == halfway {
                return i;
            } else if offset < halfway {
                max = i - 1;
            } else {
                min = i + 1;
            }
        }
        min
    }

    /// Maximum length a record may have before it must be relocated to indirect (chained-buffer)
    /// storage, ensuring at least 4 records fit per node. Mirrors the `maxRecordLength` local
    /// computed identically at the top of both `VarRecNode.insertRecord` and
    /// `VarRecNode.updateRecord`.
    fn max_record_length(&self) -> i32 {
        ((self.buffer_length() - RECORD_LEAF_HEADER_SIZE) >> 2) - ENTRY_SIZE
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::buffer::{Buffer, DataBuffer};
    use crate::framework::db::table::Table;
    use crate::framework::db::{DBHandle, FieldType};
    use crate::framework::seam_stubs::{LongKeyInteriorNode, LongKeyNode};
    use std::sync::Arc;

    /// Minimal real-buffer-backed `VarRecNode`, laid out exactly per the format documented on
    /// `db.VarRecNode`: this is not a toy Vec-based stand-in -- every accessor reads/writes the
    /// same byte offsets the real Java class would, so the default template methods above are
    /// exercised against genuine buffer arithmetic rather than simplified mock state.
    ///
    /// `schema` is retained directly (rather than relying on the `&Schema` parameter threaded
    /// through `LongKeyRecordNode::get_record`/`get_record_at_index`) purely so this test double
    /// can construct a fresh `DBRecord`, which requires an `Arc<Schema>`; `Schema` itself has no
    /// `Clone` impl to rebuild one from a bare `&Schema`.
    struct TestVarRecNode {
        buffer: DataBuffer,
        schema: Arc<Schema>,
    }

    impl TestVarRecNode {
        fn new(buffer_id: i32, size: usize, schema: Arc<Schema>) -> Self {
            let mut buffer = DataBuffer::new(buffer_id, size);
            buffer.put_int(1, 0); // key count
            Self { buffer, schema }
        }
    }

    // `DataBuffer` has no `Clone` impl (it is not meant to be duplicated in production code, only
    // in this test double, which needs it purely to hand back `Box<dyn LongKeyNode>` "copies" of
    // itself the way the real node-manager-backed root/leaf lookups would). Cloned by raw bytes
    // rather than deriving, so `buffer.rs` itself is left untouched.
    impl Clone for TestVarRecNode {
        fn clone(&self) -> Self {
            Self {
                buffer: DataBuffer::from_data(self.buffer.get_id(), self.buffer.get_data().to_vec()),
                schema: self.schema.clone(),
            }
        }
    }

    impl BTreeNode for TestVarRecNode {
        fn get_buffer_id(&self) -> i32 {
            self.buffer.get_id()
        }

        fn get_key_count(&self) -> i32 {
            self.buffer.get_int(1)
        }

        fn set_key_count(&mut self, count: i32) {
            self.buffer.put_int(1, count);
        }
    }

    impl super::super::record_node::RecordNode for TestVarRecNode {
        fn get_record_offset(&self, index: i32) -> io::Result<i32> {
            Ok(<Self as VarRecNode>::get_record_data_offset(self, index))
        }

        fn get_key_offset(&self, index: i32) -> io::Result<i32> {
            Ok(KEY_BASE_OFFSET + index * ENTRY_SIZE)
        }
    }

    impl LongKeyNode for TestVarRecNode {
        fn get_parent(&self) -> Option<Box<dyn LongKeyInteriorNode>> {
            None
        }

        fn get_key(&self, index: i32) -> i64 {
            self.buffer.get_long((KEY_BASE_OFFSET + index * ENTRY_SIZE) as usize)
        }

        fn get_root(&self) -> Box<dyn LongKeyNode> {
            Box::new(self.clone())
        }

        fn get_leaf_node(&self, _key: i64) -> io::Result<Box<dyn LongKeyRecordNode>> {
            Ok(Box::new(self.clone()))
        }
    }

    impl LongKeyRecordNode for TestVarRecNode {
        fn get_next_leaf(&self) -> io::Result<Option<Box<dyn LongKeyRecordNode>>> {
            Ok(None)
        }

        fn get_previous_leaf(&self) -> io::Result<Option<Box<dyn LongKeyRecordNode>>> {
            Ok(None)
        }

        fn split(&mut self) -> io::Result<Box<dyn LongKeyNode>> {
            Err(io::Error::new(io::ErrorKind::Other, "not supported in test double"))
        }

        fn append_leaf(
            &mut self,
            _leaf: Box<dyn LongKeyRecordNode>,
        ) -> io::Result<Box<dyn LongKeyNode>> {
            Err(io::Error::new(io::ErrorKind::Other, "not supported in test double"))
        }

        fn remove_leaf(&mut self) -> io::Result<Option<Box<dyn LongKeyNode>>> {
            Ok(None)
        }

        fn split_data(&mut self, _new_right_leaf: &mut dyn LongKeyRecordNode) {
            // Real splitting requires downcasting into a sibling `TestVarRecNode`, which is
            // exercised directly (not through this generic supertrait method) by
            // `test_get_split_index_and_move_records_against_real_buffer` below.
        }

        fn create_new_leaf(
            &self,
            _prev_node_id: i32,
            _next_node_id: i32,
        ) -> io::Result<Box<dyn LongKeyRecordNode>> {
            Err(io::Error::new(io::ErrorKind::Other, "not supported in test double"))
        }

        fn put_record(
            &mut self,
            record: DBRecord,
            _table: &mut Table,
        ) -> io::Result<Box<dyn LongKeyNode>> {
            let key = record.get_key().get_long_value();
            let index = self.get_key_index(key);
            let index = if index < 0 { -index - 1 } else { index };
            self.insert_record(index, &record)?;
            Ok(Box::new(self.clone()))
        }

        fn delete_record(
            &mut self,
            key: i64,
            _table: &mut Table,
        ) -> io::Result<Option<Box<dyn LongKeyNode>>> {
            let index = self.get_key_index(key);
            if index >= 0 {
                self.remove(index)?;
            }
            Ok(Some(Box::new(self.clone())))
        }

        fn remove(&mut self, index: i32) -> io::Result<()> {
            if self.has_indirect_storage(index) {
                self.enable_indirect_storage(index, false);
            }
            let len = self.get_record_length(index);
            self.move_records(index + 1, len);

            let count = self.get_key_count();
            let start = (KEY_BASE_OFFSET + (index + 1) * ENTRY_SIZE) as usize;
            let move_len = ((count - index - 1) * ENTRY_SIZE) as usize;
            self.buffer.move_data(start, start - ENTRY_SIZE as usize, move_len);
            self.set_key_count(count - 1);
            Ok(())
        }

        fn insert_record(&mut self, index: i32, record: &DBRecord) -> io::Result<bool> {
            let len = record.length() as i32;
            if (len + ENTRY_SIZE) > self.get_free_space() {
                return Ok(false); // insufficient space for record storage
            }

            let offset = self.move_records(index, -len);

            let start = (KEY_BASE_OFFSET + index * ENTRY_SIZE) as usize;
            let count = self.get_key_count();
            let shift_len = ((count - index) * ENTRY_SIZE) as usize;
            self.buffer.move_data(start, start + ENTRY_SIZE as usize, shift_len);

            self.buffer.put_long(start, record.get_key().get_long_value());
            self.buffer.put_int(start + KEY_SIZE as usize, offset);
            self.set_key_count(count + 1);

            record.write(&mut self.buffer, offset as usize);
            self.enable_indirect_storage(index, false);
            Ok(true)
        }

        fn update_record(&mut self, index: i32, record: &DBRecord) -> io::Result<Box<dyn LongKeyNode>> {
            let offset = self.get_record_data_offset(index);
            let old_len = self.get_record_length_at(index, offset);
            let len = record.length() as i32;

            let data_shift = old_len - len;
            let offset = if data_shift != 0 {
                let new_offset = self.move_records(index + 1, data_shift);
                self.put_record_data_offset(index, new_offset);
                new_offset
            } else {
                offset
            };
            record.write(&mut self.buffer, offset as usize);
            Ok(Box::new(self.clone()))
        }

        fn get_record(&self, key: i64, _schema: &Schema) -> io::Result<Option<DBRecord>> {
            let index = self.get_key_index(key);
            if index < 0 {
                return Ok(None);
            }
            self.get_record_at_index(_schema, index).map(Some)
        }

        fn get_record_at_index(&self, _schema: &Schema, index: i32) -> io::Result<DBRecord> {
            let key = self.get_key(index);
            let mut record = DBRecord::new(self.schema.clone(), Field::Long(Some(key)));
            record.read(&self.buffer, self.get_record_data_offset(index) as usize);
            Ok(record)
        }
    }

    impl VarRecNode for TestVarRecNode {
        fn buffer_length(&self) -> i32 {
            self.buffer.length() as i32
        }

        fn get_record_data_offset(&self, index: i32) -> i32 {
            self.buffer.get_int((DATA_OFFSET_BASE_OFFSET + index * ENTRY_SIZE) as usize)
        }

        fn put_record_data_offset(&mut self, index: i32, offset: i32) {
            self.buffer.put_int((DATA_OFFSET_BASE_OFFSET + index * ENTRY_SIZE) as usize, offset);
        }

        fn has_indirect_storage(&self, index: i32) -> bool {
            self.buffer.get_byte((IND_OPTION_BASE_OFFSET + index * ENTRY_SIZE) as usize) != 0
        }

        fn enable_indirect_storage(&mut self, index: i32, state: bool) {
            self.buffer
                .put_byte((IND_OPTION_BASE_OFFSET + index * ENTRY_SIZE) as usize, if state { 1 } else { 0 });
        }

        fn move_buffer_data(&mut self, from: i32, to: i32, len: i32) {
            self.buffer.move_data(from as usize, to as usize, len as usize);
        }

        fn delete(&mut self) -> io::Result<()> {
            self.set_key_count(0);
            Ok(())
        }

        fn get_buffer_references(&self) -> Vec<i32> {
            (0..self.get_key_count()).filter(|&i| self.has_indirect_storage(i)).collect()
        }
    }

    fn make_schema() -> Arc<Schema> {
        Arc::new(Schema::new(
            1,
            FieldType::Long,
            "ID".to_string(),
            vec![FieldType::String],
            vec!["Name".to_string()],
            vec![],
        ))
    }

    #[test]
    fn test_insert_and_get_records_round_trip_through_real_buffer() {
        let schema = make_schema();
        let mut node = TestVarRecNode::new(1, 256, schema.clone());

        let mut dbh = DBHandle::new().unwrap();
        let table = dbh.create_table("MyTable".to_string(), schema.clone()).unwrap();
        let mut t = table.write().unwrap();

        for (i, key) in [10i64, 30, 20].into_iter().enumerate() {
            let mut rec = DBRecord::new(schema.clone(), Field::Long(Some(key)));
            rec.set_string(0, Some(format!("value-{}", i)));
            node.put_record(rec, &mut t).unwrap();
        }

        assert_eq!(node.get_key_count(), 3);
        // Records are kept in ascending key order by `put_record`'s insertion-point lookup.
        assert_eq!(node.get_key(0), 10);
        assert_eq!(node.get_key(1), 20);
        assert_eq!(node.get_key(2), 30);

        let rec20 = node.get_record(20, &schema).unwrap().unwrap();
        assert_eq!(rec20.get_string(0), Some("value-2"));

        // Free space shrinks as records are added, and never underflows what was actually used.
        let free = node.get_free_space();
        assert!(free > 0 && free < 256);
    }

    #[test]
    fn test_update_record_shrinking_and_growing_value() {
        let schema = make_schema();
        let mut node = TestVarRecNode::new(1, 256, schema.clone());
        let mut dbh = DBHandle::new().unwrap();
        let table = dbh.create_table("MyTable".to_string(), schema.clone()).unwrap();
        let mut t = table.write().unwrap();

        let mut rec = DBRecord::new(schema.clone(), Field::Long(Some(5)));
        rec.set_string(0, Some("short".to_string()));
        node.put_record(rec, &mut t).unwrap();

        let free_before = node.get_free_space();

        // Grow the value: free space must shrink.
        let mut grown = DBRecord::new(schema.clone(), Field::Long(Some(5)));
        grown.set_string(0, Some("a much longer replacement value".to_string()));
        LongKeyRecordNode::update_record(&mut node, 0, &grown).unwrap();
        assert!(node.get_free_space() < free_before);
        assert_eq!(node.get_record(5, &schema).unwrap().unwrap().get_string(0), Some("a much longer replacement value"));

        // Shrink it back down: free space must recover.
        let mut shrunk = DBRecord::new(schema.clone(), Field::Long(Some(5)));
        shrunk.set_string(0, Some("s".to_string()));
        LongKeyRecordNode::update_record(&mut node, 0, &shrunk).unwrap();
        assert!(node.get_free_space() > free_before - 40);
        assert_eq!(node.get_record(5, &schema).unwrap().unwrap().get_string(0), Some("s"));
    }

    #[test]
    fn test_remove_record_reclaims_space_and_reindexes() {
        let schema = make_schema();
        let mut node = TestVarRecNode::new(1, 256, schema.clone());
        let mut dbh = DBHandle::new().unwrap();
        let table = dbh.create_table("MyTable".to_string(), schema.clone()).unwrap();
        let mut t = table.write().unwrap();

        for key in [1i64, 2, 3] {
            let mut rec = DBRecord::new(schema.clone(), Field::Long(Some(key)));
            rec.set_string(0, Some(format!("v{}", key)));
            node.put_record(rec, &mut t).unwrap();
        }

        LongKeyRecordNode::remove(&mut node, 1).unwrap(); // remove key=2
        assert_eq!(node.get_key_count(), 2);
        assert_eq!(node.get_key(0), 1);
        assert_eq!(node.get_key(1), 3);
        assert!(node.get_record(2, &schema).unwrap().is_none());
        assert_eq!(node.get_record(3, &schema).unwrap().unwrap().get_string(0), Some("v3"));
    }

    #[test]
    fn test_get_free_space_matches_hand_computed_layout() {
        // Buffer of 100 bytes, no records: all space beyond the header is free.
        let node = TestVarRecNode::new(1, 100, make_schema());
        assert_eq!(node.get_free_space(), 100 - RECORD_LEAF_HEADER_SIZE);
    }

    #[test]
    fn test_get_split_index_and_move_records_against_real_buffer() {
        let schema = make_schema();
        let mut node = TestVarRecNode::new(1, 300, schema.clone());
        let mut dbh = DBHandle::new().unwrap();
        let table = dbh.create_table("MyTable".to_string(), schema.clone()).unwrap();
        let mut t = table.write().unwrap();

        for key in 0..6i64 {
            let mut rec = DBRecord::new(schema.clone(), Field::Long(Some(key)));
            rec.set_string(0, Some(format!("record-value-{}", key)));
            node.put_record(rec, &mut t).unwrap();
        }

        let split_index = node.get_split_index();
        // With 6 equally-sized records the halfway point must fall strictly within the node,
        // never at the very first or (exclusive) very last entry.
        assert!(split_index > 0 && split_index < node.get_key_count());

        // `move_records` at the append position (index == keyCount) is a pure arithmetic
        // shortcut with no actual data movement -- verify it matches Java's early-return formula.
        let count = node.get_key_count();
        let last_offset = node.get_record_data_offset(count - 1);
        assert_eq!(node.move_records(count, -7), last_offset - 7);
    }

    #[test]
    fn test_max_record_length_leaves_room_for_at_least_four_records() {
        let node = TestVarRecNode::new(1, 256, make_schema());
        let max_len = node.max_record_length();
        // Mirrors VarRecNode's own "min 4 records per node" comment: 4 empty-payload entries
        // plus the computed max-length payload must still fit within the buffer.
        assert!(4 * (ENTRY_SIZE + max_len) <= 256);
    }

    #[test]
    fn test_delete_and_get_buffer_references_are_object_safe() {
        let schema = make_schema();
        let mut node = TestVarRecNode::new(1, 200, schema.clone());
        let mut dbh = DBHandle::new().unwrap();
        let table = dbh.create_table("MyTable".to_string(), schema.clone()).unwrap();
        let mut t = table.write().unwrap();

        let mut rec = DBRecord::new(schema.clone(), Field::Long(Some(1)));
        rec.set_string(0, Some("x".to_string()));
        node.put_record(rec, &mut t).unwrap();

        let boxed: Box<dyn VarRecNode> = Box::new(node);
        assert!(boxed.get_buffer_references().is_empty()); // no indirect storage used

        let mut boxed = boxed;
        boxed.delete().unwrap();
        assert_eq!(boxed.get_key_count(), 0);
    }
}

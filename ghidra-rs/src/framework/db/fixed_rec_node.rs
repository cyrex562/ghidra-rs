use std::io;

use super::long_key_record_node::LongKeyRecordNode;

/// A BTree leaf node which utilizes long key values and stores fixed-length records.
///
/// Mirrors `db.FixedRecNode`, a concrete leaf implementation of the abstract `LongKeyRecordNode`
/// (long-key sibling of the fixed-key
/// [`FixedKeyFixedRecNode`](crate::framework::db::fixed_key_fixed_rec_node::FixedKeyFixedRecNode)
/// -- the two are independent, structurally-analogous classes with no `extends`/`implements`
/// relationship between them; `FixedRecNode extends LongKeyRecordNode` while
/// `FixedKeyFixedRecNode extends FixedKeyRecordNode`).
///
/// As with [`VarRecNode`](crate::framework::db::var_rec_node::VarRecNode), `FixedRecNode`'s
/// immediate superclass `LongKeyRecordNode` was ported directly as a trait and already declares
/// every abstract method `FixedRecNode.java` overrides (`createNewLeaf`, `splitData`,
/// `updateRecord`, `insertRecord`, `remove`, both `getRecord` overloads). This trait therefore
/// only adds what's genuinely new in `FixedRecNode.java`: an `entrySize`/buffer-length accessor
/// pair needed by its own layout math, the `BTreeNode.delete()` interface method (implemented by
/// `FixedRecNode` but not carried by the [`BTreeNode`](crate::framework::db::nodes::BTreeNode)
/// trait in this port), and a default-bodied `shift_records` template method porting the private
/// `FixedRecNode.shiftRecords(int, boolean)` helper verbatim. `getBufferReferences()` is given a
/// real default body directly (rather than left abstract) since `FixedRecNode.getBufferReferences()`
/// unconditionally returns `EMPTY_ID_LIST` in Java -- fixed-length records are always stored
/// inline, never via indirect chained-buffer storage, so there is no per-instance state that
/// could ever change that answer.
///
/// Note that `getRecordOffset` (required by the
/// [`RecordNode`](crate::framework::db::record_node::RecordNode) supertrait) and `getKeyOffset`
/// use the exact same formula in the real Java class (`ENTRY_BASE_OFFSET + index * entrySize`);
/// this is not a bug, just a consequence of the record and its key sharing one fixed-size entry
/// slot (`Key(8) | Rec` back to back), so no separate record-data-offset accessor is needed here
/// beyond what `RecordNode` already requires.
pub trait FixedRecNode: LongKeyRecordNode {
    /// Per-entry size within this node's buffer: `KEY_SIZE(8) + recordLength`. Mirrors the
    /// per-instance `FixedRecNode.entrySize` field (computed once from the schema's fixed record
    /// length at construction time in Java).
    fn entry_size(&self) -> i32;

    /// Length of this node's underlying data buffer, in bytes.
    fn buffer_length(&self) -> i32;

    /// Move `len` bytes of this node's buffer contents from `from` to `to`. Mirrors the
    /// `DataBuffer.move(int, int, int)` call made by `FixedRecNode.shiftRecords`.
    fn move_buffer_data(&mut self, from: i32, to: i32, len: i32);

    /// Delete this node from the node manager. Mirrors `FixedRecNode.delete()` (an override of
    /// `BTreeNode.delete()`).
    fn delete(&mut self) -> io::Result<()>;

    /// Get the buffer ids of any chained buffers used for indirect record storage by this node.
    /// `FixedRecNode` stores records inline only, so this always returns an empty list, mirroring
    /// `FixedRecNode.getBufferReferences()`'s unconditional `EMPTY_ID_LIST`.
    fn get_buffer_references(&self) -> Vec<i32> {
        Vec::new()
    }

    /// Shift all records starting at `index` through the end of this node by one entry width,
    /// to the right (making room for an insertion) or to the left (closing a gap after a
    /// removal). No-op when `index` is already at the end and shifting right (nothing follows to
    /// move). Mirrors the private `FixedRecNode.shiftRecords(int, boolean)`.
    fn shift_records(&mut self, index: i32, right_shift: bool) -> io::Result<()> {
        let count = self.get_key_count();
        if index == count {
            // No movement needed for an appended record.
            return Ok(());
        }

        let entry_size = self.entry_size();
        let start = self.get_record_offset(index)?;
        let end = self.get_record_offset(count)?;
        let len = end - start;

        let dest = start + if right_shift { entry_size } else { -entry_size };
        self.move_buffer_data(start, dest, len);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::buffer::{Buffer, DataBuffer};
    use crate::framework::db::field::Field;
    use crate::framework::db::nodes::BTreeNode;
    use crate::framework::db::record::DBRecord;
    use crate::framework::db::record_node::RecordNode;
    use crate::framework::db::schema::Schema;
    use crate::framework::db::table::Table;
    use crate::framework::db::{DBHandle, FieldType};
    use crate::framework::seam_stubs::{LongKeyInteriorNode, LongKeyNode};
    use std::sync::Arc;

    const ENTRY_BASE_OFFSET: i32 = 13; // RECORD_LEAF_HEADER_SIZE, see var_rec_node.rs
    const KEY_SIZE: i32 = 8;

    /// Minimal real-buffer-backed `FixedRecNode`, laid out exactly per the format documented on
    /// `db.FixedRecNode` (`| Key0(8) | Rec0 | ... | KeyN(8) | RecN |`).
    struct TestFixedRecNode {
        buffer: DataBuffer,
        record_length: i32,
        schema: Arc<Schema>,
    }

    impl TestFixedRecNode {
        fn new(buffer_id: i32, size: usize, record_length: i32, schema: Arc<Schema>) -> Self {
            let mut buffer = DataBuffer::new(buffer_id, size);
            buffer.put_int(1, 0); // key count
            Self { buffer, record_length, schema }
        }
    }

    impl Clone for TestFixedRecNode {
        fn clone(&self) -> Self {
            Self {
                buffer: DataBuffer::from_data(self.buffer.get_id(), self.buffer.get_data().to_vec()),
                record_length: self.record_length,
                schema: self.schema.clone(),
            }
        }
    }

    impl BTreeNode for TestFixedRecNode {
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

    impl RecordNode for TestFixedRecNode {
        fn get_record_offset(&self, index: i32) -> io::Result<i32> {
            Ok(ENTRY_BASE_OFFSET + index * self.entry_size())
        }

        fn get_key_offset(&self, index: i32) -> io::Result<i32> {
            Ok(ENTRY_BASE_OFFSET + index * self.entry_size())
        }
    }

    impl LongKeyNode for TestFixedRecNode {
        fn get_parent(&self) -> Option<Box<dyn LongKeyInteriorNode>> {
            None
        }

        fn get_key(&self, index: i32) -> i64 {
            self.buffer.get_long((ENTRY_BASE_OFFSET + index * self.entry_size()) as usize)
        }

        fn get_root(&self) -> Box<dyn LongKeyNode> {
            Box::new(self.clone())
        }

        fn get_leaf_node(&self, _key: i64) -> io::Result<Box<dyn LongKeyRecordNode>> {
            Ok(Box::new(self.clone()))
        }
    }

    impl LongKeyRecordNode for TestFixedRecNode {
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
            // Real splitting requires downcasting into a sibling `TestFixedRecNode`, which is not
            // exercised by these tests: `shift_records` (this module's real standalone logic) is
            // tested directly below via `insert_record`/`remove`.
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
            if index < 0 || index >= self.get_key_count() {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "index out of bounds"));
            }
            self.shift_records(index + 1, false)?;
            self.set_key_count(self.get_key_count() - 1);
            Ok(())
        }

        fn insert_record(&mut self, index: i32, record: &DBRecord) -> io::Result<bool> {
            let entry_size = self.entry_size();
            let count = self.get_key_count();
            let capacity = (self.buffer_length() - ENTRY_BASE_OFFSET) / entry_size;
            if count >= capacity {
                return Ok(false); // insufficient space for record storage
            }

            self.shift_records(index, true)?;

            let offset = self.get_record_offset(index)? as usize;
            self.buffer.put_long(offset, record.get_key().get_long_value());
            record.write(&mut self.buffer, offset + KEY_SIZE as usize);
            self.set_key_count(count + 1);
            Ok(true)
        }

        fn update_record(&mut self, index: i32, record: &DBRecord) -> io::Result<Box<dyn LongKeyNode>> {
            let offset = self.get_record_offset(index)? as usize + KEY_SIZE as usize;
            record.write(&mut self.buffer, offset);
            Ok(Box::new(self.clone()))
        }

        fn get_record(&self, key: i64, schema: &Schema) -> io::Result<Option<DBRecord>> {
            let index = self.get_key_index(key);
            if index < 0 {
                return Ok(None);
            }
            self.get_record_at_index(schema, index).map(Some)
        }

        fn get_record_at_index(&self, _schema: &Schema, index: i32) -> io::Result<DBRecord> {
            let key = self.get_key(index);
            let mut record = DBRecord::new(self.schema.clone(), Field::Long(Some(key)));
            let offset = self.get_record_offset(index)? as usize + KEY_SIZE as usize;
            record.read(&self.buffer, offset);
            Ok(record)
        }
    }

    impl FixedRecNode for TestFixedRecNode {
        fn entry_size(&self) -> i32 {
            KEY_SIZE + self.record_length
        }

        fn buffer_length(&self) -> i32 {
            self.buffer.length() as i32
        }

        fn move_buffer_data(&mut self, from: i32, to: i32, len: i32) {
            self.buffer.move_data(from as usize, to as usize, len as usize);
        }

        fn delete(&mut self) -> io::Result<()> {
            self.set_key_count(0);
            Ok(())
        }
    }

    fn make_schema() -> Arc<Schema> {
        Arc::new(Schema::new(
            1,
            FieldType::Long,
            "ID".to_string(),
            vec![FieldType::Int],
            vec!["Value".to_string()],
            vec![],
        ))
    }

    #[test]
    fn test_insert_and_get_records_round_trip_through_real_buffer() {
        let schema = make_schema();
        let mut node = TestFixedRecNode::new(1, 128, 4, schema.clone());
        let mut dbh = DBHandle::new().unwrap();
        let table = dbh.create_table("MyTable".to_string(), schema.clone()).unwrap();
        let mut t = table.write().unwrap();

        for (key, value) in [(10i64, 100), (30, 300), (20, 200)] {
            let mut rec = DBRecord::new(schema.clone(), Field::Long(Some(key)));
            rec.set_int(0, value);
            node.put_record(rec, &mut t).unwrap();
        }

        assert_eq!(node.get_key_count(), 3);
        // Fixed-length entries are kept in ascending key order (same insertion-point behavior as
        // `VarRecNode`).
        assert_eq!(node.get_key(0), 10);
        assert_eq!(node.get_key(1), 20);
        assert_eq!(node.get_key(2), 30);

        let rec20 = node.get_record(20, &schema).unwrap().unwrap();
        assert_eq!(rec20.get_int(0), Some(200));
    }

    #[test]
    fn test_update_record_overwrites_in_place() {
        let schema = make_schema();
        let mut node = TestFixedRecNode::new(1, 128, 4, schema.clone());
        let mut dbh = DBHandle::new().unwrap();
        let table = dbh.create_table("MyTable".to_string(), schema.clone()).unwrap();
        let mut t = table.write().unwrap();

        let mut rec = DBRecord::new(schema.clone(), Field::Long(Some(5)));
        rec.set_int(0, 1);
        node.put_record(rec, &mut t).unwrap();

        let mut updated = DBRecord::new(schema.clone(), Field::Long(Some(5)));
        updated.set_int(0, 42);
        LongKeyRecordNode::update_record(&mut node, 0, &updated).unwrap();

        // In-place update never changes the key count or entry offsets -- only the payload.
        assert_eq!(node.get_key_count(), 1);
        assert_eq!(node.get_key(0), 5);
        assert_eq!(node.get_record(5, &schema).unwrap().unwrap().get_int(0), Some(42));
    }

    #[test]
    fn test_remove_shifts_trailing_entries_left() {
        let schema = make_schema();
        let mut node = TestFixedRecNode::new(1, 128, 4, schema.clone());
        let mut dbh = DBHandle::new().unwrap();
        let table = dbh.create_table("MyTable".to_string(), schema.clone()).unwrap();
        let mut t = table.write().unwrap();

        for key in [1i64, 2, 3] {
            let mut rec = DBRecord::new(schema.clone(), Field::Long(Some(key)));
            rec.set_int(0, key as i32 * 10);
            node.put_record(rec, &mut t).unwrap();
        }

        LongKeyRecordNode::remove(&mut node, 1).unwrap(); // remove key=2
        assert_eq!(node.get_key_count(), 2);
        assert_eq!(node.get_key(0), 1);
        assert_eq!(node.get_key(1), 3);
        assert!(node.get_record(2, &schema).unwrap().is_none());
        // The entry that used to be at index 2 (key=3) must have shifted down into index 1's slot.
        assert_eq!(node.get_record(3, &schema).unwrap().unwrap().get_int(0), Some(30));
    }

    #[test]
    fn test_shift_records_is_a_noop_when_appending() {
        let schema = make_schema();
        let mut node = TestFixedRecNode::new(1, 128, 4, schema.clone());
        let before = node.buffer.get_data().to_vec();
        node.shift_records(node.get_key_count(), true).unwrap(); // index == keyCount (0 here)
        assert_eq!(node.buffer.get_data(), before.as_slice());
    }

    #[test]
    fn test_insert_record_rejects_when_buffer_is_full() {
        let schema = make_schema();
        // Buffer only large enough for exactly one 12-byte entry (KEY_SIZE(8) + record_length(4)).
        let mut node = TestFixedRecNode::new(1, ENTRY_BASE_OFFSET as usize + 12, 4, schema.clone());

        let mut first = DBRecord::new(schema.clone(), Field::Long(Some(1)));
        first.set_int(0, 1);
        assert!(node.insert_record(0, &first).unwrap());

        let mut second = DBRecord::new(schema.clone(), Field::Long(Some(2)));
        second.set_int(0, 2);
        assert!(!node.insert_record(1, &second).unwrap()); // no room left
        assert_eq!(node.get_key_count(), 1);
    }

    #[test]
    fn test_delete_and_get_buffer_references_are_object_safe() {
        let schema = make_schema();
        let mut node = TestFixedRecNode::new(1, 128, 4, schema.clone());
        let mut dbh = DBHandle::new().unwrap();
        let table = dbh.create_table("MyTable".to_string(), schema.clone()).unwrap();
        let mut t = table.write().unwrap();

        let mut rec = DBRecord::new(schema.clone(), Field::Long(Some(1)));
        rec.set_int(0, 9);
        node.put_record(rec, &mut t).unwrap();

        let boxed: Box<dyn FixedRecNode> = Box::new(node);
        // FixedRecNode always stores records inline, so this is unconditionally empty.
        assert!(boxed.get_buffer_references().is_empty());

        let mut boxed = boxed;
        boxed.delete().unwrap();
        assert_eq!(boxed.get_key_count(), 0);
    }
}

use std::io;

use thiserror::Error;

use super::field::Field;
use super::record::DBRecord;
use super::record_node::RecordNode;
use super::schema::Schema;
use super::table::Table;
use crate::framework::seam_stubs::LongKeyNode;
use crate::util::exception::CancelledException;
use crate::util::msg::Msg;
use crate::util::task::TaskMonitor;

/// Combines the checked exceptions declared on `LongKeyRecordNode.isConsistent`.
#[derive(Error, Debug)]
pub enum ConsistencyCheckError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Cancelled(#[from] CancelledException),
}

/// An abstract implementation of a BTree leaf node which utilizes long key values and stores
/// records.
///
/// Mirrors `db.LongKeyRecordNode`, which extends `LongKeyNode` and implements `RecordNode`.
pub trait LongKeyRecordNode: RecordNode + LongKeyNode {
    /// Get this leaf node's right sibling, or `None` if it does not exist.
    fn get_next_leaf(&self) -> io::Result<Option<Box<dyn LongKeyRecordNode>>>;

    /// Get this leaf node's left sibling, or `None` if it does not exist.
    fn get_previous_leaf(&self) -> io::Result<Option<Box<dyn LongKeyRecordNode>>>;

    /// Split this leaf node in half and update the tree. When a split is performed, the next
    /// operation must be performed from the root node since the tree may have been
    /// restructured. Returns the root node, which may have changed.
    fn split(&mut self) -> io::Result<Box<dyn LongKeyNode>>;

    /// Append a leaf which contains one or more keys and update the tree. `leaf` is inserted as
    /// the new right sibling of this leaf (must be the same node type as this leaf). Returns the
    /// root node, which may have changed.
    fn append_leaf(
        &mut self,
        leaf: Box<dyn LongKeyRecordNode>,
    ) -> io::Result<Box<dyn LongKeyNode>>;

    /// Remove this leaf from the tree. Returns the root node, which may have changed, or `None`
    /// if the tree is now empty.
    fn remove_leaf(&mut self) -> io::Result<Option<Box<dyn LongKeyNode>>>;

    /// Split the contents of this leaf node, placing the right half of the records into the
    /// empty leaf node provided.
    fn split_data(&mut self, new_right_leaf: &mut dyn LongKeyRecordNode);

    /// Create a new leaf and add it to the node manager. The new leaf's parent is unknown.
    fn create_new_leaf(
        &self,
        prev_node_id: i32,
        next_node_id: i32,
    ) -> io::Result<Box<dyn LongKeyRecordNode>>;

    /// Insert or update a record. `table` is notified when the record is inserted or updated;
    /// this must be specified when the table has indexed columns. Returns the root node, which
    /// may have changed.
    fn put_record(
        &mut self,
        record: DBRecord,
        table: &mut Table,
    ) -> io::Result<Box<dyn LongKeyNode>>;

    /// Delete the record identified by the specified key. `table` is notified when the record is
    /// deleted. Returns the root node, which may have changed.
    fn delete_record(
        &mut self,
        key: i64,
        table: &mut Table,
    ) -> io::Result<Option<Box<dyn LongKeyNode>>>;

    /// Remove the record identified by index. This will never be the last record within the
    /// node.
    fn remove(&mut self, index: i32) -> io::Result<()>;

    /// Insert the record at the given index if there is sufficient space in the buffer. Returns
    /// `true` if the record was successfully inserted.
    fn insert_record(&mut self, index: i32, record: &DBRecord) -> io::Result<bool>;

    /// Update the record at the given index. Returns the root node, which may have changed.
    fn update_record(&mut self, index: i32, record: &DBRecord) -> io::Result<Box<dyn LongKeyNode>>;

    /// Get the record identified by the specified key, or `None` if not found.
    fn get_record(&self, key: i64, schema: &Schema) -> io::Result<Option<DBRecord>>;

    /// Get the record located at the specified index.
    fn get_record_at_index(&self, schema: &Schema, index: i32) -> io::Result<DBRecord>;

    /// Perform a binary search to locate the specified key.
    ///
    /// Returns the key index if found, else `-(key_index + 1)` indicating the insertion point.
    fn get_key_index(&self, key: i64) -> i32 {
        let mut min: i32 = 0;
        let mut max: i32 = self.get_key_count() - 1;
        while min <= max {
            let i = (min + max) / 2;
            let k = self.get_key(i);
            if k == key {
                return i;
            } else if k < key {
                min = i + 1;
            } else {
                max = i - 1;
            }
        }
        -(min + 1)
    }

    /// Perform a binary search to locate the specified field-wrapped key.
    fn get_key_index_field(&self, key: &Field) -> io::Result<i32> {
        Ok(self.get_key_index(key.get_long_value()))
    }

    /// Append a new leaf and insert the specified record. Returns the root node, which may have
    /// changed.
    fn append_new_leaf(&mut self, record: DBRecord) -> io::Result<Box<dyn LongKeyNode>> {
        let mut new_leaf = self.create_new_leaf(-1, -1)?;
        new_leaf.insert_record(0, &record)?;
        self.append_leaf(new_leaf)
    }

    /// Get the first record whose key is less than the specified key, or `None` if not found.
    fn get_record_before(&self, key: i64, schema: &Schema) -> io::Result<Option<DBRecord>> {
        let mut index = self.get_key_index(key);
        if index < 0 {
            index = -index - 2;
        } else {
            index -= 1;
        }
        if index < 0 {
            return match self.get_previous_leaf()? {
                Some(prev) => {
                    let last = prev.get_key_count() - 1;
                    Ok(Some(prev.get_record_at_index(schema, last)?))
                }
                None => Ok(None),
            };
        }
        Ok(Some(self.get_record_at_index(schema, index)?))
    }

    /// Get the first record whose key is greater than the specified key, or `None` if not found.
    fn get_record_after(&self, key: i64, schema: &Schema) -> io::Result<Option<DBRecord>> {
        let mut index = self.get_key_index(key);
        if index < 0 {
            index = -(index + 1);
        } else {
            index += 1;
        }
        if index == self.get_key_count() {
            return match self.get_next_leaf()? {
                Some(next) => Ok(Some(next.get_record_at_index(schema, 0)?)),
                None => Ok(None),
            };
        }
        Ok(Some(self.get_record_at_index(schema, index)?))
    }

    /// Get the first record whose key is less than or equal to the specified key, or `None` if
    /// not found.
    fn get_record_at_or_before(&self, key: i64, schema: &Schema) -> io::Result<Option<DBRecord>> {
        let mut index = self.get_key_index(key);
        if index < 0 {
            index = -index - 2;
        }
        if index < 0 {
            return match self.get_previous_leaf()? {
                Some(prev) => {
                    let last = prev.get_key_count() - 1;
                    Ok(Some(prev.get_record_at_index(schema, last)?))
                }
                None => Ok(None),
            };
        }
        Ok(Some(self.get_record_at_index(schema, index)?))
    }

    /// Get the first record whose key is greater than or equal to the specified key, or `None`
    /// if not found.
    fn get_record_at_or_after(&self, key: i64, schema: &Schema) -> io::Result<Option<DBRecord>> {
        let mut index = self.get_key_index(key);
        if index < 0 {
            index = -(index + 1);
        }
        if index == self.get_key_count() {
            return match self.get_next_leaf()? {
                Some(next) => Ok(Some(next.get_record_at_index(schema, 0)?)),
                None => Ok(None),
            };
        }
        Ok(Some(self.get_record_at_index(schema, index)?))
    }

    /// Log a BTree consistency error for the named table via [`Msg`].
    fn log_consistency_error(
        &self,
        table_name: &str,
        msg: &str,
        cause: Option<&dyn std::error::Error>,
    ) {
        Msg::debug(
            "LongKeyRecordNode",
            &format!("Consistency Error ({}): {}", table_name, msg),
        );
        Msg::debug(
            "LongKeyRecordNode",
            &format!(
                "  bufferID={} key[0]=0x{:x}",
                self.get_buffer_id(),
                self.get_key(0)
            ),
        );
        if let Some(err) = cause {
            Msg::error_with_error(
                "LongKeyRecordNode",
                &format!("Consistency Error ({})", table_name),
                err,
            );
        }
    }

    /// Check the consistency of this leaf node.
    ///
    /// Node identity (Java's `me != this`) is approximated via buffer id equality, since trait
    /// objects returned from sibling lookups do not preserve object identity.
    fn is_consistent(
        &self,
        table_name: &str,
        _monitor: &dyn TaskMonitor,
    ) -> Result<bool, ConsistencyCheckError> {
        let mut consistent = true;
        let mut prev_key: i64 = 0;
        for i in 0..self.get_key_count() {
            let key = self.get_key(i);
            if i != 0 && key <= prev_key {
                consistent = false;
                self.log_consistency_error(
                    table_name,
                    &format!("key[{}] <= key[{}]", i, i - 1),
                    None,
                );
            }
            prev_key = key;
        }

        let is_leftmost = match self.get_parent() {
            Some(parent) => parent.is_leftmost_key(self.get_key(0)),
            None => true,
        };
        if is_leftmost && self.get_previous_leaf()?.is_some() {
            consistent = false;
            self.log_consistency_error(table_name, "previous-leaf should not exist", None);
        }

        match self.get_next_leaf()? {
            Some(node) => {
                let is_rightmost = match self.get_parent() {
                    Some(parent) => parent.is_rightmost_key(self.get_key(0)),
                    None => true,
                };
                if is_rightmost {
                    consistent = false;
                    self.log_consistency_error(table_name, "next-leaf should not exist", None);
                } else {
                    let linked_back = node
                        .get_previous_leaf()?
                        .map(|me| me.get_buffer_id() == self.get_buffer_id())
                        .unwrap_or(false);
                    if !linked_back {
                        consistent = false;
                        self.log_consistency_error(
                            table_name,
                            "next-leaf is not linked to this leaf",
                            None,
                        );
                    }
                }
            }
            None => {
                let is_rightmost = match self.get_parent() {
                    Some(parent) => parent.is_rightmost_key(self.get_key(0)),
                    None => true,
                };
                if !is_rightmost {
                    consistent = false;
                    self.log_consistency_error(
                        table_name,
                        "this leaf is not linked to next-leaf",
                        None,
                    );
                }
            }
        }

        Ok(consistent)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::{DBHandle, FieldType};
    use crate::framework::seam_stubs::LongKeyInteriorNode;
    use crate::util::task::DummyMonitor;
    use std::sync::Arc;

    #[derive(Clone)]
    struct MockInteriorNode {
        leftmost_key: i64,
        rightmost_key: i64,
    }

    impl LongKeyInteriorNode for MockInteriorNode {
        fn is_leftmost_key(&self, key: i64) -> bool {
            key == self.leftmost_key
        }

        fn is_rightmost_key(&self, key: i64) -> bool {
            key == self.rightmost_key
        }

        fn insert(&mut self, _id: i32, _key: i64) -> io::Result<Box<dyn LongKeyNode>> {
            Err(io::Error::new(io::ErrorKind::Other, "not supported in mock"))
        }

        fn delete_child(&mut self, _key: i64) -> io::Result<Box<dyn LongKeyNode>> {
            Err(io::Error::new(io::ErrorKind::Other, "not supported in mock"))
        }

        fn key_changed(&mut self, _old_key: i64, _new_key: i64) {}
    }

    #[derive(Clone)]
    struct MockLeaf {
        buffer_id: i32,
        keys: Vec<i64>,
        records: Vec<DBRecord>,
        parent: Option<MockInteriorNode>,
        next: Option<Box<MockLeaf>>,
        prev: Option<Box<MockLeaf>>,
    }

    impl crate::framework::db::nodes::BTreeNode for MockLeaf {
        fn get_buffer_id(&self) -> i32 {
            self.buffer_id
        }

        fn get_key_count(&self) -> i32 {
            self.keys.len() as i32
        }

        fn set_key_count(&mut self, _count: i32) {}
    }

    impl RecordNode for MockLeaf {
        fn get_record_offset(&self, index: i32) -> io::Result<i32> {
            Ok(index)
        }

        fn get_key_offset(&self, index: i32) -> io::Result<i32> {
            Ok(index)
        }
    }

    impl LongKeyNode for MockLeaf {
        fn get_parent(&self) -> Option<Box<dyn LongKeyInteriorNode>> {
            self.parent
                .clone()
                .map(|p| Box::new(p) as Box<dyn LongKeyInteriorNode>)
        }

        fn get_key(&self, index: i32) -> i64 {
            self.keys[index as usize]
        }

        fn get_root(&self) -> Box<dyn LongKeyNode> {
            Box::new(self.clone())
        }

        fn get_leaf_node(&self, _key: i64) -> io::Result<Box<dyn LongKeyRecordNode>> {
            Ok(Box::new(self.clone()))
        }
    }

    impl LongKeyRecordNode for MockLeaf {
        fn get_next_leaf(&self) -> io::Result<Option<Box<dyn LongKeyRecordNode>>> {
            Ok(self
                .next
                .clone()
                .map(|n| Box::new(*n) as Box<dyn LongKeyRecordNode>))
        }

        fn get_previous_leaf(&self) -> io::Result<Option<Box<dyn LongKeyRecordNode>>> {
            Ok(self
                .prev
                .clone()
                .map(|n| Box::new(*n) as Box<dyn LongKeyRecordNode>))
        }

        fn split(&mut self) -> io::Result<Box<dyn LongKeyNode>> {
            Err(io::Error::new(io::ErrorKind::Other, "not supported in mock"))
        }

        fn append_leaf(
            &mut self,
            _leaf: Box<dyn LongKeyRecordNode>,
        ) -> io::Result<Box<dyn LongKeyNode>> {
            Err(io::Error::new(io::ErrorKind::Other, "not supported in mock"))
        }

        fn remove_leaf(&mut self) -> io::Result<Option<Box<dyn LongKeyNode>>> {
            Ok(None)
        }

        fn split_data(&mut self, _new_right_leaf: &mut dyn LongKeyRecordNode) {}

        fn create_new_leaf(
            &self,
            _prev_node_id: i32,
            _next_node_id: i32,
        ) -> io::Result<Box<dyn LongKeyRecordNode>> {
            Err(io::Error::new(io::ErrorKind::Other, "not supported in mock"))
        }

        fn put_record(
            &mut self,
            record: DBRecord,
            _table: &mut Table,
        ) -> io::Result<Box<dyn LongKeyNode>> {
            self.keys.push(record.get_key().get_long_value());
            self.records.push(record);
            Ok(Box::new(self.clone()))
        }

        fn delete_record(
            &mut self,
            key: i64,
            _table: &mut Table,
        ) -> io::Result<Option<Box<dyn LongKeyNode>>> {
            if let Some(pos) = self.keys.iter().position(|&k| k == key) {
                self.keys.remove(pos);
                self.records.remove(pos);
            }
            Ok(Some(Box::new(self.clone())))
        }

        fn remove(&mut self, index: i32) -> io::Result<()> {
            self.keys.remove(index as usize);
            self.records.remove(index as usize);
            Ok(())
        }

        fn insert_record(&mut self, index: i32, record: &DBRecord) -> io::Result<bool> {
            self.keys
                .insert(index as usize, record.get_key().get_long_value());
            self.records.insert(index as usize, record.clone());
            Ok(true)
        }

        fn update_record(&mut self, index: i32, record: &DBRecord) -> io::Result<Box<dyn LongKeyNode>> {
            self.records[index as usize] = record.clone();
            Ok(Box::new(self.clone()))
        }

        fn get_record(&self, key: i64, _schema: &Schema) -> io::Result<Option<DBRecord>> {
            Ok(self
                .keys
                .iter()
                .position(|&k| k == key)
                .map(|i| self.records[i].clone()))
        }

        fn get_record_at_index(&self, _schema: &Schema, index: i32) -> io::Result<DBRecord> {
            Ok(self.records[index as usize].clone())
        }
    }

    #[test]
    fn test_long_key_record_node_is_object_safe() {
        let schema = Arc::new(Schema::new(
            1,
            FieldType::Long,
            "ID".to_string(),
            vec![],
            vec![],
            vec![],
        ));

        let leaf1_stub = MockLeaf {
            buffer_id: 1,
            keys: vec![10],
            records: vec![DBRecord::new(schema.clone(), Field::Long(Some(10)))],
            parent: None,
            next: None,
            prev: None,
        };

        let leaf2 = MockLeaf {
            buffer_id: 2,
            keys: vec![30, 40],
            records: vec![
                DBRecord::new(schema.clone(), Field::Long(Some(30))),
                DBRecord::new(schema.clone(), Field::Long(Some(40))),
            ],
            parent: Some(MockInteriorNode { leftmost_key: 10, rightmost_key: 30 }),
            next: None,
            prev: Some(Box::new(leaf1_stub)),
        };

        let leaf1 = MockLeaf {
            buffer_id: 1,
            keys: vec![10, 20],
            records: vec![
                DBRecord::new(schema.clone(), Field::Long(Some(10))),
                DBRecord::new(schema.clone(), Field::Long(Some(20))),
            ],
            parent: Some(MockInteriorNode { leftmost_key: 10, rightmost_key: 30 }),
            next: Some(Box::new(leaf2.clone())),
            prev: None,
        };

        // Real binary-search behavior via the default `get_key_index` method.
        assert_eq!(leaf1.get_key_index(20), 1);
        assert_eq!(leaf1.get_key_index(15), -2);

        // Crosses over into the sibling leaf via the default before/after methods.
        let after = leaf1.get_record_after(20, &schema).unwrap().unwrap();
        assert_eq!(after.get_key(), &Field::Long(Some(30)));

        let before = leaf2.get_record_before(30, &schema).unwrap().unwrap();
        assert_eq!(before.get_key(), &Field::Long(Some(10)));

        // A well-linked leaf reports itself consistent.
        let monitor = DummyMonitor;
        assert!(leaf1.is_consistent("MyTable", &monitor).unwrap());

        // An out-of-order leaf is reported inconsistent.
        let broken = MockLeaf {
            buffer_id: 3,
            keys: vec![20, 10],
            records: vec![
                DBRecord::new(schema.clone(), Field::Long(Some(20))),
                DBRecord::new(schema.clone(), Field::Long(Some(10))),
            ],
            parent: None,
            next: None,
            prev: None,
        };
        assert!(!broken.is_consistent("MyTable", &monitor).unwrap());

        // Object safety: usable as a boxed trait object.
        let boxed: Box<dyn LongKeyRecordNode> = Box::new(leaf1.clone());
        assert_eq!(boxed.get_buffer_id(), 1);
        assert_eq!(boxed.get_key_count(), 2);

        // Mutating operations (put_record) via the trait, exercising append_new_leaf's
        // dependencies indirectly through the object-safe interface.
        let mut dbh = DBHandle::new().unwrap();
        let table = dbh.create_table("MyTable".to_string(), schema.clone()).unwrap();
        let mut mutable_leaf = leaf1.clone();
        {
            let mut t = table.write().unwrap();
            let rec = DBRecord::new(schema.clone(), Field::Long(Some(99)));
            let root = mutable_leaf.put_record(rec, &mut t).unwrap();
            assert_eq!(root.get_key(0), 10);
        }
        assert_eq!(mutable_leaf.get_key_count(), 3);
    }
}

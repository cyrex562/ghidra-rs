use std::io;

use super::field_key_record_node::FieldKeyRecordNode;
use super::fixed_key_node::FixedKeyNode;
use super::record::DBRecord;

/// A BTree leaf node which utilizes fixed-length key values and stores fixed-length records.
///
/// Mirrors `db.FixedKeyFixedRecNode`, a concrete leaf implementation of the abstract
/// `FixedKeyRecordNode` (itself a `FieldKeyRecordNode`), selected as a dependency-cycle
/// cut-point. Only the members declared or overridden directly within `FixedKeyFixedRecNode.java`
/// are modeled here -- the `FixedKeyRecordNode`/`FixedKeyNode` superclasses it extends (which carry
/// the shared BTree leaf-linking and split/insert orchestration logic) are out of scope for this
/// port; the root-node type they return is the ported
/// [`FixedKeyNode`](crate::framework::db::fixed_key_node::FixedKeyNode) trait. Unlike
/// [`FixedKeyVarRecNode`](crate::framework::db::fixed_key_var_rec_node::FixedKeyVarRecNode), this
/// node type stores records at a fixed per-entry offset -- `getRecordOffset`/`getKeyOffset` use the
/// same formula, so no separate record-data-offset accessor is needed beyond the inherited
/// `RecordNode`/`FieldKeyRecordNode` supertrait methods.
pub trait FixedKeyFixedRecNode: FieldKeyRecordNode {
    /// Create a new leaf and add it to the node manager. The new leaf's parent is unknown.
    fn create_new_leaf(
        &self,
        prev_leaf_id: i32,
        next_leaf_id: i32,
    ) -> io::Result<Box<dyn FixedKeyFixedRecNode>>;

    /// Exposes this node as `Any` so that `split_data` implementations can recover the concrete
    /// type of `new_right_leaf`, mirroring the unchecked `(FixedKeyFixedRecNode) newRightLeaf`
    /// cast performed in the Java original (both leaves are always the same concrete node type).
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any;

    /// Split the contents of this leaf node, placing the right half of the records into the
    /// empty leaf node provided.
    fn split_data(&mut self, new_right_leaf: &mut dyn FixedKeyFixedRecNode);

    /// Update the record at the given index. Returns the root node, which may have changed.
    fn update_record(
        &mut self,
        index: i32,
        record: &DBRecord,
    ) -> io::Result<Box<dyn FixedKeyNode>>;

    /// Insert the record at the given index if there is sufficient space in the buffer. Returns
    /// `true` if the record was successfully inserted.
    fn insert_record(&mut self, index: i32, record: &DBRecord) -> io::Result<bool>;

    /// Delete this node from the node manager.
    fn delete(&mut self) -> io::Result<()>;

    /// Get the buffer ids of any chained buffers used for indirect record storage by this node.
    ///
    /// `FixedKeyFixedRecNode` stores records inline only, so this always returns an empty list.
    fn get_buffer_references(&self) -> Vec<i32>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::field::Field;
    use crate::framework::db::field_key_interior_node::FieldKeyInteriorNode;
    use crate::framework::db::field_key_node::FieldKeyNode;
    use crate::framework::db::nodes::BTreeNode;
    use crate::framework::db::record_node::RecordNode;
    use crate::framework::db::schema::Schema;
    use crate::framework::db::table::Table;
    use crate::framework::db::{DBHandle, FieldType};
    use std::sync::Arc;

    /// Minimal stand-in for the real root node returned by `update_record`; this class never
    /// inspects the returned root, so no behavior beyond object safety is needed.
    struct MockRoot {
        buffer_id: i32,
    }

    impl BTreeNode for MockRoot {
        fn get_buffer_id(&self) -> i32 {
            self.buffer_id
        }

        fn get_key_count(&self) -> i32 {
            0
        }

        fn set_key_count(&mut self, _count: i32) {}
    }

    impl FieldKeyNode for MockRoot {
        fn get_parent(&self) -> Option<Box<dyn FieldKeyInteriorNode>> {
            None
        }

        fn get_leaf_node(&self, _key: &Field) -> io::Result<Box<dyn FieldKeyRecordNode>> {
            Err(io::Error::new(io::ErrorKind::Other, "no leaf node"))
        }

        fn get_leftmost_leaf_node(&self) -> io::Result<Box<dyn FieldKeyRecordNode>> {
            Err(io::Error::new(io::ErrorKind::Other, "no leaf node"))
        }

        fn get_rightmost_leaf_node(&self) -> io::Result<Box<dyn FieldKeyRecordNode>> {
            Err(io::Error::new(io::ErrorKind::Other, "no leaf node"))
        }

        fn compare_key_field(&self, _k: &Field, _key_index: i32) -> i32 {
            0
        }
    }

    impl FixedKeyNode for MockRoot {
        fn get_key_field(&self, _index: i32) -> Field {
            Field::Long(None)
        }

        fn is_consistent(
            &self,
            _table_name: &str,
            _monitor: &dyn crate::util::task::TaskMonitor,
        ) -> io::Result<bool> {
            Ok(true)
        }
    }

    #[derive(Clone)]
    struct MockFixedKeyFixedRecNode {
        buffer_id: i32,
        keys: Vec<Field>,
        records: Vec<DBRecord>,
    }

    impl MockFixedKeyFixedRecNode {
        fn new(buffer_id: i32) -> Self {
            Self { buffer_id, keys: vec![], records: vec![] }
        }
    }

    impl BTreeNode for MockFixedKeyFixedRecNode {
        fn get_buffer_id(&self) -> i32 {
            self.buffer_id
        }

        fn get_key_count(&self) -> i32 {
            self.keys.len() as i32
        }

        fn set_key_count(&mut self, count: i32) {
            self.keys.truncate(count as usize);
            self.records.truncate(count as usize);
        }
    }

    impl RecordNode for MockFixedKeyFixedRecNode {
        fn get_record_offset(&self, index: i32) -> io::Result<i32> {
            Ok(index * 16)
        }

        fn get_key_offset(&self, index: i32) -> io::Result<i32> {
            Ok(index * 16)
        }
    }

    impl FieldKeyNode for MockFixedKeyFixedRecNode {
        fn get_parent(&self) -> Option<Box<dyn FieldKeyInteriorNode>> {
            None
        }

        fn get_leaf_node(&self, _key: &Field) -> io::Result<Box<dyn FieldKeyRecordNode>> {
            Ok(Box::new(self.clone()))
        }

        fn get_leftmost_leaf_node(&self) -> io::Result<Box<dyn FieldKeyRecordNode>> {
            Ok(Box::new(self.clone()))
        }

        fn get_rightmost_leaf_node(&self) -> io::Result<Box<dyn FieldKeyRecordNode>> {
            Ok(Box::new(self.clone()))
        }

        fn compare_key_field(&self, k: &Field, key_index: i32) -> i32 {
            match self.keys[key_index as usize].get_long_value().cmp(&k.get_long_value()) {
                std::cmp::Ordering::Less => 1,
                std::cmp::Ordering::Greater => -1,
                std::cmp::Ordering::Equal => 0,
            }
        }
    }

    impl FieldKeyRecordNode for MockFixedKeyFixedRecNode {
        fn get_record_at_index(&self, _schema: &Schema, index: i32) -> io::Result<DBRecord> {
            Ok(self.records[index as usize].clone())
        }

        fn put_record(
            &mut self,
            record: DBRecord,
            _table: &mut Table,
        ) -> io::Result<Box<dyn FieldKeyNode>> {
            self.keys.push(record.get_key().clone());
            self.records.push(record);
            Ok(Box::new(MockRoot { buffer_id: self.buffer_id }))
        }

        fn remove(&mut self, index: i32) -> io::Result<()> {
            self.keys.remove(index as usize);
            self.records.remove(index as usize);
            Ok(())
        }

        fn has_next_leaf(&self) -> io::Result<bool> {
            Ok(false)
        }

        fn get_next_leaf(&self) -> io::Result<Option<Box<dyn FieldKeyRecordNode>>> {
            Ok(None)
        }

        fn has_previous_leaf(&self) -> io::Result<bool> {
            Ok(false)
        }

        fn get_previous_leaf(&self) -> io::Result<Option<Box<dyn FieldKeyRecordNode>>> {
            Ok(None)
        }

        fn remove_leaf(&mut self) -> io::Result<Box<dyn FieldKeyNode>> {
            Ok(Box::new(MockRoot { buffer_id: self.buffer_id }))
        }

        fn delete_record(
            &mut self,
            key: &Field,
            _table: &mut Table,
        ) -> io::Result<Box<dyn FieldKeyNode>> {
            self.keys.retain(|k| k != key);
            Ok(Box::new(MockRoot { buffer_id: self.buffer_id }))
        }

        fn get_record_at_or_after(
            &self,
            key: &Field,
            _schema: &Schema,
        ) -> io::Result<Option<DBRecord>> {
            Ok(self.records.iter().find(|r| r.get_key() >= key).cloned())
        }

        fn get_record_at_or_before(
            &self,
            key: &Field,
            _schema: &Schema,
        ) -> io::Result<Option<DBRecord>> {
            Ok(self.records.iter().rev().find(|r| r.get_key() <= key).cloned())
        }

        fn get_record_after(&self, key: &Field, _schema: &Schema) -> io::Result<Option<DBRecord>> {
            Ok(self.records.iter().find(|r| r.get_key() > key).cloned())
        }

        fn get_record_before(&self, key: &Field, _schema: &Schema) -> io::Result<Option<DBRecord>> {
            Ok(self.records.iter().rev().find(|r| r.get_key() < key).cloned())
        }

        fn get_record(&self, key: &Field, _schema: &Schema) -> io::Result<Option<DBRecord>> {
            Ok(self.records.iter().find(|r| r.get_key() == key).cloned())
        }
    }

    impl FixedKeyFixedRecNode for MockFixedKeyFixedRecNode {
        fn create_new_leaf(
            &self,
            prev_leaf_id: i32,
            next_leaf_id: i32,
        ) -> io::Result<Box<dyn FixedKeyFixedRecNode>> {
            // Buffer id for the new leaf is unrelated to the sibling ids in this mock; only their
            // presence-as-hint is modeled by folding them into a distinct id.
            let new_id = self.buffer_id + prev_leaf_id.max(0) + next_leaf_id.max(0) + 1000;
            Ok(Box::new(MockFixedKeyFixedRecNode::new(new_id)))
        }

        fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
            self
        }

        fn split_data(&mut self, new_right_leaf: &mut dyn FixedKeyFixedRecNode) {
            let split = self.keys.len() / 2;
            let right = new_right_leaf
                .as_any_mut()
                .downcast_mut::<MockFixedKeyFixedRecNode>()
                .expect("split_data test double only used with MockFixedKeyFixedRecNode");
            right.keys = self.keys.split_off(split);
            right.records = self.records.split_off(split);
        }

        fn update_record(
            &mut self,
            index: i32,
            record: &DBRecord,
        ) -> io::Result<Box<dyn FixedKeyNode>> {
            self.records[index as usize] = record.clone();
            Ok(Box::new(MockRoot { buffer_id: self.buffer_id }))
        }

        fn insert_record(&mut self, index: i32, record: &DBRecord) -> io::Result<bool> {
            self.keys.insert(index as usize, record.get_key().clone());
            self.records.insert(index as usize, record.clone());
            Ok(true)
        }

        fn delete(&mut self) -> io::Result<()> {
            self.keys.clear();
            self.records.clear();
            Ok(())
        }

        fn get_buffer_references(&self) -> Vec<i32> {
            Vec::new()
        }
    }

    #[test]
    fn test_fixed_key_fixed_rec_node_is_object_safe() {
        let mut dbh = DBHandle::new().unwrap();
        let schema = Arc::new(Schema::new(
            1,
            FieldType::Long,
            "ID".to_string(),
            vec![FieldType::String],
            vec!["Name".to_string()],
            vec![],
        ));
        let table = dbh.create_table("MyTable".to_string(), schema.clone()).unwrap();

        let mut leaf = MockFixedKeyFixedRecNode::new(1);
        {
            let mut t = table.write().unwrap();
            for i in 0..4 {
                let mut rec = DBRecord::new(schema.clone(), Field::Long(Some(i)));
                rec.set_string(0, Some(format!("rec{}", i)));
                leaf.put_record(rec, &mut t).unwrap();
            }
        }
        assert_eq!(leaf.get_key_count(), 4);

        // Exercise real split behavior via the trait method.
        let mut right = MockFixedKeyFixedRecNode::new(2);
        FixedKeyFixedRecNode::split_data(&mut leaf, &mut right);
        assert_eq!(leaf.get_key_count(), 2);
        assert_eq!(right.get_key_count(), 2);
        assert_eq!(right.records[0].get_key(), &Field::Long(Some(2)));

        // Exercise insert/update/delete through the object-safe trait interface.
        let boxed: Box<dyn FixedKeyFixedRecNode> = Box::new(leaf);
        let mut boxed = boxed;
        let new_rec = {
            let mut r = DBRecord::new(schema.clone(), Field::Long(Some(0)));
            r.set_string(0, Some("updated".to_string()));
            r
        };
        let root = boxed.update_record(0, &new_rec).unwrap();
        assert_eq!(root.get_buffer_id(), 1);

        let inserted_rec = DBRecord::new(schema.clone(), Field::Long(Some(99)));
        assert!(boxed.insert_record(0, &inserted_rec).unwrap());
        assert_eq!(boxed.get_key_count(), 3);

        let new_leaf = boxed.create_new_leaf(1, 2).unwrap();
        assert!(new_leaf.get_buffer_id() > 1000);

        assert!(boxed.delete().is_ok());
        assert_eq!(boxed.get_key_count(), 0);
        assert!(boxed.get_buffer_references().is_empty());
    }
}

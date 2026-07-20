use std::io;

use thiserror::Error;

use super::field::Field;
use super::field_key_record_node::FieldKeyRecordNode;
use super::record::DBRecord;
use crate::framework::seam_stubs::{FixedKeyInteriorNodeLike, FixedKeyNode};
use crate::util::exception::CancelledException;
use crate::util::msg::Msg;
use crate::util::task::TaskMonitor;

/// Combines the checked exceptions declared on `FixedKeyRecordNode.isConsistent`.
#[derive(Error, Debug)]
pub enum ConsistencyCheckError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Cancelled(#[from] CancelledException),
}

/// An abstract implementation of a BTree leaf node which utilizes fixed-length binary key values
/// and stores records.
///
/// Mirrors `db.FixedKeyRecordNode`, which extends `FixedKeyNode` and implements
/// [`FieldKeyRecordNode`] -- selected as a dependency-cycle cut-point. The `FixedKeyNode`
/// superclass it extends (shared node header layout, the `parent` field, `getRoot()`) and the
/// concrete `FixedKeyInteriorNode` parent-node type it calls back into are not yet ported, so both
/// are referenced opaquely via the
/// [`FixedKeyNode`](crate::framework::seam_stubs::FixedKeyNode) and
/// [`FixedKeyInteriorNodeLike`](crate::framework::seam_stubs::FixedKeyInteriorNodeLike) stubs in
/// [`seam_stubs`](crate::framework::seam_stubs). Members already declared on the
/// [`FieldKeyRecordNode`] supertrait (`putRecord`, `deleteRecord`, `getRecordBefore`/`After`/
/// `AtOrBefore`/`AtOrAfter`, leaf-sibling accessors, `removeLeaf`, etc.) are inherited as-is
/// rather than redeclared here -- Rust has no covariant override for a same-named supertrait
/// method, so only members declared or overridden directly within `FixedKeyRecordNode.java` (or
/// inherited from the not-yet-ported `FixedKeyNode` and needed by those members) are modeled as
/// new trait items.
pub trait FixedKeyRecordNode: FieldKeyRecordNode {
    /// Get the Field-wrapped key value at a specific index, mirroring the inherited (and not yet
    /// ported) `FixedKeyNode.getKeyField(int)` final method that `isConsistent`, `split`, and
    /// `appendLeaf` call directly.
    fn get_key_field(&self, index: i32) -> Field;

    /// Get this leaf's parent interior node, or `None` if this is the root. Distinct from
    /// [`FieldKeyNode::get_parent`], which can only expose the weaker `FieldKeyInteriorNode`
    /// supertrait type; `isConsistent`'s parent-callback logic (`isLeftmostKey`/`isRightmostKey`)
    /// needs the richer [`FixedKeyInteriorNodeLike`] stub.
    fn get_fixed_parent(&self) -> Option<Box<dyn FixedKeyInteriorNodeLike>>;

    /// Split this leaf node in half and update the tree. When a split is performed, the next
    /// operation must be performed from the root node since the tree may have been
    /// restructured. Returns the root node, which may have changed.
    fn split(&mut self) -> io::Result<Box<dyn FixedKeyNode>>;

    /// Append a leaf which contains one or more keys and update the tree. `leaf` is inserted as
    /// the new right sibling of this leaf (must be the same node type as this leaf). Returns the
    /// root node, which may have changed.
    fn append_leaf(&mut self, leaf: Box<dyn FixedKeyRecordNode>) -> io::Result<Box<dyn FixedKeyNode>>;

    /// Split the contents of this leaf node, placing the right half of the records into the
    /// empty leaf node provided.
    fn split_data(&mut self, new_right_leaf: &mut dyn FixedKeyRecordNode);

    /// Create a new leaf and add it to the node manager. The new leaf's parent is unknown.
    fn create_new_leaf(
        &self,
        prev_node_id: i32,
        next_node_id: i32,
    ) -> io::Result<Box<dyn FixedKeyRecordNode>>;

    /// Insert the record at the given index if there is sufficient space in the buffer. Returns
    /// `true` if the record was successfully inserted.
    fn insert_record(&mut self, index: i32, record: &DBRecord) -> io::Result<bool>;

    /// Update the record at the given index. Returns the root node, which may have changed.
    fn update_record(&mut self, index: i32, record: &DBRecord) -> io::Result<Box<dyn FixedKeyNode>>;

    /// Perform a binary search to locate the specified key.
    ///
    /// Returns the key index if found, else `-(key_index + 1)` indicating the insertion point.
    fn get_key_index(&self, key: &Field) -> i32 {
        let mut min: i32 = 0;
        let mut max: i32 = self.get_key_count() - 1;
        while min <= max {
            let i = (min + max) / 2;
            let rc = self.compare_key_field(key, i);
            if rc == 0 {
                return i;
            } else if rc > 0 {
                min = i + 1;
            } else {
                max = i - 1;
            }
        }
        -(min + 1)
    }

    /// Append a new leaf and insert the specified record. Returns the root node, which may have
    /// changed.
    fn append_new_leaf(&mut self, record: DBRecord) -> io::Result<Box<dyn FixedKeyNode>> {
        let mut new_leaf = self.create_new_leaf(-1, -1)?;
        new_leaf.insert_record(0, &record)?;
        self.append_leaf(new_leaf)
    }

    /// Log a BTree consistency error for the named table via [`Msg`].
    fn log_consistency_error(
        &self,
        table_name: &str,
        msg: &str,
        cause: Option<&dyn std::error::Error>,
    ) {
        Msg::debug(
            "FixedKeyRecordNode",
            &format!("Consistency Error ({}): {}", table_name, msg),
        );
        Msg::debug(
            "FixedKeyRecordNode",
            &format!(
                "  bufferID={} key[0]={:?}",
                self.get_buffer_id(),
                self.get_key_field(0)
            ),
        );
        if let Some(err) = cause {
            Msg::error_with_error(
                "FixedKeyRecordNode",
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
        let mut prev_key: Option<Field> = None;
        for i in 0..self.get_key_count() {
            let key = self.get_key_field(i);
            if let Some(prev) = &prev_key {
                if key <= *prev {
                    consistent = false;
                    self.log_consistency_error(
                        table_name,
                        &format!("key[{}] <= key[{}]", i, i - 1),
                        None,
                    );
                }
            }
            prev_key = Some(key);
        }

        let key0 = self.get_key_field(0);
        let is_leftmost = match self.get_fixed_parent() {
            Some(parent) => parent.is_leftmost_key(&key0),
            None => true,
        };
        if is_leftmost && self.get_previous_leaf()?.is_some() {
            consistent = false;
            self.log_consistency_error(table_name, "previous-leaf should not exist", None);
        }

        match self.get_next_leaf()? {
            Some(node) => {
                let is_rightmost = match self.get_fixed_parent() {
                    Some(parent) => parent.is_rightmost_key(&key0),
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
                let is_rightmost = match self.get_fixed_parent() {
                    Some(parent) => parent.is_rightmost_key(&key0),
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
    use crate::framework::db::field_key_interior_node::FieldKeyInteriorNode;
    use crate::framework::db::field_key_node::FieldKeyNode;
    use crate::framework::db::interior_node::InteriorNode;
    use crate::framework::db::nodes::BTreeNode;
    use crate::framework::db::record_node::RecordNode;
    use crate::framework::db::schema::Schema;
    use crate::framework::db::table::Table;
    use crate::framework::db::{DBHandle, FieldType};
    use crate::util::task::DummyMonitor;
    use std::sync::Arc;

    #[derive(Clone)]
    struct MockInteriorNode {
        buffer_id: i32,
        leftmost_key: Field,
        rightmost_key: Field,
    }

    impl BTreeNode for MockInteriorNode {
        fn get_buffer_id(&self) -> i32 {
            self.buffer_id
        }

        fn get_key_count(&self) -> i32 {
            0
        }

        fn set_key_count(&mut self, _count: i32) {}
    }

    impl InteriorNode for MockInteriorNode {}

    impl FieldKeyNode for MockInteriorNode {
        fn get_parent(
            &self,
        ) -> Option<Box<dyn crate::framework::db::field_key_interior_node::FieldKeyInteriorNode>>
        {
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

    impl FieldKeyInteriorNode for MockInteriorNode {
        fn key_changed(
            &mut self,
            _old_key: &Field,
            _new_key: &Field,
            _child_node: Option<&dyn FieldKeyNode>,
        ) -> io::Result<()> {
            Ok(())
        }
    }

    impl FixedKeyInteriorNodeLike for MockInteriorNode {
        fn is_leftmost_key(&self, key: &Field) -> bool {
            key == &self.leftmost_key
        }

        fn is_rightmost_key(&self, key: &Field) -> bool {
            key == &self.rightmost_key
        }

        fn insert(&mut self, _id: i32, _key: &Field) -> io::Result<Box<dyn FixedKeyNode>> {
            Err(io::Error::new(io::ErrorKind::Other, "not supported in mock"))
        }

        fn delete_child(&mut self, _key: &Field) -> io::Result<Box<dyn FixedKeyNode>> {
            Err(io::Error::new(io::ErrorKind::Other, "not supported in mock"))
        }
    }

    impl FixedKeyNode for MockInteriorNode {}

    #[derive(Clone)]
    struct MockLeaf {
        buffer_id: i32,
        keys: Vec<Field>,
        records: Vec<DBRecord>,
        parent: Option<MockInteriorNode>,
        next: Option<Box<MockLeaf>>,
        prev: Option<Box<MockLeaf>>,
    }

    impl BTreeNode for MockLeaf {
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

    impl RecordNode for MockLeaf {
        fn get_record_offset(&self, index: i32) -> io::Result<i32> {
            Ok(index)
        }

        fn get_key_offset(&self, index: i32) -> io::Result<i32> {
            Ok(index)
        }
    }

    impl FieldKeyNode for MockLeaf {
        fn get_parent(
            &self,
        ) -> Option<Box<dyn crate::framework::db::field_key_interior_node::FieldKeyInteriorNode>>
        {
            self.parent.clone().map(|p| {
                Box::new(p) as Box<dyn crate::framework::db::field_key_interior_node::FieldKeyInteriorNode>
            })
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
            match self.keys[key_index as usize].cmp(k) {
                std::cmp::Ordering::Less => 1,
                std::cmp::Ordering::Greater => -1,
                std::cmp::Ordering::Equal => 0,
            }
        }
    }

    impl FieldKeyRecordNode for MockLeaf {
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
            Ok(Box::new(self.clone()))
        }

        fn remove(&mut self, index: i32) -> io::Result<()> {
            self.keys.remove(index as usize);
            self.records.remove(index as usize);
            Ok(())
        }

        fn has_next_leaf(&self) -> io::Result<bool> {
            Ok(self.next.is_some())
        }

        fn get_next_leaf(&self) -> io::Result<Option<Box<dyn FieldKeyRecordNode>>> {
            Ok(self.next.clone().map(|n| Box::new(*n) as Box<dyn FieldKeyRecordNode>))
        }

        fn has_previous_leaf(&self) -> io::Result<bool> {
            Ok(self.prev.is_some())
        }

        fn get_previous_leaf(&self) -> io::Result<Option<Box<dyn FieldKeyRecordNode>>> {
            Ok(self.prev.clone().map(|n| Box::new(*n) as Box<dyn FieldKeyRecordNode>))
        }

        fn remove_leaf(&mut self) -> io::Result<Box<dyn FieldKeyNode>> {
            Ok(Box::new(self.clone()))
        }

        fn delete_record(
            &mut self,
            key: &Field,
            _table: &mut Table,
        ) -> io::Result<Box<dyn FieldKeyNode>> {
            self.keys.retain(|k| k != key);
            Ok(Box::new(self.clone()))
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

    impl FixedKeyRecordNode for MockLeaf {
        fn get_key_field(&self, index: i32) -> Field {
            self.keys[index as usize].clone()
        }

        fn get_fixed_parent(&self) -> Option<Box<dyn FixedKeyInteriorNodeLike>> {
            self.parent.clone().map(|p| Box::new(p) as Box<dyn FixedKeyInteriorNodeLike>)
        }

        fn split(&mut self) -> io::Result<Box<dyn FixedKeyNode>> {
            Err(io::Error::new(io::ErrorKind::Other, "not supported in mock"))
        }

        fn append_leaf(
            &mut self,
            _leaf: Box<dyn FixedKeyRecordNode>,
        ) -> io::Result<Box<dyn FixedKeyNode>> {
            Err(io::Error::new(io::ErrorKind::Other, "not supported in mock"))
        }

        fn split_data(&mut self, new_right_leaf: &mut dyn FixedKeyRecordNode) {
            let split = self.keys.len() / 2;
            self.keys.truncate(split);
            let right_records = self.records.split_off(split);
            for r in right_records {
                let idx = new_right_leaf.get_key_count();
                new_right_leaf.insert_record(idx, &r).ok();
            }
        }

        fn create_new_leaf(
            &self,
            _prev_node_id: i32,
            _next_node_id: i32,
        ) -> io::Result<Box<dyn FixedKeyRecordNode>> {
            Ok(Box::new(MockLeaf {
                buffer_id: self.buffer_id + 1000,
                keys: vec![],
                records: vec![],
                parent: None,
                next: None,
                prev: None,
            }))
        }

        fn insert_record(&mut self, index: i32, record: &DBRecord) -> io::Result<bool> {
            self.keys.insert(index as usize, record.get_key().clone());
            self.records.insert(index as usize, record.clone());
            Ok(true)
        }

        fn update_record(&mut self, index: i32, record: &DBRecord) -> io::Result<Box<dyn FixedKeyNode>> {
            self.records[index as usize] = record.clone();
            Ok(Box::new(MockInteriorNode {
                buffer_id: self.buffer_id,
                leftmost_key: self.keys[0].clone(),
                rightmost_key: self.keys[0].clone(),
            }))
        }
    }

    fn schema() -> Arc<Schema> {
        Arc::new(Schema::new(
            1,
            FieldType::Long,
            "ID".to_string(),
            vec![],
            vec![],
            vec![],
        ))
    }

    #[test]
    fn test_fixed_key_record_node_is_object_safe() {
        let schema = schema();

        let leaf1_stub = MockLeaf {
            buffer_id: 1,
            keys: vec![Field::Long(Some(10))],
            records: vec![DBRecord::new(schema.clone(), Field::Long(Some(10)))],
            parent: None,
            next: None,
            prev: None,
        };

        let leaf2 = MockLeaf {
            buffer_id: 2,
            keys: vec![Field::Long(Some(30)), Field::Long(Some(40))],
            records: vec![
                DBRecord::new(schema.clone(), Field::Long(Some(30))),
                DBRecord::new(schema.clone(), Field::Long(Some(40))),
            ],
            parent: Some(MockInteriorNode {
                buffer_id: 99,
                leftmost_key: Field::Long(Some(10)),
                rightmost_key: Field::Long(Some(30)),
            }),
            next: None,
            prev: Some(Box::new(leaf1_stub)),
        };

        let leaf1 = MockLeaf {
            buffer_id: 1,
            keys: vec![Field::Long(Some(10)), Field::Long(Some(20))],
            records: vec![
                DBRecord::new(schema.clone(), Field::Long(Some(10))),
                DBRecord::new(schema.clone(), Field::Long(Some(20))),
            ],
            parent: Some(MockInteriorNode {
                buffer_id: 99,
                leftmost_key: Field::Long(Some(10)),
                rightmost_key: Field::Long(Some(30)),
            }),
            next: Some(Box::new(leaf2.clone())),
            prev: None,
        };

        // Real binary-search behavior via the default `get_key_index` method.
        assert_eq!(leaf1.get_key_index(&Field::Long(Some(20))), 1);
        assert_eq!(leaf1.get_key_index(&Field::Long(Some(15))), -2);

        // A well-linked leaf reports itself consistent.
        let monitor = DummyMonitor;
        assert!(leaf1.is_consistent("MyTable", &monitor).unwrap());

        // An out-of-order leaf is reported inconsistent.
        let broken = MockLeaf {
            buffer_id: 3,
            keys: vec![Field::Long(Some(20)), Field::Long(Some(10))],
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
        let boxed: Box<dyn FixedKeyRecordNode> = Box::new(leaf1.clone());
        assert_eq!(boxed.get_buffer_id(), 1);
        assert_eq!(boxed.get_key_count(), 2);

        // Exercise real split_data behavior (delegates to insert_record on the object-safe
        // interface) and append_new_leaf's dependencies (create_new_leaf/insert_record/
        // append_leaf), all reached through the trait.
        let mut left = leaf2.clone();
        let mut right = MockLeaf {
            buffer_id: 4,
            keys: vec![],
            records: vec![],
            parent: None,
            next: None,
            prev: None,
        };
        FixedKeyRecordNode::split_data(&mut left, &mut right);
        assert_eq!(left.get_key_count(), 1);
        assert_eq!(right.get_key_count(), 1);
        assert_eq!(right.records[0].get_key(), &Field::Long(Some(40)));

        let mut dbh = DBHandle::new().unwrap();
        let table = dbh.create_table("MyTable".to_string(), schema.clone()).unwrap();
        let mut mutable_leaf = leaf1.clone();
        {
            let mut t = table.write().unwrap();
            let rec = DBRecord::new(schema.clone(), Field::Long(Some(99)));
            let root = mutable_leaf.put_record(rec, &mut t).unwrap();
            assert_eq!(root.get_key_count(), 3);
        }
        assert_eq!(mutable_leaf.get_key_count(), 3);

        let root = mutable_leaf.update_record(0, &mutable_leaf.records[0].clone()).unwrap();
        assert_eq!(root.get_buffer_id(), 1);
    }
}

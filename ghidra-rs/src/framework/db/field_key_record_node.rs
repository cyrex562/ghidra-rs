use std::io;

use super::field::Field;
use super::field_key_node::FieldKeyNode;
use super::record::DBRecord;
use super::record_node::RecordNode;
use super::schema::Schema;
use super::table::Table;

/// Common interface for `FieldKeyNode` implementations which are also a `RecordNode` (i.e., leaf
/// node).
///
/// Mirrors `db.FieldKeyRecordNode`, which extends both `RecordNode` and `FieldKeyNode`.
pub trait FieldKeyRecordNode: RecordNode + FieldKeyNode {
    /// Get the record located at the specified index.
    fn get_record_at_index(&self, schema: &Schema, index: i32) -> io::Result<DBRecord>;

    /// Insert or update a record. `table` is notified when the record is inserted or updated.
    /// Returns the root node, which may have changed.
    fn put_record(
        &mut self,
        record: DBRecord,
        table: &mut Table,
    ) -> io::Result<Box<dyn FieldKeyNode>>;

    /// Remove the record identified by index. This will never be the last record within the
    /// node.
    fn remove(&mut self, index: i32) -> io::Result<()>;

    /// Determine if this record node has a right sibling.
    fn has_next_leaf(&self) -> io::Result<bool>;

    /// Get this leaf node's right sibling, or `None` if it does not exist.
    fn get_next_leaf(&self) -> io::Result<Option<Box<dyn FieldKeyRecordNode>>>;

    /// Determine if this record node has a left sibling.
    fn has_previous_leaf(&self) -> io::Result<bool>;

    /// Get this leaf node's left sibling, or `None` if it does not exist.
    fn get_previous_leaf(&self) -> io::Result<Option<Box<dyn FieldKeyRecordNode>>>;

    /// Remove this leaf from the tree. Returns the root node, which may have changed.
    fn remove_leaf(&mut self) -> io::Result<Box<dyn FieldKeyNode>>;

    /// Delete the record identified by the specified key. `table` is notified when the record is
    /// deleted. Returns the root node, which may have changed.
    fn delete_record(
        &mut self,
        key: &Field,
        table: &mut Table,
    ) -> io::Result<Box<dyn FieldKeyNode>>;

    /// Get the record with the minimum key value which is greater than or equal to the specified
    /// key, or `None` if not found.
    fn get_record_at_or_after(&self, key: &Field, schema: &Schema) -> io::Result<Option<DBRecord>>;

    /// Get the record with the maximum key value which is less than or equal to the specified
    /// key, or `None` if not found.
    fn get_record_at_or_before(
        &self,
        key: &Field,
        schema: &Schema,
    ) -> io::Result<Option<DBRecord>>;

    /// Get the record with the minimum key value which is greater than the specified key, or
    /// `None` if not found.
    fn get_record_after(&self, key: &Field, schema: &Schema) -> io::Result<Option<DBRecord>>;

    /// Get the record with the maximum key value which is less than the specified key, or `None`
    /// if not found.
    fn get_record_before(&self, key: &Field, schema: &Schema) -> io::Result<Option<DBRecord>>;

    /// Get the record identified by the specified key, or `None` if not found.
    fn get_record(&self, key: &Field, schema: &Schema) -> io::Result<Option<DBRecord>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::nodes::BTreeNode;
    use crate::framework::db::{DBHandle, FieldType};
    use std::sync::Arc;

    struct MockFieldKeyRecordNode {
        buffer_id: i32,
        key_count: i32,
        records: Vec<DBRecord>,
    }

    impl BTreeNode for MockFieldKeyRecordNode {
        fn get_buffer_id(&self) -> i32 {
            self.buffer_id
        }

        fn get_key_count(&self) -> i32 {
            self.key_count
        }

        fn set_key_count(&mut self, count: i32) {
            self.key_count = count;
        }
    }

    impl RecordNode for MockFieldKeyRecordNode {
        fn get_record_offset(&self, index: i32) -> io::Result<i32> {
            Ok(index)
        }

        fn get_key_offset(&self, index: i32) -> io::Result<i32> {
            Ok(index)
        }
    }

    impl FieldKeyNode for MockFieldKeyRecordNode {
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

        fn compare_key_field(&self, k: &Field, key_index: i32) -> i32 {
            match self.records[key_index as usize].get_key().get_long_value().cmp(&k.get_long_value())
            {
                std::cmp::Ordering::Less => 1,
                std::cmp::Ordering::Greater => -1,
                std::cmp::Ordering::Equal => 0,
            }
        }
    }

    impl FieldKeyRecordNode for MockFieldKeyRecordNode {
        fn get_record_at_index(&self, _schema: &Schema, index: i32) -> io::Result<DBRecord> {
            Ok(self.records[index as usize].clone())
        }

        fn put_record(
            &mut self,
            record: DBRecord,
            _table: &mut Table,
        ) -> io::Result<Box<dyn FieldKeyNode>> {
            self.records.push(record);
            self.key_count = self.records.len() as i32;
            Err(io::Error::new(io::ErrorKind::Other, "no root available in mock"))
        }

        fn remove(&mut self, index: i32) -> io::Result<()> {
            self.records.remove(index as usize);
            self.key_count = self.records.len() as i32;
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
            Err(io::Error::new(io::ErrorKind::Other, "no root available in mock"))
        }

        fn delete_record(
            &mut self,
            key: &Field,
            _table: &mut Table,
        ) -> io::Result<Box<dyn FieldKeyNode>> {
            self.records.retain(|r| r.get_key() != key);
            self.key_count = self.records.len() as i32;
            Err(io::Error::new(io::ErrorKind::Other, "no root available in mock"))
        }

        fn get_record_at_or_after(
            &self,
            key: &Field,
            _schema: &Schema,
        ) -> io::Result<Option<DBRecord>> {
            Ok(self
                .records
                .iter()
                .find(|r| r.get_key() >= key)
                .cloned())
        }

        fn get_record_at_or_before(
            &self,
            key: &Field,
            _schema: &Schema,
        ) -> io::Result<Option<DBRecord>> {
            Ok(self
                .records
                .iter()
                .rev()
                .find(|r| r.get_key() <= key)
                .cloned())
        }

        fn get_record_after(&self, key: &Field, _schema: &Schema) -> io::Result<Option<DBRecord>> {
            Ok(self.records.iter().find(|r| r.get_key() > key).cloned())
        }

        fn get_record_before(
            &self,
            key: &Field,
            _schema: &Schema,
        ) -> io::Result<Option<DBRecord>> {
            Ok(self
                .records
                .iter()
                .rev()
                .find(|r| r.get_key() < key)
                .cloned())
        }

        fn get_record(&self, key: &Field, _schema: &Schema) -> io::Result<Option<DBRecord>> {
            Ok(self.records.iter().find(|r| r.get_key() == key).cloned())
        }
    }

    #[test]
    fn test_field_key_record_node_is_object_safe() {
        let mut dbh = DBHandle::new().unwrap();
        let schema = Arc::new(Schema::new(
            1,
            FieldType::Long,
            "ID".to_string(),
            vec![],
            vec![],
            vec![],
        ));
        let table = dbh.create_table("MyTable".to_string(), schema.clone()).unwrap();

        let mut node = MockFieldKeyRecordNode { buffer_id: 1, key_count: 0, records: vec![] };
        let rec1 = DBRecord::new(schema.clone(), Field::Long(Some(1)));
        let rec2 = DBRecord::new(schema.clone(), Field::Long(Some(2)));

        {
            let mut t = table.write().unwrap();
            assert!(node.put_record(rec1.clone(), &mut t).is_err());
            assert!(node.put_record(rec2.clone(), &mut t).is_err());
        }

        let boxed: Box<dyn FieldKeyRecordNode> = Box::new(node);
        assert_eq!(boxed.get_buffer_id(), 1);
        assert_eq!(boxed.get_key_count(), 2);
        assert_eq!(
            boxed.get_record_at_index(&schema, 0).unwrap().get_key(),
            &Field::Long(Some(1))
        );
        assert!(boxed.has_next_leaf().unwrap() == false);
        assert!(boxed.get_next_leaf().unwrap().is_none());
        assert_eq!(
            boxed
                .get_record(&Field::Long(Some(2)), &schema)
                .unwrap()
                .unwrap()
                .get_key(),
            &Field::Long(Some(2))
        );
        assert!(
            boxed
                .get_record_at_or_after(&Field::Long(Some(2)), &schema)
                .unwrap()
                .is_some()
        );
    }
}

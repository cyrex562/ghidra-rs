use std::io;

use super::field::Field;
use super::field_key_node::FieldKeyNode;
use crate::util::task::TaskMonitor;

/// An abstract implementation of a BTree node which utilizes variable-length `Field` key values.
///
/// Mirrors `db.VarKeyNode`, which implements `FieldKeyNode`. Low-level buffer layout methods
/// (key offset bookkeeping) are implementation details of the concrete buffer-backed struct and
/// are not part of this trait; only the surface callers cross the package boundary with is
/// exposed here: `getKeyField` (narrows `BTreeNode.getKeyField`), `getRoot` (tree-navigation,
/// mirrored after the analogous [`LongKeyNode`](crate::framework::seam_stubs::LongKeyNode)
/// placeholder), and `isConsistent` (from `BTreeNode`, not otherwise modeled anywhere in this
/// trait hierarchy, needed here since `VarKeyInteriorNode`'s consistency walk recurses into
/// either an interior or leaf child through this trait object). `getLeafNode` /
/// `getLeftmostLeafNode` / `getRightmostLeafNode` are declared abstract in Java with a narrowed
/// `VarKeyRecordNode` return type, but every real cross-package caller (`Table`) only ever
/// consumes them at the `FieldKeyRecordNode` level, so the inherited `FieldKeyNode` signatures
/// are reused as-is rather than redeclared here.
pub trait VarKeyNode: FieldKeyNode {
    /// Get the key value at a specific index.
    fn get_key_field(&self, index: i32) -> io::Result<Field>;

    /// Get the root for this node's tree. If no parent has been set, this node is assumed to be
    /// the root.
    fn get_root(&self) -> Box<dyn VarKeyNode>;

    /// Check the consistency of this node and all of its children.
    fn is_consistent(&self, table_name: &str, monitor: &dyn TaskMonitor) -> io::Result<bool>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::field_key_interior_node::FieldKeyInteriorNode;
    use crate::framework::db::field_key_record_node::FieldKeyRecordNode;
    use crate::framework::db::nodes::BTreeNode;
    use crate::util::task::DummyMonitor;

    #[derive(Clone)]
    struct MockRoot {
        buffer_id: i32,
        key: Field,
    }

    impl BTreeNode for MockRoot {
        fn get_buffer_id(&self) -> i32 {
            self.buffer_id
        }
        fn get_key_count(&self) -> i32 {
            1
        }
        fn set_key_count(&mut self, _count: i32) {}
    }

    impl FieldKeyNode for MockRoot {
        fn get_parent(&self) -> Option<Box<dyn FieldKeyInteriorNode>> {
            None
        }
        fn get_leaf_node(&self, _key: &Field) -> io::Result<Box<dyn FieldKeyRecordNode>> {
            Err(io::Error::new(io::ErrorKind::Other, "not supported in mock"))
        }
        fn get_leftmost_leaf_node(&self) -> io::Result<Box<dyn FieldKeyRecordNode>> {
            Err(io::Error::new(io::ErrorKind::Other, "not supported in mock"))
        }
        fn get_rightmost_leaf_node(&self) -> io::Result<Box<dyn FieldKeyRecordNode>> {
            Err(io::Error::new(io::ErrorKind::Other, "not supported in mock"))
        }
        fn compare_key_field(&self, k: &Field, _key_index: i32) -> i32 {
            match k.cmp(&self.key) {
                std::cmp::Ordering::Less => -1,
                std::cmp::Ordering::Greater => 1,
                std::cmp::Ordering::Equal => 0,
            }
        }
    }

    impl VarKeyNode for MockRoot {
        fn get_key_field(&self, _index: i32) -> io::Result<Field> {
            Ok(self.key.clone())
        }
        fn get_root(&self) -> Box<dyn VarKeyNode> {
            Box::new(self.clone())
        }
        fn is_consistent(&self, _table_name: &str, _monitor: &dyn TaskMonitor) -> io::Result<bool> {
            Ok(true)
        }
    }

    #[test]
    fn test_var_key_node_is_object_safe() {
        let node = MockRoot { buffer_id: 7, key: Field::Long(Some(42)) };

        // Object safety: usable as a boxed trait object.
        let boxed: Box<dyn VarKeyNode> = Box::new(node.clone());
        assert_eq!(boxed.get_buffer_id(), 7);
        assert_eq!(boxed.get_key_field(0).unwrap(), Field::Long(Some(42)));
        assert_eq!(boxed.compare_key_field(&Field::Long(Some(42)), 0), 0);
        assert_eq!(boxed.compare_key_field(&Field::Long(Some(1)), 0), -1);

        // get_root on a node with no parent returns itself.
        let root = boxed.get_root();
        assert_eq!(root.get_buffer_id(), 7);

        let monitor = DummyMonitor;
        assert!(boxed.is_consistent("MyTable", &monitor).unwrap());
    }
}

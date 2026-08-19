use std::io;

use super::field::Field;
use super::field_key_node::FieldKeyNode;
use crate::util::task::TaskMonitor;

/// An abstract implementation of a BTree node which utilizes fixed-length key values.
///
/// Mirrors `db.FixedKeyNode`, which extends [`FieldKeyNode`] -- selected as a dependency-cycle
/// cut-point referenced by both
/// [`FixedKeyInteriorNode`](crate::framework::db::fixed_key_interior_node::FixedKeyInteriorNode)
/// (as its own supertrait and the type of the children it fetches) and
/// [`FixedKeyRecordNode`](crate::framework::db::fixed_key_record_node::FixedKeyRecordNode) /
/// [`FixedKeyVarRecNode`](crate::framework::db::fixed_key_var_rec_node::FixedKeyVarRecNode) (as
/// the opaque "root, which may have changed" return type of their mutating operations). Only the
/// public surface those siblings call across the package boundary is modeled: the final
/// `getKeyField(int)` accessor (mirrored as `get_key_field`) and the `BTreeNode.isConsistent`
/// override (mirrored as `is_consistent`) that each concrete leaf/interior node provides. The
/// constructors, `nodeMgr`/`buffer` fields, `getRoot()`, and the abstract `getKey(int)` raw-byte
/// accessor are node-header/buffer-layout implementation details private to the concrete
/// buffer-backed struct that no already-ported sibling calls across the package boundary, so --
/// consistent with
/// [`FixedKeyInteriorNode`](crate::framework::db::fixed_key_interior_node::FixedKeyInteriorNode)
/// and [`FixedKeyRecordNode`](crate::framework::db::fixed_key_record_node::FixedKeyRecordNode)'s
/// own omission of `FixedKeyNode`'s low-level members -- they are left out of this trait.
pub trait FixedKeyNode: FieldKeyNode {
    /// Get the Field-wrapped key value at a specific index, mirroring the final
    /// `FixedKeyNode.getKeyField(int)` method.
    fn get_key_field(&self, index: i32) -> Field;

    /// Check the consistency of this node and all of its children, mirroring
    /// `BTreeNode.isConsistent(String, TaskMonitor)`.
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
    struct MockFixedKeyNode {
        buffer_id: i32,
        key: Field,
    }

    impl BTreeNode for MockFixedKeyNode {
        fn get_buffer_id(&self) -> i32 {
            self.buffer_id
        }

        fn get_key_count(&self) -> i32 {
            1
        }

        fn set_key_count(&mut self, _count: i32) {}
    }

    impl FieldKeyNode for MockFixedKeyNode {
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

        fn compare_key_field(&self, k: &Field, _key_index: i32) -> i32 {
            match k.cmp(&self.key) {
                std::cmp::Ordering::Less => -1,
                std::cmp::Ordering::Greater => 1,
                std::cmp::Ordering::Equal => 0,
            }
        }
    }

    impl FixedKeyNode for MockFixedKeyNode {
        fn get_key_field(&self, _index: i32) -> Field {
            self.key.clone()
        }

        fn is_consistent(&self, _table_name: &str, _monitor: &dyn TaskMonitor) -> io::Result<bool> {
            Ok(true)
        }
    }

    #[test]
    fn test_fixed_key_node_is_object_safe() {
        let node = MockFixedKeyNode { buffer_id: 7, key: Field::Long(Some(42)) };
        let monitor = DummyMonitor;

        // Real binary-comparison behavior via `compare_key_field`, exercised through a boxed
        // trait object to prove object-safety.
        let boxed: Box<dyn FixedKeyNode> = Box::new(node.clone());
        assert_eq!(boxed.get_buffer_id(), 7);
        assert_eq!(boxed.get_key_count(), 1);
        assert!(boxed.get_parent().is_none());
        assert_eq!(boxed.get_key_field(0), Field::Long(Some(42)));
        assert_eq!(boxed.compare_key_field(&Field::Long(Some(42)), 0), 0);
        assert_eq!(boxed.compare_key_field(&Field::Long(Some(1)), 0), -1);
        assert_eq!(boxed.compare_key_field(&Field::Long(Some(100)), 0), 1);
        assert!(boxed.is_consistent("MyTable", &monitor).unwrap());
        assert!(boxed.get_leaf_node(&Field::Long(Some(42))).is_err());
    }
}

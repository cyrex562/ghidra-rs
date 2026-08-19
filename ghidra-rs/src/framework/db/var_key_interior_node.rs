use std::io;

use super::field::Field;
use super::field_key_interior_node::FieldKeyInteriorNode;
use super::nodes::BTreeNode;
use super::var_key_node::VarKeyNode;
use crate::util::msg::Msg;
use crate::util::task::TaskMonitor;

/// Stores a BTree node for use as an interior node when searching for Table records within the
/// database, keyed by variable-length `Field` values.
///
/// Mirrors `db.VarKeyInteriorNode`, which extends `VarKeyNode` and implements
/// `FieldKeyInteriorNode`. Low-level buffer layout methods (offset/entry bookkeeping, node
/// splitting/balancing) are implementation details of the concrete buffer-backed struct and are
/// not part of this trait; only the surface other node types call across the package boundary
/// (`insert`, `deleteChild`, `isLeftmostKey`, `isRightmostKey`, plus the `BTreeNode`-contract
/// overrides `delete` and `getBufferReferences`) is exposed here.
pub trait VarKeyInteriorNode: FieldKeyInteriorNode + VarKeyNode {
    /// Get the child node buffer ID associated with the specified key index.
    fn get_child_buffer_id(&self, index: i32) -> i32;

    /// Fetch the child node associated with the specified key index.
    fn get_child(&self, index: i32) -> io::Result<Box<dyn VarKeyNode>>;

    /// Insert new child node (key and buffer ID are taken from `node`'s own leftmost key and
    /// buffer ID). Returns the root node, which may have changed.
    fn insert(&mut self, node: Box<dyn VarKeyNode>) -> io::Result<Box<dyn VarKeyNode>>;

    /// Callback method allowing a child node to remove itself from this parent. Rebalancing of
    /// the tree is performed if the interior node falls below the half-full point. Returns the
    /// root node.
    fn delete_child(&mut self, key: &Field) -> io::Result<Box<dyn VarKeyNode>>;

    /// Delete this node and all child nodes.
    fn delete(&mut self) -> io::Result<()>;

    /// Determine if the specified key corresponds to the leftmost key within the tree.
    fn is_leftmost_key(&self, key: &Field) -> io::Result<bool>;

    /// Determine if the specified key corresponds to the rightmost key within the tree.
    fn is_rightmost_key(&self, key: &Field) -> io::Result<bool>;

    /// Perform a binary search to locate the specified key and derive an index into the child
    /// buffer ID storage. Intended to locate the child node which contains the specified key.
    /// An existing positive index value is always returned.
    fn get_id_index(&self, key: &Field) -> i32 {
        let mut min = 1;
        let mut max = self.get_key_count() - 1;
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
        max
    }

    /// Perform a binary search to locate the specified key.
    ///
    /// Returns the key index if found, else `-(key_index + 1)` indicating the insertion point.
    fn get_key_index(&self, key: &Field) -> i32 {
        let mut min = 0;
        let mut max = self.get_key_count() - 1;
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

    /// Return all buffer IDs for those buffers which are direct children of this node.
    fn get_buffer_references(&self) -> Vec<i32> {
        (0..self.get_key_count())
            .map(|i| self.get_child_buffer_id(i))
            .collect()
    }

    /// Log a BTree consistency error for the named table via [`Msg`].
    fn log_consistency_error(&self, table_name: &str, msg: &str, cause: Option<&dyn std::error::Error>) {
        Msg::debug(
            "VarKeyInteriorNode",
            &format!("Consistency Error ({}): {}", table_name, msg),
        );
        if let Some(err) = cause {
            Msg::error_with_error(
                "VarKeyInteriorNode",
                &format!("Consistency Error ({})", table_name),
                err,
            );
        }
    }
}

/// Check the consistency of an interior node and all of its children.
///
/// Mirrors `VarKeyInteriorNode.isConsistent`. This is a free function rather than a trait method
/// (or default method) because it recurses through `VarKeyNode::is_consistent`, a distinct
/// supertrait method with the same name; a concrete implementer's own `VarKeyNode::is_consistent`
/// override is expected to call this helper for interior nodes. Node identity (Java's transient
/// `child.parent = this` reassignment, used only to steer the recursive leftmost/rightmost-key
/// checks performed by the child) is not modeled; each child is assumed to already carry a
/// correct parent reference, mirroring the same simplification made for
/// [`LongKeyRecordNode::is_consistent`](crate::framework::db::long_key_record_node::LongKeyRecordNode).
pub fn check_consistency(
    node: &dyn VarKeyInteriorNode,
    table_name: &str,
    monitor: &dyn TaskMonitor,
) -> io::Result<bool> {
    let mut consistent = true;
    let mut last_min_key: Option<Field> = None;
    let mut last_max_key: Option<Field> = None;

    for i in 0..node.get_key_count() {
        let key = node.get_key_field(i)?;

        if let Some(lmk) = &last_min_key {
            if key <= *lmk {
                consistent = false;
                node.log_consistency_error(
                    table_name,
                    &format!("child[{}].minKey <= child[{}].minKey", i, i - 1),
                    None,
                );
            }
        } else if let Some(lmxk) = &last_max_key {
            if key <= *lmxk {
                consistent = false;
                node.log_consistency_error(
                    table_name,
                    &format!("child[{}].minKey <= child[{}].maxKey", i, i - 1),
                    None,
                );
            }
        }

        last_min_key = Some(key.clone());

        let child = match node.get_child(i) {
            Ok(child) => Some(child),
            Err(e) => {
                let msg = format!("failed to fetch child node: {}", e);
                node.log_consistency_error(table_name, &msg, Some(&e as &dyn std::error::Error));
                None
            }
        };

        let child = match child {
            Some(child) => child,
            None => {
                consistent = false;
                last_max_key = Some(key);
                continue;
            }
        };

        last_max_key = Some(child.get_key_field(child.get_key_count() - 1)?);

        let child_key0 = child.get_key_field(0)?;
        if key != child_key0 {
            consistent = false;
            node.log_consistency_error(
                table_name,
                &format!("parent key entry mismatch with child[{}].minKey", i),
                None,
            );
        }

        consistent &= child.is_consistent(table_name, monitor)?;
        monitor
            .check_cancelled()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    }
    monitor
        .check_cancelled()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    Ok(consistent)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::field_key_node::FieldKeyNode;
    use crate::framework::db::field_key_record_node::FieldKeyRecordNode;
    use crate::framework::db::interior_node::InteriorNode;
    use crate::util::task::DummyMonitor;

    #[derive(Clone)]
    struct MockLeaf {
        buffer_id: i32,
        key: Field,
    }

    impl BTreeNode for MockLeaf {
        fn get_buffer_id(&self) -> i32 {
            self.buffer_id
        }
        fn get_key_count(&self) -> i32 {
            1
        }
        fn set_key_count(&mut self, _count: i32) {}
    }

    impl FieldKeyNode for MockLeaf {
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

    impl VarKeyNode for MockLeaf {
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

    #[derive(Clone)]
    struct MockInterior {
        buffer_id: i32,
        children: Vec<MockLeaf>,
    }

    impl BTreeNode for MockInterior {
        fn get_buffer_id(&self) -> i32 {
            self.buffer_id
        }
        fn get_key_count(&self) -> i32 {
            self.children.len() as i32
        }
        fn set_key_count(&mut self, _count: i32) {}
    }

    impl InteriorNode for MockInterior {}

    impl FieldKeyNode for MockInterior {
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
        fn compare_key_field(&self, k: &Field, key_index: i32) -> i32 {
            match k.cmp(&self.children[key_index as usize].key) {
                std::cmp::Ordering::Less => -1,
                std::cmp::Ordering::Greater => 1,
                std::cmp::Ordering::Equal => 0,
            }
        }
    }

    impl FieldKeyInteriorNode for MockInterior {
        fn key_changed(
            &mut self,
            _old_key: &Field,
            _new_key: &Field,
            _child_node: Option<&dyn FieldKeyNode>,
        ) -> io::Result<()> {
            Ok(())
        }
    }

    impl VarKeyNode for MockInterior {
        fn get_key_field(&self, index: i32) -> io::Result<Field> {
            Ok(self.children[index as usize].key.clone())
        }
        fn get_root(&self) -> Box<dyn VarKeyNode> {
            Box::new(self.clone())
        }
        fn is_consistent(&self, table_name: &str, monitor: &dyn TaskMonitor) -> io::Result<bool> {
            check_consistency(self, table_name, monitor)
        }
    }

    impl VarKeyInteriorNode for MockInterior {
        fn get_child_buffer_id(&self, index: i32) -> i32 {
            self.children[index as usize].buffer_id
        }
        fn get_child(&self, index: i32) -> io::Result<Box<dyn VarKeyNode>> {
            Ok(Box::new(self.children[index as usize].clone()))
        }
        fn insert(&mut self, _node: Box<dyn VarKeyNode>) -> io::Result<Box<dyn VarKeyNode>> {
            Err(io::Error::new(io::ErrorKind::Other, "not supported in mock"))
        }
        fn delete_child(&mut self, _key: &Field) -> io::Result<Box<dyn VarKeyNode>> {
            Err(io::Error::new(io::ErrorKind::Other, "not supported in mock"))
        }
        fn delete(&mut self) -> io::Result<()> {
            self.children.clear();
            Ok(())
        }
        fn is_leftmost_key(&self, key: &Field) -> io::Result<bool> {
            Ok(self.get_id_index(key) == 0)
        }
        fn is_rightmost_key(&self, key: &Field) -> io::Result<bool> {
            Ok(self.get_id_index(key) == self.get_key_count() - 1)
        }
    }

    fn make_node() -> MockInterior {
        MockInterior {
            buffer_id: 1,
            children: vec![
                MockLeaf { buffer_id: 10, key: Field::Long(Some(0)) },
                MockLeaf { buffer_id: 11, key: Field::Long(Some(10)) },
                MockLeaf { buffer_id: 12, key: Field::Long(Some(20)) },
            ],
        }
    }

    #[test]
    fn test_var_key_interior_node_is_object_safe() {
        let node = make_node();

        // Real binary-search behavior via the default `get_key_index`/`get_id_index` methods.
        assert_eq!(node.get_key_index(&Field::Long(Some(10))), 1);
        assert_eq!(node.get_key_index(&Field::Long(Some(5))), -2);
        assert_eq!(node.get_id_index(&Field::Long(Some(15))), 1);

        assert!(node.is_leftmost_key(&Field::Long(Some(0))).unwrap());
        assert!(!node.is_leftmost_key(&Field::Long(Some(10))).unwrap());
        assert!(node.is_rightmost_key(&Field::Long(Some(20))).unwrap());

        assert_eq!(node.get_buffer_references(), vec![10, 11, 12]);

        // Real consistency-check behavior, including recursion into children.
        let monitor = DummyMonitor;
        assert!(check_consistency(&node, "MyTable", &monitor).unwrap());

        // An out-of-order child set is reported inconsistent.
        let mut broken = make_node();
        broken.children[1].key = Field::Long(Some(-5));
        assert!(!check_consistency(&broken, "MyTable", &monitor).unwrap());

        // Object safety: usable as a boxed trait object.
        let mut boxed: Box<dyn VarKeyInteriorNode> = Box::new(make_node());
        assert_eq!(boxed.get_buffer_id(), 1);
        assert_eq!(boxed.get_key_count(), 3);
        boxed.delete().unwrap();
        assert_eq!(boxed.get_key_count(), 0);
    }
}

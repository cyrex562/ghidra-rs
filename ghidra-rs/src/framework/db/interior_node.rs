use super::nodes::BTreeNode;

/// Marker trait for `Table` interior nodes within the BTree structure.
///
/// Mirrors `db.InteriorNode`, a marker interface in the original Java that extends `BTreeNode`
/// without adding any members of its own.
pub trait InteriorNode: BTreeNode {}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockInteriorNode {
        buffer_id: i32,
        key_count: i32,
    }

    impl BTreeNode for MockInteriorNode {
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

    impl InteriorNode for MockInteriorNode {}

    #[test]
    fn test_interior_node_is_object_safe() {
        let mut node = MockInteriorNode { buffer_id: 1, key_count: 0 };
        node.set_key_count(5);

        let boxed: Box<dyn InteriorNode> = Box::new(node);
        assert_eq!(boxed.get_buffer_id(), 1);
        assert_eq!(boxed.get_key_count(), 5);
    }
}

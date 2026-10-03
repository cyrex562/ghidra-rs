use super::nodes::BTreeNode;

/// `Table` record leaf nodes within the BTree structure.
///
/// Mirrors `db.RecordNode`, which extends `BTreeNode`.
pub trait RecordNode: BTreeNode {
    /// Get the record offset within the node's data buffer.
    ///
    /// Returns a positive record offset within the buffer, or a negative
    /// bufferID for indirect record storage in a dedicated buffer.
    fn get_record_offset(&self, index: i32) -> std::io::Result<i32>;

    /// Get the key offset within the node's data buffer.
    ///
    /// Returns a positive record offset within the buffer.
    fn get_key_offset(&self, index: i32) -> std::io::Result<i32>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockRecordNode {
        buffer_id: i32,
        key_count: i32,
    }

    impl BTreeNode for MockRecordNode {
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

    impl RecordNode for MockRecordNode {
        fn get_record_offset(&self, index: i32) -> std::io::Result<i32> {
            Ok(100 + index)
        }

        fn get_key_offset(&self, index: i32) -> std::io::Result<i32> {
            Ok(10 + index)
        }
    }

    #[test]
    fn test_record_node_is_object_safe() {
        let mut node = MockRecordNode { buffer_id: 1, key_count: 0 };
        node.set_key_count(3);

        let boxed: Box<dyn RecordNode> = Box::new(node);
        assert_eq!(boxed.get_buffer_id(), 1);
        assert_eq!(boxed.get_key_count(), 3);
        assert_eq!(boxed.get_record_offset(2).unwrap(), 102);
        assert_eq!(boxed.get_key_offset(2).unwrap(), 12);
    }
}

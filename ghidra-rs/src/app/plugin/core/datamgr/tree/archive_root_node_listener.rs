use crate::app::seam_stubs::ArchiveNode;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;

/// A listener for archive root node lifecycle events.
///
/// Receives notifications when nodes are added to or removed from the archive root.
pub trait ArchiveRootNodeListener: Send + Sync {
    /// Called when a node has been added to the root node
    fn archive_node_added(&self, node: &dyn ArchiveNode);

    /// Called when a node is about to be removed from the root node
    fn archive_node_removed(&self, node: &dyn ArchiveNode);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockArchiveNode {
        name: String,
    }

    impl ArchiveNode for MockArchiveNode {
        fn dispose(&self) {}
        fn get_icon(&self, _expanded: bool) -> Box<dyn crate::generic::seam_stubs::Icon> {
            unimplemented!()
        }
        fn get_name(&self) -> String {
            self.name.clone()
        }
        fn get_tool_tip(&self) -> String {
            String::new()
        }
        fn is_leaf(&self) -> bool {
            false
        }
        fn is_editable(&self) -> bool {
            false
        }
        fn get_archive(&self) -> Box<dyn crate::app::seam_stubs::Archive> {
            unimplemented!()
        }
        fn structure_changed(&self) {}
        fn node_changed(&self) {}
        fn can_cut(&self) -> bool {
            false
        }
        fn is_cut(&self) -> bool {
            false
        }
        fn equals(&self, o: &dyn std::any::Any) -> bool {
            if let Some(other) = o.downcast_ref::<MockArchiveNode>() {
                self.name == other.name
            } else {
                false
            }
        }
        fn compare_to(&self, _node: &dyn crate::app::seam_stubs::GTreeNode) -> i32 {
            0
        }
        fn hash_code(&self) -> i32 {
            self.name.len() as i32
        }
        fn get_archive_node(&self) -> Box<dyn ArchiveNode> {
            Box::new(MockArchiveNode { name: self.name.clone() })
        }
        fn is_modifiable(&self) -> bool {
            false
        }
        fn find_category_node(
            &self,
            _local_category: &dyn crate::app::seam_stubs::Category,
        ) -> Box<dyn crate::app::seam_stubs::CategoryNode> {
            unimplemented!()
        }
        fn category_added(
            &self,
            _dtm: &dyn crate::app::seam_stubs::DataTypeManager,
            _path: &dyn crate::app::seam_stubs::CategoryPath,
        ) {
        }
        fn category_moved(
            &self,
            _dtm: &dyn crate::app::seam_stubs::DataTypeManager,
            _old_path: &dyn crate::app::seam_stubs::CategoryPath,
            _new_path: &dyn crate::app::seam_stubs::CategoryPath,
        ) {
        }
        fn category_removed(
            &self,
            _dtm: &dyn crate::app::seam_stubs::DataTypeManager,
            _path: &dyn crate::app::seam_stubs::CategoryPath,
        ) {
        }
        fn category_renamed(
            &self,
            _dtm: &dyn crate::app::seam_stubs::DataTypeManager,
            _old_path: &dyn crate::app::seam_stubs::CategoryPath,
            _new_path: &dyn crate::app::seam_stubs::CategoryPath,
        ) {
        }
        fn data_type_added(
            &self,
            _dtm: &dyn crate::app::seam_stubs::DataTypeManager,
            _path: &dyn crate::app::seam_stubs::DataTypePath,
        ) {
        }
        fn favorites_changed(
            &self,
            _dtm: &dyn crate::app::seam_stubs::DataTypeManager,
            _path: &dyn crate::app::seam_stubs::DataTypePath,
            _is_favorite: bool,
        ) {
        }
        fn data_type_changed(
            &self,
            _dtm: &dyn crate::app::seam_stubs::DataTypeManager,
            _path: &dyn crate::app::seam_stubs::DataTypePath,
        ) {
        }
        fn data_type_moved(
            &self,
            _dtm: &dyn crate::app::seam_stubs::DataTypeManager,
            _old_path: &dyn crate::app::seam_stubs::DataTypePath,
            _new_path: &dyn crate::app::seam_stubs::DataTypePath,
        ) {
        }
        fn data_type_removed(
            &self,
            _dtm: &dyn crate::app::seam_stubs::DataTypeManager,
            _path: &dyn crate::app::seam_stubs::DataTypePath,
        ) {
        }
        fn data_type_renamed(
            &self,
            _dtm: &dyn crate::app::seam_stubs::DataTypeManager,
            _old_path: &dyn crate::app::seam_stubs::DataTypePath,
            _new_path: &dyn crate::app::seam_stubs::DataTypePath,
        ) {
        }
        fn data_type_replaced(
            &self,
            _dtm: &dyn crate::app::seam_stubs::DataTypeManager,
            _old_path: &dyn crate::app::seam_stubs::DataTypePath,
            _new_path: &dyn crate::app::seam_stubs::DataTypePath,
            _new_data_type: &dyn crate::program::model::data::data_type::DataType,
        ) {
        }
        fn source_archive_added(
            &self,
            _manager: &dyn crate::app::seam_stubs::DataTypeManager,
            _source_archive: &dyn crate::app::seam_stubs::SourceArchive,
        ) {
        }
        fn source_archive_changed(
            &self,
            _manager: &dyn crate::app::seam_stubs::DataTypeManager,
            _source_archive: &dyn crate::app::seam_stubs::SourceArchive,
        ) {
        }
        fn program_architecture_changed(&self, _manager: &dyn crate::app::seam_stubs::DataTypeManager) {}
        fn restored(&self, _manager: &dyn crate::app::seam_stubs::DataTypeManager) {}
    }

    struct TestListener {
        added_count: AtomicU32,
        removed_count: AtomicU32,
        last_added_name: Mutex<Option<String>>,
        last_removed_name: Mutex<Option<String>>,
    }

    impl ArchiveRootNodeListener for TestListener {
        fn archive_node_added(&self, node: &dyn ArchiveNode) {
            self.added_count.fetch_add(1, Ordering::SeqCst);
            *self.last_added_name.lock().unwrap() = Some(node.get_name());
        }

        fn archive_node_removed(&self, node: &dyn ArchiveNode) {
            self.removed_count.fetch_add(1, Ordering::SeqCst);
            *self.last_removed_name.lock().unwrap() = Some(node.get_name());
        }
    }

    #[test]
    fn test_archive_node_added() {
        let listener = TestListener {
            added_count: AtomicU32::new(0),
            removed_count: AtomicU32::new(0),
            last_added_name: Mutex::new(None),
            last_removed_name: Mutex::new(None),
        };

        let node = MockArchiveNode { name: "test_archive".to_string() };
        listener.archive_node_added(&node);

        assert_eq!(listener.added_count.load(Ordering::SeqCst), 1);
        assert_eq!(listener.removed_count.load(Ordering::SeqCst), 0);
        assert_eq!(*listener.last_added_name.lock().unwrap(), Some("test_archive".to_string()));
    }

    #[test]
    fn test_archive_node_removed() {
        let listener = TestListener {
            added_count: AtomicU32::new(0),
            removed_count: AtomicU32::new(0),
            last_added_name: Mutex::new(None),
            last_removed_name: Mutex::new(None),
        };

        let node = MockArchiveNode { name: "test_archive".to_string() };
        listener.archive_node_removed(&node);

        assert_eq!(listener.added_count.load(Ordering::SeqCst), 0);
        assert_eq!(listener.removed_count.load(Ordering::SeqCst), 1);
        assert_eq!(*listener.last_removed_name.lock().unwrap(), Some("test_archive".to_string()));
    }

    #[test]
    fn test_multiple_node_events() {
        let listener = TestListener {
            added_count: AtomicU32::new(0),
            removed_count: AtomicU32::new(0),
            last_added_name: Mutex::new(None),
            last_removed_name: Mutex::new(None),
        };

        let node1 = MockArchiveNode { name: "archive1".to_string() };
        let node2 = MockArchiveNode { name: "archive2".to_string() };

        listener.archive_node_added(&node1);
        listener.archive_node_added(&node2);
        listener.archive_node_removed(&node1);

        assert_eq!(listener.added_count.load(Ordering::SeqCst), 2);
        assert_eq!(listener.removed_count.load(Ordering::SeqCst), 1);
        assert_eq!(*listener.last_added_name.lock().unwrap(), Some("archive2".to_string()));
        assert_eq!(*listener.last_removed_name.lock().unwrap(), Some("archive1".to_string()));
    }

    #[test]
    fn test_usable_as_trait_object() {
        let listener: Box<dyn ArchiveRootNodeListener> = Box::new(TestListener {
            added_count: AtomicU32::new(0),
            removed_count: AtomicU32::new(0),
            last_added_name: Mutex::new(None),
            last_removed_name: Mutex::new(None),
        });

        let node = MockArchiveNode { name: "archive".to_string() };
        listener.archive_node_added(&node);
        listener.archive_node_removed(&node);
    }
}

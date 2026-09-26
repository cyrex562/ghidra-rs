/// Interface for classes that will handle drop actions for data trees.
pub trait DataTreeFlavorHandler {
    /// Handle a drop action on a data tree.
    ///
    /// # Arguments
    ///
    /// * `tool` - The plugin tool
    /// * `data_tree` - The target data tree
    /// * `destination_node` - The destination tree node
    /// * `transfer_data` - The transfer data from the drag/drop operation
    /// * `drop_action` - The drop action type
    ///
    /// # Returns
    ///
    /// `true` if the drop was handled, `false` otherwise
    fn handle(
        &self,
        tool: &dyn crate::framework::seam_stubs::PluginTool,
        data_tree: &dyn crate::docking::seam_stubs::DataTree,
        destination_node: &dyn crate::docking::seam_stubs::GTreeNode,
        transfer_data: &dyn std::any::Any,
        drop_action: i32,
    ) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    struct TestHandler;

    impl DataTreeFlavorHandler for TestHandler {
        fn handle(
            &self,
            _tool: &dyn crate::framework::seam_stubs::PluginTool,
            _data_tree: &dyn crate::docking::seam_stubs::DataTree,
            _destination_node: &dyn crate::docking::seam_stubs::GTreeNode,
            _transfer_data: &dyn std::any::Any,
            drop_action: i32,
        ) -> bool {
            drop_action == 1
        }
    }

    #[test]
    fn handle_accepts_drop_action_1() {
        let handler = TestHandler;
        assert!(handler.handle(
            &StubTool,
            &StubTree,
            &StubNode,
            &(),
            1
        ));
    }

    #[test]
    fn handle_rejects_other_drop_actions() {
        let handler = TestHandler;
        assert!(!handler.handle(
            &StubTool,
            &StubTree,
            &StubNode,
            &(),
            2
        ));
    }

    #[test]
    fn trait_is_object_safe() {
        let handler = TestHandler;
        let _boxed: Box<dyn DataTreeFlavorHandler> = Box::new(handler);
    }

    struct StubTool;
    impl crate::framework::seam_stubs::PluginTool for StubTool {}

    struct StubTree;
    impl crate::docking::seam_stubs::DataTree for StubTree {
        fn clear_selection(&self) {}

        fn get_selection_count(&self) -> i32 {
            0
        }

        fn get_last_selected_path_component(&self) -> Box<dyn crate::docking::seam_stubs::GTreeNode> {
            Box::new(StubNode)
        }

        fn remove_selection_path(&self, _path: &dyn crate::docking::seam_stubs::TreePath) {}

        fn stop_editing(&self) {}

        fn get_real_internal_folder_for_node(
            &self,
            _node: &dyn crate::docking::seam_stubs::GTreeNode,
        ) -> Box<dyn crate::framework::model::DomainFolder> {
            unimplemented!("stub method")
        }
    }

    struct StubNode;
    impl crate::docking::seam_stubs::GTreeNode for StubNode {
        fn get_display_text(&self) -> String {
            "Test Node".to_string()
        }

        fn get_name(&self) -> String {
            "test_node".to_string()
        }

        fn get_icon(&self, _expanded: bool) -> Box<dyn crate::docking::seam_stubs::Icon> {
            Box::new(StubIcon)
        }

        fn get_tool_tip(&self) -> String {
            String::new()
        }

        fn is_leaf(&self) -> bool {
            true
        }

        fn compare_to(&self, _node: &dyn crate::docking::seam_stubs::GTreeNode) -> i32 {
            0
        }

        fn add_node(&self, _node: &dyn crate::docking::seam_stubs::GTreeNode) {}
        fn add_nodes(&self, _nodes: Vec<Box<dyn crate::docking::seam_stubs::GTreeNode>>) {}

        fn get_children(&self) -> Vec<Box<dyn crate::docking::seam_stubs::GTreeNode>> {
            Vec::new()
        }

        fn get_child_count(&self) -> i32 {
            0
        }

        fn get_child(&self, _name: &str) -> Box<dyn crate::docking::seam_stubs::GTreeNode> {
            Box::new(StubNode)
        }

        fn get_node_count(&self) -> i32 {
            1
        }

        fn get_leaf_count(&self) -> i32 {
            1
        }

        fn get_index_in_parent(&self) -> i32 {
            0
        }

        fn get_index_of_child(&self, _node: &dyn crate::docking::seam_stubs::GTreeNode) -> i32 {
            -1
        }

        fn get_tree_path(&self) -> Box<dyn crate::docking::seam_stubs::TreePath> {
            Box::new(StubTreePath)
        }

        fn remove_all(&self) {}
        fn remove_node(&self, _node: &dyn crate::docking::seam_stubs::GTreeNode) {}
        fn set_children(&self, _child_list: Vec<Box<dyn crate::docking::seam_stubs::GTreeNode>>) {}

        fn is_ancestor(&self, _node: &dyn crate::docking::seam_stubs::GTreeNode) -> bool {
            false
        }

        fn value_changed(&self, _new_value: &dyn std::any::Any) {}
        fn is_editable(&self) -> bool {
            false
        }

        fn get_root(&self) -> Box<dyn crate::docking::seam_stubs::GTreeNode> {
            Box::new(StubNode)
        }

        fn filter(
            &self,
            _filter: &dyn crate::docking::seam_stubs::GTreeFilter,
            _monitor: &dyn crate::docking::seam_stubs::TaskMonitor,
        ) -> std::io::Result<Box<dyn crate::docking::seam_stubs::GTreeNode>> {
            Ok(Box::new(StubNode))
        }

        fn load_all(&self, _monitor: &dyn crate::docking::seam_stubs::TaskMonitor) -> std::io::Result<i32> {
            Ok(0)
        }

        fn hash_code(&self) -> i32 {
            0
        }

        fn equals(&self, _obj: &dyn std::any::Any) -> bool {
            false
        }

        fn stream(&self, _depth_first: bool) -> Box<dyn crate::docking::seam_stubs::Stream> {
            Box::new(StubStream)
        }

        fn iterator(&self, _depth_first: bool) -> Box<dyn crate::docking::seam_stubs::Iterator> {
            Box::new(StubIterator)
        }

        fn to_string(&self) -> String {
            "StubNode".to_string()
        }

        fn fire_node_structure_changed(&self) {}
        fn fire_node_changed(&self) {}
        fn expand(&self) {}

        fn is_auto_expand_permitted(&self) -> bool {
            false
        }

        fn collapse(&self) {}
        fn is_expanded(&self) -> bool {
            false
        }
    }

    struct StubIcon;
    impl crate::docking::seam_stubs::Icon for StubIcon {}

    struct StubTreePath;
    impl crate::docking::seam_stubs::TreePath for StubTreePath {}

    struct StubStream;
    impl crate::docking::seam_stubs::Stream for StubStream {}

    struct StubIterator;
    impl crate::docking::seam_stubs::Iterator for StubIterator {}
}

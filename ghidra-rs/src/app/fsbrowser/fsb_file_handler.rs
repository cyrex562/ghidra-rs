use crate::app::seam_stubs::{DockingAction, FSBFileHandlerContext, FSBFileNode};
use crate::util::classfinder::extension_point::ExtensionPoint;

/// Extension point, used by `FSBComponentProvider` to create actions that appear in the fsb
/// tree, and to delegate focus and default actions.
///
/// Port of `ghidra.plugins.fsbrowser.FSBFileHandler`. Every method but
/// [`init`](Self::init) has a Java `default` body, so every other method here has a default too.
pub trait FSBFileHandler: ExtensionPoint {
    /// Called once after creation of each instance to provide useful info.
    ///
    /// `context` carries references to useful objects and services.
    fn init(&self, context: &FSBFileHandlerContext);

    /// Returns a list of [`DockingAction`]s that should be added to the `FSBComponentProvider`
    /// tree as local actions.
    fn create_actions(&self) -> Vec<DockingAction> {
        Vec::new()
    }

    /// Called when a file node is focused in the `FSBComponentProvider` tree.
    ///
    /// Returns `true` if action was taken.
    fn file_focused(&self, file_node: &FSBFileNode) -> bool {
        let _ = file_node;
        false
    }

    /// Called when a file node is the target of a 'default action' initiated by the user, such
    /// as a double click, etc.
    ///
    /// Returns `true` if action was taken, `false` if no action was taken.
    fn file_default_action(&self, file_node: &FSBFileNode) -> bool {
        let _ = file_node;
        false
    }

    /// Returns a list of [`DockingAction`]s that should be added to a popup menu. Called each
    /// time a fsb browser tree popup menu is created.
    ///
    /// Only use this method to provide actions when the actions need to be created freshly for
    /// each popup event. Normal long-lived actions should be published by
    /// [`create_actions`](Self::create_actions).
    fn get_popup_provider_actions(&self) -> Vec<DockingAction> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A handler that overrides nothing but `init`, mirroring the common Java pattern of relying
    /// on every other default no-op/empty-list body.
    struct SilentHandler;

    impl ExtensionPoint for SilentHandler {}

    impl FSBFileHandler for SilentHandler {
        fn init(&self, _context: &FSBFileHandlerContext) {}
    }

    #[test]
    fn defaults_match_java_no_op_bodies() {
        let handler = SilentHandler;
        handler.init(&FSBFileHandlerContext);

        assert!(handler.create_actions().is_empty());
        assert!(handler.get_popup_provider_actions().is_empty());
        assert_eq!(handler.file_focused(&FSBFileNode), false);
        assert_eq!(handler.file_default_action(&FSBFileNode), false);
    }

    /// A handler that overrides `file_focused`/`file_default_action`, matching a real file
    /// handler like `AddToProgramFSBFileHandler` that reacts to user interaction with a node.
    struct ReactiveHandler;

    impl ExtensionPoint for ReactiveHandler {}

    impl FSBFileHandler for ReactiveHandler {
        fn init(&self, _context: &FSBFileHandlerContext) {}

        fn file_focused(&self, _file_node: &FSBFileNode) -> bool {
            true
        }

        fn file_default_action(&self, _file_node: &FSBFileNode) -> bool {
            true
        }
    }

    #[test]
    fn overridden_methods_report_action_taken() {
        let handler: Box<dyn FSBFileHandler> = Box::new(ReactiveHandler);
        assert_eq!(handler.file_focused(&FSBFileNode), true);
        assert_eq!(handler.file_default_action(&FSBFileNode), true);
    }
}

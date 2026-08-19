use crate::framework::model::Workspace;
use crate::framework::seam_stubs::{PluginTool, PropertyChangeEvent};

/// Listener that is notified when a tool is added or removed from a workspace, or when
/// workspace properties change.
///
/// Port of `ghidra.framework.model.WorkspaceChangeListener`. In Java this interface extends
/// `java.beans.PropertyChangeListener`; its one abstract method is folded in here as
/// [`property_change`](WorkspaceChangeListener::property_change) rather than modeled as a
/// separate supertrait.
pub trait WorkspaceChangeListener {
    /// Notification that a tool was added to the given workspace.
    fn tool_added(&mut self, ws: &dyn Workspace, tool: &dyn PluginTool);

    /// Notification that a tool was removed from the given workspace.
    fn tool_removed(&mut self, ws: &dyn Workspace, tool: &dyn PluginTool);

    /// Notification that the given workspace was added by the ToolManager.
    fn workspace_added(&mut self, ws: &dyn Workspace);

    /// Notification that the given workspace was removed by the ToolManager.
    fn workspace_removed(&mut self, ws: &dyn Workspace);

    /// Notification that the given workspace is the current one.
    fn workspace_set_active(&mut self, ws: &dyn Workspace);

    /// Notification of a bound property change on a tool or workspace (e.g. a workspace rename),
    /// mirroring the inherited `PropertyChangeListener.propertyChange(PropertyChangeEvent)`.
    fn property_change(&mut self, event: &dyn PropertyChangeEvent);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockPluginTool;
    impl PluginTool for MockPluginTool {}

    struct MockPropertyChangeEvent;
    impl PropertyChangeEvent for MockPropertyChangeEvent {}

    struct MockWorkspace {
        name: String,
    }

    impl Workspace for MockWorkspace {
        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn get_tools(&self) -> Vec<Box<dyn PluginTool>> {
            Vec::new()
        }

        fn create_tool(&mut self) -> Box<dyn PluginTool> {
            Box::new(MockPluginTool)
        }

        fn run_tool(
            &mut self,
            _template: &dyn crate::framework::model::ToolTemplate,
        ) -> Box<dyn PluginTool> {
            Box::new(MockPluginTool)
        }

        fn set_name(
            &mut self,
            new_name: &str,
        ) -> Result<(), crate::util::exception::DuplicateNameException> {
            self.name = new_name.to_string();
            Ok(())
        }

        fn set_active(&mut self) {}
    }

    struct RecordingListener {
        tools_added: Vec<String>,
        tools_removed: Vec<String>,
        workspaces_added: Vec<String>,
        workspaces_removed: Vec<String>,
        active_workspace: Option<String>,
        property_change_count: usize,
    }

    impl RecordingListener {
        fn new() -> Self {
            RecordingListener {
                tools_added: Vec::new(),
                tools_removed: Vec::new(),
                workspaces_added: Vec::new(),
                workspaces_removed: Vec::new(),
                active_workspace: None,
                property_change_count: 0,
            }
        }
    }

    impl WorkspaceChangeListener for RecordingListener {
        fn tool_added(&mut self, ws: &dyn Workspace, _tool: &dyn PluginTool) {
            self.tools_added.push(ws.get_name());
        }

        fn tool_removed(&mut self, ws: &dyn Workspace, _tool: &dyn PluginTool) {
            self.tools_removed.push(ws.get_name());
        }

        fn workspace_added(&mut self, ws: &dyn Workspace) {
            self.workspaces_added.push(ws.get_name());
        }

        fn workspace_removed(&mut self, ws: &dyn Workspace) {
            self.workspaces_removed.push(ws.get_name());
        }

        fn workspace_set_active(&mut self, ws: &dyn Workspace) {
            self.active_workspace = Some(ws.get_name());
        }

        fn property_change(&mut self, _event: &dyn PropertyChangeEvent) {
            self.property_change_count += 1;
        }
    }

    #[test]
    fn notifies_tool_and_workspace_events() {
        let mut listener = RecordingListener::new();
        let ws = MockWorkspace { name: "Workspace1".to_string() };
        let tool = MockPluginTool;

        listener.tool_added(&ws, &tool);
        listener.tool_removed(&ws, &tool);
        listener.workspace_added(&ws);
        listener.workspace_removed(&ws);
        listener.workspace_set_active(&ws);
        listener.property_change(&MockPropertyChangeEvent);

        assert_eq!(listener.tools_added, vec!["Workspace1"]);
        assert_eq!(listener.tools_removed, vec!["Workspace1"]);
        assert_eq!(listener.workspaces_added, vec!["Workspace1"]);
        assert_eq!(listener.workspaces_removed, vec!["Workspace1"]);
        assert_eq!(listener.active_workspace, Some("Workspace1".to_string()));
        assert_eq!(listener.property_change_count, 1);
    }

    #[test]
    fn usable_as_trait_object() {
        let mut listener: Box<dyn WorkspaceChangeListener> = Box::new(RecordingListener::new());
        let ws = MockWorkspace { name: "Workspace2".to_string() };
        let tool = MockPluginTool;

        listener.tool_added(&ws, &tool);
        listener.workspace_set_active(&ws);
        listener.property_change(&MockPropertyChangeEvent);
    }
}

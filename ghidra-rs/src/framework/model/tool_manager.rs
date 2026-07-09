use crate::framework::model::ToolConnection;
use crate::framework::seam_stubs::{PluginTool, Workspace, WorkspaceChangeListener};
use crate::util::exception::DuplicateNameException;

/// The name to use for a new unnamed workspace; used by the Ghidra Project Window when the user
/// creates a new workspace.
pub const DEFAULT_WORKSPACE_NAME: &str = "Workspace";

/// Property used when sending the change event when a workspace name is changed.
pub const WORKSPACE_NAME_PROPERTY: &str = "WorkspaceName";

/// Interface to define methods to manage running tools and tools in the Tool Chest. The
/// `ToolManager` also keeps track of the workspaces, and what tools are running in workspace, as
/// well as the connections among tools across all workspaces.
///
/// Port of `ghidra.framework.model.ToolManager`.
pub trait ToolManager {
    /// Get the connection object for the producer and consumer tools.
    ///
    /// # Arguments
    /// * `producer` - tool that is producing the tool event
    /// * `consumer` - tool that is consuming the tool event
    fn get_connection(
        &self,
        producer: &dyn PluginTool,
        consumer: &dyn PluginTool,
    ) -> Box<dyn ToolConnection>;

    /// Get a list of tools that produce at least one tool event.
    ///
    /// # Returns
    /// empty vector if no tool produces any events
    fn get_producer_tools(&self) -> Vec<Box<dyn PluginTool>>;

    /// Get a list of tools that consume at least one tool event.
    ///
    /// # Returns
    /// empty vector if no tool consumes any events
    fn get_consumer_tools(&self) -> Vec<Box<dyn PluginTool>>;

    /// Get a list running tools across all workspaces.
    ///
    /// # Returns
    /// empty vector if there are no running tools.
    fn get_running_tools(&self) -> Vec<Box<dyn PluginTool>>;

    /// Create a workspace with the given name.
    ///
    /// # Arguments
    /// * `name` - name of workspace
    ///
    /// # Returns
    /// `Err` if a workspace with this name already exists
    fn create_workspace(
        &mut self,
        name: &str,
    ) -> Result<Box<dyn Workspace>, DuplicateNameException>;

    /// Remove the workspace.
    ///
    /// # Arguments
    /// * `ws` - workspace to remove
    fn remove_workspace(&mut self, ws: &dyn Workspace);

    /// Get list of known workspaces.
    fn get_workspaces(&self) -> Vec<Box<dyn Workspace>>;

    /// Get the active workspace.
    fn get_active_workspace(&self) -> Box<dyn Workspace>;

    /// Add the listener that will be notified when a tool is added or removed.
    ///
    /// # Arguments
    /// * `listener` - workspace listener to add
    fn add_workspace_change_listener(&mut self, listener: Box<dyn WorkspaceChangeListener>);

    /// Remove the workspace listener.
    ///
    /// # Arguments
    /// * `listener` - workspace listener to remove
    fn remove_workspace_change_listener(&mut self, listener: Box<dyn WorkspaceChangeListener>);

    /// Removes all connections involving tool.
    ///
    /// # Arguments
    /// * `tool` - tool for which to remove all connections
    fn disconnect_tool(&mut self, tool: &dyn PluginTool);

    /// A configuration change was made to the tool; a plugin was added or removed.
    ///
    /// # Arguments
    /// * `tool` - tool that changed
    fn tool_changed(&mut self, tool: &dyn PluginTool);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockPluginTool;
    impl PluginTool for MockPluginTool {}

    struct MockWorkspace;
    impl Workspace for MockWorkspace {}

    struct MockWorkspaceChangeListener;
    impl WorkspaceChangeListener for MockWorkspaceChangeListener {}

    struct MockToolConnection {
        producer: MockPluginTool,
        consumer: MockPluginTool,
    }

    impl ToolConnection for MockToolConnection {
        fn get_producer(&self) -> &dyn PluginTool {
            &self.producer
        }

        fn get_consumer(&self) -> &dyn PluginTool {
            &self.consumer
        }

        fn get_events(&self) -> Vec<String> {
            Vec::new()
        }

        fn connect(&mut self, _event_name: &str) -> Result<(), String> {
            Ok(())
        }

        fn disconnect(&mut self, _event_name: &str) -> Result<(), String> {
            Ok(())
        }

        fn is_connected(&self, _event_name: &str) -> bool {
            false
        }
    }

    struct SimpleToolManager {
        workspaces: Vec<String>,
    }

    impl ToolManager for SimpleToolManager {
        fn get_connection(
            &self,
            _producer: &dyn PluginTool,
            _consumer: &dyn PluginTool,
        ) -> Box<dyn ToolConnection> {
            Box::new(MockToolConnection { producer: MockPluginTool, consumer: MockPluginTool })
        }

        fn get_producer_tools(&self) -> Vec<Box<dyn PluginTool>> {
            Vec::new()
        }

        fn get_consumer_tools(&self) -> Vec<Box<dyn PluginTool>> {
            Vec::new()
        }

        fn get_running_tools(&self) -> Vec<Box<dyn PluginTool>> {
            Vec::new()
        }

        fn create_workspace(
            &mut self,
            name: &str,
        ) -> Result<Box<dyn Workspace>, DuplicateNameException> {
            if self.workspaces.iter().any(|w| w == name) {
                return Err(DuplicateNameException::new());
            }
            self.workspaces.push(name.to_string());
            Ok(Box::new(MockWorkspace))
        }

        fn remove_workspace(&mut self, _ws: &dyn Workspace) {}

        fn get_workspaces(&self) -> Vec<Box<dyn Workspace>> {
            self.workspaces
                .iter()
                .map(|_name| Box::new(MockWorkspace) as Box<dyn Workspace>)
                .collect()
        }

        fn get_active_workspace(&self) -> Box<dyn Workspace> {
            Box::new(MockWorkspace)
        }

        fn add_workspace_change_listener(&mut self, _listener: Box<dyn WorkspaceChangeListener>) {
        }

        fn remove_workspace_change_listener(
            &mut self,
            _listener: Box<dyn WorkspaceChangeListener>,
        ) {
        }

        fn disconnect_tool(&mut self, _tool: &dyn PluginTool) {}

        fn tool_changed(&mut self, _tool: &dyn PluginTool) {}
    }

    #[test]
    fn mock_tool_manager_is_object_safe_and_usable() {
        let mut mgr: Box<dyn ToolManager> =
            Box::new(SimpleToolManager { workspaces: Vec::new() });

        let ws = mgr.create_workspace("MyWorkspace").unwrap();
        assert_eq!(mgr.get_workspaces().len(), 1);
        assert!(mgr.create_workspace("MyWorkspace").is_err());

        mgr.remove_workspace(ws.as_ref());
        let listener = Box::new(MockWorkspaceChangeListener);
        mgr.add_workspace_change_listener(listener);

        let producer = MockPluginTool;
        let consumer = MockPluginTool;
        let conn = mgr.get_connection(&producer, &consumer);
        assert!(conn.get_events().is_empty());

        mgr.disconnect_tool(&producer);
        mgr.tool_changed(&producer);
    }
}

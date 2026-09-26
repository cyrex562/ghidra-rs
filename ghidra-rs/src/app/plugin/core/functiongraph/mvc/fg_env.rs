use std::sync::Arc;

use crate::app::seam_stubs::{
    DockingAction, FGColorProvider, FGLayoutProvider, FormatManager, FunctionGraphOptions,
    Navigatable, ProgramSelection,
};
use crate::framework::seam_stubs::PluginTool;
use crate::program::model::listing::program::Program;
use crate::program::util::program_location::ProgramLocation;

/// A simple trait that allows re-use of parts of the `FunctionGraph` API by abstracting away the
/// `FunctionGraphPlugin`. The env allows the controller to get the state of the graph, the state
/// of the tool, and to share resources among graphs.
///
/// Port of `ghidra.app.plugin.core.functiongraph.mvc.FgEnv`.
pub trait FgEnv {
    /// Port of `FgEnv.getTool()`.
    fn get_tool(&self) -> Arc<dyn PluginTool>;

    /// Port of `FgEnv.getProgram()`.
    fn get_program(&self) -> Arc<dyn Program>;

    /// Port of `FgEnv.getOptions()`.
    fn get_options(&self) -> FunctionGraphOptions;

    /// Port of `FgEnv.getColorProvider()`.
    fn get_color_provider(&self) -> Arc<dyn FGColorProvider>;

    /// Port of `FgEnv.getLayoutProviders()`.
    fn get_layout_providers(&self) -> Vec<FGLayoutProvider>;

    /// Adds the given action to the provider used by this environment.
    ///
    /// Port of `FgEnv.addLocalAction(DockingAction)`.
    fn add_local_action(&self, action: DockingAction);

    /// Returns the graph format manager that can be shared amongst all graphs.
    ///
    /// Port of `FgEnv.getUserDefinedFormat()`.
    fn get_user_defined_format(&self) -> Box<dyn FormatManager>;

    /// Sets the graph format manager that can be shared amongst all graphs.
    ///
    /// Port of `FgEnv.setUserDefinedFormat(FormatManager)`.
    fn set_user_defined_format(&self, format: Box<dyn FormatManager>);

    /// Port of `FgEnv.getNavigatable()`.
    fn get_navigatable(&self) -> Arc<dyn Navigatable>;

    /// The tool location is the program location shared by all plugins. Disconnected graphs may
    /// not be using this location.
    ///
    /// Port of `FgEnv.getToolLocation()`.
    fn get_tool_location(&self) -> Arc<dyn ProgramLocation>;

    /// Sets the selection for this function graph environment. If the graph is connected to the
    /// tool, then the selection will be sent to the tool as well as to the graph.
    ///
    /// Port of `FgEnv.setSelection(ProgramSelection)`.
    fn set_selection(&self, selection: &dyn ProgramSelection);

    /// Graph location is the program location inside of the graph, which may differ from that of
    /// the tool, such as for disconnected graphs.
    ///
    /// Port of `FgEnv.getGraphLocation()`.
    fn get_graph_location(&self) -> Arc<dyn ProgramLocation>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::DomainObject;
    use std::cell::RefCell;

    struct MockProgram;
    impl DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock-program".to_string()
        }
        fn get_language_id(&self) -> String {
            "mock:LE:32:default".to_string()
        }
    }

    struct MockTool;
    impl PluginTool for MockTool {
        fn get_tool_name(&self) -> String {
            "Function Graph".to_string()
        }
    }

    struct MockNavigatable;
    impl Navigatable for MockNavigatable {
        fn is_connected(&self) -> bool {
            true
        }
        fn get_program(&self) -> Box<dyn Program> {
            Box::new(MockProgram)
        }
    }

    struct MockLocation;
    impl ProgramLocation for MockLocation {
        fn get_program(&self) -> Arc<dyn Program> {
            Arc::new(MockProgram)
        }
        fn get_address(&self) -> crate::program::model::address::Address {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_byte_address(&self) -> crate::program::model::address::Address {
            unimplemented!("not exercised by this smoke test")
        }
    }

    struct MockColorProvider;
    impl FGColorProvider for MockColorProvider {}

    struct MockFormatManager;
    impl FormatManager for MockFormatManager {}

    struct MockSelection;
    impl ProgramSelection for MockSelection {}

    #[derive(Default)]
    struct MockFgEnv {
        actions_added: RefCell<usize>,
        selections_set: RefCell<usize>,
        format: RefCell<Option<Box<dyn FormatManager>>>,
    }

    impl FgEnv for MockFgEnv {
        fn get_tool(&self) -> Arc<dyn PluginTool> {
            Arc::new(MockTool)
        }

        fn get_program(&self) -> Arc<dyn Program> {
            Arc::new(MockProgram)
        }

        fn get_options(&self) -> FunctionGraphOptions {
            FunctionGraphOptions
        }

        fn get_color_provider(&self) -> Arc<dyn FGColorProvider> {
            Arc::new(MockColorProvider)
        }

        fn get_layout_providers(&self) -> Vec<FGLayoutProvider> {
            vec![FGLayoutProvider, FGLayoutProvider]
        }

        fn add_local_action(&self, _action: DockingAction) {
            *self.actions_added.borrow_mut() += 1;
        }

        fn get_user_defined_format(&self) -> Box<dyn FormatManager> {
            Box::new(MockFormatManager)
        }

        fn set_user_defined_format(&self, format: Box<dyn FormatManager>) {
            *self.format.borrow_mut() = Some(format);
        }

        fn get_navigatable(&self) -> Arc<dyn Navigatable> {
            Arc::new(MockNavigatable)
        }

        fn get_tool_location(&self) -> Arc<dyn ProgramLocation> {
            Arc::new(MockLocation)
        }

        fn set_selection(&self, _selection: &dyn ProgramSelection) {
            *self.selections_set.borrow_mut() += 1;
        }

        fn get_graph_location(&self) -> Arc<dyn ProgramLocation> {
            Arc::new(MockLocation)
        }
    }

    #[test]
    fn getters_reflect_env_state() {
        let env = MockFgEnv::default();

        assert_eq!(env.get_tool().get_tool_name(), "Function Graph");
        assert_eq!(Program::get_name(&*env.get_program()), "mock-program");
        assert_eq!(env.get_layout_providers().len(), 2);
        assert!(env.get_navigatable().is_connected());
        assert_eq!(
            Program::get_name(&*env.get_tool_location().get_program()),
            "mock-program"
        );
        assert_eq!(
            Program::get_name(&*env.get_graph_location().get_program()),
            "mock-program"
        );
    }

    #[test]
    fn add_local_action_and_set_selection_record_calls() {
        let env = MockFgEnv::default();
        assert_eq!(*env.actions_added.borrow(), 0);

        env.add_local_action(DockingAction);
        env.add_local_action(DockingAction);
        assert_eq!(*env.actions_added.borrow(), 2);

        env.set_selection(&MockSelection);
        assert_eq!(*env.selections_set.borrow(), 1);
    }

    #[test]
    fn set_user_defined_format_replaces_shared_format() {
        let env = MockFgEnv::default();
        assert!(env.format.borrow().is_none());

        env.set_user_defined_format(env.get_user_defined_format());
        assert!(env.format.borrow().is_some());
    }
}

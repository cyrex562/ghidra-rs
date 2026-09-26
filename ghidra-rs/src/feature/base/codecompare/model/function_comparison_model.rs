use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;

use crate::feature::base::codecompare::model::function_comparison_model_listener::FunctionComparisonModelListener;
use crate::program::model::listing::function::Function;
use crate::program::model::listing::program::Program;
use crate::util::datastruct::duo::Side;

/// A model for comparing one or more functions in a side by side display.
///
/// Port of `ghidra.features.base.codecompare.model.FunctionComparisonModel`. Java is an
/// `interface` with 9 abstract methods and 1 in-repo implementor
/// ([`MatchedFunctionComparisonModel`], not yet ported), so this becomes a `trait`
/// (rule R-interface-open-ext-point / cycle cut point).
///
/// The model supports the concept of a set of functions that can be selected for each side of
/// the comparison, and maintains the selected (active) function for each side.
///
/// Note: `removeFunctions(Collection<Function>)` and `removeFunctions(Program)` are two
/// overloads in Java; Rust has no overloading, so they are split into
/// [`remove_functions`](Self::remove_functions) and
/// [`remove_functions_for_program`](Self::remove_functions_for_program).
pub trait FunctionComparisonModel {
    /// Adds the given listener to the list of those to be notified of model changes.
    fn add_function_comparison_model_listener(
        &mut self,
        listener: Rc<RefCell<dyn FunctionComparisonModelListener>>,
    );

    /// Removes the given listener from the list of those to be notified of model changes.
    fn remove_function_comparison_model_listener(
        &mut self,
        listener: &Rc<RefCell<dyn FunctionComparisonModelListener>>,
    );

    /// Sets the function for the given side. The function must be one of the functions from that
    /// side's set of functions.
    ///
    /// Returns `true` if the function was made active, or `false` if the function does not exist
    /// for the given side.
    fn set_active_function(&mut self, side: Side, function: Arc<dyn Function>) -> bool;

    /// Returns the active (selected) function for the given side.
    fn get_active_function(&self, side: Side) -> Option<Arc<dyn Function>>;

    /// Returns the list of all functions on the given side that could be made active.
    fn get_functions(&self, side: Side) -> Vec<Arc<dyn Function>>;

    /// Removes the given function from both sides of the comparison.
    fn remove_function(&mut self, function: &dyn Function);

    /// Removes all the given functions from both sides of the comparison.
    fn remove_functions(&mut self, functions: &[Arc<dyn Function>]);

    /// Removes all functions from the given program from both sides of the comparison.
    fn remove_functions_for_program(&mut self, program: &dyn Program);

    /// Returns `true` if the model has no function to compare.
    fn is_empty(&self) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::symbol::namespace::Namespace;
    use crate::program::model::symbol::Symbol;

    struct FakeSymbol;
    impl Symbol for FakeSymbol {
        fn get_address(&self) -> crate::program::model::address::Address {
            unimplemented!("not needed for this smoke test")
        }
        fn get_name(&self) -> &str {
            unimplemented!("not needed for this smoke test")
        }
        fn get_symbol_type(&self) -> crate::program::model::symbol::SymbolType {
            unimplemented!("not needed for this smoke test")
        }
        fn get_source(&self) -> crate::program::model::symbol::SourceType {
            unimplemented!("not needed for this smoke test")
        }
        fn is_primary(&self) -> bool {
            unimplemented!("not needed for this smoke test")
        }
        fn get_id(&self) -> i64 {
            unimplemented!("not needed for this smoke test")
        }
        fn get_parent_id(&self) -> i64 {
            unimplemented!("not needed for this smoke test")
        }
    }

    /// Minimal `Function` stand-in for exercising `FunctionComparisonModel`'s bookkeeping only:
    /// membership/identity via `Arc::ptr_eq` and `get_name`. Every other method is unreachable
    /// from these tests (mirrors the `MockFunction` pattern in
    /// `program::model::listing::function::tests`, duplicated here because that one is private
    /// to its own test module).
    struct FakeFunction {
        name: &'static str,
    }

    impl Namespace for FakeFunction {
        fn get_symbol(&self) -> Arc<dyn Symbol> {
            Arc::new(FakeSymbol)
        }

        fn get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
            None
        }
    }

    #[allow(unused_variables)]
    impl Function for FakeFunction {
        fn get_name(&self) -> String { self.name.to_string() }

        fn set_name(&mut self, name: &str, source: crate::program::model::symbol::SourceType) -> Result<(), crate::program::model::listing::function::SetFunctionNameError> { unimplemented!("not needed for this smoke test") }

        fn set_call_fixup(&mut self, name: Option<&str>) { unimplemented!("not needed for this smoke test") }

        fn get_call_fixup(&self) -> Option<String> { unimplemented!("not needed for this smoke test") }

        fn get_program(&self) -> Arc<dyn Program> { unimplemented!("not needed for this smoke test") }

        fn get_comment(&self) -> Option<String> { unimplemented!("not needed for this smoke test") }

        fn get_comment_as_array(&self) -> Vec<String> { unimplemented!("not needed for this smoke test") }

        fn set_comment(&mut self, comment: Option<&str>) { unimplemented!("not needed for this smoke test") }

        fn get_repeatable_comment(&self) -> Option<String> { unimplemented!("not needed for this smoke test") }

        fn get_repeatable_comment_as_array(&self) -> Vec<String> { unimplemented!("not needed for this smoke test") }

        fn set_repeatable_comment(&mut self, comment: Option<&str>) { unimplemented!("not needed for this smoke test") }

        fn get_entry_point(&self) -> crate::program::model::address::Address { unimplemented!("not needed for this smoke test") }

        fn get_return_type(&self) -> Option<Box<dyn crate::program::model::data::data_type::DataType>> { unimplemented!("not needed for this smoke test") }

        fn set_return_type(&mut self, data_type: Box<dyn crate::program::model::data::data_type::DataType>, source: crate::program::model::symbol::SourceType) -> Result<(), crate::util::exception::InvalidInputException> { unimplemented!("not needed for this smoke test") }

        fn get_return(&self) -> Box<dyn crate::program::model::listing::Parameter> { unimplemented!("not needed for this smoke test") }

        fn set_return(&mut self, data_type: Box<dyn crate::program::model::data::data_type::DataType>, storage: Box<dyn crate::program::model::listing::variable_storage::VariableStorage>, source: crate::program::model::symbol::SourceType) -> Result<(), crate::util::exception::InvalidInputException> { unimplemented!("not needed for this smoke test") }

        fn get_signature_formal(&self, formal_signature: bool) -> Box<dyn crate::program::model::listing::FunctionSignature> { unimplemented!("not needed for this smoke test") }

        fn get_prototype_string(&self, formal_signature: bool, include_calling_convention: bool) -> String { unimplemented!("not needed for this smoke test") }

        fn get_signature_source(&self) -> crate::program::model::symbol::SourceType { unimplemented!("not needed for this smoke test") }

        fn set_signature_source(&mut self, signature_source: crate::program::model::symbol::SourceType) { unimplemented!("not needed for this smoke test") }

        fn get_stack_frame(&self) -> Box<dyn crate::program::seam_stubs::StackFrame> { unimplemented!("not needed for this smoke test") }

        fn get_stack_purge_size(&self) -> i32 { unimplemented!("not needed for this smoke test") }

        fn get_tags(&self) -> Vec<Box<dyn crate::program::model::listing::FunctionTag>> { unimplemented!("not needed for this smoke test") }

        fn add_tag(&mut self, name: &str) -> bool { unimplemented!("not needed for this smoke test") }

        fn remove_tag(&mut self, name: &str) { unimplemented!("not needed for this smoke test") }

        fn set_stack_purge_size(&mut self, purge_size: i32) { unimplemented!("not needed for this smoke test") }

        fn is_stack_purge_size_valid(&self) -> bool { unimplemented!("not needed for this smoke test") }

        fn add_parameter(&mut self, var: Box<dyn crate::program::model::listing::variable::Variable>, source: crate::program::model::symbol::SourceType) -> Result<Box<dyn crate::program::model::listing::Parameter>, crate::program::model::listing::function::FunctionEditError> { unimplemented!("not needed for this smoke test") }

        fn insert_parameter(&mut self, ordinal: i32, var: Box<dyn crate::program::model::listing::variable::Variable>, source: crate::program::model::symbol::SourceType) -> Result<Box<dyn crate::program::model::listing::Parameter>, crate::program::model::listing::function::FunctionEditError> { unimplemented!("not needed for this smoke test") }

        fn replace_parameters(&mut self, params: Vec<Box<dyn crate::program::model::listing::variable::Variable>>, update_type: crate::program::model::listing::function::FunctionUpdateType, force: bool, source: crate::program::model::symbol::SourceType) -> Result<(), crate::program::model::listing::function::FunctionEditError> { unimplemented!("not needed for this smoke test") }

        fn update_function(&mut self, calling_convention: Option<&str>, return_value: Option<Box<dyn crate::program::model::listing::variable::Variable>>, new_params: Vec<Box<dyn crate::program::model::listing::variable::Variable>>, update_type: crate::program::model::listing::function::FunctionUpdateType, force: bool, source: crate::program::model::symbol::SourceType) -> Result<(), crate::program::model::listing::function::FunctionEditError> { unimplemented!("not needed for this smoke test") }

        fn get_parameter(&self, ordinal: i32) -> Option<Box<dyn crate::program::model::listing::Parameter>> { unimplemented!("not needed for this smoke test") }

        fn remove_parameter(&mut self, ordinal: i32) { unimplemented!("not needed for this smoke test") }

        fn move_parameter(&mut self, from_ordinal: i32, to_ordinal: i32) -> Result<Box<dyn crate::program::model::listing::Parameter>, crate::util::exception::InvalidInputException> { unimplemented!("not needed for this smoke test") }

        fn get_parameter_count(&self) -> i32 { unimplemented!("not needed for this smoke test") }

        fn get_auto_parameter_count(&self) -> i32 { unimplemented!("not needed for this smoke test") }

        fn get_parameters(&self) -> Vec<Box<dyn crate::program::model::listing::Parameter>> { unimplemented!("not needed for this smoke test") }

        fn get_parameters_filtered(&self, filter: Option<&dyn crate::program::seam_stubs::VariableFilter>) -> Vec<Box<dyn crate::program::model::listing::Parameter>> { unimplemented!("not needed for this smoke test") }

        fn get_local_variables(&self) -> Vec<Box<dyn crate::program::model::listing::variable::Variable>> { unimplemented!("not needed for this smoke test") }

        fn get_local_variables_filtered(&self, filter: Option<&dyn crate::program::seam_stubs::VariableFilter>) -> Vec<Box<dyn crate::program::model::listing::variable::Variable>> { unimplemented!("not needed for this smoke test") }

        fn get_variables_filtered(&self, filter: Option<&dyn crate::program::seam_stubs::VariableFilter>) -> Vec<Box<dyn crate::program::model::listing::variable::Variable>> { unimplemented!("not needed for this smoke test") }

        fn get_all_variables(&self) -> Vec<Box<dyn crate::program::model::listing::variable::Variable>> { unimplemented!("not needed for this smoke test") }

        fn add_local_variable(&mut self, var: Box<dyn crate::program::model::listing::variable::Variable>, source: crate::program::model::symbol::SourceType) -> Result<Box<dyn crate::program::model::listing::variable::Variable>, crate::program::model::listing::function::FunctionEditError> { unimplemented!("not needed for this smoke test") }

        fn remove_variable(&mut self, var: &dyn crate::program::model::listing::variable::Variable) { unimplemented!("not needed for this smoke test") }

        fn set_body(&mut self, new_body: &dyn crate::program::model::address::AddressSetView) -> Result<(), crate::program::database::function::OverlappingFunctionException> { unimplemented!("not needed for this smoke test") }

        fn has_var_args(&self) -> bool { unimplemented!("not needed for this smoke test") }

        fn set_var_args(&mut self, has_var_args: bool) { unimplemented!("not needed for this smoke test") }

        fn is_inline(&self) -> bool { unimplemented!("not needed for this smoke test") }

        fn set_inline(&mut self, is_inline: bool) { unimplemented!("not needed for this smoke test") }

        fn has_no_return(&self) -> bool { unimplemented!("not needed for this smoke test") }

        fn set_no_return(&mut self, has_no_return: bool) { unimplemented!("not needed for this smoke test") }

        fn has_custom_variable_storage(&self) -> bool { unimplemented!("not needed for this smoke test") }

        fn set_custom_variable_storage(&mut self, has_custom_variable_storage: bool) { unimplemented!("not needed for this smoke test") }

        fn get_calling_convention(&self) -> Option<Arc<crate::program::model::lang::PrototypeModel>> { unimplemented!("not needed for this smoke test") }

        fn get_calling_convention_name(&self) -> String { unimplemented!("not needed for this smoke test") }

        fn set_calling_convention(&mut self, name: &str) -> Result<(), crate::util::exception::InvalidInputException> { unimplemented!("not needed for this smoke test") }

        fn is_thunk(&self) -> bool { unimplemented!("not needed for this smoke test") }

        fn get_thunked_function(&self, recursive: bool) -> Option<Arc<dyn Function>> { unimplemented!("not needed for this smoke test") }

        fn get_function_thunk_addresses(&self, recursive: bool) -> Option<Vec<crate::program::model::address::Address>> { unimplemented!("not needed for this smoke test") }

        fn set_thunked_function(&mut self, thunked_function: Option<Arc<dyn Function>>) -> Result<(), String> { unimplemented!("not needed for this smoke test") }

        fn is_external(&self) -> bool { unimplemented!("not needed for this smoke test") }

        fn get_external_location(&self) -> Option<Box<dyn crate::program::model::symbol::ExternalLocation>> { unimplemented!("not needed for this smoke test") }

        fn get_calling_functions(&self, monitor: &dyn crate::util::task::TaskMonitor) -> Vec<Arc<dyn Function>> { unimplemented!("not needed for this smoke test") }

        fn get_called_functions(&self, monitor: &dyn crate::util::task::TaskMonitor) -> Vec<Arc<dyn Function>> { unimplemented!("not needed for this smoke test") }

        fn promote_local_user_labels_to_global(&mut self) { unimplemented!("not needed for this smoke test") }

        fn is_deleted(&self) -> bool { unimplemented!("not needed for this smoke test") }
    }

    /// A minimal in-memory model, exercised only to prove `FunctionComparisonModel`'s contract
    /// (mirrors the subset of `AnyToAnyFunctionComparisonModel` behavior this interface promises).
    #[derive(Default)]
    struct FakeComparisonModel {
        listeners: Vec<Rc<RefCell<dyn FunctionComparisonModelListener>>>,
        left: Vec<Arc<dyn Function>>,
        right: Vec<Arc<dyn Function>>,
        active_left: Option<Arc<dyn Function>>,
        active_right: Option<Arc<dyn Function>>,
    }

    impl FakeComparisonModel {
        fn side_functions(&self, side: Side) -> &Vec<Arc<dyn Function>> {
            match side {
                Side::Left => &self.left,
                Side::Right => &self.right,
            }
        }

        fn side_functions_mut(&mut self, side: Side) -> &mut Vec<Arc<dyn Function>> {
            match side {
                Side::Left => &mut self.left,
                Side::Right => &mut self.right,
            }
        }

        fn active_mut(&mut self, side: Side) -> &mut Option<Arc<dyn Function>> {
            match side {
                Side::Left => &mut self.active_left,
                Side::Right => &mut self.active_right,
            }
        }
    }

    impl FunctionComparisonModel for FakeComparisonModel {
        fn add_function_comparison_model_listener(
            &mut self,
            listener: Rc<RefCell<dyn FunctionComparisonModelListener>>,
        ) {
            self.listeners.push(listener);
        }

        fn remove_function_comparison_model_listener(
            &mut self,
            listener: &Rc<RefCell<dyn FunctionComparisonModelListener>>,
        ) {
            self.listeners.retain(|l| !Rc::ptr_eq(l, listener));
        }

        fn set_active_function(&mut self, side: Side, function: Arc<dyn Function>) -> bool {
            let exists = self
                .side_functions(side)
                .iter()
                .any(|f| Arc::ptr_eq(f, &function));
            if !exists {
                return false;
            }
            *self.active_mut(side) = Some(function.clone());
            for listener in &self.listeners {
                listener
                    .borrow_mut()
                    .active_function_changed(side, Some(function.as_ref()));
            }
            true
        }

        fn get_active_function(&self, side: Side) -> Option<Arc<dyn Function>> {
            match side {
                Side::Left => self.active_left.clone(),
                Side::Right => self.active_right.clone(),
            }
        }

        fn get_functions(&self, side: Side) -> Vec<Arc<dyn Function>> {
            self.side_functions(side).clone()
        }

        fn remove_function(&mut self, function: &dyn Function) {
            self.left.retain(|f| !std::ptr::eq(f.as_ref(), function));
            self.right.retain(|f| !std::ptr::eq(f.as_ref(), function));
        }

        fn remove_functions(&mut self, functions: &[Arc<dyn Function>]) {
            for f in functions {
                self.left.retain(|x| !Arc::ptr_eq(x, f));
                self.right.retain(|x| !Arc::ptr_eq(x, f));
            }
        }

        fn remove_functions_for_program(&mut self, _program: &dyn Program) {
            // No program association tracked by this fake; real implementations filter by
            // `function.getProgram() == program`.
        }

        fn is_empty(&self) -> bool {
            self.left.is_empty() && self.right.is_empty()
        }
    }

    #[test]
    fn set_active_function_requires_membership() {
        let mut model = FakeComparisonModel::default();
        let f1: Arc<dyn Function> = Arc::new(FakeFunction { name: "foo" });
        model.left.push(f1.clone());

        let f2: Arc<dyn Function> = Arc::new(FakeFunction { name: "bar" });
        assert!(!model.set_active_function(Side::Left, f2));
        assert!(model.get_active_function(Side::Left).is_none());

        assert!(model.set_active_function(Side::Left, f1.clone()));
        assert!(Arc::ptr_eq(
            &model.get_active_function(Side::Left).unwrap(),
            &f1
        ));
    }

    #[test]
    fn is_empty_reflects_both_sides() {
        let mut model = FakeComparisonModel::default();
        assert!(model.is_empty());
        let f1: Arc<dyn Function> = Arc::new(FakeFunction { name: "foo" });
        model.right.push(f1);
        assert!(!model.is_empty());
    }

    #[test]
    fn remove_function_clears_from_both_sides() {
        let mut model = FakeComparisonModel::default();
        let f1: Arc<dyn Function> = Arc::new(FakeFunction { name: "foo" });
        model.left.push(f1.clone());
        model.right.push(f1.clone());
        model.remove_function(f1.as_ref());
        assert!(model.is_empty());
    }

    #[test]
    fn listener_notified_on_active_function_change() {
        #[derive(Default)]
        struct RecordingListener {
            calls: Vec<(Side, bool)>,
        }
        impl FunctionComparisonModelListener for RecordingListener {
            fn active_function_changed(&mut self, side: Side, function: Option<&dyn Function>) {
                self.calls.push((side, function.is_some()));
            }
            fn model_data_changed(&mut self) {}
        }

        let mut model = FakeComparisonModel::default();
        let listener = Rc::new(RefCell::new(RecordingListener::default()));
        model.add_function_comparison_model_listener(listener.clone());

        let f1: Arc<dyn Function> = Arc::new(FakeFunction { name: "foo" });
        model.left.push(f1.clone());
        assert!(model.set_active_function(Side::Left, f1));

        assert_eq!(listener.borrow().calls, vec![(Side::Left, true)]);
    }
}

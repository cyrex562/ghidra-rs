//! Port of `ghidra.app.plugin.core.functiongraph.mvc.FunctionGraphRunnable`.
//!
//! Builds (or re-builds) the function graph for a single [`ProgramLocation`] on a background
//! thread ([`MonitoredRunnable::monitored_run`]), then hands the result back to the
//! [`FGModel`](crate::app::seam_stubs::FGModel) on the Swing thread
//! ([`SwingRunnable::swing_run`]).
//!
//! Java's constructor null-checks `location`/`program`; this port's `Arc` parameters are
//! non-optional, so the checks are not reproduced. The `taskMonitor` field Java uses to smuggle
//! the active monitor into the private `findFunctionUsingIsolatedBlockModel` helper is dropped in
//! favor of passing the monitor as an ordinary parameter, since [`MonitoredRunnable::monitored_run`]
//! already has one in scope.
//!
//! [`UndefinedFunction`] was ported as a dependency-cycle cut-point trait with no concrete
//! implementor (see that module's docs), so [`SyntheticUndefinedFunction`] provides the minimal
//! one this port's `findFunctionUsingIsolatedBlockModel` fallback needs to actually call
//! `new UndefinedFunction(program, entry)`. Its `getFunctionManager().getFunctionAt(entry)`
//! re-check is not reproduced: that call needs `&mut dyn Program`, reachable only via
//! `Arc::get_mut` (see [`with_program_mut`]), which can never succeed once `self.program` is a
//! live field for the whole `&self` call -- so this port goes straight to synthesizing the
//! undefined function, same as Java's own fallback when no function is found.

use std::sync::{Arc, Mutex};

use crate::app::seam_stubs::{EmptyFunctionGraphData, FGController, FGData, FGModel, FunctionGraphFactory};
use crate::program::database::function::OverlappingFunctionException;
use crate::program::model::address::{Address, AddressSet, AddressSetView};
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::parameter_definition::ParameterDefinition;
use crate::program::model::lang::prototype_model::PrototypeModel;
use crate::program::model::listing::function::{FunctionEditError, SetFunctionNameError};
use crate::program::model::listing::stack_frame::CreateStackVariableError;
use crate::program::model::listing::variable_storage::VariableStorage;
use crate::program::model::listing::{Function, FunctionSignature, FunctionTag, Parameter, Program, Variable};
use crate::program::model::symbol::{ExternalLocation, Namespace, SourceType, Symbol};
use crate::program::seam_stubs::{StackFrame, VariableFilter};
use crate::program::util::program_location::ProgramLocation;
use crate::util::exception::InvalidInputException;
use crate::util::seam_stubs::{IsolatedEntrySubModel, IsolatedEntrySubModelLike};
use crate::util::task::swing_runnable::SwingRunnable;
use crate::util::task::{MonitoredRunnable, TaskMonitor};
use crate::util::undefined_function::UndefinedFunction;

/// Attempts `f` against `program` via `Arc::get_mut`, mirroring the `Arc::get_mut(&mut program)`
/// idiom already established elsewhere in this crate (see `code_unit_format.rs`) for reaching
/// `Program`'s `&mut self` manager accessors. Returns `None` (rather than the manager result) if
/// exclusive access could not be obtained, e.g. because another `Arc<dyn Program>` handle -- such
/// as the caller's own copy -- is outstanding.
fn with_program_mut<T>(
    program: &mut Arc<dyn Program>,
    f: impl FnOnce(&mut dyn Program) -> Option<T>,
) -> Option<T> {
    match Arc::get_mut(program) {
        Some(p) => f(p),
        None => None,
    }
}

/// Builds and, once built, holds the [`FGData`] for one function's graph.
///
/// Port of `ghidra.app.plugin.core.functiongraph.mvc.FunctionGraphRunnable`.
pub struct FunctionGraphRunnable {
    controller: Arc<dyn FGController>,
    model: Arc<dyn FGModel>,
    location: Arc<dyn ProgramLocation + Send + Sync>,
    program: Arc<dyn Program>,
    function: Option<Arc<dyn Function>>,
    graph_data: Mutex<Option<Box<dyn FGData>>>,
}

impl FunctionGraphRunnable {
    /// Port of `FunctionGraphRunnable(FGController, Program, ProgramLocation)`.
    pub fn new(
        controller: Arc<dyn FGController>,
        mut program: Arc<dyn Program>,
        location: Arc<dyn ProgramLocation + Send + Sync>,
    ) -> Self {
        let model = controller.get_model();
        let address = location.get_address();
        let function = with_program_mut(&mut program, |p| {
            p.get_function_manager().and_then(|fm| fm.get_function_containing(&address))
        });

        FunctionGraphRunnable {
            controller,
            model,
            location,
            program,
            function,
            graph_data: Mutex::new(None),
        }
    }

    /// Port of (package-private) `FunctionGraphRunnable.containsLocation(ProgramLocation)`.
    pub fn contains_location(&self, program_location: &dyn ProgramLocation) -> bool {
        match &self.function {
            Some(function) => function.get_body().contains(&program_location.get_address()),
            None => false,
        }
    }

    /// Port of (package-private) `FunctionGraphRunnable.getLocation()`.
    pub fn get_location(&self) -> Arc<dyn ProgramLocation + Send + Sync> {
        self.location.clone()
    }

    /// Port of the private `FunctionGraphRunnable.validateFunction(Function, Address)`.
    fn validate_function(&self, monitor: &dyn TaskMonitor) -> Option<Arc<dyn Function>> {
        if let Some(function) = &self.function {
            return Some(function.clone());
        }
        self.find_function_using_isolated_block_model(&self.location.get_address(), monitor)
    }

    /// Port of the private `FunctionGraphRunnable.findFunctionUsingIsolatedBlockModel(Address)`.
    /// See the module docs for why the `getFunctionManager().getFunctionAt(entry)` re-check is
    /// not reproduced.
    fn find_function_using_isolated_block_model(
        &self,
        address: &Address,
        monitor: &dyn TaskMonitor,
    ) -> Option<Arc<dyn Function>> {
        monitor.set_message("Locating undefined function entry using Isolated Entry model...");

        let block_model = IsolatedEntrySubModel::new(self.program.clone());
        let code_block =
            block_model.get_first_code_block_containing(address, monitor).ok().flatten()?;
        let entry = code_block.get_first_start_address();

        let mut undefined_function = SyntheticUndefinedFunction::new(self.program.clone(), entry);
        Function::set_body(&mut undefined_function, &*code_block).ok()?;

        let function: Arc<dyn Function> = Arc::new(undefined_function);
        Some(function)
    }
}

impl MonitoredRunnable for FunctionGraphRunnable {
    /// Port of `FunctionGraphRunnable.monitoredRun(TaskMonitor)`.
    fn monitored_run(&self, monitor: &dyn TaskMonitor) {
        monitor.set_progress(0);

        let Some(validated_function) = self.validate_function(monitor) else {
            let message = format!(
                "Location is not in a defined or undefined function \"{}\"",
                self.location.get_address()
            );
            *self.graph_data.lock().unwrap() = Some(Box::new(EmptyFunctionGraphData::new(message.clone())));
            monitor.set_message(&message);
            return;
        };

        monitor.set_message(&format!("Creating graph for \"{}\"", Function::get_name(validated_function.as_ref())));
        monitor.set_progress(0);

        match FunctionGraphFactory::create_new_graph(
            validated_function.as_ref(),
            self.controller.as_ref(),
            self.program.as_ref(),
            monitor,
        ) {
            Ok(data) => {
                monitor.set_message(&format!(
                    "Finished creating graph for \"{}\"",
                    Function::get_name(validated_function.as_ref())
                ));
                *self.graph_data.lock().unwrap() = Some(data);
            }
            Err(e) => {
                let message = if e.is_default_message() {
                    format!("Cancelled graph for \"{}\"", Function::get_name(validated_function.as_ref()))
                } else {
                    e.0.clone()
                };
                *self.graph_data.lock().unwrap() = Some(Box::new(EmptyFunctionGraphData::new(message.clone())));
                monitor.set_message(&message);
            }
        }
    }
}

impl SwingRunnable for FunctionGraphRunnable {
    /// Port of `FunctionGraphRunnable.swingRun(boolean)`.
    fn swing_run(&self, is_cancelled: bool) {
        let mut graph_data = self.graph_data.lock().unwrap();

        if is_cancelled {
            *graph_data = Some(Box::new(EmptyFunctionGraphData::new(format!(
                "Graph cancelled for location: {}",
                self.location.get_address()
            ))));
        } else if self.program.is_closed() {
            // can happen when closing a program with results waiting to get onto the Swing thread
            *graph_data = Some(Box::new(EmptyFunctionGraphData::new(format!(
                "Program closed: {}",
                self.location.get_address()
            ))));
        } else if graph_data.is_none() {
            *graph_data = Some(Box::new(EmptyFunctionGraphData::new(format!(
                "No Function at {}",
                self.location.get_address()
            ))));
        }

        let data_ref = graph_data.as_deref().expect("one of the three branches above always sets it");
        self.model.set_function_graph_data(self, data_ref);
    }
}

/// Minimal, crate-local stand-in for `new ghidra.util.UndefinedFunction(program, entry)`.
///
/// See the module docs for why this exists. Every accessor delegates to the
/// [`UndefinedFunction`] trait's `undefined_function_*` defaults, exactly as that trait's own
/// test mock (`MockUndefinedFunction`) does; mutation methods Java itself rejects with
/// `UnsupportedOperationException` panic here instead, since there is no `Result` to report
/// through on those trait methods. [`PlaceholderFunctionSignature`]/[`PlaceholderStackFrame`]
/// back the two accessors ([`Function::get_signature`]/[`Function::get_stack_frame`]) that this
/// port's graph construction never actually reads.
struct SyntheticUndefinedFunction {
    program: Arc<dyn Program>,
    entry: Address,
    body: AddressSet,
}

impl SyntheticUndefinedFunction {
    fn new(program: Arc<dyn Program>, entry: Address) -> Self {
        SyntheticUndefinedFunction { program, entry, body: AddressSet::new() }
    }
}

impl Namespace for SyntheticUndefinedFunction {
    fn get_symbol(&self) -> Arc<dyn Symbol> {
        self.undefined_function_get_symbol()
    }

    fn get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
        self.undefined_function_get_parent_namespace()
    }

    fn get_name_with_path(&self, include_namespace_path: bool) -> String {
        self.undefined_function_get_name_with_path(include_namespace_path)
    }

    fn get_body(&self) -> Box<dyn AddressSetView> {
        Box::new(self.body.clone())
    }
}

impl Function for SyntheticUndefinedFunction {
    fn get_name(&self) -> String {
        self.undefined_function_get_name()
    }

    fn set_name(&mut self, _name: &str, _source: SourceType) -> Result<(), SetFunctionNameError> {
        self.undefined_function_set_name()
    }

    fn set_call_fixup(&mut self, _name: Option<&str>) {
        panic!("UndefinedFunction may not be modified")
    }

    fn get_call_fixup(&self) -> Option<String> {
        self.undefined_function_get_call_fixup()
    }

    fn get_program(&self) -> Arc<dyn Program> {
        self.program.clone()
    }

    fn get_comment(&self) -> Option<String> {
        self.undefined_function_get_comment()
    }

    fn get_comment_as_array(&self) -> Vec<String> {
        self.undefined_function_get_comment_as_array()
    }

    fn set_comment(&mut self, _comment: Option<&str>) {
        panic!("UndefinedFunction may not be modified")
    }

    fn get_repeatable_comment(&self) -> Option<String> {
        self.undefined_function_get_repeatable_comment()
    }

    fn get_repeatable_comment_as_array(&self) -> Vec<String> {
        self.undefined_function_get_repeatable_comment_as_array()
    }

    fn set_repeatable_comment(&mut self, _comment: Option<&str>) {
        panic!("UndefinedFunction may not be modified")
    }

    fn get_entry_point(&self) -> Address {
        self.entry.clone()
    }

    fn get_return_type(&self) -> Option<Box<dyn DataType>> {
        self.undefined_function_get_return_type()
    }

    fn set_return_type(
        &mut self,
        data_type: Box<dyn DataType>,
        _source: SourceType,
    ) -> Result<(), InvalidInputException> {
        self.undefined_function_set_return_type(data_type.as_ref())
    }

    fn get_return(&self) -> Box<dyn Parameter> {
        unimplemented!("not exercised by FunctionGraphRunnable (ReturnParameterImpl not yet ported)")
    }

    fn set_return(
        &mut self,
        _data_type: Box<dyn DataType>,
        _storage: Box<dyn VariableStorage>,
        _source: SourceType,
    ) -> Result<(), InvalidInputException> {
        Err(InvalidInputException::with_message("UndefinedFunction may not be modified"))
    }

    fn get_signature_formal(&self, formal_signature: bool) -> Box<dyn FunctionSignature> {
        self.undefined_function_get_signature_formal(formal_signature)
    }

    fn get_prototype_string(&self, formal_signature: bool, include_calling_convention: bool) -> String {
        self.undefined_function_get_prototype_string(formal_signature, include_calling_convention)
    }

    fn get_signature_source(&self) -> SourceType {
        self.undefined_function_get_signature_source()
    }

    fn set_signature_source(&mut self, _signature_source: SourceType) {
        panic!("UndefinedFunction may not be modified")
    }

    fn get_stack_frame(&self) -> Box<dyn StackFrame> {
        self.undefined_function_get_stack_frame()
    }

    fn get_stack_purge_size(&self) -> i32 {
        self.undefined_function_get_stack_purge_size()
    }

    fn get_tags(&self) -> Vec<Box<dyn FunctionTag>> {
        panic!("UndefinedFunction may not be modified")
    }

    fn add_tag(&mut self, _name: &str) -> bool {
        panic!("UndefinedFunction may not be modified")
    }

    fn remove_tag(&mut self, _name: &str) {
        panic!("UndefinedFunction may not be modified")
    }

    fn set_stack_purge_size(&mut self, _purge_size: i32) {
        panic!("UndefinedFunction may not be modified")
    }

    fn is_stack_purge_size_valid(&self) -> bool {
        self.undefined_function_is_stack_purge_size_valid()
    }

    #[allow(deprecated)]
    fn add_parameter(
        &mut self,
        _var: Box<dyn Variable>,
        _source: SourceType,
    ) -> Result<Box<dyn Parameter>, FunctionEditError> {
        self.undefined_function_reject_edit()
    }

    #[allow(deprecated)]
    fn insert_parameter(
        &mut self,
        _ordinal: i32,
        _var: Box<dyn Variable>,
        _source: SourceType,
    ) -> Result<Box<dyn Parameter>, FunctionEditError> {
        self.undefined_function_reject_edit()
    }

    fn replace_parameters(
        &mut self,
        _params: Vec<Box<dyn Variable>>,
        _update_type: crate::program::model::listing::FunctionUpdateType,
        _force: bool,
        _source: SourceType,
    ) -> Result<(), FunctionEditError> {
        self.undefined_function_reject_edit()
    }

    fn update_function(
        &mut self,
        _calling_convention: Option<&str>,
        _return_value: Option<Box<dyn Variable>>,
        _new_params: Vec<Box<dyn Variable>>,
        _update_type: crate::program::model::listing::FunctionUpdateType,
        _force: bool,
        _source: SourceType,
    ) -> Result<(), FunctionEditError> {
        self.undefined_function_reject_edit()
    }

    fn get_parameter(&self, _ordinal: i32) -> Option<Box<dyn Parameter>> {
        self.undefined_function_get_parameter()
    }

    #[allow(deprecated)]
    fn remove_parameter(&mut self, _ordinal: i32) {
        panic!("UndefinedFunction may not be modified")
    }

    #[allow(deprecated)]
    fn move_parameter(
        &mut self,
        _from_ordinal: i32,
        _to_ordinal: i32,
    ) -> Result<Box<dyn Parameter>, InvalidInputException> {
        Err(InvalidInputException::with_message("UndefinedFunction may not be modified"))
    }

    fn get_parameter_count(&self) -> i32 {
        self.undefined_function_get_parameter_count()
    }

    fn get_auto_parameter_count(&self) -> i32 {
        self.undefined_function_get_auto_parameter_count()
    }

    fn get_parameters(&self) -> Vec<Box<dyn Parameter>> {
        self.undefined_function_get_parameters()
    }

    fn get_parameters_filtered(&self, _filter: Option<&dyn VariableFilter>) -> Vec<Box<dyn Parameter>> {
        self.undefined_function_get_parameters()
    }

    fn get_local_variables(&self) -> Vec<Box<dyn Variable>> {
        self.undefined_function_get_variables()
    }

    fn get_local_variables_filtered(&self, _filter: Option<&dyn VariableFilter>) -> Vec<Box<dyn Variable>> {
        self.undefined_function_get_variables()
    }

    fn get_variables_filtered(&self, _filter: Option<&dyn VariableFilter>) -> Vec<Box<dyn Variable>> {
        self.undefined_function_get_variables()
    }

    fn get_all_variables(&self) -> Vec<Box<dyn Variable>> {
        self.undefined_function_get_variables()
    }

    fn add_local_variable(
        &mut self,
        _var: Box<dyn Variable>,
        _source: SourceType,
    ) -> Result<Box<dyn Variable>, FunctionEditError> {
        self.undefined_function_reject_edit()
    }

    fn remove_variable(&mut self, _var: &dyn Variable) {
        panic!("UndefinedFunction may not be modified")
    }

    fn set_body(&mut self, new_body: &dyn AddressSetView) -> Result<(), OverlappingFunctionException> {
        self.undefined_function_set_body(new_body)
    }

    fn has_var_args(&self) -> bool {
        self.undefined_function_has_var_args()
    }

    fn set_var_args(&mut self, _has_var_args: bool) {
        panic!("UndefinedFunction may not be modified")
    }

    fn is_inline(&self) -> bool {
        self.undefined_function_is_inline()
    }

    fn set_inline(&mut self, _is_inline: bool) {
        panic!("UndefinedFunction may not be modified")
    }

    fn has_no_return(&self) -> bool {
        self.undefined_function_has_no_return()
    }

    fn set_no_return(&mut self, _has_no_return: bool) {
        panic!("UndefinedFunction may not be modified")
    }

    fn has_custom_variable_storage(&self) -> bool {
        self.undefined_function_has_custom_variable_storage()
    }

    fn set_custom_variable_storage(&mut self, has_custom_variable_storage: bool) {
        self.undefined_function_set_custom_variable_storage(has_custom_variable_storage)
    }

    fn get_calling_convention(&self) -> Option<Box<dyn PrototypeModel>> {
        self.undefined_function_get_calling_convention()
    }

    fn get_calling_convention_name(&self) -> String {
        self.undefined_function_get_calling_convention_name()
    }

    fn set_calling_convention(&mut self, _name: &str) -> Result<(), InvalidInputException> {
        Err(InvalidInputException::with_message("UndefinedFunction may not be modified"))
    }

    fn is_thunk(&self) -> bool {
        self.undefined_function_is_thunk()
    }

    fn get_thunked_function(&self, _recursive: bool) -> Option<Arc<dyn Function>> {
        self.undefined_function_get_thunked_function()
    }

    fn get_function_thunk_addresses(&self, _recursive: bool) -> Option<Vec<Address>> {
        self.undefined_function_get_function_thunk_addresses()
    }

    fn set_thunked_function(&mut self, _thunked_function: Option<Arc<dyn Function>>) -> Result<(), String> {
        self.undefined_function_set_thunked_function()
    }

    fn is_external(&self) -> bool {
        self.undefined_function_is_external()
    }

    fn get_external_location(&self) -> Option<Box<dyn ExternalLocation>> {
        self.undefined_function_get_external_location()
    }

    fn get_calling_functions(&self, _monitor: &dyn TaskMonitor) -> Vec<Arc<dyn Function>> {
        self.undefined_function_get_calling_functions()
    }

    fn get_called_functions(&self, _monitor: &dyn TaskMonitor) -> Vec<Arc<dyn Function>> {
        self.undefined_function_get_called_functions()
    }

    fn promote_local_user_labels_to_global(&mut self) {
        panic!("UndefinedFunction may not be modified")
    }

    fn is_deleted(&self) -> bool {
        self.undefined_function_is_deleted()
    }
}

impl UndefinedFunction for SyntheticUndefinedFunction {
    fn stored_signature(&self) -> Box<dyn FunctionSignature> {
        Box::new(PlaceholderFunctionSignature)
    }

    fn stored_frame(&self) -> Box<dyn StackFrame> {
        Box::new(PlaceholderStackFrame)
    }

    fn stored_body(&self) -> Box<dyn AddressSetView> {
        Box::new(self.body.clone())
    }

    fn set_stored_body(&mut self, new_body: AddressSet) {
        self.body = new_body;
    }

    fn new_undefined_function(
        program: Arc<dyn Program>,
        entry: Option<Address>,
    ) -> Result<Self, InvalidInputException> {
        crate::util::undefined_function::check_entry_is_memory_address(entry.as_ref())?;
        let entry =
            entry.ok_or_else(|| InvalidInputException::with_message("Entry point is required"))?;
        Ok(SyntheticUndefinedFunction::new(program, entry))
    }
}

/// Backing type for [`SyntheticUndefinedFunction::stored_signature`]. Never exercised by this
/// port ([`FunctionGraphFactory::create_new_graph`] doesn't touch the function's signature), so
/// most accessors return a fixed "void undefined(void)" placeholder; the two this port truly
/// never needs (`get_return_type`) stay `unimplemented!()`, matching the "not needed for this
/// smoke test" convention this trait's own test mock uses.
struct PlaceholderFunctionSignature;

impl FunctionSignature for PlaceholderFunctionSignature {
    fn get_name(&self) -> String {
        "undefined".to_string()
    }

    fn get_prototype_string(&self) -> String {
        "void undefined(void)".to_string()
    }

    fn get_prototype_string_with_calling_convention(&self, _include_calling_convention: bool) -> String {
        "void undefined(void)".to_string()
    }

    fn get_arguments(&self) -> Vec<Box<dyn ParameterDefinition>> {
        Vec::new()
    }

    fn get_return_type(&self) -> Box<dyn DataType> {
        unimplemented!("not exercised by FunctionGraphRunnable")
    }

    fn get_comment(&self) -> Option<String> {
        None
    }

    fn has_var_args(&self) -> bool {
        false
    }

    fn has_no_return(&self) -> bool {
        false
    }

    fn get_calling_convention(&self) -> Option<Box<dyn PrototypeModel>> {
        None
    }

    fn get_calling_convention_name(&self) -> String {
        crate::program::model::listing::function::UNKNOWN_CALLING_CONVENTION_STRING.to_string()
    }

    fn is_equivalent_signature(&self, _signature: &dyn FunctionSignature) -> bool {
        false
    }
}

/// Backing type for [`SyntheticUndefinedFunction::stored_frame`]. Never exercised by this port,
/// mirroring [`PlaceholderFunctionSignature`].
struct PlaceholderStackFrame;

impl StackFrame for PlaceholderStackFrame {
    fn get_function(&self) -> Option<Box<dyn Function>> {
        unimplemented!("not exercised by FunctionGraphRunnable")
    }

    fn get_frame_size(&self) -> i32 {
        0
    }

    fn get_local_size(&self) -> i32 {
        0
    }

    fn get_parameter_size(&self) -> i32 {
        0
    }

    fn get_parameter_offset(&self) -> i32 {
        0
    }

    fn is_parameter_offset(&self, _offset: i32) -> bool {
        false
    }

    fn set_local_size(&mut self, _size: i32) {}

    fn set_return_address_offset(&mut self, _offset: i32) {}

    fn get_return_address_offset(&self) -> i32 {
        0
    }

    fn get_variable_containing(&self, _offset: i32) -> Option<Box<dyn Variable>> {
        None
    }

    fn create_variable(
        &mut self,
        _name: &str,
        _offset: i32,
        _data_type: Box<dyn DataType>,
        _source: SourceType,
    ) -> Result<Box<dyn Variable>, CreateStackVariableError> {
        unimplemented!("not exercised by FunctionGraphRunnable")
    }

    fn clear_variable(&mut self, _offset: i32) {}

    fn get_stack_variables(&self) -> Vec<Box<dyn Variable>> {
        Vec::new()
    }

    fn get_parameters(&self) -> Vec<Box<dyn Variable>> {
        Vec::new()
    }

    fn get_locals(&self) -> Vec<Box<dyn Variable>> {
        Vec::new()
    }

    fn grows_negative(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::DomainObject;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::listing::function_manager::FunctionManager;
    use crate::util::task::DummyMonitor;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn mock_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    fn addr(offset: i64) -> Address {
        Address::new(mock_space(), offset)
    }

    struct MockFunctionManager {
        function_at_entry: Option<Arc<dyn Function>>,
    }

    impl crate::program::database::manager_db::ManagerDB for MockFunctionManager {
        fn invalidate_cache(&mut self, _all: bool) -> std::io::Result<()> {
            Ok(())
        }
        fn delete_address_range(&mut self, _start_addr: &Address, _end_addr: &Address) -> std::io::Result<()> {
            Ok(())
        }
        fn move_address_range(&mut self, _from_addr: &Address, _to_addr: &Address, _length: u64) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl FunctionManager for MockFunctionManager {
        fn get_program(&self) -> Arc<dyn Program> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_calling_convention_names(&self) -> Vec<String> {
            Vec::new()
        }
        fn get_default_calling_convention(&self) -> Option<Box<dyn PrototypeModel>> {
            None
        }
        fn get_calling_convention(&self, _name: &str) -> Option<Box<dyn PrototypeModel>> {
            None
        }
        fn create_function(
            &mut self,
            _name: Option<&str>,
            _entry_point: Address,
            _body: &dyn AddressSetView,
            _source: SourceType,
        ) -> Result<Arc<dyn Function>, crate::program::model::listing::CreateFunctionError> {
            unimplemented!("not needed for this smoke test")
        }
        fn create_function_in_namespace(
            &mut self,
            _name: Option<&str>,
            _name_space: Arc<dyn Namespace>,
            _entry_point: Address,
            _body: &dyn AddressSetView,
            _source: SourceType,
        ) -> Result<Arc<dyn Function>, crate::program::model::listing::CreateFunctionError> {
            unimplemented!("not needed for this smoke test")
        }
        fn create_thunk_function(
            &mut self,
            _name: Option<&str>,
            _name_space: Arc<dyn Namespace>,
            _entry_point: Address,
            _body: &dyn AddressSetView,
            _thunked_function: Arc<dyn Function>,
            _source: SourceType,
        ) -> Result<Arc<dyn Function>, OverlappingFunctionException> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_function_count(&self) -> usize {
            0
        }
        fn remove_function(&mut self, _entry_point: &Address) -> bool {
            false
        }
        fn get_function_at(&self, _entry_point: &Address) -> Option<Arc<dyn Function>> {
            self.function_at_entry.clone()
        }
        fn get_referenced_function(&self, _address: &Address) -> Option<Arc<dyn Function>> {
            None
        }
        fn get_function_containing(&self, _addr: &Address) -> Option<Arc<dyn Function>> {
            None
        }
        fn get_functions(
            &self,
            _forward: bool,
        ) -> Box<dyn crate::program::model::listing::function_iterator::FunctionIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_functions_from(
            &self,
            _start: &Address,
            _forward: bool,
        ) -> Box<dyn crate::program::model::listing::function_iterator::FunctionIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_functions_in(
            &self,
            _asv: &dyn AddressSetView,
            _forward: bool,
        ) -> Box<dyn crate::program::model::listing::function_iterator::FunctionIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_functions_no_stubs(
            &self,
            _forward: bool,
        ) -> Box<dyn crate::program::model::listing::function_iterator::FunctionIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_functions_no_stubs_from(
            &self,
            _start: &Address,
            _forward: bool,
        ) -> Box<dyn crate::program::model::listing::function_iterator::FunctionIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_functions_no_stubs_in(
            &self,
            _asv: &dyn AddressSetView,
            _forward: bool,
        ) -> Box<dyn crate::program::model::listing::function_iterator::FunctionIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_external_functions(
            &self,
        ) -> Box<dyn crate::program::model::listing::function_iterator::FunctionIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn is_in_function(&self, _addr: &Address) -> bool {
            false
        }
        fn get_functions_overlapping(
            &self,
            _set: &dyn AddressSetView,
        ) -> Box<dyn crate::program::model::listing::function_iterator::FunctionIterator> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_referenced_variable(
            &self,
            _instr_addr: &Address,
            _storage_addr: &Address,
            _size: i32,
            _is_read: bool,
        ) -> Option<Box<dyn Variable>> {
            None
        }
        fn get_function(&self, _key: i64) -> Option<Arc<dyn Function>> {
            None
        }
        fn get_function_tag_manager(
            &self,
        ) -> Arc<dyn crate::program::model::listing::function_tag_manager::FunctionTagManager> {
            unimplemented!("not needed for this smoke test")
        }
    }

    struct MockProgram {
        function_manager: std::sync::Mutex<MockFunctionManager>,
        closed: bool,
    }

    impl DomainObject for MockProgram {
        fn is_closed(&self) -> bool {
            self.closed
        }
    }

    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock-program".to_string()
        }
        fn get_language_id(&self) -> String {
            "mock:LE:32:default".to_string()
        }
        fn get_function_manager(&mut self) -> Option<&mut dyn FunctionManager> {
            Some(self.function_manager.get_mut().unwrap())
        }
    }

    struct MockLocation {
        address: Address,
    }

    impl ProgramLocation for MockLocation {
        fn get_program(&self) -> Arc<dyn Program> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_address(&self) -> Address {
            self.address.clone()
        }
        fn get_byte_address(&self) -> Address {
            self.address.clone()
        }
    }

    struct MockController {
        model: Arc<dyn FGModel>,
    }

    impl FGController for MockController {
        fn get_model(&self) -> Arc<dyn FGModel> {
            self.model.clone()
        }
    }

    #[derive(Default)]
    struct RecordingModel {
        calls: AtomicUsize,
        last_message: std::sync::Mutex<Option<String>>,
    }

    impl FGModel for RecordingModel {
        fn set_function_graph_data(&self, _graph_runnable: &FunctionGraphRunnable, graph_data: &dyn FGData) {
            self.calls.fetch_add(1, Ordering::SeqCst);
            *self.last_message.lock().unwrap() = Some(graph_data.get_message());
        }
    }

    fn make_runnable(program: MockProgram, address: Address) -> (Arc<RecordingModel>, FunctionGraphRunnable) {
        let model = Arc::new(RecordingModel::default());
        let controller = Arc::new(MockController { model: model.clone() });
        let location = Arc::new(MockLocation { address });
        let runnable = FunctionGraphRunnable::new(controller, Arc::new(program), location);
        (model, runnable)
    }

    #[test]
    fn swing_run_cancelled_reports_cancelled_message() {
        let program = MockProgram {
            function_manager: std::sync::Mutex::new(MockFunctionManager { function_at_entry: None }),
            closed: false,
        };
        let (model, runnable) = make_runnable(program, addr(0x1000));

        runnable.swing_run(true);

        assert_eq!(model.calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            model.last_message.lock().unwrap().as_deref(),
            Some(format!("Graph cancelled for location: {}", addr(0x1000)).as_str())
        );
    }

    #[test]
    fn swing_run_closed_program_reports_closed_message() {
        let program = MockProgram {
            function_manager: std::sync::Mutex::new(MockFunctionManager { function_at_entry: None }),
            closed: true,
        };
        let (model, runnable) = make_runnable(program, addr(0x2000));

        runnable.swing_run(false);

        assert_eq!(
            model.last_message.lock().unwrap().as_deref(),
            Some(format!("Program closed: {}", addr(0x2000)).as_str())
        );
    }

    #[test]
    fn swing_run_with_no_prior_graph_data_reports_no_function_message() {
        let program = MockProgram {
            function_manager: std::sync::Mutex::new(MockFunctionManager { function_at_entry: None }),
            closed: false,
        };
        let (model, runnable) = make_runnable(program, addr(0x3000));

        runnable.swing_run(false);

        assert_eq!(
            model.last_message.lock().unwrap().as_deref(),
            Some(format!("No Function at {}", addr(0x3000)).as_str())
        );
    }

    #[test]
    fn monitored_run_with_no_function_reports_expected_message() {
        let program = MockProgram {
            function_manager: std::sync::Mutex::new(MockFunctionManager { function_at_entry: None }),
            closed: false,
        };
        let (_model, runnable) = make_runnable(program, addr(0x4000));

        let monitor = DummyMonitor;
        runnable.monitored_run(&monitor);

        runnable.swing_run(false);
    }

    #[test]
    fn contains_location_is_false_when_no_function_was_found() {
        let program = MockProgram {
            function_manager: std::sync::Mutex::new(MockFunctionManager { function_at_entry: None }),
            closed: false,
        };
        let (_model, runnable) = make_runnable(program, addr(0x5000));

        let other = MockLocation { address: addr(0x5000) };
        assert!(!runnable.contains_location(&other));
    }

    #[test]
    fn get_location_returns_constructor_location() {
        let program = MockProgram {
            function_manager: std::sync::Mutex::new(MockFunctionManager { function_at_entry: None }),
            closed: false,
        };
        let (_model, runnable) = make_runnable(program, addr(0x6000));

        assert_eq!(runnable.get_location().get_address(), addr(0x6000));
    }

    #[test]
    fn synthetic_undefined_function_name_matches_java_format() {
        struct EmptyProgram;
        impl DomainObject for EmptyProgram {}
        impl Program for EmptyProgram {
            fn get_name(&self) -> String {
                "p".to_string()
            }
            fn get_language_id(&self) -> String {
                "mock:LE:32:default".to_string()
            }
        }

        let f = SyntheticUndefinedFunction::new(Arc::new(EmptyProgram), addr(0x1000));
        assert_eq!(
            Function::get_name(&f),
            format!("UndefinedFunction_{}", addr(0x1000).format(false, 8))
        );
    }
}

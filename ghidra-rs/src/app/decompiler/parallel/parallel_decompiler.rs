//! Port of `ghidra.app.decompiler.parallel.ParallelDecompiler`.
//!
//! The Java class only ever holds statics (a thread-pool name constant plus factory functions
//! for driving decompilation across a [`ConcurrentQ`]), so it becomes a plain module instead of
//! a field-less struct.

use std::sync::Arc;

use crate::app::seam_stubs::ChunkingParallelDecompiler;
use crate::generic::concurrent::{ConcurrentQ, GThreadPool, QCallback};
use crate::program::model::address::AddressSetView;
use crate::program::model::listing::{Function, Program};
use crate::util::task::TaskMonitor;

/// Mirrors `ParallelDecompiler.THREAD_POOL_NAME`.
pub const THREAD_POOL_NAME: &str = "Parallel Decompiler";

/// Port of `ParallelDecompiler.decompileFunctions(QCallback, Program, AddressSetView,
/// TaskMonitor)`. Decompiles every function in `program` whose entry point falls within
/// `addresses`.
pub fn decompile_functions_in_address_set<R>(
    callback: Box<dyn QCallback<Arc<dyn Function>, R>>,
    program: &mut dyn Program,
    addresses: &dyn AddressSetView,
    monitor: &dyn TaskMonitor,
) -> anyhow::Result<Vec<R>>
where
    R: Send + Sync + 'static,
{
    let function_count = program
        .get_function_manager()
        .map(|fm| fm.get_function_count())
        .unwrap_or(0);
    let listing = program
        .get_listing()
        .ok_or_else(|| anyhow::anyhow!("program has no listing"))?;
    let iterator = listing.get_functions_in(addresses, true);

    do_decompile_functions(callback, iterator, function_count as i64, monitor)
}

/// Port of `ParallelDecompiler.decompileFunctions(QCallback, Collection<Function>,
/// TaskMonitor)`. Decompiles the given functions.
pub fn decompile_functions<R>(
    callback: Box<dyn QCallback<Arc<dyn Function>, R>>,
    functions: Vec<Arc<dyn Function>>,
    monitor: &dyn TaskMonitor,
) -> anyhow::Result<Vec<R>>
where
    R: Send + Sync + 'static,
{
    let count = functions.len() as i64;
    do_decompile_functions(callback, functions.into_iter(), count, monitor)
}

/// Port of `ParallelDecompiler.decompileFunctions(QCallback, Program, Iterator<Function>,
/// Consumer<R>, TaskMonitor)`. Results are handed to `results_consumer` once every function has
/// been decompiled -- the Java doc for this overload notes it "will wait for all processing
/// before returning", so there is no streaming behavior lost by delivering results in a batch
/// here.
pub fn decompile_functions_streaming<R>(
    callback: Box<dyn QCallback<Arc<dyn Function>, R>>,
    program: &mut dyn Program,
    functions: impl Iterator<Item = Arc<dyn Function>>,
    mut results_consumer: impl FnMut(R),
    monitor: &dyn TaskMonitor,
) -> anyhow::Result<()>
where
    R: Send + Sync + 'static,
{
    let max = program
        .get_function_manager()
        .map(|fm| fm.get_function_count())
        .unwrap_or(0);

    let thread_pool = GThreadPool::get_shared_thread_pool(THREAD_POOL_NAME);
    let collect_results = false;
    let queue = ConcurrentQ::new(callback, thread_pool, 0, collect_results, false);

    monitor.initialize(max as i64);
    queue.add_all(functions.collect());
    queue.wait_until_done();

    for q_result in queue.wait_for_results() {
        if let Some(result) = q_result.result {
            results_consumer(result);
        }
    }

    Ok(())
}

fn do_decompile_functions<R>(
    callback: Box<dyn QCallback<Arc<dyn Function>, R>>,
    functions: impl Iterator<Item = Arc<dyn Function>>,
    count: i64,
    monitor: &dyn TaskMonitor,
) -> anyhow::Result<Vec<R>>
where
    R: Send + Sync + 'static,
{
    let thread_pool = GThreadPool::get_shared_thread_pool(THREAD_POOL_NAME);
    let queue = ConcurrentQ::new(callback, thread_pool, 0, true, false);

    monitor.initialize(count);
    queue.add_all(functions.collect());

    let q_results = queue.wait_for_results();

    let mut results = Vec::with_capacity(q_results.len());
    for q_result in q_results {
        if let Some(result) = q_result.result {
            results.push(result);
        }
    }

    Ok(results)
}

/// Port of `ParallelDecompiler.createChunkingParallelDecompiler(QCallback, TaskMonitor)`.
pub fn create_chunking_parallel_decompiler<R>(
    callback: Box<dyn QCallback<Arc<dyn Function>, R>>,
    monitor: &dyn TaskMonitor,
) -> ChunkingParallelDecompiler<R>
where
    R: Send + Sync + 'static,
{
    ChunkingParallelDecompiler::new(callback, monitor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::listing::function::{FunctionEditError, SetFunctionNameError};
    use crate::program::model::listing::{
        FunctionSignature, FunctionTag, FunctionUpdateType, Parameter, Variable,
    };
    use crate::program::model::symbol::{ExternalLocation, Namespace, SourceType, Symbol};
    use crate::program::model::lang::prototype_model::PrototypeModel;
    use crate::program::seam_stubs::{StackFrame, VariableFilter};
    use crate::program::model::listing::variable_storage::VariableStorage;
    use crate::program::database::function::OverlappingFunctionException;
    use crate::util::exception::InvalidInputException;
    use crate::util::task::DummyMonitor;

    fn mock_address(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    struct MockFunction(i32);

    impl Namespace for MockFunction {
        fn get_symbol(&self) -> Arc<dyn Symbol> {
            unimplemented!("not needed for this smoke test")
        }

        fn get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
            None
        }
    }

    impl Function for MockFunction {
        fn get_name(&self) -> String {
            format!("mock{}", self.0)
        }

        fn set_name(&mut self, _name: &str, _source: SourceType) -> Result<(), SetFunctionNameError> {
            Ok(())
        }

        fn set_call_fixup(&mut self, _name: Option<&str>) {}

        fn get_call_fixup(&self) -> Option<String> {
            None
        }

        fn get_program(&self) -> Arc<dyn Program> {
            unimplemented!("not needed for this smoke test")
        }

        fn get_comment(&self) -> Option<String> {
            None
        }

        fn get_comment_as_array(&self) -> Vec<String> {
            Vec::new()
        }

        fn set_comment(&mut self, _comment: Option<&str>) {}

        fn get_repeatable_comment(&self) -> Option<String> {
            None
        }

        fn get_repeatable_comment_as_array(&self) -> Vec<String> {
            Vec::new()
        }

        fn set_repeatable_comment(&mut self, _comment: Option<&str>) {}

        fn get_entry_point(&self) -> Address {
            mock_address(0x100 + self.0 as i64)
        }

        fn get_return_type(&self) -> Option<Box<dyn DataType>> {
            None
        }

        fn set_return_type(
            &mut self,
            _data_type: Box<dyn DataType>,
            _source: SourceType,
        ) -> Result<(), InvalidInputException> {
            Ok(())
        }

        fn get_return(&self) -> Box<dyn Parameter> {
            unimplemented!("not needed for this smoke test")
        }

        fn set_return(
            &mut self,
            _data_type: Box<dyn DataType>,
            _storage: Box<dyn VariableStorage>,
            _source: SourceType,
        ) -> Result<(), InvalidInputException> {
            Ok(())
        }

        fn get_signature_formal(&self, _formal_signature: bool) -> Box<dyn FunctionSignature> {
            unimplemented!("not needed for this smoke test")
        }

        fn get_prototype_string(
            &self,
            _formal_signature: bool,
            _include_calling_convention: bool,
        ) -> String {
            String::new()
        }

        fn get_signature_source(&self) -> SourceType {
            SourceType::UserDefined
        }

        fn set_signature_source(&mut self, _signature_source: SourceType) {}

        fn get_stack_frame(&self) -> Box<dyn StackFrame> {
            unimplemented!("not needed for this smoke test")
        }

        fn get_stack_purge_size(&self) -> i32 {
            0
        }

        fn get_tags(&self) -> Vec<Box<dyn FunctionTag>> {
            Vec::new()
        }

        fn add_tag(&mut self, _name: &str) -> bool {
            true
        }

        fn remove_tag(&mut self, _name: &str) {}

        fn set_stack_purge_size(&mut self, _purge_size: i32) {}

        fn is_stack_purge_size_valid(&self) -> bool {
            true
        }

        #[allow(deprecated)]
        fn add_parameter(
            &mut self,
            _var: Box<dyn Variable>,
            _source: SourceType,
        ) -> Result<Box<dyn Parameter>, FunctionEditError> {
            unimplemented!("not needed for this smoke test")
        }

        #[allow(deprecated)]
        fn insert_parameter(
            &mut self,
            _ordinal: i32,
            _var: Box<dyn Variable>,
            _source: SourceType,
        ) -> Result<Box<dyn Parameter>, FunctionEditError> {
            unimplemented!("not needed for this smoke test")
        }

        fn replace_parameters(
            &mut self,
            _params: Vec<Box<dyn Variable>>,
            _update_type: FunctionUpdateType,
            _force: bool,
            _source: SourceType,
        ) -> Result<(), FunctionEditError> {
            Ok(())
        }

        fn update_function(
            &mut self,
            _calling_convention: Option<&str>,
            _return_value: Option<Box<dyn Variable>>,
            _new_params: Vec<Box<dyn Variable>>,
            _update_type: FunctionUpdateType,
            _force: bool,
            _source: SourceType,
        ) -> Result<(), FunctionEditError> {
            Ok(())
        }

        fn get_parameter(&self, _ordinal: i32) -> Option<Box<dyn Parameter>> {
            None
        }

        #[allow(deprecated)]
        fn remove_parameter(&mut self, _ordinal: i32) {}

        #[allow(deprecated)]
        fn move_parameter(
            &mut self,
            _from_ordinal: i32,
            _to_ordinal: i32,
        ) -> Result<Box<dyn Parameter>, InvalidInputException> {
            unimplemented!("not needed for this smoke test")
        }

        fn get_parameter_count(&self) -> i32 {
            0
        }

        fn get_auto_parameter_count(&self) -> i32 {
            0
        }

        fn get_parameters(&self) -> Vec<Box<dyn Parameter>> {
            Vec::new()
        }

        fn get_parameters_filtered(
            &self,
            _filter: Option<&dyn VariableFilter>,
        ) -> Vec<Box<dyn Parameter>> {
            Vec::new()
        }

        fn get_local_variables(&self) -> Vec<Box<dyn Variable>> {
            Vec::new()
        }

        fn get_local_variables_filtered(
            &self,
            _filter: Option<&dyn VariableFilter>,
        ) -> Vec<Box<dyn Variable>> {
            Vec::new()
        }

        fn get_variables_filtered(
            &self,
            _filter: Option<&dyn VariableFilter>,
        ) -> Vec<Box<dyn Variable>> {
            Vec::new()
        }

        fn get_all_variables(&self) -> Vec<Box<dyn Variable>> {
            Vec::new()
        }

        fn add_local_variable(
            &mut self,
            _var: Box<dyn Variable>,
            _source: SourceType,
        ) -> Result<Box<dyn Variable>, FunctionEditError> {
            unimplemented!("not needed for this smoke test")
        }

        fn remove_variable(&mut self, _var: &dyn Variable) {}

        fn set_body(
            &mut self,
            _new_body: &dyn AddressSetView,
        ) -> Result<(), OverlappingFunctionException> {
            Ok(())
        }

        fn has_var_args(&self) -> bool {
            false
        }

        fn set_var_args(&mut self, _has_var_args: bool) {}

        fn is_inline(&self) -> bool {
            false
        }

        fn set_inline(&mut self, _is_inline: bool) {}

        fn has_no_return(&self) -> bool {
            false
        }

        fn set_no_return(&mut self, _has_no_return: bool) {}

        fn has_custom_variable_storage(&self) -> bool {
            false
        }

        fn set_custom_variable_storage(&mut self, _has_custom_variable_storage: bool) {}

        fn get_calling_convention(&self) -> Option<Box<dyn PrototypeModel>> {
            None
        }

        fn get_calling_convention_name(&self) -> String {
            "unknown".to_string()
        }

        fn set_calling_convention(&mut self, _name: &str) -> Result<(), InvalidInputException> {
            Ok(())
        }

        fn is_thunk(&self) -> bool {
            false
        }

        fn get_thunked_function(&self, _recursive: bool) -> Option<Arc<dyn Function>> {
            None
        }

        fn get_function_thunk_addresses(&self, _recursive: bool) -> Option<Vec<Address>> {
            None
        }

        fn set_thunked_function(
            &mut self,
            _thunked_function: Option<Arc<dyn Function>>,
        ) -> Result<(), String> {
            Ok(())
        }

        fn is_external(&self) -> bool {
            false
        }

        fn get_external_location(&self) -> Option<Box<dyn ExternalLocation>> {
            None
        }

        fn get_calling_functions(&self, _monitor: &dyn TaskMonitor) -> Vec<Arc<dyn Function>> {
            Vec::new()
        }

        fn get_called_functions(&self, _monitor: &dyn TaskMonitor) -> Vec<Arc<dyn Function>> {
            Vec::new()
        }

        fn promote_local_user_labels_to_global(&mut self) {}

        fn is_deleted(&self) -> bool {
            false
        }
    }

    struct DoublingCallback;

    impl QCallback<Arc<dyn Function>, i32> for DoublingCallback {
        fn process(
            &self,
            item: Arc<dyn Function>,
            _monitor: &dyn TaskMonitor,
        ) -> Result<i32, anyhow::Error> {
            Ok(item.get_entry_point().offset() as i32 * 2)
        }
    }

    #[test]
    fn decompile_functions_processes_every_function() {
        let functions: Vec<Arc<dyn Function>> = vec![
            Arc::new(MockFunction(1)),
            Arc::new(MockFunction(2)),
            Arc::new(MockFunction(3)),
        ];
        let monitor = DummyMonitor;

        let mut results =
            decompile_functions(Box::new(DoublingCallback), functions, &monitor).unwrap();
        results.sort();

        // entry points are 0x101, 0x102, 0x103 -- doubled by the callback.
        assert_eq!(results, vec![0x202, 0x204, 0x206]);
    }
}

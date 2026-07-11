use std::collections::HashMap;
use std::fmt::{self, Write as _};
use std::sync::{Arc, Mutex, OnceLock};

use crate::program::model::listing::Function;
use crate::util::msg::Msg;

/// A wrapper for `Arc<dyn Function>` that implements `Hash` and `Eq` based on pointer identity.
/// This allows `Arc<dyn Function>` to be used as a `HashMap` key.
struct FunctionKey(Arc<dyn Function>);

impl PartialEq for FunctionKey {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for FunctionKey {}

impl std::hash::Hash for FunctionKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        let ptr = Arc::as_ptr(&self.0) as *const () as usize;
        ptr.hash(state);
    }
}

#[derive(Default)]
struct DtrfDbgState {
    is_enabled: bool,
    client_filters: Vec<String>,
    lines_by_function: HashMap<FunctionKey, Vec<String>>,
}

fn state() -> &'static Mutex<DtrfDbgState> {
    static STATE: OnceLock<Mutex<DtrfDbgState>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(DtrfDbgState::default()))
}

/// A package utility class to allow for tests to selectively enable debug output. This class is
/// used instead of generic logging with the intent that this class will be removed when the
/// bug(s) are fixed.
///
/// Until [`DtrfDbg::enable`] is called, no data is recorded. Once enabled, all messages are
/// buffered until a call to [`DtrfDbg::disable`] is made.
///
/// Mirrors `ghidra.app.extension.datatype.finder.DtrfDbg`.
pub(crate) struct DtrfDbg;

impl DtrfDbg {
    /// Enables buffering of debug messages, discarding any messages buffered from a prior
    /// session.
    pub(crate) fn enable() {
        let mut state = state().lock().unwrap();
        state.is_enabled = true;
        state.lines_by_function.clear();
    }

    fn close(state: &mut DtrfDbgState) {
        state.is_enabled = false;
        state.lines_by_function.clear();
    }

    /// Stops buffering debug messages. If `write` is `true`, the buffered messages are grouped
    /// by function and logged via [`Msg::debug`]; otherwise they are discarded.
    pub(crate) fn disable(write: bool) {
        let mut state = state().lock().unwrap();

        if !write {
            Self::close(&mut state);
            return;
        }

        let mut output = String::new();
        for (function, lines) in state.lines_by_function.iter() {
            let _ = writeln!(output, "\n\nFunction Debug: {}", Function::get_name(&*function.0));
            for line in lines {
                let _ = writeln!(output, "{line}");
            }
        }

        if !output.trim().is_empty() {
            Msg::debug("DtrfDbg", &format!("\n\nFinal Debug:\n{output}"));
        }

        Self::close(&mut state);
    }

    /// Sets filters that will be checked against the `to_string()` of each client. The filtering
    /// is a case-sensitive 'contains' check.
    pub(crate) fn set_client_to_string_filters(filters: &[&str]) {
        let mut state = state().lock().unwrap();
        state.client_filters = filters.iter().map(|s| s.to_string()).collect();
    }

    /// Stores a message to later be printed.
    pub(crate) fn println(f: &Arc<dyn Function>, s: &str) {
        let mut state = state().lock().unwrap();
        if !state.is_enabled {
            return;
        }

        let key = FunctionKey(Arc::clone(f));
        state.lines_by_function.entry(key).or_default().push(s.to_string());
    }

    /// Stores a message to later be printed, filtering messages based on the `client` parameter.
    ///
    /// See [`DtrfDbg::set_client_to_string_filters`].
    pub(crate) fn println_for_client(f: &Arc<dyn Function>, client: Option<&dyn fmt::Display>, s: &str) {
        let mut state = state().lock().unwrap();
        if !state.is_enabled {
            return;
        }

        if !Self::passes_filter(&state.client_filters, client) {
            return;
        }

        let key = FunctionKey(Arc::clone(f));
        state.lines_by_function.entry(key).or_default().push(s.to_string());
    }

    fn passes_filter(client_filters: &[String], client: Option<&dyn fmt::Display>) -> bool {
        let Some(client) = client else {
            return true;
        };

        if client_filters.is_empty() {
            return true;
        }

        let as_string = client.to_string();
        client_filters.iter().any(|s| as_string.contains(s.as_str()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::listing::function::{FunctionEditError, SetFunctionNameError};
    use crate::program::model::listing::{
        FunctionSignature, FunctionTag, FunctionUpdateType, Parameter, Program, Variable,
    };
    use crate::program::model::symbol::{ExternalLocation, Namespace, SourceType, Symbol};
    use crate::program::seam_stubs::{PrototypeModel, StackFrame, VariableFilter, VariableStorage};
    use crate::program::database::function::OverlappingFunctionException;
    use crate::program::model::address::AddressSetView;
    use crate::util::exception::InvalidInputException;
    use crate::util::task::TaskMonitor;

    struct MockFunction {
        name: String,
    }

    impl MockFunction {
        fn new(name: &str) -> Arc<dyn Function> {
            Arc::new(Self { name: name.to_string() })
        }
    }

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
            self.name.clone()
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
            let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
            Address::new(space, 0x100)
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

        fn get_prototype_string(&self, _formal_signature: bool, _include_calling_convention: bool) -> String {
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

        fn get_parameters_filtered(&self, _filter: Option<&dyn VariableFilter>) -> Vec<Box<dyn Parameter>> {
            Vec::new()
        }

        fn get_local_variables(&self) -> Vec<Box<dyn Variable>> {
            Vec::new()
        }

        fn get_local_variables_filtered(&self, _filter: Option<&dyn VariableFilter>) -> Vec<Box<dyn Variable>> {
            Vec::new()
        }

        fn get_variables_filtered(&self, _filter: Option<&dyn VariableFilter>) -> Vec<Box<dyn Variable>> {
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

        fn set_body(&mut self, _new_body: &dyn AddressSetView) -> Result<(), OverlappingFunctionException> {
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
            String::from("unknown")
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

        fn set_thunked_function(&mut self, _thunked_function: Option<Arc<dyn Function>>) -> Result<(), String> {
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

    /// Serializes access to the global `DtrfDbg` state across tests, since `cargo test` runs
    /// tests in the same process concurrently by default.
    fn lock_dtrf_dbg_tests() -> std::sync::MutexGuard<'static, ()> {
        static TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        TEST_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
    }

    #[test]
    fn println_before_enable_is_discarded() {
        let _guard = lock_dtrf_dbg_tests();
        DtrfDbg::disable(false);

        let f = MockFunction::new("before_enable");
        DtrfDbg::println(&f, "should be dropped");
        DtrfDbg::enable();
        assert!(state().lock().unwrap().lines_by_function.is_empty());
        DtrfDbg::disable(false);
    }

    #[test]
    fn println_after_enable_is_buffered() {
        let _guard = lock_dtrf_dbg_tests();
        DtrfDbg::enable();

        let f = MockFunction::new("my_function");
        DtrfDbg::println(&f, "line one");
        DtrfDbg::println(&f, "line two");

        {
            let state = state().lock().unwrap();
            let key = FunctionKey(Arc::clone(&f));
            let lines = state.lines_by_function.get(&key).expect("function should have buffered lines");
            assert_eq!(lines, &vec!["line one".to_string(), "line two".to_string()]);
        }

        DtrfDbg::disable(false);
    }

    #[test]
    fn disable_without_write_discards_buffered_lines() {
        let _guard = lock_dtrf_dbg_tests();
        DtrfDbg::enable();

        let f = MockFunction::new("discarded_function");
        DtrfDbg::println(&f, "will be discarded");

        DtrfDbg::disable(false);

        assert!(!state().lock().unwrap().is_enabled);
        assert!(state().lock().unwrap().lines_by_function.is_empty());
    }

    #[test]
    fn disable_with_write_clears_state_after_flush() {
        let _guard = lock_dtrf_dbg_tests();
        DtrfDbg::enable();

        let f = MockFunction::new("flushed_function");
        DtrfDbg::println(&f, "flushed line");

        DtrfDbg::disable(true);

        let state = state().lock().unwrap();
        assert!(!state.is_enabled);
        assert!(state.lines_by_function.is_empty());
    }

    #[test]
    fn println_for_client_without_filters_is_buffered() {
        let _guard = lock_dtrf_dbg_tests();
        DtrfDbg::enable();
        DtrfDbg::set_client_to_string_filters(&[]);

        let f = MockFunction::new("no_filter_function");
        DtrfDbg::println_for_client(&f, Some(&"AnyClient"), "line");

        let state = state().lock().unwrap();
        let key = FunctionKey(Arc::clone(&f));
        assert_eq!(state.lines_by_function.get(&key), Some(&vec!["line".to_string()]));
        drop(state);

        DtrfDbg::disable(false);
    }

    #[test]
    fn println_for_client_with_null_client_always_passes_filter() {
        let _guard = lock_dtrf_dbg_tests();
        DtrfDbg::enable();
        DtrfDbg::set_client_to_string_filters(&["SomeFilter"]);

        let f = MockFunction::new("null_client_function");
        DtrfDbg::println_for_client(&f, None, "line");

        let state = state().lock().unwrap();
        let key = FunctionKey(Arc::clone(&f));
        assert_eq!(state.lines_by_function.get(&key), Some(&vec!["line".to_string()]));
        drop(state);

        DtrfDbg::set_client_to_string_filters(&[]);
        DtrfDbg::disable(false);
    }

    #[test]
    fn println_for_client_filters_out_non_matching_clients() {
        let _guard = lock_dtrf_dbg_tests();
        DtrfDbg::enable();
        DtrfDbg::set_client_to_string_filters(&["Wanted"]);

        let f = MockFunction::new("filtered_function");
        DtrfDbg::println_for_client(&f, Some(&"UnwantedClient"), "dropped");
        DtrfDbg::println_for_client(&f, Some(&"WantedClient"), "kept");

        let state = state().lock().unwrap();
        let key = FunctionKey(Arc::clone(&f));
        assert_eq!(state.lines_by_function.get(&key), Some(&vec!["kept".to_string()]));
        drop(state);

        DtrfDbg::set_client_to_string_filters(&[]);
        DtrfDbg::disable(false);
    }

    #[test]
    fn function_key_identity_distinguishes_same_named_functions() {
        let a = MockFunction::new("dup");
        let b = MockFunction::new("dup");

        let key_a = FunctionKey(Arc::clone(&a));
        let key_a_again = FunctionKey(Arc::clone(&a));
        let key_b = FunctionKey(Arc::clone(&b));

        assert!(key_a == key_a_again);
        assert!(key_a != key_b);
    }
}

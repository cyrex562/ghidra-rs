//! Port of `ghidra.app.cmd.function.CreateFunctionCmd`.
//!
//! Command for creating a function at an address. It copies off the parameters used to create
//! the function (entry point(s)/selection or just an address) and (in the real Java class)
//! creates the function on redo and clears it on undo.
//!
//! The Java class `extends BackgroundCommand<Program>` and, in its private `resolveThunk` /
//! static `resolveThunk` helpers, constructs and applies a `CreateThunkFunctionCmd` -- which in
//! turn constructs a `CreateFunctionCmd` (see its package-private
//! `CreateThunkFunctionCmd -> createFunctionForThunk` path) to create the function a thunk
//! refers to. That mutual construction is a genuine dependency cycle between the two classes, so
//! `CreateFunctionCmd` was promoted to a trait (rather than a concrete struct) to cut it, the same
//! convention already followed by
//! [`HighParamID`](crate::program::model::pcode::high_param_id::HighParamID) and
//! [`ParamEntry`](crate::program::model::lang::param_entry::ParamEntry).
//!
//! Not ported here:
//! - The nine constructors, a construction-time detail for a concrete implementation, not part of
//!   the dynamic-dispatch surface this trait exists to cut the cycle for (the same convention
//!   already followed by
//!   [`FunctionPrototype`](crate::program::model::pcode::function_prototype::FunctionPrototype)
//!   and [`HighParamID`](crate::program::model::pcode::high_param_id::HighParamID)).
//! - The private instance helpers `createFunction(...)` (both overloads),
//!   `handleExistingFunction`, `resolveThunk(Address, AddressSetView, TaskMonitor)`, and
//!   `findFunctionEntry`, and the private static helpers `subtractBodyFromExisting` and
//!   `restoreOriginalBodies`: none of these are part of `CreateFunctionCmd`'s public API, and a
//!   concrete implementor has direct access to its own fields/collaborators to implement
//!   `apply_to` in terms of them once `CreateThunkFunctionCmd` is itself ported.
//! - The public static utility methods `getFunctionBody` (four overloads) and
//!   `fixupFunctionBody` (two overloads): unlike `applyTo`/`getFunction`, these have no receiver
//!   to dispatch on (they don't read or write `this`), so they aren't part of the polymorphic
//!   surface a trait models -- the same reasoning already used to exclude
//!   `HighParamID.getErrorHandler(Object, String)`. Their Java bodies also depend on
//!   `ghidra.program.model.block.FollowFlow`, which is not ported yet either. A concrete
//!   implementation of this trait (or free functions alongside it) can carry them once
//!   `FollowFlow` exists.
//!
//! [`CreateFunctionCmd::apply_to`] is declared with the real Java `applyTo(Program, TaskMonitor)`
//! signature but left as a required method with no default body: its Java body is the
//! multi-branch entry-point/body/thunk-resolution algorithm described above, which calls the
//! not-yet-ported `CreateThunkFunctionCmd` and `FollowFlow`. A concrete implementor can provide it
//! precisely once those are ported (the same convention already followed by
//! [`HighParamID::decode`](crate::program::model::pcode::high_param_id::HighParamID::decode)).

use std::sync::Arc;

use crate::program::model::listing::{Function, Program};
use crate::util::task::TaskMonitor;

/// Command for creating a function at an address.
///
/// Port of `ghidra.app.cmd.function.CreateFunctionCmd`. See the module docs for what was
/// intentionally left out of this trait.
pub trait CreateFunctionCmd {
    /// Applies this command, creating (or updating) a function in `program`.
    ///
    /// Returns `true` if a function was created (or already existed) for every requested entry
    /// point. See the module docs for why this has no default body.
    ///
    /// Port of `CreateFunctionCmd.applyTo(Program, TaskMonitor)`.
    fn apply_to(&mut self, program: &mut dyn Program, monitor: &dyn TaskMonitor) -> bool;

    /// Returns the last function created by [`CreateFunctionCmd::apply_to`], or `None` if
    /// `apply_to` has not yet run or failed (mirroring the Java field `newFunc`, which starts out
    /// `null`).
    ///
    /// Port of `CreateFunctionCmd.getFunction()`.
    fn get_function(&self) -> Option<Arc<dyn Function>> {
        None
    }

    /// Returns the status message describing why [`CreateFunctionCmd::apply_to`] failed (set
    /// internally via the inherited `BackgroundCommand.setStatusMsg`), or `None` before `apply_to`
    /// runs or when it succeeds.
    ///
    /// Port of the inherited `BackgroundCommand.getStatusMsg()`, which `CreateFunctionCmd.applyTo`
    /// calls directly (via `setStatusMsg`) to report per-entry failures.
    fn status_msg(&self) -> Option<String> {
        None
    }

    /// Returns this command's name, always `"Create Function"` (every Java constructor passes
    /// this literal to `super(...)`).
    ///
    /// Port of the inherited `BackgroundCommand.getName()`.
    fn name(&self) -> String {
        "Create Function".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc as StdArc;
    use std::sync::Mutex;

    use crate::framework::model::DomainObject;
    use crate::program::database::function::OverlappingFunctionException;
    use crate::program::model::address::{
        Address, AddressSet, AddressSetView, AddressSpace, AddressSpaceType,
    };
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::lang::prototype_model::PrototypeModel;
    use crate::program::model::listing::function::{
        FunctionEditError, FunctionUpdateType, SetFunctionNameError,
    };
    use crate::program::model::listing::{
        CreateFunctionError, FunctionManager, FunctionSignature, FunctionTag, Parameter, Variable,
    };
    use crate::program::model::symbol::{ExternalLocation, Namespace, SourceType};
    use crate::program::seam_stubs::{StackFrame, VariableFilter, VariableStorage};
    use crate::util::exception::InvalidInputException;
    use crate::util::task::DummyMonitor;

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    #[allow(dead_code)]
    struct MockFunction {
        entry_point: Address,
        name_value: String,
    }

    impl Namespace for MockFunction {
        fn get_symbol(&self) -> StdArc<dyn crate::program::model::symbol::Symbol> {
            unimplemented!()
        }
        fn get_parent_namespace(&self) -> Option<StdArc<dyn Namespace>> {
            None
        }
    }

    impl Function for MockFunction {
        fn get_name(&self) -> String {
            self.name_value.clone()
        }
        fn set_name(&mut self, name: &str, _source: SourceType) -> Result<(), SetFunctionNameError> {
            self.name_value = name.to_string();
            Ok(())
        }
        fn set_call_fixup(&mut self, _name: Option<&str>) {}
        fn get_call_fixup(&self) -> Option<String> {
            None
        }
        fn get_program(&self) -> StdArc<dyn Program> {
            unimplemented!()
        }
        fn get_comment(&self) -> Option<String> {
            None
        }
        fn get_comment_as_array(&self) -> Vec<String> {
            vec![]
        }
        fn set_comment(&mut self, _comment: Option<&str>) {}
        fn get_repeatable_comment(&self) -> Option<String> {
            None
        }
        fn get_repeatable_comment_as_array(&self) -> Vec<String> {
            vec![]
        }
        fn set_repeatable_comment(&mut self, _comment: Option<&str>) {}
        fn get_entry_point(&self) -> Address {
            self.entry_point.clone()
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
            unimplemented!()
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
            unimplemented!()
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
            unimplemented!()
        }
        fn get_stack_purge_size(&self) -> i32 {
            0
        }
        fn get_tags(&self) -> Vec<Box<dyn FunctionTag>> {
            vec![]
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
            unimplemented!()
        }
        #[allow(deprecated)]
        fn insert_parameter(
            &mut self,
            _ordinal: i32,
            _var: Box<dyn Variable>,
            _source: SourceType,
        ) -> Result<Box<dyn Parameter>, FunctionEditError> {
            unimplemented!()
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
            unimplemented!()
        }
        fn get_parameter_count(&self) -> i32 {
            0
        }
        fn get_auto_parameter_count(&self) -> i32 {
            0
        }
        fn get_parameters(&self) -> Vec<Box<dyn Parameter>> {
            vec![]
        }
        fn get_parameters_filtered(
            &self,
            _filter: Option<&dyn VariableFilter>,
        ) -> Vec<Box<dyn Parameter>> {
            vec![]
        }
        fn get_local_variables(&self) -> Vec<Box<dyn Variable>> {
            vec![]
        }
        fn get_local_variables_filtered(
            &self,
            _filter: Option<&dyn VariableFilter>,
        ) -> Vec<Box<dyn Variable>> {
            vec![]
        }
        fn get_variables_filtered(
            &self,
            _filter: Option<&dyn VariableFilter>,
        ) -> Vec<Box<dyn Variable>> {
            vec![]
        }
        fn get_all_variables(&self) -> Vec<Box<dyn Variable>> {
            vec![]
        }
        fn add_local_variable(
            &mut self,
            _var: Box<dyn Variable>,
            _source: SourceType,
        ) -> Result<Box<dyn Variable>, FunctionEditError> {
            unimplemented!()
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
        fn get_thunked_function(&self, _recursive: bool) -> Option<StdArc<dyn Function>> {
            None
        }
        fn get_function_thunk_addresses(&self, _recursive: bool) -> Option<Vec<Address>> {
            None
        }
        fn set_thunked_function(
            &mut self,
            _thunked_function: Option<StdArc<dyn Function>>,
        ) -> Result<(), String> {
            Ok(())
        }
        fn is_external(&self) -> bool {
            false
        }
        fn get_external_location(&self) -> Option<Box<dyn ExternalLocation>> {
            None
        }
        fn get_calling_functions(&self, _monitor: &dyn TaskMonitor) -> Vec<StdArc<dyn Function>> {
            vec![]
        }
        fn get_called_functions(&self, _monitor: &dyn TaskMonitor) -> Vec<StdArc<dyn Function>> {
            vec![]
        }
        fn promote_local_user_labels_to_global(&mut self) {}
        fn is_deleted(&self) -> bool {
            false
        }
    }

    /// Minimal [`FunctionManager`] backing the smoke test: real, mutable function storage so
    /// [`CreateFunctionCmd::apply_to`] can be exercised against `create_function`/`get_function_at`
    /// like the real Java `createFunction` private helper does.
    struct MockFunctionManager {
        functions: Mutex<Vec<StdArc<dyn Function>>>,
    }

    impl crate::program::database::manager_db::ManagerDB for MockFunctionManager {
        fn invalidate_cache(&mut self, _all: bool) -> std::io::Result<()> {
            Ok(())
        }
        fn delete_address_range(&mut self, _start: &Address, _end: &Address) -> std::io::Result<()> {
            Ok(())
        }
        fn move_address_range(
            &mut self,
            _from: &Address,
            _to: &Address,
            _length: u64,
        ) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl FunctionManager for MockFunctionManager {
        fn get_program(&self) -> StdArc<dyn Program> {
            unimplemented!()
        }
        fn get_calling_convention_names(&self) -> Vec<String> {
            vec![]
        }
        fn get_default_calling_convention(&self) -> Option<Box<dyn PrototypeModel>> {
            None
        }
        fn get_calling_convention(&self, _name: &str) -> Option<Box<dyn PrototypeModel>> {
            None
        }
        fn create_function(
            &mut self,
            name: Option<&str>,
            entry_point: Address,
            _body: &dyn AddressSetView,
            _source: SourceType,
        ) -> Result<StdArc<dyn Function>, CreateFunctionError> {
            let mut functions = self.functions.lock().unwrap();
            if functions.iter().any(|f| f.get_entry_point() == entry_point) {
                return Err(CreateFunctionError::Overlapping(OverlappingFunctionException::new(
                    format!("function already exists at {entry_point}"),
                )));
            }
            let function: StdArc<dyn Function> = StdArc::new(MockFunction {
                entry_point,
                name_value: name.unwrap_or("FUN").to_string(),
            });
            functions.push(function.clone());
            Ok(function)
        }
        fn create_function_in_namespace(
            &mut self,
            _name: Option<&str>,
            _name_space: StdArc<dyn crate::program::model::symbol::Namespace>,
            _entry_point: Address,
            _body: &dyn AddressSetView,
            _source: SourceType,
        ) -> Result<StdArc<dyn Function>, CreateFunctionError> {
            unimplemented!()
        }
        fn create_thunk_function(
            &mut self,
            _name: Option<&str>,
            _name_space: StdArc<dyn crate::program::model::symbol::Namespace>,
            _entry_point: Address,
            _body: &dyn AddressSetView,
            _thunked_function: StdArc<dyn Function>,
            _source: SourceType,
        ) -> Result<StdArc<dyn Function>, OverlappingFunctionException> {
            unimplemented!()
        }
        fn get_function_count(&self) -> usize {
            self.functions.lock().unwrap().len()
        }
        fn remove_function(&mut self, _entry_point: &Address) -> bool {
            false
        }
        fn get_function_at(&self, entry_point: &Address) -> Option<StdArc<dyn Function>> {
            self.functions
                .lock()
                .unwrap()
                .iter()
                .find(|f| f.get_entry_point() == *entry_point)
                .cloned()
        }
        fn get_referenced_function(&self, _address: &Address) -> Option<StdArc<dyn Function>> {
            None
        }
        fn get_function_containing(&self, _addr: &Address) -> Option<StdArc<dyn Function>> {
            None
        }
        fn get_functions(&self, _forward: bool) -> Box<dyn crate::program::model::listing::FunctionIterator> {
            crate::program::model::listing::function_iterator::empty()
        }
        fn get_functions_from(
            &self,
            _start: &Address,
            _forward: bool,
        ) -> Box<dyn crate::program::model::listing::FunctionIterator> {
            crate::program::model::listing::function_iterator::empty()
        }
        fn get_functions_in(
            &self,
            _asv: &dyn AddressSetView,
            _forward: bool,
        ) -> Box<dyn crate::program::model::listing::FunctionIterator> {
            crate::program::model::listing::function_iterator::empty()
        }
        fn get_functions_no_stubs(
            &self,
            _forward: bool,
        ) -> Box<dyn crate::program::model::listing::FunctionIterator> {
            crate::program::model::listing::function_iterator::empty()
        }
        fn get_functions_no_stubs_from(
            &self,
            _start: &Address,
            _forward: bool,
        ) -> Box<dyn crate::program::model::listing::FunctionIterator> {
            crate::program::model::listing::function_iterator::empty()
        }
        fn get_functions_no_stubs_in(
            &self,
            _asv: &dyn AddressSetView,
            _forward: bool,
        ) -> Box<dyn crate::program::model::listing::FunctionIterator> {
            crate::program::model::listing::function_iterator::empty()
        }
        fn get_external_functions(&self) -> Box<dyn crate::program::model::listing::FunctionIterator> {
            crate::program::model::listing::function_iterator::empty()
        }
        fn is_in_function(&self, _addr: &Address) -> bool {
            false
        }
        fn get_functions_overlapping(
            &self,
            _set: &dyn AddressSetView,
        ) -> Box<dyn crate::program::model::listing::FunctionIterator> {
            crate::program::model::listing::function_iterator::empty()
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
        fn get_function(&self, _key: i64) -> Option<StdArc<dyn Function>> {
            None
        }
        fn get_function_tag_manager(
            &self,
        ) -> StdArc<dyn crate::program::model::listing::FunctionTagManager> {
            unimplemented!()
        }
    }

    struct MockProgram {
        function_manager: MockFunctionManager,
    }

    impl DomainObject for MockProgram {
        fn is_changed(&self) -> bool {
            false
        }
    }

    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock_program".to_string()
        }
        fn get_language_id(&self) -> String {
            "x86:LE:32:default".to_string()
        }
        fn get_function_manager(&mut self) -> Option<&mut dyn FunctionManager> {
            Some(&mut self.function_manager)
        }
    }

    /// Simplified [`CreateFunctionCmd`] backing the smoke test. Its `apply_to` mirrors the
    /// non-thunk, no-existing-function branch of the real Java `applyTo`/`createFunction`: look up
    /// (or create) the function at `entry` via the program's [`FunctionManager`], and remember it
    /// (or a failure message) for later retrieval -- proving the trait is usable behind
    /// `Box<dyn CreateFunctionCmd>` and that its accessors reflect real dispatched state, not just
    /// trivially-true defaults.
    struct SimpleCreateFunctionCmd {
        entry: Address,
        created: Option<StdArc<dyn Function>>,
        msg: Option<String>,
    }

    impl CreateFunctionCmd for SimpleCreateFunctionCmd {
        fn apply_to(&mut self, program: &mut dyn Program, _monitor: &dyn TaskMonitor) -> bool {
            let Some(function_manager) = program.get_function_manager() else {
                self.msg = Some("no function manager".to_string());
                return false;
            };
            if let Some(existing) = function_manager.get_function_at(&self.entry) {
                self.created = Some(existing);
                return true;
            }
            let body = AddressSet::new();
            match function_manager.create_function(
                None,
                self.entry.clone(),
                &body as &dyn AddressSetView,
                SourceType::Default,
            ) {
                Ok(func) => {
                    self.created = Some(func);
                    true
                }
                Err(e) => {
                    self.msg = Some(e.to_string());
                    false
                }
            }
        }

        fn get_function(&self) -> Option<StdArc<dyn Function>> {
            self.created.clone()
        }

        fn status_msg(&self) -> Option<String> {
            self.msg.clone()
        }
    }

    #[test]
    fn defaults_mirror_freshly_constructed_java_state() {
        struct Bare;
        impl CreateFunctionCmd for Bare {
            fn apply_to(&mut self, _program: &mut dyn Program, _monitor: &dyn TaskMonitor) -> bool {
                false
            }
        }

        let bare = Bare;
        assert!(bare.get_function().is_none());
        assert!(bare.status_msg().is_none());
        assert_eq!(bare.name(), "Create Function");
    }

    #[test]
    fn create_function_cmd_creates_function_and_reports_it_via_trait_object() {
        let entry = addr(0x1000);
        let mut program = MockProgram {
            function_manager: MockFunctionManager { functions: Mutex::new(Vec::new()) },
        };
        let mut cmd: Box<dyn CreateFunctionCmd> = Box::new(SimpleCreateFunctionCmd {
            entry: entry.clone(),
            created: None,
            msg: None,
        });
        let monitor = DummyMonitor;

        assert!(cmd.get_function().is_none());

        assert!(cmd.apply_to(&mut program, &monitor));
        let created = cmd.get_function().expect("function was created");
        assert_eq!(created.get_entry_point(), entry);
        assert!(cmd.status_msg().is_none());
        assert_eq!(cmd.name(), "Create Function");

        // Applying again finds the now-existing function (mirrors
        // `CreateFunctionCmd.handleExistingFunction` returning true without re-creating it).
        assert!(cmd.apply_to(&mut program, &monitor));
        assert_eq!(cmd.get_function().unwrap().get_entry_point(), entry);
    }

    #[test]
    fn create_function_cmd_reports_status_msg_when_function_manager_missing() {
        struct BareProgram;
        impl DomainObject for BareProgram {
            fn is_changed(&self) -> bool {
                false
            }
        }
        impl Program for BareProgram {
            fn get_name(&self) -> String {
                "bare".to_string()
            }
            fn get_language_id(&self) -> String {
                "x86:LE:32:default".to_string()
            }
        }

        let mut program = BareProgram;
        let mut cmd: Box<dyn CreateFunctionCmd> = Box::new(SimpleCreateFunctionCmd {
            entry: addr(0x2000),
            created: None,
            msg: None,
        });
        let monitor = DummyMonitor;

        assert!(!cmd.apply_to(&mut program, &monitor));
        assert_eq!(cmd.status_msg(), Some("no function manager".to_string()));
        assert!(cmd.get_function().is_none());
    }
}

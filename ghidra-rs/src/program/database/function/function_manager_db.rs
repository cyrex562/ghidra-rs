//! Port of `ghidra.program.database.function.FunctionManagerDB` as a trait (cycle cut-point).
//!
//! The Java class is a concrete `FunctionManager` implementation that owns the DB tables backing
//! functions (via [`FunctionAdapter`](crate::program::database::function::FunctionAdapter) and
//! [`ThunkFunctionAdapter`](crate::program::database::function::ThunkFunctionAdapter)), and reaches
//! back into a `ProgramDB` (via a `program` field set post-construction through `setProgram`) plus
//! several sibling managers (`NamespaceManager`, `SymbolManager`, `CodeManager`,
//! `DataTypeManagerDB`) obtained the same way. Those mutually-referential, construction-time
//! wirings are what make this class a dependency-cycle cut-point; this port keeps only its
//! genuinely public instance API (skipping the constructor/`initializeAdapters`,
//! `setProgram`/`programReady`/`dbError`/`dispose`, and package-private accessors/helpers used only
//! by the not-yet-ported sibling `FunctionDB` -- e.g. `getFunctionAdapter()`, `getCodeManager()`,
//! `setThunkedFunction`, `functionChanged`, `getCallFixupMap`, `getThunkedFunction`,
//! `setFunctionBody` -- as an object-safe trait, exactly as
//! [`CodeManager`](crate::program::database::code::CodeManager)'s port does) so a concrete
//! DB-backed implementor can be added later without reintroducing the cycle.
//!
//! `FunctionManagerDB implements FunctionManager`; this trait models that relationship by
//! extending the already-ported
//! [`FunctionManager`](crate::program::model::listing::FunctionManager) interface rather than
//! re-declaring its methods.
//!
//! Method names mirror the corresponding Java methods (`snake_case`d). `getThunkFunctionIds`
//! returns `Vec<i64>` rather than `Option<List<Long>>`, collapsing Java's "null means no thunks"
//! into an empty vec, mirroring how other already-ported collection-returning methods in this
//! crate avoid an `Option<Vec<_>>` wrapper.

use std::collections::HashMap;

use thiserror::Error;

use crate::program::model::address::Address;
use crate::program::model::listing::{Function, FunctionManager};
use crate::program::model::symbol::{Namespace, SourceType};
use crate::program::util::language_translator::LanguageTranslator;
use crate::util::exception::{CancelledException, InvalidInputException};
use crate::util::task::TaskMonitor;
use std::sync::Arc;

/// Combines the two checked exceptions declared on `FunctionManagerDB.initSignatureSource` and
/// `.removeExplicitThisParameters` (`IOException`, `CancelledException`).
#[derive(Error, Debug)]
pub enum SignatureUpgradeError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Cancelled(#[from] CancelledException),
}

/// Manages all functions within the program.
///
/// Port of `ghidra.program.database.function.FunctionManagerDB`. See the module docs for what was
/// intentionally left out (construction/persistence details and package-private accessors/helpers
/// used only by the not-yet-ported `FunctionDB`).
pub trait FunctionManagerDb: FunctionManager {
    /// Transform an existing external symbol into an external function. This method should only
    /// be invoked by the Function Manager. The original imported name will initially be `None`.
    ///
    /// # Arguments
    /// * `ext_space_addr` - the external space address to use when creating this external. Any
    ///   other symbol using this address must first be deleted. Results are unpredictable if this
    ///   is not done.
    /// * `name` - the external function name
    /// * `name_space` - the external function namespace
    /// * `original_import_name` - the original imported name if different from `name` (may be
    ///   `None`)
    /// * `external_program_address` - the external program address (may be `None`)
    /// * `source` - the source of this external.
    ///
    /// # Errors
    /// Returns [`InvalidInputException`] if the name is invalid.
    fn create_external_function(
        &mut self,
        ext_space_addr: Address,
        name: &str,
        name_space: Arc<dyn Namespace>,
        original_import_name: Option<&str>,
        external_program_address: Option<Address>,
        source: SourceType,
    ) -> Result<Arc<dyn Function>, InvalidInputException>;

    /// Notification that the function tags for this program have changed, invalidating the
    /// function cache.
    ///
    /// Stands in for `FunctionManagerDB.functionTagsChanged()`.
    fn function_tags_changed(&mut self);

    /// Notification that the function with the given key had its namespace changed, requiring its
    /// class-struct and parameters/return to be updated.
    ///
    /// Stands in for `FunctionManagerDB.functionNamespaceChanged(long)`.
    fn function_namespace_changed(&mut self, key: i64);

    /// Removes the function with the given key, along with its thunks, variables, tags, and body.
    /// Returns `true` if a function was actually removed.
    ///
    /// Stands in for `FunctionManagerDB.doRemoveFunction(long)`.
    fn do_remove_function(&mut self, key: i64) -> bool;

    /// Initialize function signature source when it was first introduced and attempt to disable
    /// custom storage if possible.
    ///
    /// NOTE: This method is intended to be called by `ProgramDB` only during an appropriate
    /// upgrade.
    ///
    /// Stands in for `FunctionManagerDB.initSignatureSource(TaskMonitor)`.
    ///
    /// # Errors
    /// Returns an error if the operation was cancelled via `monitor`, or if a database IO error
    /// occurred.
    fn init_signature_source(&mut self, monitor: &dyn TaskMonitor) -> Result<(), SignatureUpgradeError>;

    /// Remove parameter symbols which correspond to the 'this' parameter for all `__thiscall`
    /// functions using dynamic storage.
    ///
    /// NOTE: This method is intended to be called by `ProgramDB` only during an appropriate
    /// upgrade.
    ///
    /// Stands in for `FunctionManagerDB.removeExplicitThisParameters(TaskMonitor)`.
    ///
    /// # Errors
    /// Returns an error if the operation was cancelled via `monitor`, or if a database IO error
    /// occurred.
    fn remove_explicit_this_parameters(
        &mut self,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), SignatureUpgradeError>;

    /// Replaces every function's return data type id according to `data_type_replacement_map`
    /// (keyed by the function's current return data type id, valued by the replacement id).
    /// Thunks are skipped, since they inherit their return type from the thunked function.
    ///
    /// Stands in for `FunctionManagerDB.replaceDataTypes(Map<Long, Long>)`.
    fn replace_data_types(&mut self, data_type_replacement_map: &HashMap<i64, i64>);

    /// Returns `true` if the function with the given key is a thunk.
    ///
    /// Stands in for `FunctionManagerDB.isThunk(long)`.
    fn is_thunk(&self, key: i64) -> bool;

    /// Returns the key of the function referenced by the thunk function with the given key, or
    /// `-1` if that function is not a thunk (or does not exist).
    ///
    /// Stands in for `FunctionManagerDB.getThunkedFunctionId(long)`.
    fn get_thunked_function_id(&self, function_id: i64) -> i64;

    /// Returns the keys of the thunk functions which reference the function with the given key.
    /// Returns an empty vec if there are none, collapsing Java's `null` return.
    ///
    /// Stands in for `FunctionManagerDB.getThunkFunctionIds(long)`.
    fn get_thunk_function_ids(&self, referenced_function_id: i64) -> Vec<i64>;

    /// Perform language translation: update function return storage specifications to reflect
    /// address space and register mappings.
    ///
    /// Stands in for `FunctionManagerDB.setLanguage(LanguageTranslator, TaskMonitor)`.
    ///
    /// # Errors
    /// Returns [`CancelledException`] if the operation was cancelled via `monitor`.
    fn set_language(
        &mut self,
        translator: &dyn LanguageTranslator,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::database::function::OverlappingFunctionException;
    use crate::program::database::manager_db::ManagerDB;
    use crate::program::model::address::AddressSetView;
    use crate::program::model::lang::prototype_model::PrototypeModel;
    use crate::program::model::listing::{
        CreateFunctionError, FunctionIterator, FunctionTagManager, Program, Variable,
    };
    use std::collections::HashMap as StdHashMap;
    use std::io;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// A minimal in-memory `FunctionManagerDB`, exercising object-safety and the extra API surface
    /// (beyond `FunctionManager`) this trait adds: external-function creation, tag/namespace
    /// change notifications, removal, thunk queries, and return-type replacement.
    #[derive(Default)]
    struct MockFunctionManagerDb {
        next_key: i64,
        removed: Vec<i64>,
        thunks: StdHashMap<i64, i64>, // thunk key -> thunked function key
        return_type_ids: StdHashMap<i64, i64>,
        tags_changed: AtomicU32,
        namespace_changed: AtomicU32,
    }

    impl ManagerDB for MockFunctionManagerDb {
        fn invalidate_cache(&mut self, _all: bool) -> io::Result<()> {
            Ok(())
        }
        fn delete_address_range(&mut self, _start_addr: &Address, _end_addr: &Address) -> io::Result<()> {
            Ok(())
        }
        fn move_address_range(
            &mut self,
            _from_addr: &Address,
            _to_addr: &Address,
            _length: u64,
        ) -> io::Result<()> {
            Ok(())
        }
    }

    impl FunctionManager for MockFunctionManagerDb {
        fn get_program(&self) -> Arc<dyn Program> {
            struct MockProgram;
            impl crate::framework::model::DomainObject for MockProgram {}
            impl Program for MockProgram {
                fn get_name(&self) -> String {
                    "mock".to_string()
                }
                fn get_language_id(&self) -> String {
                    "mock:LE:32:default".to_string()
                }
            }
            Arc::new(MockProgram)
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
        ) -> Result<Arc<dyn Function>, CreateFunctionError> {
            unimplemented!("not needed for this smoke test")
        }

        fn create_function_in_namespace(
            &mut self,
            _name: Option<&str>,
            _name_space: Arc<dyn Namespace>,
            _entry_point: Address,
            _body: &dyn AddressSetView,
            _source: SourceType,
        ) -> Result<Arc<dyn Function>, CreateFunctionError> {
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
            None
        }

        fn get_referenced_function(&self, _address: &Address) -> Option<Arc<dyn Function>> {
            None
        }

        fn get_function_containing(&self, _addr: &Address) -> Option<Arc<dyn Function>> {
            None
        }

        fn get_functions(&self, _forward: bool) -> Box<dyn FunctionIterator> {
            crate::program::model::listing::function_iterator::empty()
        }

        fn get_functions_from(&self, _start: &Address, _forward: bool) -> Box<dyn FunctionIterator> {
            crate::program::model::listing::function_iterator::empty()
        }

        fn get_functions_in(
            &self,
            _asv: &dyn AddressSetView,
            _forward: bool,
        ) -> Box<dyn FunctionIterator> {
            crate::program::model::listing::function_iterator::empty()
        }

        fn get_functions_no_stubs(&self, _forward: bool) -> Box<dyn FunctionIterator> {
            crate::program::model::listing::function_iterator::empty()
        }

        fn get_functions_no_stubs_from(
            &self,
            _start: &Address,
            _forward: bool,
        ) -> Box<dyn FunctionIterator> {
            crate::program::model::listing::function_iterator::empty()
        }

        fn get_functions_no_stubs_in(
            &self,
            _asv: &dyn AddressSetView,
            _forward: bool,
        ) -> Box<dyn FunctionIterator> {
            crate::program::model::listing::function_iterator::empty()
        }

        fn get_external_functions(&self) -> Box<dyn FunctionIterator> {
            crate::program::model::listing::function_iterator::empty()
        }

        fn is_in_function(&self, _addr: &Address) -> bool {
            false
        }

        fn get_functions_overlapping(&self, _set: &dyn AddressSetView) -> Box<dyn FunctionIterator> {
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

        fn get_function(&self, _key: i64) -> Option<Arc<dyn Function>> {
            None
        }

        fn get_function_tag_manager(&self) -> Arc<dyn FunctionTagManager> {
            struct MockTagManager;
            impl FunctionTagManager for MockTagManager {
                fn get_function_tag_by_name(
                    &self,
                    _name: &str,
                ) -> Option<&dyn crate::program::model::listing::FunctionTag> {
                    None
                }
                fn get_function_tag_by_id(
                    &self,
                    _id: i64,
                ) -> Option<&dyn crate::program::model::listing::FunctionTag> {
                    None
                }
                fn get_all_function_tags(&self) -> Vec<&dyn crate::program::model::listing::FunctionTag> {
                    Vec::new()
                }
                fn is_tag_assigned(&self, _name: &str) -> bool {
                    false
                }
                fn create_function_tag(
                    &mut self,
                    _name: &str,
                    _comment: &str,
                ) -> &dyn crate::program::model::listing::FunctionTag {
                    unimplemented!("not needed for this smoke test")
                }
                fn get_use_count(&self, _tag: &dyn crate::program::model::listing::FunctionTag) -> usize {
                    0
                }
            }
            Arc::new(MockTagManager)
        }
    }

    impl FunctionManagerDb for MockFunctionManagerDb {
        fn create_external_function(
            &mut self,
            _ext_space_addr: Address,
            name: &str,
            _name_space: Arc<dyn Namespace>,
            _original_import_name: Option<&str>,
            _external_program_address: Option<Address>,
            _source: SourceType,
        ) -> Result<Arc<dyn Function>, InvalidInputException> {
            if name.is_empty() {
                return Err(InvalidInputException::new());
            }
            self.next_key += 1;
            Err(InvalidInputException::with_message(format!(
                "mock does not materialize functions ({name})"
            )))
        }

        fn function_tags_changed(&mut self) {
            self.tags_changed.fetch_add(1, Ordering::Relaxed);
        }

        fn function_namespace_changed(&mut self, _key: i64) {
            self.namespace_changed.fetch_add(1, Ordering::Relaxed);
        }

        fn do_remove_function(&mut self, key: i64) -> bool {
            if self.thunks.contains_key(&key) || self.return_type_ids.contains_key(&key) {
                self.thunks.remove(&key);
                self.return_type_ids.remove(&key);
                self.removed.push(key);
                true
            } else {
                false
            }
        }

        fn init_signature_source(&mut self, monitor: &dyn TaskMonitor) -> Result<(), SignatureUpgradeError> {
            if monitor.is_cancelled() {
                return Err(CancelledException::default().into());
            }
            Ok(())
        }

        fn remove_explicit_this_parameters(
            &mut self,
            monitor: &dyn TaskMonitor,
        ) -> Result<(), SignatureUpgradeError> {
            if monitor.is_cancelled() {
                return Err(CancelledException::default().into());
            }
            Ok(())
        }

        fn replace_data_types(&mut self, data_type_replacement_map: &HashMap<i64, i64>) {
            for (_, return_id) in self.return_type_ids.iter_mut() {
                if let Some(replacement) = data_type_replacement_map.get(return_id) {
                    *return_id = *replacement;
                }
            }
        }

        fn is_thunk(&self, key: i64) -> bool {
            self.thunks.contains_key(&key)
        }

        fn get_thunked_function_id(&self, function_id: i64) -> i64 {
            self.thunks.get(&function_id).copied().unwrap_or(-1)
        }

        fn get_thunk_function_ids(&self, referenced_function_id: i64) -> Vec<i64> {
            let mut keys: Vec<i64> = self
                .thunks
                .iter()
                .filter(|(_, referenced)| **referenced == referenced_function_id)
                .map(|(thunk, _)| *thunk)
                .collect();
            keys.sort();
            keys
        }

        fn set_language(
            &mut self,
            _translator: &dyn LanguageTranslator,
            monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            if monitor.is_cancelled() {
                return Err(CancelledException::default());
            }
            for (_, return_id) in self.return_type_ids.iter_mut() {
                *return_id += 1;
            }
            Ok(())
        }
    }

    struct MockTranslator;
    impl LanguageTranslator for MockTranslator {
        fn is_valid(&self) -> bool {
            true
        }
        fn get_old_language(&self) -> Arc<dyn crate::program::model::lang::language::Language> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_new_language(&self) -> Arc<dyn crate::program::model::lang::language::Language> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_old_language_id(&self) -> crate::program::model::lang::language_id::LanguageID {
            unimplemented!("not needed for this smoke test")
        }
        fn get_new_language_id(&self) -> crate::program::model::lang::language_id::LanguageID {
            unimplemented!("not needed for this smoke test")
        }
        fn get_old_version(&self) -> i32 {
            0
        }
        fn get_new_version(&self) -> i32 {
            0
        }
        fn get_new_address_space(
            &self,
            _old_space_name: &str,
        ) -> Option<Arc<crate::program::model::address::AddressSpace>> {
            None
        }
        fn get_old_register(
            &self,
            _old_addr: &Address,
            _size: i32,
        ) -> Option<crate::program::model::lang::register::RegisterRef> {
            None
        }
        fn get_old_register_containing(
            &self,
            _old_addr: &Address,
        ) -> Option<crate::program::model::lang::register::RegisterRef> {
            None
        }
        fn get_old_context_register(&self) -> Option<crate::program::model::lang::register::RegisterRef> {
            None
        }
        fn get_new_register(
            &self,
            _old_reg: &crate::program::model::lang::register::RegisterRef,
        ) -> Option<crate::program::model::lang::register::RegisterRef> {
            None
        }
        fn get_new_context_register(&self) -> Option<crate::program::model::lang::register::RegisterRef> {
            None
        }
        fn get_new_register_value(
            &self,
            _old_value: &dyn crate::program::seam_stubs::RegisterValue,
        ) -> Option<Box<dyn crate::program::seam_stubs::RegisterValue>> {
            None
        }
        fn is_value_translation_required(
            &self,
            _old_reg: &crate::program::model::lang::register::RegisterRef,
        ) -> bool {
            false
        }
        fn get_new_compiler_spec_id(
            &self,
            old_compiler_spec_id: &crate::program::model::lang::compiler_spec_id::CompilerSpecID,
        ) -> crate::program::model::lang::compiler_spec_id::CompilerSpecID {
            old_compiler_spec_id.clone()
        }
        fn get_old_compiler_spec(
            &self,
            _old_compiler_spec_id: &crate::program::model::lang::compiler_spec_id::CompilerSpecID,
        ) -> Result<
            Box<dyn crate::program::model::lang::compiler_spec::CompilerSpec>,
            crate::program::model::lang::compiler_spec_not_found_exception::CompilerSpecNotFoundException,
        > {
            unimplemented!("not needed for this smoke test")
        }
        fn fixup_instructions(
            &self,
            _program: &mut dyn crate::program::model::listing::Program,
            _old_language: &dyn crate::program::model::lang::language::Language,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), Box<dyn std::error::Error>> {
            Ok(())
        }
    }

    #[test]
    fn object_safe_and_tracks_thunks_and_removal() {
        let mut concrete = MockFunctionManagerDb::default();
        concrete.return_type_ids.insert(100, 7);
        concrete.thunks.insert(200, 100);
        let mut manager: Box<dyn FunctionManagerDb> = Box::new(concrete);

        manager.function_tags_changed();
        manager.function_namespace_changed(1);
        assert_eq!(manager.get_thunked_function_id(999), -1);
        assert!(manager.get_thunk_function_ids(999).is_empty());

        assert!(manager.is_thunk(200));
        assert!(!manager.is_thunk(100));
        assert_eq!(manager.get_thunked_function_id(200), 100);
        assert_eq!(manager.get_thunk_function_ids(100), vec![200]);

        // replaceDataTypes rewrites return type ids per the replacement map.
        let mut replacements = HashMap::new();
        replacements.insert(7, 42);
        manager.replace_data_types(&replacements);

        // setLanguage bumps return type ids by 1 in this mock, and respects cancellation.
        let monitor = crate::util::task::DummyMonitor;
        manager.set_language(&MockTranslator, &monitor).unwrap();

        // doRemoveFunction succeeds for a tracked key exactly once.
        assert!(manager.do_remove_function(100));
        assert!(!manager.do_remove_function(100));

        assert!(manager.init_signature_source(&monitor).is_ok());
        assert!(manager.remove_explicit_this_parameters(&monitor).is_ok());

        // Invalid input (empty name) is rejected before any key is allocated.
        struct MockNamespace;
        impl crate::program::model::symbol::Namespace for MockNamespace {
            fn get_symbol(&self) -> Arc<dyn crate::program::model::symbol::Symbol> {
                unimplemented!("not needed for this smoke test")
            }
            fn get_parent_namespace(&self) -> Option<Arc<dyn crate::program::model::symbol::Namespace>> {
                None
            }
        }
        let result = manager.create_external_function(
            test_address(0x1000),
            "",
            Arc::new(MockNamespace),
            None,
            None,
            SourceType::Analysis,
        );
        match result {
            Err(err) => assert_eq!(err, InvalidInputException::new()),
            Ok(_) => panic!("expected an InvalidInputException for an empty name"),
        }
    }

    fn test_address(offset: i64) -> Address {
        use crate::program::model::address::{AddressSpace, AddressSpaceType};
        let space = AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0);
        Address::new(space, offset)
    }
}

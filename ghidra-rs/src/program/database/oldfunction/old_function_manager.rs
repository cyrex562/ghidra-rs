//! Port of `ghidra.program.database.oldfunction.OldFunctionManager` as a trait (cycle cut-point).
//!
//! Promotes the bare marker placeholder previously carried as
//! `OldFunctionManager` in `seam_stubs.rs` (see `STUBS.tsv`'s now-removed `OldFunctionManager`
//! row) to a real port. The Java class is a concrete manager that owns the DB tables backing old
//! (pre-2.2) functions -- via [`OldFunctionDBAdapter`], [`OldStackVariableDBAdapter`], and
//! [`OldRegisterVariableDBAdapter`] -- plus a private `OldFunctionMapDB` that tracks each
//! function's address-set body, and hands `this` to a freshly-constructed `OldFunctionDataDB` on
//! every [`get_function`](OldFunctionManager::get_function) call. That mutual construction
//! (`OldFunctionManager` builds `OldFunctionDataDB`, which hands `getFunctionManager()` straight
//! back) is what made `OldFunctionDataDB` a cycle cut-point in the first place; this port
//! completes that cut on the other side, mirroring the same treatment already given to
//! [`OldFunctionDataDB`], [`OldFunctionDBAdapter`], [`OldStackVariableDBAdapter`], and
//! [`OldRegisterVariableDBAdapter`].
//!
//! `OldFunctionManager implements ErrorHandler`; this trait models that relationship by extending
//! the already-ported [`ErrorHandler`](crate::framework::db::util::ErrorHandler) rather than
//! re-declaring `dbError`.
//!
//! `OldFunctionMapDB` (the private field backing
//! [`get_function_body`](OldFunctionManager::get_function_body) and (in Java) `dispose()`) is not
//! ported yet: it is referenced here only through this trait's own required methods (never
//! called through by a default method), so it gets a minimal placeholder,
//! [`OldFunctionMapDB`](crate::program::seam_stubs::OldFunctionMapDB), in `seam_stubs.rs`, exposing
//! just the `dispose()`/`getBody(long)` pair `OldFunctionManager` actually calls on it.
//!
//! Left out of this port:
//! - The constructor and private `initializeAdapters()`: construction-time adapter-selection
//!   detail for a concrete DB-backed implementor, not part of the dynamic-dispatch surface a
//!   trait exists to cut the cycle for -- the same reasoning already applied to
//!   [`OldFunctionDBAdapter`]/[`OldStackVariableDBAdapter`]/[`OldRegisterVariableDBAdapter`]'s
//!   static `getAdapter` factories.
//! - The private `upgradeFunction(OldFunctionDataDB)` helper: its externally-visible effect is
//!   folded into [`upgrade`](OldFunctionManager::upgrade), the same treatment the constructor's
//!   private helpers were given when [`OldFunctionDataDB`] was ported.
//! - `equals`/`hashCode`/`toString`: Rust has no `Object` identity contract to satisfy.
//!
//! [`upgrade`](OldFunctionManager::upgrade) is declared with the real Java
//! `upgrade(ProgramDB, TaskMonitor)` signature but left as a required method with no default
//! body: its Java body iterates every old function (via `getFunctions()`/`upgradeFunction`),
//! creating a new function through `Program.getFunctionManager().createFunction(...)` and then
//! mutating that freshly-created `FunctionDB` through a long sequence of DB-specific setters
//! (`setCustomVariableStorage`, `setValidationEnabled`, `setStackPurgeSize`,
//! `frame.setLocalSize`/`setReturnAddressOffset`, `addParameter`/`addLocalVariable` with
//! duplicate-name retry loops). The already-ported [`Function`](crate::program::model::listing::Function)
//! trait covers those setters, but `FunctionManager::create_function` returns a shared
//! `Arc<dyn Function>` with no established pattern yet in this crate for mutating a trait object
//! behind that `Arc` (see [`CreateFunctionCmd::apply_to`](crate::app::cmd::function::create_function_cmd::CreateFunctionCmd::apply_to)
//! for the same situation and the same resolution). A concrete implementor -- which owns its
//! `FunctionDB` implementation directly, not through a shared `Arc` -- can provide this precisely.
//!
//! [`get_data_type`](OldFunctionManager::get_data_type) and
//! [`get_data_type_id`](OldFunctionManager::get_data_type_id) are likewise left required with no
//! default body: their Java bodies read/resolve against a private `dataManager` field (a
//! `DataTypeManagerDB`, set only once `upgrade()` has run) that this trait exposes no accessor
//! for, the same as Java itself has no getter for it. A concrete implementor holds that
//! collaborator directly.
//!
//! [`get_functions`](OldFunctionManager::get_functions) is given a default body in terms of
//! [`get_function_adapter`](OldFunctionManager::get_function_adapter)'s
//! [`iterate_function_records`](OldFunctionDBAdapter::iterate_function_records) and
//! [`get_function`](OldFunctionManager::get_function), returning `None` (after reporting via
//! [`ErrorHandler::db_error`](crate::framework::db::util::ErrorHandler::db_error), matching the
//! Java method's `catch (IOException e) { errHandler.dbError(e); } return null;`) instead of the
//! private `OldFunctionIteratorDB` inner class Java uses -- [`OldFunctionRecordIter`] plays that
//! role here.

use std::io;
use std::sync::Arc;

use thiserror::Error;

use crate::framework::db::util::ErrorHandler;
use crate::framework::db::{DBRecord, RecordIterator};
use crate::program::database::oldfunction::{
    OldFunctionDBAdapter, OldFunctionDataDB, OldRegisterVariableDBAdapter, OldStackVariableDBAdapter,
};
use crate::program::model::address::AddressSetView;
use crate::program::model::data::data_type::DataType;
use crate::program::model::listing::Program;
use crate::program::seam_stubs::OldFunctionMapDB;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// Combines the two checked exceptions declared on `OldFunctionManager.upgrade(ProgramDB,
/// TaskMonitor)` (`CancelledException`, `IOException`).
#[derive(Error, Debug)]
pub enum UpgradeError {
    #[error(transparent)]
    Cancelled(#[from] CancelledException),
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Manager for old (pre-Ghidra-2.2) functions, used only during a program upgrade.
///
/// Port of `ghidra.program.database.oldfunction.OldFunctionManager`. See the module docs for what
/// was intentionally left out (construction details and the private `upgradeFunction` helper),
/// which methods were given pure-algorithm default bodies, and why `upgrade`/`get_data_type`/
/// `get_data_type_id` were left required with no default body.
///
/// <b>NOTE: this type only exists to support upgrading programs saved by Ghidra 2.1 and
/// earlier.</b>
pub trait OldFunctionManager: ErrorHandler {
    /// Gets the program being upgraded, or `None` before [`upgrade`](Self::upgrade) has run.
    ///
    /// Stands in for the package-private `OldFunctionManager.getProgram()`.
    fn get_program(&self) -> Option<Arc<dyn Program>>;

    /// Gets the adapter for old function records.
    ///
    /// Stands in for the package-private `OldFunctionManager.getFunctionAdapter()`.
    fn get_function_adapter(&self) -> &dyn OldFunctionDBAdapter;

    /// Gets the adapter for old register variable records.
    ///
    /// Stands in for the package-private `OldFunctionManager.getRegisterVariableAdapter()`.
    fn get_register_variable_adapter(&self) -> &dyn OldRegisterVariableDBAdapter;

    /// Gets the adapter for old stack variable records.
    ///
    /// Stands in for the package-private `OldFunctionManager.getStackVariableAdapter()`.
    fn get_stack_variable_adapter(&self) -> &dyn OldStackVariableDBAdapter;

    /// Returns a count of old functions.
    ///
    /// Stands in for the package-private `OldFunctionManager.getFunctionCount()`.
    fn get_function_count(&self) -> i32 {
        self.get_function_adapter().get_record_count()
    }

    /// Resolves a data type by its (possibly stale) ID, substituting `DataType.DEFAULT` if it no
    /// longer exists, and wrapping it in a pointer if its resolved length is not fixed (mirroring
    /// old functions' pre-2.2 handling of variable-length/pointer-like data types).
    ///
    /// Stands in for the package-private `OldFunctionManager.getDataType(long)`. See the module
    /// docs for why this has no default body.
    fn get_data_type(&self, data_type_id: i64) -> Box<dyn DataType>;

    /// Gets (resolving if necessary) the ID for `data_type` in this program's data type manager.
    ///
    /// Stands in for the package-private `OldFunctionManager.getDataTypeId(DataType)`. See the
    /// module docs for why this has no default body.
    fn get_data_type_id(&self, data_type: &dyn DataType) -> i64;

    /// Gets the address set which makes up the body of the function with the given key.
    ///
    /// Stands in for the package-private `OldFunctionManager.getFunctionBody(long)`, which
    /// delegates to the not-yet-ported `OldFunctionMapDB.getBody(long)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn get_function_body(&self, function_key: i64) -> io::Result<Box<dyn AddressSetView>>;

    /// Builds an [`OldFunctionDataDB`] wrapping the given function record.
    ///
    /// Stands in for the package-private, `synchronized OldFunctionManager.getFunction(DBRecord)`.
    /// A concrete implementor constructs its own `OldFunctionDataDB`-implementing type here, the
    /// same way `OldFunctionDataDB`'s own (not-yet-ported) constructor is left to a concrete
    /// implementor.
    fn get_function(&self, rec: &DBRecord) -> Arc<dyn OldFunctionDataDB>;

    /// Gets an iterator over all old functions, or `None` if the underlying record iterator could
    /// not be created (after reporting the failure via
    /// [`ErrorHandler::db_error`](crate::framework::db::util::ErrorHandler::db_error)).
    ///
    /// Stands in for the package-private, `synchronized OldFunctionManager.getFunctions()`. See
    /// the module docs for how this default is built from
    /// [`get_function_adapter`](Self::get_function_adapter) and [`get_function`](Self::get_function).
    ///
    /// Bounded by `Self: Sized` because its body unsize-coerces `&self` into the
    /// `&dyn OldFunctionManager` stored on [`OldFunctionRecordIter`]; this keeps the method out of
    /// this trait's vtable (so it can't be called through an existing `Box<dyn
    /// OldFunctionManager>`/`&dyn OldFunctionManager>`) without affecting the trait's own
    /// object-safety, the same trade-off `Iterator::by_ref` and similar `Self: Sized`-bounded
    /// default methods make elsewhere in the standard library.
    fn get_functions(&self) -> Option<OldFunctionRecordIter<'_>>
    where
        Self: Sized,
    {
        match self.get_function_adapter().iterate_function_records() {
            Ok(records) => Some(OldFunctionRecordIter {
                manager: self,
                records,
            }),
            Err(e) => {
                self.db_error(e);
                None
            }
        }
    }

    /// Upgrades every old function found by [`get_functions`](Self::get_functions) into a real
    /// function within `upgrade_program`'s function manager, then disposes this manager's
    /// resources.
    ///
    /// Stands in for `OldFunctionManager.upgrade(ProgramDB, TaskMonitor)`. See the module docs
    /// for why this has no default body.
    ///
    /// # Errors
    ///
    /// Returns [`UpgradeError::Cancelled`] if `monitor` is cancelled during the upgrade, or
    /// [`UpgradeError::Io`] if there was a problem accessing the database.
    fn upgrade(
        &mut self,
        upgrade_program: &mut dyn Program,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), UpgradeError>;

    /// Permanently discards all data resources associated with this old function manager. This
    /// should be invoked once every old function has been upgraded.
    ///
    /// Stands in for `OldFunctionManager.dispose()`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn dispose(&mut self) -> io::Result<()>;
}

/// Iterator over old functions, returned by [`OldFunctionManager::get_functions`].
///
/// Stands in for the private `OldFunctionManager.OldFunctionIteratorDB` inner class: each `next()`
/// pulls the next raw record from the function adapter and hands it to
/// [`OldFunctionManager::get_function`], reporting (and stopping on) any I/O error via
/// [`ErrorHandler::db_error`](crate::framework::db::util::ErrorHandler::db_error) exactly as the
/// Java inner class's `hasNext()` does.
pub struct OldFunctionRecordIter<'a> {
    manager: &'a dyn OldFunctionManager,
    records: Box<dyn RecordIterator + 'a>,
}

impl<'a> Iterator for OldFunctionRecordIter<'a> {
    type Item = Arc<dyn OldFunctionDataDB>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.records.next() {
            Ok(Some(rec)) => Some(self.manager.get_function(&rec)),
            Ok(None) => None,
            Err(e) => {
                self.manager.db_error(e);
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::{DBHandle, Field, FieldType, Schema};
    use crate::program::model::address::{Address, AddressSet, AddressSpace, AddressSpaceType};
    use crate::program::seam_stubs::PlaceholderDataType;
    use std::cell::{Cell, RefCell};
    use std::sync::Arc;

    fn test_schema() -> Arc<Schema> {
        Arc::new(Schema::new(
            1,
            FieldType::Long,
            "Entry Point".to_string(),
            vec![FieldType::Long],
            vec!["Return DataType ID".to_string()],
            vec![],
        ))
    }

    struct VecRecordIterator {
        records: std::vec::IntoIter<DBRecord>,
    }

    impl RecordIterator for VecRecordIterator {
        fn next(&mut self) -> io::Result<Option<DBRecord>> {
            Ok(self.records.next())
        }

        fn has_next(&self) -> bool {
            self.records.as_slice().first().is_some()
        }
    }

    /// A minimal in-memory `OldFunctionDBAdapter` used only to drive
    /// `MockOldFunctionManager::get_functions` in the smoke test below.
    struct MockOldFunctionDBAdapter {
        keys: Vec<i64>,
        fail_iteration: bool,
    }

    impl OldFunctionDBAdapter for MockOldFunctionDBAdapter {
        fn delete_table(&mut self, _handle: &mut DBHandle) -> io::Result<()> {
            self.keys.clear();
            Ok(())
        }

        fn get_record_count(&self) -> i32 {
            self.keys.len() as i32
        }

        fn get_function_record(&self, function_key: i64) -> io::Result<Option<DBRecord>> {
            Ok(if self.keys.contains(&function_key) {
                Some(DBRecord::new(test_schema(), Field::Long(Some(function_key))))
            } else {
                None
            })
        }

        fn iterate_function_records(&self) -> io::Result<Box<dyn RecordIterator + '_>> {
            if self.fail_iteration {
                return Err(io::Error::new(io::ErrorKind::Other, "simulated db failure"));
            }
            let records: Vec<DBRecord> = self
                .keys
                .iter()
                .map(|&key| DBRecord::new(test_schema(), Field::Long(Some(key))))
                .collect();
            Ok(Box::new(VecRecordIterator {
                records: records.into_iter(),
            }))
        }

        fn get_address_map(&self) -> &dyn crate::program::database::map::AddressMap {
            unimplemented!("mock does not exercise get_address_map")
        }
    }

    struct MockOldFunctionDataDB {
        key: i64,
    }

    impl OldFunctionDataDB for MockOldFunctionDataDB {
        fn get_address_map(&self) -> &dyn crate::program::database::map::AddressMap {
            unimplemented!("mock does not exercise get_address_map")
        }
        fn get_function_manager(&self) -> Arc<dyn OldFunctionManager> {
            unimplemented!("mock does not exercise get_function_manager")
        }
        fn get_program(&self) -> Arc<dyn Program> {
            unimplemented!("mock does not exercise get_program")
        }
        fn get_comment(&self) -> String {
            String::new()
        }
        fn get_repeatable_comment(&self) -> String {
            String::new()
        }
        fn get_entry_point(&self) -> Address {
            let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
            Address::new(space, self.key)
        }
        fn get_body(&self) -> Box<dyn AddressSetView> {
            Box::new(AddressSet::new())
        }
        fn get_return_type(&self) -> Box<dyn DataType> {
            Box::new(PlaceholderDataType)
        }
        fn get_stack_frame(&self) -> Box<dyn crate::program::model::listing::StackFrame> {
            unimplemented!("mock does not exercise get_stack_frame")
        }
        fn get_stack_depth_change(&self) -> i32 {
            0
        }
        fn get_stack_param_offset(&self) -> i32 {
            0
        }
        fn get_stack_return_offset(&self) -> i32 {
            0
        }
        fn get_stack_local_size(&self) -> i32 {
            0
        }
        fn get_parameters(&self) -> Vec<Box<dyn crate::program::model::listing::Parameter>> {
            Vec::new()
        }
        fn get_key(&self) -> i64 {
            self.key
        }
    }

    /// A no-op `OldRegisterVariableDBAdapter`, unused by the tests below except to satisfy
    /// `MockOldFunctionManager::get_register_variable_adapter`'s return type.
    struct NoopRegisterAdapter;

    impl OldRegisterVariableDBAdapter for NoopRegisterAdapter {
        fn delete_table(&mut self, _handle: &mut DBHandle) -> io::Result<()> {
            Ok(())
        }
        fn get_record_count(&self) -> i32 {
            0
        }
        fn get_register_variable_record(&self, _key: i64) -> io::Result<Option<DBRecord>> {
            Ok(None)
        }
        fn get_register_variable_keys(&self, _function_key: i64) -> io::Result<Vec<Field>> {
            Ok(Vec::new())
        }
    }

    /// A no-op `OldStackVariableDBAdapter`, unused by the tests below except to satisfy
    /// `MockOldFunctionManager::get_stack_variable_adapter`'s return type.
    struct NoopStackAdapter;

    impl OldStackVariableDBAdapter for NoopStackAdapter {
        fn delete_table(&mut self, _handle: &mut DBHandle) -> io::Result<()> {
            Ok(())
        }
        fn get_stack_variable_record(&self, _key: i64) -> io::Result<Option<DBRecord>> {
            Ok(None)
        }
        fn get_stack_variable_keys(&self, _function_key: i64) -> io::Result<Vec<Field>> {
            Ok(Vec::new())
        }
    }

    /// A minimal `OldFunctionManager`, exercising object-safety plus the `get_function_count`
    /// default and the `get_functions` iterator-adaptation default described by the Java class.
    struct MockOldFunctionManager {
        adapter: MockOldFunctionDBAdapter,
        register_adapter: NoopRegisterAdapter,
        stack_adapter: NoopStackAdapter,
        last_error: RefCell<Option<String>>,
        disposed: Cell<bool>,
    }

    impl ErrorHandler for MockOldFunctionManager {
        fn db_error(&self, e: io::Error) {
            *self.last_error.borrow_mut() = Some(e.to_string());
        }
    }

    impl OldFunctionManager for MockOldFunctionManager {
        fn get_program(&self) -> Option<Arc<dyn Program>> {
            None
        }

        fn get_function_adapter(&self) -> &dyn OldFunctionDBAdapter {
            &self.adapter
        }

        fn get_register_variable_adapter(&self) -> &dyn OldRegisterVariableDBAdapter {
            &self.register_adapter
        }

        fn get_stack_variable_adapter(&self) -> &dyn OldStackVariableDBAdapter {
            &self.stack_adapter
        }

        fn get_data_type(&self, _data_type_id: i64) -> Box<dyn DataType> {
            Box::new(PlaceholderDataType)
        }

        fn get_data_type_id(&self, _data_type: &dyn DataType) -> i64 {
            0
        }

        fn get_function_body(&self, _function_key: i64) -> io::Result<Box<dyn AddressSetView>> {
            Ok(Box::new(AddressSet::new()))
        }

        fn get_function(&self, rec: &DBRecord) -> Arc<dyn OldFunctionDataDB> {
            let key = match rec.get_key() {
                Field::Long(Some(v)) => *v,
                _ => panic!("expected long key"),
            };
            Arc::new(MockOldFunctionDataDB { key })
        }

        fn upgrade(
            &mut self,
            _upgrade_program: &mut dyn Program,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), UpgradeError> {
            self.dispose()?;
            Ok(())
        }

        fn dispose(&mut self) -> io::Result<()> {
            self.disposed.set(true);
            Ok(())
        }
    }

    fn mock_manager(keys: Vec<i64>) -> MockOldFunctionManager {
        MockOldFunctionManager {
            adapter: MockOldFunctionDBAdapter {
                keys,
                fail_iteration: false,
            },
            register_adapter: NoopRegisterAdapter,
            stack_adapter: NoopStackAdapter,
            last_error: RefCell::new(None),
            disposed: Cell::new(false),
        }
    }

    #[test]
    fn object_safe_and_counts_functions_via_adapter() {
        let manager = mock_manager(vec![1, 2, 3]);
        let manager: Box<dyn OldFunctionManager> = Box::new(manager);
        assert_eq!(manager.get_function_count(), 3);
    }

    #[test]
    fn get_functions_adapts_record_iterator_into_old_function_data_db_iterator() {
        let manager = mock_manager(vec![10, 20]);
        let keys: Vec<i64> = manager
            .get_functions()
            .expect("iterator should be constructed")
            .map(|f| f.get_key())
            .collect();
        assert_eq!(keys, vec![10, 20]);
    }

    #[test]
    fn dispose_marks_disposed() {
        let mut manager = mock_manager(vec![]);
        manager.dispose().unwrap();
        assert!(manager.disposed.get());
    }

    #[test]
    fn get_functions_reports_adapter_failure_via_error_handler_and_returns_none() {
        let mut manager = mock_manager(vec![1]);
        manager.adapter.fail_iteration = true;

        assert!(manager.get_functions().is_none());
        assert_eq!(
            manager.last_error.borrow().as_deref(),
            Some("simulated db failure")
        );
    }
}

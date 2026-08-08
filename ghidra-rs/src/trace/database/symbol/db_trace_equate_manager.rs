//! The trace database's equate-table manager.
//!
//! Port of `ghidra.trace.database.symbol.DBTraceEquateManager`.
//!
//! It was selected as a dependency-cycle cut-point.
//!
//! The Java class `extends AbstractDBTraceSpaceBasedManager<DBTraceEquateSpace> implements
//! TraceEquateManager, DBTraceDelegatingManager<DBTraceEquateSpace>`. Every one of its public
//! methods is, in fact, just an implementation of a method already declared on one of those three
//! interfaces:
//!
//! - `dbError`/`invalidateCache` mirror
//!   [`DBTraceManager`](crate::trace::database::db_trace_manager::DBTraceManager) (the same
//!   lifecycle contract `AbstractDBTraceSpaceBasedManager` itself implements).
//! - `readLock`/`writeLock`/`getForSpace` mirror
//!   [`DBTraceDelegatingManager`](crate::trace::database::space::db_trace_delegating_manager::DBTraceDelegatingManager).
//! - `getEquateSpace`/`getEquateRegisterSpace`/`create`/`getAll`/`getByName`/`getByKey`/
//!   `getByValue`/`getReferringAddresses`/`clearReferences`/`getReferencedByValue`/`getReferenced`
//!   mirror
//!   [`TraceEquateManager`](crate::trace::model::symbol::trace_equate_manager::TraceEquateManager)
//!   (and its `TraceEquateOperations` supertrait).
//!
//! Java's covariant overrides (e.g. `getEquateSpace` returning the concrete `DBTraceEquateSpace`
//! rather than the interface's `TraceEquateSpace`) have no Rust equivalent for trait-object
//! returns, so this trait keeps the supertraits' `Box<dyn TraceEquateSpace>`/`Box<dyn
//! TraceEquate>` return types rather than inventing parallel `DBTraceEquate`/`DBTraceEquateSpace`
//! placeholder traits with no members of their own -- there is nothing left for this trait to add.

use crate::trace::database::db_trace_manager::DBTraceManager;
use crate::trace::database::space::db_trace_delegating_manager::DBTraceDelegatingManager;
use crate::trace::model::symbol::trace_equate_manager::TraceEquateManager;
use crate::trace::model::symbol::trace_equate_space::TraceEquateSpace;

/// The trace database's equate-table manager.
///
/// Port of `ghidra.trace.database.symbol.DBTraceEquateManager`.
pub trait DBTraceEquateManager:
    TraceEquateManager + DBTraceManager + DBTraceDelegatingManager<Box<dyn TraceEquateSpace>>
{
}

/// Blanket impl: any type satisfying the three supertraits automatically satisfies this trait,
/// since it declares no members of its own.
impl<T> DBTraceEquateManager for T where
    T: TraceEquateManager + DBTraceManager + DBTraceDelegatingManager<Box<dyn TraceEquateSpace>>
{
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use crate::program::model::address::{
        Address, AddressRange, AddressSet, AddressSetView, AddressSpace, AddressSpaceType,
    };
    use crate::trace::model::lifespan::Lifespan;
    use crate::trace::model::symbol::trace_equate::TraceEquate;
    use crate::trace::model::symbol::trace_equate_operations::TraceEquateOperations;
    use crate::trace::seam_stubs::{TraceStackFrame, TraceThread};
    use crate::util::exception::{CancelledException, DuplicateNameException};
    use crate::util::lock_hold::Lock;
    use crate::util::task::TaskMonitor;

    /// A no-op [`Lock`], standing in for the real read/write locks `DBTraceEquateManager`
    /// delegates through.
    struct NoOpLock;

    impl Lock for NoOpLock {
        fn lock(&self) {}
        fn unlock(&self) {}
    }

    #[derive(Clone)]
    struct MockEquate {
        name: String,
        value: i64,
    }

    impl TraceEquate for MockEquate {
        fn get_name(&self) -> &str {
            &self.name
        }
        fn get_display_name(&self) -> String {
            self.name.clone()
        }
        fn get_value(&self) -> i64 {
            self.value
        }
        fn get_display_value(&self) -> String {
            format!("0x{:x}", self.value)
        }
        fn get_reference_count(&self) -> i32 {
            0
        }
        fn add_reference(
            &mut self,
            _lifespan: Box<dyn Lifespan>,
            _thread: Option<Box<dyn TraceThread>>,
            _address: Address,
            _operand_index: i32,
        ) -> Box<dyn crate::trace::model::symbol::trace_equate_reference::TraceEquateReference> {
            unimplemented!("not exercised by this smoke test")
        }
        fn add_reference_varnode(
            &mut self,
            _lifespan: Box<dyn Lifespan>,
            _thread: Option<Box<dyn TraceThread>>,
            _address: Address,
            _varnode: crate::program::model::pcode::Varnode,
        ) -> Box<dyn crate::trace::model::symbol::trace_equate_reference::TraceEquateReference> {
            unimplemented!("not exercised by this smoke test")
        }
        fn set_name(&mut self, new_name: &str) {
            self.name = new_name.to_string();
        }
        fn get_references(
            &self,
        ) -> Vec<Box<dyn crate::trace::model::symbol::trace_equate_reference::TraceEquateReference>> {
            Vec::new()
        }
        fn get_reference(
            &self,
            _snap: i64,
            _thread: Option<&dyn TraceThread>,
            _address: &Address,
            _operand_index: i32,
        ) -> Option<Box<dyn crate::trace::model::symbol::trace_equate_reference::TraceEquateReference>> {
            None
        }
        fn get_reference_varnode(
            &self,
            _snap: i64,
            _thread: Option<&dyn TraceThread>,
            _address: &Address,
            _varnode: &crate::program::model::pcode::Varnode,
        ) -> Option<Box<dyn crate::trace::model::symbol::trace_equate_reference::TraceEquateReference>> {
            None
        }
        fn has_valid_enum(&self) -> bool {
            false
        }
        fn is_enum_based(&self) -> bool {
            false
        }
        fn get_enum(&self) -> Option<Box<dyn crate::program::model::data::enum_::Enum>> {
            None
        }
        fn delete(&mut self) {}
    }

    /// A manager backed by a flat `Vec` of equates plus a dummy lock/space table, proving the
    /// combined `TraceEquateManager + DBTraceManager + DBTraceDelegatingManager` surface can be
    /// driven through a single `Box<dyn DBTraceEquateManager>`, and that real (not trivially
    /// empty) storage flows through it.
    struct MockManager {
        equates: Vec<MockEquate>,
        read_lock: NoOpLock,
        write_lock: NoOpLock,
        invalidate_calls: Vec<bool>,
    }

    impl crate::framework::db::util::error_handler::ErrorHandler for MockManager {
        fn db_error(&self, e: std::io::Error) {
            // Interior storage isn't available on &self; record nothing, just prove the
            // trait-object call dispatches.
            let _ = e;
        }
    }

    impl DBTraceManager for MockManager {
        fn invalidate_cache(&mut self, all: bool) {
            self.invalidate_calls.push(all);
        }
    }

    impl DBTraceDelegatingManager<Box<dyn TraceEquateSpace>> for MockManager {
        fn read_lock(&self) -> &dyn Lock {
            &self.read_lock
        }
        fn write_lock(&self) -> &dyn Lock {
            &self.write_lock
        }
        fn get_for_space(
            &self,
            _space: &Arc<AddressSpace>,
            _create_if_absent: bool,
        ) -> Option<Box<dyn TraceEquateSpace>> {
            None
        }
    }

    impl TraceEquateOperations for MockManager {
        fn get_referring_addresses(&self, _span: &dyn Lifespan) -> Box<dyn AddressSetView> {
            Box::new(AddressSet::new())
        }
        fn clear_references(
            &mut self,
            _span: &dyn Lifespan,
            _asv: &dyn AddressSetView,
            monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            monitor.check_cancelled()
        }
        fn clear_references_range(
            &mut self,
            _span: &dyn Lifespan,
            _range: &AddressRange,
            monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            monitor.check_cancelled()
        }
        fn get_referenced_by_value(
            &self,
            _snap: i64,
            _address: &Address,
            _operand_index: i32,
            _value: i64,
        ) -> Option<Box<dyn TraceEquate>> {
            None
        }
        fn get_referenced(
            &self,
            _snap: i64,
            _address: &Address,
            _operand_index: i32,
        ) -> Vec<Box<dyn TraceEquate>> {
            Vec::new()
        }
        fn get_referenced_all_operands(&self, _snap: i64, _address: &Address) -> Vec<Box<dyn TraceEquate>> {
            Vec::new()
        }
    }

    impl TraceEquateManager for MockManager {
        fn get_equate_space(
            &mut self,
            _space: &Arc<AddressSpace>,
            _create_if_absent: bool,
        ) -> Option<Box<dyn TraceEquateSpace>> {
            None
        }
        fn get_equate_register_space_for_thread(
            &mut self,
            _thread: &dyn TraceThread,
            _create_if_absent: bool,
        ) -> Option<Box<dyn TraceEquateSpace>> {
            None
        }
        fn get_equate_register_space_for_frame(
            &mut self,
            _frame: &dyn TraceStackFrame,
            _create_if_absent: bool,
        ) -> Option<Box<dyn TraceEquateSpace>> {
            None
        }
        fn create(
            &mut self,
            name: &str,
            value: i64,
        ) -> Result<Box<dyn TraceEquate>, DuplicateNameException> {
            crate::trace::model::symbol::trace_equate_manager::validate_name(name);
            if self.equates.iter().any(|e| e.name == name) {
                return Err(DuplicateNameException::with_message(format!(
                    "Equate named {name} already exists"
                )));
            }
            let equate = MockEquate { name: name.to_string(), value };
            self.equates.push(equate.clone());
            Ok(Box::new(equate))
        }
        fn get_by_name(&self, name: &str) -> Option<Box<dyn TraceEquate>> {
            self.equates
                .iter()
                .find(|e| e.name == name)
                .map(|e| Box::new(e.clone()) as Box<dyn TraceEquate>)
        }
        fn get_by_key(&self, key: i64) -> Option<Box<dyn TraceEquate>> {
            self.equates
                .get(key as usize)
                .map(|e| Box::new(e.clone()) as Box<dyn TraceEquate>)
        }
        fn get_by_value(&self, value: i64) -> Vec<Box<dyn TraceEquate>> {
            self.equates
                .iter()
                .filter(|e| e.value == value)
                .map(|e| Box::new(e.clone()) as Box<dyn TraceEquate>)
                .collect()
        }
        fn get_all(&self) -> Vec<Box<dyn TraceEquate>> {
            self.equates.iter().map(|e| Box::new(e.clone()) as Box<dyn TraceEquate>).collect()
        }
    }

    #[test]
    fn blanket_impl_is_object_safe_and_drives_all_three_supertraits() {
        let mut mgr = MockManager {
            equates: Vec::new(),
            read_lock: NoOpLock,
            write_lock: NoOpLock,
            invalidate_calls: Vec::new(),
        };
        mgr.create("FOO", 42).expect("first create should succeed");
        assert!(mgr.create("FOO", 7).is_err());

        let boxed: Box<dyn DBTraceEquateManager> = Box::new(mgr);

        // TraceEquateManager surface.
        assert_eq!(boxed.get_by_name("FOO").unwrap().get_value(), 42);
        assert_eq!(boxed.get_by_value(42).len(), 1);
        assert_eq!(boxed.get_all().len(), 1);

        // DBTraceDelegatingManager surface.
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        assert!(boxed.get_for_space(&space, false).is_none());
        let _ = boxed.read_lock();
        let _ = boxed.write_lock();
    }

    #[test]
    fn invalidate_cache_reaches_through_dbtracemanager_supertrait() {
        let mut mgr = MockManager {
            equates: Vec::new(),
            read_lock: NoOpLock,
            write_lock: NoOpLock,
            invalidate_calls: Vec::new(),
        };
        let boxed: &mut dyn DBTraceEquateManager = &mut mgr;
        boxed.invalidate_cache(true);
        assert_eq!(mgr.invalidate_calls, vec![true]);
    }
}

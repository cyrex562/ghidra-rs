//! The equate table for a trace.
//!
//! Port of `ghidra.trace.model.symbol.TraceEquateManager`.
//!
//! It was selected as a dependency-cycle cut-point.
//!
//! The Java interface's two `getEquateRegisterSpace` overloads (one taking a `TraceThread`, the
//! other a `TraceStackFrame`) cannot be represented as same-named Rust methods, so each is given a
//! distinct, descriptive name below, following the convention set by
//! [`TraceEquateOperations`](crate::trace::model::symbol::trace_equate_operations::TraceEquateOperations).

use std::sync::Arc;

use crate::program::model::address::AddressSpace;
use crate::trace::model::symbol::trace_equate::TraceEquate;
use crate::trace::model::symbol::trace_equate_operations::TraceEquateOperations;
use crate::trace::model::symbol::trace_equate_space::TraceEquateSpace;
use crate::trace::seam_stubs::{TraceStackFrame, TraceThread};
use crate::util::exception::DuplicateNameException;

/// Validates a candidate equate name, mirroring `TraceEquateManager.validateName(String)`.
///
/// # Panics
/// Panics (mirroring the Java `IllegalArgumentException`) if `name` is empty or contains
/// whitespace.
pub fn validate_name(name: &str) {
    if name.is_empty() {
        panic!("name cannot be empty string");
    }
    if name.chars().any(char::is_whitespace) {
        panic!("name cannot contain whitespace");
    }
}

/// The equate table for a trace.
pub trait TraceEquateManager: TraceEquateOperations {
    /// Get the equate space for the given address space, optionally creating it if absent.
    ///
    /// Returns `None` if the space does not exist and `create_if_absent` is `false`.
    fn get_equate_space(
        &mut self,
        space: &Arc<AddressSpace>,
        create_if_absent: bool,
    ) -> Option<Box<dyn TraceEquateSpace>>;

    /// Get the equate register space for the given thread's registers, optionally creating it if
    /// absent.
    ///
    /// Returns `None` if the space does not exist and `create_if_absent` is `false`.
    ///
    /// Mirrors the Java overload `getEquateRegisterSpace(TraceThread, boolean)`.
    fn get_equate_register_space_for_thread(
        &mut self,
        thread: &dyn TraceThread,
        create_if_absent: bool,
    ) -> Option<Box<dyn TraceEquateSpace>>;

    /// Get the equate register space for the given stack frame's registers, optionally creating
    /// it if absent.
    ///
    /// Returns `None` if the space does not exist and `create_if_absent` is `false`.
    ///
    /// Mirrors the Java overload `getEquateRegisterSpace(TraceStackFrame, boolean)`.
    fn get_equate_register_space_for_frame(
        &mut self,
        frame: &dyn TraceStackFrame,
        create_if_absent: bool,
    ) -> Option<Box<dyn TraceEquateSpace>>;

    /// Create a new equate with the given name and value.
    ///
    /// Returns [`DuplicateNameException`] if an equate by that name already exists. Panics
    /// (mirroring the Java `IllegalArgumentException`) if `name` is invalid; see [`validate_name`].
    fn create(&mut self, name: &str, value: i64) -> Result<Box<dyn TraceEquate>, DuplicateNameException>;

    /// Get the equate with the given name, if any.
    fn get_by_name(&self, name: &str) -> Option<Box<dyn TraceEquate>>;

    /// Get the equate with the given (database-unique) key, if any.
    fn get_by_key(&self, key: i64) -> Option<Box<dyn TraceEquate>>;

    /// Get all equates with the given value.
    fn get_by_value(&self, value: i64) -> Vec<Box<dyn TraceEquate>>;

    /// Get all equates in the trace.
    fn get_all(&self) -> Vec<Box<dyn TraceEquate>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{
        Address, AddressRange, AddressSet, AddressSetView, AddressSpaceType,
    };
    use crate::trace::model::lifespan::Lifespan;
    use crate::util::exception::CancelledException;
    use crate::util::task::TaskMonitor;

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
        fn get_references(&self) -> Vec<Box<dyn crate::trace::model::symbol::trace_equate_reference::TraceEquateReference>> {
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

    /// A manager backed by a flat `Vec` of equates, to prove
    /// [`TraceEquateManager::create`]/[`TraceEquateManager::get_by_name`]/
    /// [`TraceEquateManager::get_by_value`] cooperate on real (not trivially-empty) storage, and
    /// that the trait remains object-safe (and its `TraceEquateOperations` supertrait remains
    /// reachable) behind a `Box<dyn TraceEquateManager>`.
    struct MockManager {
        equates: Vec<MockEquate>,
        next_key: i64,
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
        fn get_referenced(&self, _snap: i64, _address: &Address, _operand_index: i32) -> Vec<Box<dyn TraceEquate>> {
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
        fn create(&mut self, name: &str, value: i64) -> Result<Box<dyn TraceEquate>, DuplicateNameException> {
            validate_name(name);
            if self.equates.iter().any(|e| e.name == name) {
                return Err(DuplicateNameException::with_message(format!(
                    "Equate named {name} already exists"
                )));
            }
            self.next_key += 1;
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
    fn validate_name_rejects_empty_and_whitespace() {
        let empty = std::panic::catch_unwind(|| validate_name(""));
        assert!(empty.is_err());
        let whitespace = std::panic::catch_unwind(|| validate_name("has space"));
        assert!(whitespace.is_err());
        validate_name("ok_name");
    }

    #[test]
    fn create_rejects_duplicate_names_and_stores_new_ones() {
        let mut mgr = MockManager { equates: Vec::new(), next_key: -1 };

        let created = mgr.create("FOO", 42).expect("first create should succeed");
        assert_eq!(created.get_name(), "FOO");
        assert_eq!(created.get_value(), 42);

        let dup = mgr.create("FOO", 7);
        assert!(dup.is_err());

        assert_eq!(mgr.get_by_name("FOO").unwrap().get_value(), 42);
        assert_eq!(mgr.get_by_value(42).len(), 1);
        assert_eq!(mgr.get_all().len(), 1);
    }

    struct DummySpan;
    impl Lifespan for DummySpan {
        fn lmin(&self) -> i64 {
            0
        }
        fn lmax(&self) -> i64 {
            0
        }
        fn contains(&self, n: i64) -> bool {
            n == 0
        }
        fn with_min(&self, _min: i64) -> Box<dyn Lifespan> {
            Box::new(DummySpan)
        }
        fn with_max(&self, _max: i64) -> Box<dyn Lifespan> {
            Box::new(DummySpan)
        }
        fn iter(&self) -> Box<dyn Iterator<Item = i64> + '_> {
            Box::new(std::iter::once(0))
        }
    }

    #[test]
    fn is_object_safe_and_supertrait_reachable() {
        let mut mgr = MockManager { equates: Vec::new(), next_key: -1 };
        mgr.create("BAR", 1).unwrap();
        let boxed: Box<dyn TraceEquateManager> = Box::new(mgr);

        assert_eq!(boxed.get_by_key(0).unwrap().get_name(), "BAR");

        // Supertrait (TraceEquateOperations) methods remain reachable.
        let dummy_span = DummySpan;
        let _ = boxed.get_referring_addresses(&dummy_span);
    }
}

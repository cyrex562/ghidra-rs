//! Manages generic address keyed properties, backed by the program database.
//!
//! Port of `ghidra.program.database.properties.DBPropertyMapManager`.

use std::io;
use std::sync::Arc;

use crate::framework::data::OpenMode;
use crate::program::database::manager_db::ManagerDB;
use crate::program::model::listing::Program;
use crate::program::model::util::PropertyMapManager;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// Error returned by [`DBPropertyMapManager::program_ready`], mirroring the Java method's
/// `throws IOException, CancelledException`.
#[derive(Debug, thiserror::Error)]
pub enum ProgramReadyError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Cancelled(#[from] CancelledException),
}

/// Manages the set of `PropertyMap`s stored in a program's database.
///
/// Port of `ghidra.program.database.properties.DBPropertyMapManager`, which implements two Java
/// interfaces: [`PropertyMapManager`] (address-keyed property map CRUD) and `ManagerDB` (the
/// program subsection-manager lifecycle contract). This trait combines both as supertraits and
/// adds the `ManagerDB` lifecycle callbacks (`setProgram`/`programReady`) that the shared Rust
/// [`ManagerDB`] trait omits — the same convention already used by other `ManagerDB` extenders
/// such as `FunctionManager`, whose doc comment explains that `ManagerDB`'s
/// `invalidate_cache`/`delete_address_range`/`move_address_range` stand in for the Java
/// interface's `TaskMonitor`/`CancelledException`-bearing re-declarations of those same methods.
///
/// This class was selected as a dependency-cycle cut-point: `set_program` takes `Arc<dyn
/// Program>` rather than the concrete `ProgramDB` struct so that `ProgramDB` (or any other core
/// type) can hold a `Box<dyn DBPropertyMapManager>` without creating a compile-time type cycle.
pub trait DBPropertyMapManager: PropertyMapManager + ManagerDB {
    /// Callback from program used to indicate all managers have been created. When this method
    /// is invoked, all managers have been instantiated but may not be fully initialized.
    fn set_program(&mut self, program: Arc<dyn Program>);

    /// Callback from program made to each manager after the program has completed
    /// initialization. This method may be used by managers to perform additional upgrading which
    /// may have been deferred.
    ///
    /// # Errors
    /// Returns an I/O error if a database I/O error occurs, or `Cancelled` if the user cancelled
    /// the operation via `monitor`.
    fn program_ready(
        &mut self,
        open_mode: OpenMode,
        current_revision: i32,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), ProgramReadyError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::util::PropertyMap;
    use crate::program::util::{
        IntPropertyMap, LongPropertyMap, ObjectPropertyMap, StringPropertyMap, VoidPropertyMap,
    };
    use crate::util::exception::DuplicateNameException;
    use crate::util::task::DummyMonitor;
    use std::collections::BTreeMap;

    fn space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    fn addr(offset: i64) -> Address {
        Address::new(space(), offset)
    }

    struct MockProgram {
        name: String,
    }

    impl crate::framework::model::DomainObject for MockProgram {}

    impl Program for MockProgram {
        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn get_language_id(&self) -> String {
            "mock:LE:32:default".to_string()
        }
    }

    #[derive(Default)]
    struct MockIntPropertyMap {
        values: BTreeMap<Address, i32>,
    }

    impl IntPropertyMap for MockIntPropertyMap {
        fn add_int(&mut self, addr: &Address, value: i32) {
            self.values.insert(addr.clone(), value);
        }

        fn get_int(&self, addr: &Address) -> Result<i32, crate::util::exception::NoValueException> {
            self.values
                .get(addr)
                .copied()
                .ok_or_else(crate::util::exception::NoValueException::new)
        }
    }

    /// Mock implementation of [`DBPropertyMapManager`], proving the trait (with its
    /// [`PropertyMapManager`] and [`ManagerDB`] supertraits) is object-safe and can be driven
    /// through a `Box<dyn DBPropertyMapManager>`.
    #[derive(Default)]
    struct MockDBPropertyMapManager {
        int_maps: BTreeMap<String, MockIntPropertyMap>,
        program: Option<Arc<dyn Program>>,
        program_ready_calls: Vec<(OpenMode, i32)>,
        invalidate_calls: Vec<bool>,
        delete_range_calls: usize,
        move_range_calls: usize,
    }

    impl ManagerDB for MockDBPropertyMapManager {
        fn invalidate_cache(&mut self, all: bool) -> io::Result<()> {
            self.invalidate_calls.push(all);
            Ok(())
        }

        fn delete_address_range(&mut self, _start_addr: &Address, _end_addr: &Address) -> io::Result<()> {
            self.delete_range_calls += 1;
            Ok(())
        }

        fn move_address_range(
            &mut self,
            _from_addr: &Address,
            _to_addr: &Address,
            _length: u64,
        ) -> io::Result<()> {
            self.move_range_calls += 1;
            Ok(())
        }
    }

    impl PropertyMapManager for MockDBPropertyMapManager {
        fn create_int_property_map(
            &mut self,
            property_name: &str,
        ) -> Result<Box<dyn IntPropertyMap>, DuplicateNameException> {
            if self.int_maps.contains_key(property_name) {
                return Err(DuplicateNameException::new());
            }
            self.int_maps.insert(property_name.to_string(), MockIntPropertyMap::default());
            Ok(Box::new(MockIntPropertyMap::default()))
        }

        fn create_long_property_map(
            &mut self,
            _property_name: &str,
        ) -> Result<Box<dyn LongPropertyMap>, DuplicateNameException> {
            Err(DuplicateNameException::new())
        }

        fn create_string_property_map(
            &mut self,
            _property_name: &str,
        ) -> Result<Box<dyn StringPropertyMap>, DuplicateNameException> {
            Err(DuplicateNameException::new())
        }

        fn create_object_property_map(
            &mut self,
            _property_name: &str,
        ) -> Result<Box<dyn ObjectPropertyMap>, DuplicateNameException> {
            Err(DuplicateNameException::new())
        }

        fn create_void_property_map(
            &mut self,
            _property_name: &str,
        ) -> Result<Box<dyn VoidPropertyMap>, DuplicateNameException> {
            Err(DuplicateNameException::new())
        }

        fn get_property_map(&self, _property_name: &str) -> Option<Box<dyn PropertyMap>> {
            None
        }

        fn get_int_property_map(&self, _property_name: &str) -> Option<Box<dyn IntPropertyMap>> {
            None
        }

        fn get_long_property_map(&self, _property_name: &str) -> Option<Box<dyn LongPropertyMap>> {
            None
        }

        fn get_string_property_map(&self, _property_name: &str) -> Option<Box<dyn StringPropertyMap>> {
            None
        }

        fn get_object_property_map(&self, _property_name: &str) -> Option<Box<dyn ObjectPropertyMap>> {
            None
        }

        fn get_void_property_map(&self, _property_name: &str) -> Option<Box<dyn VoidPropertyMap>> {
            None
        }

        fn remove_property_map(&mut self, property_name: &str) -> bool {
            self.int_maps.remove(property_name).is_some()
        }

        fn property_managers(&self) -> Box<dyn Iterator<Item = String> + '_> {
            Box::new(self.int_maps.keys().cloned())
        }

        fn remove_all(&mut self, addr: &Address) {
            for map in self.int_maps.values_mut() {
                map.values.remove(addr);
            }
        }

        fn remove_all_range(
            &mut self,
            start_addr: &Address,
            end_addr: &Address,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            for map in self.int_maps.values_mut() {
                map.values.retain(|a, _| !(a >= start_addr && a <= end_addr));
            }
            Ok(())
        }
    }

    impl DBPropertyMapManager for MockDBPropertyMapManager {
        fn set_program(&mut self, program: Arc<dyn Program>) {
            self.program = Some(program);
        }

        fn program_ready(
            &mut self,
            open_mode: OpenMode,
            current_revision: i32,
            monitor: &dyn TaskMonitor,
        ) -> Result<(), ProgramReadyError> {
            if monitor.is_cancelled() {
                return Err(CancelledException::new("program ready cancelled").into());
            }
            self.program_ready_calls.push((open_mode, current_revision));
            Ok(())
        }
    }

    #[test]
    fn drives_full_lifecycle_through_trait_object() {
        let mut mgr: Box<dyn DBPropertyMapManager> = Box::new(MockDBPropertyMapManager::default());

        // setProgram / programReady lifecycle.
        mgr.set_program(Arc::new(MockProgram { name: "prog1".to_string() }));
        assert!(mgr
            .program_ready(OpenMode::Update, 3, &DummyMonitor)
            .is_ok());

        // PropertyMapManager: create then reject duplicate.
        assert!(mgr.create_int_property_map("intMap").is_ok());
        assert!(mgr.create_int_property_map("intMap").is_err());

        let names: Vec<_> = mgr.property_managers().collect();
        assert_eq!(names, vec!["intMap".to_string()]);

        // ManagerDB: invalidate/delete/move all delegate through the supertrait.
        assert!(mgr.invalidate_cache(true).is_ok());
        assert!(mgr.delete_address_range(&addr(0), &addr(0x10)).is_ok());
        assert!(mgr.move_address_range(&addr(0), &addr(0x100), 0x10).is_ok());

        assert!(mgr.remove_property_map("intMap"));
        assert!(!mgr.remove_property_map("intMap"));

        let names: Vec<_> = mgr.property_managers().collect();
        assert!(names.is_empty());
    }

    #[test]
    fn program_ready_reports_cancellation() {
        struct CancelledMonitor;
        impl TaskMonitor for CancelledMonitor {
            fn is_cancelled(&self) -> bool {
                true
            }
            fn set_show_progress_value(&self, _show: bool) {}
            fn set_message(&self, _message: &str) {}
            fn get_message(&self) -> String {
                String::new()
            }
            fn set_progress(&self, _value: i64) {}
            fn initialize(&self, _max: i64) {}
            fn set_maximum(&self, _max: i64) {}
            fn get_maximum(&self) -> i64 {
                0
            }
            fn set_indeterminate(&self, _indeterminate: bool) {}
            fn is_indeterminate(&self) -> bool {
                false
            }
            fn check_cancelled(&self) -> Result<(), CancelledException> {
                Err(CancelledException::new("cancelled"))
            }
            fn increment_progress(&self, _amount: i64) {}
            fn get_progress(&self) -> i64 {
                -1
            }
            fn cancel(&self) {}
            fn add_cancelled_listener(&self, _listener: Box<dyn crate::util::task::CancelledListener>) {}
            fn remove_cancelled_listener(&self, _listener: &dyn crate::util::task::CancelledListener) {}
            fn set_cancel_enabled(&self, _enabled: bool) {}
            fn is_cancel_enabled(&self) -> bool {
                true
            }
            fn clear_cancelled(&self) {}
        }

        let mut mgr = MockDBPropertyMapManager::default();
        let result = mgr.program_ready(OpenMode::Create, 0, &CancelledMonitor);
        assert!(matches!(result, Err(ProgramReadyError::Cancelled(_))));
    }
}

//! A store for loaded modules over time.
//!
//! Port of `ghidra.trace.model.modules.TraceModuleManager`.
//!
//! The manager is not bound to any particular address space and may be used to access
//! information about any memory address. For module and section management, only section
//! information can be space bound.
//!
//! Java's default `addLoadedModule(String, String, AddressRange, long)` constructs a
//! `Lifespan.nowOn(snap)` and delegates to [`TraceModuleManager::add_module`]. This crate's
//! [`Lifespan`] is a trait with no concrete, generically-constructible implementor yet (unlike
//! Java's sealed `Lifespan`, whose `nowOn` factory always produces a usable `Impl`), so there is
//! no way to build that span from just a `snap` inside a default method body. `add_loaded_module`
//! is therefore a required method here rather than a default.

use crate::program::model::address::AddressRange;
use crate::trace::model::lifespan::Lifespan;
use crate::trace::model::modules::trace_module::TraceModule;
use crate::trace::model::modules::trace_module_operations::TraceModuleOperations;
use crate::trace::model::modules::trace_section::TraceSection;
use crate::util::exception::DuplicateNameException;

/// A store for loaded modules over time.
pub trait TraceModuleManager: TraceModuleOperations {
    /// Add a module.
    ///
    /// Note that modules may overlap.
    ///
    /// # Errors
    /// Returns an error if another module with the same name already exists for the desired
    /// lifespan.
    fn add_module(
        &mut self,
        module_path: &str,
        module_name: &str,
        range: AddressRange,
        lifespan: Lifespan,
    ) -> Result<Box<dyn TraceModule>, DuplicateNameException>;

    /// Add a module which is still loaded.
    ///
    /// Mirrors Java's default `addLoadedModule(String, String, AddressRange, long)`, which
    /// delegates to [`Self::add_module`] with `Lifespan.nowOn(snap)`. See the module-level docs
    /// for why this is a required rather than default method in this port.
    ///
    /// # Errors
    /// Returns an error if another module with the same name already exists for the desired
    /// lifespan.
    fn add_loaded_module(
        &mut self,
        module_path: &str,
        module_name: &str,
        range: AddressRange,
        snap: i64,
    ) -> Result<Box<dyn TraceModule>, DuplicateNameException>;

    /// Get modules by path.
    ///
    /// Note it is possible the same module was loaded and unloaded multiple times. In that
    /// case, each load will have a separate record. It is also possible it was loaded at a
    /// different address, or that it's an entirely different module which happens to have the
    /// same path.
    ///
    /// Note that the "module path" in this case is not necessarily the path of the module's
    /// image on the target file system, though this name often contains it. Rather, this is
    /// typically the full path to the module in the target debugger's object model. Likely, the
    /// "short name" is the file system path of the module's image.
    fn get_modules_by_path(&self, module_path: &str) -> Vec<Box<dyn TraceModule>>;

    /// Get the module loaded at the given snap having the given path, or `None` if no module
    /// matches.
    fn get_loaded_module_by_path(&self, snap: i64, module_path: &str) -> Option<Box<dyn TraceModule>>;

    /// Get sections by path.
    ///
    /// Note because it's possible for a module path to be duplicated (but not within any
    /// overlapping snap), it is also possible for a section path to be duplicated.
    fn get_sections_by_path(&self, section_path: &str) -> Vec<Box<dyn TraceSection>>;

    /// Get the section loaded at the given snap having the given path, or `None` if no section
    /// matches.
    fn get_loaded_section_by_path(&self, snap: i64, section_path: &str) -> Option<Box<dyn TraceSection>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::trace::model::target::info::trace_object_info::TraceObjectInfo;
    use crate::trace::model::trace::Trace;
    use crate::trace::model::trace_unique_object::TraceUniqueObject;
    use crate::trace::seam_stubs::{ObjectKey, TraceObjectInterface};
    use std::cell::RefCell;

    struct MockObjectKey(i32);

    impl ObjectKey for MockObjectKey {
        fn equals(&self, obj: &dyn std::any::Any) -> bool {
            obj.downcast_ref::<MockObjectKey>()
                .is_some_and(|other| other.0 == self.0)
        }

        fn hash_code(&self) -> i32 {
            self.0
        }

        fn compare_to(&self, that: &dyn ObjectKey) -> i32 {
            self.hash_code() - that.hash_code()
        }
    }

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0);
        Address::new(space, offset)
    }



    #[derive(Clone)]
    struct MockModule {
        path: String,
        range: AddressRange,
    }

    impl TraceUniqueObject for MockModule {
        fn get_object_key(&self) -> Box<dyn ObjectKey> {
            Box::new(MockObjectKey(1))
        }

        fn is_deleted(&self) -> bool {
            false
        }
    }

    impl TraceObjectInterface for MockModule {}

    impl TraceModule for MockModule {
        fn get_trace(&self) -> Box<dyn Trace> {
            unimplemented!("not exercised by this smoke test")
        }

        fn add_section(
            &mut self,
            _snap: i64,
            _section_path: &str,
            _section_name: Option<&str>,
            _range: AddressRange,
        ) -> Result<Box<dyn TraceSection>, DuplicateNameException> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_path(&self) -> String {
            self.path.clone()
        }

        fn set_name(&mut self, _lifespan: Lifespan, _name: &str) {}

        fn set_name_at(&mut self, _snap: i64, _name: &str) {}

        fn get_name(&self, _snap: i64) -> String {
            self.path.clone()
        }

        fn set_range(&mut self, _lifespan: Lifespan, range: AddressRange) {
            self.range = range;
        }

        fn set_range_at(&mut self, _snap: i64, range: AddressRange) {
            self.range = range;
        }

        fn get_range(&self, _snap: i64) -> AddressRange {
            self.range.clone()
        }

        fn set_base(&mut self, _snap: i64, _base: Address) {}

        fn get_base(&self, _snap: i64) -> Address {
            self.range.min_address().clone()
        }

        fn set_max_address(&mut self, _snap: i64, _max: Address) {}

        fn get_max_address(&self, _snap: i64) -> Address {
            self.range.max_address().clone()
        }

        fn set_length(&mut self, _snap: i64, _length: i64) -> Result<(), crate::program::model::address::AddressOverflowException> {
            Ok(())
        }

        fn get_length(&self, _snap: i64) -> i64 {
            self.range.length() as i64
        }

        fn get_sections(&self, _snap: i64) -> Vec<Box<dyn TraceSection>> {
            Vec::new()
        }

        fn get_all_sections(&self) -> Vec<Box<dyn TraceSection>> {
            Vec::new()
        }

        fn get_section_by_name(&self, _snap: i64, _section_name: &str) -> Option<Box<dyn TraceSection>> {
            None
        }

        fn delete(&mut self) {}

        fn remove(&mut self, _snap: i64) {}

        fn is_valid(&self, _snap: i64) -> bool {
            true
        }

        fn is_alive(&self, _span: Lifespan) -> bool {
            true
        }
    }

    /// A minimal in-memory manager holding modules keyed by path, used to prove
    /// `TraceModuleManager` is object-safe and that `add_module`/lookup-by-path actually
    /// store and filter (not just return everything or nothing).
    #[derive(Default)]
    struct MockManager {
        modules: RefCell<Vec<MockModule>>,
    }

    impl TraceModuleOperations for MockManager {
        fn get_all_modules(&self) -> Vec<Box<dyn TraceModule>> {
            self.modules
                .borrow()
                .iter()
                .cloned()
                .map(|m| Box::new(m) as Box<dyn TraceModule>)
                .collect()
        }

        fn get_loaded_modules(&self, _snap: i64) -> Vec<Box<dyn TraceModule>> {
            self.get_all_modules()
        }

        fn get_modules_at(&self, _snap: i64, address: &Address) -> Vec<Box<dyn TraceModule>> {
            self.modules
                .borrow()
                .iter()
                .filter(|m| m.range.contains(address))
                .cloned()
                .map(|m| Box::new(m) as Box<dyn TraceModule>)
                .collect()
        }

        fn get_modules_intersecting(
            &self,
            _lifespan: Lifespan,
            range: &AddressRange,
        ) -> Vec<Box<dyn TraceModule>> {
            self.modules
                .borrow()
                .iter()
                .filter(|m| m.range.intersects(range))
                .cloned()
                .map(|m| Box::new(m) as Box<dyn TraceModule>)
                .collect()
        }

        fn get_all_sections(&self) -> Vec<Box<dyn TraceSection>> {
            Vec::new()
        }

        fn get_sections_at(&self, _snap: i64, _address: &Address) -> Vec<Box<dyn TraceSection>> {
            Vec::new()
        }

        fn get_sections_intersecting(
            &self,
            _lifespan: Lifespan,
            _range: &AddressRange,
        ) -> Vec<Box<dyn TraceSection>> {
            Vec::new()
        }
    }

    impl TraceModuleManager for MockManager {
        fn add_module(
            &mut self,
            module_path: &str,
            _module_name: &str,
            range: AddressRange,
            _lifespan: Lifespan,
        ) -> Result<Box<dyn TraceModule>, DuplicateNameException> {
            if self.modules.borrow().iter().any(|m| m.path == module_path) {
                return Err(DuplicateNameException::with_message(module_path));
            }
            let m = MockModule {
                path: module_path.to_string(),
                range,
            };
            self.modules.borrow_mut().push(m.clone());
            Ok(Box::new(m))
        }

        fn add_loaded_module(
            &mut self,
            module_path: &str,
            module_name: &str,
            range: AddressRange,
            snap: i64,
        ) -> Result<Box<dyn TraceModule>, DuplicateNameException> {
            self.add_module(
                module_path,
                module_name,
                range,
                Lifespan::span(snap, i64::MAX),
            )
        }

        fn get_modules_by_path(&self, module_path: &str) -> Vec<Box<dyn TraceModule>> {
            self.modules
                .borrow()
                .iter()
                .filter(|m| m.path == module_path)
                .cloned()
                .map(|m| Box::new(m) as Box<dyn TraceModule>)
                .collect()
        }

        fn get_loaded_module_by_path(&self, _snap: i64, module_path: &str) -> Option<Box<dyn TraceModule>> {
            self.modules
                .borrow()
                .iter()
                .find(|m| m.path == module_path)
                .cloned()
                .map(|m| Box::new(m) as Box<dyn TraceModule>)
        }

        fn get_sections_by_path(&self, _section_path: &str) -> Vec<Box<dyn TraceSection>> {
            Vec::new()
        }

        fn get_loaded_section_by_path(&self, _snap: i64, _section_path: &str) -> Option<Box<dyn TraceSection>> {
            None
        }
    }

    #[test]
    fn add_module_rejects_duplicate_path() {
        let mut mgr = MockManager::default();
        let lifespan = Lifespan::span(0, i64::MAX);
        let range = AddressRange::new(addr(0x1000), addr(0x1fff));
        assert!(mgr
            .add_module("Modules[libc.so]", "libc.so", range.clone(), lifespan)
            .is_ok());
        let result = mgr.add_module("Modules[libc.so]", "libc.so", range, lifespan);
        match result {
            Ok(_) => panic!("expected duplicate-name error"),
            Err(err) => assert!(err.0.contains("Modules[libc.so]")),
        }
    }

    #[test]
    fn get_modules_by_path_and_loaded_by_path_find_added_module() {
        let mut mgr = MockManager::default();
        let range = AddressRange::new(addr(0x2000), addr(0x2fff));
        mgr.add_loaded_module("Modules[a.so]", "a.so", range, 5).unwrap();

        assert_eq!(mgr.get_modules_by_path("Modules[a.so]").len(), 1);
        assert!(mgr.get_modules_by_path("Modules[missing]").is_empty());

        let found = mgr.get_loaded_module_by_path(5, "Modules[a.so]");
        assert!(found.is_some());
        assert_eq!(found.unwrap().get_path(), "Modules[a.so]");
        assert!(mgr.get_loaded_module_by_path(5, "Modules[missing]").is_none());
    }

    #[test]
    fn trait_object_is_object_safe() {
        let mut mgr = MockManager::default();
        let ops: &mut dyn TraceModuleManager = &mut mgr;
        let range = AddressRange::new(addr(0x3000), addr(0x3fff));
        assert!(ops.add_loaded_module("Modules[x]", "x", range, 0).is_ok());
        assert_eq!(ops.get_all_modules().len(), 1);
    }
}

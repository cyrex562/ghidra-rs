//! Operations for retrieving modules and sections from a trace.
//!
//! Port of `ghidra.trace.model.modules.TraceModuleOperations`.
//!
//! Modules do not occupy target memory in and of themselves, but rather, their sections do. Thus,
//! only the section information is mapped out by memory address. Each section inherits its
//! lifespan from the containing module.

use crate::program::model::address::{Address, AddressRange};
use crate::trace::model::lifespan::Lifespan;
use crate::trace::model::modules::trace_module::TraceModule;
use crate::trace::model::modules::trace_section::TraceSection;

/// Operations for retrieving sections from a trace.
pub trait TraceModuleOperations {
    /// Get all modules.
    fn get_all_modules(&self) -> Vec<Box<dyn TraceModule>>;

    /// Get all modules loaded at the given snap.
    fn get_loaded_modules(&self, snap: i64) -> Vec<Box<dyn TraceModule>>;

    /// Get modules at the given snap and address.
    fn get_modules_at(&self, snap: i64, address: &Address) -> Vec<Box<dyn TraceModule>>;

    /// Get the modules loaded at the given snap intersecting the given address range.
    fn get_modules_intersecting(
        &self,
        lifespan: Lifespan,
        range: &AddressRange,
    ) -> Vec<Box<dyn TraceModule>>;

    /// Get all sections.
    fn get_all_sections(&self) -> Vec<Box<dyn TraceSection>>;

    /// Get sections at the given snap and address.
    fn get_sections_at(&self, snap: i64, address: &Address) -> Vec<Box<dyn TraceSection>>;

    /// Get the sections loaded at the given snap intersecting the given address range.
    fn get_sections_intersecting(
        &self,
        lifespan: Lifespan,
        range: &AddressRange,
    ) -> Vec<Box<dyn TraceSection>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressOverflowException, AddressSpace, AddressSpaceType};
    use crate::trace::model::target::info::trace_object_info::TraceObjectInfo;
    use crate::trace::model::trace::Trace;
    use crate::trace::model::trace_unique_object::TraceUniqueObject;
    use crate::trace::model::target::iface::TraceObjectInterface;
    use crate::trace::seam_stubs::ObjectKey;
    use crate::util::exception::DuplicateNameException;

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

    impl TraceObjectInterface for MockModule {
        fn get_object(&self) -> Box<dyn crate::trace::model::target::trace_object::TraceObject> {
            unimplemented!("mock")
        }
    }

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

        fn set_length(&mut self, _snap: i64, _length: i64) -> Result<(), AddressOverflowException> {
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

    struct MockSection {
        path: String,
    }

    impl TraceUniqueObject for MockSection {
        fn get_object_key(&self) -> Box<dyn ObjectKey> {
            Box::new(MockObjectKey(2))
        }

        fn is_deleted(&self) -> bool {
            false
        }
    }

    impl TraceObjectInterface for MockSection {
        fn get_object(&self) -> Box<dyn crate::trace::model::target::trace_object::TraceObject> {
            unimplemented!("mock")
        }
    }

    impl TraceSection for MockSection {
        fn get_trace(&self) -> Box<dyn Trace> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_module(&self) -> Box<dyn TraceModule> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_path(&self) -> String {
            self.path.clone()
        }

        fn set_name(&mut self, _lifespan: Lifespan, _name: &str) {}

        fn set_name_at(&mut self, _snap: i64, _name: &str) -> Result<(), DuplicateNameException> {
            Ok(())
        }

        fn get_name(&self, _snap: i64) -> String {
            self.path.clone()
        }

        fn set_range(&mut self, _lifespan: Lifespan, _range: AddressRange) {}

        fn get_range(&self, _snap: i64) -> Option<AddressRange> {
            None
        }

        fn delete(&mut self) {}

        fn remove(&mut self, _snap: i64) {}

        fn is_valid(&self, _snap: i64) -> bool {
            true
        }
    }

    /// A minimal in-memory implementor holding one module and one section, used to prove
    /// `TraceModuleOperations` is object-safe and that the intersection/at queries actually
    /// filter (not just return everything or nothing).
    struct MockTrace {
        module_range: AddressRange,
        section_range: AddressRange,
    }

    impl TraceModuleOperations for MockTrace {
        fn get_all_modules(&self) -> Vec<Box<dyn TraceModule>> {
            vec![Box::new(MockModule {
                path: "Modules[libc.so]".to_string(),
                range: self.module_range.clone(),
            })]
        }

        fn get_loaded_modules(&self, _snap: i64) -> Vec<Box<dyn TraceModule>> {
            self.get_all_modules()
        }

        fn get_modules_at(&self, _snap: i64, address: &Address) -> Vec<Box<dyn TraceModule>> {
            if self.module_range.contains(address) {
                self.get_all_modules()
            } else {
                Vec::new()
            }
        }

        fn get_modules_intersecting(
            &self,
            _lifespan: Lifespan,
            range: &AddressRange,
        ) -> Vec<Box<dyn TraceModule>> {
            if self.module_range.intersects(range) {
                self.get_all_modules()
            } else {
                Vec::new()
            }
        }

        fn get_all_sections(&self) -> Vec<Box<dyn TraceSection>> {
            vec![Box::new(MockSection { path: ".text".to_string() })]
        }

        fn get_sections_at(&self, _snap: i64, address: &Address) -> Vec<Box<dyn TraceSection>> {
            if self.section_range.contains(address) {
                self.get_all_sections()
            } else {
                Vec::new()
            }
        }

        fn get_sections_intersecting(
            &self,
            _lifespan: Lifespan,
            range: &AddressRange,
        ) -> Vec<Box<dyn TraceSection>> {
            if self.section_range.intersects(range) {
                self.get_all_sections()
            } else {
                Vec::new()
            }
        }
    }



    fn make_trace() -> MockTrace {
        MockTrace {
            module_range: AddressRange::new(addr(0x1000), addr(0x1fff)),
            section_range: AddressRange::new(addr(0x1000), addr(0x10ff)),
        }
    }

    #[test]
    fn modules_at_filters_by_address() {
        let trace = make_trace();
        assert_eq!(trace.get_modules_at(0, &addr(0x1500)).len(), 1);
        assert!(trace.get_modules_at(0, &addr(0x5000)).is_empty());
    }

    #[test]
    fn sections_intersecting_filters_by_range() {
        let trace = make_trace();
        let span = Lifespan::span(0, 10);

        let overlapping = AddressRange::new(addr(0x1080), addr(0x2000));
        assert_eq!(
            trace.get_sections_intersecting(span, &overlapping).len(),
            1
        );

        let disjoint = AddressRange::new(addr(0x5000), addr(0x5fff));
        assert!(trace.get_sections_intersecting(span, &disjoint).is_empty());
    }

    #[test]
    fn trait_object_is_object_safe() {
        let trace = make_trace();
        let ops: &dyn TraceModuleOperations = &trace;
        assert_eq!(ops.get_all_modules().len(), 1);
        assert_eq!(ops.get_all_sections().len(), 1);
    }
}

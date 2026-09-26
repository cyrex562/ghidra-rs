//! A binary module loaded by the target and/or debugger.
//!
//! Port of `ghidra.trace.model.modules.TraceModule`.
//!
//! This also serves as a namespace for storing the module's sections. If the debugger cares to
//! parse the modules for section information, those sections should be presented as successors to
//! the module.
//!
//! Java's `setName(Lifespan, String)`/`setName(long, String)` and `setRange(Lifespan,
//! AddressRange)`/`setRange(long, AddressRange)` overloads are given distinct names, mirroring
//! the convention used for
//! [`TraceSection`](crate::trace::model::modules::trace_section::TraceSection): the lifespan form
//! keeps the base name ([`TraceModule::set_name`]/[`TraceModule::set_range`]), while the
//! single-snap form gets an `_at` suffix ([`TraceModule::set_name_at`]/[`TraceModule::set_range_at`]).
//! Likewise, the two `addSection` overloads become [`TraceModule::add_section`] (the full,
//! abstract form) and a default [`TraceModule::add_section_default_name`] (mirroring Java's
//! `addSection(long, String, AddressRange)`, which passes a `null` section name through).

use crate::program::model::address::{Address, AddressOverflowException, AddressRange};
use crate::trace::model::lifespan::Lifespan;
use crate::trace::model::modules::trace_section::TraceSection;
use crate::trace::model::target::info::trace_object_info::TraceObjectInfo;
use crate::trace::model::trace::Trace;
use crate::trace::model::trace_unique_object::TraceUniqueObject;
use crate::trace::model::target::iface::TraceObjectInterface;
use crate::util::exception::DuplicateNameException;

/// Key for the module's address-range attribute.
pub const KEY_RANGE: &str = "_range";
/// Key for the module's full-name attribute.
pub const KEY_MODULE_NAME: &str = "_module_name";

/// A binary module loaded by the target and/or debugger.
pub trait TraceModule: TraceUniqueObject + TraceObjectInterface {
    /// Returns the `@TraceObjectInfo` metadata mirrored from the Java annotation on
    /// `TraceModule`.
    fn trace_object_info() -> TraceObjectInfo
    where
        Self: Sized,
    {
        TraceObjectInfo::new(
            "Module",
            "module",
            [KEY_RANGE, KEY_MODULE_NAME],
            ["_display", KEY_RANGE],
        )
    }

    /// Get the trace containing this module.
    fn get_trace(&self) -> Box<dyn Trace>;

    /// Add a section to this module.
    ///
    /// Note while rare, it is permissible for sections to overlap. Module and section records are
    /// more informational and provide a means of recording module load and unload events, while
    /// noting the sections of which the debugger was aware. Typically each section, meeting
    /// certain criteria set by the target, is mapped into a memory region. Those regions cannot
    /// overlap. Furthermore, any overlapped mappings to static modules, which are usually derived
    /// from sections stored here, must agree on the address adjustment.
    ///
    /// # Errors
    /// Returns an error if a section with the given name already exists in this module.
    fn add_section(
        &mut self,
        snap: i64,
        section_path: &str,
        section_name: Option<&str>,
        range: AddressRange,
    ) -> Result<Box<dyn TraceSection>, DuplicateNameException>;

    /// Add a section having the same full and short names.
    ///
    /// See [`Self::add_section`].
    ///
    /// # Errors
    /// Returns an error if a section with the given name already exists in this module.
    fn add_section_default_name(
        &mut self,
        snap: i64,
        section_path: &str,
        range: AddressRange,
    ) -> Result<Box<dyn TraceSection>, DuplicateNameException> {
        self.add_section(snap, section_path, None, range)
    }

    /// Get the "full name" of this module.
    ///
    /// This is a unique key (within any snap) for retrieving the module, and may not be suitable
    /// for display on the screen. This is not likely the file system path of the module's image.
    /// Rather, it's typically the path of the module in the target debugger's object model.
    fn get_path(&self) -> String;

    /// Set the "short name" of this module across the given span of time.
    ///
    /// The given name is typically the file system path of the module's image, which is
    /// considered suitable for display on the screen.
    fn set_name(&mut self, lifespan: Lifespan, name: &str);

    /// Set the "short name" of this module from the given snap on.
    ///
    /// See [`Self::set_name`].
    fn set_name_at(&mut self, snap: i64, name: &str);

    /// Get the "short name" of this module.
    ///
    /// This defaults to the "full name," but can be modified via [`Self::set_name_at`].
    fn get_name(&self, snap: i64) -> String;

    /// Set the address range of the module across the given span of time.
    ///
    /// Typically, the minimum address in this range is the module's base address. If sections are
    /// given, this range should enclose all sections mapped into memory.
    fn set_range(&mut self, lifespan: Lifespan, range: AddressRange);

    /// Set the address range of the module from the given snap on.
    ///
    /// See [`Self::set_range`].
    fn set_range_at(&mut self, snap: i64, range: AddressRange);

    /// Get the address range of the module.
    ///
    /// See [`Self::set_range_at`].
    fn get_range(&self, snap: i64) -> AddressRange;

    /// Set the base (usually minimum) address of the module.
    ///
    /// If not given by the target's debugger, the model or the recorder should endeavor to
    /// compute it from whatever information is provided. In general, this should be the virtual
    /// memory address mapped to file offset 0 of the module's image.
    ///
    /// Note that this sets the range from the given snap on to the same range, no matter what
    /// changes may have occurred since.
    fn set_base(&mut self, snap: i64, base: Address);

    /// Get the base address of the module.
    fn get_base(&self, snap: i64) -> Address;

    /// Set the maximum address of the module.
    ///
    /// Note that this sets the range from the given snap on to the same range, no matter what
    /// changes may have occurred since.
    ///
    /// See [`Self::set_range_at`].
    fn set_max_address(&mut self, snap: i64, max: Address);

    /// Get the maximum address of the module.
    ///
    /// See [`Self::set_range_at`].
    fn get_max_address(&self, snap: i64) -> Address;

    /// Set the length of the range of the module.
    ///
    /// This adjusts the max address of the range so that its length becomes that given. Note that
    /// this sets the range from the given snap on to the same range, no matter what changes may
    /// have occurred since.
    ///
    /// See [`Self::set_range_at`].
    ///
    /// # Errors
    /// Returns an error if the length would cause the max address to overflow.
    fn set_length(&mut self, snap: i64, length: i64) -> Result<(), AddressOverflowException>;

    /// Get the length of the range of the module.
    ///
    /// See [`Self::set_range_at`].
    fn get_length(&self, snap: i64) -> i64;

    /// Collect all sections contained within this module at the given snap.
    fn get_sections(&self, snap: i64) -> Vec<Box<dyn TraceSection>>;

    /// Collect all sections contained within this module at any time.
    fn get_all_sections(&self) -> Vec<Box<dyn TraceSection>>;

    /// Get the section in this module having the given short name, if any.
    fn get_section_by_name(&self, snap: i64, section_name: &str) -> Option<Box<dyn TraceSection>>;

    /// Delete this module and its sections from the trace.
    fn delete(&mut self);

    /// Remove this module from the given snap on.
    fn remove(&mut self, snap: i64);

    /// Check if the module is valid at the given snapshot.
    fn is_valid(&self, snap: i64) -> bool;

    /// Check if the module is alive for any of the given span.
    fn is_alive(&self, span: Lifespan) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::trace::seam_stubs::ObjectKey;
    use std::sync::Mutex;

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

    /// A section stub returned by [`MockModule::add_section`], just enough to prove the returned
    /// value is usable as a `Box<dyn TraceSection>`.
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

    impl crate::trace::model::target::iface::TraceObjectInterface for MockSection {
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

    /// A minimal in-memory module backing a single, unversioned name/range pair and a list of
    /// section names, used to prove the trait is object-safe and its default method behaves
    /// correctly.
    struct MockModule {
        path: String,
        name: Mutex<String>,
        range: Mutex<AddressRange>,
        sections: Mutex<Vec<String>>,
        deleted: bool,
    }

    impl TraceUniqueObject for MockModule {
        fn get_object_key(&self) -> Box<dyn ObjectKey> {
            Box::new(MockObjectKey(1))
        }

        fn is_deleted(&self) -> bool {
            self.deleted
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
            section_path: &str,
            _section_name: Option<&str>,
            _range: AddressRange,
        ) -> Result<Box<dyn TraceSection>, DuplicateNameException> {
            let mut sections = self.sections.lock().unwrap();
            if sections.iter().any(|s| s == section_path) {
                return Err(DuplicateNameException::with_message(section_path.to_string()));
            }
            sections.push(section_path.to_string());
            Ok(Box::new(MockSection { path: section_path.to_string() }))
        }

        fn get_path(&self) -> String {
            self.path.clone()
        }

        fn set_name(&mut self, _lifespan: Lifespan, name: &str) {
            *self.name.lock().unwrap() = name.to_string();
        }

        fn set_name_at(&mut self, _snap: i64, name: &str) {
            *self.name.lock().unwrap() = name.to_string();
        }

        fn get_name(&self, _snap: i64) -> String {
            self.name.lock().unwrap().clone()
        }

        fn set_range(&mut self, _lifespan: Lifespan, range: AddressRange) {
            *self.range.lock().unwrap() = range;
        }

        fn set_range_at(&mut self, _snap: i64, range: AddressRange) {
            *self.range.lock().unwrap() = range;
        }

        fn get_range(&self, _snap: i64) -> AddressRange {
            self.range.lock().unwrap().clone()
        }

        fn set_base(&mut self, _snap: i64, base: Address) {
            let max = self.range.lock().unwrap().max_address().clone();
            *self.range.lock().unwrap() = AddressRange::new(base, max);
        }

        fn get_base(&self, _snap: i64) -> Address {
            self.range.lock().unwrap().min_address().clone()
        }

        fn set_max_address(&mut self, _snap: i64, max: Address) {
            let min = self.range.lock().unwrap().min_address().clone();
            *self.range.lock().unwrap() = AddressRange::new(min, max);
        }

        fn get_max_address(&self, _snap: i64) -> Address {
            self.range.lock().unwrap().max_address().clone()
        }

        fn set_length(&mut self, _snap: i64, length: i64) -> Result<(), AddressOverflowException> {
            let min = self.range.lock().unwrap().min_address().clone();
            let max = min.add_no_wrap(length - 1)?;
            *self.range.lock().unwrap() = AddressRange::new(min, max);
            Ok(())
        }

        fn get_length(&self, _snap: i64) -> i64 {
            self.range.lock().unwrap().length() as i64
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

        fn delete(&mut self) {
            self.deleted = true;
        }

        fn remove(&mut self, _snap: i64) {}

        fn is_valid(&self, _snap: i64) -> bool {
            !self.deleted
        }

        fn is_alive(&self, span: Lifespan) -> bool {
            !self.deleted && span.contains(0)
        }
    }

    fn make_module() -> MockModule {
        MockModule {
            path: "Modules[libc.so]".to_string(),
            name: Mutex::new("libc.so".to_string()),
            range: Mutex::new(AddressRange::new(addr(0x1000), addr(0x1fff))),
            sections: Mutex::new(Vec::new()),
            deleted: false,
        }
    }

    #[test]
    fn add_section_default_name_delegates_to_add_section() {
        let mut module = make_module();
        let section = module
            .add_section_default_name(0, ".text", AddressRange::new(addr(0x2000), addr(0x2fff)))
            .expect("first section with this path should succeed");
        assert_eq!(section.get_path(), ".text");
        assert_eq!(module.sections.lock().unwrap().as_slice(), [".text"]);

        // A second call with the same path is rejected by add_section itself, proving the
        // default method threaded the section path through rather than swallowing it.
        assert!(module
            .add_section_default_name(0, ".text", AddressRange::new(addr(0x3000), addr(0x3fff)))
            .is_err());
        assert_eq!(module.sections.lock().unwrap().len(), 1);
    }

    #[test]
    fn set_base_and_max_address_adjust_range() {
        let mut module = make_module();
        module.set_base(0, addr(0x1500));
        assert_eq!(module.get_base(0), addr(0x1500));
        assert_eq!(module.get_max_address(0), addr(0x1fff));

        module.set_max_address(0, addr(0x2fff));
        assert_eq!(module.get_max_address(0), addr(0x2fff));
        assert_eq!(module.get_range(0), AddressRange::new(addr(0x1500), addr(0x2fff)));
    }

    #[test]
    fn set_length_grows_range_from_base() {
        let mut module = make_module();
        module.set_base(0, addr(0x1000));
        module.set_length(0, 0x100).unwrap();
        assert_eq!(module.get_length(0), 0x100);
        assert_eq!(module.get_max_address(0), addr(0x10ff));
    }

    #[test]
    fn trait_object_is_object_safe() {
        let mut module: Box<dyn TraceModule> = Box::new(make_module());
        assert!(module.is_valid(0));
        module.delete();
        assert!(!module.is_valid(0));
    }
}

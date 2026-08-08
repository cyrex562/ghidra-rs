//! An allocated section of a binary module.
//!
//! Port of `ghidra.trace.model.modules.TraceSection`.
//!
//! Note that the model should only present those sections which are allocated in memory.
//! Otherwise strange things may happen, such as zero-length ranges (which [`AddressRange`]
//! hates), or overlapping ranges (which [`Trace`] hates).
//!
//! Java's `setName(Lifespan, String)` and `setName(long, String)` overloads are given distinct
//! names, mirroring the convention used for
//! [`TraceMemoryRegion`](crate::trace::model::memory::trace_memory_region::TraceMemoryRegion):
//! the lifespan form keeps the base name ([`TraceSection::set_name`]), while the single-snap form
//! (which additionally may fail with a [`DuplicateNameException`]) gets an `_at` suffix
//! ([`TraceSection::set_name_at`]).

use crate::program::model::address::{Address, AddressRange};
use crate::trace::model::lifespan::Lifespan;
use crate::trace::model::modules::trace_module::TraceModule;
use crate::trace::model::target::info::trace_object_info::TraceObjectInfo;
use crate::trace::model::trace::Trace;
use crate::trace::model::trace_unique_object::TraceUniqueObject;
use crate::trace::seam_stubs::TraceObjectInterface;
use crate::util::exception::DuplicateNameException;

/// Key for the section's module-owner attribute.
pub const KEY_MODULE: &str = "_module";
/// Key for the section's address-range attribute.
pub const KEY_RANGE: &str = "_range";

/// An allocated section of a binary module.
pub trait TraceSection: TraceUniqueObject + TraceObjectInterface {
    /// Returns the `@TraceObjectInfo` metadata mirrored from the Java annotation on
    /// `TraceSection`.
    fn trace_object_info() -> TraceObjectInfo
    where
        Self: Sized,
    {
        TraceObjectInfo::new(
            "Section",
            "section",
            [KEY_MODULE, KEY_RANGE],
            ["_display", KEY_RANGE],
        )
    }

    /// Get the trace containing this section.
    fn get_trace(&self) -> Box<dyn Trace>;

    /// Get the module containing this section.
    fn get_module(&self) -> Box<dyn TraceModule>;

    /// Get the "full name" of this section.
    ///
    /// This is a unique key (within a snap) among all sections, and may not be suitable for
    /// display on the screen.
    fn get_path(&self) -> String;

    /// Set the short name of this section across the given span of time.
    ///
    /// The given name should be the section's name from its module's image, which is considered
    /// suitable for display on the screen.
    fn set_name(&mut self, lifespan: Lifespan, name: &str);

    /// Set the short name of this section from the given snap on.
    ///
    /// The given name should be the section's name from its module's image, which is considered
    /// suitable for display on the screen.
    ///
    /// # Errors
    /// Returns an error if the specified name would conflict with another section's in this
    /// module.
    fn set_name_at(&mut self, snap: i64, name: &str) -> Result<(), DuplicateNameException>;

    /// Get the "short name" of this section.
    ///
    /// This defaults to the "full name," but can be modified via [`Self::set_name_at`].
    fn get_name(&self, snap: i64) -> String;

    /// Set the virtual memory address range of this section across the given span of time.
    fn set_range(&mut self, lifespan: Lifespan, range: AddressRange);

    /// Get the virtual memory address range of this section.
    fn get_range(&self, snap: i64) -> Option<AddressRange>;

    /// See [`Self::get_range`]; the min address in the range.
    fn get_start(&self, snap: i64) -> Option<Address> {
        self.get_range(snap).map(|range| range.min_address().clone())
    }

    /// See [`Self::get_range`]; the max address in the range.
    fn get_end(&self, snap: i64) -> Option<Address> {
        self.get_range(snap).map(|range| range.max_address().clone())
    }

    /// Delete this section from the trace.
    fn delete(&mut self);

    /// Remove this section from the given snap on.
    fn remove(&mut self, snap: i64);

    /// Check if the section is valid at the given snapshot.
    fn is_valid(&self, snap: i64) -> bool;
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

    /// A minimal in-memory section backing a single, unversioned name/range pair, used to prove
    /// the trait is object-safe and its default methods behave correctly.
    struct MockSection {
        name: Mutex<String>,
        range: Mutex<Option<AddressRange>>,
        deleted: bool,
    }

    impl TraceUniqueObject for MockSection {
        fn get_object_key(&self) -> Box<dyn ObjectKey> {
            Box::new(MockObjectKey(1))
        }

        fn is_deleted(&self) -> bool {
            self.deleted
        }
    }

    impl TraceObjectInterface for MockSection {}

    impl TraceSection for MockSection {
        fn get_trace(&self) -> Box<dyn Trace> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_module(&self) -> Box<dyn TraceModule> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_path(&self) -> String {
            self.name.lock().unwrap().clone()
        }

        fn set_name(&mut self, _lifespan: Lifespan, name: &str) {
            *self.name.lock().unwrap() = name.to_string();
        }

        fn set_name_at(&mut self, _snap: i64, name: &str) -> Result<(), DuplicateNameException> {
            if name == "taken" {
                return Err(DuplicateNameException::with_message(name.to_string()));
            }
            *self.name.lock().unwrap() = name.to_string();
            Ok(())
        }

        fn get_name(&self, _snap: i64) -> String {
            self.name.lock().unwrap().clone()
        }

        fn set_range(&mut self, _lifespan: Lifespan, range: AddressRange) {
            *self.range.lock().unwrap() = Some(range);
        }

        fn get_range(&self, _snap: i64) -> Option<AddressRange> {
            self.range.lock().unwrap().clone()
        }

        fn delete(&mut self) {
            self.deleted = true;
        }

        fn remove(&mut self, _snap: i64) {}

        fn is_valid(&self, _snap: i64) -> bool {
            !self.deleted
        }
    }

    fn make_section() -> MockSection {
        MockSection {
            name: Mutex::new("full/path/.text".to_string()),
            range: Mutex::new(None),
            deleted: false,
        }
    }

    #[test]
    fn set_name_at_rejects_duplicates() {
        let mut section = make_section();
        assert!(section.set_name_at(0, ".text").is_ok());
        assert_eq!(section.get_name(0), ".text");
        assert!(section.set_name_at(0, "taken").is_err());
    }

    #[test]
    fn get_start_and_end_derive_from_range() {
        let mut section = make_section();
        assert_eq!(section.get_start(0), None);
        assert_eq!(section.get_end(0), None);

        let lifespan = Lifespan::span(0, 10);
        let range = AddressRange::new(addr(0x1000), addr(0x1fff));
        section.set_range(lifespan, range);

        assert_eq!(section.get_start(0), Some(addr(0x1000)));
        assert_eq!(section.get_end(0), Some(addr(0x1fff)));
    }

    #[test]
    fn trait_object_is_object_safe() {
        let mut section: Box<dyn TraceSection> = Box::new(make_section());
        assert!(section.is_valid(0));
        section.delete();
        assert!(!section.is_valid(0));
    }
}

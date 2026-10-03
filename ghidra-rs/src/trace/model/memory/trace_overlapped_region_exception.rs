use std::fmt;

use crate::trace::model::memory::trace_memory_region::TraceMemoryRegion;
use crate::util::exception::UsrException;

/// Error thrown when a memory region operation would cause it to overlap another region.
///
/// Port of `ghidra.trace.model.memory.TraceOverlappedRegionException`, which extends
/// `UsrException` with a fixed message (`"Overlaps other regions"`) and a `conflicts` payload.
///
/// This is a standalone port following the [`RegisterValueException`](super::register_value_exception::RegisterValueException)
/// convention (a plain struct plus a `From` conversion to [`UsrException`]), not an implementor
/// of the pre-existing [`crate::trace::seam_stubs::TraceOverlappedRegionException`] seam trait
/// that [`TraceMemoryRegion`] was already written against: that seam's `get_conflicts()` returns
/// an *owned* `Vec<Box<dyn TraceMemoryRegion>>` from a `&self` method, which would require
/// cloning trait-object regions — `TraceMemoryRegion` (and its `TraceUniqueObject`/
/// `TraceObjectInterface` supertraits) expose no such clone operation, a limitation the seam's
/// own test double already works around by never populating real conflicts. Mirroring Java's
/// field type (`Collection<? extends TraceMemoryRegion>`) faithfully here means owning the
/// conflicts and returning them by reference instead.
pub struct TraceOverlappedRegionException {
    conflicts: Vec<Box<dyn TraceMemoryRegion>>,
}

impl TraceOverlappedRegionException {
    /// Constructs the exception with the region(s) it conflicts with.
    ///
    /// Mirrors `TraceOverlappedRegionException(Collection<? extends TraceMemoryRegion>)`, which
    /// always sets the detail message to the fixed string `"Overlaps other regions"`.
    pub fn new(conflicts: Vec<Box<dyn TraceMemoryRegion>>) -> Self {
        Self { conflicts }
    }

    /// Mirrors the inherited `UsrException.getMessage()`, always `"Overlaps other regions"`.
    pub fn message(&self) -> &str {
        "Overlaps other regions"
    }

    /// Mirrors `TraceOverlappedRegionException.getConflicts()`.
    pub fn get_conflicts(&self) -> &[Box<dyn TraceMemoryRegion>] {
        &self.conflicts
    }
}

impl fmt::Debug for TraceOverlappedRegionException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TraceOverlappedRegionException")
            .field("message", &self.message())
            .field("conflicts_len", &self.conflicts.len())
            .finish()
    }
}

impl fmt::Display for TraceOverlappedRegionException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for TraceOverlappedRegionException {}

impl From<TraceOverlappedRegionException> for UsrException {
    fn from(value: TraceOverlappedRegionException) -> Self {
        Self(value.message().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressRange};
    use crate::trace::model::lifespan::Lifespan;
    use crate::trace::model::memory::trace_memory_flag::TraceMemoryFlag;
    use crate::trace::model::memory::trace_memory_region::SetLengthError;
    use crate::trace::model::target::iface::TraceObjectInterface;
    use crate::trace::model::target::trace_object::TraceObject;
    use crate::trace::model::trace::Trace;
    use crate::trace::model::trace_unique_object::TraceUniqueObject;
    use crate::trace::seam_stubs::ObjectKey;
    use std::collections::HashSet;
    use std::error::Error;

    /// Minimal region test double, distinguished only by [`MockRegion::get_path`], sufficient to
    /// prove [`TraceOverlappedRegionException`] stores and returns real
    /// `Box<dyn TraceMemoryRegion>` conflicts rather than a stand-in.
    struct MockRegion {
        path: String,
    }

    struct MockObjectKey(&'static str);

    impl ObjectKey for MockObjectKey {
        fn equals(&self, obj: &dyn std::any::Any) -> bool {
            obj.downcast_ref::<MockObjectKey>().is_some_and(|o| o.0 == self.0)
        }
        fn hash_code(&self) -> i32 {
            self.0.len() as i32
        }
        fn compare_to(&self, that: &dyn ObjectKey) -> i32 {
            self.hash_code() - that.hash_code()
        }
    }

    impl TraceUniqueObject for MockRegion {
        fn get_object_key(&self) -> Box<dyn ObjectKey> {
            Box::new(MockObjectKey("mock-region"))
        }
        fn is_deleted(&self) -> bool {
            false
        }
    }

    impl TraceObjectInterface for MockRegion {
        fn get_object(&self) -> Box<dyn TraceObject> {
            unimplemented!("not exercised by this test")
        }
    }

    impl TraceMemoryRegion for MockRegion {
        fn get_trace(&self) -> Box<dyn Trace> {
            unimplemented!("not exercised by this test")
        }
        fn get_path(&self) -> String {
            self.path.clone()
        }
        fn set_name(&mut self, _lifespan: Lifespan, _name: &str) {
            unimplemented!("not exercised by this test")
        }
        fn set_name_at(&mut self, _snap: i64, _name: &str) {
            unimplemented!("not exercised by this test")
        }
        fn get_name(&self, _snap: i64) -> String {
            self.path.clone()
        }
        fn set_range(&mut self, _lifespan: Lifespan, _range: AddressRange) {
            unimplemented!("not exercised by this test")
        }
        fn set_range_at(
            &mut self,
            _snap: i64,
            _range: AddressRange,
        ) -> Result<(), Box<dyn crate::trace::seam_stubs::TraceOverlappedRegionException>> {
            unimplemented!("not exercised by this test")
        }
        fn get_range(&self, _snap: i64) -> AddressRange {
            unimplemented!("not exercised by this test")
        }
        fn set_min_address(
            &mut self,
            _snap: i64,
            _min: Address,
        ) -> Result<(), Box<dyn crate::trace::seam_stubs::TraceOverlappedRegionException>> {
            unimplemented!("not exercised by this test")
        }
        fn get_min_address(&self, _snap: i64) -> Address {
            unimplemented!("not exercised by this test")
        }
        fn set_max_address(
            &mut self,
            _snap: i64,
            _max: Address,
        ) -> Result<(), Box<dyn crate::trace::seam_stubs::TraceOverlappedRegionException>> {
            unimplemented!("not exercised by this test")
        }
        fn get_max_address(&self, _snap: i64) -> Address {
            unimplemented!("not exercised by this test")
        }
        fn set_length(&mut self, _snap: i64, _length: u64) -> Result<(), SetLengthError> {
            unimplemented!("not exercised by this test")
        }
        fn get_length(&self, _snap: i64) -> u64 {
            unimplemented!("not exercised by this test")
        }
        fn set_flags(&mut self, _lifespan: Lifespan, _flags: &[TraceMemoryFlag]) {
            unimplemented!("not exercised by this test")
        }
        fn set_flags_at(&mut self, _snap: i64, _flags: &[TraceMemoryFlag]) {
            unimplemented!("not exercised by this test")
        }
        fn add_flags(&mut self, _lifespan: Lifespan, _flags: &[TraceMemoryFlag]) {
            unimplemented!("not exercised by this test")
        }
        fn add_flags_at(&mut self, _snap: i64, _flags: &[TraceMemoryFlag]) {
            unimplemented!("not exercised by this test")
        }
        fn clear_flags(&mut self, _lifespan: Lifespan, _flags: &[TraceMemoryFlag]) {
            unimplemented!("not exercised by this test")
        }
        fn clear_flags_at(&mut self, _snap: i64, _flags: &[TraceMemoryFlag]) {
            unimplemented!("not exercised by this test")
        }
        fn get_flags(&self, _snap: i64) -> HashSet<TraceMemoryFlag> {
            HashSet::new()
        }
        fn delete(&mut self) {
            unimplemented!("not exercised by this test")
        }
        fn remove(&mut self, _snap: i64) {
            unimplemented!("not exercised by this test")
        }
        fn is_valid(&self, _snap: i64) -> bool {
            true
        }
    }

    fn region(path: &str) -> Box<dyn TraceMemoryRegion> {
        Box::new(MockRegion { path: path.to_string() })
    }

    #[test]
    fn message_matches_java_fixed_string() {
        let e = TraceOverlappedRegionException::new(Vec::new());
        assert_eq!(e.message(), "Overlaps other regions");
    }

    #[test]
    fn display_matches_message() {
        let e = TraceOverlappedRegionException::new(Vec::new());
        assert_eq!(e.to_string(), "Overlaps other regions");
    }

    #[test]
    fn implements_error_trait() {
        let e = TraceOverlappedRegionException::new(Vec::new());
        let _: &dyn Error = &e;
        assert!(e.source().is_none());
    }

    #[test]
    fn get_conflicts_returns_empty_for_no_conflicts() {
        let e = TraceOverlappedRegionException::new(Vec::new());
        assert!(e.get_conflicts().is_empty());
    }

    #[test]
    fn get_conflicts_returns_the_regions_it_was_built_with() {
        let e = TraceOverlappedRegionException::new(vec![region("region.one"), region("region.two")]);
        let conflicts = e.get_conflicts();
        assert_eq!(conflicts.len(), 2);
        assert_eq!(conflicts[0].get_path(), "region.one");
        assert_eq!(conflicts[1].get_path(), "region.two");
    }

    #[test]
    fn converts_to_usr_exception() {
        let e = TraceOverlappedRegionException::new(vec![region("region.one")]);
        let usr: UsrException = e.into();
        assert_eq!(usr, UsrException("Overlaps other regions".to_string()));
    }

    #[test]
    fn debug_contains_conflict_count() {
        let e = TraceOverlappedRegionException::new(vec![region("a"), region("b"), region("c")]);
        let s = format!("{:?}", e);
        assert!(s.contains("Overlaps other regions"));
        assert!(s.contains('3'));
    }

    /// Proves this concrete port can still be used wherever
    /// [`TraceMemoryRegion::set_range_at`]'s [`SetLengthError`]/seam-trait error path expects a
    /// `TraceOverlappedRegionException`-shaped message, by checking the fixed message text this
    /// port and the seam trait both agree on.
    #[test]
    fn message_matches_seam_trait_expectation() {
        let e = TraceOverlappedRegionException::new(Vec::new());
        // `SetLengthError::Overlap` formats via `e.message()` on the seam trait; this concrete
        // type's `message()` returns the identical fixed string, so a future adapter bridging
        // the two need only forward the string, not reimplement the message.
        assert_eq!(e.message(), "Overlaps other regions");
    }
}

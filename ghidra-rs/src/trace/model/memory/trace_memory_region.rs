use std::collections::HashSet;
use std::fmt;

use crate::program::model::address::{Address, AddressOverflowException, AddressRange};
use crate::trace::model::lifespan::Lifespan;
use crate::trace::model::memory::trace_memory_flag::TraceMemoryFlag;
use crate::trace::model::target::info::trace_object_info::TraceObjectInfo;
use crate::trace::model::trace::Trace;
use crate::trace::model::trace_unique_object::TraceUniqueObject;
use crate::trace::seam_stubs::{TraceObjectInterface, TraceOverlappedRegionException};

/// Key for the region's address-range attribute.
pub const KEY_RANGE: &str = "_range";
/// Key for the region's readable-flag attribute.
pub const KEY_READABLE: &str = "_readable";
/// Key for the region's writable-flag attribute.
pub const KEY_WRITABLE: &str = "_writable";
/// Key for the region's executable-flag attribute.
pub const KEY_EXECUTABLE: &str = "_executable";
/// Key for the region's volatile-flag attribute.
pub const KEY_VOLATILE: &str = "_volatile";

/// Error returned by [`TraceMemoryRegion::set_length`], combining the two checked exceptions its
/// Java counterpart (`setLength(long, long)`) declares.
pub enum SetLengthError {
    /// Extending the range would cause the max address to overflow.
    Overflow(AddressOverflowException),
    /// Extending the region would cause it to overlap another.
    Overlap(Box<dyn TraceOverlappedRegionException>),
}

impl fmt::Debug for SetLengthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SetLengthError::Overflow(e) => f.debug_tuple("Overflow").field(e).finish(),
            SetLengthError::Overlap(e) => {
                f.debug_tuple("Overlap").field(&e.message()).finish()
            }
        }
    }
}

impl fmt::Display for SetLengthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SetLengthError::Overflow(e) => write!(f, "{e}"),
            SetLengthError::Overlap(e) => write!(f, "{}", e.message()),
        }
    }
}

impl std::error::Error for SetLengthError {}

impl From<AddressOverflowException> for SetLengthError {
    fn from(e: AddressOverflowException) -> Self {
        SetLengthError::Overflow(e)
    }
}

/// A region of mapped target memory in a trace.
///
/// Port of `ghidra.trace.model.memory.TraceMemoryRegion`.
///
/// Java overloads that differ only in taking a [`Lifespan`] versus a single snap are given
/// distinct names: the lifespan form keeps the base name (`set_name`, `set_range`, `set_flags`,
/// `add_flags`, `clear_flags`), while the single-snap form gets an `_at` suffix (`set_name_at`,
/// `set_range_at`, `set_flags_at`, `add_flags_at`, `clear_flags_at`). The varargs
/// `TraceMemoryFlag...` overloads are folded into their `Collection<TraceMemoryFlag>` siblings,
/// since both are represented here by a single `&[TraceMemoryFlag]` parameter.
///
/// The `@TraceObjectInfo` annotation on the Java interface is mirrored by
/// [`TraceMemoryRegion::trace_object_info`].
pub trait TraceMemoryRegion: TraceUniqueObject + TraceObjectInterface {
    /// Returns the `@TraceObjectInfo` metadata mirrored from the Java annotation on
    /// `TraceMemoryRegion`.
    fn trace_object_info() -> TraceObjectInfo
    where
        Self: Sized,
    {
        TraceObjectInfo::new(
            "MemoryRegion",
            "region",
            [
                KEY_RANGE,
                KEY_READABLE,
                KEY_WRITABLE,
                KEY_EXECUTABLE,
                KEY_VOLATILE,
            ],
            ["_display", KEY_RANGE],
        )
    }

    /// Get the trace containing this region.
    fn get_trace(&self) -> Box<dyn Trace>;

    /// Get the "full name" of this region.
    ///
    /// This is a unique key (within any snap) for retrieving the region, and may not be suitable
    /// for display on the screen.
    fn get_path(&self) -> String;

    /// Set the "short name" of this region across the given span of time.
    ///
    /// The given name should be suitable for display on the screen.
    fn set_name(&mut self, lifespan: Lifespan, name: &str);

    /// Set the "short name" of this region from the given snap on.
    ///
    /// The given name should be suitable for display on the screen.
    fn set_name_at(&mut self, snap: i64, name: &str);

    /// Get the "short name" of this region.
    ///
    /// This defaults to the "full name," but can be modified via [`Self::set_name_at`].
    fn get_name(&self, snap: i64) -> String;

    /// Set the virtual memory address range of this region across the given span of time.
    ///
    /// The addresses in the range should be those the target's CPU would use to access the
    /// region, i.e., the virtual memory address if an MMU is involved, or the physical address
    /// if no MMU is involved.
    fn set_range(&mut self, lifespan: Lifespan, range: AddressRange);

    /// Set the virtual memory address range of this region from the given snap on.
    ///
    /// The addresses in the range should be those the target's CPU would use to access the
    /// region, i.e., the virtual memory address if an MMU is involved, or the physical address
    /// if no MMU is involved.
    ///
    /// # Errors
    /// Returns an error if the specified range would cause this region to overlap another.
    fn set_range_at(
        &mut self,
        snap: i64,
        range: AddressRange,
    ) -> Result<(), Box<dyn TraceOverlappedRegionException>>;

    /// Get the virtual memory address range of this region.
    fn get_range(&self, snap: i64) -> AddressRange;

    /// Set the minimum address of the range, from the given snap on.
    ///
    /// Note that this sets the range from the given snap on to the same range, no matter what
    /// changes may have occurred since.
    ///
    /// # Errors
    /// Returns an error if extending the region would cause it to overlap another.
    fn set_min_address(
        &mut self,
        snap: i64,
        min: Address,
    ) -> Result<(), Box<dyn TraceOverlappedRegionException>>;

    /// Get the minimum address of the range.
    fn get_min_address(&self, snap: i64) -> Address;

    /// Set the maximum address of the range, from the given snap on.
    ///
    /// Note that this sets the range from the given snap on to the same range, no matter what
    /// changes may have occurred since.
    ///
    /// # Errors
    /// Returns an error if extending the region would cause it to overlap another.
    fn set_max_address(
        &mut self,
        snap: i64,
        max: Address,
    ) -> Result<(), Box<dyn TraceOverlappedRegionException>>;

    /// Get the maximum address of the range.
    fn get_max_address(&self, snap: i64) -> Address;

    /// Set the length, in bytes, of this region's address range, from the given snap on.
    ///
    /// This adjusts the max address of the range so that its length becomes that given. Note
    /// that this sets the range from the given snap on to the same range, no matter what changes
    /// may have occurred since.
    ///
    /// # Errors
    /// Returns an error if extending the range would cause the max address to overflow, or if
    /// extending the region would cause it to overlap another.
    fn set_length(&mut self, snap: i64, length: u64) -> Result<(), SetLengthError>;

    /// Measure the length, in bytes, of this region's address range.
    fn get_length(&self, snap: i64) -> u64;

    /// Set the flags, e.g., permissions, of this region across the given span of time.
    fn set_flags(&mut self, lifespan: Lifespan, flags: &[TraceMemoryFlag]);

    /// Set the flags, e.g., permissions, of this region from the given snap on.
    fn set_flags_at(&mut self, snap: i64, flags: &[TraceMemoryFlag]);

    /// Add the given flags, e.g., permissions, to this region across the given span of time.
    fn add_flags(&mut self, lifespan: Lifespan, flags: &[TraceMemoryFlag]);

    /// Add the given flags, e.g., permissions, to this region from the given snap on.
    fn add_flags_at(&mut self, snap: i64, flags: &[TraceMemoryFlag]);

    /// Remove the given flags, e.g., permissions, from this region across the given span of
    /// time.
    fn clear_flags(&mut self, lifespan: Lifespan, flags: &[TraceMemoryFlag]);

    /// Remove the given flags, e.g., permissions, from this region from the given snap on.
    fn clear_flags_at(&mut self, snap: i64, flags: &[TraceMemoryFlag]);

    /// Get the flags, e.g., permissions, of this region.
    fn get_flags(&self, snap: i64) -> HashSet<TraceMemoryFlag>;

    /// Add or clear the [`TraceMemoryFlag::Read`] flag.
    fn set_read(&mut self, snap: i64, read: bool) {
        if read {
            self.add_flags_at(snap, &[TraceMemoryFlag::Read]);
        } else {
            self.clear_flags_at(snap, &[TraceMemoryFlag::Read]);
        }
    }

    /// Check if the [`TraceMemoryFlag::Read`] flag is present.
    fn is_read(&self, snap: i64) -> bool {
        self.get_flags(snap).contains(&TraceMemoryFlag::Read)
    }

    /// Add or clear the [`TraceMemoryFlag::Write`] flag.
    fn set_write(&mut self, snap: i64, write: bool) {
        if write {
            self.add_flags_at(snap, &[TraceMemoryFlag::Write]);
        } else {
            self.clear_flags_at(snap, &[TraceMemoryFlag::Write]);
        }
    }

    /// Check if the [`TraceMemoryFlag::Write`] flag is present.
    fn is_write(&self, snap: i64) -> bool {
        self.get_flags(snap).contains(&TraceMemoryFlag::Write)
    }

    /// Add or clear the [`TraceMemoryFlag::Execute`] flag.
    fn set_execute(&mut self, snap: i64, execute: bool) {
        if execute {
            self.add_flags_at(snap, &[TraceMemoryFlag::Execute]);
        } else {
            self.clear_flags_at(snap, &[TraceMemoryFlag::Execute]);
        }
    }

    /// Check if the [`TraceMemoryFlag::Execute`] flag is present.
    fn is_execute(&self, snap: i64) -> bool {
        self.get_flags(snap).contains(&TraceMemoryFlag::Execute)
    }

    /// Add or clear the [`TraceMemoryFlag::Volatile`] flag.
    fn set_volatile(&mut self, snap: i64, vol: bool) {
        if vol {
            self.add_flags_at(snap, &[TraceMemoryFlag::Volatile]);
        } else {
            self.clear_flags_at(snap, &[TraceMemoryFlag::Volatile]);
        }
    }

    /// Check if the [`TraceMemoryFlag::Volatile`] flag is present.
    fn is_volatile(&self, snap: i64) -> bool {
        self.get_flags(snap).contains(&TraceMemoryFlag::Volatile)
    }

    /// Delete this region from the trace.
    fn delete(&mut self);

    /// Remove this region from the given snap on.
    fn remove(&mut self, snap: i64);

    /// Check if the region is valid at the given snapshot.
    ///
    /// In object mode, a region's life may be disjoint, so checking if the snap occurs between
    /// creation and destruction is not quite sufficient. This method encapsulates validity. In
    /// object mode, it checks that the region object has a canonical parent at the given
    /// snapshot. In table mode, it checks that the lifespan contains the snap.
    fn is_valid(&self, snap: i64) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;
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



    struct MockOverlapError {
        conflicts: Vec<()>,
    }

    impl TraceOverlappedRegionException for MockOverlapError {
        fn message(&self) -> &str {
            "Overlaps other regions"
        }

        fn get_conflicts(&self) -> Vec<Box<dyn TraceMemoryRegion>> {
            self.conflicts.iter().map(|_| unreachable!()).collect()
        }
    }

    /// A minimal in-memory region backing a single, unversioned range/flag pair, used to prove
    /// the trait is object-safe and its default methods behave correctly.
    struct MockRegion {
        name: String,
        range: Mutex<AddressRange>,
        flags: Mutex<HashSet<TraceMemoryFlag>>,
        deleted: bool,
        overlap_next_set_range: bool,
    }

    fn addr(offset: i64) -> Address {
        use crate::program::model::address::AddressSpaceType;
        let space = crate::program::model::address::AddressSpace::new(
            "ram",
            64,
            1,
            AddressSpaceType::Ram,
            0,
        );
        Address::new(space, offset)
    }

    impl TraceUniqueObject for MockRegion {
        fn get_object_key(&self) -> Box<dyn ObjectKey> {
            Box::new(MockObjectKey(1))
        }

        fn is_deleted(&self) -> bool {
            self.deleted
        }
    }

    impl TraceObjectInterface for MockRegion {}

    impl TraceMemoryRegion for MockRegion {
        fn get_trace(&self) -> Box<dyn Trace> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_path(&self) -> String {
            self.name.clone()
        }

        fn set_name(&mut self, _lifespan: Lifespan, name: &str) {
            self.name = name.to_string();
        }

        fn set_name_at(&mut self, _snap: i64, name: &str) {
            self.name = name.to_string();
        }

        fn get_name(&self, _snap: i64) -> String {
            self.name.clone()
        }

        fn set_range(&mut self, _lifespan: Lifespan, range: AddressRange) {
            *self.range.lock().unwrap() = range;
        }

        fn set_range_at(
            &mut self,
            _snap: i64,
            range: AddressRange,
        ) -> Result<(), Box<dyn TraceOverlappedRegionException>> {
            if self.overlap_next_set_range {
                return Err(Box::new(MockOverlapError { conflicts: vec![] }));
            }
            *self.range.lock().unwrap() = range;
            Ok(())
        }

        fn get_range(&self, _snap: i64) -> AddressRange {
            self.range.lock().unwrap().clone()
        }

        fn set_min_address(
            &mut self,
            snap: i64,
            min: Address,
        ) -> Result<(), Box<dyn TraceOverlappedRegionException>> {
            let max = self.get_max_address(snap);
            self.set_range_at(snap, AddressRange::new(min, max))
        }

        fn get_min_address(&self, snap: i64) -> Address {
            self.get_range(snap).min_address().clone()
        }

        fn set_max_address(
            &mut self,
            snap: i64,
            max: Address,
        ) -> Result<(), Box<dyn TraceOverlappedRegionException>> {
            let min = self.get_min_address(snap);
            self.set_range_at(snap, AddressRange::new(min, max))
        }

        fn get_max_address(&self, snap: i64) -> Address {
            self.get_range(snap).max_address().clone()
        }

        fn set_length(&mut self, snap: i64, length: u64) -> Result<(), SetLengthError> {
            let min = self.get_min_address(snap);
            let range = AddressRange::from_start_len(min, length)?;
            self.set_range_at(snap, range).map_err(SetLengthError::Overlap)
        }

        fn get_length(&self, snap: i64) -> u64 {
            self.get_range(snap).length()
        }

        fn set_flags(&mut self, _lifespan: Lifespan, flags: &[TraceMemoryFlag]) {
            *self.flags.lock().unwrap() = flags.iter().copied().collect();
        }

        fn set_flags_at(&mut self, _snap: i64, flags: &[TraceMemoryFlag]) {
            *self.flags.lock().unwrap() = flags.iter().copied().collect();
        }

        fn add_flags(&mut self, _lifespan: Lifespan, flags: &[TraceMemoryFlag]) {
            self.flags.lock().unwrap().extend(flags.iter().copied());
        }

        fn add_flags_at(&mut self, _snap: i64, flags: &[TraceMemoryFlag]) {
            self.flags.lock().unwrap().extend(flags.iter().copied());
        }

        fn clear_flags(&mut self, _lifespan: Lifespan, flags: &[TraceMemoryFlag]) {
            let mut guard = self.flags.lock().unwrap();
            for f in flags {
                guard.remove(f);
            }
        }

        fn clear_flags_at(&mut self, _snap: i64, flags: &[TraceMemoryFlag]) {
            let mut guard = self.flags.lock().unwrap();
            for f in flags {
                guard.remove(f);
            }
        }

        fn get_flags(&self, _snap: i64) -> HashSet<TraceMemoryFlag> {
            self.flags.lock().unwrap().clone()
        }

        fn delete(&mut self) {
            self.deleted = true;
        }

        fn remove(&mut self, _snap: i64) {
            self.deleted = true;
        }

        fn is_valid(&self, snap: i64) -> bool {
            !self.deleted && snap >= 0
        }
    }

    fn mock_region() -> MockRegion {
        MockRegion {
            name: "bin:.text".to_string(),
            range: Mutex::new(AddressRange::new(addr(0x1000), addr(0x1fff))),
            flags: Mutex::new(HashSet::new()),
            deleted: false,
            overlap_next_set_range: false,
        }
    }

    #[test]
    fn is_object_safe() {
        let region = mock_region();
        let _dyn_ref: &dyn TraceMemoryRegion = &region;
    }

    #[test]
    fn trace_object_info_matches_java_annotation() {
        let info = MockRegion::trace_object_info();
        assert_eq!(info.schema_name, "MemoryRegion");
        assert_eq!(info.short_name, "region");
        assert_eq!(
            info.attributes,
            vec![
                KEY_RANGE.to_string(),
                KEY_READABLE.to_string(),
                KEY_WRITABLE.to_string(),
                KEY_EXECUTABLE.to_string(),
                KEY_VOLATILE.to_string(),
            ]
        );
        assert_eq!(
            info.fixed_keys,
            vec!["_display".to_string(), KEY_RANGE.to_string()]
        );
    }

    #[test]
    fn read_write_execute_volatile_default_methods_roundtrip() {
        let mut region = mock_region();
        assert!(!region.is_read(0));
        region.set_read(0, true);
        assert!(region.is_read(0));
        region.set_read(0, false);
        assert!(!region.is_read(0));

        region.set_write(0, true);
        region.set_execute(0, true);
        region.set_volatile(0, true);
        assert!(region.is_write(0));
        assert!(region.is_execute(0));
        assert!(region.is_volatile(0));

        let flags = region.get_flags(0);
        assert_eq!(flags.len(), 3);
    }

    #[test]
    fn set_length_adjusts_max_address() {
        let mut region = mock_region();
        region.set_length(0, 0x100).unwrap();
        assert_eq!(region.get_length(0), 0x100);
        assert_eq!(region.get_min_address(0), addr(0x1000));
        assert_eq!(region.get_max_address(0), addr(0x10ff));
    }

    #[test]
    fn set_length_propagates_overflow() {
        let mut region = mock_region();
        // `addr(-1)` is the space's maximum (unsigned) offset; extending past it overflows.
        *region.range.lock().unwrap() = AddressRange::new(addr(-1), addr(-1));
        let err = region.set_length(0, 2).unwrap_err();
        assert!(matches!(err, SetLengthError::Overflow(_)));
    }

    #[test]
    fn set_range_at_propagates_overlap_error() {
        let mut region = mock_region();
        region.overlap_next_set_range = true;
        let err = region
            .set_range_at(0, AddressRange::new(addr(0), addr(1)))
            .unwrap_err();
        assert_eq!(err.message(), "Overlaps other regions");
    }

    #[test]
    fn delete_and_remove_affect_validity() {
        let mut region = mock_region();
        assert!(region.is_valid(0));
        region.delete();
        assert!(!region.is_valid(0));
    }

    #[test]
    fn get_path_and_name_reflect_short_name() {
        let mut region = mock_region();
        assert_eq!(region.get_path(), "bin:.text");
        region.set_name_at(0, "bin:.data");
        assert_eq!(region.get_name(0), "bin:.data");
    }
}

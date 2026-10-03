//! Port of `ghidra.app.plugin.core.debug.service.modules.ModuleRegionMatcher`.

use crate::program::model::mem::MemoryBlock;
use crate::trace::model::memory::trace_memory_region::TraceMemoryRegion;

/// Scores how well a candidate program [`MemoryBlock`] matches a candidate trace
/// [`TraceMemoryRegion`], for use while proposing a module-to-program map.
///
/// Port of the package-private `ghidra.app.plugin.core.debug.service.modules.ModuleRegionMatcher`
/// class. Java's `block`/`region` fields are package-private and mutated directly by sibling
/// classes in the same package (e.g. an as-yet-unported `DefaultModuleMapProposal`); this port
/// exposes them as `pub` fields for the same reason, mirroring the precedent already set by
/// [`super::abstract_map_proposal::Matcher`]'s public fields.
pub struct ModuleRegionMatcher {
    pub snap: i64,
    pub block: Option<Box<dyn MemoryBlock>>,
    pub region: Option<Box<dyn TraceMemoryRegion>>,
}

impl ModuleRegionMatcher {
    /// Constructs a new, unmatched matcher for the given snap.
    ///
    /// Mirrors `ModuleRegionMatcher(long snap)`.
    pub fn new(snap: i64) -> Self {
        Self { snap, block: None, region: None }
    }

    /// Scores this candidate match.
    ///
    /// Mirrors `score()`: `0` if either side is unmatched; otherwise `3` (for the matching
    /// offset that got the two candidates paired up in the first place) plus `10` more if the
    /// block's size exactly equals the region's length at this matcher's snap.
    pub fn score(&self) -> i32 {
        let (Some(block), Some(region)) = (&self.block, &self.region) else {
            return 0; // Unmatched
        };
        let mut score = 3; // For the matching offset
        if block.get_size() == region.get_length(self.snap) {
            score += 10;
        }
        score
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressRange, AddressSpace, AddressSpaceType};
    use crate::program::model::mem::MemoryAccessException;
    use crate::trace::model::lifespan::Lifespan;
    use crate::trace::model::memory::trace_memory_flag::TraceMemoryFlag;
    use crate::trace::model::memory::trace_memory_region::SetLengthError;
    use crate::trace::model::target::iface::TraceObjectInterface;
    use crate::trace::model::trace::Trace;
    use crate::trace::model::trace_unique_object::TraceUniqueObject;
    use crate::trace::seam_stubs::{ObjectKey, TraceOverlappedRegionException};
    use std::collections::HashSet;

    fn ram_space() -> std::sync::Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn addr(offset: i64) -> Address {
        Address::new(ram_space(), offset)
    }

    struct MockBlock {
        size: u64,
    }

    impl MemoryBlock for MockBlock {
        fn get_name(&self) -> &str {
            "mock"
        }
        fn get_start(&self) -> Address {
            addr(0x1000)
        }
        fn get_end(&self) -> Address {
            addr(0x1000 + self.size as i64 - 1)
        }
        fn get_size(&self) -> u64 {
            self.size
        }
        fn is_initialized(&self) -> bool {
            true
        }
        fn get_byte(&self, _addr: &Address) -> Result<u8, MemoryAccessException> {
            unimplemented!("not exercised by this test")
        }
        fn get_bytes(&self, _addr: &Address, _dest: &mut [u8]) -> usize {
            0
        }
        fn set_bytes(&mut self, _addr: &Address, _source: &[u8]) -> Result<(), MemoryAccessException> {
            unimplemented!("not exercised by this test")
        }
    }

    struct MockObjectKey;

    impl ObjectKey for MockObjectKey {
        fn equals(&self, obj: &dyn std::any::Any) -> bool {
            obj.downcast_ref::<MockObjectKey>().is_some()
        }
        fn hash_code(&self) -> i32 {
            0
        }
        fn compare_to(&self, _that: &dyn ObjectKey) -> i32 {
            0
        }
    }

    struct MockRegion {
        length: u64,
    }

    impl TraceUniqueObject for MockRegion {
        fn get_object_key(&self) -> Box<dyn ObjectKey> {
            Box::new(MockObjectKey)
        }
        fn is_deleted(&self) -> bool {
            false
        }
    }

    impl TraceObjectInterface for MockRegion {
        fn get_object(&self) -> Box<dyn crate::trace::model::target::trace_object::TraceObject> {
            unimplemented!("not exercised by this test")
        }
    }

    impl TraceMemoryRegion for MockRegion {
        fn get_trace(&self) -> Box<dyn Trace> {
            unimplemented!("not exercised by this test")
        }
        fn get_path(&self) -> String {
            "mock-region".to_string()
        }
        fn set_name(&mut self, _lifespan: Lifespan, _name: &str) {}
        fn set_name_at(&mut self, _snap: i64, _name: &str) {}
        fn get_name(&self, _snap: i64) -> String {
            "mock-region".to_string()
        }
        fn set_range(&mut self, _lifespan: Lifespan, _range: AddressRange) {}
        fn set_range_at(
            &mut self,
            _snap: i64,
            _range: AddressRange,
        ) -> Result<(), Box<dyn TraceOverlappedRegionException>> {
            Ok(())
        }
        fn get_range(&self, _snap: i64) -> AddressRange {
            unimplemented!("not exercised by this test")
        }
        fn set_min_address(
            &mut self,
            _snap: i64,
            _min: Address,
        ) -> Result<(), Box<dyn TraceOverlappedRegionException>> {
            Ok(())
        }
        fn get_min_address(&self, _snap: i64) -> Address {
            unimplemented!("not exercised by this test")
        }
        fn set_max_address(
            &mut self,
            _snap: i64,
            _max: Address,
        ) -> Result<(), Box<dyn TraceOverlappedRegionException>> {
            Ok(())
        }
        fn get_max_address(&self, _snap: i64) -> Address {
            unimplemented!("not exercised by this test")
        }
        fn set_length(&mut self, _snap: i64, _length: u64) -> Result<(), SetLengthError> {
            Ok(())
        }
        fn get_length(&self, _snap: i64) -> u64 {
            self.length
        }
        fn set_flags(&mut self, _lifespan: Lifespan, _flags: &[TraceMemoryFlag]) {}
        fn set_flags_at(&mut self, _snap: i64, _flags: &[TraceMemoryFlag]) {}
        fn add_flags(&mut self, _lifespan: Lifespan, _flags: &[TraceMemoryFlag]) {}
        fn add_flags_at(&mut self, _snap: i64, _flags: &[TraceMemoryFlag]) {}
        fn clear_flags(&mut self, _lifespan: Lifespan, _flags: &[TraceMemoryFlag]) {}
        fn clear_flags_at(&mut self, _snap: i64, _flags: &[TraceMemoryFlag]) {}
        fn get_flags(&self, _snap: i64) -> HashSet<TraceMemoryFlag> {
            HashSet::new()
        }
        fn delete(&mut self) {}
        fn remove(&mut self, _snap: i64) {}
        fn is_valid(&self, _snap: i64) -> bool {
            true
        }
    }

    #[test]
    fn unmatched_scores_zero() {
        let matcher = ModuleRegionMatcher::new(0);
        assert_eq!(matcher.score(), 0);
    }

    #[test]
    fn only_block_present_scores_zero() {
        let mut matcher = ModuleRegionMatcher::new(0);
        matcher.block = Some(Box::new(MockBlock { size: 0x100 }));
        assert_eq!(matcher.score(), 0);
    }

    #[test]
    fn only_region_present_scores_zero() {
        let mut matcher = ModuleRegionMatcher::new(0);
        matcher.region = Some(Box::new(MockRegion { length: 0x100 }));
        assert_eq!(matcher.score(), 0);
    }

    #[test]
    fn matched_pair_with_equal_sizes_scores_thirteen() {
        let mut matcher = ModuleRegionMatcher::new(5);
        matcher.block = Some(Box::new(MockBlock { size: 0x100 }));
        matcher.region = Some(Box::new(MockRegion { length: 0x100 }));
        assert_eq!(matcher.score(), 13);
    }

    #[test]
    fn matched_pair_with_different_sizes_scores_three() {
        let mut matcher = ModuleRegionMatcher::new(5);
        matcher.block = Some(Box::new(MockBlock { size: 0x100 }));
        matcher.region = Some(Box::new(MockRegion { length: 0x200 }));
        assert_eq!(matcher.score(), 3);
    }
}

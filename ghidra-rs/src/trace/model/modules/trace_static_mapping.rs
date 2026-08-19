//! A mapped range from a trace to a Ghidra `Program`.
//!
//! Port of `ghidra.trace.model.modules.TraceStaticMapping`.
//!
//! `java.net.URL` is represented as `&str`/`String`, matching how this crate already represents
//! Ghidra URLs elsewhere (see
//! [`TraceStaticMappingManager`](crate::trace::model::modules::trace_static_mapping_manager::TraceStaticMappingManager)).

use crate::program::model::address::{Address, AddressRange};
use crate::trace::model::lifespan::Lifespan;
use crate::trace::model::trace::Trace;
use crate::trace::model::trace_unique_object::TraceUniqueObject;

/// A mapped range from this trace to a Ghidra `Program`.
pub trait TraceStaticMapping: TraceUniqueObject + Send + Sync {
    /// Get the "from" trace, i.e., the trace containing this mapping.
    fn get_trace(&self) -> std::sync::Arc<dyn Trace>;

    /// Get the "from" range.
    fn get_trace_address_range(&self) -> AddressRange;

    /// Get the "from" range's minimum address.
    fn get_min_trace_address(&self) -> Address;

    /// Get the "from" range's maximum address.
    fn get_max_trace_address(&self) -> Address;

    /// Get the length of the mapping, i.e., the length of the range, where 0 indicates `1 << 64`.
    fn get_length(&self) -> i64;

    /// Get the shift in offset from static program to dynamic trace.
    fn get_shift(&self) -> i64;

    /// Get the span of time of the mapping.
    fn get_lifespan(&self) -> Lifespan;

    /// Get the starting snap of the lifespan.
    fn get_start_snap(&self) -> i64;

    /// Get the ending snap of the lifespan.
    fn get_end_snap(&self) -> i64;

    /// Get the Ghidra URL of the "to" `Program`, i.e., static image.
    fn get_static_program_url(&self) -> String;

    /// Get the "to" address range's minimum address, as a string.
    fn get_static_address(&self) -> String;

    /// Remove this mapping from the "from" trace.
    fn delete(&mut self);

    /// Check if this mapping would conflict with the given prospective mapping.
    ///
    /// See
    /// [`TraceStaticMappingManager::find_any_conflicting`](crate::trace::model::modules::trace_static_mapping_manager::TraceStaticMappingManager::find_any_conflicting).
    fn conflicts_with(
        &self,
        range: &AddressRange,
        lifespan: Lifespan,
        to_program_url: &str,
        to_address: &str,
    ) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::trace::seam_stubs::ObjectKey;
    use std::sync::Arc;

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



    struct MockMapping {
        range: AddressRange,
        to_program_url: String,
        to_address: String,
        deleted: bool,
    }

    impl TraceUniqueObject for MockMapping {
        fn get_object_key(&self) -> Box<dyn ObjectKey> {
            Box::new(MockObjectKey(1))
        }

        fn is_deleted(&self) -> bool {
            self.deleted
        }
    }

    impl TraceStaticMapping for MockMapping {
        fn get_trace(&self) -> Arc<dyn Trace> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_trace_address_range(&self) -> AddressRange {
            self.range.clone()
        }

        fn get_min_trace_address(&self) -> Address {
            self.range.min_address().clone()
        }

        fn get_max_trace_address(&self) -> Address {
            self.range.max_address().clone()
        }

        fn get_length(&self) -> i64 {
            self.range.length() as i64
        }

        fn get_shift(&self) -> i64 {
            0
        }

        fn get_lifespan(&self) -> Lifespan {
            Lifespan::span(0, i64::MAX)
        }

        fn get_start_snap(&self) -> i64 {
            self.get_lifespan().lmin()
        }

        fn get_end_snap(&self) -> i64 {
            self.get_lifespan().lmax()
        }

        fn get_static_program_url(&self) -> String {
            self.to_program_url.clone()
        }

        fn get_static_address(&self) -> String {
            self.to_address.clone()
        }

        fn delete(&mut self) {
            self.deleted = true;
        }

        fn conflicts_with(
            &self,
            range: &AddressRange,
            _lifespan: Lifespan,
            to_program_url: &str,
            _to_address: &str,
        ) -> bool {
            self.to_program_url != to_program_url && self.range.intersects(range)
        }
    }

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0);
        Address::new(space, offset)
    }

    fn make_mapping() -> MockMapping {
        MockMapping {
            range: AddressRange::new(addr(0x1000), addr(0x1fff)),
            to_program_url: "ghidra://repo/a".to_string(),
            to_address: "0x0".to_string(),
            deleted: false,
        }
    }

    #[test]
    fn conflicts_with_detects_overlap_with_different_target() {
        let mapping = make_mapping();
        assert!(mapping.conflicts_with(
            &AddressRange::new(addr(0x1800), addr(0x2800)),
            Lifespan::span(0, 10),
            "ghidra://repo/b",
            "0x0",
        ));
        assert!(!mapping.conflicts_with(
            &AddressRange::new(addr(0x1800), addr(0x2800)),
            Lifespan::span(0, 10),
            "ghidra://repo/a",
            "0x0",
        ));
        assert!(!mapping.conflicts_with(
            &AddressRange::new(addr(0x3000), addr(0x3fff)),
            Lifespan::span(0, 10),
            "ghidra://repo/b",
            "0x0",
        ));
    }

    #[test]
    fn delete_marks_mapping_deleted() {
        let mut mapping = make_mapping();
        assert!(!mapping.is_deleted());
        mapping.delete();
        assert!(mapping.is_deleted());
    }

    #[test]
    fn trait_object_is_object_safe() {
        let mapping: Box<dyn TraceStaticMapping> = Box::new(make_mapping());
        assert_eq!(mapping.get_length(), 0xfff + 1);
        assert_eq!(mapping.get_static_program_url(), "ghidra://repo/a");
        assert_eq!(mapping.get_start_snap(), 0);
        assert_eq!(mapping.get_end_snap(), i64::MAX);
    }
}

//! Manages mappings from a trace into static images (Ghidra `Program`s).
//!
//! Port of `ghidra.trace.model.modules.TraceStaticMappingManager`.
//!
//! Most commonly, this is used to map modules listed by a connected debugger to programs already
//! imported into the same Ghidra project. It is vitally important that the image loaded by the
//! target is an exact copy of the image imported by Ghidra, or else things may not be aligned.
//!
//! Note, to best handle mapping ranges to a variety of programs, and to validate the addition of
//! new entries, it is unlikely a client should consume mapping entries directly. Instead, a
//! service should track the mappings among all open traces and programs, permitting clients to
//! mutate and consume mappings more naturally, e.g., by passing in a `Program` and `Address`
//! rather than a URL and string-ized address.
//!
//! `java.net.URL` parameters are represented as `&str`, matching how this crate already
//! represents Ghidra URLs elsewhere (see
//! [`ToolServices`](crate::framework::model::tool_services::ToolServices)).

use crate::program::model::address::{Address, AddressRange};
use crate::trace::model::lifespan::Lifespan;
use crate::trace::model::modules::trace_conflicted_mapping_exception::TraceConflictedMappingException;
use crate::trace::model::modules::trace_static_mapping::TraceStaticMapping;

/// Manages mappings from this trace into static images (Ghidra `Program`s).
pub trait TraceStaticMappingManager {
    /// Add a new mapping, if not already covered.
    ///
    /// A new mapping may overlap an existing mapping, so long as they agree in address shift.
    /// Furthermore, in such cases, the implementation may coalesce mappings to remove
    /// duplication.
    ///
    /// # Errors
    /// Returns an error if an existing mapping conflicts. See [`Self::find_any_conflicting`].
    ///
    /// Returns the new entry, or any entry which subsumes the specified mapping.
    fn add(
        &mut self,
        range: AddressRange,
        lifespan: Lifespan,
        to_program_url: &str,
        to_address: &str,
    ) -> Result<Box<dyn TraceStaticMapping>, Box<dyn TraceConflictedMappingException>>;

    /// Get all mappings in the manager.
    fn get_all_entries(&self) -> Vec<Box<dyn TraceStaticMapping>>;

    /// Find any mapping applicable to the given snap and address.
    ///
    /// Returns the mapping, or `None` if none exist at the given location.
    fn find_containing(&self, address: &Address, snap: i64) -> Option<Box<dyn TraceStaticMapping>>;

    /// Check if another mapping would conflict with the given prospective mapping.
    ///
    /// Mappings are allowed to overlap, but they must agree on the destination program and
    /// address throughout all overlapping portions.
    ///
    /// Returns a conflicting mapping, or `None` if none exist.
    fn find_any_conflicting(
        &self,
        range: &AddressRange,
        lifespan: Lifespan,
        to_program_url: &str,
        to_address: &str,
    ) -> Option<Box<dyn TraceStaticMapping>>;

    /// Find all mappings which overlap the given address range and span of time.
    ///
    /// Note, this returns overlapping entries whether or not they conflict.
    fn find_all_overlapping(
        &self,
        range: &AddressRange,
        lifespan: Lifespan,
    ) -> Vec<Box<dyn TraceStaticMapping>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use std::sync::Mutex;



    #[derive(Debug)]
    struct MockConflict;

    impl std::fmt::Display for MockConflict {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "mock conflicted mapping")
        }
    }

    impl std::error::Error for MockConflict {}

    impl TraceConflictedMappingException for MockConflict {
        fn get_conflicts(&self) -> &[Box<dyn TraceStaticMapping>] {
            &[]
        }
    }

    struct MockMapping;

    impl crate::trace::model::trace_unique_object::TraceUniqueObject for MockMapping {
        fn get_object_key(&self) -> Box<dyn crate::trace::seam_stubs::ObjectKey> {
            unimplemented!("not exercised by this smoke test")
        }

        fn is_deleted(&self) -> bool {
            false
        }
    }

    impl TraceStaticMapping for MockMapping {
        fn get_trace(&self) -> std::sync::Arc<dyn crate::trace::model::trace::Trace> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_trace_address_range(&self) -> AddressRange {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_min_trace_address(&self) -> Address {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_max_trace_address(&self) -> Address {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_length(&self) -> i64 {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_shift(&self) -> i64 {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_lifespan(&self) -> Lifespan {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_start_snap(&self) -> i64 {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_end_snap(&self) -> i64 {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_static_program_url(&self) -> String {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_static_address(&self) -> String {
            unimplemented!("not exercised by this smoke test")
        }

        fn delete(&mut self) {
            unimplemented!("not exercised by this smoke test")
        }

        fn conflicts_with(
            &self,
            _range: &AddressRange,
            _lifespan: Lifespan,
            _to_program_url: &str,
            _to_address: &str,
        ) -> bool {
            unimplemented!("not exercised by this smoke test")
        }
    }

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0);
        Address::new(space, offset)
    }

    /// A minimal in-memory manager backing a single "from" range mapped to a single "to" URL,
    /// used to prove the trait is object-safe and that conflict detection behaves correctly.
    struct MockManager {
        range: AddressRange,
        to_program_url: Mutex<Option<String>>,
    }

    impl TraceStaticMappingManager for MockManager {
        fn add(
            &mut self,
            range: AddressRange,
            _lifespan: Lifespan,
            to_program_url: &str,
            _to_address: &str,
        ) -> Result<Box<dyn TraceStaticMapping>, Box<dyn TraceConflictedMappingException>> {
            let mut current = self.to_program_url.lock().unwrap();
            if let Some(existing) = current.as_ref() {
                if existing != to_program_url && self.range.intersects(&range) {
                    return Err(Box::new(MockConflict));
                }
            }
            *current = Some(to_program_url.to_string());
            Ok(Box::new(MockMapping))
        }

        fn get_all_entries(&self) -> Vec<Box<dyn TraceStaticMapping>> {
            Vec::new()
        }

        fn find_containing(
            &self,
            _address: &Address,
            _snap: i64,
        ) -> Option<Box<dyn TraceStaticMapping>> {
            None
        }

        fn find_any_conflicting(
            &self,
            range: &AddressRange,
            _lifespan: Lifespan,
            to_program_url: &str,
            _to_address: &str,
        ) -> Option<Box<dyn TraceStaticMapping>> {
            let current = self.to_program_url.lock().unwrap();
            match current.as_ref() {
                Some(existing) if existing != to_program_url && self.range.intersects(range) => {
                    Some(Box::new(MockMapping))
                }
                _ => None,
            }
        }

        fn find_all_overlapping(
            &self,
            _range: &AddressRange,
            _lifespan: Lifespan,
        ) -> Vec<Box<dyn TraceStaticMapping>> {
            Vec::new()
        }
    }

    fn make_manager() -> MockManager {
        MockManager {
            range: AddressRange::new(addr(0x1000), addr(0x1fff)),
            to_program_url: Mutex::new(None),
        }
    }

    #[test]
    fn add_accepts_first_mapping_then_rejects_conflicting_overlap() {
        let mut manager = make_manager();
        let lifespan = Lifespan::span(0, i64::MAX);

        assert!(
            manager
                .add(
                    AddressRange::new(addr(0x1000), addr(0x1fff)),
                    lifespan,
                    "ghidra://repo/a",
                    "0x0",
                )
                .is_ok(),
            "first mapping should not conflict"
        );

        let result = manager.add(
            AddressRange::new(addr(0x1800), addr(0x2800)),
            lifespan,
            "ghidra://repo/b",
            "0x0",
        );
        let conflict = match result {
            Err(conflict) => conflict,
            Ok(_) => panic!("overlapping range mapped to a different program should conflict"),
        };
        assert!(conflict.get_conflicts().is_empty());

        assert!(
            manager
                .find_any_conflicting(
                    &AddressRange::new(addr(0x1800), addr(0x2800)),
                    lifespan,
                    "ghidra://repo/c",
                    "0x0",
                )
                .is_some(),
            "still-conflicting range should be found"
        );
    }

    #[test]
    fn trait_object_is_object_safe() {
        let manager: Box<dyn TraceStaticMappingManager> = Box::new(make_manager());
        assert!(manager.get_all_entries().is_empty());
        assert!(manager.find_all_overlapping(
            &AddressRange::new(addr(0x1000), addr(0x1fff)),
            Lifespan::span(0, 10)
        ).is_empty());
        assert!(manager.find_any_conflicting(
            &AddressRange::new(addr(0x1000), addr(0x1fff)),
            Lifespan::span(0, 10),
            "ghidra://repo/a",
            "0x0"
        ).is_none());
    }
}

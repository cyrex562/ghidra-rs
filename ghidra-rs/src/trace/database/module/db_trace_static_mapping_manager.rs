//! Port of `ghidra.trace.database.module.DBTraceStaticMappingManager`.
//!
//! The Java class is `DBTraceStaticMappingManager implements TraceStaticMappingManager,
//! DBTraceManager` -- both of which are already-ported, object-safe traits (respectively
//! [`TraceStaticMappingManager`] and [`DBTraceManager`]). It was selected as a dependency-cycle
//! cut-point, so this trait is kept minimal: it re-declares those two interfaces as supertraits
//! (mirroring Java's `implements` list) and adds the one further public member the concrete class
//! exposes beyond them, [`delete`](DBTraceStaticMappingManager::delete).
//!
//! The constructor and the class's private, DB-record-backed storage fields (`mappingStore`, a
//! `DBCachedObjectStore<DBTraceStaticMapping>`; `mappingsByAddress`, a
//! `DBCachedObjectIndex<Address, DBTraceStaticMapping>`; and `view`, an unmodifiable collection
//! over the store) are implementation details, not part of the class's cross-package API
//! contract. `DBCachedObjectStore` is not yet ported, so -- mirroring
//! [`DBTraceRegisterContextManager`](crate::trace::seam_stubs::DBTraceRegisterContextManager)'s
//! same exclusion of its own private space-table machinery -- none of that storage is represented
//! here; `add`/`get_all_entries`/`find_containing`/`find_any_conflicting`/`find_all_overlapping`
//! are inherited unchanged (as abstract methods) from [`TraceStaticMappingManager`], and
//! `invalidate_cache`/`db_error` from [`DBTraceManager`].
//!
//! `delete` mirrors the class's own `delete(DBTraceStaticMapping)` method, called from
//! `DBTraceStaticMapping.delete()` as `manager.delete(this)`. Its parameter is typed as the
//! already-ported [`TraceStaticMapping`] model interface (the concrete `DBTraceStaticMapping`
//! class itself is not yet ported), which is all this trait's abstract contract needs.

use crate::trace::database::db_trace_manager::DBTraceManager;
use crate::trace::model::modules::trace_static_mapping::TraceStaticMapping;
use crate::trace::model::modules::trace_static_mapping_manager::TraceStaticMappingManager;

/// The trace database's static-mapping manager: maps ranges of a trace to addresses in static
/// program images.
///
/// Port of `ghidra.trace.database.module.DBTraceStaticMappingManager`.
pub trait DBTraceStaticMappingManager: TraceStaticMappingManager + DBTraceManager {
    /// Remove `mapping` from the manager and notify the trace's change listeners.
    ///
    /// Mirrors `DBTraceStaticMappingManager.delete(DBTraceStaticMapping)`, which the concrete
    /// `DBTraceStaticMapping.delete()` calls as `manager.delete(this)`.
    fn delete(&mut self, mapping: &mut dyn TraceStaticMapping);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressRange, AddressSpace, AddressSpaceType};
    use crate::trace::model::lifespan::Lifespan;
    use crate::trace::model::modules::trace_conflicted_mapping_exception::{
        TraceConflictedMappingError, TraceConflictedMappingException,
    };
    use std::sync::Mutex;

    struct MockLifespan {
        min: i64,
        max: i64,
    }

    impl Lifespan for MockLifespan {
        fn lmin(&self) -> i64 {
            self.min
        }

        fn lmax(&self) -> i64 {
            self.max
        }

        fn contains(&self, n: i64) -> bool {
            self.min <= n && n <= self.max
        }

        fn with_min(&self, min: i64) -> Box<dyn Lifespan> {
            Box::new(MockLifespan { min, max: self.max })
        }

        fn with_max(&self, max: i64) -> Box<dyn Lifespan> {
            Box::new(MockLifespan { min: self.min, max })
        }

        fn iter(&self) -> Box<dyn Iterator<Item = i64> + '_> {
            Box::new(self.min..=self.max)
        }
    }

    #[derive(Clone)]
    struct MockMapping {
        range: AddressRange,
        to_program_url: String,
        deleted: bool,
    }

    impl crate::trace::model::trace_unique_object::TraceUniqueObject for MockMapping {
        fn get_object_key(&self) -> Box<dyn crate::trace::seam_stubs::ObjectKey> {
            unimplemented!("not exercised by this smoke test")
        }

        fn is_deleted(&self) -> bool {
            self.deleted
        }
    }

    impl TraceStaticMapping for MockMapping {
        fn get_trace(&self) -> std::sync::Arc<dyn crate::trace::model::trace::Trace> {
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

        fn get_lifespan(&self) -> Box<dyn Lifespan> {
            Box::new(MockLifespan { min: 0, max: i64::MAX })
        }

        fn get_start_snap(&self) -> i64 {
            0
        }

        fn get_end_snap(&self) -> i64 {
            i64::MAX
        }

        fn get_static_program_url(&self) -> String {
            self.to_program_url.clone()
        }

        fn get_static_address(&self) -> String {
            "0x0".to_string()
        }

        fn delete(&mut self) {
            self.deleted = true;
        }

        fn conflicts_with(
            &self,
            range: &AddressRange,
            _lifespan: &dyn Lifespan,
            to_program_url: &str,
            _to_address: &str,
        ) -> bool {
            self.range.intersects(range) && self.to_program_url != to_program_url
        }
    }

    /// A minimal in-memory implementor backed by a `Vec`, proving both supertraits plus `delete`
    /// are reachable through a single `Box<dyn DBTraceStaticMappingManager>`, and that `delete`
    /// actually removes an entry (not a trivially-true assertion).
    struct MockManager {
        entries: Mutex<Vec<MockMapping>>,
        invalidate_calls: Mutex<Vec<bool>>,
        last_error: Mutex<Option<String>>,
    }

    impl crate::framework::db::util::error_handler::ErrorHandler for MockManager {
        fn db_error(&self, e: std::io::Error) {
            *self.last_error.lock().unwrap() = Some(e.to_string());
        }
    }

    impl DBTraceManager for MockManager {
        fn invalidate_cache(&mut self, all: bool) {
            self.invalidate_calls.lock().unwrap().push(all);
        }
    }

    impl TraceStaticMappingManager for MockManager {
        fn add(
            &mut self,
            range: AddressRange,
            _lifespan: &dyn Lifespan,
            to_program_url: &str,
            _to_address: &str,
        ) -> Result<Box<dyn TraceStaticMapping>, Box<dyn TraceConflictedMappingException>> {
            let mut entries = self.entries.lock().unwrap();
            for existing in entries.iter() {
                if existing.conflicts_with(&range, &MockLifespan { min: 0, max: i64::MAX }, to_program_url, "0x0") {
                    return Err(Box::new(TraceConflictedMappingError::new(
                        "conflict",
                        vec![Box::new(existing.clone())],
                    )));
                }
            }
            let mapping = MockMapping { range, to_program_url: to_program_url.to_string(), deleted: false };
            entries.push(mapping.clone());
            Ok(Box::new(mapping))
        }

        fn get_all_entries(&self) -> Vec<Box<dyn TraceStaticMapping>> {
            self.entries
                .lock()
                .unwrap()
                .iter()
                .cloned()
                .map(|m| Box::new(m) as Box<dyn TraceStaticMapping>)
                .collect()
        }

        fn find_containing(&self, address: &Address, snap: i64) -> Option<Box<dyn TraceStaticMapping>> {
            self.entries
                .lock()
                .unwrap()
                .iter()
                .find(|m| m.range.contains(address) && m.get_lifespan().contains(snap))
                .cloned()
                .map(|m| Box::new(m) as Box<dyn TraceStaticMapping>)
        }

        fn find_any_conflicting(
            &self,
            range: &AddressRange,
            lifespan: &dyn Lifespan,
            to_program_url: &str,
            to_address: &str,
        ) -> Option<Box<dyn TraceStaticMapping>> {
            self.entries
                .lock()
                .unwrap()
                .iter()
                .find(|m| m.conflicts_with(range, lifespan, to_program_url, to_address))
                .cloned()
                .map(|m| Box::new(m) as Box<dyn TraceStaticMapping>)
        }

        fn find_all_overlapping(
            &self,
            range: &AddressRange,
            _lifespan: &dyn Lifespan,
        ) -> Vec<Box<dyn TraceStaticMapping>> {
            self.entries
                .lock()
                .unwrap()
                .iter()
                .filter(|m| m.range.intersects(range))
                .cloned()
                .map(|m| Box::new(m) as Box<dyn TraceStaticMapping>)
                .collect()
        }
    }

    impl DBTraceStaticMappingManager for MockManager {
        fn delete(&mut self, mapping: &mut dyn TraceStaticMapping) {
            mapping.delete();
            let url = mapping.get_static_program_url();
            self.entries.lock().unwrap().retain(|m| m.to_program_url != url);
        }
    }

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0);
        Address::new(space, offset)
    }

    fn make_manager() -> MockManager {
        MockManager {
            entries: Mutex::new(Vec::new()),
            invalidate_calls: Mutex::new(Vec::new()),
            last_error: Mutex::new(None),
        }
    }

    #[test]
    fn delete_removes_the_entry_through_the_trait_object() {
        let mut manager = make_manager();
        let mgr: &mut dyn DBTraceStaticMappingManager = &mut manager;

        let lifespan = MockLifespan { min: 0, max: i64::MAX };
        mgr.add(AddressRange::new(addr(0x1000), addr(0x1fff)), &lifespan, "ghidra://repo/a", "0x0")
            .expect("first mapping should not conflict");
        assert_eq!(mgr.get_all_entries().len(), 1);

        let mut victim = mgr.find_containing(&addr(0x1000), 0).expect("mapping should be found");
        mgr.delete(victim.as_mut());

        assert!(mgr.get_all_entries().is_empty(), "delete should remove the entry");
    }

    #[test]
    fn trait_object_reaches_both_supertraits_and_delete() {
        let mut manager = make_manager();
        let mgr: &mut dyn DBTraceStaticMappingManager = &mut manager;

        mgr.invalidate_cache(true);
        mgr.db_error(std::io::Error::new(std::io::ErrorKind::Other, "disk full"));
        assert!(mgr.find_all_overlapping(&AddressRange::new(addr(0), addr(0xff)), &MockLifespan { min: 0, max: 10 }).is_empty());

        assert_eq!(manager.invalidate_calls.lock().unwrap().as_slice(), &[true]);
        assert_eq!(manager.last_error.lock().unwrap().as_deref(), Some("disk full"));
    }
}

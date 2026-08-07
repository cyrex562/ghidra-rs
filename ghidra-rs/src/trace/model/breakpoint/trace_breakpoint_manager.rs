//! A store for recording breakpoint placement over time in a trace.
//!
//! Port of `ghidra.trace.model.breakpoint.TraceBreakpointManager`.
//!
//! Java's default `addBreakpoint(String, long, AddressRange, ...)` and
//! `placeBreakpoint(String, long, ..., ...)` overloads that take a `snap` (rather than a
//! [`Lifespan`]) construct a `Lifespan.nowOn(snap)` and delegate to the `Lifespan`-taking form.
//! This crate's [`Lifespan`] is a trait with no concrete, generically-constructible implementor
//! yet (unlike Java's sealed `Lifespan`, whose `nowOn` factory always produces a usable `Impl`),
//! so there is no way to build that span from just a `snap` inside a default method body. The
//! snap-taking overloads (`place_breakpoint`, `place_breakpoint_at_address`) are therefore
//! required methods here rather than defaults, following the precedent set by
//! [`TraceModuleManager::add_loaded_module`](crate::trace::model::modules::TraceModuleManager::add_loaded_module).
//! The overload that takes a single [`Address`] instead of an [`AddressRange`] remains a default,
//! since building a single-address range needs no `Lifespan`.

use crate::program::model::address::{Address, AddressRange};
use crate::trace::model::breakpoint::trace_breakpoint_kind::TraceBreakpointKind;
use crate::trace::model::breakpoint::trace_breakpoint_spec::TraceBreakpointSpec;
use crate::trace::model::lifespan::Lifespan;
use crate::trace::seam_stubs::{TraceBreakpointLocation, TraceThread};
use crate::util::exception::DuplicateNameException;

/// A store for recording breakpoint placement over time in a trace.
pub trait TraceBreakpointManager {
    /// Add a breakpoint to the trace.
    ///
    /// # Arguments
    /// * `path` - the "full name" of the breakpoint
    /// * `lifespan` - the lifespan of the breakpoint
    /// * `range` - the address range of the breakpoint
    /// * `threads` - an optional set of threads to which the breakpoint applies. Empty for every
    ///   thread, i.e., the process.
    /// * `kinds` - the kinds of breakpoint
    /// * `enabled` - true if the breakpoint is enabled
    /// * `comment` - a user comment
    ///
    /// # Errors
    /// Returns an error if a breakpoint with the same path already exists within an overlapping
    /// snap.
    fn add_breakpoint(
        &mut self,
        path: &str,
        lifespan: &dyn Lifespan,
        range: AddressRange,
        threads: &[Box<dyn TraceThread>],
        kinds: &[TraceBreakpointKind],
        enabled: bool,
        comment: &str,
    ) -> Result<Box<dyn TraceBreakpointLocation>, DuplicateNameException>;

    /// Add a breakpoint to the trace at a single address.
    ///
    /// See [`Self::add_breakpoint`].
    ///
    /// # Errors
    /// Returns an error if a breakpoint with the same path already exists within an overlapping
    /// snap.
    fn add_breakpoint_at_address(
        &mut self,
        path: &str,
        lifespan: &dyn Lifespan,
        address: Address,
        threads: &[Box<dyn TraceThread>],
        kinds: &[TraceBreakpointKind],
        enabled: bool,
        comment: &str,
    ) -> Result<Box<dyn TraceBreakpointLocation>, DuplicateNameException> {
        self.add_breakpoint(
            path,
            lifespan,
            AddressRange::new(address.clone(), address),
            threads,
            kinds,
            enabled,
            comment,
        )
    }

    /// Add a breakpoint to the trace starting at a given snap.
    ///
    /// Mirrors Java's default `placeBreakpoint(String, long, AddressRange, ...)`, which delegates
    /// to [`Self::add_breakpoint`] with `Lifespan.nowOn(snap)`. See the module-level docs for why
    /// this is a required rather than default method in this port.
    ///
    /// # Errors
    /// Returns an error if a breakpoint with the same path already exists within an overlapping
    /// snap.
    fn place_breakpoint(
        &mut self,
        path: &str,
        snap: i64,
        range: AddressRange,
        threads: &[Box<dyn TraceThread>],
        kinds: &[TraceBreakpointKind],
        enabled: bool,
        comment: &str,
    ) -> Result<Box<dyn TraceBreakpointLocation>, DuplicateNameException>;

    /// Add a breakpoint to the trace at a single address, starting at a given snap.
    ///
    /// Mirrors Java's default `placeBreakpoint(String, long, Address, ...)`. See the
    /// module-level docs for why this is a required rather than default method in this port.
    ///
    /// # Errors
    /// Returns an error if a breakpoint with the same path already exists within an overlapping
    /// snap.
    fn place_breakpoint_at_address(
        &mut self,
        path: &str,
        snap: i64,
        address: Address,
        threads: &[Box<dyn TraceThread>],
        kinds: &[TraceBreakpointKind],
        enabled: bool,
        comment: &str,
    ) -> Result<Box<dyn TraceBreakpointLocation>, DuplicateNameException>;

    /// Collect all breakpoint specifications in the trace.
    fn get_all_breakpoint_specifications(&self) -> Vec<Box<dyn TraceBreakpointSpec>>;

    /// Collect all breakpoint locations in the trace.
    fn get_all_breakpoint_locations(&self) -> Vec<Box<dyn TraceBreakpointLocation>>;

    /// Collect breakpoint specifications having the given "full name".
    fn get_breakpoint_specifications_by_path(&self, path: &str) -> Vec<Box<dyn TraceBreakpointSpec>>;

    /// Collect breakpoint locations having the given "full name".
    fn get_breakpoint_locations_by_path(&self, path: &str) -> Vec<Box<dyn TraceBreakpointLocation>>;

    /// Get the placed breakpoint at the given snap by the given path, or `None` if no breakpoint
    /// matches.
    fn get_placed_breakpoint_by_path(&self, snap: i64, path: &str) -> Option<Box<dyn TraceBreakpointLocation>>;

    /// Collect breakpoints containing the given snap and address.
    fn get_breakpoints_at(&self, snap: i64, address: &Address) -> Vec<Box<dyn TraceBreakpointLocation>>;

    /// Collect breakpoints intersecting the given span and address range.
    fn get_breakpoints_intersecting(
        &self,
        span: &dyn Lifespan,
        range: &AddressRange,
    ) -> Vec<Box<dyn TraceBreakpointLocation>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use std::cell::RefCell;

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

    struct MockLocation;
    impl TraceBreakpointLocation for MockLocation {}

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0);
        Address::new(space, offset)
    }

    struct Record {
        path: String,
        min: i64,
        max: i64,
        range: AddressRange,
        enabled: bool,
        comment: String,
    }

    struct RecordingManager {
        records: RefCell<Vec<Record>>,
    }

    impl RecordingManager {
        fn new() -> Self {
            Self {
                records: RefCell::new(Vec::new()),
            }
        }
    }

    impl TraceBreakpointManager for RecordingManager {
        fn add_breakpoint(
            &mut self,
            path: &str,
            lifespan: &dyn Lifespan,
            range: AddressRange,
            _threads: &[Box<dyn TraceThread>],
            _kinds: &[TraceBreakpointKind],
            enabled: bool,
            comment: &str,
        ) -> Result<Box<dyn TraceBreakpointLocation>, DuplicateNameException> {
            let mut records = self.records.borrow_mut();
            let overlaps = records.iter().any(|r| {
                r.path == path && r.min <= lifespan.lmax() && lifespan.lmin() <= r.max
            });
            if overlaps {
                return Err(DuplicateNameException::with_message(format!(
                    "breakpoint already exists at path {path}"
                )));
            }
            records.push(Record {
                path: path.to_string(),
                min: lifespan.lmin(),
                max: lifespan.lmax(),
                range,
                enabled,
                comment: comment.to_string(),
            });
            Ok(Box::new(MockLocation))
        }

        fn place_breakpoint(
            &mut self,
            path: &str,
            snap: i64,
            range: AddressRange,
            threads: &[Box<dyn TraceThread>],
            kinds: &[TraceBreakpointKind],
            enabled: bool,
            comment: &str,
        ) -> Result<Box<dyn TraceBreakpointLocation>, DuplicateNameException> {
            self.add_breakpoint(
                path,
                &MockLifespan {
                    min: snap,
                    max: i64::MAX,
                },
                range,
                threads,
                kinds,
                enabled,
                comment,
            )
        }

        fn place_breakpoint_at_address(
            &mut self,
            path: &str,
            snap: i64,
            address: Address,
            threads: &[Box<dyn TraceThread>],
            kinds: &[TraceBreakpointKind],
            enabled: bool,
            comment: &str,
        ) -> Result<Box<dyn TraceBreakpointLocation>, DuplicateNameException> {
            self.place_breakpoint(
                path,
                snap,
                AddressRange::new(address.clone(), address),
                threads,
                kinds,
                enabled,
                comment,
            )
        }

        fn get_all_breakpoint_specifications(&self) -> Vec<Box<dyn TraceBreakpointSpec>> {
            Vec::new()
        }

        fn get_all_breakpoint_locations(&self) -> Vec<Box<dyn TraceBreakpointLocation>> {
            self.records
                .borrow()
                .iter()
                .map(|_| Box::new(MockLocation) as Box<dyn TraceBreakpointLocation>)
                .collect()
        }

        fn get_breakpoint_specifications_by_path(&self, _path: &str) -> Vec<Box<dyn TraceBreakpointSpec>> {
            Vec::new()
        }

        fn get_breakpoint_locations_by_path(&self, path: &str) -> Vec<Box<dyn TraceBreakpointLocation>> {
            self.records
                .borrow()
                .iter()
                .filter(|r| r.path == path)
                .map(|_| Box::new(MockLocation) as Box<dyn TraceBreakpointLocation>)
                .collect()
        }

        fn get_placed_breakpoint_by_path(&self, snap: i64, path: &str) -> Option<Box<dyn TraceBreakpointLocation>> {
            self.records
                .borrow()
                .iter()
                .find(|r| r.path == path && r.min <= snap && snap <= r.max)
                .map(|_| Box::new(MockLocation) as Box<dyn TraceBreakpointLocation>)
        }

        fn get_breakpoints_at(&self, snap: i64, address: &Address) -> Vec<Box<dyn TraceBreakpointLocation>> {
            self.records
                .borrow()
                .iter()
                .filter(|r| r.min <= snap && snap <= r.max && r.range.contains(address))
                .map(|_| Box::new(MockLocation) as Box<dyn TraceBreakpointLocation>)
                .collect()
        }

        fn get_breakpoints_intersecting(
            &self,
            span: &dyn Lifespan,
            range: &AddressRange,
        ) -> Vec<Box<dyn TraceBreakpointLocation>> {
            self.records
                .borrow()
                .iter()
                .filter(|r| r.min <= span.lmax() && span.lmin() <= r.max && r.range.intersects(range))
                .map(|_| Box::new(MockLocation) as Box<dyn TraceBreakpointLocation>)
                .collect()
        }
    }

    fn full_lifespan() -> MockLifespan {
        MockLifespan {
            min: i64::MIN,
            max: i64::MAX,
        }
    }

    #[test]
    fn is_object_safe() {
        let mut mgr = RecordingManager::new();
        let dyn_mgr: &mut dyn TraceBreakpointManager = &mut mgr;
        let _ = dyn_mgr;
    }

    #[test]
    fn add_breakpoint_then_lookup_by_address_and_path() {
        let mut mgr = RecordingManager::new();
        let range = AddressRange::new(addr(0x1000), addr(0x1000));
        mgr.add_breakpoint(
            "Breakpoints[0]",
            &full_lifespan(),
            range,
            &[],
            &[TraceBreakpointKind::SwExecute],
            true,
            "bp0",
        )
        .expect("add should succeed");

        assert_eq!(mgr.get_all_breakpoint_locations().len(), 1);
        assert_eq!(mgr.get_breakpoint_locations_by_path("Breakpoints[0]").len(), 1);
        assert!(mgr.get_breakpoint_locations_by_path("Breakpoints[1]").is_empty());
        assert!(mgr.get_placed_breakpoint_by_path(0, "Breakpoints[0]").is_some());
        assert!(mgr.get_breakpoints_at(0, &addr(0x1000)).len() == 1);
        assert!(mgr.get_breakpoints_at(0, &addr(0x2000)).is_empty());
    }

    #[test]
    fn duplicate_overlapping_path_is_rejected() {
        let mut mgr = RecordingManager::new();
        let range = AddressRange::new(addr(0x1000), addr(0x1000));
        mgr.add_breakpoint(
            "Breakpoints[0]",
            &full_lifespan(),
            range.clone(),
            &[],
            &[TraceBreakpointKind::SwExecute],
            true,
            "bp0",
        )
        .expect("first add should succeed");

        let result = mgr.add_breakpoint(
            "Breakpoints[0]",
            &full_lifespan(),
            range,
            &[],
            &[TraceBreakpointKind::SwExecute],
            true,
            "bp0-dup",
        );
        match result {
            Ok(_) => panic!("overlapping duplicate should fail"),
            Err(e) => assert!(e.0.contains("Breakpoints[0]")),
        }
    }

    #[test]
    fn add_breakpoint_at_address_default_builds_single_point_range() {
        let mut mgr = RecordingManager::new();
        mgr.add_breakpoint_at_address(
            "Breakpoints[1]",
            &full_lifespan(),
            addr(0x2000),
            &[],
            &[TraceBreakpointKind::HwExecute],
            false,
            "bp1",
        )
        .expect("add should succeed");

        let locs = mgr.get_breakpoints_at(0, &addr(0x2000));
        assert_eq!(locs.len(), 1);
    }

    #[test]
    fn place_breakpoint_uses_snap_as_lower_bound() {
        let mut mgr = RecordingManager::new();
        let range = AddressRange::new(addr(0x3000), addr(0x3010));
        mgr.place_breakpoint(
            "Breakpoints[2]",
            10,
            range,
            &[],
            &[TraceBreakpointKind::Read],
            true,
            "bp2",
        )
        .expect("place should succeed");

        assert!(mgr.get_placed_breakpoint_by_path(9, "Breakpoints[2]").is_none());
        assert!(mgr.get_placed_breakpoint_by_path(10, "Breakpoints[2]").is_some());
        assert!(mgr.get_placed_breakpoint_by_path(1000, "Breakpoints[2]").is_some());
    }

    #[test]
    fn place_breakpoint_at_address_delegates_to_place_breakpoint() {
        let mut mgr = RecordingManager::new();
        mgr.place_breakpoint_at_address(
            "Breakpoints[3]",
            5,
            addr(0x4000),
            &[],
            &[TraceBreakpointKind::Write],
            true,
            "bp3",
        )
        .expect("place should succeed");

        assert!(mgr.get_breakpoints_at(5, &addr(0x4000)).len() == 1);
    }

    #[test]
    fn get_breakpoints_intersecting_filters_by_span_and_range() {
        let mut mgr = RecordingManager::new();
        let range = AddressRange::new(addr(0x5000), addr(0x5010));
        mgr.add_breakpoint(
            "Breakpoints[4]",
            &MockLifespan { min: 0, max: 10 },
            range,
            &[],
            &[TraceBreakpointKind::SwExecute],
            true,
            "bp4",
        )
        .expect("add should succeed");

        let hit_span = MockLifespan { min: 5, max: 20 };
        let hit_range = AddressRange::new(addr(0x5005), addr(0x5020));
        assert_eq!(mgr.get_breakpoints_intersecting(&hit_span, &hit_range).len(), 1);

        let miss_span = MockLifespan { min: 100, max: 200 };
        assert!(mgr.get_breakpoints_intersecting(&miss_span, &hit_range).is_empty());
    }
}

use crate::program::model::address::{Address, AddressRange, AddressSetView};
use crate::program::model::lang::Register;
use crate::trace::model::lifespan::Lifespan;
use crate::trace::model::listing::trace_code_unit::TraceCodeUnit;
use crate::trace::model::trace::Trace;
use crate::trace::model::trace_address_snap_range::TraceAddressSnapRange;
use crate::trace::model::guest::trace_platform::TracePlatform;

/// A view of code units stored in a trace, possibly restricted to a particular subset by type,
/// address space, or thread and frame.
///
/// Port of `ghidra.trace.model.listing.TraceBaseCodeUnitsView`.
///
/// The Java interface is generic over `T extends TraceCodeUnit`, the specific unit subtype a
/// given view yields (e.g. only instructions, or only data). Rust has no covariant-return
/// generics for this purpose, so the returned/element unit type is represented here as
/// `Box<dyn TraceCodeUnit>` (the interface's own upper bound) rather than as a type parameter;
/// narrower views should document that their trait objects can be downcast or are otherwise
/// known to be of the narrower kind.
///
/// The Java overloads of `get(...)` and `coversRange(...)`/`intersectsRange(...)` cannot be
/// represented as same-named Rust methods (Rust has no overloading), so each overload is given a
/// distinct, descriptive name below.
pub trait TraceBaseCodeUnitsView {
    /// Get the trace for this view.
    fn get_trace(&self) -> Box<dyn Trace>;

    /// Get the total number of *defined* units in this view.
    fn size(&self) -> i32;

    /// Get the nearest live unit whose start address is before the given address.
    fn get_before(&self, snap: i64, address: &Address) -> Option<Box<dyn TraceCodeUnit>>;

    /// Get the nearest live unit whose start address is at or before the given address.
    fn get_floor(&self, snap: i64, address: &Address) -> Option<Box<dyn TraceCodeUnit>>;

    /// Get the live unit containing the given address.
    fn get_containing(&self, snap: i64, address: &Address) -> Option<Box<dyn TraceCodeUnit>>;

    /// Get the unit starting at exactly this address.
    ///
    /// Note that the unit need only contain the given snap.
    fn get_at(&self, snap: i64, address: &Address) -> Option<Box<dyn TraceCodeUnit>>;

    /// Get the nearest live unit whose start address is at or after the given address.
    fn get_ceiling(&self, snap: i64, address: &Address) -> Option<Box<dyn TraceCodeUnit>>;

    /// Get the nearest live unit whose start address is after the given address.
    fn get_after(&self, snap: i64, address: &Address) -> Option<Box<dyn TraceCodeUnit>>;

    /// Get the live units whose start addresses are within the specified `[min, max]` range.
    ///
    /// `forward` orders the units by increasing address if true, descending if false. Mirrors
    /// the Java overload `get(long, Address, Address, boolean)`.
    fn get_between(
        &self,
        snap: i64,
        min: &Address,
        max: &Address,
        forward: bool,
    ) -> Vec<Box<dyn TraceCodeUnit>>;

    /// Get the live units whose start addresses are in the given set. Mirrors the Java overload
    /// `get(long, AddressSetView, boolean)`.
    fn get_in_set(
        &self,
        snap: i64,
        set: &dyn AddressSetView,
        forward: bool,
    ) -> Vec<Box<dyn TraceCodeUnit>>;

    /// Get the live units whose start addresses are within the specified range. Mirrors the Java
    /// overload `get(long, AddressRange, boolean)`.
    fn get_in_range(
        &self,
        snap: i64,
        range: &AddressRange,
        forward: bool,
    ) -> Vec<Box<dyn TraceCodeUnit>>;

    /// Get the live units whose start addresses are within the specified (unbounded) range,
    /// starting at `start`. Mirrors the Java overload `get(long, Address, boolean)`.
    fn get_from(&self, snap: i64, start: &Address, forward: bool) -> Vec<Box<dyn TraceCodeUnit>>;

    /// Get all the live units. Mirrors the Java overload `get(long, boolean)`.
    fn get_all(&self, snap: i64, forward: bool) -> Vec<Box<dyn TraceCodeUnit>>;

    /// Get the units which intersect the given box, in no particular order.
    fn get_intersecting(&self, tasr: &dyn TraceAddressSnapRange) -> Vec<Box<dyn TraceCodeUnit>>;

    /// Get all addresses contained by live units at the given snap.
    ///
    /// Note that the ranges in this set may not be coalesced.
    fn get_address_set_view(&self, snap: i64) -> Box<dyn AddressSetView>;

    /// Get all addresses contained by live units at the given snap, within a restricted range.
    ///
    /// Note that the ranges in this set may not be coalesced. The returned ranges are not
    /// necessarily enclosed by `within`, but they will intersect it.
    fn get_address_set_view_within(&self, snap: i64, within: &AddressRange) -> Box<dyn AddressSetView>;

    /// Check if the given address is contained by a live unit.
    fn contains_address(&self, snap: i64, address: &Address) -> bool;

    /// Check if the given span of snaps and range of addresses is covered by the units.
    ///
    /// This checks if every (snap, address) point within the given box is contained within some
    /// code unit in this view. Mirrors the Java overload `coversRange(Lifespan, AddressRange)`.
    fn covers_range(&self, span: Lifespan, range: &AddressRange) -> bool;

    /// Check if the given address-snap range is covered by the units. Mirrors the Java overload
    /// `coversRange(TraceAddressSnapRange)`.
    fn covers_snap_range(&self, range: &dyn TraceAddressSnapRange) -> bool;

    /// Check if the given span of snaps and range of addresses intersects any unit.
    ///
    /// This checks if any (snap, address) point within the given box is contained within some
    /// code unit in this view. Mirrors the Java overload `intersectsRange(Lifespan,
    /// AddressRange)`.
    fn intersects_range(&self, span: Lifespan, range: &AddressRange) -> bool;

    /// Check if the given span of snaps and range of addresses intersects any unit. Mirrors the
    /// Java overload `intersectsRange(TraceAddressSnapRange)`.
    fn intersects_snap_range(&self, range: &dyn TraceAddressSnapRange) -> bool;

    /// Get the unit (or component of a structure) which spans exactly the addresses of the given
    /// register, using the trace's host platform.
    fn get_for_register(&self, snap: i64, register: &Register) -> Option<Box<dyn TraceCodeUnit>> {
        let platform = self.get_trace().get_platform_manager().get_host_platform();
        self.get_for_register_on_platform(platform.as_ref(), snap, register)
    }

    /// Get the unit (or component of a structure) which spans exactly the addresses of the given
    /// platform register.
    fn get_for_register_on_platform(
        &self,
        platform: &dyn TracePlatform,
        snap: i64,
        register: &Register,
    ) -> Option<Box<dyn TraceCodeUnit>>;

    /// Get the unit which completely contains the given register, using the trace's host
    /// platform.
    ///
    /// This does not descend into structures.
    fn get_containing_register(
        &self,
        snap: i64,
        register: &Register,
    ) -> Option<Box<dyn TraceCodeUnit>> {
        let platform = self.get_trace().get_platform_manager().get_host_platform();
        self.get_containing_register_on_platform(platform.as_ref(), snap, register)
    }

    /// Get the unit which completely contains the given register.
    ///
    /// This does not descend into structures.
    fn get_containing_register_on_platform(
        &self,
        platform: &dyn TracePlatform,
        snap: i64,
        register: &Register,
    ) -> Option<Box<dyn TraceCodeUnit>>;

    /// Get the live units whose start addresses are within the given register, using the
    /// trace's host platform.
    fn get_by_register(
        &self,
        snap: i64,
        register: &Register,
        forward: bool,
    ) -> Vec<Box<dyn TraceCodeUnit>> {
        let platform = self.get_trace().get_platform_manager().get_host_platform();
        self.get_by_platform_register(platform.as_ref(), snap, register, forward)
    }

    /// Get the live units whose start addresses are within the given platform register.
    fn get_by_platform_register(
        &self,
        platform: &dyn TracePlatform,
        snap: i64,
        register: &Register,
        forward: bool,
    ) -> Vec<Box<dyn TraceCodeUnit>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSet, AddressSpace, AddressSpaceType};
    use crate::program::model::lang::Language;
    use crate::program::model::listing::code_unit::CodeUnit;
    use crate::program::model::listing::program::Program;
    use crate::program::model::mem::MemoryAccessException;
    use crate::program::model::scalar::Scalar;
    use crate::program::model::symbol::{
        ExternalReference, RefType, Reference, ReferenceIterator, SourceType, Symbol,
    };
    use crate::program::model::util::PropertySet;
    use crate::program::model::mem::MemBuffer;
use crate::program::model::listing::CommentType;
    use crate::trace::seam_stubs::TraceThread;
    use std::sync::Arc;

    #[derive(Clone)]
    struct MockUnit {
        address: Address,
        length: i32,
        start_snap: i64,
        end_snap: i64,
    }

    impl MemBuffer for MockUnit {
        fn get_byte(&self, _offset: i32) -> Result<u8, crate::program::model::mem::MemoryAccessException> {
            unimplemented!("not exercised by these tests")
        }
        fn get_bytes(&self, _buf: &mut [u8], _offset: i32) -> usize {
            unimplemented!("not exercised by these tests")
        }
        fn is_big_endian(&self) -> bool {
            unimplemented!("not exercised by these tests")
        }
        fn get_address(&self) -> Address {
            self.address.clone()
        }
    }
    impl PropertySet for MockUnit {}

    impl CodeUnit for MockUnit {
        fn get_address_string(&self, _show_block_name: bool, _pad: bool) -> String {
            format!("{:08x}", self.address.offset())
        }

        fn get_label(&self) -> Option<String> {
            None
        }

        fn get_symbols(&self) -> Vec<Arc<dyn Symbol>> {
            Vec::new()
        }

        fn get_primary_symbol(&self) -> Option<Arc<dyn Symbol>> {
            None
        }

        fn get_min_address(&self) -> Address {
            self.address.clone()
        }

        fn get_max_address(&self) -> Address {
            self.address.add_wrap(self.length as i64 - 1)
        }

        fn get_mnemonic_string(&self) -> String {
            "NOP".to_string()
        }

        fn get_comment(&self, _comment_type: CommentType) -> Option<String> {
            None
        }

        fn get_comment_as_array(&self, _comment_type: CommentType) -> Vec<String> {
            Vec::new()
        }

        fn set_comment(&mut self, _comment_type: CommentType, _comment: Option<String>) {}

        fn set_comment_as_array(&mut self, _comment_type: CommentType, _comment: &[String]) {}

        fn get_length(&self) -> i32 {
            self.length
        }

        fn get_bytes(&self) -> Result<Vec<u8>, MemoryAccessException> {
            Ok(vec![0x90; self.length as usize])
        }

        fn get_bytes_in_code_unit(
            &self,
            buffer: &mut [u8],
            _buffer_offset: i32,
        ) -> Result<(), MemoryAccessException> {
            buffer.fill(0x90);
            Ok(())
        }

        fn contains(&self, test_addr: &Address) -> bool {
            test_addr.offset() >= self.address.offset()
                && test_addr.offset() < self.address.offset() + self.length as i64
        }

        fn compare_to(&self, addr: &Address) -> i32 {
            self.address.offset().cmp(&addr.offset()) as i32
        }

        fn add_mnemonic_reference(
            &mut self,
            _ref_addr: Address,
            _ref_type: RefType,
            _source_type: SourceType,
        ) {
        }

        fn remove_mnemonic_reference(&mut self, _ref_addr: &Address) {}

        fn get_mnemonic_references(&self) -> Vec<Arc<dyn Reference>> {
            Vec::new()
        }

        fn get_operand_references(&self, _index: i32) -> Vec<Arc<dyn Reference>> {
            Vec::new()
        }

        fn get_primary_reference(&self, _index: i32) -> Option<Arc<dyn Reference>> {
            None
        }

        fn add_operand_reference(
            &mut self,
            _index: i32,
            _ref_addr: Address,
            _ref_type: RefType,
            _source_type: SourceType,
        ) {
        }

        fn remove_operand_reference(&mut self, _index: i32, _ref_addr: &Address) {}

        fn get_references_from(&self) -> Vec<Arc<dyn Reference>> {
            Vec::new()
        }

        fn get_reference_iterator_to(&self) -> Box<dyn ReferenceIterator> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_program(&self) -> Arc<dyn Program> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_external_reference(&self, _op_index: i32) -> Option<Arc<dyn ExternalReference>> {
            None
        }

        fn remove_external_reference(&mut self, _op_index: i32) {}

        fn set_primary_memory_reference(&mut self, _reference: Arc<dyn Reference>) {}

        fn set_stack_reference(
            &mut self,
            _op_index: i32,
            _offset: i32,
            _source_type: SourceType,
            _ref_type: RefType,
        ) {
        }

        fn set_register_reference(
            &mut self,
            _op_index: i32,
            _reg: &crate::program::model::lang::register::Register,
            _source_type: SourceType,
            _ref_type: RefType,
        ) {
        }

        fn get_num_operands(&self) -> i32 {
            1
        }

        fn get_address(&self, _op_index: i32) -> Option<Address> {
            None
        }

        fn get_scalar(&self, _op_index: i32) -> Option<Scalar> {
            None
        }
    }

    impl TraceCodeUnit for MockUnit {
        fn get_trace(&self) -> Box<dyn Trace> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_platform(&self) -> Box<dyn TracePlatform> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_thread(&self) -> Box<dyn TraceThread> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_language(&self) -> Box<dyn Language> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_bounds(&self) -> Box<dyn TraceAddressSnapRange> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_range(&self) -> AddressRange {
            AddressRange::new(self.address.clone(), self.address.add_wrap(self.length as i64 - 1))
        }

        fn get_lifespan(&self) -> Lifespan {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_start_snap(&self) -> i64 {
            self.start_snap
        }

        fn set_end_snap(&mut self, end_snap: i64) {
            self.end_snap = end_snap;
        }

        fn get_end_snap(&self) -> i64 {
            self.end_snap
        }

        fn delete(&mut self) {}
    }

    /// A minimal in-memory view backing store, only realistic enough to prove the trait's
    /// address/snap-filtering semantics against a small fixed fixture.
    struct MockView {
        units: Vec<MockUnit>,
    }

    impl MockView {
        fn alive_at(&self, snap: i64) -> impl Iterator<Item = &MockUnit> {
            self.units
                .iter()
                .filter(move |u| u.start_snap <= snap && snap <= u.end_snap)
        }
    }

    impl TraceBaseCodeUnitsView for MockView {
        fn get_trace(&self) -> Box<dyn Trace> {
            unimplemented!("not exercised by this smoke test")
        }

        fn size(&self) -> i32 {
            self.units.len() as i32
        }

        fn get_before(&self, snap: i64, address: &Address) -> Option<Box<dyn TraceCodeUnit>> {
            self.alive_at(snap)
                .filter(|u| u.address.offset() < address.offset())
                .max_by_key(|u| u.address.offset())
                .map(|u| Box::new(u.clone()) as Box<dyn TraceCodeUnit>)
        }

        fn get_floor(&self, snap: i64, address: &Address) -> Option<Box<dyn TraceCodeUnit>> {
            self.alive_at(snap)
                .filter(|u| u.address.offset() <= address.offset())
                .max_by_key(|u| u.address.offset())
                .map(|u| Box::new(u.clone()) as Box<dyn TraceCodeUnit>)
        }

        fn get_containing(&self, snap: i64, address: &Address) -> Option<Box<dyn TraceCodeUnit>> {
            self.alive_at(snap)
                .find(|u| u.contains(address))
                .map(|u| Box::new(u.clone()) as Box<dyn TraceCodeUnit>)
        }

        fn get_at(&self, snap: i64, address: &Address) -> Option<Box<dyn TraceCodeUnit>> {
            self.alive_at(snap)
                .find(|u| u.address.offset() == address.offset())
                .map(|u| Box::new(u.clone()) as Box<dyn TraceCodeUnit>)
        }

        fn get_ceiling(&self, snap: i64, address: &Address) -> Option<Box<dyn TraceCodeUnit>> {
            self.alive_at(snap)
                .filter(|u| u.address.offset() >= address.offset())
                .min_by_key(|u| u.address.offset())
                .map(|u| Box::new(u.clone()) as Box<dyn TraceCodeUnit>)
        }

        fn get_after(&self, snap: i64, address: &Address) -> Option<Box<dyn TraceCodeUnit>> {
            self.alive_at(snap)
                .filter(|u| u.address.offset() > address.offset())
                .min_by_key(|u| u.address.offset())
                .map(|u| Box::new(u.clone()) as Box<dyn TraceCodeUnit>)
        }

        fn get_between(
            &self,
            snap: i64,
            min: &Address,
            max: &Address,
            forward: bool,
        ) -> Vec<Box<dyn TraceCodeUnit>> {
            let mut units: Vec<&MockUnit> = self
                .alive_at(snap)
                .filter(|u| u.address.offset() >= min.offset() && u.address.offset() <= max.offset())
                .collect();
            units.sort_by_key(|u| u.address.offset());
            if !forward {
                units.reverse();
            }
            units
                .into_iter()
                .map(|u| Box::new(u.clone()) as Box<dyn TraceCodeUnit>)
                .collect()
        }

        fn get_in_set(
            &self,
            snap: i64,
            set: &dyn AddressSetView,
            forward: bool,
        ) -> Vec<Box<dyn TraceCodeUnit>> {
            let mut units: Vec<&MockUnit> =
                self.alive_at(snap).filter(|u| set.contains(&u.address)).collect();
            units.sort_by_key(|u| u.address.offset());
            if !forward {
                units.reverse();
            }
            units
                .into_iter()
                .map(|u| Box::new(u.clone()) as Box<dyn TraceCodeUnit>)
                .collect()
        }

        fn get_in_range(
            &self,
            snap: i64,
            range: &AddressRange,
            forward: bool,
        ) -> Vec<Box<dyn TraceCodeUnit>> {
            self.get_between(snap, range.min_address(), range.max_address(), forward)
        }

        fn get_from(&self, snap: i64, start: &Address, forward: bool) -> Vec<Box<dyn TraceCodeUnit>> {
            let mut units: Vec<&MockUnit> = self
                .alive_at(snap)
                .filter(|u| {
                    if forward {
                        u.address.offset() >= start.offset()
                    } else {
                        u.address.offset() <= start.offset()
                    }
                })
                .collect();
            units.sort_by_key(|u| u.address.offset());
            if !forward {
                units.reverse();
            }
            units
                .into_iter()
                .map(|u| Box::new(u.clone()) as Box<dyn TraceCodeUnit>)
                .collect()
        }

        fn get_all(&self, snap: i64, forward: bool) -> Vec<Box<dyn TraceCodeUnit>> {
            let mut units: Vec<&MockUnit> = self.alive_at(snap).collect();
            units.sort_by_key(|u| u.address.offset());
            if !forward {
                units.reverse();
            }
            units
                .into_iter()
                .map(|u| Box::new(u.clone()) as Box<dyn TraceCodeUnit>)
                .collect()
        }

        fn get_intersecting(&self, _tasr: &dyn TraceAddressSnapRange) -> Vec<Box<dyn TraceCodeUnit>> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_address_set_view(&self, snap: i64) -> Box<dyn AddressSetView> {
            let mut set = AddressSet::new();
            for u in self.alive_at(snap) {
                set.add_range(&u.get_min_address(), &u.get_max_address());
            }
            Box::new(set)
        }

        fn get_address_set_view_within(
            &self,
            snap: i64,
            within: &AddressRange,
        ) -> Box<dyn AddressSetView> {
            let mut set = AddressSet::new();
            for u in self.alive_at(snap) {
                if u.get_range().intersects(within) {
                    set.add_range(&u.get_min_address(), &u.get_max_address());
                }
            }
            Box::new(set)
        }

        fn contains_address(&self, snap: i64, address: &Address) -> bool {
            self.alive_at(snap).any(|u| u.contains(address))
        }

        fn covers_range(&self, _span: Lifespan, _range: &AddressRange) -> bool {
            unimplemented!("not exercised by this smoke test")
        }

        fn covers_snap_range(&self, _range: &dyn TraceAddressSnapRange) -> bool {
            unimplemented!("not exercised by this smoke test")
        }

        fn intersects_range(&self, _span: Lifespan, _range: &AddressRange) -> bool {
            unimplemented!("not exercised by this smoke test")
        }

        fn intersects_snap_range(&self, _range: &dyn TraceAddressSnapRange) -> bool {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_for_register_on_platform(
            &self,
            _platform: &dyn TracePlatform,
            _snap: i64,
            _register: &Register,
        ) -> Option<Box<dyn TraceCodeUnit>> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_containing_register_on_platform(
            &self,
            _platform: &dyn TracePlatform,
            _snap: i64,
            _register: &Register,
        ) -> Option<Box<dyn TraceCodeUnit>> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_by_platform_register(
            &self,
            _platform: &dyn TracePlatform,
            _snap: i64,
            _register: &Register,
            _forward: bool,
        ) -> Vec<Box<dyn TraceCodeUnit>> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    fn make_view() -> MockView {
        MockView {
            units: vec![
                MockUnit {
                    address: addr(0x400),
                    length: 4,
                    start_snap: 0,
                    end_snap: 10,
                },
                MockUnit {
                    address: addr(0x404),
                    length: 2,
                    start_snap: 0,
                    end_snap: 10,
                },
                MockUnit {
                    address: addr(0x500),
                    length: 4,
                    start_snap: 5,
                    end_snap: 20,
                },
            ],
        }
    }

    #[test]
    fn usable_as_trait_object_and_filters_by_address_and_snap() {
        let view: Box<dyn TraceBaseCodeUnitsView> = Box::new(make_view());

        assert_eq!(view.size(), 3);

        // Exact-address lookup, gated by liveness at the given snap.
        let at = view.get_at(0, &addr(0x400)).expect("unit at 0x400");
        assert_eq!(at.get_min_address(), addr(0x400));
        assert!(view.get_at(0, &addr(0x500)).is_none(), "0x500 unit is not yet alive at snap 0");
        assert!(view.get_at(5, &addr(0x500)).is_some(), "0x500 unit is alive at snap 5");

        // Nearest-neighbor navigation.
        let before = view.get_before(0, &addr(0x404)).expect("unit before 0x404");
        assert_eq!(before.get_min_address(), addr(0x400));

        let ceiling = view.get_ceiling(0, &addr(0x401)).expect("unit at/after 0x401");
        assert_eq!(ceiling.get_min_address(), addr(0x404));

        let after = view.get_after(0, &addr(0x400)).expect("unit after 0x400");
        assert_eq!(after.get_min_address(), addr(0x404));

        // Containment.
        let containing = view.get_containing(0, &addr(0x401)).expect("unit containing 0x401");
        assert_eq!(containing.get_min_address(), addr(0x400));
        assert!(view.contains_address(0, &addr(0x403)));
        assert!(!view.contains_address(0, &addr(0x406)));

        // Range query with ordering, restricted to what's alive at snap 0 (excludes 0x500).
        let forward = view.get_between(0, &addr(0x0), &addr(0x1000), true);
        let forward_addrs: Vec<i64> =
            forward.iter().map(|u| u.get_min_address().offset()).collect();
        assert_eq!(forward_addrs, vec![0x400, 0x404]);

        let backward = view.get_between(0, &addr(0x0), &addr(0x1000), false);
        let backward_addrs: Vec<i64> =
            backward.iter().map(|u| u.get_min_address().offset()).collect();
        assert_eq!(backward_addrs, vec![0x404, 0x400]);

        // At snap 5, all three units are alive.
        assert_eq!(view.get_all(5, true).len(), 3);
    }
}

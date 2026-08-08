//! A property map space for a memory space.
//!
//! Java source: `ghidra.trace.model.property.TracePropertyMapSpace`.
//!
//! The Java interface's register-taking `set`/`getEntries`/`clear` overloads cannot be
//! represented as same-named Rust methods (Rust has no overloading, and this trait already
//! inherits `set`/`set_range`/`get_entries`/`clear` from
//! [`TracePropertyMapOperations`](super::trace_property_map_operations::TracePropertyMapOperations)),
//! so each is given a distinct, descriptive name below, following the convention established by
//! [`TraceSymbolWithLocationView`](crate::trace::model::symbol::trace_symbol_with_location_view::TraceSymbolWithLocationView)
//! and [`TraceBaseCodeUnitsView`](crate::trace::model::listing::trace_base_code_units_view::TraceBaseCodeUnitsView).
//!
//! The register-taking overload of `clear` resolves the register's own occupied range via the
//! static `TraceRegisterUtils.rangeForRegister`, not yet ported. Following the same convention,
//! implementors must supply an instance via [`Self::trace_register_utils`].
use std::sync::Arc;

use crate::program::model::address::AddressSpace;
use crate::program::model::lang::Register;
use crate::trace::model::lifespan::Lifespan;
use crate::trace::model::trace::Trace;
use crate::trace::model::trace_address_snap_range::TraceAddressSnapRange;
use crate::trace::seam_stubs::{TracePlatform, TraceRegisterUtils};

use super::trace_property_map_operations::TracePropertyMapOperations;

/// A property map space for a memory space.
///
/// Port of `ghidra.trace.model.property.TracePropertyMapSpace<T>`.
pub trait TracePropertyMapSpace<T>: TracePropertyMapOperations<T>
where
    T: 'static,
{
    /// Get the trace. Mirrors `getTrace()`.
    fn get_trace(&self) -> Box<dyn Trace>;

    /// Get the address space for this space. Mirrors `getAddressSpace()`.
    fn get_address_space(&self) -> Arc<AddressSpace>;

    /// The `TraceRegisterUtils` instance used to resolve a register's own occupied range.
    /// Mirrors the static `TraceRegisterUtils.rangeForRegister` call made by
    /// [`Self::clear_register`].
    fn trace_register_utils(&self) -> &dyn TraceRegisterUtils;

    /// Set a property on the given register for the given lifespan, under the given platform.
    ///
    /// Mirrors the Java overload `set(TracePlatform, Lifespan, Register, Object)`.
    fn set_register_on_platform(
        &mut self,
        platform: &dyn TracePlatform,
        lifespan: Lifespan,
        register: &Register,
        value: T,
    ) {
        let range = platform.get_conventional_register_range(&self.get_address_space(), register);
        self.set_range(lifespan, range, value);
    }

    /// Set a property on the given register for the given lifespan, using the trace's host
    /// platform.
    ///
    /// Mirrors the Java overload `set(Lifespan, Register, Object)`.
    fn set_register(&mut self, lifespan: Lifespan, register: &Register, value: T) {
        let platform = self.get_trace().get_platform_manager().get_host_platform();
        self.set_register_on_platform(platform.as_ref(), lifespan, register, value);
    }

    /// Get all entries intersecting the given register and lifespan, under the given platform.
    ///
    /// Mirrors the Java overload `getEntries(TracePlatform, Lifespan, Register)`.
    fn get_entries_for_register_on_platform(
        &self,
        platform: &dyn TracePlatform,
        lifespan: Lifespan,
        register: &Register,
    ) -> Vec<(Box<dyn TraceAddressSnapRange>, T)> {
        let range = platform.get_conventional_register_range(&self.get_address_space(), register);
        self.get_entries(lifespan, range)
    }

    /// Get all entries intersecting the given register and lifespan, using the trace's host
    /// platform.
    ///
    /// Mirrors the Java overload `getEntries(Lifespan, Register)`.
    fn get_entries_for_register(
        &self,
        lifespan: Lifespan,
        register: &Register,
    ) -> Vec<(Box<dyn TraceAddressSnapRange>, T)> {
        let platform = self.get_trace().get_platform_manager().get_host_platform();
        self.get_entries_for_register_on_platform(platform.as_ref(), lifespan, register)
    }

    /// Remove or truncate entries so that the given box (register and lifespan) contains no
    /// entries.
    ///
    /// Mirrors the Java overload `clear(Lifespan, Register)`. Unlike the Java default (which
    /// returns `void`), this propagates the underlying [`clear`](Self::clear)'s report of
    /// whether any entry was affected.
    fn clear_register(&mut self, span: Lifespan, register: &Register) -> bool {
        let range = self.trace_register_utils().range_for_register(register);
        self.clear(span, range)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::range::AddressRange;
    use crate::program::model::address::{Address, AddressSet, AddressSetView, AddressSpaceType};
    use std::any::TypeId;

    #[derive(Clone)]
    struct MockRange {
        range: AddressRange,
        y1: i64,
        y2: i64,
    }

    impl TraceAddressSnapRange for MockRange {
        fn get_lifespan(&self) -> Lifespan {
            Lifespan::span(self.y1, self.y2)
        }

        fn get_range(&self) -> AddressRange {
            self.range.clone()
        }

        fn get_bounds(&self) -> Box<dyn TraceAddressSnapRange> {
            Box::new(self.clone())
        }

        fn immutable(
            &self,
            x1: Address,
            x2: Address,
            y1: i64,
            y2: i64,
        ) -> Box<dyn TraceAddressSnapRange> {
            Box::new(MockRange {
                range: AddressRange::new(x1, x2),
                y1,
                y2,
            })
        }
    }

    struct MockRegisterUtils;
    impl TraceRegisterUtils for MockRegisterUtils {
        fn get_thread(&self, _trace: &dyn Trace, _space: &Arc<AddressSpace>) -> Box<dyn crate::trace::seam_stubs::TraceThread> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_frame_level(&self, _trace: &dyn Trace, _space: &Arc<AddressSpace>) -> i32 {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_register_address_space(
            &self,
            _thread: &dyn crate::trace::seam_stubs::TraceThread,
            _frame_level: i32,
            _create_if_absent: bool,
        ) -> Option<Arc<AddressSpace>> {
            unimplemented!("not exercised by this smoke test")
        }

        fn buffer_for_value(
            &self,
            _register: &Register,
            _value: &dyn crate::program::seam_stubs::RegisterValue,
        ) -> Vec<u8> {
            unimplemented!("not exercised by this smoke test")
        }

        fn finish_buffer(
            &self,
            _buf: &[u8],
            _register: &Register,
        ) -> Box<dyn crate::program::seam_stubs::RegisterValue> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    /// A trivial single-space in-memory implementation, sufficient to exercise the
    /// register-taking defaults against a real conventional range computation.
    struct MockSpace {
        space: Arc<AddressSpace>,
        entries: Vec<(MockRange, i32)>,
        register_utils: MockRegisterUtils,
    }

    impl TracePropertyMapOperations<i32> for MockSpace {
        fn get_value_class(&self) -> TypeId {
            TypeId::of::<i32>()
        }

        fn set(&mut self, lifespan: Lifespan, address: Address, value: i32) {
            self.set_range(lifespan, AddressRange::new(address.clone(), address), value)
        }

        fn set_range(&mut self, lifespan: Lifespan, range: AddressRange, value: i32) {
            self.entries.push((
                MockRange {
                    range,
                    y1: lifespan.lmin(),
                    y2: lifespan.lmax(),
                },
                value,
            ));
        }

        fn get(&self, snap: i64, address: &Address) -> Option<i32> {
            self.get_entry(snap, address).map(|(_, v)| v)
        }

        fn get_entry(
            &self,
            snap: i64,
            address: &Address,
        ) -> Option<(Box<dyn TraceAddressSnapRange>, i32)> {
            self.entries
                .iter()
                .find(|(shape, _)| shape.range.contains(address) && shape.y1 <= snap && snap <= shape.y2)
                .map(|(shape, v)| (Box::new(shape.clone()) as Box<dyn TraceAddressSnapRange>, *v))
        }

        fn get_entries(
            &self,
            lifespan: Lifespan,
            range: AddressRange,
        ) -> Vec<(Box<dyn TraceAddressSnapRange>, i32)> {
            self.entries
                .iter()
                .filter(|(shape, _)| {
                    shape.range.intersects(&range) && shape.y1 <= lifespan.lmax() && lifespan.lmin() <= shape.y2
                })
                .map(|(shape, v)| (Box::new(shape.clone()) as Box<dyn TraceAddressSnapRange>, *v))
                .collect()
        }

        fn get_address_set_view(&self, span: Lifespan) -> Box<dyn AddressSetView> {
            let mut set = AddressSet::new();
            for (shape, _) in &self.entries {
                if shape.y1 <= span.lmax() && span.lmin() <= shape.y2 {
                    set.add_range_object(&shape.range);
                }
            }
            Box::new(set)
        }

        fn clear(&mut self, span: Lifespan, range: AddressRange) -> bool {
            let (lmin, lmax) = (span.lmin(), span.lmax());
            let before = self.entries.len();
            self.entries
                .retain(|(shape, _)| !shape.range.intersects(&range) || shape.y2 < lmin || lmax < shape.y1);
            self.entries.len() != before
        }
    }

    impl TracePropertyMapSpace<i32> for MockSpace {
        fn get_trace(&self) -> Box<dyn Trace> {
            unimplemented!("not exercised by this smoke test (platform-taking overloads only)")
        }

        fn get_address_space(&self) -> Arc<AddressSpace> {
            self.space.clone()
        }

        fn trace_register_utils(&self) -> &dyn TraceRegisterUtils {
            &self.register_utils
        }
    }

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0)
    }

    fn addr(offset: i64) -> Address {
        Address::new(ram_space(), offset)
    }

    /// A host platform whose conventional register range matches the register's own address and
    /// byte length, mirroring `TracePlatform`'s default identity-mapping behavior.
    struct HostPlatform;
    impl TracePlatform for HostPlatform {}

    fn make_register(offset: i64, num_bytes: i32) -> crate::program::model::lang::RegisterRef {
        Register::new("r0", "test register", addr(offset), num_bytes, false, 0)
    }

    #[test]
    fn set_register_on_platform_uses_conventional_range() {
        let mut space = MockSpace {
            space: ram_space(),
            entries: vec![],
            register_utils: MockRegisterUtils,
        };
        let register = make_register(0x1000, 4);
        space.set_register_on_platform(&HostPlatform, Lifespan::span(0, 10), &register.borrow(), 42);

        assert_eq!(space.get(5, &addr(0x1000)), Some(42));
        assert_eq!(space.get(5, &addr(0x1003)), Some(42));
        assert_eq!(space.get(5, &addr(0x1004)), None);
    }

    #[test]
    fn get_entries_for_register_on_platform_matches_set_register() {
        let mut space = MockSpace {
            space: ram_space(),
            entries: vec![],
            register_utils: MockRegisterUtils,
        };
        let register = make_register(0x2000, 8);
        space.set_register_on_platform(&HostPlatform, Lifespan::span(0, 10), &register.borrow(), 7);

        let found = space.get_entries_for_register_on_platform(
            &HostPlatform,
            Lifespan::span(0, 10),
            &register.borrow(),
        );
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].1, 7);

        let other_register = make_register(0x3000, 4);
        assert!(space
            .get_entries_for_register_on_platform(
                &HostPlatform,
                Lifespan::span(0, 10),
                &other_register.borrow(),
            )
            .is_empty());
    }

    #[test]
    fn clear_register_removes_entry_over_its_own_range() {
        let mut space = MockSpace {
            space: ram_space(),
            entries: vec![],
            register_utils: MockRegisterUtils,
        };
        let register = make_register(0x4000, 4);
        space.set_range(
            Lifespan::span(0, 10),
            AddressRange::new(addr(0x4000), addr(0x4003)),
            9,
        );

        let cleared = space.clear_register(Lifespan::span(0, 10), &register.borrow());
        assert!(cleared);
        assert_eq!(space.get(5, &addr(0x4000)), None);

        let cleared_again = space.clear_register(Lifespan::span(0, 10), &register.borrow());
        assert!(!cleared_again);
    }
}

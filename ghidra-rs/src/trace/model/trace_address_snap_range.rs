//! A 2D rectangle of address range (X axis) by snapshot lifespan (Y axis).
//!
//! Java source: `ghidra.trace.model.TraceAddressSnapRange`.
//!
//! In the original, this interface extends `Rectangle2D<Address, Long,
//! TraceAddressSnapRange>` (an F-bounded self-type) and supplies `Address`/`Long`
//! coordinate accessors as defaults derived from [`get_range`](TraceAddressSnapRange::get_range)
//! and [`get_lifespan`](TraceAddressSnapRange::get_lifespan). The ported
//! [`Rectangle2D`](crate::util::database::spatial::rect::rectangle2d::Rectangle2D) trait requires
//! `Self: Sized` (to support its generic, coordinate-typed default methods), which is
//! incompatible with the object-safe trait this cycle cut-point needs, so that supertrait
//! relationship is intentionally not reproduced here. Instead, the handful of Rectangle2D-derived
//! defaults this interface actually declares (`getX1`, `getX2`, `getY1`, `getY2`, `getBounds`,
//! `description`) are ported directly against concrete `Address`/`i64` coordinates, and
//! `immutable`/`getBounds` return `Box<dyn TraceAddressSnapRange>` in place of the Java `R` self-type.
use crate::program::model::address::range::AddressRange;
use crate::program::model::address::Address;
use crate::trace::model::lifespan::Lifespan;

/// A rectangle over `(Address, snap)` space: an address range paired with a lifespan.
pub trait TraceAddressSnapRange: Send + Sync {
    /// Returns the lifespan (snap range) of this rectangle's Y extent.
    fn get_lifespan(&self) -> Lifespan;

    /// Returns the address range of this rectangle's X extent.
    fn get_range(&self) -> AddressRange;

    /// Returns the bounding rectangle of this shape, i.e., itself.
    ///
    /// Corresponds to the Java default `getBounds() { return this; }`. Since the trait
    /// object can't return an owned `Self`, implementors provide a boxed copy of themselves.
    fn get_bounds(&self) -> Box<dyn TraceAddressSnapRange>;

    /// Returns the lower X bound (the range's minimum address).
    fn get_x1(&self) -> Address {
        self.get_range().min_address().clone()
    }

    /// Returns the upper X bound (the range's maximum address).
    fn get_x2(&self) -> Address {
        self.get_range().max_address().clone()
    }

    /// Returns the lower Y bound (the lifespan's minimum snap).
    fn get_y1(&self) -> i64 {
        self.get_lifespan().lmin()
    }

    /// Returns the upper Y bound (the lifespan's maximum snap).
    fn get_y2(&self) -> i64 {
        self.get_lifespan().lmax()
    }

    /// Constructs a new rectangle with the given bounds.
    ///
    /// Corresponds to the Java default `immutable(x1, x2, y1, y2) { return new
    /// ImmutableTraceAddressSnapRange(x1, x2, y1, y2); }`.
    /// [`ImmutableTraceAddressSnapRange`](crate::trace::model::immutable_trace_address_snap_range::ImmutableTraceAddressSnapRange)
    /// is ported as a trait, not a concrete type (it was a cycle cut-point), so there is still no
    /// single canonical implementor to construct here; this remains a required method rather than
    /// a default.
    fn immutable(
        &self,
        x1: Address,
        x2: Address,
        y1: i64,
        y2: i64,
    ) -> Box<dyn TraceAddressSnapRange>;

    /// Returns a human-readable description of this rectangle.
    fn description(&self) -> String {
        let range = self.get_range();
        format!(
            "[{}:{:x}:{:x}]{}..{}",
            range.space().name(),
            self.get_x1().offset(),
            self.get_x2().offset(),
            self.get_lifespan().lmin(),
            self.get_lifespan().lmax(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};



    #[derive(Clone)]
    struct MockRange {
        range: AddressRange,
        lifespan: Lifespan,
    }

    impl TraceAddressSnapRange for MockRange {
        fn get_lifespan(&self) -> Lifespan {
            self.lifespan
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
                lifespan: Lifespan::span(y1, y2),
            })
        }
    }

    fn ram_space() -> std::sync::Arc<AddressSpace> {
        AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0)
    }

    fn make_range(min: i64, max: i64, lo: i64, hi: i64) -> MockRange {
        let space = ram_space();
        MockRange {
            range: AddressRange::new(
                Address::new(space.clone(), min),
                Address::new(space, max),
            ),
            lifespan: Lifespan::span(lo, hi),
        }
    }

    #[test]
    fn x1_x2_derive_from_range() {
        let r = make_range(0x1000, 0x2000, 0, 10);
        assert_eq!(r.get_x1().offset(), 0x1000);
        assert_eq!(r.get_x2().offset(), 0x2000);
    }

    #[test]
    fn y1_y2_derive_from_lifespan() {
        let r = make_range(0x1000, 0x2000, 5, 15);
        assert_eq!(r.get_y1(), 5);
        assert_eq!(r.get_y2(), 15);
    }

    #[test]
    fn immutable_constructs_new_range_with_given_bounds() {
        let r = make_range(0x1000, 0x2000, 0, 10);
        let space = ram_space();
        let replaced = r.immutable(
            Address::new(space.clone(), 0x3000),
            Address::new(space, 0x4000),
            20,
            30,
        );
        assert_eq!(replaced.get_x1().offset(), 0x3000);
        assert_eq!(replaced.get_x2().offset(), 0x4000);
        assert_eq!(replaced.get_y1(), 20);
        assert_eq!(replaced.get_y2(), 30);
    }

    #[test]
    fn get_bounds_returns_equivalent_rectangle() {
        let r = make_range(0x1000, 0x2000, 0, 10);
        let bounds = r.get_bounds();
        assert_eq!(bounds.get_x1().offset(), r.get_x1().offset());
        assert_eq!(bounds.get_y2(), r.get_y2());
    }

    #[test]
    fn description_includes_space_offsets_and_lifespan() {
        let r = make_range(0x10, 0x20, 1, 2);
        assert_eq!(r.description(), "[ram:10:20]1..2");
    }

    #[test]
    fn dyn_trait_object_is_usable() {
        let r = make_range(0x1000, 0x2000, 0, 10);
        let boxed: Box<dyn TraceAddressSnapRange> = Box::new(r);
        assert_eq!(boxed.get_x1().offset(), 0x1000);
        assert_eq!(boxed.description(), "[ram:1000:2000]0..10");
    }
}

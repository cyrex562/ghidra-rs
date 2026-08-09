//! A trace value's shape: a [`ValueBox`]-bounded region addressable by parent/child/entry-key,
//! optionally denoting an address or address range.
//!
//! Java source: `ghidra.trace.database.target.ValueShape`.
//!
//! Ported as a trait because it was selected as a cycle cut-point. The Java interface is
//! `ValueShape extends BoundedShape<ValueBox>`; since [`ValueBox`] itself has non-`Self`-erasable
//! methods (`immutable`/`intersection`/etc. return `Self`, inherited from `HyperBox`), it cannot
//! be used as `dyn ValueBox`, so this trait is generic over the bounding box type `B: ValueBox`
//! rather than fixing `BoundedShape<ValueBox>` to a trait object.
use crate::program::model::address::range::AddressRange;
use crate::program::model::address::{Address, AddressFactory};
use crate::trace::database::target::value_box::ValueBox;
use crate::trace::model::lifespan::Lifespan;
use crate::trace::seam_stubs::DBTraceObject;
use crate::util::database::spatial::bounded_shape::BoundedShape;

/// A trace value's shape: bounded by a [`ValueBox`] and addressable by parent/child/entry-key.
///
/// Port of `ghidra.trace.database.target.ValueShape`.
pub trait ValueShape<B: ValueBox>: BoundedShape<B> {
    /// Get the parent object of this value.
    ///
    /// Mirrors `ValueShape.getParent()`.
    fn get_parent(&self) -> Box<dyn DBTraceObject>;

    /// Get the child object of this value.
    ///
    /// Mirrors `ValueShape.getChild()`.
    fn get_child(&self) -> Box<dyn DBTraceObject>;

    /// Get the child object of this value, or `None` if this entry's value is not an object.
    ///
    /// Mirrors `ValueShape.getChildOrNull()`.
    fn get_child_or_null(&self) -> Option<Box<dyn DBTraceObject>>;

    /// Get the key identifying this value to its parent.
    ///
    /// Mirrors `ValueShape.getEntryKey()`.
    fn get_entry_key(&self) -> String;

    /// Get the lifespan of this value.
    ///
    /// Mirrors `ValueShape.getLifespan()`.
    fn get_lifespan(&self) -> Lifespan;

    /// If the value is an address or range, the id of the address space.
    ///
    /// Mirrors `ValueShape.getAddressSpaceId()`.
    ///
    /// Returns the space id, or -1 for a non-address value.
    fn get_address_space_id(&self) -> i32;

    /// Mirrors `ValueShape.getMinAddressOffset()`.
    fn get_min_address_offset(&self) -> i64;

    /// Mirrors `ValueShape.getMaxAddressOffset()`.
    fn get_max_address_offset(&self) -> i64;

    /// Resolves this value's minimum address in the given factory's address space, or `None` if
    /// this value is not an address or range.
    ///
    /// Mirrors `ValueShape.getMinAddress(AddressFactory)`.
    fn get_min_address(&self, factory: &dyn AddressFactory) -> Option<Address> {
        let space_id = self.get_address_space_id();
        if space_id == -1 {
            return None;
        }
        let space = factory.get_address_space_by_id(space_id)?;
        Some(space.address(self.get_min_address_offset()))
    }

    /// Resolves this value's maximum address in the given factory's address space, or `None` if
    /// this value is not an address or range.
    ///
    /// Mirrors `ValueShape.getMaxAddress(AddressFactory)`.
    fn get_max_address(&self, factory: &dyn AddressFactory) -> Option<Address> {
        let space_id = self.get_address_space_id();
        if space_id == -1 {
            return None;
        }
        let space = factory.get_address_space_by_id(space_id)?;
        Some(space.address(self.get_max_address_offset()))
    }

    /// Resolves this value's address range in the given factory's address space, or `None` if
    /// this value is not an address or range.
    ///
    /// Mirrors `ValueShape.getRange(AddressFactory)`.
    fn get_range(&self, factory: &dyn AddressFactory) -> Option<AddressRange> {
        let min = self.get_min_address(factory)?;
        let max = self.get_max_address(factory)?;
        Some(AddressRange::new(min, max))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, OnceLock};

    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType, DefaultAddressFactory};
    use crate::trace::database::target::rec_address::RecAddress;
    use crate::trace::database::target::value_triple::ValueTriple;
    use crate::util::database::spatial::hyper::{EuclideanHyperSpace, HyperBox};
    use crate::util::seam_stubs::Dimension;

    #[derive(Clone, Debug, PartialEq)]
    struct MockValueBox {
        lo: ValueTriple,
        hi: ValueTriple,
    }

    impl HyperBox<ValueTriple> for MockValueBox {
        fn space(&self) -> Arc<dyn EuclideanHyperSpace<ValueTriple, MockValueBox>> {
            value_space()
        }
        fn l_corner(&self) -> ValueTriple {
            self.lo.clone()
        }
        fn u_corner(&self) -> ValueTriple {
            self.hi.clone()
        }
        fn immutable(&self, l_corner: ValueTriple, u_corner: ValueTriple) -> Self {
            MockValueBox { lo: l_corner, hi: u_corner }
        }
    }

    impl ValueBox for MockValueBox {}

    struct SnapDim;
    impl Dimension<ValueTriple, MockValueBox> for SnapDim {
        fn lower_key(&self, box_: &MockValueBox) -> String {
            box_.lo.snap.to_string()
        }
        fn upper_key(&self, box_: &MockValueBox) -> String {
            box_.hi.snap.to_string()
        }
        fn contains(&self, box_: &MockValueBox, point: &ValueTriple) -> bool {
            point.snap >= box_.lo.snap && point.snap <= box_.hi.snap
        }
        fn measure(&self, box_: &MockValueBox) -> f64 {
            (box_.hi.snap - box_.lo.snap) as f64
        }
        fn measure_union(&self, a: &MockValueBox, b: &MockValueBox) -> f64 {
            (a.hi.snap.max(b.hi.snap) - a.lo.snap.min(b.lo.snap)) as f64
        }
        fn measure_intersection(&self, a: &MockValueBox, b: &MockValueBox) -> f64 {
            let lo = a.lo.snap.max(b.lo.snap);
            let hi = a.hi.snap.min(b.hi.snap);
            if lo > hi { 0.0 } else { (hi - lo) as f64 }
        }
        fn point_distance(&self, a: &ValueTriple, b: &ValueTriple) -> f64 {
            (a.snap - b.snap).unsigned_abs() as f64
        }
        fn encloses(&self, outer: &MockValueBox, inner: &MockValueBox) -> bool {
            outer.lo.snap <= inner.lo.snap && outer.hi.snap >= inner.hi.snap
        }
    }

    struct MockValueSpace {
        dims: Vec<Box<dyn Dimension<ValueTriple, MockValueBox>>>,
    }

    impl EuclideanHyperSpace<ValueTriple, MockValueBox> for MockValueSpace {
        fn dimensions(&self) -> &[Box<dyn Dimension<ValueTriple, MockValueBox>>] {
            &self.dims
        }
        fn full(&self) -> MockValueBox {
            triple_box(0, 0, i64::MIN, i64::MAX)
        }
        fn box_center(&self, box_: &MockValueBox) -> ValueTriple {
            let mut mid = box_.lo.clone();
            mid.snap = box_.lo.snap + (box_.hi.snap - box_.lo.snap) / 2;
            mid
        }
        fn box_union_bounds(&self, a: &MockValueBox, b: &MockValueBox) -> MockValueBox {
            let mut lo = a.lo.clone();
            lo.snap = a.lo.snap.min(b.lo.snap);
            let mut hi = a.hi.clone();
            hi.snap = a.hi.snap.max(b.hi.snap);
            MockValueBox { lo, hi }
        }
        fn box_intersection(&self, b: &MockValueBox, shape: &MockValueBox) -> MockValueBox {
            let mut lo = b.lo.clone();
            lo.snap = b.lo.snap.max(shape.lo.snap);
            let mut hi = b.hi.clone();
            hi.snap = b.hi.snap.min(shape.hi.snap);
            MockValueBox { lo, hi }
        }
    }

    fn value_space() -> Arc<MockValueSpace> {
        static SPACE: OnceLock<Arc<MockValueSpace>> = OnceLock::new();
        SPACE
            .get_or_init(|| Arc::new(MockValueSpace { dims: vec![Box::new(SnapDim)] }))
            .clone()
    }

    fn triple(parent: i64, child: i64, snap: i64) -> ValueTriple {
        ValueTriple::new(parent, child, "key", snap, RecAddress::new(0, 0))
    }

    fn triple_box(parent: i64, child: i64, lo_snap: i64, hi_snap: i64) -> MockValueBox {
        MockValueBox { lo: triple(parent, child, lo_snap), hi: triple(parent, child, hi_snap) }
    }

    struct MockObject(&'static str);

    /// `DBTraceObject` is a `TraceObject`; none of its members are exercised here -- the object
    /// is only ever passed around opaquely as a shape's child.
    impl crate::trace::seam_stubs::TraceObject for MockObject {
        fn get_schema(&self) -> Box<dyn crate::trace::seam_stubs::TraceObjectSchema> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_object_key(&self) -> Box<dyn crate::trace::seam_stubs::ObjectKey> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_life(&self) -> Box<dyn crate::trace::seam_stubs::LifeSet> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    impl DBTraceObject for MockObject {}



    struct MockValueShape {
        bounds: MockValueBox,
        has_child: bool,
        address_space_id: i32,
        min_offset: i64,
        max_offset: i64,
    }

    impl BoundedShape<MockValueBox> for MockValueShape {
        fn get_bounds(&self) -> MockValueBox {
            self.bounds.clone()
        }
        fn description(&self) -> String {
            "MockValueShape".to_string()
        }
    }

    impl ValueShape<MockValueBox> for MockValueShape {
        fn get_parent(&self) -> Box<dyn DBTraceObject> {
            Box::new(MockObject("parent"))
        }
        fn get_child(&self) -> Box<dyn DBTraceObject> {
            Box::new(MockObject("child"))
        }
        fn get_child_or_null(&self) -> Option<Box<dyn DBTraceObject>> {
            if self.has_child {
                Some(Box::new(MockObject("child")))
            } else {
                None
            }
        }
        fn get_entry_key(&self) -> String {
            "key1".to_string()
        }
        fn get_lifespan(&self) -> Lifespan {
            Lifespan::span(0, 10)
        }
        fn get_address_space_id(&self) -> i32 {
            self.address_space_id
        }
        fn get_min_address_offset(&self) -> i64 {
            self.min_offset
        }
        fn get_max_address_offset(&self) -> i64 {
            self.max_offset
        }
    }

    fn make_shape(address_space_id: i32) -> MockValueShape {
        MockValueShape {
            bounds: triple_box(1, 2, 5, 10),
            has_child: true,
            address_space_id,
            min_offset: 0x1000,
            max_offset: 0x2000,
        }
    }

    fn ram_factory() -> DefaultAddressFactory {
        let ram = AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0);
        DefaultAddressFactory::new(vec![ram])
    }

    #[test]
    fn get_bounds_delegates_to_bounded_shape() {
        let shape = make_shape(0);
        assert_eq!(shape.get_bounds(), shape.bounds);
    }

    #[test]
    fn get_child_or_null_reflects_presence() {
        let with_child = make_shape(0);
        assert!(with_child.get_child_or_null().is_some());

        let without_child = MockValueShape { has_child: false, ..make_shape(0) };
        assert!(without_child.get_child_or_null().is_none());
    }

    #[test]
    fn min_and_max_address_resolve_through_factory() {
        let factory = ram_factory();
        let space_id = factory.get_address_spaces()[0].space_id();
        let shape = make_shape(space_id);

        let min = shape.get_min_address(&factory).expect("min address");
        let max = shape.get_max_address(&factory).expect("max address");
        assert_eq!(min.offset(), 0x1000);
        assert_eq!(max.offset(), 0x2000);

        let range = shape.get_range(&factory).expect("range");
        assert_eq!(range.min_address(), &min);
        assert_eq!(range.max_address(), &max);
    }

    #[test]
    fn non_address_value_resolves_to_none() {
        let factory = ram_factory();
        let shape = make_shape(-1);
        assert!(shape.get_min_address(&factory).is_none());
        assert!(shape.get_max_address(&factory).is_none());
        assert!(shape.get_range(&factory).is_none());
    }

    #[test]
    fn trait_object_is_usable() {
        let shape: Box<dyn ValueShape<MockValueBox>> = Box::new(make_shape(0));
        assert_eq!(shape.get_entry_key(), "key1");
        assert_eq!(shape.get_lifespan().lmin(), 0);
        assert!(shape.get_child_or_null().is_some());
    }
}

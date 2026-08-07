use crate::trace::database::target::value_box::ValueBox;
use crate::trace::database::target::value_triple::ValueTriple;

/// The concrete, immutable [`ValueBox`] implementation, ported as a trait because it was
/// selected as a cycle cut-point: in the original Java, `ValueBox`'s `immutable`/`description`
/// defaults construct `new ImmutableValueBox(...)`, while `ImmutableValueBox`'s own secondary
/// constructor accepts a `ValueBox`, so the two Java types reference each other directly.
///
/// Java source: `ghidra.trace.database.target.ImmutableValueBox`, a record of `(lCorner,
/// uCorner)` implementing `ValueBox` directly. Its compact constructor asserts `lCorner.snap()
/// <= uCorner.snap()` before the implicit field assignment, and its secondary constructor copies
/// an existing `ValueBox`'s corners.
///
/// The [`ValueBox`] side of this cycle was already broken when that trait was ported: `immutable`
/// and `space` were left as required (rather than default) methods on `HyperBox`/`ValueBox`
/// instead of reproducing `new ImmutableValueBox(...)`/`ValueSpace.INSTANCE` verbatim (see the
/// module doc on [`ValueBox`]). This trait exists to carry `ImmutableValueBox`'s own construction
/// contract -- the half of the cycle that lived on this side -- without reaching back into
/// `ValueBox`'s defaults.
pub trait ImmutableValueBox: ValueBox {
    /// Constructs an instance from corners already known to satisfy `l_corner.snap <=
    /// u_corner.snap`, without re-checking the invariant. Mirrors the record's implicit field
    /// assignment, i.e. the part of the compact constructor after the `assert`.
    fn from_corners_unchecked(l_corner: ValueTriple, u_corner: ValueTriple) -> Self
    where
        Self: Sized;

    /// Constructs a new instance from explicit corners, mirroring the record's canonical
    /// constructor (its compact constructor's `assert lCorner.snap() <= uCorner.snap()` followed
    /// by field assignment).
    fn new(l_corner: ValueTriple, u_corner: ValueTriple) -> Self
    where
        Self: Sized,
    {
        debug_assert!(
            l_corner.snap <= u_corner.snap,
            "lCorner.snap() <= uCorner.snap()"
        );
        Self::from_corners_unchecked(l_corner, u_corner)
    }

    /// Constructs a new instance by copying another `ValueBox`'s corners, mirroring
    /// `ImmutableValueBox(ValueBox box)`.
    fn from_value_box<B: ValueBox>(box_: &B) -> Self
    where
        Self: Sized,
    {
        Self::new(box_.l_corner(), box_.u_corner())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, OnceLock};

    use super::*;
    use crate::trace::database::target::rec_address::RecAddress;
    use crate::util::database::spatial::hyper::{EuclideanHyperSpace, HyperBox};
    use crate::util::seam_stubs::Dimension;

    #[derive(Clone, Debug, PartialEq)]
    struct MockImmutableValueBox {
        lo: ValueTriple,
        hi: ValueTriple,
    }

    impl HyperBox<ValueTriple> for MockImmutableValueBox {
        fn space(&self) -> Arc<dyn EuclideanHyperSpace<ValueTriple, MockImmutableValueBox>> {
            value_space()
        }
        fn l_corner(&self) -> ValueTriple {
            self.lo.clone()
        }
        fn u_corner(&self) -> ValueTriple {
            self.hi.clone()
        }
        fn immutable(&self, l_corner: ValueTriple, u_corner: ValueTriple) -> Self {
            <Self as ImmutableValueBox>::new(l_corner, u_corner)
        }
    }

    impl ValueBox for MockImmutableValueBox {}

    impl ImmutableValueBox for MockImmutableValueBox {
        fn from_corners_unchecked(l_corner: ValueTriple, u_corner: ValueTriple) -> Self {
            MockImmutableValueBox { lo: l_corner, hi: u_corner }
        }
    }

    struct SnapDim;
    impl Dimension<ValueTriple, MockImmutableValueBox> for SnapDim {
        fn lower_key(&self, box_: &MockImmutableValueBox) -> String {
            box_.lo.snap.to_string()
        }
        fn upper_key(&self, box_: &MockImmutableValueBox) -> String {
            box_.hi.snap.to_string()
        }
        fn contains(&self, box_: &MockImmutableValueBox, point: &ValueTriple) -> bool {
            point.snap >= box_.lo.snap && point.snap <= box_.hi.snap
        }
        fn measure(&self, box_: &MockImmutableValueBox) -> f64 {
            (box_.hi.snap - box_.lo.snap) as f64
        }
        fn measure_union(&self, a: &MockImmutableValueBox, b: &MockImmutableValueBox) -> f64 {
            (a.hi.snap.max(b.hi.snap) - a.lo.snap.min(b.lo.snap)) as f64
        }
        fn measure_intersection(
            &self,
            a: &MockImmutableValueBox,
            b: &MockImmutableValueBox,
        ) -> f64 {
            let lo = a.lo.snap.max(b.lo.snap);
            let hi = a.hi.snap.min(b.hi.snap);
            if lo > hi { 0.0 } else { (hi - lo) as f64 }
        }
        fn point_distance(&self, a: &ValueTriple, b: &ValueTriple) -> f64 {
            (a.snap - b.snap).unsigned_abs() as f64
        }
        fn encloses(&self, outer: &MockImmutableValueBox, inner: &MockImmutableValueBox) -> bool {
            outer.lo.snap <= inner.lo.snap && outer.hi.snap >= inner.hi.snap
        }
    }

    struct MockValueSpace {
        dims: Vec<Box<dyn Dimension<ValueTriple, MockImmutableValueBox>>>,
    }

    impl EuclideanHyperSpace<ValueTriple, MockImmutableValueBox> for MockValueSpace {
        fn dimensions(&self) -> &[Box<dyn Dimension<ValueTriple, MockImmutableValueBox>>] {
            &self.dims
        }
        fn full(&self) -> MockImmutableValueBox {
            triple_box(0, 0, i64::MIN, i64::MAX)
        }
        fn box_center(&self, box_: &MockImmutableValueBox) -> ValueTriple {
            let mut mid = box_.lo.clone();
            mid.snap = box_.lo.snap + (box_.hi.snap - box_.lo.snap) / 2;
            mid
        }
        fn box_union_bounds(
            &self,
            a: &MockImmutableValueBox,
            b: &MockImmutableValueBox,
        ) -> MockImmutableValueBox {
            let mut lo = a.lo.clone();
            lo.snap = a.lo.snap.min(b.lo.snap);
            let mut hi = a.hi.clone();
            hi.snap = a.hi.snap.max(b.hi.snap);
            MockImmutableValueBox { lo, hi }
        }
        fn box_intersection(
            &self,
            b: &MockImmutableValueBox,
            shape: &MockImmutableValueBox,
        ) -> MockImmutableValueBox {
            let mut lo = b.lo.clone();
            lo.snap = b.lo.snap.max(shape.lo.snap);
            let mut hi = b.hi.clone();
            hi.snap = b.hi.snap.min(shape.hi.snap);
            MockImmutableValueBox { lo, hi }
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

    fn triple_box(parent: i64, child: i64, lo_snap: i64, hi_snap: i64) -> MockImmutableValueBox {
        MockImmutableValueBox {
            lo: triple(parent, child, lo_snap),
            hi: triple(parent, child, hi_snap),
        }
    }

    #[test]
    fn new_stores_corners_in_order() {
        let lo = triple(1, 2, 5);
        let hi = triple(1, 2, 10);
        let b = MockImmutableValueBox::new(lo.clone(), hi.clone());
        assert_eq!(b.l_corner(), lo);
        assert_eq!(b.u_corner(), hi);
    }

    #[test]
    fn from_value_box_copies_corners() {
        let src = triple_box(1, 2, 5, 10);
        let copy = MockImmutableValueBox::from_value_box(&src);
        assert_eq!(copy, src);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic]
    fn new_panics_when_l_corner_snap_exceeds_u_corner_snap() {
        MockImmutableValueBox::new(triple(1, 2, 10), triple(1, 2, 5));
    }

    #[test]
    fn value_box_default_immutable_delegates_to_new() {
        // Exercises the other half of the cycle: `ValueBox::get_bounds`'s default calls
        // `self.immutable(...)`, which this mock routes through `ImmutableValueBox::new`.
        let b = triple_box(1, 2, 5, 10);
        let bounds = b.get_bounds();
        assert_eq!(bounds, b);
    }

    #[test]
    fn generic_usable_across_value_box_implementors() {
        // Proves ImmutableValueBox::from_value_box works for any ValueBox implementor, not just
        // Self, matching the Java constructor's `ValueBox` parameter type.
        fn copy_of<T: ImmutableValueBox>(src: &impl ValueBox) -> T {
            T::from_value_box(src)
        }
        let src = triple_box(3, 4, 1, 2);
        let copy: MockImmutableValueBox = copy_of(&src);
        assert_eq!(copy, src);
    }
}

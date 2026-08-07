use crate::trace::database::target::value_triple::ValueTriple;
use crate::util::database::spatial::hyper::HyperBox;

/// A box (axis-aligned range) over [`ValueTriple`] corners in a trace's value space.
///
/// Corresponds to `ghidra.trace.database.target.ValueBox`.
///
/// The Java interface is `ValueBox extends HyperBox<ValueTriple, ValueBox>`, closing the
/// F-bound of `HyperBox` at itself. In Rust this becomes a marker trait over the already-ported
/// [`HyperBox<ValueTriple>`]: `immutable` and `space` are required (non-default) methods on
/// `HyperBox` in this port, so the two identical Java defaults that construct
/// `new ImmutableValueBox(...)` / return `ValueSpace.INSTANCE` regardless of the implementor have
/// no single Self-agnostic Rust translation, and are left to each implementor -- mirroring the
/// same collapse-to-`Self` workaround `HyperBox` itself documents. The two Java overrides that
/// *are* expressible generically in terms of already-required `HyperBox` methods --
/// `getBounds()` (a box is its own bounds) and `description()` (the record-style `toString()` of
/// its corners) -- are ported below as default methods.
pub trait ValueBox: HyperBox<ValueTriple> {
    /// Returns this box's own bounds, mirroring `ValueBox.getBounds()`.
    fn get_bounds(&self) -> Self {
        self.immutable(self.l_corner(), self.u_corner())
    }

    /// Returns a human-readable description of this box, mirroring `ValueBox.description()`,
    /// which formats `new ImmutableValueBox(this)` via its record-generated `toString()`
    /// (`ImmutableValueBox[lCorner=..., uCorner=...]`).
    fn description(&self) -> String {
        format!(
            "ImmutableValueBox[lCorner={:?}, uCorner={:?}]",
            self.l_corner(),
            self.u_corner()
        )
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, OnceLock};

    use super::*;
    use crate::trace::database::target::rec_address::RecAddress;
    use crate::util::database::spatial::hyper::EuclideanHyperSpace;
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

    /// Shared singleton space, mirroring `ValueSpace.INSTANCE` without needing a
    /// self-referential `MockValueBox`.
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

    #[test]
    fn get_bounds_is_self_with_same_corners() {
        let b = triple_box(1, 2, 5, 10);
        let bounds = b.get_bounds();
        assert_eq!(bounds.l_corner().snap, 5);
        assert_eq!(bounds.u_corner().snap, 10);
        assert_eq!(bounds, b);
    }

    #[test]
    fn description_formats_corners() {
        let b = triple_box(1, 2, 5, 10);
        let desc = b.description();
        assert!(desc.starts_with("ImmutableValueBox[lCorner="));
        assert!(desc.contains("snap: 5"));
        assert!(desc.contains("snap: 10"));
    }

    #[test]
    fn contains_and_intersection_use_hyper_box_defaults() {
        let outer = triple_box(1, 2, 0, 20);
        let inner = triple_box(1, 2, 5, 10);
        assert!(outer.contains(&triple(1, 2, 8)));
        assert!(outer.encloses(&inner));
        let intersection = outer.intersection(&inner);
        assert_eq!(intersection.l_corner().snap, 5);
        assert_eq!(intersection.u_corner().snap, 10);
    }

    #[test]
    fn object_safety_of_space_dependency() {
        let b = triple_box(1, 2, 0, 4);
        let space: Arc<dyn EuclideanHyperSpace<ValueTriple, MockValueBox>> = b.space();
        assert_eq!(space.box_area(&b), 5.0);
    }
}

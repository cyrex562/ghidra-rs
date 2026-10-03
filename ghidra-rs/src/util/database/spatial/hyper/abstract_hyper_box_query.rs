//! Shared state and logic for a hyper-box range query (intersecting/enclosing/enclosed/equal-to).
//!
//! Java source: `ghidra.util.database.spatial.hyper.AbstractHyperBoxQuery<P, DS, NS, Q>`.
//!
//! # Shape
//!
//! The Java class is `public abstract class AbstractHyperBoxQuery<P, DS, NS, Q extends
//! AbstractHyperBoxQuery<P, DS, NS, Q>> implements Query<DS, NS>`: an F-bounded abstract base that
//! concrete query classes (in Ghidra, e.g. per-index `*Query` types, none yet ported) extend,
//! providing only `protected abstract Q create(NS, NS, HyperDirection)`.
//!
//! Per this crate's composition-over-inheritance convention, this becomes a plain struct,
//! [`HyperBoxQueryBase`], holding the four fields (`ls`, `us`, `space`, `direction`) plus every
//! method that does *not* require knowing the concrete subclass `Q`. A concrete query type
//! embeds a `base: HyperBoxQueryBase<P, NS>` field and implements [`Query`] by delegating
//! `terminate_early_data`/`terminate_early_node`/`test_node`/`get_bounds_comparator` to it --
//! Java overrides exactly those four `Query` methods here and leaves `test_data` abstract for the
//! subclass, so [`HyperBoxQueryBase`] likewise has no `test_data` of its own.
//!
//! The four `protected static` factory methods (`intersecting`/`enclosing`/`enclosed`/`equalTo`)
//! and the `create(NS, NS, HyperDirection)` abstract method they call become free functions here,
//! taking the "create" step as a closure parameter (mirroring Java's `QueryFactory<NS, Q>`
//! functional interface) instead of relying on a virtual dispatch back to `this.create(...)` that
//! Rust has no way to express without already knowing `Q`.
//!
//! # Comparator caching, not reproduced
//!
//! Java memoizes `getBoundsComparator()`'s result in a `comparator` field, recomputed once and
//! reused thereafter. That is a pure performance optimization with no observable effect (the
//! comparator's *behavior* is identical whether freshly built or cached), and caching a `Box<dyn
//! Fn>` behind a `&self` method here would need interior mutability with no compensating benefit,
//! so [`HyperBoxQueryBase::get_bounds_comparator`] simply rebuilds it on every call.
//!
//! # Type-erased dimension comparisons
//!
//! `terminateEarlyNode`/`testNode` fetch a single `Dimension<?, P, NS>` from
//! `space.getDimensions()` and compare arbitrary combinations of its two operands' lower/upper
//! bounds. `EuclideanHyperSpace::dimensions()` in this port holds the type-erased
//! [`crate::util::seam_stubs::Dimension`] placeholder (see that trait's docs for why), which
//! did not previously expose any bound-comparison operation; this port grows it with
//! `compare_lower`/`compare_upper`/`compare_lower_to_upper`/`compare_upper_to_lower`, the four
//! combinations these methods need, in the same string/`f64`-erased spirit as its existing
//! members.

use std::cmp::Ordering;
use std::sync::Arc;

use super::{EuclideanHyperSpace, HyperBox, HyperDirection, HyperPoint};
use crate::util::database::spatial::bounded_shape::BoundedShape;
use crate::util::database::spatial::query::QueryInclusion;
use crate::util::seam_stubs::Dimension;

/// The shared state and non-`create`-dependent logic of a hyper-box range query.
///
/// Port of `ghidra.util.database.spatial.hyper.AbstractHyperBoxQuery`. See the module docs for
/// why this is a plain struct rather than a trait/abstract-class hierarchy.
pub struct HyperBoxQueryBase<P: HyperPoint, NS: HyperBox<P>> {
    /// The "lower" query box: mirrors the protected `ls` field.
    pub ls: NS,
    /// The "upper" query box: mirrors the protected `us` field.
    pub us: NS,
    /// The coordinate space `ls`/`us` live in: mirrors the protected `space` field.
    pub space: Arc<dyn EuclideanHyperSpace<P, NS>>,
    /// The traversal direction, or `None` for Java's `null` (resolved to a default by
    /// [`Self::get_direction`]). Mirrors the protected `direction` field, which Java allows to be
    /// `null` (see [`Self::get_direction`]'s doc for where that shows up).
    pub direction: Option<HyperDirection>,
}

impl<P: HyperPoint, NS: HyperBox<P>> HyperBoxQueryBase<P, NS> {
    /// Constructs a new query base. Mirrors
    /// `AbstractHyperBoxQuery(NS, NS, EuclideanHyperSpace, HyperDirection)`.
    pub fn new(
        ls: NS,
        us: NS,
        space: Arc<dyn EuclideanHyperSpace<P, NS>>,
        direction: Option<HyperDirection>,
    ) -> Self {
        Self { ls, us, space, direction }
    }

    /// Mirrors `terminateEarlyData(DS)`: delegates to [`Self::terminate_early_node`] on the data
    /// shape's own bounds.
    pub fn terminate_early_data<DS: BoundedShape<NS>>(&self, shape: &DS) -> bool {
        self.terminate_early_node(&shape.get_bounds())
    }

    /// Mirrors the private `dimTerminateEarlyNode(Dimension, NS)`.
    fn dim_terminate_early_node(&self, dim: &dyn Dimension<P, NS>, shape: &NS) -> bool {
        if self.get_direction().forward {
            dim.compare_lower_to_upper(shape, &self.us) == Ordering::Greater
        } else {
            dim.compare_upper_to_lower(shape, &self.ls) == Ordering::Less
        }
    }

    /// Mirrors `terminateEarlyNode(NS)`.
    pub fn terminate_early_node(&self, shape: &NS) -> bool {
        let direction = self.get_direction();
        let dim = &self.space.dimensions()[direction.dimension as usize];
        self.dim_terminate_early_node(dim.as_ref(), shape)
    }

    /// Mirrors `getBoundsComparator()`, minus the memoization (see the module docs).
    pub fn get_bounds_comparator(&self) -> Box<dyn Fn(&NS, &NS) -> Ordering>
    where
        P: 'static,
        NS: 'static,
    {
        let direction = self.get_direction();
        let dim_index = direction.dimension as usize;
        let space = Arc::clone(&self.space);
        if direction.forward {
            Box::new(move |a: &NS, b: &NS| space.dimensions()[dim_index].compare_lower(a, b))
        } else {
            // Mirrors `Comparator.comparing(dim::upper, (a, b) -> dim.compare(b, a))`: order by
            // upper bound, reversed.
            Box::new(move |a: &NS, b: &NS| space.dimensions()[dim_index].compare_upper(b, a))
        }
    }

    /// Mirrors the private `isNone(Dimension, NS)`.
    fn is_none(&self, dim: &dyn Dimension<P, NS>, shape: &NS) -> bool {
        if dim.compare_lower_to_upper(shape, &self.ls) == Ordering::Greater {
            return true;
        }
        if dim.compare_lower_to_upper(shape, &self.us) == Ordering::Greater {
            return true;
        }
        if dim.compare_upper_to_lower(shape, &self.us) == Ordering::Less {
            return true;
        }
        if dim.compare_upper_to_lower(shape, &self.ls) == Ordering::Less {
            return true;
        }
        false
    }

    /// Mirrors the private `isSome(Dimension, NS)`.
    fn is_some(&self, dim: &dyn Dimension<P, NS>, shape: &NS) -> bool {
        if dim.compare_lower(shape, &self.ls) == Ordering::Less {
            return true;
        }
        if dim.compare_lower(shape, &self.us) == Ordering::Less {
            return true;
        }
        if dim.compare_upper(shape, &self.us) == Ordering::Greater {
            return true;
        }
        if dim.compare_upper(shape, &self.ls) == Ordering::Greater {
            return true;
        }
        false
    }

    /// Mirrors `testNode(NS)`.
    pub fn test_node(&self, shape: &NS) -> QueryInclusion {
        for dim in self.space.dimensions() {
            if self.is_none(dim.as_ref(), shape) {
                return QueryInclusion::None;
            }
        }
        for dim in self.space.dimensions() {
            if self.is_some(dim.as_ref(), shape) {
                return QueryInclusion::Some;
            }
        }
        QueryInclusion::All
    }

    /// Mirrors `getDirection()`: the query's traversal direction, defaulting to dimension 0,
    /// forward, when [`Self::direction`] is `None` (Java: `null`).
    pub fn get_direction(&self) -> HyperDirection {
        self.direction.unwrap_or(HyperDirection::DEFAULT)
    }

    /// Mirrors `and(Q)`: the query whose range is the intersection of this query's and `other`'s,
    /// in whichever direction `other` specifies, falling back to this query's own direction if
    /// `other`'s is unset. `factory` stands in for `create(NS, NS, HyperDirection)`.
    pub fn and<Q>(
        &self,
        other: &HyperBoxQueryBase<P, NS>,
        factory: impl FnOnce(NS, NS, Option<HyperDirection>) -> Q,
    ) -> Q {
        let ir1 = self.ls.intersection(&other.ls);
        let ir2 = self.us.intersection(&other.us);
        factory(ir1, ir2, other.direction.or(self.direction))
    }

    /// Mirrors `starting(HyperDirection)`: the same query range, restarted in `new_direction`.
    /// `factory` stands in for `create(NS, NS, HyperDirection)`.
    pub fn starting<Q>(
        &self,
        new_direction: HyperDirection,
        factory: impl FnOnce(NS, NS, Option<HyperDirection>) -> Q,
    ) -> Q
    where
        NS: Clone,
    {
        factory(self.ls.clone(), self.us.clone(), Some(new_direction))
    }
}

/// Builds the `(ls, us)` range for a query selecting every shape *intersecting* `shape`.
///
/// Mirrors the protected static `intersecting(NS, HyperDirection, QueryFactory)`. `factory`
/// stands in for Java's `QueryFactory<NS, Q>` functional interface.
pub fn intersecting<P, NS, Q>(
    shape: &NS,
    direction: Option<HyperDirection>,
    factory: impl FnOnce(NS, NS, Option<HyperDirection>) -> Q,
) -> Q
where
    P: HyperPoint,
    NS: HyperBox<P>,
{
    let full = shape.space().full();
    let ls = shape.immutable(full.l_corner(), shape.u_corner());
    let us = shape.immutable(shape.l_corner(), full.u_corner());
    factory(ls, us, direction)
}

/// Builds the `(ls, us)` range for a query selecting every shape *enclosing* `shape`.
///
/// Mirrors the protected static `enclosing(NS, HyperDirection, QueryFactory)`.
pub fn enclosing<P, NS, Q>(
    shape: &NS,
    direction: Option<HyperDirection>,
    factory: impl FnOnce(NS, NS, Option<HyperDirection>) -> Q,
) -> Q
where
    P: HyperPoint,
    NS: HyperBox<P>,
{
    let full = shape.space().full();
    let ls = shape.immutable(full.l_corner(), shape.l_corner());
    let us = shape.immutable(shape.u_corner(), full.u_corner());
    factory(ls, us, direction)
}

/// Builds the `(ls, us)` range for a query selecting every shape *enclosed by* `shape`.
///
/// Mirrors the protected static `enclosed(NS, HyperDirection, QueryFactory)`.
pub fn enclosed<P, NS, Q>(
    shape: &NS,
    direction: Option<HyperDirection>,
    factory: impl FnOnce(NS, NS, Option<HyperDirection>) -> Q,
) -> Q
where
    P: HyperPoint,
    NS: HyperBox<P>,
{
    let full = shape.space().full();
    let ls = shape.immutable(shape.l_corner(), full.u_corner());
    let us = shape.immutable(full.l_corner(), shape.u_corner());
    factory(ls, us, direction)
}

/// Builds the `(ls, us)` range for a query selecting only shapes *equal to* `shape`.
///
/// Mirrors the protected static `equalTo(NS, HyperDirection, QueryFactory)`.
pub fn equal_to<P, NS, Q>(
    shape: &NS,
    direction: Option<HyperDirection>,
    factory: impl FnOnce(NS, NS, Option<HyperDirection>) -> Q,
) -> Q
where
    P: HyperPoint,
    NS: HyperBox<P>,
{
    let ls = shape.immutable(shape.l_corner(), shape.l_corner());
    let us = shape.immutable(shape.u_corner(), shape.u_corner());
    factory(ls, us, direction)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::database::spatial::query::Query;
    use std::sync::OnceLock;

    // --- A one-dimensional `f64` box space, mirroring the mocks used by sibling test modules in
    // this package (`hyper_box.rs`, `euclidean_hyper_space.rs`, `dimension.rs`). ---

    #[derive(Clone, Copy, Debug, PartialEq)]
    struct MockPoint(f64);
    impl HyperPoint for MockPoint {}

    #[derive(Clone, Copy, Debug, PartialEq)]
    struct MockBox {
        lo: f64,
        hi: f64,
    }

    impl HyperBox<MockPoint> for MockBox {
        fn space(&self) -> Arc<dyn EuclideanHyperSpace<MockPoint, MockBox>> {
            line1d()
        }
        fn l_corner(&self) -> MockPoint {
            MockPoint(self.lo)
        }
        fn u_corner(&self) -> MockPoint {
            MockPoint(self.hi)
        }
        fn immutable(&self, l_corner: MockPoint, u_corner: MockPoint) -> Self {
            MockBox { lo: l_corner.0, hi: u_corner.0 }
        }
    }

    impl BoundedShape<MockBox> for MockBox {
        fn get_bounds(&self) -> MockBox {
            *self
        }
        fn description(&self) -> String {
            format!("MockBox[{}, {}]", self.lo, self.hi)
        }
    }

    struct AxisDim;
    impl Dimension<MockPoint, MockBox> for AxisDim {
        fn lower_key(&self, box_: &MockBox) -> String {
            box_.lo.to_string()
        }
        fn upper_key(&self, box_: &MockBox) -> String {
            box_.hi.to_string()
        }
        fn contains(&self, box_: &MockBox, point: &MockPoint) -> bool {
            point.0 >= box_.lo && point.0 <= box_.hi
        }
        fn measure(&self, box_: &MockBox) -> f64 {
            box_.hi - box_.lo
        }
        fn measure_union(&self, a: &MockBox, b: &MockBox) -> f64 {
            a.hi.max(b.hi) - a.lo.min(b.lo)
        }
        fn measure_intersection(&self, a: &MockBox, b: &MockBox) -> f64 {
            let lo = a.lo.max(b.lo);
            let hi = a.hi.min(b.hi);
            if lo > hi { 0.0 } else { hi - lo }
        }
        fn point_distance(&self, a: &MockPoint, b: &MockPoint) -> f64 {
            (a.0 - b.0).abs()
        }
        fn encloses(&self, outer: &MockBox, inner: &MockBox) -> bool {
            outer.lo <= inner.lo && outer.hi >= inner.hi
        }
        fn compare_lower(&self, a: &MockBox, b: &MockBox) -> Ordering {
            a.lo.partial_cmp(&b.lo).unwrap()
        }
        fn compare_upper(&self, a: &MockBox, b: &MockBox) -> Ordering {
            a.hi.partial_cmp(&b.hi).unwrap()
        }
        fn compare_lower_to_upper(&self, a: &MockBox, b: &MockBox) -> Ordering {
            a.lo.partial_cmp(&b.hi).unwrap()
        }
        fn compare_upper_to_lower(&self, a: &MockBox, b: &MockBox) -> Ordering {
            a.hi.partial_cmp(&b.lo).unwrap()
        }
    }

    struct Line1D {
        dims: Vec<Box<dyn Dimension<MockPoint, MockBox>>>,
    }

    impl EuclideanHyperSpace<MockPoint, MockBox> for Line1D {
        fn dimensions(&self) -> &[Box<dyn Dimension<MockPoint, MockBox>>] {
            &self.dims
        }
        fn full(&self) -> MockBox {
            MockBox { lo: f64::MIN, hi: f64::MAX }
        }
        fn box_center(&self, box_: &MockBox) -> MockPoint {
            MockPoint((box_.lo + box_.hi) / 2.0)
        }
        fn box_union_bounds(&self, a: &MockBox, b: &MockBox) -> MockBox {
            MockBox { lo: a.lo.min(b.lo), hi: a.hi.max(b.hi) }
        }
        fn box_intersection(&self, b: &MockBox, shape: &MockBox) -> MockBox {
            MockBox { lo: b.lo.max(shape.lo), hi: b.hi.min(shape.hi) }
        }
    }

    fn line1d() -> Arc<Line1D> {
        static SPACE: OnceLock<Arc<Line1D>> = OnceLock::new();
        SPACE.get_or_init(|| Arc::new(Line1D { dims: vec![Box::new(AxisDim)] })).clone()
    }

    /// A minimal concrete `Query` wrapping [`HyperBoxQueryBase`], the way a real per-index
    /// `*Query` subclass would in Java.
    struct TestQuery {
        base: HyperBoxQueryBase<MockPoint, MockBox>,
    }

    impl TestQuery {
        fn new(
            ls: MockBox,
            us: MockBox,
            direction: Option<HyperDirection>,
        ) -> TestQuery {
            TestQuery { base: HyperBoxQueryBase::new(ls, us, line1d(), direction) }
        }
    }

    impl Query<MockBox, MockBox> for TestQuery {
        fn terminate_early_data(&self, shape: &MockBox) -> bool {
            self.base.terminate_early_data(shape)
        }
        fn test_data(&self, shape: &MockBox) -> bool {
            // A reasonable stand-in for a concrete subclass's own `testData`: included exactly
            // when `test_node` would call it `All` or `Some`.
            self.base.test_node(shape) != QueryInclusion::None
        }
        fn terminate_early_node(&self, shape: &MockBox) -> bool {
            self.base.terminate_early_node(shape)
        }
        fn test_node(&self, shape: &MockBox) -> QueryInclusion {
            self.base.test_node(shape)
        }
        fn get_bounds_comparator(&self) -> Option<Box<dyn Fn(&MockBox, &MockBox) -> Ordering>> {
            Some(self.base.get_bounds_comparator())
        }
    }

    fn factory(ls: MockBox, us: MockBox, direction: Option<HyperDirection>) -> TestQuery {
        TestQuery::new(ls, us, direction)
    }

    #[test]
    fn intersecting_builds_a_half_open_range_on_each_side() {
        let shape = MockBox { lo: 3.0, hi: 7.0 };
        let q = intersecting(&shape, None, factory);
        // ls: [-inf, shape.hi]; us: [shape.lo, +inf].
        assert_eq!(q.base.ls, MockBox { lo: f64::MIN, hi: 7.0 });
        assert_eq!(q.base.us, MockBox { lo: 3.0, hi: f64::MAX });
    }

    #[test]
    fn enclosing_builds_a_range_of_supersets() {
        let shape = MockBox { lo: 3.0, hi: 7.0 };
        let q = enclosing(&shape, None, factory);
        assert_eq!(q.base.ls, MockBox { lo: f64::MIN, hi: 3.0 });
        assert_eq!(q.base.us, MockBox { lo: 7.0, hi: f64::MAX });
    }

    #[test]
    fn enclosed_builds_a_range_of_subsets() {
        let shape = MockBox { lo: 3.0, hi: 7.0 };
        let q = enclosed(&shape, None, factory);
        assert_eq!(q.base.ls, MockBox { lo: 3.0, hi: f64::MAX });
        assert_eq!(q.base.us, MockBox { lo: f64::MIN, hi: 7.0 });
    }

    #[test]
    fn equal_to_builds_a_degenerate_range_matching_only_the_shape_itself() {
        let shape = MockBox { lo: 3.0, hi: 7.0 };
        let q = equal_to(&shape, None, factory);
        assert_eq!(q.base.ls, MockBox { lo: 3.0, hi: 3.0 });
        assert_eq!(q.base.us, MockBox { lo: 7.0, hi: 7.0 });
    }

    #[test]
    fn get_direction_defaults_to_dimension_zero_forward_when_unset() {
        let q = TestQuery::new(MockBox { lo: 0.0, hi: 0.0 }, MockBox { lo: 10.0, hi: 10.0 }, None);
        assert_eq!(q.base.get_direction(), HyperDirection::new(0, true));
    }

    #[test]
    fn get_direction_returns_the_explicit_value_when_set() {
        let direction = HyperDirection::new(0, false);
        let q = TestQuery::new(
            MockBox { lo: 0.0, hi: 0.0 },
            MockBox { lo: 10.0, hi: 10.0 },
            Some(direction),
        );
        assert_eq!(q.base.get_direction(), direction);
    }

    #[test]
    fn test_node_is_all_when_shape_is_within_the_intersecting_range() {
        // Query range for "intersecting [3, 7]": ls = [-inf, 7], us = [3, +inf].
        let q = intersecting(&MockBox { lo: 3.0, hi: 7.0 }, None, factory);
        // A shape fully inside [3, 7] certainly intersects it (and every wider range too), so
        // every candidate box the tree could show at this node is included.
        assert_eq!(q.base.test_node(&MockBox { lo: 4.0, hi: 5.0 }), QueryInclusion::All);
    }

    #[test]
    fn test_node_is_none_when_shape_cannot_intersect() {
        let q = intersecting(&MockBox { lo: 3.0, hi: 7.0 }, None, factory);
        // Entirely to the right of the query range: no possible overlap.
        assert_eq!(q.base.test_node(&MockBox { lo: 100.0, hi: 200.0 }), QueryInclusion::None);
    }

    #[test]
    fn test_node_is_some_when_only_partially_overlapping_the_range() {
        let q = intersecting(&MockBox { lo: 3.0, hi: 7.0 }, None, factory);
        // Straddles the query range's edge: some but not all sub-shapes here would intersect.
        assert_eq!(q.base.test_node(&MockBox { lo: -50.0, hi: 4.0 }), QueryInclusion::Some);
    }

    #[test]
    fn terminate_early_node_stops_once_past_the_forward_bound() {
        let q = intersecting(&MockBox { lo: 3.0, hi: 7.0 }, Some(HyperDirection::new(0, true)), factory);
        // us = [3, +inf]; a shape whose lower bound exceeds us's upper bound (+inf) never
        // happens for finite values, so use enclosing (us.hi = +inf is unreachable) via a
        // narrower, explicit us instead: construct directly.
        let narrow = TestQuery::new(
            MockBox { lo: f64::MIN, hi: 10.0 },
            MockBox { lo: 0.0, hi: 5.0 },
            Some(HyperDirection::new(0, true)),
        );
        assert!(!narrow.base.terminate_early_node(&MockBox { lo: 4.0, hi: 6.0 }));
        assert!(narrow.base.terminate_early_node(&MockBox { lo: 6.0, hi: 8.0 }));
    }

    #[test]
    fn terminate_early_node_stops_once_past_the_backward_bound() {
        let narrow = TestQuery::new(
            MockBox { lo: 0.0, hi: 5.0 },
            MockBox { lo: f64::MIN, hi: 10.0 },
            Some(HyperDirection::new(0, false)),
        );
        assert!(!narrow.base.terminate_early_node(&MockBox { lo: 2.0, hi: 4.0 }));
        assert!(narrow.base.terminate_early_node(&MockBox { lo: -5.0, hi: -1.0 }));
    }

    #[test]
    fn get_bounds_comparator_orders_by_lower_bound_when_forward() {
        let q = TestQuery::new(
            MockBox { lo: 0.0, hi: 0.0 },
            MockBox { lo: 0.0, hi: 0.0 },
            Some(HyperDirection::new(0, true)),
        );
        let cmp = q.base.get_bounds_comparator();
        let a = MockBox { lo: 1.0, hi: 5.0 };
        let b = MockBox { lo: 3.0, hi: 4.0 };
        assert_eq!(cmp(&a, &b), Ordering::Less);
        assert_eq!(cmp(&b, &a), Ordering::Greater);
    }

    #[test]
    fn get_bounds_comparator_orders_by_upper_bound_descending_when_backward() {
        let q = TestQuery::new(
            MockBox { lo: 0.0, hi: 0.0 },
            MockBox { lo: 0.0, hi: 0.0 },
            Some(HyperDirection::new(0, false)),
        );
        let cmp = q.base.get_bounds_comparator();
        let a = MockBox { lo: 0.0, hi: 5.0 };
        let b = MockBox { lo: 0.0, hi: 9.0 };
        // Backward: ordered by upper bound, descending, so the *larger* upper bound sorts first.
        assert_eq!(cmp(&a, &b), Ordering::Greater);
        assert_eq!(cmp(&b, &a), Ordering::Less);
    }

    #[test]
    fn and_intersects_two_query_ranges_and_prefers_the_others_direction() {
        let q1 = TestQuery::new(
            MockBox { lo: 0.0, hi: 10.0 },
            MockBox { lo: 20.0, hi: 30.0 },
            Some(HyperDirection::new(0, true)),
        );
        let q2 = TestQuery::new(
            MockBox { lo: 5.0, hi: 15.0 },
            MockBox { lo: 18.0, hi: 25.0 },
            Some(HyperDirection::new(0, false)),
        );
        let combined = q1.base.and(&q2.base, factory);
        assert_eq!(combined.base.ls, MockBox { lo: 5.0, hi: 10.0 });
        assert_eq!(combined.base.us, MockBox { lo: 20.0, hi: 25.0 });
        assert_eq!(combined.base.direction, Some(HyperDirection::new(0, false)));
    }

    #[test]
    fn and_falls_back_to_this_direction_when_others_is_unset() {
        let q1 = TestQuery::new(
            MockBox { lo: 0.0, hi: 10.0 },
            MockBox { lo: 20.0, hi: 30.0 },
            Some(HyperDirection::new(0, true)),
        );
        let q2 = TestQuery::new(MockBox { lo: 0.0, hi: 10.0 }, MockBox { lo: 20.0, hi: 30.0 }, None);
        let combined = q1.base.and(&q2.base, factory);
        assert_eq!(combined.base.direction, Some(HyperDirection::new(0, true)));
    }

    #[test]
    fn starting_keeps_the_range_but_replaces_the_direction() {
        let q = TestQuery::new(
            MockBox { lo: 0.0, hi: 10.0 },
            MockBox { lo: 20.0, hi: 30.0 },
            Some(HyperDirection::new(0, true)),
        );
        let restarted = q.base.starting(HyperDirection::new(0, false), factory);
        assert_eq!(restarted.base.ls, q.base.ls);
        assert_eq!(restarted.base.us, q.base.us);
        assert_eq!(restarted.base.direction, Some(HyperDirection::new(0, false)));
    }

    #[test]
    fn terminate_early_data_delegates_to_terminate_early_node_via_bounds() {
        let narrow = TestQuery::new(
            MockBox { lo: f64::MIN, hi: 10.0 },
            MockBox { lo: 0.0, hi: 5.0 },
            Some(HyperDirection::new(0, true)),
        );
        // MockBox is its own bounded shape, so this should agree with terminate_early_node.
        assert_eq!(
            narrow.base.terminate_early_data(&MockBox { lo: 6.0, hi: 8.0 }),
            narrow.base.terminate_early_node(&MockBox { lo: 6.0, hi: 8.0 })
        );
    }
}

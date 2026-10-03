//! Port of `ghidra.app.plugin.core.functiongraph.graph.layout.flowchart.ColumnSegment`.

use std::cmp::Ordering;
use std::fmt;

use crate::graph::viewer::layout::grid_point::GridPoint;

use super::edge_segment::{SegmentId, SegmentRef, SegmentStore};
use super::row_segment::RowSegment;

/// Orientation of the row attached to the top or bottom of a column segment. The declaration
/// order gives Java's `LEFT < TERMINAL < RIGHT` enum ordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RowOrientation {
    /// The attached row extends to the left of this column.
    Left,
    /// There is no attached row since this segment ends at a vertex.
    Terminal,
    /// The attached row extends to the right of this column.
    Right,
}

/// A vertical segment of an articulated edge, viewed through its [`SegmentStore`].
///
/// Each pair of points in an edge's articulation list is either a column segment or a row
/// segment; the list always starts and ends with a column segment. See
/// [`edge_segment`](super::edge_segment) for how the Java linked chain maps onto the store.
pub struct ColumnSegment<'a, E> {
    pub(super) base: SegmentRef<'a, E>,
}

impl<E> Clone for ColumnSegment<'_, E> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<E> Copy for ColumnSegment<'_, E> {}

impl<'a, E> ColumnSegment<'a, E> {
    pub(super) fn new(store: &'a SegmentStore<E>, id: SegmentId) -> Self {
        Self { base: SegmentRef { store, id } }
    }

    /// The id of this segment in its store.
    pub fn id(&self) -> SegmentId {
        self.base.id
    }

    /// Java `EdgeSegment.getEdge()`.
    pub fn edge(&self) -> &'a E {
        self.base.edge()
    }

    /// Java `EdgeSegment.getOffset()`.
    pub fn offset(&self) -> i32 {
        self.base.offset()
    }

    /// All articulation points of this segment's edge.
    pub fn points(&self) -> &'a [GridPoint] {
        self.base.points()
    }

    /// Java `EdgeSegment.isBackEdge()`.
    pub fn is_back_edge(&self) -> bool {
        self.base.is_back_edge()
    }

    /// Java `EdgeSegment.startsAt(GridPoint)`.
    pub fn starts_at(&self, p: GridPoint) -> bool {
        self.base.starts_at(p)
    }

    /// Returns the grid column index of this column segment.
    pub fn col(&self) -> i32 {
        self.base.point(0).col
    }

    /// Returns the grid row where this segment starts, in articulation-point order (not
    /// necessarily the top row).
    pub fn start_row(&self) -> i32 {
        self.base.point(0).row
    }

    /// Returns the grid row where this segment ends, in articulation-point order (not
    /// necessarily the bottom row).
    pub fn end_row(&self) -> i32 {
        self.base.point(1).row
    }

    /// Compares by the top rows first and the bottom rows only if the tops are equal. This is the
    /// consistent (transitive) ordering used when segments flow in mixed directions.
    pub fn compare_to_ignore_flows(&self, other: &ColumnSegment<'_, E>) -> Ordering {
        self.compare_tops(other).then_with(|| self.compare_bottoms(other))
    }

    /// Compares following the flow direction: upward-flowing segments compare bottoms first,
    /// downward-flowing ones compare tops first. Only valid for sorting when every segment in the
    /// list flows the same way.
    pub fn compare_to_using_flows(&self, other: &ColumnSegment<'_, E>) -> Ordering {
        if self.is_flowing_upwards() {
            return self.compare_bottoms(other).then_with(|| self.compare_tops(other));
        }
        self.compare_tops(other).then_with(|| self.compare_bottoms(other))
    }

    /// Compares column segments strictly by the rows connected at the top of the segments.
    pub fn compare_tops(&self, other: &ColumnSegment<'_, E>) -> Ordering {
        let result = self.col().cmp(&other.col());
        if result != Ordering::Equal {
            return result;
        }

        let my_orientation = self.orientation_for_top_row();
        let other_orientation = other.orientation_for_top_row();
        if my_orientation != other_orientation {
            return my_orientation.cmp(&other_orientation);
        }

        match my_orientation {
            RowOrientation::Left => self
                .top_row_segment()
                .compare_lefts(&other.top_row_segment())
                .reverse(),
            RowOrientation::Right => {
                self.top_row_segment().compare_rights(&other.top_row_segment())
            }
            RowOrientation::Terminal => Ordering::Equal,
        }
    }

    /// Compares column segments strictly by the rows connected at the bottom of the segments.
    pub fn compare_bottoms(&self, other: &ColumnSegment<'_, E>) -> Ordering {
        let result = self.col().cmp(&other.col());
        if result != Ordering::Equal {
            return result;
        }

        let my_orientation = self.orientation_for_bottom_row();
        let other_orientation = other.orientation_for_bottom_row();
        if my_orientation != other_orientation {
            return my_orientation.cmp(&other_orientation);
        }

        match my_orientation {
            RowOrientation::Left => {
                self.bottom_row_segment().compare_lefts(&other.bottom_row_segment())
            }
            RowOrientation::Right => self
                .bottom_row_segment()
                .compare_rights(&other.bottom_row_segment())
                .reverse(),
            RowOrientation::Terminal => Ordering::Equal,
        }
    }

    /// Returns true if the two column segments would overlap if drawn at the same x coordinate.
    pub fn overlaps(&self, other: &ColumnSegment<'_, E>) -> bool {
        if self.virtual_min_y() > other.virtual_max_y() {
            return false;
        }
        if self.virtual_max_y() < other.virtual_min_y() {
            return false;
        }
        true
    }

    /// Java `nextSegment()`: the following row segment, or `None` for the last segment.
    pub fn next_segment(&self) -> Option<RowSegment<'a, E>> {
        self.base
            .column_has_next()
            .then(|| RowSegment { base: self.base.with_index(self.base.id.point_index + 1) })
    }

    /// Java `previousSegment()`: the preceding row segment, or `None` for the first segment.
    pub fn previous_segment(&self) -> Option<RowSegment<'a, E>> {
        (self.base.id.point_index > 0)
            .then(|| RowSegment { base: self.base.with_index(self.base.id.point_index - 1) })
    }

    /// Returns true if this is the first segment of its edge.
    pub fn is_start_segment(&self) -> bool {
        self.base.id.point_index == 0
    }

    /// Returns true if this is the last segment of its edge.
    pub fn is_end_segment(&self) -> bool {
        !self.base.column_has_next()
    }

    /// A top y position, assuming rows are one million pixels apart, that includes the offsets
    /// already assigned to the attached rows. Only meaningful for comparisons.
    pub fn virtual_min_y(&self) -> i32 {
        self.virtual_start_y().min(self.virtual_end_y())
    }

    /// A bottom y position, assuming rows are one million pixels apart, that includes the offsets
    /// already assigned to the attached rows. Only meaningful for comparisons.
    pub fn virtual_max_y(&self) -> i32 {
        self.virtual_start_y().max(self.virtual_end_y())
    }

    fn virtual_start_y(&self) -> i32 {
        // start segments get a slight downward offset so end segments finishing on the vertex
        // where this one begins do not overlap it
        let offset = self.previous_segment().map_or(1, |r| r.offset());
        self.start_row().wrapping_mul(1_000_000).wrapping_add(offset)
    }

    fn virtual_end_y(&self) -> i32 {
        // end segments get a slight upward offset so start segments leaving the vertex where
        // this one ends do not overlap it
        let offset = self.next_segment().map_or(-1, |r| r.offset());
        self.end_row().wrapping_mul(1_000_000).wrapping_add(offset)
    }

    fn top_row_segment(&self) -> RowSegment<'a, E> {
        let segment =
            if self.is_flowing_upwards() { self.next_segment() } else { self.previous_segment() };
        segment.expect("column segment has no row attached at its top")
    }

    fn bottom_row_segment(&self) -> RowSegment<'a, E> {
        let segment =
            if self.is_flowing_upwards() { self.previous_segment() } else { self.next_segment() };
        segment.expect("column segment has no row attached at its bottom")
    }

    fn orientation_for_top_row(&self) -> RowOrientation {
        if self.is_start_segment() {
            return RowOrientation::Terminal;
        }
        let top = self.top_row_segment();
        let other_col = if self.is_flowing_upwards() { top.end_col() } else { top.start_col() };
        if other_col < self.col() {
            RowOrientation::Left
        } else {
            RowOrientation::Right
        }
    }

    fn orientation_for_bottom_row(&self) -> RowOrientation {
        if self.is_end_segment() {
            return RowOrientation::Terminal;
        }
        let bottom = self.bottom_row_segment();
        let other_col =
            if self.is_flowing_upwards() { bottom.start_col() } else { bottom.end_col() };
        if other_col < self.col() {
            RowOrientation::Left
        } else {
            RowOrientation::Right
        }
    }

    /// Returns true if this segment ends above where it starts.
    pub fn is_flowing_upwards(&self) -> bool {
        self.start_row() > self.end_row()
    }

    /// Returns the final column segment of this segment's edge.
    pub fn last(&self) -> ColumnSegment<'a, E> {
        let last_index = self.base.store.last_column_index(self.base.id.edge);
        ColumnSegment { base: self.base.with_index(last_index) }
    }
}

impl<E: fmt::Display> fmt::Display for ColumnSegment<'_, E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.base.fmt_segment(f)
    }
}

/// Test helpers mirroring `EdgeSegmentTest`'s `points(start, flows...)` builder.
#[cfg(test)]
pub(super) mod test_support {
    use super::*;

    /// Builds articulation points from a start point and alternating row/column deltas.
    pub fn points(start: GridPoint, flows: &[i32]) -> Vec<GridPoint> {
        let mut points = vec![start];
        let mut next = start;
        for (i, flow) in flows.iter().enumerate() {
            if i % 2 == 0 {
                next.row += flow;
            } else {
                next.col += flow;
            }
            points.push(next);
        }
        points
    }

    /// Like [`points`] but reversed, so the chain *ends* at `end`.
    pub fn points_reverse_order(end: GridPoint, flows: &[i32]) -> Vec<GridPoint> {
        let mut points = points(end, flows);
        points.reverse();
        points
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{points, points_reverse_order};
    use super::*;

    const DOWN: i32 = 1;
    const UP: i32 = -1;
    const LEFT: i32 = -1;
    const RIGHT: i32 = 1;
    const DOWN_2: i32 = 2;
    const LEFT_2: i32 = -2;
    const RIGHT_2: i32 = 2;

    fn p(row: i32, col: i32) -> GridPoint {
        GridPoint::new(row, col)
    }

    /// Mirrors `EdgeSegmentTest.assertLessThan(ColumnSegment, ColumnSegment)`; its `sameFlow`
    /// compares `s1` with itself, so it always uses `compareToUsingFlows`.
    fn less(s1: &ColumnSegment<'_, &str>, s2: &ColumnSegment<'_, &str>) -> bool {
        s1.compare_to_using_flows(s2) == Ordering::Less
    }

    fn greater(s1: &ColumnSegment<'_, &str>, s2: &ColumnSegment<'_, &str>) -> bool {
        s1.compare_to_using_flows(s2) == Ordering::Greater
    }

    fn store_with(edges: &[(&'static str, Vec<GridPoint>)]) -> (SegmentStore<&'static str>, Vec<SegmentId>) {
        let mut store = SegmentStore::new();
        let ids = edges.iter().map(|(e, pts)| store.add_edge(*e, pts.clone())).collect();
        (store, ids)
    }

    #[test]
    fn start_segments_in_totally_different_columns() {
        let (store, ids) =
            store_with(&[("e12", points(p(0, 1), &[DOWN])), ("e13", points(p(0, 2), &[DOWN]))]);
        let (c1, c2) = (store.column(ids[0]), store.column(ids[1]));
        assert!(less(&c1, &c2));
        assert!(greater(&c2, &c1));
    }

    #[test]
    fn compare_start_segment_by_direction_of_bottom_row() {
        let pt = p(0, 0);
        let (store, ids) = store_with(&[
            ("e12", points(pt, &[DOWN_2])),
            ("e13", points(pt, &[DOWN, LEFT, DOWN])),
            ("e14", points(pt, &[DOWN, RIGHT, DOWN])),
        ]);
        let (down, left, right) = (store.column(ids[0]), store.column(ids[1]), store.column(ids[2]));
        assert!(less(&left, &down));
        assert!(greater(&down, &left));
        assert!(less(&down, &right));
        assert!(greater(&right, &down));
        assert!(less(&left, &right));
        assert!(greater(&right, &left));
        assert_eq!(down.compare_to_using_flows(&down), Ordering::Equal);
        assert_eq!(left.compare_to_using_flows(&left), Ordering::Equal);
    }

    #[test]
    fn compare_start_both_left_but_different_row_levels() {
        let pt = p(0, 0);
        let (store, ids) = store_with(&[
            ("e13", points(pt, &[DOWN, LEFT, DOWN])),
            ("e14", points(pt, &[DOWN_2, LEFT, DOWN])),
        ]);
        let (d1, d2) = (store.column(ids[0]), store.column(ids[1]));
        assert!(less(&d1, &d2));
        assert!(greater(&d2, &d1));
    }

    #[test]
    fn compare_start_both_right_but_different_row_levels() {
        let pt = p(0, 0);
        let (store, ids) = store_with(&[
            ("e13", points(pt, &[DOWN, RIGHT, DOWN])),
            ("e14", points(pt, &[DOWN_2, RIGHT, DOWN])),
        ]);
        let (d1, d2) = (store.column(ids[0]), store.column(ids[1]));
        assert!(less(&d2, &d1));
        assert!(greater(&d1, &d2));
    }

    #[test]
    fn compare_start_both_left_then_opposite_direction() {
        let pt = p(0, 0);
        let (store, ids) = store_with(&[
            ("e13", points(pt, &[DOWN, LEFT, UP])),
            ("e14", points(pt, &[DOWN, LEFT, DOWN])),
        ]);
        let (left_up, left_down) = (store.column(ids[0]), store.column(ids[1]));
        assert!(less(&left_up, &left_down));
        assert!(greater(&left_down, &left_up));
    }

    #[test]
    fn compare_start_both_rights_then_opposite_direction() {
        let pt = p(0, 0);
        let (store, ids) = store_with(&[
            ("e13", points(pt, &[DOWN, RIGHT, UP])),
            ("e14", points(pt, &[DOWN, RIGHT, DOWN])),
        ]);
        let (right_up, right_down) = (store.column(ids[0]), store.column(ids[1]));
        assert!(less(&right_down, &right_up));
        assert!(greater(&right_up, &right_down));
    }

    #[test]
    fn compare_left_down_and_left_up_different_left_column() {
        let pt = p(0, 0);
        let (store, ids) = store_with(&[
            ("a", points(pt, &[DOWN, LEFT, DOWN])),
            ("b", points(pt, &[DOWN, LEFT_2, DOWN])),
            ("c", points(pt, &[DOWN, LEFT, UP])),
            ("d", points(pt, &[DOWN, LEFT_2, UP])),
        ]);
        let (l1d, l2d, l1u, l2u) =
            (store.column(ids[0]), store.column(ids[1]), store.column(ids[2]), store.column(ids[3]));
        assert!(less(&l2d, &l1d));
        assert!(greater(&l1d, &l2d));
        assert!(less(&l1u, &l2u));
        assert!(greater(&l2u, &l1u));
    }

    #[test]
    fn compare_right_down_and_right_up_different_right_column() {
        let pt = p(0, 0);
        let (store, ids) = store_with(&[
            ("a", points(pt, &[DOWN, RIGHT, DOWN])),
            ("b", points(pt, &[DOWN, RIGHT_2, DOWN])),
            ("c", points(pt, &[DOWN, RIGHT, UP])),
            ("d", points(pt, &[DOWN, RIGHT_2, UP])),
        ]);
        let (r1d, r2d, r1u, r2u) =
            (store.column(ids[0]), store.column(ids[1]), store.column(ids[2]), store.column(ids[3]));
        assert!(less(&r1d, &r2d));
        assert!(greater(&r2d, &r1d));
        assert!(less(&r2u, &r1u));
        assert!(greater(&r1u, &r2u));
    }

    #[test]
    fn compare_left_up_but_upper_row_different_directions() {
        let pt = p(0, 0);
        let (store, ids) = store_with(&[
            ("e13", points(pt, &[DOWN, LEFT, UP, LEFT])),
            ("e14", points(pt, &[DOWN, LEFT, UP, RIGHT])),
        ]);
        let (l_u_left, l_u_right) = (store.column(ids[0]), store.column(ids[1]));
        assert!(less(&l_u_right, &l_u_left));
        assert!(greater(&l_u_left, &l_u_right));
    }

    #[test]
    fn compare_left_down_but_lower_row_different_directions() {
        let pt = p(0, 0);
        let (store, ids) = store_with(&[
            ("e13", points(pt, &[DOWN, LEFT, DOWN, LEFT])),
            ("e14", points(pt, &[DOWN, LEFT, DOWN, RIGHT])),
        ]);
        let (l_d_left, l_d_right) = (store.column(ids[0]), store.column(ids[1]));
        assert!(less(&l_d_left, &l_d_right));
        assert!(greater(&l_d_right, &l_d_left));
    }

    #[test]
    fn end_segment_is_last_of_reverse_chain() {
        let (store, ids) = store_with(&[("e", points_reverse_order(p(4, 0), &[UP, LEFT, UP]))]);
        let last = store.column(ids[0]).last();
        assert!(last.is_end_segment());
        assert!(!last.is_start_segment());
        assert_eq!((last.start_row(), last.end_row(), last.col()), (3, 4, 0));
    }

    #[test]
    fn column_start_segment_to_shared_row_depends_on_row_offsets() {
        let (mut store, ids) = store_with(&[
            ("e13", points(p(0, 1), &[DOWN, RIGHT, DOWN])),
            ("e14", points(p(0, 0), &[DOWN, RIGHT, DOWN])),
        ]);
        assert!(store.column(ids[0]).overlaps(&store.column(ids[1]).last()));

        let row = store.column(ids[1]).next_segment().unwrap().id();
        store.set_offset(row, 1);
        assert!(!store.column(ids[0]).overlaps(&store.column(ids[1]).last()));
    }

    #[test]
    fn virtual_y_uses_terminal_bias_and_row_offsets() {
        let (mut store, ids) = store_with(&[("e", points(p(0, 0), &[DOWN, RIGHT, DOWN]))]);
        let first = store.column(ids[0]);
        // start bias +1, end at row 1 plus the (zero) offset of the following row
        assert_eq!((first.virtual_min_y(), first.virtual_max_y()), (1, 1_000_000));
        let row = first.next_segment().unwrap().id();
        store.set_offset(row, 4);
        let last = store.column(ids[0]).last();
        // start is the row offset (4) past row 1, end bias -1 at row 2
        assert_eq!((last.virtual_min_y(), last.virtual_max_y()), (1_000_004, 1_999_999));
    }

    #[test]
    fn orientations_order_left_terminal_right() {
        assert!(RowOrientation::Left < RowOrientation::Terminal);
        assert!(RowOrientation::Terminal < RowOrientation::Right);
    }
}

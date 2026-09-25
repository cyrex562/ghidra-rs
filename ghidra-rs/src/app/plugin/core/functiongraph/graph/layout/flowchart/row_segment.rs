//! Port of `ghidra.app.plugin.core.functiongraph.graph.layout.flowchart.RowSegment`.

use std::cmp::Ordering;
use std::fmt;

use crate::graph::viewer::layout::grid_point::GridPoint;

use super::column_segment::ColumnSegment;
use super::edge_segment::{SegmentId, SegmentRef, SegmentStore};

/// Orientation of the column attached to one end of a row segment. The declaration order gives
/// Java's `UP < DOWN` enum ordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ColumnOrientation {
    /// The attached column extends upwards from this row.
    Up,
    /// The attached column extends downwards from this row.
    Down,
}

/// A horizontal segment of an articulated edge, viewed through its [`SegmentStore`]. A row
/// segment always has a column segment on both sides.
pub struct RowSegment<'a, E> {
    pub(super) base: SegmentRef<'a, E>,
}

impl<E> Clone for RowSegment<'_, E> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<E> Copy for RowSegment<'_, E> {}

impl<'a, E> RowSegment<'a, E> {
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

    /// Returns the grid row index of this row segment.
    pub fn row(&self) -> i32 {
        self.base.point(0).row
    }

    /// Returns the grid column where this segment starts, in articulation-point order.
    pub fn start_col(&self) -> i32 {
        self.base.point(0).col
    }

    /// Returns the grid column where this segment ends, in articulation-point order.
    pub fn end_col(&self) -> i32 {
        self.base.point(1).col
    }

    /// Returns the left-most column index of this segment.
    pub fn left_col(&self) -> i32 {
        self.start_col().min(self.end_col())
    }

    /// Returns the right-most column index of this segment.
    pub fn right_col(&self) -> i32 {
        self.start_col().max(self.end_col())
    }

    /// Compares by the left ends first and the right ends only if the lefts are equal.
    pub fn compare_to_ignore_flows(&self, other: &RowSegment<'_, E>) -> Ordering {
        self.compare_lefts(other).then_with(|| self.compare_rights(other))
    }

    /// Compares following the flow direction: left-flowing rows compare their right ends first.
    /// Only valid for sorting when every segment in the list flows the same way.
    pub fn compare_to_using_flows(&self, other: &RowSegment<'_, E>) -> Ordering {
        if self.is_flowing_left() {
            return self.compare_rights(other).then_with(|| self.compare_lefts(other));
        }
        self.compare_lefts(other).then_with(|| self.compare_rights(other))
    }

    /// Returns true if the two row segments would overlap if drawn at the same y coordinate.
    /// Rows that merely touch at a column where both are terminal (enter or leave a vertex) do
    /// not overlap.
    pub fn overlaps(&self, other: &RowSegment<'_, E>) -> bool {
        if self.left_col() > other.right_col() {
            return false;
        }
        if self.right_col() < other.left_col() {
            return false;
        }
        if self.left_col() == other.right_col() {
            return !(self.is_left_terminal() && other.is_right_terminal());
        } else if self.right_col() == other.left_col() {
            return !(self.is_right_terminal() && other.is_left_terminal());
        }
        true
    }

    /// Compares row segments strictly by the columns connected at their left ends.
    pub fn compare_lefts(&self, other: &RowSegment<'_, E>) -> Ordering {
        let result = self.row().cmp(&other.row());
        if result != Ordering::Equal {
            return result;
        }

        let my_orientation = self.orientation_for_left_column();
        let other_orientation = other.orientation_for_left_column();
        if my_orientation != other_orientation {
            return my_orientation.cmp(&other_orientation);
        }

        let mine = self.left_col_segment();
        let theirs = other.left_col_segment();
        if my_orientation == ColumnOrientation::Up {
            return mine.compare_tops(&theirs).reverse();
        }
        mine.compare_bottoms(&theirs)
    }

    /// Compares row segments strictly by the columns connected at their right ends.
    pub fn compare_rights(&self, other: &RowSegment<'_, E>) -> Ordering {
        let result = self.row().cmp(&other.row());
        if result != Ordering::Equal {
            return result;
        }

        let my_orientation = self.orientation_for_right_column();
        let other_orientation = other.orientation_for_right_column();
        if my_orientation != other_orientation {
            return my_orientation.cmp(&other_orientation);
        }

        let mine = self.right_col_segment();
        let theirs = other.right_col_segment();
        if my_orientation == ColumnOrientation::Up {
            return mine.compare_tops(&theirs);
        }
        mine.compare_bottoms(&theirs).reverse()
    }

    /// Java `nextSegment()`: a row is always followed by a column segment.
    pub fn next_segment(&self) -> ColumnSegment<'a, E> {
        ColumnSegment { base: self.base.with_index(self.base.id.point_index + 1) }
    }

    /// Java `previousSegment()`: a row is always preceded by a column segment.
    pub fn previous_segment(&self) -> ColumnSegment<'a, E> {
        ColumnSegment { base: self.base.with_index(self.base.id.point_index - 1) }
    }

    fn orientation_for_left_column(&self) -> ColumnOrientation {
        let left = self.left_col_segment();
        let other_row = if self.is_flowing_left() { left.end_row() } else { left.start_row() };
        if other_row < self.row() {
            ColumnOrientation::Up
        } else {
            ColumnOrientation::Down
        }
    }

    fn orientation_for_right_column(&self) -> ColumnOrientation {
        let right = self.right_col_segment();
        let other_row = if self.is_flowing_left() { right.start_row() } else { right.end_row() };
        if other_row < self.row() {
            ColumnOrientation::Up
        } else {
            ColumnOrientation::Down
        }
    }

    fn left_col_segment(&self) -> ColumnSegment<'a, E> {
        if self.is_flowing_left() {
            self.next_segment()
        } else {
            self.previous_segment()
        }
    }

    fn right_col_segment(&self) -> ColumnSegment<'a, E> {
        if self.is_flowing_left() {
            self.previous_segment()
        } else {
            self.next_segment()
        }
    }

    /// Returns true if this segment ends to the left of where it starts.
    pub fn is_flowing_left(&self) -> bool {
        self.start_col() > self.end_col()
    }

    fn is_left_terminal(&self) -> bool {
        let left = self.left_col_segment();
        left.is_start_segment() || left.is_end_segment()
    }

    fn is_right_terminal(&self) -> bool {
        let right = self.right_col_segment();
        right.is_start_segment() || right.is_end_segment()
    }

    /// Returns the final column segment of this segment's edge.
    pub fn last(&self) -> ColumnSegment<'a, E> {
        self.next_segment().last()
    }
}

impl<E: fmt::Display> fmt::Display for RowSegment<'_, E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.base.fmt_segment(f)
    }
}

#[cfg(test)]
mod tests {
    use super::super::column_segment::test_support::points;
    use super::*;

    const DOWN: i32 = 1;
    const UP: i32 = -1;
    const LEFT: i32 = -1;
    const RIGHT: i32 = 1;
    const RIGHT_2: i32 = 2;

    fn p(row: i32, col: i32) -> GridPoint {
        GridPoint::new(row, col)
    }

    fn store_with(
        edges: &[(&'static str, Vec<GridPoint>)],
    ) -> (SegmentStore<&'static str>, Vec<SegmentId>) {
        let mut store = SegmentStore::new();
        let ids = edges.iter().map(|(e, pts)| store.add_edge(*e, pts.clone())).collect();
        (store, ids)
    }

    /// The first row segment of the edge (Java `colSeg.nextSegment()`).
    fn first_row<'a>(store: &'a SegmentStore<&'static str>, id: SegmentId) -> RowSegment<'a, &'static str> {
        store.column(id).next_segment().unwrap()
    }

    fn assert_overlap(flows1: (GridPoint, &[i32]), flows2: (GridPoint, &[i32]), expected: bool) {
        let (store, ids) =
            store_with(&[("e13", points(flows1.0, flows1.1)), ("e14", points(flows2.0, flows2.1))]);
        let (r1, r2) = (first_row(&store, ids[0]), first_row(&store, ids[1]));
        assert_eq!(r1.overlaps(&r2), expected);
        assert_eq!(r2.overlaps(&r1), expected);
    }

    #[test]
    fn row_segment_overlap_seg1_totally_before_seg2() {
        assert_overlap((p(0, 0), &[DOWN, RIGHT, DOWN]), (p(0, 10), &[DOWN, RIGHT, DOWN]), false);
    }

    #[test]
    fn rows_leaving_same_vertex_in_opposite_directions_dont_overlap() {
        assert_overlap((p(0, 0), &[DOWN, LEFT, DOWN]), (p(0, 0), &[DOWN, RIGHT, DOWN]), false);
    }

    #[test]
    fn rows_leaving_same_vertex_in_same_direction_overlap() {
        assert_overlap((p(0, 0), &[DOWN, LEFT, DOWN]), (p(0, 0), &[DOWN, LEFT, DOWN]), true);
    }

    #[test]
    fn rows_entering_same_vertex_in_opposite_directions_dont_overlap() {
        assert_overlap((p(0, 0), &[DOWN, RIGHT, DOWN]), (p(0, 2), &[DOWN, LEFT, DOWN]), false);
    }

    #[test]
    fn rows_entering_same_vertex_in_same_directions_overlap() {
        assert_overlap((p(0, 0), &[DOWN, RIGHT_2, DOWN]), (p(0, 1), &[DOWN, RIGHT, DOWN]), true);
    }

    #[test]
    fn rows_that_start_end_on_same_column_and_one_is_terminal_and_other_isnt() {
        assert_overlap(
            (p(0, 0), &[DOWN, RIGHT, DOWN, RIGHT, DOWN]),
            (p(0, 1), &[DOWN, RIGHT, DOWN]),
            true,
        );
        assert_overlap(
            (p(0, 1), &[DOWN, LEFT, DOWN, LEFT, DOWN]),
            (p(0, 0), &[DOWN, LEFT, DOWN]),
            true,
        );
    }

    #[test]
    fn compare_rows_by_row_then_left_column_orientation() {
        let (store, ids) = store_with(&[
            ("a", points(p(0, 0), &[DOWN, RIGHT, DOWN])),
            ("b", points(p(0, 0), &[DOWN * 2, RIGHT, DOWN])),
            // same row 1 as "a", but its left column comes up from below (flowing upwards)
            ("c", points(p(3, 0), &[-2, RIGHT, UP])),
        ]);
        let (a, b, c) = (first_row(&store, ids[0]), first_row(&store, ids[1]), first_row(&store, ids[2]));
        assert_eq!(a.compare_to_using_flows(&b), Ordering::Less);
        assert_eq!(b.compare_to_using_flows(&a), Ordering::Greater);
        // a's left column hangs up (UP < DOWN), c's left column comes from below
        assert_eq!(a.compare_lefts(&c), Ordering::Less);
        assert_eq!(c.compare_lefts(&a), Ordering::Greater);
        assert_eq!(a.compare_to_using_flows(&a), Ordering::Equal);
    }

    #[test]
    fn row_accessors_and_flow() {
        let (store, ids) = store_with(&[("e", points(p(0, 3), &[DOWN, LEFT * 2, DOWN]))]);
        let row = first_row(&store, ids[0]);
        assert_eq!((row.row(), row.start_col(), row.end_col()), (1, 3, 1));
        assert_eq!((row.left_col(), row.right_col()), (1, 3));
        assert!(row.is_flowing_left());
        assert_eq!(row.previous_segment().id(), ids[0]);
        assert_eq!(row.last().id(), row.next_segment().id());
    }
}

//! Port of `ghidra.app.plugin.core.functiongraph.graph.layout.flowchart.EdgeSegment`.
//!
//! In Java, an articulated edge is a doubly-linked chain of `ColumnSegment`/`RowSegment` objects
//! that all share the edge's list of [`GridPoint`]s and each carry a mutable routing offset. The
//! chains are then sorted against *other* edges' chains while offsets are assigned.
//!
//! Per the arena + typed-ID convention (OWNERSHIP_MIGRATION.md, "Decisions recorded 2026-09-24"),
//! the chains live in one [`SegmentStore`]: each edge owns its points and one offset per segment,
//! and a segment is named by a `Copy` [`SegmentId`] = (edge, point index). The segment at an even
//! point index is a column segment and the one at an odd index is a row segment, which is exactly
//! the Java alternation (the chain always starts and ends with a column segment). The Java
//! `next`/`previous` links become `point_index ± 1`, so no back-pointers are stored.
//!
//! [`ColumnSegment`] and [`RowSegment`] are cheap `Copy` views (`&store` + id) exposing the Java
//! query/compare API; offsets are written through [`SegmentStore::set_offset`].

use std::fmt;

use crate::graph::viewer::layout::grid_point::GridPoint;

use super::column_segment::ColumnSegment;
use super::row_segment::RowSegment;

/// Identifies one edge (one articulation chain) inside a [`SegmentStore`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EdgeId(pub usize);

/// Identifies one segment of an edge: the edge plus the index into that edge's articulation
/// points of the segment's first point (Java `EdgeSegment.pointIndex`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SegmentId {
    /// The edge this segment belongs to.
    pub edge: EdgeId,
    /// Index into the edge's points of this segment's first point.
    pub point_index: usize,
}

impl SegmentId {
    /// Returns true if this id names a column (vertical) segment, i.e. its point index is even.
    pub fn is_column(&self) -> bool {
        self.point_index % 2 == 0
    }

    /// Returns true if this id names a row (horizontal) segment, i.e. its point index is odd.
    pub fn is_row(&self) -> bool {
        !self.is_column()
    }
}

#[derive(Debug, Clone)]
struct EdgeChain<E> {
    edge: E,
    points: Vec<GridPoint>,
    /// One offset per segment; `offsets[i]` belongs to the segment starting at point `i`.
    offsets: Vec<i32>,
}

/// Arena owning every edge's articulation points and per-segment routing offsets.
#[derive(Debug, Clone)]
pub struct SegmentStore<E> {
    chains: Vec<EdgeChain<E>>,
}

impl<E> Default for SegmentStore<E> {
    fn default() -> Self {
        Self { chains: Vec::new() }
    }
}

impl<E> SegmentStore<E> {
    /// Creates an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds an edge with its articulation points and returns the id of its first segment, which
    /// is always a column segment. Mirrors `new ColumnSegment<>(edge, points)`, which also builds
    /// every follow-on segment.
    ///
    /// A well-formed chain has an even number of points so that it starts and ends with a column
    /// segment (Java's documented "built-in assumption"). As in Java, an odd-length chain still
    /// builds: it ends with a row followed by a degenerate one-point column segment, whose
    /// `end_row` panics just as Java's `getEndRow()` throws.
    ///
    /// # Panics
    ///
    /// Panics if `points` has fewer than two entries.
    pub fn add_edge(&mut self, edge: E, points: Vec<GridPoint>) -> SegmentId {
        assert!(points.len() >= 2, "an edge needs at least two articulation points");
        let offsets = vec![0; points.len()];
        let id = EdgeId(self.chains.len());
        self.chains.push(EdgeChain { edge, points, offsets });
        SegmentId { edge: id, point_index: 0 }
    }

    /// Returns the number of edges in the store.
    pub fn edge_count(&self) -> usize {
        self.chains.len()
    }

    /// Returns the edge object for the given edge id.
    pub fn edge(&self, id: EdgeId) -> &E {
        &self.chains[id.0].edge
    }

    /// Returns all articulation points of the given edge.
    pub fn points(&self, id: EdgeId) -> &[GridPoint] {
        &self.chains[id.0].points
    }

    /// Returns the offset assigned to a segment (Java `EdgeSegment.getOffset()`).
    pub fn offset(&self, id: SegmentId) -> i32 {
        self.chains[id.edge.0].offsets[id.point_index]
    }

    /// Sets the offset from the grid line for a segment (Java `EdgeSegment.setOffset(int)`).
    /// Edge routing uses it to keep overlapping segments in the same row or column from being
    /// assigned the exact same layout-space location.
    pub fn set_offset(&mut self, id: SegmentId, offset: i32) {
        self.chains[id.edge.0].offsets[id.point_index] = offset;
    }

    /// Returns the first (column) segment of the given edge.
    pub fn first_segment(&self, id: EdgeId) -> ColumnSegment<'_, E> {
        ColumnSegment::new(self, SegmentId { edge: id, point_index: 0 })
    }

    /// Returns a column-segment view of `id`.
    ///
    /// # Panics
    ///
    /// Panics if `id` names a row segment.
    pub fn column(&self, id: SegmentId) -> ColumnSegment<'_, E> {
        assert!(id.is_column(), "{id:?} is not a column segment");
        ColumnSegment::new(self, id)
    }

    /// Returns a row-segment view of `id`.
    ///
    /// # Panics
    ///
    /// Panics if `id` names a column segment.
    pub fn row(&self, id: SegmentId) -> RowSegment<'_, E> {
        assert!(id.is_row(), "{id:?} is not a row segment");
        RowSegment::new(self, id)
    }

    /// Returns a view of `id` as whichever kind of segment it is.
    pub fn segment(&self, id: SegmentId) -> EdgeSegment<'_, E> {
        if id.is_column() {
            EdgeSegment::Column(ColumnSegment::new(self, id))
        } else {
            EdgeSegment::Row(RowSegment::new(self, id))
        }
    }

    /// Point index of the final column segment of edge `id` (Java `ColumnSegment.last()`).
    pub(super) fn last_column_index(&self, id: EdgeId) -> usize {
        let len = self.chains[id.0].points.len();
        if len % 2 == 0 { len - 2 } else { len - 1 }
    }
}

/// Shared state and behaviour of Java's abstract `EdgeSegment`: a segment of an articulated
/// edge, resolved against its [`SegmentStore`]. Column and row segments embed this.
pub(super) struct SegmentRef<'a, E> {
    pub(super) store: &'a SegmentStore<E>,
    pub(super) id: SegmentId,
}

impl<E> Clone for SegmentRef<'_, E> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<E> Copy for SegmentRef<'_, E> {}

impl<'a, E> SegmentRef<'a, E> {
    pub(super) fn points(&self) -> &'a [GridPoint] {
        self.store.points(self.id.edge)
    }

    pub(super) fn point(&self, offset_from_start: usize) -> GridPoint {
        self.points()[self.id.point_index + offset_from_start]
    }

    pub(super) fn edge(&self) -> &'a E {
        self.store.edge(self.id.edge)
    }

    pub(super) fn offset(&self) -> i32 {
        self.store.offset(self.id)
    }

    /// Java `EdgeSegment.isBackEdge()`: the edge ends at or above its start row.
    pub(super) fn is_back_edge(&self) -> bool {
        let points = self.points();
        points[0].row >= points[points.len() - 1].row
    }

    /// Java `EdgeSegment.startsAt(GridPoint)`.
    pub(super) fn starts_at(&self, p: GridPoint) -> bool {
        self.point(0) == p
    }

    pub(super) fn with_index(&self, point_index: usize) -> SegmentRef<'a, E> {
        SegmentRef { store: self.store, id: SegmentId { edge: self.id.edge, point_index } }
    }

    /// Java `ColumnSegment`'s constructor links a following row only when
    /// `pointIndex < points.size() - 2`.
    pub(super) fn column_has_next(&self) -> bool {
        self.id.point_index + 2 < self.points().len()
    }

    pub(super) fn fmt_segment(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    where
        E: fmt::Display,
    {
        write!(f, "{},  i = {}, offset = {}", self.edge(), self.id.point_index, self.offset())
    }
}

/// A segment of either kind; the Rust form of the abstract Java `EdgeSegment<E>` reference type
/// returned by `nextSegment()`/`previousSegment()`.
pub enum EdgeSegment<'a, E> {
    /// A vertical segment.
    Column(ColumnSegment<'a, E>),
    /// A horizontal segment.
    Row(RowSegment<'a, E>),
}

impl<E> Clone for EdgeSegment<'_, E> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<E> Copy for EdgeSegment<'_, E> {}

impl<'a, E> EdgeSegment<'a, E> {
    fn base(&self) -> SegmentRef<'a, E> {
        match self {
            EdgeSegment::Column(c) => c.base,
            EdgeSegment::Row(r) => r.base,
        }
    }

    /// The id of this segment.
    pub fn id(&self) -> SegmentId {
        self.base().id
    }

    /// Java `EdgeSegment.getEdge()`.
    pub fn edge(&self) -> &'a E {
        self.base().edge()
    }

    /// Java `EdgeSegment.getOffset()`.
    pub fn offset(&self) -> i32 {
        self.base().offset()
    }

    /// Java `EdgeSegment.isBackEdge()`.
    pub fn is_back_edge(&self) -> bool {
        self.base().is_back_edge()
    }

    /// Java `EdgeSegment.startsAt(GridPoint)`.
    pub fn starts_at(&self, p: GridPoint) -> bool {
        self.base().starts_at(p)
    }

    /// Java `EdgeSegment.nextSegment()`: `None` only after the final column segment.
    pub fn next_segment(&self) -> Option<EdgeSegment<'a, E>> {
        match self {
            EdgeSegment::Column(c) => c.next_segment().map(EdgeSegment::Row),
            EdgeSegment::Row(r) => Some(EdgeSegment::Column(r.next_segment())),
        }
    }

    /// Java `EdgeSegment.previousSegment()`: `None` only for the first column segment.
    pub fn previous_segment(&self) -> Option<EdgeSegment<'a, E>> {
        match self {
            EdgeSegment::Column(c) => c.previous_segment().map(EdgeSegment::Row),
            EdgeSegment::Row(r) => Some(EdgeSegment::Column(r.previous_segment())),
        }
    }
}

impl<E: fmt::Display> fmt::Display for EdgeSegment<'_, E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.base().fmt_segment(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(row: i32, col: i32) -> GridPoint {
        GridPoint::new(row, col)
    }

    #[test]
    fn chain_alternates_column_row_column() {
        let mut store = SegmentStore::new();
        let first = store.add_edge("e", vec![p(0, 0), p(1, 0), p(1, 2), p(3, 2)]);
        let s0 = store.segment(first);
        assert!(matches!(s0, EdgeSegment::Column(_)));
        let s1 = s0.next_segment().unwrap();
        assert!(matches!(s1, EdgeSegment::Row(_)));
        let s2 = s1.next_segment().unwrap();
        assert!(matches!(s2, EdgeSegment::Column(_)));
        assert!(s2.next_segment().is_none());
        assert_eq!(s2.previous_segment().unwrap().id(), s1.id());
        assert!(s0.previous_segment().is_none());
    }

    #[test]
    fn offsets_are_per_segment() {
        let mut store = SegmentStore::new();
        let first = store.add_edge("e", vec![p(0, 0), p(1, 0), p(1, 2), p(3, 2)]);
        let row = SegmentId { edge: first.edge, point_index: 1 };
        store.set_offset(row, 4);
        assert_eq!(store.offset(first), 0);
        assert_eq!(store.offset(row), 4);
        assert_eq!(store.segment(row).offset(), 4);
    }

    #[test]
    fn back_edge_and_starts_at() {
        let mut store = SegmentStore::new();
        let down = store.add_edge("down", vec![p(0, 0), p(2, 0)]);
        let up = store.add_edge("up", vec![p(2, 0), p(2, 0)]);
        assert!(!store.segment(down).is_back_edge());
        // start.row >= end.row counts as a back edge, including equal rows
        assert!(store.segment(up).is_back_edge());
        assert!(store.segment(down).starts_at(p(0, 0)));
        assert!(!store.segment(down).starts_at(p(2, 0)));
    }

    #[test]
    fn display_matches_java_to_string() {
        let mut store = SegmentStore::new();
        let first = store.add_edge("e12", vec![p(0, 0), p(1, 0)]);
        store.set_offset(first, -2);
        assert_eq!(store.segment(first).to_string(), "e12,  i = 0, offset = -2");
    }

    #[test]
    fn odd_point_count_ends_with_degenerate_column() {
        let mut store = SegmentStore::new();
        let first = store.add_edge("e", vec![p(0, 0), p(1, 0), p(1, 1)]);
        let last = store.column(first).last();
        assert_eq!(last.id().point_index, 2);
        assert!(last.is_end_segment());
        assert_eq!(last.previous_segment().unwrap().end_col(), 1);
    }

    #[test]
    #[should_panic]
    fn single_point_edge_is_rejected() {
        let mut store = SegmentStore::new();
        store.add_edge("e", vec![p(0, 0)]);
    }
}

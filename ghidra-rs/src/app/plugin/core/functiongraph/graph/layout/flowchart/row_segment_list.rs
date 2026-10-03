//! Port of `ghidra.app.plugin.core.functiongraph.graph.layout.flowchart.RowSegmentList`.

use std::collections::HashMap;

use super::edge_segment::{SegmentId, SegmentStore};

/// The row segments that share one grid row. Segment ids resolve against the
/// [`SegmentStore`] passed to each method.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RowSegmentList {
    edge_segments: Vec<SegmentId>,
    row: i32,
}

impl RowSegmentList {
    /// Creates an empty list for grid row `row`.
    pub fn new(row: i32) -> Self {
        Self { edge_segments: Vec::new(), row }
    }

    /// Adds a row segment to this list.
    pub fn add_segment(&mut self, segment: SegmentId) {
        self.edge_segments.push(segment);
    }

    /// Returns the grid row of this list.
    pub fn row(&self) -> i32 {
        self.row
    }

    /// Returns the segments in this list, in their current order.
    pub fn segments(&self) -> &[SegmentId] {
        &self.edge_segments
    }

    /// Returns the minimum offset of any segment in this list (never above 0).
    pub fn min_offset<E>(&self, store: &SegmentStore<E>) -> i32 {
        self.edge_segments.iter().fold(0, |min, &id| min.min(store.offset(id)))
    }

    /// Returns the maximum offset of any segment in this list (never below 0).
    pub fn max_offset<E>(&self, store: &SegmentStore<E>) -> i32 {
        self.edge_segments.iter().fold(0, |max, &id| max.max(store.offset(id)))
    }

    /// Assigns offsets to overlapping row segments so parallel edges are not drawn on top of each
    /// other. Offsets step by 2 (each unit is half an edge spacing) to match column offsets,
    /// which must be 2 apart so an even number of edges can be centered on a grid line. Segments
    /// are first sorted top to bottom, then each takes the first offset group it doesn't overlap.
    pub fn assign_offsets<E>(&mut self, store: &mut SegmentStore<E>) {
        self.sort(store);

        let mut offset_map: HashMap<i32, RowSegmentList> = HashMap::new();
        for &segment in &self.edge_segments {
            Self::assign_offset(&mut offset_map, segment, store);
        }
    }

    fn sort<E>(&mut self, store: &SegmentStore<E>) {
        if self.is_uniform_flow(store) {
            self.edge_segments
                .sort_by(|&a, &b| store.row(a).compare_to_using_flows(&store.row(b)));
        } else {
            self.edge_segments
                .sort_by(|&a, &b| store.row(a).compare_to_ignore_flows(&store.row(b)));
        }
    }

    fn is_uniform_flow<E>(&self, store: &SegmentStore<E>) -> bool {
        let Some(&first) = self.edge_segments.first() else {
            return true;
        };
        let first_is_flowing_left = store.row(first).is_flowing_left();
        self.edge_segments.iter().all(|&id| store.row(id).is_flowing_left() == first_is_flowing_left)
    }

    fn assign_offset<E>(
        offset_map: &mut HashMap<i32, RowSegmentList>,
        segment: SegmentId,
        store: &mut SegmentStore<E>,
    ) {
        // find the first offset group this segment does not overlap
        let mut offset = 0;
        while offset_map
            .entry(offset)
            .or_insert_with(|| RowSegmentList::new(0))
            .has_overlapping_segment(segment, store)
        {
            offset += 2;
        }
        store.set_offset(segment, offset);
        offset_map.entry(offset).or_insert_with(|| RowSegmentList::new(0)).add_segment(segment);
    }

    fn has_overlapping_segment<E>(&self, segment: SegmentId, store: &SegmentStore<E>) -> bool {
        let row = store.row(segment);
        self.edge_segments.iter().any(|&id| row.overlaps(&store.row(id)))
    }
}

#[cfg(test)]
mod tests {
    use super::super::column_segment::test_support::points;
    use super::*;
    use crate::graph::viewer::layout::grid_point::GridPoint;

    fn row_of(store: &SegmentStore<&str>, first: SegmentId) -> SegmentId {
        store.column(first).next_segment().unwrap().id()
    }

    #[test]
    fn overlapping_rows_get_offsets_two_apart() {
        let mut store = SegmentStore::new();
        // three rows on grid row 1, all heading right from column 0; the first two overlap
        let a = store.add_edge("a", points(GridPoint::new(0, 0), &[1, 2, 1]));
        let b = store.add_edge("b", points(GridPoint::new(0, 0), &[1, 1, 1]));
        let c = store.add_edge("c", points(GridPoint::new(0, 5), &[1, 1, 1]));
        let (ra, rb, rc) = (row_of(&store, a), row_of(&store, b), row_of(&store, c));

        let mut list = RowSegmentList::new(1);
        for id in [ra, rb, rc] {
            list.add_segment(id);
        }
        list.assign_offsets(&mut store);

        // lefts tie (same start column, both hang from a vertex above); at the right ends both
        // turn down, so the row reaching further right (a) sorts above b to avoid a crossing
        // c's left column sorts first: with both left columns hanging up, Java negates the
        // column comparison (`-compareTops`), so the right-most column (5) comes first
        assert_eq!(list.segments(), &[rc, ra, rb]);
        assert_eq!(store.offset(ra), 0);
        assert_eq!(store.offset(rb), 2);
        assert_eq!(store.offset(rc), 0);
        assert_eq!(list.min_offset(&store), 0);
        assert_eq!(list.max_offset(&store), 2);
        assert_eq!(list.row(), 1);
    }

    #[test]
    fn empty_list_is_uniform_and_has_zero_offsets() {
        let mut store: SegmentStore<&str> = SegmentStore::new();
        let mut list = RowSegmentList::new(3);
        list.assign_offsets(&mut store);
        assert_eq!(list.min_offset(&store), 0);
        assert_eq!(list.max_offset(&store), 0);
    }
}

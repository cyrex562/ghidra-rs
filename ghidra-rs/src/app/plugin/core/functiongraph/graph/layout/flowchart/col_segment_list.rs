//! Port of `ghidra.app.plugin.core.functiongraph.graph.layout.flowchart.ColSegmentList`.

use crate::graph::viewer::layout::grid_point::GridPoint;

use super::edge_segment::{SegmentId, SegmentStore};

/// The column segments that share one grid column, plus the virtual y range they cover. Segment
/// ids resolve against the [`SegmentStore`] passed to each method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ColSegmentList {
    edge_segments: Vec<SegmentId>,
    col: i32,
    min_y: i64,
    max_y: i64,
}

impl ColSegmentList {
    /// Creates an empty list for grid column `col`.
    pub fn new(col: i32) -> Self {
        Self { edge_segments: Vec::new(), col, min_y: i32::MAX as i64, max_y: i32::MIN as i64 }
    }

    /// Java `ColSegmentList(ColumnSegment)`: a list holding just `segment`, with column 0.
    pub fn with_segment<E>(segment: SegmentId, store: &SegmentStore<E>) -> Self {
        let mut list = Self::new(0);
        list.add_segment(segment, store);
        list
    }

    /// Returns the grid column of this list.
    pub fn col(&self) -> i32 {
        self.col
    }

    /// Returns the segments in this list, in their current order.
    pub fn segments(&self) -> &[SegmentId] {
        &self.edge_segments
    }

    /// Assigns offsets to overlapping column segments so parallel edges are not drawn on top of
    /// each other. Each offset unit is half an edge spacing and offsets are assigned 2 apart, so
    /// 3 parallel edges get -2, 0, 2 and 4 edges get -3, -1, 1, 3. The column is first split into
    /// groups that don't overlap vertically, which makes centering them on vertices easier.
    pub fn assign_offsets<E>(&self, store: &mut SegmentStore<E>) {
        let groups = Self::sort_into_non_overlapping_groups(&self.edge_segments, store);
        for mut group in groups {
            Self::assign_group_offsets(&mut group, store);
        }
    }

    /// Returns true if the virtual y ranges of the two lists intersect.
    pub(super) fn intersects(&self, other: &ColSegmentList) -> bool {
        if self.min_y > other.max_y {
            return false;
        }
        if other.min_y > self.max_y {
            return false;
        }
        true
    }

    /// Finds the segment of `edge` that starts at `start_point`.
    pub fn get_segment<E: PartialEq>(
        &self,
        edge: &E,
        start_point: GridPoint,
        store: &SegmentStore<E>,
    ) -> Option<SegmentId> {
        self.edge_segments.iter().copied().find(|&id| {
            let segment = store.column(id);
            segment.edge() == edge && segment.starts_at(start_point)
        })
    }

    /// Returns the minimum offset of any segment in this list (never above 0).
    pub fn min_offset<E>(&self, store: &SegmentStore<E>) -> i32 {
        self.edge_segments.iter().fold(0, |min, &id| min.min(store.offset(id)))
    }

    /// Returns the maximum offset of any segment in this list (never below 0).
    pub fn max_offset<E>(&self, store: &SegmentStore<E>) -> i32 {
        self.edge_segments.iter().fold(0, |max, &id| max.max(store.offset(id)))
    }

    /// Adds a column segment, widening the covered virtual y range. The range is computed from
    /// the row offsets assigned at the time of the call.
    pub fn add_segment<E>(&mut self, segment: SegmentId, store: &SegmentStore<E>) {
        self.edge_segments.push(segment);
        let column = store.column(segment);
        self.min_y = self.min_y.min(column.virtual_min_y() as i64);
        self.max_y = self.max_y.max(column.virtual_max_y() as i64);
    }

    fn assign_group_offsets<E>(group: &mut ColSegmentList, store: &mut SegmentStore<E>) {
        // sort the column segments left to right
        group.sort(store);

        // use a natural center line (one straight vertex-to-vertex segment) if there is one
        let natural_center = Self::find_natural_center(group, store);
        let center_index = natural_center.unwrap_or(group.edge_segments.len() / 2);
        Self::assign_offsets_around(group, center_index, store);

        // with an arbitrary center, re-center the offsets around the grid line
        if natural_center.is_none() {
            let bias = group.max_offset(store) + group.min_offset(store);
            let adjustment = -bias / 2;
            for &segment in &group.edge_segments {
                let offset = store.offset(segment);
                store.set_offset(segment, offset + adjustment);
            }
        }
    }

    fn sort<E>(&mut self, store: &SegmentStore<E>) {
        if self.is_uniform_flow(store) {
            self.edge_segments
                .sort_by(|&a, &b| store.column(a).compare_to_using_flows(&store.column(b)));
        } else {
            self.edge_segments
                .sort_by(|&a, &b| store.column(a).compare_to_ignore_flows(&store.column(b)));
        }
    }

    fn is_uniform_flow<E>(&self, store: &SegmentStore<E>) -> bool {
        let Some(&first) = self.edge_segments.first() else {
            return true;
        };
        let first_is_upward = store.column(first).is_flowing_upwards();
        self.edge_segments.iter().all(|&id| store.column(id).is_flowing_upwards() == first_is_upward)
    }

    fn assign_offsets_around<E>(
        group: &ColSegmentList,
        center: usize,
        store: &mut SegmentStore<E>,
    ) {
        let mut non_overlapping: Vec<ColSegmentList> = Vec::new();

        // negative offsets for segments left of (and including) the center
        for i in (0..=center).rev() {
            Self::assign_offset(&mut non_overlapping, group.edge_segments[i], -2, store);
        }

        // keep only the 0-offset group: segments right of center must still avoid it
        non_overlapping.truncate(1);

        // positive offsets for segments right of the center
        for i in center + 1..group.edge_segments.len() {
            Self::assign_offset(&mut non_overlapping, group.edge_segments[i], 2, store);
        }
    }

    fn assign_offset<E>(
        non_overlapping: &mut Vec<ColSegmentList>,
        segment: SegmentId,
        step_size: i32,
        store: &mut SegmentStore<E>,
    ) {
        // Walk from the highest-offset group towards the 0 group and stop at the first group the
        // segment overlaps; it joins the next one out. A segment may only take a lower offset if
        // it overlaps none of the higher groups, which keeps the crossing-minimising order.
        let mut i = non_overlapping.len();
        while i > 0 && !non_overlapping[i - 1].has_overlapping_segment(segment, store) {
            i -= 1;
        }
        // `i` is now one past the group we broke at (or 0)
        if i >= non_overlapping.len() {
            non_overlapping.push(ColSegmentList::new(i as i32));
        }
        store.set_offset(segment, i as i32 * step_size);
        non_overlapping[i].add_segment(segment, store);
    }

    fn has_overlapping_segment<E>(&self, segment: SegmentId, store: &SegmentStore<E>) -> bool {
        let column = store.column(segment);
        self.edge_segments.iter().any(|&id| column.overlaps(&store.column(id)))
    }

    fn find_natural_center<E>(group: &ColSegmentList, store: &SegmentStore<E>) -> Option<usize> {
        group.edge_segments.iter().position(|&id| store.points(id.edge).len() == 2)
    }

    fn sort_into_non_overlapping_groups<E>(
        segments: &[SegmentId],
        store: &SegmentStore<E>,
    ) -> Vec<ColSegmentList> {
        let mut groups = Vec::with_capacity(segments.len());
        for &segment in segments {
            Self::group_segment(&mut groups, segment, store);
        }
        groups
    }

    fn group_segment<E>(
        groups: &mut Vec<ColSegmentList>,
        segment: SegmentId,
        store: &SegmentStore<E>,
    ) {
        let mut new_group = ColSegmentList::with_segment(segment, store);
        for i in (0..groups.len()).rev() {
            if new_group.intersects(&groups[i]) {
                let merged = groups.remove(i);
                new_group.merge(merged);
            }
        }
        groups.push(new_group);
    }

    fn merge(&mut self, other: ColSegmentList) {
        self.edge_segments.extend(other.edge_segments);
        self.min_y = self.min_y.min(other.min_y);
        self.max_y = self.max_y.max(other.max_y);
    }
}

#[cfg(test)]
mod tests {
    use super::super::column_segment::test_support::points;
    use super::*;

    fn p(row: i32, col: i32) -> GridPoint {
        GridPoint::new(row, col)
    }

    #[test]
    fn three_parallel_straight_edges_center_on_natural_line() {
        let mut store = SegmentStore::new();
        // all three are straight two-point vertical edges in column 0. Grouping prepends each new
        // segment to the group it merges with (c, b, a), the sort is stable on ties, and the
        // first straight segment (c) is the natural center, so the rest fan out to its right
        let a = store.add_edge("a", points(p(0, 0), &[2]));
        let b = store.add_edge("b", points(p(0, 0), &[2]));
        let c = store.add_edge("c", points(p(0, 0), &[2]));
        let mut list = ColSegmentList::new(0);
        for id in [a, b, c] {
            list.add_segment(id, &store);
        }
        list.assign_offsets(&mut store);
        assert_eq!((store.offset(a), store.offset(b), store.offset(c)), (4, 2, 0));
    }

    #[test]
    fn four_overlapping_bent_edges_are_centered_around_grid_line() {
        let mut store = SegmentStore::new();
        // four edges leaving the same vertex downward then turning right to different columns;
        // no natural center, so offsets are re-centered to -3, -1, 1, 3
        let ids: Vec<_> = (1..=4)
            .map(|k| store.add_edge(k, points(p(0, 0), &[1, k, 1])))
            .collect();
        let mut list = ColSegmentList::new(0);
        for &id in &ids {
            list.add_segment(id, &store);
        }
        list.assign_offsets(&mut store);
        let mut offsets: Vec<i32> = ids.iter().map(|&id| store.offset(id)).collect();
        offsets.sort();
        assert_eq!(offsets, vec![-3, -1, 1, 3]);
        // sorted by where the bottom rows lead: the edge turning furthest right (k = 4) is
        // right-most
        assert_eq!(store.offset(ids[0]), -3);
        assert_eq!(store.offset(ids[3]), 3);
    }

    #[test]
    fn non_overlapping_segments_all_get_zero() {
        let mut store = SegmentStore::new();
        let a = store.add_edge("a", points(p(0, 0), &[1]));
        let b = store.add_edge("b", points(p(5, 0), &[1]));
        let mut list = ColSegmentList::new(0);
        list.add_segment(a, &store);
        list.add_segment(b, &store);
        list.assign_offsets(&mut store);
        assert_eq!((store.offset(a), store.offset(b)), (0, 0));
    }

    #[test]
    fn get_segment_matches_edge_and_start_point() {
        let mut store = SegmentStore::new();
        let a = store.add_edge("a", points(p(0, 0), &[1, 1, 1]));
        let mut list = ColSegmentList::new(0);
        list.add_segment(a, &store);
        assert_eq!(list.get_segment(&"a", p(0, 0), &store), Some(a));
        assert_eq!(list.get_segment(&"a", p(1, 0), &store), None);
        assert_eq!(list.get_segment(&"b", p(0, 0), &store), None);
    }

    #[test]
    fn intersects_uses_virtual_ranges() {
        let mut store = SegmentStore::new();
        let a = store.add_edge("a", points(p(0, 0), &[1]));
        let b = store.add_edge("b", points(p(1, 0), &[1]));
        let c = store.add_edge("c", points(p(3, 0), &[1]));
        let la = ColSegmentList::with_segment(a, &store);
        let lb = ColSegmentList::with_segment(b, &store);
        let lc = ColSegmentList::with_segment(c, &store);
        // a ends at row 1 (-1 bias) and b starts at row 1 (+1 bias): disjoint
        assert!(!la.intersects(&lb));
        assert!(!lb.intersects(&lc));
        assert!(la.intersects(&la));
        assert_eq!(la.col(), 0);
    }
}

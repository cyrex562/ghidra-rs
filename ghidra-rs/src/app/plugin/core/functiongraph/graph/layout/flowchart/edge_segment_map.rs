//! Port of `ghidra.app.plugin.core.functiongraph.graph.layout.flowchart.EdgeSegmentMap`.

use std::collections::HashMap;

use crate::graph::viewer::layout::grid_point::GridPoint;

use super::col_segment_list::ColSegmentList;
use super::column_segment::ColumnSegment;
use super::edge_segment::SegmentStore;
use super::row_segment_list::RowSegmentList;

/// Organizes every edge's segments into per-row and per-column lists and assigns offsets to
/// overlapping segments within each row or column. Offsets are x or y distances later added to a
/// row segment's y coordinate or a column segment's x coordinate so they don't overlap in layout
/// space. They must be computed before the grid is sized, because they affect row and column
/// sizes.
///
/// The map owns the [`SegmentStore`] holding all segments; the lists hold
/// [`SegmentId`](super::edge_segment::SegmentId)s into it, resolved with [`store`](Self::store).
#[derive(Debug, Clone)]
pub struct EdgeSegmentMap<E> {
    store: SegmentStore<E>,
    row_segment_map: HashMap<i32, RowSegmentList>,
    col_segment_map: HashMap<i32, ColSegmentList>,
}

impl<E> EdgeSegmentMap<E> {
    /// Builds the segments for every edge and assigns their offsets.
    ///
    /// Java takes a `GridLocationMap` and reads `grid.edges()` with `grid.getArticulations(edge)`
    /// for each; this takes exactly those `(edge, articulation points)` pairs.
    pub fn new(edges: impl IntoIterator<Item = (E, Vec<GridPoint>)>) -> Self {
        let mut map = Self {
            store: SegmentStore::new(),
            row_segment_map: HashMap::new(),
            col_segment_map: HashMap::new(),
        };
        map.create_edge_segments(edges);
        map.assign_edge_segment_offsets();
        map
    }

    /// The store that owns every segment; resolves the ids held by the row and column lists.
    pub fn store(&self) -> &SegmentStore<E> {
        &self.store
    }

    /// Returns all row segment lists.
    pub fn row_segments(&self) -> impl Iterator<Item = &RowSegmentList> {
        self.row_segment_map.values()
    }

    /// Returns all column segment lists.
    pub fn col_segments(&self) -> impl Iterator<Item = &ColSegmentList> {
        self.col_segment_map.values()
    }

    /// Finds the column segment of `edge` that starts at `grid_point`.
    pub fn get_column_segment(&self, edge: &E, grid_point: GridPoint) -> Option<ColumnSegment<'_, E>>
    where
        E: PartialEq,
    {
        let col_segments = self.col_segment_map.get(&grid_point.col)?;
        col_segments
            .get_segment(edge, grid_point, &self.store)
            .map(|id| self.store.column(id))
    }

    /// Clears the row and column lists.
    pub fn dispose(&mut self) {
        self.row_segment_map.clear();
        self.col_segment_map.clear();
    }

    fn create_edge_segments(&mut self, edges: impl IntoIterator<Item = (E, Vec<GridPoint>)>) {
        for (edge, grid_points) in edges {
            let first = self.store.add_edge(edge, grid_points);
            let mut col_segment = self.store.column(first);
            let mut columns = vec![col_segment.id()];
            let mut rows = Vec::new();
            while let Some(row_segment) = col_segment.next_segment() {
                rows.push(row_segment.id());
                col_segment = row_segment.next_segment();
                columns.push(col_segment.id());
            }
            for id in columns {
                let col = self.store.column(id).col();
                self.col_segment_map
                    .entry(col)
                    .or_insert_with(|| ColSegmentList::new(col))
                    .add_segment(id, &self.store);
            }
            for id in rows {
                let row = self.store.row(id).row();
                self.row_segment_map
                    .entry(row)
                    .or_insert_with(|| RowSegmentList::new(row))
                    .add_segment(id);
            }
        }
    }

    fn assign_edge_segment_offsets(&mut self) {
        // rows first: column overlap tests read the offsets of the attached rows
        for row_segments in self.row_segment_map.values_mut() {
            row_segments.assign_offsets(&mut self.store);
        }
        for col_segments in self.col_segment_map.values() {
            col_segments.assign_offsets(&mut self.store);
        }
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
    fn builds_row_and_column_lists_and_assigns_offsets() {
        // two edges leaving vertex (0,0) down then right along row 1 to columns 2 and 3
        let map = EdgeSegmentMap::new(vec![
            ("a", points(p(0, 0), &[1, 2, 1])),
            ("b", points(p(0, 0), &[1, 3, 1])),
        ]);
        let store = map.store();

        let rows: Vec<_> = map.row_segments().collect();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].row(), 1);
        assert_eq!(rows[0].segments().len(), 2);
        // the rows overlap, so one of them is pushed down by 2
        assert_eq!(rows[0].min_offset(store), 0);
        assert_eq!(rows[0].max_offset(store), 2);

        let mut cols: Vec<i32> = map.col_segments().map(|c| c.col()).collect();
        cols.sort();
        assert_eq!(cols, vec![0, 2, 3]);

        // b reaches further right, so its row sorts above a's (offset 0) to avoid a crossing
        let b_row = map.get_column_segment(&"b", p(0, 0)).unwrap().next_segment().unwrap();
        let a_row = map.get_column_segment(&"a", p(0, 0)).unwrap().next_segment().unwrap();
        assert_eq!((b_row.offset(), a_row.offset()), (0, 2));

        // the two start columns in column 0 overlap and are centered around the grid line
        let a_col = map.get_column_segment(&"a", p(0, 0)).unwrap();
        let b_col = map.get_column_segment(&"b", p(0, 0)).unwrap();
        assert_eq!((a_col.offset(), b_col.offset()), (-1, 1));
    }

    #[test]
    fn get_column_segment_finds_later_columns() {
        let map = EdgeSegmentMap::new(vec![("a", points(p(0, 0), &[1, 2, 1]))]);
        let end = map.get_column_segment(&"a", p(1, 2)).unwrap();
        assert!(end.is_end_segment());
        assert!(map.get_column_segment(&"a", p(1, 0)).is_none());
        assert!(map.get_column_segment(&"z", p(0, 0)).is_none());
    }

    #[test]
    fn dispose_clears_lists() {
        let mut map = EdgeSegmentMap::new(vec![("a", points(p(0, 0), &[1, 2, 1]))]);
        map.dispose();
        assert_eq!(map.row_segments().count(), 0);
        assert_eq!(map.col_segments().count(), 0);
        assert!(map.get_column_segment(&"a", p(0, 0)).is_none());
    }
}

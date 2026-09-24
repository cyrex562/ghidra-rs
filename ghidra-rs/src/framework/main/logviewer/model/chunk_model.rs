use std::slice;

use super::chunk::Chunk;
use super::pair::Pair;

/// Stores all chunks read in by the chunk reader. The model is responsible for handling all
/// interaction with the list of chunks.
///
/// Port of `ghidra.framework.main.logviewer.model.ChunkModel`. Java's `Iterable<Chunk>` is
/// expressed as [`ChunkModel::iter`] plus `IntoIterator for &ChunkModel`.
#[derive(Debug, Clone, Default)]
pub struct ChunkModel {
    /// All chunks currently in the table.
    chunks: Vec<Chunk>,
    /// Start byte of the row(s) currently selected in the table. Required for when the selected
    /// rows are scrolled out of view (and no chunk exists for them) but must be restored when
    /// that chunk is loaded into view again.
    pub selected_byte_start: i64,
    /// End byte of the row(s) currently selected in the table.
    pub selected_byte_end: i64,
}

impl ChunkModel {
    /// The maximum number of lines that should be read into a chunk.
    pub const NUM_LINES: i32 = 250;

    /// The maximum number of chunks to display. It can be safely increased; it is not
    /// recommended to set this less than 3.
    pub const MAX_VISIBLE_CHUNKS: i32 = 3;

    /// Creates an empty model.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds the given chunk to the end of the model.
    pub fn add(&mut self, chunk: Chunk) {
        self.chunks.push(chunk);
    }

    /// Adds a chunk at the given index.
    ///
    /// # Panics
    /// Panics if `index > self.size()` (Java throws `IndexOutOfBoundsException`).
    pub fn add_at(&mut self, index: usize, chunk: Chunk) {
        self.chunks.insert(index, chunk);
    }

    /// Removes and returns the chunk at the given index, or `None` if the index is out of range.
    pub fn remove(&mut self, index: i32) -> Option<Chunk> {
        let i = self.index(index)?;
        Some(self.chunks.remove(i))
    }

    /// Clears all chunks from the model.
    pub fn clear(&mut self) {
        self.chunks.clear();
    }

    /// Returns the number of chunks in the model.
    pub fn size(&self) -> usize {
        self.chunks.len()
    }

    /// Returns the chunk at the given index, or `None` if the index is out of range.
    pub fn get(&self, index: i32) -> Option<&Chunk> {
        self.index(index).map(|i| &self.chunks[i])
    }

    /// Returns the number of chunks in the model (Java: `getNumChunks`, same as
    /// [`size`](Self::size)).
    pub fn num_chunks(&self) -> usize {
        self.chunks.len()
    }

    /// Returns an iterator over the chunks, in order.
    pub fn iter(&self) -> slice::Iter<'_, Chunk> {
        self.chunks.iter()
    }

    /// Returns the start/end byte positions within the input file for the given table row, or
    /// `None` if the row is not within any loaded chunk.
    ///
    /// Counts lines chunk by chunk until reaching the chunk holding `row`, then looks the row up
    /// in that chunk's row map.
    pub fn file_position_for_row(&self, row: i32) -> Option<Pair> {
        let mut total_lines = 0;
        for chunk in self {
            if row < chunk.lines_in_chunk + total_lines {
                let my_row = chunk.lines_in_chunk - ((chunk.lines_in_chunk + total_lines) - row);
                return chunk.row_to_file_position_map.get(&my_row).copied();
            }
            total_lines += chunk.lines_in_chunk;
        }
        None
    }

    /// Searches the loaded chunks for one containing `selected_byte`; if found, returns the
    /// table row where it resides, otherwise `-1`.
    pub fn row_for_byte_pos(&self, selected_byte: i64) -> i32 {
        let mut total_lines = 0;
        for chunk in self {
            // See if this byte is in this chunk before doing anything.
            if selected_byte >= chunk.start && selected_byte <= chunk.end {
                // We know our byte is in this chunk, so now find out exactly which row it's in.
                for (key, value) in &chunk.row_to_file_position_map {
                    if selected_byte >= value.get_start() && selected_byte <= value.get_end() {
                        return key + total_lines;
                    }
                }
            }
            total_lines += chunk.lines_in_chunk;
        }
        -1
    }

    fn index(&self, index: i32) -> Option<usize> {
        usize::try_from(index).ok().filter(|&i| i < self.chunks.len())
    }
}

impl<'a> IntoIterator for &'a ChunkModel {
    type Item = &'a Chunk;
    type IntoIter = slice::Iter<'a, Chunk>;

    fn into_iter(self) -> Self::IntoIter {
        self.chunks.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A chunk of `lines` lines of `line_len` bytes each, starting at byte `start`.
    fn chunk(start: i64, lines: i32, line_len: i64) -> Chunk {
        let mut c = Chunk { start, lines_in_chunk: lines, ..Chunk::default() };
        for row in 0..lines {
            let s = start + row as i64 * line_len;
            c.row_to_file_position_map.insert(row, Pair::new(s, s + line_len - 1));
        }
        c.end = start + lines as i64 * line_len - 1;
        c
    }

    fn model() -> ChunkModel {
        let mut m = ChunkModel::new();
        m.add(chunk(0, 3, 10)); // rows 0..3, bytes 0..=29
        m.add(chunk(30, 2, 5)); // rows 3..5, bytes 30..=39
        m
    }

    #[test]
    fn constants_match_java() {
        assert_eq!(ChunkModel::NUM_LINES, 250);
        assert_eq!(ChunkModel::MAX_VISIBLE_CHUNKS, 3);
    }

    #[test]
    fn add_insert_get_remove_and_clear() {
        let mut m = model();
        assert_eq!(m.size(), 2);
        assert_eq!(m.num_chunks(), 2);

        m.add_at(0, chunk(100, 1, 1));
        assert_eq!(m.get(0).unwrap().start, 100);
        assert_eq!(m.get(1).unwrap().start, 0);

        // Out-of-range get/remove return null in Java.
        assert!(m.get(-1).is_none());
        assert!(m.get(3).is_none());
        assert!(m.remove(3).is_none());
        assert!(m.remove(-1).is_none());
        assert_eq!(m.size(), 3);

        assert_eq!(m.remove(0).unwrap().start, 100);
        assert_eq!(m.size(), 2);

        m.clear();
        assert_eq!(m.size(), 0);
        assert!(m.iter().next().is_none());
    }

    #[test]
    fn iterates_every_chunk_in_order() {
        let m = model();
        let starts: Vec<i64> = m.iter().map(|c| c.start).collect();
        assert_eq!(starts, [0, 30]);
        let via_into: Vec<i64> = (&m).into_iter().map(|c| c.start).collect();
        assert_eq!(via_into, starts);
    }

    #[test]
    fn file_position_for_row_spans_chunks() {
        let m = model();
        assert_eq!(m.file_position_for_row(0), Some(Pair::new(0, 9)));
        assert_eq!(m.file_position_for_row(2), Some(Pair::new(20, 29)));
        assert_eq!(m.file_position_for_row(3), Some(Pair::new(30, 34)));
        assert_eq!(m.file_position_for_row(4), Some(Pair::new(35, 39)));
        assert_eq!(m.file_position_for_row(5), None);
        assert_eq!(ChunkModel::new().file_position_for_row(0), None);
    }

    #[test]
    fn row_for_byte_pos_finds_row_or_minus_one() {
        let m = model();
        assert_eq!(m.row_for_byte_pos(0), 0);
        assert_eq!(m.row_for_byte_pos(15), 1);
        assert_eq!(m.row_for_byte_pos(29), 2);
        assert_eq!(m.row_for_byte_pos(30), 3);
        assert_eq!(m.row_for_byte_pos(39), 4);
        assert_eq!(m.row_for_byte_pos(40), -1);
        assert_eq!(m.row_for_byte_pos(-5), -1);
    }

    #[test]
    fn selection_fields_are_public_state() {
        let mut m = ChunkModel::new();
        m.selected_byte_start = 12;
        m.selected_byte_end = 34;
        assert_eq!((m.selected_byte_start, m.selected_byte_end), (12, 34));
    }
}

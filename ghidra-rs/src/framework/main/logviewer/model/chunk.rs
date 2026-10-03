use std::collections::HashMap;

use super::pair::Pair;

/// The basic unit of text displayed in the log viewer table.
///
/// Port of `ghidra.framework.main.logviewer.model.Chunk`.
///
/// A chunk does NOT contain the actual text being displayed; rather it contains metadata
/// describing the text (start/end byte positions, number of lines in the chunk, etc...).
/// Chunks are transient -- they are created and destroyed as different sections of the file are
/// required for display.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Chunk {
    /// Start byte position of this chunk.
    pub start: i64,
    /// End byte position of this chunk.
    pub end: i64,
    /// Maps a line within this chunk to a byte range within the file. If this chunk contains 20
    /// lines, `row_to_file_position_map[&5]` is the byte range of the 6th line.
    ///
    /// The line numbers in this map do NOT correspond to line numbers within the file, only
    /// within the chunk.
    pub row_to_file_position_map: HashMap<i32, Pair>,
    /// The number of text lines represented by this chunk. This should always match
    /// [`ChunkModel::NUM_LINES`](super::chunk_model::ChunkModel::NUM_LINES), except when reading
    /// the end of the file when there may not be that many lines left.
    pub lines_in_chunk: i32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_chunk_is_empty_like_java_defaults() {
        let chunk = Chunk::default();
        assert_eq!(chunk.start, 0);
        assert_eq!(chunk.end, 0);
        assert_eq!(chunk.lines_in_chunk, 0);
        assert!(chunk.row_to_file_position_map.is_empty());
    }

    #[test]
    fn fields_are_publicly_mutable() {
        let mut chunk = Chunk::default();
        chunk.start = 100;
        chunk.end = 199;
        chunk.row_to_file_position_map.insert(0, Pair::new(100, 149));
        chunk.row_to_file_position_map.insert(1, Pair::new(150, 199));
        chunk.lines_in_chunk = 2;
        assert_eq!(chunk.row_to_file_position_map[&1].get_start(), 150);
        assert_eq!(chunk.lines_in_chunk, 2);
    }
}

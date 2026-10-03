//! Port of `db.buffers.ChangeMap`.
//!
//! Facilitates decoding change-data to determine whether a specific buffer was modified by the
//! corresponding buffer file version. See [`super::change_map_file::ChangeMapFile`] for the
//! producer of this map's underlying byte data.
//!
//! The Java class is `public`, concrete, and has no `extends` clause -- it is a plain leaf data
//! holder wrapping a bitmap (`byte[]`) and a derived `maxIndex`. This is ported directly as a
//! struct; there is no inheritance to decouple via composition here.

/// A bitmap recording which buffer indexes have changed. Mirrors `db.buffers.ChangeMap`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeMap {
    map_data: Vec<u8>,
    max_index: i64,
}

impl ChangeMap {
    /// Constructs a change map over the given map data. Mirrors `ChangeMap(byte[])`.
    ///
    /// `max_index` is computed as `(mapData.length * 8) - 1`, matching Java's `int` arithmetic
    /// (kept here as `i64` so an empty map's `-1` sentinel is exact rather than wrapping, as it
    /// would if this were computed in `usize`).
    pub fn new(map_data: Vec<u8>) -> Self {
        let max_index = (map_data.len() as i64) * 8 - 1;
        Self { map_data, max_index }
    }

    /// Returns the underlying change map data as a byte slice. Mirrors `getData()`.
    pub fn get_data(&self) -> &[u8] {
        &self.map_data
    }

    /// Adds the specified map data to this map within the size constraints of this map. Mirrors
    /// `addChangeMapData(byte[])`.
    pub fn add_change_map_data(&mut self, other_map_data: &[u8]) {
        let limit = self.map_data.len().min(other_map_data.len());
        for byte_offset in 0..limit {
            self.map_data[byte_offset] |= other_map_data[byte_offset];
        }
    }

    /// Flags all indexes as changed within this change map. Index values outside the size
    /// constraints of this map are ignored. Mirrors `setChangedIndexes(int[])`.
    pub fn set_changed_indexes(&mut self, indexes: &[i32]) {
        for &index in indexes {
            if index as i64 > self.max_index {
                continue;
            }
            let byte_offset = (index / 8) as usize;
            let bit_mask = 1u8 << (index % 8);
            self.map_data[byte_offset] |= bit_mask;
        }
    }

    /// Flags all indexes as unchanged within this change map. Index values outside the size
    /// constraints of this map are ignored. Mirrors `setUnchangedIndexes(int[])`.
    pub fn set_unchanged_indexes(&mut self, indexes: &[i32]) {
        for &index in indexes {
            if index as i64 > self.max_index {
                continue;
            }
            let byte_offset = (index / 8) as usize;
            let bit_mask = !(1u8 << (index % 8));
            self.map_data[byte_offset] &= bit_mask;
        }
    }

    /// Returns true if the change map data indicates that the specified buffer has been
    /// modified. Mirrors `hasChanged(int)`.
    ///
    /// Note: the Java signature takes `mapData == null` into account even though the field is
    /// assigned unconditionally in the constructor and is never reassigned -- it can only be
    /// null if the constructor itself was passed `null`. Since this port's `map_data` is a
    /// non-nullable `Vec<u8>`, that branch is unreachable here and is intentionally omitted; the
    /// `index > maxIndex` half of the faithfully-ported condition remains below.
    pub fn has_changed(&self, index: i32) -> bool {
        if index as i64 > self.max_index {
            return true; // must be a new buffer index
        }
        let byte_offset = (index / 8) as usize;
        let bit_mask = 1u8 << (index % 8);
        (self.map_data[byte_offset] & bit_mask) != 0
    }

    /// Returns true if the specified index is within the bounds of this map. Mirrors
    /// `containsIndex(int)`.
    pub fn contains_index(&self, index: i32) -> bool {
        (index as i64) <= self.max_index
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_computes_max_index_from_byte_length() {
        let map = ChangeMap::new(vec![0u8; 2]);
        // 2 bytes * 8 bits - 1 = 15
        assert!(map.contains_index(15));
        assert!(!map.contains_index(16));
    }

    #[test]
    fn empty_map_data_has_max_index_of_negative_one() {
        // (0 * 8) - 1 == -1: no index is ever "contained", and hasChanged() always reports
        // true (treated as a new buffer index).
        let map = ChangeMap::new(vec![]);
        assert!(!map.contains_index(0));
        assert!(map.has_changed(0));
    }

    #[test]
    fn get_data_returns_underlying_bytes() {
        let map = ChangeMap::new(vec![0xAA, 0x55]);
        assert_eq!(map.get_data(), &[0xAA, 0x55]);
    }

    #[test]
    fn set_changed_indexes_sets_correct_bits() {
        let mut map = ChangeMap::new(vec![0u8; 2]);
        map.set_changed_indexes(&[0, 8, 15]);
        // index 0 -> byte 0 bit 0; index 8 -> byte 1 bit 0; index 15 -> byte 1 bit 7
        assert_eq!(map.get_data(), &[0b0000_0001, 0b1000_0001]);
        assert!(map.has_changed(0));
        assert!(map.has_changed(8));
        assert!(map.has_changed(15));
        assert!(!map.has_changed(1));
    }

    #[test]
    fn set_changed_indexes_ignores_out_of_range() {
        let mut map = ChangeMap::new(vec![0u8; 1]); // max_index = 7
        map.set_changed_indexes(&[8, 100]);
        assert_eq!(map.get_data(), &[0]);
    }

    #[test]
    fn set_unchanged_indexes_clears_correct_bits() {
        let mut map = ChangeMap::new(vec![0xFFu8; 1]);
        map.set_unchanged_indexes(&[0, 2, 4]);
        assert_eq!(map.get_data(), &[0b1110_1010]);
    }

    #[test]
    fn set_unchanged_indexes_ignores_out_of_range() {
        let mut map = ChangeMap::new(vec![0xFFu8; 1]); // max_index = 7
        map.set_unchanged_indexes(&[8, 50]);
        assert_eq!(map.get_data(), &[0xFF]);
    }

    #[test]
    fn has_changed_beyond_max_index_reports_true() {
        let map = ChangeMap::new(vec![0u8; 1]); // max_index = 7
        assert!(map.has_changed(8));
        assert!(map.has_changed(1000));
    }

    #[test]
    fn add_change_map_data_ors_within_shorter_length() {
        let mut map = ChangeMap::new(vec![0b0000_1111, 0b0000_0000]);
        // Other map is shorter (1 byte): only byte 0 is OR'd in; byte 1 is untouched.
        map.add_change_map_data(&[0b1111_0000]);
        assert_eq!(map.get_data(), &[0b1111_1111, 0b0000_0000]);
    }

    #[test]
    fn add_change_map_data_ignores_bytes_beyond_this_maps_length() {
        // Other map is longer than this map: extra bytes are ignored, mirroring Java's `limit =
        // min(this.length, other.length)` bound.
        let mut map = ChangeMap::new(vec![0u8; 1]);
        map.add_change_map_data(&[0b0000_0001, 0xFF, 0xFF]);
        assert_eq!(map.get_data(), &[0b0000_0001]);
    }

    #[test]
    fn contains_index_respects_map_bounds() {
        let map = ChangeMap::new(vec![0u8; 4]); // max_index = 31
        assert!(map.contains_index(0));
        assert!(map.contains_index(31));
        assert!(!map.contains_index(32));
    }

    #[test]
    fn negative_index_is_treated_as_within_bounds() {
        // Java quirk: `containsIndex` only checks `index <= maxIndex`, with no lower bound
        // check. A negative index therefore reports as "contained" for any non-degenerate map
        // (maxIndex >= 0), even though it is not a valid buffer index. This port faithfully
        // reproduces that -- it does not add a `>= 0` guard that the original lacks.
        let map = ChangeMap::new(vec![0u8; 1]); // max_index = 7
        assert!(map.contains_index(-1));
    }
}

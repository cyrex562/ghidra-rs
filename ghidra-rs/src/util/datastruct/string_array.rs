use super::array::Array;
use super::data_table::DataTable;

/// Minimum backing-array capacity (number of string slots).
pub const MIN_SIZE: usize = 4;

/// An array of `String` that grows as needed, backed by a single packed byte
/// buffer (rather than one allocation per string).
///
/// Port of `ghidra.util.datastruct.StringArray`. An index that was never
/// written (or was most recently `remove`d) reads back as `None`.
///
/// # Faithfully-reproduced Java quirks
///
/// `StringArray.java` computes how many bytes to reserve/copy for a string
/// using `value.length()` -- the number of **UTF-16 code units** -- not the
/// number of bytes in `value.getBytes()`. For any string containing
/// non-ASCII (multi-byte UTF-8) characters, the UTF-8 encoding is longer
/// than the UTF-16 unit count, so the stored bytes are silently truncated
/// into a corrupt/incomplete sequence (see [`Self::put`] and the
/// `put_truncates_multi_byte_utf8_strings` test below).
///
/// Additionally, the string length is stored as a Java `short` via
/// `(short)len`. For strings longer than `i16::MAX` (32767) UTF-16 units,
/// this wraps around to a negative value, and `get` (which reads the length
/// back sign-extended, not as unsigned) then treats the string as
/// zero-length and returns `""` instead of the real content (see
/// `get_returns_empty_string_for_huge_strings_due_to_short_overflow` below).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StringArray {
    bytes: Vec<u8>,
    starts: Vec<i32>,
    lengths: Vec<i16>,
    total_space_allocated: i32,
    next_free: i32,
    last_start: i32,
}

impl StringArray {
    /// Creates a new, empty `StringArray`.
    pub fn new() -> Self {
        Self {
            bytes: vec![0; 10],
            starts: vec![0; MIN_SIZE],
            lengths: vec![0; MIN_SIZE],
            total_space_allocated: 0,
            next_free: 1,
            last_start: -1,
        }
    }

    /// Puts `value` at `index`, growing the backing storage if necessary.
    ///
    /// Passing `None` is equivalent to calling [`Self::remove`].
    pub fn put(&mut self, index: usize, value: Option<&str>) {
        let Some(value) = value else {
            self.remove(index);
            return;
        };

        if index >= self.starts.len() {
            self.adjust_array_sizes(std::cmp::max(index as i64 + 1, self.starts.len() as i64 * 2));
        }
        if index as i32 > self.last_start {
            self.last_start = index as i32;
        }

        // Java: `int len = value.length();` -- UTF-16 code unit count, NOT byte count. This is
        // the root of the multi-byte-UTF-8 truncation bug documented on the struct.
        let len = value.encode_utf16().count() as i32;

        if self.starts[index] > 0 {
            if self.lengths[index] as i32 >= len {
                self.total_space_allocated -= self.lengths[index] as i32 - len;
            } else {
                self.total_space_allocated -= self.lengths[index] as i32;
                self.starts[index] = self.alloc_space(len);
            }
        } else {
            self.starts[index] = self.alloc_space(len);
        }
        // Java: `lengths[index] = (short)len;` -- narrows/wraps for len > 32767.
        self.lengths[index] = len as i16;

        let str_bytes = value.as_bytes();
        // Java: `System.arraycopy(strBytes, 0, bytes, starts[index], len)` -- copies `len`
        // (UTF-16 units) bytes of the UTF-8 encoding, truncating whenever the encoding is
        // longer than the unit count (any non-ASCII content).
        let copy_len = (len as usize).min(str_bytes.len());
        let start = self.starts[index] as usize;
        self.bytes[start..start + copy_len].copy_from_slice(&str_bytes[..copy_len]);
    }

    /// Returns the string at `index`, or `None` if not initialized to
    /// another value (including indexes past the end of the backing
    /// storage).
    ///
    /// Bytes that were truncated by the [`Self::put`] bug (see struct docs)
    /// are decoded leniently (invalid sequences become `U+FFFD`) rather than
    /// panicking, mirroring Java's non-throwing `new String(bytes, start,
    /// len)` decode.
    pub fn get(&self, index: usize) -> Option<String> {
        if index >= self.starts.len() {
            return None;
        }
        let start = self.starts[index];
        // Java: `int len = lengths[index];` -- sign-extended, NOT masked with 0xFFFF. This is
        // the root of the huge-string-returns-empty-string bug documented on the struct.
        let len = self.lengths[index] as i32;
        if start > 0 {
            if len > 0 {
                let s = start as usize;
                let l = len as usize;
                return Some(String::from_utf8_lossy(&self.bytes[s..s + l]).into_owned());
            }
            return Some(String::new());
        }
        None
    }

    /// Removes the string at `index`. A no-op if `index` is beyond the
    /// current backing storage.
    pub fn remove(&mut self, index: usize) {
        if index < self.starts.len() && self.starts[index] > 0 {
            self.total_space_allocated -= self.lengths[index] as i32;
            self.starts[index] = 0;
            if self.total_space_allocated < self.bytes.len() as i32 / 4 {
                self.adjust_space(self.total_space_allocated * 2);
            }
        }

        if index as i32 == self.last_start {
            self.find_last_start();
            if self.last_start < self.starts.len() as i32 / 4 {
                self.shrink_arrays(self.last_start * 2);
            }
        }
    }

    fn find_last_start(&mut self) {
        let mut i = self.last_start;
        while i >= 0 {
            if self.starts[i as usize] != 0 {
                self.last_start = i;
                return;
            }
            i -= 1;
        }
        self.last_start = -1;
    }

    fn adjust_array_sizes(&mut self, size: i64) {
        let size = if size < MIN_SIZE as i64 { MIN_SIZE } else { size as usize };
        self.starts.resize(size, 0);
        self.lengths.resize(size, 0);
    }

    /// Shrinks `starts`/`lengths` to `capacity` (clamped to a minimum of 4),
    /// as items at the end of the list are removed.
    fn shrink_arrays(&mut self, capacity: i32) {
        let size = std::cmp::max(capacity, 4) as usize;
        self.starts.resize(size, 0);
        self.lengths.resize(size, 0);
    }

    /// Allocates space in the byte buffer for storing a string of `size`
    /// bytes, growing the buffer first if necessary. Returns the start
    /// position in the buffer.
    fn alloc_space(&mut self, size: i32) -> i32 {
        if size > self.bytes.len() as i32 - self.next_free {
            self.adjust_space(2 * (self.total_space_allocated + size));
        }
        let ret = self.next_free;
        self.next_free += size;
        self.total_space_allocated += size;
        ret
    }

    /// Adjusts the byte buffer size as storage requirements change,
    /// compacting all live strings into the new buffer.
    fn adjust_space(&mut self, new_size: i32) {
        let new_size = std::cmp::max(new_size, 10) as usize;
        let mut new_bytes = vec![0u8; new_size];
        let mut pos = 1i32;
        for i in 0..self.starts.len() {
            if self.starts[i] > 0 {
                // Java: `lengths[i] & 0xFFFF` -- reinterprets the (possibly negative, per the
                // huge-string bug) short as an unsigned 16-bit byte count for the purposes of
                // buffer compaction, unlike `get`'s sign-extended read.
                let len = (self.lengths[i] as u16) as i32;
                let src = self.starts[i] as usize;
                let len_usize = len as usize;
                new_bytes[pos as usize..pos as usize + len_usize]
                    .copy_from_slice(&self.bytes[src..src + len_usize]);
                self.starts[i] = pos;
                pos += len;
            }
        }
        self.next_free = pos;
        self.bytes = new_bytes;
    }
}

impl Default for StringArray {
    fn default() -> Self {
        Self::new()
    }
}

impl Array for StringArray {
    fn remove(&mut self, index: usize) {
        StringArray::remove(self, index);
    }

    fn get_last_non_empty_index(&self) -> i32 {
        self.last_start
    }

    fn copy_data_to(&self, index: usize, table: &mut dyn DataTable, to_index: i32, to_col: i32) {
        table.put_string(to_index, to_col, self.get(index).unwrap_or_default());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::any::Any;
    use std::collections::HashMap;

    #[derive(Default)]
    struct MockDataTable {
        strings: HashMap<(i32, i32), String>,
    }

    impl DataTable for MockDataTable {
        fn remove_row(&mut self, _row: i32) {}
        fn copy_row_to(&self, _row: i32, _table: &mut dyn DataTable, _to_row: i32) {}
        fn put_boolean(&mut self, _row: i32, _col: i32, _value: bool) {}
        fn get_boolean(&self, _row: i32, _col: i32) -> bool {
            false
        }
        fn put_byte(&mut self, _row: i32, _col: i32, _value: i8) {}
        fn get_byte(&self, _row: i32, _col: i32) -> i8 {
            0
        }
        fn put_short(&mut self, _row: i32, _col: i32, _value: i16) {}
        fn get_short(&self, _row: i32, _col: i32) -> i16 {
            0
        }
        fn put_int(&mut self, _row: i32, _col: i32, _value: i32) {}
        fn get_int(&self, _row: i32, _col: i32) -> i32 {
            0
        }
        fn put_long(&mut self, _row: i32, _col: i32, _value: i64) {}
        fn get_long(&self, _row: i32, _col: i32) -> i64 {
            0
        }
        fn put_double(&mut self, _row: i32, _col: i32, _value: f64) {}
        fn get_double(&self, _row: i32, _col: i32) -> f64 {
            0.0
        }
        fn put_float(&mut self, _row: i32, _col: i32, _value: f32) {}
        fn get_float(&self, _row: i32, _col: i32) -> f32 {
            0.0
        }
        fn put_string(&mut self, row: i32, col: i32, value: String) {
            self.strings.insert((row, col), value);
        }
        fn get_string(&self, row: i32, col: i32) -> String {
            self.strings.get(&(row, col)).cloned().unwrap_or_default()
        }
        fn put_object(&mut self, _row: i32, _col: i32, _value: Box<dyn Any>) {}
        fn get_object(&self, _row: i32, _col: i32) -> &dyn Any {
            &()
        }
        fn put_byte_array(&mut self, _row: i32, _col: i32, _value: Vec<u8>) {}
        fn get_byte_array(&self, _row: i32, _col: i32) -> Vec<u8> {
            Vec::new()
        }
        fn put_short_array(&mut self, _row: i32, _col: i32, _value: Vec<i16>) {}
        fn get_short_array(&self, _row: i32, _col: i32) -> Vec<i16> {
            Vec::new()
        }
        fn put_int_array(&mut self, _row: i32, _col: i32, _value: Vec<i32>) {}
        fn get_int_array(&self, _row: i32, _col: i32) -> Vec<i32> {
            Vec::new()
        }
        fn put_long_array(&mut self, _row: i32, _col: i32, _value: Vec<i64>) {}
        fn get_long_array(&self, _row: i32, _col: i32) -> Vec<i64> {
            Vec::new()
        }
        fn put_float_array(&mut self, _row: i32, _col: i32, _value: Vec<f32>) {}
        fn get_float_array(&self, _row: i32, _col: i32) -> Vec<f32> {
            Vec::new()
        }
        fn put_double_array(&mut self, _row: i32, _col: i32, _value: Vec<f64>) {}
        fn get_double_array(&self, _row: i32, _col: i32) -> Vec<f64> {
            Vec::new()
        }
        fn put_string_array(&mut self, _row: i32, _col: i32, _value: Vec<String>) {}
        fn get_string_array(&self, _row: i32, _col: i32) -> Vec<String> {
            Vec::new()
        }
    }

    #[test]
    fn new_array_reads_back_none() {
        let arr = StringArray::new();
        assert_eq!(arr.get(0), None);
        assert_eq!(arr.get(1000), None);
        assert_eq!(arr.get_last_non_empty_index(), -1);
    }

    #[test]
    fn put_and_get_roundtrip_ascii() {
        let mut arr = StringArray::new();
        arr.put(2, Some("hello"));
        assert_eq!(arr.get(2), Some("hello".to_string()));
        assert_eq!(arr.get_last_non_empty_index(), 2);
    }

    #[test]
    fn put_empty_string_roundtrips() {
        let mut arr = StringArray::new();
        arr.put(0, Some(""));
        assert_eq!(arr.get(0), Some(String::new()));
    }

    #[test]
    fn put_grows_backing_storage_past_min_size() {
        let mut arr = StringArray::new();
        arr.put(100, Some("far"));
        assert_eq!(arr.get(100), Some("far".to_string()));
        assert_eq!(arr.get_last_non_empty_index(), 100);
        assert_eq!(arr.get(50), None);
    }

    #[test]
    fn overwrite_with_shorter_string_reuses_space() {
        let mut arr = StringArray::new();
        arr.put(0, Some("a longer string"));
        arr.put(0, Some("short"));
        assert_eq!(arr.get(0), Some("short".to_string()));
    }

    #[test]
    fn overwrite_with_longer_string_reallocates() {
        let mut arr = StringArray::new();
        arr.put(0, Some("hi"));
        arr.put(0, Some("a much longer replacement string"));
        assert_eq!(arr.get(0), Some("a much longer replacement string".to_string()));
    }

    #[test]
    fn put_none_is_equivalent_to_remove() {
        let mut arr = StringArray::new();
        arr.put(1, Some("x"));
        arr.put(1, None);
        assert_eq!(arr.get(1), None);
        assert_eq!(arr.get_last_non_empty_index(), -1);
    }

    #[test]
    fn remove_updates_last_non_empty_index_to_new_max() {
        let mut arr = StringArray::new();
        arr.put(1, Some("a"));
        arr.put(3, Some("b"));
        arr.remove(3);
        assert_eq!(arr.get_last_non_empty_index(), 1);
        assert_eq!(arr.get(3), None);
    }

    #[test]
    fn remove_past_end_is_noop() {
        let mut arr = StringArray::new();
        arr.remove(1000);
        assert_eq!(arr.get_last_non_empty_index(), -1);
    }

    #[test]
    fn remove_and_reinsert_many_entries() {
        let mut arr = StringArray::new();
        for i in 0..50 {
            arr.put(i, Some(&format!("value-{i}")));
        }
        for i in 0..50 {
            assert_eq!(arr.get(i), Some(format!("value-{i}")));
        }
        for i in (0..50).step_by(2) {
            arr.remove(i);
        }
        for i in 0..50 {
            if i % 2 == 0 {
                assert_eq!(arr.get(i), None);
            } else {
                assert_eq!(arr.get(i), Some(format!("value-{i}")));
            }
        }
    }

    /// Faithfully reproduces the multi-byte UTF-8 truncation bug in
    /// `StringArray.java` (see struct docs, `put` around lines 53-87): the amount of buffer
    /// space reserved and the number of bytes copied are both based on `value.length()`
    /// (UTF-16 code units), not the actual UTF-8 byte length of `value.getBytes()`. Any string
    /// containing multi-byte UTF-8 characters is silently truncated into an incomplete
    /// sequence, corrupting the stored value.
    #[test]
    fn put_truncates_multi_byte_utf8_strings() {
        let mut arr = StringArray::new();
        // "\u{e9}" (e-acute) is 1 UTF-16 unit but 2 UTF-8 bytes; Java's `len` (=1) means only
        // the first UTF-8 byte gets copied, leaving a truncated/invalid 1-byte sequence.
        let value = "\u{e9}"; // "é"
        assert_eq!(value.encode_utf16().count(), 1);
        assert_eq!(value.as_bytes().len(), 2);

        arr.put(0, Some(value));
        let stored = arr.get(0).expect("value was stored");
        // The round-tripped value is corrupted: it is NOT the original 2-byte-encoded "é". Only
        // the first raw byte (0xC3, an incomplete lead byte) was actually copied into the
        // buffer; decoding it leniently substitutes the 3-byte-UTF-8 replacement character
        // U+FFFD, so the corruption shows up as a single (wrong) character, not as byte-for-byte
        // equal length.
        assert_ne!(stored, value);
        assert_eq!(stored.chars().count(), 1);
        assert_eq!(stored, "\u{fffd}");
    }

    /// Faithfully reproduces the short-overflow bug in `StringArray.java`: `lengths[index] =
    /// (short)len` wraps around for strings longer than `Short.MAX_VALUE` (32767) UTF-16
    /// units, and `get` reads the length back sign-extended (not masked as unsigned), so it
    /// sees a negative length and falls into the `len > 0` false branch, returning `""`
    /// instead of the real (correctly-buffered) content.
    #[test]
    fn get_returns_empty_string_for_huge_strings_due_to_short_overflow() {
        let mut arr = StringArray::new();
        let huge = "a".repeat(40_000); // > i16::MAX UTF-16 units
        arr.put(0, Some(&huge));
        // The real content occupies real buffer space...
        assert!(arr.bytes.len() >= 40_000);
        // ...but reading it back is corrupted by the short-cast bug: instead of the 40,000
        // character string, `get` returns an empty string.
        assert_eq!(arr.get(0), Some(String::new()));
    }

    #[test]
    fn array_trait_copy_data_to_writes_string_column() {
        let mut arr = StringArray::new();
        arr.put(0, Some("value"));
        let mut table = MockDataTable::default();
        Array::copy_data_to(&arr, 0, &mut table, 5, 1);
        assert_eq!(table.get_string(5, 1), "value");
    }

    #[test]
    fn array_trait_copy_data_to_missing_index_writes_empty_string() {
        let arr = StringArray::new();
        let mut table = MockDataTable::default();
        Array::copy_data_to(&arr, 0, &mut table, 5, 1);
        assert_eq!(table.get_string(5, 1), "");
    }

    #[test]
    fn array_trait_remove_matches_inherent_remove() {
        let mut arr = StringArray::new();
        arr.put(0, Some("x"));
        Array::remove(&mut arr, 0);
        assert_eq!(arr.get(0), None);
    }

    #[test]
    fn default_matches_new() {
        assert_eq!(StringArray::default(), StringArray::new());
    }
}

use super::array::Array;
use super::byte_array_array::ByteArrayArray;
use super::data_table::DataTable;

/// An array of `String[]` (here, `Vec<Option<String>>`, since Java string
/// arrays may hold `null` elements) that grows as needed, backed by a single
/// packed byte buffer via [`ByteArrayArray`].
///
/// Port of `ghidra.util.datastruct.StringArrayArray`, which hand-rolls its
/// own binary encoding of a `String[]` (rather than delegating per-string
/// encoding to [`super::string_array::StringArray`]) and stores the result
/// in a `ByteArrayArray`. An index that was never written (or was most
/// recently `remove`d) reads back as `None`.
///
/// # Faithfully-reproduced Java quirks
///
/// - **`put(index, null)` removes, then crashes.** `StringArrayArray.put(int,
///   String[])` is:
///   ```java
///   public void put(int index, String[] value) {
///       if (value == null) {
///           remove(index);
///       }
///       byte[] bytes = stringArrayToBytes(value);
///       byteStore.put(index, bytes);
///   }
///   ```
///   There is no `return` after the `remove(index)` call, so passing `null`
///   both removes any existing entry *and* falls through to
///   `stringArrayToBytes(null)`, which immediately throws
///   `NullPointerException` on `value.length`. [`Self::put`] reproduces this
///   exactly: passing `None` removes the entry and then panics. See
///   `put_none_removes_entry_then_panics` below.
/// - **Multi-byte UTF-8 truncation.** Like `StringArray`, each string's
///   stored byte length is `value[i].length()` -- the UTF-16 code unit
///   count, not the UTF-8 byte count -- but the bytes actually copied come
///   from `value[i].getBytes()` (UTF-8). For any string with non-ASCII
///   (multi-byte UTF-8) characters, only the first `length()` *bytes* of the
///   (longer) UTF-8 encoding are copied, silently truncating/corrupting it.
///   See `put_truncates_multi_byte_utf8_strings` below.
/// - **2-byte length-header overflow desyncs decoding.** Each string's
///   length is written as a 2-byte, `short`-like big-endian field
///   (`(byte)(strlen>>8)`, `(byte)strlen`). A `null` element is encoded as
///   the sentinel `0xFF 0xFF` (i.e. `-1` when read back). For any real
///   string whose UTF-16 length falls in `32768..=65535`, the same 2-byte
///   field also decodes as negative (its high bit is set), so
///   `bytesToStringArray` mistakes it for a `null` element -- and, because
///   it advances `pos` by only the 2-byte header (not the string's actual
///   byte length) in that case, every subsequent element in the same array
///   decodes from the wrong offset. [`Self::bytes_to_string_array`]
///   reproduces this decode logic faithfully -- but in practice, a *single*
///   string long enough to trigger it (`>= 32768` UTF-16 units, hence `>=
///   32768` UTF-8 bytes of content alone) always makes the *overall* encoded
///   buffer exceed `i16::MAX` bytes too, which trips
///   [`ByteArrayArray`]/`PackedArrayArray`'s own, independent short-overflow
///   bug first (see that module's docs): `byte_store.get` panics with
///   `NegativeArraySizeException` before `bytes_to_string_array` is ever
///   reached. Real Java has the identical compounding failure, since
///   `StringArrayArray.java` stores into a real `ByteArrayArray` with the
///   same bug. See `get_panics_for_element_whose_length_overflows_the_header`
///   below for the (only reachable, in practice) observed behavior, and note
///   that [`Self::bytes_to_string_array`]'s own overflow handling is
///   preserved as a faithful-but-practically-unreachable translation of the
///   Java source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StringArrayArray {
    byte_store: ByteArrayArray,
}

impl StringArrayArray {
    /// Creates a new, empty `StringArrayArray`.
    pub fn new() -> Self {
        Self {
            byte_store: ByteArrayArray::new(),
        }
    }

    /// Stores the string array `value` at `index`.
    ///
    /// # Panics
    ///
    /// Passing `None` reproduces a genuine Java bug: it first removes any
    /// existing entry at `index` (matching Java's `remove(index)` call), and
    /// then unconditionally panics with an NPE-parity message (matching
    /// Java's fallthrough into `stringArrayToBytes(null)`). See the struct
    /// docs.
    pub fn put(&mut self, index: usize, value: Option<&[Option<String>]>) {
        let Some(value) = value else {
            self.remove(index);
            panic!(
                "NullPointerException (Java parity): StringArrayArray.put(index, null) has no \
                 `return` after `remove(index)` and falls through to \
                 `stringArrayToBytes(null)`, which throws on `value.length`"
            );
        };
        let bytes = Self::string_array_to_bytes(value);
        self.byte_store.put(index, Some(&bytes));
    }

    /// Retrieves the string array stored at `index`, or `None` if not
    /// initialized to another value (including indexes past the end of the
    /// backing storage).
    pub fn get(&self, index: usize) -> Option<Vec<Option<String>>> {
        let bytes = self.byte_store.get(index)?;
        Some(Self::bytes_to_string_array(&bytes))
    }

    /// Removes the array at `index`.
    pub fn remove(&mut self, index: usize) {
        self.byte_store.remove(index);
    }

    /// Encodes `value` using `StringArrayArray.java`'s hand-rolled binary
    /// format: a 4-byte big-endian element count, followed by each element
    /// as a 2-byte big-endian length prefix (`0xFFFF` for `None`) plus that
    /// many raw UTF-8 bytes.
    fn string_array_to_bytes(value: &[Option<String>]) -> Vec<u8> {
        let n = value.len() as i32;

        // Java: `int len = 4; for (...) { len += 2; if (value[i] != null) len +=
        // value[i].length(); }` -- `length()` is the UTF-16 code unit count.
        let mut utf16_lens: Vec<i32> = Vec::with_capacity(value.len());
        let mut total_len: usize = 4;
        for v in value {
            total_len += 2;
            let l = match v {
                Some(s) => s.encode_utf16().count() as i32,
                None => 0,
            };
            if v.is_some() {
                total_len += l as usize;
            }
            utf16_lens.push(l);
        }

        let mut bytes = vec![0u8; total_len];
        bytes[0] = (n >> 24) as u8;
        bytes[1] = (n >> 16) as u8;
        bytes[2] = (n >> 8) as u8;
        bytes[3] = n as u8;

        let mut pos = 4usize;
        for (i, v) in value.iter().enumerate() {
            match v {
                None => {
                    // Java: `bytes[pos++] = (byte)-1; bytes[pos++] = (byte)-1;`
                    bytes[pos] = 0xFF;
                    bytes[pos + 1] = 0xFF;
                    pos += 2;
                }
                Some(s) => {
                    let strlen = utf16_lens[i];
                    bytes[pos] = (strlen >> 8) as u8;
                    bytes[pos + 1] = strlen as u8;
                    pos += 2;

                    // Java: `System.arraycopy(value[i].getBytes(), 0, bytes, pos, strlen)` --
                    // copies `strlen` (UTF-16 units) bytes of the UTF-8 encoding. This is
                    // always in-bounds (UTF-8 byte length >= UTF-16 unit count for any valid
                    // string) but truncates whenever the encoding is longer than the unit
                    // count (any non-ASCII content) -- see struct docs.
                    let str_bytes = s.as_bytes();
                    let copy_len = strlen as usize;
                    bytes[pos..pos + copy_len].copy_from_slice(&str_bytes[..copy_len]);
                    pos += copy_len;
                }
            }
        }
        bytes
    }

    /// Decodes bytes produced by [`Self::string_array_to_bytes`], faithfully
    /// reproducing the header-overflow desync bug documented on the struct.
    fn bytes_to_string_array(bytes: &[u8]) -> Vec<Option<String>> {
        // Java: `((bytes[0] & 0xff) << 24) + ...` -- each byte zero-extended before
        // shifting (unlike the per-string length decode below).
        let num_strings = ((bytes[0] as i32) << 24)
            | ((bytes[1] as i32) << 16)
            | ((bytes[2] as i32) << 8)
            | (bytes[3] as i32);

        let mut strings: Vec<Option<String>> = vec![None; num_strings.max(0) as usize];
        let mut pos = 4usize;
        for slot in strings.iter_mut().take(num_strings.max(0) as usize) {
            // Java: `int strlen = (bytes[pos] << 8) + ((bytes[pos+1]) & 0xff);` --
            // `bytes[pos]` is a *signed* byte, sign-extended by promotion to `int`
            // before the shift; `bytes[pos+1]` is masked to unsigned.
            let hi = bytes[pos] as i8 as i32;
            let lo = bytes[pos + 1] as i32;
            let strlen = (hi << 8) + lo;
            if strlen >= 0 {
                let start = pos + 2;
                let len = strlen as usize;
                *slot = Some(String::from_utf8_lossy(&bytes[start..start + len]).into_owned());
                pos += len;
            }
            // else: leaves this slot `None`, matching Java's un-assigned `String[]`
            // slot (default `null`) -- whether that's because the element really was
            // `null`, or because its true length overflowed the 2-byte header. Either
            // way `pos` only advances past the 2-byte length field, not any string
            // content, which is exactly what desyncs decoding for later elements when
            // it's actually the overflow case.
            pos += 2;
        }
        strings
    }
}

impl Default for StringArrayArray {
    fn default() -> Self {
        Self::new()
    }
}

impl Array for StringArrayArray {
    fn remove(&mut self, index: usize) {
        StringArrayArray::remove(self, index);
    }

    fn get_last_non_empty_index(&self) -> i32 {
        self.byte_store.get_last_non_empty_index()
    }

    fn copy_data_to(&self, index: usize, table: &mut dyn DataTable, to_index: i32, to_col: i32) {
        // The `DataTable` trait's `put_string_array` takes `Vec<String>` (no `None`
        // elements); `None` entries collapse to `""` at this boundary.
        let strings: Vec<String> = self
            .get(index)
            .unwrap_or_default()
            .into_iter()
            .map(|s| s.unwrap_or_default())
            .collect();
        table.put_string_array(to_index, to_col, strings);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::any::Any;
    use std::collections::HashMap;
    use std::panic::{self, AssertUnwindSafe};

    #[derive(Default)]
    struct MockDataTable {
        string_arrays: HashMap<(i32, i32), Vec<String>>,
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
        fn put_string(&mut self, _row: i32, _col: i32, _value: String) {}
        fn get_string(&self, _row: i32, _col: i32) -> String {
            String::new()
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
        fn put_string_array(&mut self, row: i32, col: i32, value: Vec<String>) {
            self.string_arrays.insert((row, col), value);
        }
        fn get_string_array(&self, row: i32, col: i32) -> Vec<String> {
            self.string_arrays.get(&(row, col)).cloned().unwrap_or_default()
        }
    }

    fn some_strings(values: &[&str]) -> Vec<Option<String>> {
        values.iter().map(|s| Some(s.to_string())).collect()
    }

    #[test]
    fn new_array_reads_back_none() {
        let arr = StringArrayArray::new();
        assert_eq!(arr.get(0), None);
        assert_eq!(arr.get_last_non_empty_index(), -1);
    }

    #[test]
    fn put_and_get_roundtrip() {
        let mut arr = StringArrayArray::new();
        let value = some_strings(&["alpha", "beta", "gamma"]);
        arr.put(1, Some(&value));
        assert_eq!(arr.get(1), Some(value));
        assert_eq!(arr.get_last_non_empty_index(), 1);
    }

    #[test]
    fn put_and_get_roundtrip_with_null_elements() {
        let mut arr = StringArrayArray::new();
        let value = vec![Some("a".to_string()), None, Some("c".to_string())];
        arr.put(0, Some(&value));
        assert_eq!(arr.get(0), Some(value));
    }

    #[test]
    fn put_and_get_empty_array() {
        let mut arr = StringArrayArray::new();
        arr.put(0, Some(&[]));
        assert_eq!(arr.get(0), Some(vec![]));
    }

    #[test]
    fn put_grows_backing_storage_past_min_size() {
        let mut arr = StringArrayArray::new();
        let value = some_strings(&["x"]);
        arr.put(50, Some(&value));
        assert_eq!(arr.get(50), Some(value));
        assert_eq!(arr.get_last_non_empty_index(), 50);
        assert_eq!(arr.get(25), None);
    }

    #[test]
    fn remove_clears_entry() {
        let mut arr = StringArrayArray::new();
        let value = some_strings(&["gone"]);
        arr.put(0, Some(&value));
        arr.remove(0);
        assert_eq!(arr.get(0), None);
        assert_eq!(arr.get_last_non_empty_index(), -1);
    }

    /// Faithfully reproduces the missing-`return` bug documented on the struct:
    /// `put(index, None)` removes any existing entry, then panics.
    #[test]
    fn put_none_removes_entry_then_panics() {
        let mut arr = StringArrayArray::new();
        let value = some_strings(&["will be removed"]);
        arr.put(0, Some(&value));
        assert_eq!(arr.get_last_non_empty_index(), 0);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            arr.put(0, None);
        }));
        assert!(result.is_err(), "put(index, None) should panic (NPE parity)");

        // The entry was removed before the panic fired.
        assert_eq!(arr.get(0), None);
        assert_eq!(arr.get_last_non_empty_index(), -1);
    }

    #[test]
    #[should_panic(expected = "NullPointerException")]
    fn put_none_panic_message_documents_java_npe_parity() {
        let mut arr = StringArrayArray::new();
        arr.put(0, None);
    }

    /// Faithfully reproduces `StringArrayArray`'s multi-byte UTF-8 truncation bug
    /// (see struct docs): the per-string byte length is computed from
    /// `String.length()` (UTF-16 units), not the UTF-8 byte count, so any non-ASCII
    /// content gets silently truncated on the way in.
    #[test]
    fn put_truncates_multi_byte_utf8_strings() {
        let mut arr = StringArrayArray::new();
        // "é" is 1 UTF-16 unit but 2 UTF-8 bytes; three of them are 3 units / 6 bytes.
        let original = "ééé".to_string();
        assert_eq!(original.encode_utf16().count(), 3);
        assert_eq!(original.as_bytes().len(), 6);

        arr.put(0, Some(&[Some(original.clone())]));
        let roundtripped = arr.get(0).unwrap();
        let decoded = roundtripped[0].clone().unwrap();

        // Only the first 3 (of 6) UTF-8 bytes made it into storage, so the decoded
        // string is corrupted -- it is not equal to the original.
        assert_ne!(decoded, original);
    }

    /// Faithfully reproduces the 2-byte length-header overflow bug (see struct
    /// docs): `StringArrayArray.get()` delegates to the underlying `ByteArrayArray.get()`
    /// (verified against StringArrayArray.java's `get`/`byteStore` field), whose stored
    /// `short` length field wraps negative once the encoded byte length exceeds
    /// `i16::MAX` -- and unlike `StringArray.get()` (which treats a negative length as
    /// "empty" and returns `""`), `*ArrayArray.get()` asserts the length is non-negative
    /// and panics with `NegativeArraySizeException` instead. This is the same documented
    /// bug family as `IntArrayArray`/etc.'s off-by-one bounds panic, not a graceful
    /// `None` result.
    #[test]
    fn get_panics_for_element_whose_length_overflows_the_header() {
        let mut arr = StringArrayArray::new();
        let huge = "a".repeat(32_800); // 0x8020 UTF-16 units: high bit of the 16-bit field is set.
        assert_eq!(huge.encode_utf16().count(), 32_800);

        arr.put(0, Some(&[Some(huge)]));
        let result = panic::catch_unwind(AssertUnwindSafe(|| arr.get(0)));
        assert!(result.is_err(), "expected get(0) to panic (Java NegativeArraySizeException parity)");
    }

    #[test]
    fn array_trait_copy_data_to_writes_string_array_column_collapsing_nulls() {
        let mut arr = StringArrayArray::new();
        let value = vec![Some("a".to_string()), None];
        arr.put(0, Some(&value));
        let mut table = MockDataTable::default();
        Array::copy_data_to(&arr, 0, &mut table, 5, 1);
        assert_eq!(table.get_string_array(5, 1), vec!["a".to_string(), String::new()]);
    }

    #[test]
    fn array_trait_remove_matches_inherent_remove() {
        let mut arr = StringArrayArray::new();
        let value = some_strings(&["one"]);
        arr.put(0, Some(&value));
        Array::remove(&mut arr, 0);
        assert_eq!(arr.get(0), None);
    }

    #[test]
    fn default_matches_new() {
        assert_eq!(StringArrayArray::default(), StringArrayArray::new());
    }
}

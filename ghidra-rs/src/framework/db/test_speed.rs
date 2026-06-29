/// Binary search over a big-endian `i64` key array packed in a byte slice.
///
/// This variant copies each 8-byte key into a local array before decoding it,
/// mirroring the allocation pattern in the original Java `JavaBinarySearcher`.
pub struct JavaBinarySearcher;

impl JavaBinarySearcher {
    pub fn new() -> Self {
        Self
    }

    /// Search for `key` among `n_keys` packed big-endian `i64` entries in `buf`.
    ///
    /// Returns the index of the matching entry, or `-(insertion_point + 1)` when
    /// the key is absent (Java `Arrays.binarySearch` convention).
    pub fn binary_search(&self, buf: &[u8], key: i64, n_keys: usize) -> i32 {
        let mut min = 0i32;
        let mut max = n_keys as i32 - 1;
        while min <= max {
            let i = (min + max) / 2;
            let k = self.get_key(buf, i as usize);
            if k == key {
                return i;
            } else if k < key {
                min = i + 1;
            } else {
                max = i - 1;
            }
        }
        -(min + 1)
    }

    fn get_key(&self, buf: &[u8], i: usize) -> i64 {
        let data = self.get(buf, i * 8);
        i64::from_be_bytes(data)
    }

    fn get(&self, buf: &[u8], start: usize) -> [u8; 8] {
        let mut data = [0u8; 8];
        data.copy_from_slice(&buf[start..start + 8]);
        data
    }
}

impl Default for JavaBinarySearcher {
    fn default() -> Self {
        Self::new()
    }
}

/// Binary search over a big-endian `i64` key array packed in a byte slice.
///
/// This variant reads directly from the buffer without an intermediate copy,
/// mirroring the optimised `JavaBinarySearcher2` in the original Java source.
pub struct JavaBinarySearcher2;

impl JavaBinarySearcher2 {
    pub fn new() -> Self {
        Self
    }

    /// Search for `key` among `n_keys` packed big-endian `i64` entries in `buf`.
    ///
    /// Returns the index of the matching entry, or `-(insertion_point + 1)` when
    /// the key is absent (Java `Arrays.binarySearch` convention).
    pub fn binary_search(&self, buf: &[u8], key: i64, n_keys: usize) -> i32 {
        let mut min = 0i32;
        let mut max = n_keys as i32 - 1;
        while min <= max {
            let i = (min + max) / 2;
            let k = self.get_key(buf, i as usize);
            if k == key {
                return i;
            } else if k < key {
                min = i + 1;
            } else {
                max = i - 1;
            }
        }
        -(min + 1)
    }

    fn get_key(&self, data: &[u8], i: usize) -> i64 {
        let idx = i * 8;
        i64::from_be_bytes(data[idx..idx + 8].try_into().unwrap())
    }
}

impl Default for JavaBinarySearcher2 {
    fn default() -> Self {
        Self::new()
    }
}

/// Build a 16 KiB byte buffer holding 2048 big-endian `i64` values `0..2047`.
pub fn create_buf() -> Vec<u8> {
    let mut buf = vec![0u8; 16 * 1024];
    for i in 0..2 * 1024usize {
        put_long(&mut buf, i, i as i64);
    }
    buf
}

/// Write `v` as big-endian `i64` at slot `index` (byte offset `index * 8`) in `data`.
pub fn put_long(data: &mut [u8], index: usize, v: i64) {
    let i = index * 8;
    data[i..i + 8].copy_from_slice(&v.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_buf_length() {
        let buf = create_buf();
        assert_eq!(buf.len(), 16 * 1024);
    }

    #[test]
    fn test_create_buf_values() {
        let buf = create_buf();
        for i in 0..2048usize {
            let start = i * 8;
            let val = i64::from_be_bytes(buf[start..start + 8].try_into().unwrap());
            assert_eq!(val, i as i64);
        }
    }

    #[test]
    fn test_put_long_big_endian() {
        let mut data = [0u8; 8];
        put_long(&mut data, 0, 0x0102030405060708i64);
        assert_eq!(data, [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    }

    #[test]
    fn test_binary_searcher_finds_all_keys() {
        let buf = create_buf();
        let searcher = JavaBinarySearcher::new();
        for i in 0..2048usize {
            let idx = searcher.binary_search(&buf, i as i64, 2048);
            assert_eq!(idx, i as i32, "key {i} not found at expected index");
        }
    }

    #[test]
    fn test_binary_searcher_not_found_returns_negative() {
        let buf = create_buf();
        let searcher = JavaBinarySearcher::new();
        let result = searcher.binary_search(&buf, 9999, 2048);
        assert!(result < 0);
    }

    #[test]
    fn test_binary_searcher2_finds_all_keys() {
        let buf = create_buf();
        let searcher = JavaBinarySearcher2::new();
        for i in 0..2048usize {
            let idx = searcher.binary_search(&buf, i as i64, 2048);
            assert_eq!(idx, i as i32, "key {i} not found at expected index");
        }
    }

    #[test]
    fn test_binary_searcher2_not_found_returns_negative() {
        let buf = create_buf();
        let searcher = JavaBinarySearcher2::new();
        let result = searcher.binary_search(&buf, 9999, 2048);
        assert!(result < 0);
    }

    #[test]
    fn test_both_searchers_agree_on_all_keys() {
        let buf = create_buf();
        let s1 = JavaBinarySearcher::new();
        let s2 = JavaBinarySearcher2::new();
        for i in 0..2048usize {
            assert_eq!(
                s1.binary_search(&buf, i as i64, 2048),
                s2.binary_search(&buf, i as i64, 2048),
                "searchers disagree on key {i}"
            );
        }
    }

    #[test]
    fn test_binary_search_empty() {
        let buf = create_buf();
        let s = JavaBinarySearcher::new();
        assert_eq!(s.binary_search(&buf, 0, 0), -1);
    }

    #[test]
    fn test_binary_search_single_element_found() {
        let mut buf = vec![0u8; 8];
        put_long(&mut buf, 0, 42);
        let s = JavaBinarySearcher2::new();
        assert_eq!(s.binary_search(&buf, 42, 1), 0);
    }

    #[test]
    fn test_binary_search_single_element_not_found() {
        let mut buf = vec![0u8; 8];
        put_long(&mut buf, 0, 42);
        let s = JavaBinarySearcher2::new();
        assert_eq!(s.binary_search(&buf, 0, 1), -1);
        assert_eq!(s.binary_search(&buf, 100, 1), -2);
    }
}

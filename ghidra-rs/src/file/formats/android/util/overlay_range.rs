use std::io;

/// A range of bytes identified by an absolute start index.
///
/// Mirrors `ghidra.file.formats.android.util.OverlayRange`.
#[derive(Debug, Clone)]
pub struct OverlayRange {
    overlay_index: i32,
    overlay_bytes: Vec<u8>,
}

impl OverlayRange {
    /// Creates a new range from `overlay_index` and `overlay_bytes`.
    pub fn new(overlay_index: i32, overlay_bytes: Vec<u8>) -> Self {
        Self { overlay_index, overlay_bytes }
    }

    /// Returns the start index of this range.
    pub fn start_index(&self) -> i32 {
        self.overlay_index
    }

    /// Returns the end index of this range (start + byte count).
    pub fn end_index(&self) -> i32 {
        self.overlay_index + self.overlay_bytes.len() as i32
    }

    /// Returns `true` if this range contains `index`.
    pub fn contains_index(&self, index: i32) -> bool {
        index >= self.start_index() && index <= self.end_index()
    }

    /// Returns the byte at the absolute `index`.
    ///
    /// Panics if `index` is out of range, mirroring Java's array bounds exception.
    pub fn get_byte(&self, index: i32) -> u8 {
        self.overlay_bytes[(index - self.overlay_index) as usize]
    }

    /// Returns `length` bytes starting at the absolute `index`.
    ///
    /// Returns an error if the index or length is out of range.
    pub fn get_bytes(&self, index: i32, length: i32) -> io::Result<Vec<u8>> {
        let err = || io::Error::new(io::ErrorKind::InvalidInput, "specified index and length are out of range");
        let start: usize = (index - self.overlay_index).try_into().map_err(|_| err())?;
        let len: usize = length.try_into().map_err(|_| err())?;
        let end = start.checked_add(len).ok_or_else(err)?;
        self.overlay_bytes.get(start..end).map(|b| b.to_vec()).ok_or_else(err)
    }

    /// Returns all bytes in this range.
    pub fn all_bytes(&self) -> &[u8] {
        &self.overlay_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_range() -> OverlayRange {
        OverlayRange::new(10, vec![0xAA, 0xBB, 0xCC, 0xDD])
    }

    #[test]
    fn start_index_matches_constructor() {
        assert_eq!(make_range().start_index(), 10);
    }

    #[test]
    fn end_index_is_start_plus_length() {
        assert_eq!(make_range().end_index(), 14);
    }

    #[test]
    fn contains_index_inside() {
        let r = make_range();
        assert!(r.contains_index(10));
        assert!(r.contains_index(12));
        assert!(r.contains_index(14));
    }

    #[test]
    fn contains_index_outside() {
        let r = make_range();
        assert!(!r.contains_index(9));
        assert!(!r.contains_index(15));
    }

    #[test]
    fn get_byte_returns_correct_value() {
        let r = make_range();
        assert_eq!(r.get_byte(10), 0xAA);
        assert_eq!(r.get_byte(11), 0xBB);
        assert_eq!(r.get_byte(13), 0xDD);
    }

    #[test]
    fn get_bytes_returns_slice() {
        let r = make_range();
        assert_eq!(r.get_bytes(11, 2).unwrap(), vec![0xBB, 0xCC]);
    }

    #[test]
    fn get_bytes_full_range() {
        let r = make_range();
        assert_eq!(r.get_bytes(10, 4).unwrap(), vec![0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn get_bytes_out_of_range_errors() {
        let r = make_range();
        assert!(r.get_bytes(10, 10).is_err());
    }

    #[test]
    fn get_bytes_negative_offset_errors() {
        let r = make_range();
        assert!(r.get_bytes(5, 2).is_err());
    }

    #[test]
    fn get_bytes_negative_length_errors() {
        let r = make_range();
        assert!(r.get_bytes(10, -1).is_err());
    }

    #[test]
    fn all_bytes_returns_all() {
        let r = make_range();
        assert_eq!(r.all_bytes(), &[0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn zero_index_range() {
        let r = OverlayRange::new(0, vec![1, 2, 3]);
        assert_eq!(r.start_index(), 0);
        assert_eq!(r.end_index(), 3);
        assert_eq!(r.get_byte(0), 1);
        assert_eq!(r.get_bytes(0, 3).unwrap(), vec![1, 2, 3]);
    }
}

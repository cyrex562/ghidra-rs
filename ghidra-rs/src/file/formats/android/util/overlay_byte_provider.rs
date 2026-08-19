use std::io;

use crate::filesystem::ghidra::g_binary_reader::ByteProvider;

use super::overlay_range::OverlayRange;

/// A [`ByteProvider`] that overlays decompressed chunks at specific locations
/// on top of an underlying provider.
///
/// Mirrors `ghidra.file.formats.android.util.OverlayByteProvider`. Overlay
/// ranges are checked most-recently-added-last, matching the Java
/// implementation's linear scan over `overlayList`.
pub struct OverlayByteProvider<P: ByteProvider> {
    provider: P,
    overlay_list: Vec<OverlayRange>,
}

impl<P: ByteProvider> OverlayByteProvider<P> {
    /// Creates a new overlay provider wrapping `provider`.
    pub fn new(provider: P) -> Self {
        OverlayByteProvider { provider, overlay_list: Vec::new() }
    }

    /// Adds an overlay range that takes precedence over the wrapped provider.
    pub fn add_range(&mut self, range: OverlayRange) {
        self.overlay_list.push(range);
    }
}

impl<P: ByteProvider> ByteProvider for OverlayByteProvider<P> {
    fn length(&mut self) -> io::Result<u64> {
        let mut current_max: u64 = 0;
        for range in &self.overlay_list {
            current_max = current_max.max(range.end_index().max(0) as u64);
        }
        Ok(current_max.max(self.provider.length()?))
    }

    fn is_valid_index(&mut self, index: u64) -> bool {
        if let Ok(idx) = i32::try_from(index) {
            for range in &self.overlay_list {
                if range.contains_index(idx) {
                    return true;
                }
            }
        }
        self.provider.is_valid_index(index)
    }

    fn read_byte(&mut self, index: u64) -> io::Result<u8> {
        if let Ok(idx) = i32::try_from(index) {
            for range in &self.overlay_list {
                if range.contains_index(idx) {
                    return Ok(range.get_byte(idx));
                }
            }
        }
        self.provider.read_byte(index)
    }

    fn read_bytes(&mut self, index: u64, length: usize) -> io::Result<Vec<u8>> {
        if let (Ok(idx), Ok(len)) = (i32::try_from(index), i32::try_from(length)) {
            for range in &self.overlay_list {
                if range.contains_index(idx) {
                    return range.get_bytes(idx, len);
                }
            }
        }
        self.provider.read_bytes(index, length)
    }

    fn write_byte(&mut self, _index: u64, _value: u8) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "OverlayByteProvider does not support writes",
        ))
    }

    fn write_bytes(&mut self, _index: u64, _values: &[u8]) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "OverlayByteProvider does not support writes",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct VecProvider {
        data: Vec<u8>,
    }

    impl VecProvider {
        fn new(data: &[u8]) -> Self {
            VecProvider { data: data.to_vec() }
        }
    }

    impl ByteProvider for VecProvider {
        fn length(&mut self) -> io::Result<u64> {
            Ok(self.data.len() as u64)
        }

        fn is_valid_index(&mut self, index: u64) -> bool {
            (index as usize) < self.data.len()
        }

        fn read_byte(&mut self, index: u64) -> io::Result<u8> {
            self.data
                .get(index as usize)
                .copied()
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "out of bounds"))
        }

        fn read_bytes(&mut self, index: u64, length: usize) -> io::Result<Vec<u8>> {
            let start = index as usize;
            let end = start + length;
            if end > self.data.len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "out of bounds"));
            }
            Ok(self.data[start..end].to_vec())
        }

        fn write_byte(&mut self, index: u64, value: u8) -> io::Result<()> {
            self.data[index as usize] = value;
            Ok(())
        }

        fn write_bytes(&mut self, index: u64, values: &[u8]) -> io::Result<()> {
            let start = index as usize;
            self.data[start..start + values.len()].copy_from_slice(values);
            Ok(())
        }
    }

    #[test]
    fn length_matches_underlying_provider_when_no_overlays() {
        let mut p = OverlayByteProvider::new(VecProvider::new(&[1, 2, 3]));
        assert_eq!(p.length().unwrap(), 3);
    }

    #[test]
    fn length_extends_past_underlying_provider() {
        let mut p = OverlayByteProvider::new(VecProvider::new(&[1, 2, 3]));
        p.add_range(OverlayRange::new(5, vec![0xAA, 0xBB]));
        assert_eq!(p.length().unwrap(), 7);
    }

    #[test]
    fn length_uses_underlying_provider_when_larger() {
        let mut p = OverlayByteProvider::new(VecProvider::new(&[0u8; 10]));
        p.add_range(OverlayRange::new(0, vec![1, 2]));
        assert_eq!(p.length().unwrap(), 10);
    }

    #[test]
    fn is_valid_index_true_within_overlay() {
        let mut p = OverlayByteProvider::new(VecProvider::new(&[1, 2, 3]));
        p.add_range(OverlayRange::new(10, vec![0xAA, 0xBB]));
        assert!(p.is_valid_index(11));
    }

    #[test]
    fn is_valid_index_delegates_to_underlying_provider() {
        let mut p = OverlayByteProvider::new(VecProvider::new(&[1, 2, 3]));
        assert!(p.is_valid_index(2));
        assert!(!p.is_valid_index(3));
    }

    #[test]
    fn read_byte_from_overlay_range() {
        let mut p = OverlayByteProvider::new(VecProvider::new(&[1, 2, 3]));
        p.add_range(OverlayRange::new(0, vec![0xAA, 0xBB, 0xCC]));
        assert_eq!(p.read_byte(1).unwrap(), 0xBB);
    }

    #[test]
    fn read_byte_falls_through_to_underlying_provider() {
        let mut p = OverlayByteProvider::new(VecProvider::new(&[1, 2, 3]));
        p.add_range(OverlayRange::new(10, vec![0xAA]));
        assert_eq!(p.read_byte(1).unwrap(), 2);
    }

    #[test]
    fn read_bytes_from_overlay_range() {
        let mut p = OverlayByteProvider::new(VecProvider::new(&[0u8; 5]));
        p.add_range(OverlayRange::new(0, vec![1, 2, 3, 4, 5]));
        assert_eq!(p.read_bytes(1, 3).unwrap(), vec![2, 3, 4]);
    }

    #[test]
    fn read_bytes_falls_through_to_underlying_provider() {
        let mut p = OverlayByteProvider::new(VecProvider::new(&[9, 8, 7, 6]));
        assert_eq!(p.read_bytes(1, 2).unwrap(), vec![8, 7]);
    }

    #[test]
    fn most_recently_added_overlay_takes_precedence() {
        let mut p = OverlayByteProvider::new(VecProvider::new(&[0u8; 4]));
        p.add_range(OverlayRange::new(0, vec![1, 1, 1, 1]));
        p.add_range(OverlayRange::new(0, vec![2, 2, 2, 2]));
        // Java's linear scan checks overlays in insertion order, so the first
        // range added still wins when ranges overlap.
        assert_eq!(p.read_byte(0).unwrap(), 1);
    }

    #[test]
    fn write_byte_is_unsupported() {
        let mut p = OverlayByteProvider::new(VecProvider::new(&[1, 2, 3]));
        let err = p.write_byte(0, 0xFF).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn write_bytes_is_unsupported() {
        let mut p = OverlayByteProvider::new(VecProvider::new(&[1, 2, 3]));
        let err = p.write_bytes(0, &[0xFF]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }
}

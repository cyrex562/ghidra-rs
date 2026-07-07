pub mod ascii_char_set_recognizer;
pub mod char_width;

pub use ascii_char_set_recognizer::AsciiCharSetRecognizer;
pub use char_width::CharWidth;

/// Trait mirroring `ghidra.util.ascii.CharSetRecognizer`.
///
/// A recognizer that determines whether a given character (represented as an `i32`
/// Unicode code point) belongs to a particular character set.
pub trait CharSetRecognizer {
    /// Returns `true` if the character `c` belongs to this character set.
    fn contains(&self, c: i32) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct AlwaysRecognizer;
    impl CharSetRecognizer for AlwaysRecognizer {
        fn contains(&self, _c: i32) -> bool {
            true
        }
    }

    struct NeverRecognizer;
    impl CharSetRecognizer for NeverRecognizer {
        fn contains(&self, _c: i32) -> bool {
            false
        }
    }

    struct RangeRecognizer {
        lo: i32,
        hi: i32,
    }
    impl CharSetRecognizer for RangeRecognizer {
        fn contains(&self, c: i32) -> bool {
            c >= self.lo && c <= self.hi
        }
    }

    #[test]
    fn always_recognizer_accepts_all() {
        let r = AlwaysRecognizer;
        assert!(r.contains(0));
        assert!(r.contains(b'A' as i32));
        assert!(r.contains(i32::MAX));
        assert!(r.contains(-1));
    }

    #[test]
    fn never_recognizer_rejects_all() {
        let r = NeverRecognizer;
        assert!(!r.contains(0));
        assert!(!r.contains(b'A' as i32));
        assert!(!r.contains(i32::MAX));
        assert!(!r.contains(-1));
    }

    #[test]
    fn range_recognizer_boundary_values() {
        let r = RangeRecognizer { lo: 0x20, hi: 0x7E };
        assert!(r.contains(0x20));
        assert!(r.contains(0x7E));
        assert!(r.contains(0x41)); // 'A'
        assert!(!r.contains(0x1F));
        assert!(!r.contains(0x7F));
        assert!(!r.contains(-1));
    }

    #[test]
    fn trait_object_dispatch() {
        let recognizers: Vec<Box<dyn CharSetRecognizer>> = vec![
            Box::new(RangeRecognizer { lo: b'a' as i32, hi: b'z' as i32 }),
            Box::new(RangeRecognizer { lo: b'A' as i32, hi: b'Z' as i32 }),
        ];
        assert!(recognizers[0].contains(b'a' as i32));
        assert!(recognizers[0].contains(b'z' as i32));
        assert!(!recognizers[0].contains(b'A' as i32));
        assert!(recognizers[1].contains(b'A' as i32));
        assert!(!recognizers[1].contains(b'a' as i32));
    }
}

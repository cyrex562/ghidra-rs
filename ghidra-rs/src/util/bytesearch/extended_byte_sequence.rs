use super::byte_sequence::ByteSequence;

struct EmptyByteSequence;

impl ByteSequence for EmptyByteSequence {
    fn len(&self) -> usize {
        0
    }

    fn get_byte(&self, _index: usize) -> u8 {
        0
    }

    fn has_available_bytes(&self, _index: usize, _length: usize) -> bool {
        false
    }
}

/// A byte sequence view over three contiguous sub-sequences (pre, main, post) used for
/// chunked memory searching where patterns may span chunk boundaries or require look-behind.
///
/// Searching large memory ranges is partitioned into chunks. Three chunks are presented at
/// once: the pre-chunk (look-behind data), the main chunk (where matches must *start*), and
/// the post-chunk (where matches may *extend*). Negative signed indices address the
/// pre-sequence; non-negative indices address the main sequence up to `len()`, and beyond
/// that up to `extended_len()` address the post-sequence.
pub struct ExtendedByteSequence {
    main: Box<dyn ByteSequence>,
    pre: Box<dyn ByteSequence>,
    post: Box<dyn ByteSequence>,
    main_length: usize,
    extended_length: usize,
    pre_length: usize,
}

impl ExtendedByteSequence {
    /// Creates a new `ExtendedByteSequence`.
    ///
    /// - `main`: the primary sequence where search matches may start.
    /// - `pre`: look-behind bytes immediately before `main`; pass `None` for empty.
    /// - `post`: extension bytes immediately after `main` where matches may extend; pass
    ///   `None` for empty.
    /// - `overlap`: limits how many bytes of `pre` and `post` are considered accessible.
    pub fn new(
        main: Box<dyn ByteSequence>,
        pre: Option<Box<dyn ByteSequence>>,
        post: Option<Box<dyn ByteSequence>>,
        overlap: usize,
    ) -> Self {
        let main_length = main.len();
        let pre: Box<dyn ByteSequence> = pre.unwrap_or_else(|| Box::new(EmptyByteSequence));
        let post: Box<dyn ByteSequence> = post.unwrap_or_else(|| Box::new(EmptyByteSequence));
        let extended_length = main_length + overlap.min(post.len());
        let pre_length = overlap.min(pre.len());
        Self { main, pre, post, main_length, extended_length, pre_length }
    }

    /// Returns the total number of accessible bytes, including the post-sequence overlap.
    pub fn extended_len(&self) -> usize {
        self.extended_length
    }

    /// Returns the number of accessible pre-sequence bytes (reachable via negative indices).
    pub fn pre_len(&self) -> usize {
        self.pre_length
    }

    /// Returns the byte at a signed index.
    ///
    /// Negative indices access the pre-sequence (−1 is the byte immediately before main).
    /// Non-negative indices at or beyond `len()` access the post-sequence.
    pub fn get_byte_signed(&self, index: isize) -> u8 {
        if index < 0 {
            self.pre.get_byte((index + self.pre.len() as isize) as usize)
        } else if (index as usize) >= self.main_length {
            self.post.get_byte(index as usize - self.main_length)
        } else {
            self.main.get_byte(index as usize)
        }
    }

    /// Returns bytes for the signed range `[index, index + length)`.
    ///
    /// # Panics
    ///
    /// Panics if `index < -pre_len()` or `index + length > extended_len()`.
    pub fn get_bytes_signed(&self, index: isize, length: usize) -> Vec<u8> {
        if index < -(self.pre_length as isize)
            || index + length as isize > self.extended_length as isize
        {
            panic!("index out of bounds");
        }
        if index < 0 && index + length as isize <= 0 {
            let offset = (index + self.pre.len() as isize) as usize;
            return self.pre.get_bytes(offset, length);
        }
        if index >= 0 && (index as usize) + length < self.main_length {
            return self.main.get_bytes(index as usize, length);
        }
        if index >= 0 && (index as usize) >= self.main_length {
            return self.post.get_bytes(index as usize - self.main_length, length);
        }
        (0..length).map(|k| self.get_byte_signed(index + k as isize)).collect()
    }

    /// Returns whether bytes are available for the signed range `[index, index + length)`.
    pub fn has_available_bytes_signed(&self, index: isize, length: usize) -> bool {
        index >= -(self.pre_length as isize)
            && index + length as isize <= self.extended_length as isize
    }
}

impl ByteSequence for ExtendedByteSequence {
    /// Returns the length of the main (primary) sequence.
    fn len(&self) -> usize {
        self.main_length
    }

    /// Returns the byte at `index`. Indices in `[len(), extended_len())` access the
    /// post-sequence. Use [`get_byte_signed`](Self::get_byte_signed) for negative indices.
    fn get_byte(&self, index: usize) -> u8 {
        self.get_byte_signed(index as isize)
    }

    fn has_available_bytes(&self, index: usize, length: usize) -> bool {
        self.has_available_bytes_signed(index as isize, length)
    }

    fn get_bytes(&self, start: usize, length: usize) -> Vec<u8> {
        self.get_bytes_signed(start as isize, length)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct SimpleSeq(Vec<u8>);

    impl ByteSequence for SimpleSeq {
        fn len(&self) -> usize {
            self.0.len()
        }

        fn get_byte(&self, index: usize) -> u8 {
            self.0[index]
        }
    }

    fn boxed(bytes: &[u8]) -> Box<dyn ByteSequence> {
        Box::new(SimpleSeq(bytes.to_vec()))
    }

    // main=[10,20,30], pre=[1,2,3], post=[40,50,60], overlap=3
    fn make_seq() -> ExtendedByteSequence {
        ExtendedByteSequence::new(
            boxed(&[10, 20, 30]),
            Some(boxed(&[1, 2, 3])),
            Some(boxed(&[40, 50, 60])),
            3,
        )
    }

    #[test]
    fn len_returns_main_length() {
        let s = make_seq();
        assert_eq!(s.len(), 3);
    }

    #[test]
    fn extended_len_includes_post_overlap() {
        let s = make_seq();
        assert_eq!(s.extended_len(), 6); // 3 main + 3 overlap
    }

    #[test]
    fn pre_len_is_limited_by_overlap() {
        let s = make_seq();
        assert_eq!(s.pre_len(), 3);
    }

    #[test]
    fn overlap_limits_extended_len() {
        let s = ExtendedByteSequence::new(
            boxed(&[10, 20, 30]),
            Some(boxed(&[1, 2, 3])),
            Some(boxed(&[40, 50, 60])),
            2,
        );
        assert_eq!(s.extended_len(), 5); // 3 main + 2 overlap
        assert_eq!(s.pre_len(), 2);
    }

    #[test]
    fn overlap_larger_than_post_clamps_to_post_len() {
        let s = ExtendedByteSequence::new(
            boxed(&[10, 20, 30]),
            Some(boxed(&[1, 2, 3])),
            Some(boxed(&[40])),
            10,
        );
        assert_eq!(s.extended_len(), 4); // 3 + min(10,1)
        assert_eq!(s.pre_len(), 3); // min(10,3)
    }

    #[test]
    fn none_pre_results_in_zero_pre_len() {
        let s = ExtendedByteSequence::new(boxed(&[10, 20, 30]), None, None, 5);
        assert_eq!(s.pre_len(), 0);
        assert_eq!(s.extended_len(), 3);
    }

    #[test]
    fn get_byte_signed_main_region() {
        let s = make_seq();
        assert_eq!(s.get_byte_signed(0), 10);
        assert_eq!(s.get_byte_signed(1), 20);
        assert_eq!(s.get_byte_signed(2), 30);
    }

    #[test]
    fn get_byte_signed_post_region() {
        let s = make_seq();
        assert_eq!(s.get_byte_signed(3), 40);
        assert_eq!(s.get_byte_signed(4), 50);
        assert_eq!(s.get_byte_signed(5), 60);
    }

    #[test]
    fn get_byte_signed_pre_region() {
        let s = make_seq();
        // pre=[1,2,3]: index -1 → pre[2]=3, -2 → pre[1]=2, -3 → pre[0]=1
        assert_eq!(s.get_byte_signed(-1), 3);
        assert_eq!(s.get_byte_signed(-2), 2);
        assert_eq!(s.get_byte_signed(-3), 1);
    }

    #[test]
    fn has_available_bytes_signed_within_bounds() {
        let s = make_seq();
        assert!(s.has_available_bytes_signed(0, 3));
        assert!(s.has_available_bytes_signed(0, 6));
        assert!(s.has_available_bytes_signed(-3, 6));
        assert!(s.has_available_bytes_signed(-1, 1));
        assert!(s.has_available_bytes_signed(5, 1));
        assert!(s.has_available_bytes_signed(6, 0));
    }

    #[test]
    fn has_available_bytes_signed_out_of_bounds() {
        let s = make_seq();
        assert!(!s.has_available_bytes_signed(-4, 1)); // beyond pre
        assert!(!s.has_available_bytes_signed(0, 7)); // beyond extended
        assert!(!s.has_available_bytes_signed(6, 1)); // one past extended
    }

    #[test]
    fn get_bytes_signed_pure_main() {
        let s = make_seq();
        assert_eq!(s.get_bytes_signed(0, 2), vec![10, 20]);
        assert_eq!(s.get_bytes_signed(1, 1), vec![20]);
    }

    #[test]
    fn get_bytes_signed_pure_pre() {
        let s = make_seq();
        assert_eq!(s.get_bytes_signed(-3, 3), vec![1, 2, 3]);
        assert_eq!(s.get_bytes_signed(-2, 2), vec![2, 3]);
    }

    #[test]
    fn get_bytes_signed_pure_post() {
        let s = make_seq();
        assert_eq!(s.get_bytes_signed(3, 3), vec![40, 50, 60]);
        assert_eq!(s.get_bytes_signed(4, 2), vec![50, 60]);
    }

    #[test]
    fn get_bytes_signed_spanning_main_and_post() {
        let s = make_seq();
        assert_eq!(s.get_bytes_signed(2, 2), vec![30, 40]);
    }

    #[test]
    fn get_bytes_signed_spanning_pre_and_main() {
        let s = make_seq();
        assert_eq!(s.get_bytes_signed(-1, 2), vec![3, 10]);
    }

    #[test]
    fn get_bytes_signed_spanning_all_three() {
        let s = make_seq();
        assert_eq!(s.get_bytes_signed(-1, 5), vec![3, 10, 20, 30, 40]);
    }

    #[test]
    fn get_bytes_signed_full_main_range_via_span() {
        // index + size == main_length routes through span case per Java parity
        let s = make_seq();
        assert_eq!(s.get_bytes_signed(0, 3), vec![10, 20, 30]);
    }

    #[test]
    #[should_panic]
    fn get_bytes_signed_panics_when_below_pre() {
        let s = make_seq();
        let _ = s.get_bytes_signed(-4, 1);
    }

    #[test]
    #[should_panic]
    fn get_bytes_signed_panics_when_beyond_extended() {
        let s = make_seq();
        let _ = s.get_bytes_signed(0, 7);
    }

    #[test]
    fn byte_sequence_len_matches_main() {
        let s = make_seq();
        assert_eq!(s.len(), 3);
    }

    #[test]
    fn byte_sequence_get_byte_main() {
        let s = make_seq();
        assert_eq!(s.get_byte(0), 10);
        assert_eq!(s.get_byte(2), 30);
    }

    #[test]
    fn byte_sequence_get_byte_post_via_trait() {
        let s = make_seq();
        assert_eq!(s.get_byte(3), 40);
        assert_eq!(s.get_byte(5), 60);
    }

    #[test]
    fn byte_sequence_has_available_bytes_checks_extended() {
        let s = make_seq();
        assert!(s.has_available_bytes(0, 6));
        assert!(!s.has_available_bytes(0, 7));
    }

    #[test]
    fn byte_sequence_get_bytes_via_trait() {
        let s = make_seq();
        assert_eq!(s.get_bytes(1, 3), vec![20, 30, 40]);
    }

    #[test]
    fn is_empty_false_for_nonempty_main() {
        let s = make_seq();
        assert!(!s.is_empty());
    }

    #[test]
    fn is_empty_true_for_empty_main() {
        let s = ExtendedByteSequence::new(boxed(&[]), None, Some(boxed(&[1, 2])), 2);
        assert!(s.is_empty());
        assert_eq!(s.extended_len(), 2);
    }
}

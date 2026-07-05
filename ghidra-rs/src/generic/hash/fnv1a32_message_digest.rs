use crate::generic::hash::MessageDigestBehavior;

/// Port of `generic.hash.FNV1a32MessageDigest`.
///
/// Implements the 32-bit FNV-1a non-cryptographic hash as a [`MessageDigestBehavior`] for
/// composition into
/// [`AbstractMessageDigest`](crate::generic::hash::AbstractMessageDigest), which supplies the
/// `"FNV-1a"` algorithm name and 4-byte digest length that the Java constructor passed to its
/// superclass.
pub struct FNV1a32MessageDigest {
    hashvalue: i32,
}

impl FNV1a32MessageDigest {
    pub const FNV_32_OFFSET_BASIS: i32 = 0x811c_9dc5u32 as i32;
    pub const FNV_32_PRIME: i32 = 16777619;

    /// Creates a digest seeded directly with `initial_vector`, bypassing the standard FNV
    /// offset basis.
    pub fn with_initial_vector(initial_vector: i32) -> Self {
        Self { hashvalue: initial_vector }
    }

    /// Creates a digest seeded with the standard FNV-1a 32-bit offset basis.
    pub fn new() -> Self {
        let mut digest = Self { hashvalue: 0 };
        digest.init();
        digest
    }

    fn init(&mut self) {
        self.hashvalue = Self::FNV_32_OFFSET_BASIS;
    }
}

impl Default for FNV1a32MessageDigest {
    fn default() -> Self {
        Self::new()
    }
}

impl MessageDigestBehavior for FNV1a32MessageDigest {
    fn update(&mut self, input: u8) {
        self.hashvalue ^= input as i32;
        self.hashvalue = self.hashvalue.wrapping_mul(Self::FNV_32_PRIME);
    }

    fn digest_into_buf(&mut self, buf: &mut [u8], offset: usize, len: usize) -> usize {
        if buf.len() < 4 || len < 4 {
            let mut off = offset as isize + len as isize - 1;
            let shift_amount = (8i32.wrapping_mul(4i32.wrapping_sub(len as i32))) as u32;
            self.hashvalue = self.hashvalue.wrapping_shr(shift_amount);
            for _ in 0..len {
                buf[off as usize] = (self.hashvalue & 0xff) as u8;
                off -= 1;
                self.hashvalue >>= 8;
            }
            self.init();
            return len;
        }

        // unwind the loop
        let mut off = offset + 3;
        buf[off] = (self.hashvalue & 0xff) as u8;
        off -= 1;
        self.hashvalue >>= 8;
        buf[off] = (self.hashvalue & 0xff) as u8;
        off -= 1;
        self.hashvalue >>= 8;
        buf[off] = (self.hashvalue & 0xff) as u8;
        off -= 1;
        self.hashvalue >>= 8;
        buf[off] = (self.hashvalue & 0xff) as u8;
        self.init();
        4
    }

    fn digest_long(&mut self) -> i64 {
        let result = (self.hashvalue as u32) as i64;
        self.init();
        result
    }

    fn reset(&mut self) {
        self.init();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generic::hash::AbstractMessageDigest;
    use crate::generic::hash::MessageDigest;
    use crate::util::task::DummyMonitor;
    use rand::RngCore;

    fn new_digest() -> AbstractMessageDigest {
        AbstractMessageDigest::new("FNV-1a", 4, Box::new(FNV1a32MessageDigest::new()))
    }

    #[test]
    fn new_seeds_offset_basis() {
        let mut digest = new_digest();
        // Digesting zero bytes should yield the offset basis unchanged.
        assert_eq!(
            digest.digest_long(),
            (FNV1a32MessageDigest::FNV_32_OFFSET_BASIS as u32) as i64
        );
    }

    #[test]
    fn with_initial_vector_seeds_directly() {
        let mut digest =
            AbstractMessageDigest::new("FNV-1a", 4, Box::new(FNV1a32MessageDigest::with_initial_vector(7)));
        assert_eq!(digest.digest_long(), 7);
    }

    #[test]
    fn digest_resets_after_call() {
        let mut digest = new_digest();
        digest.update_bytes(&[0xcc, 0x24, 0x31, 0xc4]);
        let _ = digest.digest();
        // A second digest with no further updates should be back at the offset basis.
        assert_eq!(
            digest.digest_long(),
            (FNV1a32MessageDigest::FNV_32_OFFSET_BASIS as u32) as i64
        );
    }

    #[test]
    fn digest_long_matches_digest_bytes() {
        for seed in [0u8, 1, 2] {
            let mut digest = new_digest();
            digest.update_bytes(&[seed; 20]);
            let bytes = digest.digest();

            let mut digest = new_digest();
            digest.update_bytes(&[seed; 20]);
            let as_long = digest.digest_long();

            let mut acc: i64 = 0;
            for b in bytes {
                acc <<= 8;
                acc |= b as i64 & 0xff;
            }
            assert_eq!(as_long, acc);
        }
    }

    #[test]
    fn longer_requests_write_only_requested_window() {
        const MARKER: u8 = 0x42;
        let digest_length = 4usize;

        let mut reference_digest = new_digest();
        reference_digest.update_bytes(b"Foobar");
        let reference = reference_digest.digest();

        for before_length in 0..digest_length {
            for request_length in 0..digest_length * 2 {
                for after_length in 0..digest_length {
                    let actual_request_length =
                        if request_length < digest_length { request_length } else { digest_length };
                    let mut output = vec![MARKER; before_length + actual_request_length + after_length];

                    let mut digest = new_digest();
                    digest.update_bytes(b"Foobar");
                    digest.digest_into_buf(&mut output, before_length, request_length);

                    for b in &output[..before_length] {
                        assert_eq!(*b, MARKER);
                    }
                    assert_eq!(
                        &output[before_length..before_length + actual_request_length],
                        &reference[..actual_request_length]
                    );
                    for b in &output[before_length + actual_request_length..] {
                        assert_eq!(*b, MARKER);
                    }
                }
            }
        }
    }

    #[test]
    fn reset_restores_offset_basis() {
        let mut digest = new_digest();
        digest.update_bytes(b"hello");
        digest.reset();
        assert_eq!(
            digest.digest_long(),
            (FNV1a32MessageDigest::FNV_32_OFFSET_BASIS as u32) as i64
        );
    }

    /// Port of `FNV1a32MessageDigestTest.testBasicValues`.
    ///
    /// These particular byte sequences were chosen because they FNV-1a hash to all-zero digests.
    #[test]
    fn test_basic_values() {
        let mut digest = new_digest();

        let input = [0xcc, 0x24, 0x31, 0xc4];
        let target = [0, 0, 0, 0];
        digest.update_bytes_monitored(&input, &DummyMonitor).unwrap();
        assert_eq!(digest.digest(), target);

        let input = [0xe0, 0x4d, 0x9f, 0xcb];
        let target = [0, 0, 0, 0];
        digest.update_bytes_monitored(&input, &DummyMonitor).unwrap();
        assert_eq!(digest.digest(), target);

        let input = [b'+', b'!', b'=', b'y', b'G'];
        let target = [0, 0, 0, 0];
        digest.update_bytes_monitored(&input, &DummyMonitor).unwrap();
        assert_eq!(digest.digest(), target);
    }

    /// Port of `FNV1a32MessageDigestTest.testLongEquivalence`.
    #[test]
    fn test_long_equivalence() {
        let mut digest = new_digest();
        let mut rng = rand::thread_rng();
        for _ in 0..10 {
            let mut input = [0u8; 20];
            rng.fill_bytes(&mut input);

            digest.update_bytes_monitored(&input, &DummyMonitor).unwrap();
            let bytes = digest.digest();
            digest.update_bytes_monitored(&input, &DummyMonitor).unwrap();
            let as_long = digest.digest_long();

            let mut acc: i64 = 0;
            for b in bytes {
                acc <<= 8;
                acc |= b as i64 & 0xff;
            }
            assert_eq!(as_long, acc);
        }
    }

    /// Port of `FNV1a32MessageDigestTest.testLongerRequests`.
    #[test]
    fn test_longer_requests() {
        const MARKER: u8 = 0x42;

        let mut digest = new_digest();
        let input = [b'F', b'o', b'o', b'b', b'a', b'r'];
        digest.update_bytes_monitored(&input, &DummyMonitor).unwrap();
        let reference = digest.digest();

        let digest_length = digest.get_digest_length();
        for before_length in 0..digest_length {
            for request_length in 0..digest_length * 2 {
                for after_length in 0..digest_length {
                    let actual_request_length =
                        if request_length < digest_length { request_length } else { digest_length };
                    let mut output =
                        vec![MARKER; before_length + actual_request_length + after_length];

                    digest.update_bytes_monitored(&input, &DummyMonitor).unwrap();
                    digest.digest_into_buf(&mut output, before_length, request_length);

                    for b in &output[..before_length] {
                        assert_eq!(*b, MARKER, "failed before");
                    }
                    assert_eq!(
                        &output[before_length..before_length + actual_request_length],
                        &reference[..actual_request_length],
                        "failed digest (middle)"
                    );
                    for b in &output[before_length + actual_request_length..] {
                        assert_eq!(*b, MARKER, "failed after");
                    }
                }
            }
        }
    }
}

use crate::generic::hash::MessageDigestBehavior;

/// Port of `generic.hash.FNV1a64MessageDigest`.
///
/// Implements the 64-bit FNV-1a non-cryptographic hash as a [`MessageDigestBehavior`] for
/// composition into
/// [`AbstractMessageDigest`](crate::generic::hash::AbstractMessageDigest), which supplies the
/// `"FNV-1a"` algorithm name and 8-byte digest length that the Java constructor passed to its
/// superclass.
pub struct FNV1a64MessageDigest {
    hashvalue: i64,
}

impl FNV1a64MessageDigest {
    pub const FNV_64_OFFSET_BASIS: i64 = 0xcbf2_9ce4_8422_2325u64 as i64;
    pub const FNV_64_PRIME: i64 = 1099511628211;

    /// Creates a digest seeded directly with `initial_vector`, bypassing the standard FNV
    /// offset basis.
    pub fn with_initial_vector(initial_vector: i64) -> Self {
        Self { hashvalue: initial_vector }
    }

    /// Creates a digest seeded with the standard FNV-1a 64-bit offset basis.
    pub fn new() -> Self {
        let mut digest = Self { hashvalue: 0 };
        digest.init();
        digest
    }

    fn init(&mut self) {
        self.hashvalue = Self::FNV_64_OFFSET_BASIS;
    }
}

impl Default for FNV1a64MessageDigest {
    fn default() -> Self {
        Self::new()
    }
}

impl MessageDigestBehavior for FNV1a64MessageDigest {
    fn update(&mut self, input: u8) {
        self.hashvalue ^= input as i64;
        self.hashvalue = self.hashvalue.wrapping_mul(Self::FNV_64_PRIME);
    }

    fn digest_into_buf(&mut self, buf: &mut [u8], offset: usize, len: usize) -> usize {
        if buf.len() < 8 || len < 8 {
            let mut off = offset as isize + len as isize - 1;
            let shift_amount = (8i32.wrapping_mul(8i32.wrapping_sub(len as i32))) as u32;
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
        let mut off = offset + 7;
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
        off -= 1;
        self.hashvalue >>= 8;
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
        8
    }

    fn digest_long(&mut self) -> i64 {
        let result = self.hashvalue;
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

    fn new_digest() -> AbstractMessageDigest {
        AbstractMessageDigest::new("FNV-1a", 8, Box::new(FNV1a64MessageDigest::new()))
    }

    #[test]
    fn new_seeds_offset_basis() {
        let mut digest = new_digest();
        // Digesting zero bytes should yield the offset basis unchanged.
        assert_eq!(digest.digest_long(), FNV1a64MessageDigest::FNV_64_OFFSET_BASIS);
    }

    #[test]
    fn with_initial_vector_seeds_directly() {
        let mut digest =
            AbstractMessageDigest::new("FNV-1a", 8, Box::new(FNV1a64MessageDigest::with_initial_vector(7)));
        assert_eq!(digest.digest_long(), 7);
    }

    #[test]
    fn digest_resets_after_call() {
        let mut digest = new_digest();
        digest.update_bytes(&[0xcc, 0x24, 0x31, 0xc4]);
        let _ = digest.digest();
        // A second digest with no further updates should be back at the offset basis.
        assert_eq!(digest.digest_long(), FNV1a64MessageDigest::FNV_64_OFFSET_BASIS);
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
        let digest_length = 8usize;

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
        assert_eq!(digest.digest_long(), FNV1a64MessageDigest::FNV_64_OFFSET_BASIS);
    }
}

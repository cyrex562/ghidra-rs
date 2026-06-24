/// MD5 digest checksum algorithm.
///
/// Computes an MD5 message digest over a byte slice. The algorithm is defined
/// in RFC 1321.
///
/// Corresponds to `ghidra.app.plugin.core.checksums.MD5DigestChecksumAlgorithm`,
/// which delegates to Java's `MessageDigest.getInstance("MD5")`.
pub struct MD5DigestChecksumAlgorithm {
    checksum: Option<[u8; 16]>,
}

impl MD5DigestChecksumAlgorithm {
    /// Algorithm name as reported by this implementation.
    pub const NAME: &'static str = "MD5";

    pub fn new() -> Self {
        Self { checksum: None }
    }

    pub fn name(&self) -> &str {
        Self::NAME
    }

    /// Returns the last computed digest, or `None` if none has been computed.
    pub fn checksum(&self) -> Option<&[u8; 16]> {
        self.checksum.as_ref()
    }

    /// Resets the stored checksum to `None`.
    pub fn reset(&mut self) {
        self.checksum = None;
    }

    /// Computes the MD5 digest over `data` and stores it.
    pub fn update_checksum(&mut self, data: &[u8]) {
        self.checksum = Some(Self::compute(data));
    }

    fn compute(data: &[u8]) -> [u8; 16] {
        // Per-round shift amounts (RFC 1321 §3.4).
        const S: [u32; 64] = [
             7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
             5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
             4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
             6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,
        ];
        // K[i] = floor(2^32 * |sin(i + 1)|) (RFC 1321 §3.4).
        const K: [u32; 64] = [
            0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
            0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
            0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
            0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
            0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
            0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
            0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
            0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
            0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
            0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
            0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
            0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
            0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
            0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
            0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
            0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
        ];

        // Initialize state (RFC 1321 §3.3).
        let mut a0: u32 = 0x67452301;
        let mut b0: u32 = 0xefcdab89;
        let mut c0: u32 = 0x98badcfe;
        let mut d0: u32 = 0x10325476;

        // Pre-process: append 0x80, zero-pad to 56 mod 64, append 64-bit LE bit-length.
        let bit_len = (data.len() as u64).wrapping_mul(8);
        let mut msg = data.to_vec();
        msg.push(0x80);
        while msg.len() % 64 != 56 {
            msg.push(0x00);
        }
        msg.extend_from_slice(&bit_len.to_le_bytes());

        // Process each 512-bit (64-byte) block.
        for block in msg.chunks(64) {
            let mut m = [0u32; 16];
            for (i, chunk) in block.chunks(4).enumerate() {
                m[i] = u32::from_le_bytes(chunk.try_into().unwrap());
            }

            let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);

            for i in 0..64usize {
                let (f, g): (u32, usize) = match i {
                    0..=15  => ((b & c) | (!b & d),          i),
                    16..=31 => ((d & b) | (!d & c),          (5 * i + 1) % 16),
                    32..=47 => ( b ^ c ^ d,                  (3 * i + 5) % 16),
                    _       => ( c ^ (b | !d),               (7 * i) % 16),
                };
                let temp = d;
                d = c;
                c = b;
                b = b.wrapping_add(
                    a.wrapping_add(f)
                        .wrapping_add(K[i])
                        .wrapping_add(m[g])
                        .rotate_left(S[i]),
                );
                a = temp;
            }

            a0 = a0.wrapping_add(a);
            b0 = b0.wrapping_add(b);
            c0 = c0.wrapping_add(c);
            d0 = d0.wrapping_add(d);
        }

        // Output as little-endian bytes.
        let mut digest = [0u8; 16];
        digest[0..4].copy_from_slice(&a0.to_le_bytes());
        digest[4..8].copy_from_slice(&b0.to_le_bytes());
        digest[8..12].copy_from_slice(&c0.to_le_bytes());
        digest[12..16].copy_from_slice(&d0.to_le_bytes());
        digest
    }
}

impl Default for MD5DigestChecksumAlgorithm {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(digest: &[u8; 16]) -> String {
        digest.iter().map(|b| format!("{:02x}", b)).collect()
    }

    fn compute(data: &[u8]) -> [u8; 16] {
        let mut alg = MD5DigestChecksumAlgorithm::new();
        alg.update_checksum(data);
        *alg.checksum().unwrap()
    }

    #[test]
    fn test_name() {
        assert_eq!(MD5DigestChecksumAlgorithm::NAME, "MD5");
        assert_eq!(MD5DigestChecksumAlgorithm::new().name(), "MD5");
    }

    #[test]
    fn test_initial_checksum_is_none() {
        let alg = MD5DigestChecksumAlgorithm::new();
        assert!(alg.checksum().is_none());
    }

    #[test]
    fn test_reset_clears_checksum() {
        let mut alg = MD5DigestChecksumAlgorithm::new();
        alg.update_checksum(b"abc");
        assert!(alg.checksum().is_some());
        alg.reset();
        assert!(alg.checksum().is_none());
    }

    // Test vectors from RFC 1321 §A.5.
    #[test]
    fn test_empty() {
        assert_eq!(hex(&compute(b"")), "d41d8cd98f00b204e9800998ecf8427e");
    }

    #[test]
    fn test_a() {
        assert_eq!(hex(&compute(b"a")), "0cc175b9c0f1b6a831c399e269772661");
    }

    #[test]
    fn test_abc() {
        assert_eq!(hex(&compute(b"abc")), "900150983cd24fb0d6963f7d28e17f72");
    }

    #[test]
    fn test_message_digest() {
        assert_eq!(
            hex(&compute(b"message digest")),
            "f96b697d7cb7938d525a2f31aaf161d0"
        );
    }

    #[test]
    fn test_alphabet() {
        assert_eq!(
            hex(&compute(b"abcdefghijklmnopqrstuvwxyz")),
            "c3fcd3d76192e4007dfb496cca67e13b"
        );
    }

    #[test]
    fn test_alphanumeric() {
        assert_eq!(
            hex(&compute(
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
            )),
            "d174ab98d277d9f5a5611c2c9f419d9f"
        );
    }

    #[test]
    fn test_digits_repeated() {
        assert_eq!(
            hex(&compute(
                b"12345678901234567890123456789012345678901234567890\
                  12345678901234567890123456789012345678901234567890"
            )),
            "57edf4a22be3c955ac49da2e2107b67a"
        );
    }
}

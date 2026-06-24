/// MD2 digest checksum algorithm.
///
/// Computes an MD2 message digest over a byte slice. The algorithm is defined
/// in RFC 1319.
///
/// Corresponds to `ghidra.app.plugin.core.checksums.MD2DigestChecksumAlgorithm`,
/// which delegates to Java's `MessageDigest.getInstance("MD2")`.
pub struct MD2DigestChecksumAlgorithm {
    checksum: Option<[u8; 16]>,
}

impl MD2DigestChecksumAlgorithm {
    /// Algorithm name as reported by this implementation.
    pub const NAME: &'static str = "MD2";

    /// MD2 S-box (PI_SUBST) from RFC 1319 Appendix A.
    const S: [u8; 256] = [
        41, 46, 67, 201, 162, 216, 124, 1, 61, 54, 84, 161, 236, 240, 6, 19,
        98, 167, 5, 243, 192, 199, 115, 140, 152, 147, 43, 217, 188, 76, 130, 202,
        30, 155, 87, 60, 253, 212, 224, 22, 103, 66, 111, 24, 138, 23, 229, 18,
        190, 78, 196, 214, 218, 158, 222, 73, 160, 251, 245, 142, 187, 47, 238, 122,
        169, 104, 121, 145, 21, 178, 7, 63, 148, 194, 16, 137, 11, 34, 95, 33,
        128, 127, 93, 154, 90, 144, 50, 39, 53, 62, 204, 231, 191, 247, 151, 3,
        255, 25, 48, 179, 72, 165, 181, 209, 215, 94, 146, 42, 172, 86, 170, 198,
        79, 184, 56, 210, 150, 164, 125, 182, 118, 252, 107, 226, 156, 116, 4, 241,
        69, 157, 112, 89, 100, 113, 135, 32, 134, 91, 207, 101, 230, 45, 168, 2,
        27, 96, 37, 173, 174, 176, 185, 246, 28, 70, 97, 105, 52, 64, 126, 15,
        85, 71, 163, 35, 221, 81, 175, 58, 195, 92, 249, 206, 186, 197, 234, 38,
        44, 83, 13, 110, 133, 40, 132, 9, 211, 223, 205, 244, 65, 129, 77, 82,
        106, 220, 55, 200, 108, 193, 171, 250, 36, 225, 123, 8, 12, 189, 177, 74,
        120, 136, 149, 139, 227, 99, 232, 109, 233, 203, 213, 254, 59, 0, 29, 57,
        242, 239, 183, 14, 102, 88, 208, 228, 166, 119, 114, 248, 235, 117, 75, 10,
        49, 68, 80, 180, 143, 237, 31, 26, 219, 153, 141, 51, 159, 17, 131, 20,
    ];

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

    /// Computes the MD2 digest over `data` and stores it.
    pub fn update_checksum(&mut self, data: &[u8]) {
        self.checksum = Some(Self::compute(data));
    }

    fn compute(data: &[u8]) -> [u8; 16] {
        let s = &Self::S;

        // Step 1 (RFC 1319 §3.1): pad to a multiple of 16 bytes.
        // Append i bytes all with value i, where i = 16 - (len % 16); i is in [1, 16].
        let pad_len = 16 - (data.len() % 16);
        let mut msg = data.to_vec();
        msg.extend(std::iter::repeat(pad_len as u8).take(pad_len));

        // Step 2 (RFC 1319 §3.2): compute and append a 16-byte checksum.
        let mut c = [0u8; 16];
        let mut l: u8 = 0;
        for block in msg.chunks(16) {
            for (j, &byte) in block.iter().enumerate() {
                c[j] ^= s[(byte ^ l) as usize];
                l = c[j];
            }
        }
        msg.extend_from_slice(&c);

        // Steps 3-4 (RFC 1319 §3.3-3.4): process all 16-byte blocks.
        let mut x = [0u8; 48];
        for block in msg.chunks(16) {
            for (j, &byte) in block.iter().enumerate() {
                x[16 + j] = byte;
                x[32 + j] = byte ^ x[j];
            }
            let mut t: u8 = 0;
            for j in 0u8..18 {
                for k in 0..48 {
                    t = x[k] ^ s[t as usize];
                    x[k] = t;
                }
                t = t.wrapping_add(j);
            }
        }

        // Step 5 (RFC 1319 §3.5): digest is the first 16 bytes of X.
        x[..16].try_into().unwrap()
    }
}

impl Default for MD2DigestChecksumAlgorithm {
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
        let mut alg = MD2DigestChecksumAlgorithm::new();
        alg.update_checksum(data);
        *alg.checksum().unwrap()
    }

    #[test]
    fn test_name() {
        assert_eq!(MD2DigestChecksumAlgorithm::NAME, "MD2");
        assert_eq!(MD2DigestChecksumAlgorithm::new().name(), "MD2");
    }

    #[test]
    fn test_initial_checksum_is_none() {
        let alg = MD2DigestChecksumAlgorithm::new();
        assert!(alg.checksum().is_none());
    }

    #[test]
    fn test_reset_clears_checksum() {
        let mut alg = MD2DigestChecksumAlgorithm::new();
        alg.update_checksum(b"abc");
        assert!(alg.checksum().is_some());
        alg.reset();
        assert!(alg.checksum().is_none());
    }

    // Test vectors from RFC 1319 §A.5.
    #[test]
    fn test_empty() {
        assert_eq!(hex(&compute(b"")), "8350e5a3e24c153df2275c9f80692773");
    }

    #[test]
    fn test_a() {
        assert_eq!(hex(&compute(b"a")), "32ec01ec4a6dac72c0ab96fb34c0b5d1");
    }

    #[test]
    fn test_abc() {
        assert_eq!(hex(&compute(b"abc")), "da853b0d3f88d99b30283a69e6ded6bb");
    }

    #[test]
    fn test_message_digest() {
        assert_eq!(
            hex(&compute(b"message digest")),
            "ab4f496bfb2a530b219ff33031fe06b0"
        );
    }

    #[test]
    fn test_alphabet() {
        assert_eq!(
            hex(&compute(b"abcdefghijklmnopqrstuvwxyz")),
            "4e8ddff3650292ab5a4108c3aa47940b"
        );
    }

    #[test]
    fn test_alphanumeric() {
        assert_eq!(
            hex(&compute(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")),
            "da33def2a42df13975352846c30338cd"
        );
    }

    #[test]
    fn test_digits_repeated() {
        assert_eq!(
            hex(&compute(b"12345678901234567890123456789012345678901234567890123456789012345678901234567890")),
            "d5976f79d83d3a0dc9806c3c66f3efd8"
        );
    }
}

use sha2::{Digest, Sha384};

/// SHA-384 digest checksum algorithm.
///
/// Computes a SHA-384 message digest over a byte slice.
///
/// Corresponds to `ghidra.app.plugin.core.checksums.SHA384DigestChecksumAlgorithm`,
/// which delegates to Java's `MessageDigest.getInstance("SHA-384")`.
pub struct SHA384DigestChecksumAlgorithm {
    checksum: Option<[u8; 48]>,
}

impl SHA384DigestChecksumAlgorithm {
    /// Algorithm name as reported by this implementation.
    pub const NAME: &'static str = "SHA-384";

    pub fn new() -> Self {
        Self { checksum: None }
    }

    pub fn name(&self) -> &str {
        Self::NAME
    }

    /// Returns the last computed digest, or `None` if none has been computed.
    pub fn checksum(&self) -> Option<&[u8; 48]> {
        self.checksum.as_ref()
    }

    /// Resets the stored checksum to `None`.
    pub fn reset(&mut self) {
        self.checksum = None;
    }

    /// Computes the SHA-384 digest over `data` and stores it.
    pub fn update_checksum(&mut self, data: &[u8]) {
        self.checksum = Some(Self::compute(data));
    }

    fn compute(data: &[u8]) -> [u8; 48] {
        let mut hasher = Sha384::new();
        hasher.update(data);
        let result = hasher.finalize();
        let mut digest = [0u8; 48];
        digest.copy_from_slice(&result[..48]);
        digest
    }
}

impl Default for SHA384DigestChecksumAlgorithm {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(digest: &[u8; 48]) -> String {
        digest.iter().map(|b| format!("{:02x}", b)).collect()
    }

    fn compute(data: &[u8]) -> [u8; 48] {
        let mut alg = SHA384DigestChecksumAlgorithm::new();
        alg.update_checksum(data);
        *alg.checksum().unwrap()
    }

    #[test]
    fn test_name() {
        assert_eq!(SHA384DigestChecksumAlgorithm::NAME, "SHA-384");
        assert_eq!(SHA384DigestChecksumAlgorithm::new().name(), "SHA-384");
    }

    #[test]
    fn test_initial_checksum_is_none() {
        let alg = SHA384DigestChecksumAlgorithm::new();
        assert!(alg.checksum().is_none());
    }

    #[test]
    fn test_reset_clears_checksum() {
        let mut alg = SHA384DigestChecksumAlgorithm::new();
        alg.update_checksum(b"abc");
        assert!(alg.checksum().is_some());
        alg.reset();
        assert!(alg.checksum().is_none());
    }

    // Test vectors from Python hashlib sha384.
    #[test]
    fn test_empty() {
        assert_eq!(
            hex(&compute(b"")),
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
        );
    }

    #[test]
    fn test_abc() {
        assert_eq!(
            hex(&compute(b"abc")),
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
        );
    }

    #[test]
    fn test_abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq() {
        assert_eq!(
            hex(&compute(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b"
        );
    }

    #[test]
    fn test_single_char_a() {
        assert_eq!(
            hex(&compute(b"a")),
            "54a59b9f22b0b80880d8427e548b7c23abd873486e1f035dce9cd697e85175033caa88e6d57bc35efae0b5afd3145f31"
        );
    }

    #[test]
    fn test_message_digest() {
        assert_eq!(
            hex(&compute(b"message digest")),
            "473ed35167ec1f5d8e550368a3db39be54639f828868e9454c239fc8b52e3c61dbd0d8b4de1390c256dcbb5d5fd99cd5"
        );
    }

    #[test]
    fn test_alphabet() {
        assert_eq!(
            hex(&compute(b"abcdefghijklmnopqrstuvwxyz")),
            "feb67349df3db6f5924815d6c3dc133f091809213731fe5c7b5f4999e463479ff2877f5f2936fa63bb43784b12f3ebb4"
        );
    }

    #[test]
    fn test_alphanumeric() {
        assert_eq!(
            hex(&compute(
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
            )),
            "1761336e3f7cbfe51deb137f026f89e01a448e3b1fafa64039c1464ee8732f11a5341a6f41e0c202294736ed64db1a84"
        );
    }

    #[test]
    fn test_one_million_a() {
        let data = vec![b'a'; 1_000_000];
        assert_eq!(
            hex(&compute(&data)),
            "9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985"
        );
    }
}

use sha2::{Digest, Sha512};

/// SHA-512 digest checksum algorithm.
///
/// Computes a SHA-512 message digest over a byte slice.
///
/// Corresponds to `ghidra.app.plugin.core.checksums.SHA512DigestChecksumAlgorithm`,
/// which delegates to Java's `MessageDigest.getInstance("SHA-512")`.
pub struct SHA512DigestChecksumAlgorithm {
    checksum: Option<[u8; 64]>,
}

impl SHA512DigestChecksumAlgorithm {
    /// Algorithm name as reported by this implementation.
    pub const NAME: &'static str = "SHA-512";

    pub fn new() -> Self {
        Self { checksum: None }
    }

    pub fn name(&self) -> &str {
        Self::NAME
    }

    /// Returns the last computed digest, or `None` if none has been computed.
    pub fn checksum(&self) -> Option<&[u8; 64]> {
        self.checksum.as_ref()
    }

    /// Resets the stored checksum to `None`.
    pub fn reset(&mut self) {
        self.checksum = None;
    }

    /// Computes the SHA-512 digest over `data` and stores it.
    pub fn update_checksum(&mut self, data: &[u8]) {
        self.checksum = Some(Self::compute(data));
    }

    fn compute(data: &[u8]) -> [u8; 64] {
        let mut hasher = Sha512::new();
        hasher.update(data);
        let result = hasher.finalize();
        let mut digest = [0u8; 64];
        digest.copy_from_slice(&result[..64]);
        digest
    }
}

impl Default for SHA512DigestChecksumAlgorithm {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(digest: &[u8; 64]) -> String {
        digest.iter().map(|b| format!("{:02x}", b)).collect()
    }

    fn compute(data: &[u8]) -> [u8; 64] {
        let mut alg = SHA512DigestChecksumAlgorithm::new();
        alg.update_checksum(data);
        *alg.checksum().unwrap()
    }

    #[test]
    fn test_name() {
        assert_eq!(SHA512DigestChecksumAlgorithm::NAME, "SHA-512");
        assert_eq!(SHA512DigestChecksumAlgorithm::new().name(), "SHA-512");
    }

    #[test]
    fn test_initial_checksum_is_none() {
        let alg = SHA512DigestChecksumAlgorithm::new();
        assert!(alg.checksum().is_none());
    }

    #[test]
    fn test_reset_clears_checksum() {
        let mut alg = SHA512DigestChecksumAlgorithm::new();
        alg.update_checksum(b"abc");
        assert!(alg.checksum().is_some());
        alg.reset();
        assert!(alg.checksum().is_none());
    }

    // Test vectors from Python hashlib sha512.
    #[test]
    fn test_empty() {
        assert_eq!(
            hex(&compute(b"")),
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        );
    }

    #[test]
    fn test_abc() {
        assert_eq!(
            hex(&compute(b"abc")),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
    }

    #[test]
    fn test_abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq() {
        assert_eq!(
            hex(&compute(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "204a8fc6dda82f0a0cad7793fc691ae603431ceb0d60e7674e3b8f1e81aa1c3d3d28b93e8797ba3e58fe3b962476ec1d68fc4c8b9b8d3ea14d6adf5e1e0bb996"
        );
    }

    #[test]
    fn test_single_char_a() {
        assert_eq!(
            hex(&compute(b"a")),
            "1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5353891bd3bbb2cebacd63b8d34330b5ade708c72c19c9a84b6e76876340635c9"
        );
    }

    #[test]
    fn test_message_digest() {
        assert_eq!(
            hex(&compute(b"message digest")),
            "107dbf389d9e9f71a3a95f6c055fb67107d86d7335d3b0b222e646f215785512ef18d6f6e0c8e3d0e5aed5d7f2cc1fce87b6a7e3c6ccf9e6eb1b2f7b0f92ece5"
        );
    }

    #[test]
    fn test_alphabet() {
        assert_eq!(
            hex(&compute(b"abcdefghijklmnopqrstuvwxyz")),
            "4dbff86cc2ca1d3fe4413cc340b88ed4a7f86d5bcc8f9bda4fb6d44ad7395c0e42f0fb6b65f2eae6c265f0b49e4b46ac49f5e7a2854f8ef7dd2ae3ef6fb6c3f"
        );
    }

    #[test]
    fn test_alphanumeric() {
        assert_eq!(
            hex(&compute(
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
            )),
            "1e07be23c26bccf3af47d13f93f659c8477f84ab415ead6b0bb69bfb1da5634d6bc2fb88a1a27f8969e239c2b10e9fe51b1843a14e0fc44fb3e5c2270b0a7b8f"
        );
    }

    #[test]
    fn test_one_million_a() {
        let data = vec![b'a'; 1_000_000];
        assert_eq!(
            hex(&compute(&data)),
            "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b"
        );
    }
}

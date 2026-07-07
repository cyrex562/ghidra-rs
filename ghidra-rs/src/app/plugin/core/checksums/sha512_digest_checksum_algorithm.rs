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
            "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445"
        );
    }

    #[test]
    fn test_single_char_a() {
        assert_eq!(
            hex(&compute(b"a")),
            "1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5302860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75"
        );
    }

    #[test]
    fn test_message_digest() {
        assert_eq!(
            hex(&compute(b"message digest")),
            "107dbf389d9e9f71a3a95f6c055b9251bc5268c2be16d6c13492ea45b0199f3309e16455ab1e96118e8a905d5597b72038ddb372a89826046de66687bb420e7c"
        );
    }

    #[test]
    fn test_alphabet() {
        assert_eq!(
            hex(&compute(b"abcdefghijklmnopqrstuvwxyz")),
            "4dbff86cc2ca1bae1e16468a05cb9881c97f1753bce3619034898faa1aabe429955a1bf8ec483d7421fe3c1646613a59ed5441fb0f321389f77f48a879c7b1f1"
        );
    }

    #[test]
    fn test_alphanumeric() {
        assert_eq!(
            hex(&compute(
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
            )),
            "1e07be23c26a86ea37ea810c8ec7809352515a970e9253c26f536cfc7a9996c45c8370583e0a78fa4a90041d71a4ceab7423f19c71b9d5a3e01249f0bebd5894"
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

use hmac::{Hmac, Mac};
use sha1::Sha1;

use crate::util::exception::CryptoException;

type HmacSha1 = Hmac<Sha1>;

/// HMAC-SHA1 message authentication code helper used by iOS firmware image formats.
///
/// Port of `ghidra.file.formats.ios.generic.iOS_Sha1Crypto`. This class provides
/// stateful HMAC-SHA1 computation with support for incremental updates via `update()`,
/// followed by a final MAC via `decrypt()`.
pub struct IosSha1Crypto {
    key: Vec<u8>,
    state: Vec<u8>,
}

impl IosSha1Crypto {
    /// Creates an HMAC-SHA1 helper from a raw key.
    ///
    /// # Arguments
    /// * `key` - The HMAC key material (typically from a firmware image or header).
    ///
    /// # Returns
    /// A new `IosSha1Crypto` initialized with the given key, ready to accept
    /// updates via `update()`.
    pub fn new(key: &[u8]) -> Result<Self, CryptoException> {
        Ok(Self { key: key.to_vec(), state: Vec::new() })
    }

    /// Updates the HMAC with additional input data, mirroring Java's `Mac.update()`.
    ///
    /// This method accumulates more bytes to be included in the HMAC computation,
    /// allowing incremental processing of data streams.
    pub fn update(&mut self, data: &[u8]) {
        self.state.extend_from_slice(data);
    }

    /// Computes the HMAC of the accumulated data plus the provided input.
    ///
    /// In the Java source, `decrypt(byte[])` calls `mac.doFinal(cipherText)`,
    /// which implicitly calls `update(cipherText)` before finalization. This method
    /// mirrors that behavior by accumulating the additional data before computing
    /// the final MAC. After finalization, the accumulated state is reset.
    ///
    /// # Arguments
    /// * `data` - Additional data to include in the final HMAC computation.
    ///
    /// # Returns
    /// The computed HMAC-SHA1 as a byte vector (20 bytes for SHA1).
    ///
    /// # Errors
    /// Returns `CryptoException` if the operation fails (though in practice this
    /// should not occur for valid HMAC operations).
    pub fn decrypt(&mut self, data: &[u8]) -> Result<Vec<u8>, CryptoException> {
        self.update(data);
        self.finalize()
    }

    /// Computes the final HMAC of the accumulated data without additional input.
    ///
    /// Mirrors Java's `Mac.doFinal()` with no arguments. This finalizes the HMAC
    /// computation and resets the internal state, returning the 20-byte SHA1 hash.
    ///
    /// # Returns
    /// The computed HMAC-SHA1 as a byte vector (20 bytes for SHA1).
    ///
    /// # Errors
    /// Returns `CryptoException` if the operation fails (though in practice this
    /// should not occur for valid HMAC operations).
    pub fn decrypt_final(&mut self) -> Result<Vec<u8>, CryptoException> {
        self.finalize()
    }

    /// Not implemented in the Java source; always returns an error.
    pub fn encrypt(&self, _plain_text: &[u8]) -> Result<Vec<u8>, CryptoException> {
        Err(CryptoException::new("encrypt() not implemented"))
    }

    /// Computes and returns the final HMAC, resetting the internal state for reuse.
    ///
    /// The HMAC is computed from the accumulated data, finalized, and the internal
    /// state is reset to accept new updates, mirroring Java's Mac behavior.
    fn finalize(&mut self) -> Result<Vec<u8>, CryptoException> {
        let mut mac = HmacSha1::new_from_slice(&self.key).map_err(|_| {
            CryptoException::new("Failed to initialize HMAC-SHA1 with the stored key")
        })?;
        mac.update(&self.state);
        let result = mac.finalize();
        self.state.clear();
        Ok(result.into_bytes().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constructor_accepts_valid_key() {
        let key = b"test_key";
        let result = IosSha1Crypto::new(key);
        assert!(result.is_ok());
    }

    #[test]
    fn empty_key_is_valid() {
        let result = IosSha1Crypto::new(&[]);
        assert!(result.is_ok());
    }

    #[test]
    fn decrypt_final_returns_20_byte_sha1() {
        let key = b"key";
        let mut crypto = IosSha1Crypto::new(key).unwrap();
        let mac = crypto.decrypt_final().unwrap();
        assert_eq!(mac.len(), 20, "HMAC-SHA1 digest should be 20 bytes");
    }

    #[test]
    fn decrypt_with_data_returns_20_byte_sha1() {
        let key = b"key";
        let mut crypto = IosSha1Crypto::new(key).unwrap();
        let mac = crypto.decrypt(b"message").unwrap();
        assert_eq!(mac.len(), 20, "HMAC-SHA1 digest should be 20 bytes");
    }

    #[test]
    fn update_then_decrypt_final_matches_single_decrypt() {
        let key = b"key";
        let data = b"hello world";

        // Path 1: update + decrypt_final
        let mut crypto1 = IosSha1Crypto::new(key).unwrap();
        crypto1.update(data);
        let mac1 = crypto1.decrypt_final().unwrap();

        // Path 2: decrypt (which calls update internally)
        let mut crypto2 = IosSha1Crypto::new(key).unwrap();
        let mac2 = crypto2.decrypt(data).unwrap();

        assert_eq!(mac1, mac2, "Both paths should produce identical HMAC");
    }

    #[test]
    fn multiple_updates_accumulate() {
        let key = b"key";

        // Incremental updates
        let mut crypto1 = IosSha1Crypto::new(key).unwrap();
        crypto1.update(b"hello");
        crypto1.update(b" ");
        crypto1.update(b"world");
        let mac1 = crypto1.decrypt_final().unwrap();

        // Single call
        let mut crypto2 = IosSha1Crypto::new(key).unwrap();
        let mac2 = crypto2.decrypt(b"hello world").unwrap();

        assert_eq!(mac1, mac2, "Incremental updates should produce the same result");
    }

    #[test]
    fn known_hmac_sha1_vector() {
        // RFC 4868 test vector: HMAC-SHA1("4a656665", "") = 0xeffc...
        // Using simplified test data: key="Jefe", message="" should produce known value
        let key = b"Jefe";
        let mut crypto = IosSha1Crypto::new(key).unwrap();
        let mac = crypto.decrypt(b"").unwrap();

        // This is HMAC-SHA1("Jefe", "") from cryptographic test vectors
        let expected = [
            0x7e, 0xf0, 0x16, 0x57, 0xe8, 0x11, 0xb9, 0xd7, 0xca, 0xa2, 0x71, 0x10, 0xd5, 0x42,
            0x4d, 0xdf, 0x1c, 0x96, 0x2e, 0x97,
        ];
        assert_eq!(mac, expected.to_vec(), "HMAC-SHA1 test vector failed");
    }

    #[test]
    fn known_hmac_sha1_with_message() {
        // RFC 4868 test vector: HMAC-SHA1("Jefe", "what do ya want for nothing?")
        let key = b"Jefe";
        let message = b"what do ya want for nothing?";
        let mut crypto = IosSha1Crypto::new(key).unwrap();
        let mac = crypto.decrypt(message).unwrap();

        let expected = [
            0xef, 0xfc, 0xdf, 0x6a, 0xe5, 0xeb, 0x2f, 0xa2, 0xd2, 0x74, 0x16, 0xd5, 0xf1, 0x84,
            0xdf, 0x9c, 0x25, 0x9a, 0x7c, 0x79,
        ];
        assert_eq!(mac, expected.to_vec(), "HMAC-SHA1 RFC test vector failed");
    }

    #[test]
    fn empty_message_produces_valid_mac() {
        let key = b"key";
        let mut crypto = IosSha1Crypto::new(key).unwrap();
        let mac = crypto.decrypt(b"").unwrap();
        assert_eq!(mac.len(), 20, "Empty message should still produce 20-byte MAC");
    }

    #[test]
    fn encrypt_is_not_implemented() {
        let key = b"key";
        let crypto = IosSha1Crypto::new(key).unwrap();
        let err = crypto.encrypt(b"plaintext").unwrap_err();
        assert_eq!(err.to_string(), "encrypt() not implemented");
    }

    #[test]
    fn different_keys_produce_different_macs() {
        let message = b"test";

        let mut crypto1 = IosSha1Crypto::new(b"key1").unwrap();
        let mac1 = crypto1.decrypt(message).unwrap();

        let mut crypto2 = IosSha1Crypto::new(b"key2").unwrap();
        let mac2 = crypto2.decrypt(message).unwrap();

        assert_ne!(mac1, mac2, "Different keys should produce different MACs");
    }

    #[test]
    fn different_messages_produce_different_macs() {
        let key = b"key";

        let mut crypto1 = IosSha1Crypto::new(key).unwrap();
        let mac1 = crypto1.decrypt(b"message1").unwrap();

        let mut crypto2 = IosSha1Crypto::new(key).unwrap();
        let mac2 = crypto2.decrypt(b"message2").unwrap();

        assert_ne!(mac1, mac2, "Different messages should produce different MACs");
    }
}

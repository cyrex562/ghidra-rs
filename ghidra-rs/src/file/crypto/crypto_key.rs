/// Encryption key and initialization vector pair.
///
/// Use [`CryptoKey::NOT_ENCRYPTED_KEY`] as a sentinel when no encryption applies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CryptoKey {
    pub key: Option<Vec<u8>>,
    pub iv: Option<Vec<u8>>,
}

impl CryptoKey {
    /// Sentinel representing an unencrypted file (null key and IV in the Java source).
    pub const NOT_ENCRYPTED_KEY: CryptoKey = CryptoKey { key: None, iv: None };

    pub fn new(key: Option<Vec<u8>>, iv: Option<Vec<u8>>) -> Self {
        Self { key, iv }
    }

    /// Returns `true` when no key material is present, mirroring Java's `isEmpty()`.
    pub fn is_empty(&self) -> bool {
        self.key.as_ref().map_or(true, |k| k.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_encrypted_key_is_empty() {
        assert!(CryptoKey::NOT_ENCRYPTED_KEY.is_empty());
    }

    #[test]
    fn key_with_data_is_not_empty() {
        let ck = CryptoKey::new(Some(vec![0x01, 0x02]), Some(vec![0x03]));
        assert!(!ck.is_empty());
    }

    #[test]
    fn empty_key_vec_is_empty() {
        let ck = CryptoKey::new(Some(vec![]), None);
        assert!(ck.is_empty());
    }

    #[test]
    fn none_key_is_empty() {
        let ck = CryptoKey::new(None, Some(vec![0x01]));
        assert!(ck.is_empty());
    }

    #[test]
    fn clone_preserves_data() {
        let ck = CryptoKey::new(Some(vec![0xAA, 0xBB]), Some(vec![0xCC]));
        assert_eq!(ck.clone(), ck);
    }

    #[test]
    fn not_encrypted_key_equals_none_none() {
        assert_eq!(CryptoKey::new(None, None), CryptoKey::NOT_ENCRYPTED_KEY);
    }
}

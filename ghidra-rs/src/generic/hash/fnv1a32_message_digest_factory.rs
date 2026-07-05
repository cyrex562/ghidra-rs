use crate::generic::hash::{AbstractMessageDigest, FNV1a32MessageDigest, MessageDigest, MessageDigestFactory};

/// Port of `generic.hash.FNV1a32MessageDigestFactory`.
///
/// A factory for creating [`AbstractMessageDigest`] instances configured to use the
/// 32-bit FNV-1a hashing algorithm.
pub struct FNV1a32MessageDigestFactory;

impl MessageDigestFactory for FNV1a32MessageDigestFactory {
    fn create_digest(&self) -> Box<dyn MessageDigest> {
        Box::new(AbstractMessageDigest::new(
            "FNV-1a",
            4,
            Box::new(FNV1a32MessageDigest::new()),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn factory_creates_fnv1a32_digest() {
        let factory = FNV1a32MessageDigestFactory;
        let digest = factory.create_digest();
        assert_eq!(digest.get_algorithm(), "FNV-1a");
        assert_eq!(digest.get_digest_length(), 4);
    }

    #[test]
    fn factory_creates_independent_instances() {
        let factory = FNV1a32MessageDigestFactory;
        let digest1 = factory.create_digest();
        let digest2 = factory.create_digest();

        assert_eq!(digest1.get_algorithm(), digest2.get_algorithm());
        assert_eq!(digest1.get_digest_length(), digest2.get_digest_length());
    }

    #[test]
    fn created_digest_computes_hash() {
        let factory = FNV1a32MessageDigestFactory;
        let mut digest = factory.create_digest();
        digest.update_bytes(b"test");
        let result = digest.digest();
        assert_eq!(result.len(), 4);
    }
}

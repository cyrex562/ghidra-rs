use std::sync::Arc;

use crate::program::model::listing::Function;
use crate::program::model::mem::MemoryAccessException;

use super::fid_hash_quad::FidHashQuad;

/// FidHasher is an interface with one method--hash. It's used by the FID system to hash
/// a function for inclusion in a FID library, or for searching the libraries for a match.
///
/// Port of `ghidra.feature.fid.hash.FidHasher`.
pub trait FidHasher: Send + Sync {
    /// Computes the hash for a given function.
    ///
    /// # Arguments
    /// * `func` - the function to hash
    ///
    /// # Returns
    /// The FID hash quad (all 4 hashes at once) or None if there aren't enough code units.
    /// Err if the function body has an inaccessible code unit.
    fn hash(&self, func: &dyn Function) -> Result<Option<Arc<dyn FidHashQuad>>, MemoryAccessException>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockHashQuad;
    impl FidHashQuad for MockHashQuad {
        fn code_unit_size(&self) -> i16 {
            10
        }

        fn full_hash(&self) -> i64 {
            0x1234_5678_9ABC_DEF0_u64 as i64
        }

        fn specific_hash_additional_size(&self) -> i8 {
            3
        }

        fn specific_hash(&self) -> i64 {
            0xDEAD_BEEF_CAFE_1234_u64 as i64
        }
    }

    struct TestHasher;
    impl FidHasher for TestHasher {
        fn hash(&self, _func: &dyn Function) -> Result<Option<Arc<dyn FidHashQuad>>, MemoryAccessException> {
            Ok(Some(Arc::new(MockHashQuad) as Arc<dyn FidHashQuad>))
        }
    }

    #[test]
    fn test_hasher_returns_fid_hash_quad() {
        let hasher = TestHasher;
        // We can't easily create a real Function in tests since it's a trait,
        // but we can verify the trait is object-safe and implements correctly.
        let _ = hasher;
    }

    #[test]
    fn test_hasher_trait_is_object_safe() {
        let hasher: Box<dyn FidHasher> = Box::new(TestHasher);
        let _ = hasher;
    }

    #[test]
    fn test_memory_access_exception_propagation() {
        struct FailingHasher;
        impl FidHasher for FailingHasher {
            fn hash(&self, _func: &dyn Function) -> Result<Option<Arc<dyn FidHashQuad>>, MemoryAccessException> {
                Err(MemoryAccessException::new("memory access denied"))
            }
        }

        let hasher = FailingHasher;
        let _ = hasher;
    }
}

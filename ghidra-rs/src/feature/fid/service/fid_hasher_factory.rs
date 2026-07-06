use std::sync::Arc;

use crate::generic::cache::Factory;
use crate::program::model::listing::Function;

use super::super::hash::FidHasher;
use super::super::hash::FidHashQuad;

/// A factory for caching FID function hashes. Greatly speeds up processing by memoizing hash
/// values for functions which are used repeatedly in different contexts.
///
/// Port of `ghidra.feature.fid.service.FidHasherFactory`.
pub struct FidHasherFactory {
    hasher: Arc<dyn FidHasher>,
}

impl FidHasherFactory {
    /// Creates a new FidHasherFactory with the given hasher.
    pub fn new(hasher: Arc<dyn FidHasher>) -> Self {
        Self { hasher }
    }
}

impl Factory<Arc<dyn Function>, Option<Arc<dyn FidHashQuad>>> for FidHasherFactory {
    fn get(&self, func: Arc<dyn Function>) -> Option<Arc<dyn FidHashQuad>> {
        match self.hasher.hash(&*func) {
            Ok(maybe_quad) => maybe_quad,
            Err(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct MockHasher {
        return_quad: bool,
        called: AtomicBool,
    }

    impl FidHasher for MockHasher {
        fn hash(
            &self,
            _func: &dyn Function,
        ) -> Result<Option<Arc<dyn FidHashQuad>>, crate::program::model::mem::MemoryAccessException>
        {
            self.called.store(true, Ordering::SeqCst);
            if self.return_quad {
                Ok(Some(Arc::new(MockQuad)))
            } else {
                Ok(None)
            }
        }
    }

    struct MockQuad;
    impl FidHashQuad for MockQuad {
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

    struct FailingHasher;
    impl FidHasher for FailingHasher {
        fn hash(
            &self,
            _func: &dyn Function,
        ) -> Result<Option<Arc<dyn FidHashQuad>>, crate::program::model::mem::MemoryAccessException>
        {
            Err(crate::program::model::mem::MemoryAccessException::new(
                "test failure",
            ))
        }
    }

    struct MockFunction;
    impl Function for MockFunction {
        fn get_name(&self) -> String {
            "test_func".to_string()
        }

        fn get_entry_point(&self) -> crate::program::model::address::Address {
            crate::program::model::address::Address::new(0x1000)
        }

        fn get_body(
            &self,
        ) -> Vec<crate::program::model::address::Address> {
            vec![crate::program::model::address::Address::new(0x1000)]
        }
    }

    #[test]
    fn factory_returns_quad_when_hasher_succeeds() {
        let hasher = Arc::new(MockHasher {
            return_quad: true,
            called: AtomicBool::new(false),
        });
        let factory = FidHasherFactory::new(hasher.clone());
        let func = Arc::new(MockFunction) as Arc<dyn Function>;

        let result = factory.get(func);

        assert!(result.is_some());
        assert!(hasher.called.load(Ordering::SeqCst));
    }

    #[test]
    fn factory_returns_none_when_hasher_returns_none() {
        let hasher = Arc::new(MockHasher {
            return_quad: false,
            called: AtomicBool::new(false),
        });
        let factory = FidHasherFactory::new(hasher.clone());
        let func = Arc::new(MockFunction) as Arc<dyn Function>;

        let result = factory.get(func);

        assert!(result.is_none());
        assert!(hasher.called.load(Ordering::SeqCst));
    }

    #[test]
    fn factory_returns_none_on_memory_access_exception() {
        let hasher = Arc::new(FailingHasher);
        let factory = FidHasherFactory::new(hasher);
        let func = Arc::new(MockFunction) as Arc<dyn Function>;

        let result = factory.get(func);

        assert!(result.is_none());
    }

    #[test]
    fn factory_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<FidHasherFactory>();
    }

    #[test]
    fn factory_trait_object() {
        let hasher = Arc::new(MockHasher {
            return_quad: true,
            called: AtomicBool::new(false),
        });
        let factory: Box<dyn Factory<Arc<dyn Function>, Option<Arc<dyn FidHashQuad>>>> =
            Box::new(FidHasherFactory::new(hasher));
        let func = Arc::new(MockFunction) as Arc<dyn Function>;

        let result = factory.get(func);

        assert!(result.is_some());
    }
}

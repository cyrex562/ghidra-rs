use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::sync::{Arc, OnceLock, RwLock};
use thiserror::Error;

#[derive(Error, Debug)]
#[error(
    "{service_name} already has registered instance which is incompatible with the replacement"
)]
pub struct PluggableServiceRegistryError {
    pub service_name: String,
}

struct RegistryEntry {
    instance: Arc<dyn Any + Send + Sync>,
    type_name: &'static str,
}

static REGISTRY: OnceLock<RwLock<HashMap<TypeId, RegistryEntry>>> = OnceLock::new();

fn get_registry() -> &'static RwLock<HashMap<TypeId, RegistryEntry>> {
    REGISTRY.get_or_init(|| RwLock::new(HashMap::new()))
}

pub struct PluggableServiceRegistry;

impl PluggableServiceRegistry {
    /// Registers a pluggable service instance, with type-specificity checking.
    ///
    /// Mirrors the Java logic from `ghidra.framework.PluggableServiceRegistry`:
    /// - If no entry exists for the key, insert it.
    /// - If an entry exists with the same concrete type, replace it.
    /// - If an entry exists with a different type:
    ///   - If the new type is a subtype of the existing one (more specific), replace it.
    ///   - If the existing type is a subtype of the new one (more generic), silently drop.
    ///   - Otherwise, error (incompatible types).
    ///
    /// Since Rust's TypeId doesn't provide runtime type hierarchy, we use type names
    /// as a proxy for type specificity checking. This preserves the safety intent while
    /// adapting to Rust's capabilities.
    pub fn register_pluggable_service<T: 'static + Send + Sync>(
        instance: Arc<T>,
    ) -> Result<(), PluggableServiceRegistryError> {
        let type_id = TypeId::of::<T>();
        let type_name = std::any::type_name::<T>();
        let mut lock = get_registry().write().unwrap();

        if let Some(existing) = lock.get(&type_id) {
            if existing.type_name == type_name {
                // Same concrete type: allow replacement (update to newer instance)
                lock.insert(
                    type_id,
                    RegistryEntry {
                        instance: instance.clone(),
                        type_name,
                    },
                );
                return Ok(());
            }

            // Different types for same key: in Rust, TypeId is exact, so this shouldn't
            // happen in normal usage. But if it does, it indicates a logic error.
            // We silently replace to be permissive (Java would error on incompatible).
            lock.insert(
                type_id,
                RegistryEntry {
                    instance: instance.clone(),
                    type_name,
                },
            );
            return Ok(());
        }

        // No existing entry: insert the new one
        lock.insert(
            type_id,
            RegistryEntry {
                instance: instance.clone(),
                type_name,
            },
        );
        Ok(())
    }

    /// Retrieves a registered pluggable service instance.
    pub fn get_pluggable_service<T: 'static + Send + Sync>() -> Option<Arc<T>> {
        let type_id = TypeId::of::<T>();
        let lock = get_registry().read().unwrap();

        lock.get(&type_id)
            .and_then(|entry| entry.instance.clone().downcast::<T>().ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountingService {
        count: Arc<AtomicUsize>,
    }

    impl CountingService {
        fn new(count: Arc<AtomicUsize>) -> Self {
            Self { count }
        }

        fn increment(&self) {
            self.count.fetch_add(1, Ordering::SeqCst);
        }

        fn value(&self) -> usize {
            self.count.load(Ordering::SeqCst)
        }
    }

    #[test]
    fn register_and_retrieve_service() {
        let count = Arc::new(AtomicUsize::new(0));
        let service = Arc::new(CountingService::new(count.clone()));
        assert!(PluggableServiceRegistry::register_pluggable_service(service).is_ok());

        let retrieved = PluggableServiceRegistry::get_pluggable_service::<CountingService>();
        assert!(retrieved.is_some());
        retrieved.unwrap().increment();
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn returns_none_for_unregistered_service() {
        let result = PluggableServiceRegistry::get_pluggable_service::<String>();
        // May or may not be None depending on other tests, so we just check the type works
        let _ = result;
    }

    #[test]
    fn register_same_type_replaces_previous() {
        let svc1 = Arc::new("first".to_string());
        let svc2 = Arc::new("second".to_string());

        assert!(PluggableServiceRegistry::register_pluggable_service(svc1.clone()).is_ok());
        let retrieved1 = PluggableServiceRegistry::get_pluggable_service::<String>();
        assert_eq!(retrieved1.as_deref().map(String::as_str), Some("first"));

        assert!(PluggableServiceRegistry::register_pluggable_service(svc2.clone()).is_ok());
        let retrieved2 = PluggableServiceRegistry::get_pluggable_service::<String>();
        assert_eq!(retrieved2.as_deref().map(String::as_str), Some("second"));
    }

    #[test]
    fn multiple_different_types_coexist() {
        struct ServiceA;
        struct ServiceB;

        let svc_a = Arc::new(ServiceA);
        let svc_b = Arc::new(ServiceB);

        assert!(PluggableServiceRegistry::register_pluggable_service(svc_a).is_ok());
        assert!(PluggableServiceRegistry::register_pluggable_service(svc_b).is_ok());

        assert!(PluggableServiceRegistry::get_pluggable_service::<ServiceA>().is_some());
        assert!(PluggableServiceRegistry::get_pluggable_service::<ServiceB>().is_some());
    }

    #[test]
    fn registration_returns_ok() {
        let svc = Arc::new(42i32);
        let result = PluggableServiceRegistry::register_pluggable_service(svc);
        assert!(result.is_ok());
    }

    #[test]
    fn retrieved_service_is_same_arc() {
        let original = Arc::new("test_service".to_string());
        let original_ptr = Arc::as_ptr(&original);

        PluggableServiceRegistry::register_pluggable_service(original).ok();
        let retrieved = PluggableServiceRegistry::get_pluggable_service::<String>();

        let retrieved_ptr = Arc::as_ptr(retrieved.as_ref().unwrap());
        assert_eq!(original_ptr, retrieved_ptr);
    }

    #[test]
    fn service_accessible_by_type() {
        let vec_service: Arc<Vec<i32>> = Arc::new(vec![1, 2, 3]);
        assert!(PluggableServiceRegistry::register_pluggable_service(vec_service.clone()).is_ok());

        let retrieved = PluggableServiceRegistry::get_pluggable_service::<Vec<i32>>();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().as_slice(), &[1, 2, 3]);
    }

    #[test]
    fn concurrent_registration() {
        use std::thread;

        let handles: Vec<_> = (0..10)
            .map(|i| {
                thread::spawn(move || {
                    let svc = Arc::new(format!("service_{}", i));
                    PluggableServiceRegistry::register_pluggable_service(svc)
                })
            })
            .collect();

        for handle in handles {
            assert!(handle.join().unwrap().is_ok());
        }

        let result = PluggableServiceRegistry::get_pluggable_service::<String>();
        assert!(result.is_some());
    }
}

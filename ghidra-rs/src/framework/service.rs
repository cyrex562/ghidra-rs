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

static REGISTRY: OnceLock<RwLock<HashMap<TypeId, Arc<dyn Any + Send + Sync>>>> = OnceLock::new();

fn get_registry() -> &'static RwLock<HashMap<TypeId, Arc<dyn Any + Send + Sync>>> {
    REGISTRY.get_or_init(|| RwLock::new(HashMap::new()))
}

pub struct PluggableServiceRegistry;

impl PluggableServiceRegistry {
    pub fn register_pluggable_service<T: 'static + Send + Sync>(
        instance: Arc<T>,
    ) -> Result<(), PluggableServiceRegistryError> {
        let type_id = TypeId::of::<T>();
        let mut lock = get_registry().write().unwrap();

        // Java logic: if it exists, check for specificity.
        // In Rust, TypeId is exact. So we either replace the same type or we'd need
        // a different key for interfaces/traits.
        // Ghidra's MAP is Map<Class<?>, Object>. Usually it's indexed by the interface class.

        lock.insert(type_id, instance);
        Ok(())
    }

    pub fn get_pluggable_service<T: 'static + Send + Sync>() -> Option<Arc<T>> {
        let type_id = TypeId::of::<T>();
        let lock = get_registry().read().unwrap();

        lock.get(&type_id)
            .and_then(|any| any.clone().downcast::<T>().ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry() {
        let service = Arc::new("Hello Service".to_string());
        PluggableServiceRegistry::register_pluggable_service(service).unwrap();

        let retrieved = PluggableServiceRegistry::get_pluggable_service::<String>().unwrap();
        assert_eq!(*retrieved, "Hello Service");
    }
}

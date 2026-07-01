use std::any::TypeId;
use std::collections::HashMap;
use crate::generic::depends::err::ServiceConstructionException;

/// A constructor for a service that may depend on other services.
///
/// Mirrors Java's `generic.depends.DependentServiceConstructor<T>`, which wraps a
/// reflective method that constructs an instance of type `T` given a map of dependency
/// instances keyed by their type.
///
/// In Rust, where reflection is not available, the constructor stores a function pointer
/// or closure that accepts the dependency map and returns the constructed service.
pub struct DependentServiceConstructor {
    /// The `TypeId` of the service this constructor produces.
    service_type: TypeId,
    /// A boxed function that constructs the service from dependencies.
    constructor: Box<dyn Fn(&HashMap<TypeId, Box<dyn std::any::Any>>) -> Result<Box<dyn std::any::Any>, ServiceConstructionException>>,
}

impl DependentServiceConstructor {
    /// Creates a new `DependentServiceConstructor` with a given constructor function.
    ///
    /// The function receives a map of dependencies keyed by `TypeId` and must return
    /// a boxed instance of the service type or a `ServiceConstructionException`.
    pub fn new<F>(service_type: TypeId, constructor: F) -> Self
    where
        F: Fn(&HashMap<TypeId, Box<dyn std::any::Any>>) -> Result<Box<dyn std::any::Any>, ServiceConstructionException> + 'static,
    {
        Self {
            service_type,
            constructor: Box::new(constructor),
        }
    }

    /// Returns the `TypeId` of the service this constructor produces.
    pub fn service_type(&self) -> TypeId {
        self.service_type
    }

    /// Constructs the service by invoking the constructor with the given dependency map.
    ///
    /// Mirrors Java's `construct(Object obj, Map<Class<?>, Object> dependencies)`.
    /// In Rust, the dependency map is keyed by `TypeId` rather than `Class<?>`.
    pub fn construct(
        &self,
        dependencies: &HashMap<TypeId, Box<dyn std::any::Any>>,
    ) -> Result<Box<dyn std::any::Any>, ServiceConstructionException> {
        (self.constructor)(dependencies)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ServiceA {
        value: i32,
    }

    struct ServiceB {
        value: String,
    }

    #[test]
    fn new_stores_service_type() {
        let constructor = DependentServiceConstructor::new(
            TypeId::of::<ServiceA>(),
            |_deps| Ok(Box::new(ServiceA { value: 42 })),
        );
        assert_eq!(constructor.service_type(), TypeId::of::<ServiceA>());
    }

    #[test]
    fn construct_invokes_constructor_function() {
        let constructor = DependentServiceConstructor::new(
            TypeId::of::<ServiceA>(),
            |_deps| Ok(Box::new(ServiceA { value: 42 })),
        );

        let deps = HashMap::new();
        let result = constructor.construct(&deps);
        assert!(result.is_ok());
        let service = result.unwrap();
        let service_a = service
            .downcast_ref::<ServiceA>()
            .expect("should downcast to ServiceA");
        assert_eq!(service_a.value, 42);
    }

    #[test]
    fn construct_propagates_errors() {
        let constructor = DependentServiceConstructor::new(
            TypeId::of::<ServiceA>(),
            |_deps| {
                Err(ServiceConstructionException::new(
                    "construction failed",
                    std::io::Error::new(std::io::ErrorKind::Other, "simulated error"),
                ))
            },
        );

        let deps = HashMap::new();
        let result = constructor.construct(&deps);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.message(), "construction failed");
    }

    #[test]
    fn construct_can_access_dependencies() {
        let constructor = DependentServiceConstructor::new(
            TypeId::of::<ServiceA>(),
            |deps| {
                let service_b = deps
                    .get(&TypeId::of::<ServiceB>())
                    .and_then(|b| b.downcast_ref::<ServiceB>())
                    .ok_or_else(|| {
                        ServiceConstructionException::new(
                            "ServiceB not found in dependencies",
                            std::io::Error::new(std::io::ErrorKind::NotFound, "dep missing"),
                        )
                    })?;

                let value = service_b.value.len() as i32;
                Ok(Box::new(ServiceA { value }))
            },
        );

        let mut deps = HashMap::new();
        deps.insert(
            TypeId::of::<ServiceB>(),
            Box::new(ServiceB {
                value: "hello".to_string(),
            }) as Box<dyn std::any::Any>,
        );

        let result = constructor.construct(&deps);
        assert!(result.is_ok());
        let service = result.unwrap();
        let service_a = service.downcast_ref::<ServiceA>().unwrap();
        assert_eq!(service_a.value, 5);
    }

    #[test]
    fn multiple_constructors_are_independent() {
        let cons_a = DependentServiceConstructor::new(
            TypeId::of::<ServiceA>(),
            |_deps| Ok(Box::new(ServiceA { value: 1 })),
        );

        let cons_b = DependentServiceConstructor::new(
            TypeId::of::<ServiceB>(),
            |_deps| Ok(Box::new(ServiceB { value: "test".to_string() })),
        );

        let deps = HashMap::new();
        let result_a = cons_a.construct(&deps).unwrap();
        let result_b = cons_b.construct(&deps).unwrap();

        assert_eq!(
            result_a
                .downcast_ref::<ServiceA>()
                .unwrap()
                .value,
            1
        );
        assert_eq!(
            result_b
                .downcast_ref::<ServiceB>()
                .unwrap()
                .value,
            "test"
        );
    }
}

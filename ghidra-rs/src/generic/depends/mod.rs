pub mod dependent_service;
pub mod dependent_service_constructor;
pub mod dependent_service_resolver;
pub mod err;

#[cfg(test)]
mod dependent_service_resolver_test;

pub use dependent_service::{DependentService, Sentinel};
pub use dependent_service_constructor::DependentServiceConstructor;
pub use dependent_service_resolver::{
    DependentServiceResolver, DependentServiceResolverError, FieldSetter,
};

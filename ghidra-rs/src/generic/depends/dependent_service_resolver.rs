use std::any::{Any, TypeId};
use std::collections::{HashMap, HashSet};
use std::fmt;

use crate::generic::depends::err::{
    ServiceConstructionException, UnsatisfiedFieldsException, UnsatisfiedParameterException,
};
use crate::generic::depends::DependentServiceConstructor;

/// Installs a constructed service instance into one of `T`'s dependency-injected
/// fields, given a shared reference to the boxed instance.
///
/// Mirrors the reflective `Field::set` calls Java's resolver performs once a
/// service has been constructed. Services that must satisfy more than one field, or
/// that are also consumed as another service's constructor parameter, should be
/// boxed as a cheaply-cloneable handle (e.g. `Rc<Service>`) so the setter and any
/// downstream constructor can each obtain their own owned handle to the same
/// underlying instance via [`Any::downcast_ref`] + `clone`.
pub type FieldSetter<T> = Box<dyn Fn(&mut T, &dyn Any)>;

struct RegisteredConstructor {
    param_types: Vec<TypeId>,
    ctor: DependentServiceConstructor,
}

/// Error produced by [`DependentServiceResolver::compile`].
///
/// Mirrors the two checked exceptions Java's `DependentServiceResolver` constructor
/// declares: `UnsatisfiedFieldsException` and `UnsatisfiedParameterException`.
#[derive(Debug)]
pub enum DependentServiceResolverError {
    UnsatisfiedFields(UnsatisfiedFieldsException),
    UnsatisfiedParameter(UnsatisfiedParameterException),
}

impl fmt::Display for DependentServiceResolverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsatisfiedFields(e) => fmt::Display::fmt(e, f),
            Self::UnsatisfiedParameter(e) => fmt::Display::fmt(e, f),
        }
    }
}

impl std::error::Error for DependentServiceResolverError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::UnsatisfiedFields(e) => Some(e),
            Self::UnsatisfiedParameter(e) => Some(e),
        }
    }
}

/// Marker cause used when a [`ServiceConstructionException`] has no underlying
/// error, mirroring Java's `new ServiceConstructionException(msg, null)`.
#[derive(Debug)]
struct NoConstructorAvailable;

impl fmt::Display for NoConstructorAvailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("no constructor was registered for this service type")
    }
}

impl std::error::Error for NoConstructorAvailable {}

/// Resolves and injects a graph of dependent services into an instance of `T`.
///
/// Mirrors Java's `generic.depends.DependentServiceResolver<T>`, which discovers
/// `@DependentService`-annotated fields and factory methods on `T`'s class hierarchy
/// via reflection, topologically orders the factory methods by their parameter
/// dependencies, and then invokes them in order to populate the annotated fields.
///
/// Rust has no runtime reflection or annotation processor, so this port replaces
/// Java's automatic class-hierarchy scan (`addClass`) and static `Class`-keyed cache
/// (`CACHED`, `get`, `inject`) with an explicit registration API: callers describe
/// each service's constructor and its dependencies via [`register_constructor`],
/// and each injection point via [`register_field`]. [`compile`] then performs the
/// same topological sort and unsatisfied-dependency checks as Java's `compile()`,
/// and [`inject_services`] performs the same construct-then-assign pass as Java's
/// `injectServices(T)`.
///
/// Java's `@DependentService(override = ...)` lets one factory method satisfy both
/// its declared return type and a supertype slot, relying on Java's `isAssignableFrom`
/// subtyping. `TypeId`-based type erasure has no notion of subtyping, so there is no
/// dedicated "override" registration here: the same effect is achieved by registering
/// a second constructor for the override's `TypeId` whose `param_types` includes the
/// primary service's `TypeId`, so the resolver still orders it after the primary
/// service.
///
/// [`register_constructor`]: DependentServiceResolver::register_constructor
/// [`register_field`]: DependentServiceResolver::register_field
/// [`compile`]: DependentServiceResolver::compile
/// [`inject_services`]: DependentServiceResolver::inject_services
pub struct DependentServiceResolver<T> {
    constructors: HashMap<TypeId, RegisteredConstructor>,
    fields_by_class: HashMap<TypeId, Vec<FieldSetter<T>>>,
    ordered: Vec<TypeId>,
}

impl<T> DependentServiceResolver<T> {
    /// Creates an empty resolver with no registered constructors or fields.
    pub fn new() -> Self {
        Self {
            constructors: HashMap::new(),
            fields_by_class: HashMap::new(),
            ordered: Vec::new(),
        }
    }

    /// Registers a factory for `service_type`, along with the `TypeId`s of the
    /// other services it depends on to be constructed.
    ///
    /// Mirrors the per-method half of Java's `addClass`, which collected each
    /// `@DependentService`-annotated method's return type and parameter types.
    pub fn register_constructor<F>(
        &mut self,
        service_type: TypeId,
        param_types: impl IntoIterator<Item = TypeId>,
        constructor: F,
    ) where
        F: Fn(&HashMap<TypeId, Box<dyn Any>>) -> Result<Box<dyn Any>, ServiceConstructionException>
            + 'static,
    {
        self.constructors.insert(
            service_type,
            RegisteredConstructor {
                param_types: param_types.into_iter().collect(),
                ctor: DependentServiceConstructor::new(service_type, constructor),
            },
        );
    }

    /// Registers a field injection point for `field_type`.
    ///
    /// Mirrors the per-field half of Java's `addClass`, which collected each
    /// `@DependentService`-annotated field keyed by its declared type.
    pub fn register_field(&mut self, field_type: TypeId, setter: FieldSetter<T>) {
        self.fields_by_class.entry(field_type).or_default().push(setter);
    }

    /// Topologically orders the registered constructors by their declared
    /// dependencies, verifying every registered field has a matching constructor.
    ///
    /// Mirrors Java's `compile()`.
    pub fn compile(&mut self) -> Result<(), DependentServiceResolverError> {
        let missing: HashSet<TypeId> = self
            .fields_by_class
            .keys()
            .filter(|ty| !self.constructors.contains_key(*ty))
            .copied()
            .collect();
        if !missing.is_empty() {
            return Err(DependentServiceResolverError::UnsatisfiedFields(
                UnsatisfiedFieldsException::new(missing),
            ));
        }

        let mut deps_by_dependents: HashMap<TypeId, HashSet<TypeId>> = HashMap::new();
        for (&ty, reg) in &self.constructors {
            if !reg.param_types.is_empty() {
                deps_by_dependents.insert(ty, reg.param_types.iter().copied().collect());
            }
        }

        let mut unordered: HashSet<TypeId> = self.constructors.keys().copied().collect();
        let mut ordered = Vec::with_capacity(unordered.len());
        while !unordered.is_empty() {
            let for_round: Vec<TypeId> = unordered
                .iter()
                .filter(|ty| !deps_by_dependents.contains_key(*ty))
                .copied()
                .collect();
            if for_round.is_empty() {
                return Err(DependentServiceResolverError::UnsatisfiedParameter(
                    UnsatisfiedParameterException::new(unordered),
                ));
            }
            for ready in for_round {
                unordered.remove(&ready);
                ordered.push(ready);
                deps_by_dependents.retain(|_, deps| {
                    deps.remove(&ready);
                    !deps.is_empty()
                });
            }
        }
        self.ordered = ordered;
        Ok(())
    }

    /// Constructs every registered service in dependency order and assigns each
    /// one to its registered fields on `obj`.
    ///
    /// Mirrors Java's `injectServices(T)`. Callers must call [`compile`](Self::compile)
    /// first; construction otherwise proceeds in whatever order the last successful
    /// `compile` produced (or does nothing if `compile` was never called).
    pub fn inject_services(&self, obj: &mut T) -> Result<(), ServiceConstructionException> {
        let mut instances: HashMap<TypeId, Box<dyn Any>> = HashMap::new();
        let mut remaining_fields: HashSet<TypeId> = self.fields_by_class.keys().copied().collect();

        for &ty in &self.ordered {
            let Some(reg) = self.constructors.get(&ty) else {
                continue;
            };
            let service = reg.ctor.construct(&instances)?;

            if let Some(setters) = self.fields_by_class.get(&ty) {
                for setter in setters {
                    setter(obj, service.as_ref());
                }
                remaining_fields.remove(&ty);
            }
            instances.insert(ty, service);
        }

        if !remaining_fields.is_empty() {
            return Err(ServiceConstructionException::new(
                format!(
                    "No service constructor for {} field type(s)",
                    remaining_fields.len()
                ),
                NoConstructorAvailable,
            ));
        }
        Ok(())
    }
}

impl<T> Default for DependentServiceResolver<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::rc::Rc;

    struct ServiceA {
        value: i32,
    }

    struct ServiceB {
        label: String,
    }

    #[derive(Default)]
    struct Target {
        service_a: Option<i32>,
        service_b: Option<String>,
    }

    #[test]
    fn empty_resolver_compiles_and_injects_nothing() {
        let mut resolver: DependentServiceResolver<Target> = DependentServiceResolver::new();
        assert!(resolver.compile().is_ok());
        let mut target = Target::default();
        assert!(resolver.inject_services(&mut target).is_ok());
        assert!(target.service_a.is_none());
    }

    #[test]
    fn single_service_is_constructed_and_injected() {
        let mut resolver: DependentServiceResolver<Target> = DependentServiceResolver::new();
        resolver.register_constructor(TypeId::of::<ServiceA>(), [], |_deps| {
            Ok(Box::new(ServiceA { value: 42 }) as Box<dyn Any>)
        });
        resolver.register_field(
            TypeId::of::<ServiceA>(),
            Box::new(|t: &mut Target, v: &dyn Any| {
                t.service_a = v.downcast_ref::<ServiceA>().map(|s| s.value);
            }),
        );

        resolver.compile().expect("compile should succeed");
        let mut target = Target::default();
        resolver
            .inject_services(&mut target)
            .expect("injection should succeed");
        assert_eq!(target.service_a, Some(42));
    }

    #[test]
    fn dependent_service_is_constructed_after_its_dependency() {
        let mut resolver: DependentServiceResolver<Target> = DependentServiceResolver::new();
        resolver.register_constructor(TypeId::of::<ServiceA>(), [], |_deps| {
            Ok(Box::new(ServiceA { value: 7 }) as Box<dyn Any>)
        });
        resolver.register_constructor(
            TypeId::of::<ServiceB>(),
            [TypeId::of::<ServiceA>()],
            |deps| {
                let a = deps
                    .get(&TypeId::of::<ServiceA>())
                    .and_then(|b| b.downcast_ref::<ServiceA>())
                    .expect("ServiceA must already be constructed");
                Ok(Box::new(ServiceB { label: format!("a={}", a.value) }) as Box<dyn Any>)
            },
        );
        resolver.register_field(
            TypeId::of::<ServiceB>(),
            Box::new(|t: &mut Target, v: &dyn Any| {
                t.service_b = v.downcast_ref::<ServiceB>().map(|s| s.label.clone());
            }),
        );

        resolver.compile().expect("compile should succeed");
        let mut target = Target::default();
        resolver
            .inject_services(&mut target)
            .expect("injection should succeed");
        assert_eq!(target.service_b, Some("a=7".to_string()));
    }

    #[test]
    fn missing_constructor_for_field_is_unsatisfied_fields_error() {
        let mut resolver: DependentServiceResolver<Target> = DependentServiceResolver::new();
        resolver.register_field(
            TypeId::of::<ServiceA>(),
            Box::new(|_t: &mut Target, _v: &dyn Any| {}),
        );

        match resolver.compile() {
            Err(DependentServiceResolverError::UnsatisfiedFields(e)) => {
                assert!(e.missing().contains(&TypeId::of::<ServiceA>()));
            }
            other => panic!("expected UnsatisfiedFields, got {other:?}"),
        }
    }

    #[test]
    fn circular_dependency_is_unsatisfied_parameter_error() {
        let mut resolver: DependentServiceResolver<Target> = DependentServiceResolver::new();
        resolver.register_constructor(
            TypeId::of::<ServiceA>(),
            [TypeId::of::<ServiceB>()],
            |_deps| Ok(Box::new(ServiceA { value: 1 }) as Box<dyn Any>),
        );
        resolver.register_constructor(
            TypeId::of::<ServiceB>(),
            [TypeId::of::<ServiceA>()],
            |_deps| Ok(Box::new(ServiceB { label: String::new() }) as Box<dyn Any>),
        );

        match resolver.compile() {
            Err(DependentServiceResolverError::UnsatisfiedParameter(e)) => {
                assert_eq!(e.left().len(), 2);
            }
            other => panic!("expected UnsatisfiedParameter, got {other:?}"),
        }
    }

    #[test]
    fn constructor_error_propagates_from_inject_services() {
        let mut resolver: DependentServiceResolver<Target> = DependentServiceResolver::new();
        resolver.register_constructor(TypeId::of::<ServiceA>(), [], |_deps| {
            Err(ServiceConstructionException::new(
                "boom",
                std::io::Error::new(std::io::ErrorKind::Other, "simulated failure"),
            ))
        });

        resolver.compile().expect("compile should succeed");
        let mut target = Target::default();
        let err = resolver
            .inject_services(&mut target)
            .expect_err("construction failure should propagate");
        assert_eq!(err.message(), "boom");
    }

    #[test]
    fn shared_instance_can_satisfy_multiple_fields_via_rc() {
        struct Shared {
            id: i32,
        }

        #[derive(Default)]
        struct MultiTarget {
            first: Option<i32>,
            second: Option<i32>,
        }

        let mut resolver: DependentServiceResolver<MultiTarget> = DependentServiceResolver::new();
        resolver.register_constructor(TypeId::of::<Shared>(), [], |_deps| {
            Ok(Box::new(Rc::new(Shared { id: 99 })) as Box<dyn Any>)
        });
        resolver.register_field(
            TypeId::of::<Shared>(),
            Box::new(|t: &mut MultiTarget, v: &dyn Any| {
                t.first = v.downcast_ref::<Rc<Shared>>().map(|s| s.id);
            }),
        );
        resolver.register_field(
            TypeId::of::<Shared>(),
            Box::new(|t: &mut MultiTarget, v: &dyn Any| {
                t.second = v.downcast_ref::<Rc<Shared>>().map(|s| s.id);
            }),
        );

        resolver.compile().expect("compile should succeed");
        let mut target = MultiTarget::default();
        resolver
            .inject_services(&mut target)
            .expect("injection should succeed");
        assert_eq!(target.first, Some(99));
        assert_eq!(target.second, Some(99));
    }

    #[test]
    fn override_style_dependency_orders_after_primary_service() {
        struct Base;
        struct Derived;

        #[derive(Default)]
        struct OrderTarget {
            order: Vec<&'static str>,
        }

        let mut resolver: DependentServiceResolver<OrderTarget> = DependentServiceResolver::new();
        resolver.register_constructor(TypeId::of::<Base>(), [], |_deps| {
            Ok(Box::new(Base) as Box<dyn Any>)
        });
        resolver.register_constructor(
            TypeId::of::<Derived>(),
            [TypeId::of::<Base>()],
            |_deps| Ok(Box::new(Derived) as Box<dyn Any>),
        );
        resolver.register_field(
            TypeId::of::<Base>(),
            Box::new(|t: &mut OrderTarget, _v: &dyn Any| t.order.push("base")),
        );
        resolver.register_field(
            TypeId::of::<Derived>(),
            Box::new(|t: &mut OrderTarget, _v: &dyn Any| t.order.push("derived")),
        );

        resolver.compile().expect("compile should succeed");
        let mut target = OrderTarget::default();
        resolver
            .inject_services(&mut target)
            .expect("injection should succeed");
        assert_eq!(target.order, vec!["base", "derived"]);
    }
}

/// Tests for [`DependentServiceResolver`](crate::generic::depends::DependentServiceResolver).
///
/// Corresponds to `DependentServiceResolverTest` in the original Ghidra Java source
/// (`generic.depends`). The Java original relies on reflection to discover
/// `@DependentService`-annotated fields and factory methods on a target's class
/// hierarchy; this port instead builds the equivalent dependency graphs with the
/// resolver's explicit `register_constructor`/`register_field` API, then exercises
/// [`DependentServiceResolver::compile`] and
/// [`DependentServiceResolver::inject_services`] the same way `DependentServiceResolver
/// ::inject` does in Java.
#[cfg(test)]
mod tests {
    use crate::generic::depends::{DependentServiceResolver, DependentServiceResolverError};
    use std::any::{Any, TypeId};
    use std::rc::Rc;

    struct A;

    struct B {
        a: Rc<A>,
    }

    struct C {
        a: Rc<A>,
    }

    struct D {
        b: Rc<B>,
        c: Rc<C>,
    }

    struct E;

    struct F {
        d: Rc<D>,
    }

    #[derive(Default)]
    struct NeedsInjectionNoExtends {
        d: Option<Rc<D>>,
        a: Option<Rc<A>>,
        b: Option<Rc<B>>,
        c: Option<Rc<C>>,
    }

    fn register_no_extends_services(
        resolver: &mut DependentServiceResolver<NeedsInjectionNoExtends>,
    ) {
        resolver.register_constructor(TypeId::of::<A>(), [], |_deps| {
            Ok(Box::new(Rc::new(A)) as Box<dyn Any>)
        });
        resolver.register_constructor(TypeId::of::<B>(), [TypeId::of::<A>()], |deps| {
            let a = deps
                .get(&TypeId::of::<A>())
                .and_then(|v| v.downcast_ref::<Rc<A>>())
                .expect("A must already be constructed");
            Ok(Box::new(Rc::new(B { a: a.clone() })) as Box<dyn Any>)
        });
        resolver.register_constructor(TypeId::of::<C>(), [TypeId::of::<A>()], |deps| {
            let a = deps
                .get(&TypeId::of::<A>())
                .and_then(|v| v.downcast_ref::<Rc<A>>())
                .expect("A must already be constructed");
            Ok(Box::new(Rc::new(C { a: a.clone() })) as Box<dyn Any>)
        });
        resolver.register_constructor(
            TypeId::of::<D>(),
            [TypeId::of::<B>(), TypeId::of::<C>()],
            |deps| {
                let b = deps
                    .get(&TypeId::of::<B>())
                    .and_then(|v| v.downcast_ref::<Rc<B>>())
                    .expect("B must already be constructed");
                let c = deps
                    .get(&TypeId::of::<C>())
                    .and_then(|v| v.downcast_ref::<Rc<C>>())
                    .expect("C must already be constructed");
                Ok(Box::new(Rc::new(D { b: b.clone(), c: c.clone() })) as Box<dyn Any>)
            },
        );

        resolver.register_field(
            TypeId::of::<A>(),
            Box::new(|t: &mut NeedsInjectionNoExtends, v: &dyn Any| {
                t.a = v.downcast_ref::<Rc<A>>().cloned();
            }),
        );
        resolver.register_field(
            TypeId::of::<B>(),
            Box::new(|t: &mut NeedsInjectionNoExtends, v: &dyn Any| {
                t.b = v.downcast_ref::<Rc<B>>().cloned();
            }),
        );
        resolver.register_field(
            TypeId::of::<C>(),
            Box::new(|t: &mut NeedsInjectionNoExtends, v: &dyn Any| {
                t.c = v.downcast_ref::<Rc<C>>().cloned();
            }),
        );
        resolver.register_field(
            TypeId::of::<D>(),
            Box::new(|t: &mut NeedsInjectionNoExtends, v: &dyn Any| {
                t.d = v.downcast_ref::<Rc<D>>().cloned();
            }),
        );
    }

    #[test]
    fn test_no_extends() {
        let mut resolver: DependentServiceResolver<NeedsInjectionNoExtends> =
            DependentServiceResolver::new();
        register_no_extends_services(&mut resolver);
        resolver.compile().expect("compile should succeed");

        let mut needs = NeedsInjectionNoExtends::default();
        resolver
            .inject_services(&mut needs)
            .expect("injection should succeed");

        let a = needs.a.expect("a injected");
        let b = needs.b.expect("b injected");
        let c = needs.c.expect("c injected");
        let d = needs.d.expect("d injected");
        assert!(Rc::ptr_eq(&c, &d.c));
        assert!(Rc::ptr_eq(&b, &d.b));
        assert!(Rc::ptr_eq(&a, &c.a));
        assert!(Rc::ptr_eq(&a, &b.a));
    }

    /// Mirrors Java's `D2 extends D`, used with `@DependentService(override = D.class)` so
    /// that `createD2` satisfies the `D` slot. Since `TypeId` erasure has no subtyping,
    /// this port registers `D2` as an ordinary service that depends on `B`, `C`, and `E`,
    /// and reuses the `D`-typed field setter machinery by registering `D2`'s constructor
    /// under `D`'s `TypeId`, per [`DependentServiceResolver`]'s documented override
    /// convention.
    struct D2 {
        b: Rc<B>,
        c: Rc<C>,
        e: Rc<E>,
    }

    #[derive(Default)]
    struct NeedsInjectionOverrideD {
        a: Option<Rc<A>>,
        b: Option<Rc<B>>,
        c: Option<Rc<C>>,
        d: Option<Rc<D2>>,
        e: Option<Rc<E>>,
        f: Option<Rc<F>>,
    }

    fn register_override_d_services(
        resolver: &mut DependentServiceResolver<NeedsInjectionOverrideD>,
    ) {
        resolver.register_constructor(TypeId::of::<A>(), [], |_deps| {
            Ok(Box::new(Rc::new(A)) as Box<dyn Any>)
        });
        resolver.register_constructor(TypeId::of::<B>(), [TypeId::of::<A>()], |deps| {
            let a = deps
                .get(&TypeId::of::<A>())
                .and_then(|v| v.downcast_ref::<Rc<A>>())
                .expect("A must already be constructed");
            Ok(Box::new(Rc::new(B { a: a.clone() })) as Box<dyn Any>)
        });
        resolver.register_constructor(TypeId::of::<C>(), [TypeId::of::<A>()], |deps| {
            let a = deps
                .get(&TypeId::of::<A>())
                .and_then(|v| v.downcast_ref::<Rc<A>>())
                .expect("A must already be constructed");
            Ok(Box::new(Rc::new(C { a: a.clone() })) as Box<dyn Any>)
        });
        resolver.register_constructor(TypeId::of::<E>(), [], |_deps| {
            Ok(Box::new(Rc::new(E)) as Box<dyn Any>)
        });
        // Registered under D's TypeId: overrides the base D slot with D2, mirroring
        // `@DependentService(override = D.class) createD2(B, C, E)`.
        resolver.register_constructor(
            TypeId::of::<D>(),
            [TypeId::of::<B>(), TypeId::of::<C>(), TypeId::of::<E>()],
            |deps| {
                let b = deps
                    .get(&TypeId::of::<B>())
                    .and_then(|v| v.downcast_ref::<Rc<B>>())
                    .expect("B must already be constructed");
                let c = deps
                    .get(&TypeId::of::<C>())
                    .and_then(|v| v.downcast_ref::<Rc<C>>())
                    .expect("C must already be constructed");
                let e = deps
                    .get(&TypeId::of::<E>())
                    .and_then(|v| v.downcast_ref::<Rc<E>>())
                    .expect("E must already be constructed");
                Ok(Box::new(Rc::new(D2 { b: b.clone(), c: c.clone(), e: e.clone() }))
                    as Box<dyn Any>)
            },
        );
        resolver.register_constructor(TypeId::of::<F>(), [TypeId::of::<D>()], |deps| {
            let d2 = deps
                .get(&TypeId::of::<D>())
                .and_then(|v| v.downcast_ref::<Rc<D2>>())
                .expect("D must already be constructed");
            let d = Rc::new(D { b: d2.b.clone(), c: d2.c.clone() });
            Ok(Box::new(Rc::new(F { d })) as Box<dyn Any>)
        });

        resolver.register_field(
            TypeId::of::<A>(),
            Box::new(|t: &mut NeedsInjectionOverrideD, v: &dyn Any| {
                t.a = v.downcast_ref::<Rc<A>>().cloned();
            }),
        );
        resolver.register_field(
            TypeId::of::<B>(),
            Box::new(|t: &mut NeedsInjectionOverrideD, v: &dyn Any| {
                t.b = v.downcast_ref::<Rc<B>>().cloned();
            }),
        );
        resolver.register_field(
            TypeId::of::<C>(),
            Box::new(|t: &mut NeedsInjectionOverrideD, v: &dyn Any| {
                t.c = v.downcast_ref::<Rc<C>>().cloned();
            }),
        );
        resolver.register_field(
            TypeId::of::<D>(),
            Box::new(|t: &mut NeedsInjectionOverrideD, v: &dyn Any| {
                t.d = v.downcast_ref::<Rc<D2>>().cloned();
            }),
        );
        resolver.register_field(
            TypeId::of::<E>(),
            Box::new(|t: &mut NeedsInjectionOverrideD, v: &dyn Any| {
                t.e = v.downcast_ref::<Rc<E>>().cloned();
            }),
        );
        resolver.register_field(
            TypeId::of::<F>(),
            Box::new(|t: &mut NeedsInjectionOverrideD, v: &dyn Any| {
                t.f = v.downcast_ref::<Rc<F>>().cloned();
            }),
        );
    }

    #[test]
    fn test_override_d() {
        let mut resolver: DependentServiceResolver<NeedsInjectionOverrideD> =
            DependentServiceResolver::new();
        register_override_d_services(&mut resolver);
        resolver.compile().expect("compile should succeed");

        let mut needs = NeedsInjectionOverrideD::default();
        resolver
            .inject_services(&mut needs)
            .expect("injection should succeed");

        let a = needs.a.expect("a injected");
        let b = needs.b.expect("b injected");
        let c = needs.c.expect("c injected");
        let d = needs.d.expect("d injected");
        let e = needs.e.expect("e injected");
        let f = needs.f.expect("f injected");

        assert!(Rc::ptr_eq(&c, &d.c));
        assert!(Rc::ptr_eq(&b, &d.b));
        assert!(Rc::ptr_eq(&a, &c.a));
        assert!(Rc::ptr_eq(&a, &b.a));
        assert!(Rc::ptr_eq(&e, &d.e));
        // `f.d` is a fresh `Rc<D>` rebuilt from the overriding `D2`'s components inside
        // F's constructor (types `Rc<D2>` vs `Rc<D>` cannot share an allocation here), so
        // verify identity through the shared `B`/`C` singletons instead.
        assert!(Rc::ptr_eq(&d.b, &f.d.b));
        assert!(Rc::ptr_eq(&d.c, &f.d.c));
    }

    #[derive(Debug)]
    struct MyError;

    impl std::fmt::Display for MyError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("MyError")
        }
    }

    impl std::error::Error for MyError {}

    #[derive(Default)]
    struct NeedsInjectionExceptionThrower {
        a: Option<Rc<A>>,
    }

    #[test]
    fn test_exception() {
        let mut resolver: DependentServiceResolver<NeedsInjectionExceptionThrower> =
            DependentServiceResolver::new();
        resolver.register_constructor(TypeId::of::<A>(), [], |_deps| {
            Err(crate::generic::depends::err::ServiceConstructionException::new(
                "failed to construct A",
                MyError,
            ))
        });
        resolver.register_field(
            TypeId::of::<A>(),
            Box::new(|t: &mut NeedsInjectionExceptionThrower, v: &dyn Any| {
                t.a = v.downcast_ref::<Rc<A>>().cloned();
            }),
        );
        resolver.compile().expect("compile should succeed");

        let mut needs = NeedsInjectionExceptionThrower::default();
        let err = resolver
            .inject_services(&mut needs)
            .expect_err("construction should fail");
        assert!(err.unwrap::<MyError>().is_err());
    }

    #[derive(Default)]
    struct NeedsInjectionTwoStepExceptionThrower {
        b: Option<Rc<B>>,
        a: Option<Rc<A>>,
    }

    #[test]
    fn test_two_step_exception() {
        let mut resolver: DependentServiceResolver<NeedsInjectionTwoStepExceptionThrower> =
            DependentServiceResolver::new();
        resolver.register_constructor(TypeId::of::<A>(), [], |_deps| {
            Err(crate::generic::depends::err::ServiceConstructionException::new(
                "failed to construct A",
                MyError,
            ))
        });
        resolver.register_constructor(TypeId::of::<B>(), [TypeId::of::<A>()], |deps| {
            let a = deps
                .get(&TypeId::of::<A>())
                .and_then(|v| v.downcast_ref::<Rc<A>>())
                .expect("A must already be constructed");
            Ok(Box::new(Rc::new(B { a: a.clone() })) as Box<dyn Any>)
        });
        resolver.register_field(
            TypeId::of::<B>(),
            Box::new(|t: &mut NeedsInjectionTwoStepExceptionThrower, v: &dyn Any| {
                t.b = v.downcast_ref::<Rc<B>>().cloned();
            }),
        );
        resolver.register_field(
            TypeId::of::<A>(),
            Box::new(|t: &mut NeedsInjectionTwoStepExceptionThrower, v: &dyn Any| {
                t.a = v.downcast_ref::<Rc<A>>().cloned();
            }),
        );
        resolver.compile().expect("compile should succeed");

        let mut needs = NeedsInjectionTwoStepExceptionThrower::default();
        let err = resolver
            .inject_services(&mut needs)
            .expect_err("construction should fail");
        assert!(err.unwrap::<MyError>().is_err());
    }

    #[derive(Default)]
    struct UnsatisfiedParameter {
        b: Option<Rc<B>>,
    }

    #[test]
    fn test_unsatisfied_parameter() {
        let mut resolver: DependentServiceResolver<UnsatisfiedParameter> =
            DependentServiceResolver::new();
        resolver.register_constructor(TypeId::of::<B>(), [TypeId::of::<A>()], |deps| {
            let a = deps
                .get(&TypeId::of::<A>())
                .and_then(|v| v.downcast_ref::<Rc<A>>())
                .expect("A must already be constructed");
            Ok(Box::new(Rc::new(B { a: a.clone() })) as Box<dyn Any>)
        });
        resolver.register_field(
            TypeId::of::<B>(),
            Box::new(|t: &mut UnsatisfiedParameter, v: &dyn Any| {
                t.b = v.downcast_ref::<Rc<B>>().cloned();
            }),
        );

        match resolver.compile() {
            Err(DependentServiceResolverError::UnsatisfiedParameter(_)) => {}
            other => panic!("expected UnsatisfiedParameter, got {other:?}"),
        }
    }

    #[derive(Default)]
    struct UnsatisfiedField {
        a: Option<Rc<A>>,
    }

    #[test]
    fn test_unsatisfied_field() {
        let mut resolver: DependentServiceResolver<UnsatisfiedField> =
            DependentServiceResolver::new();
        resolver.register_field(
            TypeId::of::<A>(),
            Box::new(|t: &mut UnsatisfiedField, v: &dyn Any| {
                t.a = v.downcast_ref::<Rc<A>>().cloned();
            }),
        );

        match resolver.compile() {
            Err(DependentServiceResolverError::UnsatisfiedFields(_)) => {}
            other => panic!("expected UnsatisfiedFields, got {other:?}"),
        }
    }
}

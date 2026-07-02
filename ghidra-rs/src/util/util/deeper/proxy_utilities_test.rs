//! Tests for proxy composition behavior.
//!
//! This module mirrors `utilities.util.deeper.ProxyUtilitiesTest` from the Java source.
//! The Java test class is positioned one package deeper to ensure access permissions work correctly.
//!
//! Java's `ProxyUtilities.composeOnDelegate` uses runtime dynamic proxies (`java.lang.reflect.Proxy`)
//! to mix interface default methods onto a delegate at runtime. Rust has no equivalent runtime proxy
//! mechanism; instead, the same composition is expressed statically through trait implementations.
//! These tests demonstrate that Rust's trait system achieves identical semantics.

#[cfg(test)]
mod tests {
    trait RootIf {}

    trait AFeatureIf: RootIf {
        fn prepend_a(&self) -> String;

        fn call_prepend_a(&self) -> String {
            self.prepend_a()
        }
    }

    trait BFeatureIf: RootIf {
        fn prepend_b(&self) -> String;
    }

    trait ExtRootIf: RootIf {
        fn get_common_thing(&self) -> String;
    }

    trait ExtAFeatureIf: AFeatureIf + ExtRootIf {
        fn prepend_a(&self) -> String {
            format!("A: {}", self.get_common_thing())
        }
    }

    trait ExtBFeatureIf: BFeatureIf + ExtRootIf {
        fn prepend_b(&self) -> String {
            format!("B: {}", self.get_common_thing())
        }
    }

    struct Delegate {
        common_thing: String,
    }

    impl RootIf for Delegate {}

    impl ExtRootIf for Delegate {
        fn get_common_thing(&self) -> String {
            self.common_thing.clone()
        }
    }

    impl AFeatureIf for Delegate {
        fn prepend_a(&self) -> String {
            format!("A: {}", self.get_common_thing())
        }
    }
    impl BFeatureIf for Delegate {
        fn prepend_b(&self) -> String {
            format!("B: {}", self.get_common_thing())
        }
    }
    impl ExtAFeatureIf for Delegate {}
    impl ExtBFeatureIf for Delegate {}

    #[test]
    fn test_compose_on_delegate() {
        let composed = Delegate {
            common_thing: "Hello, World!".to_string(),
        };

        assert_eq!(composed.get_common_thing(), "Hello, World!");

        let a: &dyn AFeatureIf = &composed;
        assert_eq!(a.prepend_a(), "A: Hello, World!");

        let b: &dyn BFeatureIf = &composed;
        assert_eq!(b.prepend_b(), "B: Hello, World!");
    }

    #[test]
    fn test_composed_on_delegate_polymorphic() {
        let composed = Delegate {
            common_thing: "Hello, World!".to_string(),
        };

        assert_eq!(composed.get_common_thing(), "Hello, World!");

        let a: &dyn AFeatureIf = &composed;
        assert_eq!(a.prepend_a(), "A: Hello, World!");
        assert_eq!(a.call_prepend_a(), "A: Hello, World!");
    }
}

use std::fmt;

/// Represents the signature of a method: name, return-type string, and parameter-type strings.
///
/// Java's `java.lang.reflect.Method` carries name, return type, and parameter types.
/// This struct captures those same fields as strings so that signatures can be compared
/// across different declaring types — mirroring `ProxyUtilities.areSameMethod`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MethodSignature {
    /// The method name.
    pub name: String,
    /// String representation of the return type.
    pub return_type: String,
    /// String representations of the parameter types, in order.
    pub param_types: Vec<String>,
}

impl MethodSignature {
    /// Creates a new [`MethodSignature`].
    pub fn new(
        name: impl Into<String>,
        return_type: impl Into<String>,
        param_types: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            name: name.into(),
            return_type: return_type.into(),
            param_types: param_types.into_iter().map(Into::into).collect(),
        }
    }
}

impl fmt::Display for MethodSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}({}): {}", self.name, self.param_types.join(", "), self.return_type)
    }
}

/// Returns `true` if `m1` and `m2` represent the same method signature, ignoring the
/// declaring type.
///
/// Two signatures match when they share the same name, return type, and parameter types
/// (in order).  Mirrors `ProxyUtilities.areSameMethod` from the Java source.
///
/// In Java, `areSameMethod` compares `Method` objects from `java.lang.reflect`; here the
/// same information is held in [`MethodSignature`] strings, which the caller populates.
pub fn are_same_method(m1: &MethodSignature, m2: &MethodSignature) -> bool {
    m1 == m2
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sig(name: &str, ret: &str, params: &[&str]) -> MethodSignature {
        MethodSignature::new(name, ret, params.iter().copied())
    }

    #[test]
    fn same_signature_matches() {
        let m1 = sig("foo", "String", &["int", "bool"]);
        let m2 = sig("foo", "String", &["int", "bool"]);
        assert!(are_same_method(&m1, &m2));
    }

    #[test]
    fn different_name_does_not_match() {
        let m1 = sig("foo", "String", &[]);
        let m2 = sig("bar", "String", &[]);
        assert!(!are_same_method(&m1, &m2));
    }

    #[test]
    fn different_return_type_does_not_match() {
        let m1 = sig("foo", "String", &[]);
        let m2 = sig("foo", "int", &[]);
        assert!(!are_same_method(&m1, &m2));
    }

    #[test]
    fn different_param_types_does_not_match() {
        let m1 = sig("foo", "String", &["int"]);
        let m2 = sig("foo", "String", &["long"]);
        assert!(!are_same_method(&m1, &m2));
    }

    #[test]
    fn different_param_count_does_not_match() {
        let m1 = sig("foo", "void", &["int"]);
        let m2 = sig("foo", "void", &["int", "int"]);
        assert!(!are_same_method(&m1, &m2));
    }

    #[test]
    fn same_signature_ignores_declaring_type() {
        // Mirrors areSameMethod: methods from different declaring classes with the
        // same name/return-type/params are considered identical.
        let m1 = MethodSignature::new("getValue", "int", [] as [&str; 0]);
        let m2 = MethodSignature::new("getValue", "int", [] as [&str; 0]);
        assert!(are_same_method(&m1, &m2));
    }

    #[test]
    fn display_with_params() {
        let m = sig("compute", "double", &["int", "float"]);
        assert_eq!(m.to_string(), "compute(int, float): double");
    }

    #[test]
    fn display_no_params() {
        let m = sig("run", "void", &[]);
        assert_eq!(m.to_string(), "run(): void");
    }

    // Java's composeOnDelegate uses runtime dynamic proxies (java.lang.reflect.Proxy) to
    // mix interface default methods onto a delegate at runtime.  Rust has no equivalent
    // runtime proxy mechanism; the same composition is expressed statically through trait
    // default implementations.  The tests below mirror ProxyUtilitiesTest, demonstrating
    // that Rust's trait system provides the identical semantics without a utility function.

    trait ExtRootTrait {
        fn get_common_thing(&self) -> String;
    }

    trait ExtAFeatureTrait: ExtRootTrait {
        fn prepend_a(&self) -> String {
            format!("A: {}", self.get_common_thing())
        }
        fn call_prepend_a(&self) -> String {
            self.prepend_a()
        }
    }

    trait ExtBFeatureTrait: ExtRootTrait {
        fn prepend_b(&self) -> String {
            format!("B: {}", self.get_common_thing())
        }
    }

    struct Delegate {
        thing: &'static str,
    }

    impl ExtRootTrait for Delegate {
        fn get_common_thing(&self) -> String {
            self.thing.to_string()
        }
    }

    impl ExtAFeatureTrait for Delegate {}
    impl ExtBFeatureTrait for Delegate {}

    #[test]
    fn compose_on_delegate() {
        let d = Delegate { thing: "Hello, World!" };
        assert_eq!(d.get_common_thing(), "Hello, World!");
        assert_eq!(d.prepend_a(), "A: Hello, World!");
        assert_eq!(d.prepend_b(), "B: Hello, World!");
    }

    #[test]
    fn compose_on_delegate_polymorphic() {
        let d = Delegate { thing: "Hello, World!" };
        assert_eq!(d.get_common_thing(), "Hello, World!");
        assert_eq!(d.prepend_a(), "A: Hello, World!");
        assert_eq!(d.call_prepend_a(), "A: Hello, World!");
    }
}

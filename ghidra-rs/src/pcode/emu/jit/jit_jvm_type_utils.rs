/// Utilities for generating JVM type signatures for ASM bytecode generation.
///
/// Corresponds to `ghidra.pcode.emu.jit.JitJvmTypeUtils`.
///
/// The internal representation of signatures accepted by the ASM API may vary across
/// versions; if the ASM version changes, these utilities may need revision.

/// A Java type for JVM signature generation.
///
/// Corresponds to `java.lang.reflect.Type` and its concrete subtypes.
#[derive(Debug, Clone, PartialEq)]
pub enum JavaType {
    /// A plain class or interface, represented by its JVM internal name
    /// (e.g., `java/lang/String`).
    Class(String),
    /// A generic array type.
    Array(Box<JavaType>),
    /// A parameterized (generic) class or interface.
    Parameterized {
        /// JVM internal name of the raw type (e.g., `java/util/List`).
        raw: String,
        /// Type arguments.
        args: Vec<JavaType>,
    },
    /// A wildcard type (`?`, `? extends T`, or `? super T`).
    Wildcard(WildcardBound),
    /// A type variable, stored with its upper bounds.
    TypeVariable(Vec<JavaType>),
}

/// The bound of a wildcard Java type.
#[derive(Debug, Clone, PartialEq)]
pub enum WildcardBound {
    /// Unbounded wildcard: `?`
    Unbounded,
    /// Upper-bounded wildcard: `? extends T`
    Extends(Box<JavaType>),
    /// Lower-bounded wildcard: `? super T`
    Super(Box<JavaType>),
}

/// Converts a dotted Java class name to a JVM internal name by replacing `.` with `/`.
///
/// Example: `java.lang.String` → `java/lang/String`.
///
/// Corresponds to `JitJvmTypeUtils.classToInternalName`.
pub fn class_to_internal_name(dotted_name: &str) -> String {
    dotted_name.replace('.', "/")
}

/// Gets the JVM internal name of a raw (non-generic) class type.
///
/// Panics if `ty` is not a [`JavaType::Class`] variant.
///
/// Corresponds to `JitJvmTypeUtils.rawToInternalName`.
pub fn raw_to_internal_name(ty: &JavaType) -> &str {
    match ty {
        JavaType::Class(name) => name,
        _ => panic!("expected a Class variant for raw_to_internal_name"),
    }
}

/// Gets the JVM signature for a wildcard type.
///
/// - `?` (unbounded, upper bound is Object) → `*`
/// - `? extends T` (upper bound is T) → `+sig(T)`
/// - `? super T` (lower bound is T, upper bound is Object) → `-sig(T)`
///
/// Corresponds to `JitJvmTypeUtils.wildToSignature`.
pub fn wild_to_signature(bound: &WildcardBound) -> String {
    match bound {
        WildcardBound::Unbounded => "*".to_string(),
        WildcardBound::Extends(t) => format!("+{}", type_to_signature(t)),
        WildcardBound::Super(t) => format!("-{}", type_to_signature(t)),
    }
}

/// Gets the JVM generic type signature for a Java type.
///
/// - `Class(C)` → `LC;`
/// - `Array(T)` → `[sig(T)`
/// - `Parameterized { raw, args }` → `Lraw<sig(A),sig(B),...>;`
/// - `Wildcard(b)` → see [`wild_to_signature`]
/// - `TypeVariable` is not supported and will panic.
///
/// Corresponds to `JitJvmTypeUtils.typeToSignature`.
pub fn type_to_signature(ty: &JavaType) -> String {
    match ty {
        JavaType::Class(name) => format!("L{};", name),
        JavaType::Array(elem) => format!("[{}", type_to_signature(elem)),
        JavaType::Parameterized { raw, args } => {
            let args_str = args
                .iter()
                .map(type_to_signature)
                .collect::<Vec<_>>()
                .join(",");
            format!("L{}<{}>;", raw, args_str)
        }
        JavaType::Wildcard(bound) => wild_to_signature(bound),
        JavaType::TypeVariable(_) => panic!("type variables are not supported in type_to_signature"),
    }
}

/// Computes the erasure of a set of type variable upper bounds.
///
/// Returns `java/lang/Object` if there are no bounds; otherwise the erasure of the first bound.
///
/// Corresponds to `JitJvmTypeUtils.eraseBounds`.
pub fn erase_bounds(bounds: &[JavaType]) -> JavaType {
    if bounds.is_empty() {
        JavaType::Class("java/lang/Object".to_string())
    } else {
        erase(&bounds[0])
    }
}

/// Computes the type erasure of a Java type.
///
/// - `Class` → same class
/// - `Array(T)` → `Array(erase(T))`
/// - `Parameterized { raw, .. }` → `Class(raw)`
/// - `TypeVariable(bounds)` → `erase_bounds(bounds)`
/// - `Wildcard(Extends(T))` → `erase_bounds([T])`
/// - `Wildcard(Super(_) | Unbounded)` → `java/lang/Object`
///
/// Corresponds to `JitJvmTypeUtils.erase`.
pub fn erase(ty: &JavaType) -> JavaType {
    match ty {
        JavaType::Class(_) => ty.clone(),
        JavaType::Array(elem) => JavaType::Array(Box::new(erase(elem))),
        JavaType::Parameterized { raw, .. } => JavaType::Class(raw.clone()),
        JavaType::TypeVariable(bounds) => erase_bounds(bounds),
        JavaType::Wildcard(WildcardBound::Extends(t)) => erase_bounds(&[*t.clone()]),
        JavaType::Wildcard(WildcardBound::Super(_) | WildcardBound::Unbounded) => {
            JavaType::Class("java/lang/Object".to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn class_to_internal_name_replaces_dots() {
        assert_eq!(class_to_internal_name("java.lang.String"), "java/lang/String");
        assert_eq!(class_to_internal_name("java.util.List"), "java/util/List");
    }

    #[test]
    fn class_to_internal_name_no_dots() {
        assert_eq!(class_to_internal_name("Object"), "Object");
    }

    #[test]
    fn raw_to_internal_name_returns_class_name() {
        let ty = JavaType::Class("java/lang/String".to_string());
        assert_eq!(raw_to_internal_name(&ty), "java/lang/String");
    }

    #[test]
    fn type_to_signature_class() {
        let ty = JavaType::Class("java/lang/String".to_string());
        assert_eq!(type_to_signature(&ty), "Ljava/lang/String;");
    }

    #[test]
    fn type_to_signature_array() {
        let ty = JavaType::Array(Box::new(JavaType::Class("java/lang/String".to_string())));
        assert_eq!(type_to_signature(&ty), "[Ljava/lang/String;");
    }

    #[test]
    fn type_to_signature_nested_array() {
        let ty = JavaType::Array(Box::new(JavaType::Array(Box::new(JavaType::Class(
            "java/lang/String".to_string(),
        )))));
        assert_eq!(type_to_signature(&ty), "[[Ljava/lang/String;");
    }

    #[test]
    fn type_to_signature_parameterized_single_arg() {
        let ty = JavaType::Parameterized {
            raw: "java/util/List".to_string(),
            args: vec![JavaType::Class("java/lang/String".to_string())],
        };
        assert_eq!(type_to_signature(&ty), "Ljava/util/List<Ljava/lang/String;>;");
    }

    #[test]
    fn type_to_signature_parameterized_multiple_args() {
        let ty = JavaType::Parameterized {
            raw: "java/util/Map".to_string(),
            args: vec![
                JavaType::Class("java/lang/String".to_string()),
                JavaType::Class("java/lang/Integer".to_string()),
            ],
        };
        assert_eq!(
            type_to_signature(&ty),
            "Ljava/util/Map<Ljava/lang/String;,Ljava/lang/Integer;>;"
        );
    }

    #[test]
    fn wild_to_signature_unbounded() {
        assert_eq!(wild_to_signature(&WildcardBound::Unbounded), "*");
    }

    #[test]
    fn wild_to_signature_extends() {
        let bound =
            WildcardBound::Extends(Box::new(JavaType::Class("java/lang/Number".to_string())));
        assert_eq!(wild_to_signature(&bound), "+Ljava/lang/Number;");
    }

    #[test]
    fn wild_to_signature_super() {
        let bound =
            WildcardBound::Super(Box::new(JavaType::Class("java/lang/Integer".to_string())));
        assert_eq!(wild_to_signature(&bound), "-Ljava/lang/Integer;");
    }

    #[test]
    fn type_to_signature_wildcard_unbounded_in_parameterized() {
        let ty = JavaType::Parameterized {
            raw: "java/util/List".to_string(),
            args: vec![JavaType::Wildcard(WildcardBound::Unbounded)],
        };
        assert_eq!(type_to_signature(&ty), "Ljava/util/List<*>;");
    }

    #[test]
    fn type_to_signature_wildcard_super_in_parameterized() {
        let ty = JavaType::Parameterized {
            raw: "java/util/List".to_string(),
            args: vec![JavaType::Wildcard(WildcardBound::Super(Box::new(
                JavaType::Class("java/lang/Integer".to_string()),
            )))],
        };
        assert_eq!(type_to_signature(&ty), "Ljava/util/List<-Ljava/lang/Integer;>;");
    }

    #[test]
    fn type_to_signature_wildcard_extends_in_parameterized() {
        let ty = JavaType::Parameterized {
            raw: "java/util/List".to_string(),
            args: vec![JavaType::Wildcard(WildcardBound::Extends(Box::new(
                JavaType::Class("java/lang/Number".to_string()),
            )))],
        };
        assert_eq!(type_to_signature(&ty), "Ljava/util/List<+Ljava/lang/Number;>;");
    }

    #[test]
    fn erase_class_is_identity() {
        let ty = JavaType::Class("java/lang/String".to_string());
        assert_eq!(erase(&ty), ty);
    }

    #[test]
    fn erase_parameterized_gives_raw() {
        let ty = JavaType::Parameterized {
            raw: "java/util/List".to_string(),
            args: vec![JavaType::Class("java/lang/String".to_string())],
        };
        assert_eq!(erase(&ty), JavaType::Class("java/util/List".to_string()));
    }

    #[test]
    fn erase_array_erases_element() {
        let ty = JavaType::Array(Box::new(JavaType::Parameterized {
            raw: "java/util/List".to_string(),
            args: vec![JavaType::Class("java/lang/String".to_string())],
        }));
        assert_eq!(
            erase(&ty),
            JavaType::Array(Box::new(JavaType::Class("java/util/List".to_string())))
        );
    }

    #[test]
    fn erase_type_variable_no_bounds_gives_object() {
        let ty = JavaType::TypeVariable(vec![]);
        assert_eq!(erase(&ty), JavaType::Class("java/lang/Object".to_string()));
    }

    #[test]
    fn erase_type_variable_with_bound() {
        let ty = JavaType::TypeVariable(vec![JavaType::Class("java/lang/Number".to_string())]);
        assert_eq!(erase(&ty), JavaType::Class("java/lang/Number".to_string()));
    }

    #[test]
    fn erase_wildcard_unbounded_gives_object() {
        let ty = JavaType::Wildcard(WildcardBound::Unbounded);
        assert_eq!(erase(&ty), JavaType::Class("java/lang/Object".to_string()));
    }

    #[test]
    fn erase_wildcard_super_gives_object() {
        let ty = JavaType::Wildcard(WildcardBound::Super(Box::new(JavaType::Class(
            "java/lang/Integer".to_string(),
        ))));
        assert_eq!(erase(&ty), JavaType::Class("java/lang/Object".to_string()));
    }

    #[test]
    fn erase_wildcard_extends_gives_bound() {
        let ty = JavaType::Wildcard(WildcardBound::Extends(Box::new(JavaType::Class(
            "java/lang/Number".to_string(),
        ))));
        assert_eq!(erase(&ty), JavaType::Class("java/lang/Number".to_string()));
    }

    #[test]
    fn erase_bounds_empty_gives_object() {
        assert_eq!(erase_bounds(&[]), JavaType::Class("java/lang/Object".to_string()));
    }

    #[test]
    fn erase_bounds_returns_erasure_of_first() {
        let bounds = vec![JavaType::Parameterized {
            raw: "java/util/List".to_string(),
            args: vec![JavaType::Class("java/lang/String".to_string())],
        }];
        assert_eq!(erase_bounds(&bounds), JavaType::Class("java/util/List".to_string()));
    }
}

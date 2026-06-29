use std::collections::HashSet;

/// A method descriptor with its declared annotation names, analogous to
/// `java.lang.reflect.Method` together with its `getAnnotation` results.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AnnotatedMethod {
    /// Fully-qualified name of the type that declares this method.
    pub declaring_type: String,
    /// The method name.
    pub name: String,
    /// String representation of the return type.
    pub return_type: String,
    /// String representations of the parameter types, in order.
    pub param_types: Vec<String>,
}

impl AnnotatedMethod {
    /// Creates a new [`AnnotatedMethod`].
    pub fn new(
        declaring_type: impl Into<String>,
        name: impl Into<String>,
        return_type: impl Into<String>,
        param_types: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            declaring_type: declaring_type.into(),
            name: name.into(),
            return_type: return_type.into(),
            param_types: param_types.into_iter().map(Into::into).collect(),
        }
    }
}

/// A node in a class/interface hierarchy, analogous to `java.lang.Class<?>` in the
/// context of `AnnotationUtilities`: it carries the methods declared directly on this
/// type (each paired with their annotation names) plus references to immediate supertypes.
///
/// Mirrors `Class.getSuperclass()` + `Class.getInterfaces()` by listing supertypes
/// in order: superclass first, then implemented interfaces.
pub struct TypeNode {
    /// A unique name for this type (e.g. fully-qualified class name).
    pub type_name: String,
    /// Methods declared directly on this type, each paired with its annotation names.
    pub declared_methods: Vec<(AnnotatedMethod, Vec<String>)>,
    /// Immediate supertypes: superclass first, then implemented interfaces.
    pub supertypes: Vec<TypeNode>,
}

impl TypeNode {
    /// Creates a new leaf [`TypeNode`] (no supertypes).
    pub fn new(
        type_name: impl Into<String>,
        declared_methods: Vec<(AnnotatedMethod, Vec<String>)>,
    ) -> Self {
        Self {
            type_name: type_name.into(),
            declared_methods,
            supertypes: Vec::new(),
        }
    }

    /// Creates a [`TypeNode`] with the given supertypes.
    pub fn with_supertypes(
        type_name: impl Into<String>,
        declared_methods: Vec<(AnnotatedMethod, Vec<String>)>,
        supertypes: Vec<TypeNode>,
    ) -> Self {
        Self {
            type_name: type_name.into(),
            declared_methods,
            supertypes,
        }
    }
}

/// Collects from among the given type node, its supertypes, and their supertypes
/// (recursively) all methods bearing the given annotation name.
///
/// Mirrors `AnnotationUtilities.collectAnnotatedMethods(annotCls, cls)` from the Java
/// source. Because Rust has no runtime reflection, the type hierarchy and annotation
/// names must be supplied explicitly by the caller via [`TypeNode`].
///
/// The traversal visits each type at most once (cycle-safe), processing supertypes
/// depth-first before the declaring type — replicating the Java recursion order.
pub fn collect_annotated_methods(annot_name: &str, ty: &TypeNode) -> HashSet<AnnotatedMethod> {
    let mut result = HashSet::new();
    let mut visited = HashSet::new();
    collect_inner(annot_name, ty, &mut result, &mut visited);
    result
}

fn collect_inner(
    annot_name: &str,
    ty: &TypeNode,
    result: &mut HashSet<AnnotatedMethod>,
    visited: &mut HashSet<String>,
) {
    if !visited.insert(ty.type_name.clone()) {
        return;
    }
    for supertype in &ty.supertypes {
        collect_inner(annot_name, supertype, result, visited);
    }
    for (method, annotations) in &ty.declared_methods {
        if annotations.iter().any(|a| a == annot_name) {
            result.insert(method.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn method(declaring: &str, name: &str) -> AnnotatedMethod {
        AnnotatedMethod::new(declaring, name, "void", [] as [&str; 0])
    }

    fn leaf(type_name: &str, methods: Vec<(AnnotatedMethod, Vec<String>)>) -> TypeNode {
        TypeNode::new(type_name, methods)
    }

    #[test]
    fn single_type_annotated_method() {
        let m = method("Foo", "doSomething");
        let node = leaf("Foo", vec![(m.clone(), vec!["Handler".to_string()])]);
        let result = collect_annotated_methods("Handler", &node);
        assert_eq!(result.len(), 1);
        assert!(result.contains(&m));
    }

    #[test]
    fn no_annotated_methods_returns_empty() {
        let m = method("Foo", "doSomething");
        let node = leaf("Foo", vec![(m, vec!["OtherAnnotation".to_string()])]);
        let result = collect_annotated_methods("Handler", &node);
        assert!(result.is_empty());
    }

    #[test]
    fn multiple_annotations_only_matching_annotation_collected() {
        let m = method("Foo", "doSomething");
        let node = leaf(
            "Foo",
            vec![(m.clone(), vec!["Callback".to_string(), "Handler".to_string()])],
        );
        assert!(collect_annotated_methods("Handler", &node).contains(&m));
        assert!(collect_annotated_methods("Callback", &node).contains(&m));
        assert!(collect_annotated_methods("Other", &node).is_empty());
    }

    #[test]
    fn inherited_annotated_method_collected_from_supertype() {
        let m = method("Base", "handleEvent");
        let base = leaf("Base", vec![(m.clone(), vec!["Handler".to_string()])]);
        let sub = TypeNode::with_supertypes("Sub", vec![], vec![base]);
        let result = collect_annotated_methods("Handler", &sub);
        assert!(result.contains(&m));
    }

    #[test]
    fn unannotated_supertype_method_not_collected() {
        let m = method("Base", "handleEvent");
        let base = leaf("Base", vec![(m, vec![])]);
        let sub = TypeNode::with_supertypes("Sub", vec![], vec![base]);
        assert!(collect_annotated_methods("Handler", &sub).is_empty());
    }

    #[test]
    fn diamond_inheritance_type_visited_once() {
        // Shared -> A -> Diamond, Shared -> B -> Diamond
        // The method on Shared should appear exactly once.
        let m = method("Shared", "onEvent");
        let shared = leaf("Shared", vec![(m.clone(), vec!["Handler".to_string()])]);

        // We can't share one TypeNode between two parents (ownership), so mirror the
        // Java test by constructing two identical Shared nodes — the visited set keyed
        // on type_name ensures only one contributes its methods.
        let shared2 = leaf("Shared", vec![(m.clone(), vec!["Handler".to_string()])]);

        let a = TypeNode::with_supertypes("A", vec![], vec![shared]);
        let b = TypeNode::with_supertypes("B", vec![], vec![shared2]);
        let diamond = TypeNode::with_supertypes("Diamond", vec![], vec![a, b]);

        let result = collect_annotated_methods("Handler", &diamond);
        assert_eq!(result.len(), 1, "shared method must appear exactly once");
        assert!(result.contains(&m));
    }

    #[test]
    fn methods_from_multiple_supertypes_all_collected() {
        let m1 = method("IA", "onA");
        let m2 = method("IB", "onB");
        let ia = leaf("IA", vec![(m1.clone(), vec!["Handler".to_string()])]);
        let ib = leaf("IB", vec![(m2.clone(), vec!["Handler".to_string()])]);
        let concrete = TypeNode::with_supertypes("Concrete", vec![], vec![ia, ib]);
        let result = collect_annotated_methods("Handler", &concrete);
        assert_eq!(result.len(), 2);
        assert!(result.contains(&m1));
        assert!(result.contains(&m2));
    }

    #[test]
    fn annotated_method_on_subtype_and_supertype_both_collected() {
        let m_base = method("Base", "handle");
        let m_sub = method("Sub", "handle");
        let base = leaf("Base", vec![(m_base.clone(), vec!["Handler".to_string()])]);
        let sub = TypeNode::with_supertypes(
            "Sub",
            vec![(m_sub.clone(), vec!["Handler".to_string()])],
            vec![base],
        );
        let result = collect_annotated_methods("Handler", &sub);
        // Different declaring_type means both are distinct AnnotatedMethod values.
        assert_eq!(result.len(), 2);
        assert!(result.contains(&m_base));
        assert!(result.contains(&m_sub));
    }
}

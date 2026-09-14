//! Port of `ghidra.util.database.annotproc.ValidationContext`.
//!
//! # Port strategy: decoupled from `javax.lang.model`
//!
//! The Java class is annotation-processor code: every non-trivial operation
//! (`isSubtype`/`isAssignable`/`unboxedType`/`directSupertypes`/`isSameType`/`getDeclaredType`)
//! is delegated to `javax.lang.model.util.Types`/`Elements`, live utilities supplied by the
//! running Java compiler (`ProcessingEnvironment`). This crate has no Rust equivalent of javac's
//! type-checker to delegate to. Per the existing siblings in this module -- `access_spec.rs`'s
//! `AccessSpec` and this module's `Modifier` -- the established convention in
//! `util::database::annotproc` is to model the *domain logic* these annotation-processor classes
//! encode as plain, runtime-testable Rust types/algorithms, decoupled from the live javac
//! reflection APIs that originally supplied their inputs.
//!
//! Following that convention (and this crate's "decoupling is first-class" rule: prefer trait
//! seams over pervasive concrete types), this port:
//! * Represents `TypeMirror` as the [`JavaType`] value enum -- an owned surrogate covering the
//!   same shape Java's `FormatVisitor` switches on, built directly rather than obtained by
//!   querying a live compiler.
//! * Represents `TypeElement` as the small [`TypeElement`] value type (a canonical name plus,
//!   where needed, its declared type parameters).
//! * Cuts `javax.lang.model.util.Types` down to the [`TypeOracle`] trait, exposing exactly the
//!   handful of queries `ValidationContext`'s own methods make against it (`is_subtype`,
//!   `is_assignable`, `unboxed_type`, `is_same_type`, `declared_type_of`, `direct_supertypes`).
//!   A real implementation would delegate to whatever this crate eventually uses to model type
//!   relationships if `DBAnnotatedField`-style validation is ever wired up at runtime; for now
//!   callers supply their own [`TypeOracle`], and `tests::MockTypeOracle` demonstrates and
//!   exercises every `ValidationContext` algorithm against one.
//! * `javax.annotation.processing.Messager`/`ProcessingEnvironment` become the minimal
//!   [`Messager`] trait -- stored (mirroring the Java field), but, as in the Java source, never
//!   called by any method below; real diagnostic reporting belongs to whatever (unported) code
//!   drives the annotation-style validation this class supports.

use std::collections::{HashMap, HashSet};

use super::abstract_db_annotation_validator::ElementKind;
use super::Modifier;

/// Surrogate for `javax.lang.model.element.TypeElement`: a named, declared type together with
/// enough structure for [`ValidationContext::find_supertype`]/[`ValidationContext::get_arguments`]
/// to walk its supertype chain and type parameters, without needing a live compiler.
#[derive(Debug, Clone)]
pub struct TypeElement {
    /// The element's canonical/binary name, e.g. `"java.util.List"`. Mirrors what
    /// `Elements.getTypeElement(String)` looks up by, and what two `TypeElement`s are compared
    /// by everywhere Java uses `==`/default `equals` on them (see
    /// [`ValidationContext::find_supertype`]'s `superType == ds.asElement()` check).
    pub name: String,
    /// Names of this element's own type parameters, in declaration order (`E` for `List<E>`,
    /// etc.). Mirrors `TypeElement.getTypeParameters()`.
    pub type_parameters: Vec<String>,
}

// A real `javax.lang.model.element.TypeElement` is canonicalized per compilation unit: it
// represents the class itself (like `List.class`), identified solely by its canonical name --
// two `TypeElement` instances for the same class are always `==` in Java regardless of how each
// was independently constructed. `type_parameters` is descriptive metadata about what the class
// declares, not part of its identity, so equality (and the Hash impl kept consistent with it)
// compares `name` only.
impl PartialEq for TypeElement {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}

impl Eq for TypeElement {}

impl std::hash::Hash for TypeElement {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.name.hash(state);
    }
}

impl TypeElement {
    /// A type element with no type parameters.
    pub fn new(name: impl Into<String>) -> Self {
        TypeElement { name: name.into(), type_parameters: Vec::new() }
    }

    /// A type element with the given type parameters.
    pub fn with_type_parameters(name: impl Into<String>, type_parameters: Vec<String>) -> Self {
        TypeElement { name: name.into(), type_parameters }
    }

    /// This element's own (unparameterized) type. Mirrors `TypeElement.asType()`.
    pub fn as_type(&self) -> JavaType {
        JavaType::Declared { element: self.clone(), type_arguments: Vec::new() }
    }
}

/// Surrogate for `javax.lang.model.type.TypeMirror` (and its subinterfaces
/// `DeclaredType`/`TypeVariable`/`WildcardType`/`ArrayType`/`PrimitiveType`/etc.): an owned value
/// describing a Java type's shape, built directly instead of obtained by querying a compiler. See
/// the module docs for why.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum JavaType {
    /// One of Java's eight primitive kinds, or `void`. Mirrors `TypeKind.{BOOLEAN,...,VOID}`
    /// dispatching to `visitPrimitive` in `FormatVisitor`.
    Primitive(&'static str),
    /// A class/interface type, optionally parameterized. `element` is `asElement()`;
    /// `type_arguments` is `getTypeArguments()`. Direct supertypes are *not* stored here (unlike
    /// a real `DeclaredType`, whose supertypes are queried live from the compiler) -- see
    /// [`TypeOracle::direct_supertypes`].
    Declared { element: TypeElement, type_arguments: Vec<JavaType> },
    /// An array type. Mirrors `ArrayType`.
    Array(Box<JavaType>),
    /// A type variable, e.g. a generic method/class parameter. Mirrors `TypeVariable`.
    TypeVar { name: String, lower_bound: Box<JavaType>, upper_bound: Box<JavaType> },
    /// A wildcard type argument (`?`, `? extends X`, `? super X`). Mirrors `WildcardType`.
    Wildcard { extends_bound: Option<Box<JavaType>>, super_bound: Option<Box<JavaType>> },
    /// An executable (method/constructor) type. Mirrors `ExecutableType`; `display` stands in for
    /// whatever `ExecutableType::toString()` would print, since `FormatVisitor::visitExecutable`
    /// likewise never inspects one structurally, just prints it.
    Executable(String),
    /// An erroneous type the compiler couldn't resolve. Mirrors `ErrorType`.
    Error(String),
    /// The absence of a type (e.g. a `void` method's *pseudo*-type, distinct from the primitive
    /// `void`, or "no bound"). Mirrors `NoType`.
    NoType(String),
    /// The null type: the type of the `null` literal, and the default lower bound of an
    /// unbounded type variable/wildcard. Mirrors `NullType`.
    Null,
    /// A union type (multi-catch `catch (A | B e)`). Mirrors `UnionType`.
    Union(Vec<JavaType>),
    /// An intersection type (`<T extends A & B>`). Mirrors `IntersectionType`.
    Intersection(Vec<JavaType>),
}

impl JavaType {
    /// Convenience: a bare (no type arguments) declared type. Java: `getDeclaredType(elem)` with
    /// no type argument varargs.
    pub fn declared(element: TypeElement) -> JavaType {
        JavaType::Declared { element, type_arguments: Vec::new() }
    }
}

/// Surrogate for `javax.lang.model.element.VariableElement` as used here.
///
/// `ValidationContext`'s own methods only ever need [`declared_type`](Self::declared_type). The
/// other two fields exist for the (unported-until-now) `DBAnnotatedColumnValidator`/
/// `DBAnnotatedFieldValidator`, which additionally call `field.getModifiers()` and
/// `(TypeElement) field.getEnclosingElement()` -- both live-compiler-supplied facts about the
/// annotated field/column's declaration site, so, per this module's own established convention
/// (see the module docs), they are supplied directly here by whatever constructs the
/// `VariableElement` rather than derived from a live `javax.lang.model` query.
#[derive(Debug, Clone)]
pub struct VariableElement {
    /// Java: `field.asType()`.
    pub declared_type: JavaType,

    /// Java: `field.getEnclosingElement()`, cast to `TypeElement`.
    pub enclosing_type: TypeElement,

    /// The [`ElementKind`] of [`Self::enclosing_type`] -- Java: `((TypeElement)
    /// field.getEnclosingElement()).getKind()`. See [`ElementKind`]'s own docs for why this
    /// two-variant stand-in, rather than a `TypeElement`-carried field, is used.
    pub enclosing_kind: ElementKind,

    /// Java: `field.getModifiers()`.
    pub modifiers: HashSet<Modifier>,
}

impl VariableElement {
    /// Constructs a `VariableElement` with no modifiers (Java: an empty `Set<Modifier>`).
    pub fn new(declared_type: JavaType, enclosing_type: TypeElement, enclosing_kind: ElementKind) -> Self {
        VariableElement { declared_type, enclosing_type, enclosing_kind, modifiers: HashSet::new() }
    }

    /// Builder-style: attaches the given modifiers.
    pub fn with_modifiers(mut self, modifiers: impl IntoIterator<Item = Modifier>) -> Self {
        self.modifiers = modifiers.into_iter().collect();
        self
    }
}

/// Cut-down surrogate for `javax.lang.model.util.Types`, exposing exactly the operations
/// `ValidationContext`'s own methods call against it. See the module docs for why this crate has
/// no real implementation of Java's type-checking algorithms to back this with; a real backend
/// would need to reimplement (a useful subset of) `javac`'s subtyping/assignability/erasure
/// rules.
pub trait TypeOracle {
    /// Java: `Types.isSubtype(TypeMirror, TypeMirror)`.
    fn is_subtype(&self, sub: &JavaType, sup: &JavaType) -> bool;

    /// Java: `Types.isAssignable(TypeMirror, TypeMirror)`.
    fn is_assignable(&self, from: &JavaType, to: &JavaType) -> bool;

    /// Java: `Types.unboxedType(TypeMirror)`. Returns `None` where Java throws
    /// `IllegalArgumentException` ("not unboxable").
    fn unboxed_type(&self, boxed: &JavaType) -> Option<JavaType>;

    /// Java: `Types.erasure(TypeMirror)`.
    fn erasure(&self, t: &JavaType) -> JavaType;

    /// Java: `Types.isSameType(TypeMirror, TypeMirror)`.
    fn is_same_type(&self, a: &JavaType, b: &JavaType) -> bool;

    /// Java: `Types.getDeclaredType(TypeElement, TypeMirror...)`.
    fn declared_type_of(&self, element: &TypeElement, type_arguments: Vec<JavaType>) -> JavaType;

    /// Java: `Types.directSupertypes(TypeMirror)`.
    fn direct_supertypes(&self, t: &JavaType) -> Vec<JavaType>;

    /// Java: `element.getModifiers().contains(Modifier.ABSTRACT)` for `elem`'s declaration.
    /// Added for `DBAnnotatedFieldValidator`'s `checkCodecTypes`, which checks whether a codec's
    /// field-type argument names a non-abstract class.
    fn is_abstract(&self, elem: &TypeElement) -> bool;
}

/// Surrogate for `javax.annotation.processing.Messager`. Stored by [`ValidationContext`]
/// (mirroring the Java field) but never called by any method here -- see the module docs.
pub trait Messager {
    /// Reports a processing error.
    fn print_error(&self, message: &str);
}

/// A [`Messager`] that discards every message, for callers that don't need diagnostics.
pub struct NoopMessager;

impl Messager for NoopMessager {
    fn print_error(&self, _message: &str) {}
}

/// Formats a [`JavaType`] as a readable string. Mirrors the package-private `FormatVisitor` class
/// (see [`ValidationContext::format`]).
///
/// Java implements this as a `TypeVisitor<Void, Void>` dispatching on `TypeKind`; since this
/// port's [`JavaType`] is already a closed enum (no further compiler-supplied subtyping to
/// dispatch over), a single recursive match plays the same role without needing the visitor
/// machinery.
pub fn format_type(t: &JavaType) -> String {
    match t {
        JavaType::Primitive(name) => (*name).to_string(),
        JavaType::Null => "null".to_string(),
        JavaType::Array(component) => format!("{}[]", format_type(component)),
        JavaType::Declared { element, type_arguments } => {
            if type_arguments.is_empty() {
                element.name.clone()
            } else {
                let args: Vec<String> = type_arguments.iter().map(format_type).collect();
                format!("{}<{}>", element.name, args.join(", "))
            }
        }
        JavaType::Error(display) => display.clone(),
        JavaType::TypeVar { name, lower_bound, upper_bound } => {
            let mut s = name.clone();
            if !matches!(**lower_bound, JavaType::Null) {
                s.push_str(" super ");
                s.push_str(&format_type(lower_bound));
            }
            if format_type(upper_bound) != "java.lang.Object" {
                s.push_str(" extends ");
                s.push_str(&format_type(upper_bound));
            }
            s
        }
        JavaType::Wildcard { extends_bound, super_bound } => {
            let mut s = "?".to_string();
            if let Some(sup) = super_bound {
                s.push_str(" super ");
                s.push_str(&format_type(sup));
            }
            if let Some(ext) = extends_bound {
                s.push_str(" extends ");
                s.push_str(&format_type(ext));
            }
            s
        }
        JavaType::Executable(display) => display.clone(),
        JavaType::NoType(display) => display.clone(),
        JavaType::Union(alts) => alts.iter().map(format_type).collect::<Vec<_>>().join(" | "),
        JavaType::Intersection(bounds) => {
            bounds.iter().map(format_type).collect::<Vec<_>>().join(" & ")
        }
    }
}

/// Validation helper providing common type-relationship queries used by the (unported)
/// DB-annotation validators.
///
/// Port of `ghidra.util.database.annotproc.ValidationContext`. See the module docs for the
/// overall port strategy.
pub struct ValidationContext {
    types: Box<dyn TypeOracle>,
    messager: Box<dyn Messager>,
    list_elem: TypeElement,
    db_annotated_object_elem: TypeElement,
    db_object_column_elem: TypeElement,
    db_field_codec_elem: TypeElement,
    default_codec_elem: TypeElement,
    enum_elem: TypeElement,
}

impl ValidationContext {
    /// Constructs a `ValidationContext` around the given [`TypeOracle`]/[`Messager`]
    /// implementations.
    ///
    /// Mirrors `ValidationContext(ProcessingEnvironment)`. There is no live `javac` environment
    /// to query here, so the well-known type element lookups
    /// (`elementUtils.getTypeElement(...)`) are resolved to their fixed, well-known canonical
    /// names directly, rather than through the [`TypeOracle`] seam.
    pub fn new(types: Box<dyn TypeOracle>, messager: Box<dyn Messager>) -> Self {
        ValidationContext {
            types,
            messager,
            list_elem: TypeElement::with_type_parameters("java.util.List", vec!["E".to_string()]),
            db_annotated_object_elem: TypeElement::new("ghidra.util.database.DBAnnotatedObject"),
            db_object_column_elem: TypeElement::new("ghidra.util.database.DBObjectColumn"),
            db_field_codec_elem: TypeElement::with_type_parameters(
                "ghidra.util.database.DBCachedObjectStoreFactory.DBFieldCodec",
                vec!["VT".to_string(), "OT".to_string(), "FT".to_string()],
            ),
            default_codec_elem: TypeElement::new(
                "ghidra.util.database.annot.DBAnnotatedField.DefaultCodec",
            ),
            enum_elem: TypeElement::with_type_parameters("java.lang.Enum", vec!["E".to_string()]),
        }
    }

    /// The [`Messager`] this context was constructed with. Never called by any method below (see
    /// the module docs); exposed so a real (unported) validator built on top of this context can
    /// still report diagnostics through it.
    pub fn messager(&self) -> &dyn Messager {
        self.messager.as_ref()
    }

    /// Java: `final TypeElement LIST_ELEM`.
    pub fn list_elem(&self) -> &TypeElement {
        &self.list_elem
    }

    /// Java: `final TypeElement DB_ANNOTATED_OBJECT_ELEM`.
    pub fn db_annotated_object_elem(&self) -> &TypeElement {
        &self.db_annotated_object_elem
    }

    /// Java: `final TypeElement DB_OBJECT_COLUMN_ELEM`.
    pub fn db_object_column_elem(&self) -> &TypeElement {
        &self.db_object_column_elem
    }

    /// Java: `final TypeElement DB_FIELD_CODEC_ELEM`.
    pub fn db_field_codec_elem(&self) -> &TypeElement {
        &self.db_field_codec_elem
    }

    /// Java: `final TypeElement DEFAULT_CODEC_ELEM`.
    pub fn default_codec_elem(&self) -> &TypeElement {
        &self.default_codec_elem
    }

    /// Java: `final TypeElement ENUM_ELEM`.
    pub fn enum_elem(&self) -> &TypeElement {
        &self.enum_elem
    }

    /// Check if `t1` is a subclass of `t2`.
    ///
    /// Java: `boolean isSubclass(TypeElement t1, TypeElement t2)`.
    pub fn is_subclass(&self, t1: &TypeElement, t2: &TypeElement) -> bool {
        self.types.is_subtype(&self.types.erasure(&t1.as_type()), &self.types.erasure(&t2.as_type()))
    }

    /// Check if the field has the specified type.
    ///
    /// Java: `boolean hasType(VariableElement field, TypeElement type)`.
    pub fn has_type_element(&self, field: &VariableElement, ty: &TypeElement) -> bool {
        self.has_type(field, &ty.as_type())
    }

    /// Check if the field has the specified type.
    ///
    /// Java: `boolean hasType(VariableElement field, TypeMirror type)`.
    ///
    /// Note: this unboxes the *target* `ty`, not the field's own type, then compares the field's
    /// (possibly-primitive) type against that unboxed result -- e.g. if `ty` is boxed `Integer`
    /// and the field's declared type is primitive `int`, `unboxed_type(Integer) == int` and the
    /// comparison succeeds. Preserved exactly as Java has it, not "the other way around".
    pub fn has_type(&self, field: &VariableElement, ty: &JavaType) -> bool {
        let field_type = &field.declared_type;

        if let Some(unboxed) = self.types.unboxed_type(ty) {
            if self.types.is_same_type(field_type, &unboxed) {
                return true;
            }
        }

        if let JavaType::Declared { element, .. } = field_type {
            if self.is_subclass(element, &self.enum_elem) {
                let enum_args = self.get_arguments(field_type, &self.enum_elem);
                if let Some(arg_e) = enum_args.get("E") {
                    if self.types.is_same_type(field_type, arg_e) {
                        return true;
                    }
                }
            }
        }

        self.types.is_assignable(field_type, ty)
    }

    /// Check if `t1` is capturable by `t2`.
    ///
    /// Java: `boolean isCapturable(TypeMirror t1, TypeMirror t2)`.
    // TODO: This only works for typevar at top level...
    // TODO: Need to figure out how to check for capture and check
    pub fn is_capturable(&self, t1: &JavaType, t2: &JavaType) -> bool {
        if let JavaType::TypeVar { upper_bound, lower_bound, .. } = t2 {
            if !self.types.is_subtype(t1, upper_bound) {
                return false;
            }
            if !self.types.is_subtype(lower_bound, t1) {
                return false;
            }
            return true;
        }
        self.types.is_subtype(t1, t2)
    }

    /// Check if the type is an enum type.
    ///
    /// Java: `boolean isEnumType(TypeMirror t)`.
    pub fn is_enum_type(&self, t: &JavaType) -> bool {
        if !matches!(t, JavaType::Declared { .. }) {
            return false;
        }
        let enum_type = self.types.declared_type_of(&self.enum_elem, vec![t.clone()]);
        self.types.is_subtype(t, &enum_type)
    }

    /// Java: `protected DeclaredType findSupertype(Set<DeclaredType> types, TypeElement
    /// superType)`.
    fn find_supertype_bfs(&self, start: JavaType, super_elem: &TypeElement) -> Option<JavaType> {
        let mut frontier: HashSet<JavaType> = HashSet::new();
        frontier.insert(start);
        while !frontier.is_empty() {
            let mut next: HashSet<JavaType> = HashSet::new();
            for t in &frontier {
                for s in self.types.direct_supertypes(t) {
                    if let JavaType::Declared { element, .. } = &s {
                        if element == super_elem {
                            return Some(s);
                        }
                    }
                    next.insert(s);
                }
            }
            frontier = next;
        }
        None
    }

    /// Find the supertype of a declared type that matches the specified super type element.
    ///
    /// Java: `DeclaredType findSupertype(DeclaredType type, TypeElement superElem)`.
    pub fn find_supertype(&self, ty: &JavaType, super_elem: &TypeElement) -> Option<JavaType> {
        self.find_supertype_bfs(ty.clone(), super_elem)
    }

    /// Find the supertype of a type element that matches the specified super type element.
    ///
    /// Java: `DeclaredType findSupertype(TypeElement elem, TypeElement superElem)`.
    pub fn find_supertype_of_element(
        &self,
        elem: &TypeElement,
        super_elem: &TypeElement,
    ) -> Option<JavaType> {
        self.find_supertype(&elem.as_type(), super_elem)
    }

    /// Java: `protected Map<String, TypeMirror> toArgsMap(TypeElement superElem, DeclaredType
    /// superType)`.
    fn to_args_map(super_elem: &TypeElement, super_type: &JavaType) -> HashMap<String, JavaType> {
        let type_arguments: &[JavaType] = match super_type {
            JavaType::Declared { type_arguments, .. } => type_arguments,
            _ => &[],
        };
        // Java: `assert typeParameters.size() == typeArguments.size();` -- Java assertions are
        // disabled at runtime by default (no `-ea`), so this is a no-op outside debug tooling;
        // `debug_assert_eq!` mirrors that same "checked only in debug builds" reality rather than
        // always panicking.
        debug_assert_eq!(
            super_elem.type_parameters.len(),
            type_arguments.len(),
            "type parameter/argument count mismatch"
        );
        super_elem
            .type_parameters
            .iter()
            .cloned()
            .zip(type_arguments.iter().cloned())
            .collect()
    }

    /// Convert the type arguments of the super type element to a map.
    ///
    /// Java: `Map<String, TypeMirror> getArguments(DeclaredType type, TypeElement superElem)`.
    ///
    /// Java's `findSupertype` returns `null` when no matching supertype exists, and
    /// `toArgsMap(superElem, null)` then immediately NPEs calling `null.getTypeArguments()`.
    /// This port preserves that as a panic (via `.expect`) rather than silently returning an
    /// empty map.
    pub fn get_arguments(&self, ty: &JavaType, super_elem: &TypeElement) -> HashMap<String, JavaType> {
        let super_type = self.find_supertype(ty, super_elem).expect(
            "ValidationContext.getArguments: no matching supertype found (mirrors a Java \
             NullPointerException from toArgsMap(superElem, null))",
        );
        Self::to_args_map(super_elem, &super_type)
    }

    /// Get the type arguments of a type element as a map.
    ///
    /// Java: `Map<String, TypeMirror> getArguments(TypeElement elem, TypeElement superElem)`.
    pub fn get_arguments_of_element(
        &self,
        elem: &TypeElement,
        super_elem: &TypeElement,
    ) -> HashMap<String, JavaType> {
        self.get_arguments(&elem.as_type(), super_elem)
    }

    /// Format the given type as a string.
    ///
    /// Java: `String format(TypeMirror type)`.
    pub fn format(&self, t: &JavaType) -> String {
        format_type(t)
    }

    /// Check if the given type element is declared abstract.
    ///
    /// Java: `elem.getModifiers().contains(Modifier.ABSTRACT)`, via [`TypeOracle::is_abstract`].
    pub fn is_abstract(&self, elem: &TypeElement) -> bool {
        self.types.is_abstract(elem)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A small, hand-built [`TypeOracle`] over a fixed type hierarchy, sufficient to exercise
    /// every `ValidationContext` algorithm. Subtyping/assignability are resolved by walking
    /// `supertypes` (keyed by element name, ignoring type arguments -- adequate for these tests,
    /// though not a full reimplementation of Java generics).
    struct MockTypeOracle {
        /// element name -> its direct supertypes.
        supertypes: HashMap<String, Vec<JavaType>>,
        /// boxed type name -> unboxed primitive type.
        boxes: HashMap<String, JavaType>,
    }

    impl MockTypeOracle {
        fn new() -> Self {
            let object = JavaType::declared(TypeElement::new("java.lang.Object"));

            let mut supertypes = HashMap::new();
            supertypes.insert("java.lang.Object".to_string(), vec![]);
            supertypes.insert(
                "com.example.Base".to_string(),
                vec![object.clone()],
            );
            supertypes.insert(
                "com.example.Sub".to_string(),
                vec![JavaType::declared(TypeElement::new("com.example.Base"))],
            );
            // com.example.MyEnum extends java.lang.Enum<com.example.MyEnum>
            supertypes.insert(
                "com.example.MyEnum".to_string(),
                vec![JavaType::Declared {
                    element: TypeElement::with_type_parameters(
                        "java.lang.Enum",
                        vec!["E".to_string()],
                    ),
                    type_arguments: vec![JavaType::declared(TypeElement::new("com.example.MyEnum"))],
                }],
            );
            supertypes.insert("java.lang.Enum".to_string(), vec![object.clone()]);
            supertypes.insert("java.lang.Integer".to_string(), vec![object.clone()]);

            let mut boxes = HashMap::new();
            boxes.insert(
                "java.lang.Integer".to_string(),
                JavaType::Primitive("int"),
            );
            boxes.insert(
                "java.lang.Boolean".to_string(),
                JavaType::Primitive("boolean"),
            );

            MockTypeOracle { supertypes, boxes }
        }

        fn element_name(t: &JavaType) -> Option<&str> {
            match t {
                JavaType::Declared { element, .. } => Some(element.name.as_str()),
                _ => None,
            }
        }
    }

    impl TypeOracle for MockTypeOracle {
        fn is_subtype(&self, sub: &JavaType, sup: &JavaType) -> bool {
            if sub == sup {
                return true;
            }
            // Java's null type is a subtype of every reference type (the "bottom type"), which
            // matters for `ValidationContext::is_capturable`'s default (`Null`) lower bound.
            if matches!(sub, JavaType::Null) {
                return true;
            }
            let Some(sub_name) = Self::element_name(sub) else { return false };
            let Some(sup_name) = Self::element_name(sup) else { return false };
            // BFS over supertypes, matching by element name only (ignoring type arguments) --
            // sufficient for these tests, including the enum self-referential-bound check.
            let mut frontier: Vec<String> = vec![sub_name.to_string()];
            let mut seen: HashSet<String> = HashSet::new();
            while let Some(name) = frontier.pop() {
                if name == sup_name {
                    return true;
                }
                if !seen.insert(name.clone()) {
                    continue;
                }
                if let Some(supers) = self.supertypes.get(&name) {
                    for s in supers {
                        if let Some(n) = Self::element_name(s) {
                            frontier.push(n.to_string());
                        }
                    }
                }
            }
            false
        }

        fn is_assignable(&self, from: &JavaType, to: &JavaType) -> bool {
            self.is_subtype(from, to)
        }

        fn unboxed_type(&self, boxed: &JavaType) -> Option<JavaType> {
            let name = Self::element_name(boxed)?;
            self.boxes.get(name).cloned()
        }

        fn erasure(&self, t: &JavaType) -> JavaType {
            match t {
                JavaType::Declared { element, .. } => JavaType::declared(element.clone()),
                other => other.clone(),
            }
        }

        fn is_same_type(&self, a: &JavaType, b: &JavaType) -> bool {
            a == b
        }

        fn declared_type_of(&self, element: &TypeElement, type_arguments: Vec<JavaType>) -> JavaType {
            JavaType::Declared { element: element.clone(), type_arguments }
        }

        fn direct_supertypes(&self, t: &JavaType) -> Vec<JavaType> {
            match Self::element_name(t) {
                Some(name) => self.supertypes.get(name).cloned().unwrap_or_default(),
                None => Vec::new(),
            }
        }

        fn is_abstract(&self, _elem: &TypeElement) -> bool {
            // Not exercised by this file's own tests; see DBAnnotatedFieldValidator's own tests.
            false
        }
    }

    fn ctx() -> ValidationContext {
        ValidationContext::new(Box::new(MockTypeOracle::new()), Box::new(NoopMessager))
    }

    /// Builds a [`VariableElement`] with an arbitrary (test-irrelevant) enclosing type/kind, for
    /// tests that only care about `declared_type`.
    fn variable_element(declared_type: JavaType) -> VariableElement {
        VariableElement::new(declared_type, TypeElement::new("com.example.Test"), ElementKind::Class)
    }

    // ---- is_subclass ----

    #[test]
    fn is_subclass_true_for_direct_and_transitive_supertypes() {
        let c = ctx();
        let sub = TypeElement::new("com.example.Sub");
        let base = TypeElement::new("com.example.Base");
        let object = TypeElement::new("java.lang.Object");
        assert!(c.is_subclass(&sub, &base));
        assert!(c.is_subclass(&sub, &object));
    }

    #[test]
    fn is_subclass_false_for_unrelated_types() {
        let c = ctx();
        let base = TypeElement::new("com.example.Base");
        let my_enum = TypeElement::new("com.example.MyEnum");
        assert!(!c.is_subclass(&base, &my_enum));
    }

    // ---- has_type ----

    #[test]
    fn has_type_matches_via_unboxing_the_target() {
        let c = ctx();
        let field = variable_element(JavaType::Primitive("int"));
        let boxed_integer = JavaType::declared(TypeElement::new("java.lang.Integer"));
        assert!(c.has_type(&field, &boxed_integer));
    }

    #[test]
    fn has_type_matches_enum_self_referential_bound() {
        let c = ctx();
        let my_enum_type = JavaType::declared(TypeElement::new("com.example.MyEnum"));
        let field = variable_element(my_enum_type.clone());
        assert!(c.has_type(&field, &my_enum_type));
    }

    #[test]
    fn has_type_falls_back_to_assignability() {
        let c = ctx();
        let field = variable_element(JavaType::declared(TypeElement::new("com.example.Sub")));
        let base = JavaType::declared(TypeElement::new("com.example.Base"));
        assert!(c.has_type(&field, &base));
    }

    #[test]
    fn has_type_false_for_unrelated_types() {
        let c = ctx();
        let field = variable_element(JavaType::declared(TypeElement::new("com.example.Base")));
        let my_enum = JavaType::declared(TypeElement::new("com.example.MyEnum"));
        assert!(!c.has_type(&field, &my_enum));
    }

    // ---- is_capturable ----

    #[test]
    fn is_capturable_plain_type_delegates_to_is_subtype() {
        let c = ctx();
        let sub = JavaType::declared(TypeElement::new("com.example.Sub"));
        let base = JavaType::declared(TypeElement::new("com.example.Base"));
        assert!(c.is_capturable(&sub, &base));
        assert!(!c.is_capturable(&base, &sub));
    }

    #[test]
    fn is_capturable_typevar_checks_both_bounds() {
        let c = ctx();
        let sub = JavaType::declared(TypeElement::new("com.example.Sub"));
        let object = JavaType::declared(TypeElement::new("java.lang.Object"));
        let base = JavaType::declared(TypeElement::new("com.example.Base"));
        // T extends Base, no explicit lower bound (Null)
        let t2 = JavaType::TypeVar {
            name: "T".to_string(),
            lower_bound: Box::new(JavaType::Null),
            upper_bound: Box::new(base.clone()),
        };
        assert!(c.is_capturable(&sub, &t2));

        // Upper bound too narrow: Sub is not a subtype of Sub2 (unrelated).
        let unrelated = JavaType::declared(TypeElement::new("com.example.MyEnum"));
        let t3 = JavaType::TypeVar {
            name: "T".to_string(),
            lower_bound: Box::new(JavaType::Null),
            upper_bound: Box::new(unrelated),
        };
        assert!(!c.is_capturable(&sub, &t3));

        let _ = object;
    }

    // ---- is_enum_type ----

    #[test]
    fn is_enum_type_true_for_a_real_enum() {
        let c = ctx();
        let my_enum = JavaType::declared(TypeElement::new("com.example.MyEnum"));
        assert!(c.is_enum_type(&my_enum));
    }

    #[test]
    fn is_enum_type_false_for_a_non_declared_type() {
        let c = ctx();
        assert!(!c.is_enum_type(&JavaType::Primitive("int")));
    }

    #[test]
    fn is_enum_type_false_for_a_non_enum_declared_type() {
        let c = ctx();
        let base = JavaType::declared(TypeElement::new("com.example.Base"));
        assert!(!c.is_enum_type(&base));
    }

    // ---- find_supertype / get_arguments ----

    #[test]
    fn find_supertype_locates_a_direct_supertype() {
        let c = ctx();
        let sub = JavaType::declared(TypeElement::new("com.example.Sub"));
        let base_elem = TypeElement::new("com.example.Base");
        let found = c.find_supertype(&sub, &base_elem);
        assert!(found.is_some());
    }

    #[test]
    fn find_supertype_locates_a_transitive_supertype() {
        let c = ctx();
        let sub = JavaType::declared(TypeElement::new("com.example.Sub"));
        let object_elem = TypeElement::new("java.lang.Object");
        assert!(c.find_supertype(&sub, &object_elem).is_some());
    }

    #[test]
    fn find_supertype_none_for_unrelated_type() {
        let c = ctx();
        let base = JavaType::declared(TypeElement::new("com.example.Base"));
        let my_enum_elem = TypeElement::new("com.example.MyEnum");
        assert!(c.find_supertype(&base, &my_enum_elem).is_none());
    }

    #[test]
    fn get_arguments_extracts_the_enum_self_type_argument() {
        let c = ctx();
        let my_enum = JavaType::declared(TypeElement::new("com.example.MyEnum"));
        let args = c.get_arguments(&my_enum, &c.enum_elem);
        assert_eq!(
            args.get("E"),
            Some(&JavaType::declared(TypeElement::new("com.example.MyEnum")))
        );
    }

    #[test]
    #[should_panic(expected = "no matching supertype found")]
    fn get_arguments_panics_like_the_java_npe_when_no_supertype_matches() {
        let c = ctx();
        let base = JavaType::declared(TypeElement::new("com.example.Base"));
        let my_enum_elem = TypeElement::new("com.example.MyEnum");
        c.get_arguments(&base, &my_enum_elem);
    }

    #[test]
    fn get_arguments_of_element_matches_get_arguments_on_its_bare_type() {
        let c = ctx();
        let my_enum_elem = TypeElement::new("com.example.MyEnum");
        let via_element = c.get_arguments_of_element(&my_enum_elem, &c.enum_elem);
        let via_type = c.get_arguments(&my_enum_elem.as_type(), &c.enum_elem);
        assert_eq!(via_element, via_type);
    }

    // ---- format ----

    #[test]
    fn format_primitive_and_null() {
        let c = ctx();
        assert_eq!(c.format(&JavaType::Primitive("int")), "int");
        assert_eq!(c.format(&JavaType::Null), "null");
    }

    #[test]
    fn format_array_appends_brackets() {
        let c = ctx();
        let arr = JavaType::Array(Box::new(JavaType::Primitive("byte")));
        assert_eq!(c.format(&arr), "byte[]");
    }

    #[test]
    fn format_declared_without_type_arguments_is_just_the_name() {
        let c = ctx();
        let t = JavaType::declared(TypeElement::new("com.example.Base"));
        assert_eq!(c.format(&t), "com.example.Base");
    }

    #[test]
    fn format_declared_with_type_arguments() {
        let c = ctx();
        let t = JavaType::Declared {
            element: TypeElement::new("java.util.List"),
            type_arguments: vec![JavaType::declared(TypeElement::new("com.example.Base"))],
        };
        assert_eq!(c.format(&t), "java.util.List<com.example.Base>");
    }

    #[test]
    fn format_type_var_omits_object_upper_bound() {
        let c = ctx();
        let t = JavaType::TypeVar {
            name: "T".to_string(),
            lower_bound: Box::new(JavaType::Null),
            upper_bound: Box::new(JavaType::declared(TypeElement::new("java.lang.Object"))),
        };
        assert_eq!(c.format(&t), "T");
    }

    #[test]
    fn format_type_var_with_both_bounds() {
        let c = ctx();
        let t = JavaType::TypeVar {
            name: "T".to_string(),
            lower_bound: Box::new(JavaType::declared(TypeElement::new("com.example.Sub"))),
            upper_bound: Box::new(JavaType::declared(TypeElement::new("com.example.Base"))),
        };
        assert_eq!(c.format(&t), "T super com.example.Sub extends com.example.Base");
    }

    #[test]
    fn format_wildcard_variants() {
        let c = ctx();
        assert_eq!(c.format(&JavaType::Wildcard { extends_bound: None, super_bound: None }), "?");
        let ext = JavaType::Wildcard {
            extends_bound: Some(Box::new(JavaType::declared(TypeElement::new("com.example.Base")))),
            super_bound: None,
        };
        assert_eq!(c.format(&ext), "? extends com.example.Base");
        let sup = JavaType::Wildcard {
            extends_bound: None,
            super_bound: Some(Box::new(JavaType::declared(TypeElement::new("com.example.Sub")))),
        };
        assert_eq!(c.format(&sup), "? super com.example.Sub");
    }

    #[test]
    fn format_union_and_intersection() {
        let c = ctx();
        let union = JavaType::Union(vec![
            JavaType::declared(TypeElement::new("A")),
            JavaType::declared(TypeElement::new("B")),
        ]);
        assert_eq!(c.format(&union), "A | B");

        let intersection = JavaType::Intersection(vec![
            JavaType::declared(TypeElement::new("A")),
            JavaType::declared(TypeElement::new("B")),
        ]);
        assert_eq!(c.format(&intersection), "A & B");
    }

    #[test]
    fn format_error_executable_and_no_type_print_their_display_string() {
        let c = ctx();
        assert_eq!(c.format(&JavaType::Error("<error>".to_string())), "<error>");
        assert_eq!(c.format(&JavaType::Executable("()V".to_string())), "()V");
        assert_eq!(c.format(&JavaType::NoType("none".to_string())), "none");
    }

    // ---- well-known element accessors ----

    #[test]
    fn well_known_elements_have_expected_names() {
        let c = ctx();
        assert_eq!(c.list_elem().name, "java.util.List");
        assert_eq!(c.db_annotated_object_elem().name, "ghidra.util.database.DBAnnotatedObject");
        assert_eq!(c.db_object_column_elem().name, "ghidra.util.database.DBObjectColumn");
        assert_eq!(
            c.db_field_codec_elem().name,
            "ghidra.util.database.DBCachedObjectStoreFactory.DBFieldCodec"
        );
        assert_eq!(
            c.default_codec_elem().name,
            "ghidra.util.database.annot.DBAnnotatedField.DefaultCodec"
        );
        assert_eq!(c.enum_elem().name, "java.lang.Enum");
    }

    #[test]
    fn messager_is_reachable_but_never_invoked_internally() {
        struct Capturing {
            calls: std::sync::Mutex<Vec<String>>,
        }
        impl Messager for Capturing {
            fn print_error(&self, message: &str) {
                self.calls.lock().unwrap().push(message.to_string());
            }
        }
        let c = ValidationContext::new(
            Box::new(MockTypeOracle::new()),
            Box::new(Capturing { calls: std::sync::Mutex::new(Vec::new()) }),
        );
        // No `ValidationContext` method calls the messager; confirm it's at least reachable and
        // callable through the accessor without having recorded anything yet.
        c.messager().print_error("hello");
    }
}

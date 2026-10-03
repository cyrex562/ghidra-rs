//! Port of `ghidra.util.database.annotproc.DBAnnotatedFieldValidator`.
//!
//! # `javaToDBTypeMap`/`ENUM_CODEC_ELEM` construction without a live compiler
//!
//! Java's constructor builds `javaToDBTypeMap` (mapping each of the DB-persistable Java types to
//! their default codec) and resolves `ENUM_CODEC_ELEM` entirely through `ctx.typeUtils`/
//! `ctx.elementUtils` -- live `javac` utilities this crate has no equivalent of (see
//! `ValidationContext`'s own module docs). Since every one of those lookups is for a *fixed,
//! well-known* type (`boolean`/`Boolean`, `byte`/`Byte`, ..., `String`, `byte[]`, `long[]`, and
//! the handful of `DBCachedObjectStoreFactory`-nested codec classes), this port builds them the
//! same way [`ValidationContext::new`] already builds its own well-known [`TypeElement`]s:
//! directly, as fixed [`JavaType`]/[`TypeElement`] values, rather than through the [`TypeOracle`]
//! seam.
//!
//! # `getCodecTypeElement()`'s annotation-mirror machinery becomes a caller-supplied fact
//!
//! Java's `getCodecTypeElement()` reads the `codec` member off a live `@DBAnnotatedField`
//! annotation instance (via `field.getAnnotation(...)`, with the `MirroredTypeException` dance
//! `Class`-valued annotation members require during annotation processing). There is no live
//! annotation instance here; per this package's established convention (`ValidationContext`'s
//! `TypeOracle`, `AbstractDBAnnotationValidator`'s `ElementKind`, `DBAnnotatedColumnValidator`'s
//! `VariableElement.enclosing_type`/`enclosing_kind`), the *result* of that resolution -- the
//! [`TypeElement`] the annotation's `codec` member actually names -- is supplied directly as
//! [`DBAnnotatedFieldValidator::new`]'s `specified_codec` parameter.

use std::collections::HashMap;

use crate::util::database::annotproc::{
    AbstractDBAnnotationValidator, JavaType, Modifier, TypeElement, ValidationContext, VariableElement,
};

const FACTORY_NAME: &str = "ghidra.util.database.DBCachedObjectStoreFactory";

fn codec_name(simple: &str) -> String {
    format!("{FACTORY_NAME}.{simple}")
}

/// The simple name of the annotation this validator checks, mirroring
/// `DBAnnotatedField.class.getSimpleName()`. See [`super::db_annotated_column_validator`]'s
/// analogous constant for why this is a literal rather than derived from a ported annotation type.
const ANNOTATION_SIMPLE_NAME: &str = "DBAnnotatedField";

/// A validator for fields annotated with `DBAnnotatedField`.
///
/// Port of `ghidra.util.database.annotproc.DBAnnotatedFieldValidator`. Ensures fields annotated
/// with `DBAnnotatedField` meet the criteria required for database fields in Ghidra.
///
/// Java's `class DBAnnotatedFieldValidator extends AbstractDBAnnotationValidator` becomes, per
/// this crate's composition-over-inheritance convention, a struct holding a `base:
/// AbstractDBAnnotationValidator` field.
pub struct DBAnnotatedFieldValidator {
    base: AbstractDBAnnotationValidator,
    field: VariableElement,
    java_to_db_type_map: HashMap<JavaType, TypeElement>,
    enum_codec_elem: TypeElement,
    /// The codec [`TypeElement`] the field's `@DBAnnotatedField(codec = ...)` member actually
    /// names. See the module docs.
    specified_codec: TypeElement,
}

impl DBAnnotatedFieldValidator {
    /// Construct a new validator with the specified validation context, field element, and the
    /// codec type element the field's annotation specifies (or [`ValidationContext::default_codec_elem`]
    /// to mean "use the default codec for the field's type", matching
    /// `@DBAnnotatedField`'s own default `codec` value).
    ///
    /// Port of `DBAnnotatedFieldValidator(ValidationContext, VariableElement)`; see the module
    /// docs for why `specified_codec` is an added parameter here rather than resolved internally.
    pub fn new(ctx: ValidationContext, field: VariableElement, specified_codec: TypeElement) -> Self {
        let mut type_map: HashMap<JavaType, TypeElement> = HashMap::new();
        Self::put_primitive_type_codec(&mut type_map, "boolean", "java.lang.Boolean", &codec_name("BooleanDBFieldCodec"));
        Self::put_primitive_type_codec(&mut type_map, "byte", "java.lang.Byte", &codec_name("ByteDBFieldCodec"));
        Self::put_primitive_type_codec(&mut type_map, "short", "java.lang.Short", &codec_name("ShortDBFieldCodec"));
        Self::put_primitive_type_codec(&mut type_map, "int", "java.lang.Integer", &codec_name("IntDBFieldCodec"));
        Self::put_primitive_type_codec(&mut type_map, "long", "java.lang.Long", &codec_name("LongDBFieldCodec"));
        Self::put_type_codec(&mut type_map, "java.lang.String", &codec_name("StringDBFieldCodec"));
        Self::put_primitive_array_type_codec(&mut type_map, "byte", &codec_name("ByteArrayDBFieldCodec"));
        Self::put_primitive_array_type_codec(&mut type_map, "long", &codec_name("LongArrayDBFieldCodec"));
        // NOTE: Enum requires subtype check (see get_default_codec_type).

        let enum_codec_elem = TypeElement::new(codec_name("EnumDBByteFieldCodec"));

        DBAnnotatedFieldValidator {
            base: AbstractDBAnnotationValidator::new(ctx),
            field,
            java_to_db_type_map: type_map,
            enum_codec_elem,
            specified_codec,
        }
    }

    /// Associate a primitive type and its boxed type with the specified codec type in the map.
    ///
    /// Port of `putPrimitiveTypeCodec(Map, TypeKind, String)`.
    fn put_primitive_type_codec(
        map: &mut HashMap<JavaType, TypeElement>,
        primitive_name: &'static str,
        boxed_class_name: &str,
        codec_class_name: &str,
    ) {
        let primitive = JavaType::Primitive(primitive_name);
        let boxed = JavaType::declared(TypeElement::new(boxed_class_name));
        let codec = TypeElement::new(codec_class_name);
        map.insert(primitive, codec.clone());
        map.insert(boxed, codec);
    }

    /// Associate a specified class type with the specified codec type in the map.
    ///
    /// Port of `putTypeCodec(Map, Class, String)`.
    fn put_type_codec(map: &mut HashMap<JavaType, TypeElement>, class_name: &str, codec_class_name: &str) {
        map.insert(JavaType::declared(TypeElement::new(class_name)), TypeElement::new(codec_class_name));
    }

    /// Associate a primitive array type with the specified codec type in the map.
    ///
    /// Port of `putPrimitiveArrayTypeCodec(Map, TypeKind, String)`.
    fn put_primitive_array_type_codec(
        map: &mut HashMap<JavaType, TypeElement>,
        primitive_name: &'static str,
        codec_class_name: &str,
    ) {
        let array = JavaType::Array(Box::new(JavaType::Primitive(primitive_name)));
        map.insert(array, TypeElement::new(codec_class_name));
    }

    /// The field element this validator was constructed with.
    ///
    /// Java has no counterpart accessor (the `field` field is directly reachable within the
    /// class); exposed here so sibling validators outside this module -- e.g.
    /// [`DBAnnotatedObjectValidator`](super::DBAnnotatedObjectValidator)'s `checkAccess` -- can
    /// reach it despite Rust's per-module (not per-class) privacy.
    pub fn field(&self) -> &VariableElement {
        &self.field
    }

    /// Validate the annotated field to ensure it meets the requirements for database fields.
    ///
    /// Performs the following checks:
    /// * The field must not be declared as `final`.
    /// * The field must not be declared as `static`.
    /// * The enclosing type of the field must meet the criteria defined in
    ///   [`AbstractDBAnnotationValidator::check_enclosing_type`].
    /// * The codec types for the field must be appropriate.
    ///
    /// Port of `validate()`.
    pub fn validate(&self) {
        let ctx = &self.base.ctx;

        if self.field.modifiers.contains(&Modifier::Final) {
            ctx.messager().print_error(&format!(
                "@{} cannot be applied to a final field",
                ANNOTATION_SIMPLE_NAME
            ));
        }
        if self.field.modifiers.contains(&Modifier::Static) {
            ctx.messager().print_error(&format!(
                "@{} cannot be applied to a static field",
                ANNOTATION_SIMPLE_NAME
            ));
        }

        self.base.check_enclosing_type(
            ANNOTATION_SIMPLE_NAME,
            self.field.enclosing_kind,
            &self.field.enclosing_type,
        );
        self.check_codec_types(&self.field.enclosing_type);
    }

    /// Return the default codec type element for the specified Java type.
    ///
    /// Port of `getDefaultCodecType(TypeMirror)`.
    fn get_default_codec_type(&self, java_type: &JavaType) -> Option<TypeElement> {
        if self.base.ctx.is_enum_type(java_type) {
            return Some(self.enum_codec_elem.clone());
        }
        self.java_to_db_type_map.get(java_type).cloned()
    }

    /// Return the codec type element specified in the `@DBAnnotatedField` annotation for the
    /// field, or the default codec type if none is specified.
    ///
    /// Port of `getCodecTypeElement()`. See the module docs for why `specified_codec` is
    /// caller-supplied rather than resolved via annotation-mirror machinery here.
    fn get_codec_type_element(&self) -> Option<TypeElement> {
        if self.specified_codec == *self.base.ctx.default_codec_elem() {
            return self.get_default_codec_type(&self.field.declared_type);
        }
        Some(self.specified_codec.clone())
    }

    /// Check the codec types associated with the field to ensure they meet the necessary
    /// requirements.
    ///
    /// Port of `checkCodecTypes(TypeElement)`.
    fn check_codec_types(&self, object_type: &TypeElement) {
        let ctx = &self.base.ctx;

        let Some(codec_type) = self.get_codec_type_element() else {
            ctx.messager().print_error(&format!(
                "Could not select default codec for {}. @{}.codec must be specified.",
                ctx.format(&self.field.declared_type),
                ANNOTATION_SIMPLE_NAME
            ));
            return;
        };

        // REQUIREMENTS:
        //   1) ValueType matches the field's type exactly
        //      Cannot be super or extends because it's read/write
        //   2) ObjectType is super of the containing object
        //      Need to ensure extra interfaces (intersection) are considered
        //   3) FieldType is non-abstract
        //   4) The codec has an appropriate constructor

        let args = ctx.get_arguments_of_element(&codec_type, ctx.db_field_codec_elem());

        // 1)
        if let Some(arg_vt) = args.get("VT") {
            if !ctx.has_type(&self.field, arg_vt) {
                ctx.messager().print_error(&format!(
                    "Codec {} can only be used with fields of type {}",
                    codec_type.name,
                    ctx.format(arg_vt)
                ));
            }
        }

        // 2) (INCOMPLETE)
        if let Some(arg_ot) = args.get("OT") {
            if !ctx.is_capturable(&object_type.as_type(), arg_ot) {
                ctx.messager().print_error(&format!(
                    "Codec {} requires the containing object to conform to {}",
                    codec_type.name,
                    ctx.format(arg_ot)
                ));
            }
        }

        // 3)
        if let Some(arg_ft) = args.get("FT") {
            match arg_ft {
                JavaType::Declared { element, .. } => {
                    if ctx.is_abstract(element) {
                        ctx.messager().print_error(&format!(
                            "Codec {} must have a non-abstract class for its field type, not {}",
                            codec_type.name,
                            ctx.format(arg_ft)
                        ));
                    }
                }
                other => {
                    ctx.messager().print_error(&format!(
                        "Codec {} must have a non-abstract class for its field type, not {}",
                        codec_type.name,
                        ctx.format(other)
                    ));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::database::annotproc::{ElementKind, Messager, TypeOracle};
    use std::cell::RefCell;
    use std::collections::HashSet;

    /// A `MockTypeOracle` over a small fixed hierarchy sufficient to exercise `checkCodecTypes`:
    /// - `com.example.MyTable` is a `DBAnnotatedObject` subclass (matches
    ///   `DBAnnotatedColumnValidator`'s own mock precedent).
    /// - `com.example.MyEnum` is an `Enum`.
    /// - `com.example.SomeCodec<VT, OT, FT>` extends `DBFieldCodec<VT, OT, FT>` with fixed type
    ///   arguments, so `get_arguments_of_element` can resolve VT/OT/FT.
    /// - `com.example.ConcreteField`/`com.example.AbstractField` distinguish the "3) FieldType
    ///   must be non-abstract" check.
    struct MockTypeOracle {
        abstract_elems: HashSet<String>,
    }

    impl MockTypeOracle {
        fn new() -> Self {
            let mut abstract_elems = HashSet::new();
            abstract_elems.insert("com.example.AbstractField".to_string());
            MockTypeOracle { abstract_elems }
        }
    }

    impl TypeOracle for MockTypeOracle {
        fn is_subtype(&self, sub: &JavaType, sup: &JavaType) -> bool {
            if sub == sup {
                return true;
            }
            let (JavaType::Declared { element: sub_elem, .. }, JavaType::Declared { element: sup_elem, .. }) =
                (sub, sup)
            else {
                return false;
            };
            match (sub_elem.name.as_str(), sup_elem.name.as_str()) {
                ("com.example.MyTable", "ghidra.util.database.DBAnnotatedObject") => true,
                ("com.example.MyEnum", "java.lang.Enum") => true,
                _ => false,
            }
        }
        fn is_assignable(&self, from: &JavaType, to: &JavaType) -> bool {
            self.is_subtype(from, to)
        }
        fn unboxed_type(&self, _boxed: &JavaType) -> Option<JavaType> {
            None
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
        fn direct_supertypes(&self, _t: &JavaType) -> Vec<JavaType> {
            Vec::new()
        }
        fn is_abstract(&self, elem: &TypeElement) -> bool {
            self.abstract_elems.contains(&elem.name)
        }
    }

    struct CapturingMessager {
        messages: RefCell<Vec<String>>,
    }
    impl CapturingMessager {
        fn new() -> Self {
            Self { messages: RefCell::new(Vec::new()) }
        }
    }
    impl Messager for CapturingMessager {
        fn print_error(&self, message: &str) {
            self.messages.borrow_mut().push(message.to_string());
        }
    }
    struct ForwardingMessager(std::rc::Rc<CapturingMessager>);
    impl Messager for ForwardingMessager {
        fn print_error(&self, message: &str) {
            self.0.print_error(message);
        }
    }

    fn ctx() -> (ValidationContext, std::rc::Rc<CapturingMessager>) {
        let inner = std::rc::Rc::new(CapturingMessager::new());
        let ctx = ValidationContext::new(Box::new(MockTypeOracle::new()), Box::new(ForwardingMessager(inner.clone())));
        (ctx, inner)
    }

    fn codec_type_element() -> TypeElement {
        TypeElement::with_type_parameters(
            "com.example.SomeCodec",
            vec!["VT".to_string(), "OT".to_string(), "FT".to_string()],
        )
    }

    /// Builds a `ValidationContext` whose [`TypeOracle::direct_supertypes`] makes
    /// `com.example.SomeCodec` (unparameterized) report a single direct supertype:
    /// `DBFieldCodec<vt, ot, ft>` for the given argument type names, so
    /// `get_arguments_of_element` can resolve VT/OT/FT for `check_codec_types`.
    struct CodecOracle {
        inner: MockTypeOracle,
        vt: JavaType,
        ot: JavaType,
        ft: JavaType,
    }

    impl TypeOracle for CodecOracle {
        fn is_subtype(&self, sub: &JavaType, sup: &JavaType) -> bool {
            self.inner.is_subtype(sub, sup)
        }
        fn is_assignable(&self, from: &JavaType, to: &JavaType) -> bool {
            self.inner.is_assignable(from, to)
        }
        fn unboxed_type(&self, boxed: &JavaType) -> Option<JavaType> {
            self.inner.unboxed_type(boxed)
        }
        fn erasure(&self, t: &JavaType) -> JavaType {
            self.inner.erasure(t)
        }
        fn is_same_type(&self, a: &JavaType, b: &JavaType) -> bool {
            self.inner.is_same_type(a, b)
        }
        fn declared_type_of(&self, element: &TypeElement, type_arguments: Vec<JavaType>) -> JavaType {
            self.inner.declared_type_of(element, type_arguments)
        }
        fn direct_supertypes(&self, t: &JavaType) -> Vec<JavaType> {
            if let JavaType::Declared { element, .. } = t {
                if element.name == "com.example.SomeCodec" {
                    return vec![JavaType::Declared {
                        element: TypeElement::with_type_parameters(
                            "ghidra.util.database.DBCachedObjectStoreFactory.DBFieldCodec",
                            vec!["VT".to_string(), "OT".to_string(), "FT".to_string()],
                        ),
                        type_arguments: vec![self.vt.clone(), self.ot.clone(), self.ft.clone()],
                    }];
                }
            }
            self.inner.direct_supertypes(t)
        }
        fn is_abstract(&self, elem: &TypeElement) -> bool {
            self.inner.is_abstract(elem)
        }
    }

    fn ctx_with_codec(vt: JavaType, ot: JavaType, ft: JavaType) -> (ValidationContext, std::rc::Rc<CapturingMessager>) {
        let inner = std::rc::Rc::new(CapturingMessager::new());
        let oracle = CodecOracle { inner: MockTypeOracle::new(), vt, ot, ft };
        let ctx = ValidationContext::new(Box::new(oracle), Box::new(ForwardingMessager(inner.clone())));
        (ctx, inner)
    }

    fn table_type() -> TypeElement {
        TypeElement::new("com.example.MyTable")
    }

    fn concrete_field_type() -> JavaType {
        JavaType::declared(TypeElement::new("com.example.ConcreteField"))
    }

    fn abstract_field_type() -> JavaType {
        JavaType::declared(TypeElement::new("com.example.AbstractField"))
    }

    #[test]
    fn valid_field_with_matching_codec_reports_nothing() {
        let field_type = concrete_field_type();
        let (ctx, messager) = ctx_with_codec(
            field_type.clone(),
            JavaType::declared(table_type()),
            concrete_field_type(),
        );
        let field = VariableElement::new(field_type, table_type(), ElementKind::Class);
        let validator = DBAnnotatedFieldValidator::new(ctx, field, codec_type_element());

        validator.validate();
        assert!(messager.messages.borrow().is_empty(), "{:?}", messager.messages.borrow());
    }

    #[test]
    fn final_field_reports_final_error() {
        let field_type = concrete_field_type();
        let (ctx, messager) = ctx_with_codec(field_type.clone(), JavaType::declared(table_type()), concrete_field_type());
        let field = VariableElement::new(field_type, table_type(), ElementKind::Class)
            .with_modifiers([Modifier::Final]);
        let validator = DBAnnotatedFieldValidator::new(ctx, field, codec_type_element());

        validator.validate();
        assert!(messager.messages.borrow().iter().any(|m| m.contains("cannot be applied to a final field")));
    }

    #[test]
    fn static_field_reports_static_error() {
        let field_type = concrete_field_type();
        let (ctx, messager) = ctx_with_codec(field_type.clone(), JavaType::declared(table_type()), concrete_field_type());
        let field = VariableElement::new(field_type, table_type(), ElementKind::Class)
            .with_modifiers([Modifier::Static]);
        let validator = DBAnnotatedFieldValidator::new(ctx, field, codec_type_element());

        validator.validate();
        assert!(messager.messages.borrow().iter().any(|m| m.contains("cannot be applied to a static field")));
    }

    #[test]
    fn mismatched_value_type_reports_codec_value_type_error() {
        // Codec's VT is `int`, but the field's own type is a declared class -- mismatch.
        let field_type = concrete_field_type();
        let (ctx, messager) =
            ctx_with_codec(JavaType::Primitive("int"), JavaType::declared(table_type()), concrete_field_type());
        let field = VariableElement::new(field_type, table_type(), ElementKind::Class);
        let validator = DBAnnotatedFieldValidator::new(ctx, field, codec_type_element());

        validator.validate();
        assert!(messager
            .messages
            .borrow()
            .iter()
            .any(|m| m.contains("can only be used with fields of type")));
    }

    #[test]
    fn abstract_field_type_reports_non_abstract_requirement_error() {
        let field_type = concrete_field_type();
        let (ctx, messager) =
            ctx_with_codec(field_type.clone(), JavaType::declared(table_type()), abstract_field_type());
        let field = VariableElement::new(field_type, table_type(), ElementKind::Class);
        let validator = DBAnnotatedFieldValidator::new(ctx, field, codec_type_element());

        validator.validate();
        assert!(messager
            .messages
            .borrow()
            .iter()
            .any(|m| m.contains("must have a non-abstract class for its field type")));
    }

    #[test]
    fn non_declared_field_type_reports_non_abstract_requirement_error() {
        // FT resolves to a primitive, not a DECLARED type at all -- Java's `argFT.getKind() !=
        // TypeKind.DECLARED` branch.
        let field_type = concrete_field_type();
        let (ctx, messager) =
            ctx_with_codec(field_type.clone(), JavaType::declared(table_type()), JavaType::Primitive("int"));
        let field = VariableElement::new(field_type, table_type(), ElementKind::Class);
        let validator = DBAnnotatedFieldValidator::new(ctx, field, codec_type_element());

        validator.validate();
        assert!(messager
            .messages
            .borrow()
            .iter()
            .any(|m| m.contains("must have a non-abstract class for its field type")));
    }

    #[test]
    fn default_codec_for_a_primitive_int_field_is_found_and_valid() {
        let (ctx, messager) = ctx();
        let field = VariableElement::new(JavaType::Primitive("int"), table_type(), ElementKind::Class);
        let default_codec = ctx.default_codec_elem().clone();
        let validator = DBAnnotatedFieldValidator::new(ctx, field, default_codec);

        // No codec-argument resolution happens (the default int codec has no direct supertypes
        // wired up in this plain MockTypeOracle), so `get_arguments` panics inside
        // `check_codec_types` unless a codec was actually resolved and its args are queried --
        // the point of this test is just that `get_default_codec_type` finds the int codec
        // rather than falling into "no codec found".
        let default_codec_type = validator.get_default_codec_type(&JavaType::Primitive("int"));
        assert!(default_codec_type.is_some());
        assert_eq!(default_codec_type.unwrap().name, "ghidra.util.database.DBCachedObjectStoreFactory.IntDBFieldCodec");
        let _ = messager;
    }

    #[test]
    fn default_codec_for_an_enum_type_is_the_enum_codec() {
        let (ctx, _messager) = ctx();
        let field = VariableElement::new(
            JavaType::declared(TypeElement::new("com.example.MyEnum")),
            table_type(),
            ElementKind::Class,
        );
        let default_codec = ctx.default_codec_elem().clone();
        let validator = DBAnnotatedFieldValidator::new(ctx, field, default_codec);

        let resolved = validator.get_default_codec_type(&JavaType::declared(TypeElement::new("com.example.MyEnum")));
        assert_eq!(
            resolved.unwrap().name,
            "ghidra.util.database.DBCachedObjectStoreFactory.EnumDBByteFieldCodec"
        );
    }

    #[test]
    fn no_default_codec_found_reports_must_be_specified_error() {
        let (ctx, messager) = ctx();
        // A type with no entry in the well-known map and not an enum: no default codec.
        let field = VariableElement::new(
            JavaType::declared(TypeElement::new("com.example.NoCodecForThis")),
            table_type(),
            ElementKind::Class,
        );
        let default_codec = ctx.default_codec_elem().clone();
        let validator = DBAnnotatedFieldValidator::new(ctx, field, default_codec);

        validator.validate();
        assert!(messager
            .messages
            .borrow()
            .iter()
            .any(|m| m.contains("Could not select default codec")));
    }

    #[test]
    fn non_class_enclosing_type_reports_enclosing_type_error() {
        let field_type = concrete_field_type();
        let (ctx, messager) = ctx_with_codec(field_type.clone(), JavaType::declared(table_type()), concrete_field_type());
        let field = VariableElement::new(field_type, table_type(), ElementKind::Other);
        let validator = DBAnnotatedFieldValidator::new(ctx, field, codec_type_element());

        validator.validate();
        assert!(messager.messages.borrow().iter().any(|m| m.contains("can only be applied to fields in a class")));
    }
}

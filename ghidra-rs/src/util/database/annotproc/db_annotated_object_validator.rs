//! Port of `ghidra.util.database.annotproc.DBAnnotatedObjectValidator`.
//!
//! Validates `DBAnnotatedObject`-related annotations on a given type element: ensures that
//! `@DBAnnotatedField`, `@DBAnnotatedColumn`, and `@DBAnnotatedObjectInfo` are applied correctly
//! and consistently on the fields and columns of a class.
//!
//! # Port strategy: constructor-injected facts, and `ctx` moved to call sites
//!
//! Per this module's established convention (see [`ValidationContext`]'s own docs, and
//! [`super::db_annotated_field_validator`]'s `specified_codec` parameter), facts a live `javac`
//! compiler would supply via reflection are instead supplied directly by the caller:
//! * `type.getKind()` and `type.getModifiers()` become the `type_kind`/`type_modifiers`
//!   constructor parameters (mirroring [`super::abstract_db_annotation_validator::ElementKind`]'s
//!   own precedent for "no `ElementKind`-equivalent field on [`TypeElement`]").
//! * `type.getAnnotation(DBAnnotatedObjectInfo.class)` -- whether the annotation is present, and
//!   if so its `version()` member -- becomes the `annotation_version: Option<i32>` constructor
//!   parameter (`None` for "annotation absent", matching `getAnnotation` returning `null`).
//! * Each `DBAnnotatedField`/`DBAnnotatedColumn` annotation's own members
//!   (`column()`/`value()`, and, for fields, the resolved `codec` type) become explicit
//!   parameters to [`DBAnnotatedObjectValidator::add_annotated_field`]/
//!   [`DBAnnotatedObjectValidator::add_annotated_column`], for the same reason.
//!
//! Separately, [`ValidationContext`] is not `Clone` (it owns `Box<dyn TypeOracle>`/`Box<dyn
//! Messager>` trait objects), while Java shares one `ValidationContext` instance by reference
//! across every validator in a compilation unit. Since
//! [`DBAnnotatedFieldValidator::new`]/[`DBAnnotatedColumnValidator::new`] already established the
//! convention that each validator *owns* its `ValidationContext` (taken by value), this validator
//! does not hold one long-lived `ctx` field either: [`DBAnnotatedObjectValidator::add_annotated_field`]/
//! [`DBAnnotatedObjectValidator::add_annotated_column`] each take their own owned `ValidationContext`
//! to construct their sub-validator with (as Java's constructor calls do, just requiring an
//! explicit instance here rather than reusing a shared field), and
//! [`DBAnnotatedObjectValidator::validate`] takes a `&ValidationContext` for its own top-level
//! checks. A real (unported) driver wiring this family up at runtime would supply equivalent
//! `TypeOracle`/`Messager` implementations to each call.

use std::collections::HashSet;

use crate::util::database::annotproc::{
    AccessSpec, DBAnnotatedColumnValidator, DBAnnotatedFieldValidator, ElementKind, Modifier,
    TypeElement, ValidationContext, VariableElement,
};

/// The simple name of the `@DBAnnotatedObjectInfo` annotation this validator checks, mirroring
/// `DBAnnotatedObjectInfo.class.getSimpleName()`. See [`super::db_annotated_column_validator`]'s
/// analogous constant for why this is a literal rather than derived from a ported annotation type.
const ANNOTATION_SIMPLE_NAME: &str = "DBAnnotatedObjectInfo";

/// Validate `DBAnnotatedObject`-related annotations on a given type element.
///
/// Port of `ghidra.util.database.annotproc.DBAnnotatedObjectValidator`. See the module docs for
/// this port's deviations from the Java constructor/field shape.
pub struct DBAnnotatedObjectValidator {
    type_elem: TypeElement,
    type_kind: ElementKind,
    type_modifiers: HashSet<Modifier>,
    annotation_version: Option<i32>,
    /// Port of `Map<String, DBAnnotatedFieldValidator> fieldsByName`. Java uses a
    /// `LinkedHashMap` for stable insertion-order iteration in `checkMissing`; a `Vec` of pairs
    /// preserves the same order (including "re-adding an existing name updates the value in
    /// place, without moving its position") without requiring an ordered-map crate dependency.
    fields_by_name: Vec<(String, DBAnnotatedFieldValidator)>,
    /// Port of `Map<String, DBAnnotatedColumnValidator> columnsByName`. See
    /// [`Self::fields_by_name`]'s docs.
    columns_by_name: Vec<(String, DBAnnotatedColumnValidator)>,
}

impl DBAnnotatedObjectValidator {
    /// Construct a new validator for the given type element.
    ///
    /// Port of `DBAnnotatedObjectValidator(ValidationContext ctx, TypeElement type)`. See the
    /// module docs for why `type_kind`/`type_modifiers`/`annotation_version` are additional
    /// parameters here, and why there is no `ctx` parameter (see
    /// [`DBAnnotatedObjectValidator::validate`]/[`DBAnnotatedObjectValidator::add_annotated_field`]/
    /// [`DBAnnotatedObjectValidator::add_annotated_column`] instead).
    pub fn new(
        type_elem: TypeElement,
        type_kind: ElementKind,
        type_modifiers: HashSet<Modifier>,
        annotation_version: Option<i32>,
    ) -> Self {
        DBAnnotatedObjectValidator {
            type_elem,
            type_kind,
            type_modifiers,
            annotation_version,
            fields_by_name: Vec::new(),
            columns_by_name: Vec::new(),
        }
    }

    /// Add a field annotated with `@DBAnnotatedField` to be validated.
    ///
    /// Port of `void addAnnotatedField(VariableElement field)`. Java reads the annotation's
    /// `column()` member (the key) via live reflection, and `DBAnnotatedFieldValidator` itself
    /// separately resolves the annotation's `codec` member; both become explicit parameters here
    /// -- see the module docs. Java's `assert annotation != null` has no counterpart: there is no
    /// possibility of a missing annotation to assert against once its facts are supplied directly.
    pub fn add_annotated_field(
        &mut self,
        ctx: ValidationContext,
        field: VariableElement,
        column_name: impl Into<String>,
        specified_codec: TypeElement,
    ) {
        let validator = DBAnnotatedFieldValidator::new(ctx, field, specified_codec);
        Self::put(&mut self.fields_by_name, column_name.into(), validator);
    }

    /// Add a column annotated with `@DBAnnotatedColumn` to the validator.
    ///
    /// Port of `void addAnnotatedColumn(VariableElement column)`. See
    /// [`DBAnnotatedObjectValidator::add_annotated_field`]'s docs for why `column_name` (Java:
    /// the annotation's `value()` member) is an explicit parameter here.
    pub fn add_annotated_column(
        &mut self,
        ctx: ValidationContext,
        column: VariableElement,
        column_name: impl Into<String>,
    ) {
        let validator = DBAnnotatedColumnValidator::new(ctx, column);
        Self::put(&mut self.columns_by_name, column_name.into(), validator);
    }

    /// `LinkedHashMap.put`-equivalent insertion: replaces the value in place if `key` is already
    /// present (preserving its original position), otherwise appends.
    fn put<V>(map: &mut Vec<(String, V)>, key: String, value: V) {
        if let Some(entry) = map.iter_mut().find(|(k, _)| *k == key) {
            entry.1 = value;
        } else {
            map.push((key, value));
        }
    }

    fn get_field(&self, name: &str) -> Option<&DBAnnotatedFieldValidator> {
        self.fields_by_name.iter().find(|(k, _)| k == name).map(|(_, v)| v)
    }

    fn get_column(&self, name: &str) -> Option<&DBAnnotatedColumnValidator> {
        self.columns_by_name.iter().find(|(k, _)| k == name).map(|(_, v)| v)
    }

    /// Validate the annotated fields, columns, and the type element itself.
    ///
    /// Port of `void validate()`. `ctx` is used for this validator's own top-level checks; each
    /// field/column sub-validator already carries its own `ValidationContext`, supplied when it
    /// was added (see the module docs).
    pub fn validate(&self, ctx: &ValidationContext) {
        let has_annotation = self.annotation_version.is_some();

        // Java: `if (annotation != null && type.getKind() != ElementKind.CLASS) {...} else if
        // (annotation != null && type.getModifiers().contains(Modifier.ABSTRACT)) {...}` -- an
        // if/else-if pair, so at most one of these two fires.
        if has_annotation && self.type_kind != ElementKind::Class {
            ctx.messager().print_error(&format!(
                "@{ANNOTATION_SIMPLE_NAME} cannot be applied to an interface"
            ));
        } else if has_annotation && self.type_modifiers.contains(&Modifier::Abstract) {
            ctx.messager().print_error(&format!(
                "@{ANNOTATION_SIMPLE_NAME} cannot be applied to an abstract class"
            ));
        }

        if has_annotation && !ctx.is_subclass(&self.type_elem, ctx.db_annotated_object_elem()) {
            // Java quirk, faithfully preserved: the format arguments are `("DBAnnotatedObject",
            // DBAnnotatedObjectInfo.class.getSimpleName())`, i.e. the literal "DBAnnotatedObject"
            // fills the `@%s` slot and the annotation's own simple name fills the "subclasses of
            // %s" slot -- the reverse of what the message seems to intend (compare the very next
            // check's message below, which reads correctly).
            ctx.messager().print_error(&format!(
                "@DBAnnotatedObject can only be applied to subclasses of {ANNOTATION_SIMPLE_NAME}"
            ));
        }

        if !has_annotation && !self.type_modifiers.contains(&Modifier::Abstract) {
            ctx.messager().print_error(&format!(
                "Non-abstract subclasses of DBAnnotatedObject must have @{ANNOTATION_SIMPLE_NAME} annotation"
            ));
        }

        if let Some(version) = self.annotation_version {
            if version < 0 {
                ctx.messager().print_error(&format!(
                    "@{ANNOTATION_SIMPLE_NAME}.version cannot be negative"
                ));
            }
        }

        self.validate_fields();
        self.validate_columns();

        self.check_missing(ctx);
    }

    /// Validate all fields annotated with `@DBAnnotatedField`.
    ///
    /// Port of `protected void validateFields()`.
    fn validate_fields(&self) {
        for (_, fv) in &self.fields_by_name {
            fv.validate();
        }
    }

    /// Validate all columns annotated with `@DBAnnotatedColumn`.
    ///
    /// Port of `protected void validateColumns()`.
    fn validate_columns(&self) {
        for (_, cv) in &self.columns_by_name {
            cv.validate();
        }
    }

    /// Check for missing corresponding annotations between fields and columns.
    ///
    /// Port of `protected void checkMissing()`.
    fn check_missing(&self, ctx: &ValidationContext) {
        // Port of `Set<String> names = new LinkedHashSet<>(); names.addAll(fieldsByName.keySet());
        // names.addAll(columnsByName.keySet());` -- fields' names first, then any additional names
        // seen only in columns, each exactly once, in first-seen order.
        let mut names: Vec<&str> = Vec::new();
        for (name, _) in &self.fields_by_name {
            if !names.contains(&name.as_str()) {
                names.push(name);
            }
        }
        for (name, _) in &self.columns_by_name {
            if !names.contains(&name.as_str()) {
                names.push(name);
            }
        }

        for name in names {
            let fv = self.get_field(name);
            let cv = self.get_column(name);

            if fv.is_none() && cv.is_some() && !self.type_modifiers.contains(&Modifier::Abstract) {
                ctx.messager().print_error(&format!(
                    "@DBAnnotatedColumn is missing corresponding @DBAnnotatedField of the same \
                     column name: {name}"
                ));
            }
            if fv.is_some() && cv.is_none() && !self.type_modifiers.contains(&Modifier::Abstract) {
                ctx.messager().print_error(&format!(
                    "@DBAnnotatedField is missing corresponding @DBAnnotatedColumn of the same \
                     column name: {name}"
                ));
            }
            if let (Some(fv), Some(cv)) = (fv, cv) {
                self.check_access(ctx, fv.field(), cv.column(), name);
            }
        }
    }

    /// Check that the access specifiers of the field and column are compatible.
    ///
    /// Port of `protected void checkAccess(VariableElement field, VariableElement column, String
    /// name)`.
    fn check_access(&self, ctx: &ValidationContext, field: &VariableElement, column: &VariableElement, name: &str) {
        let field_spec = AccessSpec::get(&field.modifiers);
        let column_spec = AccessSpec::get(&column.modifiers);
        if !AccessSpec::is_same_or_more_permissive(field_spec, column_spec) {
            ctx.messager().print_error(&format!(
                "field with @DBAnnotatedColumn should have same or greater access than field \
                 with corresponding @DBAnnotatedField for column name: {name}"
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::database::annotproc::{JavaType, Messager, TypeOracle};
    use std::cell::RefCell;

    /// A `TypeOracle` over a small fixed hierarchy: `com.example.MyTable` is a
    /// `DBAnnotatedObject` subclass, matching the precedent set by this module's other test files.
    struct MockTypeOracle;

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
            sub_elem.name == "com.example.MyTable"
                && sup_elem.name == "ghidra.util.database.DBAnnotatedObject"
        }
        fn is_assignable(&self, from: &JavaType, to: &JavaType) -> bool {
            self.is_subtype(from, to)
        }
        fn unboxed_type(&self, _boxed: &JavaType) -> Option<JavaType> {
            None
        }
        fn erasure(&self, t: &JavaType) -> JavaType {
            t.clone()
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
        fn is_abstract(&self, _elem: &TypeElement) -> bool {
            false
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

    /// A fresh `ValidationContext` writing into the given shared sink, for constructing one of
    /// [`DBAnnotatedObjectValidator`]'s sub-validators (each of which owns its own context -- see
    /// the module docs).
    fn ctx_into(sink: &std::rc::Rc<CapturingMessager>) -> ValidationContext {
        ValidationContext::new(Box::new(MockTypeOracle), Box::new(ForwardingMessager(sink.clone())))
    }

    fn sink_and_ctx() -> (std::rc::Rc<CapturingMessager>, ValidationContext) {
        let sink = std::rc::Rc::new(CapturingMessager::new());
        let ctx = ctx_into(&sink);
        (sink, ctx)
    }

    fn good_table_type() -> TypeElement {
        TypeElement::new("com.example.MyTable")
    }

    fn bad_table_type() -> TypeElement {
        TypeElement::new("com.example.NotADbAnnotatedObject")
    }

    // ---- validate(): the "annotation present/absent" checks, with no fields/columns ----

    #[test]
    fn valid_annotated_concrete_subclass_reports_nothing() {
        let (sink, ctx) = sink_and_ctx();
        let validator = DBAnnotatedObjectValidator::new(
            good_table_type(),
            ElementKind::Class,
            HashSet::new(),
            Some(0),
        );
        validator.validate(&ctx);
        assert!(sink.messages.borrow().is_empty(), "{:?}", sink.messages.borrow());
    }

    #[test]
    fn annotation_on_a_non_class_reports_interface_error_only() {
        let (sink, ctx) = sink_and_ctx();
        let validator = DBAnnotatedObjectValidator::new(
            good_table_type(),
            ElementKind::Other,
            HashSet::new(),
            Some(0),
        );
        validator.validate(&ctx);
        let messages = sink.messages.borrow();
        assert!(messages.iter().any(|m| m.contains("cannot be applied to an interface")));
        // if/else-if: the abstract-class message must not also fire.
        assert!(!messages.iter().any(|m| m.contains("cannot be applied to an abstract class")));
    }

    #[test]
    fn annotation_on_an_abstract_class_reports_abstract_error_only() {
        let (sink, ctx) = sink_and_ctx();
        let mut modifiers = HashSet::new();
        modifiers.insert(Modifier::Abstract);
        let validator =
            DBAnnotatedObjectValidator::new(good_table_type(), ElementKind::Class, modifiers, Some(0));
        validator.validate(&ctx);
        let messages = sink.messages.borrow();
        assert!(messages.iter().any(|m| m.contains("cannot be applied to an abstract class")));
        assert!(!messages.iter().any(|m| m.contains("cannot be applied to an interface")));
        // An abstract class with the annotation present is not subject to the "must have
        // annotation" check (that only fires when the annotation is absent).
        assert!(!messages.iter().any(|m| m.contains("must have")));
    }

    #[test]
    fn annotation_present_but_not_a_db_annotated_object_subclass_reports_the_quirky_message() {
        let (sink, ctx) = sink_and_ctx();
        let validator =
            DBAnnotatedObjectValidator::new(bad_table_type(), ElementKind::Class, HashSet::new(), Some(0));
        validator.validate(&ctx);
        let messages = sink.messages.borrow();
        // Java quirk: the message reads "@DBAnnotatedObject can only be applied to subclasses of
        // DBAnnotatedObjectInfo" -- the literal and the annotation's simple name are swapped
        // relative to what the sentence seems to intend. Preserved exactly, see `validate`'s docs.
        assert!(messages.iter().any(|m| m
            == "@DBAnnotatedObject can only be applied to subclasses of DBAnnotatedObjectInfo"));
    }

    #[test]
    fn no_annotation_on_a_non_abstract_class_reports_must_have_annotation_error() {
        let (sink, ctx) = sink_and_ctx();
        let validator =
            DBAnnotatedObjectValidator::new(good_table_type(), ElementKind::Class, HashSet::new(), None);
        validator.validate(&ctx);
        let messages = sink.messages.borrow();
        assert!(messages.iter().any(|m| m.contains(
            "Non-abstract subclasses of DBAnnotatedObject must have @DBAnnotatedObjectInfo annotation"
        )));
    }

    #[test]
    fn no_annotation_on_an_abstract_class_reports_nothing() {
        let (sink, ctx) = sink_and_ctx();
        let mut modifiers = HashSet::new();
        modifiers.insert(Modifier::Abstract);
        let validator =
            DBAnnotatedObjectValidator::new(good_table_type(), ElementKind::Class, modifiers, None);
        validator.validate(&ctx);
        assert!(sink.messages.borrow().is_empty(), "{:?}", sink.messages.borrow());
    }

    #[test]
    fn negative_version_reports_an_error_independent_of_the_other_checks() {
        let (sink, ctx) = sink_and_ctx();
        let validator = DBAnnotatedObjectValidator::new(
            good_table_type(),
            ElementKind::Class,
            HashSet::new(),
            Some(-1),
        );
        validator.validate(&ctx);
        let messages = sink.messages.borrow();
        assert!(messages.iter().any(|m| m.contains("version cannot be negative")));
    }

    #[test]
    fn multiple_independent_checks_can_co_fire() {
        // annotation present, wrong kind (fires check 1), AND not a DBAnnotatedObject subclass
        // (fires check 3, independent of the if/else-if above it), AND negative version.
        let (sink, ctx) = sink_and_ctx();
        let validator = DBAnnotatedObjectValidator::new(
            bad_table_type(),
            ElementKind::Other,
            HashSet::new(),
            Some(-1),
        );
        validator.validate(&ctx);
        let messages = sink.messages.borrow();
        assert!(messages.iter().any(|m| m.contains("cannot be applied to an interface")));
        assert!(messages.iter().any(|m| m.contains("can only be applied to subclasses of")));
        assert!(messages.iter().any(|m| m.contains("version cannot be negative")));
        assert_eq!(messages.len(), 3);
    }

    // ---- check_missing / check_access, via fields/columns added directly ----

    fn abstract_modifiers() -> HashSet<Modifier> {
        let mut m = HashSet::new();
        m.insert(Modifier::Abstract);
        m
    }

    /// A validator whose own type-level checks are all silent (no annotation, abstract class),
    /// isolating `check_missing`/`check_access` as the only possible sources of messages. Since
    /// `check_missing`'s own "missing corresponding annotation" messages are themselves gated on
    /// *not* being abstract (matching Java's `!type.getModifiers().contains(ABSTRACT)` guard --
    /// see [`abstract_class_suppresses_the_missing_corresponding_annotation_warnings`]), this is
    /// only useful for isolating `check_access`, not the "missing" messages themselves.
    fn silent_type_validator() -> DBAnnotatedObjectValidator {
        DBAnnotatedObjectValidator::new(good_table_type(), ElementKind::Class, abstract_modifiers(), None)
    }

    /// A validator with no annotation and *not* abstract: `validate`'s own top-level checks would
    /// report "must have @DBAnnotatedObjectInfo annotation" (harmless noise for the `.any(...)`
    /// assertions these tests make), but critically -- unlike [`silent_type_validator`] --
    /// `check_missing`'s "missing corresponding annotation" messages are *not* suppressed.
    fn non_abstract_no_annotation_validator() -> DBAnnotatedObjectValidator {
        DBAnnotatedObjectValidator::new(good_table_type(), ElementKind::Class, HashSet::new(), None)
    }

    fn db_object_column_type() -> JavaType {
        JavaType::declared(TypeElement::new("ghidra.util.database.DBObjectColumn"))
    }

    fn concrete_field_type() -> JavaType {
        JavaType::declared(TypeElement::new("com.example.ConcreteField"))
    }

    fn codec_type_element() -> TypeElement {
        TypeElement::with_type_parameters(
            "com.example.SomeCodec",
            vec!["VT".to_string(), "OT".to_string(), "FT".to_string()],
        )
    }

    #[test]
    fn field_missing_its_corresponding_column_reports_a_warning() {
        let (sink, ctx) = sink_and_ctx();
        let mut validator = non_abstract_no_annotation_validator();
        let field =
            VariableElement::new(concrete_field_type(), good_table_type(), ElementKind::Class);
        let default_codec = ctx.default_codec_elem().clone();
        validator.add_annotated_field(ctx_into(&sink), field, "count", default_codec);

        validator.check_missing(&ctx);

        assert!(sink
            .messages
            .borrow()
            .iter()
            .any(|m| m.contains("@DBAnnotatedField is missing corresponding @DBAnnotatedColumn")));
    }

    #[test]
    fn column_missing_its_corresponding_field_reports_a_warning() {
        let (sink, ctx) = sink_and_ctx();
        let mut validator = non_abstract_no_annotation_validator();
        let column = VariableElement::new(db_object_column_type(), good_table_type(), ElementKind::Class)
            .with_modifiers([Modifier::Static]);
        validator.add_annotated_column(ctx_into(&sink), column, "count");

        validator.check_missing(&ctx);

        assert!(sink
            .messages
            .borrow()
            .iter()
            .any(|m| m.contains("@DBAnnotatedColumn is missing corresponding @DBAnnotatedField")));
    }

    #[test]
    fn abstract_class_suppresses_the_missing_corresponding_annotation_warnings() {
        let (sink, ctx) = sink_and_ctx();
        // silent_type_validator() is already abstract.
        let mut validator = silent_type_validator();
        let field =
            VariableElement::new(concrete_field_type(), good_table_type(), ElementKind::Class);
        let default_codec = ctx.default_codec_elem().clone();
        validator.add_annotated_field(ctx_into(&sink), field, "count", default_codec);

        validator.check_missing(&ctx);

        assert!(sink.messages.borrow().is_empty(), "{:?}", sink.messages.borrow());
    }

    #[test]
    fn matched_field_and_column_with_compatible_access_reports_nothing_from_check_access() {
        let (sink, ctx) = sink_and_ctx();
        let mut validator = silent_type_validator();

        let field = VariableElement::new(concrete_field_type(), good_table_type(), ElementKind::Class)
            .with_modifiers([Modifier::Public]);
        validator.add_annotated_field(ctx_into(&sink), field, "count", codec_type_element());

        let column = VariableElement::new(db_object_column_type(), good_table_type(), ElementKind::Class)
            .with_modifiers([Modifier::Static, Modifier::Public]);
        validator.add_annotated_column(ctx_into(&sink), column, "count");

        validator.check_missing(&ctx);
        assert!(sink.messages.borrow().is_empty(), "{:?}", sink.messages.borrow());
    }

    #[test]
    fn matched_field_and_column_with_incompatible_access_reports_check_access_warning() {
        let (sink, ctx) = sink_and_ctx();
        let mut validator = silent_type_validator();

        // checkAccess requires the *column*'s access to be same-or-greater than the *field*'s --
        // here the column (private) is less permissive than the field (public), violating it.
        let field = VariableElement::new(concrete_field_type(), good_table_type(), ElementKind::Class)
            .with_modifiers([Modifier::Public]);
        validator.add_annotated_field(ctx_into(&sink), field, "count", codec_type_element());

        let column = VariableElement::new(db_object_column_type(), good_table_type(), ElementKind::Class)
            .with_modifiers([Modifier::Static, Modifier::Private]);
        validator.add_annotated_column(ctx_into(&sink), column, "count");

        validator.check_missing(&ctx);
        assert!(sink
            .messages
            .borrow()
            .iter()
            .any(|m| m.contains("should have same or greater access")));
    }

    #[test]
    fn re_adding_a_field_under_the_same_name_replaces_it_in_place() {
        let (sink, ctx) = sink_and_ctx();
        let mut validator = silent_type_validator();

        let field1 = VariableElement::new(concrete_field_type(), good_table_type(), ElementKind::Class)
            .with_modifiers([Modifier::Final]);
        validator.add_annotated_field(ctx_into(&sink), field1, "count", codec_type_element());
        assert_eq!(validator.fields_by_name.len(), 1);

        let field2 = VariableElement::new(concrete_field_type(), good_table_type(), ElementKind::Class);
        validator.add_annotated_field(ctx_into(&sink), field2, "count", codec_type_element());
        // Still exactly one entry (replaced, not duplicated).
        assert_eq!(validator.fields_by_name.len(), 1);
    }
}

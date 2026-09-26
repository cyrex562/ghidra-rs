//! Port of `ghidra.util.database.annotproc.DBAnnotatedObjectProcessor`.
//!
//! # Port strategy: facts instead of a live `RoundEnvironment`
//!
//! The Java class is a compile-time `javax.annotation.processing.Processor`: `process` is driven
//! by a live `RoundEnvironment`, calling `roundEnv.getElementsAnnotatedWith(X.class)` three times
//! to discover every element in the current compilation round annotated with
//! `@DBAnnotatedObjectInfo`/`@DBAnnotatedField`/`@DBAnnotatedColumn`. This crate has no Rust
//! equivalent of a live `javac` round to query. Per this module's established convention (see
//! [`ValidationContext`]'s and [`DBAnnotatedObjectValidator`]'s own module docs), the facts such a
//! live round would supply are instead passed directly by the caller: [`process`](DBAnnotatedObjectProcessor::process)
//! takes the *already-collected* elements for each of the three annotations as
//! [`AnnotatedObjectInfo`]/[`AnnotatedFieldInfo`]/[`AnnotatedColumnInfo`] lists, rather than
//! querying for them.
//!
//! # Port strategy: a `ValidationContext` factory instead of one shared instance
//!
//! Java's `init(ProcessingEnvironment)` builds one `ValidationContext` and stores it in a `ctx`
//! field, shared by reference across every validator constructed during `process`. This port's
//! [`ValidationContext`] is not `Clone` (it owns `Box<dyn TypeOracle>`/`Box<dyn Messager>` trait
//! objects -- see its own module docs), while [`DBAnnotatedObjectValidator`]'s established
//! convention (see its module docs) has each validator *own* its `ValidationContext` rather than
//! borrow a shared one. So [`DBAnnotatedObjectProcessor::new`] (standing in for `init`) instead
//! takes a *factory* closure producing a fresh, equivalent `ValidationContext` on demand -- one
//! call per validator/sub-validator constructed, exactly mirroring how many distinct
//! `ValidationContext` references Java's single shared instance effectively stands in for.

use crate::util::database::annotproc::{
    DBAnnotatedObjectValidator, ElementKind, Modifier, TypeElement, ValidationContext,
    VariableElement,
};
use std::collections::HashSet;

/// The canonical (fully-qualified) names of the three annotations this processor supports.
///
/// Port of `DBAnnotatedObjectProcessor.SUPPORTED_ANNOTATIONS`, specifically as consumed by
/// `getSupportedAnnotationTypes()`'s `.map(Class::getCanonicalName)`. Per this module's
/// established convention of using literal simple/canonical names rather than deriving them from
/// a ported annotation type (see e.g. `DBAnnotatedColumnValidator`/`DBAnnotatedFieldValidator`'s
/// own `ANNOTATION_SIMPLE_NAME` constants), these are built from the package Java imports
/// unqualified (`ghidra.util.database.annot.*`).
pub const SUPPORTED_ANNOTATIONS: [&str; 3] = [
    "ghidra.util.database.annot.DBAnnotatedColumn",
    "ghidra.util.database.annot.DBAnnotatedField",
    "ghidra.util.database.annot.DBAnnotatedObjectInfo",
];

/// Describes one element found via `roundEnv.getElementsAnnotatedWith(DBAnnotatedObjectInfo.class)`.
///
/// `annotation_version` mirrors `type.getAnnotation(DBAnnotatedObjectInfo.class).version()` --
/// always `Some` here, since a `TypeElement` only appears in this list because the live round
/// found the annotation actually present (see [`DBAnnotatedObjectProcessor::process`]'s docs for
/// why `None` is reserved for elements reached only via [`AnnotatedFieldInfo`]/
/// [`AnnotatedColumnInfo`]).
pub struct AnnotatedObjectInfo {
    /// The annotated type. Java: `(TypeElement) element`.
    pub type_elem: TypeElement,
    /// Java: `type.getKind()`.
    pub type_kind: ElementKind,
    /// Java: `type.getModifiers()`.
    pub type_modifiers: HashSet<Modifier>,
    /// Java: `type.getAnnotation(DBAnnotatedObjectInfo.class).version()`.
    pub annotation_version: i32,
}

/// Describes one element found via `roundEnv.getElementsAnnotatedWith(DBAnnotatedField.class)`.
pub struct AnnotatedFieldInfo {
    /// The annotated field. Java: `(VariableElement) field`.
    pub field: VariableElement,
    /// Java: the field's own `@DBAnnotatedField` annotation's `column()` member.
    pub column_name: String,
    /// Java: the field's own `@DBAnnotatedField` annotation's `codec` member, resolved to a type
    /// element (see [`DBAnnotatedObjectValidator::add_annotated_field`]'s identical parameter).
    pub specified_codec: TypeElement,
    /// The modifiers of [`Self::field`]'s enclosing type -- Java: `field.getEnclosingElement()
    /// .getModifiers()`. Supplied directly for the same reason `field`'s own facts are (see the
    /// module docs); only consulted if this field's enclosing type has no corresponding
    /// [`AnnotatedObjectInfo`] entry, in which case [`DBAnnotatedObjectProcessor::process`]
    /// constructs that type's validator lazily (mirroring Java's `computeIfAbsent`).
    pub enclosing_modifiers: HashSet<Modifier>,
}

/// Describes one element found via `roundEnv.getElementsAnnotatedWith(DBAnnotatedColumn.class)`.
pub struct AnnotatedColumnInfo {
    /// The annotated column field. Java: `(VariableElement) column`.
    pub column: VariableElement,
    /// Java: the column's own `@DBAnnotatedColumn` annotation's `value()` member.
    pub column_name: String,
    /// See [`AnnotatedFieldInfo::enclosing_modifiers`]'s identical docs.
    pub enclosing_modifiers: HashSet<Modifier>,
}

/// A compile-time annotation processor for [`DBAnnotatedObject`](crate::util::database::DBAnnotatedObject)-related
/// annotations.
///
/// This processor performs compile-time validation checks on annotations related to
/// `DBAnnotatedObject`. It does not generate any code, but perhaps one day, it will.
///
/// Port of `ghidra.util.database.annotproc.DBAnnotatedObjectProcessor`. See the module docs for
/// this port's deviations from Java's live-annotation-processor shape.
pub struct DBAnnotatedObjectProcessor {
    ctx_factory: Box<dyn Fn() -> ValidationContext>,
}

impl DBAnnotatedObjectProcessor {
    /// Initialize the processor with a factory for the [`ValidationContext`]s it will need.
    ///
    /// Port of `synchronized void init(ProcessingEnvironment env)`. See the module docs for why
    /// this takes a factory rather than one shared `ValidationContext` (Java: `ctx = new
    /// ValidationContext(env)`).
    pub fn new(ctx_factory: impl Fn() -> ValidationContext + 'static) -> Self {
        DBAnnotatedObjectProcessor { ctx_factory: Box::new(ctx_factory) }
    }

    /// `LinkedHashMap.computeIfAbsent`-equivalent: returns the index of `key`'s existing entry, or
    /// appends a freshly-constructed one (via `make`) and returns its index. Unlike
    /// [`DBAnnotatedObjectValidator`]'s own `put` helper (which *replaces* an existing entry),
    /// this never overwrites one that's already present -- matching `computeIfAbsent`'s contract.
    fn compute_index(
        types: &mut Vec<(TypeElement, DBAnnotatedObjectValidator)>,
        key: TypeElement,
        make: impl FnOnce() -> DBAnnotatedObjectValidator,
    ) -> usize {
        if let Some(idx) = types.iter().position(|(k, _)| *k == key) {
            return idx;
        }
        types.push((key, make()));
        types.len() - 1
    }

    /// Process the specified annotations for the current round of processing.
    ///
    /// Port of `boolean process(Set<? extends TypeElement> annotations, RoundEnvironment
    /// roundEnv)`. See the module docs for why the three `roundEnv.getElementsAnnotatedWith(...)`
    /// calls become the `object_infos`/`fields`/`columns` parameters instead.
    ///
    /// Always returns `true` (Java: unconditionally `return true`, claiming the annotations).
    pub fn process(
        &self,
        object_infos: Vec<AnnotatedObjectInfo>,
        fields: Vec<AnnotatedFieldInfo>,
        columns: Vec<AnnotatedColumnInfo>,
    ) -> bool {
        // Port of `Map<TypeElement, DBAnnotatedObjectValidator> types = new LinkedHashMap<>();` --
        // a `Vec` of pairs preserves LinkedHashMap's stable insertion-order iteration, matching
        // DBAnnotatedObjectValidator's own identical `fields_by_name`/`columns_by_name` precedent.
        let mut types: Vec<(TypeElement, DBAnnotatedObjectValidator)> = Vec::new();

        // for (Element element : roundEnv.getElementsAnnotatedWith(DBAnnotatedObjectInfo.class)) {
        //     TypeElement type = (TypeElement) element;
        //     types.put(type, new DBAnnotatedObjectValidator(ctx, type));
        // }
        for info in object_infos {
            let validator = DBAnnotatedObjectValidator::new(
                info.type_elem.clone(),
                info.type_kind,
                info.type_modifiers,
                Some(info.annotation_version),
            );
            if let Some(idx) = types.iter().position(|(k, _)| *k == info.type_elem) {
                types[idx].1 = validator;
            } else {
                types.push((info.type_elem, validator));
            }
        }

        // for (Element field : roundEnv.getElementsAnnotatedWith(DBAnnotatedField.class)) {
        //     VariableElement varField = (VariableElement) field;
        //     TypeElement type = (TypeElement) field.getEnclosingElement();
        //     DBAnnotatedObjectValidator validator =
        //         types.computeIfAbsent(type, t -> new DBAnnotatedObjectValidator(ctx, type));
        //     validator.addAnnotatedField(varField);
        // }
        for f in fields {
            let enclosing = f.field.enclosing_type.clone();
            let enclosing_kind = f.field.enclosing_kind;
            let enclosing_modifiers = f.enclosing_modifiers.clone();
            let idx = Self::compute_index(&mut types, enclosing.clone(), || {
                // Reached only when `enclosing` has no @DBAnnotatedObjectInfo entry above -- in a
                // live compiler round that is only possible when the annotation is genuinely
                // absent (getElementsAnnotatedWith would otherwise have already enumerated it),
                // so `annotation_version: None` here is not a simplification but the actual fact.
                DBAnnotatedObjectValidator::new(enclosing, enclosing_kind, enclosing_modifiers, None)
            });
            types[idx].1.add_annotated_field((self.ctx_factory)(), f.field, f.column_name, f.specified_codec);
        }

        // for (Element column : roundEnv.getElementsAnnotatedWith(DBAnnotatedColumn.class)) {
        //     VariableElement varColumn = (VariableElement) column;
        //     TypeElement type = (TypeElement) column.getEnclosingElement();
        //     DBAnnotatedObjectValidator validator =
        //         types.computeIfAbsent(type, t -> new DBAnnotatedObjectValidator(ctx, type));
        //     validator.addAnnotatedColumn(varColumn);
        // }
        for c in columns {
            let enclosing = c.column.enclosing_type.clone();
            let enclosing_kind = c.column.enclosing_kind;
            let enclosing_modifiers = c.enclosing_modifiers.clone();
            let idx = Self::compute_index(&mut types, enclosing.clone(), || {
                DBAnnotatedObjectValidator::new(enclosing, enclosing_kind, enclosing_modifiers, None)
            });
            types[idx].1.add_annotated_column((self.ctx_factory)(), c.column, c.column_name);
        }

        // for (DBAnnotatedObjectValidator ov : types.values()) {
        //     ov.validate();
        // }
        for (_, validator) in &types {
            let ctx = (self.ctx_factory)();
            validator.validate(&ctx);
        }

        true
    }

    /// Return the set of supported annotation types.
    ///
    /// Port of `Set<String> getSupportedAnnotationTypes()`.
    pub fn supported_annotation_types(&self) -> HashSet<&'static str> {
        SUPPORTED_ANNOTATIONS.into_iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::database::annotproc::{JavaType, Messager, TypeOracle};
    use std::cell::RefCell;
    use std::rc::Rc;

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
        // `com.example.SomeCodec` (unparameterized) reports a single direct supertype:
        // `DBFieldCodec<VT, OT, FT>` with VT/OT/FT fixed to exactly the field's declared type /
        // the enclosing table's own type / the field's declared type again -- matching
        // `DBAnnotatedFieldValidator`'s own identical `CodecOracle` test precedent (see that
        // module's tests), needed so `DBAnnotatedFieldValidator::check_codec_types`'s
        // `ctx.get_arguments_of_element(&codec_type, ctx.db_field_codec_elem())` call (made via
        // this processor's `process` -> `DBAnnotatedObjectValidator::validate_fields`) finds a
        // matching supertype instead of hitting `ValidationContext::get_arguments`'s "no matching
        // supertype found" panic -- exactly the pitfall this session's own porting notes warn
        // about for this module's tests.
        fn direct_supertypes(&self, t: &JavaType) -> Vec<JavaType> {
            if let JavaType::Declared { element, .. } = t {
                if element.name == "com.example.SomeCodec" {
                    let field_type = JavaType::declared(TypeElement::new("com.example.ConcreteField"));
                    let table_type = JavaType::declared(TypeElement::new("com.example.MyTable"));
                    return vec![JavaType::Declared {
                        element: TypeElement::with_type_parameters(
                            "ghidra.util.database.DBCachedObjectStoreFactory.DBFieldCodec",
                            vec!["VT".to_string(), "OT".to_string(), "FT".to_string()],
                        ),
                        type_arguments: vec![field_type.clone(), table_type, field_type],
                    }];
                }
            }
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
    struct ForwardingMessager(Rc<CapturingMessager>);
    impl Messager for ForwardingMessager {
        fn print_error(&self, message: &str) {
            self.0.print_error(message);
        }
    }

    fn sink_and_processor() -> (Rc<CapturingMessager>, DBAnnotatedObjectProcessor) {
        let sink = Rc::new(CapturingMessager::new());
        let sink_for_factory = Rc::clone(&sink);
        let processor = DBAnnotatedObjectProcessor::new(move || {
            ValidationContext::new(
                Box::new(MockTypeOracle),
                Box::new(ForwardingMessager(Rc::clone(&sink_for_factory))),
            )
        });
        (sink, processor)
    }

    fn good_table_type() -> TypeElement {
        TypeElement::new("com.example.MyTable")
    }

    fn field_declared_type() -> JavaType {
        JavaType::declared(TypeElement::new("com.example.ConcreteField"))
    }

    fn column_declared_type() -> JavaType {
        JavaType::declared(TypeElement::new("ghidra.util.database.DBObjectColumn"))
    }

    fn codec_type_element() -> TypeElement {
        TypeElement::with_type_parameters(
            "com.example.SomeCodec",
            vec!["VT".to_string(), "OT".to_string(), "FT".to_string()],
        )
    }

    #[test]
    fn supported_annotation_types_matches_the_three_db_annotations() {
        let (_sink, processor) = sink_and_processor();
        let types = processor.supported_annotation_types();
        assert_eq!(types.len(), 3);
        assert!(types.contains("ghidra.util.database.annot.DBAnnotatedObjectInfo"));
        assert!(types.contains("ghidra.util.database.annot.DBAnnotatedField"));
        assert!(types.contains("ghidra.util.database.annot.DBAnnotatedColumn"));
    }

    #[test]
    fn process_returns_true() {
        let (_sink, processor) = sink_and_processor();
        assert!(processor.process(Vec::new(), Vec::new(), Vec::new()));
    }

    #[test]
    fn well_formed_class_with_matched_field_and_column_reports_nothing() {
        let (sink, processor) = sink_and_processor();

        let object_infos = vec![AnnotatedObjectInfo {
            type_elem: good_table_type(),
            type_kind: ElementKind::Class,
            type_modifiers: HashSet::new(),
            annotation_version: 0,
        }];
        let field = VariableElement::new(field_declared_type(), good_table_type(), ElementKind::Class)
            .with_modifiers([Modifier::Public]);
        let fields = vec![AnnotatedFieldInfo {
            field,
            column_name: "count".to_string(),
            specified_codec: codec_type_element(),
            enclosing_modifiers: HashSet::new(),
        }];
        let column = VariableElement::new(column_declared_type(), good_table_type(), ElementKind::Class)
            .with_modifiers([Modifier::Static, Modifier::Public]);
        let columns = vec![AnnotatedColumnInfo {
            column,
            column_name: "count".to_string(),
            enclosing_modifiers: HashSet::new(),
        }];

        processor.process(object_infos, fields, columns);

        assert!(sink.messages.borrow().is_empty(), "{:?}", sink.messages.borrow());
    }

    #[test]
    fn field_without_a_matching_column_reports_the_missing_column_warning() {
        let (sink, processor) = sink_and_processor();

        let object_infos = vec![AnnotatedObjectInfo {
            type_elem: good_table_type(),
            type_kind: ElementKind::Class,
            type_modifiers: HashSet::new(),
            annotation_version: 0,
        }];
        let field = VariableElement::new(field_declared_type(), good_table_type(), ElementKind::Class);
        let fields = vec![AnnotatedFieldInfo {
            field,
            column_name: "count".to_string(),
            specified_codec: codec_type_element(),
            enclosing_modifiers: HashSet::new(),
        }];

        processor.process(object_infos, fields, Vec::new());

        let messages = sink.messages.borrow();
        assert!(messages
            .iter()
            .any(|m| m.contains("@DBAnnotatedField is missing corresponding @DBAnnotatedColumn")));
    }

    #[test]
    fn field_whose_enclosing_type_has_no_object_info_creates_a_lazy_validator() {
        // No AnnotatedObjectInfo for `good_table_type()` at all -- the validator for it must be
        // constructed lazily (mirroring Java's `computeIfAbsent`), with `annotation_version` truly
        // absent (see the module docs), which independently also fires the "must have
        // @DBAnnotatedObjectInfo" top-level check for a non-abstract class.
        let (sink, processor) = sink_and_processor();

        let field = VariableElement::new(field_declared_type(), good_table_type(), ElementKind::Class);
        let fields = vec![AnnotatedFieldInfo {
            field,
            column_name: "count".to_string(),
            specified_codec: codec_type_element(),
            enclosing_modifiers: HashSet::new(),
        }];

        processor.process(Vec::new(), fields, Vec::new());

        let messages = sink.messages.borrow();
        assert!(messages.iter().any(|m| m.contains("must have @DBAnnotatedObjectInfo annotation")));
        assert!(messages
            .iter()
            .any(|m| m.contains("@DBAnnotatedField is missing corresponding @DBAnnotatedColumn")));
    }

    #[test]
    fn field_and_column_sharing_an_enclosing_type_reuse_the_same_lazily_created_validator() {
        // Both the field and the column belong to the same (object-info-less) enclosing type; if
        // `compute_index` created two separate validators instead of reusing one (the
        // `computeIfAbsent` contract), the "missing corresponding" warnings would fire even though
        // both halves are actually present.
        let (sink, processor) = sink_and_processor();

        let field = VariableElement::new(field_declared_type(), good_table_type(), ElementKind::Class)
            .with_modifiers([Modifier::Public]);
        let fields = vec![AnnotatedFieldInfo {
            field,
            column_name: "count".to_string(),
            specified_codec: codec_type_element(),
            enclosing_modifiers: HashSet::new(),
        }];
        let column = VariableElement::new(column_declared_type(), good_table_type(), ElementKind::Class)
            .with_modifiers([Modifier::Static, Modifier::Public]);
        let columns = vec![AnnotatedColumnInfo {
            column,
            column_name: "count".to_string(),
            enclosing_modifiers: HashSet::new(),
        }];

        processor.process(Vec::new(), fields, columns);

        let messages = sink.messages.borrow();
        assert!(!messages.iter().any(|m| m.contains("missing corresponding")));
    }

    #[test]
    fn abstract_class_with_annotation_reports_the_abstract_class_error() {
        // Mirrors DBAnnotatedObjectValidator's own
        // `annotation_on_an_abstract_class_reports_abstract_error_only` test: `@DBAnnotatedObjectInfo`
        // present on an abstract class is itself an error (the annotation is meant for concrete
        // subclasses), independent of whether it has any fields/columns at all.
        let (sink, processor) = sink_and_processor();
        let mut modifiers = HashSet::new();
        modifiers.insert(Modifier::Abstract);

        let object_infos = vec![AnnotatedObjectInfo {
            type_elem: good_table_type(),
            type_kind: ElementKind::Class,
            type_modifiers: modifiers,
            annotation_version: 0,
        }];

        processor.process(object_infos, Vec::new(), Vec::new());

        let messages = sink.messages.borrow();
        assert!(messages.iter().any(|m| m.contains("cannot be applied to an abstract class")));
        assert_eq!(messages.len(), 1);
    }

    #[test]
    fn abstract_class_with_no_annotation_and_no_fields_or_columns_is_never_validated() {
        // An abstract class with neither the annotation nor any annotated fields/columns never
        // appears in any of `object_infos`/`fields`/`columns`, so (mirroring Java's
        // `roundEnv.getElementsAnnotatedWith` simply never surfacing it) no validator is ever
        // constructed for it at all -- trivially no messages.
        let (sink, processor) = sink_and_processor();

        processor.process(Vec::new(), Vec::new(), Vec::new());

        assert!(sink.messages.borrow().is_empty(), "{:?}", sink.messages.borrow());
    }

    #[test]
    fn re_processing_the_same_type_via_object_info_replaces_rather_than_duplicates() {
        // Mirrors `types.put` (not `computeIfAbsent`) for the object-info loop: a second
        // AnnotatedObjectInfo for the same type_elem replaces the first entry rather than
        // creating a duplicate validator (which would otherwise double every message).
        let (sink, processor) = sink_and_processor();

        let object_infos = vec![
            AnnotatedObjectInfo {
                type_elem: good_table_type(),
                type_kind: ElementKind::Class,
                type_modifiers: HashSet::new(),
                annotation_version: -1,
            },
            AnnotatedObjectInfo {
                type_elem: good_table_type(),
                type_kind: ElementKind::Class,
                type_modifiers: HashSet::new(),
                annotation_version: 0,
            },
        ];

        processor.process(object_infos, Vec::new(), Vec::new());

        let messages = sink.messages.borrow();
        // Only the second entry (version 0, non-negative) should have been validated.
        assert!(!messages.iter().any(|m| m.contains("version cannot be negative")));
    }
}

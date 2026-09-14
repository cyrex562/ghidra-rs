//! Port of `ghidra.util.database.annotproc.DBAnnotatedColumnValidator`.

use crate::util::database::annotproc::{AbstractDBAnnotationValidator, Modifier, ValidationContext, VariableElement};

/// The simple name of the annotation this validator checks, mirroring
/// `DBAnnotatedColumn.class.getSimpleName()`. There is no ported `DBAnnotatedColumn` annotation
/// type to call `.getSimpleName()` on (it's a `javax.lang.model` reflection artifact of the
/// annotation processor this class supports), so, per this package's established convention (see
/// [`AbstractDBAnnotationValidator::check_enclosing_type`]'s own `annot_type_simple_name`
/// parameter), the name is just the literal string.
const ANNOTATION_SIMPLE_NAME: &str = "DBAnnotatedColumn";

/// A validator for fields annotated with `DBAnnotatedColumn`.
///
/// Port of `ghidra.util.database.annotproc.DBAnnotatedColumnValidator`. Ensures fields annotated
/// with `DBAnnotatedColumn` comply with the expected criteria for database columns in Ghidra.
///
/// Java's `class DBAnnotatedColumnValidator extends AbstractDBAnnotationValidator` becomes, per
/// this crate's composition-over-inheritance convention, a struct holding a `base:
/// AbstractDBAnnotationValidator` field.
pub struct DBAnnotatedColumnValidator {
    base: AbstractDBAnnotationValidator,
    column: VariableElement,
}

impl DBAnnotatedColumnValidator {
    /// Construct a new validator with the specified validation context and the column element.
    ///
    /// Port of `DBAnnotatedColumnValidator(ValidationContext, VariableElement)`.
    pub fn new(ctx: ValidationContext, column: VariableElement) -> Self {
        DBAnnotatedColumnValidator { base: AbstractDBAnnotationValidator::new(ctx), column }
    }

    /// Validate the annotated column field.
    ///
    /// Performs the following checks to ensure it meets the requirements for database columns:
    /// * The field must be of the type specified by `ctx.DB_OBJECT_COLUMN_ELEM`.
    /// * The field must not be declared as `final`.
    /// * The field must be declared as `static`.
    /// * The enclosing type of the field must meet the criteria defined in
    ///   [`AbstractDBAnnotationValidator::check_enclosing_type`].
    ///
    /// Port of `validate()`.
    pub fn validate(&self) {
        let ctx = &self.base.ctx;

        if !ctx.has_type_element(&self.column, ctx.db_object_column_elem()) {
            ctx.messager().print_error(&format!(
                "@{} can only be applied to fields of type {}",
                ANNOTATION_SIMPLE_NAME,
                ctx.db_object_column_elem().name
            ));
        }

        if self.column.modifiers.contains(&Modifier::Final) {
            ctx.messager().print_error(&format!(
                "@{} cannot be applied to a final field",
                ANNOTATION_SIMPLE_NAME
            ));
        }

        if !self.column.modifiers.contains(&Modifier::Static) {
            ctx.messager().print_error(&format!(
                "@{} must be applied to a static field",
                ANNOTATION_SIMPLE_NAME
            ));
        }

        self.base.check_enclosing_type(
            ANNOTATION_SIMPLE_NAME,
            self.column.enclosing_kind,
            &self.column.enclosing_type,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::database::annotproc::{ElementKind, JavaType, Messager, TypeElement, TypeOracle};
    use std::cell::RefCell;

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
            // "com.example.MyTable" stands in for a real `DBAnnotatedObject` subclass, mirroring
            // `AbstractDBAnnotationValidator`'s own `MockTypeOracle` (see that file's tests).
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

    fn validator_with(column: VariableElement) -> (DBAnnotatedColumnValidator, std::rc::Rc<CapturingMessager>) {
        struct ForwardingMessager(std::rc::Rc<CapturingMessager>);
        impl Messager for ForwardingMessager {
            fn print_error(&self, message: &str) {
                self.0.print_error(message);
            }
        }

        let inner = std::rc::Rc::new(CapturingMessager::new());
        let ctx = ValidationContext::new(Box::new(MockTypeOracle), Box::new(ForwardingMessager(inner.clone())));
        (DBAnnotatedColumnValidator::new(ctx, column), inner)
    }

    fn db_object_column_type() -> JavaType {
        JavaType::declared(TypeElement::new("ghidra.util.database.DBObjectColumn"))
    }

    fn valid_column() -> VariableElement {
        VariableElement::new(
            db_object_column_type(),
            TypeElement::new("com.example.MyTable"),
            ElementKind::Class,
        )
        .with_modifiers([Modifier::Static])
    }

    #[test]
    fn valid_static_non_final_db_object_column_field_reports_nothing() {
        let (validator, messager) = validator_with(valid_column());
        validator.validate();
        assert!(messager.messages.borrow().is_empty());
    }

    #[test]
    fn wrong_type_reports_type_error() {
        let column = VariableElement::new(
            JavaType::Primitive("int"),
            TypeElement::new("com.example.MyTable"),
            ElementKind::Class,
        )
        .with_modifiers([Modifier::Static]);
        let (validator, messager) = validator_with(column);
        validator.validate();
        let messages = messager.messages.borrow();
        assert!(messages.iter().any(|m| m.contains("can only be applied to fields of type")));
    }

    #[test]
    fn final_field_reports_final_error() {
        let column = VariableElement::new(
            db_object_column_type(),
            TypeElement::new("com.example.MyTable"),
            ElementKind::Class,
        )
        .with_modifiers([Modifier::Static, Modifier::Final]);
        let (validator, messager) = validator_with(column);
        validator.validate();
        let messages = messager.messages.borrow();
        assert!(messages.iter().any(|m| m.contains("cannot be applied to a final field")));
    }

    #[test]
    fn non_static_field_reports_static_error() {
        let column = VariableElement::new(
            db_object_column_type(),
            TypeElement::new("com.example.MyTable"),
            ElementKind::Class,
        );
        let (validator, messager) = validator_with(column);
        validator.validate();
        let messages = messager.messages.borrow();
        assert!(messages.iter().any(|m| m.contains("must be applied to a static field")));
    }

    #[test]
    fn non_class_enclosing_type_reports_enclosing_type_error() {
        let column = VariableElement::new(
            db_object_column_type(),
            TypeElement::new("com.example.MyInterface"),
            ElementKind::Other,
        )
        .with_modifiers([Modifier::Static]);
        let (validator, messager) = validator_with(column);
        validator.validate();
        let messages = messager.messages.borrow();
        assert!(messages.iter().any(|m| m.contains("can only be applied to fields in a class")));
    }

    #[test]
    fn multiple_violations_report_multiple_errors() {
        let column = VariableElement::new(
            JavaType::Primitive("int"),
            TypeElement::new("com.example.MyTable"),
            ElementKind::Class,
        )
        .with_modifiers([Modifier::Final]);
        let (validator, messager) = validator_with(column);
        validator.validate();
        // Wrong type, final, and not static -- three independent errors, matching Java's
        // non-short-circuiting sequence of `if` checks.
        assert_eq!(messager.messages.borrow().len(), 3);
    }
}

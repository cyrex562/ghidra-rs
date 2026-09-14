//! Port of `ghidra.util.database.annotproc.AbstractDBAnnotationValidator`.
//!
//! An abstract class for validating annotations on `DBAnnotatedObject`. Performs validation
//! checks on annotated fields and their enclosing types.
//!
//! # Port strategy
//!
//! Per this module's own established convention (see [`ValidationContext`]'s docs), annotation-
//! processor-only state supplied by a live `javac` is decoupled rather than modeled directly:
//! - `Class<? extends Annotation> annotType` is used only for its `getSimpleName()`; this port
//!   takes that name directly as a `&str`.
//! - `VariableElement field` is used only as the diagnostic-position argument to
//!   `Messager.printMessage(Kind, CharSequence, Element)`; since [`Messager`]'s
//!   [`print_error`](Messager::print_error) (the only method this port's `Messager` trait
//!   exposes -- see its own docs on why diagnostic positioning isn't modeled) takes just a
//!   message, `field` carries no information this port can act on and is dropped.
//! - `TypeElement type`'s `getKind() != ElementKind.CLASS` check needs to know whether the
//!   enclosing type is a plain class; since [`TypeElement`] (this module's `javax.lang.model`
//!   surrogate) has no `ElementKind`-equivalent field, [`ElementKind`] is introduced here as a
//!   minimal, two-variant stand-in (`Class` vs. everything else, since that's the only
//!   distinction `checkEnclosingType` ever makes) supplied by the caller alongside `type_elem`,
//!   the same way callers already supply facts a live compiler would otherwise provide (e.g.
//!   [`TypeOracle`]).

use crate::util::database::annotproc::{TypeElement, ValidationContext};

/// Minimal stand-in for `javax.lang.model.element.ElementKind`, covering exactly the distinction
/// [`AbstractDBAnnotationValidator::check_enclosing_type`] makes: whether an enclosing type is a
/// plain class. See the module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ElementKind {
    /// Corresponds to `ElementKind.CLASS`.
    Class,
    /// Any other `ElementKind` (`INTERFACE`, `ENUM`, `RECORD`, ...).
    Other,
}

/// An abstract validator for validating annotations on `DBAnnotatedObject`.
///
/// Port of `ghidra.util.database.annotproc.AbstractDBAnnotationValidator`. Performs validation
/// checks on annotated fields and their enclosing types.
///
/// Java's (unported) `DBAnnotatedColumnValidator`/`DBAnnotatedFieldValidator` subclasses would,
/// per this crate's composition-over-inheritance convention, embed this struct as a `base` field
/// rather than inheriting from it.
pub struct AbstractDBAnnotationValidator {
    /// Port of `protected final ValidationContext ctx`.
    pub ctx: ValidationContext,
}

impl AbstractDBAnnotationValidator {
    /// Construct a new validator with the specified validation context.
    ///
    /// Port of `AbstractDBAnnotationValidator(ValidationContext)`.
    pub fn new(ctx: ValidationContext) -> Self {
        AbstractDBAnnotationValidator { ctx }
    }

    /// Check the enclosing type of the annotated field.
    ///
    /// * `annot_type_simple_name` -- the simple name of the annotation being validated (Java:
    ///   `annotType.getSimpleName()`).
    /// * `kind` -- the [`ElementKind`] of `type_elem`; see the module docs.
    /// * `type_elem` -- the enclosing type of the field.
    ///
    /// Port of `checkEnclosingType(Class<? extends Annotation>, VariableElement, TypeElement)`.
    pub fn check_enclosing_type(
        &self,
        annot_type_simple_name: &str,
        kind: ElementKind,
        type_elem: &TypeElement,
    ) {
        if kind != ElementKind::Class {
            self.ctx.messager().print_error(&format!(
                "@{} can only be applied to fields in a class",
                annot_type_simple_name
            ));
        } else if !self.ctx.is_subclass(type_elem, self.ctx.db_annotated_object_elem()) {
            self.ctx.messager().print_error(&format!(
                "@{} can only be applied within a subclass of {}",
                annot_type_simple_name,
                self.ctx.db_annotated_object_elem().name
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::database::annotproc::{JavaType, Messager, TypeOracle};
    use std::cell::RefCell;

    /// A `TypeOracle` over a small fixed hierarchy: `com.example.GoodObject` extends
    /// `ghidra.util.database.DBAnnotatedObject`; `com.example.BadObject` does not.
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
            sub_elem.name == "com.example.GoodObject"
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

    fn validator() -> (AbstractDBAnnotationValidator, std::rc::Rc<CapturingMessager>) {
        // ValidationContext owns its Messager as a `Box<dyn Messager>`, so route captured
        // messages out through a shared `Rc` the boxed messager forwards into.
        struct ForwardingMessager(std::rc::Rc<CapturingMessager>);
        impl Messager for ForwardingMessager {
            fn print_error(&self, message: &str) {
                self.0.print_error(message);
            }
        }

        let inner = std::rc::Rc::new(CapturingMessager::new());
        let ctx = ValidationContext::new(
            Box::new(MockTypeOracle),
            Box::new(ForwardingMessager(inner.clone())),
        );
        (AbstractDBAnnotationValidator::new(ctx), inner)
    }

    #[test]
    fn non_class_kind_reports_class_only_error() {
        let (validator, messager) = validator();
        let type_elem = TypeElement::new("com.example.SomeInterface");

        validator.check_enclosing_type("MyAnnotation", ElementKind::Other, &type_elem);

        let messages = messager.messages.borrow();
        assert_eq!(messages.len(), 1);
        assert_eq!(
            messages[0],
            "@MyAnnotation can only be applied to fields in a class"
        );
    }

    #[test]
    fn class_not_a_dbannotatedobject_subclass_reports_subclass_error() {
        let (validator, messager) = validator();
        let type_elem = TypeElement::new("com.example.BadObject");

        validator.check_enclosing_type("MyAnnotation", ElementKind::Class, &type_elem);

        let messages = messager.messages.borrow();
        assert_eq!(messages.len(), 1);
        assert_eq!(
            messages[0],
            "@MyAnnotation can only be applied within a subclass of ghidra.util.database.DBAnnotatedObject"
        );
    }

    #[test]
    fn class_that_is_a_dbannotatedobject_subclass_reports_nothing() {
        let (validator, messager) = validator();
        let type_elem = TypeElement::new("com.example.GoodObject");

        validator.check_enclosing_type("MyAnnotation", ElementKind::Class, &type_elem);

        assert!(messager.messages.borrow().is_empty());
    }

    #[test]
    fn ctx_field_is_reachable_for_subclass_equivalent_composition() {
        // Mirrors `protected final ValidationContext ctx` being accessible to Java subclasses;
        // a Rust "subclass" embeds this struct and can reach `ctx` directly.
        let (validator, _messager) = validator();
        assert_eq!(validator.ctx.enum_elem().name, "java.lang.Enum");
    }
}

pub mod abstract_db_annotation_validator;
pub mod access_spec;
pub mod validation_context;

pub use abstract_db_annotation_validator::{AbstractDBAnnotationValidator, ElementKind};
pub use access_spec::AccessSpec;
pub use validation_context::{
    format_type, JavaType, Messager, NoopMessager, TypeElement, TypeOracle, ValidationContext,
    VariableElement,
};

/// Mirrors `javax.lang.model.element.Modifier` for access-specifier determination.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Modifier {
    Public,
    Protected,
    Private,
    Abstract,
    Default,
    Static,
    Final,
    Transient,
    Volatile,
    Synchronized,
    Native,
    StrictFp,
}

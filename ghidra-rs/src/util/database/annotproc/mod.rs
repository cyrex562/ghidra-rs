pub mod access_spec;

pub use access_spec::AccessSpec;

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

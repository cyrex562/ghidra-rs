use std::borrow::Cow;

/// Transforms names of data types, functions, and namespaces for display.
///
/// This mirrors Ghidra's `NameTransformer` interface.
pub trait NameTransformer {
    /// Returns a transformed version of the input.
    fn simplify<'a>(&self, input: &'a str) -> Cow<'a, str>;
}

/// Transformer that never alters its input.
///
/// This mirrors Ghidra's `IdentityNameTransformer`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct IdentityNameTransformer;

impl NameTransformer for IdentityNameTransformer {
    fn simplify<'a>(&self, input: &'a str) -> Cow<'a, str> {
        Cow::Borrowed(input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_transformer_returns_input_unchanged() {
        let transformer = IdentityNameTransformer;

        assert_eq!(transformer.simplify("std::vector<int>").as_ref(), "std::vector<int>");
        assert_eq!(transformer.simplify("").as_ref(), "");
    }

    #[test]
    fn transformer_trait_can_be_used_dynamically() {
        let transformer: &dyn NameTransformer = &IdentityNameTransformer;

        assert_eq!(transformer.simplify("Namespace::Function").as_ref(), "Namespace::Function");
    }
}

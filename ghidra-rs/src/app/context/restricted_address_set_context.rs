/// Marker trait for `Navigatable` contexts that don't support navigating to the entire
/// program. Typically, these are used by providers that show only one function at a time such
/// as the Decompiler.
///
/// Port of `ghidra.app.context.RestrictedAddressSetContext`.
pub trait RestrictedAddressSetContext {
    // marker interface
}

#[cfg(test)]
mod tests {
    use super::*;

    struct SingleFunctionContext;

    impl RestrictedAddressSetContext for SingleFunctionContext {}

    /// Mirrors `NavigatableContextAction.isValidContext`, which special-cases actions that
    /// don't support `RestrictedAddressSetContext` by checking `instanceof`.
    fn supports_restricted_context(
        context: Option<&dyn RestrictedAddressSetContext>,
        supports_restricted: bool,
    ) -> bool {
        supports_restricted || context.is_none()
    }

    #[test]
    fn restricted_context_only_allowed_when_supported() {
        let restricted: Box<dyn RestrictedAddressSetContext> = Box::new(SingleFunctionContext);

        // An action that doesn't support restricted contexts rejects one.
        assert!(!supports_restricted_context(Some(restricted.as_ref()), false));
        // ...but accepts it once the action declares support.
        assert!(supports_restricted_context(Some(restricted.as_ref()), true));
        // Unrestricted (whole-program) contexts are never rejected on this basis.
        assert!(supports_restricted_context(None, false));
    }
}

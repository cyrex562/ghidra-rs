//! A sub-scope for local variable declarations.
//!
//! Port of `ghidra.pcode.emu.jit.gen.util.SubScope`.

use crate::pcode::seam_stubs::Scope;

/// A sub-scope for local variable declarations.
///
/// Corresponds to `ghidra.pcode.emu.jit.gen.util.SubScope`.
pub trait SubScope: Scope {
    /// Close this sub-scope, releasing associated resources.
    fn close(&mut self);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockSubScope;

    impl Scope for MockSubScope {}

    impl SubScope for MockSubScope {
        fn close(&mut self) {
            // Mock implementation: no-op for testing
        }
    }

    #[test]
    fn test_sub_scope_close() {
        let mut scope = MockSubScope;
        scope.close(); // Should not panic
    }

    #[test]
    fn test_sub_scope_trait_object() {
        let mut scope: Box<dyn SubScope> = Box::new(MockSubScope);
        scope.close(); // Should not panic
    }
}

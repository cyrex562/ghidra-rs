//! A container for the pieces of a decompiled function.

/// Holds the decompiled output of a single function.
///
/// Corresponds to `ghidra.app.decompiler.DecompiledFunction`.
#[derive(Debug, Clone)]
pub struct DecompiledFunction {
    signature: String,
    c: String,
}

impl DecompiledFunction {
    /// Creates a new `DecompiledFunction`.
    ///
    /// # Arguments
    /// * `signature` - The function signature or prototype (e.g. `"int foo(double d)"`)
    /// * `c` - The complete C code of the function
    pub fn new(signature: impl Into<String>, c: impl Into<String>) -> Self {
        Self {
            signature: signature.into(),
            c: c.into(),
        }
    }

    /// Returns the function signature or prototype (e.g. `"int foo(double d)"`).
    pub fn signature(&self) -> &str {
        &self.signature
    }

    /// Returns the complete C code of the function.
    pub fn c(&self) -> &str {
        &self.c
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_stores_fields() {
        let f = DecompiledFunction::new("int foo(double d)", "int foo(double d) { return 0; }");
        assert_eq!(f.signature(), "int foo(double d)");
        assert_eq!(f.c(), "int foo(double d) { return 0; }");
    }

    #[test]
    fn test_empty_fields() {
        let f = DecompiledFunction::new("", "");
        assert_eq!(f.signature(), "");
        assert_eq!(f.c(), "");
    }

    #[test]
    fn test_clone_preserves_fields() {
        let f = DecompiledFunction::new("void bar()", "void bar() {}");
        let cloned = f.clone();
        assert_eq!(cloned.signature(), f.signature());
        assert_eq!(cloned.c(), f.c());
    }
}

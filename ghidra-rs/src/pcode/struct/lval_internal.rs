/// Corresponds to `ghidra.pcode.struct.LValInternal`.
///
/// A value which can be used on either side of an assignment, with support for structured access
/// patterns (field and array indexing) as well as in-place modifications.
///
/// This trait extends both LVal (from StructuredSleigh) and RValInternal to provide a complete
/// interface for assignable values in structured Sleigh code generation.
pub trait LValInternal:
    crate::pcode::seam_stubs::LVal + crate::pcode::r#struct::rval_internal::RValInternal
{
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lval_internal_trait_exists() {
        // Smoke test: verify the trait is properly defined and can be referenced.
        // This test passes if the module compiles successfully.
    }
}

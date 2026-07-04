use crate::program::seam_stubs::{CompositeInternal, Union};

/// Marker trait for `Union` implementations that are internal to the data type
/// manager (as opposed to externally-supplied implementations).
///
/// Port of `ghidra.program.model.data.UnionInternal`.
pub trait UnionInternal: Union + CompositeInternal {}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockUnion;

    impl Union for MockUnion {}
    impl CompositeInternal for MockUnion {}
    impl UnionInternal for MockUnion {}

    #[test]
    fn usable_as_trait_object() {
        let u = MockUnion;
        let _dyn_union: &dyn UnionInternal = &u;
    }
}

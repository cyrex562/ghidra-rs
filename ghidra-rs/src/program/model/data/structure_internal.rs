use crate::program::model::data::composite::Composite;
use crate::program::model::data::structure::Structure;
use crate::program::seam_stubs::CompositeInternal;

/// Marker trait for `Structure` implementations that are internal to the data type
/// manager (as opposed to externally-supplied implementations).
///
/// Port of `ghidra.program.model.data.StructureInternal`.
pub trait StructureInternal: Structure + CompositeInternal {}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockStructure;

    impl crate::program::model::data::data_type::DataType for MockStructure {}
    impl Composite for MockStructure {}
    impl Structure for MockStructure {}
    impl CompositeInternal for MockStructure {}
    impl StructureInternal for MockStructure {}

    #[test]
    fn usable_as_trait_object() {
        let s = MockStructure;
        let _dyn_struct: &dyn StructureInternal = &s;
    }
}

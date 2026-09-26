use std::vec::Vec;

use crate::app::util::bin::struct_converter::StructConverter;
use crate::program::model::data::category_path::CategoryPath;

pub const CATEGORY: &str = "/SwiftTypeMetadata";
pub static CATEGORY_PATH: once_cell::sync::Lazy<CategoryPath> =
    once_cell::sync::Lazy::new(|| CategoryPath::parse(CATEGORY).expect("valid category path"));

/// Implemented by all Swift type metadata structures.
///
/// Port of the abstract class `ghidra.app.util.bin.format.swift.SwiftTypeMetadataStructure`.
pub trait SwiftTypeMetadataStructure: StructConverter {
    /// Returns the name of this `SwiftTypeMetadataStructure`.
    fn get_structure_name(&self) -> String;

    /// Returns a short description of this `SwiftTypeMetadataStructure`.
    fn get_description(&self) -> String;

    /// Returns a list of `SwiftTypeMetadataStructure`s that trail this structure.
    fn get_trailing_objects(&self) -> Vec<Box<dyn SwiftTypeMetadataStructure>> {
        Vec::new()
    }
}

/// Shared state for `SwiftTypeMetadataStructure` implementations.
///
/// Holds the `base` field and provides the concrete methods from the abstract Java class.
/// This struct is meant to be embedded in concrete implementations that provide the abstract
/// methods via the `SwiftTypeMetadataStructure` trait.
#[derive(Debug, Clone)]
pub struct SwiftTypeMetadataStructureBase {
    base: i64,
}

impl SwiftTypeMetadataStructureBase {
    /// Creates a new `SwiftTypeMetadataStructureBase` with the given base address.
    pub fn new(base: i64) -> Self {
        SwiftTypeMetadataStructureBase { base }
    }

    /// Returns the base "address" of this structure.
    pub fn get_base(&self) -> i64 {
        self.base
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_struct_stores_and_retrieves_base() {
        let base_val = 0x1000i64;
        let base_struct = SwiftTypeMetadataStructureBase::new(base_val);
        assert_eq!(base_struct.get_base(), base_val);
    }

    #[test]
    fn base_struct_clone_preserves_base() {
        let base_struct = SwiftTypeMetadataStructureBase::new(0x2000i64);
        let cloned = base_struct.clone();
        assert_eq!(base_struct.get_base(), cloned.get_base());
    }

    #[test]
    fn category_path_is_valid() {
        let path = CATEGORY_PATH.clone();
        assert!(!path.get_path().is_empty());
    }
}

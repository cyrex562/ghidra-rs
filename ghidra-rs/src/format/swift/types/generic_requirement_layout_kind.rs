//! Port of `ghidra.app.util.bin.format.swift.types.GenericRequirementLayoutKind`.

use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::swift::swift_type_metadata_structure::CATEGORY_PATH;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::enum_::Enum;
use crate::program::model::data::enum_data_type::EnumDataType;

/// Swift `GenericRequirementLayoutKind` values.
///
/// Port of `ghidra.app.util.bin.format.swift.types.GenericRequirementLayoutKind`.
///
/// See: <https://github.com/swiftlang/swift/blob/main/include/swift/ABI/MetadataValues.h>
///
/// # Deviations from Java
///
/// The Java enum genuinely only declares one constant (`Class(0)`); this is not an
/// under-porting, it mirrors the Java source's own (single-member) `enum` declaration exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GenericRequirementLayoutKind {
    Class,
}

impl GenericRequirementLayoutKind {
    /// All variants, in Java declaration order (mirrors `values()`).
    pub const VALUES: [GenericRequirementLayoutKind; 1] = [GenericRequirementLayoutKind::Class];

    /// Java: `getValue()`.
    pub fn get_value(&self) -> i32 {
        match self {
            GenericRequirementLayoutKind::Class => 0,
        }
    }

    /// The name of this kind, matching Java's `Enum.name()` (used for the `EnumDataType` member
    /// names built by [`to_data_type`](Self::to_data_type)).
    pub fn name(&self) -> &'static str {
        match self {
            GenericRequirementLayoutKind::Class => "Class",
        }
    }

    /// Java: `static GenericRequirementLayoutKind valueOf(int value)`, `return
    /// Arrays.stream(values()).filter(e -> e.getValue() == value).findFirst().orElse(null);`.
    pub fn value_of(value: i32) -> Option<Self> {
        Self::VALUES.iter().copied().find(|k| k.get_value() == value)
    }
}

impl StructConverter for GenericRequirementLayoutKind {
    /// Java: `toDataType()`. Note this builds a 1-byte enum datatype named
    /// `GenericRequirementLayoutKind` with one member per variant, independent of which
    /// particular `self` variant `to_data_type` was called on -- matching Java's identical
    /// behavior (the instance is only used to reach the shared `values()`/category machinery).
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        let mut dt = EnumDataType::new_in_category(
            CATEGORY_PATH.clone(),
            "GenericRequirementLayoutKind".to_string(),
            1,
        );
        for kind in Self::VALUES {
            dt.add(kind.name(), kind.get_value() as i64);
        }
        Ok(Box::new(dt))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_value_matches_java_declared_value() {
        assert_eq!(GenericRequirementLayoutKind::Class.get_value(), 0);
    }

    #[test]
    fn value_of_resolves_the_declared_value() {
        assert_eq!(GenericRequirementLayoutKind::value_of(0), Some(GenericRequirementLayoutKind::Class));
    }

    #[test]
    fn value_of_unknown_value_is_none() {
        assert_eq!(GenericRequirementLayoutKind::value_of(1), None);
        assert_eq!(GenericRequirementLayoutKind::value_of(-1), None);
    }

    #[test]
    fn to_data_type_builds_one_byte_enum_with_the_single_member() {
        let dt = GenericRequirementLayoutKind::Class.to_data_type().unwrap();
        assert_eq!(dt.get_name(), "GenericRequirementLayoutKind");
        assert_eq!(dt.get_length(), 1);
    }

    #[test]
    fn enum_values_match_get_value_per_kind() {
        let mut dt = EnumDataType::new_in_category(
            CATEGORY_PATH.clone(),
            "GenericRequirementLayoutKind".to_string(),
            1,
        );
        for kind in GenericRequirementLayoutKind::VALUES {
            dt.add(kind.name(), kind.get_value() as i64);
        }
        assert_eq!(dt.get_value_for_name("Class"), Some(0));
    }
}

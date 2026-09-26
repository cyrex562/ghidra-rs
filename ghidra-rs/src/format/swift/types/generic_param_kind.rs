//! Port of `ghidra.app.util.bin.format.swift.types.GenericParamKind`.

use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::swift::swift_type_metadata_structure::CATEGORY_PATH;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::enum_::Enum;
use crate::program::model::data::enum_data_type::EnumDataType;

/// Swift `GenericParamKind` values.
///
/// Port of `ghidra.app.util.bin.format.swift.types.GenericParamKind`.
///
/// See: <https://github.com/swiftlang/swift/blob/main/include/swift/ABI/MetadataValues.h>
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GenericParamKind {
    Type,
    TypePack,
    Value,
}

impl GenericParamKind {
    /// All variants, in Java declaration order (mirrors `values()`).
    pub const VALUES: [GenericParamKind; 3] =
        [GenericParamKind::Type, GenericParamKind::TypePack, GenericParamKind::Value];

    /// Java: `getValue()`.
    pub fn get_value(&self) -> i32 {
        match self {
            GenericParamKind::Type => 0,
            GenericParamKind::TypePack => 1,
            GenericParamKind::Value => 2,
        }
    }

    /// The name of this kind, matching Java's `Enum.name()` (used for the `EnumDataType` member
    /// names built by [`to_data_type`](Self::to_data_type)).
    pub fn name(&self) -> &'static str {
        match self {
            GenericParamKind::Type => "Type",
            GenericParamKind::TypePack => "TypePack",
            GenericParamKind::Value => "Value",
        }
    }

    /// Java: `static GenericParamKind valueOf(int value)`, `return
    /// Arrays.stream(values()).filter(e -> e.getValue() == value).findFirst().orElse(null);`.
    pub fn value_of(value: i32) -> Option<Self> {
        Self::VALUES.iter().copied().find(|k| k.get_value() == value)
    }
}

impl StructConverter for GenericParamKind {
    /// Java: `toDataType()`. Note this builds a 1-byte enum datatype named `GenericParamKind`
    /// with one member per variant, independent of which particular `self` variant `to_data_type`
    /// was called on -- matching Java's identical behavior (the instance is only used to reach the
    /// shared `values()`/category machinery).
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        let mut dt =
            EnumDataType::new_in_category(CATEGORY_PATH.clone(), "GenericParamKind".to_string(), 1);
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
    fn get_value_matches_java_declared_values() {
        assert_eq!(GenericParamKind::Type.get_value(), 0);
        assert_eq!(GenericParamKind::TypePack.get_value(), 1);
        assert_eq!(GenericParamKind::Value.get_value(), 2);
    }

    #[test]
    fn value_of_resolves_every_declared_value() {
        for kind in GenericParamKind::VALUES {
            assert_eq!(GenericParamKind::value_of(kind.get_value()), Some(kind));
        }
    }

    #[test]
    fn value_of_unknown_value_is_none() {
        assert_eq!(GenericParamKind::value_of(3), None);
        assert_eq!(GenericParamKind::value_of(-1), None);
    }

    #[test]
    fn name_matches_variant_names() {
        assert_eq!(GenericParamKind::Type.name(), "Type");
        assert_eq!(GenericParamKind::TypePack.name(), "TypePack");
        assert_eq!(GenericParamKind::Value.name(), "Value");
    }

    #[test]
    fn to_data_type_builds_one_byte_enum_with_every_member() {
        let dt = GenericParamKind::Type.to_data_type().unwrap();
        assert_eq!(dt.get_name(), "GenericParamKind");
        assert_eq!(dt.get_length(), 1);

        // Calling on a different variant still builds the same full enum -- see the docs.
        let dt2 = GenericParamKind::Value.to_data_type().unwrap();
        assert_eq!(dt2.get_name(), "GenericParamKind");
        assert_eq!(dt2.get_length(), 1);
    }

    #[test]
    fn enum_values_match_get_value_per_kind() {
        let mut dt =
            EnumDataType::new_in_category(CATEGORY_PATH.clone(), "GenericParamKind".to_string(), 1);
        for kind in GenericParamKind::VALUES {
            dt.add(kind.name(), kind.get_value() as i64);
        }
        assert_eq!(dt.get_value_for_name("Type"), Some(0));
        assert_eq!(dt.get_value_for_name("TypePack"), Some(1));
        assert_eq!(dt.get_value_for_name("Value"), Some(2));
    }
}

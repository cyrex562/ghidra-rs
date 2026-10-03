//! Port of `ghidra.app.util.bin.format.swift.types.TypeReferenceKind`.

use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::swift::swift_type_metadata_structure::CATEGORY_PATH;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::enum_::Enum;
use crate::program::model::data::enum_data_type::EnumDataType;

/// Swift `TypeReferenceKind` values.
///
/// Port of `ghidra.app.util.bin.format.swift.types.TypeReferenceKind`.
///
/// See: <https://github.com/swiftlang/swift/blob/main/include/swift/ABI/MetadataValues.h>
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TypeReferenceKind {
    DirectTypeDescriptor,
    IndirectTypeDescriptor,
    DirectObjCClassName,
    IndirectObjCClass,
}

impl TypeReferenceKind {
    /// All variants, in Java declaration order (mirrors `values()`).
    pub const VALUES: [TypeReferenceKind; 4] = [
        TypeReferenceKind::DirectTypeDescriptor,
        TypeReferenceKind::IndirectTypeDescriptor,
        TypeReferenceKind::DirectObjCClassName,
        TypeReferenceKind::IndirectObjCClass,
    ];

    /// Java: `getValue()`.
    pub fn get_value(&self) -> i32 {
        match self {
            TypeReferenceKind::DirectTypeDescriptor => 0,
            TypeReferenceKind::IndirectTypeDescriptor => 1,
            TypeReferenceKind::DirectObjCClassName => 2,
            TypeReferenceKind::IndirectObjCClass => 3,
        }
    }

    /// The name of this kind, matching Java's `Enum.name()` (used for the `EnumDataType` member
    /// names built by [`to_data_type`](Self::to_data_type)).
    pub fn name(&self) -> &'static str {
        match self {
            TypeReferenceKind::DirectTypeDescriptor => "DirectTypeDescriptor",
            TypeReferenceKind::IndirectTypeDescriptor => "IndirectTypeDescriptor",
            TypeReferenceKind::DirectObjCClassName => "DirectObjCClassName",
            TypeReferenceKind::IndirectObjCClass => "IndirectObjCClass",
        }
    }

    /// Java: `static TypeReferenceKind valueOf(int value)`, `return
    /// Arrays.stream(values()).filter(e -> e.getValue() == value).findFirst().orElse(null);`.
    pub fn value_of(value: i32) -> Option<Self> {
        Self::VALUES.iter().copied().find(|k| k.get_value() == value)
    }
}

impl StructConverter for TypeReferenceKind {
    /// Java: `toDataType()`. Note this builds a 1-byte enum datatype named `TypeReferenceKind`
    /// with one member per variant, independent of which particular `self` variant
    /// `to_data_type` was called on -- matching Java's identical behavior (the instance is only
    /// used to reach the shared `values()`/category machinery).
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        let mut dt = EnumDataType::new_in_category(
            CATEGORY_PATH.clone(),
            "TypeReferenceKind".to_string(),
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
    fn get_value_matches_java_declared_values() {
        assert_eq!(TypeReferenceKind::DirectTypeDescriptor.get_value(), 0);
        assert_eq!(TypeReferenceKind::IndirectTypeDescriptor.get_value(), 1);
        assert_eq!(TypeReferenceKind::DirectObjCClassName.get_value(), 2);
        assert_eq!(TypeReferenceKind::IndirectObjCClass.get_value(), 3);
    }

    #[test]
    fn value_of_resolves_every_declared_value() {
        for kind in TypeReferenceKind::VALUES {
            assert_eq!(TypeReferenceKind::value_of(kind.get_value()), Some(kind));
        }
    }

    #[test]
    fn value_of_unknown_value_is_none() {
        assert_eq!(TypeReferenceKind::value_of(4), None);
        assert_eq!(TypeReferenceKind::value_of(-1), None);
    }

    #[test]
    fn to_data_type_builds_one_byte_enum_with_every_member() {
        let dt = TypeReferenceKind::DirectTypeDescriptor.to_data_type().unwrap();
        assert_eq!(dt.get_name(), "TypeReferenceKind");
        assert_eq!(dt.get_length(), 1);

        // Calling on a different variant still builds the same full enum -- see the docs.
        let dt2 = TypeReferenceKind::IndirectObjCClass.to_data_type().unwrap();
        assert_eq!(dt2.get_name(), "TypeReferenceKind");
        assert_eq!(dt2.get_length(), 1);
    }

    #[test]
    fn enum_values_match_get_value_per_kind() {
        let mut dt = EnumDataType::new_in_category(
            CATEGORY_PATH.clone(),
            "TypeReferenceKind".to_string(),
            1,
        );
        for kind in TypeReferenceKind::VALUES {
            dt.add(kind.name(), kind.get_value() as i64);
        }
        assert_eq!(dt.get_value_for_name("DirectTypeDescriptor"), Some(0));
        assert_eq!(dt.get_value_for_name("IndirectObjCClass"), Some(3));
    }
}

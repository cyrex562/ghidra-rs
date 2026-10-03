//! Port of `ghidra.app.util.bin.format.swift.types.ContextDescriptorKind`.

use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::swift::swift_type_metadata_structure::CATEGORY_PATH;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::enum_::Enum;
use crate::program::model::data::enum_data_type::EnumDataType;

/// Swift `ContextDescriptorKind` values.
///
/// Port of `ghidra.app.util.bin.format.swift.types.ContextDescriptorKind`.
///
/// See: <https://github.com/swiftlang/swift/blob/main/include/swift/ABI/MetadataValues.h>
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ContextDescriptorKind {
    /// This context descriptor represents a module.
    Module,
    /// This context descriptor represents an extension.
    Extension,
    /// This context descriptor represents an anonymous possibly-generic context such as a
    /// function body.
    Anonymous,
    /// This context descriptor represents a protocol context.
    Protocol,
    /// This context descriptor represents an opaque type alias.
    OpaqueType,
    /// This context descriptor represents a class.
    Class,
    /// This context descriptor represents a struct.
    Struct,
    /// This context descriptor represents an enum.
    Enum,
}

impl ContextDescriptorKind {
    /// All variants, in Java declaration order (mirrors `values()`).
    pub const VALUES: [ContextDescriptorKind; 8] = [
        ContextDescriptorKind::Module,
        ContextDescriptorKind::Extension,
        ContextDescriptorKind::Anonymous,
        ContextDescriptorKind::Protocol,
        ContextDescriptorKind::OpaqueType,
        ContextDescriptorKind::Class,
        ContextDescriptorKind::Struct,
        ContextDescriptorKind::Enum,
    ];

    /// Java: `getValue()`.
    pub fn get_value(&self) -> i32 {
        match self {
            ContextDescriptorKind::Module => 0,
            ContextDescriptorKind::Extension => 1,
            ContextDescriptorKind::Anonymous => 2,
            ContextDescriptorKind::Protocol => 3,
            ContextDescriptorKind::OpaqueType => 4,
            ContextDescriptorKind::Class => 16,
            ContextDescriptorKind::Struct => 17,
            ContextDescriptorKind::Enum => 18,
        }
    }

    /// The name of this kind, matching Java's `Enum.name()` (used for the `EnumDataType` member
    /// names built by [`to_data_type`](Self::to_data_type)).
    pub fn name(&self) -> &'static str {
        match self {
            ContextDescriptorKind::Module => "Module",
            ContextDescriptorKind::Extension => "Extension",
            ContextDescriptorKind::Anonymous => "Anonymous",
            ContextDescriptorKind::Protocol => "Protocol",
            ContextDescriptorKind::OpaqueType => "OpaqueType",
            ContextDescriptorKind::Class => "Class",
            ContextDescriptorKind::Struct => "Struct",
            ContextDescriptorKind::Enum => "Enum",
        }
    }

    /// Java: `static ContextDescriptorKind valueOf(int value)`, `return
    /// Arrays.stream(values()).filter(e -> e.getValue() == value).findFirst().orElse(null);`.
    pub fn value_of(value: i32) -> Option<Self> {
        Self::VALUES.iter().copied().find(|k| k.get_value() == value)
    }
}

impl StructConverter for ContextDescriptorKind {
    /// Java: `toDataType()`. Note this builds a 1-byte enum datatype named
    /// `ContextDescriptorKind` with one member per variant, independent of which particular
    /// `self` variant `to_data_type` was called on -- matching Java's identical behavior (the
    /// instance is only used to reach the shared `values()`/category machinery).
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        let mut dt = EnumDataType::new_in_category(
            CATEGORY_PATH.clone(),
            "ContextDescriptorKind".to_string(),
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
        assert_eq!(ContextDescriptorKind::Module.get_value(), 0);
        assert_eq!(ContextDescriptorKind::Extension.get_value(), 1);
        assert_eq!(ContextDescriptorKind::Anonymous.get_value(), 2);
        assert_eq!(ContextDescriptorKind::Protocol.get_value(), 3);
        assert_eq!(ContextDescriptorKind::OpaqueType.get_value(), 4);
        assert_eq!(ContextDescriptorKind::Class.get_value(), 16);
        assert_eq!(ContextDescriptorKind::Struct.get_value(), 17);
        assert_eq!(ContextDescriptorKind::Enum.get_value(), 18);
    }

    #[test]
    fn value_of_resolves_every_declared_value() {
        for kind in ContextDescriptorKind::VALUES {
            assert_eq!(ContextDescriptorKind::value_of(kind.get_value()), Some(kind));
        }
    }

    #[test]
    fn value_of_unknown_value_is_none() {
        // 5..=15 is a real gap between OpaqueType(4) and Class(16) -- nothing maps to it.
        assert_eq!(ContextDescriptorKind::value_of(5), None);
        assert_eq!(ContextDescriptorKind::value_of(15), None);
        assert_eq!(ContextDescriptorKind::value_of(19), None);
        assert_eq!(ContextDescriptorKind::value_of(-1), None);
    }

    #[test]
    fn to_data_type_builds_one_byte_enum_with_every_member() {
        let dt = ContextDescriptorKind::Module.to_data_type().unwrap();
        assert_eq!(dt.get_name(), "ContextDescriptorKind");
        assert_eq!(dt.get_length(), 1);

        // Calling on a different variant still builds the same full enum -- see the docs.
        let dt2 = ContextDescriptorKind::Enum.to_data_type().unwrap();
        assert_eq!(dt2.get_name(), "ContextDescriptorKind");
        assert_eq!(dt2.get_length(), 1);
    }

    #[test]
    fn enum_values_match_get_value_per_kind() {
        let mut dt = EnumDataType::new_in_category(
            CATEGORY_PATH.clone(),
            "ContextDescriptorKind".to_string(),
            1,
        );
        for kind in ContextDescriptorKind::VALUES {
            dt.add(kind.name(), kind.get_value() as i64);
        }
        assert_eq!(dt.get_value_for_name("Module"), Some(0));
        assert_eq!(dt.get_value_for_name("Class"), Some(16));
        assert_eq!(dt.get_value_for_name("Enum"), Some(18));
    }
}

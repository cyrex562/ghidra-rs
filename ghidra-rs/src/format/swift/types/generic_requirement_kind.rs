//! Port of `ghidra.app.util.bin.format.swift.types.GenericRequirementKind`.

use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::swift::swift_type_metadata_structure::CATEGORY_PATH;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::enum_::Enum;
use crate::program::model::data::enum_data_type::EnumDataType;

/// Swift `GenericRequirementKind` values.
///
/// Port of `ghidra.app.util.bin.format.swift.types.GenericRequirementKind`.
///
/// See: <https://github.com/swiftlang/swift/blob/main/include/swift/ABI/MetadataValues.h>
///
/// # Deviations from Java
///
/// `IntertedProtocol` is a verbatim typo in the Java source (evidently meant to read
/// "InvertedProtocol", matching the `InvertibleProtocolKind` values this kind is otherwise
/// consistent with). Preserved exactly, including the typo, per this crate's convention of
/// faithfully reproducing such Java-source quirks rather than silently fixing them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GenericRequirementKind {
    Protocol,
    SameType,
    BaseClass,
    SameConformance,
    SameShape,
    /// Verbatim Java-source typo for "InvertedProtocol" -- see the enum docs.
    IntertedProtocol,
    Layout,
}

impl GenericRequirementKind {
    /// All variants, in Java declaration order (mirrors `values()`).
    pub const VALUES: [GenericRequirementKind; 7] = [
        GenericRequirementKind::Protocol,
        GenericRequirementKind::SameType,
        GenericRequirementKind::BaseClass,
        GenericRequirementKind::SameConformance,
        GenericRequirementKind::SameShape,
        GenericRequirementKind::IntertedProtocol,
        GenericRequirementKind::Layout,
    ];

    /// Java: `getValue()`.
    pub fn get_value(&self) -> i32 {
        match self {
            GenericRequirementKind::Protocol => 0,
            GenericRequirementKind::SameType => 1,
            GenericRequirementKind::BaseClass => 2,
            GenericRequirementKind::SameConformance => 3,
            GenericRequirementKind::SameShape => 4,
            GenericRequirementKind::IntertedProtocol => 5,
            GenericRequirementKind::Layout => 0x1f,
        }
    }

    /// The name of this kind, matching Java's `Enum.name()` (used for the `EnumDataType` member
    /// names built by [`to_data_type`](Self::to_data_type)).
    pub fn name(&self) -> &'static str {
        match self {
            GenericRequirementKind::Protocol => "Protocol",
            GenericRequirementKind::SameType => "SameType",
            GenericRequirementKind::BaseClass => "BaseClass",
            GenericRequirementKind::SameConformance => "SameConformance",
            GenericRequirementKind::SameShape => "SameShape",
            GenericRequirementKind::IntertedProtocol => "IntertedProtocol",
            GenericRequirementKind::Layout => "Layout",
        }
    }

    /// Java: `static GenericRequirementKind valueOf(int value)`, `return
    /// Arrays.stream(values()).filter(e -> e.getValue() == value).findFirst().orElse(null);`.
    pub fn value_of(value: i32) -> Option<Self> {
        Self::VALUES.iter().copied().find(|k| k.get_value() == value)
    }
}

impl StructConverter for GenericRequirementKind {
    /// Java: `toDataType()`. Note this builds a 1-byte enum datatype named
    /// `GenericRequirementKind` with one member per variant, independent of which particular
    /// `self` variant `to_data_type` was called on -- matching Java's identical behavior (the
    /// instance is only used to reach the shared `values()`/category machinery).
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        let mut dt = EnumDataType::new_in_category(
            CATEGORY_PATH.clone(),
            "GenericRequirementKind".to_string(),
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
        assert_eq!(GenericRequirementKind::Protocol.get_value(), 0);
        assert_eq!(GenericRequirementKind::SameType.get_value(), 1);
        assert_eq!(GenericRequirementKind::BaseClass.get_value(), 2);
        assert_eq!(GenericRequirementKind::SameConformance.get_value(), 3);
        assert_eq!(GenericRequirementKind::SameShape.get_value(), 4);
        assert_eq!(GenericRequirementKind::IntertedProtocol.get_value(), 5);
        assert_eq!(GenericRequirementKind::Layout.get_value(), 0x1f);
    }

    #[test]
    fn value_of_resolves_every_declared_value() {
        for kind in GenericRequirementKind::VALUES {
            assert_eq!(GenericRequirementKind::value_of(kind.get_value()), Some(kind));
        }
    }

    #[test]
    fn value_of_unknown_value_is_none() {
        // 5 (IntertedProtocol) to 0x1f (Layout) is a real gap -- nothing maps to it.
        assert_eq!(GenericRequirementKind::value_of(6), None);
        assert_eq!(GenericRequirementKind::value_of(-1), None);
    }

    #[test]
    fn name_preserves_the_verbatim_java_typo() {
        assert_eq!(GenericRequirementKind::IntertedProtocol.name(), "IntertedProtocol");
    }

    #[test]
    fn to_data_type_builds_one_byte_enum_with_every_member() {
        let dt = GenericRequirementKind::Protocol.to_data_type().unwrap();
        assert_eq!(dt.get_name(), "GenericRequirementKind");
        assert_eq!(dt.get_length(), 1);

        // Calling on a different variant still builds the same full enum -- see the docs.
        let dt2 = GenericRequirementKind::Layout.to_data_type().unwrap();
        assert_eq!(dt2.get_name(), "GenericRequirementKind");
        assert_eq!(dt2.get_length(), 1);
    }

    #[test]
    fn enum_values_match_get_value_per_kind() {
        let mut dt = EnumDataType::new_in_category(
            CATEGORY_PATH.clone(),
            "GenericRequirementKind".to_string(),
            1,
        );
        for kind in GenericRequirementKind::VALUES {
            dt.add(kind.name(), kind.get_value() as i64);
        }
        assert_eq!(dt.get_value_for_name("Protocol"), Some(0));
        assert_eq!(dt.get_value_for_name("Layout"), Some(0x1f));
        assert_eq!(dt.get_value_for_name("IntertedProtocol"), Some(5));
    }
}

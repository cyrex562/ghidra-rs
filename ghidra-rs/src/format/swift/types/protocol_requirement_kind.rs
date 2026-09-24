//! Port of `ghidra.app.util.bin.format.swift.types.ProtocolRequirementKind`.

use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::swift::swift_type_metadata_structure::CATEGORY_PATH;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::enum_::Enum;
use crate::program::model::data::enum_data_type::EnumDataType;

/// Swift `ProtocolRequirementFlags::Kind` values.
///
/// Port of `ghidra.app.util.bin.format.swift.types.ProtocolRequirementKind`.
///
/// See: <https://github.com/swiftlang/swift/blob/main/include/swift/ABI/MetadataValues.h>
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtocolRequirementKind {
    BaseProtocol,
    Method,
    Init,
    Getter,
    Setter,
    ReadCoroutine,
    ModifyCoroutine,
    AssociatedTypeAccessFunction,
    AssociatedConformanceAccessFunction,
}

impl ProtocolRequirementKind {
    /// All variants, in Java declaration order (mirrors `values()`).
    pub const VALUES: [ProtocolRequirementKind; 9] = [
        ProtocolRequirementKind::BaseProtocol,
        ProtocolRequirementKind::Method,
        ProtocolRequirementKind::Init,
        ProtocolRequirementKind::Getter,
        ProtocolRequirementKind::Setter,
        ProtocolRequirementKind::ReadCoroutine,
        ProtocolRequirementKind::ModifyCoroutine,
        ProtocolRequirementKind::AssociatedTypeAccessFunction,
        ProtocolRequirementKind::AssociatedConformanceAccessFunction,
    ];

    /// Java: `getValue()`.
    pub fn get_value(&self) -> i32 {
        match self {
            ProtocolRequirementKind::BaseProtocol => 0,
            ProtocolRequirementKind::Method => 1,
            ProtocolRequirementKind::Init => 2,
            ProtocolRequirementKind::Getter => 3,
            ProtocolRequirementKind::Setter => 4,
            ProtocolRequirementKind::ReadCoroutine => 5,
            ProtocolRequirementKind::ModifyCoroutine => 6,
            ProtocolRequirementKind::AssociatedTypeAccessFunction => 7,
            ProtocolRequirementKind::AssociatedConformanceAccessFunction => 8,
        }
    }

    /// The name of this kind, matching Java's `Enum.name()`.
    pub fn name(&self) -> &'static str {
        match self {
            ProtocolRequirementKind::BaseProtocol => "BaseProtocol",
            ProtocolRequirementKind::Method => "Method",
            ProtocolRequirementKind::Init => "Init",
            ProtocolRequirementKind::Getter => "Getter",
            ProtocolRequirementKind::Setter => "Setter",
            ProtocolRequirementKind::ReadCoroutine => "ReadCoroutine",
            ProtocolRequirementKind::ModifyCoroutine => "ModifyCoroutine",
            ProtocolRequirementKind::AssociatedTypeAccessFunction => "AssociatedTypeAccessFunction",
            ProtocolRequirementKind::AssociatedConformanceAccessFunction => {
                "AssociatedConformanceAccessFunction"
            }
        }
    }

    /// Java: `static ProtocolRequirementKind valueOf(int value)`; `None` stands in for Java's
    /// `null` when no kind has the given value.
    pub fn value_of(value: i32) -> Option<Self> {
        Self::VALUES.iter().copied().find(|k| k.get_value() == value)
    }
}

impl StructConverter for ProtocolRequirementKind {
    /// Java: `toDataType()`. Builds a 1-byte enum datatype named `ProtocolRequirementKind` with
    /// one member per variant, independent of which variant it is called on (as in Java).
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        let mut dt = EnumDataType::new_in_category(
            CATEGORY_PATH.clone(),
            "ProtocolRequirementKind".to_string(),
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
        for (i, kind) in ProtocolRequirementKind::VALUES.iter().enumerate() {
            assert_eq!(kind.get_value(), i as i32);
        }
        // Note the ordering differs from MethodDescriptorKind: ReadCoroutine precedes Modify.
        assert_eq!(ProtocolRequirementKind::ReadCoroutine.get_value(), 5);
        assert_eq!(ProtocolRequirementKind::ModifyCoroutine.get_value(), 6);
    }

    #[test]
    fn value_of_round_trips_and_rejects_unknown() {
        for kind in ProtocolRequirementKind::VALUES {
            assert_eq!(ProtocolRequirementKind::value_of(kind.get_value()), Some(kind));
        }
        assert_eq!(ProtocolRequirementKind::value_of(9), None);
        assert_eq!(ProtocolRequirementKind::value_of(15), None);
    }

    #[test]
    fn to_data_type_builds_one_byte_enum_with_every_member() {
        let dt = ProtocolRequirementKind::Method.to_data_type().unwrap();
        assert_eq!(dt.get_name(), "ProtocolRequirementKind");
        assert_eq!(dt.get_length(), 1);
        let e = dt.as_enum().expect("enum datatype");
        assert_eq!(e.get_value_for_name("BaseProtocol"), Some(0));
        assert_eq!(e.get_value_for_name("AssociatedConformanceAccessFunction"), Some(8));
    }
}

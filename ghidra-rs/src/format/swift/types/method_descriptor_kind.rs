//! Port of `ghidra.app.util.bin.format.swift.types.MethodDescriptorKind`.

use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::swift::swift_type_metadata_structure::CATEGORY_PATH;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::enum_::Enum;
use crate::program::model::data::enum_data_type::EnumDataType;

/// Swift `MethodDescriptorFlags::Kind` values.
///
/// Port of `ghidra.app.util.bin.format.swift.types.MethodDescriptorKind`.
///
/// See: <https://github.com/swiftlang/swift/blob/main/include/swift/ABI/MetadataValues.h>
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MethodDescriptorKind {
    Method,
    Init,
    Getter,
    Setter,
    ModifyCoroutine,
    ReadCoroutine,
}

impl MethodDescriptorKind {
    /// All variants, in Java declaration order (mirrors `values()`).
    pub const VALUES: [MethodDescriptorKind; 6] = [
        MethodDescriptorKind::Method,
        MethodDescriptorKind::Init,
        MethodDescriptorKind::Getter,
        MethodDescriptorKind::Setter,
        MethodDescriptorKind::ModifyCoroutine,
        MethodDescriptorKind::ReadCoroutine,
    ];

    /// Java: `getValue()`.
    pub fn get_value(&self) -> i32 {
        match self {
            MethodDescriptorKind::Method => 0,
            MethodDescriptorKind::Init => 1,
            MethodDescriptorKind::Getter => 2,
            MethodDescriptorKind::Setter => 3,
            MethodDescriptorKind::ModifyCoroutine => 4,
            MethodDescriptorKind::ReadCoroutine => 5,
        }
    }

    /// The name of this kind, matching Java's `Enum.name()`.
    pub fn name(&self) -> &'static str {
        match self {
            MethodDescriptorKind::Method => "Method",
            MethodDescriptorKind::Init => "Init",
            MethodDescriptorKind::Getter => "Getter",
            MethodDescriptorKind::Setter => "Setter",
            MethodDescriptorKind::ModifyCoroutine => "ModifyCoroutine",
            MethodDescriptorKind::ReadCoroutine => "ReadCoroutine",
        }
    }

    /// Java: `static MethodDescriptorKind valueOf(int value)`; `None` stands in for Java's `null`
    /// when no kind has the given value.
    pub fn value_of(value: i32) -> Option<Self> {
        Self::VALUES.iter().copied().find(|k| k.get_value() == value)
    }
}

impl StructConverter for MethodDescriptorKind {
    /// Java: `toDataType()`. Builds a 1-byte enum datatype named `MethodDescriptorKind` with one
    /// member per variant, independent of which variant it is called on (as in Java).
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        let mut dt = EnumDataType::new_in_category(
            CATEGORY_PATH.clone(),
            "MethodDescriptorKind".to_string(),
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
        let expected = [0, 1, 2, 3, 4, 5];
        for (kind, value) in MethodDescriptorKind::VALUES.iter().zip(expected) {
            assert_eq!(kind.get_value(), value);
        }
    }

    #[test]
    fn value_of_round_trips_and_rejects_unknown() {
        for kind in MethodDescriptorKind::VALUES {
            assert_eq!(MethodDescriptorKind::value_of(kind.get_value()), Some(kind));
        }
        assert_eq!(MethodDescriptorKind::value_of(6), None);
        assert_eq!(MethodDescriptorKind::value_of(-1), None);
    }

    #[test]
    fn names_match_java_constants() {
        assert_eq!(MethodDescriptorKind::ModifyCoroutine.name(), "ModifyCoroutine");
        assert_eq!(MethodDescriptorKind::ReadCoroutine.name(), "ReadCoroutine");
    }

    #[test]
    fn to_data_type_builds_one_byte_enum_with_every_member() {
        let dt = MethodDescriptorKind::Getter.to_data_type().unwrap();
        assert_eq!(dt.get_name(), "MethodDescriptorKind");
        assert_eq!(dt.get_length(), 1);
        let e = dt.as_enum().expect("enum datatype");
        assert_eq!(e.get_value_for_name("Method"), Some(0));
        assert_eq!(e.get_value_for_name("ReadCoroutine"), Some(5));
    }
}

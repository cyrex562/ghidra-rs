//! Port of `ghidra.app.util.bin.format.swift.types.InvertibleProtocolKind`.

use std::collections::HashSet;

use crate::app::util::bin::struct_converter::{StructConverter, ToDataTypeError};
use crate::format::swift::swift_type_metadata_structure::CATEGORY_PATH;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::enum_::Enum;
use crate::program::model::data::enum_data_type::EnumDataType;

/// Swift `InvertibleProtocolKind` values.
///
/// Port of `ghidra.app.util.bin.format.swift.types.InvertibleProtocolKind`.
///
/// See: <https://github.com/swiftlang/swift/blob/main/include/swift/ABI/InvertibleProtocols.h>
/// and <https://github.com/swiftlang/swift/blob/main/include/swift/ABI/InvertibleProtocols.def>
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InvertibleProtocolKind {
    Copyable,
    Escapable,
}

impl InvertibleProtocolKind {
    /// All variants, in Java declaration order (mirrors `values()`).
    pub const VALUES: [InvertibleProtocolKind; 2] =
        [InvertibleProtocolKind::Copyable, InvertibleProtocolKind::Escapable];

    /// The bit number that represents the kind.
    ///
    /// Java: `getBit()`.
    pub fn get_bit(&self) -> i32 {
        match self {
            InvertibleProtocolKind::Copyable => 0,
            InvertibleProtocolKind::Escapable => 1,
        }
    }

    /// The name of this kind, matching Java's `Enum.name()` (used for the `EnumDataType` member
    /// names built by [`to_data_type`](Self::to_data_type)).
    pub fn name(&self) -> &'static str {
        match self {
            InvertibleProtocolKind::Copyable => "Copyable",
            InvertibleProtocolKind::Escapable => "Escapable",
        }
    }

    /// Returns the [`HashSet`] of [`InvertibleProtocolKind`]s that map to the given kind value.
    ///
    /// Java: `static Set<InvertibleProtocolKind> valueOf(short value)`.
    pub fn value_of(value: i16) -> HashSet<InvertibleProtocolKind> {
        let mut set = HashSet::new();
        // Java widens `short` to `int` for the shift (`value >> bitPos`); do the same here so bit
        // 15 of a negative value sign-extends identically.
        let widened = value as i32;
        for bit_pos in 0..16 {
            let bit = (widened >> bit_pos) & 0x1;
            if bit != 0 {
                if let Some(kind) = Self::VALUES.iter().find(|k| k.get_bit() == bit_pos) {
                    set.insert(*kind);
                }
            }
        }
        set
    }
}

impl StructConverter for InvertibleProtocolKind {
    /// Java: `toDataType()`. Note this builds a 2-byte enum datatype named
    /// `InvertibleProtocolKind` with one member per variant (bit flags), independent of which
    /// particular `self` variant `to_data_type` was called on -- matching Java's identical
    /// behavior (the instance is only used to reach the shared `values()`/category machinery).
    fn to_data_type(&self) -> Result<Box<dyn DataType>, ToDataTypeError> {
        let mut dt = EnumDataType::new_in_category(
            CATEGORY_PATH.clone(),
            "InvertibleProtocolKind".to_string(),
            2,
        );
        for kind in Self::VALUES {
            dt.add(kind.name(), 1i64 << kind.get_bit());
        }
        Ok(Box::new(dt))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_bit_matches_java_declaration_order() {
        assert_eq!(InvertibleProtocolKind::Copyable.get_bit(), 0);
        assert_eq!(InvertibleProtocolKind::Escapable.get_bit(), 1);
    }

    #[test]
    fn value_of_extracts_set_bits() {
        let set = InvertibleProtocolKind::value_of(0b01);
        assert_eq!(set, HashSet::from([InvertibleProtocolKind::Copyable]));

        let set = InvertibleProtocolKind::value_of(0b10);
        assert_eq!(set, HashSet::from([InvertibleProtocolKind::Escapable]));

        let set = InvertibleProtocolKind::value_of(0b11);
        assert_eq!(
            set,
            HashSet::from([InvertibleProtocolKind::Copyable, InvertibleProtocolKind::Escapable])
        );
    }

    #[test]
    fn value_of_zero_is_empty() {
        assert!(InvertibleProtocolKind::value_of(0).is_empty());
    }

    #[test]
    fn value_of_ignores_bits_with_no_matching_kind() {
        // Bit 5 doesn't correspond to any InvertibleProtocolKind.
        let set = InvertibleProtocolKind::value_of(0b100000);
        assert!(set.is_empty());
    }

    #[test]
    fn value_of_handles_negative_short_via_sign_extended_widening() {
        // -1i16 has every bit set; widened to i32 via sign extension it still has bits 0 and 1
        // set, so both kinds should be extracted (mirroring Java's int-promoted `>>`).
        let set = InvertibleProtocolKind::value_of(-1i16);
        assert_eq!(
            set,
            HashSet::from([InvertibleProtocolKind::Copyable, InvertibleProtocolKind::Escapable])
        );
    }

    #[test]
    fn to_data_type_builds_two_byte_enum_named_after_the_kind() {
        // `to_data_type` returns `Box<dyn DataType>` (the fixed `StructConverter` signature),
        // which only exposes `DataType`'s own name/length accessors, not `Enum`'s member
        // accessors -- checked separately below via the concrete `EnumDataType`.
        let dt = InvertibleProtocolKind::Copyable.to_data_type().unwrap();
        assert_eq!(dt.get_name(), "InvertibleProtocolKind");
        assert_eq!(dt.get_length(), 2);

        let dt = InvertibleProtocolKind::Escapable.to_data_type().unwrap();
        assert_eq!(dt.get_name(), "InvertibleProtocolKind");
        assert_eq!(dt.get_length(), 2);
    }

    #[test]
    fn enum_values_are_bit_shifted_per_kind() {
        let mut dt = EnumDataType::new_in_category(
            CATEGORY_PATH.clone(),
            "InvertibleProtocolKind".to_string(),
            2,
        );
        for kind in InvertibleProtocolKind::VALUES {
            dt.add(kind.name(), 1i64 << kind.get_bit());
        }
        assert_eq!(dt.get_value_for_name("Copyable"), Some(1));
        assert_eq!(dt.get_value_for_name("Escapable"), Some(2));
    }
}

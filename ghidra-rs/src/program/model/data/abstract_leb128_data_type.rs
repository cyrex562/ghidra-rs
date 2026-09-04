//! Port of `ghidra.program.model.data.AbstractLeb128DataType`, promoted to a trait because it
//! was selected as a dependency-cycle cut-point.
//!
//! The Java class `extends BuiltIn implements Dynamic`, so this trait extends both already-ported
//! traits: [`BuiltIn`] and [`Dynamic`] -- mirroring
//! [`AlignmentDataType`](super::alignment_data_type::AlignmentDataType)/
//! [`AIFFDataType`](super::aiff_data_type::AIFFDataType), which document the same shape of
//! `BuiltIn + Dynamic` cut-point in more detail.
//!
//! The private `signed` field (set by the constructor and read by every override) has no trait
//! storage equivalent; it is exposed as a required accessor,
//! [`AbstractLeb128DataType::leb128_is_signed`], mirroring the `undefinedN_is_signed`-style
//! accessors used elsewhere in this crate for instance state a trait cannot hold directly.
//!
//! `getLength(MemBuffer, int)` (overriding the abstract `Dynamic.getLength(MemBuffer, int)`,
//! ported as [`Dynamic::get_dynamic_length`]) and `getValue`/`getRepresentation` all go through
//! `LEB128.getLength(InputStream)`/`LEB128.read(InputStream, boolean)`
//! ([`Leb128::get_length`](super::leb128::Leb128::get_length)/[`Leb128::read`](super::leb128::Leb128::read)),
//! reading from a fresh [`MemBufferInputStream`] each time exactly as the Java original opens a
//! fresh `buf.getInputStream(0, maxLength)` each time.
//!
//! Several methods here share a name with an already-provided default method on [`DataType`]/
//! [`Dynamic`] (`getLength()`, `getValueClass(Settings)`, `getValue(...)`,
//! `getRepresentation(...)`, `canSpecifyLength()`, `getDefaultLabelPrefix()`). Rust does not allow
//! a subtrait to override a supertrait's same-named default without creating an ambiguous call
//! site, so -- mirroring [`AlignmentDataType`]'s `alignment_*` convention -- those overrides are
//! exposed here under distinct `leb128_*` names. A concrete `impl DataType + BuiltInDataType +
//! Dynamic for ...` should delegate to these; [`Dynamic::get_dynamic_length`]/
//! [`Dynamic::get_replacement_base_type`] have no default at all, so a concrete implementation's
//! overrides should delegate to
//! [`leb128_dynamic_length`](AbstractLeb128DataType::leb128_dynamic_length)/
//! [`leb128_replacement_base_type`](AbstractLeb128DataType::leb128_replacement_base_type)
//! directly.
//!
//! `getBuiltInSettingsDefinitions()` (overriding the defaulted
//! [`BuiltIn::get_built_in_settings_definitions`], which is uniquely named already and so needs
//! no renaming here) returns the single `FORMAT` = [`FormatSettingsDefinition::DEF_HEX`]
//! definition.
//!
//! No `clone(DataTypeManager)` override exists on `AbstractLeb128DataType.java` itself (it is
//! left for [`SignedLeb128DataType`](super::signed_leb128_data_type::SignedLeb128DataType)/
//! [`UnsignedLeb128DataType`](super::unsigned_leb128_data_type::UnsignedLeb128DataType) to
//! implement), so this trait declares none either.

use std::any::{Any, TypeId};

use crate::docking::settings::format_settings_definition::FormatSettingsDefinition;
use crate::docking::settings::settings::Settings;
use crate::docking::settings::settings_definition::SettingsDefinition;
use crate::program::model::data::built_in::BuiltIn;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::dynamic::Dynamic;
use crate::program::model::data::leb128::Leb128;
use crate::program::model::mem::{MemBuffer, MemBufferInputStream};
use crate::program::model::scalar::scalar::Scalar;

/// Minimal stand-in for `ghidra.program.model.data.ByteDataType.dataType`, used by
/// [`AbstractLeb128DataType::leb128_replacement_base_type`]. Mirrors
/// [`AlignmentDataType`](super::alignment_data_type)'s own `BytePlaceholderDataType`.
struct BytePlaceholderDataType;

impl DataType for BytePlaceholderDataType {
    fn get_length(&self) -> i32 {
        1
    }
    fn get_name(&self) -> String {
        "byte".to_string()
    }
}

/// An abstract base for a LEB128 variable length integer data type.
///
/// Port of `ghidra.program.model.data.AbstractLeb128DataType`. See the module docs for the
/// naming conventions used to resolve clashes with [`DataType`]/[`Dynamic`], and for what was
/// left required.
pub trait AbstractLeb128DataType: BuiltIn + Dynamic {
    /// Port of the private `AbstractLeb128DataType.signed` field, set by the constructor.
    /// Required since a trait cannot hold instance state directly.
    fn leb128_is_signed(&self) -> bool;

    /// Port of `AbstractLeb128DataType.getLength()`, which overrides the default
    /// `DataType.getLength()`. Always `-1` (this type's length is only known once actual data is
    /// consulted).
    fn leb128_length(&self) -> i32 {
        -1
    }

    /// Port of `AbstractLeb128DataType.getLength(MemBuffer, int)`, which overrides the abstract
    /// `Dynamic.getLength(MemBuffer, int)` (ported as [`Dynamic::get_dynamic_length`]).
    fn leb128_dynamic_length(&self, buf: &dyn MemBuffer, max_length: i32) -> i32 {
        let max_length = if max_length < 0 { Leb128::MAX_SUPPORTED_LENGTH as i32 } else { max_length };
        let mut stream = MemBufferInputStream::with_range(buf, 0, max_length);
        Leb128::get_length(&mut stream).unwrap_or(-1)
    }

    /// Port of `AbstractLeb128DataType.getValueClass(Settings)`, which overrides the default
    /// `DataType.getValueClass(Settings)`. Returns the [`TypeId`] of [`Scalar`], standing in for
    /// `Scalar.class`.
    fn leb128_value_class(&self, settings: &dyn Settings) -> Option<TypeId> {
        let _ = settings;
        Some(TypeId::of::<Scalar>())
    }

    /// Port of `AbstractLeb128DataType.getValue(MemBuffer, Settings, int)`, which overrides the
    /// default `DataType.getValue(...)`. Returns `None` where the Java original returns `null`
    /// (a length that could not be determined, or an I/O error reading the LEB128 bytes).
    fn leb128_value(
        &self,
        buf: &dyn MemBuffer,
        settings: &dyn Settings,
        max_length: i32,
    ) -> Option<Box<dyn Any>> {
        let _ = settings;
        let max_length = if max_length < 0 { Leb128::MAX_SUPPORTED_LENGTH as i32 } else { max_length };

        let len = self.leb128_dynamic_length(buf, max_length);
        if len < 1 {
            return None; // error, or more than 10 bytes long
        }

        let mut stream = MemBufferInputStream::with_range(buf, 0, max_length);
        let val = Leb128::read(&mut stream, self.leb128_is_signed()).ok()?;

        // Approximate bitLength from storage byte length.
        let mut bit_length = (len * 7).min(64);
        let modulus = bit_length % 8;
        if modulus != 0 {
            bit_length += 8 - modulus;
        }

        Some(Box::new(Scalar::new_with_signedness(bit_length as u8, val, self.leb128_is_signed())) as Box<dyn Any>)
    }

    /// Port of `AbstractLeb128DataType.getRepresentation(MemBuffer, Settings, int)`, which
    /// overrides the default `DataType.getRepresentation(...)`.
    fn leb128_representation(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> String {
        let Some(value) = self.leb128_value(buf, settings, length) else {
            return "??".to_string();
        };
        let scalar = value.downcast_ref::<Scalar>().expect("leb128_value always returns a Scalar");

        let format = FormatSettingsDefinition::DEF_HEX;
        let radix = format.get_radix(settings) as u32;
        let postfix = format.get_representation_postfix(settings);

        let val_str = scalar.to_string_formatted(radix, false, self.leb128_is_signed(), "", "");
        format!("{}{}", val_str.to_uppercase(), postfix)
    }

    /// Port of `AbstractLeb128DataType.getReplacementBaseType()`, which overrides the abstract
    /// `Dynamic.getReplacementBaseType()` and returns `ByteDataType.dataType`. See
    /// [`AlignmentDataType::alignment_replacement_base_type`](super::alignment_data_type::AlignmentDataType::alignment_replacement_base_type)
    /// for why this returns a minimal stand-in rather than a real `ByteDataType` instance.
    fn leb128_replacement_base_type(&self) -> Box<dyn DataType> {
        Box::new(BytePlaceholderDataType)
    }

    /// Port of `AbstractLeb128DataType.canSpecifyLength()`, which overrides the default
    /// `Dynamic.canSpecifyLength()`. Always `true`.
    fn leb128_can_specify_length(&self) -> bool {
        true
    }

    /// Port of `AbstractLeb128DataType.getDefaultLabelPrefix()`, which overrides the default
    /// `DataType.getDefaultLabelPrefix()`. Returns the instance's `name`.
    fn leb128_default_label_prefix(&self) -> Option<String> {
        Some(self.get_name())
    }

    /// Port of the protected `AbstractLeb128DataType.getBuiltInSettingsDefinitions()`, which
    /// overrides the defaulted (empty) [`BuiltIn::get_built_in_settings_definitions`]. Returns
    /// the single `FORMAT` = [`FormatSettingsDefinition::DEF_HEX`] definition.
    fn leb128_built_in_settings_definitions(&self) -> Vec<Box<dyn SettingsDefinition>> {
        vec![Box::new(FormatSettingsDefinition::DEF_HEX)]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, SpecialAddress};
    use crate::program::model::data::built_in_data_type::BuiltInDataType;
    use crate::program::model::data::category_path::{CategoryPath, ROOT};
    use crate::program::model::data::data_organization::DataOrganization;
    use crate::program::model::data::data_type_impl::DataTypeImpl;
    use crate::program::model::data::source_archive::SourceArchive;
    use crate::program::model::mem::MemoryAccessException;
    use crate::util::UniversalID;
    use std::sync::Weak;

    struct MockSettings;
    impl Settings for MockSettings {}

    struct BytesMemBuffer(Vec<u8>);
    impl MemBuffer for BytesMemBuffer {
        fn get_byte(&self, offset: i32) -> Result<u8, MemoryAccessException> {
            self.0
                .get(offset as usize)
                .copied()
                .ok_or_else(|| MemoryAccessException::new("out of bounds"))
        }
        fn get_bytes(&self, _buf: &mut [u8], _offset: i32) -> usize {
            unimplemented!("not exercised by these tests")
        }
        fn is_big_endian(&self) -> bool {
            unimplemented!("not exercised by these tests")
        }
        fn get_address(&self) -> Address {
            SpecialAddress::no_address()
        }
    }

    struct MockLeb128 {
        signed: bool,
    }

    impl DataType for MockLeb128 {
        fn get_name(&self) -> String {
            if self.signed { "sleb128" } else { "uleb128" }.to_string()
        }
        fn get_category_path(&self) -> CategoryPath {
            ROOT.clone()
        }
        fn get_length(&self) -> i32 {
            self.leb128_length()
        }
    }

    impl DataTypeImpl for MockLeb128 {
        fn stored_default_settings(&self) -> Box<dyn Settings> {
            Box::new(MockSettings)
        }
        fn set_stored_default_settings(&mut self, _settings: Box<dyn Settings>) {}
        fn stored_source_archive(&self) -> Option<Box<dyn SourceArchive>> {
            None
        }
        fn set_stored_source_archive(&mut self, _archive: Option<Box<dyn SourceArchive>>) {}
        fn stored_universal_id(&self) -> UniversalID {
            UniversalID::new(0)
        }
        fn stored_last_change_time(&self) -> i64 {
            0
        }
        fn set_stored_last_change_time(&mut self, _last_change_time: i64) {}
        fn stored_last_change_time_in_source_archive(&self) -> i64 {
            0
        }
        fn set_stored_last_change_time_in_source_archive(&mut self, _last_change_time: i64) {}
        fn stored_parent_refs(&self) -> Vec<Weak<dyn DataType>> {
            Vec::new()
        }
        fn set_stored_parent_refs(&mut self, _parents: Vec<Weak<dyn DataType>>) {}
    }

    impl BuiltInDataType for MockLeb128 {
        fn get_c_type_declaration(
            &self,
            _data_organization: Option<&dyn DataOrganization>,
        ) -> Option<String> {
            None
        }
        fn set_default_settings(&mut self, _settings: &dyn Settings) {}
    }

    impl BuiltIn for MockLeb128 {
        fn built_in_is_equivalent(&self, dt: &dyn DataType) -> bool {
            dt.get_name() == self.get_name()
        }
    }

    impl Dynamic for MockLeb128 {
        fn get_dynamic_length(&self, buf: &dyn MemBuffer, max_length: i32) -> i32 {
            self.leb128_dynamic_length(buf, max_length)
        }
        fn can_specify_length(&self) -> bool {
            self.leb128_can_specify_length()
        }
        fn get_replacement_base_type(&self) -> Box<dyn DataType> {
            self.leb128_replacement_base_type()
        }
    }

    impl AbstractLeb128DataType for MockLeb128 {
        fn leb128_is_signed(&self) -> bool {
            self.signed
        }
    }

    #[test]
    fn usable_as_trait_object() {
        let dt = MockLeb128 { signed: true };
        let dyn_dt: &dyn AbstractLeb128DataType = &dt;
        assert_eq!(dyn_dt.leb128_length(), -1);
        assert_eq!(DataType::get_length(dyn_dt), -1);
        assert!(dyn_dt.leb128_can_specify_length());
        assert!(dyn_dt.can_specify_length());
        assert_eq!(dyn_dt.leb128_default_label_prefix(), Some("sleb128".to_string()));
        assert_eq!(dyn_dt.leb128_replacement_base_type().get_length(), 1);
        assert_eq!(dyn_dt.leb128_value_class(&MockSettings), Some(TypeId::of::<Scalar>()));
        assert_eq!(dyn_dt.leb128_built_in_settings_definitions().len(), 1);
    }

    #[test]
    fn unsigned_single_byte_value_round_trips() {
        // LEB128 0x05 (no continuation bit) == 5.
        let dt = MockLeb128 { signed: false };
        let buf = BytesMemBuffer(vec![0x05]);
        let value = dt.leb128_value(&buf, &MockSettings, -1).unwrap();
        let scalar = value.downcast_ref::<Scalar>().unwrap();
        assert_eq!(scalar.get_unsigned_value(), 5);
        assert_eq!(dt.leb128_dynamic_length(&buf, -1), 1);
    }

    #[test]
    fn unsigned_multi_byte_value_round_trips() {
        // LEB128 0xE5 0x8E 0x26 == 624485 (the canonical LEB128 spec example).
        let dt = MockLeb128 { signed: false };
        let buf = BytesMemBuffer(vec![0xE5, 0x8E, 0x26]);
        let value = dt.leb128_value(&buf, &MockSettings, -1).unwrap();
        let scalar = value.downcast_ref::<Scalar>().unwrap();
        assert_eq!(scalar.get_unsigned_value(), 624485);
        assert_eq!(dt.leb128_dynamic_length(&buf, -1), 3);
    }

    #[test]
    fn signed_negative_value_round_trips() {
        // LEB128 0x9B 0xF1 0x59 == -624485 (the canonical LEB128 spec example, signed).
        let dt = MockLeb128 { signed: true };
        let buf = BytesMemBuffer(vec![0x9B, 0xF1, 0x59]);
        let value = dt.leb128_value(&buf, &MockSettings, -1).unwrap();
        let scalar = value.downcast_ref::<Scalar>().unwrap();
        assert_eq!(scalar.get_signed_value(), -624485);
    }

    #[test]
    fn value_is_none_when_the_stream_never_terminates() {
        // All continuation bits set, no terminating byte within MAX_SUPPORTED_LENGTH.
        let dt = MockLeb128 { signed: false };
        let buf = BytesMemBuffer(vec![0x80; Leb128::MAX_SUPPORTED_LENGTH + 1]);
        assert!(dt.leb128_value(&buf, &MockSettings, -1).is_none());
    }

    #[test]
    fn representation_is_uppercase_hex_with_h_postfix() {
        let dt = MockLeb128 { signed: false };
        let buf = BytesMemBuffer(vec![0xE5, 0x8E, 0x26]); // 624485 == 0x98765
        assert_eq!(dt.leb128_representation(&buf, &MockSettings, -1), "98765h");
    }

    #[test]
    fn representation_is_question_marks_when_value_is_unavailable() {
        let dt = MockLeb128 { signed: false };
        let buf = BytesMemBuffer(vec![0x80; Leb128::MAX_SUPPORTED_LENGTH + 1]);
        assert_eq!(dt.leb128_representation(&buf, &MockSettings, -1), "??");
    }
}

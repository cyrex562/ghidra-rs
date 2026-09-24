//! Port of `ghidra.program.model.data.ShiftedAddressDataType`, promoted to a trait because it was
//! selected as a dependency-cycle cut-point.
//!
//! The Java class `extends BuiltIn`, already ported as a trait ([`BuiltIn`]), so this trait
//! extends it directly, mirroring
//! [`SegmentedCodePointerDataType`](super::segmented_code_pointer_data_type::SegmentedCodePointerDataType).
//!
//! Several methods here share a name with an already-provided default method on [`DataType`]/
//! [`BuiltIn`] (`getMnemonic(Settings)`, `getLength()`, `hasLanguageDependantLength()`,
//! `getDescription()`, `getValue(...)`, `getValueClass(Settings)`, `getRepresentation(...)`,
//! `getBuiltInSettingsDefinitions()`). Rust does not allow a subtrait to override a supertrait's
//! same-named default without creating an ambiguous call site, so -- mirroring
//! [`CharDataType`](super::char_data_type::CharDataType)'s `char_*` convention -- those overrides
//! are exposed here under distinct `shifted_address_*` names. A concrete `impl DataType + BuiltIn
//! for ...` should delegate to these.
//!
//! `getAddressValue(MemBuffer, int, int, AddressSpace)` (the public static helper) is ported as
//! the free function [`get_shifted_address_value`]. Its Java body's `instanceof SegmentedAddress`
//! guard (rejecting a segmented `buf.getAddress()`) is not ported for the same reason
//! [`PointerDataType`](super::pointer_data_type::PointerDataType)'s module docs already give for
//! omitting the analogous `instanceof SegmentedAddressSpace` branch:
//! [`AddressSpace`](crate::program::model::address::AddressSpace) and
//! [`SegmentedAddressSpace`](crate::program::model::address::SegmentedAddressSpace) are unrelated
//! concrete structs in this port (composition, not the Java subclassing relationship), so there is
//! no way to detect at runtime that a given `Arc<AddressSpace>`/`Address` is "really" segmented.
//! `DataConverter.getInstance(boolean).getValue(bytes, size)` (an unsigned big-endian-style decode
//! of the stored bytes, respecting `buf`'s own endianness first) is reimplemented directly rather
//! than routing through that not-yet-ported trait, mirroring
//! [`PointerDataType`]'s own private `getStoredOffset` re-implementation. The subsequent `val <<
//! shift` uses [`i64::wrapping_shl`] to reproduce Java's `long << int` masked-shift-amount
//! semantics exactly (Java masks the shift distance to `shift & 0x3f` for a `long` operand, which
//! is exactly what `wrapping_shl` does), in case a compiler spec ever supplies a negative or
//! out-of-range pointer shift. `targetSpace.getAddress(val, true)` (word-offset form) is ported as
//! [`AddressSpace::address_from_word_offset`](crate::program::model::address::AddressSpace::address_from_word_offset),
//! matching [`SegmentedCodePointerDataType`]'s precedent for the same Java overload; both
//! `AddressOutOfBoundsException` and `IllegalArgumentException` collapse to `None`, matching the
//! Java method's two empty `catch` blocks falling through to `return null;`.
//!
//! `getString(MemBuffer, Settings)` (the protected helper backing `getRepresentation`) is exposed
//! as [`shifted_address_string`](ShiftedAddressDataType::shifted_address_string).
//!
//! `clone(DataTypeManager)` is left as a required method (no default), mirroring every other
//! `BuiltIn`-derived cut-point trait in this crate.
//!
//! Static state not translated: the `dataType` singleton (needs a concrete struct) and the
//! `ClassTranslator.put(...)` legacy-name registrations (needs `ClassTranslator`, not yet ported).

use std::any::{Any, TypeId};
use std::sync::Arc;

use crate::docking::settings::settings::Settings;
use crate::docking::settings::settings_definition::SettingsDefinition;
use crate::program::model::address::{Address, AddressSpace};
use crate::program::model::data::built_in::BuiltIn;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::mem::MemBuffer;

/// Generate an address value based upon bytes stored at the specified buffer location.
///
/// Port of the public static `ShiftedAddressDataType.getAddressValue(MemBuffer, int, int,
/// AddressSpace)`. See the module docs for what was omitted (the `instanceof SegmentedAddress`
/// guard) and how the shift and word-offset construction were ported.
pub fn get_shifted_address_value(
    buf: &dyn MemBuffer,
    size: i32,
    shift: i32,
    target_space: &Arc<AddressSpace>,
) -> Option<Address> {
    if size <= 0 || size > 8 {
        return None;
    }

    let mut bytes = vec![0u8; size as usize];
    if buf.get_bytes_into(&mut bytes, 0) != size {
        return None;
    }

    // DataConverter.getInstance(buf.isBigEndian()).getValue(bytes, size): an unsigned decode of
    // the stored bytes, respecting the buffer's own byte order.
    if !buf.is_big_endian() {
        bytes.reverse();
    }
    let mut val: i64 = 0;
    for b in &bytes {
        val = (val << 8) | (*b as i64);
    }

    let val = val.wrapping_shl(shift as u32 & 0x3f);

    target_space.address_from_word_offset(val).ok()
}

/// Provides a definition of a shifted address (as specified by a compiler spec) within a program.
///
/// Port of `ghidra.program.model.data.ShiftedAddressDataType`. See the module docs for what was
/// ported, added, and omitted.
///
/// Static state not translated: the `dataType` singleton (needs a concrete struct) and the
/// `ClassTranslator.put(...)` legacy-name registrations (needs `ClassTranslator`, not yet ported).
pub trait ShiftedAddressDataType: BuiltIn {
    /// Port of `ShiftedAddressDataType.getMnemonic(Settings)`, which overrides the default
    /// `DataType.getMnemonic(Settings)`. Always `"addr"`.
    fn shifted_address_mnemonic(&self, settings: &dyn Settings) -> String {
        let _ = settings;
        "addr".to_string()
    }

    /// Port of `ShiftedAddressDataType.getLength()`, which overrides the default
    /// `DataType.getLength()`.
    fn shifted_address_length(&self) -> i32 {
        self.get_data_organization().get_pointer_size()
    }

    /// Port of `ShiftedAddressDataType.hasLanguageDependantLength()`, which overrides the default
    /// `DataType.hasLanguageDependantLength()`. Always `true`.
    fn shifted_address_has_language_dependant_length(&self) -> bool {
        true
    }

    /// Port of `ShiftedAddressDataType.getDescription()`, which overrides the default
    /// `DataType.getDescription()`.
    fn shifted_address_description(&self) -> String {
        "shifted address (as specified by compiler spec)".to_string()
    }

    /// Port of `ShiftedAddressDataType.getValue(MemBuffer, Settings, int)`, which overrides the
    /// default `DataType.getValue(...)`. Delegates to [`get_shifted_address_value`] using this
    /// type's data organization's pointer size/shift and `buf`'s own address space.
    fn shifted_address_value(
        &self,
        buf: &dyn MemBuffer,
        settings: &dyn Settings,
        length: i32,
    ) -> Option<Box<dyn Any>> {
        let _ = (settings, length);
        let data_org = self.get_data_organization();
        get_shifted_address_value(
            buf,
            data_org.get_pointer_size(),
            data_org.get_pointer_shift(),
            buf.get_address().space(),
        )
        .map(|addr| Box::new(addr) as Box<dyn Any>)
    }

    /// Port of `ShiftedAddressDataType.getValueClass(Settings)`, which overrides the default
    /// `DataType.getValueClass(Settings)`. Returns the [`TypeId`] of [`Address`], standing in for
    /// `Address.class`.
    fn shifted_address_value_class(&self, settings: &dyn Settings) -> Option<TypeId> {
        let _ = settings;
        Some(TypeId::of::<Address>())
    }

    /// Port of the protected `ShiftedAddressDataType.getString(MemBuffer, Settings)`, backing
    /// [`shifted_address_representation`](Self::shifted_address_representation). `"??"` when
    /// [`shifted_address_value`](Self::shifted_address_value) is `None`, otherwise the computed
    /// address's `Display` string (matching the Java `addr.toString()` fallthrough).
    fn shifted_address_string(&self, buf: &dyn MemBuffer, settings: &dyn Settings) -> String {
        match self.shifted_address_value(buf, settings, self.shifted_address_length()) {
            Some(value) => match value.downcast_ref::<Address>() {
                Some(addr) => addr.to_string(),
                None => "??".to_string(),
            },
            None => "??".to_string(),
        }
    }

    /// Port of `ShiftedAddressDataType.getRepresentation(MemBuffer, Settings, int)`, which
    /// overrides the default `DataType.getRepresentation(...)`.
    fn shifted_address_representation(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> String {
        let _ = length;
        self.shifted_address_string(buf, settings)
    }

    /// Port of the protected `ShiftedAddressDataType.getBuiltInSettingsDefinitions()`, which
    /// overrides the default [`BuiltIn::get_built_in_settings_definitions`]. Always empty,
    /// matching the Java `SETTINGS_DEFS = {}` constant.
    fn shifted_address_built_in_settings_definitions(&self) -> Vec<Box<dyn SettingsDefinition>> {
        Vec::new()
    }

    /// Port of `ShiftedAddressDataType.clone(DataTypeManager)`. Left as a required method (no
    /// default); see
    /// [`ByteDataType::byte_clone`](super::byte_data_type::ByteDataType::byte_clone) for why.
    fn shifted_address_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn ShiftedAddressDataType>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::AddressSpaceType;
    use crate::program::model::data::built_in_data_type::BuiltInDataType;
    use crate::program::model::data::category_path::{CategoryPath, ROOT};
    use crate::program::model::data::data_organization_impl::DataOrganizationImpl;
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::data::data_type_impl::DataTypeImpl;
    use crate::program::model::data::source_archive::SourceArchive;
    use crate::program::model::mem::MemoryAccessException;
    use crate::util::UniversalID;
    use std::sync::Weak;

    struct MockSettings;
    impl Settings for MockSettings {}

            /// A real [`DataOrganizationImpl`] configured as this test expects.
    fn mock_data_organization(pointer_size: i32, pointer_shift: i32) -> DataOrganizationImpl {
        let mut org = DataOrganizationImpl::get_default_organization(None);
        org.set_big_endian(true);
        org.set_pointer_size(pointer_size);
        org.set_pointer_shift(pointer_shift);
        org.set_char_is_signed(true);
        org.set_char_size(1);
        org.set_wide_char_size(2);
        org.set_short_size(2);
        org.set_integer_size(4);
        org.set_long_size(8);
        org.set_long_long_size(8);
        org.set_float_size(4);
        org.set_double_size(8);
        org.set_long_double_size(8);
        org.set_absolute_max_alignment(0);
        org.set_machine_alignment(8);
        org.set_default_alignment(1);
        org.set_default_pointer_alignment(8);
        org.clear_size_alignment_map();
        org
    }

    struct FixedMemBuffer {
        bytes: Vec<u8>,
        space: Arc<AddressSpace>,
        big_endian: bool,
    }
    impl MemBuffer for FixedMemBuffer {
        fn get_bytes(&self, buf: &mut [u8], offset: i32) -> usize {
            let start = offset as usize;
            let mut n = 0;
            for (i, slot) in buf.iter_mut().enumerate() {
                match self.bytes.get(start + i) {
                    Some(&b) => {
                        *slot = b;
                        n += 1;
                    }
                    None => break,
                }
            }
            n
        }
        fn is_big_endian(&self) -> bool {
            self.big_endian
        }
        fn get_address(&self) -> Address {
            self.space.address(0)
        }
        fn get_byte(&self, offset: i32) -> Result<u8, MemoryAccessException> {
            self.bytes
                .get(offset as usize)
                .copied()
                .ok_or_else(|| MemoryAccessException::new("out of bounds"))
        }
    }

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    #[derive(Clone)]
    struct MockShiftedAddress {
        pointer_size: i32,
        pointer_shift: i32,
    }

    impl DataType for MockShiftedAddress {
        fn get_name(&self) -> String {
            "ShiftedAddress".to_string()
        }
        fn get_category_path(&self) -> CategoryPath {
            ROOT.clone()
        }
        fn get_length(&self) -> i32 {
            self.shifted_address_length()
        }
        fn get_description(&self) -> String {
            self.shifted_address_description()
        }
        fn get_mnemonic(&self, settings: &dyn Settings) -> String {
            self.shifted_address_mnemonic(settings)
        }
        fn get_representation(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> String {
            self.shifted_address_representation(buf, settings, length)
        }
        fn get_value(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> Option<Box<dyn Any>> {
            self.shifted_address_value(buf, settings, length)
        }
        fn get_data_organization(&self) -> Arc<DataOrganizationImpl> {
            Arc::new(mock_data_organization(self.pointer_size, self.pointer_shift))
        }
    }

    impl DataTypeImpl for MockShiftedAddress {
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

    impl BuiltInDataType for MockShiftedAddress {
        fn get_c_type_declaration(
            &self,
            _data_organization: Option<&DataOrganizationImpl>,
        ) -> Option<String> {
            None
        }
        fn set_default_settings(&mut self, _settings: &dyn Settings) {}
    }

    impl BuiltIn for MockShiftedAddress {
        fn built_in_is_equivalent(&self, dt: &dyn DataType) -> bool {
            dt.get_name() == self.get_name()
        }
    }

    impl ShiftedAddressDataType for MockShiftedAddress {
        fn shifted_address_clone(
            &self,
            _dtm: Option<Box<dyn DataTypeManager>>,
        ) -> Box<dyn ShiftedAddressDataType> {
            Box::new(self.clone())
        }
    }

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    #[test]
    fn usable_as_trait_object() {
        let dt = MockShiftedAddress { pointer_size: 4, pointer_shift: 0 };
        let dyn_dt: &dyn ShiftedAddressDataType = &dt;
        assert_eq!(dyn_dt.shifted_address_length(), 4);
        assert_eq!(
            dyn_dt.shifted_address_description(),
            "shifted address (as specified by compiler spec)"
        );
        assert_eq!(dyn_dt.shifted_address_mnemonic(&MockSettings), "addr");
        assert!(dyn_dt.shifted_address_has_language_dependant_length());
        assert_eq!(
            dyn_dt.shifted_address_value_class(&MockSettings),
            Some(TypeId::of::<Address>())
        );
        assert!(dyn_dt.shifted_address_built_in_settings_definitions().is_empty());
    }

    #[test]
    fn get_shifted_address_value_shifts_the_decoded_offset() {
        let space = ram_space();
        // size=2, shift=4: stored value 0x0001 -> shifted 0x0010.
        let buf = FixedMemBuffer { bytes: vec![0x00, 0x01], space: space.clone(), big_endian: true };
        let addr = get_shifted_address_value(&buf, 2, 4, &space).unwrap();
        assert_eq!(addr.offset(), 0x10);
    }

    #[test]
    fn get_shifted_address_value_respects_little_endian_buffers() {
        let space = ram_space();
        let buf = FixedMemBuffer { bytes: vec![0x02, 0x00], space: space.clone(), big_endian: false };
        let addr = get_shifted_address_value(&buf, 2, 0, &space).unwrap();
        assert_eq!(addr.offset(), 2);
    }

    #[test]
    fn get_shifted_address_value_none_for_invalid_size() {
        let space = ram_space();
        let buf = FixedMemBuffer { bytes: vec![0x00, 0x01], space: space.clone(), big_endian: true };
        assert!(get_shifted_address_value(&buf, 0, 0, &space).is_none());
        assert!(get_shifted_address_value(&buf, 9, 0, &space).is_none());
    }

    #[test]
    fn get_shifted_address_value_none_on_short_read() {
        let space = ram_space();
        let buf = FixedMemBuffer { bytes: vec![0x00], space: space.clone(), big_endian: true };
        assert!(get_shifted_address_value(&buf, 2, 0, &space).is_none());
    }

    #[test]
    fn value_delegates_through_data_organization_and_buf_address_space() {
        let dt = MockShiftedAddress { pointer_size: 2, pointer_shift: 1 };
        let space = ram_space();
        let buf = FixedMemBuffer { bytes: vec![0x00, 0x05], space: space.clone(), big_endian: true };
        let value = dt.shifted_address_value(&buf, &MockSettings, 2).unwrap();
        let addr = value.downcast_ref::<Address>().unwrap();
        assert_eq!(addr.offset(), 10);
    }

    #[test]
    fn representation_matches_the_computed_address_display() {
        let dt = MockShiftedAddress { pointer_size: 2, pointer_shift: 0 };
        let space = ram_space();
        let buf = FixedMemBuffer { bytes: vec![0x00, 0x07], space: space.clone(), big_endian: true };
        let value = dt.shifted_address_value(&buf, &MockSettings, 2).unwrap();
        let addr = value.downcast_ref::<Address>().unwrap();
        assert_eq!(
            dt.shifted_address_representation(&buf, &MockSettings, 2),
            addr.to_string()
        );
    }

    #[test]
    fn representation_is_question_marks_when_the_read_fails() {
        let dt = MockShiftedAddress { pointer_size: 4, pointer_shift: 0 };
        let space = ram_space();
        let buf = FixedMemBuffer { bytes: vec![0x00], space, big_endian: true };
        assert_eq!(dt.shifted_address_representation(&buf, &MockSettings, 4), "??");
    }

    #[test]
    fn clone_produces_an_equivalent_instance() {
        let dt = MockShiftedAddress { pointer_size: 4, pointer_shift: 0 };
        let cloned = dt.shifted_address_clone(None);
        assert_eq!(cloned.get_name(), dt.get_name());
    }
}

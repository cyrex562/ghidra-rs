//! Port of `ghidra.program.model.data.Undefined6DataType`, promoted to a trait because it was
//! selected as a dependency-cycle cut-point.
//!
//! The Java class `extends Undefined` and represents a 6-byte value that has not yet been
//! defined as a particular type of data. Mirrors
//! [`Undefined1DataType`](super::undefined1_data_type::Undefined1DataType) -- see that module's
//! docs for the naming/shape conventions reused here.
//!
//! The private `getValue(MemBuffer)` helper reads a big-endian 48-bit value out of a leading int
//! and a trailing short: `(buf.getInt(0) << 16) + (buf.getShort(4) & 0xffff)`, masked to
//! `0..=0xffffffffffff`. The `getInt(0) << 16` term is Java `int` arithmetic (32-bit, so the
//! shift truncates within that width before widening to `long`), reproduced here with an
//! explicit `i32` shift before widening to `i64` -- see [`undefined_48bit_value`]. This is an
//! upstream quirk (preserved faithfully, not "fixed"): shifting a full 32-bit `int` left by 16
//! discards its top 16 bits, i.e. the bytes at buffer offsets 0 and 1 are silently dropped
//! entirely before the offset-4 short is added in. So despite `Undefined6DataType` nominally
//! covering 6 bytes, its `getValue`/`getRepresentation` never actually reflect the first two of
//! them. See the `value_drops_the_leading_two_bytes_...` test.

use std::any::Any;

use crate::docking::settings::settings::Settings;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::data::undefined::Undefined;
use crate::program::model::mem::MemoryAccessException;
use crate::program::model::scalar::scalar::Scalar;
use crate::program::model::mem::MemBuffer;
use crate::util::StringFormat;

/// Port of the private `Undefined6DataType.getValue(MemBuffer)` helper.
fn undefined_48bit_value(buf: &dyn MemBuffer) -> Result<i64, MemoryAccessException> {
    let hi = (buf.get_int(0)? as i32) << 16;
    let lo = (buf.get_short(4)? as i64) & 0xffff;
    let val = (hi as i64) + lo;
    Ok(val & 0xffffffffffff)
}

/// Port of `ghidra.program.model.data.Undefined6DataType`.
///
/// Provides an implementation of a byte that has not been defined yet as a particular type of
/// data in the program. See [`Undefined1DataType`](super::undefined1_data_type::Undefined1DataType)'s
/// module docs for what was ported, added, and omitted.
pub trait Undefined6DataType: Undefined {
    /// Port of `Undefined6DataType.getLength()`.
    fn undefined6_get_length(&self) -> i32 {
        6
    }

    /// Port of `Undefined6DataType.getDescription()`.
    fn undefined6_get_description(&self) -> String {
        "Undefined 6-Byte".to_string()
    }

    /// Port of `Undefined6DataType.getMnemonic(Settings)`, which returns the instance's `name`.
    fn undefined6_get_mnemonic(&self, settings: &dyn Settings) -> String {
        let _ = settings;
        self.get_name()
    }

    /// Port of `Undefined6DataType.getRepresentation(MemBuffer, Settings, int)`.
    fn undefined6_get_representation(
        &self,
        buf: &dyn MemBuffer,
        settings: &dyn Settings,
        length: i32,
    ) -> String {
        let _ = (settings, length);
        match undefined_48bit_value(buf) {
            Ok(val) => {
                let hex = format!("{val:X}");
                StringFormat::pad_it(&hex, 12, 'h', true)
            }
            Err(_) => "??".to_string(),
        }
    }

    /// Port of `Undefined6DataType.getValue(MemBuffer, Settings, int)`, which returns the
    /// undefined 48-bit value as an unsigned `Scalar`.
    fn undefined6_get_value(
        &self,
        buf: &dyn MemBuffer,
        settings: &dyn Settings,
        length: i32,
    ) -> Option<Box<dyn Any>> {
        let _ = (settings, length);
        undefined_48bit_value(buf)
            .ok()
            .map(|val| Box::new(Scalar::new(48, val)) as Box<dyn Any>)
    }

    /// Port of `Undefined6DataType.clone(DataTypeManager)`. Left as a required method (no
    /// default); see [`Undefined1DataType::undefined1_clone`](super::undefined1_data_type::Undefined1DataType::undefined1_clone).
    fn undefined6_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn Undefined6DataType>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, SpecialAddress};
    use crate::program::model::data::built_in_data_type::BuiltInDataType;
    use crate::program::model::data::category_path::{CategoryPath, ROOT};
    use crate::program::model::data::data_organization_impl::DataOrganizationImpl;

    struct MockSettings;
    impl Settings for MockSettings {}

    #[derive(Clone)]
    struct MockUndefined6 {
        bound_to_other_manager: bool,
    }

    impl DataType for MockUndefined6 {
        fn get_name(&self) -> String {
            "undefined6".to_string()
        }
        fn get_category_path(&self) -> CategoryPath {
            ROOT.clone()
        }
        fn get_length(&self) -> i32 {
            self.undefined6_get_length()
        }
        fn get_description(&self) -> String {
            self.undefined6_get_description()
        }
        fn get_mnemonic(&self, settings: &dyn Settings) -> String {
            self.undefined6_get_mnemonic(settings)
        }
        fn get_representation(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> String {
            self.undefined6_get_representation(buf, settings, length)
        }
        fn get_value(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> Option<Box<dyn Any>> {
            self.undefined6_get_value(buf, settings, length)
        }
        fn is_undefined_type(&self) -> bool {
            true
        }
    }

    impl BuiltInDataType for MockUndefined6 {
        fn get_c_type_declaration(
            &self,
            _data_organization: Option<&DataOrganizationImpl>,
        ) -> Option<String> {
            None
        }
        fn set_default_settings(&mut self, _settings: &dyn Settings) {}
    }

    impl Undefined for MockUndefined6 {}

    impl Undefined6DataType for MockUndefined6 {
        fn undefined6_clone(
            &self,
            dtm: Option<Box<dyn DataTypeManager>>,
        ) -> Box<dyn Undefined6DataType> {
            match dtm {
                Some(_) if self.bound_to_other_manager => {
                    Box::new(MockUndefined6 { bound_to_other_manager: false })
                }
                _ => Box::new(self.clone()),
            }
        }
    }

    struct MockBuf {
        bytes: [u8; 6],
    }
    impl MemBuffer for MockBuf {
        fn get_bytes(&self, buf: &mut [u8], offset: i32) -> usize {
            let start = offset as usize;
            let mut n = 0;
            for (i, slot) in buf.iter_mut().enumerate() {
                match self.bytes.get(start + i) {
                    Some(&byte) => {
                        *slot = byte;
                        n += 1;
                    }
                    None => break,
                }
            }
            n
        }
        fn is_big_endian(&self) -> bool {
            true
        }
        fn get_address(&self) -> Address {
            SpecialAddress::no_address()
        }
        fn get_byte(&self, offset: i32) -> Result<u8, MemoryAccessException> {
            self.bytes
                .get(offset as usize)
                .copied()
                .ok_or_else(|| MemoryAccessException::new("out of bounds"))
        }
    }

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    #[test]
    fn usable_as_trait_object() {
        let dt: Box<dyn Undefined6DataType> = Box::new(MockUndefined6 { bound_to_other_manager: false });
        assert_eq!(dt.undefined6_get_length(), 6);
        assert_eq!(dt.undefined6_get_description(), "Undefined 6-Byte");
        assert!(dt.is_undefined_type());
    }

    #[test]
    fn mnemonic_delegates_to_instance_name() {
        let dt = MockUndefined6 { bound_to_other_manager: false };
        let settings = MockSettings;
        assert_eq!(dt.undefined6_get_mnemonic(&settings), "undefined6");
    }

    #[test]
    fn representation_pads_to_twelve_hex_digits() {
        let dt = MockUndefined6 { bound_to_other_manager: false };
        let settings = MockSettings;
        let buf = MockBuf { bytes: [0x00, 0x00, 0x00, 0x00, 0x00, 0x0A] };
        assert_eq!(dt.undefined6_get_representation(&buf, &settings, 6), "00000000000Ah");
    }

    #[test]
    fn value_drops_the_leading_two_bytes_due_to_32_bit_int_shift_truncation() {
        // Upstream quirk (faithfully preserved): `buf.getInt(0) << 16` is Java `int` (32-bit)
        // arithmetic, so the leading 16 bits (bytes at offsets 0 and 1) are shifted out and lost
        // before the short at offset 4 is added in.
        let dt = MockUndefined6 { bound_to_other_manager: false };
        let settings = MockSettings;
        let buf = MockBuf { bytes: [0xAA, 0xBB, 0x01, 0x02, 0x03, 0x04] };

        let value = dt.undefined6_get_value(&buf, &settings, 6).unwrap();
        let scalar = value.downcast_ref::<Scalar>().unwrap();
        assert_eq!(scalar.get_unsigned_value(), 0x01020304u64);
    }

    #[test]
    fn value_masks_to_48_bits_even_with_all_bits_set() {
        let dt = MockUndefined6 { bound_to_other_manager: false };
        let settings = MockSettings;
        let buf = MockBuf { bytes: [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF] };

        let value = dt.undefined6_get_value(&buf, &settings, 6).unwrap();
        let scalar = value.downcast_ref::<Scalar>().unwrap();
        assert_eq!(scalar.get_unsigned_value(), 0xffffffffffffu64);
    }

    #[test]
    fn clone_with_matching_manager_preserves_identity() {
        let dt = MockUndefined6 { bound_to_other_manager: false };
        let cloned = dt.undefined6_clone(Some(Box::new(MockDataTypeManager)));
        assert_eq!(cloned.get_name(), "undefined6");
    }

    #[test]
    fn clone_with_new_manager_rebinds_instance() {
        let dt = MockUndefined6 { bound_to_other_manager: true };
        let cloned = dt.undefined6_clone(Some(Box::new(MockDataTypeManager)));
        assert_eq!(cloned.get_name(), "undefined6");
        assert_eq!(cloned.undefined6_get_length(), 6);
    }
}

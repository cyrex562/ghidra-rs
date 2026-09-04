//! Port of `ghidra.program.model.data.Undefined5DataType`, promoted to a trait because it was
//! selected as a dependency-cycle cut-point.
//!
//! The Java class `extends Undefined` and represents a 5-byte value that has not yet been
//! defined as a particular type of data. Mirrors
//! [`Undefined1DataType`](super::undefined1_data_type::Undefined1DataType) -- see that module's
//! docs for the naming/shape conventions reused here.
//!
//! The private `getValue(MemBuffer)` helper reads a big-endian 40-bit value out of a leading int
//! and a trailing byte: `(buf.getInt(0) << 8) + (buf.getByte(4) & 0xff)`, masked to
//! `0..=0xffffffffff`. The `getInt(0) << 8` term is Java `int` arithmetic (32-bit, so the shift
//! truncates within that width before widening to `long`), reproduced here with an explicit
//! `i32` shift before widening to `i64` -- see [`undefined_40bit_value`]. This is an upstream
//! quirk (preserved faithfully, not "fixed"): it silently discards the byte at offset 0 of the
//! buffer entirely (shifted out of the 32-bit `int` before the widening to `long` ever happens),
//! so despite `Undefined5DataType` nominally covering 5 bytes, its `getValue`/`getRepresentation`
//! never actually reflect the first of them. See the `value_drops_the_leading_byte_...` test.

use std::any::Any;

use crate::docking::settings::settings::Settings;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::data::undefined::Undefined;
use crate::program::model::mem::MemoryAccessException;
use crate::program::model::scalar::scalar::Scalar;
use crate::program::model::mem::MemBuffer;
use crate::util::StringFormat;

/// Port of the private `Undefined5DataType.getValue(MemBuffer)` helper.
fn undefined_40bit_value(buf: &dyn MemBuffer) -> Result<i64, MemoryAccessException> {
    let hi = (buf.get_int(0)? as i32) << 8;
    let lo = (buf.get_byte(4)? as i64) & 0xff;
    let val = (hi as i64) + lo;
    Ok(val & 0xffffffffff)
}

/// Port of `ghidra.program.model.data.Undefined5DataType`.
///
/// Provides an implementation of a byte that has not been defined yet as a particular type of
/// data in the program. See [`Undefined1DataType`](super::undefined1_data_type::Undefined1DataType)'s
/// module docs for what was ported, added, and omitted.
pub trait Undefined5DataType: Undefined {
    /// Port of `Undefined5DataType.getLength()`.
    fn undefined5_get_length(&self) -> i32 {
        5
    }

    /// Port of `Undefined5DataType.getDescription()`.
    fn undefined5_get_description(&self) -> String {
        "Undefined 5-Byte".to_string()
    }

    /// Port of `Undefined5DataType.getMnemonic(Settings)`, which returns the instance's `name`.
    fn undefined5_get_mnemonic(&self, settings: &dyn Settings) -> String {
        let _ = settings;
        self.get_name()
    }

    /// Port of `Undefined5DataType.getRepresentation(MemBuffer, Settings, int)`.
    fn undefined5_get_representation(
        &self,
        buf: &dyn MemBuffer,
        settings: &dyn Settings,
        length: i32,
    ) -> String {
        let _ = (settings, length);
        match undefined_40bit_value(buf) {
            Ok(val) => {
                let hex = format!("{val:X}");
                StringFormat::pad_it(&hex, 10, 'h', true)
            }
            Err(_) => "??".to_string(),
        }
    }

    /// Port of `Undefined5DataType.getValue(MemBuffer, Settings, int)`, which returns the
    /// undefined 40-bit value as an unsigned `Scalar`.
    fn undefined5_get_value(
        &self,
        buf: &dyn MemBuffer,
        settings: &dyn Settings,
        length: i32,
    ) -> Option<Box<dyn Any>> {
        let _ = (settings, length);
        undefined_40bit_value(buf)
            .ok()
            .map(|val| Box::new(Scalar::new(40, val)) as Box<dyn Any>)
    }

    /// Port of `Undefined5DataType.clone(DataTypeManager)`. Left as a required method (no
    /// default); see [`Undefined1DataType::undefined1_clone`](super::undefined1_data_type::Undefined1DataType::undefined1_clone).
    fn undefined5_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn Undefined5DataType>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, SpecialAddress};
    use crate::program::model::data::built_in_data_type::BuiltInDataType;
    use crate::program::model::data::category_path::{CategoryPath, ROOT};
    use crate::program::model::data::data_organization::DataOrganization;

    struct MockSettings;
    impl Settings for MockSettings {}

    #[derive(Clone)]
    struct MockUndefined5 {
        bound_to_other_manager: bool,
    }

    impl DataType for MockUndefined5 {
        fn get_name(&self) -> String {
            "undefined5".to_string()
        }
        fn get_category_path(&self) -> CategoryPath {
            ROOT.clone()
        }
        fn get_length(&self) -> i32 {
            self.undefined5_get_length()
        }
        fn get_description(&self) -> String {
            self.undefined5_get_description()
        }
        fn get_mnemonic(&self, settings: &dyn Settings) -> String {
            self.undefined5_get_mnemonic(settings)
        }
        fn get_representation(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> String {
            self.undefined5_get_representation(buf, settings, length)
        }
        fn get_value(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> Option<Box<dyn Any>> {
            self.undefined5_get_value(buf, settings, length)
        }
        fn is_undefined_type(&self) -> bool {
            true
        }
    }

    impl BuiltInDataType for MockUndefined5 {
        fn get_c_type_declaration(
            &self,
            _data_organization: Option<&dyn DataOrganization>,
        ) -> Option<String> {
            None
        }
        fn set_default_settings(&mut self, _settings: &dyn Settings) {}
    }

    impl Undefined for MockUndefined5 {}

    impl Undefined5DataType for MockUndefined5 {
        fn undefined5_clone(
            &self,
            dtm: Option<Box<dyn DataTypeManager>>,
        ) -> Box<dyn Undefined5DataType> {
            match dtm {
                Some(_) if self.bound_to_other_manager => {
                    Box::new(MockUndefined5 { bound_to_other_manager: false })
                }
                _ => Box::new(self.clone()),
            }
        }
    }

    struct MockBuf {
        bytes: [u8; 5],
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
        let dt: Box<dyn Undefined5DataType> = Box::new(MockUndefined5 { bound_to_other_manager: false });
        assert_eq!(dt.undefined5_get_length(), 5);
        assert_eq!(dt.undefined5_get_description(), "Undefined 5-Byte");
        assert!(dt.is_undefined_type());
    }

    #[test]
    fn mnemonic_delegates_to_instance_name() {
        let dt = MockUndefined5 { bound_to_other_manager: false };
        let settings = MockSettings;
        assert_eq!(dt.undefined5_get_mnemonic(&settings), "undefined5");
    }

    #[test]
    fn representation_pads_to_ten_hex_digits() {
        let dt = MockUndefined5 { bound_to_other_manager: false };
        let settings = MockSettings;
        let buf = MockBuf { bytes: [0x00, 0x00, 0x00, 0x00, 0x0A] };
        assert_eq!(dt.undefined5_get_representation(&buf, &settings, 5), "000000000Ah");
    }

    #[test]
    fn value_drops_the_leading_byte_due_to_32_bit_int_shift_truncation() {
        // Upstream quirk (faithfully preserved): `buf.getInt(0) << 8` is Java `int` (32-bit)
        // arithmetic, so the leading byte (bits 24..31 of the int) is shifted out and lost
        // before the byte at offset 4 is added in. The result only ever reflects bytes 1..4,
        // never byte 0, regardless of what byte 0 contains.
        let dt = MockUndefined5 { bound_to_other_manager: false };
        let settings = MockSettings;
        let buf = MockBuf { bytes: [0xAA, 0x01, 0x02, 0x03, 0x04] };

        let value = dt.undefined5_get_value(&buf, &settings, 5).unwrap();
        let scalar = value.downcast_ref::<Scalar>().unwrap();
        assert_eq!(scalar.get_unsigned_value(), 0x01020304u64);
    }

    #[test]
    fn value_masks_to_40_bits_even_with_all_bits_set() {
        let dt = MockUndefined5 { bound_to_other_manager: false };
        let settings = MockSettings;
        let buf = MockBuf { bytes: [0xFF, 0xFF, 0xFF, 0xFF, 0xFF] };

        let value = dt.undefined5_get_value(&buf, &settings, 5).unwrap();
        let scalar = value.downcast_ref::<Scalar>().unwrap();
        assert_eq!(scalar.get_unsigned_value(), 0xffffffffffu64);
    }

    #[test]
    fn clone_with_matching_manager_preserves_identity() {
        let dt = MockUndefined5 { bound_to_other_manager: false };
        let cloned = dt.undefined5_clone(Some(Box::new(MockDataTypeManager)));
        assert_eq!(cloned.get_name(), "undefined5");
    }

    #[test]
    fn clone_with_new_manager_rebinds_instance() {
        let dt = MockUndefined5 { bound_to_other_manager: true };
        let cloned = dt.undefined5_clone(Some(Box::new(MockDataTypeManager)));
        assert_eq!(cloned.get_name(), "undefined5");
        assert_eq!(cloned.undefined5_get_length(), 5);
    }
}

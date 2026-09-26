//! Port of `ghidra.program.model.data.Undefined7DataType`, promoted to a trait because it was
//! selected as a dependency-cycle cut-point.
//!
//! The Java class `extends Undefined` and represents a 7-byte value that has not yet been
//! defined as a particular type of data. Mirrors
//! [`Undefined1DataType`](super::undefined1_data_type::Undefined1DataType) -- see that module's
//! docs for the naming/shape conventions reused here.
//!
//! The private `getValue(MemBuffer)` helper assembles a value from a leading int, a short, and a
//! trailing byte: `(buf.getInt(0) << 24) + ((buf.getShort(4) & 0xffff) << 8) + (buf.getByte(6) &
//! 0xff)`, masked with `0xffffffffffff`. Two upstream quirks are preserved here faithfully (not
//! "fixed"):
//!
//! - The mask itself is `0xffffffffffff` -- **48** bits (12 hex digits), not the 56 bits a
//!   7-byte value would need. This looks like a copy-paste oversight from
//!   [`Undefined6DataType`](super::undefined6_data_type::Undefined6DataType) (which uses the
//!   same 48-bit mask, correctly, for its own 6-byte/48-bit value). The `Scalar` is still
//!   constructed with a 56-bit length (`new Scalar(56, getValue(buf))`), so the *reported* bit
//!   width and the *actual* masked value width disagree.
//! - `buf.getInt(0) << 24` is Java `int` (32-bit) arithmetic, so the shift truncates within that
//!   32-bit width: only the lowest 8 bits of the leading int (the byte at buffer offset 3)
//!   survive the shift into the top byte of the sum; the bytes at offsets 0, 1, and 2 are
//!   shifted out and lost entirely, before the short/byte terms are even added in.
//!
//! Between the two quirks, `Undefined7DataType.getValue`/`getRepresentation` never actually
//! reflect the bytes at offsets 0, 1, or 2 -- only offsets 3 through 6. See the
//! `value_drops_the_leading_three_bytes_...` test. Reproduced here with an explicit `i32` shift
//! before widening to `i64` -- see [`undefined_value`].

use std::any::Any;

use crate::docking::settings::settings::Settings;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::data::undefined::Undefined;
use crate::program::model::mem::MemoryAccessException;
use crate::program::model::scalar::scalar::Scalar;
use crate::program::model::mem::MemBuffer;
use crate::util::StringFormat;

/// Port of the private `Undefined7DataType.getValue(MemBuffer)` helper. See the module docs for
/// the two upstream quirks (mask width, shift truncation) preserved here faithfully.
fn undefined_value(buf: &dyn MemBuffer) -> Result<i64, MemoryAccessException> {
    let hi = (buf.get_int(0)? as i32) << 24;
    let mid = ((buf.get_short(4)? as i64) & 0xffff) << 8;
    let lo = (buf.get_byte(6)? as i64) & 0xff;
    let val = (hi as i64) + mid + lo;
    Ok(val & 0xffffffffffff)
}

/// Port of `ghidra.program.model.data.Undefined7DataType`.
///
/// Provides an implementation of a byte that has not been defined yet as a particular type of
/// data in the program. See [`Undefined1DataType`](super::undefined1_data_type::Undefined1DataType)'s
/// module docs for what was ported, added, and omitted, and this module's own docs for the two
/// upstream quirks preserved in [`undefined_value`].
pub trait Undefined7DataType: Undefined {
    /// Port of `Undefined7DataType.getLength()`.
    fn undefined7_get_length(&self) -> i32 {
        7
    }

    /// Port of `Undefined7DataType.getDescription()`.
    fn undefined7_get_description(&self) -> String {
        "Undefined 7-Byte".to_string()
    }

    /// Port of `Undefined7DataType.getMnemonic(Settings)`, which returns the instance's `name`.
    fn undefined7_get_mnemonic(&self, settings: &dyn Settings) -> String {
        let _ = settings;
        self.get_name()
    }

    /// Port of `Undefined7DataType.getRepresentation(MemBuffer, Settings, int)`.
    fn undefined7_get_representation(
        &self,
        buf: &dyn MemBuffer,
        settings: &dyn Settings,
        length: i32,
    ) -> String {
        let _ = (settings, length);
        match undefined_value(buf) {
            Ok(val) => {
                let hex = format!("{val:X}");
                StringFormat::pad_it(&hex, 14, 'h', true)
            }
            Err(_) => "??".to_string(),
        }
    }

    /// Port of `Undefined7DataType.getValue(MemBuffer, Settings, int)`, which returns the
    /// undefined value as a (nominally 56-bit, see module docs) unsigned `Scalar`.
    fn undefined7_get_value(
        &self,
        buf: &dyn MemBuffer,
        settings: &dyn Settings,
        length: i32,
    ) -> Option<Box<dyn Any>> {
        let _ = (settings, length);
        undefined_value(buf)
            .ok()
            .map(|val| Box::new(Scalar::new(56, val)) as Box<dyn Any>)
    }

    /// Port of `Undefined7DataType.clone(DataTypeManager)`. Left as a required method (no
    /// default); see [`Undefined1DataType::undefined1_clone`](super::undefined1_data_type::Undefined1DataType::undefined1_clone).
    fn undefined7_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn Undefined7DataType>;
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
    struct MockUndefined7 {
        bound_to_other_manager: bool,
    }

    impl DataType for MockUndefined7 {
        fn get_name(&self) -> String {
            "undefined7".to_string()
        }
        fn get_category_path(&self) -> CategoryPath {
            ROOT.clone()
        }
        fn get_length(&self) -> i32 {
            self.undefined7_get_length()
        }
        fn get_description(&self) -> String {
            self.undefined7_get_description()
        }
        fn get_mnemonic(&self, settings: &dyn Settings) -> String {
            self.undefined7_get_mnemonic(settings)
        }
        fn get_representation(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> String {
            self.undefined7_get_representation(buf, settings, length)
        }
        fn get_value(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> Option<Box<dyn Any>> {
            self.undefined7_get_value(buf, settings, length)
        }
        fn is_undefined_type(&self) -> bool {
            true
        }
    }

    impl BuiltInDataType for MockUndefined7 {
        fn get_c_type_declaration(
            &self,
            _data_organization: Option<&DataOrganizationImpl>,
        ) -> Option<String> {
            None
        }
        fn set_default_settings(&mut self, _settings: &dyn Settings) {}
    }

    impl Undefined for MockUndefined7 {}

    impl Undefined7DataType for MockUndefined7 {
        fn undefined7_clone(
            &self,
            dtm: Option<Box<dyn DataTypeManager>>,
        ) -> Box<dyn Undefined7DataType> {
            match dtm {
                Some(_) if self.bound_to_other_manager => {
                    Box::new(MockUndefined7 { bound_to_other_manager: false })
                }
                _ => Box::new(self.clone()),
            }
        }
    }

    struct MockBuf {
        bytes: [u8; 7],
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
        let dt: Box<dyn Undefined7DataType> = Box::new(MockUndefined7 { bound_to_other_manager: false });
        assert_eq!(dt.undefined7_get_length(), 7);
        assert_eq!(dt.undefined7_get_description(), "Undefined 7-Byte");
        assert!(dt.is_undefined_type());
    }

    #[test]
    fn mnemonic_delegates_to_instance_name() {
        let dt = MockUndefined7 { bound_to_other_manager: false };
        let settings = MockSettings;
        assert_eq!(dt.undefined7_get_mnemonic(&settings), "undefined7");
    }

    #[test]
    fn representation_pads_to_fourteen_hex_digits() {
        let dt = MockUndefined7 { bound_to_other_manager: false };
        let settings = MockSettings;
        let buf = MockBuf { bytes: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0A] };
        assert_eq!(dt.undefined7_get_representation(&buf, &settings, 7), "0000000000000Ah");
    }

    #[test]
    fn value_drops_the_leading_three_bytes_due_to_32_bit_int_shift_truncation() {
        // Upstream quirks (faithfully preserved, see module docs): `buf.getInt(0) << 24` is Java
        // `int` (32-bit) arithmetic, so only the byte at offset 3 survives the shift; the bytes
        // at offsets 0, 1, and 2 are lost entirely.
        let dt = MockUndefined7 { bound_to_other_manager: false };
        let settings = MockSettings;
        let buf = MockBuf { bytes: [0xAA, 0xBB, 0xCC, 0x01, 0x02, 0x03, 0x04] };

        let value = dt.undefined7_get_value(&buf, &settings, 7).unwrap();
        let scalar = value.downcast_ref::<Scalar>().unwrap();
        assert_eq!(scalar.get_unsigned_value(), 0x01020304u64);
    }

    #[test]
    fn value_masks_to_48_bits_not_56_even_with_all_bits_set() {
        // Upstream quirk (faithfully preserved, see module docs): the mask is 48 bits even
        // though the Scalar is constructed with a 56-bit length.
        let dt = MockUndefined7 { bound_to_other_manager: false };
        let settings = MockSettings;
        let buf = MockBuf { bytes: [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF] };

        let value = dt.undefined7_get_value(&buf, &settings, 7).unwrap();
        let scalar = value.downcast_ref::<Scalar>().unwrap();
        assert_eq!(scalar.get_unsigned_value(), 0xffffffffffffu64);
        assert_eq!(scalar.bit_length(), 56);
    }

    #[test]
    fn clone_with_matching_manager_preserves_identity() {
        let dt = MockUndefined7 { bound_to_other_manager: false };
        let cloned = dt.undefined7_clone(Some(Box::new(MockDataTypeManager)));
        assert_eq!(cloned.get_name(), "undefined7");
    }

    #[test]
    fn clone_with_new_manager_rebinds_instance() {
        let dt = MockUndefined7 { bound_to_other_manager: true };
        let cloned = dt.undefined7_clone(Some(Box::new(MockDataTypeManager)));
        assert_eq!(cloned.get_name(), "undefined7");
        assert_eq!(cloned.undefined7_get_length(), 7);
    }
}

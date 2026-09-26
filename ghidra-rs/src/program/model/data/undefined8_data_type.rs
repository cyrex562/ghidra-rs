//! Port of `ghidra.program.model.data.Undefined8DataType`, promoted to a trait because it was
//! selected as a dependency-cycle cut-point.
//!
//! The Java class `extends Undefined` and represents an 8-byte value that has not yet been
//! defined as a particular type of data. Mirrors
//! [`Undefined1DataType`](super::undefined1_data_type::Undefined1DataType) -- see that module's
//! docs for the naming/shape conventions reused here.
//!
//! The private `getValue(MemBuffer)` helper is simply `buf.getLong(0)` -- unlike its
//! [`Undefined2DataType`](super::undefined2_data_type::Undefined2DataType)..
//! [`Undefined7DataType`](super::undefined7_data_type::Undefined7DataType) siblings, there is no
//! narrower Java primitive to assemble a full 64-bit value out of, so there is no masking and no
//! `int`-shift-truncation quirk to reproduce here.

use std::any::Any;

use crate::docking::settings::settings::Settings;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::data::undefined::Undefined;
use crate::program::model::mem::MemoryAccessException;
use crate::program::model::scalar::scalar::Scalar;
use crate::program::model::mem::MemBuffer;
use crate::util::StringFormat;

/// Port of the private `Undefined8DataType.getValue(MemBuffer)` helper: reads the buffer's first
/// long.
fn undefined_long_value(buf: &dyn MemBuffer) -> Result<i64, MemoryAccessException> {
    buf.get_long(0)
}

/// Port of `ghidra.program.model.data.Undefined8DataType`.
///
/// Provides an implementation of an 8-byte dataType that has not been defined yet as a
/// particular type of data in the program. See [`Undefined1DataType`](super::undefined1_data_type::Undefined1DataType)'s
/// module docs for what was ported, added, and omitted.
pub trait Undefined8DataType: Undefined {
    /// Port of `Undefined8DataType.getLength()`.
    fn undefined8_get_length(&self) -> i32 {
        8
    }

    /// Port of `Undefined8DataType.getDescription()`.
    fn undefined8_get_description(&self) -> String {
        "Undefined Quad Word".to_string()
    }

    /// Port of `Undefined8DataType.getMnemonic(Settings)`, which returns the instance's `name`.
    fn undefined8_get_mnemonic(&self, settings: &dyn Settings) -> String {
        let _ = settings;
        self.get_name()
    }

    /// Port of `Undefined8DataType.getRepresentation(MemBuffer, Settings, int)`.
    fn undefined8_get_representation(
        &self,
        buf: &dyn MemBuffer,
        settings: &dyn Settings,
        length: i32,
    ) -> String {
        let _ = (settings, length);
        match undefined_long_value(buf) {
            Ok(val) => {
                let hex = format!("{val:X}");
                StringFormat::pad_it(&hex, 16, 'h', true)
            }
            Err(_) => "??".to_string(),
        }
    }

    /// Port of `Undefined8DataType.getValue(MemBuffer, Settings, int)`, which returns the
    /// undefined long as a (signed, per the 2-arg `Scalar` constructor) 64-bit `Scalar`.
    fn undefined8_get_value(
        &self,
        buf: &dyn MemBuffer,
        settings: &dyn Settings,
        length: i32,
    ) -> Option<Box<dyn Any>> {
        let _ = (settings, length);
        undefined_long_value(buf)
            .ok()
            .map(|val| Box::new(Scalar::new(64, val)) as Box<dyn Any>)
    }

    /// Port of `Undefined8DataType.clone(DataTypeManager)`. Left as a required method (no
    /// default); see [`Undefined1DataType::undefined1_clone`](super::undefined1_data_type::Undefined1DataType::undefined1_clone).
    fn undefined8_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn Undefined8DataType>;
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
    struct MockUndefined8 {
        bound_to_other_manager: bool,
    }

    impl DataType for MockUndefined8 {
        fn get_name(&self) -> String {
            "undefined8".to_string()
        }
        fn get_category_path(&self) -> CategoryPath {
            ROOT.clone()
        }
        fn get_length(&self) -> i32 {
            self.undefined8_get_length()
        }
        fn get_description(&self) -> String {
            self.undefined8_get_description()
        }
        fn get_mnemonic(&self, settings: &dyn Settings) -> String {
            self.undefined8_get_mnemonic(settings)
        }
        fn get_representation(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> String {
            self.undefined8_get_representation(buf, settings, length)
        }
        fn get_value(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> Option<Box<dyn Any>> {
            self.undefined8_get_value(buf, settings, length)
        }
        fn is_undefined_type(&self) -> bool {
            true
        }
    }

    impl BuiltInDataType for MockUndefined8 {
        fn get_c_type_declaration(
            &self,
            _data_organization: Option<&DataOrganizationImpl>,
        ) -> Option<String> {
            None
        }
        fn set_default_settings(&mut self, _settings: &dyn Settings) {}
    }

    impl Undefined for MockUndefined8 {}

    impl Undefined8DataType for MockUndefined8 {
        fn undefined8_clone(
            &self,
            dtm: Option<Box<dyn DataTypeManager>>,
        ) -> Box<dyn Undefined8DataType> {
            match dtm {
                Some(_) if self.bound_to_other_manager => {
                    Box::new(MockUndefined8 { bound_to_other_manager: false })
                }
                _ => Box::new(self.clone()),
            }
        }
    }

    struct MockBuf {
        bytes: [u8; 8],
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
        let dt: Box<dyn Undefined8DataType> = Box::new(MockUndefined8 { bound_to_other_manager: false });
        assert_eq!(dt.undefined8_get_length(), 8);
        assert_eq!(dt.undefined8_get_description(), "Undefined Quad Word");
        assert!(dt.is_undefined_type());
    }

    #[test]
    fn mnemonic_delegates_to_instance_name() {
        let dt = MockUndefined8 { bound_to_other_manager: false };
        let settings = MockSettings;
        assert_eq!(dt.undefined8_get_mnemonic(&settings), "undefined8");
    }

    #[test]
    fn representation_pads_to_sixteen_hex_digits() {
        let dt = MockUndefined8 { bound_to_other_manager: false };
        let settings = MockSettings;
        let buf = MockBuf { bytes: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0A] };
        assert_eq!(dt.undefined8_get_representation(&buf, &settings, 8), "000000000000000Ah");
    }

    #[test]
    fn value_is_a_64_bit_scalar_of_all_eight_bytes() {
        let dt = MockUndefined8 { bound_to_other_manager: false };
        let settings = MockSettings;
        let buf = MockBuf { bytes: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08] };

        let value = dt.undefined8_get_value(&buf, &settings, 8).unwrap();
        let scalar = value.downcast_ref::<Scalar>().unwrap();
        assert_eq!(scalar.get_unsigned_value(), 0x0102030405060708u64);
    }

    #[test]
    fn clone_with_matching_manager_preserves_identity() {
        let dt = MockUndefined8 { bound_to_other_manager: false };
        let cloned = dt.undefined8_clone(Some(Box::new(MockDataTypeManager)));
        assert_eq!(cloned.get_name(), "undefined8");
    }

    #[test]
    fn clone_with_new_manager_rebinds_instance() {
        let dt = MockUndefined8 { bound_to_other_manager: true };
        let cloned = dt.undefined8_clone(Some(Box::new(MockDataTypeManager)));
        assert_eq!(cloned.get_name(), "undefined8");
        assert_eq!(cloned.undefined8_get_length(), 8);
    }
}

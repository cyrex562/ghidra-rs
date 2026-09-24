//! Port of `ghidra.program.model.data.Undefined4DataType`, promoted to a trait because it was
//! selected as a dependency-cycle cut-point.
//!
//! The Java class `extends Undefined` and represents a 4-byte value that has not yet been
//! defined as a particular type of data. Mirrors
//! [`Undefined1DataType`](super::undefined1_data_type::Undefined1DataType) -- see that module's
//! docs for the naming/shape conventions reused here.
//!
//! The private `getValue(MemBuffer)` helper reads the buffer's first int and masks it to an
//! unsigned value in `0..=0xffffffff`.

use std::any::Any;

use crate::docking::settings::settings::Settings;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::data::undefined::Undefined;
use crate::program::model::mem::MemoryAccessException;
use crate::program::model::scalar::scalar::Scalar;
use crate::program::model::mem::MemBuffer;
use crate::util::StringFormat;

/// Port of the private `Undefined4DataType.getValue(MemBuffer)` helper: reads the buffer's first
/// int and masks it to an unsigned value in `0..=0xffffffff`.
fn undefined_int_value(buf: &dyn MemBuffer) -> Result<i64, MemoryAccessException> {
    buf.get_int(0).map(|v| (v as i64) & 0xffffffff)
}

/// Port of `ghidra.program.model.data.Undefined4DataType`.
///
/// Provides an implementation of a 4-byte dataType that has not been defined yet as a particular
/// type of data in the program. See [`Undefined1DataType`](super::undefined1_data_type::Undefined1DataType)'s
/// module docs for what was ported, added, and omitted.
pub trait Undefined4DataType: Undefined {
    /// Port of `Undefined4DataType.getLength()`.
    fn undefined4_get_length(&self) -> i32 {
        4
    }

    /// Port of `Undefined4DataType.getDescription()`.
    fn undefined4_get_description(&self) -> String {
        "Undefined Double Word".to_string()
    }

    /// Port of `Undefined4DataType.getMnemonic(Settings)`, which returns the instance's `name`.
    fn undefined4_get_mnemonic(&self, settings: &dyn Settings) -> String {
        let _ = settings;
        self.get_name()
    }

    /// Port of `Undefined4DataType.getRepresentation(MemBuffer, Settings, int)`.
    fn undefined4_get_representation(
        &self,
        buf: &dyn MemBuffer,
        settings: &dyn Settings,
        length: i32,
    ) -> String {
        let _ = (settings, length);
        match undefined_int_value(buf) {
            Ok(val) => {
                let hex = format!("{val:X}");
                StringFormat::pad_it(&hex, 8, 'h', true)
            }
            Err(_) => "??".to_string(),
        }
    }

    /// Port of `Undefined4DataType.getValue(MemBuffer, Settings, int)`, which returns the
    /// undefined int as an unsigned 32-bit `Scalar`.
    fn undefined4_get_value(
        &self,
        buf: &dyn MemBuffer,
        settings: &dyn Settings,
        length: i32,
    ) -> Option<Box<dyn Any>> {
        let _ = (settings, length);
        undefined_int_value(buf)
            .ok()
            .map(|val| Box::new(Scalar::new(32, val)) as Box<dyn Any>)
    }

    /// Port of `Undefined4DataType.clone(DataTypeManager)`. Left as a required method (no
    /// default); see [`Undefined1DataType::undefined1_clone`](super::undefined1_data_type::Undefined1DataType::undefined1_clone).
    fn undefined4_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn Undefined4DataType>;
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
    struct MockUndefined4 {
        bound_to_other_manager: bool,
    }

    impl DataType for MockUndefined4 {
        fn get_name(&self) -> String {
            "undefined4".to_string()
        }
        fn get_category_path(&self) -> CategoryPath {
            ROOT.clone()
        }
        fn get_length(&self) -> i32 {
            self.undefined4_get_length()
        }
        fn get_description(&self) -> String {
            self.undefined4_get_description()
        }
        fn get_mnemonic(&self, settings: &dyn Settings) -> String {
            self.undefined4_get_mnemonic(settings)
        }
        fn get_representation(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> String {
            self.undefined4_get_representation(buf, settings, length)
        }
        fn get_value(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> Option<Box<dyn Any>> {
            self.undefined4_get_value(buf, settings, length)
        }
        fn is_undefined_type(&self) -> bool {
            true
        }
    }

    impl BuiltInDataType for MockUndefined4 {
        fn get_c_type_declaration(
            &self,
            _data_organization: Option<&DataOrganizationImpl>,
        ) -> Option<String> {
            None
        }
        fn set_default_settings(&mut self, _settings: &dyn Settings) {}
    }

    impl Undefined for MockUndefined4 {}

    impl Undefined4DataType for MockUndefined4 {
        fn undefined4_clone(
            &self,
            dtm: Option<Box<dyn DataTypeManager>>,
        ) -> Box<dyn Undefined4DataType> {
            match dtm {
                Some(_) if self.bound_to_other_manager => {
                    Box::new(MockUndefined4 { bound_to_other_manager: false })
                }
                _ => Box::new(self.clone()),
            }
        }
    }

    struct MockBuf {
        bytes: [u8; 4],
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
        let dt: Box<dyn Undefined4DataType> = Box::new(MockUndefined4 { bound_to_other_manager: false });
        assert_eq!(dt.undefined4_get_length(), 4);
        assert_eq!(dt.undefined4_get_description(), "Undefined Double Word");
        assert!(dt.is_undefined_type());
    }

    #[test]
    fn mnemonic_delegates_to_instance_name() {
        let dt = MockUndefined4 { bound_to_other_manager: false };
        let settings = MockSettings;
        assert_eq!(dt.undefined4_get_mnemonic(&settings), "undefined4");
    }

    #[test]
    fn representation_pads_to_eight_hex_digits() {
        let dt = MockUndefined4 { bound_to_other_manager: false };
        let settings = MockSettings;
        let buf = MockBuf { bytes: [0x00, 0x00, 0x00, 0x0A] };
        assert_eq!(dt.undefined4_get_representation(&buf, &settings, 4), "0000000Ah");
    }

    #[test]
    fn value_is_unsigned_32_bit_scalar_masked_from_the_int() {
        let dt = MockUndefined4 { bound_to_other_manager: false };
        let settings = MockSettings;
        let buf = MockBuf { bytes: [0xFF, 0xFF, 0xFF, 0xFF] };

        let value = dt.undefined4_get_value(&buf, &settings, 4).unwrap();
        let scalar = value.downcast_ref::<Scalar>().unwrap();
        assert_eq!(scalar.get_unsigned_value(), 0xffffffff);
    }

    #[test]
    fn clone_with_matching_manager_preserves_identity() {
        let dt = MockUndefined4 { bound_to_other_manager: false };
        let cloned = dt.undefined4_clone(Some(Box::new(MockDataTypeManager)));
        assert_eq!(cloned.get_name(), "undefined4");
    }

    #[test]
    fn clone_with_new_manager_rebinds_instance() {
        let dt = MockUndefined4 { bound_to_other_manager: true };
        let cloned = dt.undefined4_clone(Some(Box::new(MockDataTypeManager)));
        assert_eq!(cloned.get_name(), "undefined4");
        assert_eq!(cloned.undefined4_get_length(), 4);
    }
}

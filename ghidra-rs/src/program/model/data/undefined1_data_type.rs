//! Port of `ghidra.program.model.data.Undefined1DataType`, promoted to a trait because it was
//! selected as a dependency-cycle cut-point.
//!
//! The Java class `extends Undefined` and represents a single byte that has not yet been defined
//! as a particular type of data. Mirroring [`IntegerDataType`](super::integer_data_type)'s own
//! treatment of its supertrait, this trait extends [`Undefined`] directly, since
//! `Undefined1DataType.java` contributes no interface beyond it -- only *behavior* overrides.
//!
//! Methods that only *override* an already-ported supertrait method with
//! `Undefined1DataType`-specific behavior (`getLength`, `getDescription`, `getMnemonic`,
//! `getRepresentation`, `getValue`) cannot be redeclared here without creating an ambiguous method
//! name with [`DataType`] (Rust does not allow a subtrait to "override" a supertrait's default
//! method by re-declaring it). Instead, mirroring [`IntegerDataType`](super::integer_data_type)'s
//! `integer_*` convention, the real `Undefined1DataType`-specific values for those overrides are
//! exposed here under distinct `undefined1_*` names; a concrete implementation should implement
//! [`DataType`] directly and delegate to these helpers.
//!
//! The private `getValue(MemBuffer)` helper (masks the buffer's first byte to an unsigned `long`)
//! has no instance state of its own, so it is ported as a private free function
//! ([`undefined_byte_value`]) rather than a trait method, and reused by both
//! [`undefined1_get_representation`](Undefined1DataType::undefined1_get_representation) and
//! [`undefined1_get_value`](Undefined1DataType::undefined1_get_value), matching how the Java
//! original calls it from both overrides.
//!
//! `clone(DataTypeManager)` returns `this` when the supplied manager already matches this
//! instance's manager, and otherwise constructs a *new* `Undefined1DataType` bound to the supplied
//! manager -- unlike [`DefaultDataType`](super::default_data_type::DefaultDataType)'s identical
//! singleton, this type actually carries a per-instance `DataTypeManager`. Mirroring
//! [`IntegerDataType::integer_clone`](super::integer_data_type::IntegerDataType::integer_clone),
//! [`undefined1_clone`](Undefined1DataType::undefined1_clone) is left as a required method (no
//! default): a mock implementor cannot generically decide manager-identity or construct a fresh
//! `Self` from a trait default.
//!
//! The public constructors (`Undefined1DataType()` / `Undefined1DataType(DataTypeManager)`, which
//! forward `"undefined1"` to the `Undefined` supertype constructor) and the public static
//! singleton field (`Undefined1DataType.dataType`) have no trait equivalent (traits declare
//! neither constructors nor static fields); each concrete implementor is expected to name itself
//! `"undefined1"` via [`DataType::get_name`] and to expose its own singleton instance however it
//! sees fit.
//!
//! `getMnemonic(Settings)` returns the instance's `name` field directly (inherited unchanged from
//! `DataType`'s protected field), so it is ported as a delegation to [`DataType::get_name`] rather
//! than a hardcoded literal.

use std::any::Any;

use crate::docking::settings::settings::Settings;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::data::undefined::Undefined;
use crate::program::model::mem::MemoryAccessException;
use crate::program::model::scalar::scalar::Scalar;
use crate::program::model::mem::MemBuffer;
use crate::util::StringFormat;

/// Port of the private `Undefined1DataType.getValue(MemBuffer)` helper: reads the buffer's first
/// byte and masks it to an unsigned value in `0..=0xff`.
fn undefined_byte_value(buf: &dyn MemBuffer) -> Result<i64, MemoryAccessException> {
    buf.get_byte(0).map(|b| (b as i64) & 0xff)
}

/// Port of `ghidra.program.model.data.Undefined1DataType`.
///
/// Provides an implementation of a byte that has not been defined yet as a particular type of
/// data in the program. See the module docs for what was ported, added, and omitted.
pub trait Undefined1DataType: Undefined {
    /// Port of `Undefined1DataType.getLength()`. Exposed under a distinct name since
    /// [`DataType::get_length`] already provides a (different) default. A concrete `impl DataType
    /// for ...` should delegate to this.
    fn undefined1_get_length(&self) -> i32 {
        1
    }

    /// Port of `Undefined1DataType.getDescription()`. Exposed under a distinct name since
    /// [`DataType::get_description`] already provides a (different) default. A concrete `impl
    /// DataType for ...` should delegate to this.
    fn undefined1_get_description(&self) -> String {
        "Undefined Byte".to_string()
    }

    /// Port of `Undefined1DataType.getMnemonic(Settings)`, which returns the instance's `name`.
    /// Exposed under a distinct name since [`DataType::get_mnemonic`] already provides a
    /// (different) default. A concrete `impl DataType for ...` should delegate to this.
    fn undefined1_get_mnemonic(&self, settings: &dyn Settings) -> String {
        let _ = settings;
        self.get_name()
    }

    /// Port of `Undefined1DataType.getRepresentation(MemBuffer, Settings, int)`. Exposed under a
    /// distinct name since [`DataType::get_representation`] already provides a (different)
    /// default. A concrete `impl DataType for ...` should delegate to this.
    fn undefined1_get_representation(
        &self,
        buf: &dyn MemBuffer,
        settings: &dyn Settings,
        length: i32,
    ) -> String {
        let _ = (settings, length);
        match undefined_byte_value(buf) {
            Ok(val) => {
                let hex = format!("{val:X}");
                StringFormat::pad_it(&hex, 2, 'h', true)
            }
            Err(_) => "??".to_string(),
        }
    }

    /// Port of `Undefined1DataType.getValue(MemBuffer, Settings, int)`, which returns the
    /// undefined byte as an unsigned 8-bit `Scalar`. Exposed under a distinct name since
    /// [`DataType::get_value`] already provides a (different) default. A concrete `impl DataType
    /// for ...` should delegate to this.
    fn undefined1_get_value(
        &self,
        buf: &dyn MemBuffer,
        settings: &dyn Settings,
        length: i32,
    ) -> Option<Box<dyn Any>> {
        let _ = (settings, length);
        undefined_byte_value(buf)
            .ok()
            .map(|val| Box::new(Scalar::new(8, val)) as Box<dyn Any>)
    }

    /// Port of `Undefined1DataType.clone(DataTypeManager)`. Returns `self` unchanged when `dtm`
    /// already matches this instance's manager, otherwise a fresh instance bound to `dtm`. Left as
    /// a required method (no default); see the module docs for why.
    fn undefined1_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn Undefined1DataType>;
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
    struct MockUndefined1 {
        bound_to_other_manager: bool,
    }

    impl DataType for MockUndefined1 {
        fn get_name(&self) -> String {
            "undefined1".to_string()
        }
        fn get_category_path(&self) -> CategoryPath {
            ROOT.clone()
        }
        fn get_length(&self) -> i32 {
            self.undefined1_get_length()
        }
        fn get_description(&self) -> String {
            self.undefined1_get_description()
        }
        fn get_mnemonic(&self, settings: &dyn Settings) -> String {
            self.undefined1_get_mnemonic(settings)
        }
        fn get_representation(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> String {
            self.undefined1_get_representation(buf, settings, length)
        }
        fn get_value(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> Option<Box<dyn Any>> {
            self.undefined1_get_value(buf, settings, length)
        }
        fn is_undefined_type(&self) -> bool {
            true
        }
    }

    impl BuiltInDataType for MockUndefined1 {
        fn get_c_type_declaration(
            &self,
            _data_organization: Option<&dyn DataOrganization>,
        ) -> Option<String> {
            None
        }
        fn set_default_settings(&mut self, _settings: &dyn Settings) {}
    }

    impl Undefined for MockUndefined1 {}

    impl Undefined1DataType for MockUndefined1 {
        fn undefined1_clone(
            &self,
            dtm: Option<Box<dyn DataTypeManager>>,
        ) -> Box<dyn Undefined1DataType> {
            match dtm {
                Some(_) if self.bound_to_other_manager => {
                    Box::new(MockUndefined1 { bound_to_other_manager: false })
                }
                _ => Box::new(self.clone()),
            }
        }
    }

    struct MockBuf {
        byte: i8,
    }
    impl MemBuffer for MockBuf {
        fn get_bytes(&self, _buf: &mut [u8], _offset: i32) -> usize {
            unimplemented!("not exercised by these tests")
        }
        fn is_big_endian(&self) -> bool {
            unimplemented!("not exercised by these tests")
        }
        fn get_address(&self) -> Address {
            SpecialAddress::no_address()
        }
        fn get_byte(&self, _offset: i32) -> Result<u8, MemoryAccessException> {
            Ok(self.byte as u8)
        }
    }

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    #[test]
    fn usable_as_trait_object() {
        let dt: Box<dyn Undefined1DataType> = Box::new(MockUndefined1 { bound_to_other_manager: false });
        assert_eq!(dt.undefined1_get_length(), 1);
        assert_eq!(dt.undefined1_get_description(), "Undefined Byte");
        assert!(dt.is_undefined_type());
    }

    #[test]
    fn mnemonic_delegates_to_instance_name() {
        let dt = MockUndefined1 { bound_to_other_manager: false };
        let settings = MockSettings;
        assert_eq!(dt.undefined1_get_mnemonic(&settings), "undefined1");
    }

    #[test]
    fn representation_pads_single_hex_digit_with_trailing_h() {
        let dt = MockUndefined1 { bound_to_other_manager: false };
        let settings = MockSettings;
        let buf = MockBuf { byte: 0x0A };
        assert_eq!(dt.undefined1_get_representation(&buf, &settings, 1), "0Ah");
    }

    #[test]
    fn representation_does_not_pad_two_hex_digits() {
        let dt = MockUndefined1 { bound_to_other_manager: false };
        let settings = MockSettings;
        let buf = MockBuf { byte: 0xFFu8 as i8 };
        assert_eq!(dt.undefined1_get_representation(&buf, &settings, 1), "FFh");
    }

    #[test]
    fn value_is_unsigned_8_bit_scalar_masked_from_the_byte() {
        let dt = MockUndefined1 { bound_to_other_manager: false };
        let settings = MockSettings;
        let buf = MockBuf { byte: -1 };

        let value = dt.undefined1_get_value(&buf, &settings, 1).unwrap();
        let scalar = value.downcast_ref::<Scalar>().unwrap();
        assert_eq!(scalar.get_unsigned_value(), 0xff);
    }

    #[test]
    fn clone_with_matching_manager_preserves_identity() {
        let dt = MockUndefined1 { bound_to_other_manager: false };
        let cloned = dt.undefined1_clone(Some(Box::new(MockDataTypeManager)));
        assert_eq!(cloned.get_name(), "undefined1");
    }

    #[test]
    fn clone_with_new_manager_rebinds_instance() {
        let dt = MockUndefined1 { bound_to_other_manager: true };
        let cloned = dt.undefined1_clone(Some(Box::new(MockDataTypeManager)));
        assert_eq!(cloned.get_name(), "undefined1");
        assert_eq!(cloned.undefined1_get_length(), 1);
    }
}

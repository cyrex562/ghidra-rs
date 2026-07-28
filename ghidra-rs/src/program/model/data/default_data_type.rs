//! Port of `ghidra.program.model.data.DefaultDataType`, promoted to a trait because it was
//! selected as a dependency-cycle cut-point.
//!
//! The Java class `extends DataTypeImpl` and is otherwise a private, single-instance singleton
//! (`DefaultDataType.dataType`) representing a byte that has not yet been defined as a particular
//! type of data. Mirroring [`DataTypeImpl`](super::data_type_impl)'s own treatment of its
//! supertrait, this trait extends [`DataTypeImpl`] directly, since `DefaultDataType.java`
//! contributes no interface beyond it -- only *behavior* overrides.
//!
//! Several methods here share a name with an already-provided default method on [`DataType`]
//! (`getMnemonic`, `getLength`, `getDescription`, `getRepresentation`, `getValue`, `addParent`,
//! `removeParent`, `getLastChangeTime`) or delegate to a [`DataTypeImpl`] default under a
//! different name (`clone`/`copy`, which map to [`DataType::clone_data_type`]/
//! [`DataType::copy_data_type`]; `addParent`/`removeParent`, which [`DataTypeImpl`] already
//! overrides via [`DataTypeImpl::data_type_impl_add_parent`]/
//! [`DataTypeImpl::data_type_impl_remove_parent`]). Rust does not allow a subtrait to override a
//! supertrait's same-named default without creating an ambiguous call site, so -- mirroring
//! [`DataTypeImpl`]'s `data_type_impl_*` convention -- those overrides are exposed here under
//! distinct `default_data_type_*` names, each matching the signature of the [`DataType`] method
//! it stands in for so a concrete `impl DataType for ...` can delegate directly.
//!
//! `getValueClass(Settings)` always returns `Scalar.class` here, which *differs* from
//! [`DataType::get_value_class`]'s inherited default (`None`), so -- unlike
//! [`DataTypeImpl`]'s two truly-identical overrides, which were dropped entirely -- it *is*
//! re-declared, as [`DefaultDataType::default_data_type_get_value_class`] (Java's `Scalar.class`
//! corresponds to [`std::any::TypeId::of::<Scalar>()`]).
//!
//! `clone(DataTypeManager)`/`copy(DataTypeManager)` both just `return this` in Java (the type is a
//! private singleton, so handing back the same reference is always correct). A default trait
//! method can't return `Self` as a fresh `Box<dyn DataType>` without knowing `Self` is `Clone`, so
//! [`default_data_type_clone`](DefaultDataType::default_data_type_clone)/
//! [`default_data_type_copy`](DefaultDataType::default_data_type_copy) each add a
//! `Self: Clone + 'static` bound (mirroring
//! [`DataTypeImpl::data_type_impl_get_alignment`]'s precedent of dropping a single method from
//! the vtable via a per-method `Self: Sized` bound, which keeps the rest of the trait usable as
//! `dyn DefaultDataType`) and hand back `Box::new(self.clone())`.
//!
//! `isEquivalent(DataType)` is Java reference equality (`dt == this`), ported the same way
//! [`DataTypeImpl::data_type_impl_remove_parent`] ports its own `dt == dataType` check: raw
//! data-pointer comparison, since `dyn DataType` has no identity operator. This likewise requires
//! a per-method `Self: Sized` bound, to unsize-coerce `self` to `&dyn DataType` for the
//! comparison.
//!
//! `getLastChangeTime()` returns
//! [`NO_SOURCE_SYNC_TIME`](crate::program::model::data::data_type::NO_SOURCE_SYNC_TIME) rather
//! than the inherited [`DataTypeImpl`] default's stored-field value (both are `0` today for a
//! freshly-constructed instance, but the Java source explicitly names the sync-time constant, so
//! that choice is ported faithfully rather than left to the inherited default).
//!
//! The private constructor (`DefaultDataType()`, which forwards `CategoryPath.ROOT, "undefined",
//! null` to the `DataTypeImpl` supertype constructor) and the public static singleton field
//! (`DefaultDataType.dataType`) have no trait equivalent (traits declare neither constructors nor
//! static fields); each concrete implementor is expected to name itself `"undefined"` and live at
//! [`CategoryPath::ROOT`](crate::program::model::data::category_path::ROOT) via
//! [`DataType::get_name`]/[`DataType::get_category_path`], and to expose its own singleton
//! instance however it sees fit (e.g. a `once_cell::sync::Lazy` static, mirroring this crate's
//! existing [`ROOT`](crate::program::model::data::category_path::ROOT) convention).
//!
//! Implementors are expected to override [`DataType::is_default_data_type`] to return `true`,
//! mirroring the precedent [`Undefined`](crate::program::model::data::undefined::Undefined) sets
//! for [`DataType::is_undefined_type`] -- that flag (not a downcast to this trait) is what
//! [`Undefined::is_undefined`](crate::program::model::data::undefined::is_undefined) actually
//! checks for the `instanceof DefaultDataType` case.

use std::any::{Any, TypeId};

use crate::docking::settings::settings::Settings;
use crate::program::model::data::data_type::{DataType, NO_SOURCE_SYNC_TIME};
use crate::program::model::data::data_type_impl::DataTypeImpl;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::scalar::scalar::Scalar;
use crate::program::seam_stubs::MemBuffer;

/// Port of `ghidra.program.model.data.DefaultDataType`.
///
/// Represents a byte that has not yet been defined as a particular type of data in the program.
/// See the module docs for what was ported, added, and omitted.
pub trait DefaultDataType: DataTypeImpl {
    /// Port of `DefaultDataType.getMnemonic(Settings)`. Exposed under a distinct name since
    /// [`DataType::get_mnemonic`] already provides a (different) default. A concrete `impl
    /// DataType for ...` should delegate to this.
    fn default_data_type_get_mnemonic(&self, settings: &dyn Settings) -> String {
        let _ = settings;
        "??".to_string()
    }

    /// Port of `DefaultDataType.getLength()`. Exposed under a distinct name since
    /// [`DataType::get_length`] already provides a (different) default. A concrete `impl DataType
    /// for ...` should delegate to this.
    fn default_data_type_get_length(&self) -> i32 {
        1
    }

    /// Port of `DefaultDataType.getDescription()`. Exposed under a distinct name since
    /// [`DataType::get_description`] already provides a (different) default. A concrete `impl
    /// DataType for ...` should delegate to this.
    fn default_data_type_get_description(&self) -> String {
        "Undefined Byte".to_string()
    }

    /// Port of `DefaultDataType.getRepresentation(MemBuffer, Settings, int)`. Exposed under a
    /// distinct name since [`DataType::get_representation`] already provides a (different)
    /// default. A concrete `impl DataType for ...` should delegate to this.
    fn default_data_type_get_representation(
        &self,
        buf: &dyn MemBuffer,
        settings: &dyn Settings,
        length: i32,
    ) -> String {
        let _ = (settings, length);
        match buf.get_byte(0) {
            Ok(byte) => {
                let b = (byte as u8) as u32;
                let mut rep = format!("{b:X}h");
                if rep.len() == 2 {
                    rep = format!("0{rep}");
                }
                if b > 31 && b < 128 {
                    rep.push_str("    ");
                    rep.push(b as u8 as char);
                }
                rep
            }
            Err(_) => "??".to_string(),
        }
    }

    /// Port of `DefaultDataType.getValue(MemBuffer, Settings, int)`, which returns the undefined
    /// byte as a `Scalar`. Exposed under a distinct name since [`DataType::get_value`] already
    /// provides a (different) default. A concrete `impl DataType for ...` should delegate to
    /// this.
    fn default_data_type_get_value(
        &self,
        buf: &dyn MemBuffer,
        settings: &dyn Settings,
        length: i32,
    ) -> Option<Box<dyn Any>> {
        let _ = (settings, length);
        buf.get_byte(0)
            .ok()
            .map(|byte| Box::new(Scalar::new(8, byte as i64)) as Box<dyn Any>)
    }

    /// Port of `DefaultDataType.getValueClass(Settings)`, which always returns `Scalar.class`.
    /// Exposed under a distinct name since [`DataType::get_value_class`]'s inherited default
    /// (`None`) differs from this override's value; a concrete `impl DataType for ...` should
    /// delegate to this.
    fn default_data_type_get_value_class(&self, settings: &dyn Settings) -> Option<TypeId> {
        let _ = settings;
        Some(TypeId::of::<Scalar>())
    }

    /// Port of `DefaultDataType.clone(DataTypeManager)`, which just `return this` (the type is a
    /// private singleton). Requires `Self: Clone + 'static` to hand back a fresh owned copy of
    /// the same value; see the module docs for why this drops the method from the trait's vtable.
    fn default_data_type_clone(&self, dtm: &dyn DataTypeManager) -> Box<dyn DataType>
    where
        Self: Clone + 'static,
    {
        let _ = dtm;
        Box::new(self.clone())
    }

    /// Port of `DefaultDataType.copy(DataTypeManager)`, which just `return this` (the type is a
    /// private singleton). Requires `Self: Clone + 'static`; see
    /// [`default_data_type_clone`](Self::default_data_type_clone) and the module docs.
    fn default_data_type_copy(&self, dtm: &dyn DataTypeManager) -> Box<dyn DataType>
    where
        Self: Clone + 'static,
    {
        let _ = dtm;
        Box::new(self.clone())
    }

    /// Port of `DefaultDataType.isEquivalent(DataType)`, Java reference equality (`dt == this`).
    /// Approximated via raw data-pointer comparison, mirroring
    /// [`DataTypeImpl::data_type_impl_remove_parent`]'s identical approximation for its own
    /// reference-equality check. Requires `Self: Sized` to unsize-coerce `self` to `&dyn
    /// DataType`; see the module docs.
    fn default_data_type_is_equivalent(&self, dt: &dyn DataType) -> bool
    where
        Self: Sized,
    {
        let self_ptr = self as *const Self as *const ();
        let other_ptr = dt as *const dyn DataType as *const ();
        std::ptr::eq(self_ptr, other_ptr)
    }

    /// Port of `DefaultDataType.addParent(DataType)`, a no-op ("this datatype is STATIC, don't
    /// hold on to parents"). Exposed under a distinct name since
    /// [`DataTypeImpl::data_type_impl_add_parent`] already provides a (different, storing)
    /// default. A concrete `impl DataType for ...` should delegate to this instead.
    fn default_data_type_add_parent(&mut self, dt: &dyn DataType) {
        let _ = dt;
    }

    /// Port of `DefaultDataType.removeParent(DataType)`, a no-op ("this datatype is STATIC, don't
    /// hold on to parents"). Exposed under a distinct name since
    /// [`DataTypeImpl::data_type_impl_remove_parent`] already provides a (different, mutating)
    /// default. A concrete `impl DataType for ...` should delegate to this instead.
    fn default_data_type_remove_parent(&mut self, dt: &dyn DataType) {
        let _ = dt;
    }

    /// Port of `DefaultDataType.getLastChangeTime()`, which returns `NO_SOURCE_SYNC_TIME` rather
    /// than the inherited [`DataTypeImpl`] default's stored-field value. Exposed under a distinct
    /// name since [`DataTypeImpl::data_type_impl_get_last_change_time`] already provides that
    /// (different) default.
    fn default_data_type_get_last_change_time(&self) -> i64 {
        NO_SOURCE_SYNC_TIME
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::data::category_path::{CategoryPath, ROOT};
    use crate::program::model::data::data_type_impl::DataTypeImpl;
    use crate::program::model::scalar::scalar::Scalar;
    use crate::program::model::address::{Address, SpecialAddress};
    use crate::program::model::data::data_type_manager::DataTypeManager;
    use crate::program::model::data::source_archive::SourceArchive;
    use crate::program::model::mem::MemoryAccessException;
    use crate::util::UniversalID;
    use std::sync::Weak;

    struct MockSettings;
    impl Settings for MockSettings {
        fn is_immutable_settings(&self) -> bool {
            true
        }
    }

    #[derive(Clone)]
    struct MockUndefinedByte;

    impl DataType for MockUndefinedByte {
        fn get_name(&self) -> String {
            "undefined".to_string()
        }
        fn get_category_path(&self) -> CategoryPath {
            ROOT.clone()
        }
        fn get_mnemonic(&self, settings: &dyn Settings) -> String {
            self.default_data_type_get_mnemonic(settings)
        }
        fn get_length(&self) -> i32 {
            self.default_data_type_get_length()
        }
        fn get_description(&self) -> String {
            self.default_data_type_get_description()
        }
        fn get_representation(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> String {
            self.default_data_type_get_representation(buf, settings, length)
        }
        fn get_value(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> Option<Box<dyn Any>> {
            self.default_data_type_get_value(buf, settings, length)
        }
        fn get_value_class(&self, settings: &dyn Settings) -> Option<TypeId> {
            self.default_data_type_get_value_class(settings)
        }
        fn is_equivalent(&self, dt: &dyn DataType) -> bool {
            self.default_data_type_is_equivalent(dt)
        }
        fn is_default_data_type(&self) -> bool {
            true
        }
    }

    impl DataTypeImpl for MockUndefinedByte {
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

    impl DefaultDataType for MockUndefinedByte {}

    struct MockBuf {
        byte: i8,
    }
    impl MemBuffer for MockBuf {
        fn get_address(&self) -> Address {
            SpecialAddress::no_address()
        }
        fn get_byte(&self, _offset: i32) -> Result<i8, MemoryAccessException> {
            Ok(self.byte)
        }
    }

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    #[test]
    fn usable_as_trait_object() {
        let dt: Box<dyn DefaultDataType> = Box::new(MockUndefinedByte);
        assert_eq!(dt.get_name(), "undefined");
        assert_eq!(dt.default_data_type_get_length(), 1);
        assert_eq!(dt.default_data_type_get_description(), "Undefined Byte");
        assert!(dt.is_default_data_type());
    }

    #[test]
    fn representation_pads_single_hex_digit_for_non_printable_byte() {
        let dt = MockUndefinedByte;
        let settings = MockSettings;

        let buf = MockBuf { byte: 0x0A };
        assert_eq!(dt.default_data_type_get_representation(&buf, &settings, 1), "0Ah");
    }

    #[test]
    fn representation_appends_printable_char_for_ascii_byte() {
        let dt = MockUndefinedByte;
        let settings = MockSettings;

        let buf = MockBuf { byte: 0x41 };
        assert_eq!(dt.default_data_type_get_representation(&buf, &settings, 1), "41h    A");
    }

    #[test]
    fn representation_omits_char_suffix_outside_printable_range() {
        let dt = MockUndefinedByte;
        let settings = MockSettings;

        let buf = MockBuf { byte: 0x00u8 as i8 };
        assert_eq!(dt.default_data_type_get_representation(&buf, &settings, 1), "00h");

        let buf = MockBuf { byte: 0xFFu8 as i8 };
        assert_eq!(dt.default_data_type_get_representation(&buf, &settings, 1), "FFh");
    }

    #[test]
    fn value_is_signed_8_bit_scalar_of_the_byte() {
        let dt = MockUndefinedByte;
        let settings = MockSettings;
        let buf = MockBuf { byte: -1 };

        let value = dt.default_data_type_get_value(&buf, &settings, 1).unwrap();
        let scalar = value.downcast_ref::<Scalar>().unwrap();
        assert_eq!(scalar.get_signed_value(), -1);
        assert!(scalar.is_signed());
    }

    #[test]
    fn value_class_is_scalar() {
        let dt = MockUndefinedByte;
        let settings = MockSettings;
        assert_eq!(
            dt.default_data_type_get_value_class(&settings),
            Some(TypeId::of::<Scalar>())
        );
    }

    #[test]
    fn is_equivalent_is_reference_equality_not_structural() {
        let a = MockUndefinedByte;
        let b = MockUndefinedByte;
        assert!(a.default_data_type_is_equivalent(&a));
        assert!(!a.default_data_type_is_equivalent(&b));
    }

    #[test]
    fn clone_and_copy_return_an_equivalent_singleton_instance() {
        let dt = MockUndefinedByte;
        let dtm = MockDataTypeManager;
        assert_eq!(dt.default_data_type_clone(&dtm).get_name(), "undefined");
        assert_eq!(dt.default_data_type_copy(&dtm).get_name(), "undefined");
    }

    #[test]
    fn add_and_remove_parent_are_no_ops() {
        let mut dt = MockUndefinedByte;
        // Should not panic, and should not need any parent-storage state to be wired up.
        dt.default_data_type_add_parent(&MockUndefinedByte);
        dt.default_data_type_remove_parent(&MockUndefinedByte);
    }

    #[test]
    fn last_change_time_is_no_source_sync_time() {
        let dt = MockUndefinedByte;
        assert_eq!(dt.default_data_type_get_last_change_time(), NO_SOURCE_SYNC_TIME);
        assert_eq!(dt.default_data_type_get_last_change_time(), 0);
    }
}

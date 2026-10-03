//! Port of `ghidra.program.model.data.DefaultDataType`.
//!
//! The Java class is a private-constructor singleton (`DefaultDataType.dataType`) that extends
//! `DataTypeImpl` (not `BuiltIn`): a byte that has not yet been defined as a particular type of
//! data. It is exposed here as [`DefaultDataType::data_type`] / [`DefaultDataType::instance`];
//! there is no public constructor, matching Java.
//!
//! `clone`/`copy` return `this` in Java. Rust hands out an owned `Box<dyn DataType>`, so they
//! return another handle on the same (stateless apart from its universal ID) value;
//! `isEquivalent` (`dt == this`) accordingly holds for exactly the `DefaultDataType` values.

use std::any::{Any, TypeId};
use std::sync::{Arc, OnceLock, Weak};

use crate::docking::settings::settings::Settings;
use crate::program::model::data::built_in::{same_class, shared_default_organization, DefaultSettingsSnapshot};
use crate::program::model::data::category_path::{CategoryPath, ROOT};
use crate::program::model::data::data_organization_impl::DataOrganizationImpl;
use crate::program::model::data::data_type::{DataType, NO_SOURCE_SYNC_TIME};
use crate::program::model::data::data_type_impl::DataTypeImpl;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::data::source_archive::SourceArchive;
use crate::program::model::mem::MemBuffer;
use crate::program::model::scalar::Scalar;
use crate::util::universal_id_generator::next_id;
use crate::util::UniversalID;

/// The Java name of the default data type.
const NAME: &str = "undefined";

/// Provides an implementation of a byte that has not been defined yet as a particular type of
/// data in the program.
///
/// Port of `ghidra.program.model.data.DefaultDataType`.
#[derive(Debug, Clone)]
pub struct DefaultDataType {
    universal_id: UniversalID,
}

impl DefaultDataType {
    /// The singleton instance (Java: `DefaultDataType.dataType`).
    pub fn instance() -> &'static Arc<DefaultDataType> {
        static INSTANCE: OnceLock<Arc<DefaultDataType>> = OnceLock::new();
        INSTANCE.get_or_init(|| Arc::new(DefaultDataType { universal_id: next_id() }))
    }

    /// An owned handle on the singleton value (Java: `DataType.DEFAULT` where a caller holds data
    /// types as `Box<dyn DataType>`).
    pub fn boxed() -> Box<dyn DataType> {
        Box::new(DefaultDataType::instance().as_ref().clone())
    }

    /// The singleton instance as a `DataType` handle (Java: `DefaultDataType.dataType`).
    pub fn data_type() -> Arc<dyn DataType> {
        DefaultDataType::instance().clone()
    }
}

impl std::fmt::Display for DefaultDataType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(NAME)
    }
}

impl DataTypeImpl for DefaultDataType {
    fn stored_default_settings(&self) -> Box<dyn Settings> {
        // `SettingsImpl.NO_SETTINGS`.
        Box::new(DefaultSettingsSnapshot::default())
    }
    // The singleton's settings are the immutable `NO_SETTINGS`.
    fn set_stored_default_settings(&mut self, _settings: Box<dyn Settings>) {}
    fn stored_source_archive(&self) -> Option<Box<dyn SourceArchive>> {
        None
    }
    fn set_stored_source_archive(&mut self, _archive: Option<Box<dyn SourceArchive>>) {}
    fn stored_universal_id(&self) -> UniversalID {
        self.universal_id
    }
    fn stored_last_change_time(&self) -> i64 {
        NO_SOURCE_SYNC_TIME
    }
    fn set_stored_last_change_time(&mut self, _last_change_time: i64) {}
    fn stored_last_change_time_in_source_archive(&self) -> i64 {
        NO_SOURCE_SYNC_TIME
    }
    fn set_stored_last_change_time_in_source_archive(&mut self, _last_change_time: i64) {}
    // "this datatype is STATIC, don't hold on to parents".
    fn stored_parent_refs(&self) -> Vec<Weak<dyn DataType>> {
        Vec::new()
    }
    fn set_stored_parent_refs(&mut self, _parents: Vec<Weak<dyn DataType>>) {}
}

impl DataType for DefaultDataType {
    fn get_name(&self) -> String {
        NAME.to_string()
    }

    fn get_category_path(&self) -> CategoryPath {
        ROOT.clone()
    }

    fn get_data_organization(&self) -> Arc<DataOrganizationImpl> {
        shared_default_organization()
    }

    fn get_default_settings(&self) -> Box<dyn Settings> {
        self.data_type_impl_get_default_settings()
    }

    /// Port of `DefaultDataType.getMnemonic(Settings)`.
    fn get_mnemonic(&self, _settings: &dyn Settings) -> String {
        "??".to_string()
    }

    fn get_length(&self) -> i32 {
        1
    }

    fn get_aligned_length(&self) -> i32 {
        self.data_type_impl_get_aligned_length()
    }

    fn get_alignment(&self) -> i32 {
        self.data_type_impl_get_alignment()
    }

    fn get_description(&self) -> String {
        "Undefined Byte".to_string()
    }

    /// Port of `DefaultDataType.getRepresentation`: two upper-case hex digits and `h`, followed by
    /// the character itself when the byte is printable ASCII (32..=127 exclusive of 127).
    fn get_representation(&self, buf: &dyn MemBuffer, _settings: &dyn Settings, _length: i32) -> String {
        match buf.get_byte(0) {
            Ok(b) => {
                let mut rep = format!("{b:X}h");
                if rep.len() == 2 {
                    rep = format!("0{rep}");
                }
                if b > 31 && b < 128 {
                    rep.push_str("    ");
                    rep.push(b as char);
                }
                rep
            }
            Err(_) => "??".to_string(),
        }
    }

    /// Port of `DefaultDataType.getValue`: a signed 8-bit [`Scalar`] of the byte.
    fn get_value(&self, buf: &dyn MemBuffer, _settings: &dyn Settings, _length: i32) -> Option<Box<dyn Any>> {
        buf.get_signed_byte(0)
            .ok()
            .map(|b| Box::new(Scalar::new(8, b as i64)) as Box<dyn Any>)
    }

    fn get_value_class(&self, _settings: &dyn Settings) -> Option<TypeId> {
        Some(TypeId::of::<Scalar>())
    }

    fn clone_data_type(&self, _dtm: &dyn DataTypeManager) -> Box<dyn DataType> {
        Box::new(self.clone())
    }

    fn copy_data_type(&self, _dtm: &dyn DataTypeManager) -> Box<dyn DataType> {
        Box::new(self.clone())
    }

    fn is_equivalent(&self, dt: &dyn DataType) -> bool {
        same_class(self, dt)
    }

    fn get_universal_id(&self) -> UniversalID {
        self.data_type_impl_get_universal_id()
    }

    fn get_last_change_time(&self) -> i64 {
        NO_SOURCE_SYNC_TIME
    }

    fn get_default_abbreviated_label_prefix(&self) -> Option<String> {
        self.get_default_label_prefix()
    }

    fn runtime_class(&self) -> Option<TypeId> {
        Some(TypeId::of::<Self>())
    }

    fn is_default_data_type(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::data::abstract_integer_data_type::test_support::{buf, LongSettings};
    use crate::program::model::data::byte_data_type::ByteDataType;
    use crate::program::model::data::undefined::{get_undefined_data_type, is_undefined};

    #[test]
    fn java_constants() {
        let dt = DefaultDataType::instance();
        assert_eq!(dt.get_name(), "undefined");
        assert_eq!(dt.get_path_name(), "/undefined");
        assert_eq!(dt.get_length(), 1);
        assert_eq!(dt.get_aligned_length(), 1);
        assert_eq!(dt.get_description(), "Undefined Byte");
        assert_eq!(dt.get_mnemonic(&LongSettings::default()), "??");
        assert_eq!(dt.get_value_class(&LongSettings::default()), Some(TypeId::of::<Scalar>()));
        assert_eq!(dt.get_last_change_time(), 0);
        assert!(dt.get_settings_definitions().is_empty());
        assert!(dt.get_default_settings().is_empty());
        assert!(dt.get_default_settings().is_immutable_settings());
        assert!(dt.get_source_archive().is_none());
    }

    #[test]
    fn representation_shows_printable_characters() {
        let dt = DefaultDataType::instance();
        let s = LongSettings::default();
        assert_eq!(dt.get_representation(&buf(&[0x41], false), &s, 1), "41h    A");
        assert_eq!(dt.get_representation(&buf(&[0x05], false), &s, 1), "05h");
        assert_eq!(dt.get_representation(&buf(&[0x20], false), &s, 1), "20h     ");
        assert_eq!(dt.get_representation(&buf(&[0x7f], false), &s, 1), "7Fh    \u{7f}");
        assert_eq!(dt.get_representation(&buf(&[0x80], false), &s, 1), "80h");
        assert_eq!(dt.get_representation(&buf(&[0x1f], false), &s, 1), "1Fh");
        assert_eq!(dt.get_representation(&buf(&[], false), &s, 1), "??");
    }

    #[test]
    fn value_is_signed_byte_scalar() {
        let dt = DefaultDataType::instance();
        let s = LongSettings::default();
        let value = dt.get_value(&buf(&[0xff], false), &s, 1).unwrap();
        let scalar = value.downcast_ref::<Scalar>().unwrap();
        assert_eq!(scalar.get_signed_value(), -1);
        assert_eq!(scalar.bit_length(), 8);
        assert!(dt.get_value(&buf(&[], false), &s, 1).is_none());
    }

    #[test]
    fn singleton_identity_and_undefined_helpers() {
        let a = DefaultDataType::data_type();
        assert!(Arc::ptr_eq(&a, &DefaultDataType::data_type()));
        assert!(Arc::ptr_eq(&a, &get_undefined_data_type(0)));
        assert!(Arc::ptr_eq(&a, &get_undefined_data_type(-3)));
        assert!(a.is_default_data_type());
        assert!(a.is_equivalent(DefaultDataType::instance().as_ref()));
        assert!(!a.is_equivalent(ByteDataType::instance().as_ref()));
        assert!(is_undefined(Box::new(DefaultDataType::instance().as_ref().clone())));
        assert_eq!(a.get_universal_id(), DefaultDataType::instance().get_universal_id());
    }
}

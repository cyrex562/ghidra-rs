//! Port of `ghidra.program.model.data.BadDataType`, promoted to a trait because it was selected
//! as a dependency-cycle cut-point.
//!
//! The Java class `extends BuiltIn implements Dynamic`, so this trait extends both already-ported
//! traits: [`BuiltIn`] and [`Dynamic`] -- mirroring
//! [`AIFFDataType`](super::aiff_data_type::AIFFDataType)/
//! [`AlignmentDataType`](super::alignment_data_type::AlignmentDataType), which document the same
//! shape of `BuiltIn + Dynamic` cut-point in more detail.
//!
//! Several methods here share a name with an already-provided default method on [`DataType`]/
//! [`Dynamic`] (`getMnemonic(Settings)`, `getLength()`, `getDescription()`, `getValue(...)`,
//! `isEquivalent(DataType)`, `getRepresentation(...)`, `canSpecifyLength()`, `getLength(MemBuffer,
//! int)`). Rust does not allow a subtrait to override a supertrait's same-named default without
//! creating an ambiguous call site, so -- mirroring [`AIFFDataType`]'s `aiff_*` convention -- most
//! are exposed here under distinct `bad_*` names. A concrete `impl DataType + BuiltInDataType +
//! Dynamic for ...` should delegate to these; [`Dynamic::get_dynamic_length`] has no default at
//! all, so a concrete implementation's override should delegate to
//! [`bad_dynamic_length`](BadDataType::bad_dynamic_length) directly.
//!
//! `isEquivalent(DataType)` (`dt instanceof BadDataType`) is *not* given a new `bad_*` method
//! here: it is exactly the same override point [`BuiltIn::built_in_is_equivalent`] already left
//! required (no default) for this reason -- an arbitrary `&dyn DataType` carries no runtime type
//! identity generically (see [`BuiltIn`]'s own module docs). A concrete implementation's
//! `built_in_is_equivalent` should implement `dt instanceof BadDataType` directly (e.g. via its
//! own [`DataType::is_bad_type`]-style marker, following the established `is_void_type`/
//! `is_boolean_type` convention, should one ever be added to [`DataType`]).
//!
//! `getReplacementBaseType()` (overriding the abstract `Dynamic.getReplacementBaseType()`) returns
//! Java `null` -- unlike every other `Dynamic` cut-point trait in this crate (which always returns
//! a real placeholder `Box<dyn DataType>`, since that trait method has no `Option` wrapper).
//! [`BadDataType::bad_replacement_base_type`] is exposed as `Option<Box<dyn DataType>>` to
//! preserve that `null` faithfully; a concrete `Dynamic::get_replacement_base_type` override
//! cannot return `None` directly (the trait signature requires an owned `Box<dyn DataType>`), so
//! it must decide its own `null`-safe fallback (e.g. panicking, matching what any real Java caller
//! dereferencing this `null` would already risk).
//!
//! `clone(DataTypeManager)` always returns `this` unconditionally (the Java constructor is
//! private, enforcing a true singleton) -- unlike every other `BuiltIn.clone(DataTypeManager)`
//! override in this crate (which builds a *new* instance bound to `dtm` when it differs). Left as
//! a required method (no default) since returning `self` as a `Box<dyn BadDataType>` from `&self`
//! is not expressible generically without `Self: Sized + Clone`; a concrete implementation should
//! have this simply clone/rewrap itself regardless of `dtm`.

use std::any::Any;

use crate::docking::settings::settings::Settings;
use crate::program::model::data::built_in::BuiltIn;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::data::dynamic::Dynamic;
use crate::program::model::mem::MemBuffer;

/// Provides an implementation of a data type that is not valid (bad) as it is used in the
/// program.
///
/// Port of `ghidra.program.model.data.BadDataType`. See the module docs for the naming
/// conventions used to resolve clashes with [`DataType`]/[`Dynamic`], and for what was left
/// required or given an `Option`-shaped stand-in for `null`.
pub trait BadDataType: BuiltIn + Dynamic {
    /// Port of `BadDataType.getDescription()`, which overrides the default
    /// `DataType.getDescription()`.
    fn bad_description(&self) -> String {
        "** Bad Data Type **".to_string()
    }

    /// Port of `BadDataType.getMnemonic(Settings)`, which overrides the default
    /// `DataType.getMnemonic(Settings)`. Falls back to [`DataType::get_name`], matching the Java
    /// `return getName();` body.
    fn bad_mnemonic(&self, settings: &dyn Settings) -> String {
        let _ = settings;
        self.get_name()
    }

    /// Port of `BadDataType.getLength()`, which overrides the default `DataType.getLength()`
    /// (which returns `0`, not the `-1` this type reports).
    fn bad_length(&self) -> i32 {
        -1
    }

    /// Port of `BadDataType.getValue(MemBuffer, Settings, int)`, which overrides the default
    /// `DataType.getValue(...)`. Returns [`bad_description`](Self::bad_description), boxed as
    /// `Any` (standing in for `Object`), matching the Java `return getDescription();` body.
    fn bad_value(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> Option<Box<dyn Any>> {
        let _ = (buf, settings, length);
        Some(Box::new(self.bad_description()) as Box<dyn Any>)
    }

    /// Port of `BadDataType.getRepresentation(MemBuffer, Settings, int)`, which overrides the
    /// default `DataType.getRepresentation(...)`. Always
    /// [`bad_description`](Self::bad_description), matching the Java original.
    fn bad_representation(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> String {
        let _ = (buf, settings, length);
        self.bad_description()
    }

    /// Port of `BadDataType.canSpecifyLength()`, which overrides the default
    /// `Dynamic.canSpecifyLength()`. Always `true`.
    fn bad_can_specify_length(&self) -> bool {
        true
    }

    /// Port of `BadDataType.getLength(MemBuffer, int)`, which overrides the abstract
    /// `Dynamic.getLength(MemBuffer, int)` (ported as [`Dynamic::get_dynamic_length`]). Always
    /// `-1`, regardless of `buf`/`max_length`.
    fn bad_dynamic_length(&self, buf: &dyn MemBuffer, max_length: i32) -> i32 {
        let _ = (buf, max_length);
        -1
    }

    /// Port of `BadDataType.getReplacementBaseType()`, which overrides the abstract
    /// `Dynamic.getReplacementBaseType()` and always returns Java `null`. See the module docs for
    /// why this is `Option`-shaped rather than matching `Dynamic::get_replacement_base_type`'s own
    /// non-optional signature.
    fn bad_replacement_base_type(&self) -> Option<Box<dyn DataType>> {
        None
    }

    /// Returns this same `BadDataType` instance regardless of `dtm`, mirroring
    /// `BadDataType.clone(DataTypeManager)`'s unconditional `return this;` (this type is a true
    /// singleton -- its Java constructor is private). Left as a required method (no default); see
    /// the module docs for why.
    fn bad_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn BadDataType>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, SpecialAddress};
    use crate::program::model::data::built_in_data_type::BuiltInDataType;
    use crate::program::model::data::category_path::{CategoryPath, ROOT};
    use crate::program::model::data::data_organization_impl::DataOrganizationImpl;
    use crate::program::model::data::data_type_impl::DataTypeImpl;
    use crate::program::model::data::source_archive::SourceArchive;
    use crate::program::model::mem::MemoryAccessException;
    use crate::util::UniversalID;
    use std::sync::Weak;

    struct MockSettings;
    impl Settings for MockSettings {}

    struct MockMemBuffer;
    impl MemBuffer for MockMemBuffer {
        fn get_byte(&self, _offset: i32) -> Result<u8, MemoryAccessException> {
            unimplemented!("not exercised by these tests")
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

    struct MockBadDataType;

    impl DataType for MockBadDataType {
        fn get_name(&self) -> String {
            "-BAD-".to_string()
        }
        fn get_category_path(&self) -> CategoryPath {
            ROOT.clone()
        }
        fn get_length(&self) -> i32 {
            self.bad_length()
        }
    }

    impl DataTypeImpl for MockBadDataType {
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

    impl BuiltInDataType for MockBadDataType {
        fn get_c_type_declaration(
            &self,
            _data_organization: Option<&DataOrganizationImpl>,
        ) -> Option<String> {
            None
        }
        fn set_default_settings(&mut self, _settings: &dyn Settings) {}
    }

    impl BuiltIn for MockBadDataType {
        fn built_in_is_equivalent(&self, dt: &dyn DataType) -> bool {
            dt.get_name() == self.get_name()
        }
    }

    impl Dynamic for MockBadDataType {
        fn get_dynamic_length(&self, buf: &dyn MemBuffer, max_length: i32) -> i32 {
            self.bad_dynamic_length(buf, max_length)
        }
        fn can_specify_length(&self) -> bool {
            self.bad_can_specify_length()
        }
        fn get_replacement_base_type(&self) -> Box<dyn DataType> {
            self.bad_replacement_base_type()
                .expect("BadDataType has no replacement base type")
        }
    }

    impl BadDataType for MockBadDataType {
        fn bad_clone(&self, _dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn BadDataType> {
            Box::new(MockBadDataType)
        }
    }

    #[test]
    fn usable_as_trait_object() {
        let dt = MockBadDataType;
        let dyn_dt: &dyn BadDataType = &dt;
        assert_eq!(dyn_dt.bad_description(), "** Bad Data Type **");
        assert_eq!(dyn_dt.bad_mnemonic(&MockSettings), "-BAD-");
        assert_eq!(dyn_dt.bad_length(), -1);
        assert_eq!(DataType::get_length(dyn_dt), -1);
        assert!(dyn_dt.bad_can_specify_length());
        assert!(dyn_dt.can_specify_length());
    }

    #[test]
    fn value_and_representation_are_the_description() {
        let dt = MockBadDataType;
        let buf = MockMemBuffer;
        assert_eq!(dt.bad_representation(&buf, &MockSettings, -1), "** Bad Data Type **");
        let value = dt.bad_value(&buf, &MockSettings, -1).unwrap();
        assert_eq!(value.downcast_ref::<String>().unwrap(), "** Bad Data Type **");
    }

    #[test]
    fn dynamic_length_is_always_negative_one() {
        let dt = MockBadDataType;
        let buf = MockMemBuffer;
        assert_eq!(dt.bad_dynamic_length(&buf, 100), -1);
        assert_eq!(dt.get_dynamic_length(&buf, 100), -1);
    }

    #[test]
    fn replacement_base_type_is_none() {
        let dt = MockBadDataType;
        assert!(dt.bad_replacement_base_type().is_none());
    }

    #[test]
    fn clone_always_returns_an_equivalent_singleton() {
        let dt = MockBadDataType;
        let cloned = dt.bad_clone(None);
        assert_eq!(cloned.bad_description(), dt.bad_description());
        assert_eq!(cloned.get_name(), dt.get_name());
    }
}

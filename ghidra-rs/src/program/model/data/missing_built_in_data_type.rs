//! Port of `ghidra.program.model.data.MissingBuiltInDataType`, promoted to a trait because it
//! was selected as a dependency-cycle cut-point.
//!
//! The Java class `extends DataTypeImpl implements Dynamic`, so this trait extends both
//! already-ported traits: [`DataTypeImpl`] and [`Dynamic`] -- unlike most other `Dynamic`
//! cut-points in this crate (which extend [`BuiltIn`], itself `DataTypeImpl + BuiltInDataType`),
//! this one skips `BuiltIn` and extends `DataTypeImpl` directly, exactly mirroring the Java
//! `extends`/`implements` clause.
//!
//! The private `missingBuiltInName`/`missingBuiltInClassPath` fields have no trait storage
//! equivalent; they are exposed as required accessors,
//! [`MissingBuiltInDataType::missing_built_in_name`]/
//! [`MissingBuiltInDataType::missing_built_in_class_path`], mirroring the
//! `leb128_is_signed`-style accessors used elsewhere in this crate for instance state a trait
//! cannot hold directly. The constructor's `path == null ? CategoryPath.ROOT : path` and
//! `"-MISSING-" + missingBuiltInName` name-composition, and the `BuiltInSourceArchive.INSTANCE`/
//! `NO_SOURCE_SYNC_TIME`/`NO_LAST_CHANGE_TIME` wiring, are all constructor concerns with no trait
//! equivalent (traits declare no constructors); a concrete implementor is expected to replicate
//! them.
//!
//! Several methods here share a name with an already-provided default method on [`DataType`]/
//! [`DataTypeImpl`]/[`Dynamic`] (`getMnemonic(Settings)`, `getLength()`, `getDescription()`,
//! `getRepresentation(...)`, `getValue(...)`, `canSpecifyLength()`, `getLength(MemBuffer, int)`,
//! `getLastChangeTime()`). Rust does not allow a subtrait to override a supertrait's same-named
//! default without creating an ambiguous call site, so -- mirroring
//! [`BadDataType`](super::bad_data_type::BadDataType)'s `bad_*` convention -- those overrides are
//! exposed here under distinct `missing_built_in_*` names. A concrete `impl DataType +
//! BuiltInDataType + DataTypeImpl + Dynamic for ...` should delegate to these;
//! [`Dynamic::get_dynamic_length`]/[`Dynamic::get_replacement_base_type`] have no default at all,
//! so a concrete implementation's overrides should delegate to
//! [`missing_built_in_dynamic_length`](MissingBuiltInDataType::missing_built_in_dynamic_length)/
//! [`missing_built_in_replacement_base_type`](MissingBuiltInDataType::missing_built_in_replacement_base_type)
//! directly.
//!
//! `isEquivalent(DataType)` compares `missingBuiltInClassPath` against another
//! `MissingBuiltInDataType`'s -- unlike [`BadDataType::bad_*`]'s reasoning for the *same* Java
//! method name (there, the override point was already claimed by [`BuiltIn::built_in_is_equivalent`]),
//! nothing in this trait's `DataTypeImpl + Dynamic` supertrait chain claims `is_equivalent`
//! already, so this port could redeclare it directly with no ambiguity -- but it needs a `dt
//! instanceof MissingBuiltInDataType` downcast that no generic `&dyn DataType` provides, so it is
//! exposed under `missing_built_in_is_equivalent` and left required (no default) anyway, for
//! the same "no generic runtime type identity" reason as `BadDataType`'s.
//!
//! `copy(DataTypeManager)` (`final`, wrapping `clone(DataTypeManager)`) is exposed as
//! [`MissingBuiltInDataType::missing_built_in_copy`], mirroring
//! [`BuiltIn::built_in_copy`](super::built_in::BuiltIn::built_in_copy)'s identical shape (delegate
//! to [`DataType::clone_data_type`]) -- needed here since this trait does not extend `BuiltIn` and
//! so cannot reuse that method.
//!
//! `getCTypeDeclaration(DataOrganization)` (always `null`) and `setDefaultSettings(Settings)`
//! (no-op) are exactly [`BuiltInDataType`]'s own required (no-default) methods; every concrete
//! implementor already supplies its own bodies for those (see any other `Dynamic` cut-point's
//! test module in this crate), so no `missing_built_in_*` wrapper is declared for either here --
//! a concrete implementation just needs to return `None`/do nothing, matching the Java override.
//!
//! `setCategory()` is a brand-new protected no-op method (not `@Override`-annotated, and not
//! overriding anything on `DataTypeImpl`/`AbstractDataType`, which only ever declare
//! `setCategoryPath`), so it is ported here as a trivial default with no supertrait relationship,
//! [`MissingBuiltInDataType::missing_built_in_set_category`].
//!
//! `clone(DataTypeManager)` is left as a required method (no default), mirroring every other
//! `DataTypeImpl`/`BuiltIn`-derived cut-point trait in this crate.

use std::any::Any;

use crate::docking::settings::settings::Settings;
use crate::program::model::data::data_type::{DataType, NO_SOURCE_SYNC_TIME};
use crate::program::model::data::data_type_impl::DataTypeImpl;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::data::dynamic::Dynamic;
use crate::program::model::mem::MemBuffer;

/// Provides an implementation of a data type that stands in for a missing built-in data type.
///
/// Port of `ghidra.program.model.data.MissingBuiltInDataType`. See the module docs for the
/// naming conventions used to resolve clashes with [`DataType`]/[`DataTypeImpl`]/[`Dynamic`], and
/// for what was left required.
pub trait MissingBuiltInDataType: DataTypeImpl + Dynamic {
    /// Port of `MissingBuiltInDataType.missingBuiltInName`/`getMissingBuiltInName()`: the name of
    /// the missing built-in data type this instance stands in for. Required since a trait cannot
    /// hold instance state directly.
    fn missing_built_in_name(&self) -> String;

    /// Port of `MissingBuiltInDataType.missingBuiltInClassPath`/`getMissingBuiltInClassPath()`:
    /// the classpath of the missing built-in data type this instance stands in for. Required
    /// since a trait cannot hold instance state directly.
    fn missing_built_in_class_path(&self) -> String;

    /// Port of `MissingBuiltInDataType.getMnemonic(Settings)`, which returns [`DataType::get_name`].
    fn missing_built_in_mnemonic(&self, settings: &dyn Settings) -> String {
        let _ = settings;
        self.get_name()
    }

    /// Port of `MissingBuiltInDataType.getLength()`, which overrides the default
    /// `DataType.getLength()`. Always `-1`.
    fn missing_built_in_length(&self) -> i32 {
        -1
    }

    /// Port of `MissingBuiltInDataType.canSpecifyLength()`, which overrides the default
    /// `Dynamic.canSpecifyLength()`. Always `true`.
    fn missing_built_in_can_specify_length(&self) -> bool {
        true
    }

    /// Port of `MissingBuiltInDataType.getLength(MemBuffer, int)`, which overrides the abstract
    /// `Dynamic.getLength(MemBuffer, int)` (ported as [`Dynamic::get_dynamic_length`]). Always
    /// `-1`, regardless of `buf`/`max_length`.
    fn missing_built_in_dynamic_length(&self, buf: &dyn MemBuffer, max_length: i32) -> i32 {
        let _ = (buf, max_length);
        -1
    }

    /// Port of `MissingBuiltInDataType.getDescription()`, which overrides the default
    /// `DataType.getDescription()`.
    fn missing_built_in_description(&self) -> String {
        format!("Missing Built-In Data Type: {}", self.missing_built_in_class_path())
    }

    /// Port of `MissingBuiltInDataType.getRepresentation(MemBuffer, Settings, int)`, which
    /// overrides the default `DataType.getRepresentation(...)`. Always
    /// [`missing_built_in_class_path`](Self::missing_built_in_class_path).
    fn missing_built_in_representation(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> String {
        let _ = (buf, settings, length);
        self.missing_built_in_class_path()
    }

    /// Port of `MissingBuiltInDataType.getValue(MemBuffer, Settings, int)`, which overrides the
    /// default `DataType.getValue(...)`. Returns
    /// [`missing_built_in_class_path`](Self::missing_built_in_class_path), boxed as `Any`
    /// (standing in for `Object`).
    fn missing_built_in_value(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> Option<Box<dyn Any>> {
        let _ = (buf, settings, length);
        Some(Box::new(self.missing_built_in_class_path()) as Box<dyn Any>)
    }

    /// Port of `MissingBuiltInDataType.getReplacementBaseType()`, which overrides the abstract
    /// `Dynamic.getReplacementBaseType()` and always returns Java `null`. `Option`-shaped rather
    /// than matching `Dynamic::get_replacement_base_type`'s own non-optional signature, mirroring
    /// [`BadDataType::bad_replacement_base_type`](super::bad_data_type::BadDataType::bad_replacement_base_type).
    fn missing_built_in_replacement_base_type(&self) -> Option<Box<dyn DataType>> {
        None
    }

    /// Port of `MissingBuiltInDataType.isEquivalent(DataType)`. See the module docs for why this
    /// is left required (no default) despite no supertrait already claiming the name.
    fn missing_built_in_is_equivalent(&self, dt: &dyn DataType) -> bool;

    /// Port of `MissingBuiltInDataType.getLastChangeTime()`, which overrides
    /// [`DataTypeImpl::data_type_impl_get_last_change_time`] (the stored `lastChangeTime` field)
    /// with an unconditional [`NO_SOURCE_SYNC_TIME`].
    fn missing_built_in_last_change_time(&self) -> i64 {
        NO_SOURCE_SYNC_TIME
    }

    /// Port of the final `MissingBuiltInDataType.copy(DataTypeManager)`, wrapping
    /// `clone(DataTypeManager)`. See the module docs for why this trait declares its own
    /// (mirroring [`BuiltIn::built_in_copy`](super::built_in::BuiltIn::built_in_copy)) rather than
    /// reusing that one.
    fn missing_built_in_copy(&self, dtm: &dyn DataTypeManager) -> Box<dyn DataType> {
        self.clone_data_type(dtm)
    }

    /// Port of the protected `MissingBuiltInDataType.setCategory()`, a brand-new no-op method
    /// with no supertrait relationship; see the module docs.
    fn missing_built_in_set_category(&self) {}

    /// Port of `MissingBuiltInDataType.clone(DataTypeManager)`. Left as a required method (no
    /// default); see
    /// [`Undefined1DataType::undefined1_clone`](super::undefined1_data_type::Undefined1DataType::undefined1_clone)
    /// for why.
    fn missing_built_in_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn MissingBuiltInDataType>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, SpecialAddress};
    use crate::program::model::data::built_in_data_type::BuiltInDataType;
    use crate::program::model::data::category_path::{CategoryPath, ROOT};
    use crate::program::model::data::data_organization::DataOrganization;
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

    #[derive(Clone)]
    struct MockMissingBuiltIn {
        name: String,
        class_path: String,
    }

    impl DataType for MockMissingBuiltIn {
        fn get_name(&self) -> String {
            format!("-MISSING-{}", self.name)
        }
        fn get_category_path(&self) -> CategoryPath {
            ROOT.clone()
        }
        fn get_length(&self) -> i32 {
            self.missing_built_in_length()
        }
        fn get_description(&self) -> String {
            self.missing_built_in_description()
        }
        fn get_mnemonic(&self, settings: &dyn Settings) -> String {
            self.missing_built_in_mnemonic(settings)
        }
        fn get_representation(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> String {
            self.missing_built_in_representation(buf, settings, length)
        }
        fn get_value(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> Option<Box<dyn Any>> {
            self.missing_built_in_value(buf, settings, length)
        }
        fn get_last_change_time(&self) -> i64 {
            self.missing_built_in_last_change_time()
        }
        fn is_equivalent(&self, dt: &dyn DataType) -> bool {
            self.missing_built_in_is_equivalent(dt)
        }
    }

    impl DataTypeImpl for MockMissingBuiltIn {
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

    impl BuiltInDataType for MockMissingBuiltIn {
        fn get_c_type_declaration(
            &self,
            _data_organization: Option<&dyn DataOrganization>,
        ) -> Option<String> {
            None // matches MissingBuiltInDataType.getCTypeDeclaration always returning null
        }
        fn set_default_settings(&mut self, _settings: &dyn Settings) {} // matches the no-op override
    }

    impl Dynamic for MockMissingBuiltIn {
        fn get_dynamic_length(&self, buf: &dyn MemBuffer, max_length: i32) -> i32 {
            self.missing_built_in_dynamic_length(buf, max_length)
        }
        fn can_specify_length(&self) -> bool {
            self.missing_built_in_can_specify_length()
        }
        fn get_replacement_base_type(&self) -> Box<dyn DataType> {
            self.missing_built_in_replacement_base_type()
                .expect("MissingBuiltInDataType has no replacement base type")
        }
    }

    impl MissingBuiltInDataType for MockMissingBuiltIn {
        fn missing_built_in_name(&self) -> String {
            self.name.clone()
        }
        fn missing_built_in_class_path(&self) -> String {
            self.class_path.clone()
        }
        fn missing_built_in_is_equivalent(&self, dt: &dyn DataType) -> bool {
            dt.get_name() == self.get_name()
        }
        fn missing_built_in_clone(
            &self,
            _dtm: Option<Box<dyn DataTypeManager>>,
        ) -> Box<dyn MissingBuiltInDataType> {
            Box::new(self.clone())
        }
    }

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    fn make(name: &str, class_path: &str) -> MockMissingBuiltIn {
        MockMissingBuiltIn { name: name.to_string(), class_path: class_path.to_string() }
    }

    #[test]
    fn usable_as_trait_object() {
        let dt = make("FooDataType", "com.example.FooDataType");
        let dyn_dt: &dyn MissingBuiltInDataType = &dt;
        assert_eq!(dyn_dt.missing_built_in_name(), "FooDataType");
        assert_eq!(dyn_dt.missing_built_in_class_path(), "com.example.FooDataType");
        assert_eq!(dyn_dt.missing_built_in_length(), -1);
        assert_eq!(DataType::get_length(dyn_dt), -1);
        assert!(dyn_dt.missing_built_in_can_specify_length());
        assert!(dyn_dt.can_specify_length());
        assert_eq!(dyn_dt.get_name(), "-MISSING-FooDataType");
    }

    #[test]
    fn description_and_representation_and_value_use_the_class_path() {
        let dt = make("FooDataType", "com.example.FooDataType");
        let buf = MockMemBuffer;
        assert_eq!(dt.missing_built_in_description(), "Missing Built-In Data Type: com.example.FooDataType");
        assert_eq!(
            dt.missing_built_in_representation(&buf, &MockSettings, -1),
            "com.example.FooDataType"
        );
        let value = dt.missing_built_in_value(&buf, &MockSettings, -1).unwrap();
        assert_eq!(value.downcast_ref::<String>().unwrap(), "com.example.FooDataType");
    }

    #[test]
    fn dynamic_length_is_always_negative_one() {
        let dt = make("FooDataType", "com.example.FooDataType");
        let buf = MockMemBuffer;
        assert_eq!(dt.missing_built_in_dynamic_length(&buf, 100), -1);
        assert_eq!(dt.get_dynamic_length(&buf, 100), -1);
    }

    #[test]
    fn replacement_base_type_is_none() {
        let dt = make("FooDataType", "com.example.FooDataType");
        assert!(dt.missing_built_in_replacement_base_type().is_none());
    }

    #[test]
    fn last_change_time_is_always_no_source_sync_time_ignoring_stored_field() {
        let dt = make("FooDataType", "com.example.FooDataType");
        assert_eq!(dt.missing_built_in_last_change_time(), NO_SOURCE_SYNC_TIME);
        assert_eq!(DataType::get_last_change_time(&dt), NO_SOURCE_SYNC_TIME);
    }

    #[test]
    fn is_equivalent_compares_by_class_path_derived_name() {
        let a = make("FooDataType", "com.example.FooDataType");
        let b = make("FooDataType", "com.example.FooDataType");
        let c = make("BarDataType", "com.example.BarDataType");
        assert!(a.missing_built_in_is_equivalent(&b));
        assert!(!a.missing_built_in_is_equivalent(&c));
    }

    #[test]
    fn copy_delegates_to_clone_data_type() {
        struct CopyTestType;
        impl DataType for CopyTestType {
            fn get_length(&self) -> i32 {
                -1
            }
            fn clone_data_type(&self, _dtm: &dyn DataTypeManager) -> Box<dyn DataType> {
                struct Marker;
                impl DataType for Marker {
                    fn get_length(&self) -> i32 {
                        -1
                    }
                    fn get_name(&self) -> String {
                        "cloned-marker".to_string()
                    }
                }
                Box::new(Marker)
            }
        }
        impl DataTypeImpl for CopyTestType {
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
        impl BuiltInDataType for CopyTestType {
            fn get_c_type_declaration(
                &self,
                _data_organization: Option<&dyn DataOrganization>,
            ) -> Option<String> {
                None
            }
            fn set_default_settings(&mut self, _settings: &dyn Settings) {}
        }
        impl Dynamic for CopyTestType {
            fn get_dynamic_length(&self, _buf: &dyn MemBuffer, _max_length: i32) -> i32 {
                -1
            }
            fn get_replacement_base_type(&self) -> Box<dyn DataType> {
                unimplemented!("not exercised by this test")
            }
        }
        impl MissingBuiltInDataType for CopyTestType {
            fn missing_built_in_name(&self) -> String {
                "X".to_string()
            }
            fn missing_built_in_class_path(&self) -> String {
                "com.example.X".to_string()
            }
            fn missing_built_in_is_equivalent(&self, _dt: &dyn DataType) -> bool {
                false
            }
            fn missing_built_in_clone(
                &self,
                _dtm: Option<Box<dyn DataTypeManager>>,
            ) -> Box<dyn MissingBuiltInDataType> {
                unimplemented!("not exercised by this test")
            }
        }

        let dt = CopyTestType;
        let copied = dt.missing_built_in_copy(&MockDataTypeManager);
        assert_eq!(copied.get_name(), "cloned-marker");
    }

    #[test]
    fn set_category_is_a_no_op() {
        let dt = make("FooDataType", "com.example.FooDataType");
        dt.missing_built_in_set_category(); // must not panic
    }

    #[test]
    fn clone_produces_an_equivalent_instance() {
        let dt = make("FooDataType", "com.example.FooDataType");
        let cloned = dt.missing_built_in_clone(None);
        assert_eq!(cloned.missing_built_in_class_path(), dt.missing_built_in_class_path());
    }
}

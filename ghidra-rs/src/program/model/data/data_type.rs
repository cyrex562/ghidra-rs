use std::any::{Any, TypeId};

use thiserror::Error;

use crate::program::model::data::category_path::{CategoryPath, ROOT};
use crate::program::model::data::data_organization::DataOrganization;
use crate::program::model::data::data_type_display_options::DataTypeDisplayOptions;
use crate::program::model::data::data_type_with_charset::DataTypeEncodeError;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::data::source_archive::SourceArchive;
use crate::program::model::data::typedef_settings_definition::TypeDefSettingsDefinition;
use crate::program::seam_stubs::{DataTypePath, MemBuffer, Settings, SettingsDefinition};
use crate::util::exception::{DuplicateNameException, InvalidNameException};
use crate::util::UniversalID;

/// Datatype name conflict suffix.
///
/// See `DataTypeUtilities` for various methods related to conflict name handling. Direct use of
/// this string in application/user-level code is discouraged.
pub const CONFLICT_SUFFIX: &str = ".conflict";

/// Prefix used to encode a typedef's settings-derived attributes into its generated name.
pub const TYPEDEF_ATTRIBUTE_PREFIX: &str = "__((";

/// Suffix used to encode a typedef's settings-derived attributes into its generated name.
pub const TYPEDEF_ATTRIBUTE_SUFFIX: &str = "))";

/// Sentinel value returned by [`DataType::get_last_change_time_in_source_archive`] when this
/// datatype has never been synchronized with a source archive.
pub const NO_SOURCE_SYNC_TIME: i64 = 0;

/// Sentinel value returned by [`DataType::get_last_change_time`] when this datatype has no
/// recorded last-change time.
pub const NO_LAST_CHANGE_TIME: i64 = 0;

/// Error produced when renaming a [`DataType`] fails, standing in for the two checked exceptions
/// declared on the Java methods `DataType.setName(String)` and
/// `DataType.setNameAndCategory(CategoryPath, String)`.
#[derive(Error, Debug, PartialEq)]
pub enum SetDataTypeNameError {
    #[error(transparent)]
    Duplicate(#[from] DuplicateNameException),
    #[error(transparent)]
    InvalidName(#[from] InvalidNameException),
}

/// Error produced by [`DataType::set_description`] when a datatype does not allow its
/// description to be changed, standing in for `java.lang.UnsupportedOperationException`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsupportedOperationError(pub String);

impl std::fmt::Display for UnsupportedOperationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for UnsupportedOperationError {}

/// The interface that all datatypes must implement.
///
/// Port of `ghidra.program.model.data.DataType`.
///
/// This trait was promoted from a minimal placeholder (see `seam_stubs.rs`) that already carried
/// `get_length`/`is_zero_length`/`is_not_yet_defined`/`get_settings_definitions`/
/// `get_default_settings`, which map directly onto this interface's abstract methods of the same
/// shape. It also carried `is_structure`/`is_typedef`/`typedef_base_data_type`/`is_array`/
/// `into_array_stringable`/`is_pointer`, which have no direct counterpart on this interface (they
/// stand in for `instanceof Structure`/`instanceof TypeDef` + `TypeDef.getBaseDataType()`/
/// `instanceof Array`/`instanceof ArrayStringable`/`instanceof Pointer` checks, since Rust trait
/// objects cannot be downcast to another trait object without extra machinery); they are retained
/// here as a superset so existing callers keep compiling.
///
/// Every method (including ones abstract in the Java interface) is given a default so that
/// existing mock/test implementations which relied on the placeholder's blanket defaults are
/// unaffected by this promotion. Concrete implementations (`DataTypeImpl`, `DataTypeDB`, and the
/// various built-in/composite datatypes) will override these with real behavior once they are
/// ported.
///
/// The Java static singleton fields `DEFAULT` and `VOID` are omitted since they require
/// `DefaultDataType`/`VoidDataType`, which are not yet ported.
pub trait DataType {
    /// Indicates if the length of this data-type is determined based upon the
    /// `DataOrganization` obtained from the associated `DataTypeManager`.
    fn has_language_dependant_length(&self) -> bool {
        false
    }

    /// Get the list of settings definitions available for use with this datatype.
    fn get_settings_definitions(&self) -> Vec<Box<dyn SettingsDefinition>> {
        Vec::new()
    }

    /// Get the list of all settings definitions for this datatype that may be used for an
    /// associated `TypeDef`.
    fn get_type_def_settings_definitions(&self) -> Vec<Box<dyn TypeDefSettingsDefinition>> {
        Vec::new()
    }

    /// Gets the settings for this data type.
    fn get_default_settings(&self) -> Box<dyn Settings> {
        Box::new(EmptyDataTypeSettings)
    }

    /// Returns an instance of this DataType using the specified `DataTypeManager` to allow its
    /// use of the corresponding `DataOrganization` while retaining its unique identity and
    /// archive association if applicable.
    fn clone_data_type(&self, dtm: &dyn DataTypeManager) -> Box<dyn DataType> {
        let _ = dtm;
        Box::new(EmptyDataType)
    }

    /// Returns a new instance (shallow copy) of this DataType with a new identity and no source
    /// archive association.
    fn copy_data_type(&self, dtm: &dyn DataTypeManager) -> Box<dyn DataType> {
        let _ = dtm;
        Box::new(EmptyDataType)
    }

    /// Gets the categoryPath associated with this datatype.
    fn get_category_path(&self) -> CategoryPath {
        ROOT.clone()
    }

    /// Returns the dataTypePath for this datatype.
    fn get_data_type_path(&self) -> DataTypePath {
        DataTypePath::new(self.get_category_path(), self.get_name())
    }

    /// Set the categoryPath associated with this datatype.
    fn set_category_path(&mut self, path: CategoryPath) -> Result<(), DuplicateNameException> {
        let _ = path;
        Ok(())
    }

    /// Get the DataTypeManager containing this datatype, or `None` if this datatype is not
    /// currently associated with one.
    fn get_data_type_manager(&self) -> Option<Box<dyn DataTypeManager>> {
        None
    }

    /// Gets the name for referring to this datatype (i.e.: Word).
    fn get_display_name(&self) -> String {
        self.get_name()
    }

    /// Get the name of this datatype.
    fn get_name(&self) -> String {
        String::new()
    }

    /// Get the full category path name that includes this datatype's name.
    fn get_path_name(&self) -> String {
        let path = self.get_category_path().get_path();
        if path.ends_with(crate::program::model::data::category_path::DELIMITER_CHAR) {
            format!("{path}{}", self.get_name())
        } else {
            format!(
                "{path}{}{}",
                crate::program::model::data::category_path::DELIMITER_STRING,
                self.get_name()
            )
        }
    }

    /// Sets the name of the datatype.
    fn set_name(&mut self, name: &str) -> Result<(), SetDataTypeNameError> {
        let _ = name;
        Ok(())
    }

    /// Sets the name and category of a datatype at the same time.
    fn set_name_and_category(
        &mut self,
        path: CategoryPath,
        name: &str,
    ) -> Result<(), SetDataTypeNameError> {
        let _ = (path, name);
        Ok(())
    }

    /// Get the mnemonic for this DataType.
    fn get_mnemonic(&self, settings: &dyn Settings) -> String {
        let _ = settings;
        self.get_name()
    }

    /// Get the length of this DataType as a number of 8-bit bytes.
    fn get_length(&self) -> i32 {
        0
    }

    /// Get the aligned-length of this datatype as a number of 8-bit bytes.
    fn get_aligned_length(&self) -> i32 {
        self.get_length()
    }

    /// Whether this dataType is (or wraps) a zero-length component (e.g. a zero-element array).
    fn is_zero_length(&self) -> bool {
        false
    }

    /// Whether this dataType has not yet had its internal composition specified.
    fn is_not_yet_defined(&self) -> bool {
        false
    }

    /// Get a String briefly describing this DataType.
    fn get_description(&self) -> String {
        String::new()
    }

    /// Sets a String briefly describing this DataType.
    fn set_description(&mut self, description: &str) -> Result<(), UnsupportedOperationError> {
        let _ = description;
        Ok(())
    }

    /// Returns the interpreted data value as an instance of the advertised value class, or
    /// `None` if the data is invalid.
    fn get_value(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> Option<Box<dyn Any>> {
        let _ = (buf, settings, length);
        None
    }

    /// Check if this type supports encoding (patching).
    fn is_encodable(&self) -> bool {
        false
    }

    /// Encode bytes from a value appropriate for this DataType.
    fn encode_value(
        &self,
        value: &dyn Any,
        buf: &dyn MemBuffer,
        settings: &dyn Settings,
        length: i32,
    ) -> Result<Vec<u8>, DataTypeEncodeError> {
        let _ = (value, buf, settings, length);
        Err(DataTypeEncodeError("encoding not supported".to_string()))
    }

    /// Get the Rust `TypeId` of the value to be returned by this datatype (see
    /// [`DataType::get_value`]), standing in for Java's `Class<?>`. `None` if it can vary or is
    /// unspecified.
    fn get_value_class(&self, settings: &dyn Settings) -> Option<TypeId> {
        let _ = settings;
        None
    }

    /// Returns the appropriate string to use as the default label prefix in the absence of any
    /// data, or `None` if none specified.
    fn get_default_label_prefix(&self) -> Option<String> {
        None
    }

    /// Returns the prefix to use for this datatype when an abbreviated prefix is desired, or
    /// `None`.
    fn get_default_abbreviated_label_prefix(&self) -> Option<String> {
        None
    }

    /// Returns the appropriate string to use as the default label prefix, given the actual data
    /// bytes. Mirrors the Java overload `getDefaultLabelPrefix(MemBuffer, Settings, int,
    /// DataTypeDisplayOptions)`.
    fn get_default_label_prefix_for_data(
        &self,
        buf: &dyn MemBuffer,
        settings: &dyn Settings,
        len: i32,
        options: &dyn DataTypeDisplayOptions,
    ) -> Option<String> {
        let _ = (buf, settings, len, options);
        self.get_default_label_prefix()
    }

    /// Returns the appropriate string to use as the default label prefix, taking into account
    /// that there exists a reference to the data that references `offcut_offset` bytes into this
    /// type.
    fn get_default_offcut_label_prefix(
        &self,
        buf: &dyn MemBuffer,
        settings: &dyn Settings,
        len: i32,
        options: &dyn DataTypeDisplayOptions,
        offcut_offset: i32,
    ) -> Option<String> {
        let _ = offcut_offset;
        self.get_default_label_prefix_for_data(buf, settings, len, options)
    }

    /// Get bytes from memory in a printable format for this type.
    fn get_representation(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> String {
        let _ = (buf, settings, length);
        String::new()
    }

    /// Encode bytes according to the display format for this type.
    fn encode_representation(
        &self,
        repr: &str,
        buf: &dyn MemBuffer,
        settings: &dyn Settings,
        length: i32,
    ) -> Result<Vec<u8>, DataTypeEncodeError> {
        let _ = (repr, buf, settings, length);
        Err(DataTypeEncodeError("encoding not supported".to_string()))
    }

    /// Returns true if this datatype has been deleted and is no longer valid.
    fn is_deleted(&self) -> bool {
        false
    }

    /// Check if the given datatype is equivalent to this datatype. The precise meaning of
    /// "equivalent" is datatype dependent.
    fn is_equivalent(&self, dt: &dyn DataType) -> bool {
        let _ = dt;
        false
    }

    /// Notification that the given datatype's size has changed.
    fn data_type_size_changed(&mut self, dt: &dyn DataType) {
        let _ = dt;
    }

    /// Notification that the given datatype's alignment has changed.
    fn data_type_alignment_changed(&mut self, dt: &dyn DataType) {
        let _ = dt;
    }

    /// Informs this datatype that the given datatype has been deleted.
    fn data_type_deleted(&mut self, dt: &dyn DataType) {
        let _ = dt;
    }

    /// Informs this datatype that the given `old_dt` has been replaced with `new_dt`.
    fn data_type_replaced(&mut self, old_dt: &dyn DataType, new_dt: &dyn DataType) {
        let _ = (old_dt, new_dt);
    }

    /// Inform this data type that it has the given parent.
    fn add_parent(&mut self, dt: &dyn DataType) {
        let _ = dt;
    }

    /// Remove a parent datatype.
    fn remove_parent(&mut self, dt: &dyn DataType) {
        let _ = dt;
    }

    /// Informs this datatype that its name has changed from the indicated old name.
    fn data_type_name_changed(&mut self, dt: &dyn DataType, old_name: &str) {
        let _ = (dt, old_name);
    }

    /// Get the parents of this datatype.
    fn get_parents(&self) -> Vec<Box<dyn DataType>> {
        Vec::new()
    }

    /// Gets the alignment to be used when aligning this datatype within another datatype.
    fn get_alignment(&self) -> i32 {
        1
    }

    /// Check if this datatype depends on the existence of the given datatype (i.e., if the
    /// specified datatype is removed this datatype must also be removed).
    fn depends_on(&self, dt: &dyn DataType) -> bool {
        let _ = dt;
        false
    }

    /// Get the source archive where this type originated, or `None` if it did not originate from
    /// a source archive.
    fn get_source_archive(&self) -> Option<Box<dyn SourceArchive>> {
        None
    }

    /// Set the source archive where this type originated.
    fn set_source_archive(&mut self, archive: Box<dyn SourceArchive>) {
        let _ = archive;
    }

    /// Get the timestamp corresponding to the last time this type was changed within its
    /// datatype manager.
    fn get_last_change_time(&self) -> i64 {
        NO_LAST_CHANGE_TIME
    }

    /// Get the timestamp corresponding to the last time this type was sync'd within its source
    /// archive.
    fn get_last_change_time_in_source_archive(&self) -> i64 {
        NO_SOURCE_SYNC_TIME
    }

    /// Get the universal ID for this datatype.
    fn get_universal_id(&self) -> UniversalID {
        UniversalID::new(0)
    }

    /// For datatypes that support change, this method replaces the internals of this datatype
    /// with the internals of the given datatype.
    fn replace_with(&mut self, data_type: &dyn DataType) {
        let _ = data_type;
    }

    /// Sets the lastChangeTime for this datatype.
    fn set_last_change_time(&mut self, last_change_time: i64) {
        let _ = last_change_time;
    }

    /// Sets the lastChangeTimeInSourceArchive for this datatype.
    fn set_last_change_time_in_source_archive(&mut self, last_change_time_in_source_archive: i64) {
        let _ = last_change_time_in_source_archive;
    }

    /// Returns the DataOrganization associated with this data-type.
    ///
    /// No meaningful `DataOrganization` fallback is available yet since no concrete
    /// implementation has been ported; overriding implementations must supply their own.
    fn get_data_organization(&self) -> Box<dyn DataOrganization> {
        unimplemented!("DataType::get_data_organization has no default implementation yet")
    }

    /// Stands in for `instanceof Structure`.
    fn is_structure(&self) -> bool {
        false
    }

    /// Stands in for `instanceof Union`.
    fn is_union(&self) -> bool {
        false
    }

    /// Stands in for `instanceof TypeDef`.
    fn is_typedef(&self) -> bool {
        false
    }

    /// Stands in for `((TypeDef) dataType).getBaseDataType()`; only meaningful when
    /// `is_typedef()` is `true`.
    fn typedef_base_data_type(&self) -> Option<Box<dyn DataType>> {
        None
    }

    /// Stands in for `instanceof Array`.
    fn is_array(&self) -> bool {
        false
    }

    /// Stands in for `dt instanceof ArrayStringable ? (ArrayStringable) dt : null`, used by
    /// [`get_array_stringable`](crate::program::model::data::array_stringable::get_array_stringable).
    fn into_array_stringable(
        self: Box<Self>,
    ) -> Option<Box<dyn crate::program::model::data::array_stringable::ArrayStringable>> {
        None
    }

    /// Stands in for `instanceof Pointer`, used by
    /// [`TypeDef::is_pointer`](crate::program::model::data::typedef::TypeDef::is_pointer).
    fn is_pointer(&self) -> bool {
        false
    }
}

/// Trivial fallback used by this trait's default methods where the Java interface has no
/// meaningful zero-value to fall back on.
struct EmptyDataType;
impl DataType for EmptyDataType {}

/// Trivial fallback used by [`DataType::get_default_settings`].
struct EmptyDataTypeSettings;
impl Settings for EmptyDataTypeSettings {}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockDataType;
    impl DataType for MockDataType {}

    #[test]
    fn usable_as_trait_object() {
        let dt = MockDataType;
        let dyn_dt: &dyn DataType = &dt;
        assert_eq!(dyn_dt.get_length(), 0);
        assert!(!dyn_dt.is_zero_length());
        assert!(!dyn_dt.is_not_yet_defined());
        assert!(!dyn_dt.is_pointer());
        assert!(dyn_dt.get_settings_definitions().is_empty());
        assert!(dyn_dt.get_parents().is_empty());
    }

    #[test]
    fn default_display_name_delegates_to_name() {
        struct Named;
        impl DataType for Named {
            fn get_name(&self) -> String {
                "byte".to_string()
            }
        }
        let dt = Named;
        assert_eq!(dt.get_display_name(), "byte");
    }

    #[test]
    fn default_path_name_uses_root_category() {
        struct Named;
        impl DataType for Named {
            fn get_name(&self) -> String {
                "byte".to_string()
            }
        }
        let dt = Named;
        assert_eq!(dt.get_path_name(), "/byte");
    }

    #[test]
    fn overriding_is_pointer_and_aligned_length() {
        struct PointerLike;
        impl DataType for PointerLike {
            fn is_pointer(&self) -> bool {
                true
            }
            fn get_length(&self) -> i32 {
                8
            }
        }
        let dt = PointerLike;
        assert!(dt.is_pointer());
        assert_eq!(dt.get_aligned_length(), 8);
    }

    #[test]
    fn default_encode_value_and_representation_are_unsupported() {
        struct NotEncodable;
        impl DataType for NotEncodable {}

        struct MockBuf;
        impl MemBuffer for MockBuf {}

        struct MockSettings;
        impl Settings for MockSettings {}

        let dt = NotEncodable;
        assert!(!dt.is_encodable());
        assert!(dt
            .encode_value(&0i32, &MockBuf, &MockSettings, -1)
            .is_err());
        assert!(dt
            .encode_representation("0", &MockBuf, &MockSettings, -1)
            .is_err());
    }
}

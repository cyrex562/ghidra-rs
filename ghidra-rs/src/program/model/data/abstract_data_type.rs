//! Port of `ghidra.program.model.data.AbstractDataType`, promoted to a trait because it was
//! selected as a dependency-cycle cut-point.
//!
//! The Java class `implements DataType` directly and contributes no additional public API surface
//! beyond it -- only field storage (`name`/`categoryPath`/`dataMgr`) plus overrides of `DataType`'s
//! own default methods -- so, mirroring [`DataTypeImpl`](super::data_type_impl::DataTypeImpl)'s
//! treatment of the same kind of base-class layer, this trait extends [`DataType`] directly.
//!
//! Most of `AbstractDataType`'s overrides turn out to already be the exact default bodies carried
//! by [`DataType`] in `data_type.rs` (unsurprising: that trait's own doc comment notes it absorbed
//! this same "many DataType methods are stubbed out" behavior from its placeholder predecessor).
//! Per [`DataTypeImpl`](super::data_type_impl::DataTypeImpl)'s and
//! [`CompositeDataTypeImpl`](super::composite_data_type_impl::CompositeDataTypeImpl)'s precedent of
//! skipping re-declaration of identical defaults, the following are intentionally **not**
//! re-declared here (all identical to the existing [`DataType`] default):
//! `getTypeDefSettingsDefinitions`, `getDataTypePath` (both compose `get_category_path()`/
//! `get_name()` the same way), `getDisplayName`, `getPathName` (both build `category_path +
//! delimiter + name`; compare [`DataTypePath::get_path`](super::data_type_path::DataTypePath::get_path)),
//! `getMnemonic` (returns the raw `name` field, the same value `get_name()` returns once a concrete
//! implementor delegates it to [`AbstractDataType::abstract_data_type_get_name`]), `isNotYetDefined`,
//! `isZeroLength`, `toString` (delegates to `getDisplayName()`, needing no additional logic here --
//! see [`CompositeDataTypeImpl`](super::composite_data_type_impl::CompositeDataTypeImpl)'s identical
//! treatment of its own `toString`), `isDeleted`, `setName`, `setNameAndCategory`,
//! `dataTypeSizeChanged`, `dataTypeAlignmentChanged`, `dataTypeDeleted`, `dataTypeReplaced`,
//! `addParent`, `removeParent`, `getParents`, `dependsOn`, `getSourceArchive`, `setSourceArchive`,
//! `getLastChangeTime`, `getLastChangeTimeInSourceArchive`, `getUniversalID` (Java returns `null`;
//! [`DataType::get_universal_id`]'s existing default represents "no id" as `UniversalID::new(0)`,
//! the sentinel already used throughout this port), `dataTypeNameChanged`, `replaceWith`,
//! `setLastChangeTime`, `setLastChangeTimeInSourceArchive`, `setDescription` (this override never
//! actually throws despite its `throws` clause -- it is a plain no-op, unlike
//! [`DataTypeImpl::data_type_impl_set_description`](super::data_type_impl::DataTypeImpl::data_type_impl_set_description)),
//! `hasLanguageDependantLength`, `getDefaultLabelPrefix`, `setCategoryPath` (a no-op here too -- the
//! field is only ever populated at construction), `getDefaultLabelPrefix(MemBuffer, Settings, int,
//! DataTypeDisplayOptions)`, `getDefaultOffcutLabelPrefix`, `isEncodable`, `encodeValue`, and
//! `encodeRepresentation`.
//!
//! What remains -- and is ported below -- is real behavior the [`DataType`] default doesn't already
//! provide:
//!   - `getCategoryPath`/`getName`/`getDataTypeManager` return the stored `categoryPath`/`name`/
//!     `dataMgr` fields, exposed via required accessors (mirroring
//!     [`DataTypeImpl`](super::data_type_impl::DataTypeImpl)'s `stored_*` convention) since traits
//!     have no field storage. Each clashes by name with a [`DataType`] default of the same name, so
//!     -- following that same precedent -- they are exposed here under distinct
//!     `abstract_data_type_*` names for a concrete `impl DataType for ...` to delegate to.
//!   - `getDataOrganization` (`final`) resolves through `dataMgr` when present, otherwise falls
//!     back to the static `DataOrganizationImpl.getDefaultOrganization()`.
//!   - the `protected static getDataOrganization(DataTypeManager)` helper is ported as the free
//!     function [`default_data_organization`].
//!   - `getDefaultAbbreviatedLabelPrefix` delegates to `self.getDefaultLabelPrefix()` -- a *virtual*
//!     call that picks up a concrete override -- unlike [`DataType::get_default_abbreviated_label_prefix`]'s
//!     existing default, which unconditionally returns `None`. Exposed as
//!     `abstract_data_type_get_default_abbreviated_label_prefix` for the same name-clash reason as
//!     above.
//!   - the constructor's `IllegalArgumentException` validation (null/empty name, and
//!     `DataUtilities.isValidDataTypeName`) is ported as the free function
//!     [`check_new_abstract_data_type_args`], which implementors are expected to call from their own
//!     constructor; it panics exactly where the Java constructor throws `IllegalArgumentException`,
//!     mirroring this crate's established convention for that exception (see e.g.
//!     `util::timer::g_timer`, `util::string_utilities`). The `path == null` check has no Rust
//!     equivalent: [`CategoryPath`](super::category_path::CategoryPath) is always constructed by
//!     value, never null.

use std::sync::Arc;

use crate::program::model::data::category_path::CategoryPath;
use crate::program::model::data::data_organization_impl::DataOrganizationImpl;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::data::data_utilities::DataUtilities;

/// The data organization of `data_mgr`, or the default organization without one.
///
/// Port of the protected static `AbstractDataType.getDataOrganization(DataTypeManager)`.
pub fn default_data_organization(data_mgr: Option<&dyn DataTypeManager>) -> Arc<DataOrganizationImpl> {
    match data_mgr {
        Some(mgr) => mgr.get_data_organization(),
        None => Arc::new(DataOrganizationImpl::get_default_organization(None)),
    }
}

/// Port of the `AbstractDataType(CategoryPath, String, DataTypeManager)` constructor's validation.
///
/// Implementors are expected to call this from their own constructor before storing `name`.
///
/// # Panics
/// Panics (standing in for `IllegalArgumentException`) if `name` is empty or is not a valid
/// datatype name according to `utilities`.
pub fn check_new_abstract_data_type_args(name: &str, utilities: &dyn DataUtilities) {
    if name.is_empty() {
        panic!("Name is null or empty!");
    }
    if !utilities.is_valid_data_type_name(name) {
        panic!("Invalid DataType name: {name}");
    }
}

/// Base class for DataType classes. Many of the DataType methods are stubbed out so simple
/// datatype classes can be created without implementing too many methods.
///
/// Port of `ghidra.program.model.data.AbstractDataType`. See the module-level documentation for
/// the conventions used to resolve name clashes with [`DataType`], for the required accessors
/// standing in for private fields, and for what was left identical to an existing default,
/// re-homed under a distinct name, or ported as a free function.
pub trait AbstractDataType: DataType {
    /// Backing storage for the protected `name` field.
    fn stored_name(&self) -> String;

    /// Backing storage for the protected `categoryPath` field.
    fn stored_category_path(&self) -> CategoryPath;

    /// Backing storage for the private final `dataMgr` field. Java has no setter for this field
    /// (only the constructor assigns it), so no mutator is exposed.
    fn stored_data_type_manager(&self) -> Option<Box<dyn DataTypeManager>>;

    /// Port of `AbstractDataType.getCategoryPath()`. Exposed under a distinct name since
    /// [`DataType::get_category_path`] already provides a (different) default. A concrete `impl
    /// DataType for ...` should delegate to this.
    fn abstract_data_type_get_category_path(&self) -> CategoryPath {
        self.stored_category_path()
    }

    /// Port of `AbstractDataType.getName()`. Exposed under a distinct name since
    /// [`DataType::get_name`] already provides a (different) default. A concrete `impl DataType
    /// for ...` should delegate to this.
    fn abstract_data_type_get_name(&self) -> String {
        self.stored_name()
    }

    /// Port of the final `AbstractDataType.getDataTypeManager()`. Exposed under a distinct name
    /// since [`DataType::get_data_type_manager`] already provides a (placeholder) default. A
    /// concrete `impl DataType for ...` should delegate to this.
    fn abstract_data_type_get_data_type_manager(&self) -> Option<Box<dyn DataTypeManager>> {
        self.stored_data_type_manager()
    }

    /// Port of the final `AbstractDataType.getDataOrganization()`. Exposed under a distinct name
    /// since [`DataType::get_data_organization`] already provides a (panicking) placeholder
    /// default. A concrete `impl DataType for ...` should delegate to this.
    fn abstract_data_type_get_data_organization(&self) -> Arc<DataOrganizationImpl> {
        default_data_organization(self.stored_data_type_manager().as_deref())
    }

    /// Port of `AbstractDataType.getDefaultAbbreviatedLabelPrefix()`. Exposed under a distinct
    /// name since [`DataType::get_default_abbreviated_label_prefix`] already provides a (different,
    /// non-delegating) default. A concrete `impl DataType for ...` should delegate to this.
    fn abstract_data_type_get_default_abbreviated_label_prefix(&self) -> Option<String> {
        self.get_default_label_prefix()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::data::category_path::ROOT;

    /// A real [`DataOrganizationImpl`] configured as this test expects.
    fn mock_data_organization(pointer_size: i32) -> DataOrganizationImpl {
        let mut org = DataOrganizationImpl::get_default_organization(None);
        org.set_big_endian(false);
        org.set_pointer_size(pointer_size);
        org.set_pointer_shift(0);
        org.set_char_is_signed(true);
        org.set_char_size(1);
        org.set_wide_char_size(2);
        org.set_short_size(2);
        org.set_integer_size(4);
        org.set_long_size(4);
        org.set_long_long_size(8);
        org.set_float_size(4);
        org.set_double_size(8);
        org.set_long_double_size(8);
        org.set_absolute_max_alignment(0);
        org.set_machine_alignment(8);
        org.set_default_alignment(1);
        org.set_default_pointer_alignment(4);
        org.clear_size_alignment_map();
        org
    }

    struct MockDataTypeManager {
        pointer_size: i32,
    }
    impl DataTypeManager for MockDataTypeManager {
        fn get_data_organization(&self) -> Arc<DataOrganizationImpl> {
            Arc::new(mock_data_organization(self.pointer_size))
        }
    }

    struct Util;
    impl DataUtilities for Util {}

    struct MockAbstractDataType {
        name: String,
        category_path: CategoryPath,
        // A fresh `Box<dyn DataTypeManager>` is built on demand from this rather than stored
        // directly, since `Box<dyn DataTypeManager>` isn't `Clone` and `stored_data_type_manager`
        // only has `&self` -- mirroring how `DataType::get_data_type_manager` is documented
        // elsewhere in this crate as "a freshly built `Box` each call".
        data_mgr_pointer_size: Option<i32>,
        default_label_prefix: Option<String>,
    }

    impl MockAbstractDataType {
        fn new(
            category_path: CategoryPath,
            name: &str,
            data_mgr_pointer_size: Option<i32>,
        ) -> Self {
            check_new_abstract_data_type_args(name, &Util);
            MockAbstractDataType {
                name: name.to_string(),
                category_path,
                data_mgr_pointer_size,
                default_label_prefix: None,
            }
        }
    }

    impl DataType for MockAbstractDataType {
        fn get_category_path(&self) -> CategoryPath {
            self.abstract_data_type_get_category_path()
        }
        fn get_name(&self) -> String {
            self.abstract_data_type_get_name()
        }
        fn get_data_type_manager(&self) -> Option<Box<dyn DataTypeManager>> {
            self.abstract_data_type_get_data_type_manager()
        }
        fn get_data_organization(&self) -> Arc<DataOrganizationImpl> {
            self.abstract_data_type_get_data_organization()
        }
        fn get_default_label_prefix(&self) -> Option<String> {
            self.default_label_prefix.clone()
        }
        fn get_default_abbreviated_label_prefix(&self) -> Option<String> {
            self.abstract_data_type_get_default_abbreviated_label_prefix()
        }
    }

    impl AbstractDataType for MockAbstractDataType {
        fn stored_name(&self) -> String {
            self.name.clone()
        }
        fn stored_category_path(&self) -> CategoryPath {
            self.category_path.clone()
        }
        fn stored_data_type_manager(&self) -> Option<Box<dyn DataTypeManager>> {
            self.data_mgr_pointer_size
                .map(|pointer_size| -> Box<dyn DataTypeManager> {
                    Box::new(MockDataTypeManager { pointer_size })
                })
        }
    }

    #[test]
    fn usable_as_trait_object() {
        let dt: Box<dyn AbstractDataType> =
            Box::new(MockAbstractDataType::new(ROOT.clone(), "dword", None));
        assert_eq!(dt.stored_name(), "dword");
        assert_eq!(dt.abstract_data_type_get_name(), "dword");
        assert_eq!(dt.abstract_data_type_get_category_path(), ROOT.clone());
    }

    #[test]
    fn data_type_methods_delegate_through_abstract_data_type() {
        let dt = MockAbstractDataType::new(ROOT.clone(), "byte", None);
        // Exercised via the `DataType` trait object to prove the delegation wiring, not just the
        // `AbstractDataType`-specific accessor.
        let dyn_dt: &dyn DataType = &dt;
        assert_eq!(dyn_dt.get_name(), "byte");
        assert_eq!(dyn_dt.get_category_path(), ROOT.clone());
        assert_eq!(dyn_dt.get_display_name(), "byte");
        assert_eq!(dyn_dt.get_path_name(), "/byte");
    }

    #[test]
    fn get_default_abbreviated_label_prefix_delegates_to_overridden_default_prefix() {
        let mut dt = MockAbstractDataType::new(ROOT.clone(), "byte", None);
        dt.default_label_prefix = Some("BYTE".to_string());
        let dyn_dt: &dyn DataType = &dt;
        assert_eq!(
            dyn_dt.get_default_abbreviated_label_prefix(),
            Some("BYTE".to_string())
        );
    }

    #[test]
    fn get_data_organization_delegates_to_data_type_manager_when_present() {
        let dt = MockAbstractDataType::new(ROOT.clone(), "pointer", Some(8));
        assert_eq!(
            dt.abstract_data_type_get_data_organization().get_pointer_size(),
            8
        );
    }

    #[test]
    #[should_panic(expected = "Name is null or empty!")]
    fn constructor_rejects_empty_name() {
        MockAbstractDataType::new(ROOT.clone(), "", None);
    }

    #[test]
    #[should_panic(expected = "Invalid DataType name")]
    fn constructor_rejects_invalid_name() {
        MockAbstractDataType::new(ROOT.clone(), "\u{0007}", None);
    }
}

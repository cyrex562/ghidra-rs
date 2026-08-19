//! Port of `ghidra.program.model.data.DataTypeImpl`, promoted to a trait because it was selected
//! as a dependency-cycle cut-point.
//!
//! The Java class `extends AbstractDataType`. `AbstractDataType` (itself `implements DataType`)
//! is not yet ported, but -- mirroring [`CompositeDataTypeImpl`](super::composite_data_type_impl)'s
//! treatment of the equally-unported `GenericDataType`/`DataTypeImpl` layer it sits on top of --
//! this trait extends [`DataType`] directly, since `DataTypeImpl.java` itself contributes no
//! interface beyond `DataType` (its overrides are all real *behavior*, not additional API
//! surface).
//!
//! Several methods here share a name with an already-provided default method on [`DataType`]
//! (`getDefaultSettings`, `getAlignedLength`, `getAlignment`, `addParent`, `removeParent`,
//! `getParents`, `getLastChangeTime`, `getLastChangeTimeInSourceArchive`, `getSourceArchive`,
//! `setSourceArchive`, `getUniversalID`, `replaceWith`, `setLastChangeTime`,
//! `setLastChangeTimeInSourceArchive`, `setDescription`). Rust does not allow a subtrait to
//! override a supertrait's same-named default without creating an ambiguous call site, so --
//! mirroring [`CompositeDataTypeImpl`](super::composite_data_type_impl)'s `composite_impl_*`
//! convention -- those overrides are exposed here under distinct `data_type_impl_*` names. A
//! concrete `impl DataType for ...` should delegate to these.
//!
//! Two Java overrides are *identical* to the [`DataType`] default already in place, so they are
//! intentionally not re-declared here (matching the precedent set by
//! [`AbstractComplexDataType::complex_length`](super::abstract_complex_data_type::AbstractComplexDataType)'s
//! note about `getAlignedLength()`):
//!   - `getValueClass(Settings)` always returns `null`, exactly [`DataType::get_value_class`]'s
//!     existing default (`None`).
//!   - `getSettingsDefinitions()` always returns an empty array, exactly
//!     [`DataType::get_settings_definitions`]'s existing default (`Vec::new()`).
//!
//! The private fields `defaultSettings`, `universalID`, `sourceArchive`, `lastChangeTime`, and
//! `lastChangeTimeInSourceArchive` have no home on a trait, so they are exposed via required
//! accessor methods ([`DataTypeImpl::stored_default_settings`]/
//! [`DataTypeImpl::set_stored_default_settings`], etc.) that implementors are expected to back
//! with real storage -- mirroring [`CompositeDataTypeImpl::stored_description`]'s accessor
//! convention. The constructor logic that seeds these fields (`System.currentTimeMillis()` for
//! `lastChangeTime`, `UniversalIdGenerator.nextID()` when no `universalID` is supplied, etc.) has
//! no trait equivalent either (traits have no constructors) and is left to implementors.
//!
//! `parentList` (a `List<WeakReference<DataType>>`) is exposed the same way, as
//! [`DataTypeImpl::stored_parent_refs`]/[`DataTypeImpl::set_stored_parent_refs`], typed
//! `Vec<Weak<dyn DataType>>`/`Arc<dyn DataType>` -- mirroring
//! [`NoisyStructureBuilder`](super::noisy_structure_builder)'s established precedent of using
//! `Arc<dyn DataType>` to model a Java `DataType` reference shared between multiple owners.
//! Unlike the "fresh `Box` each call" limitation documented on
//! [`NoisyStructureBuilder`](super::noisy_structure_builder) (where reference-identity checks had
//! to be approximated with [`DataType::is_equivalent`]/[`DataType::get_data_type_path`] equality),
//! an `Arc`/`Weak` pair *does* preserve a stable address for the same underlying object, so
//! [`DataTypeImpl::data_type_impl_remove_parent`]'s `dt == dataType` reference-equality check is
//! ported faithfully via raw data-pointer comparison instead of a structural approximation.
//!
//! The five `protected` `notify*(...)` helpers (`notifySizeChanged`, `notifyAlignmentChanged`,
//! `notifyNameChanged`, `notifyDeleted`, `notifyReplaced`, and their shared `notifyParents`
//! backer) are intentionally **not** ported. Each ultimately needs to call a `&mut self` method
//! (`dataTypeSizeChanged` etc.) on a parent reached only through a weak back-reference -- but
//! that is provably impossible to do soundly here: [`Weak::upgrade`] only ever returns `Some` when
//! at least one *other* strong owner keeps the parent alive (our list stores only [`Weak`], never
//! [`Arc`]), so the upgraded clone plus that other owner means `Arc::get_mut` on the upgraded
//! handle is guaranteed to see a strong count of at least two and therefore always returns `None`.
//! A faithful port would require every concrete parent to adopt its own interior-mutability
//! convention (e.g. `Arc<Mutex<Inner>>`), which no other trait in this crate currently does for
//! [`DataType`]; that decision belongs to whichever concrete type first needs it, not to this
//! cycle-breaking port. [`DataTypeImpl::data_type_impl_get_parents`] gives implementors everything
//! they need to build their own notification scheme on top.
//!
//! `hashCode()`/`equals(Object)` are ported as [`DataTypeImpl::data_type_impl_hash_code`]/
//! [`DataTypeImpl::data_type_impl_equals`]. The hash uses Rust's `DefaultHasher` over
//! `get_name()` rather than replicating Java's exact `String.hashCode()` polynomial -- only
//! internal consistency (equal names hash equally) is required, not cross-language parity.
//! `equals`'s `otherDt.getDataTypeManager() == getDataTypeManager()` reference-equality check is
//! ported as a comparison of each side's [`DataTypeManager::get_universal_id`], since
//! [`DataType::get_data_type_manager`] already returns a freshly built `Box` with no stable
//! address to compare.
//!
//! The package-private `checkValidName(String)` helper is ported as
//! [`DataTypeImpl::data_type_impl_check_valid_name`], taking a `&dyn DataUtilities` parameter
//! (rather than requiring `Self: DataUtilities`) since `DataUtilities::is_valid_data_type_name`
//! already carries the real logic as a default method on that already-ported trait.

use std::sync::{Arc, Weak};

use crate::docking::settings::settings::Settings;
use crate::program::model::data::data_organization::DataOrganization;
use crate::program::model::data::data_type::{DataType, UnsupportedOperationError};
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::data::data_utilities::DataUtilities;
use crate::program::model::data::source_archive::SourceArchive;
use crate::util::exception::InvalidNameException;
use crate::util::UniversalID;

/// Port of the private static `DataTypeImpl.computeAlignedLength(DataType)`.
///
/// # Panics
/// Panics (standing in for `UnsupportedOperationException`) if `data_type` is a typedef,
/// composite, or array: "Typedefs must defer to base datatype for aligned-length determination."
fn compute_aligned_length<T: DataType + ?Sized>(data_type: &T) -> i32 {
    if data_type.is_typedef()
        || data_type.is_structure()
        || data_type.is_union()
        || data_type.is_array()
    {
        panic!(
            "computeAlignedLength is not supported for TypeDef, Composite, or Array datatypes"
        );
    }
    let len = data_type.get_length();
    if len <= 0 || data_type.is_pointer() {
        return len;
    }
    let align = data_type.get_data_organization().get_size_alignment(len);
    let modulo = len % align;
    if modulo != 0 {
        len + (align - modulo)
    } else {
        len
    }
}

/// Base implementation for dataTypes.
///
/// Port of `ghidra.program.model.data.DataTypeImpl`. See the module-level documentation for the
/// conventions used to resolve name clashes with [`DataType`], for the required accessors
/// standing in for private fields, and for what was left required, defaulted, or intentionally
/// omitted.
pub trait DataTypeImpl: DataType {
    /// Backing storage for the protected `defaultSettings` field.
    fn stored_default_settings(&self) -> Box<dyn Settings>;

    /// Mutator for the protected `defaultSettings` field's backing storage.
    fn set_stored_default_settings(&mut self, settings: Box<dyn Settings>);

    /// Backing storage for the private `sourceArchive` field.
    fn stored_source_archive(&self) -> Option<Box<dyn SourceArchive>>;

    /// Mutator for the private `sourceArchive` field's backing storage.
    fn set_stored_source_archive(&mut self, archive: Option<Box<dyn SourceArchive>>);

    /// Backing storage for the private `universalID` field. Java has no public setter for this
    /// field (only the constructor assigns it), so no mutator is exposed.
    fn stored_universal_id(&self) -> UniversalID;

    /// Backing storage for the private `lastChangeTime` field.
    fn stored_last_change_time(&self) -> i64;

    /// Mutator for the private `lastChangeTime` field's backing storage.
    fn set_stored_last_change_time(&mut self, last_change_time: i64);

    /// Backing storage for the private `lastChangeTimeInSourceArchive` field.
    fn stored_last_change_time_in_source_archive(&self) -> i64;

    /// Mutator for the private `lastChangeTimeInSourceArchive` field's backing storage.
    fn set_stored_last_change_time_in_source_archive(&mut self, last_change_time: i64);

    /// Backing storage for the private `parentList` field.
    fn stored_parent_refs(&self) -> Vec<Weak<dyn DataType>>;

    /// Mutator for the private `parentList` field's backing storage.
    fn set_stored_parent_refs(&mut self, parents: Vec<Weak<dyn DataType>>);

    /// Port of `DataTypeImpl.getDefaultSettings()`. Exposed under a distinct name since
    /// [`DataType::get_default_settings`] already provides a (placeholder) default. A concrete
    /// `impl DataType for ...` should delegate to this.
    fn data_type_impl_get_default_settings(&self) -> Box<dyn Settings> {
        self.stored_default_settings()
    }

    /// Port of `DataTypeImpl.getAlignedLength()`. Exposed under a distinct name since
    /// [`DataType::get_aligned_length`] already provides a (different) default. A concrete `impl
    /// DataType for ...` should delegate to this.
    fn data_type_impl_get_aligned_length(&self) -> i32 {
        compute_aligned_length(self)
    }

    /// Port of `DataTypeImpl.getAlignment()`. Exposed under a distinct name since
    /// [`DataType::get_alignment`] already provides a (different) default. A concrete `impl
    /// DataType for ...` should delegate to this.
    ///
    /// Requires `Self: Sized`: unlike [`data_type_impl_get_aligned_length`](Self::data_type_impl_get_aligned_length),
    /// this must hand `self` to [`DataOrganization::get_alignment`], whose signature is fixed to
    /// `&dyn DataType`, which requires an unsized coercion only available for a known-`Sized`
    /// source. This keeps the rest of the trait (including this method's callers, via a concrete
    /// `impl DataType`) usable as `dyn DataTypeImpl`; only this one method drops out of the vtable.
    fn data_type_impl_get_alignment(&self) -> i32
    where
        Self: Sized,
    {
        let length = self.get_length();
        if length < 0 {
            return 1;
        }
        self.get_data_organization().get_alignment(self)
    }

    /// Port of `DataTypeImpl.addParent(DataType)`. Exposed under a distinct name since
    /// [`DataType::add_parent`] already provides a (no-op) default. A concrete `impl DataType for
    /// ...` should delegate to this.
    fn data_type_impl_add_parent(&mut self, dt: Arc<dyn DataType>) {
        let mut refs = self.stored_parent_refs();
        refs.push(Arc::downgrade(&dt));
        self.set_stored_parent_refs(refs);
    }

    /// Port of `DataTypeImpl.removeParent(DataType)`. Exposed under a distinct name since
    /// [`DataType::remove_parent`] already provides a (no-op) default. A concrete `impl DataType
    /// for ...` should delegate to this.
    ///
    /// Prunes any dead weak references encountered along the way, then removes the first live
    /// parent whose address matches `dt` (mirroring Java's reference-equality `dt == dataType`
    /// check, approximated here via raw data-pointer comparison since `dyn DataType` has no
    /// identity operator).
    fn data_type_impl_remove_parent(&mut self, dt: &dyn DataType) {
        let target_ptr = dt as *const dyn DataType as *const ();
        let refs = self.stored_parent_refs();
        let mut kept = Vec::with_capacity(refs.len());
        let mut removed = false;
        for weak in refs {
            if removed {
                kept.push(weak);
                continue;
            }
            match weak.upgrade() {
                None => {}
                Some(parent) => {
                    let parent_ptr = Arc::as_ptr(&parent) as *const ();
                    if std::ptr::eq(parent_ptr, target_ptr) {
                        removed = true;
                    } else {
                        kept.push(Arc::downgrade(&parent));
                    }
                }
            }
        }
        self.set_stored_parent_refs(kept);
    }

    /// Port of `DataTypeImpl.getParents()`. Exposed under a distinct name since
    /// [`DataType::get_parents`] already provides a (no-op) default, and because this needs
    /// `&mut self` (unlike the supertrait method) to prune dead weak references as a side effect,
    /// exactly as the Java original does while iterating. A concrete `impl DataType for ...`
    /// cannot delegate directly (its `get_parents` takes `&self`); it should instead call this
    /// from wherever it has `&mut self` available and cache/expose the result as needed.
    fn data_type_impl_get_parents(&mut self) -> Vec<Arc<dyn DataType>> {
        let refs = self.stored_parent_refs();
        let mut live = Vec::with_capacity(refs.len());
        let mut kept = Vec::with_capacity(refs.len());
        for weak in refs {
            if let Some(parent) = weak.upgrade() {
                kept.push(Arc::downgrade(&parent));
                live.push(parent);
            }
        }
        self.set_stored_parent_refs(kept);
        live
    }

    /// Port of `DataTypeImpl.getLastChangeTime()`. Exposed under a distinct name since
    /// [`DataType::get_last_change_time`] already provides a (placeholder) default. A concrete
    /// `impl DataType for ...` should delegate to this.
    fn data_type_impl_get_last_change_time(&self) -> i64 {
        self.stored_last_change_time()
    }

    /// Port of `DataTypeImpl.getLastChangeTimeInSourceArchive()`. Exposed under a distinct name
    /// since [`DataType::get_last_change_time_in_source_archive`] already provides a (placeholder)
    /// default. A concrete `impl DataType for ...` should delegate to this.
    fn data_type_impl_get_last_change_time_in_source_archive(&self) -> i64 {
        self.stored_last_change_time_in_source_archive()
    }

    /// Port of `DataTypeImpl.getSourceArchive()`. Exposed under a distinct name since
    /// [`DataType::get_source_archive`] already provides a (placeholder) default. A concrete
    /// `impl DataType for ...` should delegate to this.
    fn data_type_impl_get_source_archive(&self) -> Option<Box<dyn SourceArchive>> {
        self.stored_source_archive()
    }

    /// Port of `DataTypeImpl.setSourceArchive(SourceArchive)`. Exposed under a distinct name
    /// since [`DataType::set_source_archive`] already provides a (no-op) default. A concrete
    /// `impl DataType for ...` should delegate to this.
    fn data_type_impl_set_source_archive(&mut self, archive: Option<Box<dyn SourceArchive>>) {
        self.set_stored_source_archive(archive);
    }

    /// Port of `DataTypeImpl.getUniversalID()`. Exposed under a distinct name since
    /// [`DataType::get_universal_id`] already provides a (placeholder) default. A concrete `impl
    /// DataType for ...` should delegate to this.
    fn data_type_impl_get_universal_id(&self) -> UniversalID {
        self.stored_universal_id()
    }

    /// Port of `DataTypeImpl.replaceWith(DataType)`. Exposed under a distinct name since
    /// [`DataType::replace_with`] already provides a (no-op) default; unlike that default, this
    /// unconditionally panics, standing in for the unconditional `UnsupportedOperationException`
    /// thrown by the Java original. A concrete `impl DataType for ...` should delegate to this.
    fn data_type_impl_replace_with(&mut self, data_type: &dyn DataType) {
        let _ = data_type;
        panic!("replaceWith is not supported for this datatype");
    }

    /// Port of `DataTypeImpl.setLastChangeTime(long)`. Exposed under a distinct name since
    /// [`DataType::set_last_change_time`] already provides a (no-op) default. A concrete `impl
    /// DataType for ...` should delegate to this.
    fn data_type_impl_set_last_change_time(&mut self, last_change_time: i64) {
        self.set_stored_last_change_time(last_change_time);
    }

    /// Port of `DataTypeImpl.setLastChangeTimeInSourceArchive(long)`. Exposed under a distinct
    /// name since [`DataType::set_last_change_time_in_source_archive`] already provides a (no-op)
    /// default. A concrete `impl DataType for ...` should delegate to this.
    fn data_type_impl_set_last_change_time_in_source_archive(&mut self, last_change_time: i64) {
        self.set_stored_last_change_time_in_source_archive(last_change_time);
    }

    /// Port of `DataTypeImpl.setDescription(String)`. Exposed under a distinct name since
    /// [`DataType::set_description`] already provides a (silently-succeeding) default; unlike
    /// that default, this unconditionally errors, standing in for the unconditional
    /// `UnsupportedOperationException` thrown by the Java original. A concrete `impl DataType for
    /// ...` should delegate to this.
    fn data_type_impl_set_description(
        &mut self,
        description: &str,
    ) -> Result<(), UnsupportedOperationError> {
        let _ = description;
        Err(UnsupportedOperationError(
            "This data type does not allow its description to be changed.".to_string(),
        ))
    }

    /// Port of the package-private `DataTypeImpl.checkValidName(String)`.
    ///
    /// # Errors
    /// Returns [`InvalidNameException`] if `checked_name` is not a valid data-type name according
    /// to `utilities`.
    fn data_type_impl_check_valid_name(
        &self,
        checked_name: &str,
        utilities: &dyn DataUtilities,
    ) -> Result<(), InvalidNameException> {
        if !utilities.is_valid_data_type_name(checked_name) {
            return Err(InvalidNameException(format!("Invalid Name: {checked_name}")));
        }
        Ok(())
    }

    /// Port of the final `DataTypeImpl.hashCode()`. Uses Rust's `DefaultHasher` over `get_name()`
    /// rather than replicating Java's exact `String.hashCode()` algorithm -- only internal
    /// consistency (equal names hash equally) is required.
    fn data_type_impl_hash_code(&self) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        self.get_name().hash(&mut hasher);
        hasher.finish()
    }

    /// Port of the final `DataTypeImpl.equals(Object)`.
    ///
    /// `otherDt.getDataTypeManager() == getDataTypeManager()`'s reference-equality check is
    /// approximated by comparing each side's [`DataTypeManager::get_universal_id`], since
    /// [`DataType::get_data_type_manager`] returns a freshly built `Box` with no stable address
    /// to compare (both `None` counts as equal, matching two `null` managers in Java).
    fn data_type_impl_equals(&self, other: &dyn DataType) -> bool {
        let self_mgr_id = self.get_data_type_manager().map(|m| m.get_universal_id());
        let other_mgr_id = other.get_data_type_manager().map(|m| m.get_universal_id());
        self_mgr_id == other_mgr_id
            && self.get_category_path() == other.get_category_path()
            && self.get_name() == other.get_name()
            && self.is_equivalent(other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::data::category_path::{CategoryPath, ROOT};

    struct MockSettings {
        immutable: bool,
    }
    impl Settings for MockSettings {
        fn is_immutable_settings(&self) -> bool {
            self.immutable
        }
    }

    // Every `set_stored_*` below takes `&mut self`, so the stored state needs no interior
    // mutability; plain fields also keep this mock `Send + Sync`, as `DataType` requires. The
    // settings box is reduced to the one flag the mock ever reads back, since `dyn Settings` is
    // itself neither `Send` nor `Sync`.
    struct MockDataTypeImpl {
        name: String,
        length: i32,
        category_path: CategoryPath,
        default_settings_immutable: bool,
        universal_id: UniversalID,
        last_change_time: i64,
        last_change_time_in_source_archive: i64,
        parents: Vec<Weak<dyn DataType>>,
    }

    impl MockDataTypeImpl {
        fn new(name: &str, length: i32) -> Self {
            Self {
                name: name.to_string(),
                length,
                category_path: ROOT.clone(),
                default_settings_immutable: false,
                universal_id: UniversalID::new(1),
                last_change_time: 0,
                last_change_time_in_source_archive: 0,
                parents: Vec::new(),
            }
        }
    }

    impl DataType for MockDataTypeImpl {
        fn get_name(&self) -> String {
            self.name.clone()
        }
        fn get_length(&self) -> i32 {
            self.length
        }
        fn get_category_path(&self) -> CategoryPath {
            self.category_path.clone()
        }
        fn is_equivalent(&self, dt: &dyn DataType) -> bool {
            self.get_name() == dt.get_name() && self.get_length() == dt.get_length()
        }
    }

    impl DataTypeImpl for MockDataTypeImpl {
        fn stored_default_settings(&self) -> Box<dyn Settings> {
            Box::new(MockSettings { immutable: self.default_settings_immutable })
        }
        fn set_stored_default_settings(&mut self, settings: Box<dyn Settings>) {
            self.default_settings_immutable = settings.is_immutable_settings();
        }
        fn stored_source_archive(&self) -> Option<Box<dyn SourceArchive>> {
            None
        }
        fn set_stored_source_archive(&mut self, _archive: Option<Box<dyn SourceArchive>>) {}
        fn stored_universal_id(&self) -> UniversalID {
            self.universal_id
        }
        fn stored_last_change_time(&self) -> i64 {
            self.last_change_time
        }
        fn set_stored_last_change_time(&mut self, last_change_time: i64) {
            self.last_change_time = last_change_time;
        }
        fn stored_last_change_time_in_source_archive(&self) -> i64 {
            self.last_change_time_in_source_archive
        }
        fn set_stored_last_change_time_in_source_archive(&mut self, last_change_time: i64) {
            self.last_change_time_in_source_archive = last_change_time;
        }
        fn stored_parent_refs(&self) -> Vec<Weak<dyn DataType>> {
            self.parents.clone()
        }
        fn set_stored_parent_refs(&mut self, parents: Vec<Weak<dyn DataType>>) {
            self.parents = parents;
        }
    }

    #[test]
    fn usable_as_trait_object() {
        // Length 0 keeps `data_type_impl_get_aligned_length` on the early-return branch, since
        // `MockDataTypeImpl` doesn't implement `DataType::get_data_organization` (no default
        // implementation exists for it yet -- see that method's own doc comment).
        let dt: Box<dyn DataTypeImpl> = Box::new(MockDataTypeImpl::new("byte", 0));
        assert_eq!(dt.get_name(), "byte");
        assert_eq!(dt.data_type_impl_get_aligned_length(), 0);
    }

    #[test]
    fn add_parent_then_get_parents_returns_live_parent() {
        let mut child = MockDataTypeImpl::new("child", 4);
        let parent: Arc<dyn DataType> = Arc::new(MockDataTypeImpl::new("parent", 8));
        child.data_type_impl_add_parent(Arc::clone(&parent));

        let live = child.data_type_impl_get_parents();
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].get_name(), "parent");
    }

    #[test]
    fn get_parents_prunes_dropped_parent() {
        let mut child = MockDataTypeImpl::new("child", 4);
        {
            let parent: Arc<dyn DataType> = Arc::new(MockDataTypeImpl::new("parent", 8));
            child.data_type_impl_add_parent(Arc::clone(&parent));
            // `parent` dropped at the end of this block; only the weak ref remains.
        }
        assert!(child.data_type_impl_get_parents().is_empty());
    }

    #[test]
    fn remove_parent_removes_only_matching_reference() {
        let mut child = MockDataTypeImpl::new("child", 4);
        let parent_a: Arc<dyn DataType> = Arc::new(MockDataTypeImpl::new("a", 1));
        let parent_b: Arc<dyn DataType> = Arc::new(MockDataTypeImpl::new("b", 2));
        child.data_type_impl_add_parent(Arc::clone(&parent_a));
        child.data_type_impl_add_parent(Arc::clone(&parent_b));

        child.data_type_impl_remove_parent(&*parent_a);

        let live = child.data_type_impl_get_parents();
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].get_name(), "b");
    }

    #[test]
    fn equals_true_for_same_name_category_and_equivalence() {
        let a = MockDataTypeImpl::new("dword", 4);
        let b = MockDataTypeImpl::new("dword", 4);
        assert!(a.data_type_impl_equals(&b));
    }

    #[test]
    fn equals_false_for_different_name() {
        let a = MockDataTypeImpl::new("dword", 4);
        let b = MockDataTypeImpl::new("word", 2);
        assert!(!a.data_type_impl_equals(&b));
    }

    #[test]
    fn hash_code_is_consistent_for_equal_names() {
        let a = MockDataTypeImpl::new("dword", 4);
        let b = MockDataTypeImpl::new("dword", 999);
        assert_eq!(a.data_type_impl_hash_code(), b.data_type_impl_hash_code());
    }

    #[test]
    fn set_description_is_always_unsupported() {
        let mut dt = MockDataTypeImpl::new("byte", 1);
        assert!(dt.data_type_impl_set_description("new description").is_err());
    }

    #[test]
    #[should_panic(expected = "replaceWith is not supported")]
    fn replace_with_panics() {
        let mut dt = MockDataTypeImpl::new("byte", 1);
        let other = MockDataTypeImpl::new("other", 1);
        dt.data_type_impl_replace_with(&other);
    }

    #[test]
    fn get_aligned_length_returns_raw_length_for_pointer() {
        struct MockPointer;
        impl DataType for MockPointer {
            fn get_length(&self) -> i32 {
                8
            }
            fn is_pointer(&self) -> bool {
                true
            }
        }
        impl DataTypeImpl for MockPointer {
            fn stored_default_settings(&self) -> Box<dyn Settings> {
                Box::new(MockSettings { immutable: false })
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

        let dt = MockPointer;
        assert_eq!(dt.data_type_impl_get_aligned_length(), 8);
    }

    #[test]
    fn get_alignment_returns_one_for_negative_length() {
        let dt = MockDataTypeImpl::new("weird", -1);
        assert_eq!(dt.data_type_impl_get_alignment(), 1);
    }
}

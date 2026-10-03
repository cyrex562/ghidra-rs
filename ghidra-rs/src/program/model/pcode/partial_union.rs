//! Port of `ghidra.program.model.pcode.PartialUnion`, promoted to a trait because it was selected
//! as a dependency-cycle cut-point.
//!
//! The Java class `extends AbstractDataType`, which is not yet ported in this crate. Every member
//! `PartialUnion` actually overrides from it is already covered by the already-ported
//! [`DataType`] trait (`ghidra.program.model.data.DataType`), so no `seam_stubs` placeholder is
//! needed for `AbstractDataType` itself.
//!
//! The three private fields (`unionDataType`, `offset`, `size`) have no Rust equivalent since
//! traits cannot store state; they are instead exposed as required accessor methods
//! ([`get_parent`](PartialUnion::get_parent), [`get_offset`](PartialUnion::get_offset),
//! [`partial_union_length`](PartialUnion::partial_union_length)) that a concrete implementation is
//! expected to back with its own fields.
//!
//! Methods that only *override* an already-ported [`DataType`] default method with
//! `PartialUnion`-specific behavior (`getLength`, `getAlignedLength`, `getSettingsDefinitions`,
//! `getDefaultSettings`, `clone`, `copy`, `getValueClass`, `isEquivalent`, `getAlignment`) cannot
//! be redeclared here without creating an ambiguous method name with [`DataType`] (Rust does not
//! allow a subtrait to "override" a supertrait's default method by re-declaring it). Instead, the
//! real `PartialUnion`-specific values for those overrides are exposed here under distinct
//! `partial_union_*` names, mirroring the convention established by
//! [`IntegerDataType`](crate::program::model::data::integer_data_type::IntegerDataType); a future
//! concrete implementation should implement [`DataType`] directly and delegate to these helpers.
//!
//! `getDescription()` -> `partial_union_description` is likewise exposed under a distinct name,
//! even though its intended override ("Partial Union (internal)") is what a real implementor
//! should return from `DataType::get_description`.
//!
//! `getValue`/`getRepresentation` are not re-exposed: both simply return `null` in Java ("Should
//! not be placed on memory"), which is exactly [`DataType::get_value`]'s and
//! [`DataType::get_representation`]'s existing default behavior (`None` / an empty `String`), so
//! no override is needed.
//!
//! `isEquivalent(DataType)` starts with an `instanceof PartialUnion` check that Rust has no
//! general downcast for on a `dyn DataType`; mirroring the precedent set by
//! [`DataTypeComponent::is_equivalent`](crate::program::model::data::data_type_component::DataTypeComponent),
//! [`partial_union_is_equivalent`](PartialUnion::partial_union_is_equivalent) instead takes
//! `&dyn PartialUnion` directly, pushing the "is this actually a `PartialUnion`" decision to the
//! caller.
//!
//! `getStrippedDataType()` calls the static factory `Undefined.getUndefinedDataType(size)`, which
//! is itself omitted from the already-ported [`Undefined`](crate::program::model::data::undefined::Undefined)
//! trait (see that module's docs) because it builds a registry keyed off concrete sibling types
//! (`Undefined1DataType` .. `Undefined8DataType`) that are not yet ported. For the same reason,
//! [`get_stripped_data_type`](PartialUnion::get_stripped_data_type) is left here as a required
//! method with no default; port it alongside those concrete types instead.
//!
//! The package-private constructor (`PartialUnion(DataTypeManager, DataType, int, int)`, which
//! forwards to `AbstractDataType(CategoryPath.ROOT, "partialunion", dtm)`) has no Rust equivalent
//! since traits cannot declare constructors; each concrete implementor is expected to replicate it
//! via [`DataType::get_name`]/[`DataType::get_category_path`].

use std::any::TypeId;

use crate::docking::settings::settings::Settings;
use crate::docking::settings::settings_definition::SettingsDefinition;
use crate::program::model::data::data_type::{DataType, UnsupportedOperationError};

/// A data-type representing an unspecified piece of a parent Union data-type.
///
/// Port of `ghidra.program.model.pcode.PartialUnion`. See the module docs for what was ported,
/// renamed, and omitted.
pub trait PartialUnion: DataType {
    /// The Union data-type (or Typedef of a Union) of which this is a part.
    ///
    /// Port of `PartialUnion.getParent()`.
    fn get_parent(&self) -> Box<dyn DataType>;

    /// The offset, in bytes, of this part within its parent Union.
    ///
    /// Port of `PartialUnion.getOffset()`.
    fn get_offset(&self) -> i32;

    /// Get a data-type that can be used as a formal replacement for this (internal) data-type.
    ///
    /// Port of `PartialUnion.getStrippedDataType()`. Left as a required method (no default); see
    /// the module docs for why the real `Undefined.getUndefinedDataType(int)` factory it delegates
    /// to is not available yet.
    fn get_stripped_data_type(&self) -> Box<dyn DataType>;

    /// The number of bytes in this partial.
    ///
    /// Port of `PartialUnion.getLength()`, which overrides the abstract `DataType.getLength()`.
    /// Exposed under a distinct name since [`DataType`] already declares `get_length`; see the
    /// module docs for why it cannot be redeclared here. Left as a required method (no default)
    /// since it is backed directly by the private `size` field, which has no computable fallback.
    fn partial_union_length(&self) -> i32;

    /// The aligned length of this partial.
    ///
    /// Port of `PartialUnion.getAlignedLength()`, which overrides `DataType.getAlignedLength()`.
    /// Exposed under a distinct name since [`DataType`] already declares `get_aligned_length`; see
    /// the module docs for why it cannot be redeclared here.
    fn partial_union_aligned_length(&self) -> i32 {
        self.partial_union_length()
    }

    /// A brief description of this data-type.
    ///
    /// Port of `PartialUnion.getDescription()`, which overrides `DataType.getDescription()`.
    /// Exposed under a distinct name since [`DataType`] already declares `get_description`; see
    /// the module docs for why it cannot be redeclared here.
    fn partial_union_description(&self) -> String {
        "Partial Union (internal)".to_string()
    }

    /// The list of settings definitions available for use with this datatype, delegated to the
    /// parent Union.
    ///
    /// Port of `PartialUnion.getSettingsDefinitions()`, which overrides
    /// `DataType.getSettingsDefinitions()`. Exposed under a distinct name since [`DataType`]
    /// already declares `get_settings_definitions`; see the module docs for why it cannot be
    /// redeclared here.
    fn partial_union_settings_definitions(&self) -> Vec<Box<dyn SettingsDefinition>> {
        self.get_parent().get_settings_definitions()
    }

    /// The settings for this data type, delegated to the parent Union.
    ///
    /// Port of `PartialUnion.getDefaultSettings()`, which overrides
    /// `DataType.getDefaultSettings()`. Exposed under a distinct name since [`DataType`] already
    /// declares `get_default_settings`; see the module docs for why it cannot be redeclared here.
    fn partial_union_default_settings(&self) -> Box<dyn Settings> {
        self.get_parent().get_default_settings()
    }

    /// Port of `PartialUnion.clone(DataTypeManager)`, which overrides
    /// `DataType.clone_data_type` and always throws `UnsupportedOperationException("may not be
    /// cloned")`, since a `PartialUnion` is internal to the `PcodeDataTypeManager`. Exposed under
    /// a distinct name since [`DataType`] already declares `clone_data_type`; see the module docs
    /// for why it cannot be redeclared here.
    fn partial_union_clone(&self) -> Result<Box<dyn DataType>, UnsupportedOperationError> {
        Err(UnsupportedOperationError("may not be cloned".to_string()))
    }

    /// Port of `PartialUnion.copy(DataTypeManager)`, which overrides `DataType.copy_data_type`
    /// and always throws `UnsupportedOperationException("may not be copied")`, since a
    /// `PartialUnion` is internal to the `PcodeDataTypeManager`. Exposed under a distinct name
    /// since [`DataType`] already declares `copy_data_type`; see the module docs for why it
    /// cannot be redeclared here.
    fn partial_union_copy(&self) -> Result<Box<dyn DataType>, UnsupportedOperationError> {
        Err(UnsupportedOperationError("may not be copied".to_string()))
    }

    /// The Rust `TypeId` of the value this datatype would decode to, delegated to the parent
    /// Union.
    ///
    /// Port of `PartialUnion.getValueClass(Settings)`, which overrides
    /// `DataType.getValueClass(Settings)`. Exposed under a distinct name since [`DataType`]
    /// already declares `get_value_class`; see the module docs for why it cannot be redeclared
    /// here.
    fn partial_union_value_class(&self, settings: &dyn Settings) -> Option<TypeId> {
        self.get_parent().get_value_class(settings)
    }

    /// Check if the given `PartialUnion` is equivalent to this one.
    ///
    /// Port of `PartialUnion.isEquivalent(DataType)`, which overrides
    /// `DataType.isEquivalent(DataType)`. Exposed under a distinct name (and takes `&dyn
    /// PartialUnion` rather than `&dyn DataType`) since [`DataType`] already declares
    /// `is_equivalent`; see the module docs for why it cannot be redeclared here and why the
    /// `instanceof PartialUnion` check is pushed to the caller.
    fn partial_union_is_equivalent(&self, other: &dyn PartialUnion) -> bool {
        if self.get_offset() != other.get_offset()
            || self.partial_union_length() != other.partial_union_length()
        {
            return false;
        }
        self.get_parent().is_equivalent(other.get_parent().as_ref())
    }

    /// Port of `PartialUnion.getAlignment()`, which overrides `DataType.getAlignment()` and
    /// always returns `0`. Exposed under a distinct name since [`DataType`] already declares
    /// `get_alignment`; see the module docs for why it cannot be redeclared here.
    fn partial_union_alignment(&self) -> i32 {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockUnionDataType {
        settings_calls: std::sync::atomic::AtomicU32,
    }

    impl DataType for MockUnionDataType {
        fn get_length(&self) -> i32 {
            8
        }
        fn get_settings_definitions(&self) -> Vec<Box<dyn SettingsDefinition>> {
            self.settings_calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Vec::new()
        }
        fn is_equivalent(&self, dt: &dyn DataType) -> bool {
            self.get_length() == dt.get_length()
        }
    }

    struct MockPartialUnion {
        offset: i32,
        size: i32,
    }

    impl DataType for MockPartialUnion {
        fn get_length(&self) -> i32 {
            self.partial_union_length()
        }
        fn get_description(&self) -> String {
            self.partial_union_description()
        }
        fn get_alignment(&self) -> i32 {
            self.partial_union_alignment()
        }
    }

    impl PartialUnion for MockPartialUnion {
        fn get_parent(&self) -> Box<dyn DataType> {
            Box::new(MockUnionDataType {
                settings_calls: std::sync::atomic::AtomicU32::new(0),
            })
        }
        fn get_offset(&self) -> i32 {
            self.offset
        }
        fn get_stripped_data_type(&self) -> Box<dyn DataType> {
            Box::new(MockUnionDataType {
                settings_calls: std::sync::atomic::AtomicU32::new(0),
            })
        }
        fn partial_union_length(&self) -> i32 {
            self.size
        }
    }

    #[test]
    fn partial_union_usable_as_trait_object() {
        let pu = MockPartialUnion { offset: 4, size: 2 };
        let dyn_pu: &dyn PartialUnion = &pu;

        assert_eq!(dyn_pu.get_offset(), 4);
        assert_eq!(dyn_pu.partial_union_length(), 2);
        assert_eq!(dyn_pu.partial_union_aligned_length(), 2);
        assert_eq!(dyn_pu.partial_union_description(), "Partial Union (internal)");
        assert_eq!(dyn_pu.partial_union_alignment(), 0);
    }

    #[test]
    fn partial_union_delegates_settings_to_parent() {
        let pu = MockPartialUnion { offset: 0, size: 4 };
        assert!(pu.partial_union_settings_definitions().is_empty());
    }

    #[test]
    fn partial_union_clone_and_copy_are_unsupported() {
        let pu = MockPartialUnion { offset: 0, size: 4 };
        assert!(pu.partial_union_clone().is_err());
        assert!(pu.partial_union_copy().is_err());
    }

    #[test]
    fn partial_union_is_equivalent_compares_offset_size_and_parent() {
        let a = MockPartialUnion { offset: 4, size: 2 };
        let b = MockPartialUnion { offset: 4, size: 2 };
        let c = MockPartialUnion { offset: 8, size: 2 };

        assert!(a.partial_union_is_equivalent(&b));
        assert!(!a.partial_union_is_equivalent(&c));
    }

    #[test]
    fn partial_union_as_data_type_trait_object() {
        let pu = MockPartialUnion { offset: 0, size: 6 };
        let dyn_dt: &dyn DataType = &pu;

        assert_eq!(dyn_dt.get_length(), 6);
        assert_eq!(dyn_dt.get_description(), "Partial Union (internal)");
    }
}

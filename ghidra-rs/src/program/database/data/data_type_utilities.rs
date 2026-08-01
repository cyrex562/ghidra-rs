//! Port of `ghidra.program.database.data.DataTypeUtilities`.
//!
//! The Java class is a `private`-constructor static-method utility. It was selected as a
//! dependency-cycle cut-point, so -- mirroring
//! [`DataUtilities`](crate::program::model::data::data_utilities::DataUtilities) and
//! [`VariableUtilities`](crate::program::model::listing::variable_utilities::VariableUtilities)
//! -- it is ported here as a Rust trait with default-implemented methods instead of free
//! functions: callers depend on `&dyn DataTypeUtilities` (a trait-object seam) rather than
//! importing this module's concrete machinery directly. A bare `impl DataTypeUtilities for Foo
//! {}` is enough to use every method, since every method has a real default implementation. The
//! private helper methods that back the public API have no receiver of their own in Java and are
//! ported as ordinary module-private free functions (some generic over `N: Namespace + ?Sized`
//! where the Java helper is shared between a plain `Namespace` and a `GhidraClass` caller -- a
//! trait method itself cannot be generic without losing object-safety, but a private free
//! function can, and calling it with a `&dyn GhidraClass` monomorphizes `N = dyn GhidraClass`
//! without needing any trait-object upcasting, since `GhidraClass: Namespace` already makes `dyn
//! GhidraClass: Namespace` hold).
//!
//! ## Object-safety adaptations
//!
//! - The two `Class<T> classConstraint` generic methods (`findDataType`,
//!   `findNamespaceQualifiedDataType`) are ported as non-generic methods taking an optional
//!   `&dyn Fn(&dyn DataType) -> bool` predicate in place of `Class<T>::isAssignableFrom`, and
//!   return `Box<dyn DataType>` rather than a caller-chosen `T`.
//! - [`find_existing_class_struct`](DataTypeUtilities::find_existing_class_struct) similarly
//!   returns `Box<dyn DataType>` rather than `Structure`, since this crate's `DataType` trait has
//!   no owned downcast to `Structure` (only two `into_*` owned downcasts exist, for `Array`/
//!   `Composite`); callers can check [`DataType::is_structure`].
//! - [`get_typedef_replacement`](DataTypeUtilities::get_typedef_replacement) returns
//!   `Result<Option<Box<dyn DataType>>, String>` rather than always returning a non-null
//!   `DataType`: the Java method's final fallthrough (`return typedef;`) hands back the *same*
//!   object the caller already owns a reference to, which this port cannot reconstruct as an
//!   owned value from a borrowed `&dyn TypeDef` parameter. `Ok(None)` stands in for that
//!   fallthrough -- callers should keep using their own `typedef` reference in that case.
//! - [`get_base_data_type`](DataTypeUtilities::get_base_data_type),
//!   [`get_contained_data_types`](DataTypeUtilities::get_contained_data_types), and
//!   [`get_merger`](DataTypeUtilities::get_merger) take/return owned `Box<dyn DataType>` (or
//!   consume an owned parameter) in a couple of spots where the Java original relies on returning
//!   the *same* input reference back to the caller; this port instead threads ownership through
//!   explicitly.
//! - Reference-identity comparisons (Java's `==`/`!=` on `DataType`/`TypeDef` values, e.g.
//!   `directReplacement.equals(refDt)` in `getTypedefReplacement`, or the shortcut `dataType1 ==
//!   dataType2` in `isSameKindDataType`) are approximated with
//!   [`DataType::is_equivalent`] (checked both directions), matching the established substitution
//!   already used elsewhere in this crate (see `DataUtilities`'s module docs for the same
//!   trade-off) since no general reference-identity facility exists for `dyn DataType`.
//! [`is_second_part_of_first`](DataTypeUtilities::is_second_part_of_first) instead compares
//! [`DataType::get_data_type_path`], mirroring the established substitution already used by
//! [`CompositeDataTypeImpl`](crate::program::model::data::composite_data_type_impl)'s own partial
//! port of this same method.
//!
//! ## Grown methods
//!
//! Several `instanceof`-standin downcasts needed by this port did not previously exist on
//! already-ported real traits; they were grown as defaulted methods (so existing implementors
//! keep compiling), following the established convention used throughout this crate:
//! - [`DataType::as_union`], [`DataType::as_function_definition`],
//!   [`DataType::as_built_in_data_type`], [`DataType::as_built_in`].
//! - [`DataTypeManager::as_program_based`](crate::program::model::data::data_type_manager::DataTypeManager::as_program_based)
//!   -- `instanceof ProgramBasedDataTypeManager`.
//! - [`Program::get_preferred_root_namespace_category_path`](crate::program::model::listing::Program::get_preferred_root_namespace_category_path)
//!   -- this is a real (if previously unported) method on the Java `Program` interface, not an
//!   `instanceof` standin; it defaults to the root category, mirroring `ProgramDB`'s own default.
//!
//! ## Known simplifications
//!
//! - `cPrimitiveNameMap`/`cTypedefBuiltInNameRemap` are static maps of *concrete singleton
//!   instances* of every C primitive/typedef-replacement `BuiltIn` datatype (`CharDataType.
//!   dataType`, `IntegerDataType.dataType`, ...). None of those concrete singletons exist in this
//!   crate yet -- each primitive datatype class (e.g.
//!   [`CharDataType`](crate::program::model::data::char_data_type::CharDataType)) was itself
//!   already ported as its own cycle-cut-point trait with no concrete implementation (see that
//!   trait's module docs). [`get_c_primitive_data_type`](DataTypeUtilities::get_c_primitive_data_type)
//!   and the private `getValidReplacement` (ported as
//!   [`get_valid_replacement`](DataTypeUtilities::get_valid_replacement)) therefore delegate the
//!   actual singleton lookup to a defaulted hook
//!   ([`c_primitive_data_type_for_name`](DataTypeUtilities::c_primitive_data_type_for_name),
//!   [`typedef_built_in_replacement_for_name`](DataTypeUtilities::typedef_built_in_replacement_for_name))
//!   that returns `None` by default; concrete implementors with real primitive singletons
//!   available should override these. The real name-normalization algorithm around each hook is
//!   still ported faithfully.
//! - `getValidReplacement`'s `replacementDt instanceof DataTypeWithCharset` branch cannot be
//!   replicated against the opaque `Box<dyn DataType>` returned by the hook above (there is no
//!   marker for "implements `DataTypeWithCharset`" on `DataType` itself); this port instead
//!   accepts any non-integer replacement, which is a strict superset of the Java behavior but
//!   matches it in practice since every non-integer entry in the real `cTypedefBuiltInNameRemap`
//!   is one of the charset-bearing wide-char types.
//! - `isSameKindBuiltInDataType`'s "shared common `BuiltIn` superclass" check walks Java class
//!   hierarchy reflection (`getClass().getSuperclass()` up to `BuiltIn.class`), which has no
//!   equivalent on `dyn DataType` (no general RTTI facility). This port instead uses the
//!   `is_integer_type`/`is_floating_point` markers already on [`DataType`] for the two documented
//!   "same abstract base" cases (`AbstractIntegerDataType`/`AbstractFloatDataType`), falling back
//!   to name equality (the closest available proxy) for everything else, including the
//!   `AbstractStringDataType` case and the "exact same implementation class" case. See
//!   [`is_same_kind_built_in_data_type`].
//! - `isSameKindDataType`'s `Array` branch faithfully reproduces an apparent upstream typo:
//!   `dataType2 instanceof Array a1 && dataType2 instanceof Array a2` tests `dataType2` twice,
//!   never actually consulting `dataType1`. Preserved as-is rather than "fixed", per this port's
//!   general policy of translating behavior exactly.
//! - `isConflictDataType`'s final regex check is applied to `dt.getName()` (the *original*,
//!   possibly pointer/array-decorated name) rather than the base datatype's name used by its
//!   sibling methods (`getNameWithoutConflict`/`getConflictValue`) -- this is a known, class-doc-
//!   acknowledged Java quirk ("`BASE_DATATYPE_CONFLICT_PATTERN` may never be applied to a pointer
//!   or array name as it will always fail to match"), preserved here rather than "fixed".
//! - `checkValidReplacementDataType`'s `dataType instanceof DataTypeDB` early-exit is dropped:
//!   its only effect is to skip the void/default/bitfield/factory/dynamic checks for DB-backed
//!   instances, none of which a real `DataTypeDB` implementation would ever match anyway (those
//!   bool markers all default to `false` and are only set by the specific non-DB datatype classes
//!   they name), so the checks are safe to always run. Adding a downcast here would also require
//!   the model-layer `DataType` trait to depend on the database-layer `DataTypeDb` trait, which
//!   this port avoids for layering reasons.
//! - `isSameOrEquivalentDataType`'s `dataType2 instanceof DataTypeDB` fast path (which flips which
//!   side calls `isEquivalent`, purely as a DB-side performance optimization) is dropped for the
//!   same layering reason; `isEquivalent` is expected to be symmetric, so the result is
//!   unaffected, just without the DB-side fast path.

use std::collections::{HashSet, VecDeque};

use once_cell::sync::Lazy;
use regex::Regex;

use crate::app::util::symbol_path::{SymbolPath, SymbolPathError, SymbolPathNode};
use crate::docking::settings::settings::Settings;
use crate::program::database::data::merge::DataTypeMergeException;
use crate::program::model::data::array::Array;
use crate::program::model::data::category::Category;
use crate::program::model::data::category_path::{CategoryPath, DELIMITER_STRING};
use crate::program::model::data::data_type::{DataType, CONFLICT_SUFFIX};
use crate::program::model::data::data_type_dependency_exception::DataTypeDependencyException;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::data::typedef::TypeDef;
use crate::program::model::listing::GhidraClass;
use crate::program::model::symbol::Namespace;
use crate::program::seam_stubs::{
    DataTypeMerger, EnumMergerPlaceholder, StructureMergerPlaceholder, TypedefDataTypePlaceholder,
    UnionMergerPlaceholder,
};

static BASE_DATATYPE_CONFLICT_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(&format!("{}([_]{{0,1}}\\d+){{0,1}}$", regex::escape(CONFLICT_SUFFIX))).unwrap()
});

static DATATYPE_POINTER_ARRAY_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(( \*\d*)|(\[\d+\]))+$").unwrap());

/// Static helper methods relating to datatypes.
///
/// Port of `ghidra.program.database.data.DataTypeUtilities`. See the module docs for what was
/// ported, grown, and deliberately diverged from.
pub trait DataTypeUtilities {
    /// Get a BuiltIn `TypeDef` replacement, if one exists, for the specified fabricated typedef.
    ///
    /// This method is intended to be used by parsers prior to resolving or applying a fabricated
    /// fixed-length typedef to allow a portable implementation to be used in its place.
    ///
    /// Returns `Ok(Some(dt))` for an actual replacement, or `Ok(None)` if no replacement was
    /// found (the caller should keep using its own `typedef` reference in that case -- see the
    /// module docs for why this diverges from the Java `return typedef;` fallthrough).
    ///
    /// # Errors
    /// Returns `Err` if `typedef` was not constructed or cloned for a specific data type manager,
    /// mirroring the `IllegalArgumentException` thrown by the Java source.
    fn get_typedef_replacement(
        &self,
        typedef: &dyn TypeDef,
        enforce_size_match: bool,
    ) -> Result<Option<Box<dyn DataType>>, String> {
        let dtm = typedef
            .get_data_type_manager()
            .ok_or_else(|| "typedef does not target a specific data type manager".to_string())?;

        let direct_replacement = self.get_valid_replacement(typedef, enforce_size_match, dtm.as_ref());
        let direct_matches_name = direct_replacement
            .as_ref()
            .map(|r| r.get_name() == typedef.get_name())
            .unwrap_or(false);
        if direct_matches_name {
            return Ok(direct_replacement);
        }

        let ref_dt = typedef.get_data_type();
        if let Some(inner_td) = ref_dt.as_typedef() {
            let inner_replacement = self.get_typedef_replacement(inner_td, enforce_size_match)?;
            if inner_replacement.is_some() {
                // NOTE: mirrors the Java source exactly, which wraps `refDt` (the *original*
                // nested typedef) here rather than the just-computed `inner_replacement` -- an
                // apparent upstream quirk, preserved as-is.
                return Ok(Some(Box::new(TypedefDataTypePlaceholder::new(
                    typedef.get_category_path(),
                    typedef.get_name(),
                    ref_dt,
                ))));
            }
        }

        if let Some(replacement) = direct_replacement {
            if !replacement.is_equivalent(ref_dt.as_ref()) {
                return Ok(Some(Box::new(TypedefDataTypePlaceholder::new(
                    typedef.get_category_path(),
                    typedef.get_name(),
                    replacement,
                ))));
            }
        }

        Ok(None)
    }

    /// Hook returning the concrete `BuiltIn` singleton, if any, matching a normalized C primitive
    /// type name (e.g. `"unsigned int"`), standing in for a lookup against Java's
    /// `cPrimitiveNameMap`. See the module docs for why this defaults to `None`.
    fn c_primitive_data_type_for_name(&self, normalized_name: &str) -> Option<Box<dyn DataType>> {
        let _ = normalized_name;
        None
    }

    /// Hook returning the concrete `BuiltIn` typedef-replacement singleton, if any, for a typedef
    /// name (e.g. `"uint32_t"`), standing in for a lookup against Java's
    /// `cTypedefBuiltInNameRemap`. See the module docs for why this defaults to `None`.
    fn typedef_built_in_replacement_for_name(&self, name: &str) -> Option<Box<dyn DataType>> {
        let _ = name;
        None
    }

    /// Get valid typedef replacement.
    fn get_valid_replacement(
        &self,
        typedef: &dyn TypeDef,
        enforce_size_match: bool,
        dtm: &dyn DataTypeManager,
    ) -> Option<Box<dyn DataType>> {
        let mut replacement_dt = self.typedef_built_in_replacement_for_name(&typedef.get_name())?;

        if enforce_size_match {
            if replacement_dt.has_language_dependant_length() {
                replacement_dt = replacement_dt.clone_data_type(dtm);
            }
            if typedef.get_length() != replacement_dt.get_length() {
                return None;
            }
        }

        let td_dt = typedef.get_base_data_type();

        if replacement_dt.is_integer_type() {
            if td_dt.is_integer_type()
                && replacement_dt.is_signed_integer_type() == td_dt.is_signed_integer_type()
            {
                return Some(replacement_dt.clone_data_type(dtm));
            }
            return None;
        }

        Some(replacement_dt.clone_data_type(dtm))
    }

    /// Returns every datatype directly or indirectly contained within `root_data_type`,
    /// including `root_data_type` itself.
    fn get_contained_data_types(&self, root_data_type: Box<dyn DataType>) -> Vec<Box<dyn DataType>> {
        let mut seen: HashSet<String> = HashSet::new();
        let mut result: Vec<Box<dyn DataType>> = Vec::new();
        let mut queue: VecDeque<Box<dyn DataType>> = VecDeque::new();

        seen.insert(root_data_type.get_path_name());
        queue.push_back(root_data_type);

        while let Some(dt) = queue.pop_front() {
            for contained_dt in get_direct_contained_data_types(dt.as_ref()) {
                if seen.insert(contained_dt.get_path_name()) {
                    queue.push_back(contained_dt);
                }
            }
            result.push(dt);
        }
        result
    }

    /// Check to see if the second data type is the same as the first data type or is part of it.
    ///
    /// Note: pointers to the second data type are references and therefore are not considered to
    /// be part of the first and won't cause `true` to be returned. If you pass a pointer for the
    /// first or second parameter, it will return `false`.
    fn is_second_part_of_first(&self, first_data_type: &dyn DataType, second_data_type: &dyn DataType) -> bool {
        if first_data_type.is_pointer() || second_data_type.is_pointer() {
            return false;
        }
        if first_data_type.get_data_type_path() == second_data_type.get_data_type_path() {
            return true;
        }
        if let Some(array) = first_data_type.as_array() {
            let element = array.get_data_type();
            return self.is_second_part_of_first(element.as_ref(), second_data_type);
        }
        if let Some(typedef) = first_data_type.as_typedef() {
            let inner = typedef.get_data_type();
            return self.is_second_part_of_first(inner.as_ref(), second_data_type);
        }
        if let Some(composite) = first_data_type.as_composite() {
            for dtc in composite.get_defined_components() {
                let dt_to_check = dtc.get_data_type();
                if self.is_second_part_of_first(dt_to_check.as_ref(), second_data_type) {
                    return true;
                }
            }
        }
        false
    }

    /// This method returns an error if the indicated component data type is an ancestor of the
    /// specified `data_type` (i.e., the specified component data type has a component or
    /// sub-component containing the specified `data_type`).
    ///
    /// # Errors
    /// Returns [`DataTypeDependencyException`] if the ancestry check fails.
    fn check_ancestry(
        &self,
        data_type: &dyn DataType,
        component_data_type: &dyn DataType,
    ) -> Result<(), DataTypeDependencyException> {
        if self.is_second_part_of_first(component_data_type, data_type) {
            return Err(DataTypeDependencyException::with_message(format!(
                "Data type {} has {} within it.",
                component_data_type.get_display_name(),
                data_type.get_display_name()
            )));
        }
        Ok(())
    }

    /// Check if the specified replacement data type pair is invalid.
    ///
    /// # Errors
    /// Returns `Err` if an invalid replaced/replacement data type pair is specified, mirroring
    /// the `IllegalArgumentException` thrown by the Java source.
    fn check_valid_replacement(&self, replaced_dt: &dyn DataType, replacement_dt: &dyn DataType) -> Result<(), String> {
        self.check_valid_replacement_data_type(replaced_dt)?;
        self.check_valid_replacement_data_type(replacement_dt)?;
        self.check_for_invalid_function_definition_replacement(replaced_dt, replacement_dt)
    }

    /// Validate the replacement data type. Certain data types are not permitted to participate in
    /// a replacement including a Factory datatype, a Dynamic datatype, or a bitfield.
    ///
    /// # Errors
    /// Returns `Err` if an invalid datatype is specified.
    fn check_valid_replacement_data_type(&self, data_type: &dyn DataType) -> Result<(), String> {
        if data_type.is_void_type() {
            return Err(
                "IllegalArgumentException: Replacement data type may not be 'void' data type".to_string(),
            );
        }
        if data_type.is_default_data_type() {
            return Err(
                "IllegalArgumentException: Replacement data type may not be 'default' undefined data type"
                    .to_string(),
            );
        }
        if data_type.is_bit_field_type() {
            return Err(format!(
                "IllegalArgumentException: Replacement data type may not be a bitfield: {}",
                data_type.get_name()
            ));
        }
        if data_type.is_factory_type() {
            return Err(format!(
                "IllegalArgumentException: Replacement data type may not be a Factory data type: {}",
                data_type.get_name()
            ));
        }
        if data_type.is_dynamic_type() {
            return Err(format!(
                "IllegalArgumentException: Replacement data type may not be a Dynamic data type: {}",
                data_type.get_name()
            ));
        }
        Ok(())
    }

    /// Determine if the replacement data type pair represents an invalid function definition
    /// replacement.
    ///
    /// # Errors
    /// Returns `Err` if an invalid replaced/replacement data type pair is specified.
    fn check_for_invalid_function_definition_replacement(
        &self,
        replaced_dt: &dyn DataType,
        replacement_dt: &dyn DataType,
    ) -> Result<(), String> {
        let replaced_base: Box<dyn DataType>;
        let replaced_base_dt: &dyn DataType = match replaced_dt.as_typedef() {
            Some(td) => {
                replaced_base = td.get_base_data_type();
                replaced_base.as_ref()
            }
            None => replaced_dt,
        };

        let replacement_base: Box<dyn DataType>;
        let replacement_base_dt: &dyn DataType = match replacement_dt.as_typedef() {
            Some(td) => {
                replacement_base = td.get_base_data_type();
                replacement_base.as_ref()
            }
            None => replacement_dt,
        };

        if replaced_base_dt.is_function_definition_type() {
            if !replacement_base_dt.is_function_definition_type() {
                return Err(format!(
                    "IllegalArgumentException: Existing function definition \"{}\" may not be replaced with \"{}\"",
                    replaced_dt.get_name(),
                    replacement_dt.get_name()
                ));
            }
        } else if replacement_base_dt.is_function_definition_type() {
            return Err(format!(
                "IllegalArgumentException: Existing data type \"{}\" may not be replaced with function definition \"{}\"",
                replaced_dt.get_name(),
                replacement_dt.get_name()
            ));
        }
        Ok(())
    }

    /// Returns `true` if the two dataTypes have the same source archive and the same universal
    /// ID.
    fn is_same_data_type(&self, data_type1: &dyn DataType, data_type2: &dyn DataType) -> bool {
        let id1 = data_type1.get_universal_id();
        let id2 = data_type2.get_universal_id();
        // A zero-valued `UniversalID` stands in for Java's `null`; see
        // `DataTypeArchiveIdDumper`'s module docs for the established convention.
        if id1.value() == 0 || id2.value() == 0 || id1 != id2 {
            return false;
        }
        let archive1 = data_type1.get_source_archive();
        let archive2 = data_type2.get_source_archive();
        match (archive1, archive2) {
            (Some(a1), Some(a2)) => a1.source_archive_id() == a2.source_archive_id(),
            _ => false,
        }
    }

    /// Returns `true` if two dataTypes have the same source archive and the same universal ID, OR
    /// are equivalent.
    fn is_same_or_equivalent_data_type(&self, data_type1: &dyn DataType, data_type2: &dyn DataType) -> bool {
        if self.is_same_data_type(data_type1, data_type2) {
            return true;
        }
        data_type1.is_equivalent(data_type2)
    }

    /// Determine if two dataTypes are the same kind of datatype without considering naming or
    /// component makeup. The use of Typedefs is ignored and stripped away for comparison.
    fn is_same_kind_data_type(&self, data_type1: &dyn DataType, data_type2: &dyn DataType) -> bool {
        is_same_kind_data_type_impl(data_type1, data_type2)
    }

    /// Get the base data type for the specified data type stripping away pointers and arrays
    /// only.
    ///
    /// Returns `None` for a default pointer.
    fn get_base_data_type(&self, dt: Box<dyn DataType>) -> Option<Box<dyn DataType>> {
        let mut current = dt;
        loop {
            let next = if let Some(ptr) = current.as_pointer() {
                ptr.get_data_type()
            } else if let Some(arr) = current.as_array() {
                Some(arr.get_data_type())
            } else {
                return Some(current);
            };
            match next {
                Some(inner) => current = inner,
                None => return None,
            }
        }
    }

    /// Get the innermost (non-array) element data type of an array, following nested arrays.
    fn get_array_base_data_type(&self, array_dt: &dyn Array) -> Box<dyn DataType> {
        let dt = array_dt.get_data_type();
        if dt.as_array().is_some() {
            let nested = dt.into_array().expect("as_array() confirmed this is an array");
            self.get_array_base_data_type(nested.as_ref())
        } else {
            dt
        }
    }

    /// Get the array's displayed name, following nested arrays and appending dimensions.
    fn get_array_name(&self, array_dt: &dyn Array, show_base_size_for_dynamics: bool) -> String {
        let mut buf = self.get_array_base_data_type(array_dt).get_name();
        if show_base_size_for_dynamics {
            buf.push_str(&array_element_length_for_dynamic(array_dt));
        }
        buf.push_str(&array_dimensions(array_dt));
        buf
    }

    /// Get the array's display name, following nested arrays and appending dimensions.
    fn get_array_display_name(&self, array_dt: &dyn Array, show_base_size_for_dynamics: bool) -> String {
        let mut buf = self.get_array_base_data_type(array_dt).get_display_name();
        if show_base_size_for_dynamics {
            buf.push_str(&array_element_length_for_dynamic(array_dt));
        }
        buf.push_str(&array_dimensions(array_dt));
        buf
    }

    /// Get the array's mnemonic, following nested arrays and appending dimensions.
    fn get_array_mnemonic(
        &self,
        array_dt: &dyn Array,
        show_base_size_for_dynamics: bool,
        settings: &dyn Settings,
    ) -> String {
        let mut buf = self.get_array_base_data_type(array_dt).get_mnemonic(settings);
        if show_base_size_for_dynamics {
            buf.push_str(&array_element_length_for_dynamic(array_dt));
        }
        buf.push_str(&array_dimensions(array_dt));
        buf
    }

    /// Create a data type category path derived from the specified namespace and rooted from the
    /// specified `base_category`.
    fn get_data_type_category_path(&self, base_category: &CategoryPath, namespace: Option<&dyn Namespace>) -> CategoryPath {
        data_type_category_path(base_category, namespace)
    }

    /// Find the structure data type which corresponds to the specified class namespace within
    /// the specified data type manager.
    ///
    /// The structure must utilize a namespace-based category path, however the match criteria can
    /// be fuzzy and relies primarily on the full class namespace. Returns the found datatype as
    /// an opaque `DataType`; callers should check [`DataType::is_structure`] (see the module docs
    /// for why this diverges from the Java `Structure` return type).
    fn find_existing_class_struct(
        &self,
        dtm: &dyn DataTypeManager,
        class_namespace: &dyn GhidraClass,
    ) -> Option<Box<dyn DataType>> {
        let is_structure: &dyn Fn(&dyn DataType) -> bool = &|dt| dt.is_structure();
        let name = class_namespace.get_name();

        if let Some(dt) = find_preferred_data_type(dtm, Some(class_namespace), &name, Some(is_structure), true) {
            return Some(dt);
        }

        let namespace_paths = get_relative_category_paths(Some(class_namespace));
        find_data_type_matching(dtm, &name, Some(is_structure), |cp| {
            category_match_type_for_paths(cp, namespace_paths.as_ref(), true)
        })
    }

    /// Attempt to find the data type whose name and specified namespace match a stored data type
    /// within the specified `dtm`. `class_constraint`, if given, filters candidates (standing in
    /// for Java's `Class<T> classConstraint`; see the module docs).
    fn find_data_type(
        &self,
        dtm: &dyn DataTypeManager,
        namespace: Option<&dyn Namespace>,
        dt_name: &str,
        class_constraint: Option<&dyn Fn(&dyn DataType) -> bool>,
    ) -> Option<Box<dyn DataType>> {
        if let Some(dt) = find_preferred_data_type(dtm, namespace, dt_name, class_constraint, false) {
            return Some(dt);
        }
        let namespace_paths = get_relative_category_paths(namespace);
        find_data_type_matching(dtm, dt_name, class_constraint, |cp| {
            category_match_type_for_paths(cp, namespace_paths.as_ref(), false)
        })
    }

    /// Attempt to find the data type whose `dt_name_with_namespace` matches a stored data type
    /// within the specified `dtm`. The namespace will be used in checking data type parent
    /// categories.
    ///
    /// NOTE: name parsing assumes `::` namespace delimiters, which can be thrown off if the name
    /// includes template information which could itself contain namespaces.
    ///
    /// # Errors
    /// Returns `Err` if `dt_name_with_namespace` cannot be parsed as a symbol path.
    fn find_namespace_qualified_data_type(
        &self,
        dtm: &dyn DataTypeManager,
        dt_name_with_namespace: &str,
        class_constraint: Option<&dyn Fn(&dyn DataType) -> bool>,
    ) -> Result<Option<Box<dyn DataType>>, SymbolPathError> {
        let path_list = SymbolPathNode::parse(dt_name_with_namespace)?.as_list();
        let name_index = path_list.len() - 1;
        let dt_name = &path_list[name_index];

        if let Some(root_path) = preferred_root_namespace_category_path(dtm) {
            let namespace_path = &path_list[..name_index];
            if let Some(dt) = assignable_data_type(dtm, &root_path, Some(namespace_path), dt_name, class_constraint) {
                return Ok(Some(dt));
            }
        }

        let mut namespace_path = String::new();
        for part in &path_list[..name_index] {
            namespace_path.push_str(DELIMITER_STRING);
            namespace_path.push_str(part);
        }

        Ok(find_data_type_matching(dtm, dt_name, class_constraint, |cp| {
            category_match_type_for_namespace_path(cp, &namespace_path)
        }))
    }

    /// Return the appropriate datatype for a given C primitive datatype name (e.g. `"unsigned
    /// int"`, `"long long"`).
    fn get_c_primitive_data_type(&self, data_type_name: &str) -> Option<Box<dyn DataType>> {
        let mut name = data_type_name.to_string();
        if name.contains(' ') {
            name = name.trim().split_whitespace().collect::<Vec<_>>().join(" ");
        }
        let name = name.to_lowercase();
        self.c_primitive_data_type_for_name(&name)
    }

    /// Get the name of a data type with all conflict naming patterns removed, optionally
    /// including its category path.
    fn get_name_without_conflict(&self, data_type: &dyn DataType, include_category_path: bool) -> String {
        let name = self.get_name_without_conflict_for_type(data_type);
        if include_category_path {
            data_type.get_category_path().get_path_for_child(&name).unwrap_or(name)
        } else {
            name
        }
    }

    /// Get the name of a data type name string with all conflict naming patterns removed.
    fn get_name_without_conflict_for_name(&self, data_type_name: &str) -> String {
        let decorations = pointer_array_decorations(data_type_name);
        let base = match decorations {
            Some(d) => &data_type_name[..data_type_name.len() - d.len()],
            None => data_type_name,
        };
        let name = BASE_DATATYPE_CONFLICT_PATTERN.replace_all(base, "");
        match decorations {
            Some(d) => format!("{name}{d}"),
            None => name.into_owned(),
        }
    }

    /// Get a datatype's name without its conflict suffix.
    fn get_name_without_conflict_for_type(&self, dt: &dyn DataType) -> String {
        let dt_name = dt.get_name();
        if !can_have_conflict_name(Some(dt)) {
            return dt_name; // e.g., many BuiltIn types
        }
        if !dt.is_pointer() && !dt.is_array() {
            return BASE_DATATYPE_CONFLICT_PATTERN.replace_all(&dt_name, "").into_owned();
        }
        let Some(base) = base_data_type_from_ref(dt) else {
            return dt_name; // e.g., default pointer
        };
        if !can_have_conflict_name(Some(base.as_ref())) {
            return dt_name; // e.g., pointer to BuiltIn
        }
        let base_name = base.get_name();
        let decorations = &dt_name[base_name.len()..];
        let cleaned = BASE_DATATYPE_CONFLICT_PATTERN.replace_all(&base_name, "");
        format!("{cleaned}{decorations}")
    }

    /// Get the conflict value associated with a conflict datatype.
    ///
    /// Returns `-1` when the type does not have a conflict name, `0` when the conflict name does
    /// not have a number (i.e. `.conflict`), or a positive value corresponding to the conflict
    /// number in the name (e.g. `2` for `.conflict2`).
    fn get_conflict_value(&self, data_type: &dyn DataType) -> i32 {
        if !can_have_conflict_name(Some(data_type)) {
            return -1;
        }
        if !data_type.is_pointer() && !data_type.is_array() {
            return base_conflict_value(&data_type.get_name());
        }
        let Some(base) = base_data_type_from_ref(data_type) else {
            return -1;
        };
        if !can_have_conflict_name(Some(base.as_ref())) {
            return -1;
        }
        base_conflict_value(&base.get_name())
    }

    /// Get the conflict value associated with a conflict datatype name string.
    fn get_conflict_value_for_name(&self, data_type_name: &str) -> i32 {
        let decorations = pointer_array_decorations(data_type_name);
        let base = match decorations {
            Some(d) => &data_type_name[..data_type_name.len() - d.len()],
            None => data_type_name,
        };
        base_conflict_value(base)
    }

    /// Determine if the specified data type name is a conflict name.
    fn is_conflict_data_type_name(&self, data_type_name: &str) -> bool {
        let decorations = pointer_array_decorations(data_type_name);
        let base = match decorations {
            Some(d) => &data_type_name[..data_type_name.len() - d.len()],
            None => data_type_name,
        };
        BASE_DATATYPE_CONFLICT_PATTERN.is_match(base)
    }

    /// Determine if the specified data type has a conflict name.
    fn is_conflict_data_type(&self, dt: &dyn DataType) -> bool {
        if !can_have_conflict_name(Some(dt)) {
            return false; // e.g., many BuiltIn types
        }
        let has_qualifying_base = if !dt.is_pointer() && !dt.is_array() {
            true
        } else {
            match base_data_type_from_ref(dt) {
                Some(base) => can_have_conflict_name(Some(base.as_ref())),
                None => false, // e.g., default pointer
            }
        };
        if !has_qualifying_base {
            return false;
        }
        // NOTE: matches the original name (including any pointer/array decorations), not the
        // base datatype's name -- see the module docs for why this is a preserved Java quirk.
        BASE_DATATYPE_CONFLICT_PATTERN.is_match(&dt.get_name())
    }

    /// Compares two data type name strings to determine if they are equivalent names, ignoring
    /// any conflict patterns present.
    fn equals_ignore_conflict(&self, name1: &str, name2: &str) -> bool {
        self.get_name_without_conflict_for_name(name1) == self.get_name_without_conflict_for_name(name2)
    }

    /// Returns `true` if there is a merger that can handle the given datatype. Currently only
    /// structures, unions, and enums are supported.
    fn supports_merge(&self, data_type: &dyn DataType) -> bool {
        data_type.as_composite().is_some() || data_type.as_enum().is_some()
    }

    /// Convenience method for getting the appropriate datatype merger.
    ///
    /// # Errors
    /// Returns `Err` if the two datatypes are not eligible to be merged (not the same type, or
    /// not one of structure/union/enum).
    fn get_merger(&self, dt1: &dyn DataType, dt2: &dyn DataType) -> Result<Box<dyn DataTypeMerger>, DataTypeMergeException> {
        if let Some(struct1) = dt1.as_structure() {
            if let Some(struct2) = dt2.as_structure() {
                return Ok(Box::new(StructureMergerPlaceholder::new(struct1, struct2)));
            }
            return Err(merge_error("structure", dt1, dt2));
        }
        if let Some(union1) = dt1.as_union() {
            if let Some(union2) = dt2.as_union() {
                return Ok(Box::new(UnionMergerPlaceholder::new(union1, union2)));
            }
            return Err(merge_error("union", dt1, dt2));
        }
        if let Some(enum1) = dt1.as_enum() {
            if let Some(enum2) = dt2.as_enum() {
                return Ok(Box::new(EnumMergerPlaceholder::new(enum1, enum2)));
            }
            return Err(merge_error("enum", dt1, dt2));
        }
        Err(DataTypeMergeException::new("Merge target must be one of structure, union, or enum."))
    }
}

fn merge_error(type_name: &str, merge_to_dt: &dyn DataType, selected_dt: &dyn DataType) -> DataTypeMergeException {
    DataTypeMergeException::new(format!(
        "Can't merge non-{} '{}' datatype into structure '{}' ",
        type_name,
        selected_dt.get_name(),
        merge_to_dt.get_name()
    ))
}

fn get_direct_contained_data_types(dt: &dyn DataType) -> Vec<Box<dyn DataType>> {
    if let Some(array) = dt.as_array() {
        return vec![array.get_data_type()];
    }
    if let Some(pointer) = dt.as_pointer() {
        return pointer.get_data_type().into_iter().collect();
    }
    if let Some(composite) = dt.as_composite() {
        let mut list = Vec::new();
        for i in 0..composite.get_num_components() {
            if let Ok(component) = composite.get_component(i) {
                list.push(component.get_data_type());
            }
        }
        return list;
    }
    if let Some(typedef) = dt.as_typedef() {
        return vec![typedef.get_data_type()];
    }
    if let Some(func_def) = dt.as_function_definition() {
        let mut list = vec![func_def.get_return_type()];
        for arg in func_def.get_arguments() {
            list.push(arg.get_data_type());
        }
        return list;
    }
    // Enum, BuiltInDataType, BitFieldDataType, MissingBuiltInDataType, DataType::DEFAULT, and any
    // other/unknown case are all no-ops in the Java source, except that Java throws
    // AssertException for a truly unrecognized DataType. This port treats every remaining case
    // identically -- an empty result -- trading that assertion for a safe fallback, consistent
    // with this crate's general policy (see `DataUtilities`'s module docs for the same
    // trade-off).
    Vec::new()
}

fn base_data_type_from_ref(dt: &dyn DataType) -> Option<Box<dyn DataType>> {
    let next = if let Some(ptr) = dt.as_pointer() {
        ptr.get_data_type()
    } else if let Some(arr) = dt.as_array() {
        Some(arr.get_data_type())
    } else {
        return None;
    };
    match next {
        Some(mut current) => loop {
            let next = if let Some(ptr) = current.as_pointer() {
                ptr.get_data_type()
            } else if let Some(arr) = current.as_array() {
                Some(arr.get_data_type())
            } else {
                return Some(current);
            };
            match next {
                Some(inner) => current = inner,
                None => return None,
            }
        },
        None => None,
    }
}

fn array_base_element_length(array_dt: &dyn Array) -> i32 {
    let dt = array_dt.get_data_type();
    if dt.as_array().is_some() {
        let nested = dt.into_array().expect("as_array() confirmed this is an array");
        array_base_element_length(nested.as_ref())
    } else {
        array_dt.get_element_length()
    }
}

fn array_element_length_for_dynamic(array_dt: &dyn Array) -> String {
    if get_array_base_length(array_dt) <= 0 {
        format!(" {{{}}} ", array_base_element_length(array_dt))
    } else {
        String::new()
    }
}

fn get_array_base_length(array_dt: &dyn Array) -> i32 {
    let dt = array_dt.get_data_type();
    if dt.as_array().is_some() {
        let nested = dt.into_array().expect("as_array() confirmed this is an array");
        get_array_base_length(nested.as_ref())
    } else {
        dt.get_length()
    }
}

fn array_dimensions(array_dt: &dyn Array) -> String {
    let mut s = format!("[{}]", array_dt.get_num_elements());
    let dt = array_dt.get_data_type();
    if dt.as_array().is_some() {
        let nested = dt.into_array().expect("as_array() confirmed this is an array");
        s.push_str(&array_dimensions(nested.as_ref()));
    }
    s
}

/// Faithful port of `DataTypeUtilities.isSameKindDataType`'s recursive walk. See the module docs
/// for the identity-comparison and `Array`-branch-typo divergences.
fn is_same_kind_data_type_impl(dt1: &dyn DataType, dt2: &dyn DataType) -> bool {
    if dt1.is_equivalent(dt2) || dt2.is_equivalent(dt1) {
        return true;
    }

    let base1: Box<dyn DataType>;
    let dt1 = match dt1.as_typedef() {
        Some(td) => {
            base1 = td.get_base_data_type();
            base1.as_ref()
        }
        None => dt1,
    };
    let base2: Box<dyn DataType>;
    let dt2 = match dt2.as_typedef() {
        Some(td) => {
            base2 = td.get_base_data_type();
            base2.as_ref()
        }
        None => dt2,
    };

    if let (Some(p1), Some(p2)) = (dt1.as_pointer(), dt2.as_pointer()) {
        return match (p1.get_data_type(), p2.get_data_type()) {
            (Some(a), Some(b)) => is_same_kind_data_type_impl(a.as_ref(), b.as_ref()),
            (None, None) => true,
            _ => false,
        };
    }

    // Faithful reproduction of the upstream typo: both `a1`/`a2` come from `dt2`, never `dt1`.
    if let (Some(a1), Some(a2)) = (dt2.as_array(), dt2.as_array()) {
        return is_same_kind_data_type_impl(a1.get_data_type().as_ref(), a2.get_data_type().as_ref());
    }

    if dt1.as_enum().is_some() {
        return dt2.as_enum().is_some();
    }
    if dt1.is_structure() {
        return dt2.is_structure();
    }
    if dt1.is_union() {
        return dt2.is_union();
    }
    if dt1.as_built_in_data_type().is_some() {
        return is_same_kind_built_in_data_type(dt1, dt2);
    }
    false
}

fn is_same_kind_built_in_data_type(dt1: &dyn DataType, dt2: &dyn DataType) -> bool {
    if dt1.as_built_in().is_some() {
        if dt1.is_integer_type() {
            return dt2.is_integer_type();
        }
        if dt1.is_floating_point() {
            return dt2.is_floating_point();
        }
        return dt1.get_name() == dt2.get_name();
    }
    dt1.get_name() == dt2.get_name()
}

fn can_have_conflict_name(dt: Option<&dyn DataType>) -> bool {
    let Some(dt) = dt else { return false };
    dt.as_built_in().is_none() || dt.is_pointer()
}

fn pointer_array_decorations(data_type_name: &str) -> Option<&str> {
    if !data_type_name.contains('*') && !data_type_name.contains('[') {
        return None;
    }
    let m = DATATYPE_POINTER_ARRAY_PATTERN.find(data_type_name)?;
    Some(&data_type_name[m.start()..])
}

fn base_conflict_value(base_data_type_name: &str) -> i32 {
    let Some(m) = BASE_DATATYPE_CONFLICT_PATTERN.find(base_data_type_name) else {
        return -1;
    };
    let mut start_ix = m.start() + CONFLICT_SUFFIX.len();
    let bytes = base_data_type_name.as_bytes();
    if start_ix < base_data_type_name.len() && bytes[start_ix] == b'_' {
        start_ix += 1;
    }
    let value_str = &base_data_type_name[start_ix..];
    if value_str.is_empty() {
        return 0;
    }
    value_str.parse::<i32>().unwrap_or(-1)
}

fn data_type_category_path<N: Namespace + ?Sized>(base_category: &CategoryPath, namespace: Option<&N>) -> CategoryPath {
    let Some(namespace) = namespace else {
        return base_category.clone();
    };
    if namespace.is_global() {
        return base_category.clone();
    }

    // Collect innermost-first (namespace, its parent, grandparent, ...), stopping before the
    // global namespace, then reverse to outermost-first -- matching
    // `NamespaceUtils.getNamespaceParts(Namespace)`.
    let mut is_library = vec![namespace.as_library().is_some()];
    let mut names = vec![namespace.get_name()];
    let mut current = namespace.get_parent_namespace();
    while let Some(n) = current {
        if n.is_global() {
            break;
        }
        is_library.push(n.as_library().is_some());
        names.push(n.get_name());
        current = n.get_parent_namespace();
    }
    names.reverse();
    is_library.reverse();

    let mut parts: Vec<String> = Vec::new();
    for (name, lib) in names.into_iter().zip(is_library) {
        // Assume a Library is a root and no other categories are above it.
        if lib {
            break;
        }
        parts.push(name);
    }

    let refs: Vec<&str> = parts.iter().map(String::as_str).collect();
    base_category.extend(&refs)
}

/// Relative category paths corresponding to a namespace, matching
/// `DataTypeUtilities.getRelativeCategoryPaths(Namespace)`'s two-element return array.
struct RelativeCategoryPaths {
    namespace_path: String,
    parent_namespace_path: String,
}

fn get_relative_category_paths<N: Namespace + ?Sized>(namespace: Option<&N>) -> Option<RelativeCategoryPaths> {
    let namespace = namespace?;
    if namespace.is_global() || namespace.as_library().is_some() {
        return None;
    }
    let mut parent_namespace_path = String::new();
    if let Some(parent) = namespace.get_parent_namespace() {
        for n in parent.get_path_list(true) {
            parent_namespace_path.push_str(DELIMITER_STRING);
            parent_namespace_path.push_str(&CategoryPath::escape_string(&n));
        }
    }
    let mut namespace_path = parent_namespace_path.clone();
    namespace_path.push_str(DELIMITER_STRING);
    namespace_path.push_str(&CategoryPath::escape_string(&namespace.get_name()));
    Some(RelativeCategoryPaths { namespace_path, parent_namespace_path })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CategoryMatchType {
    None,
    Secondary,
    Preferred,
}

fn category_match_type_for_namespace_path(category_path: &CategoryPath, namespace_path: &str) -> CategoryMatchType {
    if namespace_path.is_empty() {
        return if category_path.is_root() {
            CategoryMatchType::Preferred
        } else {
            CategoryMatchType::Secondary
        };
    }
    let path = category_path.get_path();
    if path.ends_with(namespace_path) {
        CategoryMatchType::Preferred
    } else {
        CategoryMatchType::None
    }
}

fn category_match_type_for_paths(
    category_path: &CategoryPath,
    namespace_paths: Option<&RelativeCategoryPaths>,
    parent_namespace_preferred: bool,
) -> CategoryMatchType {
    let Some(paths) = namespace_paths else {
        return if category_path.is_root() {
            CategoryMatchType::Preferred
        } else {
            CategoryMatchType::Secondary
        };
    };

    let path = category_path.get_path();
    if parent_namespace_preferred && path.ends_with(&paths.parent_namespace_path) {
        return CategoryMatchType::Preferred;
    }
    if path.ends_with(&paths.namespace_path) {
        return if parent_namespace_preferred {
            CategoryMatchType::Secondary
        } else {
            CategoryMatchType::Preferred
        };
    }
    CategoryMatchType::None
}

fn assignable_data_type_in_category(
    category: &dyn Category,
    dt_name: &str,
    class_constraint: Option<&dyn Fn(&dyn DataType) -> bool>,
) -> Option<Box<dyn DataType>> {
    let dt = category.get_data_type(dt_name)?;
    match class_constraint {
        Some(pred) if !pred(dt.as_ref()) => None,
        _ => Some(dt),
    }
}

fn assignable_data_type(
    dtm: &dyn DataTypeManager,
    root_path: &CategoryPath,
    namespace_path: Option<&[String]>,
    dt_name: &str,
    class_constraint: Option<&dyn Fn(&dyn DataType) -> bool>,
) -> Option<Box<dyn DataType>> {
    let category = dtm.get_category_at_path(root_path)?;
    let namespace_path = namespace_path.filter(|p| !p.is_empty());
    let Some(namespace_path) = namespace_path else {
        return assignable_data_type_in_category(category.as_ref(), dt_name, class_constraint);
    };
    let refs: Vec<&str> = namespace_path.iter().map(String::as_str).collect();
    let category_path = root_path.extend(&refs);
    let category = dtm.get_category_at_path(&category_path)?;
    assignable_data_type_in_category(category.as_ref(), dt_name, class_constraint)
}

fn preferred_root_namespace_category_path(dtm: &dyn DataTypeManager) -> Option<CategoryPath> {
    let program_based = dtm.as_program_based()?;
    Some(program_based.get_program().get_preferred_root_namespace_category_path())
}

fn find_preferred_data_type<N: Namespace + ?Sized>(
    dtm: &dyn DataTypeManager,
    namespace: Option<&N>,
    dt_name: &str,
    class_constraint: Option<&dyn Fn(&dyn DataType) -> bool>,
    parent_namespace_preferred: bool,
) -> Option<Box<dyn DataType>> {
    let root_path = preferred_root_namespace_category_path(dtm)?;

    let use_root_only = match namespace {
        None => true,
        Some(n) => n.is_global() || n.as_library().is_some(),
    };
    if use_root_only {
        return assignable_data_type(dtm, &root_path, None, dt_name, class_constraint);
    }
    let namespace = namespace.expect("use_root_only is false only when namespace is Some");

    if parent_namespace_preferred {
        if let Some(parent) = namespace.get_parent_namespace() {
            let path = parent.get_path_list(true);
            if let Some(dt) = assignable_data_type(dtm, &root_path, Some(&path), dt_name, class_constraint) {
                return Some(dt);
            }
        }
    }

    let path = namespace.get_path_list(true);
    assignable_data_type(dtm, &root_path, Some(&path), dt_name, class_constraint)
}

fn find_data_type_matching(
    dtm: &dyn DataTypeManager,
    dt_name: &str,
    class_constraint: Option<&dyn Fn(&dyn DataType) -> bool>,
    category_matcher: impl Fn(&CategoryPath) -> CategoryMatchType,
) -> Option<Box<dyn DataType>> {
    let mut list: Vec<Box<dyn DataType>> = Vec::new();
    dtm.find_data_types(dt_name, &mut list);
    list.sort_by(|a, b| {
        let pa = a.get_category_path().get_path();
        let pb = b.get_category_path().get_path();
        pa.len().cmp(&pb.len()).then_with(|| pa.cmp(&pb))
    });

    let mut secondary: Option<Box<dyn DataType>> = None;
    for dt in list {
        if let Some(pred) = class_constraint {
            if !pred(dt.as_ref()) {
                continue;
            }
        }
        match category_matcher(&dt.get_category_path()) {
            CategoryMatchType::Preferred => return Some(dt),
            CategoryMatchType::Secondary if secondary.is_none() => secondary = Some(dt),
            _ => {}
        }
    }
    secondary
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::data::composite::Composite;
    use crate::program::model::data::data_type_component::DataTypeComponent;

    struct Marker;
    impl DataTypeUtilities for Marker {}

    #[derive(Clone)]
    struct LeafDataType {
        name: String,
    }

    impl DataType for LeafDataType {
        fn get_name(&self) -> String {
            self.name.clone()
        }
    }

    struct MockComponent {
        data_type: LeafDataType,
    }

    impl DataTypeComponent for MockComponent {
        fn get_data_type(&self) -> Box<dyn DataType> {
            Box::new(self.data_type.clone())
        }
    }

    struct MockComposite {
        components: Vec<LeafDataType>,
    }

    impl DataType for MockComposite {
        fn get_name(&self) -> String {
            "MockStruct".to_string()
        }

        fn as_composite(&self) -> Option<&dyn Composite> {
            Some(self)
        }
    }

    impl Composite for MockComposite {
        fn get_num_defined_components(&self) -> i32 {
            self.components.len() as i32
        }

        fn get_defined_components(&self) -> Vec<Box<dyn DataTypeComponent>> {
            self.components
                .iter()
                .cloned()
                .map(|dt| Box::new(MockComponent { data_type: dt }) as Box<dyn DataTypeComponent>)
                .collect()
        }
    }

    #[test]
    fn is_second_part_of_first_finds_nested_component() {
        let util: Box<dyn DataTypeUtilities> = Box::new(Marker);
        let target = LeafDataType { name: "int".into() };
        let other = LeafDataType { name: "float".into() };
        let composite = MockComposite { components: vec![other, target.clone()] };

        assert!(util.is_second_part_of_first(&composite, &target));
        assert!(!util.is_second_part_of_first(&composite, &LeafDataType { name: "double".into() }));
    }

    #[test]
    fn strips_conflict_suffix_preserving_pointer_decoration() {
        let util = Marker;
        assert_eq!(util.get_name_without_conflict_for_name("Foo.conflict3 *32"), "Foo *32");
        assert_eq!(util.get_name_without_conflict_for_name("Foo.conflict"), "Foo");
        assert_eq!(util.get_name_without_conflict_for_name("Bar"), "Bar");
    }

    #[test]
    fn equals_ignore_conflict_normalizes_both_sides() {
        let util = Marker;
        assert!(util.equals_ignore_conflict("Foo.conflict", "Foo.conflict2"));
        assert!(!util.equals_ignore_conflict("Foo.conflict", "Bar.conflict"));
    }

    #[test]
    fn conflict_value_parses_trailing_number() {
        let util = Marker;
        assert_eq!(util.get_conflict_value_for_name("Foo.conflict2"), 2);
        assert_eq!(util.get_conflict_value_for_name("Foo.conflict"), 0);
        assert_eq!(util.get_conflict_value_for_name("Foo"), -1);
    }

    #[test]
    fn is_conflict_data_type_name_detects_suffix() {
        let util = Marker;
        assert!(util.is_conflict_data_type_name("Foo.conflict"));
        assert!(util.is_conflict_data_type_name("Foo.conflict12"));
        assert!(!util.is_conflict_data_type_name("Foo"));
    }
}

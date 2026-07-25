//! Port of `ghidra.program.database.data.CompositeDB` as a trait (cycle cut-point).
//!
//! The Java class is a package-private, abstract `extends DataTypeDB implements
//! CompositeInternal` providing the shared database-backed behavior for `StructureDB` and
//! `UnionDB`. `DataTypeDB` is not yet ported, so -- mirroring the sibling non-DB port
//! [`CompositeDataTypeImpl`](crate::program::model::data::composite_data_type_impl::CompositeDataTypeImpl)'s
//! convention of extending only the already-ported interfaces its unported superclass
//! implements -- this trait extends [`CompositeInternal`] directly (which already pulls in
//! [`Composite`] and [`DataType`]).
//!
//! Most of `CompositeDB`'s public surface either delegates straight through to a supertrait
//! default that already exists (`DataType::get_description`/`DataType::set_description`,
//! `getAlignedLength`/`getUniversalID`/`setUniversalID`/`getLastChangeTime*`/
//! `setLastChangeTime*`, [`Composite::is_part_of`]) or is functionally identical to a method
//! [`CompositeDataTypeImpl`](crate::program::model::data::composite_data_type_impl::CompositeDataTypeImpl)
//! already ported for the non-DB sibling class (`isPartOf` via `DataTypeUtilities.isSecondPartOfFirst`),
//! so none of that is repeated here.
//!
//! `getAlignment()`, `hasLanguageDependantLength()`, and `repack(boolean, boolean)` collide by
//! name with an existing same-shaped default already declared on [`DataType`]/[`Composite`]
//! (`get_alignment`, `has_language_dependant_length`, `repack`). Rust does not allow a subtrait
//! to override a supertrait's same-named default without creating an ambiguous (or, worse,
//! silently-shadowed) call site, so -- mirroring
//! [`CompositeDataTypeImpl`](crate::program::model::data::composite_data_type_impl::CompositeDataTypeImpl)'s
//! `composite_impl_*` convention -- those three are exposed here under distinct
//! `composite_db_*` names instead.
//!
//! What *is* ported here, as real default-bodied trait methods:
//!   - [`CompositeDb::get_non_packed_alignment`] -- port of the protected final
//!     `CompositeDB.getNonPackedAlignment()`.
//!   - [`CompositeDb::validate_data_type`] -- port of the protected
//!     `CompositeDB.validateDataType(DataType)`. Unlike
//!     [`CompositeDataTypeImpl::composite_impl_validate_data_type`](crate::program::model::data::composite_data_type_impl::CompositeDataTypeImpl::composite_impl_validate_data_type)
//!     (left required there because `DataType` exposed no `instanceof Dynamic`/`FactoryDataType`
//!     hook at the time), this port takes advantage of the [`DataType::is_dynamic_type`]/
//!     [`DataType::is_factory_type`] instanceof stand-ins that now exist, and takes
//!     `Dynamic.canSpecifyLength()`'s result as an explicit `dynamic_can_specify_length`
//!     parameter (only consulted when `data_type.is_dynamic_type()` is true) since `Dynamic`
//!     itself still has no generic downcast hook. The `Undefined1DataType.dataType` singleton
//!     substituted for `DataType.DEFAULT` is likewise supplied by the caller as
//!     `default_replacement`, since `Undefined1DataType` is not yet ported.
//!   - [`CompositeDb::get_preferred_component_length`] /
//!     [`CompositeDb::get_preferred_component_length_default`] -- port of the two
//!     `CompositeDB.getPreferredComponentLength` overloads. The Java bodies are identical to
//!     [`CompositeDataTypeImpl::composite_impl_preferred_component_length`](crate::program::model::data::composite_data_type_impl::CompositeDataTypeImpl::composite_impl_preferred_component_length)'s
//!     up to the shared tail call into the static `DataTypeComponentImpl.getPreferredComponentLength`,
//!     so this port reuses that same already-ported tail-call helper
//!     ([`preferred_component_length_for_data_type`](crate::program::model::data::composite_data_type_impl::preferred_component_length_for_data_type))
//!     rather than re-implementing it, and takes the same `is_dynamic_with_specifiable_length`
//!     boolean stand-in for `(dataType instanceof Dynamic dynamic) && dynamic.canSpecifyLength()`.
//!
//! What stays a *required* (non-defaulted) trait method, because `CompositeDB` itself declares
//! it `abstract` (implemented by `StructureDB`/`UnionDB`):
//!   - [`CompositeDb::composite_db_has_language_dependant_length`] -- `hasLanguageDependantLength()`.
//!   - [`CompositeDb::get_computed_alignment`] -- `getComputedAlignment(boolean)`.
//!   - [`CompositeDb::composite_db_repack`] -- `repack(boolean, boolean)`.
//!   - [`CompositeDb::fixup_components`] -- `fixupComponents()`, which throws `IOException` in
//!     Java, hence the `io::Result` return here.
//!   - [`CompositeDb::for_each_defined_component`] -- the package-private abstract
//!     `forEachDefinedComponent(Consumer<DataTypeComponentDB>)`, using `&dyn DataTypeComponent`
//!     in place of the unported concrete `DataTypeComponentDB`, matching
//!     [`CompositeDataTypeImpl::for_each_defined_component`](crate::program::model::data::composite_data_type_impl::CompositeDataTypeImpl::for_each_defined_component)'s
//!     equivalent treatment.
//!
//! `getAlignment()` is ported as [`CompositeDb::composite_db_get_alignment`] with a simplified body --
//! `self.get_computed_alignment(false)` -- rather than the real
//! `getComputedAlignment(refreshIfNeeded() && dataMgr.isTransactionActive())`: the lock/refresh/
//! transaction-state plumbing belongs to the not-yet-ported `DataTypeDB`/`DataTypeManagerDB`
//! pair, and is out of scope for this cycle-cut (the already-ported
//! [`StructureDb`](super::structure_db::StructureDb) took the same "leave the not-yet-ported
//! DB plumbing out, capture the reusable algorithm" approach for its own `refresh`/manager
//! backreference).
//!
//! `createComponent`, `setFieldName`, `setComment`, `doCheckedResolve`, `updateBitFieldDataType`,
//! `postPointerResolve`, `doSetPackingAndAlignment`, and the `do*Record` family all construct or
//! mutate a concrete `DataTypeComponentDB`/`DBRecord` via `compositeAdapter`/`componentAdapter`/
//! `dataMgr` in ways that need real per-instance record/adapter storage this trait does not yet
//! prescribe (mirroring how `StructureDb` deferred the equivalent DB-record plumbing); they are
//! left for a future port once `DataTypeDB` itself (or a fuller `CompositeDb` accessor contract)
//! is in place, rather than being modeled here as more placeholder stubs.

use std::io;

use crate::program::model::data::composite_data_type_impl::preferred_component_length_for_data_type;
use crate::program::model::data::composite_internal::{
    CompositeInternal, DEFAULT_ALIGNMENT, MACHINE_ALIGNMENT,
};
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_component::{uses_zero_length_component, DataTypeComponent};

/// Abstract database implementation for a structure or union.
///
/// Port of `ghidra.program.database.data.CompositeDB`.
pub trait CompositeDb: CompositeInternal {
    /// Stands in for the abstract `CompositeDB.hasLanguageDependantLength()`.
    fn composite_db_has_language_dependant_length(&self) -> bool;

    /// Get computed alignment and optionally update the backing record. Stands in for the
    /// abstract `CompositeDB.getComputedAlignment(boolean)`.
    fn get_computed_alignment(&mut self, update_record: bool) -> i32;

    /// Repack components within this composite based on the current packing, alignment, and
    /// data organization settings. Returns `true` if a layout change was detected. Stands in for
    /// the abstract `CompositeDB.repack(boolean, boolean)`.
    fn composite_db_repack(&mut self, is_auto_change: bool, notify: bool) -> bool;

    /// Perform any necessary component adjustments based on sizes of components differing from
    /// their specification. Stands in for the abstract `CompositeDB.fixupComponents()`.
    fn fixup_components(&mut self) -> io::Result<()>;

    /// Invokes `consumer` once per defined component. Stands in for the package-private abstract
    /// `CompositeDB.forEachDefinedComponent(Consumer<DataTypeComponentDB>)`.
    fn for_each_defined_component(&self, consumer: &mut dyn FnMut(&dyn DataTypeComponent));

    /// Port of the `final` `CompositeDB.getAlignment()`, simplified per the module-level
    /// documentation to skip the not-yet-ported lock/refresh/transaction-state check.
    fn composite_db_get_alignment(&mut self) -> i32 {
        self.get_computed_alignment(false)
    }

    /// Port of the protected final `CompositeDB.getNonPackedAlignment()`.
    fn get_non_packed_alignment(&self) -> i32 {
        let alignment = self.get_stored_minimum_alignment();
        if alignment == DEFAULT_ALIGNMENT {
            1
        } else if alignment == MACHINE_ALIGNMENT {
            self.get_data_organization().get_machine_alignment()
        } else {
            alignment
        }
    }

    /// Port of the protected `CompositeDB.validateDataType(DataType)`. See the module-level
    /// documentation for `default_replacement` (stands in for `Undefined1DataType.dataType`) and
    /// `dynamic_can_specify_length` (stands in for `Dynamic.canSpecifyLength()`, only consulted
    /// when `data_type.is_dynamic_type()`).
    ///
    /// # Errors
    /// Returns `Err` if `data_type` is not allowed to be added to this composite (mirrors
    /// `IllegalArgumentException`).
    fn validate_data_type(
        &self,
        data_type: Box<dyn DataType>,
        default_replacement: Box<dyn DataType>,
        dynamic_can_specify_length: bool,
    ) -> Result<Box<dyn DataType>, String> {
        if data_type.is_default_data_type() {
            if self.is_packing_enabled() || self.is_union() {
                return Ok(default_replacement);
            }
            return Ok(data_type);
        }
        if data_type.is_dynamic_type() {
            if !dynamic_can_specify_length {
                return Err(invalid_component_data_type(data_type.as_ref()));
            }
        } else if data_type.is_factory_type() || data_type.get_length() <= 0 {
            return Err(invalid_component_data_type(data_type.as_ref()));
        }
        Ok(data_type)
    }

    /// Port of `CompositeDB.getPreferredComponentLength(DataType, int, int)`. See the
    /// module-level documentation for why `is_dynamic_with_specifiable_length` stands in for
    /// `(dataType instanceof Dynamic dynamic) && dynamic.canSpecifyLength()`.
    ///
    /// # Errors
    /// Returns `Err` if a positive length cannot be determined for a non-dynamic `data_type`
    /// (mirrors `IllegalArgumentException`).
    fn get_preferred_component_length(
        &self,
        data_type: &dyn DataType,
        is_dynamic_with_specifiable_length: bool,
        length: i32,
        max_length: i32,
    ) -> Result<i32, String> {
        if uses_zero_length_component(data_type) {
            return Ok(0);
        }
        if !is_dynamic_with_specifiable_length {
            if self.is_packing_enabled() {
                let aligned = data_type.get_aligned_length();
                if aligned > 0 {
                    return Ok(aligned);
                }
            } else if self.is_union() {
                // enforce Union component size for fixed-length types
                let l = data_type.get_length();
                if l > 0 {
                    return Ok(l);
                }
            } else if max_length >= 0 {
                // length determined by datatype but must not exceed maxLength
                let l = data_type.get_length().min(max_length);
                if l > 0 {
                    return Ok(l);
                }
            }
        }
        preferred_component_length_for_data_type(data_type, is_dynamic_with_specifiable_length, length)
    }

    /// Port of `CompositeDB.getPreferredComponentLength(DataType, int)`.
    ///
    /// # Errors
    /// See [`CompositeDb::get_preferred_component_length`].
    fn get_preferred_component_length_default(
        &self,
        data_type: &dyn DataType,
        is_dynamic_with_specifiable_length: bool,
        length: i32,
    ) -> Result<i32, String> {
        self.get_preferred_component_length(data_type, is_dynamic_with_specifiable_length, length, -1)
    }
}

/// Builds the `IllegalArgumentException` message shared by both `validateDataType` error paths.
fn invalid_component_data_type(data_type: &dyn DataType) -> String {
    format!(
        "IllegalArgumentException: The \"{}\" data type is not allowed in a composite data type.",
        data_type.get_name()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::data::alignment_type::AlignmentType;
    use crate::program::model::data::composite::Composite;
    use crate::program::model::data::data_organization::DataOrganization;
    use crate::program::model::data::packing_type::PackingType;
    use std::cell::RefCell;

    struct MockDataType {
        name: &'static str,
        length: i32,
        is_default: bool,
        is_dynamic: bool,
        is_factory: bool,
    }

    impl DataType for MockDataType {
        fn get_name(&self) -> String {
            self.name.to_string()
        }
        fn get_length(&self) -> i32 {
            self.length
        }
        fn is_default_data_type(&self) -> bool {
            self.is_default
        }
        fn is_dynamic_type(&self) -> bool {
            self.is_dynamic
        }
        fn is_factory_type(&self) -> bool {
            self.is_factory
        }
    }

    fn plain(name: &'static str, length: i32) -> Box<dyn DataType> {
        Box::new(MockDataType {
            name,
            length,
            is_default: false,
            is_dynamic: false,
            is_factory: false,
        })
    }

    struct MockDataOrganization;
    impl DataOrganization for MockDataOrganization {
        fn is_big_endian(&self) -> bool {
            false
        }
        fn get_pointer_size(&self) -> i32 {
            8
        }
        fn get_pointer_shift(&self) -> i32 {
            0
        }
        fn is_signed_char(&self) -> bool {
            true
        }
        fn get_char_size(&self) -> i32 {
            1
        }
        fn get_wide_char_size(&self) -> i32 {
            2
        }
        fn get_short_size(&self) -> i32 {
            2
        }
        fn get_integer_size(&self) -> i32 {
            4
        }
        fn get_long_size(&self) -> i32 {
            8
        }
        fn get_long_long_size(&self) -> i32 {
            8
        }
        fn get_float_size(&self) -> i32 {
            4
        }
        fn get_double_size(&self) -> i32 {
            8
        }
        fn get_long_double_size(&self) -> i32 {
            8
        }
        fn get_absolute_max_alignment(&self) -> i32 {
            0
        }
        fn get_machine_alignment(&self) -> i32 {
            8
        }
        fn get_default_alignment(&self) -> i32 {
            1
        }
        fn get_default_pointer_alignment(&self) -> i32 {
            8
        }
        fn get_size_alignment(&self, _size: i32) -> i32 {
            1
        }
        fn get_bit_field_packing(
            &self,
        ) -> Box<dyn crate::program::model::data::bit_field_packing::BitFieldPacking> {
            struct MockBitFieldPacking;
            impl crate::program::model::data::bit_field_packing::BitFieldPacking for MockBitFieldPacking {
                fn use_ms_convention(&self) -> bool {
                    false
                }
                fn is_type_alignment_enabled(&self) -> bool {
                    true
                }
                fn get_zero_length_boundary(&self) -> i32 {
                    0
                }
            }
            Box::new(MockBitFieldPacking)
        }
        fn get_size_alignment_count(&self) -> i32 {
            0
        }
        fn get_sizes(&self) -> Vec<i32> {
            vec![]
        }
        fn get_integer_c_type_approximation(&self, _size: i32, _signed: bool) -> String {
            String::new()
        }
        fn get_alignment(&self, _data_type: &dyn DataType) -> i32 {
            1
        }
    }

    /// Minimal DB-backed [`CompositeDb`], proving object-safety and exercising real
    /// `validateDataType`/`getPreferredComponentLength`/`getNonPackedAlignment` behavior.
    struct MockCompositeDb {
        packing_type: PackingType,
        is_union: bool,
        minimum_alignment: i32,
        computed_alignment_calls: RefCell<Vec<bool>>,
    }

    impl DataType for MockCompositeDb {
        fn is_union(&self) -> bool {
            self.is_union
        }
        fn get_data_organization(&self) -> Box<dyn DataOrganization> {
            Box::new(MockDataOrganization)
        }
    }

    impl Composite for MockCompositeDb {
        fn get_packing_type(&self) -> PackingType {
            self.packing_type
        }
    }

    impl CompositeInternal for MockCompositeDb {
        fn get_stored_minimum_alignment(&self) -> i32 {
            self.minimum_alignment
        }
    }

    impl CompositeDb for MockCompositeDb {
        fn composite_db_has_language_dependant_length(&self) -> bool {
            false
        }
        fn get_computed_alignment(&mut self, update_record: bool) -> i32 {
            self.computed_alignment_calls.borrow_mut().push(update_record);
            4
        }
        fn composite_db_repack(&mut self, _is_auto_change: bool, _notify: bool) -> bool {
            false
        }
        fn fixup_components(&mut self) -> io::Result<()> {
            Ok(())
        }
        fn for_each_defined_component(&self, _consumer: &mut dyn FnMut(&dyn DataTypeComponent)) {}
    }

    fn union_composite() -> MockCompositeDb {
        MockCompositeDb {
            packing_type: PackingType::Disabled,
            is_union: true,
            minimum_alignment: DEFAULT_ALIGNMENT,
            computed_alignment_calls: RefCell::new(Vec::new()),
        }
    }

    fn structure_composite() -> MockCompositeDb {
        MockCompositeDb {
            packing_type: PackingType::Disabled,
            is_union: false,
            minimum_alignment: DEFAULT_ALIGNMENT,
            computed_alignment_calls: RefCell::new(Vec::new()),
        }
    }

    #[test]
    fn usable_as_trait_object_and_forwards_alignment() {
        let mut c: Box<dyn CompositeDb> = Box::new(structure_composite());
        assert_eq!(c.composite_db_get_alignment(), 4);
    }

    #[test]
    fn validate_data_type_substitutes_default_for_union() {
        let mut c = union_composite();
        let default_dt: Box<dyn DataType> = Box::new(MockDataType {
            name: "DEFAULT",
            length: 1,
            is_default: true,
            is_dynamic: false,
            is_factory: false,
        });
        let replacement = plain("undefined1", 1);
        let result = c.validate_data_type(default_dt, replacement, true).unwrap();
        assert_eq!(result.get_name(), "undefined1");
        // getAlignment still reaches the trait's abstract get_computed_alignment override.
        assert_eq!(c.composite_db_get_alignment(), 4);
        assert_eq!(*c.computed_alignment_calls.borrow(), vec![false]);
    }

    #[test]
    fn validate_data_type_passes_default_through_for_non_packed_structure() {
        let s = structure_composite();
        let default_dt: Box<dyn DataType> = Box::new(MockDataType {
            name: "DEFAULT",
            length: 1,
            is_default: true,
            is_dynamic: false,
            is_factory: false,
        });
        let result = s
            .validate_data_type(default_dt, plain("undefined1", 1), true)
            .unwrap();
        assert_eq!(result.get_name(), "DEFAULT");
    }

    #[test]
    fn validate_data_type_rejects_non_length_specifiable_dynamic() {
        let s = structure_composite();
        let dynamic_dt: Box<dyn DataType> = Box::new(MockDataType {
            name: "string-dynamic",
            length: -1,
            is_default: false,
            is_dynamic: true,
            is_factory: false,
        });
        let err = match s.validate_data_type(dynamic_dt, plain("undefined1", 1), false) {
            Err(e) => e,
            Ok(_) => panic!("expected an error"),
        };
        assert!(err.contains("string-dynamic"));
        assert!(err.contains("IllegalArgumentException"));
    }

    #[test]
    fn validate_data_type_rejects_zero_length_non_dynamic() {
        let s = structure_composite();
        let zero_len: Box<dyn DataType> = Box::new(MockDataType {
            name: "factory-type",
            length: 0,
            is_default: false,
            is_dynamic: false,
            is_factory: true,
        });
        let err = match s.validate_data_type(zero_len, plain("undefined1", 1), true) {
            Err(e) => e,
            Ok(_) => panic!("expected an error"),
        };
        assert!(err.contains("factory-type"));
    }

    #[test]
    fn validate_data_type_accepts_ordinary_fixed_length_type() {
        let s = structure_composite();
        let ok = s
            .validate_data_type(plain("int", 4), plain("undefined1", 1), true)
            .unwrap();
        assert_eq!(ok.get_name(), "int");
    }

    #[test]
    fn preferred_component_length_enforces_union_component_size() {
        let u = union_composite();
        assert_eq!(
            u.get_preferred_component_length(plain("int", 4).as_ref(), false, -1, -1)
                .unwrap(),
            4
        );
    }

    #[test]
    fn preferred_component_length_default_matches_explicit_no_max() {
        let s = structure_composite();
        let dt = plain("byte", 1);
        assert_eq!(
            s.get_preferred_component_length_default(dt.as_ref(), false, -1)
                .unwrap(),
            s.get_preferred_component_length(dt.as_ref(), false, -1, -1)
                .unwrap()
        );
    }

    #[test]
    fn non_packed_alignment_reports_machine_alignment_when_configured() {
        let mut s = structure_composite();
        s.minimum_alignment = MACHINE_ALIGNMENT;
        assert_eq!(s.get_non_packed_alignment(), 8);
    }

    #[test]
    fn non_packed_alignment_defaults_to_one() {
        let s = structure_composite();
        assert_eq!(s.get_non_packed_alignment(), 1);
    }

    #[test]
    fn alignment_type_reflects_stored_minimum_alignment() {
        let s = structure_composite();
        assert_eq!(s.get_alignment_type(), AlignmentType::Default);
    }
}

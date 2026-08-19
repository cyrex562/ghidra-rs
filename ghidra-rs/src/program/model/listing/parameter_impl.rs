//! Port of `ghidra.program.model.listing.ParameterImpl`, promoted to a trait because it was
//! selected as a dependency-cycle cut-point.
//!
//! Mirrors the `stored_*`/`variable_impl_*` convention established by
//! [`VariableImpl`](crate::program::model::listing::variable_impl::VariableImpl): the private
//! `ordinal` field is exposed via a required [`stored_ordinal`](ParameterImpl::stored_ordinal)
//! accessor, and each method `ParameterImpl` overrides is exposed as a defaulted
//! `parameter_impl_*` method. A concrete type implementing both `VariableImpl` and
//! [`Parameter`] is expected to delegate its `Variable`/`Parameter` method bodies to these,
//! exactly as `MockVariableImpl` delegates to `VariableImpl` in the sibling module.
//!
//! `DataTypeManager.getPointer`/`getPointer(DataType, int)` and `DataOrganization.getPointerSize`
//! are already ported ([`DataTypeManager::get_pointer`]/[`DataTypeManager::get_pointer_with_size`],
//! [`DataOrganization::get_pointer_size`]), so [`ParameterImpl::parameter_impl_get_data_type`] uses
//! them directly. `VariableStorage.isForcedIndirect()`/`isAutoStorage()` have no counterpart yet on
//! the [`VariableStorage`](crate::program::model::listing::variable_storage::VariableStorage) trait, so
//! this port grows that stub with two `false`-defaulted methods (see `STUBS.tsv`).
//!
//! `SymbolUtilities.isDefaultParameterName(String)` has no ported counterpart yet; rather than
//! growing the (already fully-ported, unrelated) `symbol_utilities` module for a single
//! `Parameter`-specific predicate, it is reproduced locally as [`is_default_parameter_name`], keyed
//! off the already-ported
//! [`function::DEFAULT_PARAM_PREFIX`](crate::program::model::listing::function::DEFAULT_PARAM_PREFIX).

use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::listing::function::DEFAULT_PARAM_PREFIX;
use crate::program::model::listing::variable_impl::VariableImpl;
use crate::program::model::listing::{AutoParameterType, Parameter, Variable};

/// Mirrors `SymbolUtilities.isDefaultParameterName(String)`: true if `name` is absent/empty, or is
/// exactly [`DEFAULT_PARAM_PREFIX`] followed by a valid `i32` (e.g. `"param_1"`).
fn is_default_parameter_name(name: Option<&str>) -> bool {
    let Some(name) = name else {
        return true;
    };
    if name.is_empty() {
        return true;
    }
    match name.strip_prefix(DEFAULT_PARAM_PREFIX) {
        Some(tail) => tail.parse::<i32>().is_ok(),
        None => false,
    }
}

/// Field-backed default implementation of the `Parameter`-specific overrides `ParameterImpl` gives
/// real bodies to, layered on top of [`VariableImpl`].
///
/// Port of `ghidra.program.model.listing.ParameterImpl`. See the module docs for the `stored_*`
/// accessor / `parameter_impl_*` method-naming convention.
pub trait ParameterImpl: VariableImpl + Parameter {
    /// Backing storage for the `ordinal` field.
    fn stored_ordinal(&self) -> i32;

    /// Default body for [`VariableImpl::has_default_name`], overridden to recognize
    /// `"param_N"`-shaped default parameter names.
    ///
    /// Port of `ParameterImpl.hasDefaultName` (`final`).
    fn parameter_impl_has_default_name(&self) -> bool {
        is_default_parameter_name(self.stored_name().as_deref())
    }

    /// Default body for [`Parameter::get_ordinal`].
    ///
    /// Port of `ParameterImpl.getOrdinal` (`final`).
    fn parameter_impl_get_ordinal(&self) -> i32 {
        self.stored_ordinal()
    }

    /// Default body for [`Variable::get_first_use_offset`]: a parameter's first use is always the
    /// function entry point.
    ///
    /// Port of `ParameterImpl.getFirstUseOffset` (`final`).
    fn parameter_impl_get_first_use_offset(&self) -> i32 {
        0
    }

    /// Default body for [`Parameter::get_formal_data_type`]: the datatype before any
    /// forced-indirect pointer wrapping, i.e. plain `VariableImpl::variable_impl_get_data_type`.
    ///
    /// Port of `ParameterImpl.getFormalDataType` (delegates to `super.getDataType()`, i.e.
    /// `VariableImpl.getDataType()`).
    fn parameter_impl_get_formal_data_type(&self) -> Box<dyn DataType> {
        self.variable_impl_get_data_type()
    }

    /// Default body for [`Variable::get_data_type`]: wraps the formal datatype in a pointer sized
    /// to the storage if the calling convention forced this parameter to be passed indirectly.
    ///
    /// Port of `ParameterImpl.getDataType`.
    fn parameter_impl_get_data_type(&self) -> Box<dyn DataType> {
        let formal = self.parameter_impl_get_formal_data_type();
        let Some(storage) = self.variable_impl_get_variable_storage() else {
            return formal;
        };
        if !storage.is_forced_indirect() {
            return formal;
        }
        let Some(dtm) = self.get_program().get_data_type_manager() else {
            return formal;
        };
        let ptr_size = storage.size();
        if ptr_size != dtm.get_data_organization().get_pointer_size() {
            dtm.get_pointer_with_size(formal.as_ref(), ptr_size)
        } else {
            dtm.get_pointer(formal.as_ref())
        }
    }

    /// Default body for [`Parameter::is_forced_indirect`].
    ///
    /// Port of `ParameterImpl.isForcedIndirect`.
    fn parameter_impl_is_forced_indirect(&self) -> bool {
        self.variable_impl_get_variable_storage()
            .map(|s| s.is_forced_indirect())
            .unwrap_or(false)
    }

    /// Default body for [`Parameter::is_auto_parameter`] (via [`Variable::is_auto_parameter`]).
    ///
    /// Port of `ParameterImpl.isAutoParameter`.
    fn parameter_impl_is_auto_parameter(&self) -> bool {
        self.variable_impl_get_variable_storage()
            .map(|s| s.is_auto_storage())
            .unwrap_or(false)
    }

    /// Default body for [`Parameter::get_auto_parameter_type`].
    ///
    /// Port of `ParameterImpl.getAutoParameterType`.
    fn parameter_impl_get_auto_parameter_type(&self) -> Option<AutoParameterType> {
        self.variable_impl_get_variable_storage()
            .and_then(|s| s.get_auto_parameter_type())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Ordering;
    use std::sync::Arc;

    use crate::program::model::address::Address;
    use crate::program::model::data::bit_field_packing::BitFieldPacking;
    use crate::program::model::data::data_organization::DataOrganization;
    use crate::program::model::lang::RegisterRef;
    use crate::program::model::listing::variable::{SetVariableNameError, UnsupportedOperationError};
    use crate::program::model::listing::{Function, Program};
    use crate::program::model::pcode::Varnode;
    use crate::program::model::symbol::{SourceType, Symbol};
    use crate::program::seam_stubs::{PlaceholderVariableStorage};
    use crate::program::model::listing::variable_storage::VariableStorage;
    use crate::util::exception::InvalidInputException;

    /// Minimal fixed-endian, 4-byte-pointer [`BitFieldPacking`]/[`DataOrganization`] pair, used
    /// only to give [`MockDataTypeManager::get_data_organization`] something to return; no test
    /// here exercises bitfield packing or any size/alignment other than the pointer size.
    struct MockBitFieldPacking;
    impl BitFieldPacking for MockBitFieldPacking {
        fn use_ms_convention(&self) -> bool {
            false
        }
        fn is_type_alignment_enabled(&self) -> bool {
            false
        }
        fn get_zero_length_boundary(&self) -> i32 {
            0
        }
    }

    struct MockDataOrganization;
    impl DataOrganization for MockDataOrganization {
        fn is_big_endian(&self) -> bool {
            false
        }
        fn get_pointer_size(&self) -> i32 {
            4
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
            4
        }
        fn get_short_size(&self) -> i32 {
            2
        }
        fn get_integer_size(&self) -> i32 {
            4
        }
        fn get_long_size(&self) -> i32 {
            4
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
            4
        }
        fn get_default_alignment(&self) -> i32 {
            1
        }
        fn get_default_pointer_alignment(&self) -> i32 {
            4
        }
        fn get_size_alignment(&self, _size: i32) -> i32 {
            1
        }
        fn get_bit_field_packing(&self) -> Box<dyn BitFieldPacking> {
            Box::new(MockBitFieldPacking)
        }
        fn get_size_alignment_count(&self) -> i32 {
            0
        }
        fn get_sizes(&self) -> Vec<i32> {
            Vec::new()
        }
        fn get_integer_c_type_approximation(&self, _size: i32, _signed: bool) -> String {
            String::new()
        }
        fn get_alignment(&self, _data_type: &dyn DataType) -> i32 {
            1
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct MockDataType {
        length: i32,
    }

    impl DataType for MockDataType {
        fn get_name(&self) -> String {
            format!("mock{}", self.length)
        }
        fn get_length(&self) -> i32 {
            self.length
        }
    }

    struct MockProgram;
    impl crate::framework::model::DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }
        fn get_language_id(&self) -> String {
            "mock:LE:32:default".to_string()
        }
        fn get_data_type_manager(&self) -> Option<Box<dyn DataTypeManager>> {
            Some(Box::new(MockDataTypeManager))
        }
    }

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {
        fn get_data_organization(&self) -> Box<dyn DataOrganization> {
            Box::new(MockDataOrganization)
        }
    }

    /// [`VariableStorage`] whose `is_forced_indirect`/`size` are configurable, used to exercise
    /// [`ParameterImpl::parameter_impl_get_data_type`]'s pointer-wrapping branch.
    #[derive(Clone)]
    struct ForcedIndirectStorage {
        size: i32,
    }
    impl VariableStorage for ForcedIndirectStorage {
        fn is_forced_indirect(&self) -> bool {
            true
        }
        fn size(&self) -> i32 {
            self.size
        }
        // `stored_variable_storage` (see `MockParameterImpl` below, mirroring `MockVariableImpl`
        // in the sibling `variable_impl` module) rebuilds storage via `with_varnodes` on every
        // read since `dyn VariableStorage` has no `Clone`; overriding it here (instead of falling
        // through to the default, which would rebuild a plain `VarnodeListStorage` and silently
        // lose `is_forced_indirect`) keeps that round-trip faithful.
        fn with_varnodes(&self, _varnodes: Vec<Varnode>) -> Box<dyn VariableStorage> {
            Box::new(self.clone())
        }
    }

    /// Minimal `ParameterImpl`/`VariableImpl`/`Parameter` implementor backed by plain struct
    /// fields, mirroring `MockVariableImpl` in the sibling `variable_impl` module. Every method
    /// this port gives a real algorithm to just delegates to its `parameter_impl_*`/
    /// `variable_impl_*` counterpart.
    struct MockParameterImpl {
        name: Option<String>,
        data_type: MockDataType,
        comment: Option<String>,
        source_type: SourceType,
        storage: Option<Box<dyn VariableStorage>>,
        program: Arc<dyn Program>,
        ordinal: i32,
    }

    impl VariableImpl for MockParameterImpl {
        fn has_default_name(&self) -> bool {
            self.parameter_impl_has_default_name()
        }
        fn stored_name(&self) -> Option<String> {
            self.name.clone()
        }
        fn set_stored_name(&mut self, name: Option<String>) {
            self.name = name;
        }
        fn stored_data_type(&self) -> Box<dyn DataType> {
            Box::new(self.data_type)
        }
        fn set_stored_data_type(&mut self, data_type: Box<dyn DataType>) {
            self.data_type = MockDataType {
                length: data_type.get_length(),
            };
        }
        fn stored_comment(&self) -> Option<String> {
            self.comment.clone()
        }
        fn set_stored_comment(&mut self, comment: Option<String>) {
            self.comment = comment;
        }
        fn stored_source_type(&self) -> SourceType {
            self.source_type
        }
        fn set_stored_source_type(&mut self, source_type: SourceType) {
            self.source_type = source_type;
        }
        fn stored_variable_storage(&self) -> Option<Box<dyn VariableStorage>> {
            self.storage
                .as_ref()
                .map(|s| s.with_varnodes(s.get_varnodes()))
        }
        fn set_stored_variable_storage(&mut self, storage: Option<Box<dyn VariableStorage>>) {
            self.storage = storage;
        }
    }

    impl ParameterImpl for MockParameterImpl {
        fn stored_ordinal(&self) -> i32 {
            self.ordinal
        }
    }

    impl Variable for MockParameterImpl {
        fn get_data_type(&self) -> Box<dyn DataType> {
            self.parameter_impl_get_data_type()
        }
        fn set_data_type_with_storage(
            &mut self,
            data_type: Box<dyn DataType>,
            storage: Box<dyn VariableStorage>,
            force: bool,
            source: SourceType,
        ) -> Result<(), InvalidInputException> {
            self.variable_impl_set_data_type_with_storage(data_type, storage, force, source)
        }
        fn set_data_type(
            &mut self,
            data_type: Box<dyn DataType>,
            source: SourceType,
        ) -> Result<(), InvalidInputException> {
            self.variable_impl_set_data_type(data_type, source)
        }
        fn set_data_type_aligned(
            &mut self,
            data_type: Box<dyn DataType>,
            align: bool,
            force: bool,
            source: SourceType,
        ) -> Result<(), InvalidInputException> {
            self.variable_impl_set_data_type_aligned(data_type, align, force, source)
        }
        fn get_name(&self) -> Option<String> {
            self.variable_impl_get_name()
        }
        fn get_length(&self) -> i32 {
            self.variable_impl_get_length()
        }
        fn is_valid(&self) -> bool {
            self.variable_impl_is_valid()
        }
        fn get_function(&self) -> Option<Box<dyn Function>> {
            self.variable_impl_get_function()
        }
        fn get_program(&self) -> Arc<dyn Program> {
            self.program.clone()
        }
        fn get_source(&self) -> SourceType {
            self.variable_impl_get_source()
        }
        fn set_name(&mut self, name: &str, source: SourceType) -> Result<(), SetVariableNameError> {
            self.variable_impl_set_name(name, source)
        }
        fn get_comment(&self) -> Option<String> {
            self.variable_impl_get_comment()
        }
        fn set_comment(&mut self, comment: Option<String>) {
            self.variable_impl_set_comment(comment)
        }
        fn get_variable_storage(&self) -> Option<Box<dyn VariableStorage>> {
            self.variable_impl_get_variable_storage()
        }
        fn get_first_storage_varnode(&self) -> Option<Varnode> {
            self.variable_impl_get_first_storage_varnode()
        }
        fn get_last_storage_varnode(&self) -> Option<Varnode> {
            self.variable_impl_get_last_storage_varnode()
        }
        fn is_stack_variable(&self) -> bool {
            self.variable_impl_is_stack_variable()
        }
        fn has_stack_storage(&self) -> bool {
            self.variable_impl_has_stack_storage()
        }
        fn is_register_variable(&self) -> bool {
            self.variable_impl_is_register_variable()
        }
        fn get_register(&self) -> Option<RegisterRef> {
            self.variable_impl_get_register()
        }
        fn get_registers(&self) -> Option<Vec<RegisterRef>> {
            self.variable_impl_get_registers()
        }
        fn get_min_address(&self) -> Option<Address> {
            self.variable_impl_get_min_address()
        }
        fn get_stack_offset(&self) -> Result<i32, UnsupportedOperationError> {
            self.variable_impl_get_stack_offset()
        }
        fn is_memory_variable(&self) -> bool {
            self.variable_impl_is_memory_variable()
        }
        fn is_unique_variable(&self) -> bool {
            self.variable_impl_is_unique_variable()
        }
        fn is_compound_variable(&self) -> bool {
            self.variable_impl_is_compound_variable()
        }
        fn has_assigned_storage(&self) -> bool {
            self.variable_impl_has_assigned_storage()
        }
        fn get_first_use_offset(&self) -> i32 {
            self.parameter_impl_get_first_use_offset()
        }
        fn get_symbol(&self) -> Option<Arc<dyn Symbol>> {
            None
        }
        fn is_equivalent(&self, variable: &dyn Variable) -> bool {
            self.variable_impl_is_equivalent(variable)
        }
        fn compare_to(&self, other: &dyn Variable) -> Ordering {
            self.variable_impl_compare_to(other)
        }
        fn is_parameter(&self) -> bool {
            true
        }
        fn is_auto_parameter(&self) -> bool {
            self.parameter_impl_is_auto_parameter()
        }
        fn parameter_ordinal(&self) -> Option<i32> {
            Some(self.stored_ordinal())
        }
    }

    impl Parameter for MockParameterImpl {
        fn get_ordinal(&self) -> i32 {
            self.parameter_impl_get_ordinal()
        }
        fn is_auto_parameter(&self) -> bool {
            self.parameter_impl_is_auto_parameter()
        }
        fn get_auto_parameter_type(&self) -> Option<AutoParameterType> {
            self.parameter_impl_get_auto_parameter_type()
        }
        fn is_forced_indirect(&self) -> bool {
            self.parameter_impl_is_forced_indirect()
        }
        fn get_formal_data_type(&self) -> Box<dyn DataType> {
            self.parameter_impl_get_formal_data_type()
        }
    }

    fn mock_program() -> Arc<dyn Program> {
        Arc::new(MockProgram)
    }

    fn new_param(name: &str, ordinal: i32, length: i32) -> MockParameterImpl {
        MockParameterImpl {
            name: Some(name.to_string()),
            data_type: MockDataType { length },
            comment: None,
            source_type: SourceType::UserDefined,
            storage: Some(Box::new(PlaceholderVariableStorage)),
            program: mock_program(),
            ordinal,
        }
    }

    #[test]
    fn has_default_name_recognizes_param_prefix() {
        assert!(is_default_parameter_name(Some("param_1")));
        assert!(is_default_parameter_name(Some("")));
        assert!(is_default_parameter_name(None));
        assert!(!is_default_parameter_name(Some("count")));
        assert!(!is_default_parameter_name(Some("param_abc")));
    }

    #[test]
    fn get_ordinal_and_first_use_offset() {
        let param = new_param("count", 2, 4);
        assert_eq!(Parameter::get_ordinal(&param), 2);
        assert_eq!(param.get_first_use_offset(), 0);
    }

    #[test]
    fn get_formal_data_type_matches_stored_data_type_when_not_forced_indirect() {
        let param = new_param("count", 0, 4);
        assert_eq!(param.get_formal_data_type().get_length(), 4);
        assert_eq!(param.get_data_type().get_length(), 4);
        assert!(!param.is_forced_indirect());
    }

    #[test]
    fn get_data_type_wraps_pointer_when_forced_indirect() {
        let mut param = new_param("big_struct", 0, 64);
        param.storage = Some(Box::new(ForcedIndirectStorage { size: 8 }));
        assert!(param.is_forced_indirect());
        // The formal type is unchanged...
        assert_eq!(param.get_formal_data_type().get_length(), 64);
        // ...but the effective type is wrapped in a pointer (the mock `DataTypeManager`'s default
        // `get_pointer`/`get_pointer_with_size` bodies build an `EmptyPointer`, whose own length
        // differs from the formal type -- proving `getDataType()` did not just fall through to
        // `getFormalDataType()`).
        assert_ne!(
            param.get_data_type().get_length(),
            param.get_formal_data_type().get_length()
        );
    }

    #[test]
    fn is_auto_parameter_reflects_storage() {
        let mut param = new_param("__return_storage_ptr__", -1, 4);
        assert!(!Variable::is_auto_parameter(&param));

        struct AutoStorage;
        impl VariableStorage for AutoStorage {
            fn is_auto_storage(&self) -> bool {
                true
            }
            fn get_auto_parameter_type(&self) -> Option<AutoParameterType> {
                Some(AutoParameterType::ReturnStoragePtr)
            }
            // See the identical override on `ForcedIndirectStorage` above for why this is needed.
            fn with_varnodes(&self, _varnodes: Vec<Varnode>) -> Box<dyn VariableStorage> {
                Box::new(AutoStorage)
            }
        }
        param.storage = Some(Box::new(AutoStorage));
        assert!(Variable::is_auto_parameter(&param));
        assert_eq!(
            param.get_auto_parameter_type(),
            Some(AutoParameterType::ReturnStoragePtr)
        );
    }

    #[test]
    fn trait_object_usage_is_object_safe() {
        let param: Box<dyn ParameterImpl> = Box::new(new_param("count", 1, 4));
        assert_eq!(param.stored_ordinal(), 1);
        assert!(param.parameter_impl_has_default_name() == false);
    }
}

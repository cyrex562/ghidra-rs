//! Port of `ghidra.program.database.data.FunctionDefinitionDB` as a trait (cycle cut-point).
//!
//! The Java class is a package-private, concrete `FunctionDefinition` implementation that
//! extends the not-yet-ported abstract `DataTypeDB` (itself backed by a shared
//! `record`/`lock`/`dataMgr` triple) and holds direct references to the already-ported
//! [`FunctionDefinitionDBAdapter`](super::function_definition_db_adapter::FunctionDefinitionDBAdapter)
//! and [`FunctionParameterAdapter`](super::function_parameter_adapter::FunctionParameterAdapter)
//! traits. Every public method belonging to the
//! [`FunctionDefinition`](crate::program::model::data::function_definition::FunctionDefinition)
//! (which itself pulls in
//! [`FunctionSignature`](crate::program::model::listing::FunctionSignature) and
//! [`DataType`](crate::program::model::data::data_type::DataType)) contract is already declared
//! there, so none of it is repeated here.
//!
//! The two pieces of `FunctionDefinitionDB`'s own contract that matter for the dependency cycle,
//! mirroring [`ArrayDb`](super::array_db::ArrayDb)'s treatment of the identical
//! `DataTypeDB`/`DataTypeManagerDB` situation:
//!   - [`FunctionDefinitionDb::refresh`] -- stands in for the protected `DataTypeDB.refresh(DBRecord)`
//!     as overridden by `FunctionDefinitionDB` (re-loads the record and its parameter list,
//!     detecting deletion when the backing record is gone).
//!   - [`FunctionDefinitionDb::owning_data_type_manager`] -- stands in for the constructor-injected
//!     `dataMgr` field. `DataTypeManagerDB` constructs `FunctionDefinitionDB` instances (handing
//!     them their adapters and manager back-reference), and `FunctionDefinitionDB` holds a
//!     reference back to that same manager -- the mutual construction-time dependency that makes
//!     it a cycle cut-point, modeled via the [`DataTypeManagerDb`] trait.
//!
//! One real algorithm is ported here as a default-bodied method:
//!   - [`FunctionDefinitionDb::function_definition_db_prototype_string`] -- port of
//!     `FunctionDefinitionDB.getPrototypeString(boolean)`, built entirely from already-ported
//!     [`FunctionSignature`]/[`DataType`] accessors. It cannot be named `get_prototype_string`
//!     (the zero-arg form already has a default on [`FunctionSignature`]) or
//!     `get_prototype_string_with_calling_convention` (declared `abstract` there, so a subtrait
//!     cannot supply its body -- only the implementing type can); mirroring
//!     [`CompositeDb`](super::composite_db::CompositeDb)'s `composite_db_*` convention, it is
//!     exposed under a distinct name instead.
//!
//! `getArguments`, `getReturnType`, `setArguments`, `setReturnType`, `setComment`, `setVarArgs`,
//! `setNoReturn`, `setGenericCallingConvention`, `setCallingConvention`, `replaceArgument`,
//! `hasVarArgs`, `hasNoReturn`, `getCallingConvention`, `getCallingConventionName`, and
//! `getComment` are all already declared (abstract) on `FunctionDefinition`/`FunctionSignature`,
//! so a `FunctionDefinitionDb` implementor supplies them directly rather than through this trait.
//! `replaceWith`/`doReplaceWith`, `postPointerResolve`, `dataTypeDeleted`, `dataTypeReplaced`,
//! `isEquivalent`/`isEquivalentSignature`, `copy`/`clone`, and the `do*Record` family all
//! construct or mutate a concrete `ParameterDefinitionDB`/`DBRecord`/`FunctionDefinitionDataType`
//! via `funDefAdapter`/`paramAdapter`/`dataMgr`'s resolve-cache and conflict-handler machinery
//! (`DataTypeConflictHandler`, `DataTypeUtilities.equalsIgnoreConflict`) in ways that need real
//! per-instance record/adapter/cache plumbing this trait does not yet prescribe; they are left for
//! a future port once `DataTypeDB` itself (or a fuller `FunctionDefinitionDb` accessor contract)
//! is in place, rather than being modeled here as more placeholder stubs.

use std::sync::Arc;

use crate::framework::db::DBRecord;
use crate::program::database::data::data_type_manager_db::DataTypeManagerDb;
use crate::program::model::data::function_definition::FunctionDefinition;
use crate::program::model::listing::function::UNKNOWN_CALLING_CONVENTION_STRING;
use crate::program::model::listing::function_signature::{
    FunctionSignature, NORETURN_DISPLAY_STRING, VAR_ARGS_DISPLAY_STRING, VOID_PARAM_DISPLAY_STRING,
};

/// Database implementation of the [`FunctionDefinition`] interface.
///
/// Port of `ghidra.program.database.data.FunctionDefinitionDB`.
pub trait FunctionDefinitionDb: FunctionDefinition {
    /// Re-synchronizes this function definition's cached state (including its parameter list)
    /// against the latest database record, looking the record up via this definition's backing
    /// `FunctionDefinitionDBAdapter`/key when `record` is `None`. Returns `false` if the
    /// underlying record no longer exists (the function definition has been deleted).
    ///
    /// Stands in for the protected `DataTypeDB.refresh(DBRecord)` as overridden by
    /// `FunctionDefinitionDB`.
    fn refresh(&mut self, record: Option<DBRecord>) -> bool;

    /// Returns the database-backed manager that owns this function definition's record.
    ///
    /// Stands in for the constructor-injected `dataMgr` field, accessed throughout
    /// `FunctionDefinitionDB` (e.g. `getReturnType`, `doSetReturnType`,
    /// `getCallingConventionName`).
    fn owning_data_type_manager(&self) -> Arc<dyn DataTypeManagerDb>;

    /// Get string representation of the function signature.
    ///
    /// `include_calling_convention`: if true, the prototype will include the call convention
    /// declaration if known, as well as a `noreturn` indicator if applicable.
    ///
    /// Port of `FunctionDefinitionDB.getPrototypeString(boolean)`. See the module-level
    /// documentation for why this cannot be named
    /// `get_prototype_string_with_calling_convention`.
    fn function_definition_db_prototype_string(&self, include_calling_convention: bool) -> String {
        let mut buf = String::new();
        if include_calling_convention && self.has_no_return() {
            buf.push_str(NORETURN_DISPLAY_STRING);
            buf.push(' ');
        }
        let return_type = self.get_return_type();
        buf.push_str(&return_type.get_display_name());
        buf.push(' ');
        if include_calling_convention {
            let calling_convention = self.get_calling_convention_name();
            if calling_convention != UNKNOWN_CALLING_CONVENTION_STRING {
                buf.push_str(&calling_convention);
                buf.push(' ');
            }
        }
        buf.push_str(&FunctionSignature::get_name(self));
        buf.push('(');

        let has_var_args = self.has_var_args();
        let args = self.get_arguments();
        let n = args.len();
        for (i, param) in args.iter().enumerate() {
            buf.push_str(&param.get_data_type().get_display_name());
            buf.push(' ');
            if let Some(name) = param.get_name() {
                buf.push_str(&name);
            }
            if i < n - 1 || has_var_args {
                buf.push_str(", ");
            }
        }
        if has_var_args {
            buf.push_str(VAR_ARGS_DISPLAY_STRING);
        } else if n == 0 {
            buf.push_str(VOID_PARAM_DISPLAY_STRING);
        }
        buf.push(')');

        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::data::data_type_manager::DataTypeManager;
    use crate::program::model::data::parameter_definition::ParameterDefinition;
    use crate::program::model::listing::FunctionSignature;
    use crate::program::model::lang::prototype_model::PrototypeModel;
    use std::cmp::Ordering;
    use std::io;

    struct MockDataType(&'static str);
    impl DataType for MockDataType {
        fn get_name(&self) -> String {
            self.0.to_string()
        }
    }

    struct MockParameter {
        name: Option<&'static str>,
        type_name: &'static str,
    }

    impl ParameterDefinition for MockParameter {
        fn get_ordinal(&self) -> i32 {
            0
        }
        fn get_data_type(&self) -> Box<dyn DataType> {
            Box::new(MockDataType(self.type_name))
        }
        fn set_data_type(&mut self, _data_type: Box<dyn DataType>) -> Result<(), String> {
            Ok(())
        }
        fn get_name(&self) -> Option<String> {
            self.name.map(|n| n.to_string())
        }
        fn get_length(&self) -> i32 {
            4
        }
        fn set_name(&mut self, _name: Option<String>) {}
        fn get_comment(&self) -> Option<String> {
            None
        }
        fn set_comment(&mut self, _comment: Option<String>) {}
        fn is_equivalent_variable(&self, _variable: &dyn crate::program::model::listing::Variable) -> bool {
            false
        }
        fn is_equivalent_parameter(&self, _parm: &dyn ParameterDefinition) -> bool {
            false
        }
        fn compare_to(&self, _other: &dyn ParameterDefinition) -> Ordering {
            Ordering::Equal
        }
    }

    struct MockDataTypeManagerDb;
    impl DataTypeManager for MockDataTypeManagerDb {}
    impl DataTypeManagerDb for MockDataTypeManagerDb {
        fn db_error(&mut self, _error: io::Error) {}
        fn add_data_type_to_replace(&mut self, _data_type_id: i64, _replacement: Box<dyn DataType>) {}
        fn add_data_type_to_delete(&mut self, _data_type_id: i64) {}
    }

    /// Minimal DB-backed [`FunctionDefinitionDb`], proving object-safety and exercising real
    /// `getPrototypeString(boolean)` behavior (varargs, void-param, and calling-convention
    /// rendering).
    struct MockFunctionDefinitionDb {
        name: String,
        var_args: bool,
        no_return: bool,
        calling_convention: String,
        params: Vec<MockParameter>,
        deleted: bool,
        manager: Arc<MockDataTypeManagerDb>,
    }

    impl DataType for MockFunctionDefinitionDb {
        fn get_name(&self) -> String {
            self.name.clone()
        }
    }

    impl FunctionSignature for MockFunctionDefinitionDb {
        fn get_name(&self) -> String {
            self.name.clone()
        }
        fn get_prototype_string_with_calling_convention(
            &self,
            include_calling_convention: bool,
        ) -> String {
            self.function_definition_db_prototype_string(include_calling_convention)
        }
        fn get_arguments(&self) -> Vec<Box<dyn ParameterDefinition>> {
            self.params
                .iter()
                .map(|p| -> Box<dyn ParameterDefinition> {
                    Box::new(MockParameter { name: p.name, type_name: p.type_name })
                })
                .collect()
        }
        fn get_return_type(&self) -> Box<dyn DataType> {
            Box::new(MockDataType("int"))
        }
        fn get_comment(&self) -> Option<String> {
            None
        }
        fn has_var_args(&self) -> bool {
            self.var_args
        }
        fn has_no_return(&self) -> bool {
            self.no_return
        }
        fn get_calling_convention(&self) -> Option<Box<dyn PrototypeModel>> {
            None
        }
        fn get_calling_convention_name(&self) -> String {
            self.calling_convention.clone()
        }
        fn is_equivalent_signature(&self, signature: &dyn FunctionSignature) -> bool {
            self.name == signature.get_name()
        }
    }

    impl FunctionDefinition for MockFunctionDefinitionDb {
        fn set_arguments(&mut self, _args: Vec<Box<dyn ParameterDefinition>>) {}
        fn set_return_type(&mut self, _data_type: Box<dyn DataType>) -> Result<(), String> {
            Ok(())
        }
        fn set_comment(&mut self, _comment: Option<String>) {}
        fn set_var_args(&mut self, has_var_args: bool) {
            self.var_args = has_var_args;
        }
        fn set_no_return(&mut self, has_no_return: bool) {
            self.no_return = has_no_return;
        }
        fn set_generic_calling_convention(
            &mut self,
            _generic_calling_convention: &dyn crate::program::seam_stubs::GenericCallingConvention,
        ) {
        }
        fn set_calling_convention(
            &mut self,
            _convention_name: Option<String>,
        ) -> Result<(), crate::util::exception::InvalidInputException> {
            Ok(())
        }
        fn replace_argument(
            &mut self,
            _ordinal: i32,
            _name: Option<String>,
            _dt: Box<dyn DataType>,
            _comment: Option<String>,
            _source: crate::program::model::symbol::source_type::SourceType,
        ) {
        }
    }

    impl FunctionDefinitionDb for MockFunctionDefinitionDb {
        fn refresh(&mut self, record: Option<DBRecord>) -> bool {
            match record {
                None => !self.deleted,
                Some(_) => true,
            }
        }
        fn owning_data_type_manager(&self) -> Arc<dyn DataTypeManagerDb> {
            self.manager.clone()
        }
    }

    fn sample(var_args: bool, no_return: bool) -> MockFunctionDefinitionDb {
        MockFunctionDefinitionDb {
            name: "foo".to_string(),
            var_args,
            no_return,
            calling_convention: UNKNOWN_CALLING_CONVENTION_STRING.to_string(),
            params: vec![
                MockParameter { name: Some("a"), type_name: "int" },
                MockParameter { name: Some("b"), type_name: "char" },
            ],
            deleted: false,
            manager: Arc::new(MockDataTypeManagerDb),
        }
    }

    #[test]
    fn usable_as_trait_object_and_refreshes() {
        let mut def: Box<dyn FunctionDefinitionDb> = Box::new(sample(false, false));
        assert!(def.refresh(None));
        let manager = def.owning_data_type_manager();
        assert_eq!(manager.get_universal_id(), manager.get_universal_id());
    }

    #[test]
    fn prototype_string_renders_fixed_arguments() {
        let def = sample(false, false);
        assert_eq!(
            def.function_definition_db_prototype_string(false),
            "int foo(int a, char b)"
        );
    }

    #[test]
    fn prototype_string_renders_var_args() {
        let mut def = sample(true, false);
        def.params.clear();
        assert_eq!(def.function_definition_db_prototype_string(false), "int foo(...)");
    }

    #[test]
    fn prototype_string_renders_void_for_no_parameters() {
        let mut def = sample(false, false);
        def.params.clear();
        assert_eq!(def.function_definition_db_prototype_string(false), "int foo(void)");
    }

    #[test]
    fn prototype_string_includes_no_return_and_known_calling_convention() {
        let mut def = sample(false, true);
        def.calling_convention = "__stdcall".to_string();
        assert_eq!(
            def.function_definition_db_prototype_string(true),
            "noreturn int __stdcall foo(int a, char b)"
        );
    }

    #[test]
    fn refresh_detects_deletion() {
        let mut def = sample(false, false);
        def.deleted = true;
        assert!(!def.refresh(None));
    }
}

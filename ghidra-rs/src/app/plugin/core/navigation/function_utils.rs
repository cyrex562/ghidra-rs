//! Port of `ghidra.app.plugin.core.navigation.FunctionUtils`.
//!
//! Java's version is a statics-only utility class (implicit default constructor, no instance
//! state); this port represents that directly as a module of free functions rather than a
//! zero-instance struct, per this crate's convention for statics holders.

use crate::app::util::viewer::field::field_string_info::FieldStringInfo;
use crate::program::model::listing::Function;
use crate::program::model::listing::function::UNKNOWN_CALLING_CONVENTION_STRING;
use crate::program::model::symbol::Namespace;

/// Returns a [`FieldStringInfo`] for the given function's return type. This info contains the
/// return type string and its location in the function signature.
///
/// Port of `FunctionUtils.getFunctionReturnTypeStringInfo(Function, String)`.
///
/// # Panics
/// Panics if `function.get_return_type()` is `None`. Real Ghidra functions always carry a
/// (possibly `undefined`) return type; Java's `function.getReturnType().getName()` is called
/// unchecked here too, so an absent return type would `NullPointerException` there just the same.
pub fn get_function_return_type_string_info(
    function: &dyn Function,
    function_signature_string: &str,
) -> FieldStringInfo {
    let return_type = function
        .get_return_type()
        .expect("function has no return type (Java: unchecked NullPointerException here)");
    FieldStringInfo::new(function_signature_string, return_type.get_name(), 0)
}

/// Returns a [`FieldStringInfo`] for the given function's name. This info contains the name
/// string and its location in the function signature.
///
/// Port of `FunctionUtils.getFunctionNameStringInfo(Function, String)`.
pub fn get_function_name_string_info(
    function: &dyn Function,
    function_signature_string: &str,
) -> FieldStringInfo {
    let mut function_name = qualified_function_name(function);

    // check for fully-qualified name
    let mut offset = index_of(function_signature_string, &function_name);
    if offset == -1 {
        function_name = Function::get_name(function);
        offset = index_of(function_signature_string, &function_name);
    }

    FieldStringInfo::new(function_signature_string, function_name, offset)
}

/// Port of `function.getName(true)`: the function's name prefixed with its full parent namespace
/// path.
///
/// Java's `Function` (via `Symbol`) has a single `getName(boolean)` that both the namespace path
/// walk and the leaf name come from. This crate splits that in two: [`Function::get_name`] (this
/// function's own name) and, inherited from [`Namespace`],
/// [`Namespace::get_name_with_path`]/[`Namespace::get_path_list`] (which -- being defined on
/// `Namespace`, not `Function` -- build their path using *`Namespace::get_name`*, a distinct
/// trait method that a concrete `Function` implementor is not required to keep in sync with its
/// own `Function::get_name` override). Rather than risk that mismatch for the leaf element, this
/// walks the parent chain directly, using [`Function::get_name`] only for the function itself and
/// [`Namespace::get_name`] (via each ancestor's `Namespace` object, which are never `Function`s
/// themselves in practice) for every ancestor -- the same algorithm
/// [`Namespace::get_path_list`]'s default implementation uses internally.
fn qualified_function_name(function: &dyn Function) -> String {
    let mut parts = vec![Function::get_name(function)];
    let mut current = function.get_parent_namespace();
    while let Some(namespace) = current {
        if namespace.is_global() {
            break;
        }
        parts.push(namespace.get_name());
        current = namespace.get_parent_namespace();
    }
    parts.reverse();
    parts.join(crate::program::model::symbol::DELIMITER)
}

/// Port of `FunctionUtils.getCallingConventionSignatureOffset(Function)`.
pub fn get_calling_convention_signature_offset(function: &dyn Function) -> i32 {
    let Some(calling_convention) = function.get_calling_convention() else {
        return 0;
    };
    let Some(calling_convention_name) = calling_convention.get_name() else {
        return 0;
    };
    if calling_convention_name == UNKNOWN_CALLING_CONVENTION_STRING {
        return 0;
    }
    calling_convention_name.len() as i32 + 1
}

/// Returns a [`FieldStringInfo`] for each of the given function's parameters. Each returned
/// [`FieldStringInfo`] contains a single string, retrievable from
/// [`FieldStringInfo::field_string`], that is a space-separated combination of the parameter's
/// datatype and name.
///
/// Port of `FunctionUtils.getFunctionParameterStringInfos(Function, String)`.
pub fn get_function_parameter_string_infos(
    function: &dyn Function,
    function_signature_string: &str,
) -> Vec<FieldStringInfo> {
    let arguments = function.get_parameters();

    let mut start_index = index_of(function_signature_string, "(") + 1;
    let mut list = Vec::new();
    for parameter in &arguments {
        let data_type_name = parameter.get_data_type().get_display_name();
        let parameter_name = parameter.get_name().unwrap_or_default();

        start_index = index_of_from(function_signature_string, &data_type_name, start_index);
        list.push(FieldStringInfo::new(
            function_signature_string,
            format!("{data_type_name} {parameter_name}"),
            start_index,
        ));

        // push the starting point past the name of the current parameter
        start_index =
            index_of_from(function_signature_string, &parameter_name, start_index) + parameter_name.len() as i32;
    }

    list
}

/// Mirrors `String.indexOf(String)`: the byte offset of the first occurrence of `needle` in
/// `haystack`, or `-1` if absent. Returns a sentinel `i32` rather than `Option<usize>` since
/// every caller here stores the result straight into a [`FieldStringInfo`] without checking, the
/// same as Java's unchecked use of `indexOf`'s `-1` sentinel.
fn index_of(haystack: &str, needle: &str) -> i32 {
    index_of_from(haystack, needle, 0)
}

/// Mirrors `String.indexOf(String, int fromIndex)`: like [`index_of`], but starting the search at
/// byte offset `from_index` (clamped to `0`, matching Java's clamping of a negative `fromIndex`).
fn index_of_from(haystack: &str, needle: &str, from_index: i32) -> i32 {
    let start = from_index.max(0) as usize;
    match haystack.get(start..) {
        Some(slice) => slice.find(needle).map_or(-1, |pos| (start + pos) as i32),
        None => -1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSetView, AddressSpace, AddressSpaceType};
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::lang::prototype_model::PrototypeModel;
    use crate::program::model::listing::function::{SetFunctionNameError, UNKNOWN_CALLING_CONVENTION_STRING};
    use crate::program::model::listing::variable_storage::VariableStorage;
    use crate::program::model::listing::{
        AutoParameterType, FunctionSignature, FunctionTag, FunctionUpdateType, Parameter, Program, Variable,
    };
    use crate::program::model::symbol::{Namespace, SetParentNamespaceError, SourceType, Symbol, SymbolType};
    use crate::program::model::listing::variable::SetVariableNameError;
    use crate::util::exception::InvalidInputException;
    use crate::util::task::TaskMonitor;
    use std::cmp::Ordering;
    use std::sync::Arc;

    struct MockDataType {
        name: String,
        display_name: String,
    }
    impl DataType for MockDataType {
        fn get_name(&self) -> String {
            self.name.clone()
        }
        fn get_display_name(&self) -> String {
            self.display_name.clone()
        }
    }
    fn mock_data_type(name: &str) -> MockDataType {
        MockDataType { name: name.to_string(), display_name: name.to_string() }
    }

    struct MockProgram;
    impl crate::framework::model::DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock_program".to_string()
        }
        fn get_language_id(&self) -> String {
            "mock:LE:32:default".to_string()
        }
    }

    struct MockSymbol {
        name: String,
    }
    impl Symbol for MockSymbol {
        fn get_address(&self) -> Address {
            ram_address(0)
        }
        fn get_name(&self) -> &str {
            &self.name
        }
        fn get_symbol_type(&self) -> SymbolType {
            SymbolType::Function
        }
        fn get_source(&self) -> SourceType {
            SourceType::UserDefined
        }
        fn is_primary(&self) -> bool {
            true
        }
        fn get_id(&self) -> i64 {
            1
        }
        fn get_parent_id(&self) -> i64 {
            0
        }
    }

    /// A namespace with a name and, optionally, a further parent -- enough to exercise
    /// `qualified_function_name`'s ancestor walk.
    struct MockNamespace {
        name: String,
        parent: Option<Arc<dyn Namespace>>,
    }
    impl Namespace for MockNamespace {
        fn get_symbol(&self) -> Arc<dyn Symbol> {
            Arc::new(MockSymbol { name: self.name.clone() })
        }
        fn get_name(&self) -> String {
            self.name.clone()
        }
        fn get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
            self.parent.clone()
        }
    }

    struct MockPrototypeModel {
        name: Option<String>,
    }
    impl PrototypeModel for MockPrototypeModel {
        fn get_name(&self) -> Option<String> {
            self.name.clone()
        }
    }

    /// A minimal [`Variable`]/[`Parameter`] pair, following the same shape as `variable.rs`'s own
    /// `MockVariable` test double.
    struct MockParameter {
        data_type_name: String,
        name: Option<String>,
    }

    impl Variable for MockParameter {
        fn get_data_type(&self) -> Box<dyn DataType> {
            Box::new(mock_data_type(&self.data_type_name))
        }
        fn set_data_type_with_storage(
            &mut self,
            _data_type: Box<dyn DataType>,
            _storage: Box<dyn VariableStorage>,
            _force: bool,
            _source: SourceType,
        ) -> Result<(), InvalidInputException> {
            Ok(())
        }
        fn set_data_type(
            &mut self,
            _data_type: Box<dyn DataType>,
            _source: SourceType,
        ) -> Result<(), InvalidInputException> {
            Ok(())
        }
        fn set_data_type_aligned(
            &mut self,
            _data_type: Box<dyn DataType>,
            _align_stack: bool,
            _force: bool,
            _source: SourceType,
        ) -> Result<(), InvalidInputException> {
            Ok(())
        }
        fn get_name(&self) -> Option<String> {
            self.name.clone()
        }
        fn get_length(&self) -> i32 {
            self.data_type_name.len() as i32
        }
        fn is_valid(&self) -> bool {
            true
        }
        fn get_function(&self) -> Option<Box<dyn Function>> {
            None
        }
        fn get_program(&self) -> Arc<dyn Program> {
            Arc::new(MockProgram)
        }
        fn get_source(&self) -> SourceType {
            SourceType::UserDefined
        }
        fn set_name(&mut self, name: &str, _source: SourceType) -> Result<(), SetVariableNameError> {
            self.name = Some(name.to_string());
            Ok(())
        }
        fn get_comment(&self) -> Option<String> {
            None
        }
        fn set_comment(&mut self, _comment: Option<String>) {}
        fn get_variable_storage(&self) -> Option<Box<dyn VariableStorage>> {
            None
        }
        fn get_first_storage_varnode(&self) -> Option<crate::program::model::pcode::Varnode> {
            None
        }
        fn get_last_storage_varnode(&self) -> Option<crate::program::model::pcode::Varnode> {
            None
        }
        fn is_stack_variable(&self) -> bool {
            false
        }
        fn has_stack_storage(&self) -> bool {
            false
        }
        fn is_register_variable(&self) -> bool {
            false
        }
        fn get_register(&self) -> Option<crate::program::model::lang::RegisterRef> {
            None
        }
        fn get_registers(&self) -> Option<Vec<crate::program::model::lang::RegisterRef>> {
            None
        }
        fn get_min_address(&self) -> Option<Address> {
            None
        }
        fn get_stack_offset(
            &self,
        ) -> Result<i32, crate::program::model::listing::variable::UnsupportedOperationError> {
            Err(crate::program::model::listing::variable::UnsupportedOperationError(
                "not a simple stack variable".to_string(),
            ))
        }
        fn is_memory_variable(&self) -> bool {
            false
        }
        fn is_unique_variable(&self) -> bool {
            false
        }
        fn is_compound_variable(&self) -> bool {
            false
        }
        fn has_assigned_storage(&self) -> bool {
            false
        }
        fn get_first_use_offset(&self) -> i32 {
            0
        }
        fn get_symbol(&self) -> Option<Arc<dyn Symbol>> {
            None
        }
        fn is_equivalent(&self, variable: &dyn Variable) -> bool {
            self.get_name() == variable.get_name()
        }
        fn compare_to(&self, other: &dyn Variable) -> Ordering {
            self.get_name().cmp(&other.get_name())
        }
    }

    impl Parameter for MockParameter {
        fn get_ordinal(&self) -> i32 {
            0
        }
        fn is_auto_parameter(&self) -> bool {
            false
        }
        fn get_auto_parameter_type(&self) -> Option<AutoParameterType> {
            None
        }
        fn is_forced_indirect(&self) -> bool {
            false
        }
        fn get_formal_data_type(&self) -> Box<dyn DataType> {
            self.get_data_type()
        }
    }

    struct MockFunction {
        name: String,
        parent: Option<Arc<dyn Namespace>>,
        return_type: Option<String>,
        calling_convention: Option<Option<String>>,
        parameters: Vec<(String, Option<String>)>,
    }

    impl Namespace for MockFunction {
        fn get_symbol(&self) -> Arc<dyn Symbol> {
            Arc::new(MockSymbol { name: self.name.clone() })
        }
        fn get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
            self.parent.clone()
        }
    }

    impl Function for MockFunction {
        fn get_name(&self) -> String {
            self.name.clone()
        }
        fn set_name(&mut self, _name: &str, _source: SourceType) -> Result<(), SetFunctionNameError> {
            Ok(())
        }
        fn set_call_fixup(&mut self, _name: Option<&str>) {}
        fn get_call_fixup(&self) -> Option<String> {
            None
        }
        fn get_program(&self) -> Arc<dyn Program> {
            Arc::new(MockProgram)
        }
        fn get_comment(&self) -> Option<String> {
            None
        }
        fn get_comment_as_array(&self) -> Vec<String> {
            Vec::new()
        }
        fn set_comment(&mut self, _comment: Option<&str>) {}
        fn get_repeatable_comment(&self) -> Option<String> {
            None
        }
        fn get_repeatable_comment_as_array(&self) -> Vec<String> {
            Vec::new()
        }
        fn set_repeatable_comment(&mut self, _comment: Option<&str>) {}
        fn get_entry_point(&self) -> Address {
            ram_address(0x1000)
        }
        fn get_return_type(&self) -> Option<Box<dyn DataType>> {
            self.return_type.as_deref().map(|n| Box::new(mock_data_type(n)) as Box<dyn DataType>)
        }
        fn set_return_type(
            &mut self,
            _data_type: Box<dyn DataType>,
            _source: SourceType,
        ) -> Result<(), InvalidInputException> {
            Ok(())
        }
        fn get_return(&self) -> Box<dyn Parameter> {
            unimplemented!("not exercised by this test")
        }
        fn set_return(
            &mut self,
            _data_type: Box<dyn DataType>,
            _storage: Box<dyn VariableStorage>,
            _source: SourceType,
        ) -> Result<(), InvalidInputException> {
            Ok(())
        }
        fn get_signature_formal(&self, _formal_signature: bool) -> Box<dyn FunctionSignature> {
            unimplemented!("not exercised by this test")
        }
        fn get_prototype_string(&self, _formal_signature: bool, _include_calling_convention: bool) -> String {
            String::new()
        }
        fn get_signature_source(&self) -> SourceType {
            SourceType::UserDefined
        }
        fn set_signature_source(&mut self, _signature_source: SourceType) {}
        fn get_stack_frame(&self) -> Box<dyn crate::program::seam_stubs::StackFrame> {
            unimplemented!("not exercised by this test")
        }
        fn get_stack_purge_size(&self) -> i32 {
            0
        }
        fn get_tags(&self) -> Vec<Box<dyn FunctionTag>> {
            Vec::new()
        }
        fn add_tag(&mut self, _name: &str) -> bool {
            false
        }
        fn remove_tag(&mut self, _name: &str) {}
        fn set_stack_purge_size(&mut self, _purge_size: i32) {}
        fn is_stack_purge_size_valid(&self) -> bool {
            false
        }
        #[allow(deprecated)]
        fn add_parameter(
            &mut self,
            _var: Box<dyn Variable>,
            _source: SourceType,
        ) -> Result<Box<dyn Parameter>, crate::program::model::listing::function::FunctionEditError> {
            unimplemented!("not exercised by this test")
        }
        #[allow(deprecated)]
        fn insert_parameter(
            &mut self,
            _ordinal: i32,
            _var: Box<dyn Variable>,
            _source: SourceType,
        ) -> Result<Box<dyn Parameter>, crate::program::model::listing::function::FunctionEditError> {
            unimplemented!("not exercised by this test")
        }
        fn replace_parameters(
            &mut self,
            _params: Vec<Box<dyn Variable>>,
            _update_type: FunctionUpdateType,
            _force: bool,
            _source: SourceType,
        ) -> Result<(), crate::program::model::listing::function::FunctionEditError> {
            Ok(())
        }
        fn update_function(
            &mut self,
            _calling_convention: Option<&str>,
            _return_value: Option<Box<dyn Variable>>,
            _new_params: Vec<Box<dyn Variable>>,
            _update_type: FunctionUpdateType,
            _force: bool,
            _source: SourceType,
        ) -> Result<(), crate::program::model::listing::function::FunctionEditError> {
            Ok(())
        }
        fn get_parameter(&self, _ordinal: i32) -> Option<Box<dyn Parameter>> {
            None
        }
        #[allow(deprecated)]
        fn remove_parameter(&mut self, _ordinal: i32) {}
        #[allow(deprecated)]
        fn move_parameter(
            &mut self,
            _from_ordinal: i32,
            _to_ordinal: i32,
        ) -> Result<Box<dyn Parameter>, InvalidInputException> {
            unimplemented!("not exercised by this test")
        }
        fn get_parameter_count(&self) -> i32 {
            self.parameters.len() as i32
        }
        fn get_auto_parameter_count(&self) -> i32 {
            0
        }
        fn get_parameters(&self) -> Vec<Box<dyn Parameter>> {
            self.parameters
                .iter()
                .map(|(type_name, name)| {
                    Box::new(MockParameter { data_type_name: type_name.clone(), name: name.clone() })
                        as Box<dyn Parameter>
                })
                .collect()
        }
        fn get_parameters_filtered(
            &self,
            _filter: Option<&dyn crate::program::seam_stubs::VariableFilter>,
        ) -> Vec<Box<dyn Parameter>> {
            self.get_parameters()
        }
        fn get_local_variables(&self) -> Vec<Box<dyn Variable>> {
            Vec::new()
        }
        fn get_local_variables_filtered(
            &self,
            _filter: Option<&dyn crate::program::seam_stubs::VariableFilter>,
        ) -> Vec<Box<dyn Variable>> {
            Vec::new()
        }
        fn get_variables_filtered(
            &self,
            _filter: Option<&dyn crate::program::seam_stubs::VariableFilter>,
        ) -> Vec<Box<dyn Variable>> {
            Vec::new()
        }
        fn get_all_variables(&self) -> Vec<Box<dyn Variable>> {
            Vec::new()
        }
        fn add_local_variable(
            &mut self,
            _var: Box<dyn Variable>,
            _source: SourceType,
        ) -> Result<Box<dyn Variable>, crate::program::model::listing::function::FunctionEditError> {
            unimplemented!("not exercised by this test")
        }
        fn remove_variable(&mut self, _var: &dyn Variable) {}
        fn set_body(
            &mut self,
            _new_body: &dyn AddressSetView,
        ) -> Result<(), crate::program::database::function::OverlappingFunctionException> {
            Ok(())
        }
        fn has_var_args(&self) -> bool {
            false
        }
        fn set_var_args(&mut self, _has_var_args: bool) {}
        fn is_inline(&self) -> bool {
            false
        }
        fn set_inline(&mut self, _is_inline: bool) {}
        fn has_no_return(&self) -> bool {
            false
        }
        fn set_no_return(&mut self, _has_no_return: bool) {}
        fn has_custom_variable_storage(&self) -> bool {
            false
        }
        fn set_custom_variable_storage(&mut self, _has_custom_variable_storage: bool) {}
        fn get_calling_convention(&self) -> Option<Box<dyn PrototypeModel>> {
            self.calling_convention
                .clone()
                .map(|name| Box::new(MockPrototypeModel { name }) as Box<dyn PrototypeModel>)
        }
        fn get_calling_convention_name(&self) -> String {
            self.calling_convention
                .clone()
                .flatten()
                .unwrap_or_else(|| UNKNOWN_CALLING_CONVENTION_STRING.to_string())
        }
        fn set_calling_convention(&mut self, _name: &str) -> Result<(), InvalidInputException> {
            Ok(())
        }
        fn is_thunk(&self) -> bool {
            false
        }
        fn get_thunked_function(&self, _recursive: bool) -> Option<Arc<dyn Function>> {
            None
        }
        fn get_function_thunk_addresses(&self, _recursive: bool) -> Option<Vec<Address>> {
            None
        }
        fn set_thunked_function(&mut self, _thunked_function: Option<Arc<dyn Function>>) -> Result<(), String> {
            Ok(())
        }
        fn is_external(&self) -> bool {
            false
        }
        fn get_external_location(&self) -> Option<Box<dyn crate::program::model::symbol::ExternalLocation>> {
            None
        }
        fn get_calling_functions(&self, _monitor: &dyn TaskMonitor) -> Vec<Arc<dyn Function>> {
            Vec::new()
        }
        fn get_called_functions(&self, _monitor: &dyn TaskMonitor) -> Vec<Arc<dyn Function>> {
            Vec::new()
        }
        fn promote_local_user_labels_to_global(&mut self) {}
        fn is_deleted(&self) -> bool {
            false
        }
    }

    fn ram_address(offset: i64) -> Address {
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        Address::new(ram, offset)
    }

    fn simple_function(name: &str) -> MockFunction {
        MockFunction {
            name: name.to_string(),
            parent: None,
            return_type: Some("void".to_string()),
            calling_convention: None,
            parameters: Vec::new(),
        }
    }

    #[test]
    fn return_type_string_info_uses_the_return_types_name_at_offset_zero() {
        let function = simple_function("myFunction");
        let info = get_function_return_type_string_info(&function, "void myFunction(void)");
        assert_eq!(info.field_string(), "void");
        assert_eq!(info.offset(), 0);
    }

    #[test]
    #[should_panic(expected = "function has no return type")]
    fn return_type_string_info_panics_without_a_return_type() {
        let mut function = simple_function("myFunction");
        function.return_type = None;
        let _ = get_function_return_type_string_info(&function, "void myFunction(void)");
    }

    #[test]
    fn name_string_info_finds_the_simple_name_when_no_namespace() {
        let function = simple_function("myFunction");
        let info = get_function_name_string_info(&function, "void myFunction(void)");
        assert_eq!(info.field_string(), "myFunction");
        assert_eq!(info.offset(), 5);
    }

    #[test]
    fn name_string_info_prefers_the_fully_qualified_name_when_present_in_the_signature() {
        let parent = Arc::new(MockNamespace { name: "MyClass".to_string(), parent: None });
        let function = MockFunction {
            name: "myMethod".to_string(),
            parent: Some(parent),
            return_type: Some("void".to_string()),
            calling_convention: None,
            parameters: Vec::new(),
        };

        let info = get_function_name_string_info(&function, "void MyClass::myMethod(void)");
        assert_eq!(info.field_string(), "MyClass::myMethod");
        assert_eq!(info.offset(), 5);
    }

    #[test]
    fn name_string_info_falls_back_to_the_simple_name_when_the_qualified_name_is_absent() {
        let parent = Arc::new(MockNamespace { name: "MyClass".to_string(), parent: None });
        let function = MockFunction {
            name: "myMethod".to_string(),
            parent: Some(parent),
            return_type: Some("void".to_string()),
            calling_convention: None,
            parameters: Vec::new(),
        };

        // Signature was rendered without the namespace prefix.
        let info = get_function_name_string_info(&function, "void myMethod(void)");
        assert_eq!(info.field_string(), "myMethod");
        assert_eq!(info.offset(), 5);
    }

    #[test]
    fn calling_convention_offset_is_zero_with_no_calling_convention() {
        let function = simple_function("f");
        assert_eq!(get_calling_convention_signature_offset(&function), 0);
    }

    #[test]
    fn calling_convention_offset_is_zero_for_unknown_calling_convention() {
        let mut function = simple_function("f");
        function.calling_convention = Some(Some(UNKNOWN_CALLING_CONVENTION_STRING.to_string()));
        assert_eq!(get_calling_convention_signature_offset(&function), 0);
    }

    #[test]
    fn calling_convention_offset_is_name_length_plus_one() {
        let mut function = simple_function("f");
        function.calling_convention = Some(Some("__stdcall".to_string()));
        assert_eq!(get_calling_convention_signature_offset(&function), "__stdcall".len() as i32 + 1);
    }

    #[test]
    fn parameter_string_infos_cover_each_parameter_in_order() {
        let mut function = simple_function("add");
        function.parameters =
            vec![("int".to_string(), Some("a".to_string())), ("int".to_string(), Some("b".to_string()))];

        let signature = "int add(int a, int b)";
        let infos = get_function_parameter_string_infos(&function, signature);

        // Java's real search starts just past the '(' (index 8 here), not from the start of the
        // signature -- a plain `signature.find("int a")` would wrongly match the "int a" that's
        // a literal prefix of "int add(" itself, at offset 0.
        assert_eq!(infos.len(), 2);
        assert_eq!(infos[0].field_string(), "int a");
        assert_eq!(infos[0].offset(), 8);
        assert_eq!(infos[1].field_string(), "int b");
        assert_eq!(infos[1].offset(), signature.rfind("int b").unwrap() as i32);
    }

    #[test]
    fn parameter_string_infos_is_empty_for_a_function_with_no_parameters() {
        let function = simple_function("noop");
        let infos = get_function_parameter_string_infos(&function, "void noop(void)");
        assert!(infos.is_empty());
    }

    #[test]
    fn index_of_matches_javas_string_index_of() {
        assert_eq!(index_of("hello world", "world"), 6);
        assert_eq!(index_of("hello world", "xyz"), -1);
    }

    #[test]
    fn index_of_from_matches_javas_string_index_of_with_from_index() {
        assert_eq!(index_of_from("aXbXc", "X", 2), 3);
        assert_eq!(index_of_from("aXbXc", "X", -5), 1);
        assert_eq!(index_of_from("abc", "z", 0), -1);
    }
}

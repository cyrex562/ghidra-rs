use std::cmp::Ordering;
use std::fmt;
use std::sync::Arc;

use crate::docking::widgets::table::DisplayStringProvider;
use crate::feature::vt::gui::editors::DisplayableOffset;
use crate::program::model::address::{Address, SpecialAddress};
use crate::program::model::listing::Function;

/// A displayable offset for a variable's storage address within a function.
///
/// Corresponds to `ghidra.feature.vt.gui.provider.markuptable.DisplayableVariableOffset`
/// in the Java source.
pub struct DisplayableVariableOffset {
    function: Arc<dyn Function>,
    parameter_address: Option<Address>,
    offset: i64,
    offset_as_big_integer: Option<i128>,
}

impl DisplayableVariableOffset {
    /// Creates a new displayable variable offset for `parameter_address` within `function`.
    ///
    /// `parameter_address` mirrors Java's nullable `Address` parameter; `None` corresponds
    /// to a null address, in which case the offset defaults to zero.
    pub fn new(function: Arc<dyn Function>, parameter_address: Option<Address>) -> Self {
        let offset = parameter_address.as_ref().map(|a| a.offset()).unwrap_or(0);
        let offset_as_big_integer = parameter_address
            .as_ref()
            .map(|a| a.unsigned_offset() as i128);
        Self {
            function,
            parameter_address,
            offset,
            offset_as_big_integer,
        }
    }

    /// Returns the function this variable offset belongs to.
    pub fn function(&self) -> &Arc<dyn Function> {
        &self.function
    }
}

impl DisplayStringProvider for DisplayableVariableOffset {
    fn display_string(&self) -> String {
        match &self.parameter_address {
            Some(address) if *address != SpecialAddress::no_address() => address.to_string(),
            _ => Self::NO_OFFSET.to_string(),
        }
    }
}

impl fmt::Display for DisplayableVariableOffset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.display_string())
    }
}

impl DisplayableOffset for DisplayableVariableOffset {
    fn get_address(&self) -> Address {
        self.parameter_address
            .clone()
            .unwrap_or_else(SpecialAddress::no_address)
    }

    fn get_offset(&self) -> i64 {
        self.offset
    }

    fn get_offset_as_big_integer(&self) -> i128 {
        self.offset_as_big_integer.unwrap_or(0)
    }
}

impl PartialEq for DisplayableVariableOffset {
    fn eq(&self, other: &Self) -> bool {
        self.parameter_address == other.parameter_address
    }
}

impl Eq for DisplayableVariableOffset {}

impl PartialOrd for DisplayableVariableOffset {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for DisplayableVariableOffset {
    fn cmp(&self, other: &Self) -> Ordering {
        match (&self.parameter_address, &other.parameter_address) {
            (None, None) => Ordering::Equal,
            (None, Some(_)) => Ordering::Less,
            (Some(_), None) => Ordering::Greater,
            (Some(a), Some(b)) => a.cmp(b),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::database::function::OverlappingFunctionException;
    use crate::program::model::address::{AddressSetView, AddressSpace, AddressSpaceType};
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::listing::function::{
        FunctionEditError, FunctionUpdateType, SetFunctionNameError,
        UNKNOWN_CALLING_CONVENTION_STRING,
    };
    use crate::program::model::listing::{FunctionSignature, FunctionTag, Parameter, Program, Variable};
    use crate::program::model::symbol::{ExternalLocation, Namespace, SourceType, Symbol};
    use crate::program::seam_stubs::{PrototypeModel, StackFrame, VariableFilter, VariableStorage};
    use crate::util::exception::InvalidInputException;
    use crate::util::task::TaskMonitor;

    struct MockSymbol;

    impl Symbol for MockSymbol {
        fn get_address(&self) -> Address {
            unimplemented!()
        }

        fn get_name(&self) -> &str {
            "mock"
        }

        fn get_symbol_type(&self) -> crate::program::model::symbol::SymbolType {
            crate::program::model::symbol::SymbolType::Function
        }

        fn get_source(&self) -> crate::program::model::symbol::SourceType {
            crate::program::model::symbol::SourceType::UserDefined
        }

        fn is_primary(&self) -> bool {
            true
        }

        fn get_id(&self) -> i64 {
            0
        }

        fn get_parent_id(&self) -> i64 {
            0
        }
    }

    struct MockFunction;

    impl Namespace for MockFunction {
        fn get_symbol(&self) -> Arc<dyn Symbol> {
            Arc::new(MockSymbol)
        }

        fn get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
            None
        }
    }

    impl Function for MockFunction {
        fn get_name(&self) -> String {
            "mock_function".to_string()
        }

        fn set_name(
            &mut self,
            _name: &str,
            _source: SourceType,
        ) -> Result<(), SetFunctionNameError> {
            Ok(())
        }

        fn set_call_fixup(&mut self, _name: Option<&str>) {}

        fn get_call_fixup(&self) -> Option<String> {
            None
        }

        fn get_program(&self) -> Arc<dyn Program> {
            struct MockProgram;
            impl crate::framework::model::DomainObject for MockProgram {}
            impl Program for MockProgram {
                fn get_name(&self) -> String {
                    "mock".to_string()
                }
                fn get_language_id(&self) -> String {
                    "mock:LE:32:default".to_string()
                }
            }
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
            unimplemented!()
        }

        fn get_return_type(&self) -> Option<Box<dyn DataType>> {
            None
        }

        fn set_return_type(
            &mut self,
            _data_type: Box<dyn DataType>,
            _source: SourceType,
        ) -> Result<(), InvalidInputException> {
            Ok(())
        }

        fn get_return(&self) -> Box<dyn Parameter> {
            unimplemented!()
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
            unimplemented!()
        }

        fn get_prototype_string(
            &self,
            _formal_signature: bool,
            _include_calling_convention: bool,
        ) -> String {
            "mock_function".to_string()
        }

        fn get_signature_source(&self) -> SourceType {
            SourceType::UserDefined
        }

        fn set_signature_source(&mut self, _signature_source: SourceType) {}

        fn get_stack_frame(&self) -> Box<dyn StackFrame> {
            unimplemented!()
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
        ) -> Result<Box<dyn Parameter>, FunctionEditError> {
            unimplemented!()
        }

        #[allow(deprecated)]
        fn insert_parameter(
            &mut self,
            _ordinal: i32,
            _var: Box<dyn Variable>,
            _source: SourceType,
        ) -> Result<Box<dyn Parameter>, FunctionEditError> {
            unimplemented!()
        }

        fn replace_parameters(
            &mut self,
            _params: Vec<Box<dyn Variable>>,
            _update_type: FunctionUpdateType,
            _force: bool,
            _source: SourceType,
        ) -> Result<(), FunctionEditError> {
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
        ) -> Result<(), FunctionEditError> {
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
            unimplemented!()
        }

        fn get_parameter_count(&self) -> i32 {
            0
        }

        fn get_auto_parameter_count(&self) -> i32 {
            0
        }

        fn get_parameters(&self) -> Vec<Box<dyn Parameter>> {
            Vec::new()
        }

        fn get_parameters_filtered(&self, _filter: Option<&dyn VariableFilter>) -> Vec<Box<dyn Parameter>> {
            Vec::new()
        }

        fn get_local_variables(&self) -> Vec<Box<dyn Variable>> {
            Vec::new()
        }

        fn get_local_variables_filtered(
            &self,
            _filter: Option<&dyn VariableFilter>,
        ) -> Vec<Box<dyn Variable>> {
            Vec::new()
        }

        fn get_variables_filtered(&self, _filter: Option<&dyn VariableFilter>) -> Vec<Box<dyn Variable>> {
            Vec::new()
        }

        fn get_all_variables(&self) -> Vec<Box<dyn Variable>> {
            Vec::new()
        }

        fn add_local_variable(
            &mut self,
            _var: Box<dyn Variable>,
            _source: SourceType,
        ) -> Result<Box<dyn Variable>, FunctionEditError> {
            unimplemented!()
        }

        fn remove_variable(&mut self, _var: &dyn Variable) {}

        fn set_body(
            &mut self,
            _new_body: &dyn AddressSetView,
        ) -> Result<(), OverlappingFunctionException> {
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
            None
        }

        fn get_calling_convention_name(&self) -> String {
            UNKNOWN_CALLING_CONVENTION_STRING.to_string()
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

        fn set_thunked_function(
            &mut self,
            _thunked_function: Option<Arc<dyn Function>>,
        ) -> Result<(), String> {
            Ok(())
        }

        fn is_external(&self) -> bool {
            false
        }

        fn get_external_location(&self) -> Option<Box<dyn ExternalLocation>> {
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

    fn mock_function() -> Arc<dyn Function> {
        Arc::new(MockFunction)
    }

    #[test]
    fn new_with_some_address_computes_offset_fields() {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let addr = space.address(0x1000);

        let displayable = DisplayableVariableOffset::new(mock_function(), Some(addr.clone()));

        assert_eq!(displayable.get_offset(), 0x1000);
        assert_eq!(displayable.get_offset_as_big_integer(), 0x1000i128);
        assert_eq!(displayable.get_address(), addr);
    }

    #[test]
    fn new_with_none_address_defaults_offset_to_zero() {
        let displayable = DisplayableVariableOffset::new(mock_function(), None);

        assert_eq!(displayable.get_offset(), 0);
        assert_eq!(displayable.get_offset_as_big_integer(), 0);
        assert_eq!(displayable.get_address(), SpecialAddress::no_address());
    }

    #[test]
    fn display_string_is_no_offset_when_address_missing() {
        let displayable = DisplayableVariableOffset::new(mock_function(), None);

        assert_eq!(displayable.display_string(), DisplayableVariableOffset::NO_OFFSET);
        assert_eq!(displayable.to_string(), DisplayableVariableOffset::NO_OFFSET);
    }

    #[test]
    fn display_string_is_no_offset_for_sentinel_no_address() {
        let displayable =
            DisplayableVariableOffset::new(mock_function(), Some(SpecialAddress::no_address()));

        assert_eq!(displayable.display_string(), DisplayableVariableOffset::NO_OFFSET);
    }

    #[test]
    fn display_string_uses_address_to_string() {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let addr = space.address(0x2000);

        let displayable = DisplayableVariableOffset::new(mock_function(), Some(addr.clone()));

        assert_eq!(displayable.display_string(), addr.to_string());
    }

    #[test]
    fn compare_to_orders_none_before_some() {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let addr = space.address(0x1000);

        let none_offset = DisplayableVariableOffset::new(mock_function(), None);
        let some_offset = DisplayableVariableOffset::new(mock_function(), Some(addr));

        assert_eq!(none_offset.cmp(&some_offset), Ordering::Less);
        assert_eq!(some_offset.cmp(&none_offset), Ordering::Greater);
    }

    #[test]
    fn compare_to_treats_both_none_as_equal() {
        let a = DisplayableVariableOffset::new(mock_function(), None);
        let b = DisplayableVariableOffset::new(mock_function(), None);

        assert_eq!(a.cmp(&b), Ordering::Equal);
        assert!(a == b);
    }

    #[test]
    fn compare_to_delegates_to_address_ordering() {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let low = DisplayableVariableOffset::new(mock_function(), Some(space.address(0x1000)));
        let high = DisplayableVariableOffset::new(mock_function(), Some(space.address(0x2000)));

        assert_eq!(low.cmp(&high), Ordering::Less);
        assert!(low < high);
    }
}

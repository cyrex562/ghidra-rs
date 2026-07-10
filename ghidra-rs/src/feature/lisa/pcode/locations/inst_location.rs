use std::any::Any;
use std::cmp::Ordering;
use std::fmt;
use std::sync::Arc;

use crate::program::model::address::Address;
use crate::program::model::listing::Function;

use super::CodeLocation;

/// A code location within a function, identified by an instruction address.
///
/// InstLocation represents a specific instruction location within a function's
/// address space, used by the LiSA analysis framework to track program points.
///
/// Corresponds to `ghidra.lisa.pcode.locations.InstLocation` in the Java source.
#[derive(Clone)]
pub struct InstLocation {
    function: Arc<dyn Function>,
    addr: Address,
}

impl fmt::Debug for InstLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InstLocation")
            .field("addr", &self.addr)
            .field("function", &"<dyn Function>")
            .finish()
    }
}

impl InstLocation {
    /// Creates a new instruction location within the given function at the specified address.
    pub fn new(function: Arc<dyn Function>, addr: Address) -> Self {
        Self { function, addr }
    }

    /// Returns a reference to the function containing this instruction location.
    pub fn function(&self) -> &Arc<dyn Function> {
        &self.function
    }

    /// Returns the address of this instruction location.
    pub fn get_address(&self) -> &Address {
        &self.addr
    }
}

impl CodeLocation for InstLocation {
    fn compare_to(&self, other: &dyn CodeLocation) -> Ordering {
        if let Some(inst_loc) = other.as_any().downcast_ref::<InstLocation>() {
            self.addr.cmp(&inst_loc.addr)
        } else {
            Ordering::Less
        }
    }

    fn get_code_location(&self) -> String {
        self.addr.to_string()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl PartialEq for InstLocation {
    fn eq(&self, other: &Self) -> bool {
        self.addr == other.addr
    }
}

impl Eq for InstLocation {}

impl std::hash::Hash for InstLocation {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.addr.hash(state);
    }
}

impl PartialOrd for InstLocation {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for InstLocation {
    fn cmp(&self, other: &Self) -> Ordering {
        self.addr.cmp(&other.addr)
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
    use crate::program::model::listing::{
        FunctionSignature, FunctionTag, Parameter, Program, Variable,
    };
    use crate::program::model::symbol::{ExternalLocation, Namespace, SourceType, Symbol};
    use crate::program::seam_stubs::{PrototypeModel, StackFrame, VariableFilter, VariableStorage};
    use crate::util::exception::InvalidInputException;
    use crate::util::task::TaskMonitor;

    // Mock implementation of Function for testing
    struct MockFunction;

    impl Namespace for MockFunction {
        fn get_symbol(&self) -> Arc<dyn Symbol> {
            unimplemented!()
        }
        fn get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
            None
        }
    }

    impl Function for MockFunction {
        fn get_name(&self) -> String {
            "test_function".to_string()
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
            unimplemented!()
        }

        fn get_comment(&self) -> Option<String> {
            None
        }

        fn get_comment_as_array(&self) -> Vec<String> {
            vec![]
        }

        fn set_comment(&mut self, _comment: Option<&str>) {}

        fn get_repeatable_comment(&self) -> Option<String> {
            None
        }

        fn get_repeatable_comment_as_array(&self) -> Vec<String> {
            vec![]
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
            String::new()
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
            vec![]
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
            vec![]
        }

        fn get_parameters_filtered(&self, _filter: Option<&dyn VariableFilter>) -> Vec<Box<dyn Parameter>> {
            vec![]
        }

        fn get_local_variables(&self) -> Vec<Box<dyn Variable>> {
            vec![]
        }

        fn get_local_variables_filtered(
            &self,
            _filter: Option<&dyn VariableFilter>,
        ) -> Vec<Box<dyn Variable>> {
            vec![]
        }

        fn get_variables_filtered(&self, _filter: Option<&dyn VariableFilter>) -> Vec<Box<dyn Variable>> {
            vec![]
        }

        fn get_all_variables(&self) -> Vec<Box<dyn Variable>> {
            vec![]
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
            vec![]
        }

        fn get_called_functions(&self, _monitor: &dyn TaskMonitor) -> Vec<Arc<dyn Function>> {
            vec![]
        }

        fn promote_local_user_labels_to_global(&mut self) {}

        fn is_deleted(&self) -> bool {
            false
        }
    }

    #[test]
    fn inst_location_stores_function_and_address() {
        let ram = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 0);
        let addr = Address::new(ram.clone(), 0x1000);
        let func = Arc::new(MockFunction);

        let loc = InstLocation::new(func.clone(), addr.clone());

        assert_eq!(loc.get_address(), &addr);
    }

    #[test]
    fn code_location_returns_address_string() {
        let ram = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 0);
        let addr = Address::new(ram.clone(), 0x2000);
        let func = Arc::new(MockFunction);

        let loc = InstLocation::new(func, addr.clone());

        assert_eq!(loc.get_code_location(), addr.to_string());
    }

    #[test]
    fn inst_locations_compare_by_address() {
        let ram = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 0);
        let addr1 = Address::new(ram.clone(), 0x1000);
        let addr2 = Address::new(ram.clone(), 0x2000);
        let func = Arc::new(MockFunction);

        let loc1 = InstLocation::new(func.clone(), addr1);
        let loc2 = InstLocation::new(func, addr2);

        assert!(loc1 < loc2);
        assert_eq!(loc1.compare_to(&loc2 as &dyn CodeLocation), Ordering::Less);
    }

    #[test]
    fn inst_locations_with_same_address_are_equal() {
        let ram = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 0);
        let addr = Address::new(ram, 0x3000);
        let func = Arc::new(MockFunction);

        let loc1 = InstLocation::new(func.clone(), addr.clone());
        let loc2 = InstLocation::new(func, addr);

        assert_eq!(loc1, loc2);
    }

    #[test]
    fn inst_location_hash_is_based_on_address() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let ram = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 0);
        let addr = Address::new(ram.clone(), 0x4000);
        let func = Arc::new(MockFunction);

        let loc1 = InstLocation::new(func.clone(), addr.clone());
        let loc2 = InstLocation::new(func, addr);

        let mut hasher1 = DefaultHasher::new();
        loc1.hash(&mut hasher1);
        let hash1 = hasher1.finish();

        let mut hasher2 = DefaultHasher::new();
        loc2.hash(&mut hasher2);
        let hash2 = hasher2.finish();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn inst_location_clone_creates_independent_copy() {
        let ram = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 0);
        let addr = Address::new(ram, 0x5000);
        let func = Arc::new(MockFunction);

        let loc1 = InstLocation::new(func, addr.clone());
        let loc2 = loc1.clone();

        assert_eq!(loc1, loc2);
        assert_eq!(loc1.get_address(), loc2.get_address());
    }
}

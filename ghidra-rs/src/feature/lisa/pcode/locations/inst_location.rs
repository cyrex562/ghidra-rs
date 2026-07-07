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
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    // Mock implementation of Function for testing
    struct MockFunction;

    impl Function for MockFunction {
        fn get_name(&self) -> String {
            "test_function".to_string()
        }

        fn set_name(
            &mut self,
            _name: &str,
            _source: crate::program::model::symbol::SourceType,
        ) -> Result<(), crate::program::model::listing::SetFunctionNameError> {
            Ok(())
        }

        fn set_call_fixup(&mut self, _name: Option<&str>) {}

        fn get_call_fixup(&self) -> Option<String> {
            None
        }

        fn get_program(&self) -> Arc<dyn crate::program::model::listing::Program> {
            unimplemented!()
        }

        fn get_comment(&self) -> Option<String> {
            None
        }

        fn get_comment_as_array(&self) -> Vec<String> {
            vec![]
        }

        fn set_comment(&mut self, _comment: Option<&str>) {}

        fn get_entry_point(&self) -> Address {
            unimplemented!()
        }

        fn get_body(&self) -> crate::program::model::address::AddressSetView {
            unimplemented!()
        }

        fn contains(&self, _addr: &Address) -> bool {
            false
        }

        fn get_external_location(&self) -> Option<crate::program::seam_stubs::ExternalLocation> {
            None
        }

        fn is_external(&self) -> bool {
            false
        }

        fn get_signature(&self) -> Arc<dyn crate::program::model::listing::FunctionSignature> {
            unimplemented!()
        }

        fn replace_parameters(
            &mut self,
            _vars: Vec<Arc<dyn crate::program::model::listing::Variable>>,
            _update_type: crate::program::model::listing::FunctionUpdateType,
        ) -> Result<(), crate::program::model::listing::FunctionEditError> {
            Ok(())
        }

        fn get_parameters(&self) -> Vec<Arc<dyn crate::program::model::listing::Parameter>> {
            vec![]
        }

        fn add_local_variable(
            &mut self,
            _var: Arc<dyn crate::program::model::listing::Variable>,
        ) -> Result<Arc<dyn crate::program::model::listing::Variable>, crate::program::model::listing::FunctionEditError>
        {
            unimplemented!()
        }

        fn get_local_variables(&self) -> Vec<Arc<dyn crate::program::model::listing::Variable>> {
            vec![]
        }

        fn get_return_type(&self) -> Arc<dyn crate::program::model::data::DataType> {
            unimplemented!()
        }

        fn set_return_type(
            &mut self,
            _data_type: Arc<dyn crate::program::model::data::DataType>,
        ) -> Result<(), crate::util::exception::InvalidInputException> {
            Ok(())
        }

        fn is_stack_purge_loss_of_precision(&self) -> bool {
            false
        }

        fn get_calling_convention(&self) -> Option<String> {
            None
        }

        fn set_calling_convention(&mut self, _name: Option<&str>) {}

        fn get_repeat_pattern(&self) -> Option<String> {
            None
        }

        fn set_repeat_pattern(&mut self, _pattern: Option<&str>) {}

        fn get_thunk_functions(&self) -> Vec<Arc<dyn Function>> {
            vec![]
        }

        fn is_thunk(&self) -> bool {
            false
        }

        fn get_thunked_function(&self) -> Option<Arc<dyn Function>> {
            None
        }

        fn set_thunked_function(&mut self, _function: Option<Arc<dyn Function>>) {}

        fn get_tags(&self) -> Vec<Arc<dyn crate::program::model::listing::FunctionTag>> {
            vec![]
        }

        fn add_tag(&mut self, _tag: &crate::program::model::listing::FunctionTag) -> bool {
            false
        }

        fn remove_tag(&mut self, _tag_name: &str) -> bool {
            false
        }

        fn get_stack_frame(
            &self,
        ) -> Result<Arc<dyn crate::program::seam_stubs::StackFrame>, Box<dyn std::error::Error>> {
            unimplemented!()
        }

        fn get_register_vars(&self) -> Vec<Arc<dyn crate::program::model::listing::Variable>> {
            vec![]
        }

        fn get_stack_vars(
            &self,
        ) -> Vec<Arc<dyn crate::program::model::listing::Variable>> {
            vec![]
        }

        fn get_variables(
            &self,
            _filter: &crate::program::seam_stubs::VariableFilter,
        ) -> Vec<Arc<dyn crate::program::model::listing::Variable>> {
            vec![]
        }

        fn get_variable_containing(
            &self,
            _addr: &Address,
        ) -> Option<Arc<dyn crate::program::model::listing::Variable>> {
            None
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

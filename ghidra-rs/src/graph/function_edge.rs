use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use crate::program::model::listing::Function;

use super::g_edge::GEdge;

/// An edge between two functions.
///
/// This edge is never added to the graph, but exists to maintain relationships between
/// functions outside of the visual graph.
pub struct FunctionEdge {
    start: Arc<dyn Function>,
    end: Arc<dyn Function>,
}

impl FunctionEdge {
    /// Creates a new function edge between two functions.
    pub fn new(start: Arc<dyn Function>, end: Arc<dyn Function>) -> Self {
        Self { start, end }
    }

    /// Returns the start (tail) function of this edge.
    pub fn get_start(&self) -> Arc<dyn Function> {
        Arc::clone(&self.start)
    }

    /// Returns the end (head) function of this edge.
    pub fn get_end(&self) -> Arc<dyn Function> {
        Arc::clone(&self.end)
    }
}

impl GEdge<Arc<dyn Function>> for FunctionEdge {
    fn get_start(&self) -> &Arc<dyn Function> {
        &self.start
    }

    fn get_end(&self) -> &Arc<dyn Function> {
        &self.end
    }
}

impl fmt::Display for FunctionEdge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}, {}]",
            Function::get_name(self.start.as_ref()),
            Function::get_name(self.end.as_ref())
        )
    }
}

impl PartialEq for FunctionEdge {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.start, &other.start) && Arc::ptr_eq(&self.end, &other.end)
    }
}

impl Eq for FunctionEdge {}

impl Hash for FunctionEdge {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let start_ptr = Arc::as_ptr(&self.start) as *const () as usize;
        let end_ptr = Arc::as_ptr(&self.end) as *const () as usize;
        start_ptr.hash(state);
        end_ptr.hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockFunction {
        name: String,
    }

    impl MockFunction {
        fn new(name: &str) -> Self {
            Self {
                name: name.to_string(),
            }
        }
    }

    impl Function for MockFunction {
        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn set_name(&mut self, _name: &str, _source: crate::program::model::symbol::SourceType) -> Result<(), crate::program::model::listing::SetFunctionNameError> {
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

        fn get_repeatable_comment(&self) -> Option<String> {
            None
        }

        fn get_repeatable_comment_as_array(&self) -> Vec<String> {
            vec![]
        }

        fn set_repeatable_comment(&mut self, _comment: Option<&str>) {}

        fn get_entry_point(&self) -> crate::program::model::address::Address {
            unimplemented!()
        }

        fn get_return_type(&self) -> Option<Box<dyn crate::program::model::data::data_type::DataType>> {
            None
        }

        fn set_return_type(
            &mut self,
            _data_type: Box<dyn crate::program::model::data::data_type::DataType>,
            _source: crate::program::model::symbol::SourceType,
        ) -> Result<(), crate::util::exception::InvalidInputException> {
            Ok(())
        }

        fn get_return(&self) -> Box<dyn crate::program::model::listing::Parameter> {
            unimplemented!()
        }

        fn set_return(
            &mut self,
            _data_type: Box<dyn crate::program::model::data::data_type::DataType>,
            _storage: Box<dyn crate::program::seam_stubs::VariableStorage>,
            _source: crate::program::model::symbol::SourceType,
        ) -> Result<(), crate::util::exception::InvalidInputException> {
            Ok(())
        }

        fn get_signature_formal(&self, _formal_signature: bool) -> Box<dyn crate::program::model::listing::FunctionSignature> {
            unimplemented!()
        }

        fn get_prototype_string(&self, _formal_signature: bool, _include_calling_convention: bool) -> String {
            String::new()
        }

        fn get_signature_source(&self) -> crate::program::model::symbol::SourceType {
            unimplemented!()
        }

        fn set_signature_source(&mut self, _signature_source: crate::program::model::symbol::SourceType) {}

        fn get_stack_frame(&self) -> Box<dyn crate::program::seam_stubs::StackFrame> {
            unimplemented!()
        }

        fn get_stack_purge_size(&self) -> i32 {
            0
        }

        fn get_tags(&self) -> Vec<Box<dyn crate::program::model::listing::FunctionTag>> {
            vec![]
        }

        fn add_tag(&mut self, _name: &str) -> bool {
            true
        }

        fn remove_tag(&mut self, _name: &str) {}

        fn set_stack_purge_size(&mut self, _purge_size: i32) {}

        fn is_stack_purge_size_valid(&self) -> bool {
            true
        }

        fn add_parameter(
            &mut self,
            _var: Box<dyn crate::program::model::listing::Variable>,
            _source: crate::program::model::symbol::SourceType,
        ) -> Result<Box<dyn crate::program::model::listing::Parameter>, crate::program::model::listing::FunctionEditError> {
            unimplemented!()
        }

        fn insert_parameter(
            &mut self,
            _ordinal: i32,
            _var: Box<dyn crate::program::model::listing::Variable>,
            _source: crate::program::model::symbol::SourceType,
        ) -> Result<Box<dyn crate::program::model::listing::Parameter>, crate::program::model::listing::FunctionEditError> {
            unimplemented!()
        }

        fn replace_parameters(
            &mut self,
            _params: Vec<Box<dyn crate::program::model::listing::Variable>>,
            _update_type: crate::program::model::listing::FunctionUpdateType,
            _force: bool,
            _source: crate::program::model::symbol::SourceType,
        ) -> Result<(), crate::program::model::listing::FunctionEditError> {
            Ok(())
        }

        fn update_function(
            &mut self,
            _calling_convention: Option<&str>,
            _return_value: Option<Box<dyn crate::program::model::listing::Variable>>,
            _new_params: Vec<Box<dyn crate::program::model::listing::Variable>>,
            _update_type: crate::program::model::listing::FunctionUpdateType,
            _force: bool,
            _source: crate::program::model::symbol::SourceType,
        ) -> Result<(), crate::program::model::listing::FunctionEditError> {
            Ok(())
        }

        fn get_parameters(&self) -> Vec<Box<dyn crate::program::model::listing::Parameter>> {
            vec![]
        }

        fn get_parameter(&self, _ordinal: i32) -> Option<Box<dyn crate::program::model::listing::Parameter>> {
            None
        }

        fn get_parameter_count(&self) -> i32 {
            0
        }

        fn get_local_variables(&self) -> Vec<Box<dyn crate::program::model::listing::Variable>> {
            vec![]
        }

        fn add_local_variable(
            &mut self,
            _var: Box<dyn crate::program::model::listing::Variable>,
            _source: crate::program::model::symbol::SourceType,
        ) -> Result<Box<dyn crate::program::model::listing::Variable>, crate::program::model::listing::FunctionEditError> {
            unimplemented!()
        }

        fn remove_variable(&mut self, _var: &dyn crate::program::model::listing::Variable) {}

        fn get_variables(&self, _filter: crate::program::seam_stubs::VariableFilter) -> Vec<Box<dyn crate::program::model::listing::Variable>> {
            vec![]
        }

        fn get_variable_containing(
            &self,
            _address: crate::program::model::address::Address,
            _stack_offset: i32,
        ) -> Option<Box<dyn crate::program::model::listing::Variable>> {
            None
        }

        fn get_variable_at_offset(&self, _offset: i32) -> Option<Box<dyn crate::program::model::listing::Variable>> {
            None
        }

        fn has_custom_variable_storage(&self) -> bool {
            false
        }

        fn set_custom_variable_storage(&mut self, _custom_storage: bool) {}

        fn is_external(&self) -> bool {
            false
        }

        fn get_external_location(&self) -> Option<Box<dyn crate::program::seam_stubs::ExternalLocation>> {
            None
        }

        fn set_external_location(&mut self, _external_location: Option<&str>) {}

        fn get_thunked_function(&self, _recursive: bool) -> Option<Arc<dyn Function>> {
            None
        }

        fn set_thunked_function(&mut self, _thunked_function: Option<Arc<dyn Function>>) -> Result<(), String> {
            Ok(())
        }

        fn is_thunk(&self) -> bool {
            false
        }

        fn get_calling_functions(&self, _monitor: &dyn crate::util::task::TaskMonitor) -> Vec<Arc<dyn Function>> {
            vec![]
        }

        fn get_called_functions(&self, _monitor: &dyn crate::util::task::TaskMonitor) -> Vec<Arc<dyn Function>> {
            vec![]
        }

        fn get_body(&self) -> crate::program::model::address::AddressSetView {
            unimplemented!()
        }

        fn set_body(&mut self, _addresses: crate::program::model::address::AddressSetView) -> Result<(), crate::program::database::function::OverlappingFunctionException> {
            Ok(())
        }

        fn get_signature_source_type(&self) -> crate::program::model::symbol::SourceType {
            unimplemented!()
        }

        fn set_signature_source_type(&mut self, _source: crate::program::model::symbol::SourceType) {}

        fn get_namespace(&self) -> Option<Box<dyn crate::program::model::symbol::Namespace>> {
            None
        }

        fn set_namespace(&mut self, _namespace: Box<dyn crate::program::model::symbol::Namespace>) -> Result<(), crate::util::exception::InvalidInputException> {
            Ok(())
        }
    }

    impl crate::program::model::symbol::Namespace for MockFunction {
        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn set_name(&mut self, _name: &str) -> Result<(), crate::util::exception::DuplicateNameException> {
            Ok(())
        }

        fn get_id(&self) -> u64 {
            0
        }

        fn get_symbol_table(&self) -> Box<dyn crate::program::seam_stubs::SymbolTable> {
            unimplemented!()
        }

        fn get_type(&self) -> crate::program::model::symbol::NamespaceType {
            crate::program::model::symbol::NamespaceType::Function
        }

        fn get_parent_namespace(&self) -> Option<Box<dyn crate::program::model::symbol::Namespace>> {
            None
        }

        fn set_parent_namespace(&mut self, _namespace: Box<dyn crate::program::model::symbol::Namespace>) -> Result<(), crate::util::exception::InvalidInputException> {
            Ok(())
        }
    }

    #[test]
    fn test_create_function_edge() {
        let start = Arc::new(MockFunction::new("func_start")) as Arc<dyn Function>;
        let end = Arc::new(MockFunction::new("func_end")) as Arc<dyn Function>;
        let edge = FunctionEdge::new(Arc::clone(&start), Arc::clone(&end));

        assert_eq!(edge.get_start().get_name(), "func_start");
        assert_eq!(edge.get_end().get_name(), "func_end");
    }

    #[test]
    fn test_function_edge_display() {
        let start = Arc::new(MockFunction::new("foo")) as Arc<dyn Function>;
        let end = Arc::new(MockFunction::new("bar")) as Arc<dyn Function>;
        let edge = FunctionEdge::new(Arc::clone(&start), Arc::clone(&end));

        assert_eq!(edge.to_string(), "[foo, bar]");
    }

    #[test]
    fn test_function_edge_equality_same_pointers() {
        let start = Arc::new(MockFunction::new("func_a")) as Arc<dyn Function>;
        let end = Arc::new(MockFunction::new("func_b")) as Arc<dyn Function>;

        let edge1 = FunctionEdge::new(Arc::clone(&start), Arc::clone(&end));
        let edge2 = FunctionEdge::new(Arc::clone(&start), Arc::clone(&end));

        assert_eq!(edge1, edge2);
    }

    #[test]
    fn test_function_edge_inequality_different_start() {
        let start1 = Arc::new(MockFunction::new("func_a")) as Arc<dyn Function>;
        let start2 = Arc::new(MockFunction::new("func_a")) as Arc<dyn Function>;
        let end = Arc::new(MockFunction::new("func_b")) as Arc<dyn Function>;

        let edge1 = FunctionEdge::new(Arc::clone(&start1), Arc::clone(&end));
        let edge2 = FunctionEdge::new(Arc::clone(&start2), Arc::clone(&end));

        assert_ne!(edge1, edge2);
    }

    #[test]
    fn test_function_edge_inequality_different_end() {
        let start = Arc::new(MockFunction::new("func_a")) as Arc<dyn Function>;
        let end1 = Arc::new(MockFunction::new("func_b")) as Arc<dyn Function>;
        let end2 = Arc::new(MockFunction::new("func_b")) as Arc<dyn Function>;

        let edge1 = FunctionEdge::new(Arc::clone(&start), Arc::clone(&end1));
        let edge2 = FunctionEdge::new(Arc::clone(&start), Arc::clone(&end2));

        assert_ne!(edge1, edge2);
    }

    #[test]
    fn test_function_edge_hash_consistency() {
        use std::collections::HashSet;

        let start = Arc::new(MockFunction::new("func_a")) as Arc<dyn Function>;
        let end = Arc::new(MockFunction::new("func_b")) as Arc<dyn Function>;

        let edge1 = FunctionEdge::new(Arc::clone(&start), Arc::clone(&end));
        let edge2 = FunctionEdge::new(Arc::clone(&start), Arc::clone(&end));

        let mut set = HashSet::new();
        set.insert(edge1);
        assert!(set.contains(&edge2));
    }

    #[test]
    fn test_function_edge_implements_g_edge() {
        let start = Arc::new(MockFunction::new("caller")) as Arc<dyn Function>;
        let end = Arc::new(MockFunction::new("callee")) as Arc<dyn Function>;
        let edge = FunctionEdge::new(Arc::clone(&start), Arc::clone(&end));

        let start_ref = edge.get_start();
        let end_ref = edge.get_end();

        assert_eq!(start_ref.get_name(), "caller");
        assert_eq!(end_ref.get_name(), "callee");
    }

    #[test]
    fn test_get_start_returns_cloned_arc() {
        let start = Arc::new(MockFunction::new("func_start")) as Arc<dyn Function>;
        let end = Arc::new(MockFunction::new("func_end")) as Arc<dyn Function>;
        let edge = FunctionEdge::new(Arc::clone(&start), Arc::clone(&end));

        let retrieved_start = edge.get_start();
        assert!(Arc::ptr_eq(&start, &retrieved_start));
    }

    #[test]
    fn test_get_end_returns_cloned_arc() {
        let start = Arc::new(MockFunction::new("func_start")) as Arc<dyn Function>;
        let end = Arc::new(MockFunction::new("func_end")) as Arc<dyn Function>;
        let edge = FunctionEdge::new(Arc::clone(&start), Arc::clone(&end));

        let retrieved_end = edge.get_end();
        assert!(Arc::ptr_eq(&end, &retrieved_end));
    }
}

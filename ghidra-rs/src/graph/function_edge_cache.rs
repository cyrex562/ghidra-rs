use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::program::model::listing::Function;

use super::function_edge::FunctionEdge;

/// A wrapper for Arc<dyn Function> that implements Hash and Eq based on pointer identity.
/// This allows Arc<dyn Function> to be used as HashMap keys.
#[derive(Clone)]
struct FunctionKey(Arc<dyn Function>);

impl PartialEq for FunctionKey {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for FunctionKey {}

impl std::hash::Hash for FunctionKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        let ptr = Arc::as_ptr(&self.0) as *const () as usize;
        ptr.hash(state);
    }
}

/// A cache for known function edges.
///
/// Maintains all known edges and tracks which functions have been processed
/// for their incoming and outgoing connections.
pub struct FunctionEdgeCache {
    /// Contains all known edges, indexed by function.
    /// Note: having a function as a key in this map is not enough to know if it has been
    /// processed already (as the function can be added by processing edges of other
    /// nodes). Being in this structure means that it has been processed for its
    /// incoming and outgoing connections.
    all_edges_by_function: HashMap<FunctionKey, HashSet<FunctionEdge>>,
    /// Tracks which functions have been processed for their incoming and outgoing connections.
    tracked: HashSet<FunctionKey>,
}

impl FunctionEdgeCache {
    /// Creates a new, empty function edge cache.
    pub fn new() -> Self {
        Self {
            all_edges_by_function: HashMap::new(),
            tracked: HashSet::new(),
        }
    }

    /// Returns the set of edges for the given function, creating an empty set if none exists.
    pub fn get(&mut self, f: Arc<dyn Function>) -> &mut HashSet<FunctionEdge> {
        let key = FunctionKey(Arc::clone(&f));
        self.all_edges_by_function.entry(key).or_insert_with(HashSet::new)
    }

    /// Returns true if the given function has been tracked (processed).
    pub fn is_tracked(&self, f: &Arc<dyn Function>) -> bool {
        let key = FunctionKey(Arc::clone(f));
        self.tracked.contains(&key)
    }

    /// Marks the given function as tracked (processed).
    pub fn set_tracked(&mut self, f: Arc<dyn Function>) {
        let key = FunctionKey(f);
        self.tracked.insert(key);
    }
}

impl Default for FunctionEdgeCache {
    fn default() -> Self {
        Self::new()
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

        fn get_external_location(&self) -> Option<Box<dyn crate::program::model::symbol::ExternalLocation>> {
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
    fn test_create_cache() {
        let cache = FunctionEdgeCache::new();
        assert_eq!(cache.tracked.len(), 0);
        assert_eq!(cache.all_edges_by_function.len(), 0);
    }

    #[test]
    fn test_get_creates_empty_set() {
        let mut cache = FunctionEdgeCache::new();
        let func = Arc::new(MockFunction::new("test_func")) as Arc<dyn Function>;

        let edges = cache.get(Arc::clone(&func));
        assert!(edges.is_empty());
    }

    #[test]
    fn test_set_tracked() {
        let mut cache = FunctionEdgeCache::new();
        let func = Arc::new(MockFunction::new("test_func")) as Arc<dyn Function>;

        assert!(!cache.is_tracked(&func));
        cache.set_tracked(Arc::clone(&func));
        assert!(cache.is_tracked(&func));
    }

    #[test]
    fn test_add_and_retrieve_edges() {
        let mut cache = FunctionEdgeCache::new();
        let start = Arc::new(MockFunction::new("start")) as Arc<dyn Function>;
        let end = Arc::new(MockFunction::new("end")) as Arc<dyn Function>;
        let edge = FunctionEdge::new(Arc::clone(&start), Arc::clone(&end));

        let edges = cache.get(Arc::clone(&start));
        edges.insert(edge.clone());

        let retrieved_edges = cache.get(Arc::clone(&start));
        assert_eq!(retrieved_edges.len(), 1);
        assert!(retrieved_edges.contains(&edge));
    }

    #[test]
    fn test_multiple_functions() {
        let mut cache = FunctionEdgeCache::new();
        let func1 = Arc::new(MockFunction::new("func1")) as Arc<dyn Function>;
        let func2 = Arc::new(MockFunction::new("func2")) as Arc<dyn Function>;
        let func3 = Arc::new(MockFunction::new("func3")) as Arc<dyn Function>;

        let edge1 = FunctionEdge::new(Arc::clone(&func1), Arc::clone(&func2));
        let edge2 = FunctionEdge::new(Arc::clone(&func2), Arc::clone(&func3));

        cache.get(Arc::clone(&func1)).insert(edge1.clone());
        cache.get(Arc::clone(&func2)).insert(edge2.clone());

        assert_eq!(cache.get(Arc::clone(&func1)).len(), 1);
        assert_eq!(cache.get(Arc::clone(&func2)).len(), 1);
        assert_eq!(cache.get(Arc::clone(&func3)).len(), 0);
    }

    #[test]
    fn test_tracked_functions_separate_from_edges() {
        let mut cache = FunctionEdgeCache::new();
        let func1 = Arc::new(MockFunction::new("func1")) as Arc<dyn Function>;
        let func2 = Arc::new(MockFunction::new("func2")) as Arc<dyn Function>;

        let edge = FunctionEdge::new(Arc::clone(&func1), Arc::clone(&func2));
        cache.get(Arc::clone(&func1)).insert(edge);

        assert!(!cache.is_tracked(&func1));
        cache.set_tracked(Arc::clone(&func1));
        assert!(cache.is_tracked(&func1));
        assert!(!cache.is_tracked(&func2));
    }

    #[test]
    fn test_same_function_reference_tracked() {
        let mut cache = FunctionEdgeCache::new();
        let func = Arc::new(MockFunction::new("test")) as Arc<dyn Function>;
        let func_clone = Arc::clone(&func);

        cache.set_tracked(Arc::clone(&func));
        assert!(cache.is_tracked(&func_clone));
    }

    #[test]
    fn test_different_function_references_not_tracked() {
        let mut cache = FunctionEdgeCache::new();
        let func1 = Arc::new(MockFunction::new("test")) as Arc<dyn Function>;
        let func2 = Arc::new(MockFunction::new("test")) as Arc<dyn Function>;

        cache.set_tracked(Arc::clone(&func1));
        assert!(cache.is_tracked(&func1));
        assert!(!cache.is_tracked(&func2));
    }

    #[test]
    fn test_default_creates_empty_cache() {
        let cache = FunctionEdgeCache::default();
        assert_eq!(cache.tracked.len(), 0);
        assert_eq!(cache.all_edges_by_function.len(), 0);
    }
}

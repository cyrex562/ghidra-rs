use std::cmp::Ordering;
use std::fmt;

use crate::program::model::listing::Function;

/// A row object representing a function in a table, identified by the function's symbol ID.
#[derive(Clone)]
pub struct FunctionRowObject {
    function: std::sync::Arc<dyn Function>,
}

impl fmt::Debug for FunctionRowObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FunctionRowObject")
            .field("key", &self.get_key())
            .finish()
    }
}

impl FunctionRowObject {
    /// Creates a new row object wrapping the given function.
    pub fn new(function: std::sync::Arc<dyn Function>) -> Self {
        Self { function }
    }

    /// Returns a reference to the wrapped function.
    pub fn get_function(&self) -> &std::sync::Arc<dyn Function> {
        &self.function
    }

    /// Returns the function's symbol ID, which serves as the unique key for this row.
    fn get_key(&self) -> i64 {
        self.function.get_symbol().get_id()
    }
}

impl PartialEq for FunctionRowObject {
    fn eq(&self, other: &Self) -> bool {
        self.get_key() == other.get_key()
    }
}

impl Eq for FunctionRowObject {}

impl std::hash::Hash for FunctionRowObject {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.get_key().hash(state);
    }
}

impl PartialOrd for FunctionRowObject {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for FunctionRowObject {
    fn cmp(&self, other: &Self) -> Ordering {
        self.get_key().cmp(&other.get_key())
    }
}

impl fmt::Display for FunctionRowObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[id={}, name={}]",
            self.get_key(),
            self.function.get_prototype_string(false, false)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::Arc;

    use crate::program::model::listing::Function;
    use crate::program::model::symbol::{Namespace, Symbol};

    struct MockSymbol {
        id: i64,
    }

    impl Symbol for MockSymbol {
        fn get_address(&self) -> crate::program::model::address::Address {
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
            self.id
        }

        fn get_parent_id(&self) -> i64 {
            0
        }
    }

    struct MockFunction {
        symbol_id: i64,
        signature: String,
    }

    impl Namespace for MockFunction {
        fn get_symbol(&self) -> Arc<dyn Symbol> {
            Arc::new(MockSymbol { id: self.symbol_id })
        }

        fn get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
            None
        }
    }

    impl Function for MockFunction {
        fn get_name(&self) -> String {
            self.signature.clone()
        }

        fn set_name(
            &mut self,
            name: &str,
            _source: crate::program::model::symbol::SourceType,
        ) -> Result<(), crate::program::model::listing::SetFunctionNameError> {
            self.signature = name.to_string();
            Ok(())
        }

        fn set_call_fixup(&mut self, _name: Option<&str>) {}

        fn get_call_fixup(&self) -> Option<String> {
            None
        }

        fn get_program(&self) -> Arc<dyn crate::program::model::listing::Program> {
            struct MockProgram;
            impl crate::program::model::listing::Program for MockProgram {
                fn get_name(&self) -> &str {
                    "mock"
                }
                fn get_language_id(&self) -> &str {
                    "mock:LE:32:default"
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
            struct MockSignature;
            impl crate::program::model::listing::FunctionSignature for MockSignature {
                fn get_name(&self) -> String {
                    String::new()
                }

                fn get_prototype_string_with_calling_convention(
                    &self,
                    _include_calling_convention: bool,
                ) -> String {
                    String::new()
                }

                fn get_arguments(
                    &self,
                ) -> Vec<Box<dyn crate::program::model::data::parameter_definition::ParameterDefinition>>
                {
                    Vec::new()
                }

                fn get_return_type(&self) -> Box<dyn crate::program::model::data::data_type::DataType> {
                    unimplemented!()
                }

                fn get_comment(&self) -> Option<String> {
                    None
                }

                fn has_var_args(&self) -> bool {
                    false
                }

                fn has_no_return(&self) -> bool {
                    false
                }

                fn get_calling_convention(
                    &self,
                ) -> Option<Box<dyn crate::program::seam_stubs::PrototypeModel>> {
                    None
                }

                fn get_calling_convention_name(&self) -> String {
                    String::new()
                }

                fn is_equivalent_signature(
                    &self,
                    _signature: &dyn crate::program::model::listing::FunctionSignature,
                ) -> bool {
                    false
                }
            }
            Box::new(MockSignature)
        }

        fn get_prototype_string(
            &self,
            _formal_signature: bool,
            _include_calling_convention: bool,
        ) -> String {
            self.signature.clone()
        }

        fn get_signature_source(&self) -> crate::program::model::symbol::SourceType {
            crate::program::model::symbol::SourceType::UserDefined
        }

        fn set_signature_source(&mut self, _signature_source: crate::program::model::symbol::SourceType) {}

        fn get_stack_frame(&self) -> Box<dyn crate::program::seam_stubs::StackFrame> {
            unimplemented!()
        }

        fn get_stack_purge_size(&self) -> i32 {
            0
        }

        fn get_tags(&self) -> Vec<Box<dyn crate::program::model::listing::FunctionTag>> {
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

        fn add_parameter(
            &mut self,
            _parameter: Box<dyn crate::program::model::listing::Parameter>,
            _index: Option<i32>,
        ) -> Result<Box<dyn crate::program::model::listing::Parameter>, crate::program::model::listing::FunctionEditError>
        {
            unimplemented!()
        }

        fn insert_parameter(
            &mut self,
            _ordinal: i32,
            _parameter: Box<dyn crate::program::model::listing::Parameter>,
        ) -> Result<Box<dyn crate::program::model::listing::Parameter>, crate::program::model::listing::FunctionEditError>
        {
            unimplemented!()
        }

        fn get_parameters(&self) -> Vec<Box<dyn crate::program::model::listing::Parameter>> {
            Vec::new()
        }

        fn get_parameter(&self, _ordinal: i32) -> Option<Box<dyn crate::program::model::listing::Parameter>> {
            None
        }

        fn remove_parameter(&mut self, _ordinal: i32) {}

        fn replace_parameters(
            &mut self,
            _params: Vec<Box<dyn crate::program::model::listing::Parameter>>,
            _update_type: crate::program::model::listing::FunctionUpdateType,
        ) -> Result<(), crate::program::model::listing::FunctionEditError> {
            unimplemented!()
        }

        fn update_function(
            &mut self,
            _calling_convention: Option<&str>,
            _params: Vec<Box<dyn crate::program::model::listing::Parameter>>,
            _force_custom_storage: bool,
            _update_type: crate::program::model::listing::FunctionUpdateType,
        ) -> Result<(), crate::program::model::listing::FunctionEditError> {
            unimplemented!()
        }

        fn get_calling_convention_name(&self) -> Option<String> {
            None
        }

        fn get_prototype_model(&self) -> Option<Arc<dyn crate::program::seam_stubs::PrototypeModel>> {
            None
        }

        fn set_calling_convention(&mut self, _name: &str) -> Result<(), crate::util::exception::InvalidInputException> {
            Ok(())
        }

        fn get_local_variables(&self) -> Vec<Box<dyn crate::program::model::listing::Variable>> {
            Vec::new()
        }

        fn add_local_variable(
            &mut self,
            _var: Box<dyn crate::program::model::listing::Variable>,
            _index: Option<usize>,
        ) -> Result<Box<dyn crate::program::model::listing::Variable>, crate::program::model::listing::FunctionEditError>
        {
            unimplemented!()
        }

        fn remove_local_variable(&mut self, _storage: Box<dyn crate::program::seam_stubs::VariableStorage>) {}

        fn is_deleted(&self) -> bool {
            false
        }
    }

    #[test]
    fn test_new_and_get_function() {
        let func = Arc::new(MockFunction {
            symbol_id: 42,
            signature: "test_func".to_string(),
        });
        let obj = FunctionRowObject::new(func.clone());
        assert_eq!(obj.get_key(), 42);
    }

    #[test]
    fn test_equality() {
        let func_a = Arc::new(MockFunction {
            symbol_id: 10,
            signature: "func_a".to_string(),
        });
        let func_b = Arc::new(MockFunction {
            symbol_id: 10,
            signature: "func_b".to_string(),
        });
        let func_c = Arc::new(MockFunction {
            symbol_id: 20,
            signature: "func_c".to_string(),
        });

        let obj_a = FunctionRowObject::new(func_a);
        let obj_b = FunctionRowObject::new(func_b);
        let obj_c = FunctionRowObject::new(func_c);

        assert_eq!(obj_a, obj_b);
        assert_ne!(obj_a, obj_c);
    }

    #[test]
    fn test_ordering() {
        let func_lo = Arc::new(MockFunction {
            symbol_id: 1,
            signature: "low".to_string(),
        });
        let func_hi = Arc::new(MockFunction {
            symbol_id: 2,
            signature: "high".to_string(),
        });

        let obj_lo = FunctionRowObject::new(func_lo);
        let obj_hi = FunctionRowObject::new(func_hi);

        assert!(obj_lo < obj_hi);
        assert!(obj_hi > obj_lo);
        assert_eq!(obj_lo.cmp(&obj_lo), Ordering::Equal);
    }

    #[test]
    fn test_hash_consistency() {
        let func_a = Arc::new(MockFunction {
            symbol_id: 99,
            signature: "test".to_string(),
        });
        let func_b = Arc::new(MockFunction {
            symbol_id: 99,
            signature: "test".to_string(),
        });

        let obj_a = FunctionRowObject::new(func_a);
        let obj_b = FunctionRowObject::new(func_b);

        let mut set = HashSet::new();
        set.insert(obj_a);
        assert!(set.contains(&obj_b));
    }

    #[test]
    fn test_display() {
        let func = Arc::new(MockFunction {
            symbol_id: 7,
            signature: "test_func".to_string(),
        });
        let obj = FunctionRowObject::new(func);
        let display_str = obj.to_string();
        assert!(display_str.contains("id=7"));
        assert!(display_str.contains("test_func"));
    }

    #[test]
    fn test_hash_in_collection() {
        let func_1 = Arc::new(MockFunction {
            symbol_id: 1,
            signature: "f1".to_string(),
        });
        let func_2 = Arc::new(MockFunction {
            symbol_id: 2,
            signature: "f2".to_string(),
        });
        let func_1_dup = Arc::new(MockFunction {
            symbol_id: 1,
            signature: "f1_dup".to_string(),
        });

        let obj_1 = FunctionRowObject::new(func_1);
        let obj_2 = FunctionRowObject::new(func_2);
        let obj_1_dup = FunctionRowObject::new(func_1_dup);

        let mut set = HashSet::new();
        set.insert(obj_1);
        set.insert(obj_2);
        set.insert(obj_1_dup);

        assert_eq!(set.len(), 2);
    }

    #[test]
    fn test_ordering_in_sort() {
        let func_3 = Arc::new(MockFunction {
            symbol_id: 3,
            signature: "f3".to_string(),
        });
        let func_1 = Arc::new(MockFunction {
            symbol_id: 1,
            signature: "f1".to_string(),
        });
        let func_2 = Arc::new(MockFunction {
            symbol_id: 2,
            signature: "f2".to_string(),
        });

        let mut objs = vec![
            FunctionRowObject::new(func_3),
            FunctionRowObject::new(func_1),
            FunctionRowObject::new(func_2),
        ];
        objs.sort();

        assert_eq!(objs[0].get_key(), 1);
        assert_eq!(objs[1].get_key(), 2);
        assert_eq!(objs[2].get_key(), 3);
    }
}

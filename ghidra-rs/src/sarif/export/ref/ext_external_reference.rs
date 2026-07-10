use crate::program::model::data::isf::IsfObject;
use crate::program::model::symbol::ExternalReference;

/// Represents external reference metadata extracted from an [`ExternalReference`] for SARIF export.
///
/// Mirrors `ExtExternalReference` from Ghidra's `sarif.export.ref` package.
/// Captures essential metadata from an external reference, including information about
/// the external location (name, original import, associated function, etc.).
pub struct ExtExternalReference {
    pub index: String,
    pub kind: String,
    pub op_index: i32,
    pub source_type: String,
    pub name: Option<String>,
    pub orig_import: Option<String>,
    pub is_class: bool,
    pub is_function: bool,
    pub lib_label: Option<String>,
    pub lib_addr: Option<String>,
    pub lib_ext_addr: Option<String>,
}

impl ExtExternalReference {
    /// Creates a new `ExtExternalReference` from an [`ExternalReference`].
    ///
    /// Extracts reference metadata from the base reference type, as well as detailed
    /// information from the associated external location.
    pub fn new(reference: &dyn ExternalReference) -> Self {
        let reference_type = reference.reference_type();
        let index = (reference_type.value() as u8).to_string();
        let kind = reference_type.name().to_string();
        let op_index = reference.operand_index();
        let source_type = reference.source().display_string().to_string();

        let ext_loc = reference.get_external_location();

        let name = ext_loc.get_parent_namespace()
            .map(|ns| ns.get_name_with_path(true));
        let orig_import = ext_loc.get_original_imported_name();
        let is_class = ext_loc.get_data_type().is_some();
        let is_function = ext_loc.get_function().is_some();

        let lib_label = if ext_loc.get_label().is_empty() {
            None
        } else {
            Some(ext_loc.get_label())
        };

        let lib_addr = ext_loc.get_address().map(|addr| addr.to_string());
        let lib_ext_addr = ext_loc.get_external_space_address().map(|addr| addr.to_string());

        Self {
            index,
            kind,
            op_index,
            source_type,
            name,
            orig_import,
            is_class,
            is_function,
            lib_label,
            lib_addr,
            lib_ext_addr,
        }
    }
}

impl IsfObject for ExtExternalReference {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};

    fn default_space() -> std::sync::Arc<crate::program::model::address::AddressSpace> {
        crate::program::model::address::AddressSpace::new(
            "ram",
            64,
            1,
            crate::program::model::address::AddressSpaceType::Ram,
            0,
        )
    }

    use crate::program::model::data::data_type::DataType;
    use crate::program::model::listing::Function;
    use crate::program::model::symbol::{
        ExternalLocation, Namespace, NamespaceType, RefType, SourceType, Symbol,
    };
    use std::sync::Arc;

    struct MockSymbol;
    impl Symbol for MockSymbol {
        fn get_address(&self) -> Address {
            let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
            Address::new(space, 0)
        }

        fn get_name(&self) -> &str {
            "namespace"
        }

        fn get_symbol_type(&self) -> crate::program::model::symbol::SymbolType {
            crate::program::model::symbol::SymbolType::Namespace
        }

        fn get_source(&self) -> SourceType {
            SourceType::Default
        }

        fn is_primary(&self) -> bool {
            false
        }

        fn get_id(&self) -> i64 {
            -1
        }

        fn get_parent_id(&self) -> i64 {
            -1
        }
    }

    struct MockNamespace;
    impl Namespace for MockNamespace {
        fn get_symbol(&self) -> Arc<dyn Symbol> {
            Arc::new(MockSymbol)
        }

        fn get_name(&self) -> String {
            "namespace".to_string()
        }

        fn get_name_with_path(&self, include_namespace_path: bool) -> String {
            if include_namespace_path {
                "test::namespace".to_string()
            } else {
                "namespace".to_string()
            }
        }

        fn get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
            None
        }
    }

    struct MockDataType;
    impl DataType for MockDataType {
        fn get_name(&self) -> String {
            "DataType".to_string()
        }

        fn get_display_name(&self) -> String {
            "DataType".to_string()
        }

        fn get_length(&self) -> i32 {
            0
        }

        fn get_description(&self) -> String {
            String::new()
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

        fn get_type(&self) -> NamespaceType {
            NamespaceType::Function
        }
    }

    impl Function for MockFunction {
        fn get_name(&self) -> String {
            "func".to_string()
        }

        fn set_name(
            &mut self,
            _name: &str,
            _source: SourceType,
        ) -> Result<(), crate::program::model::listing::function::SetFunctionNameError> {
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

        fn get_entry_point(&self) -> Address {
            Address::new(default_space(), 0)
        }

        fn get_return_type(&self) -> Option<Box<dyn DataType>> {
            None
        }

        fn set_return_type(
            &mut self,
            _data_type: Box<dyn DataType>,
            _source: SourceType,
        ) -> Result<(), crate::util::exception::InvalidInputException> {
            Ok(())
        }

        fn get_return(&self) -> Box<dyn crate::program::model::listing::Parameter> {
            unimplemented!()
        }

        fn set_return(
            &mut self,
            _data_type: Box<dyn DataType>,
            _storage: Box<dyn crate::program::seam_stubs::VariableStorage>,
            _source: SourceType,
        ) -> Result<(), crate::util::exception::InvalidInputException> {
            Ok(())
        }

        fn get_signature_formal(
            &self,
            _formal_signature: bool,
        ) -> Box<dyn crate::program::model::listing::FunctionSignature> {
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
            SourceType::Default
        }

        fn set_signature_source(&mut self, _signature_source: SourceType) {}

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

        #[allow(deprecated)]
        fn add_parameter(
            &mut self,
            _var: Box<dyn crate::program::model::listing::Variable>,
            _source: SourceType,
        ) -> Result<Box<dyn crate::program::model::listing::Parameter>, crate::program::model::listing::function::FunctionEditError> {
            unimplemented!()
        }

        #[allow(deprecated)]
        fn insert_parameter(
            &mut self,
            _ordinal: i32,
            _var: Box<dyn crate::program::model::listing::Variable>,
            _source: SourceType,
        ) -> Result<Box<dyn crate::program::model::listing::Parameter>, crate::program::model::listing::function::FunctionEditError> {
            unimplemented!()
        }

        fn replace_parameters(
            &mut self,
            _params: Vec<Box<dyn crate::program::model::listing::Variable>>,
            _update_type: crate::program::model::listing::FunctionUpdateType,
            _force: bool,
            _source: SourceType,
        ) -> Result<(), crate::program::model::listing::function::FunctionEditError> {
            Ok(())
        }

        fn update_function(
            &mut self,
            _calling_convention: Option<&str>,
            _return_value: Option<Box<dyn crate::program::model::listing::Variable>>,
            _new_params: Vec<Box<dyn crate::program::model::listing::Variable>>,
            _update_type: crate::program::model::listing::FunctionUpdateType,
            _force: bool,
            _source: SourceType,
        ) -> Result<(), crate::program::model::listing::function::FunctionEditError> {
            Ok(())
        }

        fn get_parameter(
            &self,
            _ordinal: i32,
        ) -> Option<Box<dyn crate::program::model::listing::Parameter>> {
            None
        }

        #[allow(deprecated)]
        fn remove_parameter(&mut self, _ordinal: i32) {}

        #[allow(deprecated)]
        fn move_parameter(
            &mut self,
            _from_ordinal: i32,
            _to_ordinal: i32,
        ) -> Result<Box<dyn crate::program::model::listing::Parameter>, crate::util::exception::InvalidInputException> {
            unimplemented!()
        }

        fn get_parameter_count(&self) -> i32 {
            0
        }

        fn get_auto_parameter_count(&self) -> i32 {
            0
        }

        fn get_parameters(&self) -> Vec<Box<dyn crate::program::model::listing::Parameter>> {
            vec![]
        }

        fn get_parameters_filtered(
            &self,
            _filter: Option<&dyn crate::program::seam_stubs::VariableFilter>,
        ) -> Vec<Box<dyn crate::program::model::listing::Parameter>> {
            vec![]
        }

        fn get_local_variables(&self) -> Vec<Box<dyn crate::program::model::listing::Variable>> {
            vec![]
        }

        fn get_local_variables_filtered(
            &self,
            _filter: Option<&dyn crate::program::seam_stubs::VariableFilter>,
        ) -> Vec<Box<dyn crate::program::model::listing::Variable>> {
            vec![]
        }

        fn get_variables_filtered(
            &self,
            _filter: Option<&dyn crate::program::seam_stubs::VariableFilter>,
        ) -> Vec<Box<dyn crate::program::model::listing::Variable>> {
            vec![]
        }

        fn get_all_variables(&self) -> Vec<Box<dyn crate::program::model::listing::Variable>> {
            vec![]
        }

        fn add_local_variable(
            &mut self,
            _var: Box<dyn crate::program::model::listing::Variable>,
            _source: SourceType,
        ) -> Result<Box<dyn crate::program::model::listing::Variable>, crate::program::model::listing::function::FunctionEditError> {
            unimplemented!()
        }

        fn remove_variable(&mut self, _var: &dyn crate::program::model::listing::Variable) {}

        fn set_body(
            &mut self,
            _new_body: &dyn crate::program::model::address::AddressSetView,
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

        fn get_calling_convention(&self) -> Option<Box<dyn crate::program::seam_stubs::PrototypeModel>> {
            None
        }

        fn get_calling_convention_name(&self) -> String {
            String::from("unknown")
        }

        fn set_calling_convention(&mut self, _name: &str) -> Result<(), crate::util::exception::InvalidInputException> {
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

        fn get_calling_functions(
            &self,
            _monitor: &dyn crate::util::task::TaskMonitor,
        ) -> Vec<Arc<dyn Function>> {
            vec![]
        }

        fn get_called_functions(
            &self,
            _monitor: &dyn crate::util::task::TaskMonitor,
        ) -> Vec<Arc<dyn Function>> {
            vec![]
        }

        fn promote_local_user_labels_to_global(&mut self) {}

        fn is_deleted(&self) -> bool {
            false
        }
    }

    struct MockExternalLocation {
        has_data_type: bool,
        has_function: bool,
        label: String,
        parent_ns: Option<Arc<dyn Namespace>>,
        address: Option<Address>,
        ext_space_address: Option<Address>,
        original_imported_name: Option<String>,
    }

    impl ExternalLocation for MockExternalLocation {
        fn get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
            self.parent_ns.clone()
        }

        fn get_label(&self) -> String {
            self.label.clone()
        }

        fn get_original_imported_name(&self) -> Option<String> {
            self.original_imported_name.clone()
        }

        fn get_address(&self) -> Option<Address> {
            self.address.clone()
        }

        fn get_external_space_address(&self) -> Option<Address> {
            self.ext_space_address.clone()
        }

        fn get_data_type(&self) -> Option<Box<dyn DataType>> {
            if self.has_data_type {
                Some(Box::new(MockDataType))
            } else {
                None
            }
        }

        fn get_function(&self) -> Option<Arc<dyn Function>> {
            if self.has_function {
                Some(Arc::new(MockFunction))
            } else {
                None
            }
        }
    }

    struct MockExternalReference {
        ref_type: RefType,
        operand_index: i32,
        source: SourceType,
        external_location: Box<dyn ExternalLocation>,
    }

    impl crate::program::model::symbol::Reference for MockExternalReference {
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }

        fn from_address(&self) -> Address {
            Address::new(default_space(), 0)
        }

        fn to_address(&self) -> Address {
            Address::new(default_space(), 0)
        }

        fn is_primary(&self) -> bool {
            false
        }

        fn symbol_id(&self) -> i64 {
            -1
        }

        fn reference_type(&self) -> RefType {
            self.ref_type
        }

        fn operand_index(&self) -> i32 {
            self.operand_index
        }

        fn is_mnemonic_reference(&self) -> bool {
            self.operand_index == RefType::MNEMONIC
        }

        fn is_operand_reference(&self) -> bool {
            self.operand_index >= 0
        }

        fn is_stack_reference(&self) -> bool {
            false
        }

        fn is_external_reference(&self) -> bool {
            true
        }

        fn is_entry_point_reference(&self) -> bool {
            false
        }

        fn is_memory_reference(&self) -> bool {
            false
        }

        fn is_register_reference(&self) -> bool {
            false
        }

        fn is_offset_reference(&self) -> bool {
            false
        }

        fn is_shifted_reference(&self) -> bool {
            false
        }

        fn source(&self) -> SourceType {
            self.source
        }
    }

    impl ExternalReference for MockExternalReference {
        fn get_external_location(&self) -> Box<dyn ExternalLocation> {
            Box::new(MockExternalLocation {
                has_data_type: false,
                has_function: false,
                label: String::new(),
                parent_ns: None,
                address: None,
                ext_space_address: None,
                original_imported_name: None,
            })
        }

        fn get_library_name(&self) -> String {
            "test.lib".to_string()
        }

        fn get_label(&self) -> Option<String> {
            Some("test_symbol".to_string())
        }
    }

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    #[test]
    fn extracts_base_reference_fields() {
        let mock_ext_loc = Box::new(MockExternalLocation {
            has_data_type: false,
            has_function: false,
            label: String::new(),
            parent_ns: None,
            address: None,
            ext_space_address: None,
            original_imported_name: None,
        });

        let mock_ref = MockExternalReference {
            ref_type: RefType::Data,
            operand_index: 0,
            source: SourceType::Default,
            external_location: mock_ext_loc,
        };

        let ext_ref = ExtExternalReference::new(&mock_ref);

        assert_eq!(ext_ref.index, RefType::Data.value().to_string());
        assert_eq!(ext_ref.kind, RefType::Data.name());
        assert_eq!(ext_ref.op_index, 0);
        assert_eq!(ext_ref.source_type, SourceType::Default.display_string());
    }

    #[test]
    fn extracts_external_location_fields() {
        let mock_ext_loc = Box::new(MockExternalLocation {
            has_data_type: false,
            has_function: false,
            label: "myLabel".to_string(),
            parent_ns: Some(Arc::new(MockNamespace)),
            address: Some(addr(0x1000)),
            ext_space_address: Some(addr(0x2000)),
            original_imported_name: Some("original_name".to_string()),
        });

        let mock_ref = MockExternalReference {
            ref_type: RefType::UnconditionalCall,
            operand_index: 1,
            source: SourceType::Imported,
            external_location: mock_ext_loc,
        };

        let ext_ref = ExtExternalReference::new(&mock_ref);

        assert_eq!(ext_ref.lib_label, Some("myLabel".to_string()));
        assert_eq!(ext_ref.orig_import, Some("original_name".to_string()));
        assert!(ext_ref.lib_addr.is_some());
        assert!(ext_ref.lib_ext_addr.is_some());
    }

    #[test]
    fn detects_function() {
        let mock_ext_loc = Box::new(MockExternalLocation {
            has_data_type: false,
            has_function: true,
            label: String::new(),
            parent_ns: None,
            address: None,
            ext_space_address: None,
            original_imported_name: None,
        });

        let mock_ref = MockExternalReference {
            ref_type: RefType::UnconditionalCall,
            operand_index: 0,
            source: SourceType::Default,
            external_location: mock_ext_loc,
        };

        let ext_ref = ExtExternalReference::new(&mock_ref);

        assert!(ext_ref.is_function);
        assert!(!ext_ref.is_class);
    }

    #[test]
    fn detects_class_via_data_type() {
        let mock_ext_loc = Box::new(MockExternalLocation {
            has_data_type: true,
            has_function: false,
            label: String::new(),
            parent_ns: None,
            address: None,
            ext_space_address: None,
            original_imported_name: None,
        });

        let mock_ref = MockExternalReference {
            ref_type: RefType::Data,
            operand_index: 0,
            source: SourceType::Default,
            external_location: mock_ext_loc,
        };

        let ext_ref = ExtExternalReference::new(&mock_ref);

        assert!(ext_ref.is_class);
        assert!(!ext_ref.is_function);
    }

    #[test]
    fn handles_missing_optional_fields() {
        let mock_ext_loc = Box::new(MockExternalLocation {
            has_data_type: false,
            has_function: false,
            label: String::new(),
            parent_ns: None,
            address: None,
            ext_space_address: None,
            original_imported_name: None,
        });

        let mock_ref = MockExternalReference {
            ref_type: RefType::Data,
            operand_index: 0,
            source: SourceType::Default,
            external_location: mock_ext_loc,
        };

        let ext_ref = ExtExternalReference::new(&mock_ref);

        assert!(ext_ref.name.is_none());
        assert!(ext_ref.orig_import.is_none());
        assert!(ext_ref.lib_label.is_none());
        assert!(ext_ref.lib_addr.is_none());
        assert!(ext_ref.lib_ext_addr.is_none());
    }

    #[test]
    fn implements_isf_object() {
        fn accepts_isf_object<T: IsfObject>(_: &T) {}

        let mock_ext_loc = Box::new(MockExternalLocation {
            has_data_type: false,
            has_function: false,
            label: String::new(),
            parent_ns: None,
            address: None,
            ext_space_address: None,
            original_imported_name: None,
        });

        let mock_ref = MockExternalReference {
            ref_type: RefType::Data,
            operand_index: 0,
            source: SourceType::Default,
            external_location: mock_ext_loc,
        };

        let ext_ref = ExtExternalReference::new(&mock_ref);
        accepts_isf_object(&ext_ref);
    }

    #[test]
    fn handles_empty_label_as_none() {
        let mock_ext_loc = Box::new(MockExternalLocation {
            has_data_type: false,
            has_function: false,
            label: String::new(),
            parent_ns: None,
            address: None,
            ext_space_address: None,
            original_imported_name: None,
        });

        let mock_ref = MockExternalReference {
            ref_type: RefType::Data,
            operand_index: 0,
            source: SourceType::Default,
            external_location: mock_ext_loc,
        };

        let ext_ref = ExtExternalReference::new(&mock_ref);
        assert!(ext_ref.lib_label.is_none());
    }

    #[test]
    fn handles_non_empty_label() {
        let mock_ext_loc = Box::new(MockExternalLocation {
            has_data_type: false,
            has_function: false,
            label: "actual_label".to_string(),
            parent_ns: None,
            address: None,
            ext_space_address: None,
            original_imported_name: None,
        });

        let mock_ref = MockExternalReference {
            ref_type: RefType::Data,
            operand_index: 0,
            source: SourceType::Default,
            external_location: mock_ext_loc,
        };

        let ext_ref = ExtExternalReference::new(&mock_ref);
        assert_eq!(ext_ref.lib_label, Some("actual_label".to_string()));
    }
}

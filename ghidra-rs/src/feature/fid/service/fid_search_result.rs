//! Port of `ghidra.feature.fid.service.FidSearchResult`.

use std::sync::Arc;

use crate::feature::fid::hash::fid_hash_quad::FidHashQuad;
use crate::feature::fid::service::fid_match::FidMatch;
use crate::program::model::listing::Function;

/// Represents the result of a search operation on the FID libraries.
///
/// Port of `ghidra.feature.fid.service.FidSearchResult`.
pub struct FidSearchResult {
    pub function: Arc<dyn Function>,
    pub hash_quad: Arc<dyn FidHashQuad>,
    pub matches: Vec<Box<dyn FidMatch>>,
}

impl FidSearchResult {
    /// Java: `FidSearchResult(Function func, FidHashQuad hashQuad, List<FidMatch> matches)`.
    pub fn new(
        func: Arc<dyn Function>,
        hash_quad: Arc<dyn FidHashQuad>,
        matches: Vec<Box<dyn FidMatch>>,
    ) -> Self {
        Self { function: func, hash_quad, matches }
    }

    /// Removes every match whose function's name starts with `prefix`, keeping the rest.
    ///
    /// Java: `void filterBySymbolPrefix(String prefix)`.
    ///
    /// # Deviations from Java
    ///
    /// Java's method is misleadingly named: reading the body (`if
    /// (!function.getName().startsWith(prefix)) { result.add(match); }`), it actually *removes*
    /// matches whose function name starts with `prefix` and *keeps* the rest -- the opposite of
    /// what "filter by symbol prefix" suggests at first glance (one might expect it to keep only
    /// matches *matching* the prefix). Reproduced faithfully here rather than fixed.
    pub fn filter_by_symbol_prefix(&mut self, prefix: &str) {
        let mut result = Vec::new();
        for m in self.matches.drain(..) {
            let function = m.get_function_record();
            if !function.get_name().starts_with(prefix) {
                result.push(m);
            }
        }
        // Replace old matches list with filtered list.
        self.matches = result;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feature::fid::db::fid_db::test_support::minimal_fid_db;
    use crate::feature::fid::db::function_record::FunctionRecord;
    use crate::feature::fid::db::library_record::LibraryRecord;
    use crate::feature::fid::plugin::hash_lookup_list_mode::HashLookupListMode;
    use crate::feature::fid::service::fid_match_score::FidMatchScore;
    use crate::feature::seam_stubs::{StringRecord, StringsTable};
    use crate::framework::db::field::{Field, FieldType};
    use crate::framework::db::record::DBRecord;
    use crate::framework::db::schema::Schema;
    use crate::program::model::address::{Address, AddressSetView, AddressSpace, AddressSpaceType};
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::listing::function::{FunctionEditError, SetFunctionNameError};
    use crate::program::model::listing::{
        FunctionSignature, FunctionTag, FunctionUpdateType, Parameter, Program, Variable,
    };
    use crate::program::model::symbol::{ExternalLocation, Namespace, SourceType, Symbol};
    use crate::program::model::lang::prototype_model::PrototypeModel;
    use crate::program::seam_stubs::{StackFrame, VariableFilter};
    use crate::program::model::listing::variable_storage::VariableStorage;
    use crate::util::exception::InvalidInputException;
    use crate::util::task::TaskMonitor;
    use std::collections::HashMap;
    use std::sync::Mutex;

    fn mock_address(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    /// Minimal `Function` mock, mirroring the established pattern already used by
    /// [`crate::program::model::listing::function_iterator`]'s own `MockFunction` (each file in
    /// this crate defines its own, per this codebase's established convention -- there is no
    /// shared reusable mock).
    struct MockFunction;

    impl Namespace for MockFunction {
        fn get_symbol(&self) -> Arc<dyn Symbol> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
            None
        }
    }

    impl Function for MockFunction {
        fn get_name(&self) -> String {
            "mock".to_string()
        }
        fn set_name(&mut self, _name: &str, _source: SourceType) -> Result<(), SetFunctionNameError> {
            Ok(())
        }
        fn set_call_fixup(&mut self, _name: Option<&str>) {}
        fn get_call_fixup(&self) -> Option<String> {
            None
        }
        fn get_program(&self) -> Arc<dyn Program> {
            unimplemented!("not needed for this smoke test")
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
            mock_address(0x100)
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
            unimplemented!("not needed for this smoke test")
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
            unimplemented!("not needed for this smoke test")
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
            unimplemented!("not needed for this smoke test")
        }
        fn get_stack_purge_size(&self) -> i32 {
            0
        }
        fn get_tags(&self) -> Vec<Box<dyn FunctionTag>> {
            Vec::new()
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
            _var: Box<dyn Variable>,
            _source: SourceType,
        ) -> Result<Box<dyn Parameter>, FunctionEditError> {
            unimplemented!("not needed for this smoke test")
        }
        #[allow(deprecated)]
        fn insert_parameter(
            &mut self,
            _ordinal: i32,
            _var: Box<dyn Variable>,
            _source: SourceType,
        ) -> Result<Box<dyn Parameter>, FunctionEditError> {
            unimplemented!("not needed for this smoke test")
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
            unimplemented!("not needed for this smoke test")
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
        fn get_local_variables_filtered(&self, _filter: Option<&dyn VariableFilter>) -> Vec<Box<dyn Variable>> {
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
            unimplemented!("not needed for this smoke test")
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
        fn get_calling_convention(&self) -> Option<Arc<PrototypeModel>> {
            None
        }
        fn get_calling_convention_name(&self) -> String {
            "unknown".to_string()
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

    struct TestQuad;
    impl FidHashQuad for TestQuad {
        fn code_unit_size(&self) -> i16 {
            4
        }
        fn full_hash(&self) -> i64 {
            0x1234
        }
        fn specific_hash_additional_size(&self) -> i8 {
            0
        }
        fn specific_hash(&self) -> i64 {
            0x5678
        }
    }

    struct FakeStringsTable {
        strings: Mutex<HashMap<i64, String>>,
    }

    impl StringsTable for FakeStringsTable {
        fn lookup_string(&self, id: i64) -> Option<StringRecord> {
            self.strings.lock().unwrap().get(&id).cloned().map(|v| StringRecord::new(id, v))
        }
    }

    fn function_record_schema() -> Arc<Schema> {
        Arc::new(Schema::new(
            0,
            FieldType::Long,
            "Function ID".to_string(),
            vec![
                FieldType::Short,
                FieldType::Long,
                FieldType::Byte,
                FieldType::Long,
                FieldType::Long,
                FieldType::Long,
                FieldType::Long,
                FieldType::Long,
                FieldType::Byte,
            ],
            vec![
                "Code Unit Size".to_string(),
                "Full Hash".to_string(),
                "Specific Hash Additional Size".to_string(),
                "Specific Hash".to_string(),
                "Library ID".to_string(),
                "Name ID".to_string(),
                "Entry Point".to_string(),
                "Domain Path ID".to_string(),
                "Flags".to_string(),
            ],
            vec![],
        ))
    }

    /// Builds a `FunctionRecord` named `name`, using the same approach established by
    /// [`crate::feature::fid::db::function_record`]'s own tests.
    fn function_record(id: i64, name: &str) -> FunctionRecord {
        let mut strings = HashMap::new();
        strings.insert(1, name.to_string());
        let strings_table = Arc::new(FakeStringsTable { strings: Mutex::new(strings) });
        let fid_db = minimal_fid_db(strings_table);
        let mut record = DBRecord::new(function_record_schema(), Field::Long(Some(id)));
        record.set_long(5, 1); // NAME_ID_COL -> string id 1
        FunctionRecord::new(fid_db, record)
    }

    fn library_record(id: i64) -> LibraryRecord {
        let schema = Arc::new(Schema::new(
            0,
            FieldType::Long,
            "Key".to_string(),
            vec![FieldType::String; 8],
            vec![
                "LibraryFamilyName".to_string(),
                "LibraryVersion".to_string(),
                "LibraryVariant".to_string(),
                "GhidraVersion".to_string(),
                "GhidraLanguageID".to_string(),
                "GhidraLanguageVersion".to_string(),
                "GhidraLanguageMinorVersion".to_string(),
                "GhidraCompilerSpecID".to_string(),
            ],
            vec![],
        ));
        let record = DBRecord::new(schema, Field::Long(Some(id)));
        LibraryRecord::new(record)
    }

    struct TestMatch {
        function_record: FunctionRecord,
        library: LibraryRecord,
        entry: Address,
    }

    impl FidMatchScore for TestMatch {
        fn get_function_record(&self) -> &FunctionRecord {
            &self.function_record
        }
        fn get_primary_function_code_unit_score(&self) -> f32 {
            1.0
        }
        fn get_primary_function_match_mode(&self) -> HashLookupListMode {
            HashLookupListMode::Full
        }
        fn get_child_function_code_unit_score(&self) -> f32 {
            0.0
        }
        fn get_parent_function_code_unit_score(&self) -> f32 {
            0.0
        }
        fn get_overall_score(&self) -> f32 {
            1.0
        }
    }

    impl FidMatch for TestMatch {
        fn get_matched_function_entry_point(&self) -> Address {
            self.entry.clone()
        }
        fn get_library_record(&self) -> &LibraryRecord {
            &self.library
        }
    }

    fn make_match(id: i64, name: &str) -> Box<dyn FidMatch> {
        Box::new(TestMatch {
            function_record: function_record(id, name),
            library: library_record(id),
            entry: mock_address(id),
        })
    }

    fn make_result(matches: Vec<Box<dyn FidMatch>>) -> FidSearchResult {
        FidSearchResult::new(Arc::new(MockFunction), Arc::new(TestQuad), matches)
    }

    #[test]
    fn constructor_stores_all_three_fields() {
        let result = make_result(vec![make_match(1, "foo")]);
        // Disambiguated: `MockFunction` implements both `Namespace::get_name` (default) and
        // `Function::get_name`, so plain dot-call syntax is ambiguous.
        assert_eq!(Function::get_name(result.function.as_ref()), "mock");
        assert_eq!(result.hash_quad.full_hash(), 0x1234);
        assert_eq!(result.matches.len(), 1);
    }

    #[test]
    fn filter_by_symbol_prefix_removes_matches_whose_name_starts_with_the_prefix() {
        // Java quirk (see the method's own doc comment): this *removes* matches whose function
        // name starts with `prefix`, and *keeps* the rest -- despite the method's name suggesting
        // the opposite. Reproduced faithfully.
        let mut result = make_result(vec![
            make_match(1, "prefix_foo"),
            make_match(2, "other"),
            make_match(3, "prefix_bar"),
        ]);

        result.filter_by_symbol_prefix("prefix_");

        assert_eq!(result.matches.len(), 1);
        assert_eq!(result.matches[0].get_function_record().get_name(), "other");
    }

    #[test]
    fn filter_by_symbol_prefix_keeps_everything_when_nothing_matches() {
        let mut result = make_result(vec![make_match(1, "alpha"), make_match(2, "beta")]);

        result.filter_by_symbol_prefix("zzz");

        assert_eq!(result.matches.len(), 2);
    }

    #[test]
    fn filter_by_symbol_prefix_removes_everything_when_all_match() {
        let mut result = make_result(vec![make_match(1, "pfx_a"), make_match(2, "pfx_b")]);

        result.filter_by_symbol_prefix("pfx_");

        assert!(result.matches.is_empty());
    }

    #[test]
    fn filter_by_symbol_prefix_on_empty_matches_stays_empty() {
        let mut result = make_result(vec![]);
        result.filter_by_symbol_prefix("anything");
        assert!(result.matches.is_empty());
    }
}

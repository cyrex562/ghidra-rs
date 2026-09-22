use crate::app::seam_stubs::FieldMatcher;
use crate::program::model::data::data_type::DataType;

/// A simple service to trigger a search for applied datatypes.
///
/// Port of `ghidra.app.plugin.core.navigation.FindAppliedDataTypesService`. Java is an
/// `interface` with 3 abstract methods and 1 in-repo implementor, so this becomes a `trait`
/// (rule R-interface-open-ext-point).
///
/// Java overloads `findAndDisplayAppliedDataTypeAddresses` three ways (by data type alone, by
/// data type + field name, and by data type + [`FieldMatcher`]); Rust has no overloading, so each
/// overload gets a distinct, descriptive name. `FieldMatcher` is a concrete class (not an
/// interface) that already has a minimal placeholder at
/// [`crate::app::seam_stubs::FieldMatcher`] (reused here rather than redefined).
pub trait FindAppliedDataTypesService {
    /// Find all places where `data_type` is applied and display the results.
    fn find_and_display_applied_data_type_addresses(&mut self, data_type: &dyn DataType);

    /// Find all places where `data_type` is applied, restricted to `field_name`, and display the
    /// results.
    fn find_and_display_applied_data_type_addresses_for_field(
        &mut self,
        data_type: &dyn DataType,
        field_name: &str,
    );

    /// Find all places where `data_type` is applied, restricted by `field_matcher`, and display
    /// the results. The matcher may be 'empty' (matching all fields regardless of field).
    fn find_and_display_applied_data_type_addresses_matching(
        &mut self,
        data_type: &dyn DataType,
        field_matcher: &FieldMatcher,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct RecordingFindAppliedDataTypesService {
        calls: Vec<String>,
    }

    struct StubDataType;

    impl DataType for StubDataType {
        fn get_name(&self) -> String {
            "MyStruct".to_string()
        }
    }

    impl FindAppliedDataTypesService for RecordingFindAppliedDataTypesService {
        fn find_and_display_applied_data_type_addresses(&mut self, data_type: &dyn DataType) {
            self.calls.push(format!("all:{}", data_type.get_name()));
        }

        fn find_and_display_applied_data_type_addresses_for_field(
            &mut self,
            data_type: &dyn DataType,
            field_name: &str,
        ) {
            self.calls
                .push(format!("field:{}.{}", data_type.get_name(), field_name));
        }

        fn find_and_display_applied_data_type_addresses_matching(
            &mut self,
            data_type: &dyn DataType,
            field_matcher: &FieldMatcher,
        ) {
            self.calls.push(format!(
                "matcher:{}:{}",
                data_type.get_name(),
                field_matcher.is_ignored()
            ));
        }
    }

    #[test]
    fn dispatches_all_three_overload_variants() {
        let mut service = RecordingFindAppliedDataTypesService::default();
        let dt = StubDataType;

        service.find_and_display_applied_data_type_addresses(&dt);
        service.find_and_display_applied_data_type_addresses_for_field(&dt, "count");
        service.find_and_display_applied_data_type_addresses_matching(&dt, &FieldMatcher::default());

        assert_eq!(
            service.calls,
            vec![
                "all:MyStruct".to_string(),
                "field:MyStruct.count".to_string(),
                "matcher:MyStruct:true".to_string(),
            ]
        );
    }

    #[test]
    fn usable_as_trait_object() {
        let mut service: Box<dyn FindAppliedDataTypesService> =
            Box::new(RecordingFindAppliedDataTypesService::default());
        service.find_and_display_applied_data_type_addresses(&StubDataType);
    }
}

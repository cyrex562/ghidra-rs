use crate::feature::seam_stubs::FunctionDatabase;

/// A function database that uses SQL as the query language.
///
/// Port of `ghidra.features.bsim.query.SQLFunctionDatabase`.
pub trait SQLFunctionDatabase: FunctionDatabase + Send + Sync {
    /// Generate SQL bitwise-and syntax for use in database query WHERE clause.
    ///
    /// # Arguments
    ///
    /// * `v1` - first value
    /// * `v2` - second value
    ///
    /// # Returns
    ///
    /// SQL bitwise-and expression as a string
    fn format_bit_and_sql(&self, v1: &str, v2: &str) -> String;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockSQLFunctionDatabase;

    impl FunctionDatabase for MockSQLFunctionDatabase {
        fn to_string(&self) -> String {
            "MockSQLFunctionDatabase".to_string()
        }

        fn get_integer(&self) -> i32 {
            0
        }

        fn is_password_change_allowed(&self) -> bool {
            false
        }

        fn change_password(&self, _new_password: &[char]) -> String {
            "Not supported".to_string()
        }

        fn get_status(&self) -> crate::feature::bsim::query::b_sim_jdbc_data_source::Status {
            crate::feature::bsim::query::b_sim_jdbc_data_source::Status::Unconnected
        }

        fn get_connection_type(&self) -> crate::feature::bsim::query::b_sim_jdbc_data_source::ConnectionType {
            crate::feature::bsim::query::b_sim_jdbc_data_source::ConnectionType::UnencryptedNoAuthentication
        }

        fn get_user_name(&self) -> String {
            "mock_user".to_string()
        }

        fn get_lsh_vector_factory(
            &self,
        ) -> std::sync::Arc<crate::generic::seam_stubs::LSHVectorFactory> {
            panic!("Not implemented in mock")
        }

        fn get_info(&self) -> Box<dyn crate::feature::seam_stubs::DatabaseInformation> {
            panic!("Not implemented in mock")
        }

        fn compare_layout(&self) -> i32 {
            0
        }

        fn get_server_info(&self) -> crate::feature::bsim::query::BSimServerInfo {
            panic!("Not implemented in mock")
        }

        fn get_url_string(&self) -> String {
            "jdbc:mock://localhost".to_string()
        }

        fn initialize(&self) -> bool {
            false
        }

        fn close(&self) {}

        fn get_last_error(&self) -> Box<dyn crate::feature::seam_stubs::BSimError> {
            panic!("Not implemented in mock")
        }

        fn query(&self, _query: &dyn crate::feature::seam_stubs::BSimQuery) -> Box<dyn crate::feature::bsim::query::protocol::QueryResponseRecord> {
            panic!("Not implemented in mock")
        }

        fn check_settings_for_query(
            &self,
            _manage: &dyn crate::feature::seam_stubs::DescriptionManager,
            _info: &dyn crate::feature::seam_stubs::DatabaseInformation,
        ) -> std::io::Result<()> {
            Ok(())
        }

        fn check_settings_for_insert(
            &self,
            _manage: &dyn crate::feature::seam_stubs::DescriptionManager,
            _info: &dyn crate::feature::seam_stubs::DatabaseInformation,
        ) -> std::io::Result<bool> {
            Ok(false)
        }

        fn construct_fatal_error(
            &self,
            _flags: i32,
            _newrec: &crate::feature::seam_stubs::ExecutableRecord,
            _orig: &crate::feature::seam_stubs::ExecutableRecord,
        ) -> String {
            "Fatal error".to_string()
        }

        fn construct_nonfatal_error(
            &self,
            _flags: i32,
            _newrec: &crate::feature::seam_stubs::ExecutableRecord,
            _orig: &crate::feature::seam_stubs::ExecutableRecord,
        ) -> String {
            "Non-fatal error".to_string()
        }

        fn load_configuration_template(&self, _configname: &str) -> std::io::Result<Box<dyn crate::feature::seam_stubs::Configuration>> {
            Err(std::io::Error::new(std::io::ErrorKind::NotFound, "Not implemented"))
        }

        fn generate_lsh_vector_factory(&self) -> Box<dyn crate::feature::seam_stubs::WeightedLSHCosineVectorFactory> {
            panic!("Not implemented in mock")
        }

        fn get_queried_functions_per_stage(&self) -> i32 {
            10
        }

        fn get_overview_functions_per_stage(&self) -> i32 {
            5
        }
    }

    impl SQLFunctionDatabase for MockSQLFunctionDatabase {
        fn format_bit_and_sql(&self, v1: &str, v2: &str) -> String {
            format!("({} & {})", v1, v2)
        }
    }

    #[test]
    fn test_format_bit_and_sql_simple() {
        let db = MockSQLFunctionDatabase;
        assert_eq!(db.format_bit_and_sql("col1", "0xFF"), "(col1 & 0xFF)");
    }

    #[test]
    fn test_format_bit_and_sql_complex() {
        let db = MockSQLFunctionDatabase;
        assert_eq!(
            db.format_bit_and_sql("table.column", "mask_value"),
            "(table.column & mask_value)"
        );
    }

    #[test]
    fn test_format_bit_and_sql_with_expressions() {
        let db = MockSQLFunctionDatabase;
        assert_eq!(
            db.format_bit_and_sql("(a + b)", "(c * d)"),
            "((a + b) & (c * d))"
        );
    }
}

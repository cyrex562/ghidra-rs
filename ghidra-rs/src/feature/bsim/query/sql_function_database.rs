use crate::feature::bsim::query::function_database::FunctionDatabase;

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
        fn get_status(&self) -> crate::feature::bsim::query::function_database::Status {
            crate::feature::bsim::query::function_database::Status::Unconnected
        }

        fn get_connection_type(
            &self,
        ) -> crate::feature::bsim::query::function_database::ConnectionType {
            crate::feature::bsim::query::function_database::ConnectionType::UnencryptedNoAuthentication
        }

        fn get_user_name(&self) -> String {
            "mock_user".to_string()
        }

        fn get_lsh_vector_factory(
            &self,
        ) -> std::sync::Arc<crate::generic::seam_stubs::LSHVectorFactory> {
            panic!("Not implemented in mock")
        }

        fn get_info(
            &self,
        ) -> Option<crate::feature::bsim::query::description::DatabaseInformation> {
            None
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

        fn get_last_error(&self) -> crate::feature::bsim::query::function_database::BSimError {
            panic!("Not implemented in mock")
        }

        fn query(
            &self,
            _query: &dyn crate::feature::bsim::query::protocol::BSimQuery,
        ) -> Option<Box<dyn crate::feature::bsim::query::protocol::QueryResponseRecord>> {
            None
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

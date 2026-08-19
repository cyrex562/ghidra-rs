//! Port of `ghidra.features.bsim.query.protocol.BSimQuery`.
//!
//! A BSim database query that can be serialized to/from XML and executed via
//! [`FunctionDatabase::query`](crate::feature::bsim::query::function_database::FunctionDatabase::query)
//! to produce a specific [`QueryResponseRecord`]. Java's `BSimQuery<R>` is an abstract class with
//! `name`/`response` instance fields and a mix of abstract methods (`saveXml`, `restoreXml`) and
//! concrete, overridable methods (`buildResponseTemplate`, `getDescriptionManager`,
//! `getLocalStagingCopy`) that default to no-ops/`null`. This port splits that into
//! [`BSimQueryBase`] (the shared state and its non-overridable accessors) and [`BSimQuery`] (the
//! trait covering the abstract and overridable methods, with defaults matching Java's), the same
//! way [`QueryResponseRecordBase`]/[`QueryResponseRecord`] split the sibling response hierarchy.

use std::io::{self, Write};

use crate::feature::bsim::query::description::DescriptionManager;
use crate::feature::bsim::query::function_database::FunctionDatabase;
use crate::feature::bsim::query::lsh_exception::LshException;
use crate::feature::bsim::query::protocol::QueryResponseRecord;
use crate::feature::seam_stubs::LSHVectorFactory;
use crate::util::seam_stubs::XmlPullParser;

/// The shared state carried by every `BSimQuery` implementation: the query's XML tag name, and
/// the response produced by executing it (if any).
///
/// Port of the `name` and `response` fields of `ghidra.features.bsim.query.protocol.BSimQuery`.
pub struct BSimQueryBase {
    name: String,
    response: Option<Box<dyn QueryResponseRecord>>,
}

impl BSimQueryBase {
    /// Java: `BSimQuery(String name)`.
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into(), response: None }
    }

    /// Java: `getName()`.
    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// Java: `clearResponse()`.
    pub fn clear_response(&mut self) {
        self.response = None;
    }

    /// Java: `getResponse()`.
    pub fn get_response(&self) -> Option<&dyn QueryResponseRecord> {
        self.response.as_deref()
    }

    /// Record the response produced by executing this query.
    pub fn set_response(&mut self, response: Box<dyn QueryResponseRecord>) {
        self.response = Some(response);
    }

    /// Move the response out of this query, leaving it cleared.
    ///
    /// Java hands out `getResponse()` and lets callers keep the reference alongside the query's
    /// own; a Rust caller that needs to own the accumulating global response takes it instead.
    pub fn take_response(&mut self) -> Option<Box<dyn QueryResponseRecord>> {
        self.response.take()
    }
}

/// The abstract and overridable operations of a `BSimQuery`, plus the concrete convenience
/// methods that dispatch through them.
///
/// Port of `ghidra.features.bsim.query.protocol.BSimQuery<R>`. Concrete implementations embed a
/// [`BSimQueryBase`] and implement `base()`/`base_mut()` alongside the abstract methods
/// (`save_xml`, `restore_xml`).
pub trait BSimQuery: Send + Sync {
    /// The shared state (name and response) every query carries.
    fn base(&self) -> &BSimQueryBase;

    /// Mutable access to the shared state.
    fn base_mut(&mut self) -> &mut BSimQueryBase;

    /// Build the response template for this query.
    ///
    /// Java: `buildResponseTemplate()`. Default implementation does nothing; most subclasses
    /// override it to allocate a matching [`QueryResponseRecord`].
    fn build_response_template(&mut self) {}

    /// Save this query to XML.
    ///
    /// Java: `saveXml(Writer)`.
    fn save_xml(&self, fwrite: &mut dyn Write) -> io::Result<()>;

    /// Restore this query from XML.
    ///
    /// Java: `restoreXml(XmlPullParser, LSHVectorFactory)`.
    fn restore_xml(
        &mut self,
        parser: &dyn XmlPullParser,
        vector_factory: &dyn LSHVectorFactory,
    ) -> Result<(), LshException>;

    /// Java: `getName()`. Default implementation delegates to the base.
    fn get_name(&self) -> &str {
        self.base().get_name()
    }

    /// Java: `clearResponse()`. Default implementation delegates to the base.
    fn clear_response(&mut self) {
        self.base_mut().clear_response()
    }

    /// Java: `getResponse()`. Default implementation delegates to the base.
    fn get_response(&self) -> Option<&dyn QueryResponseRecord> {
        self.base().get_response()
    }

    /// Java: `getDescriptionManager()`. Default implementation returns `None` (Java returns
    /// `null`); subclasses that hold functions to query override it.
    fn get_description_manager(&self) -> Option<&DescriptionManager> {
        None
    }

    /// Java: `getLocalStagingCopy()`. Default implementation returns `None` (Java returns
    /// `null`); subclasses used with `StagingManager` override it.
    fn get_local_staging_copy(&self) -> Option<Box<dyn BSimQuery>> {
        None
    }

    /// Execute this query via [`FunctionDatabase::query`].
    ///
    /// Java: `execute(FunctionDatabase)`, `final` in Java: subclasses influence the result only
    /// through [`FunctionDatabase::query`], not by overriding this method.
    fn execute(&self, database: &dyn FunctionDatabase) -> Option<Box<dyn QueryResponseRecord>>
    where
        Self: Sized,
    {
        database.query(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feature::bsim::query::b_sim_server_info::BSimServerInfo;
    use crate::feature::bsim::query::description::DatabaseInformation;
    use crate::feature::bsim::query::function_database::{BSimError, ConnectionType, ErrorCategory, Status};
    use crate::feature::bsim::query::protocol::QueryResponseRecordBase;
    use std::sync::Arc;

    /// A minimal response record, just enough to round-trip through `BSimQueryBase`.
    struct MockResponse {
        base: QueryResponseRecordBase,
    }

    impl QueryResponseRecord for MockResponse {
        fn base(&self) -> &QueryResponseRecordBase {
            &self.base
        }

        fn save_xml(&self, _fwrite: &mut dyn Write) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn base_new_starts_with_no_response() {
        let base = BSimQueryBase::new("mockquery");
        assert_eq!(base.get_name(), "mockquery");
        assert!(base.get_response().is_none());
    }

    #[test]
    fn base_set_and_clear_response_round_trip() {
        let mut base = BSimQueryBase::new("mockquery");
        base.set_response(Box::new(MockResponse { base: QueryResponseRecordBase::new("mockresponse") }));
        assert_eq!(base.get_response().unwrap().get_name(), "mockresponse");

        base.clear_response();
        assert!(base.get_response().is_none());
    }

    /// A query that just writes/reads its name, to exercise the trait's default methods.
    struct MockQuery {
        base: BSimQueryBase,
    }

    impl MockQuery {
        fn new() -> Self {
            Self { base: BSimQueryBase::new("mockquery") }
        }
    }

    impl BSimQuery for MockQuery {
        fn base(&self) -> &BSimQueryBase {
            &self.base
        }

        fn base_mut(&mut self) -> &mut BSimQueryBase {
            &mut self.base
        }

        fn save_xml(&self, fwrite: &mut dyn Write) -> io::Result<()> {
            write!(fwrite, "<{}/>", self.base.get_name())
        }

        fn restore_xml(
            &mut self,
            _parser: &dyn XmlPullParser,
            _vector_factory: &dyn LSHVectorFactory,
        ) -> Result<(), LshException> {
            Ok(())
        }
    }

    #[test]
    fn trait_default_get_name_delegates_to_base() {
        let query = MockQuery::new();
        assert_eq!(query.get_name(), "mockquery");
    }

    #[test]
    fn trait_defaults_match_java_null_returns() {
        let mut query = MockQuery::new();
        // Java: buildResponseTemplate() default body does nothing.
        query.build_response_template();
        // Java: getDescriptionManager() default returns null.
        assert!(query.get_description_manager().is_none());
        // Java: getLocalStagingCopy() default returns null.
        assert!(query.get_local_staging_copy().is_none());
    }

    #[test]
    fn trait_save_xml_matches_expected_output() {
        let query = MockQuery::new();
        let mut buffer = Vec::new();
        query.save_xml(&mut buffer).unwrap();
        assert_eq!(String::from_utf8(buffer).unwrap(), "<mockquery/>");
    }

    #[test]
    fn base_clear_response_via_trait_default() {
        let mut query = MockQuery::new();
        query
            .base_mut()
            .set_response(Box::new(MockResponse { base: QueryResponseRecordBase::new("r") }));
        assert!(query.get_response().is_some());
        query.clear_response();
        assert!(query.get_response().is_none());
    }

    /// A database whose `query()` hands back a fixed response, to exercise `execute()`.
    struct MockDatabase {
        response_name: &'static str,
    }

    impl FunctionDatabase for MockDatabase {
        fn get_status(&self) -> Status {
            Status::Ready
        }

        fn get_connection_type(&self) -> ConnectionType {
            ConnectionType::UnencryptedNoAuthentication
        }

        fn get_user_name(&self) -> String {
            "ghidra".to_string()
        }

        fn get_lsh_vector_factory(&self) -> Arc<crate::generic::seam_stubs::LSHVectorFactory> {
            unimplemented!("not used by this test")
        }

        fn get_info(&self) -> Option<DatabaseInformation> {
            None
        }

        fn compare_layout(&self) -> i32 {
            0
        }

        fn get_server_info(&self) -> BSimServerInfo {
            unimplemented!("not used by this test")
        }

        fn get_url_string(&self) -> String {
            "postgresql://myhost/myrepo".to_string()
        }

        fn initialize(&self) -> bool {
            true
        }

        fn close(&self) {}

        fn get_last_error(&self) -> BSimError {
            BSimError::new(ErrorCategory::Connection, "no connection")
        }

        fn query(&self, _query: &dyn BSimQuery) -> Option<Box<dyn QueryResponseRecord>> {
            Some(Box::new(MockResponse { base: QueryResponseRecordBase::new(self.response_name) }))
        }
    }

    #[test]
    fn execute_dispatches_to_function_database_query() {
        // Java: `execute(database)` is exactly `(R) database.query(this)`.
        let query = MockQuery::new();
        let database = MockDatabase { response_name: "mockresponse" };
        let response = query.execute(&database);
        assert_eq!(response.unwrap().get_name(), "mockresponse");
    }
}

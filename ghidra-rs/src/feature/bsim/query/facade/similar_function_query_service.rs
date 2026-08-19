//! Port of `ghidra.features.bsim.query.facade.SimilarFunctionQueryService`.
//!
//! A simple facade that lets a caller query a BSim server for functions matching a given set of
//! functions.
//!
//! # Divergences from the Java
//!
//! * Java's `AutoCloseable` becomes [`Drop`] plus the explicit [`close`](SimilarFunctionQueryService::close).
//! * Java's `protected FunctionDatabase createDatabase(String)` exists purely so tests can
//!   override it. Rust has no method overriding, so the seam is an injectable
//!   [`DatabaseFactory`] closure instead; when none is set the default builds a client through
//!   [`b_sim_client_factory`].
//! * `doQuery` returns the accumulated global response by *reference* in Java, which is then both
//!   handed to the listener and returned. Rust cannot alias an owned value that way, so the
//!   global response is an [`Arc`] the two share.
//! * Java's `FunctionSymbolIterator` is a one-line adapter from `FunctionSymbol` to its
//!   `Function`; here it is [`function_objects`], which is the same `getObject()` mapping.
//! * Java calls `GenSignatures.scanFunctions`, which drives a `ParallelDecompileTask`. That path
//!   is not ported, so [`GenSignatures::scan_functions_metadata`] -- the metadata-only variant
//!   that is ported -- stands in for it.
//! * Where Java would dereference a null `database` and throw a `NullPointerException` (the
//!   signature-generation and query-nearest paths), this returns a [`QueryDatabaseException`]
//!   saying the connection is not established.

use std::fmt;
use std::io;
use std::marker::PhantomData;
use std::sync::{Arc, Mutex};

use crate::feature::bsim::query::b_sim_client_factory;
use crate::feature::bsim::query::b_sim_server_info::BSimServerInfo;
use crate::feature::bsim::query::description::{DatabaseInformation, DescriptionManager};
use crate::feature::bsim::query::facade::{
    DatabaseInfo, QueryDatabaseException, SFResultsUpdateListener,
};
use crate::feature::bsim::query::function_database::{
    BSimError, ConnectionType, FunctionDatabase, Status,
};
use crate::feature::bsim::query::gen_signatures::GenSignatures;
use crate::feature::bsim::query::protocol::{
    BSimQuery, QueryNearest, QueryNearestVector, QueryResponseRecord,
};
use crate::feature::seam_stubs::{
    FunctionStaging, NullStaging, SFOverviewInfo, SFQueryInfo, SFQueryResult, StagingManager,
};
use crate::generic::seam_stubs::LSHVectorFactory;
use crate::program::database::symbol::FunctionSymbol;
use crate::program::model::listing::{Function, Program};
use crate::util::exception::CancelledException;
use crate::util::task::{DummyMonitor, TaskMonitor};

/// Builds the [`FunctionDatabase`] client for a server URL.
///
/// Stands in for Java's `protected createDatabase(String)`, which subclasses override in tests.
pub type DatabaseFactory =
    Box<dyn Fn(&str) -> io::Result<Box<dyn FunctionDatabase>> + Send + Sync>;

/// The two exceptions the querying methods throw, as one error type.
///
/// Java: `throws QueryDatabaseException, CancelledException`.
#[derive(Debug)]
pub enum QueryError {
    /// Java: `QueryDatabaseException`.
    Database(QueryDatabaseException),
    /// Java: `CancelledException`, raised by `TaskMonitor.checkCancelled()`.
    Cancelled(CancelledException),
}

impl fmt::Display for QueryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            QueryError::Database(e) => e.fmt(f),
            QueryError::Cancelled(e) => write!(f, "CancelledException: {}", e.0),
        }
    }
}

impl PartialEq for QueryError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (QueryError::Database(a), QueryError::Database(b)) => a == b,
            (QueryError::Cancelled(a), QueryError::Cancelled(b)) => a.0 == b.0,
            _ => false,
        }
    }
}

impl std::error::Error for QueryError {}

impl From<QueryDatabaseException> for QueryError {
    fn from(e: QueryDatabaseException) -> Self {
        QueryError::Database(e)
    }
}

impl From<CancelledException> for QueryError {
    fn from(e: CancelledException) -> Self {
        QueryError::Cancelled(e)
    }
}

/// A listener that does nothing, used when the caller supplies none.
///
/// Port of the private inner class `SimilarFunctionQueryService.NullListener<R>`.
struct NullListener<R>(PhantomData<fn() -> R>);

impl<R> NullListener<R> {
    fn new() -> Self {
        Self(PhantomData)
    }
}

impl<R> SFResultsUpdateListener<R> for NullListener<R> {
    fn result_added(&self, _partial_response: &dyn QueryResponseRecord) {
        // no-op
    }

    fn set_final_result(&self, _result: Option<R>) {
        // no-op
    }
}

/// Java's `FunctionSymbolIterator`: the `Function` behind each queried `FunctionSymbol`.
///
/// Symbols with no function object are dropped; Java's iterator would yield `null` for them and
/// the consumers all skip nulls.
fn function_objects(symbols: &[Box<dyn FunctionSymbol>]) -> Vec<Arc<dyn Function>> {
    symbols.iter().filter_map(|symbol| symbol.get_object()).collect()
}

/// A facade for querying a BSim server for functions similar to a given set of functions.
///
/// Port of `ghidra.features.bsim.query.facade.SimilarFunctionQueryService`.
pub struct SimilarFunctionQueryService {
    database: Option<Box<dyn FunctionDatabase>>,

    /// Program associated with the signature generator.
    program: Arc<Mutex<dyn Program>>,

    /// Cache of signature information collected so far.
    signature_generator: Option<GenSignatures>,

    /// Number of stages to place a query with; 0 means "get it from the query".
    num_stages: i32,

    database_factory: Option<DatabaseFactory>,
}

impl SimilarFunctionQueryService {
    /// Java: `SimilarFunctionQueryService(Program)`.
    pub fn new(program: Arc<Mutex<dyn Program>>) -> Self {
        Self {
            database: None,
            program,
            signature_generator: None,
            num_stages: 0,
            database_factory: None,
        }
    }

    /// Java: the package-private `SimilarFunctionQueryService(Program, FunctionDatabase)`, which
    /// exists for dependency injection in tests.
    pub(crate) fn with_database(
        program: Arc<Mutex<dyn Program>>,
        database: Box<dyn FunctionDatabase>,
    ) -> Self {
        Self {
            database: Some(database),
            program,
            signature_generator: None,
            num_stages: 0,
            database_factory: None,
        }
    }

    /// Install the seam standing in for Java's overridable `createDatabase(String)`.
    pub(crate) fn set_database_factory(&mut self, factory: DatabaseFactory) {
        self.database_factory = Some(factory);
    }

    /// Given a list of functions to query, prepare the final [`QueryNearest`] object which will
    /// be marshalled to the server. This involves generating the signatures for each of the
    /// functions and accumulating their function descriptions.
    ///
    /// Java: `generateQueryNearest(SFQueryInfo, TaskMonitor)`.
    pub fn generate_query_nearest(
        &mut self,
        query_info: &dyn SFQueryInfo,
        monitor: &dyn TaskMonitor,
    ) -> Result<QueryNearest, QueryDatabaseException> {
        let mut result = query_info.build_query_nearest();
        let functions = query_info.get_functions();
        self.do_signature_generation(&functions, monitor)?;
        self.transfer_cached_functions(
            &mut result.manage,
            &functions,
            query_info.get_pre_filter(),
        )?;
        Ok(result)
    }

    /// The overview counterpart of [`generate_query_nearest`](Self::generate_query_nearest).
    ///
    /// Java: `generateQueryNearestVector(SFOverviewInfo, TaskMonitor)`.
    pub fn generate_query_nearest_vector(
        &mut self,
        overview_info: &dyn SFOverviewInfo,
        monitor: &dyn TaskMonitor,
    ) -> Result<QueryNearestVector, QueryDatabaseException> {
        let mut result = overview_info.build_query_nearest_vector();
        let functions = overview_info.get_functions();
        self.do_signature_generation(&functions, monitor)?;
        self.transfer_cached_functions(
            &mut result.manage,
            &functions,
            overview_info.get_pre_filter(),
        )?;
        Ok(result)
    }

    /// Issue a password change request to the server.
    ///
    /// Returns `None` if the change was successful, or the error message.
    ///
    /// Java: the deprecated `changePassword(String, char[])`, which builds a `PasswordChange`
    /// request and executes it. Assembling that request needs `ResponsePassword`, which is not
    /// ported; [`FunctionDatabase::change_password`] is the ported form of the same exchange, so
    /// this delegates to it after Java's `Status.Ready` guard.
    #[deprecated(note = "Java marks changePassword deprecated")]
    pub fn change_password(&self, username: &str, new_password: &[char]) -> Option<String> {
        let _ = username; // Java sends it as `PasswordChange.username`.
        match &self.database {
            Some(database) if database.get_status() == Status::Ready => {
                database.change_password(new_password)
            }
            _ => Some("Connection not established".to_string()),
        }
    }

    /// Query the given server with the parameters provided by `query_info`.
    ///
    /// Returns the result object containing the retrieved similar functions.
    ///
    /// Java: `querySimilarFunctions(SFQueryInfo, SFResultsUpdateListener<SFQueryResult>, TaskMonitor)`.
    /// As in Java, the listener is told the final result even when the query fails.
    pub fn query_similar_functions(
        &mut self,
        query_info: &dyn SFQueryInfo,
        listener: Option<&dyn SFResultsUpdateListener<SFQueryResult>>,
        monitor: Option<&dyn TaskMonitor>,
    ) -> Result<SFQueryResult, QueryError> {
        let dummy = DummyMonitor;
        let monitor = monitor.unwrap_or(&dummy);
        let null_listener = NullListener::new();
        let listener = listener.unwrap_or(&null_listener);

        let result = self.do_query_similar_functions(query_info, listener, monitor);
        // Java's `finally` block: the listener always hears the final result, null on failure.
        listener.set_final_result(result.as_ref().ok().cloned());
        result
    }

    fn do_query_similar_functions(
        &mut self,
        query_info: &dyn SFQueryInfo,
        listener: &dyn SFResultsUpdateListener<SFQueryResult>,
        monitor: &dyn TaskMonitor,
    ) -> Result<SFQueryResult, QueryError> {
        self.check_ready("Connection with database not established")?;

        //
        // Perform the required initialization:
        // -Initialize signature generator
        // -Hash the functions
        // -Create the query
        // -Create the staging
        //
        let mut query = self.generate_query_nearest(query_info, monitor)?;

        let database = self.database.as_deref().expect("connection checked above");
        let mut local_num_stages = self.num_stages;
        if local_num_stages == 0 {
            let funcs_per_stage = database.get_queried_functions_per_stage();
            local_num_stages = query_info.get_number_of_stages(funcs_per_stage);
        }
        let mut staging_manager = Self::create_staging_manager(
            query_info.get_functions().len() as i32,
            local_num_stages,
        );

        //
        // Perform the query
        //
        let response = Self::do_query(
            database,
            &mut query,
            staging_manager.as_mut(),
            listener,
            monitor,
        )?;

        //
        // Create the results for our facade interface
        //
        let database_info = DatabaseInfo::new(
            database.get_url_string(),
            database.get_info().unwrap_or_else(DatabaseInformation::new),
        );
        Ok(SFQueryResult::new(database_info, response))
    }

    /// Query the given server for similar function overview information.
    ///
    /// Java: `overviewSimilarFunctions(SFOverviewInfo, SFResultsUpdateListener<ResponseNearestVector>, TaskMonitor)`,
    /// which casts the raw response to `ResponseNearestVector`. That type is not ported and Rust
    /// has no downcast for it, so the raw response record is returned.
    pub fn overview_similar_functions(
        &mut self,
        overview_info: &dyn SFOverviewInfo,
        listener: Option<&dyn SFResultsUpdateListener<Arc<dyn QueryResponseRecord>>>,
        monitor: Option<&dyn TaskMonitor>,
    ) -> Result<Arc<dyn QueryResponseRecord>, QueryError> {
        let dummy = DummyMonitor;
        let monitor = monitor.unwrap_or(&dummy);
        let null_listener = NullListener::new();
        let listener = listener.unwrap_or(&null_listener);

        let result = self.do_overview_similar_functions(overview_info, listener, monitor);
        listener.set_final_result(result.as_ref().ok().cloned());
        result
    }

    fn do_overview_similar_functions(
        &mut self,
        overview_info: &dyn SFOverviewInfo,
        listener: &dyn SFResultsUpdateListener<Arc<dyn QueryResponseRecord>>,
        monitor: &dyn TaskMonitor,
    ) -> Result<Arc<dyn QueryResponseRecord>, QueryError> {
        self.check_ready("Connection to database not established")?;

        let mut query = self.generate_query_nearest_vector(overview_info, monitor)?;

        let database = self.database.as_deref().expect("connection checked above");
        let mut local_num_stages = self.num_stages;
        if local_num_stages == 0 {
            let funcs_per_stage = database.get_overview_functions_per_stage();
            local_num_stages = overview_info.get_number_of_stages(funcs_per_stage);
        }
        let mut staging_manager = Self::create_staging_manager(
            overview_info.get_functions().len() as i32,
            local_num_stages,
        );

        Self::do_query(database, &mut query, staging_manager.as_mut(), listener, monitor)
    }

    /// A lower-level (more flexible) query of the database. The query is not staged unless a
    /// `staging_manager` is supplied.
    ///
    /// Java: `queryRaw(BSimQuery<?>, StagingManager, SFResultsUpdateListener<QueryResponseRecord>, TaskMonitor)`.
    pub fn query_raw(
        &mut self,
        query: &mut dyn BSimQuery,
        staging_manager: Option<Box<dyn StagingManager>>,
        listener: Option<&dyn SFResultsUpdateListener<Arc<dyn QueryResponseRecord>>>,
        monitor: Option<&dyn TaskMonitor>,
    ) -> Result<Arc<dyn QueryResponseRecord>, QueryError> {
        let dummy = DummyMonitor;
        let monitor = monitor.unwrap_or(&dummy);
        let null_listener = NullListener::new();
        let listener = listener.unwrap_or(&null_listener);
        let mut staging_manager =
            staging_manager.unwrap_or_else(|| Box::new(NullStaging::new()));

        let result = match self.check_ready("Connection to database not established") {
            Ok(()) => {
                let database = self.database.as_deref().expect("connection checked above");
                Self::do_query(database, query, staging_manager.as_mut(), listener, monitor)
            }
            Err(e) => Err(e.into()),
        };
        listener.set_final_result(result.as_ref().ok().cloned());
        result
    }

    /// Java: `dispose()`, an alias for [`close`](Self::close).
    pub fn dispose(&mut self) {
        self.close();
    }

    /// Java: `close()`, the `AutoCloseable` implementation.
    pub fn close(&mut self) {
        if let Some(database) = self.database.take() {
            database.close();
        }
        if let Some(mut signature_generator) = self.signature_generator.take() {
            signature_generator.dispose();
        }
    }

    /// Java: `setNumberOfStages(int)`.
    pub fn set_number_of_stages(&mut self, val: i32) {
        self.num_stages = val;
    }

    /// Java: `updateProgram(Program)`. The cached signature generator belongs to the old program,
    /// so it is dropped whenever the program actually changes (Java compares by reference, which
    /// is [`Arc::ptr_eq`] here).
    pub fn update_program(&mut self, new_program: Arc<Mutex<dyn Program>>) {
        if !Arc::ptr_eq(&self.program, &new_program) {
            self.program = new_program;
            self.signature_generator = None;
        }
    }

    /// Run `query` against `database`, one stage at a time, merging each staged response into the
    /// global one.
    ///
    /// Java: the private `doQuery(BSimQuery<?>, StagingManager, SFResultsUpdateListener<?>, TaskMonitor)`.
    fn do_query<R>(
        database: &dyn FunctionDatabase,
        query: &mut dyn BSimQuery,
        staging_manager: &mut dyn StagingManager,
        listener: &dyn SFResultsUpdateListener<R>,
        monitor: &dyn TaskMonitor,
    ) -> Result<Arc<dyn QueryResponseRecord>, QueryError> {
        let mut have_more = staging_manager
            .initialize(&*query)
            .map_err(|e| QueryDatabaseException::new(e.message()))?;
        query.build_response_template();

        let mut global_response = query.base_mut().take_response();

        monitor.set_message("Querying database");
        monitor.initialize(staging_manager.get_total_size() as i64);

        while have_more {
            monitor.check_cancelled()?;

            // Get the current staged form of the query. `None` means the global query itself.
            let response = {
                let staged: &dyn BSimQuery = match staging_manager.get_query() {
                    Some(staged) => staged,
                    None => &*query,
                };
                database.query(staged)
            };

            let Some(response) = response else {
                return Err(QueryDatabaseException::new(database.get_last_error().message).into());
            };

            match global_response.as_ref() {
                // Merge the staged response with the global response.
                Some(global) => {
                    global
                        .merge_results(response.as_ref())
                        .map_err(|e| QueryDatabaseException::new(e.message()))?;
                    listener.result_added(response.as_ref());
                }
                // Java's template always exists; the ported queries cannot build one yet, so the
                // first staged response becomes the global one.
                None => {
                    listener.result_added(response.as_ref());
                    global_response = Some(response);
                }
            }

            have_more = staging_manager
                .next_stage()
                .map_err(|e| QueryDatabaseException::new(e.message()))?;
            if have_more {
                // Make space for the next stage.
                match staging_manager.get_query() {
                    Some(staged) => staged.clear_response(),
                    None => query.clear_response(),
                }
            }
            monitor.set_progress(staging_manager.get_queries_made() as i64);
        }

        global_response
            .map(Arc::from)
            .ok_or_else(|| QueryDatabaseException::new("Query produced no response").into())
    }

    /// The [`BSimServerInfo`] for this database, or `None` if not currently associated with a
    /// [`FunctionDatabase`].
    ///
    /// Java: `getServerInfo()`.
    pub fn get_server_info(&self) -> Option<BSimServerInfo> {
        self.database.as_ref().map(|database| database.get_server_info())
    }

    /// Java: `getDatabaseStatus()`, which reports `Unconnected` when there is no database.
    pub fn get_database_status(&self) -> Status {
        match &self.database {
            Some(database) => database.get_status(),
            None => Status::Unconnected,
        }
    }

    /// Java: `getDatabaseConnectionType()`, which reports `Unencrypted_No_Authentication` when
    /// there is no database.
    pub fn get_database_connection_type(&self) -> ConnectionType {
        match &self.database {
            Some(database) => database.get_connection_type(),
            None => ConnectionType::UnencryptedNoAuthentication,
        }
    }

    /// Java: `getDatabaseInformation()`.
    pub fn get_database_information(&self) -> Option<DatabaseInformation> {
        self.database.as_ref().and_then(|database| database.get_info())
    }

    /// Java: `getUserName()`.
    pub fn get_user_name(&self) -> Option<String> {
        self.database.as_ref().map(|database| database.get_user_name())
    }

    /// Java: `getLSHVectorFactory()`.
    pub fn get_lsh_vector_factory(&self) -> Option<Arc<LSHVectorFactory>> {
        self.database.as_ref().map(|database| database.get_lsh_vector_factory())
    }

    /// Java: `getLastError()`.
    pub fn get_last_error(&self) -> Option<BSimError> {
        self.database.as_ref().map(|database| database.get_last_error())
    }

    /// A string explaining the database compatibility between this client and the server, or
    /// `None` when the two are compatible (or compatibility could not be determined).
    ///
    /// Java: `getDatabaseCompatibility()`.
    pub fn get_database_compatibility(&self) -> Option<String> {
        let database = self.database.as_ref()?;
        database.get_info()?;
        match database.compare_layout() {
            compare if compare < 0 => Some(
                "This client is incompatible with the earlier database format on the server"
                    .to_string(),
            ),
            compare if compare > 0 => Some(
                "The server is using a later database format than is supported by this client"
                    .to_string(),
            ),
            _ => None,
        }
    }

    /// Java: the overridable `protected createDatabase(String)`.
    ///
    /// Java derives the BSim URL first, which also understands `ghidra://` URLs by inferring a
    /// PostgreSQL server on the same host; that path needs a `GhidraURL`, so the default here
    /// takes the BSim-protocol branch of `deriveBSimURL`, namely
    /// [`b_sim_client_factory::build_url`].
    fn create_database(&self, url_string: &str) -> io::Result<Box<dyn FunctionDatabase>> {
        match &self.database_factory {
            Some(factory) => factory(url_string),
            None => b_sim_client_factory::build_client(
                &b_sim_client_factory::build_url(url_string)?,
                false,
            ),
        }
    }

    /// Java: `initializeDatabase(String)`.
    pub fn initialize_database(
        &mut self,
        server_url_string: &str,
    ) -> Result<(), QueryDatabaseException> {
        if self.is_same_database(server_url_string)
            && self.get_database_status() == Status::Ready
        {
            return Ok(()); // Trying to connect with server which is still ready
        }

        if let Some(database) = self.database.take() {
            database.close(); // Shutdown old connection (or erroneous connection)
        }

        // Java: `catch (MalformedURLException e)`.
        let database = self
            .create_database(server_url_string)
            .map_err(|e| QueryDatabaseException::new(format!("Bad database URL: {e}")))?;
        let success = database.initialize();
        self.database = Some(database);
        if !success {
            let error_msg = self
                .database
                .as_ref()
                .map(|database| database.get_last_error().message)
                .unwrap_or_default();
            return Err(QueryDatabaseException::new(error_msg));
        }
        Ok(())
    }

    fn is_same_database(&self, server_url_string: &str) -> bool {
        self.database.as_ref().is_some_and(|db| db.get_url_string() == server_url_string)
    }

    /// Java's repeated `database == null || database.getStatus() != Status.Ready` guard.
    fn check_ready(&self, message: &str) -> Result<(), QueryDatabaseException> {
        if self.get_database_status() == Status::Ready {
            Ok(())
        } else {
            Err(QueryDatabaseException::new(message))
        }
    }

    /// Java: `doSignatureGeneration(Set<FunctionSymbol>, TaskMonitor)`.
    fn do_signature_generation(
        &mut self,
        functions: &[Box<dyn FunctionSymbol>],
        monitor: &dyn TaskMonitor,
    ) -> Result<(), QueryDatabaseException> {
        if functions.is_empty() {
            return Ok(());
        }

        if self.signature_generator.is_none() {
            self.signature_generator = Some(self.create_signature_generator()?);
        }
        let vector_factory = self
            .database
            .as_ref()
            .ok_or_else(|| QueryDatabaseException::new("Connection with database not established"))?
            .get_lsh_vector_factory();

        let generator = self.signature_generator.as_mut().expect("created just above");
        generator
            .set_vector_factory(vector_factory)
            .map_err(|e| QueryDatabaseException::from_error(&e))?;

        monitor.set_message("Hashing function signatures...");
        // TODO: do this work in a loop so that one failure doesn't stop the entire process...the
        //       downside is losing parallelization
        generator.scan_functions_metadata(Some(function_objects(functions)), Some(monitor));
        Ok(())
    }

    /// Java: the `signatureGenerator.transferCachedFunctions(...)` call shared by the two
    /// `generateQuery*` methods. Java would throw a `NullPointerException` when no signature
    /// generator has been built yet (which happens exactly when there are no functions to
    /// transfer); here there is simply nothing to transfer.
    fn transfer_cached_functions(
        &self,
        otherman: &mut DescriptionManager,
        functions: &[Box<dyn FunctionSymbol>],
        pre_filter: &crate::feature::seam_stubs::PreFilter,
    ) -> Result<(), QueryDatabaseException> {
        let Some(generator) = self.signature_generator.as_ref() else {
            return Ok(());
        };
        generator
            .transfer_cached_functions(otherman, function_objects(functions), pre_filter)
            .map_err(|e| QueryDatabaseException::new(e.message()))?;
        Ok(())
    }

    /// Java: `createSignatureGenerator()`.
    fn create_signature_generator(&self) -> Result<GenSignatures, QueryDatabaseException> {
        let mut new_signature_generator = GenSignatures::new(false);
        new_signature_generator
            .open_program(Arc::clone(&self.program), None, None, None, None, None)
            .map_err(|e| {
                QueryDatabaseException::with_cause("Unable to signature functions", &e)
            })?;
        Ok(new_signature_generator)
    }

    /// Java: `createStagingManager(int numqueries, int stages)`.
    fn create_staging_manager(numqueries: i32, stages: i32) -> Box<dyn StagingManager> {
        if stages == 1 {
            return Box::new(NullStaging::new());
        }

        let number_of_functions_per_query = if stages > numqueries {
            // when the number of stages is greater than the number of functions, lower the stage
            // count to execute one function at a time (stages becomes numqueries)
            1
        } else {
            // Java is `(int) Math.ceil(numqueries / stages)`: the division is integer division,
            // so the ceiling never rounds anything up. Kept as-is.
            numqueries / stages
        };

        Box::new(FunctionStaging::new(number_of_functions_per_query))
    }
}

impl Drop for SimilarFunctionQueryService {
    /// Java: `AutoCloseable`, i.e. `close()` at the end of a try-with-resources block.
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feature::bsim::query::function_database::ErrorCategory;
    use crate::feature::bsim::query::protocol::QueryResponseRecordBase;
    use crate::framework::model::DomainObject;
    use std::io::Write;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct MockProgram;
    impl DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }
        fn get_language_id(&self) -> String {
            "x86:LE:64:default".to_string()
        }
    }

    /// `Arc<dyn QueryResponseRecord>` has no `Debug`, so `unwrap_err` is unavailable on the
    /// query results.
    fn expect_err(
        result: Result<Arc<dyn QueryResponseRecord>, QueryError>,
    ) -> QueryError {
        match result {
            Ok(response) => panic!("expected an error, got response {}", response.get_name()),
            Err(e) => e,
        }
    }

    fn mock_program() -> Arc<Mutex<dyn Program>> {
        Arc::new(Mutex::new(MockProgram))
    }

    struct MockResponse {
        base: QueryResponseRecordBase,
    }

    impl MockResponse {
        fn new(name: &str) -> Self {
            Self { base: QueryResponseRecordBase::new(name) }
        }
    }

    impl QueryResponseRecord for MockResponse {
        fn base(&self) -> &QueryResponseRecordBase {
            &self.base
        }

        fn save_xml(&self, _fwrite: &mut dyn Write) -> io::Result<()> {
            Ok(())
        }
    }

    struct MockDatabase {
        status: Status,
        url: String,
        info: Option<DatabaseInformation>,
        layout: i32,
        initialize_succeeds: bool,
        respond: bool,
        queries: AtomicUsize,
    }

    impl MockDatabase {
        fn ready() -> Self {
            Self {
                status: Status::Ready,
                url: "postgresql://myhost/myrepo".to_string(),
                info: Some(DatabaseInformation::new()),
                layout: 0,
                initialize_succeeds: true,
                respond: true,
                queries: AtomicUsize::new(0),
            }
        }
    }

    impl FunctionDatabase for MockDatabase {
        fn get_status(&self) -> Status {
            self.status
        }

        fn get_connection_type(&self) -> ConnectionType {
            ConnectionType::SslPasswordAuthentication
        }

        fn get_user_name(&self) -> String {
            "ghidra".to_string()
        }

        fn get_lsh_vector_factory(&self) -> Arc<LSHVectorFactory> {
            unimplemented!("not used by these tests")
        }

        fn get_info(&self) -> Option<DatabaseInformation> {
            self.info.clone()
        }

        fn compare_layout(&self) -> i32 {
            self.layout
        }

        fn get_server_info(&self) -> BSimServerInfo {
            unimplemented!("not used by these tests")
        }

        fn get_url_string(&self) -> String {
            self.url.clone()
        }

        fn initialize(&self) -> bool {
            self.initialize_succeeds
        }

        fn close(&self) {}

        fn get_last_error(&self) -> BSimError {
            BSimError::new(ErrorCategory::Connection, "mock database error")
        }

        fn query(&self, _query: &dyn BSimQuery) -> Option<Box<dyn QueryResponseRecord>> {
            self.queries.fetch_add(1, Ordering::SeqCst);
            self.respond.then(|| Box::new(MockResponse::new("responsenearest")) as Box<_>)
        }
    }

    /// Records what the listener was told, the way Java's real listeners do.
    #[derive(Default)]
    struct RecordingListener {
        added: AtomicUsize,
        final_set: AtomicUsize,
        final_was_some: AtomicUsize,
    }

    impl<R> SFResultsUpdateListener<R> for RecordingListener {
        fn result_added(&self, _partial_response: &dyn QueryResponseRecord) {
            self.added.fetch_add(1, Ordering::SeqCst);
        }

        fn set_final_result(&self, result: Option<R>) {
            self.final_set.fetch_add(1, Ordering::SeqCst);
            if result.is_some() {
                self.final_was_some.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    #[test]
    fn accessors_report_javas_no_database_defaults() {
        let service = SimilarFunctionQueryService::new(mock_program());

        // Java: getDatabaseStatus() -> Status.Unconnected when database == null.
        assert_eq!(service.get_database_status(), Status::Unconnected);
        // Java: getDatabaseConnectionType() -> ConnectionType.Unencrypted_No_Authentication.
        assert_eq!(
            service.get_database_connection_type(),
            ConnectionType::UnencryptedNoAuthentication
        );
        // Java: each of these returns null when database == null.
        assert!(service.get_server_info().is_none());
        assert!(service.get_database_information().is_none());
        assert!(service.get_user_name().is_none());
        assert!(service.get_last_error().is_none());
        assert!(service.get_database_compatibility().is_none());
    }

    #[test]
    fn accessors_delegate_to_the_database() {
        let service = SimilarFunctionQueryService::with_database(
            mock_program(),
            Box::new(MockDatabase::ready()),
        );

        assert_eq!(service.get_database_status(), Status::Ready);
        assert_eq!(
            service.get_database_connection_type(),
            ConnectionType::SslPasswordAuthentication
        );
        assert_eq!(service.get_user_name().unwrap(), "ghidra");
        assert_eq!(service.get_last_error().unwrap().message, "mock database error");
        assert!(service.get_database_information().is_some());
    }

    #[test]
    fn database_compatibility_matches_javas_three_layout_cases() {
        let mut database = MockDatabase::ready();
        database.layout = -1;
        let service =
            SimilarFunctionQueryService::with_database(mock_program(), Box::new(database));
        assert_eq!(
            service.get_database_compatibility().unwrap(),
            "This client is incompatible with the earlier database format on the server"
        );

        let mut database = MockDatabase::ready();
        database.layout = 1;
        let service =
            SimilarFunctionQueryService::with_database(mock_program(), Box::new(database));
        assert_eq!(
            service.get_database_compatibility().unwrap(),
            "The server is using a later database format than is supported by this client"
        );

        // Java: layout 0 -> null (compatible).
        let service = SimilarFunctionQueryService::with_database(
            mock_program(),
            Box::new(MockDatabase::ready()),
        );
        assert!(service.get_database_compatibility().is_none());

        // Java: info == null -> null, whatever the layout says.
        let mut database = MockDatabase::ready();
        database.info = None;
        database.layout = -1;
        let service =
            SimilarFunctionQueryService::with_database(mock_program(), Box::new(database));
        assert!(service.get_database_compatibility().is_none());
    }

    #[test]
    #[allow(deprecated)]
    fn change_password_requires_a_ready_connection() {
        let service = SimilarFunctionQueryService::new(mock_program());
        assert_eq!(
            service.change_password("ghidra", &['a', 'b']).unwrap(),
            "Connection not established"
        );

        let mut database = MockDatabase::ready();
        database.status = Status::Error;
        let service =
            SimilarFunctionQueryService::with_database(mock_program(), Box::new(database));
        assert_eq!(
            service.change_password("ghidra", &['a', 'b']).unwrap(),
            "Connection not established"
        );
    }

    #[test]
    fn create_staging_manager_matches_javas_stage_arithmetic() {
        // Java: stages == 1 -> NullStaging, which is always a single stage.
        let mut staging = SimilarFunctionQueryService::create_staging_manager(20, 1);
        let query = QueryNearest::new();
        assert!(!staging.initialize(&query).unwrap()); // no functions -> no initial stage
        assert!(!staging.next_stage().unwrap());
        assert!(staging.get_query().is_none());

        // Java: stages > numqueries -> one function per query.
        let staging = SimilarFunctionQueryService::create_staging_manager(3, 10);
        assert_eq!(staging.get_total_size(), 0);

        // Java: (int) Math.ceil(numqueries / stages) is plain integer division.
        let staging = SimilarFunctionQueryService::create_staging_manager(20, 3);
        assert_eq!(staging.get_total_size(), 0);
    }

    #[test]
    fn query_raw_rejects_a_connection_that_is_not_ready() {
        let mut service = SimilarFunctionQueryService::new(mock_program());
        let mut query = QueryNearest::new();
        let listener = RecordingListener::default();

        let err = expect_err(service.query_raw(&mut query, None, Some(&listener), None));
        assert_eq!(
            err,
            QueryError::Database(QueryDatabaseException::new(
                "Connection to database not established"
            ))
        );
        // Java's `finally` still reports a (null) final result.
        assert_eq!(listener.final_set.load(Ordering::SeqCst), 1);
        assert_eq!(listener.final_was_some.load(Ordering::SeqCst), 0);
        assert_eq!(listener.added.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn query_raw_runs_one_stage_and_reports_the_response() {
        let mut service = SimilarFunctionQueryService::with_database(
            mock_program(),
            Box::new(MockDatabase::ready()),
        );
        // NullStaging.initialize returns true when the query carries no description manager;
        // QueryNearest always has one, so give it a query without one to get a single stage.
        let mut query = QueryNearest::new();
        query.manage = DescriptionManager::new();
        let listener = RecordingListener::default();

        // With an empty description manager NullStaging reports no initial stage, exactly as
        // Java does, so no query is sent and there is no response to return.
        let err = expect_err(service.query_raw(
            &mut query,
            Some(Box::new(NullStaging::new())),
            Some(&listener),
            None,
        ));
        assert_eq!(
            err,
            QueryError::Database(QueryDatabaseException::new("Query produced no response"))
        );
        assert_eq!(listener.added.load(Ordering::SeqCst), 0);
    }

    /// A staging manager that reports a fixed number of stages, standing in for a populated
    /// `FunctionStaging`.
    struct CountingStaging {
        remaining: i32,
        queries_made: i32,
    }

    impl StagingManager for CountingStaging {
        fn get_total_size(&self) -> i32 {
            3
        }

        fn get_queries_made(&self) -> i32 {
            self.queries_made
        }

        fn get_query(&mut self) -> Option<&mut (dyn BSimQuery + 'static)> {
            None
        }

        fn initialize(
            &mut self,
            _query: &dyn BSimQuery,
        ) -> Result<bool, crate::feature::bsim::query::LshException> {
            Ok(self.remaining > 0)
        }

        fn next_stage(&mut self) -> Result<bool, crate::feature::bsim::query::LshException> {
            self.remaining -= 1;
            self.queries_made += 1;
            Ok(self.remaining > 0)
        }
    }

    #[test]
    fn query_raw_merges_every_stage_and_notifies_the_listener() {
        let mut service = SimilarFunctionQueryService::with_database(
            mock_program(),
            Box::new(MockDatabase::ready()),
        );
        let mut query = QueryNearest::new();
        let listener = RecordingListener::default();

        let response = service
            .query_raw(
                &mut query,
                Some(Box::new(CountingStaging { remaining: 3, queries_made: 0 })),
                Some(&listener),
                None,
            )
            .unwrap();

        assert_eq!(response.get_name(), "responsenearest");
        // Java: resultAdded is called once per staged response.
        assert_eq!(listener.added.load(Ordering::SeqCst), 3);
        assert_eq!(listener.final_set.load(Ordering::SeqCst), 1);
        assert_eq!(listener.final_was_some.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn query_raw_reports_the_databases_last_error_when_a_stage_fails() {
        let mut database = MockDatabase::ready();
        database.respond = false;
        let mut service =
            SimilarFunctionQueryService::with_database(mock_program(), Box::new(database));
        let mut query = QueryNearest::new();

        let err = expect_err(service.query_raw(
            &mut query,
            Some(Box::new(CountingStaging { remaining: 1, queries_made: 0 })),
            None,
            None,
        ));
        // Java: throw new LSHException(database.getLastError().message), rewrapped by queryRaw.
        assert_eq!(
            err,
            QueryError::Database(QueryDatabaseException::new("mock database error"))
        );
    }

    #[test]
    fn initialize_database_uses_the_injected_factory_and_reports_failure() {
        let mut service = SimilarFunctionQueryService::new(mock_program());
        service.set_database_factory(Box::new(|_url| {
            let mut database = MockDatabase::ready();
            database.initialize_succeeds = false;
            Ok(Box::new(database) as Box<dyn FunctionDatabase>)
        }));

        // Java: !success -> QueryDatabaseException carrying getLastError().message.
        let err = service.initialize_database("postgresql://myhost/myrepo").unwrap_err();
        assert_eq!(err.message(), "mock database error");
        // Java keeps the database it just built, even though initialization failed.
        assert_eq!(service.get_database_status(), Status::Ready);
    }

    #[test]
    fn initialize_database_is_a_no_op_for_the_same_ready_server() {
        let mut service = SimilarFunctionQueryService::with_database(
            mock_program(),
            Box::new(MockDatabase::ready()),
        );
        let calls = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&calls);
        service.set_database_factory(Box::new(move |_url| {
            counted.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(MockDatabase::ready()) as Box<dyn FunctionDatabase>)
        }));

        // Same URL, still Ready: Java returns without rebuilding the client.
        service.initialize_database("postgresql://myhost/myrepo").unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        // A different URL does rebuild it.
        service.initialize_database("postgresql://otherhost/myrepo").unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn initialize_database_rejects_a_malformed_url() {
        let mut service = SimilarFunctionQueryService::new(mock_program());
        // Java: catch (MalformedURLException e) -> "Bad database URL: " + e.getMessage().
        let err = service.initialize_database("not a url").unwrap_err();
        assert!(err.message().starts_with("Bad database URL: "));
    }

    #[test]
    fn close_drops_the_database_and_is_idempotent() {
        let mut service = SimilarFunctionQueryService::with_database(
            mock_program(),
            Box::new(MockDatabase::ready()),
        );
        assert_eq!(service.get_database_status(), Status::Ready);

        service.close();
        assert_eq!(service.get_database_status(), Status::Unconnected);

        // Java: dispose() just calls close(), and close() tolerates a null database.
        service.dispose();
        assert_eq!(service.get_database_status(), Status::Unconnected);
    }

    #[test]
    fn update_program_only_drops_the_generator_when_the_program_changes() {
        let program = mock_program();
        let mut service = SimilarFunctionQueryService::new(Arc::clone(&program));
        service.signature_generator = Some(GenSignatures::new(false));

        // Same program: Java's `this.program != newProgram` is false, generator survives.
        service.update_program(Arc::clone(&program));
        assert!(service.signature_generator.is_some());

        // Different program: the cached generator belongs to the old one and is dropped.
        service.update_program(mock_program());
        assert!(service.signature_generator.is_none());
    }

    #[test]
    fn set_number_of_stages_overrides_the_query_supplied_count() {
        let mut service = SimilarFunctionQueryService::new(mock_program());
        assert_eq!(service.num_stages, 0); // Java's constructor sets numStages = 0
        service.set_number_of_stages(4);
        assert_eq!(service.num_stages, 4);
    }
}

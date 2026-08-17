//! Port of `ghidra.features.bsim.query.FunctionDatabase`.
//!
//! Java's `FunctionDatabase` is an `AutoCloseable` interface with a handful of nested types
//! (`Status`, `ConnectionType`, `ErrorCategory`, `BSimError`, `DatabaseNonFatalException`), a few
//! `default` methods, and a set of `static` helpers. Rust has no nested types, so the enums and
//! structs are siblings of the trait in this module, the `default` methods become trait methods
//! with bodies, and the `static` helpers become free functions.
//!
//! `Status` and `ConnectionType` were already ported alongside
//! [`BSimJDBCDataSource`](crate::feature::bsim::query::b_sim_jdbc_data_source), which is the other
//! Java type that uses them; they are re-exported here rather than redefined.

use std::fmt;
use std::io;
use std::sync::Arc;

use crate::feature::bsim::query::b_sim_server_info::BSimServerInfo;
use crate::feature::bsim::query::description::{DatabaseInformation, DescriptionManager};
use crate::feature::bsim::query::lsh_exception::LshException;
use crate::feature::bsim::query::protocol::QueryResponseRecord;
use crate::feature::seam_stubs::{BSimQuery, Configuration, ExecutableRecord, VectorResult};
use crate::framework::application::Application;
use crate::generic::seam_stubs::{LSHVectorFactory, WeightedLSHCosineVector};

pub use crate::feature::bsim::query::b_sim_jdbc_data_source::{ConnectionType, Status};

/// Severity/kind of a [`BSimError`].
///
/// Port of `FunctionDatabase.ErrorCategory`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ErrorCategory {
    Unused,
    Nonfatal,
    Fatal,
    Initialization,
    Format,
    Nodatabase,
    Connection,
    Authentication,
    AuthenticationCancelled,
}

impl ErrorCategory {
    /// Java: `ErrorCategory.getInteger()`, the ordinal-like label each constant carries.
    pub fn get_integer(&self) -> i32 {
        match self {
            ErrorCategory::Unused => 0,
            ErrorCategory::Nonfatal => 1,
            ErrorCategory::Fatal => 2,
            ErrorCategory::Initialization => 3,
            ErrorCategory::Format => 4,
            ErrorCategory::Nodatabase => 5,
            ErrorCategory::Connection => 6,
            ErrorCategory::Authentication => 7,
            ErrorCategory::AuthenticationCancelled => 8,
        }
    }
}

/// Error structure returned by [`FunctionDatabase::get_last_error`].
///
/// Port of `FunctionDatabase.BSimError`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BSimError {
    pub category: ErrorCategory,
    pub message: String,
}

impl BSimError {
    /// Java: `BSimError(ErrorCategory cat, String msg)`.
    pub fn new(category: ErrorCategory, message: impl Into<String>) -> Self {
        Self { category, message: message.into() }
    }
}

impl fmt::Display for BSimError {
    /// Java: `toString()` returns the message alone.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

/// A database problem the caller is expected to recover from.
///
/// Port of `FunctionDatabase.DatabaseNonFatalException`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatabaseNonFatalException {
    message: String,
}

impl DatabaseNonFatalException {
    pub fn new(message: impl Into<String>) -> Self {
        Self { message: message.into() }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for DatabaseNonFatalException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DatabaseNonFatalException: {}", self.message)
    }
}

impl std::error::Error for DatabaseNonFatalException {}

/// The two exceptions `checkSettingsForInsert` can throw, as one error type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InsertSettingsError {
    /// Java: `DatabaseNonFatalException`.
    NonFatal(DatabaseNonFatalException),
    /// Java: `LSHException`.
    Fatal(LshException),
}

impl fmt::Display for InsertSettingsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InsertSettingsError::NonFatal(e) => e.fmt(f),
            InsertSettingsError::Fatal(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for InsertSettingsError {}

/// A connection to a BSim function database.
///
/// Port of the `ghidra.features.bsim.query.FunctionDatabase` interface. Java's `AutoCloseable`
/// supertype shows up as [`close`](FunctionDatabase::close).
pub trait FunctionDatabase: Send + Sync {
    /// The status of the current connection with this database.
    fn get_status(&self) -> Status;

    /// The type of connection.
    fn get_connection_type(&self) -> ConnectionType;

    /// The username being used to establish the connection.
    fn get_user_name(&self) -> String;

    /// The factory the database is using to create `LSHVector` objects.
    fn get_lsh_vector_factory(&self) -> Arc<LSHVectorFactory>;

    /// General characteristics and descriptions of this database.
    ///
    /// Java returns `null` before the connection has produced any information, hence the
    /// [`Option`].
    fn get_info(&self) -> Option<DatabaseInformation>;

    /// Compare the actual database layout with the layout expected by this client.
    ///
    /// Returns -1 if the info layout version is earlier than the current client expectation, 1 if
    /// it is later, and 0 if they are the same.
    fn compare_layout(&self) -> i32;

    /// The [`BSimServerInfo`] object for this database.
    fn get_server_info(&self) -> BSimServerInfo;

    /// Java: `getURLString()`, which is deprecated in favour of
    /// [`get_server_info`](FunctionDatabase::get_server_info).
    fn get_url_string(&self) -> String;

    /// Initialize (a connection with) the database.
    ///
    /// If initialization is not successful this returns `false` and a description of the error
    /// can be obtained from [`get_last_error`](FunctionDatabase::get_last_error).
    fn initialize(&self) -> bool;

    /// Close down (the connection with) the database.
    fn close(&self);

    /// If the last query failed to produce a response, use this to recover the error.
    fn get_last_error(&self) -> BSimError;

    /// Send a query to the database.
    ///
    /// Java returns `null` when an error occurred, in which case
    /// [`get_last_error`](FunctionDatabase::get_last_error) explains why; that is [`None`] here.
    fn query(&self, query: &dyn BSimQuery) -> Option<Box<dyn QueryResponseRecord>>;

    /// Determine if the connected database supports a user password change.
    fn is_password_change_allowed(&self) -> bool {
        self.get_status() == Status::Ready
            && self.get_connection_type() == ConnectionType::SslPasswordAuthentication
    }

    /// Issue a password change request to the server.
    ///
    /// Returns `None` if the change was successful, or the error message.
    ///
    /// Java builds a `PasswordChange` request, executes it against this database and clears the
    /// password data afterwards. Executing a request needs `BSimQuery.execute`, which is not
    /// ported yet, so the default here performs only the two guard checks Java performs first;
    /// implementations that support a password change override it.
    fn change_password(&self, new_password: &[char]) -> Option<String> {
        let _ = new_password;
        if self.get_status() != Status::Ready {
            return Some("Connection not established".to_string());
        }
        if !self.is_password_change_allowed() {
            return Some("Password change not supported".to_string());
        }
        Some("Password change not supported".to_string())
    }

    /// The maximum number of functions to be queried per staged query when searching for similar
    /// functions, or 0 for the default (generally ten per stage).
    fn get_queried_functions_per_stage(&self) -> i32 {
        0
    }

    /// The maximum number of functions to be queried per staged query when performing an overview
    /// query, or 0 for the default (generally ten per stage).
    fn get_overview_functions_per_stage(&self) -> i32 {
        0
    }

    // The typed query paths below stand in for Java's `BSimQuery.execute(FunctionDatabase)`,
    // which hands the query to `query()` and casts the response back to the query's response
    // type. The ported response records carry no results yet, so each seam method returns the
    // one field of the Java response its caller reads, and `None` where Java returns a null
    // response (i.e. the query failed, and `get_last_error()` explains why). Defaults return
    // `None` so implementations only override the queries they support.

    /// Java: `new QueryInfo().execute(db).info`.
    fn query_info(&self) -> Option<DatabaseInformation> {
        None
    }

    /// Java: `QueryName` limited to `max_func` functions of the executable with the given md5,
    /// with the callgraph, category and signature fill-ins turned off; yields `ResponseName.manage`.
    fn query_name(&self, _md5: &str, _max_func: i32) -> Option<DescriptionManager> {
        None
    }

    /// Java: `QueryExeInfo(limit, ...).execute(db).records`.
    fn query_exe_info(&self, _limit: i32) -> Option<Vec<Arc<ExecutableRecord>>> {
        None
    }

    /// Java: `QueryVectorId` with the given ids; yields `ResponseVectorId.vectorResults`, one
    /// entry per requested id.
    fn query_vector_id(&self, _ids: &[i64]) -> Option<Vec<VectorResult>> {
        None
    }

    /// Java: `QueryNearestVector` for a single vector at similarity threshold `thresh`; yields
    /// `ResponseNearestVector.result`, one list of near vectors per queried vector.
    fn query_nearest_vector(
        &self,
        _vec: &WeightedLSHCosineVector,
        _thresh: f64,
    ) -> Option<Vec<Vec<VectorResult>>> {
        None
    }

    /// Java: `QueryVectorMatch` for the given vector ids, capped at `max` functions per id;
    /// yields `ResponseVectorMatch.manage`.
    fn query_vector_match(&self, _vector_ids: &[i64], _max: i32) -> Option<DescriptionManager> {
        None
    }
}

/// Java: the private static `getFormattedVersion(int, int, int)`.
fn get_formatted_version(maj: i16, min: i16, settings: i32) -> String {
    format!("{}.{}:0x{:02x}", maj, min, settings)
}

/// Verify that signature data being queried was generated with settings the database understands.
///
/// Port of the static `FunctionDatabase.checkSettingsForQuery`.
pub fn check_settings_for_query(
    manage: &DescriptionManager,
    info: &DatabaseInformation,
) -> Result<(), LshException> {
    let res = info.check_signature_settings(
        manage.get_major_version(),
        manage.get_minor_version(),
        manage.get_settings(),
    );
    if res <= 1 || res == 4 {
        return Ok(());
    }
    if res == 3 {
        return Err(LshException::new("Query signature data has no setting information"));
    }
    Err(LshException::new(format!(
        "Query signature data {} does not match database {}",
        get_formatted_version(
            manage.get_major_version(),
            manage.get_minor_version(),
            manage.get_settings()
        ),
        get_formatted_version(info.major, info.minor, info.settings)
    )))
}

/// Verify that signature data being inserted was generated with settings the database understands.
///
/// Returns `true` when this is the first insert into a database that has no settings of its own
/// yet, and `false` when the settings match exactly.
///
/// Port of the static `FunctionDatabase.checkSettingsForInsert`.
pub fn check_settings_for_insert(
    manage: &DescriptionManager,
    info: &DatabaseInformation,
) -> Result<bool, InsertSettingsError> {
    if manage.num_functions() == 0 {
        return Err(InsertSettingsError::NonFatal(DatabaseNonFatalException::new(
            "Empty signature file",
        )));
    }
    let res = info.check_signature_settings(
        manage.get_major_version(),
        manage.get_minor_version(),
        manage.get_settings(),
    );
    if res == 0 {
        return Ok(false);
    }
    if res == 1 {
        return Err(InsertSettingsError::Fatal(LshException::new(
            "Trying to insert signature data with slight differences in settings",
        )));
    }
    if res == 4 {
        return Ok(true); // This apparently is the first insert
    }
    if res == 3 {
        return Err(InsertSettingsError::Fatal(LshException::new(
            "Trying to insert signature data with no setting information",
        )));
    }
    Err(InsertSettingsError::Fatal(LshException::new(format!(
        "Trying to insert signature data {} with settings that don't match database {}",
        get_formatted_version(
            manage.get_major_version(),
            manage.get_minor_version(),
            manage.get_settings()
        ),
        get_formatted_version(info.major, info.minor, info.settings)
    ))))
}

/// Describe the fatal metadata differences between an executable about to be ingested and the
/// copy already in the database, or `None` if `flags` carries no fatal difference.
///
/// Port of the static `FunctionDatabase.constructFatalError`, whose `flags` are the
/// `ExecutableRecord.METADATA_*` bits `compareMetadata` returns.
pub fn construct_fatal_error(
    flags: i32,
    newrec: &ExecutableRecord,
    orig: &ExecutableRecord,
) -> Option<String> {
    if flags & ExecutableRecord::METADATA_ARCH != 0 {
        Some(format!(
            "{} already ingested with different architecture field: {}",
            newrec.get_name_exec(),
            orig.get_architecture()
        ))
    } else if flags & ExecutableRecord::METADATA_COMP != 0 {
        Some(format!(
            "{} already ingested with different compiler field: {}",
            newrec.get_name_exec(),
            orig.get_name_compiler()
        ))
    } else if flags & ExecutableRecord::METADATA_LIBR != 0 {
        Some(format!(
            "{} already ingested -- library field differs!!",
            newrec.get_name_exec()
        ))
    } else if flags & ExecutableRecord::METADATA_REPO != 0 {
        Some(format!(
            "{} already ingested from a different repository: {}",
            newrec.get_name_exec(),
            orig.get_repository().unwrap_or_default()
        ))
    } else {
        None
    }
}

/// Describe the non-fatal metadata differences between an executable about to be ingested and the
/// copy already in the database.
///
/// Port of the static `FunctionDatabase.constructNonfatalError`.
pub fn construct_nonfatal_error(
    flags: i32,
    newrec: &ExecutableRecord,
    orig: &ExecutableRecord,
) -> String {
    if flags & ExecutableRecord::METADATA_NAME != 0 {
        format!(
            "{} already ingested with a different name: {}",
            newrec.get_name_exec(),
            orig.get_name_exec()
        )
    } else if flags & ExecutableRecord::METADATA_PATH != 0 {
        format!(
            "{} already ingested under a different path: {}",
            newrec.get_name_exec(),
            orig.get_path().unwrap_or_default()
        )
    } else if flags & ExecutableRecord::METADATA_DATE != 0 {
        // Java prints `orig.getDate().toString()`; the ported record carries the date as
        // milliseconds since the epoch, so that is what is shown.
        format!(
            "{} already ingested with a different date: {}",
            newrec.get_name_exec(),
            orig.get_date()
        )
    } else {
        format!("{} already ingested with UNKNOWN difference in metadata", newrec.get_name_exec())
    }
}

/// Load a BSim configuration template out of the BSim module's data directory into `config`.
///
/// Port of the static `FunctionDatabase.loadConfigurationTemplate`. Java allocates the
/// `Configuration` itself and resolves its own module through the `Application` static; neither is
/// available here (`Configuration` is not ported, and [`Application`] is a trait rather than a
/// static), so both are passed in.
pub fn load_configuration_template(
    app: &dyn Application,
    config: &mut dyn Configuration,
    configname: &str,
) -> Result<(), LshException> {
    let module_data_sub_directory =
        app.get_module_data_sub_directory("BSim", "").map_err(configuration_error)?;
    config.load_template(&module_data_sub_directory, configname).map_err(configuration_error)
}

/// Java catches `FileNotFoundException`, `IOException` and `SAXException` separately around the
/// configuration load; there is one `io::Error` here, so the kind picks the message.
fn configuration_error(e: io::Error) -> LshException {
    match e.kind() {
        io::ErrorKind::NotFound => {
            LshException::new(format!("Missing configuration data: {}", e))
        }
        io::ErrorKind::InvalidData => {
            LshException::new("Unable to parse configuration template")
        }
        _ => LshException::new("Could open module data directory"),
    }
}

/// Central location for building the vector factory used by a [`FunctionDatabase`].
///
/// Java returns a `WeightedLSHCosineVectorFactory`; the placeholder [`LSHVectorFactory`] stands in
/// for the whole factory family until `generic.lsh.vector` is ported.
pub fn generate_lsh_vector_factory() -> LSHVectorFactory {
    LSHVectorFactory::default()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A database that is only as connected as the test asks it to be.
    struct MockDatabase {
        status: Status,
        connection_type: ConnectionType,
    }

    impl MockDatabase {
        fn new(status: Status, connection_type: ConnectionType) -> Self {
            Self { status, connection_type }
        }
    }

    impl FunctionDatabase for MockDatabase {
        fn get_status(&self) -> Status {
            self.status
        }

        fn get_connection_type(&self) -> ConnectionType {
            self.connection_type
        }

        fn get_user_name(&self) -> String {
            "ghidra".to_string()
        }

        fn get_lsh_vector_factory(&self) -> Arc<LSHVectorFactory> {
            Arc::new(generate_lsh_vector_factory())
        }

        fn get_info(&self) -> Option<DatabaseInformation> {
            None
        }

        fn compare_layout(&self) -> i32 {
            0
        }

        fn get_server_info(&self) -> BSimServerInfo {
            unimplemented!("not used by these tests")
        }

        fn get_url_string(&self) -> String {
            "postgresql://myhost/myrepo".to_string()
        }

        fn initialize(&self) -> bool {
            self.status == Status::Ready
        }

        fn close(&self) {}

        fn get_last_error(&self) -> BSimError {
            BSimError::new(ErrorCategory::Connection, "no connection")
        }

        fn query(&self, _query: &dyn BSimQuery) -> Option<Box<dyn QueryResponseRecord>> {
            None
        }
    }

    /// A manager whose signature settings the checks below compare against a database's.
    fn manager_with(maj: i16, min: i16, settings: i32, functions: usize) -> DescriptionManager {
        let mut manage = DescriptionManager::new();
        manage.set_version(maj, min);
        manage.set_settings(settings);
        let exe = manage
            .new_executable_record(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "exe",
                "gcc",
                "x86:LE:64:default",
                0,
                None,
                None,
                None,
            )
            .unwrap();
        for index in 0..functions {
            let function = manage.new_function_description(
                &format!("func_{}", index),
                0x1000 + index as i64,
                Arc::clone(&exe),
            );
            manage.insert_function(function);
        }
        manage
    }

    fn info_with(major: i16, minor: i16, settings: i32) -> DatabaseInformation {
        let mut info = DatabaseInformation::new();
        info.major = major;
        info.minor = minor;
        info.settings = settings;
        info
    }

    #[test]
    fn error_category_labels_match_java() {
        // Java: ErrorCategory constants carry the labels 0 through 8, in declaration order.
        assert_eq!(ErrorCategory::Unused.get_integer(), 0);
        assert_eq!(ErrorCategory::Fatal.get_integer(), 2);
        assert_eq!(ErrorCategory::Authentication.get_integer(), 7);
        assert_eq!(ErrorCategory::AuthenticationCancelled.get_integer(), 8);
    }

    #[test]
    fn bsim_error_prints_only_its_message() {
        // Java: BSimError.toString() returns `message`, not the category.
        let error = BSimError::new(ErrorCategory::Nodatabase, "no such database");
        assert_eq!(error.to_string(), "no such database");
    }

    #[test]
    fn formatted_version_pads_the_settings_to_two_hex_digits() {
        // Java: String.format("%d.%d:0x%02x", maj, min, settings).
        assert_eq!(get_formatted_version(4, 2, 7), "4.2:0x07");
        assert_eq!(get_formatted_version(1, 0, 0x1a), "1.0:0x1a");
    }

    #[test]
    fn password_change_needs_a_ready_password_authenticated_connection() {
        // Java: isPasswordChangeAllowed() is Ready && SSL_Password_Authentication.
        let ready_ssl =
            MockDatabase::new(Status::Ready, ConnectionType::SslPasswordAuthentication);
        assert!(ready_ssl.is_password_change_allowed());

        let ready_unencrypted =
            MockDatabase::new(Status::Ready, ConnectionType::UnencryptedNoAuthentication);
        assert!(!ready_unencrypted.is_password_change_allowed());

        let busy_ssl = MockDatabase::new(Status::Busy, ConnectionType::SslPasswordAuthentication);
        assert!(!busy_ssl.is_password_change_allowed());
    }

    #[test]
    fn change_password_reports_the_guard_that_rejected_it() {
        // Java: an unready connection reports "Connection not established" before anything else.
        let unconnected =
            MockDatabase::new(Status::Unconnected, ConnectionType::SslPasswordAuthentication);
        assert_eq!(
            unconnected.change_password(&['s', 'e', 'c', 'r', 'e', 't']),
            Some("Connection not established".to_string())
        );

        // Java: a ready connection that cannot change passwords reports the second message.
        let unsupported =
            MockDatabase::new(Status::Ready, ConnectionType::SslNoAuthentication);
        assert_eq!(
            unsupported.change_password(&['s', 'e', 'c', 'r', 'e', 't']),
            Some("Password change not supported".to_string())
        );
    }

    #[test]
    fn functions_per_stage_default_to_the_database_default() {
        // Java: both default methods return 0, meaning "use the caller's own default".
        let db = MockDatabase::new(Status::Ready, ConnectionType::SslNoAuthentication);
        assert_eq!(db.get_queried_functions_per_stage(), 0);
        assert_eq!(db.get_overview_functions_per_stage(), 0);
    }

    #[test]
    fn query_settings_accept_an_exact_and_a_minor_difference() {
        let info = info_with(4, 2, 7);
        // checkSignatureSettings == 0 (exact match) and == 1 (minor version off by one) both pass.
        assert!(check_settings_for_query(&manager_with(4, 2, 7, 1), &info).is_ok());
        assert!(check_settings_for_query(&manager_with(4, 3, 7, 1), &info).is_ok());
    }

    #[test]
    fn query_settings_reject_missing_and_mismatched_settings() {
        let info = info_with(4, 2, 7);
        // checkSignatureSettings == 3: the query data carries no settings of its own.
        let no_settings = check_settings_for_query(&manager_with(0, 0, 0, 1), &info).unwrap_err();
        assert_eq!(no_settings.message(), "Query signature data has no setting information");

        // checkSignatureSettings == 2: the settings mismatch, and both versions are reported.
        let mismatch = check_settings_for_query(&manager_with(5, 2, 9, 1), &info).unwrap_err();
        assert_eq!(
            mismatch.message(),
            "Query signature data 5.2:0x09 does not match database 4.2:0x07"
        );
    }

    #[test]
    fn query_settings_accept_a_database_with_no_settings_yet() {
        // checkSignatureSettings == 4: the database itself has nothing to compare against.
        let empty_db = info_with(0, 0, 0);
        assert!(check_settings_for_query(&manager_with(4, 2, 7, 1), &empty_db).is_ok());
    }

    #[test]
    fn insert_rejects_an_empty_signature_file_before_looking_at_settings() {
        // Java throws DatabaseNonFatalException before calling checkSignatureSettings at all,
        // so even perfectly matching settings are rejected when there are no functions.
        let error = check_settings_for_insert(&manager_with(4, 2, 7, 0), &info_with(4, 2, 7))
            .unwrap_err();
        assert_eq!(
            error,
            InsertSettingsError::NonFatal(DatabaseNonFatalException::new("Empty signature file"))
        );
    }

    #[test]
    fn insert_reports_whether_this_is_the_first_insert() {
        // checkSignatureSettings == 0: settings match, and the database already has data.
        assert_eq!(
            check_settings_for_insert(&manager_with(4, 2, 7, 1), &info_with(4, 2, 7)).unwrap(),
            false
        );
        // checkSignatureSettings == 4: the database has no settings yet, so this is the first.
        assert_eq!(
            check_settings_for_insert(&manager_with(4, 2, 7, 1), &info_with(0, 0, 0)).unwrap(),
            true
        );
    }

    #[test]
    fn insert_rejects_slightly_and_wholly_different_settings() {
        let info = info_with(4, 2, 7);
        // checkSignatureSettings == 1: a minor version difference is fatal for an insert, even
        // though the same difference is accepted for a query.
        let slight = check_settings_for_insert(&manager_with(4, 3, 7, 1), &info).unwrap_err();
        assert_eq!(
            slight,
            InsertSettingsError::Fatal(LshException::new(
                "Trying to insert signature data with slight differences in settings"
            ))
        );

        // checkSignatureSettings == 3: no settings at all in the data being inserted.
        let none = check_settings_for_insert(&manager_with(0, 0, 0, 1), &info).unwrap_err();
        assert_eq!(
            none,
            InsertSettingsError::Fatal(LshException::new(
                "Trying to insert signature data with no setting information"
            ))
        );

        // checkSignatureSettings == 2: an outright mismatch names both versions.
        let mismatch = check_settings_for_insert(&manager_with(5, 2, 9, 1), &info).unwrap_err();
        assert_eq!(
            mismatch.to_string(),
            "LSHException: Trying to insert signature data 5.2:0x09 with settings that don't \
             match database 4.2:0x07"
        );
    }

    /// The two executables `construct_*_error` compare: same md5, differing metadata.
    fn ingest_pair() -> (Arc<ExecutableRecord>, Arc<ExecutableRecord>) {
        let mut incoming = DescriptionManager::new();
        let newrec = incoming
            .new_executable_record(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "helloworld",
                "gcc",
                "x86:LE:64:default",
                1000,
                Some("ghidra://repo"),
                Some("/new/path"),
                None,
            )
            .unwrap();
        let mut stored = DescriptionManager::new();
        let orig = stored
            .new_executable_record(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "helloworld.exe",
                "visualstudio",
                "x86:LE:32:default",
                2000,
                Some("ghidra://other"),
                Some("/old/path"),
                None,
            )
            .unwrap();
        (newrec, orig)
    }

    #[test]
    fn fatal_error_reports_the_highest_priority_difference_only() {
        let (newrec, orig) = ingest_pair();
        // Java tests the bits in order, so architecture wins over compiler when both are set.
        assert_eq!(
            construct_fatal_error(
                ExecutableRecord::METADATA_ARCH | ExecutableRecord::METADATA_COMP,
                &newrec,
                &orig
            ),
            Some(
                "helloworld already ingested with different architecture field: x86:LE:32:default"
                    .to_string()
            )
        );
        assert_eq!(
            construct_fatal_error(ExecutableRecord::METADATA_COMP, &newrec, &orig),
            Some("helloworld already ingested with different compiler field: visualstudio".to_string())
        );
        assert_eq!(
            construct_fatal_error(ExecutableRecord::METADATA_LIBR, &newrec, &orig),
            Some("helloworld already ingested -- library field differs!!".to_string())
        );
        assert_eq!(
            construct_fatal_error(ExecutableRecord::METADATA_REPO, &newrec, &orig),
            Some("helloworld already ingested from a different repository: ghidra://other".to_string())
        );
    }

    #[test]
    fn fatal_error_is_absent_when_no_fatal_bit_is_set() {
        let (newrec, orig) = ingest_pair();
        // Java returns null when only non-fatal bits (here, the name) are set.
        assert_eq!(construct_fatal_error(ExecutableRecord::METADATA_NAME, &newrec, &orig), None);
    }

    #[test]
    fn nonfatal_error_describes_name_path_date_and_falls_back() {
        let (newrec, orig) = ingest_pair();
        assert_eq!(
            construct_nonfatal_error(ExecutableRecord::METADATA_NAME, &newrec, &orig),
            "helloworld already ingested with a different name: helloworld.exe"
        );
        assert_eq!(
            construct_nonfatal_error(ExecutableRecord::METADATA_PATH, &newrec, &orig),
            // The record normalizes the path it was constructed with, dropping the leading slash.
            "helloworld already ingested under a different path: old/path"
        );
        assert_eq!(
            construct_nonfatal_error(ExecutableRecord::METADATA_DATE, &newrec, &orig),
            "helloworld already ingested with a different date: 2000"
        );
        // Java falls through to the UNKNOWN message when no known bit is set.
        assert_eq!(
            construct_nonfatal_error(0, &newrec, &orig),
            "helloworld already ingested with UNKNOWN difference in metadata"
        );
    }
}

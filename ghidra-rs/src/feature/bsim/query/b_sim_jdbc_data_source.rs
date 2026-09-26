use std::io;
use std::sync::Arc;

use crate::feature::bsim::query::b_sim_server_info::BSimServerInfo;

/// Status of a connection to a BSim database.
///
/// Port of `ghidra.features.bsim.query.FunctionDatabase.Status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Status {
    Unconnected,
    Busy,
    Error,
    Ready,
}

impl Status {
    pub fn as_str(&self) -> &'static str {
        match self {
            Status::Unconnected => "Unconnected",
            Status::Busy => "Busy",
            Status::Error => "Error",
            Status::Ready => "Ready",
        }
    }
}

impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Type of connection to a BSim database.
///
/// Port of `ghidra.features.bsim.query.FunctionDatabase.ConnectionType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ConnectionType {
    SslNoAuthentication,
    SslPasswordAuthentication,
    UnencryptedNoAuthentication,
}

/// A JDBC data source providing connections to a BSim database.
///
/// Port of `ghidra.features.bsim.query.BSimJDBCDataSource`.
pub trait BSimJDBCDataSource: Send + Sync {
    /// Get the status of the current connection with this database.
    fn get_status(&self) -> Status;

    /// Get DB connection object performing any required authentication.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection fails.
    fn get_connection(&self) -> io::Result<Arc<dyn Connection>>;

    /// Get the type of connection.
    fn get_connection_type(&self) -> ConnectionType;

    /// Get the server info that corresponds to this data source.
    ///
    /// It is important to note that the returned instance is normalized for the purpose of
    /// caching and may not match the original server info object used to obtain this data source
    /// instance.
    fn get_server_info(&self) -> BSimServerInfo;

    /// Get the number of active connections in the associated connection pool.
    fn get_active_connections(&self) -> i32;

    /// Get the number of idle connections in the associated connection pool.
    fn get_idle_connections(&self) -> i32;

    /// Dispose the pooled datasource.
    fn dispose(&self);
}

/// A JDBC database connection.
pub trait Connection: Send + Sync {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_display() {
        assert_eq!(Status::Unconnected.to_string(), "Unconnected");
        assert_eq!(Status::Busy.to_string(), "Busy");
        assert_eq!(Status::Error.to_string(), "Error");
        assert_eq!(Status::Ready.to_string(), "Ready");
    }

    #[test]
    fn test_status_as_str() {
        assert_eq!(Status::Unconnected.as_str(), "Unconnected");
        assert_eq!(Status::Busy.as_str(), "Busy");
        assert_eq!(Status::Error.as_str(), "Error");
        assert_eq!(Status::Ready.as_str(), "Ready");
    }

    #[test]
    fn test_connection_type_values() {
        assert_eq!(ConnectionType::SslNoAuthentication, ConnectionType::SslNoAuthentication);
        assert_ne!(ConnectionType::SslNoAuthentication, ConnectionType::SslPasswordAuthentication);
    }

    #[test]
    fn test_status_ordering() {
        assert!(Status::Unconnected < Status::Busy);
        assert!(Status::Busy < Status::Error);
        assert!(Status::Error < Status::Ready);
    }
}

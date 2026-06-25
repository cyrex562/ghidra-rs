use std::net::TcpStream;
use std::process::Child;

/// A class that represents a connection to Eclipse.
pub struct EclipseConnection {
    process: Option<Child>,
    socket: Option<TcpStream>,
}

impl EclipseConnection {
    /// Creates a new Eclipse connection object that represents no connection.
    pub fn new() -> Self {
        EclipseConnection {
            process: None,
            socket: None,
        }
    }

    /// Creates a new Eclipse connection object.
    ///
    /// # Arguments
    ///
    /// * `process` - The Eclipse process that we launched (could be None).
    /// * `socket` - The socket connected to Eclipse (could be None).
    pub fn new_with_connection(process: Option<Child>, socket: Option<TcpStream>) -> Self {
        EclipseConnection { process, socket }
    }

    /// Gets the Eclipse process that we launched.
    ///
    /// Returns the Eclipse process that we launched. Could be None if we didn't need to
    /// launch an Eclipse to establish a connection, or if we failed to launch Eclipse.
    pub fn get_process(&self) -> Option<&Child> {
        self.process.as_ref()
    }

    /// Gets the socket connection to Eclipse.
    ///
    /// Returns the socket connection to Eclipse. Could be None if a connection was
    /// never established.
    pub fn get_socket(&self) -> Option<&TcpStream> {
        self.socket.as_ref()
    }

    /// Consumes the EclipseConnection and returns the process (if any).
    pub fn into_process(self) -> Option<Child> {
        self.process
    }

    /// Consumes the EclipseConnection and returns the socket (if any).
    pub fn into_socket(self) -> Option<TcpStream> {
        self.socket
    }
}

impl Default for EclipseConnection {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_default_connection() {
        let conn = EclipseConnection::new();
        assert!(conn.get_process().is_none());
        assert!(conn.get_socket().is_none());
    }

    #[test]
    fn test_default_trait() {
        let conn = EclipseConnection::default();
        assert!(conn.get_process().is_none());
        assert!(conn.get_socket().is_none());
    }

    #[test]
    fn test_new_with_none_values() {
        let conn = EclipseConnection::new_with_connection(None, None);
        assert!(conn.get_process().is_none());
        assert!(conn.get_socket().is_none());
    }

    #[test]
    fn test_into_process() {
        let conn = EclipseConnection::new_with_connection(None, None);
        let process = conn.into_process();
        assert!(process.is_none());
    }

    #[test]
    fn test_into_socket() {
        let conn = EclipseConnection::new_with_connection(None, None);
        let socket = conn.into_socket();
        assert!(socket.is_none());
    }
}

use std::io;

use thiserror::Error;

use crate::framework::client::RepositoryServerAdapter;
use crate::framework::model::ProjectData;
use crate::framework::seam_stubs::GhidraURLWrappedContentLike;

/// Ghidra content type - domain folder/file wrapped within a [`GhidraURLWrappedContentLike`]
/// object, mirroring `GhidraURLConnection.GHIDRA_WRAPPED_CONTENT`.
pub const GHIDRA_WRAPPED_CONTENT: &str = "GhidraWrappedContent";

/// Ghidra content type - repository server in the form of a [`RepositoryServerAdapter`],
/// mirroring `GhidraURLConnection.REPOSITORY_SERVER_CONTENT`.
pub const REPOSITORY_SERVER_CONTENT: &str = "RepositoryServer";

/// Connection status codes.
///
/// Port of the nested enum `GhidraURLConnection.StatusCode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusCode {
    /// Ghidra Status-Code 20: OK.
    Ok,
    /// Ghidra Status-Code 401: Unauthorized. Occurs when repository access is denied.
    Unauthorized,
    /// Ghidra Status-Code 404: Not Found. Occurs when repository or project does not exist.
    NotFound,
    /// Ghidra Status-Code 423: Locked. Occurs when project is locked (i.e., in use).
    Locked,
    /// Ghidra Status-Code 503: Unavailable. Covers a variety of connection errors which are
    /// reported/logged by the Ghidra Server support code.
    Unavailable,
}

impl StatusCode {
    /// Returns the numeric status code, mirroring `StatusCode.getCode()`.
    pub fn code(&self) -> i32 {
        match self {
            StatusCode::Ok => 20,
            StatusCode::Unauthorized => 401,
            StatusCode::NotFound => 404,
            StatusCode::Locked => 423,
            StatusCode::Unavailable => 503,
        }
    }

    /// Returns the human-readable description, mirroring `StatusCode.getDescription()`.
    pub fn description(&self) -> &'static str {
        match self {
            StatusCode::Ok => "OK",
            StatusCode::Unauthorized => "Unauthorized",
            StatusCode::NotFound => "Not Found",
            StatusCode::Locked => "Locked Project",
            StatusCode::Unavailable => "Unavailable",
        }
    }
}

/// Content associated with a connected [`GhidraURLConnection`], mirroring the two concrete
/// runtime types `getContent()` may return: a domain folder/file wrapped within
/// `GhidraURLWrappedContent`, or a server-only URL's `RepositoryServerAdapter`.
pub enum GhidraURLContent {
    /// Domain folder/file content, mirroring content of type [`GHIDRA_WRAPPED_CONTENT`].
    Wrapped(Box<dyn GhidraURLWrappedContentLike>),
    /// Repository server content, mirroring content of type [`REPOSITORY_SERVER_CONTENT`].
    RepositoryServer(Box<dyn RepositoryServerAdapter>),
}

impl GhidraURLContent {
    /// Returns the content type string associated with this content's variant, mirroring the
    /// non-null cases of `GhidraURLConnection.getContentType()`.
    pub fn content_type(&self) -> &'static str {
        match self {
            GhidraURLContent::Wrapped(_) => GHIDRA_WRAPPED_CONTENT,
            GhidraURLContent::RepositoryServer(_) => REPOSITORY_SERVER_CONTENT,
        }
    }
}

/// Error returned by [`GhidraURLConnection::set_read_only`].
///
/// Combines the two unchecked exceptions `GhidraURLConnection.setReadOnly(boolean)` may throw.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum SetReadOnlyError {
    /// Mirrors `IllegalStateException("Already connected")`.
    #[error("Already connected")]
    AlreadyConnected,
    /// Mirrors `UnsupportedOperationException("write access to local projects not supported")`,
    /// thrown when attempting to enable write access on a local project URL (local project URL
    /// connections only support read-only access due to inadequate cleanup/disposal strategy).
    #[error("write access to local projects not supported")]
    LocalWriteUnsupported,
}

/// A connection to a resource identified by a Ghidra URL (`ghidra://...`), providing access to a
/// repository, repository server, local project, or the domain folder/file content therein.
///
/// Port of `ghidra.framework.protocol.ghidra.GhidraURLConnection`, which `extends
/// java.net.URLConnection`. The inherited `URLConnection` surface (e.g. `getURL()`) is not
/// ported here since it is not declared or overridden by this class; only members declared
/// directly on `GhidraURLConnection` are represented.
///
/// Selected as a dependency-cycle cut-point, so every method here takes `&self` and returns
/// owned/boxed values, matching the convention used elsewhere in this crate for cut-point traits
/// (e.g. [`RepositoryAdapter`](crate::framework::client::RepositoryAdapter),
/// [`TransientProjectData`](crate::framework::protocol::ghidra::TransientProjectData)).
/// Implementations are expected to back the connection/read-only/status-code state this trait's
/// methods observe and mutate with interior mutability, mirroring the underlying Java class's own
/// mutable instance fields (`connected`, `statusCode`, `projectData`, `refObject`, `readOnly`).
///
/// The two-argument constructors (`GhidraURLConnection(URL)` and
/// `GhidraURLConnection(URL, GhidraProtocolHandler)`) are not represented as trait methods --
/// construction is implementation-specific and does not need to be dynamically dispatched; real
/// implementations should expose an inherent `new`/`with_protocol_handler` constructor instead.
pub trait GhidraURLConnection {
    /// Returns `true` if this is a read-only connection, mirroring `isReadOnly()`. Before
    /// connecting, this reflects the connection intention set via [`Self::set_read_only`]; once
    /// connected, real implementations should reflect the underlying protocol connector's actual
    /// read-only state instead.
    fn is_read_only(&self) -> bool;

    /// Sets the read-only state for this connection prior to connecting or getting content. The
    /// default access is read-only. Mirrors `setReadOnly(boolean)`.
    ///
    /// **Note:** Local project URL connections only support read-only access.
    ///
    /// # Errors
    /// Returns [`SetReadOnlyError::AlreadyConnected`] if already connected, or
    /// [`SetReadOnlyError::LocalWriteUnsupported`] if attempting to enable write access for a
    /// local project URL.
    fn set_read_only(&self, state: bool) -> Result<(), SetReadOnlyError>;

    /// Gets the repository name associated with this connection, mirroring
    /// `getRepositoryName()`. Returns `None` if the URL does not identify a specific repository.
    fn get_repository_name(&self) -> Option<String>;

    /// Gets the repository folder path associated with this connection, mirroring
    /// `getFolderPath()`. If an ambiguous path has been specified, the folder path may change
    /// after a connection is established.
    fn get_folder_path(&self) -> Option<String>;

    /// Gets the repository folder item name associated with this connection, mirroring
    /// `getFolderItemName()`. If an ambiguous path has been specified, the folder item name may
    /// become `None` after a connection is established.
    fn get_folder_item_name(&self) -> Option<String>;

    /// Gets the status code from a Ghidra URL connect attempt, connecting first if needed,
    /// mirroring `getStatusCode()`.
    ///
    /// # Errors
    /// Returns `io::Error` if an error occurred connecting to the server.
    fn get_status_code(&self) -> io::Result<Option<StatusCode>>;

    /// Returns the content type of this connection, mirroring `getContentType()`. Returns `None`
    /// if not yet connected or no content is available; otherwise one of
    /// [`GHIDRA_WRAPPED_CONTENT`], [`REPOSITORY_SERVER_CONTENT`], or `"Unknown"`. Unlike
    /// [`Self::get_content`], this never triggers a connection attempt.
    fn get_content_type(&self) -> Option<String>;

    /// Gets content associated with the URL, connecting first if needed, mirroring
    /// `getContent()`. Returns `None` if the connection status code did not resolve to `Ok`.
    ///
    /// # Errors
    /// Returns `io::Error` if an IO error occurs.
    fn get_content(&self) -> io::Result<Option<GhidraURLContent>>;

    /// If this URL connects and corresponds to a valid repository or local project, obtains the
    /// associated [`ProjectData`], connecting first if needed. Mirrors `getProjectData()`.
    ///
    /// The caller is responsible for properly [closing](ProjectData::close) the returned project
    /// data instance when no longer in use, failure to do so may prevent release of the
    /// repository handle to the server until the process exits. It is important that `close` is
    /// invoked once, and only once, per call to this method to ensure project "use" tracking is
    /// properly maintained. Improperly invoking close on a shared transient `ProjectData`
    /// instance may cause the underlying storage to be prematurely disposed.
    ///
    /// # Errors
    /// Returns `io::Error` if an IO error occurs.
    fn get_project_data(&self) -> io::Result<Option<Box<dyn ProjectData>>>;

    /// Connects to the resource specified by the associated URL, mirroring `connect()`. A no-op
    /// if already connected.
    ///
    /// # Errors
    /// Returns `io::Error` if a connection error occurs.
    fn connect(&self) -> io::Result<()>;

    /// Mirrors `getInputStream()`, which always throws `UnknownServiceException` since Ghidra
    /// URL connections do not support streamed input.
    ///
    /// # Errors
    /// Always returns `io::Error` with kind [`io::ErrorKind::Unsupported`].
    fn get_input_stream(&self) -> io::Result<Vec<u8>> {
        Err(unknown_service_error())
    }

    /// Mirrors `getOutputStream()`, which always throws `UnknownServiceException` since Ghidra
    /// URL connections do not support streamed output.
    ///
    /// # Errors
    /// Always returns `io::Error` with kind [`io::ErrorKind::Unsupported`].
    fn get_output_stream(&self) -> io::Result<()> {
        Err(unknown_service_error())
    }
}

/// Builds the `io::Error` returned by the default [`GhidraURLConnection::get_input_stream`] and
/// [`GhidraURLConnection::get_output_stream`] bodies, mirroring `UnknownServiceException`.
fn unknown_service_error() -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, "Ghidra URL connections do not support streaming")
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    struct MockRepositoryServerAdapter;
    impl RepositoryServerAdapter for MockRepositoryServerAdapter {}

    struct MockGhidraURLConnection {
        is_local: bool,
        read_only: Cell<bool>,
        connected: Cell<bool>,
        status: Cell<Option<StatusCode>>,
    }

    impl MockGhidraURLConnection {
        fn new(is_local: bool) -> Self {
            Self {
                is_local,
                read_only: Cell::new(true),
                connected: Cell::new(false),
                status: Cell::new(None),
            }
        }
    }

    impl GhidraURLConnection for MockGhidraURLConnection {
        fn is_read_only(&self) -> bool {
            self.read_only.get()
        }

        fn set_read_only(&self, state: bool) -> Result<(), SetReadOnlyError> {
            if self.connected.get() {
                return Err(SetReadOnlyError::AlreadyConnected);
            }
            if self.is_local && !state {
                return Err(SetReadOnlyError::LocalWriteUnsupported);
            }
            self.read_only.set(state);
            Ok(())
        }

        fn get_repository_name(&self) -> Option<String> {
            Some("MyRepo".to_string())
        }

        fn get_folder_path(&self) -> Option<String> {
            Some("/".to_string())
        }

        fn get_folder_item_name(&self) -> Option<String> {
            None
        }

        fn get_status_code(&self) -> io::Result<Option<StatusCode>> {
            if self.status.get().is_none() {
                self.connect()?;
            }
            Ok(self.status.get())
        }

        fn get_content_type(&self) -> Option<String> {
            if !self.connected.get() {
                return None;
            }
            Some(REPOSITORY_SERVER_CONTENT.to_string())
        }

        fn get_content(&self) -> io::Result<Option<GhidraURLContent>> {
            if !self.connected.get() {
                self.connect()?;
            }
            if self.status.get() != Some(StatusCode::Ok) {
                return Ok(None);
            }
            Ok(Some(GhidraURLContent::RepositoryServer(Box::new(
                MockRepositoryServerAdapter,
            ))))
        }

        fn get_project_data(&self) -> io::Result<Option<Box<dyn ProjectData>>> {
            if !self.connected.get() {
                self.connect()?;
            }
            Ok(None)
        }

        fn connect(&self) -> io::Result<()> {
            if self.connected.get() {
                return Ok(());
            }
            self.connected.set(true);
            self.status.set(Some(StatusCode::Ok));
            Ok(())
        }
    }

    #[test]
    fn status_code_numeric_values_and_descriptions() {
        assert_eq!(StatusCode::Ok.code(), 20);
        assert_eq!(StatusCode::Unauthorized.code(), 401);
        assert_eq!(StatusCode::NotFound.code(), 404);
        assert_eq!(StatusCode::Locked.code(), 423);
        assert_eq!(StatusCode::Unavailable.code(), 503);
        assert_eq!(StatusCode::Locked.description(), "Locked Project");
    }

    #[test]
    fn usable_as_trait_object_and_connects_lazily() {
        let conn = MockGhidraURLConnection::new(false);
        let dyn_conn: &dyn GhidraURLConnection = &conn;

        assert!(dyn_conn.is_read_only());
        assert!(dyn_conn.get_content_type().is_none());

        let status = dyn_conn.get_status_code().unwrap();
        assert_eq!(status, Some(StatusCode::Ok));
        assert_eq!(
            dyn_conn.get_content_type().as_deref(),
            Some(REPOSITORY_SERVER_CONTENT)
        );

        let content = dyn_conn.get_content().unwrap().unwrap();
        assert_eq!(content.content_type(), REPOSITORY_SERVER_CONTENT);
        assert!(matches!(content, GhidraURLContent::RepositoryServer(_)));
    }

    #[test]
    fn set_read_only_rejects_write_access_after_connect() {
        let conn = MockGhidraURLConnection::new(false);
        conn.connect().unwrap();

        let err = conn.set_read_only(false).unwrap_err();
        assert_eq!(err, SetReadOnlyError::AlreadyConnected);
    }

    #[test]
    fn set_read_only_rejects_write_access_for_local_project() {
        let conn = MockGhidraURLConnection::new(true);
        let err = conn.set_read_only(false).unwrap_err();
        assert_eq!(err, SetReadOnlyError::LocalWriteUnsupported);
        assert!(conn.is_read_only());
    }

    #[test]
    fn input_and_output_streams_are_unsupported_by_default() {
        struct BareConnection;
        impl GhidraURLConnection for BareConnection {
            fn is_read_only(&self) -> bool {
                true
            }
            fn set_read_only(&self, _state: bool) -> Result<(), SetReadOnlyError> {
                Ok(())
            }
            fn get_repository_name(&self) -> Option<String> {
                None
            }
            fn get_folder_path(&self) -> Option<String> {
                None
            }
            fn get_folder_item_name(&self) -> Option<String> {
                None
            }
            fn get_status_code(&self) -> io::Result<Option<StatusCode>> {
                Ok(None)
            }
            fn get_content_type(&self) -> Option<String> {
                None
            }
            fn get_content(&self) -> io::Result<Option<GhidraURLContent>> {
                Ok(None)
            }
            fn get_project_data(&self) -> io::Result<Option<Box<dyn ProjectData>>> {
                Ok(None)
            }
            fn connect(&self) -> io::Result<()> {
                Ok(())
            }
        }

        let conn = BareConnection;
        assert_eq!(
            conn.get_input_stream().unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        assert_eq!(
            conn.get_output_stream().unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
    }
}

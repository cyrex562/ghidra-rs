use std::cell::{Cell, RefCell};
use std::io;

use crate::framework::client::{NotConnectedException, RepositoryAdapter, RepositoryServerAdapter};
use crate::framework::model::ProjectLocator;
use crate::framework::protocol::ghidra::ghidra_url::parse_hierarchical;
use crate::framework::protocol::ghidra::{GhidraProtocolConnector, GhidraURL, StatusCode};

fn malformed_url(msg: impl Into<String>) -> io::Error {
    // Mirrors `MalformedURLException`, matching the convention already used by the sibling
    // `ghidra_url`/`ghidra_protocol_handler`/`default_ghidra_protocol_handler` ports.
    io::Error::new(io::ErrorKind::InvalidInput, msg.into())
}

/// Provides support for the Ghidra URL protocol which specifies a local Ghidra project without
/// extension. This connector is responsible for producing a suitable `ProjectLocator` for
/// accessing the project files.
///
/// Port of `ghidra.framework.protocol.ghidra.DefaultLocalGhidraProtocolConnector`, a concrete
/// class extending the already-ported abstract `GhidraProtocolConnector`
/// ([`GhidraProtocolConnector`] trait). That trait's own doc comment explains that the abstract
/// parent's construction pipeline (`checkProtocol`/`checkUserInfo`/`checkHostInfo`/
/// `parseRepositoryName`/`initFolderItemPath`/`parseItemPath`) is deliberately excluded from the
/// trait's dyn-dispatched surface, to be reproduced by each concrete connector as private/inherent
/// construction helpers instead -- which is exactly what [`Self::new`] and its private helpers do
/// below, reusing [`parse_hierarchical`] (widened to `pub(crate)` on the sibling `ghidra_url`
/// module for this purpose) for the underlying URI decomposition rather than hand-duplicating it.
///
/// # Deviations from Java
///
/// * **`GhidraURL.getProjectStorageLocator` is taken as an injected dependency.** Java resolves it
///   via the static utility class `GhidraURL`; the ported [`GhidraURL`] trait requires an
///   implementor to supply `make_project_locator`/`handler`, and no concrete implementation exists
///   anywhere in this crate yet (only test mocks). [`Self::new`] therefore takes `&dyn GhidraURL`
///   as an explicit parameter rather than reaching for a hardcoded global.
/// * **`itemPath` is not stored as a field.** Java's parent class stores the parsed `itemPath` in a
///   `protected final String itemPath` field, but `DefaultLocalGhidraProtocolConnector` itself
///   never reads it anywhere (there is no public getter for it on [`GhidraProtocolConnector`]
///   either, and this subclass's own `connect(RepositoryAdapter)` override bypasses
///   `resolveItemPath()` -- the only method that would have consulted it -- entirely, throwing
///   immediately instead). Computing it is still performed, for its `folder_path`/`folder_item_name`
///   side effects (`init_folder_item_path`), just without retaining the otherwise-dead result.
/// * **Two accessors can panic.** [`GhidraProtocolConnector::get_repository_name`] and
///   [`GhidraProtocolConnector::connect`] each dereference `localStorageLocator` in Java
///   (`localStorageLocator.getName()` / `localStorageLocator.exists()`) with no null check --
///   `GhidraURL.getProjectStorageLocator` can return `null` for a URL with an empty project name,
///   and the constructor does not reject that. That is reproduced faithfully (not "fixed") as a
///   panic here -- see each method's own docs and the dedicated `#[should_panic]` tests below.
/// * **`getLocalProjectData` stops short of constructing a `DefaultProjectData`.** The `connect()`
///   -then-short-circuit-on-non-OK-status behavior is fully implemented and tested; the final
///   `new DefaultProjectData(...)` construction step is not, since the ported
///   [`DefaultProjectData`](crate::framework::data::DefaultProjectData) trait deliberately has no
///   constructible implementation in this crate (construction was left implementation-specific by
///   that earlier port). See [`Self::get_local_project_data`]'s own docs.
pub struct DefaultLocalGhidraProtocolConnector {
    /// Mirrors `localStorageLocator`. `None` mirrors Java's `null` (see the struct's own docs on
    /// `GhidraURL.getProjectStorageLocator` returning `null` for an empty project name).
    local_storage_locator: Option<Box<dyn ProjectLocator>>,
    folder_path: RefCell<String>,
    folder_item_name: RefCell<Option<String>>,
    status_code: Cell<Option<StatusCode>>,
    read_only: Cell<bool>,
}

impl DefaultLocalGhidraProtocolConnector {
    /// Construct a protocol connector for use with a local file-based Ghidra project.
    ///
    /// `ghidra_url` is a Ghidra local file-based project URL (`ghidra:/path/projectName`).
    /// `url_support` supplies [`GhidraURL::get_project_storage_locator`] (see the struct's own
    /// docs on why this is an injected parameter).
    ///
    /// Mirrors `DefaultLocalGhidraProtocolConnector(URL ghidraURL)`, which itself first runs the
    /// abstract parent's own construction pipeline (`super(ghidraURL)`) before resolving the
    /// project storage locator.
    ///
    /// # Errors
    /// Returns an [`io::Error`] with kind [`io::ErrorKind::InvalidInput`] if `ghidra_url` is
    /// invalid, mirroring `MalformedURLException`.
    pub(crate) fn new(ghidra_url: &str, url_support: &dyn GhidraURL) -> io::Result<Self> {
        // Mirrors `GhidraProtocolConnector`'s own constructor pipeline: checkProtocol(),
        // checkUserInfo(), checkHostInfo() (overridden below), parseRepositoryName() (not
        // overridden by this subclass, but still able to fail construction -- see
        // `parse_repository_name`), parseItemPath() (overridden below, for its
        // folder_path/folder_item_name side effects -- see the struct's own docs on `itemPath`).
        Self::check_protocol(ghidra_url)?;

        let parts = parse_hierarchical(ghidra_url).ok_or_else(|| malformed_url("invalid URL"))?;
        Self::check_user_info(parts.authority)?;
        Self::check_host_info(parts.authority)?;
        Self::parse_repository_name(parts.path)?;

        let mut connector = Self {
            local_storage_locator: None,
            folder_path: RefCell::new(String::new()),
            folder_item_name: RefCell::new(None),
            status_code: Cell::new(None),
            read_only: Cell::new(false),
        };
        connector.init_folder_item_path(parts.query)?;

        connector.local_storage_locator = url_support
            .get_project_storage_locator(ghidra_url)
            .map_err(|e| malformed_url(e.to_string()))?;

        Ok(connector)
    }

    /// Mirrors the protected `GhidraProtocolConnector.checkProtocol()` (not overridden by this
    /// subclass).
    fn check_protocol(ghidra_url: &str) -> io::Result<()> {
        if !ghidra_url.starts_with("ghidra:") {
            return Err(malformed_url("expected ghidra URL protocol"));
        }
        Ok(())
    }

    /// Mirrors the protected `GhidraProtocolConnector.checkUserInfo()` (not overridden by this
    /// subclass). A local URL's decomposed form never has an authority component with user info,
    /// so this is only reachable for a malformed input.
    fn check_user_info(authority: Option<&str>) -> io::Result<()> {
        if authority.is_some_and(|a| a.contains('@')) {
            return Err(malformed_url("URL does not support user info"));
        }
        Ok(())
    }

    /// Mirrors the overridden `DefaultLocalGhidraProtocolConnector.checkHostInfo()`: unlike the
    /// parent's own version (which *requires* a host), a local URL must have *no* host
    /// specification at all.
    fn check_host_info(authority: Option<&str>) -> io::Result<()> {
        if authority.is_some_and(|a| !a.is_empty()) {
            return Err(malformed_url("unsupported host specification"));
        }
        Ok(())
    }

    /// Mirrors the private `GhidraProtocolConnector.parseRepositoryName()` (not overridden by this
    /// subclass). The result is not retained (see the struct's own docs on `itemPath`/
    /// `repositoryName` being dead state for this subclass): only its potential
    /// `MalformedURLException` matters here, since this subclass's own
    /// [`GhidraProtocolConnector::get_repository_name`] override never consults it.
    fn parse_repository_name(path: &str) -> io::Result<()> {
        if path.trim().is_empty() || path.len() < 2 || !path.starts_with('/') {
            return Ok(()); // content corresponds to RepositoryServerAdapter
        }
        let rest = &path[1..];
        let first_segment = match rest.find('/') {
            Some(i) => &rest[..i],
            None => rest,
        };
        if first_segment.is_empty() {
            return Err(malformed_url("invalid path specification"));
        }
        Ok(())
    }

    /// Mirrors the `protected final` `GhidraProtocolConnector.initFolderItemPath(String)` (not
    /// overridable, called here from the overridden `parseItemPath()`). Initializes
    /// `folder_path`/`folder_item_name` from the given (already-raw, undecoded) content path.
    fn init_folder_item_path(&self, content_path: Option<&str>) -> io::Result<()> {
        let Some(content_path) = content_path.filter(|s| !s.trim().is_empty()) else {
            *self.folder_path.borrow_mut() = "/".to_string();
            return Ok(());
        };

        if !content_path.starts_with('/') {
            return Err(malformed_url("invalid content path specification"));
        }

        let is_folder = content_path.ends_with('/');
        let path_to_split =
            if is_folder { &content_path[..content_path.len() - 1] } else { content_path };
        let pieces: Vec<&str> = path_to_split.split('/').collect();

        let mut folder_path = String::new();
        let mut folder_item_name = None;
        for (i, piece) in pieces.iter().enumerate().skip(1) {
            if piece.is_empty() {
                return Err(malformed_url("invalid content path specification"));
            }
            if !is_folder && i == pieces.len() - 1 {
                folder_item_name = Some((*piece).to_string());
            } else {
                folder_path.push('/');
                folder_path.push_str(piece);
            }
        }
        if folder_path.is_empty() {
            folder_path = "/".to_string();
        }

        *self.folder_path.borrow_mut() = folder_path;
        *self.folder_item_name.borrow_mut() = folder_item_name;
        Ok(())
    }

    /// Get the `ProjectLocator` associated with a local project URL.
    ///
    /// Returns `None` if `GhidraURL::get_project_storage_locator` could not derive one for the
    /// constructing URL (an empty project name) -- see the struct's own docs.
    ///
    /// Mirrors `getLocalProjectLocator()`.
    pub fn get_local_project_locator(&self) -> Option<&dyn ProjectLocator> {
        self.local_storage_locator.as_deref()
    }

    /// Connect and establish a local project data instance. Opening a project for write access is
    /// subject to in-use lock restriction. See [`GhidraProtocolConnector::get_status_code`] if
    /// `None` is returned.
    ///
    /// Mirrors the package-private `getLocalProjectData(boolean readOnlyAccess)`.
    ///
    /// # Errors
    /// Returns an [`io::Error`] if an IO error occurs, mirroring `throws IOException`.
    ///
    /// # Panics
    /// The `connect()`-then-short-circuit-on-non-OK-status behavior below is fully implemented and
    /// tested. If `connect()` *does* return [`StatusCode::Ok`], this panics: constructing a
    /// `DefaultProjectData` (Java's `new DefaultProjectData(localStorageLocator, !readOnlyAccess,
    /// false)`) is blocked on the ported
    /// [`DefaultProjectData`](crate::framework::data::DefaultProjectData) trait having no
    /// constructible implementation anywhere in this crate yet (construction was deliberately left
    /// implementation-specific by that earlier port); see the struct's own docs.
    pub fn get_local_project_data(&self, read_only_access: bool) -> io::Result<Option<()>> {
        if GhidraProtocolConnector::connect(self, read_only_access)? != StatusCode::Ok {
            return Ok(None);
        }
        unimplemented!(
            "DefaultLocalGhidraProtocolConnector::get_local_project_data requires constructing a \
             DefaultProjectData, which has no constructible implementation in this crate yet"
        )
    }
}

impl GhidraProtocolConnector for DefaultLocalGhidraProtocolConnector {
    /// Mirrors the overridden `getRepositoryRootGhidraURL()`, which always returns `null`
    /// ("not applicable").
    fn get_repository_root_ghidra_url(&self) -> Option<String> {
        None
    }

    /// Mirrors the overridden `getRepositoryName()`.
    ///
    /// # Panics
    /// Panics if the connector's `local_storage_locator` is `None` -- mirrors Java's
    /// `NullPointerException` from `localStorageLocator.getName()`. See the struct's own docs.
    fn get_repository_name(&self) -> Option<String> {
        Some(
            self.local_storage_locator
                .as_ref()
                .expect(
                    "local_storage_locator is None (mirrors Java's NullPointerException from \
                     localStorageLocator.getName())",
                )
                .get_name(),
        )
    }

    fn get_folder_path(&self) -> Option<String> {
        Some(self.folder_path.borrow().clone())
    }

    fn get_folder_item_name(&self) -> Option<String> {
        self.folder_item_name.borrow().clone()
    }

    fn get_status_code(&self) -> Option<StatusCode> {
        self.status_code.get()
    }

    /// This connector never establishes a `RepositoryAdapter` (local project access only).
    fn get_repository_adapter(&self) -> Option<Box<dyn RepositoryAdapter>> {
        None
    }

    /// This connector never establishes a `RepositoryServerAdapter` (local project access only).
    fn get_repository_server_adapter(&self) -> Option<Box<dyn RepositoryServerAdapter>> {
        None
    }

    /// Mirrors the overridden `connect(boolean readOnlyAccess)`.
    ///
    /// # Panics
    /// Panics if the connector's `local_storage_locator` is `None` -- mirrors Java's
    /// `NullPointerException` from `localStorageLocator.exists()`. See the struct's own docs.
    fn connect(&self, read_only: bool) -> io::Result<StatusCode> {
        self.read_only.set(read_only);
        let locator = self.local_storage_locator.as_ref().expect(
            "local_storage_locator is None (mirrors Java's NullPointerException from \
             localStorageLocator.exists())",
        );
        let status = if !locator.exists() { StatusCode::NotFound } else { StatusCode::Ok };
        self.status_code.set(Some(status));
        Ok(status)
    }

    /// Mirrors the overridden package-private `connect(RepositoryAdapter)`, which always throws
    /// `UnsupportedOperationException("local project access only")`.
    fn connect_to_repository(&self, _repository: Box<dyn RepositoryAdapter>) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "local project access only"))
    }

    /// Mirrors the overridden `isReadOnly()`.
    fn is_read_only(&self) -> Result<bool, NotConnectedException> {
        if self.status_code.get().is_none() {
            return Err(NotConnectedException::new("not connected"));
        }
        Ok(self.read_only.get())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::ProjectLocator;
    use std::cell::RefCell as StdRefCell;
    use std::rc::Rc;

    #[derive(Clone)]
    struct MockProjectLocator {
        name: String,
        exists: Rc<StdRefCell<bool>>,
    }

    impl ProjectLocator for MockProjectLocator {
        fn exists(&self) -> bool {
            *self.exists.borrow()
        }

        fn get_name(&self) -> String {
            self.name.clone()
        }
    }

    struct MockGhidraURL {
        locator: RefCell<Option<Box<dyn Fn() -> Box<dyn ProjectLocator>>>>,
    }

    impl MockGhidraURL {
        fn with_locator(name: &str, exists: bool) -> Self {
            let name = name.to_string();
            let exists = Rc::new(StdRefCell::new(exists));
            MockGhidraURL {
                locator: RefCell::new(Some(Box::new(move || {
                    Box::new(MockProjectLocator { name: name.clone(), exists: exists.clone() })
                        as Box<dyn ProjectLocator>
                }))),
            }
        }

        fn none() -> Self {
            MockGhidraURL { locator: RefCell::new(None) }
        }
    }

    impl GhidraURL for MockGhidraURL {
        fn make_project_locator(
            &self,
            _dir_path: &str,
            _project_name: &str,
        ) -> Box<dyn ProjectLocator> {
            unimplemented!("not exercised: get_project_storage_locator is overridden below")
        }

        fn handler(&self) -> Box<dyn crate::framework::seam_stubs::GhidraUrlHandlerLike> {
            unimplemented!("not exercised by these tests")
        }

        fn get_project_storage_locator(
            &self,
            _local_project_url: &str,
        ) -> io::Result<Option<Box<dyn ProjectLocator>>> {
            Ok(self.locator.borrow().as_ref().map(|make| make()))
        }
    }

    #[test]
    fn new_rejects_non_ghidra_protocol() {
        let url_support = MockGhidraURL::none();
        // `DefaultLocalGhidraProtocolConnector` has no `Debug` impl (its `ProjectLocator` field
        // isn't one), so the error is extracted via `match` instead of `Result::unwrap_err`.
        match DefaultLocalGhidraProtocolConnector::new("http:/path/Proj", &url_support) {
            Ok(_) => panic!("expected a malformed URL error"),
            Err(err) => assert_eq!(err.kind(), io::ErrorKind::InvalidInput),
        }
    }

    #[test]
    fn new_rejects_a_host_specification() {
        // A "//host/..." form decomposes with a non-empty authority, which this subclass's
        // checkHostInfo override rejects (opposite of the parent's own requirement).
        let url_support = MockGhidraURL::with_locator("Proj", true);
        match DefaultLocalGhidraProtocolConnector::new("ghidra://host/repo", &url_support) {
            Ok(_) => panic!("expected a malformed URL error"),
            Err(err) => assert_eq!(err.kind(), io::ErrorKind::InvalidInput),
        }
    }

    #[test]
    fn new_parses_folder_path_and_item_name_from_query() {
        let url_support = MockGhidraURL::with_locator("MyProject", true);
        let connector =
            DefaultLocalGhidraProtocolConnector::new("ghidra:/home/user/MyProject?/a/b/file", &url_support)
                .unwrap();

        assert_eq!(connector.get_folder_path().as_deref(), Some("/a/b"));
        assert_eq!(connector.get_folder_item_name().as_deref(), Some("file"));
    }

    #[test]
    fn new_with_folder_only_query_has_no_item_name() {
        let url_support = MockGhidraURL::with_locator("MyProject", true);
        let connector =
            DefaultLocalGhidraProtocolConnector::new("ghidra:/home/user/MyProject?/a/b/", &url_support)
                .unwrap();

        assert_eq!(connector.get_folder_path().as_deref(), Some("/a/b"));
        assert_eq!(connector.get_folder_item_name(), None);
    }

    #[test]
    fn new_without_query_defaults_folder_path_to_root() {
        let url_support = MockGhidraURL::with_locator("MyProject", true);
        let connector =
            DefaultLocalGhidraProtocolConnector::new("ghidra:/home/user/MyProject", &url_support)
                .unwrap();

        assert_eq!(connector.get_folder_path().as_deref(), Some("/"));
        assert_eq!(connector.get_folder_item_name(), None);
    }

    #[test]
    fn get_repository_root_ghidra_url_is_always_none() {
        let url_support = MockGhidraURL::with_locator("MyProject", true);
        let connector =
            DefaultLocalGhidraProtocolConnector::new("ghidra:/home/user/MyProject", &url_support)
                .unwrap();
        assert!(connector.get_repository_root_ghidra_url().is_none());
    }

    #[test]
    fn get_repository_name_returns_the_project_locator_name() {
        let url_support = MockGhidraURL::with_locator("MyProject", true);
        let connector =
            DefaultLocalGhidraProtocolConnector::new("ghidra:/home/user/MyProject", &url_support)
                .unwrap();
        assert_eq!(connector.get_repository_name().as_deref(), Some("MyProject"));
    }

    /// Java quirk, reproduced faithfully: `getRepositoryName()` dereferences a possibly-null
    /// `localStorageLocator` with no null check.
    #[test]
    #[should_panic(expected = "local_storage_locator is None")]
    fn get_repository_name_panics_when_locator_is_none() {
        let url_support = MockGhidraURL::none();
        let connector =
            DefaultLocalGhidraProtocolConnector::new("ghidra:/home/user/MyProject", &url_support)
                .unwrap();
        let _ = connector.get_repository_name();
    }

    #[test]
    fn connect_reports_ok_when_project_exists() {
        let url_support = MockGhidraURL::with_locator("MyProject", true);
        let connector =
            DefaultLocalGhidraProtocolConnector::new("ghidra:/home/user/MyProject", &url_support)
                .unwrap();

        assert!(connector.get_status_code().is_none());
        let status = GhidraProtocolConnector::connect(&connector, true).unwrap();
        assert_eq!(status, StatusCode::Ok);
        assert_eq!(connector.get_status_code(), Some(StatusCode::Ok));
        assert_eq!(connector.is_read_only().unwrap(), true);
    }

    #[test]
    fn connect_reports_not_found_when_project_does_not_exist() {
        let url_support = MockGhidraURL::with_locator("MyProject", false);
        let connector =
            DefaultLocalGhidraProtocolConnector::new("ghidra:/home/user/MyProject", &url_support)
                .unwrap();

        let status = GhidraProtocolConnector::connect(&connector, false).unwrap();
        assert_eq!(status, StatusCode::NotFound);
        assert_eq!(connector.is_read_only().unwrap(), false);
    }

    /// Java quirk, reproduced faithfully: `connect(boolean)` dereferences a possibly-null
    /// `localStorageLocator` with no null check.
    #[test]
    #[should_panic(expected = "local_storage_locator is None")]
    fn connect_panics_when_locator_is_none() {
        let url_support = MockGhidraURL::none();
        let connector =
            DefaultLocalGhidraProtocolConnector::new("ghidra:/home/user/MyProject", &url_support)
                .unwrap();
        let _ = GhidraProtocolConnector::connect(&connector, true);
    }

    #[test]
    fn is_read_only_reports_not_connected_before_connect() {
        let url_support = MockGhidraURL::with_locator("MyProject", true);
        let connector =
            DefaultLocalGhidraProtocolConnector::new("ghidra:/home/user/MyProject", &url_support)
                .unwrap();
        assert!(connector.is_read_only().is_err());
    }

    #[test]
    fn connect_to_repository_is_unsupported() {
        let url_support = MockGhidraURL::with_locator("MyProject", true);
        let connector =
            DefaultLocalGhidraProtocolConnector::new("ghidra:/home/user/MyProject", &url_support)
                .unwrap();

        struct StubRepo;
        impl RepositoryAdapter for StubRepo {
            fn get_name(&self) -> String {
                "repo".to_string()
            }
            fn is_connected(&self) -> bool {
                true
            }
            fn connect(&self) -> io::Result<()> {
                Ok(())
            }
        }

        let err = connector.connect_to_repository(Box::new(StubRepo)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn get_local_project_locator_reflects_url_support() {
        let url_support = MockGhidraURL::with_locator("MyProject", true);
        let connector =
            DefaultLocalGhidraProtocolConnector::new("ghidra:/home/user/MyProject", &url_support)
                .unwrap();
        assert_eq!(connector.get_local_project_locator().unwrap().get_name(), "MyProject");
    }

    #[test]
    fn get_local_project_locator_is_none_when_url_support_finds_nothing() {
        let url_support = MockGhidraURL::none();
        let connector =
            DefaultLocalGhidraProtocolConnector::new("ghidra:/home/user/MyProject", &url_support)
                .unwrap();
        assert!(connector.get_local_project_locator().is_none());
    }

    #[test]
    fn get_local_project_data_returns_none_without_constructing_project_data_when_not_found() {
        let url_support = MockGhidraURL::with_locator("MyProject", false);
        let connector =
            DefaultLocalGhidraProtocolConnector::new("ghidra:/home/user/MyProject", &url_support)
                .unwrap();
        // status ends up NOT_FOUND, so the (unimplemented) DefaultProjectData construction path
        // is never reached.
        assert!(connector.get_local_project_data(false).unwrap().is_none());
    }
}

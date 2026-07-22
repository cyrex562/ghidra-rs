use std::io;

use crate::framework::model::ProjectLocator;
use crate::framework::remote::DEFAULT_PORT;
use crate::framework::seam_stubs::GhidraUrlHandlerLike;
use crate::util::NamingUtilities;

/// The Ghidra URL scheme name, mirroring `GhidraURL.PROTOCOL`.
pub const PROTOCOL: &str = "ghidra";

const PROTOCOL_URL_START: &str = "ghidra:";

/// File extension for a local project's marker file, mirroring `GhidraURL.MARKER_FILE_EXTENSION`.
pub const MARKER_FILE_EXTENSION: &str = ".gpr";

/// File extension for a local project's storage directory, mirroring
/// `GhidraURL.PROJECT_DIRECTORY_EXTENSION`.
pub const PROJECT_DIRECTORY_EXTENSION: &str = ".rep";

/// Utility trait which provides support for creating Ghidra local project and remote repository
/// URLs. Valid Ghidra URL forms include:
/// - `ghidra:[ext:]//<host>:<port>/<repository-name>[/<folder-path>]/[<folderItemName>[#ref]]`
/// - `ghidra:/[X:/]<project-path>/<project-name>[?[/<folder-path>]/[<folderItemName>[#ref]]]`
/// - `ghidra:////UNCServer/UNCshare/<project-name>[?[/<folder-path>]/[<folderItemName>[#ref]]]`
///
/// NOTE: `[ext:]` corresponds to an optional Ghidra server extension protocol if supported. This
/// requires a corresponding [`GhidraProtocolHandler`](crate::framework::protocol::ghidra::GhidraProtocolHandler)
/// extension. Helper methods within this utility are not provided for forming such URLs.
///
/// Port of `ghidra.framework.protocol.ghidra.GhidraURL`, a static-method-only utility class
/// (private constructor). `java.net.URL`/`URI` parameters and returns are represented as
/// `&str`/`String`, matching how this crate already represents Ghidra URLs elsewhere (see
/// [`Project`](crate::framework::model::Project)). Overloaded Java methods that differ only in
/// taking a `String` vs. a `URL` collapse into a single method here since both are represented
/// identically; overloads that differ in behavior (e.g. the two distinct `isServerURL` checks)
/// keep distinct names instead.
///
/// Selected as a dependency-cycle cut-point, so every method here takes `&self` and returns
/// owned values, matching the convention used elsewhere in this crate for cut-point traits (e.g.
/// [`GenericRunInfo`](crate::framework::generic_run_info::GenericRunInfo), which is likewise a
/// static-method-only Java utility class). `ProjectLocator` construction and the `Handler`
/// extension-protocol support check are exposed as required seam methods
/// ([`Self::make_project_locator`], [`Self::handler`]) since no concrete implementation of either
/// is available yet; default method bodies implement the rest of the class's logic directly,
/// mirroring [`GenericRunInfo`]'s own mix of seam accessors and default-bodied logic methods.
///
/// This port implements URL construction/decomposition with a minimal, purpose-built parser
/// rather than a full `java.net.URI`-equivalent library; it is sufficient for the Ghidra URL forms
/// documented above but does not replicate `java.net.URI`'s general RFC 3986 percent-encoding
/// rules exactly (only the ASCII space character is percent-encoded/decoded in path components,
/// which is sufficient since [`NamingUtilities::check_name`] already restricts path element
/// character sets to values that need no other escaping).
pub trait GhidraURL {
    /// Construct a new project locator for the given absolute directory path and project name,
    /// standing in for `new ProjectLocator(dirPath, name)`. Construction is implementation
    /// specific (there is no dynamically-dispatched "static constructor" in Rust), so this is a
    /// required seam method with no default body.
    fn make_project_locator(&self, dir_path: &str, project_name: &str) -> Box<dyn ProjectLocator>;

    /// Returns the seam onto `ghidra.framework.protocol.ghidra.Handler`'s
    /// `isSupportedURL(URL)`, used by [`Self::is_supported_server_url`].
    fn handler(&self) -> Box<dyn GhidraUrlHandlerLike>;

    /// Determine if the specified URL refers to a local project and it exists. Mirrors
    /// `localProjectExists(URL)`.
    fn local_project_exists(&self, url: &str) -> bool {
        match self.get_project_storage_locator(url) {
            Ok(Some(loc)) => loc.exists(),
            _ => false,
        }
    }

    /// Determine if the specified string appears to be a possible Ghidra URL (starts with
    /// `"ghidra:"`), or tests if the given URL is using the Ghidra protocol. Merges
    /// `isGhidraURL(String)` and `isGhidraURL(URL)`.
    fn is_ghidra_url(&self, str: &str) -> bool {
        str.starts_with(PROTOCOL_URL_START)
    }

    /// Determine if URL string uses a local Ghidra project URL format (e.g.
    /// `ghidra:/path...`). Extensive validation is not performed; this method is intended to
    /// differentiate from a server URL only. Merges `isLocalURL(String)` and `isLocalURL(URL)`.
    fn is_local_url(&self, str: &str) -> bool {
        is_local_url_str(str)
    }

    /// Determine if a URL string corresponds to a remote Ghidra server URL (e.g.
    /// `ghidra://host...`). Extensive validation is not performed; this method is intended to
    /// differentiate between a local and remote Ghidra URL only. Mirrors `isServerURL(String)`.
    fn is_server_url(&self, str: &str) -> bool {
        self.is_ghidra_url(str) && !self.is_local_url(str)
    }

    /// Determine if the specified URL is any type of supported server Ghidra URL. If a Ghidra
    /// server extension URL is specified the corresponding
    /// [`GhidraProtocolHandler`](crate::framework::protocol::ghidra::GhidraProtocolHandler)
    /// extension must be present or `false` will be returned. Mirrors `isServerURL(URL)`
    /// (distinct from [`Self::is_server_url`], the plain `isServerURL(String)` overload).
    fn is_supported_server_url(&self, url: &str) -> bool {
        if !self.is_ghidra_url(url) {
            return false;
        }
        self.handler().is_supported_url(url)
    }

    /// Determine if the specified path is only valid on a Windows platform. Such paths contain
    /// either a drive specification or UNC path (e.g. `C:\`, `/C:/`, `//server/...`,
    /// `\\server\..`). NOTE: This does not check for existence of the specified path. Mirrors
    /// `isWindowsOnlyPath(String)`.
    fn is_windows_only_path(&self, path: &str) -> bool {
        let normalized = path.replace('\\', "/");
        is_windows_drive_path(&normalized) || is_unc_path(&normalized)
    }

    /// Get the project locator which corresponds to the specified local project URL. Confirm
    /// local project URL with [`Self::is_local_url`] prior to method use. Mirrors
    /// `getProjectStorageLocator(URL)`.
    ///
    /// Returns `Ok(None)` if an invalid (empty-name) path was specified.
    ///
    /// # Errors
    /// Returns `io::Error` with kind [`io::ErrorKind::InvalidInput`] if `local_project_url` is not
    /// a [valid local project URL](Self::is_local_url), mirroring `IllegalArgumentException`.
    fn get_project_storage_locator(
        &self,
        local_project_url: &str,
    ) -> io::Result<Option<Box<dyn ProjectLocator>>> {
        if !self.is_local_url(local_project_url) {
            return Err(invalid_input("Invalid local Ghidra project URL"));
        }

        let parts = parse_hierarchical(local_project_url)
            .ok_or_else(|| invalid_input("Invalid local Ghidra project URL"))?;
        let path = parts.path;

        let index = path.rfind('/');
        let dir_path = match index {
            Some(0) | None => "/",
            Some(i) => &path[..i],
        };
        let dir_path = dir_path.strip_prefix("////").map(|_| &dir_path[2..]).unwrap_or(dir_path);

        let name = match index {
            Some(i) => &path[i + 1..],
            None => path,
        };
        if name.is_empty() {
            return Ok(None);
        }

        Ok(Some(self.make_project_locator(dir_path, name)))
    }

    /// Get the URL-decoded reference/fragment from the URL, or `None`. Mirrors
    /// `getDecodedReference(URL)`.
    fn get_decoded_reference(&self, url: &str) -> Option<String> {
        let fragment = url.split('#').nth(1)?;
        if fragment.trim().is_empty() {
            return None;
        }
        let decoded = percent_decode(fragment).replace("%2B", "+");
        Some(decoded)
    }

    /// Get the shared repository name associated with a repository URL, or `None` if not
    /// applicable. For Ghidra URL extensions it is assumed that the first path element
    /// corresponds to the repository name. Mirrors `getRepositoryName(URL)`.
    fn get_repository_name(&self, url: &str) -> Option<String> {
        if !self.is_supported_server_url(url) {
            return None;
        }
        let path = server_uri_path(url)?;
        if path.len() < 2 || !path.starts_with('/') || path[1..].starts_with('/') {
            return None;
        }
        let path = &path[1..];
        let name = path.split('/').next().unwrap_or(path);
        Some(name.to_string())
    }

    /// Determine if the specified URL is any type of server "repository" URL. No checking is
    /// performed as to the existence of the server or repository. NOTE: ghidra protocol
    /// extensions are not currently supported (e.g. `ghidra:http://...`). Mirrors
    /// `isServerRepositoryURL(URL)`.
    fn is_server_repository_url(&self, url: &str) -> bool {
        if !self.is_supported_server_url(url) {
            return false;
        }
        let Some(path) = server_uri_path(url) else {
            return false;
        };
        path.starts_with('/') && path.len() > 1 && !path[1..].starts_with('/')
    }

    /// Ensure that an absolute path is specified and normalize its format (e.g. Windows path
    /// separators are converted to `/`). Mirrors `checkLocalAbsolutePath(String, boolean)`.
    ///
    /// # Errors
    /// Returns `io::Error` with kind [`io::ErrorKind::InvalidInput`] if an invalid path is
    /// specified, mirroring `IllegalArgumentException`.
    fn check_local_absolute_path(&self, absolute_path: &str, is_directory: bool) -> io::Result<String> {
        let mut path = absolute_path.replace('\\', "/");

        if is_unc_path(&path) {
            check_valid_project_path(&path, 2)?;
            if is_directory && !path.ends_with('/') {
                path.push('/');
            }
            return Ok(path);
        } else if path.starts_with("//") {
            return Err(invalid_input(format!("Invalid UNC path: {absolute_path}")));
        }

        let mut scan_index = 1usize;
        if is_windows_drive_path(&path) {
            if !path.starts_with('/') {
                path = format!("/{path}");
            }
            if path.len() == 3 {
                path.push('/');
            }
            scan_index = 4;
        } else if !path.starts_with('/') {
            return Err(invalid_input("Absolute path required"));
        }

        check_valid_project_path(&path, scan_index)?;

        if is_directory && !path.ends_with('/') {
            path.push('/');
        }
        Ok(path)
    }

    /// Create a Ghidra URL from a string form of a Ghidra URL or local project path. This method
    /// can consume strings produced by [`Self::get_display_string`]. Mirrors `toURL(String)`.
    ///
    /// # Errors
    /// Returns `io::Error` with kind [`io::ErrorKind::InvalidInput`] if an invalid path or URL is
    /// specified, mirroring `IllegalArgumentException`.
    fn to_url(&self, project_path_or_url: &str) -> io::Result<String> {
        if !self.is_ghidra_url(project_path_or_url) {
            if project_path_or_url.ends_with(PROJECT_DIRECTORY_EXTENSION)
                || project_path_or_url.ends_with(MARKER_FILE_EXTENSION)
            {
                let ext = project_path_or_url
                    .rfind('.')
                    .map(|i| &project_path_or_url[i..])
                    .unwrap_or("");
                return Err(invalid_input(format!("Project path must omit extension: {ext}")));
            }
            let path = self.check_local_absolute_path(project_path_or_url, false)?;
            let min_split_index = if path.as_bytes().get(2) == Some(&b':') { 3 } else { 0 };
            let split_index = path.rfind('/');
            let split_index = match split_index {
                Some(i) if i >= min_split_index && path.len() != i + 1 => i,
                _ => {
                    return Err(invalid_input("Absolute project path is missing project name"));
                }
            };
            let split_index = split_index + 1;
            let location = &path[..split_index];
            let project_name = &path[split_index..];
            return self.make_project_url(location, project_name, None, None);
        }

        // NOTE: We assume the string is already properly encoded in its external form.
        Ok(project_path_or_url.to_string())
    }

    /// Create a new URL which is resolved from a base Ghidra project or repository URL to which
    /// the specified content folder or file path is added along with the optional reference.
    /// Mirrors `resolve(URL, String, String)`.
    ///
    /// # Errors
    /// Returns `io::Error` with kind [`io::ErrorKind::InvalidInput`] if an invalid Ghidra project
    /// or repository URL, or an invalid folder/file path, is specified, mirroring
    /// `IllegalArgumentException`.
    fn resolve(
        &self,
        ghidra_url: &str,
        project_file_path: Option<&str>,
        r#ref: Option<&str>,
    ) -> io::Result<String> {
        let project_file_path = match project_file_path {
            Some(p) if !p.trim().is_empty() => {
                if !p.starts_with('/') || p.contains('\\') {
                    return Err(invalid_input("Absolute path required using '/' delimiter"));
                }
                check_valid_project_path(p, 1)?;
                Some(p)
            }
            _ => None,
        };

        let ref_encoded = encode_ref_plus(r#ref);

        if self.is_local_url(ghidra_url) {
            let parts = parse_hierarchical(ghidra_url)
                .ok_or_else(|| invalid_input(format!("Invalid project/repository URL: {ghidra_url}")))?;
            let system_project_path = force_local_unc_path_if_needed(parts.path);
            let mut out = format!("{PROTOCOL_URL_START}{system_project_path}");
            if let Some(p) = project_file_path {
                out.push('?');
                out.push_str(p);
            }
            if let Some(r) = &ref_encoded {
                out.push('#');
                out.push_str(r);
            }
            return Ok(out);
        }

        if let Some(repo_name) = self.get_repository_name(ghidra_url) {
            let mut path = format!("/{repo_name}");
            if let Some(p) = project_file_path {
                path.push_str(p);
            }

            let parts = parse_hierarchical(ghidra_url)
                .ok_or_else(|| invalid_input(format!("Invalid project/repository URL: {ghidra_url}")))?;
            let authority = parts.authority.unwrap_or_default();
            let mut out = format!("ghidra://{authority}{path}");
            if let Some(r) = &ref_encoded {
                out.push('#');
                out.push_str(r);
            }
            return Ok(out);
        }

        Err(invalid_input(format!("Invalid project/repository URL: {ghidra_url}")))
    }

    /// Get Ghidra URL which corresponds to the local-project or repository with any file path or
    /// query details removed. Mirrors `getProjectURL(URL)`.
    ///
    /// # Errors
    /// Returns `io::Error` with kind [`io::ErrorKind::InvalidInput`] if `ghidra_url` does not
    /// properly identify a remote repository or local project.
    fn get_project_url(&self, ghidra_url: &str) -> io::Result<String> {
        self.resolve(ghidra_url, None, None)
    }

    /// Get the decoded project content pathname referenced by the specified Ghidra file/folder
    /// URL. If path is missing, the root folder is returned. Mirrors `getProjectPathname(URL)`.
    ///
    /// # Errors
    /// Returns `io::Error` with kind [`io::ErrorKind::InvalidInput`] if `ghidra_url` is invalid.
    fn get_project_pathname(&self, ghidra_url: &str) -> io::Result<String> {
        if self.is_local_url(ghidra_url) {
            let parts = parse_hierarchical(ghidra_url)
                .ok_or_else(|| invalid_input("Invalid project/repository URL"))?;
            return match parts.query {
                None => Ok("/".to_string()),
                Some(q) if q.starts_with('/') => Ok(percent_decode(q)),
                Some(_) => Err(invalid_input("Missing absolute project content path")),
            };
        }

        if self.is_supported_server_url(ghidra_url) {
            let path = server_uri_path(ghidra_url)
                .ok_or_else(|| invalid_input("Invalid project/repository URL"))?;
            // Skip repo name (first path element).
            return match path[1..].find('/') {
                Some(ix) => Ok(path[1 + ix..].to_string()),
                None => Ok("/".to_string()),
            };
        }

        Err(invalid_input("Invalid project/repository URL"))
    }

    /// Force the specified URL to specify a folder. This may be necessary when only folders are
    /// supported since Ghidra permits both a folder and file to have the same name within its
    /// parent folder. Mirrors `getFolderURL(URL)`.
    ///
    /// # Errors
    /// Returns `io::Error` with kind [`io::ErrorKind::InvalidInput`] if `ghidra_url` is neither a
    /// [valid remote server URL](Self::is_server_repository_url) nor a
    /// [local project URL](Self::is_local_url).
    fn get_folder_url(&self, ghidra_url: &str) -> io::Result<String> {
        let mut folder_path = self.get_project_pathname(ghidra_url)?;
        if !folder_path.ends_with('/') {
            folder_path.push('/');
        }
        self.resolve(ghidra_url, Some(&folder_path), self.get_decoded_reference(ghidra_url).as_deref())
    }

    /// Get a normalized URL which eliminates use of host names and optional URL ref which may
    /// prevent direct comparison. Mirrors `getNormalizedURL(URL)`.
    ///
    /// # Errors
    /// Returns `io::Error` with kind [`io::ErrorKind::InvalidInput`] if `url` does not specify the
    /// Ghidra protocol, or is otherwise invalid.
    fn get_normalized_url(&self, url: &str) -> io::Result<String> {
        if !self.is_ghidra_url(url) {
            return Err(invalid_input("Ghidra URL required"));
        }

        let parts =
            parse_hierarchical(url).ok_or_else(|| invalid_input("Invalid Ghidra URL"))?;

        if self.is_local_url(url) {
            let mut out = format!("{PROTOCOL_URL_START}{}", parts.path);
            if let Some(q) = parts.query {
                out.push('?');
                out.push_str(q);
            }
            return Ok(out);
        }

        let authority = parts.authority.unwrap_or_default();
        let (host, port) = split_authority(authority);
        let revised_host = host_as_ip_address(host);
        Ok(format!(
            "ghidra://{revised_host}{}{}",
            port.map(|p| format!(":{p}")).unwrap_or_default(),
            parts.path
        ))
    }

    /// Generate preferred display string for Ghidra URLs. NOTE: the display-friendly string
    /// returned is intended for display use only and should not be parsed back into a URL.
    /// Mirrors `getDisplayString(URL)`.
    fn get_display_string(&self, url: &str) -> String {
        if self.is_local_url(url) {
            if let Some(parts) = parse_hierarchical(url) {
                let query_blank = parts.query.map(str::trim).unwrap_or("").is_empty();
                let fragment_blank = parts.fragment.map(str::trim).unwrap_or("").is_empty();
                if query_blank && fragment_blank {
                    let path = parts.path;
                    let bytes = path.as_bytes();
                    if bytes.len() > 2
                        && bytes[2] == b':'
                        && bytes.get(3) == Some(&b'/')
                        && (bytes[1] as char).is_ascii_alphabetic()
                    {
                        return path[1..].replace('/', "\\");
                    }
                    return path.to_string();
                }
            }
        }
        url.to_string()
    }

    /// Create a URL which refers to a local Ghidra project with optional project folder/file path
    /// and optional reference. Merges the `makeURL(String, String)` and
    /// `makeURL(String, String, String, String)` overloads (the former passes `None`/`None` for
    /// the latter two parameters).
    ///
    /// # Errors
    /// Returns `io::Error` with kind [`io::ErrorKind::InvalidInput`] if an absolute
    /// `project_location` path is not specified, mirroring `IllegalArgumentException`.
    fn make_project_url(
        &self,
        project_location: &str,
        project_name: &str,
        project_file_path: Option<&str>,
        r#ref: Option<&str>,
    ) -> io::Result<String> {
        if project_location.trim().is_empty() || project_name.trim().is_empty() {
            return Err(invalid_input("Invalid project location and/or name"));
        }
        check_name(project_name, "Project name")?;

        let mut path = self.check_local_absolute_path(project_location, true)?;
        path = check_unc_path_for_url(&path);
        path.push_str(project_name);

        let project_file_path = match project_file_path {
            Some(p) if !p.trim().is_empty() => {
                if !p.starts_with('/') || p.contains('\\') {
                    return Err(invalid_input("Absolute path required using '/' delimiter"));
                }
                check_valid_project_path(p, 1)?;
                Some(p)
            }
            _ => None,
        };

        let mut out = format!("{PROTOCOL_URL_START}{path}");
        if let Some(p) = project_file_path {
            out.push('?');
            out.push_str(p);
        }
        if let Some(r) = encode_ref_plus(r#ref) {
            out.push('#');
            out.push_str(&r);
        }
        Ok(out)
    }

    /// Create a URL which refers to a Ghidra project with optional project file and ref. If
    /// project locator corresponds to a transient project a server URL form will be returned.
    /// Merges the `makeURL(ProjectLocator)` and `makeURL(ProjectLocator, String, String)`
    /// overloads. Mirrors `makeURL(ProjectLocator, String, String)`.
    ///
    /// # Errors
    /// Returns `io::Error` with kind [`io::ErrorKind::InvalidInput`] if an invalid
    /// `project_file_path` is specified or URL construction otherwise fails.
    fn make_project_url_for_locator(
        &self,
        project_locator: &dyn ProjectLocator,
        project_file_path: Option<&str>,
        r#ref: Option<&str>,
    ) -> io::Result<String> {
        self.resolve(&project_locator.url(), project_file_path, r#ref)
    }

    /// Create a URL which refers to Ghidra Server repository content. Path may correspond to
    /// either a file or folder. Merges the `makeURL(String, int, String, String)` and
    /// `makeURL(String, int, String, String, String)` overloads.
    ///
    /// # Errors
    /// Returns `io::Error` with kind [`io::ErrorKind::InvalidInput`] if arguments are specified
    /// which cannot be encoded into a URL.
    fn make_repository_url(
        &self,
        host: &str,
        port: i32,
        repository_name: &str,
        repository_path: Option<&str>,
        r#ref: Option<&str>,
    ) -> io::Result<String> {
        if host.trim().is_empty() {
            return Err(invalid_input("host required"));
        }
        if repository_name.trim().is_empty() {
            return Err(invalid_input("repository name required"));
        }
        check_name(repository_name, "Repository name")?;
        let port = if port == 0 || port == DEFAULT_PORT as i32 { -1 } else { port };

        let mut path = format!("/{repository_name}");
        if let Some(repository_path) = repository_path {
            if !repository_path.trim().is_empty() {
                if !repository_path.starts_with('/') || repository_path.contains('\\') {
                    return Err(invalid_input("Invalid repository path"));
                }
                if repository_path.len() != 1 {
                    let mut check_path = &repository_path[1..];
                    if let Some(stripped) = check_path.strip_suffix('/') {
                        check_path = stripped;
                    }
                    check_valid_project_path(check_path, 0)?;
                }
                path.push_str(repository_path);
            }
        }

        let mut out = format!("ghidra://{}", percent_encode_space(host));
        if port > 0 {
            out.push(':');
            out.push_str(&port.to_string());
        }
        out.push_str(&path);
        if let Some(r) = encode_ref_plus(r#ref) {
            out.push('#');
            out.push_str(&r);
        }
        Ok(out)
    }

    /// Create a URL which refers to Ghidra Server named repository and its root folder. Mirrors
    /// `makeURL(String, int, String)`.
    ///
    /// # Errors
    /// Returns `io::Error` with kind [`io::ErrorKind::InvalidInput`] if arguments are specified
    /// which cannot be encoded into a URL.
    fn make_repository_root_url(&self, host: &str, port: i32, repository_name: &str) -> io::Result<String> {
        self.make_repository_url(host, port, repository_name, None, None)
    }

    /// Create a URL which refers to Ghidra Server repository content addressed as a named child
    /// of a repository folder. Mirrors `makeURL(String, int, String, String, String, String)`.
    ///
    /// # Errors
    /// Returns `io::Error` with kind [`io::ErrorKind::InvalidInput`] if required arguments are
    /// blank or invalid.
    fn make_repository_child_url(
        &self,
        host: &str,
        port: i32,
        repository_name: &str,
        repository_folder_path: &str,
        child_name: &str,
        r#ref: Option<&str>,
    ) -> io::Result<String> {
        let mut path = repository_folder_path.to_string();
        if !path.ends_with('/') {
            path.push('/');
        }
        path.push_str(child_name);

        self.make_repository_url(host, port, repository_name, Some(&path), r#ref)
    }

    /// Create a URL which refers to Ghidra Server (i.e. no specific repository). Mirrors
    /// `makeURL(String, int)`.
    ///
    /// # Errors
    /// Returns `io::Error` with kind [`io::ErrorKind::InvalidInput`] if arguments are specified
    /// which cannot be encoded into a URL.
    fn make_server_url(&self, host: &str, port: i32) -> io::Result<String> {
        let mut out = format!("ghidra://{}", percent_encode_space(host));
        if port > 0 {
            out.push(':');
            out.push_str(&port.to_string());
        }
        Ok(out)
    }
}

/// Builds the `io::Error` returned for `IllegalArgumentException`-equivalent validation failures,
/// mirroring the convention used by the sibling `ghidra_protocol_handler`/
/// `default_ghidra_protocol_handler` ports for `MalformedURLException`.
fn invalid_input(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg.into())
}

fn check_name(name: &str, element_type: &str) -> io::Result<()> {
    NamingUtilities::check_name(name, Some(element_type)).map_err(invalid_input)
}

/// Check for a valid project path (see [`NamingUtilities::check_name`]), mirroring the private
/// `checkValidProjectPath(String, int)`.
fn check_valid_project_path(path: &str, start_index: usize) -> io::Result<()> {
    let str = if start_index >= path.len() { "" } else { &path[start_index..] };
    if !str.is_empty() {
        for s in str.split('/') {
            check_name(s, "")?;
        }
    }
    Ok(())
}

/// Determine if URL string uses a local Ghidra project URL format, mirroring
/// `IS_LOCAL_URL_PATTERN` (`^ghidra:(/|////)(?![/]).*`). Rust's `regex` crate has no lookahead
/// support, so this is implemented directly: the pattern matches exactly one or exactly four
/// leading slashes after `"ghidra:"` (a negative lookahead disallowing a further `/` is
/// automatically satisfied since the slash run-length is checked for an exact count).
fn is_local_url_str(s: &str) -> bool {
    match s.strip_prefix(PROTOCOL_URL_START) {
        Some(rest) => {
            let slash_count = rest.chars().take_while(|&c| c == '/').count();
            slash_count == 1 || slash_count == 4
        }
        None => false,
    }
}

/// Mirrors `WINDOWS_DRIVE_PATH_PATTERN` (`^[/]{0,1}[A-Za-z]:(/.*)?`).
fn is_windows_drive_path(s: &str) -> bool {
    let rest = s.strip_prefix('/').unwrap_or(s);
    let mut chars = rest.chars();
    let Some(letter) = chars.next() else { return false };
    if !letter.is_ascii_alphabetic() {
        return false;
    }
    if chars.next() != Some(':') {
        return false;
    }
    matches!(chars.next(), None | Some('/'))
}

/// Mirrors `UNC_PATH_PATTERN` (`^//(?![/]).+/(?![/]).+`).
fn is_unc_path(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("//") else { return false };
    if rest.starts_with('/') {
        return false;
    }
    match rest.find('/') {
        None => false,
        Some(idx) => {
            let server = &rest[..idx];
            let after = &rest[idx + 1..];
            !server.is_empty() && !after.is_empty() && !after.starts_with('/')
        }
    }
}

/// Mirrors `STARTS_WITH_TWO_FORWARD_SLASHES_PATTERN` (`^//(?![/]).*`).
fn starts_with_two_forward_slashes(s: &str) -> bool {
    s.starts_with("//") && !s.starts_with("///")
}

/// A minimal decomposition of a hierarchical (non-opaque) Ghidra URL string, standing in for the
/// subset of `java.net.URI` accessors this class needs (`getAuthority`, `getPath`, `getQuery`,
/// `getFragment`). Percent-decoding is intentionally NOT performed here; callers decode
/// components as needed (see [`percent_decode`]).
struct UriParts<'a> {
    authority: Option<&'a str>,
    path: &'a str,
    query: Option<&'a str>,
    fragment: Option<&'a str>,
}

/// Parses a hierarchical (non-opaque) Ghidra URL, i.e. one whose scheme-specific part begins with
/// `/` -- covering both the local project form (1 or 4 leading slashes) and the server/repository
/// authority form (2 leading slashes). Returns `None` for a non-Ghidra or opaque (protocol
/// extension, e.g. `ghidra:http://...`) URL.
fn parse_hierarchical(url: &str) -> Option<UriParts<'_>> {
    let rest = url.strip_prefix(PROTOCOL_URL_START)?;
    if !rest.starts_with('/') {
        return None;
    }

    let (before_fragment, fragment) = split_once_char(rest, '#');
    let (before_query, query) = split_once_char(before_fragment, '?');

    if starts_with_two_forward_slashes(before_query) {
        let after_slashes = &before_query[2..];
        let (authority, path) = match after_slashes.find('/') {
            Some(i) => (&after_slashes[..i], &after_slashes[i..]),
            None => (after_slashes, ""),
        };
        return Some(UriParts { authority: Some(authority), path, query, fragment });
    }

    Some(UriParts { authority: None, path: before_query, query, fragment })
}

fn split_once_char(s: &str, c: char) -> (&str, Option<&str>) {
    match s.find(c) {
        Some(i) => (&s[..i], Some(&s[i + c.len_utf8()..])),
        None => (s, None),
    }
}

/// Splits an authority component (`host` or `host:port`) into `(host, port)`, mirroring
/// `URI.getHost()`/`URI.getPort()`.
fn split_authority(authority: &str) -> (&str, Option<i32>) {
    match authority.rsplit_once(':') {
        Some((host, port_str)) => match port_str.parse::<i32>() {
            Ok(port) => (host, Some(port)),
            Err(_) => (authority, None),
        },
        None => (authority, None),
    }
}

/// Gets the URL-decoded path contained within the specified URL, including the repository name.
/// Mirrors the private `getServerURIPath(URI)` for the non-opaque (hierarchical) case; the opaque
/// protocol-extension case (`ghidra:ext://...`) is not supported by this simplified parser.
fn server_uri_path(url: &str) -> Option<String> {
    let parts = parse_hierarchical(url)?;
    if parts.authority.is_none() {
        return None;
    }
    if parts.path.trim().is_empty() {
        return None;
    }
    Some(percent_decode(parts.path))
}

/// Perform preliminary encode of `+` within a raw ref string, mirroring `encodeRefPlus(String)`.
fn encode_ref_plus(raw_ref: Option<&str>) -> Option<String> {
    match raw_ref {
        Some(r) if !r.trim().is_empty() => Some(r.replace('+', "%2B")),
        _ => None,
    }
}

/// Force preservation of a UNC path's leading slashes when embedded in a URL, mirroring the
/// private `forceLocalUNCPathIfNeeded(String)`.
fn force_local_unc_path_if_needed(path: &str) -> String {
    if path.starts_with("//") && path.len() > 3 && path.as_bytes()[2] != b'/' {
        format!("//{path}")
    } else {
        path.to_string()
    }
}

/// Adjust a UNC path starting with exactly 2 forward slashes when used to form a URL, mirroring
/// the private `checkUncPathForURL(String)`.
fn check_unc_path_for_url(path: &str) -> String {
    if starts_with_two_forward_slashes(path) {
        format!("//{path}")
    } else {
        path.to_string()
    }
}

/// Percent-encodes the ASCII space character, sufficient for the restricted path-element
/// character set enforced by [`NamingUtilities::check_name`] (see the trait-level doc comment for
/// why fuller RFC 3986 escaping is not needed).
fn percent_encode_space(s: &str) -> String {
    s.replace(' ', "%20")
}

/// General percent-decoding (`%XX` -> byte), mirroring the relevant subset of
/// `URLDecoder.decode(String, "UTF-8")` (this class's usages never rely on `URLDecoder`'s
/// `'+'`-to-space form-encoding behavior, only its `%XX` decoding).
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 3 <= bytes.len() {
            if let Ok(byte) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Resolves a hostname to its IP address string if possible, otherwise returns the supplied host
/// string unchanged, mirroring the private `getHostAsIpAddress(String)`. Uses the standard
/// library resolver; like the Java original's `InetAddress.getByName`, silently falls back to the
/// original hostname if resolution fails (e.g. no network access, unknown host).
fn host_as_ip_address(host: &str) -> String {
    if host.trim().is_empty() {
        return host.to_string();
    }
    use std::net::ToSocketAddrs;
    (host, 0u16)
        .to_socket_addrs()
        .ok()
        .and_then(|mut addrs| addrs.next())
        .map(|addr| addr.ip().to_string())
        .unwrap_or_else(|| host.to_string())
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::rc::Rc;

    use super::*;

    #[derive(Clone)]
    struct MockProjectLocator {
        dir_path: String,
        name: String,
        exists: Rc<RefCell<bool>>,
    }

    impl ProjectLocator for MockProjectLocator {
        fn exists(&self) -> bool {
            *self.exists.borrow()
        }

        fn url(&self) -> String {
            format!("ghidra:{}{}", self.dir_path, self.name)
        }
    }

    struct MockGhidraUrlHandler {
        supported: bool,
    }

    impl GhidraUrlHandlerLike for MockGhidraUrlHandler {
        fn is_supported_url(&self, _url: &str) -> bool {
            self.supported
        }
    }

    struct MockGhidraURL {
        existing_projects: Rc<RefCell<HashMap<String, bool>>>,
        handler_supported: bool,
    }

    impl MockGhidraURL {
        fn new() -> Self {
            Self { existing_projects: Rc::new(RefCell::new(HashMap::new())), handler_supported: true }
        }

        fn mark_exists(&self, dir_path: &str, name: &str) {
            self.existing_projects.borrow_mut().insert(format!("{dir_path}{name}"), true);
        }
    }

    impl GhidraURL for MockGhidraURL {
        fn make_project_locator(&self, dir_path: &str, project_name: &str) -> Box<dyn ProjectLocator> {
            let key = format!("{dir_path}{project_name}");
            let exists = self.existing_projects.borrow().get(&key).copied().unwrap_or(false);
            Box::new(MockProjectLocator {
                dir_path: dir_path.to_string(),
                name: project_name.to_string(),
                exists: Rc::new(RefCell::new(exists)),
            })
        }

        fn handler(&self) -> Box<dyn GhidraUrlHandlerLike> {
            Box::new(MockGhidraUrlHandler { supported: self.handler_supported })
        }
    }

    #[test]
    fn is_ghidra_url_and_is_local_url_classify_url_forms() {
        let g = MockGhidraURL::new();
        let dyn_g: &dyn GhidraURL = &g;

        assert!(dyn_g.is_ghidra_url("ghidra:/a/b/proj"));
        assert!(!dyn_g.is_ghidra_url("http://a/b"));

        // Matches the class javadoc's documented examples.
        assert!(dyn_g.is_local_url("ghidra:/path"));
        assert!(dyn_g.is_local_url("ghidra:////path"));
        assert!(!dyn_g.is_local_url("ghidra://path"));

        assert!(dyn_g.is_server_url("ghidra://host/repo"));
        assert!(!dyn_g.is_server_url("ghidra:/a/b/proj"));
    }

    #[test]
    fn make_project_url_round_trips_through_get_project_storage_locator() {
        let g = MockGhidraURL::new();
        g.mark_exists("/home/user", "MyProject");

        let url = g.make_project_url("/home/user", "MyProject", None, None).unwrap();
        assert_eq!(url, "ghidra:/home/user/MyProject");

        let locator = g.get_project_storage_locator(&url).unwrap().unwrap();
        assert!(locator.exists());
        assert!(g.local_project_exists(&url));

        let other_url = g.make_project_url("/home/user", "OtherProject", None, None).unwrap();
        assert!(!g.local_project_exists(&other_url));
    }

    #[test]
    fn make_project_url_rejects_invalid_project_name() {
        let g = MockGhidraURL::new();
        let err = g.make_project_url("/home/user", ".hidden", None, None).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn to_url_rejects_project_path_with_extension() {
        let g = MockGhidraURL::new();
        let err = g.to_url("/home/user/MyProject.gpr").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn resolve_appends_file_path_and_ref_to_local_url() {
        let g = MockGhidraURL::new();
        let base = g.make_project_url("/home/user", "MyProject", None, None).unwrap();

        let resolved = g.resolve(&base, Some("/a/b"), Some("line1")).unwrap();
        assert_eq!(resolved, "ghidra:/home/user/MyProject?/a/b#line1");

        assert_eq!(g.get_project_pathname(&resolved).unwrap(), "/a/b");
        assert_eq!(g.get_decoded_reference(&resolved).as_deref(), Some("line1"));
    }

    #[test]
    fn make_repository_url_and_get_repository_name_round_trip() {
        let g = MockGhidraURL::new();
        let url = g.make_repository_url("localhost", 0, "MyRepo", Some("/a/b"), None).unwrap();
        assert_eq!(url, "ghidra://localhost/MyRepo/a/b");

        assert!(g.is_supported_server_url(&url));
        assert_eq!(g.get_repository_name(&url).as_deref(), Some("MyRepo"));
        assert!(g.is_server_repository_url(&url));
        assert_eq!(g.get_project_pathname(&url).unwrap(), "/a/b");
    }

    #[test]
    fn is_supported_server_url_respects_handler_seam() {
        let mut g = MockGhidraURL::new();
        g.handler_supported = false;
        let url = g.make_repository_url("localhost", 0, "MyRepo", None, None).unwrap();

        assert!(!g.is_supported_server_url(&url));
        assert_eq!(g.get_repository_name(&url), None);
    }

    #[test]
    fn get_display_string_converts_windows_drive_path_and_falls_back_otherwise() {
        let g = MockGhidraURL::new();

        let win_url = g.make_project_url("C:/proj", "MyProject", None, None).unwrap();
        assert_eq!(g.get_display_string(&win_url), "C:\\proj\\MyProject");

        let repo_url = g.make_repository_url("localhost", 0, "MyRepo", None, None).unwrap();
        assert_eq!(g.get_display_string(&repo_url), repo_url);
    }

    #[test]
    fn check_local_absolute_path_normalizes_and_validates() {
        let g = MockGhidraURL::new();
        assert_eq!(
            g.check_local_absolute_path("C:\\a\\b", true).unwrap(),
            "/C:/a/b/"
        );
        assert!(g.check_local_absolute_path("relative/path", false).is_err());
    }

    #[test]
    fn is_windows_only_path_detects_drive_and_unc_forms() {
        let g = MockGhidraURL::new();
        assert!(g.is_windows_only_path("C:\\a\\b"));
        assert!(g.is_windows_only_path("//server/share/a"));
        assert!(!g.is_windows_only_path("/home/user/proj"));
    }

}

//! Rust port of `ghidra.features.bsim.query.BSimClientFactory`.
//!
//! # Shape
//!
//! The Java class has no fields and only five static methods, so it ports to a plain module of
//! free functions rather than a field-less struct: Rust doesn't need a class to hang statics off
//! of (shape rule R7-statics-holder).
//!
//! # Unported dependencies / cycle break
//!
//! `build_client` and `build_client_from_server_info` construct one of three concrete
//! `FunctionDatabase` implementations chosen by URL protocol -- `PostgresFunctionDatabase`,
//! `ElasticDatabase`, `H2FileFunctionDatabase` -- none ported yet; this file sits on the
//! dependency cycle those three form with the query protocol. All three are genuine Java classes
//! (not interfaces), so each is stubbed in [`crate::feature::seam_stubs`] as a concrete struct
//! implementing [`FunctionDatabase`] -- the interface -- rather than as a trait object itself; see
//! `STUBS.tsv` for provenance.
//!
//! `derive_bsim_url` also needs
//! [`GhidraURL::is_server_repository_url`](crate::framework::protocol::ghidra::GhidraURL), an
//! already-ported cut-point trait with no concrete production implementation in the crate yet
//! (the Java method calls the equivalent static), so it takes a `&dyn GhidraURL` parameter rather
//! than assuming one.
//!
//! # URL representation
//!
//! `java.net.URL` parameters and returns are represented as `&str`/`String`, matching how this
//! crate already represents Ghidra URLs elsewhere (see
//! [`GhidraURL`](crate::framework::protocol::ghidra::GhidraURL)). [`ParsedUrl`] is a minimal,
//! purpose-built parser sufficient for the `protocol://host/path` and `protocol:/path` URL forms
//! this factory handles; it does not replicate `java.net.URL`'s full parsing behavior (e.g. opaque
//! URLs with no leading `/` after the scheme).

use std::io;

use crate::feature::bsim::query::b_sim_server_info::BSimServerInfo;
use crate::feature::bsim::query::function_database::FunctionDatabase;
use crate::feature::seam_stubs::{
    ElasticDatabase, H2FileFunctionDatabase, PostgresFunctionDatabase,
};
use crate::framework::protocol::ghidra::{GhidraURL, PROTOCOL};

fn malformed_url(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg.into())
}

/// A minimally-parsed BSim/Ghidra URL: `scheme://[authority]/path` or `scheme:path`. Stands in
/// for `java.net.URL`, which this crate does not otherwise depend on; only the pieces
/// `BSimClientFactory` reads (`getProtocol`, `getPath`, `getHost`, `getAuthority`) are extracted.
struct ParsedUrl {
    protocol: String,
    authority: Option<String>,
    path: String,
}

impl ParsedUrl {
    fn parse(url_string: &str) -> io::Result<Self> {
        let (protocol, rest) = url_string
            .split_once(':')
            .filter(|(scheme, _)| !scheme.is_empty())
            .ok_or_else(|| malformed_url(format!("Malformed URL: {url_string}")))?;
        let (authority, path) = match rest.strip_prefix("//") {
            Some(after) => match after.find('/') {
                Some(i) => (Some(after[..i].to_string()), after[i..].to_string()),
                None => (Some(after.to_string()), String::new()),
            },
            None => (None, rest.to_string()),
        };
        Ok(Self { protocol: protocol.to_string(), authority, path })
    }

    fn host(&self) -> Option<&str> {
        self.authority.as_deref().map(|a| a.split(':').next().unwrap_or(a))
    }
}

/// Build a root URL for connecting to a BSim database.
///  1. A valid protocol must be provided.
///  2. There must be a path of exactly 1 element, which names the specific repository.
///
/// Acceptable protocols are `postgresql://`, `https://` (or possibly `http://`), `file:/`.
///
/// Mirrors `buildURL(String)`.
///
/// # Errors
/// Returns an [`io::Error`] with kind [`io::ErrorKind::InvalidInput`] if the URL string cannot be
/// parsed, mirroring `MalformedURLException`.
pub fn build_url(url_string: &str) -> io::Result<String> {
    let parsed = ParsedUrl::parse(url_string)?;
    check_parsed_bsim_server_url(&parsed)?;
    Ok(url_string.to_string())
}

/// Validate a BSim DB URL. Acceptable protocols are `postgresql://`, `https://` (or possibly
/// `http://`), `elastic://`, `file:/`.
///
/// Mirrors `checkBSimServerURL(URL)`.
///
/// # Errors
/// Returns an [`io::Error`] with kind [`io::ErrorKind::InvalidInput`] if the URL string is not a
/// supported BSim DB URL, mirroring `MalformedURLException`.
pub fn check_bsim_server_url(url_string: &str) -> io::Result<()> {
    check_parsed_bsim_server_url(&ParsedUrl::parse(url_string)?)
}

fn check_parsed_bsim_server_url(url: &ParsedUrl) -> io::Result<()> {
    if !matches!(url.protocol.as_str(), "postgresql" | "https" | "elastic" | "file") {
        return Err(malformed_url("Protocol not permissable for BSim URL"));
    }
    if url.path.is_empty() || url.path == "/" {
        return Err(malformed_url("BSim URL missing DB name/path"));
    }
    if url.protocol != "file" && url.path[1..].contains('/') {
        return Err(malformed_url("BSim URL must specify exactly 1 path element"));
    }
    Ok(())
}

/// Construct the root URL to a specific BSim repository given a "related" URL.
///
/// The root URL will have an explicit protocol, a hostname + other mods (the authority), and 1
/// level of path -- that first level path indicates the particular repository being referenced on
/// the host. The "related" URL `url_string` can be an explicitly provided URL pointing to the
/// BSim repository, possibly with additional path levels, which are simply stripped from the
/// final root URL. Alternately `url_string` can reference a ghidra server, as indicated by the
/// "ghidra" protocol -- in this case the true BSim URL is derived from the ghidra URL in some way.
///
/// `ghidra_url` supplies the
/// [`GhidraURL::is_server_repository_url`](crate::framework::protocol::ghidra::GhidraURL) check
/// the Java method calls statically.
///
/// Mirrors `deriveBSimURL(String)`.
///
/// # Errors
/// Returns an [`io::Error`] with kind [`io::ErrorKind::InvalidInput`] if the given URL string
/// cannot be parsed, or a local ghidra URL is specified, mirroring `MalformedURLException` and
/// `IllegalArgumentException` respectively.
pub fn derive_bsim_url(ghidra_url: &dyn GhidraURL, url_string: &str) -> io::Result<String> {
    let parsed = ParsedUrl::parse(url_string)?;
    if matches!(parsed.protocol.as_str(), "postgresql" | "https" | "elastic" | "file") {
        check_parsed_bsim_server_url(&parsed)?;
        return Ok(url_string.to_string()); // URL already corresponds to BSim server protocol
    }
    if !ghidra_url.is_server_repository_url(url_string) {
        return Err(malformed_url(format!("Unable to infer BSim URL from: {url_string}")));
    }
    if parsed.path.is_empty() || parsed.path == "/" {
        return Err(malformed_url("URL is missing a repository path"));
    }
    let endrepos = parsed.path[1..].find('/').map(|i| i + 1);
    // Currently, all we do is assume that the BSim server is a PostgreSQL server on the same
    // host and with the same repo name as the ghidra server.
    let mut repository_url = if parsed.protocol == PROTOCOL {
        format!("postgresql://{}", parsed.host().unwrap_or_default())
    } else {
        format!("{}://{}", parsed.protocol, parsed.authority.as_deref().unwrap_or_default())
    };
    match endrepos {
        Some(i) => repository_url.push_str(&parsed.path[..i]),
        None => repository_url.push_str(&parsed.path),
    }
    build_url(&repository_url)
}

/// Given the server details for a BSim server, construct the appropriate BSim client object
/// (implementing [`FunctionDatabase`]). The returned instance must be
/// [`FunctionDatabase::close`]d when done using it to prevent depletion of database connections.
///
/// Mirrors `buildClient(BSimServerInfo, boolean)`, which wraps the checked
/// `MalformedURLException` a well-formed `BSimServerInfo` should never actually throw in an
/// unchecked `RuntimeException`; the `.expect` below mirrors that "unexpected" assertion.
///
/// # Panics
/// Panics if `bsim_server_info` produces a malformed BSim URL.
pub fn build_client_from_server_info(
    bsim_server_info: &BSimServerInfo,
    is_async: bool,
) -> Box<dyn FunctionDatabase> {
    build_client(&bsim_server_info.to_url_string(), is_async)
        .expect("BSimServerInfo produced a malformed BSim URL") // unexpected
}

/// Given the URL for a BSim server, construct the appropriate BSim client object (implementing
/// [`FunctionDatabase`]). The returned instance must be [`FunctionDatabase::close`]d when done
/// using it to prevent depletion of database connections.
///
/// Mirrors `buildClient(URL, boolean)`.
///
/// # Errors
/// Returns an [`io::Error`] with kind [`io::ErrorKind::InvalidInput`] if there's a problem
/// creating the database client, mirroring `MalformedURLException`.
pub fn build_client(bsim_url: &str, is_async: bool) -> io::Result<Box<dyn FunctionDatabase>> {
    let protocol = ParsedUrl::parse(bsim_url)?.protocol;
    match protocol.as_str() {
        "postgresql" => Ok(Box::new(PostgresFunctionDatabase::new(bsim_url, is_async))),
        "https" | "elastic" => Ok(Box::new(ElasticDatabase::new(bsim_url))),
        "file" => Ok(Box::new(H2FileFunctionDatabase::new(bsim_url))),
        other => Err(malformed_url(format!("Unsupported protocol: {other}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::ProjectLocator;
    use crate::framework::seam_stubs::GhidraUrlHandlerLike;

    struct MockGhidraUrlHandler;

    impl GhidraUrlHandlerLike for MockGhidraUrlHandler {
        fn is_supported_url(&self, _url: &str) -> bool {
            true
        }
    }

    struct MockGhidraURL;

    impl GhidraURL for MockGhidraURL {
        fn make_project_locator(&self, _dir_path: &str, _project_name: &str) -> Box<dyn ProjectLocator> {
            panic!("not used by BSimClientFactory tests")
        }

        fn handler(&self) -> Box<dyn GhidraUrlHandlerLike> {
            Box::new(MockGhidraUrlHandler)
        }
    }

    #[test]
    fn build_url_accepts_supported_protocols() {
        assert_eq!(build_url("postgresql://myhost/myrepo").unwrap(), "postgresql://myhost/myrepo");
        assert_eq!(build_url("https://myhost/myrepo").unwrap(), "https://myhost/myrepo");
        assert_eq!(build_url("elastic://myhost/myrepo").unwrap(), "elastic://myhost/myrepo");
        assert_eq!(build_url("file:/some/path/db.mv.db").unwrap(), "file:/some/path/db.mv.db");
    }

    #[test]
    fn build_url_rejects_unsupported_protocol() {
        let err = build_url("ftp://myhost/myrepo").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn check_bsim_server_url_rejects_missing_path() {
        let err = check_bsim_server_url("postgresql://myhost").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("missing DB name/path"));
    }

    #[test]
    fn check_bsim_server_url_rejects_multi_element_path_for_non_file_protocol() {
        let err = check_bsim_server_url("postgresql://myhost/repo/extra").unwrap_err();
        assert!(err.to_string().contains("exactly 1 path element"));
    }

    #[test]
    fn check_bsim_server_url_allows_multi_element_path_for_file_protocol() {
        check_bsim_server_url("file:/some/nested/path/db.mv.db").unwrap();
    }

    #[test]
    fn derive_bsim_url_passes_through_already_bsim_urls() {
        let ghidra_url = MockGhidraURL;
        // A direct BSim-protocol URL is validated as-is -- extra path levels are not stripped the
        // way they are for a ghidra-derived URL below.
        assert!(derive_bsim_url(&ghidra_url, "postgresql://myhost/myrepo/extra/levels").is_err());
        assert_eq!(
            derive_bsim_url(&ghidra_url, "postgresql://myhost/myrepo").unwrap(),
            "postgresql://myhost/myrepo"
        );
    }

    #[test]
    fn derive_bsim_url_infers_postgres_server_from_ghidra_url() {
        let ghidra_url = MockGhidraURL;
        assert_eq!(
            derive_bsim_url(&ghidra_url, "ghidra://myhost/myrepo").unwrap(),
            "postgresql://myhost/myrepo"
        );
        // Extra path levels below the repository are stripped.
        assert_eq!(
            derive_bsim_url(&ghidra_url, "ghidra://myhost/myrepo/some/folder").unwrap(),
            "postgresql://myhost/myrepo"
        );
    }

    #[test]
    fn derive_bsim_url_rejects_url_the_injected_ghidra_url_cannot_classify() {
        let ghidra_url = MockGhidraURL;
        // Not a BSim protocol and not a "ghidra:" URL, so `GhidraURL::is_server_repository_url`
        // rejects it and no BSim URL can be inferred.
        assert!(derive_bsim_url(&ghidra_url, "ghidraext://myhost/myrepo").is_err());
    }

    #[test]
    fn build_client_dispatches_on_protocol() {
        let postgres = build_client("postgresql://myhost/myrepo", true).unwrap();
        assert_eq!(postgres.get_url_string(), "postgresql://myhost/myrepo");

        let elastic = build_client("https://myhost/myrepo", false).unwrap();
        assert_eq!(elastic.get_url_string(), "https://myhost/myrepo");

        let elastic2 = build_client("elastic://myhost/myrepo", false).unwrap();
        assert_eq!(elastic2.get_url_string(), "elastic://myhost/myrepo");

        let h2 = build_client("file:/some/path/db.mv.db", false).unwrap();
        assert_eq!(h2.get_url_string(), "file:/some/path/db.mv.db");
    }

    #[test]
    fn build_client_rejects_unsupported_protocol() {
        let err = match build_client("ftp://myhost/myrepo", false) {
            Err(e) => e,
            Ok(_) => panic!("expected an unsupported-protocol error"),
        };
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }
}

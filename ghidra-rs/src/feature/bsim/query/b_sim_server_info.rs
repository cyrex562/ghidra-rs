//! Rust port of `ghidra.features.bsim.query.BSimServerInfo`.
//!
//! # Shape
//!
//! The Java class is a concrete, immutable value object that nothing extends, so it ports to a
//! plain `struct` taken/returned by value or by reference -- never as a trait object.
//!
//! # URL representation
//!
//! `java.net.URL` parameters and returns are represented as `&str`/`String`, matching how the rest
//! of the BSim port already represents URLs (see
//! [`b_sim_client_factory`](crate::feature::bsim::query::b_sim_client_factory)). [`from_url`] uses
//! a purpose-built parser sufficient for the `scheme://[userinfo@]host[:port]/path` and
//! `scheme:path` forms this class accepts; Java's `toURL()` (which simply wraps `toURLString()` in
//! a `java.net.URL`) has no separate Rust counterpart -- use
//! [`to_url_string`](BSimServerInfo::to_url_string).
//!
//! `java.net.URLEncoder`/`URLDecoder` are reimplemented here ([`url_encode`]/[`url_decode`]) in
//! their `application/x-www-form-urlencoded` form, which is what the Java class uses. That form
//! percent-encodes `/`, which is why a `file:` DB URL looks like `file:%2Fpath%2Fto%2Fdb.mv.db`.
//!
//! # Java statics
//!
//! `ClientUtil.getUserName()` (used as the default DB user name) simply forwards to
//! `SystemUtilities.getUserName()`, which is already ported as
//! [`SystemUtilities::get_user_name`](crate::util::system_utilities::SystemUtilities::get_user_name),
//! so that is called directly rather than stubbing `ClientUtil`.
//!
//! Java's `setUserInfo(BasicDataSource)` is not ported: `BasicDataSource` is an Apache DBCP type
//! with no Rust counterpart in this crate. The two pieces of state it copies are available
//! directly as [`get_user_name`](BSimServerInfo::get_user_name) and
//! [`get_password`](BSimServerInfo::get_password), so a pooled-datasource port can apply them
//! itself.

use std::fmt;
use std::io;

use crate::feature::bsim::query::function_database::FunctionDatabase;
use crate::util::system_utilities::SystemUtilities;

/// Default port used for a [`DBType::Postgres`] server.
pub const DEFAULT_POSTGRES_PORT: i32 = 5432;

/// Default port used for a [`DBType::Elastic`] server.
pub const DEFAULT_ELASTIC_PORT: i32 = 9200;

/// File extension imposed for a [`DBType::File`] server. This is a rigid H2 database convention.
pub const H2_FILE_EXTENSION: &str = ".mv.db";

/// Characters which may not appear in an H2 database file path.
const BAD_H2_CHARS: &str = "';\"";

/// Enumerated database types.
///
/// Port of `BSimServerInfo.DBType`. [`as_str`](DBType::as_str) yields the Java enum constant name,
/// which is what `BSimServerInfo.toString()` embeds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DBType {
    Postgres,
    Elastic,
    File,
}

impl DBType {
    pub fn as_str(&self) -> &'static str {
        match self {
            DBType::Postgres => "postgres",
            DBType::Elastic => "elastic",
            DBType::File => "file",
        }
    }

    /// Declaration order of the Java enum constants, which `hashCode()` depends on (enum
    /// hash codes vary from run to run, so Java hashes the ordinal instead).
    fn ordinal(&self) -> i32 {
        match self {
            DBType::Postgres => 0,
            DBType::Elastic => 1,
            DBType::File => 2,
        }
    }
}

impl fmt::Display for DBType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg.into())
}

/// Connection details for a BSim database server.
///
/// Port of `ghidra.features.bsim.query.BSimServerInfo`. All instances are validated at
/// construction, so every accessor is infallible.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BSimServerInfo {
    db_type: DBType,
    /// `username[:password]`; `None` for [`DBType::File`] and for a default login.
    userinfo: Option<String>,
    /// `None` for [`DBType::File`].
    host: Option<String>,
    port: i32,
    db_name: String,
}

impl BSimServerInfo {
    /// Construct a new `BSimServerInfo`.
    ///
    /// Mirrors `BSimServerInfo(DBType, String, String, int, String)`.
    ///
    /// * `userinfo` - connection user info, `username[:password]` (ignored for [`DBType::File`]).
    ///   If blank, the default user name is used (see
    ///   [`get_user_name`](BSimServerInfo::get_user_name)).
    /// * `host` - host name (ignored for [`DBType::File`]).
    /// * `port` - port number (ignored for [`DBType::File`], `-1` for default).
    /// * `db_name` - simple database name, except for [`DBType::File`] which should reflect an
    ///   absolute file path. On Windows OS the path may start with a drive letter.
    ///
    /// # Errors
    /// Returns an [`io::Error`] of kind [`io::ErrorKind::InvalidInput`] if invalid arguments are
    /// specified, mirroring Java's `IllegalArgumentException`.
    pub fn new(
        db_type: DBType,
        userinfo: Option<&str>,
        host: Option<&str>,
        port: i32,
        db_name: &str,
    ) -> io::Result<Self> {
        if matches!(db_type, DBType::Postgres | DBType::Elastic)
            && host.is_none_or(|h| h.is_empty())
        {
            return Err(invalid("host required"));
        }

        let db_name = db_name.trim();
        if db_name.is_empty() {
            return Err(invalid("Non-empty dbName required"));
        }

        if db_type == DBType::File {
            return Ok(Self {
                db_type,
                userinfo: None,
                host: None,
                port: -1,
                db_name: cleanup_filename(db_name)?,
            });
        }

        if db_name.contains('/') || db_name.contains('\\') {
            // may want additional validation
            return Err(invalid(format!("Invalid {db_type} dbName: {db_name}")));
        }
        let userinfo = cleanup_user_info(userinfo)?;
        let port = match db_type {
            DBType::Postgres if port <= 0 => DEFAULT_POSTGRES_PORT,
            DBType::Elastic if port <= 0 => DEFAULT_ELASTIC_PORT,
            _ if port <= 0 => -1,
            _ => port,
        };

        Ok(Self {
            db_type,
            userinfo,
            host: host.map(str::to_string),
            port,
            db_name: db_name.to_string(),
        })
    }

    /// Construct a new `BSimServerInfo` using the user's default user name.
    ///
    /// Mirrors `BSimServerInfo(DBType, String, int, String)`.
    ///
    /// # Errors
    /// Returns an [`io::Error`] of kind [`io::ErrorKind::InvalidInput`] if invalid arguments are
    /// specified.
    pub fn with_default_login(
        db_type: DBType,
        host: Option<&str>,
        port: i32,
        db_name: &str,
    ) -> io::Result<Self> {
        Self::new(db_type, None, host, port, db_name)
    }

    /// Construct a new `BSimServerInfo` for a [`DBType::File`] type database, whose `db_name`
    /// should reflect an absolute file path (on Windows OS the path may start with a drive
    /// letter).
    ///
    /// Mirrors `BSimServerInfo(String)`.
    ///
    /// # Errors
    /// Returns an [`io::Error`] of kind [`io::ErrorKind::InvalidInput`] if invalid arguments are
    /// specified.
    pub fn for_file(db_name: &str) -> io::Result<Self> {
        let db_name = db_name.trim();
        if db_name.is_empty() {
            return Err(invalid("Non-empty dbName required"));
        }
        Ok(Self {
            db_type: DBType::File,
            userinfo: None,
            host: None,
            port: -1,
            db_name: cleanup_filename(db_name)?,
        })
    }

    /// Construct a new `BSimServerInfo` from a suitable database URL (i.e., `postgresql:`,
    /// `https:`, `elastic:`, `file:`). For non-file URLs, the hostname or address may be preceded
    /// by a DB user info (e.g., `postgresql://user@host:port/dbname`).
    ///
    /// Mirrors `BSimServerInfo(URL)`.
    ///
    /// # Errors
    /// Returns an [`io::Error`] of kind [`io::ErrorKind::InvalidInput`] if an unsupported or
    /// malformed URL is specified.
    pub fn from_url(url: &str) -> io::Result<Self> {
        let parsed = ParsedUrl::parse(url)?;
        let protocol = parsed.protocol.as_str();

        let (db_type, host, userinfo, port) = match protocol {
            "postgresql" => (
                DBType::Postgres,
                Some(check_url_field(parsed.host(), "host")?),
                url_user_info(parsed.userinfo())?,
                parsed.port.filter(|p| *p > 0).unwrap_or(DEFAULT_POSTGRES_PORT),
            ),
            "https" | "elastic" => (
                DBType::Elastic,
                Some(check_url_field(parsed.host(), "host")?),
                url_user_info(parsed.userinfo())?,
                parsed.port.filter(|p| *p > 0).unwrap_or(DEFAULT_ELASTIC_PORT),
            ),
            _ if protocol.starts_with("file") => {
                if !parsed.host().is_empty() {
                    return Err(invalid(format!("Remote file URL not supported: {url}")));
                }
                (DBType::File, None, None, -1)
            }
            _ => return Err(invalid(format!("Unsupported BSim URL protocol: {protocol}"))),
        };

        let mut path = parsed.path.as_str();
        if db_type != DBType::File {
            path = path
                .strip_prefix('/')
                .ok_or_else(|| invalid(format!("Missing dbName in URL: {url}")))?
                .trim();
        }
        let path = url_decode(&check_url_field(path, "path")?)?;
        let db_name = if db_type == DBType::File {
            cleanup_filename(&path)?
        } else if path.contains('/') {
            return Err(invalid(format!("Invalid dbName in URL: {path}")));
        } else {
            path
        };

        Ok(Self { db_type, userinfo, host, port, db_name })
    }

    /// Determine if this server info corresponds to a Windows OS file path.
    pub fn is_windows_file_path(&self) -> bool {
        self.db_type == DBType::File && is_windows_file_path(&self.db_name)
    }

    /// Return BSim server info in URL format.
    ///
    /// Warning: if user info with a password has been specified it will be returned in the URL.
    pub fn to_url_string(&self) -> String {
        match self.db_type {
            DBType::Postgres => format!(
                "postgresql://{}{}{}/{}",
                self.format_url_user_info(),
                self.host.as_deref().unwrap_or_default(),
                self.port_string(),
                url_encode(&self.db_name)
            ),
            DBType::Elastic => format!(
                "https://{}{}{}/{}",
                self.format_url_user_info(),
                self.host.as_deref().unwrap_or_default(),
                self.port_string(),
                url_encode(&self.db_name)
            ),
            DBType::File => format!("file:{}", url_encode(&self.db_name)), // h2:
        }
    }

    fn format_url_user_info(&self) -> String {
        let Some(userinfo) = self.userinfo.as_deref() else {
            return String::new();
        };
        let encoded = match userinfo.split_once(':') {
            Some((user, password)) => format!("{}:{}", url_encode(user), url_encode(password)),
            None => url_encode(userinfo),
        };
        format!("{encoded}@")
    }

    fn port_string(&self) -> String {
        if self.port > 0 { format!(":{}", self.port) } else { String::new() }
    }

    /// BSim database type.
    pub fn get_db_type(&self) -> DBType {
        self.db_type
    }

    /// Determine if user information includes a password.
    ///
    /// NOTE: use of passwords with this object and URLs is discouraged.
    pub fn has_password(&self) -> bool {
        self.userinfo.as_deref().is_some_and(|u| u.contains(':'))
    }

    /// The password portion of the user info, if any.
    ///
    /// Stands in for the password half of Java's `setUserInfo(BasicDataSource)`.
    pub fn get_password(&self) -> Option<&str> {
        self.userinfo.as_deref().and_then(|u| u.split_once(':')).map(|(_, password)| password)
    }

    /// Determine if user info was stipulated during construction.
    pub fn has_default_login(&self) -> bool {
        self.userinfo.is_none()
    }

    /// Get the remote database user name to be used when establishing a connection, obtained from
    /// the user information provided during instantiation ([`None`] for [`DBType::File`]).
    pub fn get_user_name(&self) -> Option<String> {
        if self.db_type == DBType::File {
            return None;
        }
        let Some(userinfo) = self.userinfo.as_deref() else {
            return Some(SystemUtilities::get_user_name());
        };
        Some(match userinfo.split_once(':') {
            Some((user, _)) if !user.is_empty() => user.to_string(),
            _ => userinfo.to_string(),
        })
    }

    /// Get the remote database user information to be used when establishing a connection
    /// ([`None`] for [`DBType::File`]).
    pub fn get_user_info(&self) -> Option<&str> {
        self.userinfo.as_deref()
    }

    /// Get the server hostname or IP address as originally specified ([`None`] for
    /// [`DBType::File`]).
    pub fn get_server_name(&self) -> Option<&str> {
        self.host.as_deref()
    }

    /// Get the port number.
    pub fn get_port(&self) -> i32 {
        self.port
    }

    /// Get the DB name.
    pub fn get_db_name(&self) -> &str {
        &self.db_name
    }

    /// Get the DB name; for [`DBType::File`] the directory path is excluded from the returned
    /// name.
    ///
    /// Java memoizes this in a `shortDbName` field; here the short name is always a slice of
    /// `db_name`, so no cache is needed.
    pub fn get_short_db_name(&self) -> &str {
        match self.db_type {
            DBType::File => self.db_name.rsplit_once('/').map_or(&*self.db_name, |(_, name)| name),
            _ => &self.db_name,
        }
    }

    /// The `java.lang.Object.hashCode()` value Java computes for this instance.
    ///
    /// `BSimServerManager` persists server entries by this hash, so it must keep producing the
    /// exact Java values -- including the quirk that user info is folded in only when present.
    /// Rust-side hashing (the derived [`Hash`] impl) is independent of this.
    pub fn hash_code(&self) -> i32 {
        // use dbType ordinal; enum hashcodes vary from run to run
        let mut hashcode = java_objects_hash(&[
            java_string_hash(&self.db_name),
            self.db_type.ordinal(),
            self.host.as_deref().map_or(0, java_string_hash),
            self.port,
        ]);
        // Due to the use of hashcode by BSimServerManager for persisting server entries we cannot
        // change the hashing function above and must only incorporate inclusion of userinfo if it
        // is specified.
        if let Some(userinfo) = self.userinfo.as_deref() {
            hashcode = hashcode.wrapping_mul(31).wrapping_add(java_string_hash(userinfo));
        }
        hashcode
    }

    /// Get a BSim [`FunctionDatabase`] instance which corresponds to this DB server info.
    ///
    /// The instance should be [closed](FunctionDatabase::close) when no longer in use to ensure
    /// that any associated database connection and resources are properly released.
    ///
    /// * `is_async` - true if database commits should be asynchronous (may not be applicable).
    pub fn get_function_database(&self, is_async: bool) -> Box<dyn FunctionDatabase> {
        crate::feature::bsim::query::b_sim_client_factory::build_client_from_server_info(
            self, is_async,
        )
    }
}

impl fmt::Display for BSimServerInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.db_type {
            DBType::File => write!(f, "{}  ({});", self.get_short_db_name(), self.db_name),
            _ => write!(
                f,
                "{}  ({}: {})",
                self.db_name,
                self.db_type,
                self.host.as_deref().unwrap_or("null")
            ),
        }
    }
}

impl Ord for BSimServerInfo {
    /// Java's `compareTo` orders purely by `toString()`, so two infos that differ only in user
    /// info compare equal here while [`PartialEq`] reports them unequal. That inconsistency is
    /// Java's, and is preserved so sorted BSim server lists keep their existing order.
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.to_string().cmp(&other.to_string())
    }
}

impl PartialOrd for BSimServerInfo {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Mirrors `cleanupUserInfo`: blank user info becomes "no user info", and a leading `:` (empty
/// user name) is rejected.
fn cleanup_user_info(userinfo: Option<&str>) -> io::Result<Option<String>> {
    let Some(userinfo) = userinfo.map(str::trim).filter(|u| !u.is_empty()) else {
        return Ok(None);
    };
    if userinfo.starts_with(':') {
        return Err(invalid("Invalid userinfo specified"));
    }
    Ok(Some(userinfo.to_string()))
}

/// Mirrors `cleanupFilename`: transform `name` into an acceptable H2 DB file path.
fn cleanup_filename(name: &str) -> io::Result<String> {
    if name.contains(|c| BAD_H2_CHARS.contains(c)) {
        return Err(invalid(format!(
            "Bad character in H2 database path. Disallowed characters: {BAD_H2_CHARS}"
        )));
    }
    let mut db_name = name.trim().replace('\\', "/");
    if (!db_name.starts_with('/') && !is_windows_file_path(&db_name)) || db_name.ends_with('/') {
        return Err(invalid(format!("Invalid absolute file path: {db_name}")));
    }
    if !db_name.ends_with(H2_FILE_EXTENSION) {
        db_name.push_str(H2_FILE_EXTENSION);
    }
    Ok(db_name)
}

fn check_url_field(val: &str, name: &str) -> io::Result<String> {
    if val.is_empty() {
        return Err(invalid(format!("Invalid {name} in URL")));
    }
    Ok(val.trim().to_string())
}

/// Check for a Windows path after all `\` chars have been converted to `/` chars, e.g. `C:/a/b/c`.
fn is_windows_file_path(path: &str) -> bool {
    let mut chars = path.chars();
    match (chars.next(), chars.next(), chars.next(), chars.next()) {
        (Some(drive), Some(':'), Some('/'), Some(c)) => drive.is_alphabetic() && c != '/',
        _ => false,
    }
}

/// Mirrors `getURLUserInfo`: decode the user name and password halves separately so that an
/// encoded `:` inside either half is not mistaken for the separator.
fn url_user_info(userinfo: Option<&str>) -> io::Result<Option<String>> {
    let Some(userinfo) = userinfo else {
        return Ok(None);
    };
    let decoded = match userinfo.split_once(':') {
        Some((user, password)) => format!("{}:{}", url_decode(user)?, url_decode(password)?),
        None => url_decode(userinfo)?,
    };
    cleanup_user_info(Some(&decoded))
}

/// `java.net.URLEncoder.encode(text, UTF_8)`: `application/x-www-form-urlencoded` form, which
/// keeps only `[A-Za-z0-9.\-*_]` and turns a space into `+`.
fn url_encode(text: &str) -> String {
    let mut encoded = String::with_capacity(text.len());
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'-' | b'*' | b'_' => {
                encoded.push(byte as char)
            }
            b' ' => encoded.push('+'),
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}

/// `java.net.URLDecoder.decode(text, UTF_8)`.
///
/// # Errors
/// Returns an [`io::Error`] of kind [`io::ErrorKind::InvalidInput`] for a truncated or non-hex
/// `%` escape, or for an escape sequence that is not valid UTF-8, mirroring Java's
/// `IllegalArgumentException`.
fn url_decode(text: &str) -> io::Result<String> {
    let bytes = text.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                decoded.push(b' ');
                i += 1;
            }
            b'%' => {
                let hex = bytes
                    .get(i + 1..i + 3)
                    .and_then(|h| std::str::from_utf8(h).ok())
                    .and_then(|h| u8::from_str_radix(h, 16).ok())
                    .ok_or_else(|| {
                        invalid(format!(
                            "URLDecoder: Incomplete trailing escape (%) pattern in: {text}"
                        ))
                    })?;
                decoded.push(hex);
                i += 3;
            }
            b => {
                decoded.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(decoded).map_err(|e| invalid(format!("URLDecoder: {e}")))
}

/// `java.lang.String.hashCode()`.
fn java_string_hash(text: &str) -> i32 {
    // Java hashes UTF-16 code units, not chars.
    text.encode_utf16().fold(0i32, |hash, unit| hash.wrapping_mul(31).wrapping_add(unit as i32))
}

/// `java.util.Objects.hash(...)` over element hash codes (`0` stands in for a `null` element).
fn java_objects_hash(element_hashes: &[i32]) -> i32 {
    element_hashes.iter().fold(1i32, |hash, h| hash.wrapping_mul(31).wrapping_add(*h))
}

/// A minimally-parsed database URL: `scheme://[userinfo@]host[:port][/path]` or `scheme:path`.
/// Stands in for `java.net.URL`, of which only the pieces `BSimServerInfo` reads are extracted.
struct ParsedUrl {
    protocol: String,
    authority: Option<String>,
    port: Option<i32>,
    path: String,
}

impl ParsedUrl {
    fn parse(url_string: &str) -> io::Result<Self> {
        let (protocol, rest) = url_string
            .split_once(':')
            .filter(|(scheme, _)| !scheme.is_empty())
            .ok_or_else(|| invalid(format!("Malformed URL: {url_string}")))?;
        let (authority, path) = match rest.strip_prefix("//") {
            Some(after) => match after.find('/') {
                Some(i) => (Some(after[..i].to_string()), after[i..].to_string()),
                None => (Some(after.to_string()), String::new()),
            },
            None => (None, rest.to_string()),
        };
        // The port follows the last ':' of the host portion of the authority, if any.
        let host_part = authority.as_deref().map(host_portion).unwrap_or_default();
        let port = match host_part.rsplit_once(':') {
            Some((_, port)) => Some(port.parse::<i32>().map_err(|_| {
                invalid(format!("Invalid port number in URL: {url_string}"))
            })?),
            None => None,
        };
        Ok(Self { protocol: protocol.to_string(), authority, port, path })
    }

    fn userinfo(&self) -> Option<&str> {
        self.authority.as_deref().and_then(|a| a.rsplit_once('@')).map(|(userinfo, _)| userinfo)
    }

    fn host(&self) -> &str {
        let host_part = self.authority.as_deref().map(host_portion).unwrap_or_default();
        host_part.rsplit_once(':').map_or(host_part, |(host, _)| host)
    }
}

fn host_portion(authority: &str) -> &str {
    authority.rsplit_once('@').map_or(authority, |(_, host)| host)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn postgres_defaults_port_and_user_name() {
        let info = BSimServerInfo::with_default_login(DBType::Postgres, Some("myhost"), -1, "mydb")
            .unwrap();
        assert_eq!(info.get_db_type(), DBType::Postgres);
        assert_eq!(info.get_port(), DEFAULT_POSTGRES_PORT);
        assert_eq!(info.get_server_name(), Some("myhost"));
        assert_eq!(info.get_db_name(), "mydb");
        assert!(info.has_default_login());
        assert!(!info.has_password());
        // No user info given, so the default (OS) user name is used.
        assert_eq!(info.get_user_name(), Some(SystemUtilities::get_user_name()));
        assert_eq!(info.to_url_string(), "postgresql://myhost:5432/mydb");
        assert_eq!(info.to_string(), "mydb  (postgres: myhost)");
    }

    #[test]
    fn elastic_defaults_port_and_uses_https_url() {
        let info =
            BSimServerInfo::new(DBType::Elastic, Some("bob:secret"), Some("myhost"), 0, "mydb")
                .unwrap();
        assert_eq!(info.get_port(), DEFAULT_ELASTIC_PORT);
        assert!(info.has_password());
        assert_eq!(info.get_password(), Some("secret"));
        assert_eq!(info.get_user_name().as_deref(), Some("bob"));
        assert_eq!(info.get_user_info(), Some("bob:secret"));
        assert_eq!(info.to_url_string(), "https://bob:secret@myhost:9200/mydb");
    }

    #[test]
    fn explicit_port_is_kept() {
        let info =
            BSimServerInfo::with_default_login(DBType::Postgres, Some("myhost"), 5555, "mydb")
                .unwrap();
        assert_eq!(info.get_port(), 5555);
        assert!(info.to_url_string().starts_with("postgresql://myhost:5555/"));
    }

    #[test]
    fn non_file_db_name_may_not_contain_separators() {
        assert!(
            BSimServerInfo::with_default_login(DBType::Postgres, Some("myhost"), -1, "a/b").is_err()
        );
        assert!(
            BSimServerInfo::with_default_login(DBType::Elastic, Some("myhost"), -1, r"a\b").is_err()
        );
    }

    #[test]
    fn host_is_required_for_server_types_but_not_for_file() {
        assert!(BSimServerInfo::with_default_login(DBType::Postgres, None, -1, "mydb").is_err());
        assert!(BSimServerInfo::with_default_login(DBType::Elastic, Some(""), -1, "mydb").is_err());
        // A file DB ignores host/port/userinfo entirely.
        let info = BSimServerInfo::new(
            DBType::File,
            Some("bob:secret"),
            Some("myhost"),
            5555,
            "/a/b/db.mv.db",
        )
        .unwrap();
        assert_eq!(info.get_server_name(), None);
        assert_eq!(info.get_port(), -1);
        assert_eq!(info.get_user_info(), None);
        assert_eq!(info.get_user_name(), None);
    }

    #[test]
    fn empty_db_name_is_rejected() {
        assert!(
            BSimServerInfo::with_default_login(DBType::Postgres, Some("h"), -1, "   ").is_err()
        );
        assert!(BSimServerInfo::for_file("  ").is_err());
    }

    #[test]
    fn leading_colon_user_info_is_rejected_and_blank_becomes_default_login() {
        assert!(
            BSimServerInfo::new(DBType::Postgres, Some(":secret"), Some("h"), -1, "mydb").is_err()
        );
        let info =
            BSimServerInfo::new(DBType::Postgres, Some("   "), Some("h"), -1, "mydb").unwrap();
        assert!(info.has_default_login());
    }

    #[test]
    fn file_db_name_gets_extension_and_forward_slashes() {
        let info = BSimServerInfo::for_file("/a/b/mydb").unwrap();
        assert_eq!(info.get_db_name(), "/a/b/mydb.mv.db");
        assert_eq!(info.get_short_db_name(), "mydb.mv.db");
        assert!(!info.is_windows_file_path());
        assert_eq!(info.to_string(), "mydb.mv.db  (/a/b/mydb.mv.db);");

        let windows = BSimServerInfo::for_file(r"C:\a\b\mydb.mv.db").unwrap();
        assert_eq!(windows.get_db_name(), "C:/a/b/mydb.mv.db");
        assert!(windows.is_windows_file_path());
    }

    #[test]
    fn file_db_name_must_be_absolute_and_clean() {
        assert!(BSimServerInfo::for_file("relative/path/db").is_err());
        assert!(BSimServerInfo::for_file("/a/b/").is_err());
        assert!(BSimServerInfo::for_file("/a/b';drop").is_err());
    }

    #[test]
    fn file_url_round_trips_through_form_encoding() {
        let info = BSimServerInfo::for_file("/a/b/mydb.mv.db").unwrap();
        // URLEncoder's x-www-form-urlencoded form escapes '/' as %2F.
        assert_eq!(info.to_url_string(), "file:%2Fa%2Fb%2Fmydb.mv.db");
        assert_eq!(BSimServerInfo::from_url(&info.to_url_string()).unwrap(), info);
        // A plain, unencoded file URL is accepted too.
        assert_eq!(BSimServerInfo::from_url("file:/a/b/mydb.mv.db").unwrap(), info);
    }

    #[test]
    fn from_url_parses_postgres_url_with_user_info() {
        let info = BSimServerInfo::from_url("postgresql://bob:se%3Acret@myhost:5555/mydb").unwrap();
        assert_eq!(info.get_db_type(), DBType::Postgres);
        assert_eq!(info.get_server_name(), Some("myhost"));
        assert_eq!(info.get_port(), 5555);
        assert_eq!(info.get_db_name(), "mydb");
        assert_eq!(info.get_user_name().as_deref(), Some("bob"));
        assert_eq!(info.get_password(), Some("se:cret"));
        assert_eq!(info.to_url_string(), "postgresql://bob:se%3Acret@myhost:5555/mydb");
    }

    #[test]
    fn from_url_applies_protocol_defaults() {
        let postgres = BSimServerInfo::from_url("postgresql://myhost/mydb").unwrap();
        assert_eq!(postgres.get_port(), DEFAULT_POSTGRES_PORT);
        assert!(postgres.has_default_login());

        let elastic = BSimServerInfo::from_url("elastic://myhost/mydb").unwrap();
        assert_eq!(elastic.get_db_type(), DBType::Elastic);
        assert_eq!(elastic.get_port(), DEFAULT_ELASTIC_PORT);
        // An elastic server always renders back as an https URL.
        assert_eq!(elastic.to_url_string(), "https://myhost:9200/mydb");
        assert_eq!(BSimServerInfo::from_url("https://myhost/mydb").unwrap(), elastic);
    }

    #[test]
    fn from_url_rejects_bad_urls() {
        assert!(BSimServerInfo::from_url("ftp://myhost/mydb").is_err());
        assert!(BSimServerInfo::from_url("postgresql://myhost").is_err()); // no dbName
        assert!(BSimServerInfo::from_url("postgresql:///mydb").is_err()); // no host
        assert!(BSimServerInfo::from_url("postgresql://myhost/db%2Fname").is_err()); // '/' in name
        assert!(BSimServerInfo::from_url("file://remotehost/a/b/db.mv.db").is_err());
    }

    #[test]
    fn equality_ignores_nothing_but_ordering_uses_to_string() {
        let plain = BSimServerInfo::with_default_login(DBType::Postgres, Some("h"), -1, "mydb")
            .unwrap();
        let with_user =
            BSimServerInfo::new(DBType::Postgres, Some("bob"), Some("h"), -1, "mydb").unwrap();
        assert_ne!(plain, with_user);
        // Java's compareTo only compares toString(), which excludes user info.
        assert_eq!(plain.cmp(&with_user), std::cmp::Ordering::Equal);

        let other_db = BSimServerInfo::with_default_login(DBType::Postgres, Some("h"), -1, "adb")
            .unwrap();
        assert!(other_db < plain);
    }

    #[test]
    fn hash_code_matches_java_object_hash() {
        // Values computed from Java's Objects.hash(dbName, dbType.ordinal(), host, port), with
        // userinfo folded in as 31 * hash + userinfo.hashCode() only when present.
        let plain =
            BSimServerInfo::with_default_login(DBType::Postgres, Some("myhost"), -1, "mydb")
                .unwrap();
        assert_eq!(plain.hash_code(), -1263738245);

        let with_user =
            BSimServerInfo::new(DBType::Postgres, Some("bob"), Some("myhost"), -1, "mydb").unwrap();
        assert_eq!(with_user.hash_code(), -521082214);

        let file = BSimServerInfo::for_file("/a/b/db.mv.db").unwrap();
        assert_eq!(file.hash_code(), -396222139);
    }

    #[test]
    fn java_string_hash_matches_java() {
        assert_eq!(java_string_hash(""), 0);
        assert_eq!(java_string_hash("bob"), 97717);
        assert_eq!(java_string_hash("hello world"), 1794106052);
    }

    #[test]
    fn url_encoding_matches_java_url_encoder() {
        assert_eq!(url_encode("/a/b/db.mv.db"), "%2Fa%2Fb%2Fdb.mv.db");
        assert_eq!(url_encode("a b+c"), "a+b%2Bc");
        assert_eq!(url_encode("*_-."), "*_-.");
        assert_eq!(url_decode("%2Fa+b%2Bc").unwrap(), "/a b+c");
        assert!(url_decode("%2").is_err());
        assert!(url_decode("%zz").is_err());
    }
}

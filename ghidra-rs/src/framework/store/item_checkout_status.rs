//! Port of `ghidra.framework.store.ItemCheckoutStatus`.
//!
//! Immutable status information for a checked-out item. The Java class implements
//! `Serializable` via a custom `writeObject`/`readObject` pair that writes a leading
//! format-version tag (`VERSION = 3`) and then reads it back with version-gated logic (the
//! `checkoutType` field only exists from version 3 onward; `projectPath` only exists from
//! version 2 onward). Unlike the sibling class
//! [`ItemVersion`](crate::framework::store::version::ItemVersion) (port of
//! `ghidra.framework.store.Version`), which mirrors that same `Serializable` intent via plain
//! derived `serde::Serialize`/`serde::Deserialize`, this port does not derive `serde` traits: its
//! `checkout_type` field is [`CheckoutType`], which does not (yet) derive them, and nothing in
//! this codebase deserializes the Java wire form directly, so there is no forcing need to widen
//! `CheckoutType`'s trait surface just for this.
//!
//! ## `getProjectPath()`/related bug (not reproduced by API shape, but noted)
//!
//! Java's static `getProjectPath(String, boolean)` concatenates `projectPath` onto the hostname
//! prefix with plain `+`, so a `null` `projectPath` argument would serialize as the literal
//! string `"null"`. This port takes `&str` instead of a nullable value, so that particular
//! `null`-concatenation quirk has no Rust equivalent to reproduce; the sole real caller
//! (`GhidraFileData`) always passes a non-null `ProjectLocator.toString()`.
//!
//! ## Genuine bugs reproduced faithfully
//!
//! - `equals(Object)` (source line 242) compares `time != other.time` where every other
//!   surrounding comparison uses `==`. This means two statuses with identical `checkoutId`,
//!   `user`, and `version` -- and the *same* `time` -- compare **unequal**, while two statuses
//!   that differ only in `time` compare **equal**. This also breaks the `equals`/`hashCode`
//!   contract, since `hashCode()` (source line 221) folds `time` in the ordinary way. See
//!   [`ItemCheckoutStatus::eq`] and the `equals_bug_*` tests below.
//! - `getProjectName()`/`getProjectLocation()`/`getUserHostName()` only strip the `"host::"`
//!   prefix (or extract the host name) when `path.indexOf("::") > 0`; an empty host name (giving
//!   `"::rest"`, `indexOf` returning `0`) is treated the same as *no* `"::"` at all (`indexOf`
//!   returning `-1`), since both fail the `> 0` check. See [`ItemCheckoutStatus::strip_host_prefix`]
//!   and the `empty_host_prefix_not_stripped` test.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::framework::store::CheckoutType;

/// Immutable status information for a checked-out item. Port of `ItemCheckoutStatus`.
#[derive(Debug, Clone)]
pub struct ItemCheckoutStatus {
    checkout_id: i64,
    checkout_type: CheckoutType,
    user: String,
    version: i32,
    time: i64,
    project_path: Option<String>,
}

impl ItemCheckoutStatus {
    /// Creates a new `ItemCheckoutStatus`. Port of
    /// `ItemCheckoutStatus(long, CheckoutType, String, int, long, String)`.
    ///
    /// - `checkout_id`: unique checkout ID
    /// - `checkout_type`: type of checkout
    /// - `user`: user name
    /// - `version`: version of the file which was checked out
    /// - `time`: time (milliseconds since the Unix epoch) when the checkout was completed
    /// - `project_path`: user's local project path, if known; backslashes are normalized to
    ///   forward slashes, mirroring the constructor's `projectPath.replace('\\', '/')`.
    pub fn new(
        checkout_id: i64,
        checkout_type: CheckoutType,
        user: impl Into<String>,
        version: i32,
        time: i64,
        project_path: Option<&str>,
    ) -> Self {
        Self {
            checkout_id,
            checkout_type,
            user: user.into(),
            version,
            time,
            project_path: project_path.map(|p| p.replace('\\', "/")),
        }
    }

    /// Returns the unique ID for the associated checkout. Port of `getCheckoutId()`.
    pub fn checkout_id(&self) -> i64 {
        self.checkout_id
    }

    /// Returns the checkout type. Port of `getCheckoutType()`.
    pub fn checkout_type(&self) -> CheckoutType {
        self.checkout_type
    }

    /// Returns the user name for the associated checkout. Port of `getUser()`.
    pub fn user(&self) -> &str {
        &self.user
    }

    /// Returns the file version which was checked out. Port of `getCheckoutVersion()`.
    pub fn checkout_version(&self) -> i32 {
        self.version
    }

    /// Returns the time (milliseconds since the Unix epoch) at which the checkout was completed.
    /// Port of `getCheckoutTime()`.
    pub fn checkout_time(&self) -> i64 {
        self.time
    }

    /// Returns the time at which the checkout was completed, as a [`SystemTime`]. Port of
    /// `getCheckoutDate()` (`new Date(time)`). `time` is milliseconds since the Unix epoch and is
    /// clamped to `0` if negative, since [`Duration`] (and therefore [`SystemTime`] built from
    /// [`UNIX_EPOCH`]) cannot represent a negative offset the way `java.util.Date` can.
    pub fn checkout_date(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_millis(self.time.max(0) as u64)
    }

    /// Returns the user's local project path, if known. Port of `getProjectPath()`.
    pub fn project_path(&self) -> Option<&str> {
        self.project_path.as_deref()
    }

    /// Strips the leading `"host::"` prefix from `path`, mirroring the shared logic in
    /// `getProjectName()`/`getProjectLocation()`: `int ix = path.indexOf("::"); if (ix > 0) path
    /// = path.substring(ix + 2);`. Note the `> 0` (not `>= 0`): a path that starts with `"::"`
    /// (i.e. an empty host name) is faithfully left unstripped, same as a path with no `"::"` at
    /// all.
    fn strip_host_prefix(path: &str) -> &str {
        match path.find("::") {
            Some(ix) if ix > 0 => &path[ix + 2..],
            _ => path,
        }
    }

    /// Returns the project name derived from [`Self::project_path`], or `None` if one can not be
    /// constructed. Port of `getProjectName()`.
    pub fn project_name(&self) -> Option<String> {
        let path = Self::strip_host_prefix(self.project_path.as_deref()?);
        let ix = path.rfind('/')?;
        Some(path[ix + 1..].to_string())
    }

    /// Returns the project location derived from [`Self::project_path`], or `None` if one can not
    /// be constructed. Port of `getProjectLocation()`.
    pub fn project_location(&self) -> Option<String> {
        let path = Self::strip_host_prefix(self.project_path.as_deref()?);
        let ix = path.rfind('/')?;
        Some(path[..ix].to_string())
    }

    /// Returns the user's hostname associated with the original checkout, or `None`. Port of
    /// `getUserHostName()`. Like [`Self::strip_host_prefix`], a `"::"` at index `0` (empty host
    /// name) is treated as absent.
    pub fn user_host_name(&self) -> Option<&str> {
        let path = self.project_path.as_deref()?;
        match path.find("::") {
            Some(ix) if ix > 0 => Some(&path[..ix]),
            _ => None,
        }
    }

    /// Builds a project path string suitable for checkout requests, prefixed with the local
    /// machine's hostname (or `"<standalone>"` if it can not be determined). Port of the static
    /// `getProjectPath(String, boolean)`.
    pub fn build_project_path(project_path: &str, is_transient: bool) -> String {
        let hostname = local_host_name();
        if is_transient {
            format!("{hostname}::<Transient>")
        } else {
            format!("{hostname}::{project_path}")
        }
    }
}

impl PartialEq for ItemCheckoutStatus {
    /// Port of `equals(Object)`. Faithfully reproduces a genuine bug in the Java source
    /// (`ItemCheckoutStatus.java:242`): the final comparison is `time != other.time` where every
    /// other field comparison uses `==`. As a result this is `true` only when the times *differ*
    /// (given equal `checkoutId`/`user`/`version`), and `false` when every field -- including
    /// `time` -- matches. This is almost certainly meant to be `time == other.time`, but per this
    /// project's convention, genuine upstream Java bugs are ported faithfully rather than
    /// silently fixed.
    fn eq(&self, other: &Self) -> bool {
        self.checkout_id == other.checkout_id
            && self.user == other.user
            && self.version == other.version
            && self.time != other.time
    }
}

impl std::hash::Hash for ItemCheckoutStatus {
    /// Port of `hashCode()`. Note this is an ordinary, internally-consistent hash (unlike
    /// [`PartialEq::eq`] above), so `ItemCheckoutStatus`'s `Hash`/`PartialEq` impls do not
    /// satisfy Rust's usual "equal values hash equally" contract -- this mirrors the Java
    /// class's own broken `equals`/`hashCode` contract rather than papering over it.
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        let prime: i32 = 31;
        let mut result: i32 = 1;
        result = prime.wrapping_mul(result).wrapping_add(
            (self.checkout_id ^ ((self.checkout_id as u64 >> 32) as i64)) as i32,
        );
        result = prime
            .wrapping_mul(result)
            .wrapping_add((self.time ^ ((self.time as u64 >> 32) as i64)) as i32);
        result = prime
            .wrapping_mul(result)
            .wrapping_add(java_string_hash(&self.user));
        result = prime.wrapping_mul(result).wrapping_add(self.version);
        state.write_i32(result);
    }
}

/// Computes the Java `String.hashCode()` equivalent for a string, needed by
/// [`ItemCheckoutStatus`]'s `Hash` impl. Mirrors the small local helper of the same name
/// duplicated elsewhere in this crate (e.g. `symbol_manager.rs`) rather than a shared utility.
fn java_string_hash(s: &str) -> i32 {
    let mut hash = 0i32;
    for c in s.encode_utf16() {
        hash = hash.wrapping_mul(31).wrapping_add(c as i32);
    }
    hash
}

/// Determines the local machine's hostname, mirroring `InetAddress.getLocalHost().getHostName()`
/// with a `"<standalone>"` fallback on failure (matching the Java `catch (UnknownHostException)`
/// branch in `getProjectPath(String, boolean)`). Follows the same env-var-then-`hostname`-command
/// approach already used by `current_hostname()` in
/// `generic::util::file_locker`, rather than reaching for a new dependency or `unsafe` FFI.
fn local_host_name() -> String {
    if let Ok(h) = std::env::var("HOSTNAME") {
        if !h.is_empty() {
            return h;
        }
    }
    std::process::Command::new("hostname")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "<standalone>".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make(checkout_id: i64, user: &str, version: i32, time: i64) -> ItemCheckoutStatus {
        ItemCheckoutStatus::new(
            checkout_id,
            CheckoutType::Normal,
            user,
            version,
            time,
            Some("myhost::MyProject/MyProgram"),
        )
    }

    #[test]
    fn accessors_roundtrip() {
        let s = make(42, "alice", 3, 1_700_000_000_000);
        assert_eq!(s.checkout_id(), 42);
        assert_eq!(s.checkout_type(), CheckoutType::Normal);
        assert_eq!(s.user(), "alice");
        assert_eq!(s.checkout_version(), 3);
        assert_eq!(s.checkout_time(), 1_700_000_000_000);
        assert_eq!(s.project_path(), Some("myhost::MyProject/MyProgram"));
        assert_eq!(
            s.checkout_date(),
            std::time::UNIX_EPOCH + std::time::Duration::from_millis(1_700_000_000_000)
        );
    }

    #[test]
    fn checkout_date_clamps_negative_time_to_epoch() {
        let s = make(1, "alice", 1, -5);
        assert_eq!(s.checkout_date(), std::time::UNIX_EPOCH);
    }

    #[test]
    fn constructor_normalizes_backslashes_in_project_path() {
        let s = ItemCheckoutStatus::new(
            1,
            CheckoutType::Exclusive,
            "bob",
            1,
            0,
            Some(r"myhost::C:\Projects\MyProject"),
        );
        assert_eq!(s.project_path(), Some("myhost::C:/Projects/MyProject"));
    }

    #[test]
    fn project_name_and_location_strip_host_prefix() {
        let s = make(1, "alice", 1, 0);
        assert_eq!(s.project_name(), Some("MyProgram".to_string()));
        assert_eq!(s.project_location(), Some("MyProject".to_string()));
        assert_eq!(s.user_host_name(), Some("myhost"));
    }

    #[test]
    fn project_name_none_without_project_path() {
        let s = ItemCheckoutStatus::new(1, CheckoutType::Normal, "alice", 1, 0, None);
        assert_eq!(s.project_name(), None);
        assert_eq!(s.project_location(), None);
        assert_eq!(s.user_host_name(), None);
    }

    #[test]
    fn project_name_none_without_slash_after_host_strip() {
        // No '/' remains after stripping "host::", so both getProjectName/getProjectLocation
        // return null in the Java source (path.lastIndexOf('/') < 0), not the whole path.
        let s = ItemCheckoutStatus::new(1, CheckoutType::Normal, "alice", 1, 0, Some("myhost::NoSlash"));
        assert_eq!(s.project_name(), None);
        assert_eq!(s.project_location(), None);
        assert_eq!(s.user_host_name(), Some("myhost"));
    }

    #[test]
    fn no_host_prefix_present_uses_whole_path() {
        let s = ItemCheckoutStatus::new(1, CheckoutType::Normal, "alice", 1, 0, Some("MyProject/MyProgram"));
        assert_eq!(s.project_name(), Some("MyProgram".to_string()));
        assert_eq!(s.project_location(), Some("MyProject".to_string()));
        assert_eq!(s.user_host_name(), None);
    }

    /// Faithful reproduction of the `ItemCheckoutStatus.java:242` `indexOf("::") > 0` (not `>=
    /// 0`) check: a path beginning with "::" (as if the host name were empty) has `indexOf`
    /// return `0`, which fails `> 0`, so the prefix is *not* stripped -- identical to the
    /// "no '::' present at all" case.
    #[test]
    fn empty_host_prefix_not_stripped() {
        let s = ItemCheckoutStatus::new(1, CheckoutType::Normal, "alice", 1, 0, Some("::MyProject/MyProgram"));
        // Not stripped, so the leading "::" is still part of the path handed to lastIndexOf('/').
        assert_eq!(s.project_name(), Some("MyProgram".to_string()));
        assert_eq!(s.project_location(), Some("::MyProject".to_string()));
        // getUserHostName also requires ix > 0, so it returns None here too, even though "::" is
        // present (at index 0).
        assert_eq!(s.user_host_name(), None);
    }

    #[test]
    fn build_project_path_transient() {
        let path = ItemCheckoutStatus::build_project_path("MyProject", true);
        assert!(path.ends_with("::<Transient>"));
    }

    #[test]
    fn build_project_path_non_transient() {
        let path = ItemCheckoutStatus::build_project_path("MyProject/MyProgram", false);
        assert!(path.ends_with("::MyProject/MyProgram"));
    }

    /// Direct demonstration of the genuine Java bug documented on `PartialEq::eq`: two statuses
    /// identical in every field -- including `time` -- compare as **unequal**, because the real
    /// `equals(Object)` source uses `time != other.time` instead of `time == other.time`.
    #[test]
    fn equals_bug_identical_statuses_compare_unequal() {
        let a = make(7, "alice", 2, 12345);
        let b = make(7, "alice", 2, 12345);
        assert_eq!(a.checkout_id, b.checkout_id);
        assert_eq!(a.user, b.user);
        assert_eq!(a.version, b.version);
        assert_eq!(a.time, b.time);
        assert_ne!(a, b, "reproduces ItemCheckoutStatus.java:242's `time != other.time` bug");
    }

    /// The flip side of the same bug: two statuses that differ *only* in `time` compare as
    /// **equal**.
    #[test]
    fn equals_bug_differing_only_in_time_compares_equal() {
        let a = make(7, "alice", 2, 111);
        let b = make(7, "alice", 2, 222);
        assert_eq!(a, b, "reproduces ItemCheckoutStatus.java:242's `time != other.time` bug");
    }

    #[test]
    fn equals_still_respects_other_fields() {
        let a = make(7, "alice", 2, 111);
        let different_user = make(7, "bob", 2, 222);
        assert_ne!(a, different_user);

        let different_id = make(9, "alice", 2, 222);
        assert_ne!(a, different_id);

        let different_version = make(7, "alice", 3, 222);
        assert_ne!(a, different_version);
    }

    /// `hash_code`/`equals` are inconsistent by design (mirroring the Java class): two statuses
    /// that `equals()` reports equal (differing only in `time`) need not -- and generally will
    /// not -- hash equally, since `hashCode()` folds `time` in normally.
    #[test]
    fn hash_and_equals_are_inconsistent_like_java() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let a = make(7, "alice", 2, 111);
        let b = make(7, "alice", 2, 222);
        assert_eq!(a, b);

        let mut ha = DefaultHasher::new();
        a.hash(&mut ha);
        let mut hb = DefaultHasher::new();
        b.hash(&mut hb);
        assert_ne!(
            ha.finish(),
            hb.finish(),
            "equal (per the buggy equals()) statuses with different `time` hash differently, \
             just like the real Java class"
        );
    }
}

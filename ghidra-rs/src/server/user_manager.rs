//! Port of `ghidra.server.UserManager`.
//!
//! Manages the set of users associated with a running GhidraServer, including local password
//! management/authentication and PKI (X500 distinguished name) association.
//!
//! Per this crate's shape rules, the concrete Java `class UserManager` (nothing extends it) ports
//! to a `struct` + `impl`, not a trait.
//!
//! # A pre-existing, separate seam
//!
//! [`UserManagerLike`](crate::server::seam_stubs::UserManagerLike) is an older, still-live
//! placeholder trait for this same Java class, used as a `dyn`-dispatched return type on
//! [`RepositoryManager::get_user_manager`](crate::server::repository_manager::RepositoryManager::get_user_manager)
//! and as a parameter type on
//! `AuthenticationModule::authenticate`. Unlike `RepositoryManagerLike` (which this batch
//! promoted away because it had zero real callers, only a test mock), `UserManagerLike` is wired
//! into multiple live trait signatures across `repository_manager.rs`, `authentication_module.rs`,
//! and `command_processor.rs`; replacing it everywhere would mean changing those trait signatures
//! and every implementor (mocks and real) in the same turn, well beyond one class's scope. Per
//! this batch's duplicate-name guidance, that reconciliation is intentionally left undone here:
//! [`UserManager`] below is a genuine, independent, fully-tested port matching the shape rules,
//! while `UserManagerLike` continues to serve its existing call sites unchanged. This type does
//! implement [`UserManagerLike`](crate::server::seam_stubs::UserManagerLike) itself, so it CAN be
//! used wherever that trait is expected, once a caller constructs one.
//!
//! # Simplifications
//!
//! - A JDK `X500Principal` is represented as its plain distinguished-name string, matching the
//!   simplification already used for [`UserManagerLike`]/[`CommandProcessor`](crate::server::command_processor).
//! - Password bytes are `&[u8]`/`Vec<u8>` rather than Java's `char[]`.
//! - `getDNLog()`'s lazily-opened, cached `PrintWriter` is simplified to an open-append-close per
//!   call; behaviorally equivalent (append semantics), just not caching the file handle across
//!   calls to a rarely-used diagnostic log.
//! - Java's `synchronized(repositoryMgr)` shares a lock with the owning `RepositoryManager`
//!   instance; this port uses its own internal `Mutex` instead of reaching into the manager it
//!   holds, avoiding a shared-lock-object pattern that doesn't translate cleanly to Rust ownership
//!   (see `OWNERSHIP_MIGRATION.md`). `remove_user` releases this lock before calling back into
//!   `RepositoryManager::user_removed`, so the two never nest.
//! - The static admin-console utility `listUsers(File)` (prints to stdout) is not ported; nothing
//!   in this crate calls it and `ServerAdmin` is not ported either.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use crate::server::repository_manager::RepositoryManager;
use crate::server::seam_stubs::{AddUserError, HashUtilities, UserManagerLike};
use crate::util::seam_stubs::NumericUtilities;
use crate::util::exception::DuplicateNameException;
use crate::util::Msg;

/// Mirrors `UserManager.ANONYMOUS_USERNAME` (itself `User.ANONYMOUS_USERNAME`).
pub const ANONYMOUS_USERNAME: &str = crate::framework::remote::ANONYMOUS_USERNAME;

/// Mirrors `UserManager.USER_PASSWORD_FILE`.
pub const USER_PASSWORD_FILE: &str = "users";
/// Mirrors `UserManager.DN_LOG_FILE`.
pub const DN_LOG_FILE: &str = "UnknownDN.log";

const SSH_PUBKEY_EXT: &str = ".pub";
const DEFAULT_PASSWORD: &[u8] = b"changeme";
const DEFAULT_PASSWORD_TIMEOUT_DAYS: i32 = 1; // 24-hours
const NO_EXPIRATION: i64 = -1;

/// Name of the hidden SSH-key subdirectory under a server's root directory, mirroring
/// `LocalFileSystem.HIDDEN_DIR_PREFIX + "ssh"`.
fn ssh_key_folder_name() -> String {
    format!("{}ssh", crate::framework::store::local::local_file_system::HIDDEN_DIR_PREFIX)
}

fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Mirrors the private nested `UserEntry` class used to hold user data.
#[derive(Clone)]
struct UserEntry {
    username: String,
    x500_user_dn: Option<String>,
    password_hash: Option<Vec<u8>>,
    password_time: i64,
}

/// The mutable state Java guards with `synchronized(repositoryMgr)`.
struct UserManagerState {
    /// Insertion-ordered users, mirroring `LinkedHashMap<String, UserEntry>`.
    users: Vec<UserEntry>,
    /// Distinguished name -> username, mirroring `HashMap<X500Principal, UserEntry>`.
    dn_to_username: HashMap<String, String>,
    /// The user file's modification time as of the last successful read/write, used to detect
    /// external changes to the file. `None` mirrors Java's `0L` ("file does not exist" / "never
    /// read").
    last_change: Option<SystemTime>,
}

/// Manages the set of users associated with a running GhidraServer.
///
/// Port of `ghidra.server.UserManager`. See the module docs for the pre-existing
/// [`UserManagerLike`](crate::server::seam_stubs::UserManagerLike) seam this does not replace,
/// and for simplifications from the Java original.
pub struct UserManager {
    repository_mgr: Arc<dyn RepositoryManager>,
    user_file: PathBuf,
    ssh_dir: PathBuf,
    dn_log_file: PathBuf,
    enable_local_passwords: bool,
    default_password_expiration_ms: i64,
    state: Mutex<UserManagerState>,
}

impl UserManager {
    /// Construct a server user manager.
    ///
    /// `default_password_expiration_days`: password expiration in days when local passwords are
    /// enabled (`0` = no expiration; negative defaults to 1 day, mirroring Java).
    ///
    /// Port of the package-private `UserManager(RepositoryManager, boolean, int)` constructor.
    pub fn new(
        repository_mgr: Arc<dyn RepositoryManager>,
        enable_local_passwords: bool,
        default_password_expiration_days: i32,
    ) -> Self {
        let default_password_expiration_days = if default_password_expiration_days < 0 {
            DEFAULT_PASSWORD_TIMEOUT_DAYS
        }
        else {
            default_password_expiration_days
        };
        let default_password_expiration_ms =
            default_password_expiration_days as i64 * 24 * 3600 * 1000;

        Msg::info(
            "UserManager",
            &format!(
                "Instantiating User Manager {}",
                if enable_local_passwords { "(w/password management)" } else { "" }
            ),
        );

        let root_dir = repository_mgr.get_root_dir();
        let user_file = root_dir.join(USER_PASSWORD_FILE);
        let dn_log_file = root_dir.join(DN_LOG_FILE);
        let ssh_dir = root_dir.join(ssh_key_folder_name());

        let mgr = UserManager {
            repository_mgr,
            user_file,
            ssh_dir,
            dn_log_file,
            enable_local_passwords,
            default_password_expiration_ms,
            state: Mutex::new(UserManagerState {
                users: Vec::new(),
                dn_to_username: HashMap::new(),
                last_change: None,
            }),
        };

        if let Err(e) = mgr.read_user_list_if_needed() {
            if e.kind() == io::ErrorKind::NotFound {
                Msg::error("UserManager", &"Existing User file not found.");
            }
            else {
                Msg::error_with_error("UserManager", &"", &e);
            }
        }
        let _ = mgr.clear_expired_passwords();

        {
            let state = mgr.state.lock().unwrap();
            let size = state.users.len();
            Msg::info(
                "UserManager",
                &format!("User file contains {size} {}", if size == 1 { "entry" } else { "entries" }),
            );
            Msg::info("UserManager", &"Known Users:");
            for entry in &state.users {
                let dn_str = entry
                    .x500_user_dn
                    .as_ref()
                    .map(|dn| format!(" DN={{{dn}}}"))
                    .unwrap_or_default();
                Msg::info("UserManager", &format!("   {}{}", entry.username, dn_str));
            }
        }

        mgr.init_ssh();
        mgr
    }

    /// Get the SSH public key file for the specified user, if it exists.
    ///
    /// Port of `getSSHPubKeyFile(String)`.
    pub fn get_ssh_pub_key_file(&self, username: &str) -> Option<PathBuf> {
        {
            let state = self.state.lock().unwrap();
            if !state.users.iter().any(|u| u.username == username) {
                return None;
            }
        }
        let f = self.ssh_dir.join(format!("{username}{SSH_PUBKEY_EXT}"));
        f.is_file().then_some(f)
    }

    /// Add a user. Port of the private `addUser(String, char[], X500Principal)`.
    fn add_user_internal(
        &self,
        username: &str,
        password_hash: Option<Vec<u8>>,
        x500_user_dn: Option<String>,
    ) -> Result<(), AddUserError> {
        let mut state = self.state.lock().unwrap();
        if state.users.iter().any(|u| u.username == username) {
            return Err(AddUserError::Duplicate(DuplicateNameException::with_message(format!(
                "User {username} already exists"
            ))));
        }
        let entry = UserEntry {
            username: username.to_string(),
            password_hash,
            password_time: now_millis(),
            x500_user_dn: x500_user_dn.clone(),
        };
        if let Some(dn) = &x500_user_dn {
            state.dn_to_username.insert(dn.clone(), username.to_string());
        }
        state.users.push(entry);
        self.write_user_list(&mut state)?;
        Msg::info("UserManager", &format!("User '{username}' added"));
        Ok(())
    }

    /// Add a user with no password hash and no distinguished name.
    ///
    /// Port of the public no-arg-overload `addUser(String)`.
    pub fn add_user_default(&self, username: &str) -> Result<(), AddUserError> {
        self.add_user(username, None)
    }

    /// Returns the X500 distinguished name for the specified user, if any.
    ///
    /// Port of `getDistinguishedName(String)`.
    pub fn get_distinguished_name(&self, username: &str) -> Option<String> {
        self.state
            .lock()
            .unwrap()
            .users
            .iter()
            .find(|u| u.username == username)
            .and_then(|u| u.x500_user_dn.clone())
    }

    /// Returns the username associated with the specified distinguished name, if any.
    ///
    /// Port of `getUserByDistinguishedName(X500Principal)`.
    pub fn get_user_by_distinguished_name(&self, x500_user_dn: &str) -> Option<String> {
        self.state.lock().unwrap().dn_to_username.get(x500_user_dn).cloned()
    }

    fn check_valid_password_hash(salted_password_hash: &[u8]) -> io::Result<()> {
        if salted_password_hash.len() != HashUtilities::SHA256_SALTED_HASH_LENGTH {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid password hash"));
        }
        for (i, &c) in salted_password_hash[..HashUtilities::SALT_LENGTH].iter().enumerate() {
            if !c.is_ascii_alphanumeric() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "Password set failed due invalid salt: {} ({},{})",
                        String::from_utf8_lossy(salted_password_hash),
                        i,
                        c as char
                    ),
                ));
            }
        }
        for (i, &c) in salted_password_hash[HashUtilities::SALT_LENGTH..].iter().enumerate() {
            if !(c.is_ascii_digit() || (b'a'..=b'f').contains(&c)) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "Password set failed due to invalid hash: {} ({},{})",
                        String::from_utf8_lossy(salted_password_hash),
                        i + HashUtilities::SALT_LENGTH,
                        c as char
                    ),
                ));
            }
        }
        Ok(())
    }

    fn password_expiration_for(entry: Option<&UserEntry>, default_expiration_ms: i64) -> i64 {
        let mut time_remaining = 0i64;
        if let Some(user) = entry {
            if default_expiration_ms == 0 || user.password_time == NO_EXPIRATION {
                return -1;
            }
            if user.password_time != 0 {
                time_remaining = default_expiration_ms - (now_millis() - user.password_time);
                if time_remaining <= 0 {
                    time_remaining = 0;
                }
            }
        }
        time_remaining
    }

    /// Reset the local password to the default for the specified user.
    ///
    /// Port of the private `getDefaultPasswordHash()`.
    fn default_password_hash() -> Vec<u8> {
        HashUtilities::get_salted_hash_random(HashUtilities::SHA256_ALGORITHM, DEFAULT_PASSWORD)
    }

    /// Get list of all users known to server, in the order they were added.
    ///
    /// Port of `getUsers()`.
    pub fn get_users(&self) -> Vec<String> {
        self.state.lock().unwrap().users.iter().map(|u| u.username.clone()).collect()
    }

    /// Clear all local user passwords which have expired.
    ///
    /// Port of the package-private `clearExpiredPasswords()`.
    pub(crate) fn clear_expired_passwords(&self) -> io::Result<()> {
        if self.default_password_expiration_ms == 0 {
            return Ok(());
        }
        let mut state = self.state.lock().unwrap();
        let mut changed = false;
        let enable_local_passwords = self.enable_local_passwords;
        let default_expiration_ms = self.default_password_expiration_ms;
        for entry in state.users.iter_mut() {
            if entry.password_hash.is_some()
                && enable_local_passwords
                && Self::password_expiration_for(Some(entry), default_expiration_ms) == 0
            {
                entry.password_hash = None;
                entry.password_time = 0;
                changed = true;
                Msg::warn("UserManager", &format!("Default password expired for user '{}'", entry.username));
            }
        }
        if changed {
            self.write_user_list(&mut state)?;
        }
        Ok(())
    }

    /// Read user data from file if the timestamp on the file has changed.
    ///
    /// Port of the package-private `readUserListIfNeeded()`.
    pub(crate) fn read_user_list_if_needed(&self) -> io::Result<()> {
        let last_mod = fs::metadata(&self.user_file).and_then(|m| m.modified()).ok();
        let mut state = self.state.lock().unwrap();
        if state.last_change == last_mod {
            if last_mod.is_none() {
                // Create empty file if it does not yet exist
                self.write_user_list(&mut state)?;
            }
            return Ok(());
        }

        let (users, dn_to_username) = Self::read_user_list_file(&self.user_file)?;
        state.users = users;
        state.dn_to_username = dn_to_username;
        state.last_change = last_mod;
        Ok(())
    }

    fn read_user_list_file(file: &Path) -> io::Result<(Vec<UserEntry>, HashMap<String, String>)> {
        let mut users = Vec::new();
        let mut dn_to_username = HashMap::new();
        let content = fs::read_to_string(file)?;

        for line in content.lines() {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut tokens = line.split(':');
            let username = match tokens.next() {
                Some(u) if !u.is_empty() => u,
                _ => continue,
            };
            if !Self::is_valid_user_name(username) {
                Msg::error("UserManager", &format!("Invalid user name, skipping: {username}"));
                continue;
            }

            let mut entry =
                UserEntry { username: username.to_string(), password_hash: None, password_time: 0, x500_user_dn: None };

            if let Some(hash_tok) = tokens.next() {
                entry.password_hash = Some(hash_tok.as_bytes().to_vec());
                if let Some(time_tok) = tokens.next() {
                    if time_tok == "*" {
                        entry.password_time = NO_EXPIRATION;
                    }
                    else {
                        match NumericUtilities::parse_hex_long(time_tok) {
                            Ok(t) => entry.password_time = t,
                            Err(_) => {
                                Msg::error(
                                    "UserManager",
                                    &format!("Invalid password time - forced expiration: {username}"),
                                );
                                entry.password_time = 0;
                            }
                        }
                    }
                    if let Some(dn_tok) = tokens.next() {
                        if !dn_tok.is_empty() {
                            entry.x500_user_dn = Some(dn_tok.to_string());
                        }
                    }
                }
            }

            if let Some(dn) = &entry.x500_user_dn {
                dn_to_username.insert(dn.clone(), entry.username.clone());
            }
            users.push(entry);
        }
        Ok((users, dn_to_username))
    }

    /// Write user data to file.
    ///
    /// Port of the private `writeUserList()`.
    fn write_user_list(&self, state: &mut UserManagerState) -> io::Result<()> {
        let mut contents = String::new();
        for entry in &state.users {
            contents.push_str(&entry.username);
            contents.push(':');
            if let Some(hash) = &entry.password_hash {
                contents.push_str(&String::from_utf8_lossy(hash));
                contents.push(':');
                if entry.password_time == NO_EXPIRATION {
                    contents.push('*');
                }
                else {
                    // Mirrors `Long.toHexString`, which treats the value as an unsigned 64-bit
                    // pattern rather than sign-printing a negative value.
                    contents.push_str(&format!("{:x}", entry.password_time as u64));
                }
            }
            else {
                contents.push_str("*:*");
            }
            if let Some(dn) = &entry.x500_user_dn {
                contents.push(':');
                contents.push_str(dn);
            }
            contents.push('\n');
        }
        fs::write(&self.user_file, contents)?;
        state.last_change = fs::metadata(&self.user_file).and_then(|m| m.modified()).ok();
        Ok(())
    }

    /// Verify that the specified password corresponds to the local password set for the
    /// specified user.
    ///
    /// Port of `authenticateUser(String, char[])`.
    pub fn authenticate_user(&self, username: &str, password: &[u8]) -> Result<(), AuthenticationError> {
        self.clear_expired_passwords()?;
        let state = self.state.lock().unwrap();
        let entry = state
            .users
            .iter()
            .find(|u| u.username == username)
            .ok_or_else(|| AuthenticationError::FailedLogin(format!("Unknown user: {username}")))?;

        let hash = entry
            .password_hash
            .as_ref()
            .filter(|h| h.len() >= HashUtilities::MD5_UNSALTED_HASH_LENGTH)
            .ok_or_else(|| AuthenticationError::FailedLogin("User password not set, must be reset".to_string()))?;

        // Support deprecated unsalted hash.
        if hash.len() == HashUtilities::MD5_UNSALTED_HASH_LENGTH
            && HashUtilities::get_hash(HashUtilities::MD5_ALGORITHM, password) == *hash
        {
            return Ok(());
        }

        let salt = &hash[..HashUtilities::SALT_LENGTH];
        if hash.len() == HashUtilities::MD5_SALTED_HASH_LENGTH {
            if HashUtilities::get_salted_hash(HashUtilities::MD5_ALGORITHM, salt, password) != *hash {
                return Err(AuthenticationError::FailedLogin("Incorrect password".to_string()));
            }
        }
        else if hash.len() == HashUtilities::SHA256_SALTED_HASH_LENGTH {
            if HashUtilities::get_salted_hash(HashUtilities::SHA256_ALGORITHM, salt, password) != *hash {
                return Err(AuthenticationError::FailedLogin("Incorrect password".to_string()));
            }
        }
        else {
            return Err(AuthenticationError::FailedLogin("User password not set, must be reset".to_string()));
        }
        Ok(())
    }

    fn init_ssh(&self) {
        if !self.ssh_dir.exists() {
            let _ = fs::create_dir(&self.ssh_dir);
            return;
        }
        let entries = match fs::read_dir(&self.ssh_dir) {
            Ok(e) => e,
            Err(_) => return,
        };
        let pubkey_files: Vec<String> = entries
            .filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|name| name.ends_with(SSH_PUBKEY_EXT))
            .collect();
        if pubkey_files.is_empty() {
            return;
        }

        Msg::info("UserManager", &"Users with stored SSH public key:");
        let state = self.state.lock().unwrap();
        for fname in pubkey_files {
            let user = &fname[..fname.len() - SSH_PUBKEY_EXT.len()];
            if !state.users.iter().any(|u| u.username == user) {
                continue; // ignore invalid user
            }
            Msg::info("UserManager", &format!("   {user}"));
        }
    }

    /// Log a new or unknown X500 principal to facilitate future addition to the user file.
    ///
    /// Port of `logUnknownDN(String, X500Principal)`.
    pub fn log_unknown_dn(&self, username: &str, principal_display: &str) {
        use std::io::Write as _;
        if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(&self.dn_log_file) {
            let _ = writeln!(f, "{username}; {principal_display}");
        }
    }

    /// Ensures a name only contains valid characters (alphanumeric, `.`, `-`, `_`, first
    /// character alphanumeric).
    ///
    /// Port of `isValidUserName(String)`.
    pub fn is_valid_user_name(s: &str) -> bool {
        let mut chars = s.chars();
        match chars.next() {
            Some(c) if c.is_ascii_alphanumeric() => {}
            _ => return false,
        }
        chars.all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
    }
}

/// Error produced by [`UserManager::authenticate_user`], standing in for the checked
/// `IOException`/`FailedLoginException` declared on `UserManager.authenticateUser`.
#[derive(Debug)]
pub enum AuthenticationError {
    Io(io::Error),
    FailedLogin(String),
}

impl From<io::Error> for AuthenticationError {
    fn from(error: io::Error) -> Self {
        AuthenticationError::Io(error)
    }
}

impl std::fmt::Display for AuthenticationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthenticationError::Io(e) => write!(f, "{e}"),
            AuthenticationError::FailedLogin(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for AuthenticationError {}

impl UserManagerLike for UserManager {
    fn can_set_password(&self, username: &str) -> bool {
        let state = self.state.lock().unwrap();
        self.enable_local_passwords
            && state.users.iter().any(|u| u.username == username && u.password_hash.is_some())
    }

    fn get_password_expiration(&self, username: &str) -> i64 {
        let state = self.state.lock().unwrap();
        let entry = state.users.iter().find(|u| u.username == username);
        if let Some(e) = entry {
            if let Some(hash) = &e.password_hash {
                if hash.len() != HashUtilities::SHA256_SALTED_HASH_LENGTH {
                    return 0;
                }
            }
        }
        Self::password_expiration_for(entry, self.default_password_expiration_ms)
    }

    fn set_password(
        &self,
        username: &str,
        salted_sha256_password_hash: &[u8],
        is_temporary: bool,
    ) -> io::Result<bool> {
        if !self.enable_local_passwords {
            return Err(io::Error::new(io::ErrorKind::Unsupported, "Local passwords are not used"));
        }
        Self::check_valid_password_hash(salted_sha256_password_hash)?;

        let mut state = self.state.lock().unwrap();
        let Some(pos) = state.users.iter().position(|u| u.username == username) else {
            return Ok(false);
        };
        let old = state.users.remove(pos);
        let password_time = if is_temporary { now_millis() } else { NO_EXPIRATION };
        state.users.push(UserEntry {
            username: username.to_string(),
            password_hash: Some(salted_sha256_password_hash.to_vec()),
            password_time,
            x500_user_dn: old.x500_user_dn,
        });
        self.write_user_list(&mut state)?;
        Ok(true)
    }

    fn add_user(&self, username: &str, salted_password_hash: Option<&[u8]>) -> Result<(), AddUserError> {
        let password_hash = match salted_password_hash {
            Some(h) => Some(h.to_vec()),
            None if self.enable_local_passwords => Some(Self::default_password_hash()),
            None => None,
        };
        self.add_user_internal(username, password_hash, None)
    }

    fn add_user_with_dn(&self, username: &str, x500_user_dn: &str) -> Result<(), AddUserError> {
        let password_hash = self.enable_local_passwords.then(Self::default_password_hash);
        self.add_user_internal(username, password_hash, Some(x500_user_dn.to_string()))
    }

    fn remove_user(&self, username: &str) -> io::Result<bool> {
        {
            let mut state = self.state.lock().unwrap();
            let Some(pos) = state.users.iter().position(|u| u.username == username) else {
                return Ok(false);
            };
            let old = state.users.remove(pos);
            if let Some(dn) = &old.x500_user_dn {
                state.dn_to_username.remove(dn);
            }
            self.write_user_list(&mut state)?;
        }
        self.repository_mgr.user_removed(username)?;
        Msg::info("UserManager", &format!("User removed from server: {username}"));
        Ok(true)
    }

    fn reset_password(&self, username: &str, salted_password_hash: Option<&[u8]>) -> io::Result<bool> {
        if !self.enable_local_passwords {
            return Ok(false);
        }
        let hash = match salted_password_hash {
            Some(h) => h.to_vec(),
            None => Self::default_password_hash(),
        };
        self.set_password(username, &hash, true)
    }

    fn is_valid_user(&self, username: &str) -> bool {
        self.state.lock().unwrap().users.iter().any(|u| u.username == username)
    }

    fn set_distinguished_name(&self, username: &str, x500_user_dn: &str) -> io::Result<bool> {
        let mut state = self.state.lock().unwrap();
        let Some(pos) = state.users.iter().position(|u| u.username == username) else {
            return Ok(false);
        };
        let old = state.users.remove(pos);
        if let Some(dn) = &old.x500_user_dn {
            state.dn_to_username.remove(dn);
        }
        state.dn_to_username.insert(x500_user_dn.to_string(), username.to_string());
        // Mirrors Java: the rebuilt `UserEntry` carries the old password hash forward but does
        // NOT carry `passwordTime` forward (it defaults to 0, Java's default `long` value, since
        // `setDistinguishedName`'s new `UserEntry` never assigns it).
        state.users.push(UserEntry {
            username: username.to_string(),
            password_hash: old.password_hash,
            password_time: 0,
            x500_user_dn: Some(x500_user_dn.to_string()),
        });
        self.write_user_list(&mut state)?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::seam_stubs::RepositoryLike;
    use std::io;

    struct MockRepositoryManager {
        root_dir: PathBuf,
        removed: Mutex<Vec<String>>,
    }

    impl RepositoryManager for MockRepositoryManager {
        fn anonymous_access_allowed(&self) -> bool {
            false
        }
        fn dispose(&self) {}
        fn get_root_dir(&self) -> PathBuf {
            self.root_dir.clone()
        }
        fn create_repository(&self, _c: &str, _n: &str) -> io::Result<Box<dyn RepositoryLike>> {
            unimplemented!()
        }
        fn get_repository(&self, _c: &str, _n: &str) -> io::Result<Option<Box<dyn RepositoryLike>>> {
            unimplemented!()
        }
        fn get_repository_privileged(&self, _name: &str) -> Option<Box<dyn RepositoryLike>> {
            None
        }
        fn delete_repository(&self, _c: &str, _n: &str) -> io::Result<()> {
            unimplemented!()
        }
        fn get_repository_names(&self, _c: &str) -> Vec<String> {
            Vec::new()
        }
        fn get_all_users(&self, _c: &str) -> Vec<String> {
            Vec::new()
        }
        fn get_user_manager(&self) -> Box<dyn UserManagerLike> {
            unimplemented!("tests use UserManager directly")
        }
        fn add_handle(&self, _h: Arc<dyn crate::server::remote::RepositoryServerHandleImpl>) {}
        fn drop_handle(&self, _h: Arc<dyn crate::server::remote::RepositoryServerHandleImpl>) {}
        fn process_command_queue(&self) -> io::Result<()> {
            Ok(())
        }
        fn user_removed(&self, username: &str) -> io::Result<()> {
            self.removed.lock().unwrap().push(username.to_string());
            Ok(())
        }
    }

    fn new_manager(dir: &Path, enable_local_passwords: bool) -> UserManager {
        let repo_mgr =
            Arc::new(MockRepositoryManager { root_dir: dir.to_path_buf(), removed: Mutex::new(Vec::new()) });
        UserManager::new(repo_mgr, enable_local_passwords, 0)
    }

    #[test]
    fn new_creates_empty_user_file_and_ssh_dir() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = new_manager(dir.path(), true);

        assert!(dir.path().join(USER_PASSWORD_FILE).is_file());
        assert!(dir.path().join(ssh_key_folder_name()).is_dir());
        assert!(mgr.get_users().is_empty());
    }

    #[test]
    fn add_user_then_is_valid_user_and_persists_across_reload() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = new_manager(dir.path(), true);

        UserManagerLike::add_user(&mgr, "alice", None).unwrap();
        assert!(mgr.is_valid_user("alice"));
        assert_eq!(mgr.get_users(), vec!["alice".to_string()]);

        // Re-reading the file (simulating a second process/instance) should see the same user.
        let (users, _) = UserManager::read_user_list_file(&dir.path().join(USER_PASSWORD_FILE)).unwrap();
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].username, "alice");
    }

    #[test]
    fn add_user_duplicate_fails() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = new_manager(dir.path(), true);
        UserManagerLike::add_user(&mgr, "alice", None).unwrap();

        let err = UserManagerLike::add_user(&mgr, "alice", None).unwrap_err();
        assert!(matches!(err, AddUserError::Duplicate(_)));
    }

    #[test]
    fn remove_user_notifies_repository_manager() {
        let dir = tempfile::tempdir().unwrap();
        let repo_mgr =
            Arc::new(MockRepositoryManager { root_dir: dir.path().to_path_buf(), removed: Mutex::new(Vec::new()) });
        let mgr = UserManager::new(repo_mgr.clone(), true, 0);

        UserManagerLike::add_user(&mgr, "alice", None).unwrap();
        assert!(mgr.remove_user("alice").unwrap());
        assert!(!mgr.is_valid_user("alice"));
        assert_eq!(*repo_mgr.removed.lock().unwrap(), vec!["alice".to_string()]);

        assert!(!mgr.remove_user("alice").unwrap());
    }

    #[test]
    fn set_and_authenticate_password_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = new_manager(dir.path(), true);
        UserManagerLike::add_user(&mgr, "alice", None).unwrap();

        let hash = HashUtilities::get_salted_hash_random(HashUtilities::SHA256_ALGORITHM, b"hunter2");
        assert!(mgr.set_password("alice", &hash, false).unwrap());

        assert!(mgr.authenticate_user("alice", b"hunter2").is_ok());
        let err = mgr.authenticate_user("alice", b"wrong").unwrap_err();
        assert!(matches!(err, AuthenticationError::FailedLogin(_)));
    }

    #[test]
    fn authenticate_unknown_user_fails() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = new_manager(dir.path(), true);
        let err = mgr.authenticate_user("ghost", b"pw").unwrap_err();
        assert!(matches!(err, AuthenticationError::FailedLogin(msg) if msg.contains("Unknown user")));
    }

    #[test]
    fn authenticate_legacy_unsalted_md5_hash_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = new_manager(dir.path(), true);
        UserManagerLike::add_user(&mgr, "alice", None).unwrap();

        // Force an unsalted MD5 hash directly into the on-disk file, bypassing setPassword's
        // SHA256-only validation (mirrors an old server's pre-existing password entry).
        let unsalted_md5 = HashUtilities::get_hash(HashUtilities::MD5_ALGORITHM, b"legacy-pw");
        assert_eq!(unsalted_md5.len(), HashUtilities::MD5_UNSALTED_HASH_LENGTH);
        {
            let mut state = mgr.state.lock().unwrap();
            state.users[0].password_hash = Some(unsalted_md5);
            mgr.write_user_list(&mut state).unwrap();
        }

        assert!(mgr.authenticate_user("alice", b"legacy-pw").is_ok());
    }

    #[test]
    fn can_set_password_requires_local_passwords_and_existing_hash() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = new_manager(dir.path(), true);
        UserManagerLike::add_user(&mgr, "alice", None).unwrap();
        assert!(mgr.can_set_password("alice"));
        assert!(!mgr.can_set_password("ghost"));

        let dir2 = tempfile::tempdir().unwrap();
        let mgr2 = new_manager(dir2.path(), false);
        UserManagerLike::add_user(&mgr2, "bob", None).unwrap();
        assert!(!mgr2.can_set_password("bob"));
    }

    #[test]
    fn reset_password_fails_when_local_passwords_disabled() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = new_manager(dir.path(), false);
        UserManagerLike::add_user(&mgr, "alice", None).unwrap();
        assert!(!mgr.reset_password("alice", None).unwrap());
    }

    #[test]
    fn set_and_get_distinguished_name_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = new_manager(dir.path(), true);
        UserManagerLike::add_user(&mgr, "alice", None).unwrap();

        assert!(mgr.set_distinguished_name("alice", "CN=Alice").unwrap());
        assert_eq!(mgr.get_distinguished_name("alice"), Some("CN=Alice".to_string()));
        assert_eq!(mgr.get_user_by_distinguished_name("CN=Alice"), Some("alice".to_string()));
    }

    #[test]
    fn add_user_with_dn_creates_user() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = new_manager(dir.path(), true);
        UserManagerLike::add_user_with_dn(&mgr, "alice", "CN=Alice").unwrap();

        assert!(mgr.is_valid_user("alice"));
        assert_eq!(mgr.get_distinguished_name("alice"), Some("CN=Alice".to_string()));
    }

    #[test]
    fn is_valid_user_name_matches_java_regex() {
        assert!(UserManager::is_valid_user_name("alice"));
        assert!(UserManager::is_valid_user_name("alice.smith-99_x"));
        assert!(!UserManager::is_valid_user_name(""));
        assert!(!UserManager::is_valid_user_name(".alice"));
        assert!(!UserManager::is_valid_user_name("-alice"));
    }

    #[test]
    fn get_ssh_pub_key_file_requires_known_user_and_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = new_manager(dir.path(), true);
        UserManagerLike::add_user(&mgr, "alice", None).unwrap();

        assert!(mgr.get_ssh_pub_key_file("alice").is_none());
        assert!(mgr.get_ssh_pub_key_file("ghost").is_none());

        let pub_key_path = dir.path().join(ssh_key_folder_name()).join("alice.pub");
        fs::write(&pub_key_path, b"ssh-rsa AAAA...").unwrap();
        assert_eq!(mgr.get_ssh_pub_key_file("alice"), Some(pub_key_path));
    }
}

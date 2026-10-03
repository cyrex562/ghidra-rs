//! Minimal placeholder traits for core types not yet ported, used to break
//! dependency cycles. Each placeholder is replaced by the real port later.

use std::io;

use thiserror::Error;

use crate::util::exception::DuplicateNameException;

/// Error produced by [`UserManagerLike::add_user`]/[`UserManagerLike::add_user_with_dn`],
/// standing in for the checked `DuplicateNameException`/`IOException` declared on
/// `UserManager.addUser`.
#[derive(Error, Debug)]
pub enum AddUserError {
    #[error(transparent)]
    Duplicate(#[from] DuplicateNameException),
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Placeholder for `ghidra.server.UserManager`, needed by
/// [`AuthenticationModule`](crate::server::security::AuthenticationModule),
/// [`RepositoryServerHandleImpl`](crate::server::remote::repository_server_handle_impl::RepositoryServerHandleImpl),
/// and [`CommandProcessor`](crate::server::command_processor)'s svrAdmin command handling.
///
/// `AuthenticationModule.authenticate` only ever receives this type to hand along to concrete
/// implementations (e.g. a password-file authentication module validates credentials against
/// it); the interface itself never calls a method on it. `RepositoryServerHandleImpl` calls
/// `canSetPassword`/`getPasswordExpiration`/`setPassword` directly on the `UserManager` returned
/// by `RepositoryManager.getUserManager()`. `CommandProcessor` additionally calls
/// `addUser`/`removeUser`/`resetPassword`/`isValidUser`/`setDistinguishedName` (its
/// `-add`/`-remove`/`-reset`/`-dn`/`-grant` svrAdmin commands), so those five are added here too.
/// A JDK `X500Principal` is represented as its plain distinguished-name string, since nothing in
/// this crate else models `javax.security.auth.x500` and the only operations `CommandProcessor`
/// performs on one are constructing it from a string and reading that string back.
pub trait UserManagerLike: Send + Sync {
    /// Returns true if local passwords are in use and can be changed by the given user.
    fn can_set_password(&self, username: &str) -> bool;

    /// Returns the amount of time in milliseconds until the user's password will expire, or -1
    /// if it will not expire.
    fn get_password_expiration(&self, username: &str) -> i64;

    /// Sets the password for the given user. `salted_sha256_password_hash` is a 4-character salt
    /// followed by a 64-hex-digit SHA256 password hash. Returns true if successful, false if the
    /// user was not found.
    fn set_password(
        &self,
        username: &str,
        salted_sha256_password_hash: &[u8],
        is_temporary: bool,
    ) -> io::Result<bool>;

    /// Adds a new user to the server access list with an optional password hash.
    ///
    /// Mirrors the package-private `UserManager.addUser(String, char[])`.
    fn add_user(
        &self,
        username: &str,
        salted_password_hash: Option<&[u8]>,
    ) -> Result<(), AddUserError>;

    /// Adds a new user to the server access list with an X500 distinguished name (PKI), and no
    /// local password.
    ///
    /// Mirrors `UserManager.addUser(String, X500Principal)`.
    fn add_user_with_dn(&self, username: &str, x500_user_dn: &str) -> Result<(), AddUserError>;

    /// Removes the specified user from the server access list. Returns true if an existing user
    /// was removed, false if not found.
    ///
    /// Mirrors `UserManager.removeUser(String)`.
    fn remove_user(&self, username: &str) -> io::Result<bool>;

    /// Resets the local password to the default for the specified user, or to
    /// `salted_password_hash` if given. Returns false if local passwords are not in use.
    ///
    /// Mirrors `UserManager.resetPassword(String, char[])`.
    fn reset_password(
        &self,
        username: &str,
        salted_password_hash: Option<&[u8]>,
    ) -> io::Result<bool>;

    /// Returns true if the specified user is known to the server.
    ///
    /// Mirrors `UserManager.isValidUser(String)`.
    fn is_valid_user(&self, username: &str) -> bool;

    /// Sets the X500 distinguished name for a user. Returns true if successful, false if the
    /// user was not found.
    ///
    /// Mirrors `UserManager.setDistinguishedName(String, X500Principal)`.
    fn set_distinguished_name(&self, username: &str, x500_user_dn: &str) -> io::Result<bool>;
}

/// Placeholder for `ghidra.server.stream.RemoteBlockStreamHandle`, needed by
/// [`BlockStreamServer`](crate::server::stream::BlockStreamServer).
///
/// The Java class is itself constructed with a live `BlockStreamServer` reference, so porting it
/// here would recreate the dependency cycle `BlockStreamServer` was extracted to break. A handle
/// only needs to expose its assigned stream ID and pending-connection state to the server's
/// registration bookkeeping (`registerBlockStream`), so this placeholder captures just those two
/// accessors until the real handle is ported.
pub trait RemoteBlockStreamHandleLike: Send + Sync {
    /// Get the unique ID for this stream.
    fn stream_id(&self) -> u64;

    /// Determine if a connection has not yet been requested for this handle.
    fn is_pending(&self) -> bool;
}

/// Placeholder for `ghidra.server.store.RepositoryFolder`, needed by
/// [`RepositoryFile`](crate::server::store::repository_file::RepositoryFile) before the real
/// class is ported.
///
/// The two Java classes form a direct dependency cycle: `RepositoryFolder` holds a `fileMap` of
/// `RepositoryFile`s and calls back into them, while `RepositoryFile.getParent()` returns its
/// owning `RepositoryFolder` and `RepositoryFile.moveTo()` takes a new `RepositoryFolder` as its
/// destination. `RepositoryFile` was selected as the cycle cut-point, so this placeholder captures
/// only the members `RepositoryFile` needs from its folder: the pathname (used to build its own
/// `getPathname()`, and to report old/new paths on a move) and the two package-private
/// notification callbacks (`fileDeleted`, `fileMoved`) a `RepositoryFile` implementation invokes
/// on its former parent after a delete or move completes.
pub trait RepositoryFolderLike: Send + Sync {
    /// Returns the folder's path within the repository.
    fn get_pathname(&self) -> String;

    /// Notifies this folder that the given file has been deleted, so it can be dropped from the
    /// folder's cached file map.
    fn file_deleted(&self, file: &dyn crate::server::store::repository_file::RepositoryFile);

    /// Notifies this folder that the given file (previously named `old_name`) has moved to
    /// `new_folder`, so it can be dropped from the folder's cached file map.
    fn file_moved(
        &self,
        file: &dyn crate::server::store::repository_file::RepositoryFile,
        old_name: &str,
        new_folder: &dyn RepositoryFolderLike,
    );
}

/// Placeholder for `ghidra.server.Repository`, needed by
/// [`RepositoryHandleImpl`](crate::server::remote::repository_handle_impl::RepositoryHandleImpl).
///
/// `Repository` holds an `ArrayList<RepositoryHandleImpl>` and calls `checkHandle`/
/// `dispatchEvents`/`dispose` directly on the concrete type, while `RepositoryHandleImpl` holds a
/// `Repository` field and calls back into it. `RepositoryHandleImpl` was selected as the cycle
/// cut-point, so this placeholder captures only the members reached through
/// `RepositoryHandleImpl::get_repository()` by its (not yet ported) sibling classes
/// `RemoteBufferFileImpl`/`RemoteManagedBufferFileImpl`: logging a message against an optional
/// folder/item path and user, and reading the repository's name. [`CommandProcessor`]'s svrAdmin
/// `GRANT_USER_COMMAND`/`REVOKE_USER_COMMAND` handling additionally needs
/// [`set_user_permission`](Self::set_user_permission)/[`remove_user`](Self::remove_user).
///
/// [`CommandProcessor`]: crate::server::command_processor
pub trait RepositoryLike: Send + Sync {
    /// Append a log entry associated with an optional folder/item path and optional user.
    fn log(&self, path: Option<&str>, msg: &str, user: Option<&str>);

    /// Returns the name of this repository.
    fn get_name(&self) -> String;

    /// Sets a user's permission level for this repository (`User.READ_ONLY`/`WRITE`/`ADMIN`).
    ///
    /// Mirrors `Repository.setUserPermission(String, int)`.
    fn set_user_permission(&self, username: &str, permission: i32);

    /// Removes a user's access to this repository.
    ///
    /// Mirrors `Repository.removeUser(String)`.
    fn remove_user(&self, username: &str);
}

// `ghidra.server.RepositoryManager`'s placeholder (`RepositoryManagerLike`) has been replaced by
// the real port at [`crate::server::repository_manager::RepositoryManager`].

/// Placeholder for `generic.hash.HashUtilities`, needed by
/// [`UserManager`](crate::server::user_manager::UserManager) for local password hashing.
///
/// `HashUtilities` is a concrete Java class (not an interface), so this is a plain statics
/// holder, not a `dyn`-dispatched trait. Only the salted-hash operations `UserManager` needs
/// are implemented (`getHash`/`getSaltedHash`/`hexDump`); the stream/file/list-hashing overloads
/// and `getRandomLetterOrDigit`'s package-private visibility are out of scope. Password bytes are
/// modeled as `&[u8]`/`Vec<u8>` rather than Java's `char[]`, matching the rest of this crate's
/// server-auth surface (see [`UserManagerLike`]).
pub struct HashUtilities;

impl HashUtilities {
    pub const MD5_ALGORITHM: &'static str = "MD5";
    pub const SHA256_ALGORITHM: &'static str = "SHA-256";
    pub const SALT_LENGTH: usize = 4;
    pub const MD5_UNSALTED_HASH_LENGTH: usize = 32;
    pub const MD5_SALTED_HASH_LENGTH: usize = Self::MD5_UNSALTED_HASH_LENGTH + Self::SALT_LENGTH;
    pub const SHA256_UNSALTED_HASH_LENGTH: usize = 64;
    pub const SHA256_SALTED_HASH_LENGTH: usize = Self::SHA256_UNSALTED_HASH_LENGTH + Self::SALT_LENGTH;

    /// Generate hash in a hex character representation, unsalted.
    ///
    /// Mirrors `HashUtilities.getHash(String, char[])`.
    pub fn get_hash(algorithm: &str, msg: &[u8]) -> Vec<u8> {
        Self::get_salted_hash(algorithm, &[], msg)
    }

    /// Generate salted hash for the specified message. The supplied salt is returned as a
    /// prefix to the returned hash.
    ///
    /// Mirrors `HashUtilities.getSaltedHash(String, char[], char[])`.
    ///
    /// # Panics
    /// Panics if `algorithm` is not `MD5_ALGORITHM`/`SHA256_ALGORITHM`, mirroring Java's
    /// unchecked `IllegalArgumentException` for an unsupported `MessageDigest` algorithm.
    pub fn get_salted_hash(algorithm: &str, salt: &[u8], msg: &[u8]) -> Vec<u8> {
        let mut msg_bytes = Vec::with_capacity(salt.len() + msg.len());
        msg_bytes.extend_from_slice(salt);
        msg_bytes.extend_from_slice(msg);
        let hash = Self::hex_dump(&Self::digest(algorithm, &msg_bytes));

        let mut salted_hash = Vec::with_capacity(salt.len() + hash.len());
        salted_hash.extend_from_slice(salt);
        salted_hash.extend_from_slice(&hash);
        salted_hash
    }

    /// Generate salted hash for the specified message using a random 4-character
    /// alphanumeric salt, returned as a prefix to the hash.
    ///
    /// Mirrors `HashUtilities.getSaltedHash(String, char[])`.
    pub fn get_salted_hash_random(algorithm: &str, msg: &[u8]) -> Vec<u8> {
        let salt: Vec<u8> = (0..Self::SALT_LENGTH).map(|_| Self::random_letter_or_digit()).collect();
        Self::get_salted_hash(algorithm, &salt, msg)
    }

    /// Mirrors the package-private `getRandomLetterOrDigit()`.
    fn random_letter_or_digit() -> u8 {
        let val = rand::random::<u32>() % 62; // 0-9,A-Z,a-z (10+26+26=62)
        if val < 10 {
            b'0' + val as u8
        }
        else if val < 36 {
            b'A' + (val - 10) as u8
        }
        else {
            b'a' + (val - 36) as u8
        }
    }

    fn digest(algorithm: &str, data: &[u8]) -> Vec<u8> {
        match algorithm {
            "MD5" => {
                use md5::{Digest, Md5};
                let mut hasher = Md5::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }
            "SHA-256" => {
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }
            other => panic!("Algorithm not supported: {other}"),
        }
    }

    /// Convert binary data to a sequence of lowercase hex characters.
    ///
    /// Mirrors `HashUtilities.hexDump(byte[])`.
    pub fn hex_dump(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(data.len() * 2);
        for b in data {
            out.extend_from_slice(format!("{b:02x}").as_bytes());
        }
        out
    }
}

// `ghidra.util.NumericUtilities` (needed by `UserManager` for `parseHexLong`) already has a
// placeholder at `crate::util::seam_stubs::NumericUtilities` -- reused directly rather than
// duplicating a second `NumericUtilities` here. A duplicate previously existed at
// `crate::app::seam_stubs::NumericUtilities`; it has been retired in favor of this canonical one.

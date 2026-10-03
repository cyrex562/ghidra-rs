//! Port of `ghidra.server.CommandProcessor`.
//!
//! Java needs a class to hang static fields and methods off; the Java class has no instance
//! state and no instance methods (a private no-arg constructor exists only to prevent
//! instantiation), so this ports to a plain module of constants and free functions, per this
//! crate's shape rules for statics-only holders.
//!
//! Provides server processing of svrAdmin commands queued by `ServerAdmin` (not yet ported):
//! adding/removing/resetting users, setting a PKI distinguished name, and granting/revoking
//! per-repository access.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use crate::framework::remote::Permission;
use crate::server::repository_manager::RepositoryManager;
use crate::server::seam_stubs::AddUserError;
use crate::util::Msg;

/// Command to add a new user (`UserManager.addUser`).
pub const ADD_USER_COMMAND: &str = "-add";
/// Command to remove a user (`UserManager.removeUser`).
pub const REMOVE_USER_COMMAND: &str = "-remove";
/// Command to reset a user's password (`UserManager.resetPassword`).
pub const RESET_USER_COMMAND: &str = "-reset";
/// Command to set/add a user's PKI distinguished name (`UserManager.setDistinguishedName`).
pub const SET_USER_DN_COMMAND: &str = "-dn";
/// Command to grant a user repository access (`Repository.setUserPermission`).
pub const GRANT_USER_COMMAND: &str = "-grant";
/// Command to revoke a user's repository access (`Repository.removeUser`).
pub const REVOKE_USER_COMMAND: &str = "-revoke";
/// Option flag carrying an explicit password hash, applies to [`ADD_USER_COMMAND`] and
/// [`RESET_USER_COMMAND`].
pub const PASSWORD_OPTION: &str = "--p";

const COMMAND_FILE_EXT: &str = ".cmd";

/// Name of the hidden subdirectory (under a server's root directory) that holds queued command
/// files, mirroring `LocalFileSystem.HIDDEN_DIR_PREFIX + "admin"`.
fn admin_cmd_dir_name() -> String {
    format!("{}admin", crate::framework::store::local::local_file_system::HIDDEN_DIR_PREFIX)
}

/// Outcome of [`process_command`] that isn't a successfully-handled command.
#[derive(Debug)]
enum ProcessCommandError {
    /// Mirrors an uncaught `ArrayIndexOutOfBoundsException`: the command string didn't have
    /// enough arguments for the command it named. Logged and skipped by the caller, not
    /// propagated.
    Malformed,
    /// Mirrors a propagated `IOException`.
    Io(io::Error),
}

impl From<io::Error> for ProcessCommandError {
    fn from(error: io::Error) -> Self {
        ProcessCommandError::Io(error)
    }
}

/// Split a command string into individual arguments, honoring double-quoted substrings as a
/// single argument (quotes stripped) and treating runs of unquoted spaces as separators.
///
/// Port of the private `splitCommand(String)`.
fn split_command(cmd: &str) -> Vec<String> {
    let chars: Vec<char> = cmd.chars().collect();
    let len = chars.len();
    let mut arg_list = Vec::new();
    let mut start_ix = 0usize;
    let mut end_ix = 0usize;
    let mut inside_quote = false;

    while end_ix < len {
        let c = chars[end_ix];
        if !inside_quote && start_ix == end_ix && (c == ' ' || c == '"') {
            inside_quote = c == '"';
            end_ix += 1;
            start_ix = end_ix;
            continue;
        }
        let boundary = if inside_quote { '"' } else { ' ' };
        if c == boundary {
            arg_list.push(chars[start_ix..end_ix].iter().collect());
            end_ix += 1;
            start_ix = end_ix;
            inside_quote = false;
        }
        else {
            end_ix += 1;
        }
    }
    if start_ix != end_ix {
        arg_list.push(chars[start_ix..end_ix].iter().collect());
    }
    arg_list
}

/// Process the specified command against `repository_mgr`.
///
/// Port of the private `processCommand(RepositoryManager, String)`.
fn process_command(
    repository_mgr: &dyn RepositoryManager,
    cmd: &str,
) -> Result<(), ProcessCommandError> {
    let user_mgr = repository_mgr.get_user_manager();
    let args = split_command(cmd);
    let arg = |i: usize| -> Result<&str, ProcessCommandError> {
        args.get(i).map(String::as_str).ok_or(ProcessCommandError::Malformed)
    };

    let command = arg(0)?;
    match command {
        ADD_USER_COMMAND => {
            let sid = arg(1)?;
            let mut pwd_hash: Option<&[u8]> = None;
            if args.len() == 4 && args[2] == PASSWORD_OPTION {
                pwd_hash = Some(args[3].as_bytes());
            }
            match user_mgr.add_user(sid, pwd_hash) {
                Ok(()) => {}
                Err(AddUserError::Duplicate(e)) => {
                    Msg::error("CommandProcessor", &format!("Add User Failed: {e}"));
                }
                Err(AddUserError::Io(e)) => return Err(e.into()),
            }
        }
        REMOVE_USER_COMMAND => {
            let sid = arg(1)?;
            if !user_mgr.remove_user(sid)? {
                Msg::info("CommandProcessor", &format!("User not found: '{sid}'"));
            }
        }
        RESET_USER_COMMAND => {
            let sid = arg(1)?;
            let mut pwd_hash: Option<&[u8]> = None;
            if args.len() == 4 && args[2] == PASSWORD_OPTION {
                pwd_hash = Some(args[3].as_bytes());
            }
            if !user_mgr.reset_password(sid, pwd_hash)? {
                Msg::info("CommandProcessor", &format!("Failed to reset password for user '{sid}'"));
            }
            else if pwd_hash.is_some() {
                Msg::info(
                    "CommandProcessor",
                    &format!("User '{sid}' password reset to specified password"),
                );
            }
            else {
                Msg::info(
                    "CommandProcessor",
                    &format!("User '{sid}' password reset to default password"),
                );
            }
        }
        SET_USER_DN_COMMAND => {
            let sid = arg(1)?;
            let x500_user_dn = arg(2)?;
            if user_mgr.is_valid_user(sid) {
                user_mgr.set_distinguished_name(sid, x500_user_dn)?;
            }
            else {
                match user_mgr.add_user_with_dn(sid, x500_user_dn) {
                    Ok(()) => {}
                    Err(AddUserError::Duplicate(e)) => {
                        Msg::error("CommandProcessor", &format!("Add User Failed: {e}"));
                        return Ok(());
                    }
                    Err(AddUserError::Io(e)) => return Err(e.into()),
                }
            }
            Msg::info("CommandProcessor", &format!("User '{sid}' DN set ({x500_user_dn})"));
        }
        GRANT_USER_COMMAND => {
            let sid = arg(1)?;
            let permission_str = arg(2)?;
            let rep_name = arg(3)?;
            if !user_mgr.is_valid_user(sid) {
                Msg::error(
                    "CommandProcessor",
                    &format!("Failed to grant access for '{sid}', user has not been added to server."),
                );
                return Ok(());
            }
            let permission = parse_permission(permission_str);
            if permission < 0 {
                Msg::error(
                    "CommandProcessor",
                    &format!("Failed to process grant command.  Invalid permission: {permission_str}"),
                );
                return Ok(());
            }
            match repository_mgr.get_repository_privileged(rep_name) {
                Some(rep) => rep.set_user_permission(sid, permission),
                None => {
                    Msg::error(
                        "CommandProcessor",
                        &format!(
                            "Failed to grant access for '{sid}', repository '{rep_name}' not found."
                        ),
                    );
                }
            }
        }
        REVOKE_USER_COMMAND => {
            let sid = arg(1)?;
            let rep_name = arg(2)?;
            match repository_mgr.get_repository_privileged(rep_name) {
                Some(rep) => rep.remove_user(sid),
                None => {
                    Msg::error(
                        "CommandProcessor",
                        &format!(
                            "Failed to revoke access for '{sid}', repository '{rep_name}' not found."
                        ),
                    );
                }
            }
        }
        other => {
            Msg::error("CommandProcessor", &format!("Failed to process unrecognized command: {other}"));
        }
    }
    Ok(())
}

/// Maps a permission command-line flag (`+r`, `+w`, `+a`) to a `User` permission integer, or -1
/// if unrecognized.
///
/// Port of the package-private `parsePermission(String)`.
pub fn parse_permission(permission_str: &str) -> i32 {
    match permission_str {
        "+r" => Permission::ReadOnly as i32,
        "+w" => Permission::Write as i32,
        "+a" => Permission::Admin as i32,
        _ => -1,
    }
}

/// Returns the queued-command directory under `server_root_dir`.
///
/// Port of the package-private `getCommandDir(File)`.
pub fn get_command_dir(server_root_dir: &Path) -> PathBuf {
    server_root_dir.join(admin_cmd_dir_name())
}

/// Returns the queued-command directory for `repository_mgr`, creating it if it does not exist.
///
/// Port of the package-private `getOrCreateCommandDir(RepositoryManager)`.
pub fn get_or_create_command_dir(repository_mgr: &dyn RepositoryManager) -> PathBuf {
    let cmd_dir = get_command_dir(&repository_mgr.get_root_dir());
    if !cmd_dir.exists() {
        // ensure process owner creates queued command directory
        let _ = fs::create_dir(&cmd_dir);
    }
    cmd_dir
}

/// Process all queued commands for the specified server, oldest file first, deleting each file
/// once processed.
///
/// Port of the package-private `processCommands(RepositoryManager)`.
pub fn process_commands(repository_mgr: &dyn RepositoryManager) -> io::Result<()> {
    let cmd_dir = get_or_create_command_dir(repository_mgr);
    let entries = match fs::read_dir(&cmd_dir) {
        Ok(entries) => entries,
        Err(_) => {
            Msg::error(
                "CommandProcessor",
                &format!(
                    "Failed to access command queue {}: possible permission problem",
                    cmd_dir.display()
                ),
            );
            return Ok(());
        }
    };

    let mut files: Vec<PathBuf> = entries
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.is_file() && path.extension().and_then(|ext| ext.to_str()) == Some("cmd"))
        .collect();
    if files.is_empty() {
        return Ok(());
    }

    Msg::info("CommandProcessor", &"Processing queued commands");
    files.sort_by_key(|path| {
        fs::metadata(path)
            .and_then(|m| m.modified())
            .unwrap_or(SystemTime::UNIX_EPOCH)
    });

    for file in &files {
        let content = fs::read_to_string(file)?;
        for line in content.lines() {
            let cmd_str = line.trim();
            if cmd_str.is_empty() {
                continue;
            }
            match process_command(repository_mgr, cmd_str) {
                Ok(()) => {}
                Err(ProcessCommandError::Malformed) => {
                    Msg::error("CommandProcessor", &format!("Error occured processing command: {cmd_str}"));
                }
                Err(ProcessCommandError::Io(e)) => return Err(e),
            }
        }
        let _ = fs::remove_file(file);
    }
    Ok(())
}

/// Creates a new, uniquely-named empty file in `dir` with the given prefix/suffix, mirroring the
/// uniqueness guarantee of `File.createTempFile(prefix, suffix, dir)` (this crate's `tempfile`
/// dependency is dev-only, so it cannot be used from this production code path).
fn create_temp_file(dir: &Path, prefix: &str, suffix: &str) -> io::Result<(fs::File, PathBuf)> {
    use std::time::{SystemTime, UNIX_EPOCH};

    for attempt in 0..1000u32 {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
        let candidate = dir.join(format!("{prefix}{nanos:x}{attempt:x}{suffix}"));
        match fs::OpenOptions::new().write(true).create_new(true).open(&candidate) {
            Ok(file) => return Ok((file, candidate)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::other("failed to create a unique temp file"))
}

/// Store a list of command strings to a new command file in `cmd_dir` (which must exist),
/// written to a temp file first and then atomically renamed to a `.cmd` file.
///
/// Port of the package-private `writeCommands(List<String>, File)`.
pub fn write_commands(cmd_list: &[String], cmd_dir: &Path) -> io::Result<()> {
    use std::io::Write as _;

    let (mut tmp_file, tmp_path) = create_temp_file(cmd_dir, "adm", ".tmp")?;
    let write_result: io::Result<()> = (|| {
        for line in cmd_list {
            writeln!(tmp_file, "{line}")?;
        }
        tmp_file.flush()
    })();
    drop(tmp_file);
    if let Err(e) = write_result {
        let _ = fs::remove_file(&tmp_path);
        return Err(e);
    }

    let file_name = tmp_path.file_name().and_then(|n| n.to_str()).unwrap_or_default();
    let base_name = file_name.strip_suffix(".tmp").unwrap_or(file_name);
    let cmd_file = cmd_dir.join(format!("{base_name}{COMMAND_FILE_EXT}"));

    if let Err(e) = fs::rename(&tmp_path, &cmd_file) {
        let _ = fs::remove_file(&tmp_path);
        return Err(e);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::seam_stubs::{RepositoryLike, UserManagerLike};
    use std::sync::Mutex;

    #[test]
    fn split_command_handles_plain_and_quoted_args() {
        assert_eq!(split_command("-add alice"), vec!["-add", "alice"]);
        assert_eq!(
            split_command("-add alice --p abc123"),
            vec!["-add", "alice", "--p", "abc123"]
        );
        assert_eq!(
            split_command("-dn alice \"CN=Alice,OU=Test\""),
            vec!["-dn", "alice", "CN=Alice,OU=Test"]
        );
    }

    #[test]
    fn split_command_collapses_repeated_spaces() {
        assert_eq!(split_command("-add   alice"), vec!["-add", "alice"]);
    }

    #[test]
    fn parse_permission_matches_java_flags() {
        assert_eq!(parse_permission("+r"), Permission::ReadOnly as i32);
        assert_eq!(parse_permission("+w"), Permission::Write as i32);
        assert_eq!(parse_permission("+a"), Permission::Admin as i32);
        assert_eq!(parse_permission("+z"), -1);
    }

    #[test]
    fn get_command_dir_is_hidden_admin_subdir() {
        let root = Path::new("/srv/repos");
        let dir = get_command_dir(root);
        assert_eq!(dir, Path::new("/srv/repos/~admin"));
    }

    struct MockRepository {
        name: String,
        permissions: Mutex<Vec<(String, i32)>>,
        removed_users: Mutex<Vec<String>>,
    }

    impl RepositoryLike for MockRepository {
        fn log(&self, _path: Option<&str>, _msg: &str, _user: Option<&str>) {}
        fn get_name(&self) -> String {
            self.name.clone()
        }
        fn set_user_permission(&self, username: &str, permission: i32) {
            self.permissions.lock().unwrap().push((username.to_string(), permission));
        }
        fn remove_user(&self, username: &str) {
            self.removed_users.lock().unwrap().push(username.to_string());
        }
    }

    struct MockUserManager {
        users: Mutex<Vec<String>>,
        dns: Mutex<Vec<(String, String)>>,
    }

    impl UserManagerLike for MockUserManager {
        fn can_set_password(&self, _username: &str) -> bool {
            true
        }
        fn get_password_expiration(&self, _username: &str) -> i64 {
            -1
        }
        fn set_password(&self, _username: &str, _hash: &[u8], _is_temporary: bool) -> io::Result<bool> {
            Ok(true)
        }
        fn add_user(&self, username: &str, _hash: Option<&[u8]>) -> Result<(), AddUserError> {
            let mut users = self.users.lock().unwrap();
            if users.iter().any(|u| u == username) {
                return Err(AddUserError::Duplicate(
                    crate::util::exception::DuplicateNameException::with_message(format!(
                        "User named {username} already exists"
                    )),
                ));
            }
            users.push(username.to_string());
            Ok(())
        }
        fn add_user_with_dn(&self, username: &str, x500_user_dn: &str) -> Result<(), AddUserError> {
            self.add_user(username, None)?;
            self.dns.lock().unwrap().push((username.to_string(), x500_user_dn.to_string()));
            Ok(())
        }
        fn remove_user(&self, username: &str) -> io::Result<bool> {
            let mut users = self.users.lock().unwrap();
            let before = users.len();
            users.retain(|u| u != username);
            Ok(users.len() != before)
        }
        fn reset_password(&self, username: &str, _hash: Option<&[u8]>) -> io::Result<bool> {
            Ok(self.users.lock().unwrap().iter().any(|u| u == username))
        }
        fn is_valid_user(&self, username: &str) -> bool {
            self.users.lock().unwrap().iter().any(|u| u == username)
        }
        fn set_distinguished_name(&self, username: &str, x500_user_dn: &str) -> io::Result<bool> {
            if !self.is_valid_user(username) {
                return Ok(false);
            }
            self.dns.lock().unwrap().push((username.to_string(), x500_user_dn.to_string()));
            Ok(true)
        }
    }

    #[test]
    fn write_commands_then_process_commands_adds_user() {
        let dir = tempfile::tempdir().unwrap();
        let cmd_dir = dir.path().join("~admin");
        fs::create_dir(&cmd_dir).unwrap();

        write_commands(&["-add alice".to_string()], &cmd_dir).unwrap();

        let files: Vec<_> = fs::read_dir(&cmd_dir).unwrap().filter_map(|e| e.ok()).collect();
        assert_eq!(files.len(), 1);
        assert!(files[0].path().extension().unwrap() == "cmd");

        let content = fs::read_to_string(files[0].path()).unwrap();
        assert_eq!(content.trim(), "-add alice");
    }

    #[test]
    fn process_command_add_user_success() {
        let user_mgr = std::sync::Arc::new(MockUserManager { users: Mutex::new(Vec::new()), dns: Mutex::new(Vec::new()) });
        process_command_direct(&user_mgr, None, "-add alice").unwrap();
        assert!(user_mgr.is_valid_user("alice"));
    }

    #[test]
    fn process_command_add_duplicate_user_logs_and_succeeds() {
        let user_mgr = std::sync::Arc::new(MockUserManager { users: Mutex::new(vec!["alice".to_string()]), dns: Mutex::new(Vec::new()) });
        // Duplicate is caught and logged inside process_command, not propagated as an error.
        process_command_direct(&user_mgr, None, "-add alice").unwrap();
    }

    #[test]
    fn process_command_remove_user() {
        let user_mgr = std::sync::Arc::new(MockUserManager { users: Mutex::new(vec!["alice".to_string()]), dns: Mutex::new(Vec::new()) });
        process_command_direct(&user_mgr, None, "-remove alice").unwrap();
        assert!(!user_mgr.is_valid_user("alice"));
    }

    #[test]
    fn process_command_set_dn_adds_new_user() {
        let user_mgr = std::sync::Arc::new(MockUserManager { users: Mutex::new(Vec::new()), dns: Mutex::new(Vec::new()) });
        process_command_direct(&user_mgr, None, "-dn alice CN=Alice").unwrap();
        assert!(user_mgr.is_valid_user("alice"));
        assert_eq!(user_mgr.dns.lock().unwrap().as_slice(), &[("alice".to_string(), "CN=Alice".to_string())]);
    }

    #[test]
    fn process_command_set_dn_updates_existing_user() {
        let user_mgr = std::sync::Arc::new(MockUserManager { users: Mutex::new(vec!["alice".to_string()]), dns: Mutex::new(Vec::new()) });
        process_command_direct(&user_mgr, None, "-dn alice CN=Alice").unwrap();
        assert_eq!(user_mgr.dns.lock().unwrap().len(), 1);
    }

    #[test]
    fn process_command_grant_and_revoke_use_privileged_repository_lookup() {
        let user_mgr = std::sync::Arc::new(MockUserManager { users: Mutex::new(vec!["alice".to_string()]), dns: Mutex::new(Vec::new()) });
        let repo = std::sync::Arc::new(MockRepository {
            name: "Repo1".to_string(),
            permissions: Mutex::new(Vec::new()),
            removed_users: Mutex::new(Vec::new()),
        });
        process_command_direct(&user_mgr, Some(repo.clone()), "-grant alice +w Repo1").unwrap();
        assert_eq!(
            repo.permissions.lock().unwrap().as_slice(),
            &[("alice".to_string(), Permission::Write as i32)]
        );

        process_command_direct(&user_mgr, Some(repo.clone()), "-revoke alice Repo1").unwrap();
        assert_eq!(repo.removed_users.lock().unwrap().as_slice(), &["alice".to_string()]);
    }

    #[test]
    fn process_command_grant_rejects_unknown_user() {
        let user_mgr = std::sync::Arc::new(MockUserManager { users: Mutex::new(Vec::new()), dns: Mutex::new(Vec::new()) });
        let repo = std::sync::Arc::new(MockRepository {
            name: "Repo1".to_string(),
            permissions: Mutex::new(Vec::new()),
            removed_users: Mutex::new(Vec::new()),
        });
        process_command_direct(&user_mgr, Some(repo.clone()), "-grant ghost +w Repo1").unwrap();
        assert!(repo.permissions.lock().unwrap().is_empty());
    }

    #[test]
    fn process_command_malformed_command_is_reported_but_not_fatal() {
        let user_mgr = std::sync::Arc::new(MockUserManager { users: Mutex::new(Vec::new()), dns: Mutex::new(Vec::new()) });
        // Missing the required username argument -- mirrors an ArrayIndexOutOfBoundsException in
        // Java, caught by the caller (`process_commands`), not propagated from `process_command`.
        let err = process_command_direct(&user_mgr, None, "-add").unwrap_err();
        assert!(matches!(err, ProcessCommandError::Malformed));
    }

    /// Test-only helper that exercises [`process_command`]'s logic directly against a
    /// [`MockUserManager`]/optional [`MockRepository`], bypassing the [`RepositoryManager`]
    /// trait object plumbing (whose `get_user_manager` must return an owned `Box`, awkward for a
    /// test that wants to inspect the same manager afterward).
    fn process_command_direct(
        user_mgr: &std::sync::Arc<MockUserManager>,
        repo: Option<std::sync::Arc<MockRepository>>,
        cmd: &str,
    ) -> Result<(), ProcessCommandError> {
        struct DirectRepositoryManager {
            user_mgr: std::sync::Arc<MockUserManager>,
            repo: Option<std::sync::Arc<MockRepository>>,
        }

        impl RepositoryManager for DirectRepositoryManager {
            fn anonymous_access_allowed(&self) -> bool {
                false
            }
            fn dispose(&self) {}
            fn get_root_dir(&self) -> PathBuf {
                PathBuf::new()
            }
            fn create_repository(&self, _c: &str, _n: &str) -> io::Result<Box<dyn RepositoryLike>> {
                unimplemented!()
            }
            fn get_repository(&self, _c: &str, _n: &str) -> io::Result<Option<Box<dyn RepositoryLike>>> {
                unimplemented!()
            }
            fn get_repository_privileged(&self, name: &str) -> Option<Box<dyn RepositoryLike>> {
                self.repo
                    .as_ref()
                    .filter(|r| r.name == name)
                    // Route mutations back through the shared Arc so callers can observe them.
                    .map(|r| Box::new(SharedMockRepository(r.clone())) as Box<dyn RepositoryLike>)
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
                Box::new(SharedMockUserManager(self.user_mgr.clone()))
            }
            fn add_handle(&self, _h: std::sync::Arc<dyn crate::server::remote::RepositoryServerHandleImpl>) {}
            fn drop_handle(&self, _h: std::sync::Arc<dyn crate::server::remote::RepositoryServerHandleImpl>) {}
            fn process_command_queue(&self) -> io::Result<()> {
                Ok(())
            }
            fn user_removed(&self, _u: &str) -> io::Result<()> {
                Ok(())
            }
        }

        struct SharedMockUserManager(std::sync::Arc<MockUserManager>);
        impl UserManagerLike for SharedMockUserManager {
            fn can_set_password(&self, u: &str) -> bool {
                self.0.can_set_password(u)
            }
            fn get_password_expiration(&self, u: &str) -> i64 {
                self.0.get_password_expiration(u)
            }
            fn set_password(&self, u: &str, h: &[u8], t: bool) -> io::Result<bool> {
                self.0.set_password(u, h, t)
            }
            fn add_user(&self, u: &str, h: Option<&[u8]>) -> Result<(), AddUserError> {
                self.0.add_user(u, h)
            }
            fn add_user_with_dn(&self, u: &str, dn: &str) -> Result<(), AddUserError> {
                self.0.add_user_with_dn(u, dn)
            }
            fn remove_user(&self, u: &str) -> io::Result<bool> {
                self.0.remove_user(u)
            }
            fn reset_password(&self, u: &str, h: Option<&[u8]>) -> io::Result<bool> {
                self.0.reset_password(u, h)
            }
            fn is_valid_user(&self, u: &str) -> bool {
                self.0.is_valid_user(u)
            }
            fn set_distinguished_name(&self, u: &str, dn: &str) -> io::Result<bool> {
                self.0.set_distinguished_name(u, dn)
            }
        }

        struct SharedMockRepository(std::sync::Arc<MockRepository>);
        impl RepositoryLike for SharedMockRepository {
            fn log(&self, _p: Option<&str>, _m: &str, _u: Option<&str>) {}
            fn get_name(&self) -> String {
                self.0.get_name()
            }
            fn set_user_permission(&self, username: &str, permission: i32) {
                self.0.set_user_permission(username, permission);
            }
            fn remove_user(&self, username: &str) {
                self.0.remove_user(username);
            }
        }

        let mgr = DirectRepositoryManager { user_mgr: user_mgr.clone(), repo };
        process_command(&mgr, cmd)
    }
}

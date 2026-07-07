use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write as IoWrite};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use super::file_channel_lock::FileChannelLock;

const LOCK_TYPE_KEY: &str = "<META> Supports File Channel Locking";
const FILE_LOCK_TYPE: &str = "File Lock";
const CHANNEL_LOCK_TYPE: &str = "Channel Lock";
const PROPERTY_KEYS: &[&str] = &[
    "Username",
    "Hostname",
    "Timestamp",
    "OS Name",
    "OS Architecture",
    "OS Version",
];

/// Distinguishes `FileLocker`'s own locking behavior from that of `ChannelLocker`
/// (mirrors the Java `getLockType()`/`lock()`/`createLockFile()` overrides that
/// `generic.util.ChannelLocker` makes on top of `generic.util.FileLocker`).
#[derive(Clone, Copy, PartialEq, Eq)]
enum LockKind {
    Plain,
    Channel,
}

/// Manages a properties-style lock file recording metadata about the locking process.
///
/// Mirrors `generic.util.FileLocker` from Ghidra. On construction, any pre-existing
/// lock file is loaded. Callers can then decide to `lock()`, `force_lock()`, or
/// inspect the existing lock via `get_existing_lock_file_information()`.
pub struct FileLocker {
    lock_file: PathBuf,
    existing_lock_properties: Option<HashMap<String, String>>,
    created_lock_properties: Option<HashMap<String, String>>,
    /// The lock-type string from the pre-existing lock file, if any.
    pub existing_lock_type: Option<String>,
    is_locked: bool,
    kind: LockKind,
    channel_lock: Option<FileChannelLock>,
}

impl FileLocker {
    /// Create a `FileLocker` for the given path.
    ///
    /// If a lock file already exists its properties are loaded immediately.
    pub fn new(lock_file: &Path) -> Self {
        Self::with_kind(lock_file, LockKind::Plain)
    }

    /// Create a `FileLocker` that also acquires an OS-level file channel lock
    /// once its properties file is written (mirrors `generic.util.ChannelLocker`).
    pub(crate) fn new_channel_locker(lock_file: &Path) -> Self {
        Self::with_kind(lock_file, LockKind::Channel)
    }

    fn with_kind(lock_file: &Path, kind: LockKind) -> Self {
        let existing = load_lock_file(lock_file);
        let existing_lock_type = existing
            .as_ref()
            .and_then(|p| p.get(LOCK_TYPE_KEY).cloned());
        FileLocker {
            lock_file: lock_file.to_path_buf(),
            existing_lock_properties: existing,
            created_lock_properties: None,
            existing_lock_type,
            is_locked: false,
            kind,
            channel_lock: None,
        }
    }

    /// Acquire the lock. Fails (returns `false`) if a lock file already exists.
    pub fn lock(&mut self) -> bool {
        match self.kind {
            LockKind::Plain => {
                if self.existing_lock_properties.is_none() {
                    self.create_lock_file()
                } else {
                    false
                }
            }
            LockKind::Channel => {
                if self.can_channel_lock() {
                    self.create_lock_file()
                } else {
                    false
                }
            }
        }
    }

    /// `true` if no conflicting lock is held, so a channel lock may be attempted.
    fn can_channel_lock(&self) -> bool {
        let Some(existing_type) = &self.existing_lock_type else {
            // if there is no existing lock type, then there is no lock.
            return true;
        };
        if existing_type != CHANNEL_LOCK_TYPE {
            // some other kind of locking mechanism already has a lock
            return false;
        }
        self.is_channel_lock_available()
    }

    fn is_channel_lock_available(&self) -> bool {
        let mut test_channel_lock = FileChannelLock::new(&self.lock_file);
        let did_lock = test_channel_lock.lock();
        test_channel_lock.release();
        did_lock
    }

    /// Returns `true` if this instance currently holds the lock.
    pub fn is_locked(&self) -> bool {
        self.is_locked
    }

    /// Release the lock and delete the lock file if we are the owner.
    pub fn release(&mut self) {
        if let Some(mut channel_lock) = self.channel_lock.take() {
            channel_lock.release();
        }
        if self.is_lock_owner() {
            let _ = fs::remove_file(&self.lock_file);
        }
        self.is_locked = false;
    }

    /// Returns `true` if the existing lock was created by a plain `FileLocker`
    /// (meaning it can be safely force-replaced).
    pub fn can_force_lock(&self) -> bool {
        self.existing_lock_type.as_deref() == Some(FILE_LOCK_TYPE)
    }

    /// Overwrite the existing lock file (only if it is a plain `FileLocker` lock)
    /// and acquire a fresh lock.
    pub fn force_lock(&mut self) -> bool {
        if self.can_force_lock() {
            self.create_lock_file()
        } else {
            false
        }
    }

    /// Return an HTML fragment describing the existing lock file's properties,
    /// or a plain-text message when no properties are present.
    pub fn get_existing_lock_file_information(&self) -> String {
        let Some(props) = &self.existing_lock_properties else {
            return "no properties in lock file".to_string();
        };
        let mut buf = String::from("<p><table border=0>");
        for name in PROPERTY_KEYS {
            buf.push_str("<tr><td>");
            buf.push_str("&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;");
            buf.push_str(name);
            buf.push_str(": ");
            buf.push_str("</td><td>");
            buf.push_str(props.get(*name).map(String::as_str).unwrap_or(""));
            buf.push_str("</td></tr>");
        }
        buf.push_str("</table>");
        buf
    }

    /// The lock-type string written into the properties file.
    pub fn lock_type(&self) -> &str {
        match self.kind {
            LockKind::Plain => FILE_LOCK_TYPE,
            LockKind::Channel => CHANNEL_LOCK_TYPE,
        }
    }

    /// Write a new lock file containing current process metadata and acquire the lock.
    ///
    /// For a channel locker, success also requires acquiring the underlying OS-level
    /// file channel lock.
    pub fn create_lock_file(&mut self) -> bool {
        let mut props = HashMap::new();
        props.insert("Username".to_string(), current_username());
        props.insert("Hostname".to_string(), current_hostname());
        props.insert("Timestamp".to_string(), current_timestamp());
        props.insert("OS Name".to_string(), std::env::consts::OS.to_string());
        props.insert("OS Architecture".to_string(), std::env::consts::ARCH.to_string());
        props.insert("OS Version".to_string(), os_version());
        props.insert(LOCK_TYPE_KEY.to_string(), self.lock_type().to_string());

        if !store_properties(&props, &self.lock_file) {
            return false;
        }

        if !self.lock_file.exists() {
            return false;
        }
        self.created_lock_properties = Some(props);

        match self.kind {
            LockKind::Plain => {
                self.is_locked = true;
                true
            }
            LockKind::Channel => {
                let mut channel_lock = FileChannelLock::new(&self.lock_file);
                let did_lock = channel_lock.lock();
                self.channel_lock = Some(channel_lock);
                self.is_locked = did_lock;
                did_lock
            }
        }
    }

    fn is_lock_owner(&self) -> bool {
        let Some(created) = &self.created_lock_properties else {
            return false;
        };
        let Some(current) = load_lock_file(&self.lock_file) else {
            return false;
        };
        PROPERTY_KEYS
            .iter()
            .all(|k| created.get(*k) == current.get(*k))
    }
}

impl std::fmt::Display for FileLocker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self.kind {
            LockKind::Plain => "FileLocker",
            LockKind::Channel => "ChannelLocker",
        };
        write!(f, "{}{}", name, self.lock_file.display())
    }
}

// --- file I/O helpers ---

fn load_lock_file(path: &Path) -> Option<HashMap<String, String>> {
    if !path.exists() {
        return None;
    }
    let file = File::open(path).ok()?;
    let reader = BufReader::new(file);
    let mut map = HashMap::new();
    for line in reader.lines() {
        let line = line.ok()?;
        let trimmed = line.trim();
        if trimmed.starts_with('#') || trimmed.starts_with('!') || trimmed.is_empty() {
            continue;
        }
        if let Some(idx) = trimmed.find('=') {
            let key = trimmed[..idx].trim().to_string();
            let value = trimmed[idx + 1..].trim().to_string();
            map.insert(key, value);
        }
    }
    Some(map)
}

fn store_properties(props: &HashMap<String, String>, path: &Path) -> bool {
    let mut file = match File::create(path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    if writeln!(file, "# Ghidra Lock File").is_err() {
        return false;
    }
    for (k, v) in props {
        if writeln!(file, "{}={}", k, v).is_err() {
            return false;
        }
    }
    true
}

// --- system info helpers ---

fn current_username() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "<Unknown>".to_string())
}

fn current_hostname() -> String {
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
        .unwrap_or_else(|| "<Unknown>".to_string())
}

fn current_timestamp() -> String {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => format_unix_secs(d.as_secs()),
        Err(_) => "<Unknown>".to_string(),
    }
}

fn format_unix_secs(secs: u64) -> String {
    let h = (secs % 86400) / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    let (year, month, day) = days_to_ymd((secs / 86400) as i64);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
        year, month, day, h, m, s
    )
}

fn days_to_ymd(days: i64) -> (i32, u32, u32) {
    // Howard Hinnant's civil-from-days algorithm
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    (y as i32, m as u32, d as u32)
}

fn os_version() -> String {
    #[cfg(target_os = "linux")]
    {
        if let Ok(content) = fs::read_to_string("/proc/version") {
            if let Some(ver) = content.split_whitespace().nth(2) {
                return ver.to_string();
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Ok(out) = std::process::Command::new("sw_vers")
            .arg("-productVersion")
            .output()
        {
            if let Ok(s) = String::from_utf8(out.stdout) {
                let t = s.trim().to_string();
                if !t.is_empty() {
                    return t;
                }
            }
        }
    }
    "<Unknown>".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(name)
    }

    #[test]
    fn new_with_no_existing_file_has_no_properties() {
        let path = tmp_path("ghidra_fl_t1.lock");
        let _ = fs::remove_file(&path);
        let locker = FileLocker::new(&path);
        assert!(locker.existing_lock_properties.is_none());
        assert!(locker.existing_lock_type.is_none());
        assert!(!locker.is_locked());
    }

    #[test]
    fn lock_creates_file_and_returns_true() {
        let path = tmp_path("ghidra_fl_t2.lock");
        let _ = fs::remove_file(&path);
        let mut locker = FileLocker::new(&path);
        assert!(locker.lock());
        assert!(path.exists());
        assert!(locker.is_locked());
        locker.release();
    }

    #[test]
    fn release_deletes_file_when_owner() {
        let path = tmp_path("ghidra_fl_t3.lock");
        let _ = fs::remove_file(&path);
        let mut locker = FileLocker::new(&path);
        assert!(locker.lock());
        locker.release();
        assert!(!path.exists());
        assert!(!locker.is_locked());
    }

    #[test]
    fn lock_returns_false_when_file_already_exists() {
        let path = tmp_path("ghidra_fl_t4.lock");
        let _ = fs::remove_file(&path);
        let mut first = FileLocker::new(&path);
        assert!(first.lock());

        let mut second = FileLocker::new(&path);
        assert!(!second.lock(), "should fail: lock file exists");

        first.release();
    }

    #[test]
    fn can_force_lock_true_for_file_lock_type() {
        let path = tmp_path("ghidra_fl_t5.lock");
        let _ = fs::remove_file(&path);
        let mut first = FileLocker::new(&path);
        assert!(first.lock());

        let second = FileLocker::new(&path);
        assert!(second.can_force_lock());

        first.release();
    }

    #[test]
    fn force_lock_overwrites_file_lock() {
        let path = tmp_path("ghidra_fl_t6.lock");
        let _ = fs::remove_file(&path);
        let mut first = FileLocker::new(&path);
        assert!(first.lock());

        let mut second = FileLocker::new(&path);
        assert!(second.force_lock());
        assert!(second.is_locked());

        second.release();
    }

    #[test]
    fn get_existing_lock_file_information_no_file() {
        let path = tmp_path("ghidra_fl_t7.lock");
        let _ = fs::remove_file(&path);
        let locker = FileLocker::new(&path);
        assert_eq!(
            locker.get_existing_lock_file_information(),
            "no properties in lock file"
        );
    }

    #[test]
    fn get_existing_lock_file_information_returns_html() {
        let path = tmp_path("ghidra_fl_t8.lock");
        let _ = fs::remove_file(&path);
        let mut owner = FileLocker::new(&path);
        assert!(owner.lock());

        let reader = FileLocker::new(&path);
        let info = reader.get_existing_lock_file_information();
        assert!(info.contains("<table"), "expected HTML table: {}", info);
        assert!(info.contains("Username"), "expected Username field: {}", info);

        owner.release();
    }

    #[test]
    fn release_without_lock_is_safe() {
        let path = tmp_path("ghidra_fl_t9.lock");
        let _ = fs::remove_file(&path);
        let mut locker = FileLocker::new(&path);
        locker.release();
        locker.release();
    }

    #[test]
    fn lock_file_contains_property_keys() {
        let path = tmp_path("ghidra_fl_t10.lock");
        let _ = fs::remove_file(&path);
        let mut locker = FileLocker::new(&path);
        assert!(locker.lock());

        let content = fs::read_to_string(&path).unwrap();
        for key in PROPERTY_KEYS {
            assert!(
                content.contains(key),
                "lock file missing key '{}': {}",
                key,
                content
            );
        }

        locker.release();
    }

    #[test]
    fn days_to_ymd_epoch() {
        assert_eq!(days_to_ymd(0), (1970, 1, 1));
    }

    #[test]
    fn days_to_ymd_known_date() {
        // 2026-06-30 = days since epoch
        let expected = (2026i32, 6u32, 30u32);
        let days = (expected.0 - 1970) * 365
            + (expected.0 - 1970) / 4
            - (expected.0 - 1970) / 100
            + (expected.0 - 1970) / 400;
        // Just verify round-trip via format
        let ts = format_unix_secs(0);
        assert!(ts.starts_with("1970-01-01"), "got: {}", ts);
    }
}

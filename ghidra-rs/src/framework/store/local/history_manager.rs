//! Port of `ghidra.framework.store.local.HistoryManager`.

use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Write};
use std::path::PathBuf;

use crate::framework::store::local::local_file_system::is_refresh_required;
use crate::framework::store::ItemVersion;

/// File name (within an item's data directory) used to store version history data.
pub const HISTORY_FILE: &str = "history.dat";

/// The subset of `LocalFolderItem`'s package-private surface that [`HistoryManager`] depends on:
/// its data storage directory, and its logging hook.
///
/// [`LocalFolderItem`](crate::framework::store::local::LocalFolderItem) was ported as an
/// object-safe trait that only carries the class's *public* API (see that trait's doc comment);
/// `getDataDir()` and the package-private `log(String, String)` helper it uses are not part of
/// that surface. This trait stands in for just those two members so `HistoryManager` can depend
/// on an owning item abstractly rather than on any single concrete `LocalFolderItem`
/// implementation.
pub trait HistoryManagerItem {
    /// Returns the data storage directory for this item (mirrors the package-private
    /// `LocalFolderItem.getDataDir()`).
    fn data_dir(&self) -> PathBuf;

    /// Logs an activity message for this item (mirrors the package-private
    /// `LocalFolderItem.log(String, String)`, itself a thin wrapper over
    /// `fileSystem.log(this, msg, user)`).
    fn log(&self, msg: &str, user: Option<&str>);
}

/// Manages version data for a versioned `LocalFolderItem`. History data is maintained within the
/// file `history.dat` located within the item's data directory.
///
/// Mirrors `ghidra.framework.store.local.HistoryManager`, which is package-private in Java; it is
/// `pub` here since Rust module privacy does not map directly onto Java package privacy, matching
/// the convention already established for other originally-package-private types in this crate.
pub struct HistoryManager {
    item: Box<dyn HistoryManagerItem>,
    min_version: i32,
    cur_version: i32,
    versions: Vec<ItemVersion>,
}

impl HistoryManager {
    /// Constructor.
    ///
    /// - `item`: folder item.
    /// - `create`: if true an empty history data file is written (in-memory only -- the file
    ///   itself is only actually written once the first version is added, exactly as in the
    ///   Java constructor, which sets `versions = new Version[0]` but never calls
    ///   `writeHistoryFile()`), else the initial data is left unread until first accessed
    ///   (mirrors the Java constructor's own lazy behavior: `minVersion`/`curVersion` start at
    ///   `0` and `versions` starts empty, populated lazily by [`Self::validate`]).
    pub fn new(item: Box<dyn HistoryManagerItem>, create: bool) -> Self {
        let _ = create; // both branches start from the same empty-in-memory state; see doc comment above.
        Self {
            item,
            min_version: 0,
            cur_version: 0,
            versions: Vec::new(),
        }
    }

    fn history_file(&self) -> PathBuf {
        self.item.data_dir().join(HISTORY_FILE)
    }

    /// Add and/or remove history entries to agree with the specified minimum and current
    /// versions.
    ///
    /// Returns true if a version correction was performed.
    ///
    /// # Errors
    /// Returns an `io::Error` if an IO error occurs reading or writing the history file.
    ///
    /// # Panics
    /// Panics if `min_version < 1 || cur_version < min_version` (mirrors the Java method's
    /// unchecked `IllegalArgumentException`).
    pub fn fix_history(&mut self, min_version: i32, cur_version: i32) -> io::Result<bool> {
        self.validate()?;
        if min_version == self.min_version && cur_version == self.cur_version {
            return Ok(false);
        }

        assert!(
            min_version >= 1 && cur_version >= min_version,
            "min_version must be >= 1 and cur_version must be >= min_version"
        );

        let mut new_versions: Vec<ItemVersion> = Vec::with_capacity((cur_version - min_version + 1) as usize);

        let mut old_ix: usize = 0;
        let mut version = min_version;
        if min_version < self.min_version {
            while version < self.min_version && version <= cur_version {
                // Add missing versions.
                new_versions.push(ItemVersion::new(version, 0, "<Recovered>", "<Unknown>"));
                version += 1;
            }
        }
        if version >= self.min_version && version <= self.cur_version {
            // Keep as many existing version entries as possible.
            while self.versions[old_ix].version() < version {
                old_ix += 1;
            }
            while version <= self.cur_version && version <= cur_version {
                new_versions.push(self.versions[old_ix].clone());
                old_ix += 1;
                version += 1;
            }
        }
        while version <= cur_version {
            // Add missing versions.
            new_versions.push(ItemVersion::new(version, 0, "<Recovered>", "<Unknown>"));
            version += 1;
        }

        self.versions = new_versions;
        self.min_version = min_version;
        self.cur_version = cur_version;
        self.write_history_file();

        Ok(true)
    }

    /// Record the creation of a new item version.
    ///
    /// - `version`: version number.
    /// - `time`: version creation time.
    /// - `comment`: version comment.
    /// - `user`: user who created the version.
    ///
    /// # Errors
    /// Returns an `io::Error` if an IO error occurs.
    ///
    /// Real Java quirk preserved: if `version` does not equal `cur_version + 1` (a check that
    /// "should have been performed by item"), this method silently logs an error and returns
    /// *without* recording anything -- it does not return an `Err`.
    pub fn version_added(&mut self, version: i32, time: i64, comment: &str, user: &str) -> io::Result<()> {
        self.validate()?;

        if version != self.cur_version + 1 {
            self.item.log(
                &format!(
                    "ERROR! unexpected version {} created, expected version {}",
                    version,
                    self.cur_version + 1
                ),
                Some(user),
            );
            return Ok(());
        }

        self.item.log(&format!("version {version} created"), Some(user));
        let ver = ItemVersion::new(version, time, user, comment);

        self.append_history_file(&ver);

        self.versions.push(ver);
        self.cur_version = version;
        if version == 1 {
            self.min_version = 1;
        }
        Ok(())
    }

    /// Remove the specified version from the history data. This method only modifies the data if
    /// the minimum or latest version is specified.
    ///
    /// - `version`: minimum or latest version.
    /// - `user`: user performing the removal.
    ///
    /// # Errors
    /// Returns an `io::Error` if an IO error occurs.
    ///
    /// Real Java quirks preserved: if there is only one version, or if `version` names neither
    /// the current minimum nor maximum version, this method silently logs an error and returns
    /// *without* modifying anything (again, "should have been performed by item").
    pub fn version_deleted(&mut self, version: i32, user: &str) -> io::Result<()> {
        self.validate()?;
        if self.versions.len() <= 1 {
            self.item.log(
                &format!(
                    "ERROR! version {version} deleted illegally, min={}, max={}",
                    self.min_version, self.cur_version
                ),
                Some(user),
            );
            return Ok(());
        }

        if version == self.versions[0].version() {
            self.versions.remove(0);
            self.min_version = self.versions[0].version();
        } else if version == self.versions[self.versions.len() - 1].version() {
            self.versions.pop();
            self.cur_version = self.versions[self.versions.len() - 1].version();
        } else {
            self.item.log(
                &format!(
                    "ERROR! version {version} deleted illegally, min={}, max={}",
                    self.min_version, self.cur_version
                ),
                Some(user),
            );
            return Ok(());
        }
        self.item.log(&format!("version {version} deleted"), Some(user));
        self.write_history_file();
        Ok(())
    }

    /// Return all versions contained within the history. Versions are ordered oldest to newest
    /// (i.e. minimum to latest).
    ///
    /// # Errors
    /// Returns an `io::Error` if an IO error occurs.
    pub fn get_versions(&mut self) -> io::Result<Vec<ItemVersion>> {
        self.validate()?;
        Ok(self.versions.clone())
    }

    /// Return a specific version, or `None` if not found.
    ///
    /// # Errors
    /// Returns an `io::Error` if an IO error occurs.
    ///
    /// Real Java quirk preserved: the bounds check is `version >= min_version && version <
    /// cur_version` (strictly less-than on the upper bound) rather than `<=`. This means the
    /// current/latest version can *never* be retrieved via this method -- including when there is
    /// only a single version, where `min_version == cur_version` makes the check fail entirely.
    pub fn get_version(&mut self, version: i32) -> io::Result<Option<ItemVersion>> {
        self.validate()?;
        if version >= self.min_version && version < self.cur_version {
            Ok(self.versions.get((version - self.min_version) as usize).cloned())
        } else {
            Ok(None)
        }
    }

    /// If the history data file has been updated, the history data will be re-initialized from
    /// the file.
    ///
    /// Real Java quirk preserved: despite the class-level javadoc describing this refresh as
    /// conditional on `LocalFileSystem.isRefreshRequired()`, the actual implementation
    /// unconditionally re-reads the history file *every time this is called*, whenever that file
    /// exists -- `is_refresh_required()` only controls whether in-memory state is first reset to
    /// empty before that unconditional re-read. In other words: any external modification to the
    /// history file is picked up on the very next `HistoryManager` call, regardless of the
    /// refresh-required flag.
    fn validate(&mut self) -> io::Result<()> {
        if is_refresh_required() {
            self.versions.clear();
            self.min_version = 0;
            self.cur_version = 0;
        }
        let history_file = self.history_file();
        if history_file.exists() {
            let old_versions = self.versions.clone();
            let old_min = self.min_version;
            let old_cur = self.cur_version;
            let mut success = false;
            let result = self.read_history_file();
            if result.is_ok() {
                success = true;
            }
            if !success {
                self.versions = old_versions;
                self.min_version = old_min;
                self.cur_version = old_cur;
            }
            result
        } else {
            self.versions.clear();
            Ok(())
        }
    }

    /// Read data from the history file.
    fn read_history_file(&mut self) -> io::Result<()> {
        let mut list: Vec<ItemVersion> = Vec::new();
        self.min_version = 0;
        self.cur_version = 0;

        let history_file = self.history_file();
        let file = File::open(&history_file)?;
        let reader = BufReader::new(file);
        for line in reader.lines() {
            let line = line?;
            let ver = decode_version(&line).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, format!("Bad history file: {}", history_file.display()))
            })?;
            let version = ver.version();
            if self.cur_version != 0 && version != self.cur_version + 1 {
                // Versions must be in sequential order.
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Bad history file{}", history_file.display()),
                ));
            }
            if self.min_version == 0 {
                self.min_version = version;
            }
            self.cur_version = version;
            list.push(ver);
        }

        self.versions = list;
        Ok(())
    }

    /// Write all history data to file. Mirrors `writeHistoryFile`, which logs (rather than
    /// propagates) any `IOException` it encounters -- this port does the same, hence no `Result`
    /// return.
    fn write_history_file(&self) {
        if let Err(e) = self.try_write_history_file() {
            self.item.log(&format!("ERROR! failed to update history file: {e}"), None);
        }
    }

    fn try_write_history_file(&self) -> io::Result<()> {
        let history_file = self.history_file();
        let parent = history_file.parent().map(|p| p.to_path_buf()).unwrap_or_default();
        let tmp_file = parent.join(format!("{HISTORY_FILE}.new"));
        let _ = fs::remove_file(&tmp_file);

        {
            let mut out = File::create(&tmp_file)?;
            for ver in &self.versions {
                writeln!(out, "{}", encode_version(ver))?;
            }
        }

        let mut old_file: Option<PathBuf> = None;
        if history_file.exists() {
            let bak_file = parent.join(format!("{HISTORY_FILE}.bak"));
            let _ = fs::remove_file(&bak_file);
            if fs::rename(&history_file, &bak_file).is_err() {
                return Err(io::Error::new(io::ErrorKind::Other, "file is in use"));
            }
            old_file = Some(bak_file);
        }
        if fs::rename(&tmp_file, &history_file).is_err() {
            if let Some(ref old) = old_file {
                let _ = fs::rename(old, &history_file);
            }
            return Err(io::Error::new(io::ErrorKind::Other, "file error - backup may exist"));
        }
        if let Some(ref old) = old_file {
            let _ = fs::remove_file(old);
        }
        Ok(())
    }

    /// Write new version data to file. Mirrors `appendHistoryFile`, which likewise logs (rather
    /// than propagates) any `IOException`.
    fn append_history_file(&self, ver: &ItemVersion) {
        if let Err(e) = self.try_append_history_file(ver) {
            self.item.log(&format!("ERROR! failed to update history file: {e}"), None);
        }
    }

    fn try_append_history_file(&self, ver: &ItemVersion) -> io::Result<()> {
        let history_file = self.history_file();
        let mut out = fs::OpenOptions::new().create(true).append(true).open(&history_file)?;
        writeln!(out, "{}", encode_version(ver))?;
        Ok(())
    }
}

/// Encode item version data for file output. Field order (`version;user;createTime;comment`)
/// mirrors the Java layout exactly.
fn encode_version(ver: &ItemVersion) -> String {
    let mut buf = String::new();
    buf.push_str(&ver.version().to_string());
    buf.push(';');
    buf.push_str(ver.user());
    buf.push(';');
    buf.push_str(&ver.create_time().to_string());
    buf.push(';');
    encode_string(ver.comment(), &mut buf);
    buf
}

/// Decode item version data from a file line.
///
/// NOTE: Java's `decodeVersion` tokenizes with `StringTokenizer(line, ";")`, which silently skips
/// over consecutive/empty delimiter runs rather than producing empty tokens. This port uses a
/// plain `split(';')` instead, which does yield empty tokens for consecutive `;` characters. This
/// only matters for already-corrupt input (a legitimately encoded line never contains a raw,
/// unescaped `;`, since [`encode_string`] escapes it as `\s`); a well-formed line parses
/// identically either way, including the common trailing-empty-comment case.
fn decode_version(line: &str) -> Result<ItemVersion, ()> {
    let mut parts = line.split(';');
    let version: i32 = parts.next().ok_or(())?.parse().map_err(|_| ())?;
    let user = parts.next().ok_or(())?.to_string();
    let time: i64 = parts.next().ok_or(())?.parse().map_err(|_| ())?;
    let comment = match parts.next() {
        Some(raw) => decode_string(raw),
        None => String::new(),
    };
    Ok(ItemVersion::new(version, time, user, comment))
}

/// Escape special characters within a string and append to the output buffer.
///
/// Real Java quirk preserved: `;` (the field separator) is escaped as the two-character sequence
/// `\s` -- not the more expected `\;` -- alongside the usual `\n`, `\r`, and `\\` escapes.
fn encode_string(text: &str, buf: &mut String) {
    for c in text.chars() {
        match c {
            '\n' => buf.push_str("\\n"),
            '\r' => buf.push_str("\\r"),
            ';' => buf.push_str("\\s"),
            '\\' => buf.push_str("\\\\"),
            _ => buf.push(c),
        }
    }
}

/// Decode an escaped string produced by [`encode_string`].
fn decode_string(text: &str) -> String {
    let mut buf = String::with_capacity(text.len());
    let mut control_char = false;
    for c in text.chars() {
        if c == '\\' {
            control_char = true;
        } else if control_char {
            match c {
                'n' => buf.push('\n'),
                'r' => buf.push('\r'),
                's' => buf.push(';'),
                other => buf.push(other),
            }
            control_char = false;
        } else {
            buf.push(c);
        }
    }
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::sync::atomic::{AtomicU32, Ordering};

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    struct TestItem {
        dir: PathBuf,
        log: RefCell<Vec<String>>,
    }

    impl TestItem {
        fn new(label: &str) -> Self {
            let id = COUNTER.fetch_add(1, Ordering::Relaxed);
            let mut dir = std::env::temp_dir();
            dir.push(format!("history_manager_test_{}_{}_{}", std::process::id(), label, id));
            fs::create_dir_all(&dir).unwrap();
            Self { dir, log: RefCell::new(Vec::new()) }
        }
    }

    impl HistoryManagerItem for TestItem {
        fn data_dir(&self) -> PathBuf {
            self.dir.clone()
        }
        fn log(&self, msg: &str, user: Option<&str>) {
            self.log.borrow_mut().push(format!("{msg} (user={user:?})"));
        }
    }

    fn manager(label: &str) -> (HistoryManager, std::rc::Rc<TestItem>) {
        let item = std::rc::Rc::new(TestItem::new(label));
        (HistoryManager::new(Box::new(RcItem(item.clone())), true), item)
    }

    /// Wraps an `Rc<TestItem>` so it can be boxed as a `dyn HistoryManagerItem` while the test
    /// keeps its own `Rc` clone around for inspecting the log.
    struct RcItem(std::rc::Rc<TestItem>);
    impl HistoryManagerItem for RcItem {
        fn data_dir(&self) -> PathBuf {
            self.0.data_dir()
        }
        fn log(&self, msg: &str, user: Option<&str>) {
            self.0.log(msg, user);
        }
    }

    #[test]
    fn version_added_then_get_versions_and_get_version() {
        let (mut mgr, _item) = manager("basic");
        mgr.version_added(1, 100, "first", "alice").unwrap();
        mgr.version_added(2, 200, "second", "bob").unwrap();

        let versions = mgr.get_versions().unwrap();
        assert_eq!(versions.len(), 2);
        assert_eq!(versions[0].user(), "alice");
        assert_eq!(versions[1].user(), "bob");

        // get_version(1) succeeds (1 >= min(1) && 1 < cur(2)).
        let v1 = mgr.get_version(1).unwrap();
        assert_eq!(v1.unwrap().user(), "alice");
    }

    #[test]
    fn get_version_of_current_version_is_always_none_quirk() {
        let (mut mgr, _item) = manager("current_quirk");
        mgr.version_added(1, 100, "only", "alice").unwrap();
        // Single version: min_version == cur_version == 1, so `1 < cur_version` is false.
        assert_eq!(mgr.get_version(1).unwrap(), None);

        mgr.version_added(2, 200, "second", "bob").unwrap();
        // Even with two versions, the *current* (latest) version is still unreachable.
        assert_eq!(mgr.get_version(2).unwrap(), None);
        // But the non-latest version 1 is reachable.
        assert!(mgr.get_version(1).unwrap().is_some());
    }

    #[test]
    fn version_added_out_of_sequence_is_silently_ignored() {
        let (mut mgr, item) = manager("out_of_sequence");
        mgr.version_added(1, 100, "first", "alice").unwrap();
        // Expected next version is 2; supply 5 instead.
        mgr.version_added(5, 500, "bad", "eve").unwrap();

        let versions = mgr.get_versions().unwrap();
        assert_eq!(versions.len(), 1, "out-of-sequence version must not be recorded");
        assert!(item.log.borrow().iter().any(|l| l.contains("unexpected version 5")));
    }

    #[test]
    fn version_deleted_single_version_is_silently_ignored() {
        let (mut mgr, item) = manager("delete_single");
        mgr.version_added(1, 100, "only", "alice").unwrap();
        mgr.version_deleted(1, "alice").unwrap();

        let versions = mgr.get_versions().unwrap();
        assert_eq!(versions.len(), 1, "deleting the only version must be a no-op");
        assert!(item.log.borrow().iter().any(|l| l.contains("deleted illegally")));
    }

    #[test]
    fn version_deleted_middle_version_is_silently_ignored() {
        let (mut mgr, item) = manager("delete_middle");
        mgr.version_added(1, 100, "a", "alice").unwrap();
        mgr.version_added(2, 200, "b", "alice").unwrap();
        mgr.version_added(3, 300, "c", "alice").unwrap();

        mgr.version_deleted(2, "alice").unwrap();

        let versions = mgr.get_versions().unwrap();
        assert_eq!(versions.len(), 3, "deleting a middle version must be a no-op");
        assert!(item.log.borrow().iter().any(|l| l.contains("deleted illegally")));
    }

    #[test]
    fn version_deleted_min_and_max_update_bounds() {
        let (mut mgr, _item) = manager("delete_bounds");
        mgr.version_added(1, 100, "a", "alice").unwrap();
        mgr.version_added(2, 200, "b", "alice").unwrap();
        mgr.version_added(3, 300, "c", "alice").unwrap();

        mgr.version_deleted(1, "alice").unwrap();
        let versions = mgr.get_versions().unwrap();
        assert_eq!(versions.len(), 2);
        assert_eq!(versions[0].version(), 2);

        mgr.version_deleted(3, "alice").unwrap();
        let versions = mgr.get_versions().unwrap();
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].version(), 2);
    }

    #[test]
    fn semicolon_and_backslash_round_trip_through_encode_decode() {
        // NOTE: only the *comment* field is escaped by `encode_string`/`decode_string` (mirroring
        // Java's `encodeVersion`, which calls `encodeString` on the comment only, appending the
        // user name raw) -- a literal `;` in `user` would break parsing. That's a real, if
        // obscure, Java limitation this port doesn't attempt to paper over; this test only
        // exercises escaping in the field Java actually escapes.
        let ver = ItemVersion::new(1, 42, "user", "a;b\\c\nd\re");
        let encoded = encode_version(&ver);
        // The literal `;` in the comment must have been escaped, so splitting on `;` yields
        // exactly 4 fields (version, user, time, comment) even though the comment contains one.
        assert_eq!(encoded.split(';').count(), 4);
        let decoded = decode_version(&encoded).unwrap();
        assert_eq!(decoded.user(), "user");
        // NOT a clean round-trip: `decodeString`'s `if next == '\\' { controlChar = true }` check
        // (verified against HistoryManager.java lines 427-428) runs unconditionally, even when
        // `controlChar` is already true -- so a literal backslash decoded from an escaped `\\`
        // pair never reaches the "already in an escape, treat this char as the payload" branch.
        // The backslash is silently dropped and the character right after it is misread as the
        // escape payload instead (here, `c`, which harmlessly falls through `decodeString`'s
        // `default: buf.append(next)` arm). This is a genuine bug in Ghidra's real Java
        // decodeString, faithfully reproduced -- not a port defect.
        assert_eq!(decoded.comment(), "a;bc\nd\re");
    }

    #[test]
    fn semicolon_is_escaped_as_backslash_s_not_backslash_semicolon() {
        let mut buf = String::new();
        encode_string("a;b", &mut buf);
        assert_eq!(buf, "a\\sb");
    }

    #[test]
    fn history_persists_across_manager_instances() {
        let item = std::rc::Rc::new(TestItem::new("persist"));
        {
            let mut mgr = HistoryManager::new(Box::new(RcItem(item.clone())), true);
            mgr.version_added(1, 1, "c1", "alice").unwrap();
            mgr.version_added(2, 2, "c2", "bob").unwrap();
        }
        // A fresh manager over the same data directory picks up the persisted history file.
        let mut mgr2 = HistoryManager::new(Box::new(RcItem(item.clone())), false);
        let versions = mgr2.get_versions().unwrap();
        assert_eq!(versions.len(), 2);
        assert_eq!(versions[0].comment(), "c1");
        assert_eq!(versions[1].comment(), "c2");
    }

    #[test]
    fn fix_history_extends_with_recovered_placeholders() {
        let (mut mgr, _item) = manager("fix_extend");
        mgr.version_added(1, 100, "a", "alice").unwrap();
        mgr.version_added(2, 200, "b", "alice").unwrap();

        // Widen the range to 1..=4: versions 3 and 4 don't exist yet, so they should be
        // synthesized as "<Recovered>"/"<Unknown>" placeholders.
        let changed = mgr.fix_history(1, 4).unwrap();
        assert!(changed);

        let versions = mgr.get_versions().unwrap();
        assert_eq!(versions.len(), 4);
        assert_eq!(versions[2].user(), "<Recovered>");
        assert_eq!(versions[2].comment(), "<Unknown>");
        assert_eq!(versions[3].version(), 4);
    }

    #[test]
    fn fix_history_no_op_when_bounds_already_match() {
        let (mut mgr, _item) = manager("fix_noop");
        mgr.version_added(1, 100, "a", "alice").unwrap();
        let changed = mgr.fix_history(1, 1).unwrap();
        assert!(!changed);
    }

    #[test]
    #[should_panic]
    fn fix_history_rejects_invalid_bounds() {
        let (mut mgr, _item) = manager("fix_invalid");
        mgr.version_added(1, 100, "a", "alice").unwrap();
        let _ = mgr.fix_history(5, 1);
    }

    #[test]
    fn validate_always_rereads_file_regardless_of_refresh_flag() {
        // Faithful quirk test: even without `set_validation_required()` having been called,
        // `validate()` unconditionally re-reads the history file whenever it exists, so an
        // external modification is picked up on the very next call.
        let item = std::rc::Rc::new(TestItem::new("always_reread"));
        let mut mgr = HistoryManager::new(Box::new(RcItem(item.clone())), true);
        mgr.version_added(1, 1, "c1", "alice").unwrap();

        // Externally append a second version line directly to the history file, bypassing the
        // manager entirely.
        let history_path = item.data_dir().join(HISTORY_FILE);
        let mut out = fs::OpenOptions::new().append(true).open(&history_path).unwrap();
        writeln!(out, "{}", encode_version(&ItemVersion::new(2, 2, "bob", "external"))).unwrap();
        drop(out);

        let versions = mgr.get_versions().unwrap();
        assert_eq!(versions.len(), 2, "external modification should be visible on next call");
        assert_eq!(versions[1].user(), "bob");
    }

    #[test]
    fn bad_history_file_reports_error() {
        let item = TestItem::new("bad_file");
        fs::write(item.data_dir().join(HISTORY_FILE), "not-a-valid-line\n").unwrap();
        let mut mgr = HistoryManager::new(Box::new(RcItem(std::rc::Rc::new(item))), false);
        assert!(mgr.get_versions().is_err());
    }
}

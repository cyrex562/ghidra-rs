//! Port of `ghidra.app.plugin.processors.sleigh.SleighLanguageFile`.
//!
//! Represents a Sleigh `.sla` and `.slaspec` file, and a way to lock them to ensure exclusive
//! access while checking/updating the files. In Java this is a concrete class; it was selected as
//! a dependency-cycle cut-point, so its instance surface is promoted to the [`SleighLanguageFile`]
//! trait here.
//!
//! Two of Java's static factories are ported as free functions: [`get_language_resource_file`]
//! and [`from_sla_filename`], which returns the one concrete implementation here,
//! [`LocatedSleighLanguageFile`]. Since the SLEIGH compiler (`SleighCompile.run_compilation`) is
//! not ported, that implementation never creates a lock file and cannot compile: it is Java's
//! "cannot lock" mode, in which languages load from the existing `.sla`. Not ported:
//! `fromSlaFilename_UserDir`, the lock-file protocol (`withLock`, lock-holder info) and
//! `compileSlaFile` (the [`SleighLanguageFile::compile_sla_file`]/[`SleighLanguageFile::with_lock`]
//! trait methods stay required so a future compiling implementation can supply them).
//!
//! [`SleighLanguageFile::needs_compilation`], [`SleighLanguageFile::is_sla_file_stale`], and
//! [`SleighLanguageFile::describe`] (`toString`) do get real default bodies, since they only
//! depend on already-ported types ([`ResourceFile`], [`SleighPreprocessor`]).

use std::io;
use std::path::Path;
use std::time::Duration;

use crate::generic::jar::resource_file::ResourceFile;
use crate::sleigh::grammar::frontend::preprocessor::SleighPreprocessor;
use crate::sleigh::grammar::frontend::preprocessor_definitions::HashMapPreprocessorDefinitions;
use crate::util::exception::TimeoutException;
use crate::util::task::TaskMonitor;

use super::sleigh_exception::SleighException;

/// Extension of a Sleigh language specification source file. Port of
/// `SleighLanguageFile.SLASPEC_EXT`.
pub const SLASPEC_EXT: &str = ".slaspec";
/// Extension of a compiled Sleigh language file. Port of `SleighLanguageFile.SLA_EXT`.
pub const SLA_EXT: &str = ".sla";

/// A Sleigh `.sla`/`.slaspec` file pair, with the ability to lock and (re)compile them. Port of
/// the instance contract of `ghidra.app.plugin.processors.sleigh.SleighLanguageFile` (see the
/// module docs for why this is a trait and what is out of scope).
pub trait SleighLanguageFile: Send + Sync {
    /// The compiled `.sla` file. Port of `SleighLanguageFile.getSlaFile()`.
    fn sla_file(&self) -> &ResourceFile;

    /// The `.slaspec` source file. Port of `SleighLanguageFile.getSlaSpecFile()`.
    fn sla_spec_file(&self) -> &ResourceFile;

    /// `true` if this language's files can be locked, or `false` if they can't be locked (e.g.
    /// embedded in a `.jar` file). Port of `SleighLanguageFile.canLock()`.
    fn can_lock(&self) -> bool;

    /// The lock file path, meaningful only when [`Self::can_lock`] is `true`. Port of
    /// `SleighLanguageFile.getLockFile()`.
    fn lock_file(&self) -> Option<&Path>;

    /// The format version number embedded in the compiled `.sla` file, or `-1` if it can't be read
    /// or the file doesn't exist. Port of `SleighLanguageFile.getSlaVersion()`.
    ///
    /// NOTE: should only be called while holding the lock acquired via [`Self::with_lock`].
    ///
    /// Not given a default body: reading the embedded format version needs
    /// `ghidra.pcode.utils.SlaFormat`, which is not yet ported (see module docs).
    fn sla_version(&self) -> i32;

    /// Compiles the `.slaspec` file and replaces the `.sla` file with the newly compiled Sleigh
    /// output. Port of `SleighLanguageFile.compileSlaFile(TaskMonitor)`.
    ///
    /// NOTE: should only be called while holding the lock acquired via [`Self::with_lock`].
    ///
    /// Not given a default body: needs `SleighCompileOptions` and `SleighCompile.run_compilation`,
    /// neither of which is ported yet (see module docs).
    ///
    /// # Errors
    /// Returns an error if compilation fails.
    fn compile_sla_file(&self, monitor: &dyn TaskMonitor) -> Result<(), SleighException>;

    /// Executes `r` while holding an exclusive lock on [`Self::lock_file`]. Port of
    /// `SleighLanguageFile.withLock(Duration, TaskMonitor, CheckedRunnable)`. Java's generic
    /// `CheckedRunnable<E>` becomes a boxed closure here, since a trait object can't be generic
    /// over `E`.
    ///
    /// Not given a default body: real OS-level file locking is implementation-specific (see
    /// module docs).
    ///
    /// # Errors
    /// Returns [`WithLockError::Io`] if there's no lock file or an I/O error acquiring/releasing
    /// it, [`WithLockError::Timeout`] if `timeout` elapses first, or [`WithLockError::Runnable`]
    /// if `r` itself fails.
    fn with_lock(
        &self,
        timeout: Duration,
        monitor: &dyn TaskMonitor,
        r: &mut dyn FnMut() -> Result<(), Box<dyn std::error::Error + Send + Sync>>,
    ) -> Result<(), WithLockError>;

    /// `true` if the `.sla` file needs to be compiled/recompiled: conditions are a missing `.sla`,
    /// a `.sla` older than the `.slaspec`, or an embedded sla-format version that doesn't match
    /// `required_sla_format_version`. Port of `SleighLanguageFile.needsCompilation(int)`.
    ///
    /// NOTE: should only be called while holding the lock acquired via [`Self::with_lock`].
    fn needs_compilation(&self, required_sla_format_version: i32) -> bool {
        !self.sla_file().exists()
            || self.is_sla_file_stale()
            || self.sla_version() != required_sla_format_version
    }

    /// `true` if the `.slaspec` file (or any `@include`d `.sinc` file) is newer than the current
    /// `.sla` file, indicating the `.sla` file should be recompiled. `false` if the `.slaspec`/`.sla`
    /// files are embedded in a jar (single-jar mode). Port of `SleighLanguageFile.isSlaFileStale()`.
    ///
    /// NOTE: should only be called while holding the lock acquired via [`Self::with_lock`].
    fn is_sla_file_stale(&self) -> bool {
        // NOTE: SleighPreprocessor doesn't use ResourceFiles, so any `@include` directives it
        // processes won't go through ResourceFile.getFile() (mirrors the Java NOTE on this
        // method).
        let Some(spec_path) = self.sla_spec_file().get_file(false) else {
            // slaspec file is embedded in a jar: always assume the sla file is correct.
            return false;
        };
        let mut definitions = HashMapPreprocessorDefinitions::new();
        let sla_spec_last_mod = SleighPreprocessor::new(&mut definitions, spec_path)
            .scan_for_timestamp()
            // sla_spec_last_mod will force recompilation on error; the parse error itself is
            // handled elsewhere, mirroring the Java catch block.
            .unwrap_or(u64::MAX);
        let sla_last_mod = self.sla_file().last_modified(); // 0 if it does not exist
        // `ResourceFile::last_modified()` returns Unix seconds, while the scanned
        // `sla_spec_last_mod` above is in milliseconds (mirroring Java's `File.lastModified()`);
        // scale to a common unit before comparing.
        sla_last_mod == 0 || sla_spec_last_mod > sla_last_mod.saturating_mul(1000)
    }

    /// Human-readable `"<slaspec path> -> <sla path>"` description. Port of
    /// `SleighLanguageFile.toString()`.
    fn describe(&self) -> String {
        format!(
            "{} -> {}",
            self.sla_spec_file().absolute_path(),
            self.sla_file().absolute_path()
        )
    }
}

/// Error produced by [`SleighLanguageFile::with_lock`]. Ports the checked exceptions thrown by
/// `SleighLanguageFile.withLock`: `IOException`, `TimeoutException`, and the caller-supplied
/// runnable's own exception type `E` (boxed here, since `E` can't be a type parameter on a trait
/// object).
#[derive(Debug)]
pub enum WithLockError {
    /// I/O error acquiring or releasing the lock file.
    Io(io::Error),
    /// Timed out waiting to acquire the lock file.
    Timeout(TimeoutException),
    /// The locked runnable `r` itself returned an error.
    Runnable(Box<dyn std::error::Error + Send + Sync>),
}

impl std::fmt::Display for WithLockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WithLockError::Io(e) => write!(f, "{e}"),
            WithLockError::Timeout(e) => write!(f, "{e}"),
            WithLockError::Runnable(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for WithLockError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            WithLockError::Io(e) => Some(e),
            WithLockError::Timeout(e) => Some(e),
            WithLockError::Runnable(e) => Some(e.as_ref()),
        }
    }
}

impl From<io::Error> for WithLockError {
    fn from(e: io::Error) -> Self {
        WithLockError::Io(e)
    }
}

impl From<TimeoutException> for WithLockError {
    fn from(e: TimeoutException) -> Self {
        WithLockError::Timeout(e)
    }
}

/// A `.sla`/`.slaspec` pair located by [`from_sla_filename`], in Java's "no lock file" mode.
///
/// Java's `fromSlaFilename` tries to create a `<sla>.lock` file next to the `.sla` and, when it
/// can, recompiles stale `.sla` files under that lock (`SleighLanguage.initialize`). The SLEIGH
/// compiler (`SleighCompile`) is not ported, so this port never creates the lock file: every
/// located file behaves as Java's single-jar/read-only-directory case (`canLock()` is `false`),
/// in which `SleighLanguage` decodes the `.sla` as it is, without a freshness check.
#[derive(Clone)]
pub struct LocatedSleighLanguageFile {
    sla: ResourceFile,
    sla_spec: ResourceFile,
}

impl LocatedSleighLanguageFile {
    /// A file pair for an explicit `.sla` and `.slaspec` (neither has to exist).
    pub fn new(sla: ResourceFile, sla_spec: ResourceFile) -> Self {
        Self { sla, sla_spec }
    }
}

impl SleighLanguageFile for LocatedSleighLanguageFile {
    fn sla_file(&self) -> &ResourceFile {
        &self.sla
    }

    fn sla_spec_file(&self) -> &ResourceFile {
        &self.sla_spec
    }

    fn can_lock(&self) -> bool {
        false
    }

    fn lock_file(&self) -> Option<&Path> {
        None
    }

    /// Port of `getSlaVersion()`: the format version in the `.sla` header, or -1 if the file is
    /// missing or has no header.
    fn sla_version(&self) -> i32 {
        let Ok(mut stream) = self.sla.get_input_stream() else {
            return -1;
        };
        crate::pcode::utils::sla_format::get_sla_format(&mut stream).unwrap_or(-1)
    }

    /// Always fails: compiling needs the SLEIGH compiler, which is not ported (and Java never
    /// compiles a file that cannot be locked).
    fn compile_sla_file(&self, _monitor: &dyn TaskMonitor) -> Result<(), SleighException> {
        Err(SleighException::with_message(format!(
            "Cannot compile {}: the SLEIGH compiler is not available",
            self.sla_spec.absolute_path()
        )))
    }

    /// Always fails with an I/O error: this file has no lock file ([`Self::can_lock`] is
    /// `false`), as Java's `withLock` does for a `SleighLanguageFile` without one.
    fn with_lock(
        &self,
        _timeout: Duration,
        _monitor: &dyn TaskMonitor,
        _r: &mut dyn FnMut() -> Result<(), Box<dyn std::error::Error + Send + Sync>>,
    ) -> Result<(), WithLockError> {
        Err(WithLockError::Io(io::Error::other(format!(
            "No lock file for {}",
            self.sla.absolute_path()
        ))))
    }
}

/// `FilenameUtils.removeExtension`: `name` without its last `.ext` (if the dot is in the final
/// path component).
fn remove_extension(name: &str) -> &str {
    let file_start = name.rfind(['/', '\\']).map_or(0, |i| i + 1);
    match name[file_start..].rfind('.') {
        Some(dot) => &name[..file_start + dot],
        None => name,
    }
}

/// Port of `SleighLanguageFile.getLanguageResourceFile(ResourceFile, String, String)`: the
/// existing file `filename` (a name or relative path) relative to `dir`.
///
/// When it is not there, Java searches the whole application for files with
/// `expected_extension` named like `filename` (`findFile`/`findFiles`); here that search covers
/// the directory trees `search_roots` (pass none to disable it). A unique match is used; with
/// several, Java's check of the *requested* path against the relative path (which passes for any
/// relative name) makes it use the first match, and so does this port.
///
/// # Errors
/// [`SleighFileException`](super::sleigh_file_exception::SleighFileException) if the file is
/// missing or its name does not match the file system's case exactly.
pub fn get_language_resource_file(
    dir: &ResourceFile,
    filename: &str,
    expected_extension: &str,
    search_roots: &[std::path::PathBuf],
) -> Result<ResourceFile, super::sleigh_file_exception::SleighFileException> {
    use super::sleigh_file_exception::SleighFileException;
    let Some(f) = find_file(dir, filename, expected_extension, search_roots) else {
        return Err(SleighFileException::new(format!(
            "Missing sleigh file({expected_extension}): {}",
            dir.join(filename).absolute_path()
        )));
    };
    let result = crate::program::model::lang::sleigh::manual::exists_and_is_case_dependent(&f);
    if !result.is_ok() {
        return Err(SleighFileException::new(format!(
            "Sleigh file {} is not properly case dependent: {}",
            f.absolute_path(),
            result.message()
        )));
    }
    Ok(f)
}

/// Port of the private `findFile(ResourceFile, String, String)`. Java returns the canonical
/// file; the file is returned as named here so that the case check above sees the requested
/// spelling (a canonical path would always match the file system's case).
fn find_file(
    parent_dir: &ResourceFile,
    file_name_or_relative_path: &str,
    extension: &str,
    search_roots: &[std::path::PathBuf],
) -> Option<ResourceFile> {
    let file = parent_dir.join(file_name_or_relative_path);
    if file.exists() {
        return Some(file);
    }
    let file_name = std::path::Path::new(file_name_or_relative_path).file_name()?.to_str()?;
    let mut files = Vec::new();
    for root in search_roots {
        find_files(root, file_name, extension, &mut files);
    }
    files.into_iter().next().map(ResourceFile::new)
}

/// Port of the private `findFiles(String, String)`, over `dir`'s tree (sorted, so the "first"
/// match is deterministic).
fn find_files(dir: &std::path::Path, file_name: &str, extension: &str, out: &mut Vec<std::path::PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut paths: Vec<std::path::PathBuf> = entries.filter_map(|e| e.ok().map(|e| e.path())).collect();
    paths.sort();
    for path in paths {
        if path.is_dir() {
            find_files(&path, file_name, extension, out);
        } else if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            if name == file_name && name.ends_with(extension) {
                out.push(path);
            }
        }
    }
}

/// Port of `SleighLanguageFile.fromSlaFilename(ResourceFile, String)`: locates the `.slaspec`
/// named after `sla_filename` (with or without `.sla`) in `dir` and pairs it with the `.sla` next
/// to it; when there is no `.slaspec`, falls back to the `.sla` and assumes the `.slaspec` is next
/// to it. See [`LocatedSleighLanguageFile`] for why no lock file is created.
///
/// # Errors
/// [`SleighFileException`](super::sleigh_file_exception::SleighFileException) if neither file can
/// be found (reporting the missing `.slaspec`, as Java does).
pub fn from_sla_filename(
    dir: &ResourceFile,
    sla_filename: &str,
    search_roots: &[std::path::PathBuf],
) -> Result<LocatedSleighLanguageFile, super::sleigh_file_exception::SleighFileException> {
    let base_name = if sla_filename.ends_with(SLA_EXT) {
        remove_extension(sla_filename)
    } else {
        sla_filename
    };
    let sibling = |file: &ResourceFile, ext: &str| -> ResourceFile {
        let name = file.name();
        let stem = remove_extension(&name).to_string();
        match file.get_parent_file() {
            Some(parent) => parent.join(&format!("{stem}{ext}")),
            None => ResourceFile::new(std::path::PathBuf::from(format!("{stem}{ext}"))),
        }
    };
    match get_language_resource_file(dir, &format!("{base_name}{SLASPEC_EXT}"), SLASPEC_EXT, search_roots) {
        Ok(sla_spec) => {
            let sla = sibling(&sla_spec, SLA_EXT);
            Ok(LocatedSleighLanguageFile::new(sla, sla_spec))
        }
        Err(original) => match get_language_resource_file(dir, &format!("{base_name}{SLA_EXT}"), SLA_EXT, search_roots) {
            Ok(sla) => {
                let sla_spec = sibling(&sla, SLASPEC_EXT);
                Ok(LocatedSleighLanguageFile::new(sla, sla_spec))
            }
            Err(_) => Err(original),
        },
    }
}

#[cfg(test)]
mod located_tests {
    use super::*;

    fn dir_with(files: &[&str]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for f in files {
            std::fs::write(dir.path().join(f), b"sla\x04rest").unwrap();
        }
        dir
    }

    #[test]
    fn from_sla_filename_pairs_slaspec_with_sibling_sla() {
        let dir = dir_with(&["mylang.slaspec", "mylang.sla"]);
        let root = ResourceFile::new(dir.path().to_path_buf());
        for name in ["mylang.sla", "mylang"] {
            let f = from_sla_filename(&root, name, &[]).unwrap();
            assert_eq!(f.sla_file().name(), "mylang.sla");
            assert_eq!(f.sla_spec_file().name(), "mylang.slaspec");
            assert!(!f.can_lock());
            assert!(f.lock_file().is_none());
        }
        // No lock file is created next to the .sla.
        assert!(!dir.path().join("mylang.sla.lock").exists());
    }

    #[test]
    fn from_sla_filename_falls_back_to_sla_without_slaspec() {
        let dir = dir_with(&["only.sla"]);
        let root = ResourceFile::new(dir.path().to_path_buf());
        let f = from_sla_filename(&root, "only.sla", &[]).unwrap();
        assert!(f.sla_file().exists());
        assert_eq!(f.sla_spec_file().name(), "only.slaspec");
        assert!(!f.sla_spec_file().exists());
    }

    #[test]
    fn from_sla_filename_reports_missing_slaspec() {
        let dir = dir_with(&[]);
        let root = ResourceFile::new(dir.path().to_path_buf());
        let err = from_sla_filename(&root, "nothing.sla", &[]).err().unwrap();
        assert!(err.message().contains("Missing sleigh file(.slaspec)"), "{}", err.message());
    }

    #[test]
    fn get_language_resource_file_rejects_wrong_case() {
        let dir = dir_with(&["Upper.pspec"]);
        let root = ResourceFile::new(dir.path().to_path_buf());
        assert!(get_language_resource_file(&root, "Upper.pspec", ".pspec", &[]).is_ok());
        // On a case-sensitive file system the file is simply missing; on a case-insensitive one it
        // is found but not properly case dependent. Either way it is an error.
        assert!(get_language_resource_file(&root, "upper.pspec", ".pspec", &[]).is_err());
    }

    #[test]
    fn get_language_resource_file_falls_back_to_searching_the_roots_by_name() {
        let dir = dir_with(&[]);
        std::fs::create_dir_all(dir.path().join("old")).unwrap();
        std::fs::write(dir.path().join("shared.cspec"), b"").unwrap();
        let old = ResourceFile::new(dir.path().join("old"));
        assert!(get_language_resource_file(&old, "shared.cspec", ".cspec", &[]).is_err());
        let found =
            get_language_resource_file(&old, "shared.cspec", ".cspec", &[dir.path().to_path_buf()]).unwrap();
        assert_eq!(found.absolute_path(), dir.path().join("shared.cspec").to_string_lossy());
        // Only files with the expected extension are candidates.
        assert!(get_language_resource_file(&old, "shared.cspec", ".pspec", &[dir.path().to_path_buf()]).is_err());
    }

    #[test]
    fn sla_version_reads_the_header_and_compile_is_unavailable() {
        let dir = dir_with(&["v.sla"]);
        let sla = ResourceFile::new(dir.path().join("v.sla"));
        let f = LocatedSleighLanguageFile::new(sla, ResourceFile::new(dir.path().join("v.slaspec")));
        assert_eq!(f.sla_version(), 4);
        let missing = LocatedSleighLanguageFile::new(
            ResourceFile::new(dir.path().join("none.sla")),
            ResourceFile::new(dir.path().join("none.slaspec")),
        );
        assert_eq!(missing.sla_version(), -1);
        assert!(f.compile_sla_file(&crate::util::task::DummyMonitor).is_err());
    }

    #[test]
    fn remove_extension_only_strips_the_last_component_extension() {
        assert_eq!(remove_extension("x86-64.sla"), "x86-64");
        assert_eq!(remove_extension("a.b/c"), "a.b/c");
        assert_eq!(remove_extension("noext"), "noext");
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::task::DummyMonitor;
    use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
    use std::sync::Mutex;
    use tempfile::tempdir;

    /// Mock [`SleighLanguageFile`] backed by real temp files, proving object-safety and
    /// exercising the real default-method bodies (`needs_compilation`, `is_sla_file_stale`,
    /// `describe`), plus a simple in-memory single-holder lock for `with_lock`.
    struct MockSleighLanguageFile {
        sla: ResourceFile,
        sla_spec: ResourceFile,
        lock_path: std::path::PathBuf,
        sla_version: AtomicI32,
        locked: Mutex<bool>,
        compiled: AtomicBool,
    }

    impl SleighLanguageFile for MockSleighLanguageFile {
        fn sla_file(&self) -> &ResourceFile {
            &self.sla
        }

        fn sla_spec_file(&self) -> &ResourceFile {
            &self.sla_spec
        }

        fn can_lock(&self) -> bool {
            true
        }

        fn lock_file(&self) -> Option<&Path> {
            Some(&self.lock_path)
        }

        fn sla_version(&self) -> i32 {
            self.sla_version.load(Ordering::SeqCst)
        }

        fn compile_sla_file(&self, monitor: &dyn TaskMonitor) -> Result<(), SleighException> {
            monitor.set_message("Compiling Language File...");
            self.compiled.store(true, Ordering::SeqCst);
            self.sla_version.store(7, Ordering::SeqCst);
            Ok(())
        }

        fn with_lock(
            &self,
            _timeout: Duration,
            _monitor: &dyn TaskMonitor,
            r: &mut dyn FnMut() -> Result<(), Box<dyn std::error::Error + Send + Sync>>,
        ) -> Result<(), WithLockError> {
            let mut guard = self.locked.lock().unwrap();
            if *guard {
                return Err(WithLockError::Timeout(TimeoutException::new(
                    "already locked",
                )));
            }
            *guard = true;
            let result = r().map_err(WithLockError::Runnable);
            *guard = false;
            result
        }
    }

    fn mock_with(dir: &std::path::Path, spec_body: &str, touch_sla: bool) -> MockSleighLanguageFile {
        let spec_path = dir.join("x86.slaspec");
        std::fs::write(&spec_path, spec_body).unwrap();
        let sla_path = dir.join("x86.sla");
        if touch_sla {
            std::fs::write(&sla_path, b"compiled").unwrap();
        }
        MockSleighLanguageFile {
            sla: ResourceFile::new(sla_path),
            sla_spec: ResourceFile::new(spec_path),
            lock_path: dir.join("x86.sla.lock"),
            sla_version: AtomicI32::new(5),
            locked: Mutex::new(false),
            compiled: AtomicBool::new(false),
        }
    }

    #[test]
    fn boxed_trait_object_is_usable() {
        let dir = tempdir().unwrap();
        let file: Box<dyn SleighLanguageFile> = Box::new(mock_with(dir.path(), "define endian=little;", true));
        assert!(file.can_lock());
        assert!(file.lock_file().is_some());
        assert_eq!(file.sla_version(), 5);
    }

    #[test]
    fn describe_formats_slaspec_arrow_sla() {
        let dir = tempdir().unwrap();
        let file = mock_with(dir.path(), "define endian=little;", true);
        let description = file.describe();
        assert!(description.contains(" -> "));
        assert!(description.starts_with(&file.sla_spec_file().absolute_path()));
        assert!(description.ends_with(&file.sla_file().absolute_path()));
    }

    #[test]
    fn needs_compilation_false_when_sla_present_fresh_and_version_matches() {
        let dir = tempdir().unwrap();
        // Write the slaspec, then wait long enough that the (second-resolution) sla mtime lands
        // in a strictly later second, so the sla file is unambiguously "fresh".
        let spec_path = dir.path().join("x86.slaspec");
        std::fs::write(&spec_path, "define endian=little;").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(2100));
        let sla_path = dir.path().join("x86.sla");
        std::fs::write(&sla_path, b"compiled").unwrap();
        let file = MockSleighLanguageFile {
            sla: ResourceFile::new(sla_path),
            sla_spec: ResourceFile::new(spec_path),
            lock_path: dir.path().join("x86.sla.lock"),
            sla_version: AtomicI32::new(5),
            locked: Mutex::new(false),
            compiled: AtomicBool::new(false),
        };
        assert!(!file.needs_compilation(5));
    }

    #[test]
    fn needs_compilation_true_when_sla_missing() {
        let dir = tempdir().unwrap();
        let file = mock_with(dir.path(), "define endian=little;", false);
        assert!(file.needs_compilation(5));
    }

    #[test]
    fn needs_compilation_true_when_version_mismatch() {
        let dir = tempdir().unwrap();
        let file = mock_with(dir.path(), "define endian=little;", true);
        assert!(file.needs_compilation(999));
    }

    #[test]
    fn is_sla_file_stale_false_for_embedded_slaspec() {
        // A ResourceFile with no backing filesystem path (get_file(false) == None) mirrors a
        // slaspec embedded in a jar: isSlaFileStale should short-circuit to false.
        struct AlwaysEmbedded;
        impl crate::generic::jar::resource::Resource for AlwaysEmbedded {
            fn absolute_path(&self) -> String {
                "embedded:x86.slaspec".to_string()
            }
            fn name(&self) -> String {
                "x86.slaspec".to_string()
            }
            fn is_directory(&self) -> bool {
                false
            }
            fn is_file(&self) -> bool {
                true
            }
            fn exists(&self) -> bool {
                true
            }
            fn last_modified(&self) -> u64 {
                0
            }
            fn length(&self) -> u64 {
                0
            }
            fn get_input_stream(&self) -> io::Result<Box<dyn io::Read>> {
                Err(io::Error::new(io::ErrorKind::Unsupported, "embedded"))
            }
            fn get_output_stream(&self) -> io::Result<Box<dyn io::Write>> {
                Err(io::Error::new(io::ErrorKind::Unsupported, "embedded"))
            }
            fn get_file(&self) -> Option<std::path::PathBuf> {
                None
            }
            fn get_resource(&self, _path: &str) -> Box<dyn crate::generic::jar::resource::Resource> {
                unimplemented!("not exercised by this smoke test")
            }
            fn list_files(&self) -> Option<Vec<ResourceFile>> {
                None
            }
            fn list_files_filtered(
                &self,
                _filter: &dyn crate::generic::jar::resource_file_filter::ResourceFileFilter,
            ) -> Option<Vec<ResourceFile>> {
                None
            }
            fn parent(&self) -> Option<Box<dyn crate::generic::jar::resource::Resource>> {
                None
            }
            fn to_url(&self) -> io::Result<String> {
                Ok(self.absolute_path())
            }
            fn to_uri(&self) -> String {
                self.absolute_path()
            }
            fn delete(&self) -> bool {
                false
            }
            fn canonical_path(&self) -> io::Result<String> {
                Ok(self.absolute_path())
            }
            fn canonical_resource(&self) -> Box<dyn crate::generic::jar::resource::Resource> {
                Box::new(AlwaysEmbedded)
            }
            fn can_write(&self) -> bool {
                false
            }
            fn mkdir(&self) -> bool {
                false
            }
            fn file_system_root(&self) -> std::path::PathBuf {
                std::path::PathBuf::new()
            }
            fn resource_as_file(&self, _resource_file: &ResourceFile) -> std::path::PathBuf {
                std::path::PathBuf::new()
            }
        }

        let dir = tempdir().unwrap();
        let mut file = mock_with(dir.path(), "define endian=little;", true);
        file.sla_spec = ResourceFile::from_resource(Box::new(AlwaysEmbedded));
        assert!(!file.is_sla_file_stale());
    }

    #[test]
    fn is_sla_file_stale_true_when_slaspec_newer_than_sla() {
        let dir = tempdir().unwrap();
        // Write the sla first, then the slaspec, so the slaspec's scanned timestamp is newer.
        let sla_path = dir.path().join("x86.sla");
        std::fs::write(&sla_path, b"compiled").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(2100));
        let spec_path = dir.path().join("x86.slaspec");
        std::fs::write(&spec_path, "define endian=little;").unwrap();

        let file = MockSleighLanguageFile {
            sla: ResourceFile::new(sla_path),
            sla_spec: ResourceFile::new(spec_path),
            lock_path: dir.path().join("x86.sla.lock"),
            sla_version: AtomicI32::new(5),
            locked: Mutex::new(false),
            compiled: AtomicBool::new(false),
        };
        assert!(file.is_sla_file_stale());
    }

    #[test]
    fn with_lock_runs_closure_and_releases_lock() {
        let dir = tempdir().unwrap();
        let file = mock_with(dir.path(), "define endian=little;", true);
        let ran = AtomicBool::new(false);
        let monitor = DummyMonitor;
        file.with_lock(Duration::from_millis(10), &monitor, &mut || {
            ran.store(true, Ordering::SeqCst);
            Ok(())
        })
        .unwrap();
        assert!(ran.load(Ordering::SeqCst));
        assert!(!*file.locked.lock().unwrap());
    }

    #[test]
    fn with_lock_propagates_runnable_error() {
        let dir = tempdir().unwrap();
        let file = mock_with(dir.path(), "define endian=little;", true);
        let monitor = DummyMonitor;
        let err = file
            .with_lock(Duration::from_millis(10), &monitor, &mut || {
                Err(Box::<dyn std::error::Error + Send + Sync>::from("boom"))
            })
            .unwrap_err();
        assert!(matches!(err, WithLockError::Runnable(_)));
        assert_eq!(err.to_string(), "boom");
    }

    #[test]
    fn compile_sla_file_updates_version_and_reports_progress() {
        let dir = tempdir().unwrap();
        let file = mock_with(dir.path(), "define endian=little;", true);
        let monitor = DummyMonitor;
        file.compile_sla_file(&monitor).unwrap();
        assert_eq!(file.sla_version(), 7);
        assert!(file.compiled.load(Ordering::SeqCst));
    }
}

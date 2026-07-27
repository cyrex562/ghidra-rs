//! Port of `ghidra.app.plugin.processors.sleigh.SleighLanguageFile`.
//!
//! Represents a Sleigh `.sla` and `.slaspec` file, and a way to lock them to ensure exclusive
//! access while checking/updating the files. In Java this is a concrete class; it was selected as
//! a dependency-cycle cut-point, so its instance surface is promoted to the [`SleighLanguageFile`]
//! trait here.
//!
//! Java's three static factories (`getLanguageResourceFile`, `fromSlaFilename`,
//! `fromSlaFilename_UserDir`) are not ported: they all bottom out in `ghidra.framework.Application`
//! (module/installation discovery) and `utilities.util.FileUtilities.existsAndIsCaseDependent`,
//! neither of which exist in this crate yet (mirroring the same scope decision already made for
//! `SleighPreprocessor`'s `@include` handling -- see the `TODO(sleigh-frontend)` note in
//! [`crate::sleigh::grammar::frontend::preprocessor`]). Likewise, [`SleighLanguageFile::sla_version`]
//! (needs `ghidra.pcode.utils.SlaFormat.getSlaFormat`) and
//! [`SleighLanguageFile::compile_sla_file`]/[`SleighLanguageFile::with_lock`] (need
//! `ghidra.pcodeCPort.slgh_compile.SleighCompileOptions` and `SleighCompile.run_compilation`,
//! explicitly marked "not ported" in [`crate::decompiler::slgh_compile::sleigh_compile`]) are left
//! as required trait methods rather than given a half-real default body: a future concrete
//! implementation backed by those types can supply them.
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

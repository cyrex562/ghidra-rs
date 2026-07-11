use std::fmt;
use std::fs::File;
use std::io;
use std::io::{Read, Seek, Write as IoWrite};
use std::path::Path;
use std::time::SystemTime;

use zip::write::{SimpleFileOptions, ZipWriter};
use zip::CompressionMethod;

use crate::util::msg::Msg;
use crate::util::task::TaskMonitor;

/// A writer that silently discards all output.
///
/// Use this when an API requires a [`fmt::Write`] or [`io::Write`] but you want
/// to suppress all output without null-checking at every call site.
///
/// Mirrors `generic.io.NullWriter` from Ghidra.
pub struct NullWriter;

impl fmt::Write for NullWriter {
    fn write_str(&mut self, _s: &str) -> fmt::Result {
        Ok(())
    }
}

impl io::Write for NullWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A print writer that silently discards all output.
///
/// Mirrors `generic.io.NullPrintWriter` from Ghidra. Provides an `Option`-aware
/// constructor via [`dummy_if_null`] for ergonomic handling of nullable writer
/// parameters without null-checks at call sites.
pub struct NullPrintWriter(NullWriter);

impl NullPrintWriter {
    /// Creates a new null print writer.
    pub fn new() -> Self {
        Self(NullWriter)
    }

    /// Returns the provided writer if `Some`, otherwise creates a new `NullPrintWriter`.
    ///
    /// Mirrors the Java static method `dummyIfNull(PrintWriter pw)`.
    pub fn dummy_if_null<W: Default>(writer: Option<W>) -> DummyOrWriter<W> {
        match writer {
            Some(w) => DummyOrWriter::Writer(w),
            None => DummyOrWriter::Dummy(Self::new()),
        }
    }
}

impl Default for NullPrintWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Write for NullPrintWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.0.write_str(s)
    }
}

impl io::Write for NullPrintWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

/// An enum that holds either a user-provided writer or a `NullPrintWriter`.
///
/// Returned by [`NullPrintWriter::dummy_if_null`] to provide type-safe
/// null-coalescing behavior.
pub enum DummyOrWriter<W> {
    Writer(W),
    Dummy(NullPrintWriter),
}

impl<W: fmt::Write> fmt::Write for DummyOrWriter<W> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        match self {
            DummyOrWriter::Writer(w) => w.write_str(s),
            DummyOrWriter::Dummy(d) => d.write_str(s),
        }
    }
}

impl<W: io::Write> io::Write for DummyOrWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            DummyOrWriter::Writer(w) => w.write(buf),
            DummyOrWriter::Dummy(d) => d.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            DummyOrWriter::Writer(w) => w.flush(),
            DummyOrWriter::Dummy(d) => d.flush(),
        }
    }
}

/// A class for writing to a jar output stream.
///
/// Mirrors `generic.io.JarWriter`. Wraps a `zip::ZipWriter` (the Rust analogue of Java's
/// `JarOutputStream`, itself a `ZipOutputStream` carrying jar metadata) and adds
/// directory-recursion, extension exclusion, and [`TaskMonitor`] cancellation support.
pub struct JarWriter<W: IoWrite + Seek> {
    jar_out: ZipWriter<W>,
    excluded_extensions: Vec<String>,
}

impl<W: IoWrite + Seek> JarWriter<W> {
    /// Creates a new `JarWriter` with no excluded extensions.
    ///
    /// Mirrors the Java `JarWriter(JarOutputStream jarOut)` constructor.
    pub fn new(jar_out: ZipWriter<W>) -> Self {
        Self::with_excluded_extensions(jar_out, Vec::new())
    }

    /// Creates a new `JarWriter` that skips, during recursion, files whose names end with
    /// one of `excluded_extensions`.
    ///
    /// Mirrors the Java `JarWriter(JarOutputStream jarOut, String[] excludedExtensions)`
    /// constructor.
    pub fn with_excluded_extensions(jar_out: ZipWriter<W>, excluded_extensions: Vec<String>) -> Self {
        JarWriter { jar_out, excluded_extensions }
    }

    /// Outputs an individual file to the jar.
    ///
    /// `jar_path` is the base path prepended to the file as it is written to the jar.
    /// Mirrors the Java `outputFile(File baseFile, String jarPath, TaskMonitor monitor)`.
    /// Returns `true` if the file is output to the jar file successfully.
    pub fn output_file(&mut self, base_file: &Path, jar_path: &str, monitor: &dyn TaskMonitor) -> bool {
        if base_file.is_dir() {
            return false;
        }

        let mut input = match File::open(base_file) {
            Ok(f) => f,
            Err(fnfe) => {
                Msg::error_with_error("JarWriter", &format!("Unexpected Exception: {fnfe}"), &fnfe);
                return false;
            }
        };

        let time = input
            .metadata()
            .and_then(|m| m.modified())
            .unwrap_or(SystemTime::UNIX_EPOCH);
        let name = base_file
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();

        self.output_entry(&format!("{jar_path}{name}"), time, &mut input, monitor)
    }

    /// Outputs an individual entry to the jar. `input` is read until EOF.
    ///
    /// Mirrors the Java `outputEntry(String path, long time, InputStream in, TaskMonitor monitor)`.
    /// Returns `true` if the entry is output to the jar file successfully.
    pub fn output_entry(
        &mut self,
        path: &str,
        time: SystemTime,
        input: &mut dyn Read,
        monitor: &dyn TaskMonitor,
    ) -> bool {
        let mut options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
        if let Some(mtime) = zip_datetime_from(time) {
            options = options.last_modified_time(mtime);
        }

        monitor.set_message(&format!("Writing {path}"));

        if let Err(ioe) = self.jar_out.start_file(path, options) {
            Msg::error_with_error("JarWriter", &format!("Unexpected Exception: {ioe}"), &ioe);
            return false;
        }

        let mut bytes = [0u8; 4096];
        loop {
            let num_read = match input.read(&mut bytes) {
                Ok(0) => return true,
                Ok(n) => n,
                Err(ioe) => {
                    Msg::error_with_error("JarWriter", &format!("Unexpected Exception: {ioe}"), &ioe);
                    return false;
                }
            };

            if monitor.is_cancelled() {
                return false;
            }

            if let Err(ioe) = self.jar_out.write_all(&bytes[..num_read]) {
                Msg::error_with_error("JarWriter", &format!("Unexpected Exception: {ioe}"), &ioe);
                return false;
            }
        }
    }

    /// Recursively outputs a directory to the jar output stream. If `base_file` is a file
    /// then it is simply output to the jar.
    ///
    /// `jar_path` is the base path prepended to the files as they are written to the jar.
    /// Mirrors the Java `outputRecursively(File baseFile, String jarPath, TaskMonitor monitor)`.
    /// Returns `true` if all files are recursively output to the jar file.
    pub fn output_recursively(&mut self, base_file: &Path, jar_path: &str, monitor: &dyn TaskMonitor) -> bool {
        let mut succeeded = true;

        if base_file.is_dir() {
            // Java's `File.listFiles()` order is filesystem-dependent and was never a
            // meaningful part of the original behavior; sort for deterministic output.
            let mut sub_files: Vec<_> = match std::fs::read_dir(base_file) {
                Ok(entries) => entries.filter_map(|e| e.ok()).map(|e| e.path()).collect(),
                Err(ioe) => {
                    Msg::error_with_error("JarWriter", &format!("Unexpected Exception: {ioe}"), &ioe);
                    return false;
                }
            };
            sub_files.sort();

            let name = base_file
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            let new_path = format!("{jar_path}{name}{}", std::path::MAIN_SEPARATOR);

            for sub_file in &sub_files {
                if monitor.is_cancelled() {
                    break;
                }
                succeeded = self.output_recursively(sub_file, &new_path, monitor) && succeeded;
            }
        }
        else {
            let name = base_file
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            if self.excluded_extensions.iter().any(|ext| name.ends_with(ext.as_str())) {
                return true;
            }
            succeeded = self.output_file(base_file, jar_path, monitor);
        }

        succeeded
    }

    /// Returns the jar output stream being used by this `JarWriter`.
    ///
    /// Mirrors the Java `getJarOutputStream()`.
    pub fn jar_output_stream(&mut self) -> &mut ZipWriter<W> {
        &mut self.jar_out
    }

    /// Finishes writing the archive and returns the underlying writer.
    pub fn close(self) -> io::Result<W> {
        let writer = self.jar_out.finish()?;
        Ok(writer)
    }
}

/// Converts a `SystemTime` into a `zip::DateTime` if it falls within the range the zip/DOS
/// timestamp format supports (1980..=2107).
fn zip_datetime_from(time: SystemTime) -> Option<zip::DateTime> {
    let secs = time.duration_since(std::time::UNIX_EPOCH).ok()?.as_secs();

    let days = (secs / 86400) as i64;
    let (year, month, day) = days_to_ymd(days);
    let hour = ((secs % 86400) / 3600) as u8;
    let minute = ((secs % 3600) / 60) as u8;
    let second = (secs % 60) as u8;

    if !(1980..=2107).contains(&year) {
        return None;
    }

    zip::DateTime::from_date_and_time(year as u16, month, day, hour, minute, second).ok()
}

/// Converts a count of days since the Unix epoch (1970-01-01) into `(year, month, day)`
/// using Howard Hinnant's civil-from-days algorithm.
fn days_to_ymd(days: i64) -> (i32, u8, u8) {
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    (y as i32, m as u8, d as u8)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Write as FmtWrite;
    use std::io::Write as IoWrite;

    #[test]
    fn fmt_write_str_discards_output() {
        let mut w = NullWriter;
        assert!(w.write_str("hello").is_ok());
    }

    #[test]
    fn fmt_write_macro_discards_output() {
        let mut w = NullWriter;
        assert!(std::fmt::Write::write_fmt(&mut w, format_args!("value={}", 42)).is_ok());
    }

    #[test]
    fn io_write_returns_buf_len() {
        let mut w = NullWriter;
        let buf = b"some bytes";
        assert_eq!(w.write(buf).unwrap(), buf.len());
    }

    #[test]
    fn io_write_empty_buf() {
        let mut w = NullWriter;
        assert_eq!(w.write(&[]).unwrap(), 0);
    }

    #[test]
    fn io_flush_succeeds() {
        let mut w = NullWriter;
        assert!(w.flush().is_ok());
    }

    #[test]
    fn io_write_all_succeeds() {
        let mut w = NullWriter;
        assert!(w.write_all(b"discard this").is_ok());
    }

    #[test]
    fn null_print_writer_new() {
        let _pw = NullPrintWriter::new();
    }

    #[test]
    fn null_print_writer_default() {
        let _pw = NullPrintWriter::default();
    }

    #[test]
    fn null_print_writer_fmt_write() {
        let mut pw = NullPrintWriter::new();
        assert!(pw.write_str("test").is_ok());
        assert!(std::fmt::Write::write_fmt(&mut pw, format_args!("value={}", 123)).is_ok());
    }

    #[test]
    fn null_print_writer_io_write() {
        let mut pw = NullPrintWriter::new();
        assert_eq!(pw.write(b"bytes").unwrap(), 5);
        assert!(pw.write_all(b"more").is_ok());
        assert!(pw.flush().is_ok());
    }

    #[test]
    fn dummy_if_null_with_some() {
        let vec = Vec::new();
        let mut dw = NullPrintWriter::dummy_if_null::<std::io::Cursor<Vec<u8>>>(Some(
            std::io::Cursor::new(vec),
        ));
        let buf = b"test";
        if let DummyOrWriter::Writer(ref mut w) = dw {
            assert_eq!(w.write(buf).unwrap(), 4);
        } else {
            panic!("expected Writer variant");
        }
    }

    #[test]
    fn dummy_if_null_with_none() {
        let dw = NullPrintWriter::dummy_if_null::<std::io::Cursor<Vec<u8>>>(None);
        if let DummyOrWriter::Dummy(_) = dw {
            // expected
        } else {
            panic!("expected Dummy variant");
        }
    }

    #[test]
    fn dummy_or_writer_write_with_writer() {
        let vec = Vec::new();
        let cursor = std::io::Cursor::new(vec);
        let mut dw = DummyOrWriter::Writer(cursor);
        assert_eq!(dw.write(b"test").unwrap(), 4);
    }

    #[test]
    fn dummy_or_writer_write_with_dummy() {
        let mut dw = DummyOrWriter::<std::io::Cursor<Vec<u8>>>::Dummy(NullPrintWriter::new());
        assert_eq!(dw.write(b"discarded").unwrap(), 9);
    }

    #[test]
    fn dummy_or_writer_flush_with_writer() {
        let vec = Vec::new();
        let cursor = std::io::Cursor::new(vec);
        let mut dw = DummyOrWriter::Writer(cursor);
        assert!(dw.flush().is_ok());
    }

    #[test]
    fn dummy_or_writer_flush_with_dummy() {
        let mut dw = DummyOrWriter::<std::io::Cursor<Vec<u8>>>::Dummy(NullPrintWriter::new());
        assert!(dw.flush().is_ok());
    }

    #[test]
    fn dummy_or_writer_fmt_write_with_writer() {
        let mut buf = String::new();
        let mut dw = DummyOrWriter::Writer(&mut buf);
        assert!(dw.write_str("hello").is_ok());
        assert_eq!(buf, "hello");
    }

    #[test]
    fn dummy_or_writer_fmt_write_with_dummy() {
        let mut dw = DummyOrWriter::<String>::Dummy(NullPrintWriter::new());
        assert!(dw.write_str("ignored").is_ok());
    }

    use crate::util::task::DummyMonitor;
    use std::io::Cursor;
    use std::sync::atomic::{AtomicBool, Ordering};
    use zip::ZipArchive;

    struct RecordingMonitor {
        cancelled: AtomicBool,
    }

    impl RecordingMonitor {
        fn new() -> Self {
            Self { cancelled: AtomicBool::new(false) }
        }
    }

    impl TaskMonitor for RecordingMonitor {
        fn is_cancelled(&self) -> bool {
            self.cancelled.load(Ordering::SeqCst)
        }
        fn set_show_progress_value(&self, _show: bool) {}
        fn set_message(&self, _message: &str) {}
        fn get_message(&self) -> String {
            String::new()
        }
        fn set_progress(&self, _value: i64) {}
        fn initialize(&self, _max: i64) {}
        fn set_maximum(&self, _max: i64) {}
        fn get_maximum(&self) -> i64 {
            0
        }
        fn set_indeterminate(&self, _indeterminate: bool) {}
        fn is_indeterminate(&self) -> bool {
            false
        }
        fn check_cancelled(&self) -> Result<(), crate::util::exception::CancelledException> {
            Ok(())
        }
        fn increment_progress(&self, _amount: i64) {}
        fn get_progress(&self) -> i64 {
            0
        }
        fn cancel(&self) {
            self.cancelled.store(true, Ordering::SeqCst);
        }
        fn add_cancelled_listener(&self, _listener: Box<dyn crate::util::task::CancelledListener>) {}
        fn remove_cancelled_listener(&self, _listener: &dyn crate::util::task::CancelledListener) {}
        fn set_cancel_enabled(&self, _enabled: bool) {}
        fn is_cancel_enabled(&self) -> bool {
            true
        }
        fn clear_cancelled(&self) {}
    }

    #[test]
    fn jar_writer_output_entry_writes_content() {
        let buf = Cursor::new(Vec::new());
        let mut writer = JarWriter::new(ZipWriter::new(buf));
        let monitor = DummyMonitor;

        let mut data = Cursor::new(b"hello jar".to_vec());
        let ok = writer.output_entry("hello.txt", SystemTime::UNIX_EPOCH, &mut data, &monitor);
        assert!(ok);

        let cursor = writer.close().unwrap();
        let mut archive = ZipArchive::new(cursor).unwrap();
        let mut contents = String::new();
        archive.by_name("hello.txt").unwrap().read_to_string(&mut contents).unwrap();
        assert_eq!(contents, "hello jar");
    }

    #[test]
    fn jar_writer_output_entry_cancelled_returns_false() {
        let buf = Cursor::new(Vec::new());
        let mut writer = JarWriter::new(ZipWriter::new(buf));
        let monitor = RecordingMonitor::new();
        monitor.cancel();

        let mut data = Cursor::new(b"data".to_vec());
        let ok = writer.output_entry("cancelled.txt", SystemTime::UNIX_EPOCH, &mut data, &monitor);
        assert!(!ok);
    }

    #[test]
    fn jar_writer_output_file_rejects_directory() {
        let dir = tempfile::tempdir().unwrap();
        let buf = Cursor::new(Vec::new());
        let mut writer = JarWriter::new(ZipWriter::new(buf));
        let monitor = DummyMonitor;

        let ok = writer.output_file(dir.path(), "", &monitor);
        assert!(!ok);
    }

    #[test]
    fn jar_writer_output_file_missing_file_returns_false() {
        let buf = Cursor::new(Vec::new());
        let mut writer = JarWriter::new(ZipWriter::new(buf));
        let monitor = DummyMonitor;

        let missing = Path::new("/nonexistent/path/does-not-exist.txt");
        let ok = writer.output_file(missing, "", &monitor);
        assert!(!ok);
    }

    #[test]
    fn jar_writer_output_file_writes_named_entry() {
        use std::io::Write as _;

        let mut source = tempfile::NamedTempFile::new().unwrap();
        source.write_all(b"file contents").unwrap();
        source.flush().unwrap();

        let buf = Cursor::new(Vec::new());
        let mut writer = JarWriter::new(ZipWriter::new(buf));
        let monitor = DummyMonitor;

        let ok = writer.output_file(source.path(), "prefix/", &monitor);
        assert!(ok);

        let name = source.path().file_name().unwrap().to_string_lossy().into_owned();
        let expected_path = format!("prefix/{name}");

        let cursor = writer.close().unwrap();
        let mut archive = ZipArchive::new(cursor).unwrap();
        let mut contents = String::new();
        archive.by_name(&expected_path).unwrap().read_to_string(&mut contents).unwrap();
        assert_eq!(contents, "file contents");
    }

    #[test]
    fn jar_writer_output_recursively_writes_nested_files() {
        use std::io::Write as _;

        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("a.txt"), b"aaa").unwrap();
        let sub_dir = root.path().join("sub");
        std::fs::create_dir(&sub_dir).unwrap();
        let mut sub_file = File::create(sub_dir.join("b.txt")).unwrap();
        sub_file.write_all(b"bbb").unwrap();
        drop(sub_file);

        let buf = Cursor::new(Vec::new());
        let mut writer = JarWriter::new(ZipWriter::new(buf));
        let monitor = DummyMonitor;

        let ok = writer.output_recursively(root.path(), "", &monitor);
        assert!(ok);

        let root_name = root.path().file_name().unwrap().to_string_lossy().into_owned();
        let sep = std::path::MAIN_SEPARATOR;

        let cursor = writer.close().unwrap();
        let mut archive = ZipArchive::new(cursor).unwrap();
        assert_eq!(archive.len(), 2);

        let mut a = String::new();
        archive
            .by_name(&format!("{root_name}{sep}a.txt"))
            .unwrap()
            .read_to_string(&mut a)
            .unwrap();
        assert_eq!(a, "aaa");

        let mut b = String::new();
        archive
            .by_name(&format!("{root_name}{sep}sub{sep}b.txt"))
            .unwrap()
            .read_to_string(&mut b)
            .unwrap();
        assert_eq!(b, "bbb");
    }

    #[test]
    fn jar_writer_output_recursively_skips_excluded_extensions() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("keep.txt"), b"keep").unwrap();
        std::fs::write(root.path().join("skip.class"), b"skip").unwrap();

        let buf = Cursor::new(Vec::new());
        let mut writer =
            JarWriter::with_excluded_extensions(ZipWriter::new(buf), vec![".class".to_string()]);
        let monitor = DummyMonitor;

        let ok = writer.output_recursively(root.path(), "", &monitor);
        assert!(ok);

        let root_name = root.path().file_name().unwrap().to_string_lossy().into_owned();
        let sep = std::path::MAIN_SEPARATOR;

        let cursor = writer.close().unwrap();
        let mut archive = ZipArchive::new(cursor).unwrap();
        assert_eq!(archive.len(), 1);
        assert!(archive.by_name(&format!("{root_name}{sep}keep.txt")).is_ok());
    }

    #[test]
    fn jar_writer_output_recursively_single_file() {
        use std::io::Write as _;

        let mut source = tempfile::NamedTempFile::new().unwrap();
        source.write_all(b"solo").unwrap();
        source.flush().unwrap();

        let buf = Cursor::new(Vec::new());
        let mut writer = JarWriter::new(ZipWriter::new(buf));
        let monitor = DummyMonitor;

        let ok = writer.output_recursively(source.path(), "", &monitor);
        assert!(ok);

        let name = source.path().file_name().unwrap().to_string_lossy().into_owned();
        let cursor = writer.close().unwrap();
        let mut archive = ZipArchive::new(cursor).unwrap();
        let mut contents = String::new();
        archive.by_name(&name).unwrap().read_to_string(&mut contents).unwrap();
        assert_eq!(contents, "solo");
    }

    #[test]
    fn jar_writer_jar_output_stream_accessor() {
        let buf = Cursor::new(Vec::new());
        let mut writer = JarWriter::new(ZipWriter::new(buf));
        let _stream: &mut ZipWriter<Cursor<Vec<u8>>> = writer.jar_output_stream();
    }

    #[test]
    fn zip_datetime_from_out_of_range_returns_none() {
        // Before 1980, outside what the zip/DOS timestamp format supports.
        assert!(zip_datetime_from(std::time::UNIX_EPOCH).is_none());
    }

    #[test]
    fn days_to_ymd_known_dates() {
        assert_eq!(days_to_ymd(0), (1970, 1, 1));
        assert_eq!(days_to_ymd(10957), (2000, 1, 1));
    }
}

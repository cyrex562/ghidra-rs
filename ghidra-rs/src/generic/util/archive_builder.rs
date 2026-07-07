//! Port of `generic.util.ArchiveBuilder`.
//!
//! Accumulates entries into a zip/jar archive by writing them to an underlying
//! `zip::ZipWriter`. Mirrors the Java class which wraps a `ZipOutputStream`:
//! entries can be added from a file on disk (`add_file`) or synthesized from a
//! list of text lines (`create_file`), and the stream is finished with `close`.

use std::io::{Read, Seek, Write};
use std::path::Path;

use zip::write::{SimpleFileOptions, ZipWriter};
use zip::CompressionMethod;

use crate::util::exception::AssertException;

/// Builds a zip/jar archive by writing entries to an underlying writer.
///
/// This is the direct analogue of `generic.util.ArchiveBuilder`, which wraps a
/// `java.util.zip.ZipOutputStream`. It is generic over any seekable writer,
/// matching the Java behavior where the concrete stream (jar or plain zip) is
/// supplied by the caller (the `JarArchiveBuilder` / `ZipArchiveBuilder`
/// subclasses in Ghidra).
pub struct ArchiveBuilder<W: Write + Seek> {
    zip_out: ZipWriter<W>,
}

impl<W: Write + Seek> ArchiveBuilder<W> {
    /// Wraps the given writer in a new `ArchiveBuilder`.
    ///
    /// Mirrors the Java `ArchiveBuilder(ZipOutputStream zos)` constructor.
    pub fn new(writer: W) -> Self {
        ArchiveBuilder {
            zip_out: ZipWriter::new(writer),
        }
    }

    /// Finishes the archive and returns the underlying writer.
    ///
    /// Mirrors the Java `close()` method. Unlike Java, this consumes the builder
    /// and hands the finished writer back so the caller can flush/inspect it.
    pub fn close(self) -> std::io::Result<W> {
        let writer = self.zip_out.finish()?;
        Ok(writer)
    }

    /// Adds an entry named `path` whose contents are read from `file`.
    ///
    /// Mirrors the Java `addFile(String path, File file)`. Fails with an
    /// [`AssertException`]-derived error if `file` is not a regular file (the
    /// Java code throws `AssertException` when handed a directory).
    pub fn add_file(&mut self, path: &str, file: &Path) -> std::io::Result<()> {
        let metadata = std::fs::metadata(file)?;
        if !metadata.is_file() {
            let err = AssertException::with_message("Attempted to write a directory to the jar file");
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, err.to_string()));
        }

        let mut options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
        if let Some(mtime) = last_modified_datetime(&metadata) {
            options = options.last_modified_time(mtime);
        }

        self.zip_out.start_file(path, options)?;

        let mut in_file = std::fs::File::open(file)?;
        let mut bytes = [0u8; 4096];
        loop {
            let num_read = in_file.read(&mut bytes)?;
            if num_read == 0 {
                break;
            }
            self.zip_out.write_all(&bytes[..num_read])?;
        }

        Ok(())
    }

    /// Creates an entry named `path` from `lines`, writing each line followed by
    /// a `'\n'`.
    ///
    /// Mirrors the Java `createFile(String path, List<String> lines)`.
    pub fn create_file<I, S>(&mut self, path: &str, lines: I) -> std::io::Result<()>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
        self.zip_out.start_file(path, options)?;

        for line in lines {
            self.zip_out.write_all(line.as_ref().as_bytes())?;
            self.zip_out.write_all(b"\n")?;
        }

        Ok(())
    }
}

/// Converts a file's modification time into a `zip::DateTime` if possible.
///
/// Builds the archive entry's timestamp from the file's last-modified time,
/// mirroring the Java `entry.setTime(file.lastModified())`. We decompose the
/// Unix timestamp into calendar fields ourselves so no additional date crate is
/// required.
fn last_modified_datetime(metadata: &std::fs::Metadata) -> Option<zip::DateTime> {
    let modified = metadata.modified().ok()?;
    let secs = modified.duration_since(std::time::UNIX_EPOCH).ok()?.as_secs();

    let days = (secs / 86400) as i64;
    let (year, month, day) = days_to_ymd(days);
    let hour = ((secs % 86400) / 3600) as u8;
    let minute = ((secs % 3600) / 60) as u8;
    let second = (secs % 60) as u8;

    // The zip/DOS timestamp format only supports years 1980..=2107.
    if !(1980..=2107).contains(&year) {
        return None;
    }

    zip::DateTime::from_date_and_time(year as u16, month, day, hour, minute, second).ok()
}

/// Converts a count of days since the Unix epoch (1970-01-01) into `(year,
/// month, day)` using Howard Hinnant's civil-from-days algorithm.
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
    use std::io::Cursor;
    use zip::ZipArchive;

    #[test]
    fn create_file_roundtrips_entry_names_and_contents() {
        let buf = Cursor::new(Vec::new());
        let mut builder = ArchiveBuilder::new(buf);

        builder
            .create_file("dir/first.txt", vec!["alpha", "beta"])
            .unwrap();
        builder
            .create_file("second.txt", vec!["only line"])
            .unwrap();

        let cursor = builder.close().unwrap();

        let mut archive = ZipArchive::new(cursor).unwrap();
        assert_eq!(archive.len(), 2);

        let mut first = String::new();
        archive
            .by_name("dir/first.txt")
            .unwrap()
            .read_to_string(&mut first)
            .unwrap();
        assert_eq!(first, "alpha\nbeta\n");

        let mut second = String::new();
        archive
            .by_name("second.txt")
            .unwrap()
            .read_to_string(&mut second)
            .unwrap();
        assert_eq!(second, "only line\n");
    }

    #[test]
    fn add_file_roundtrips_file_contents() {
        use std::io::Write as _;

        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(b"hello archive").unwrap();
        tmp.flush().unwrap();

        let buf = Cursor::new(Vec::new());
        let mut builder = ArchiveBuilder::new(buf);
        builder.add_file("payload.bin", tmp.path()).unwrap();
        let cursor = builder.close().unwrap();

        let mut archive = ZipArchive::new(cursor).unwrap();
        assert_eq!(archive.len(), 1);

        let mut contents = String::new();
        archive
            .by_name("payload.bin")
            .unwrap()
            .read_to_string(&mut contents)
            .unwrap();
        assert_eq!(contents, "hello archive");
    }

    #[test]
    fn add_file_rejects_directory() {
        let dir = tempfile::tempdir().unwrap();

        let buf = Cursor::new(Vec::new());
        let mut builder = ArchiveBuilder::new(buf);
        let result = builder.add_file("adir", dir.path());

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("directory"),
            "expected directory error, got: {err}"
        );
    }

    #[test]
    fn days_to_ymd_known_dates() {
        assert_eq!(days_to_ymd(0), (1970, 1, 1));
        // 2000-01-01 is 10957 days after the epoch.
        assert_eq!(days_to_ymd(10957), (2000, 1, 1));
    }

    #[test]
    fn empty_archive_has_no_entries() {
        let buf = Cursor::new(Vec::new());
        let builder = ArchiveBuilder::new(buf);
        let cursor = builder.close().unwrap();

        let archive = ZipArchive::new(cursor).unwrap();
        assert_eq!(archive.len(), 0);
    }
}

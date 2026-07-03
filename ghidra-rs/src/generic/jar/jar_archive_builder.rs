//! Port of `generic.util.JarArchiveBuilder`.
//!
//! Builds a jar archive (which is just a zip file) by writing entries to a file on disk.
//! This is a thin wrapper around [`ArchiveBuilder`] that handles creating the output file.

use std::fs::File;
use std::io;
use std::path::Path;

use super::super::util::archive_builder::ArchiveBuilder;

/// Builds a jar archive to a file on disk.
///
/// This is the direct analogue of `generic.util.JarArchiveBuilder`, which wraps a
/// `java.util.jar.JarOutputStream` (which is itself just a `java.util.zip.ZipOutputStream`
/// with metadata).
///
/// Mirrors the Java API: the constructor takes an output path and creates the file,
/// then methods like `add_file` and `create_file` add entries to the archive.
pub struct JarArchiveBuilder {
    builder: ArchiveBuilder<File>,
}

impl JarArchiveBuilder {
    /// Creates a new jar archive builder, opening a file for writing at the given path.
    ///
    /// Mirrors the Java `JarArchiveBuilder(File outputFile)` constructor.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be opened for writing.
    pub fn new<P: AsRef<Path>>(output_file: P) -> io::Result<Self> {
        let file = File::create(output_file)?;
        Ok(JarArchiveBuilder {
            builder: ArchiveBuilder::new(file),
        })
    }

    /// Adds an entry named `path` whose contents are read from `file`.
    ///
    /// Mirrors the Java `addFile(String path, File file)`.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read, or if `file` is not a regular file.
    pub fn add_file(&mut self, path: &str, file: &Path) -> io::Result<()> {
        self.builder.add_file(path, file)
    }

    /// Creates an entry named `path` from `lines`, writing each line followed by a newline.
    ///
    /// Mirrors the Java `createFile(String path, List<String> lines)`.
    ///
    /// # Errors
    ///
    /// Returns an error if writing to the archive fails.
    pub fn create_file<I, S>(&mut self, path: &str, lines: I) -> io::Result<()>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.builder.create_file(path, lines)
    }

    /// Finishes writing the archive and closes the underlying file.
    ///
    /// Mirrors the Java `close()` method.
    ///
    /// # Errors
    ///
    /// Returns an error if the archive cannot be finalized.
    pub fn close(self) -> io::Result<()> {
        let _ = self.builder.close()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use tempfile::NamedTempFile;
    use zip::ZipArchive;

    #[test]
    fn new_creates_file() {
        let temp = NamedTempFile::new().unwrap();
        let temp_path = temp.path().to_path_buf();
        drop(temp);

        let builder = JarArchiveBuilder::new(&temp_path).unwrap();
        builder.close().unwrap();

        assert!(temp_path.exists());
    }

    #[test]
    fn add_file_creates_archive_entry() {
        let temp = NamedTempFile::new().unwrap();
        let temp_path = temp.path().to_path_buf();
        drop(temp);

        let mut source_file = NamedTempFile::new().unwrap();
        source_file.write_all(b"test content").unwrap();
        source_file.flush().unwrap();

        let mut builder = JarArchiveBuilder::new(&temp_path).unwrap();
        builder.add_file("test.txt", source_file.path()).unwrap();
        builder.close().unwrap();

        let file = std::fs::File::open(&temp_path).unwrap();
        let mut archive = ZipArchive::new(file).unwrap();
        assert_eq!(archive.len(), 1);

        let mut entry = archive.by_name("test.txt").unwrap();
        let mut contents = String::new();
        entry.read_to_string(&mut contents).unwrap();
        assert_eq!(contents, "test content");
    }

    #[test]
    fn create_file_creates_archive_entry() {
        let temp = NamedTempFile::new().unwrap();
        let temp_path = temp.path().to_path_buf();
        drop(temp);

        let mut builder = JarArchiveBuilder::new(&temp_path).unwrap();
        builder
            .create_file("lines.txt", vec!["line1", "line2", "line3"])
            .unwrap();
        builder.close().unwrap();

        let file = std::fs::File::open(&temp_path).unwrap();
        let mut archive = ZipArchive::new(file).unwrap();
        assert_eq!(archive.len(), 1);

        let mut entry = archive.by_name("lines.txt").unwrap();
        let mut contents = String::new();
        entry.read_to_string(&mut contents).unwrap();
        assert_eq!(contents, "line1\nline2\nline3\n");
    }

    #[test]
    fn multiple_entries() {
        let temp = NamedTempFile::new().unwrap();
        let temp_path = temp.path().to_path_buf();
        drop(temp);

        let mut source1 = NamedTempFile::new().unwrap();
        source1.write_all(b"first").unwrap();
        source1.flush().unwrap();

        let mut source2 = NamedTempFile::new().unwrap();
        source2.write_all(b"second").unwrap();
        source2.flush().unwrap();

        let mut builder = JarArchiveBuilder::new(&temp_path).unwrap();
        builder.add_file("a.txt", source1.path()).unwrap();
        builder.add_file("b.txt", source2.path()).unwrap();
        builder
            .create_file("c.txt", vec!["generated"])
            .unwrap();
        builder.close().unwrap();

        let file = std::fs::File::open(&temp_path).unwrap();
        let mut archive = ZipArchive::new(file).unwrap();
        assert_eq!(archive.len(), 3);

        let mut a = String::new();
        archive.by_name("a.txt").unwrap().read_to_string(&mut a).unwrap();
        assert_eq!(a, "first");

        let mut b = String::new();
        archive.by_name("b.txt").unwrap().read_to_string(&mut b).unwrap();
        assert_eq!(b, "second");

        let mut c = String::new();
        archive.by_name("c.txt").unwrap().read_to_string(&mut c).unwrap();
        assert_eq!(c, "generated\n");
    }

    #[test]
    fn reject_directory() {
        let temp = NamedTempFile::new().unwrap();
        let temp_path = temp.path().to_path_buf();
        drop(temp);

        let dir = tempfile::tempdir().unwrap();

        let mut builder = JarArchiveBuilder::new(&temp_path).unwrap();
        let result = builder.add_file("mydir", dir.path());

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("directory"),
            "expected directory error, got: {err}"
        );
    }
}

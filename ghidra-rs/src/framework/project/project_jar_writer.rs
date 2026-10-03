use std::fs::File;
use std::io::{Read, Seek, Write as IoWrite};
use std::ops::{Deref, DerefMut};
use std::path::Path;

use zip::write::SimpleFileOptions;
use zip::ZipWriter;

use crate::generic::io::JarWriter;
use crate::util::msg::Msg;

const PROPERTIES_FILE_NAME: &str = ".properties";
const ORIGINAL_PROPERTIES_FILE_NAME: &str = "original.properties";

/// Writes the files of a project to a jar output stream.
///
/// Mirrors `ghidra.framework.project.ProjectJarWriter`, which subclasses
/// `generic.io.JarWriter` solely to override file output: a project file
/// named `.properties` is written under the name `original.properties` so
/// it doesn't collide with jar-level `.properties` handling, and the entry
/// is written directly rather than through the inherited `outputEntry`
/// (the Java override takes no `TaskMonitor`, so cancellation/progress
/// reporting are skipped here too). `Deref`/`DerefMut` to the inner
/// [`JarWriter`] expose its unmodified inherited methods (`output_recursively`,
/// `output_entry`, `jar_output_stream`).
pub struct ProjectJarWriter<W: IoWrite + Seek> {
    inner: JarWriter<W>,
}

impl<W: IoWrite + Seek> ProjectJarWriter<W> {
    /// Creates a new `ProjectJarWriter` writing to `jar_out`.
    ///
    /// Mirrors the Java `ProjectJarWriter(JarOutputStream jarOut)` constructor.
    pub fn new(jar_out: ZipWriter<W>) -> Self {
        Self { inner: JarWriter::new(jar_out) }
    }

    /// Outputs an individual file to the jar.
    ///
    /// `jar_path` is the base path to prepend to the file as it is written
    /// to the jar output stream. Mirrors the Java `outputFile(File baseFile,
    /// String jarPath)`. Returns `true` if the file was written to the jar
    /// successfully.
    pub fn output_file(&mut self, base_file: &Path, jar_path: &str) -> bool {
        if base_file.is_dir() {
            return false;
        }

        let mut input = match File::open(base_file) {
            Ok(f) => f,
            Err(fnfe) => {
                Msg::error_with_error(
                    "ProjectJarWriter",
                    &format!("Unexpected Exception: {fnfe}"),
                    &fnfe,
                );
                return false;
            }
        };

        let mut name = base_file
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if name == PROPERTIES_FILE_NAME {
            name = ORIGINAL_PROPERTIES_FILE_NAME.to_string();
        }

        let options = SimpleFileOptions::default();
        let jar_out = self.inner.jar_output_stream();
        if let Err(ioe) = jar_out.start_file(format!("{jar_path}{name}"), options) {
            Msg::error_with_error(
                "ProjectJarWriter",
                &format!("Unexpected Exception: {ioe}"),
                &ioe,
            );
            return false;
        }

        let mut succeeded = true;
        let mut bytes = [0u8; 4096];
        loop {
            match input.read(&mut bytes) {
                Ok(0) => break,
                Ok(num_read) => {
                    if jar_out.write_all(&bytes[..num_read]).is_err() {
                        succeeded = false;
                        break;
                    }
                }
                Err(_ioe) => {
                    succeeded = false;
                    break;
                }
            }
        }

        succeeded
    }
}

impl<W: IoWrite + Seek> Deref for ProjectJarWriter<W> {
    type Target = JarWriter<W>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<W: IoWrite + Seek> DerefMut for ProjectJarWriter<W> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use zip::ZipArchive;

    #[test]
    fn output_file_rejects_directory() {
        let dir = tempfile::tempdir().unwrap();
        let buf = Cursor::new(Vec::new());
        let mut writer = ProjectJarWriter::new(ZipWriter::new(buf));

        assert!(!writer.output_file(dir.path(), ""));
    }

    #[test]
    fn output_file_missing_file_returns_false() {
        let buf = Cursor::new(Vec::new());
        let mut writer = ProjectJarWriter::new(ZipWriter::new(buf));

        let missing = Path::new("/nonexistent/path/does-not-exist.txt");
        assert!(!writer.output_file(missing, ""));
    }

    #[test]
    fn output_file_writes_named_entry() {
        use std::io::Write as _;

        let mut source = tempfile::NamedTempFile::new().unwrap();
        source.write_all(b"file contents").unwrap();
        source.flush().unwrap();

        let buf = Cursor::new(Vec::new());
        let mut writer = ProjectJarWriter::new(ZipWriter::new(buf));

        assert!(writer.output_file(source.path(), "prefix/"));

        let name = source.path().file_name().unwrap().to_string_lossy().into_owned();
        let expected_path = format!("prefix/{name}");

        let cursor = writer.inner.close().unwrap();
        let mut archive = ZipArchive::new(cursor).unwrap();
        let mut contents = String::new();
        archive.by_name(&expected_path).unwrap().read_to_string(&mut contents).unwrap();
        assert_eq!(contents, "file contents");
    }

    #[test]
    fn output_file_renames_properties_file() {
        use std::io::Write as _;

        let dir = tempfile::tempdir().unwrap();
        let props_path = dir.path().join(PROPERTIES_FILE_NAME);
        let mut props_file = File::create(&props_path).unwrap();
        props_file.write_all(b"key=value").unwrap();
        drop(props_file);

        let buf = Cursor::new(Vec::new());
        let mut writer = ProjectJarWriter::new(ZipWriter::new(buf));

        assert!(writer.output_file(&props_path, ""));

        let cursor = writer.inner.close().unwrap();
        let mut archive = ZipArchive::new(cursor).unwrap();
        let mut contents = String::new();
        archive
            .by_name(ORIGINAL_PROPERTIES_FILE_NAME)
            .unwrap()
            .read_to_string(&mut contents)
            .unwrap();
        assert_eq!(contents, "key=value");
        assert!(archive.by_name(PROPERTIES_FILE_NAME).is_err());
    }

    #[test]
    fn deref_exposes_inherited_output_recursively() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("a.txt"), b"aaa").unwrap();

        let buf = Cursor::new(Vec::new());
        let mut writer = ProjectJarWriter::new(ZipWriter::new(buf));
        let monitor = crate::util::task::DummyMonitor;

        assert!(writer.output_recursively(root.path(), "", &monitor));

        let root_name = root.path().file_name().unwrap().to_string_lossy().into_owned();
        let sep = std::path::MAIN_SEPARATOR;

        let cursor = writer.inner.close().unwrap();
        let mut archive = ZipArchive::new(cursor).unwrap();
        let mut a = String::new();
        archive
            .by_name(&format!("{root_name}{sep}a.txt"))
            .unwrap()
            .read_to_string(&mut a)
            .unwrap();
        assert_eq!(a, "aaa");
    }
}

//! Port of `ghidra.app.script.ResourceFileJavaFileObject`.
//!
//! A `javax.tools.JavaFileObject` that works with Ghidra's `ResourceFileJavaFileManager`,
//! used to dynamically compile Ghidra scripts.
//!
//! This promotes the placeholder previously in [`crate::script::seam_stubs`] (which modeled only
//! the two members [`ResourceFileJavaFileManager`](
//! crate::script::resource_file_java_file_manager::ResourceFileJavaFileManager) needed --
//! `get_name`/`to_uri`) to a full port of the Java class's `JavaFileObject` surface.
//!
//! `javax.tools.JavaFileManager`/`JavaCompiler` themselves have no in-process Rust equivalent
//! (see [`ResourceFileJavaFileManager`]'s module doc), so the two members meaningful only to a
//! real JDK compiler's introspection (`getNestingKind()`/`getAccessLevel()`, which this class
//! always answers `null`) are kept as `None`-returning stand-ins rather than backed by real
//! `javax.lang.model.element` enums.

use std::fmt;
use std::io::{self, Read, Write};

use crate::generic::jar::resource_file::ResourceFile;
use crate::script::seam_stubs::FileKind;

/// The file-extension `javax.tools.JavaFileObject.Kind` associates with each [`FileKind`]
/// variant, mirroring `Kind.extension` (`SOURCE = ".java"`, `CLASS = ".class"`,
/// `HTML = ".html"`, `OTHER = ""`).
fn extension_for(kind: FileKind) -> &'static str {
    match kind {
        FileKind::Source => ".java",
        FileKind::Class => ".class",
        FileKind::Html => ".html",
        FileKind::Other => "",
    }
}

/// A [`ResourceFile`]-backed `javax.tools.JavaFileObject`.
///
/// Port of `ghidra.app.script.ResourceFileJavaFileObject`. This class is used to dynamically
/// compile Ghidra scripts.
pub struct ResourceFileJavaFileObject {
    file: ResourceFile,
    path_name: String,
    kind: FileKind,
}

impl ResourceFileJavaFileObject {
    /// Mirrors `ResourceFileJavaFileObject(ResourceFile sourceRoot, ResourceFile file, Kind kind)`.
    ///
    /// `path_name` is `file`'s absolute path with `sourceRoot`'s absolute path (and the
    /// following separator) stripped off. Java computes this via
    /// `pathName = file.getAbsolutePath().substring(sourceRootPath.length() + 1)`, which throws
    /// `StringIndexOutOfBoundsException` if `file` does not actually live under `sourceRoot`;
    /// every real caller ([`ResourceFileJavaFileManager`](
    /// crate::script::resource_file_java_file_manager::ResourceFileJavaFileManager)) only ever
    /// passes a `file` it just found nested under `sourceRoot`, so rather than reproduce that
    /// crash, this port falls back to `file`'s full absolute path in the (otherwise-unreachable)
    /// case where the prefix doesn't match.
    pub fn new(source_root: &ResourceFile, file: ResourceFile, kind: FileKind) -> Self {
        let source_root_path = source_root.absolute_path();
        let file_path = file.absolute_path();
        let path_name = file_path
            .strip_prefix(&source_root_path)
            .map(|s| s.trim_start_matches(std::path::MAIN_SEPARATOR).to_string())
            .unwrap_or(file_path);
        Self { file, path_name, kind }
    }

    /// Mirrors `getFile()`: the [`ResourceFile`] this object represents.
    pub fn get_file(&self) -> &ResourceFile {
        &self.file
    }

    /// Mirrors `toUri()`. Java returns a real `java.net.URI`; nothing in this crate needs to
    /// resolve or parse it (only compare it, via
    /// [`ResourceFileJavaFileManager::is_same_file`](
    /// crate::script::resource_file_java_file_manager::ResourceFileJavaFileManager::is_same_file)),
    /// so a stable string identity is enough.
    pub fn to_uri(&self) -> String {
        format!("file://{}", self.file.absolute_path())
    }

    /// Mirrors `getName()`: the path relative to the source root this object was constructed
    /// with.
    pub fn get_name(&self) -> &str {
        &self.path_name
    }

    /// Mirrors `openInputStream()`.
    pub fn open_input_stream(&self) -> io::Result<Box<dyn Read>> {
        self.file.get_input_stream()
    }

    /// Mirrors `openOutputStream()`, which unconditionally throws
    /// `UnsupportedOperationException` -- this file object is read-only. The Java method
    /// declares `throws IOException`, so an [`io::Error`] (rather than a panic) is the faithful
    /// Rust shape for the always-thrown condition.
    pub fn open_output_stream(&self) -> io::Result<Box<dyn Write>> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "openOutputStream is not supported"))
    }

    /// Mirrors `openReader(boolean)`.
    ///
    /// Java wraps the raw byte stream in `new InputStreamReader(file.getInputStream())` -- no
    /// charset argument, so decoding uses the JVM's *platform default charset*. Rust has no
    /// equivalent ambient default, so bytes are decoded as UTF-8 here: losslessly when
    /// `ignore_encoding_errors` is `false` (a decode failure becomes an [`io::Error`]), or via
    /// lossy replacement when `ignore_encoding_errors` is `true`, matching the caller's stated
    /// tolerance for malformed input.
    pub fn open_reader(&self, ignore_encoding_errors: bool) -> io::Result<String> {
        let mut bytes = Vec::new();
        self.file.get_input_stream()?.read_to_end(&mut bytes)?;
        if ignore_encoding_errors {
            Ok(String::from_utf8_lossy(&bytes).into_owned())
        } else {
            String::from_utf8(bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
        }
    }

    /// Mirrors `getCharContent(boolean)`.
    ///
    /// Java builds the result by repeatedly calling `BufferedReader.readLine()` (which strips
    /// the original line terminator from each line) and re-appending `"\n"` after every line --
    /// *including the last one*, even when the source has no trailing newline. That is a genuine
    /// quirk: the returned content is not always byte-identical to the source once re-encoded.
    /// It is faithfully reproduced here (not "fixed") -- see
    /// [`get_char_content_always_appends_trailing_newline`](
    /// tests::get_char_content_always_appends_trailing_newline) for a dedicated test.
    pub fn get_char_content(&self, ignore_encoding_errors: bool) -> io::Result<String> {
        let content = self.open_reader(ignore_encoding_errors)?;
        let mut result = String::with_capacity(content.len() + 1);
        for line in content.lines() {
            result.push_str(line);
            result.push('\n');
        }
        Ok(result)
    }

    /// Mirrors `openWriter()`, which unconditionally throws `UnsupportedOperationException`.
    pub fn open_writer(&self) -> io::Result<Box<dyn Write>> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "openWriter is not supported"))
    }

    /// Mirrors `getLastModified()`.
    pub fn get_last_modified(&self) -> i64 {
        self.file.last_modified() as i64
    }

    /// Mirrors `delete()`, which unconditionally throws `UnsupportedOperationException`. Java's
    /// `boolean delete()` signature has no `Result`-friendly shape to carry that failure, so
    /// (matching this crate's existing precedent for unconditional unchecked-exception ports,
    /// e.g. `program::database::properties::generic_saveable`) this panics rather than ever
    /// returning `false`.
    pub fn delete(&self) -> bool {
        panic!("UnsupportedOperationException: ResourceFileJavaFileObject.delete is not supported")
    }

    /// Mirrors `getKind()`.
    pub fn get_kind(&self) -> FileKind {
        self.kind
    }

    /// Mirrors `isNameCompatible(String, Kind)`.
    ///
    /// Java's `equalsIgnoreCase` fallback is a general (locale-independent) case fold; Rust's
    /// closest built-in is `str::to_lowercase`, used here rather than `eq_ignore_ascii_case` so
    /// non-ASCII names still fold the same way Java's does.
    pub fn is_name_compatible(&self, compatible_name: &str, test_kind: FileKind) -> bool {
        if self.kind != test_kind && test_kind == FileKind::Other {
            return false;
        }

        let test_name = format!("{compatible_name}{}", extension_for(test_kind));
        let my_name = self.file.name();
        if my_name == test_name {
            return true;
        }

        // check for OSes with non-unique case
        if my_name.to_lowercase() == test_name.to_lowercase() {
            let my_canonical_name = self.canonical_name();
            return my_canonical_name == test_name;
        }

        false
    }

    /// Mirrors `file.getCanonicalFile().getName()`, the OS-non-unique-case fallback branch of
    /// [`is_name_compatible`](Self::is_name_compatible). [`ResourceFile`] doesn't expose Java's
    /// canonical-file resolution, so this resolves the canonical path directly via
    /// [`std::fs::canonicalize`] on the underlying file path when one is available, falling back
    /// to the plain (uncanonicalized) name otherwise -- e.g. for a non-existent or
    /// non-plain-file resource, where Java's `getCanonicalFile()` would itself just hand back an
    /// equivalent, uncanonicalized file.
    fn canonical_name(&self) -> String {
        self.file
            .get_file(false)
            .and_then(|path| std::fs::canonicalize(path).ok())
            .and_then(|canon| canon.file_name().map(|n| n.to_string_lossy().into_owned()))
            .unwrap_or_else(|| self.file.name())
    }

    /// Mirrors `getNestingKind()`, which always returns `null`.
    pub fn get_nesting_kind(&self) -> Option<()> {
        None
    }

    /// Mirrors `getAccessLevel()`, which always returns `null`.
    pub fn get_access_level(&self) -> Option<()> {
        None
    }
}

impl fmt::Display for ResourceFileJavaFileObject {
    /// Mirrors the overridden `toString()`, which intentionally returns just the file's bare
    /// name (`file.getName()`) rather than [`get_name`](Self::get_name)'s source-root-relative
    /// path -- "so stack traces use the name of the file and not this class's name", per the
    /// Java doc comment on this override (Java's default `Object.toString()`, `ClassName@hash`,
    /// is what would otherwise appear when a dynamic script compile error is reported).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.file.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn write(dir: &std::path::Path, relative: &str, contents: &str) {
        let path = dir.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, contents).unwrap();
    }

    #[test]
    fn get_name_returns_path_relative_to_source_root() {
        let dir = tempdir().unwrap();
        write(dir.path(), "com/example/Foo.java", "class Foo {}");
        let source_dir = ResourceFile::new(dir.path().to_path_buf());
        let file = ResourceFile::new(dir.path().join("com/example/Foo.java"));

        let object = ResourceFileJavaFileObject::new(&source_dir, file, FileKind::Source);
        assert_eq!(object.get_name(), "com/example/Foo.java");
    }

    #[test]
    fn to_string_returns_bare_file_name_not_relative_path() {
        let dir = tempdir().unwrap();
        write(dir.path(), "com/example/Foo.java", "class Foo {}");
        let source_dir = ResourceFile::new(dir.path().to_path_buf());
        let file = ResourceFile::new(dir.path().join("com/example/Foo.java"));

        let object = ResourceFileJavaFileObject::new(&source_dir, file, FileKind::Source);
        assert_eq!(object.get_name(), "com/example/Foo.java");
        assert_eq!(object.to_string(), "Foo.java");
    }

    #[test]
    fn open_input_stream_reads_file_contents() {
        let dir = tempdir().unwrap();
        write(dir.path(), "Foo.java", "class Foo {}");
        let source_dir = ResourceFile::new(dir.path().to_path_buf());
        let file = ResourceFile::new(dir.path().join("Foo.java"));

        let object = ResourceFileJavaFileObject::new(&source_dir, file, FileKind::Source);
        let mut contents = String::new();
        object.open_input_stream().unwrap().read_to_string(&mut contents).unwrap();
        assert_eq!(contents, "class Foo {}");
    }

    #[test]
    fn open_output_stream_is_unsupported() {
        let dir = tempdir().unwrap();
        write(dir.path(), "Foo.java", "class Foo {}");
        let source_dir = ResourceFile::new(dir.path().to_path_buf());
        let file = ResourceFile::new(dir.path().join("Foo.java"));

        let object = ResourceFileJavaFileObject::new(&source_dir, file, FileKind::Source);
        match object.open_output_stream() {
            Err(err) => assert_eq!(err.kind(), io::ErrorKind::Unsupported),
            Ok(_) => panic!("expected openOutputStream to be unsupported"),
        }
    }

    #[test]
    fn open_writer_is_unsupported() {
        let dir = tempdir().unwrap();
        write(dir.path(), "Foo.java", "class Foo {}");
        let source_dir = ResourceFile::new(dir.path().to_path_buf());
        let file = ResourceFile::new(dir.path().join("Foo.java"));

        let object = ResourceFileJavaFileObject::new(&source_dir, file, FileKind::Source);
        match object.open_writer() {
            Err(err) => assert_eq!(err.kind(), io::ErrorKind::Unsupported),
            Ok(_) => panic!("expected openWriter to be unsupported"),
        }
    }

    /// Java bug/quirk: `ResourceFileJavaFileObject.getCharContent` rebuilds its result by
    /// calling `BufferedReader.readLine()` in a loop and appending `"\n"` after *every* line,
    /// including the final one -- even when the source file has no trailing newline at all. See
    /// `ResourceFileJavaFileObject.java` lines 85-99. This test pins that faithfully-reproduced
    /// quirk down rather than "fixing" it to preserve the original trailing-newline-or-not state.
    #[test]
    fn get_char_content_always_appends_trailing_newline() {
        let dir = tempdir().unwrap();
        write(dir.path(), "NoTrailingNewline.java", "a\nb");
        let source_dir = ResourceFile::new(dir.path().to_path_buf());
        let file = ResourceFile::new(dir.path().join("NoTrailingNewline.java"));

        let object = ResourceFileJavaFileObject::new(&source_dir, file, FileKind::Source);
        let content = object.get_char_content(false).unwrap();

        assert_eq!(content, "a\nb\n", "a trailing newline is synthesized even though the source had none");
    }

    #[test]
    fn get_char_content_of_empty_file_is_empty() {
        let dir = tempdir().unwrap();
        write(dir.path(), "Empty.java", "");
        let source_dir = ResourceFile::new(dir.path().to_path_buf());
        let file = ResourceFile::new(dir.path().join("Empty.java"));

        let object = ResourceFileJavaFileObject::new(&source_dir, file, FileKind::Source);
        assert_eq!(object.get_char_content(false).unwrap(), "");
    }

    #[test]
    fn get_last_modified_matches_underlying_file() {
        let dir = tempdir().unwrap();
        write(dir.path(), "Foo.java", "class Foo {}");
        let source_dir = ResourceFile::new(dir.path().to_path_buf());
        let file = ResourceFile::new(dir.path().join("Foo.java"));
        let expected = file.last_modified() as i64;

        let object = ResourceFileJavaFileObject::new(&source_dir, file, FileKind::Source);
        assert_eq!(object.get_last_modified(), expected);
    }

    #[test]
    fn delete_panics_with_unsupported_operation() {
        let dir = tempdir().unwrap();
        write(dir.path(), "Foo.java", "class Foo {}");
        let source_dir = ResourceFile::new(dir.path().to_path_buf());
        let file = ResourceFile::new(dir.path().join("Foo.java"));
        let object = ResourceFileJavaFileObject::new(&source_dir, file, FileKind::Source);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| object.delete()));
        assert!(result.is_err(), "delete() must panic, mirroring UnsupportedOperationException");
    }

    #[test]
    fn get_kind_returns_constructed_kind() {
        let dir = tempdir().unwrap();
        write(dir.path(), "Foo.class", "");
        let source_dir = ResourceFile::new(dir.path().to_path_buf());
        let file = ResourceFile::new(dir.path().join("Foo.class"));

        let object = ResourceFileJavaFileObject::new(&source_dir, file, FileKind::Class);
        assert_eq!(object.get_kind(), FileKind::Class);
    }

    #[test]
    fn is_name_compatible_matches_exact_name_and_extension() {
        let dir = tempdir().unwrap();
        write(dir.path(), "Foo.java", "class Foo {}");
        let source_dir = ResourceFile::new(dir.path().to_path_buf());
        let file = ResourceFile::new(dir.path().join("Foo.java"));

        let object = ResourceFileJavaFileObject::new(&source_dir, file, FileKind::Source);
        assert!(object.is_name_compatible("Foo", FileKind::Source));
        assert!(!object.is_name_compatible("Bar", FileKind::Source));
    }

    #[test]
    fn is_name_compatible_returns_false_immediately_for_mismatched_other_kind() {
        let dir = tempdir().unwrap();
        write(dir.path(), "Foo.java", "class Foo {}");
        let source_dir = ResourceFile::new(dir.path().to_path_buf());
        let file = ResourceFile::new(dir.path().join("Foo.java"));

        // this object's own kind is Source (not Other), and the requested testKind is Other:
        // isNameCompatible short-circuits to false without even comparing names.
        let object = ResourceFileJavaFileObject::new(&source_dir, file, FileKind::Source);
        assert!(!object.is_name_compatible("Foo", FileKind::Other));
    }

    /// Exercises the "OSes with non-unique case" fallback branch. On this crate's CI/dev
    /// filesystem (case-sensitive Linux), canonicalization does not fold case, so this correctly
    /// returns `false` -- matching Java's real behavior on a case-sensitive OS, where
    /// `getCanonicalFile()` would likewise hand back the original (differently-cased) name.
    #[test]
    fn is_name_compatible_case_mismatch_falls_back_to_canonical_name() {
        let dir = tempdir().unwrap();
        write(dir.path(), "Foo.java", "class Foo {}");
        let source_dir = ResourceFile::new(dir.path().to_path_buf());
        let file = ResourceFile::new(dir.path().join("Foo.java"));

        let object = ResourceFileJavaFileObject::new(&source_dir, file, FileKind::Source);
        assert!(!object.is_name_compatible("foo", FileKind::Source));
    }

    #[test]
    fn get_nesting_kind_and_access_level_are_always_none() {
        let dir = tempdir().unwrap();
        write(dir.path(), "Foo.java", "class Foo {}");
        let source_dir = ResourceFile::new(dir.path().to_path_buf());
        let file = ResourceFile::new(dir.path().join("Foo.java"));

        let object = ResourceFileJavaFileObject::new(&source_dir, file, FileKind::Source);
        assert_eq!(object.get_nesting_kind(), None);
        assert_eq!(object.get_access_level(), None);
    }

    #[test]
    fn to_uri_is_stable_and_distinguishes_files() {
        let dir = tempdir().unwrap();
        write(dir.path(), "Foo.java", "class Foo {}");
        write(dir.path(), "Bar.java", "class Bar {}");
        let source_dir = ResourceFile::new(dir.path().to_path_buf());

        let foo = ResourceFileJavaFileObject::new(
            &source_dir,
            ResourceFile::new(dir.path().join("Foo.java")),
            FileKind::Source,
        );
        let foo_again = ResourceFileJavaFileObject::new(
            &source_dir,
            ResourceFile::new(dir.path().join("Foo.java")),
            FileKind::Source,
        );
        let bar = ResourceFileJavaFileObject::new(
            &source_dir,
            ResourceFile::new(dir.path().join("Bar.java")),
            FileKind::Source,
        );

        assert_eq!(foo.to_uri(), foo_again.to_uri());
        assert_ne!(foo.to_uri(), bar.to_uri());
    }
}

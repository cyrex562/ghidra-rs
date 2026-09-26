//! Port of `generic.jar.Resource` and `generic.jar.FileResource`.
//!
//! `Resource` is Java's interface for representing a file-system-like object, regardless of
//! whether it is a real file or an entry inside a compressed (jar) filesystem; `FileResource` is
//! its concrete, real-filesystem-backed implementation, wrapping a plain `java.io.File`.
//!
//! # Scope of this port
//!
//! The `Resource` trait and `FileResource` struct pre-date this port and are already used
//! throughout the crate (via [`ResourceFile`](super::resource_file::ResourceFile), itself used
//! pervasively -- see e.g. [`crate::framework::application`],
//! [`crate::app::plugin::core::osgi::bundle_map`]). The original 11 members
//! (`get_resource`/`absolute_path`/`name`/`is_directory`/`is_file`/`exists`/`last_modified`/
//! `length`/`get_input_stream`/`get_output_stream`/`get_file`) are therefore left with their
//! existing behavior and signatures untouched to avoid regressing that wide surface. This port
//! *adds* the remaining members of the real Java `Resource` interface/`FileResource` class that
//! were missing: `listFiles()`/`listFiles(ResourceFileFilter)`, `getParent()`, `toURL()`,
//! `toURI()`, `delete()`, `getCanonicalPath()`, `getCanonicalResource()`, `canWrite()`, `mkdir()`,
//! `getFileSystemRoot()`, and `getResourceAsFile(ResourceFile)`. `Resource` has exactly one
//! implementor in this crate (`FileResource` itself), so adding required trait methods is safe.
//!
//! # `getParent()`/`getFileSystemRoot()`: Java's `File.getParentFile()` null quirk
//!
//! Java's `File("name.txt").getParentFile()` returns `null` for a bare, single-component
//! relative path (no directory separator), since `File` never consults the filesystem or CWD to
//! answer this -- it's purely a string operation. Rust's [`Path::parent`] differs subtly here: for
//! a single relative component it returns `Some("")` (an *empty* path), not `None`. [`java_parent`]
//! reproduces Java's exact null-for-bare-name behavior by treating that empty-path case as `None`,
//! and both [`FileResource::parent`]/[`Resource::parent`] and
//! [`Resource::file_system_root`]/[`FileResource::file_system_root`] are built on it so they match
//! `FileResource.getParent()`/`getFileSystemRoot()` precisely, including for relative paths (whose
//! Java "root" is just the outermost path component actually present in the string -- no absolute
//! resolution against the CWD is performed, matching `getParentFile()`'s purely lexical nature).
//!
//! # `getResourceAsFile(ResourceFile)` ignores its argument (preserved quirk)
//!
//! Java's `FileResource.getResourceAsFile(ResourceFile resourceFile) { return file; }` never
//! actually inspects its parameter -- it always returns this resource's own backing file. This is
//! preserved faithfully by [`FileResource::resource_as_file`] rather than "fixed" to use the
//! argument; see `resource_as_file_ignores_its_argument_matching_java_quirk` below.
//!
//! # Documented simplifications
//!
//! * [`Resource::can_write`]/[`FileResource::can_write`] approximates Java's `File.canWrite()`
//!   (a real OS access-permission check) via [`std::fs::Permissions::readonly`], since this crate
//!   has no portable syscall-level "can this process write here" check available without adding a
//!   new dependency. This is an adequate approximation for the common case (a file's own
//!   read-only bit) but does not model owner/group/ACL-level permission nuances the way a real
//!   `access(2)` check would.
//! * [`Resource::canonical_path`]/[`FileResource::canonical_path`] delegates to
//!   [`std::fs::canonicalize`], which (unlike Java's `File.getCanonicalPath()`) requires the path
//!   to exist; a nonexistent path yields an `Err` here where Java could still lexically normalize
//!   one.
//! * [`Resource::to_uri`]/[`Resource::to_url`] produce a `file://`-prefixed string rather than a
//!   real, percent-encoded URI/URL object, matching the established precedent in
//!   [`ResourceFileJavaFileObject::to_uri`](crate::script::resource_file_java_file_object::ResourceFileJavaFileObject::to_uri)
//!   and [`JarEntryRootNode::to_url`](super::jar_entry_root_node::JarEntryRootNode::to_url).

use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use super::resource_file::ResourceFile;
use super::resource_file_filter::ResourceFileFilter;

/// Reproduces Java's `File.getParentFile()`: the given path without its final component, or
/// `None` if there is none. See the module docs for why this isn't simply [`Path::parent`].
fn java_parent(path: &Path) -> Option<PathBuf> {
    let parent = path.parent()?;
    if parent.as_os_str().is_empty() {
        return None;
    }
    Some(parent.to_path_buf())
}

pub trait Resource: Send + Sync {
    fn get_resource(&self, path: &str) -> Box<dyn Resource>;
    fn absolute_path(&self) -> String;
    fn name(&self) -> String;
    fn is_directory(&self) -> bool;
    fn is_file(&self) -> bool;
    fn exists(&self) -> bool;
    fn last_modified(&self) -> u64;
    fn length(&self) -> u64;
    fn get_input_stream(&self) -> io::Result<Box<dyn Read>>;
    fn get_output_stream(&self) -> io::Result<Box<dyn Write>>;
    fn get_file(&self) -> Option<PathBuf>;

    /// Port of `Resource.listFiles()`. Returns `None` when the underlying `File.listFiles()`
    /// would (not a directory, or an I/O error occurred).
    fn list_files(&self) -> Option<Vec<ResourceFile>>;

    /// Port of `Resource.listFiles(ResourceFileFilter)`. Returns `None` under the same conditions
    /// as [`list_files`](Self::list_files); once the underlying directory listing succeeds, this
    /// always returns `Some` (even if the filter accepts nothing).
    fn list_files_filtered(&self, filter: &dyn ResourceFileFilter) -> Option<Vec<ResourceFile>>;

    /// Port of `Resource.getParent()`.
    fn parent(&self) -> Option<Box<dyn Resource>>;

    /// Port of `Resource.toURL()`.
    fn to_url(&self) -> io::Result<String>;

    /// Port of `Resource.toURI()`.
    fn to_uri(&self) -> String;

    /// Port of `Resource.delete()`.
    fn delete(&self) -> bool;

    /// Port of `Resource.getCanonicalPath()`.
    fn canonical_path(&self) -> io::Result<String>;

    /// Port of `Resource.getCanonicalResource()`.
    fn canonical_resource(&self) -> Box<dyn Resource>;

    /// Port of `Resource.canWrite()`.
    fn can_write(&self) -> bool;

    /// Port of `Resource.mkdir()`.
    fn mkdir(&self) -> bool;

    /// Port of `Resource.getFileSystemRoot()`.
    fn file_system_root(&self) -> PathBuf;

    /// Port of `Resource.getResourceAsFile(ResourceFile)`. See the module docs for the Java
    /// quirk this preserves (the argument is ignored).
    fn resource_as_file(&self, resource_file: &ResourceFile) -> PathBuf;
}

/// Port of `generic.jar.FileResource`: a [`Resource`] backed by a real filesystem file.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FileResource {
    path: PathBuf,
}

impl FileResource {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl std::fmt::Display for FileResource {
    /// Port of `FileResource.toString()`: `return getAbsolutePath();`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.absolute_path())
    }
}

impl Resource for FileResource {
    fn get_resource(&self, path: &str) -> Box<dyn Resource> {
        Box::new(FileResource::new(self.path.join(path)))
    }

    fn absolute_path(&self) -> String {
        self.path.to_string_lossy().to_string()
    }

    fn name(&self) -> String {
        self.path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default()
    }

    fn is_directory(&self) -> bool {
        self.path.is_dir()
    }

    fn is_file(&self) -> bool {
        self.path.is_file()
    }

    fn exists(&self) -> bool {
        self.path.exists()
    }

    fn last_modified(&self) -> u64 {
        fs::metadata(&self.path)
            .and_then(|m| m.modified())
            .map(|t| {
                t.duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
            })
            .unwrap_or(0)
    }

    fn length(&self) -> u64 {
        fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0)
    }

    fn get_input_stream(&self) -> io::Result<Box<dyn Read>> {
        Ok(Box::new(fs::File::open(&self.path)?))
    }

    fn get_output_stream(&self) -> io::Result<Box<dyn Write>> {
        Ok(Box::new(fs::File::create(&self.path)?))
    }

    fn get_file(&self) -> Option<PathBuf> {
        Some(self.path.clone())
    }

    fn list_files(&self) -> Option<Vec<ResourceFile>> {
        let entries = fs::read_dir(&self.path).ok()?;
        let mut result = Vec::new();
        for entry in entries {
            let entry = entry.ok()?;
            result.push(ResourceFile::from_resource(Box::new(FileResource::new(entry.path()))));
        }
        Some(result)
    }

    fn list_files_filtered(&self, filter: &dyn ResourceFileFilter) -> Option<Vec<ResourceFile>> {
        let all = self.list_files()?;
        Some(all.into_iter().filter(|f| filter.accept(f)).collect())
    }

    fn parent(&self) -> Option<Box<dyn Resource>> {
        if let Some(parent) = java_parent(&self.path) {
            return Some(Box::new(FileResource::new(parent)));
        }
        // Java: `file.getAbsoluteFile().getParentFile()`. `getAbsoluteFile()` prepends the CWD
        // for a relative path without resolving symlinks/`.`/`..` -- matched here rather than
        // `std::fs::canonicalize`, which does both of those and also requires the path to exist.
        let absolute = if self.path.is_absolute() {
            self.path.clone()
        } else {
            std::env::current_dir().ok()?.join(&self.path)
        };
        java_parent(&absolute).map(|p| Box::new(FileResource::new(p)) as Box<dyn Resource>)
    }

    fn to_url(&self) -> io::Result<String> {
        Ok(self.to_uri())
    }

    fn to_uri(&self) -> String {
        format!("file://{}", self.path.display())
    }

    fn delete(&self) -> bool {
        if self.path.is_dir() {
            fs::remove_dir(&self.path).is_ok()
        } else {
            fs::remove_file(&self.path).is_ok()
        }
    }

    fn canonical_path(&self) -> io::Result<String> {
        Ok(self.path.canonicalize()?.to_string_lossy().to_string())
    }

    fn canonical_resource(&self) -> Box<dyn Resource> {
        match self.path.canonicalize() {
            Ok(p) => Box::new(FileResource::new(p)),
            Err(_) => Box::new(self.clone()),
        }
    }

    fn can_write(&self) -> bool {
        fs::metadata(&self.path).map(|m| !m.permissions().readonly()).unwrap_or(false)
    }

    fn mkdir(&self) -> bool {
        fs::create_dir(&self.path).is_ok()
    }

    fn file_system_root(&self) -> PathBuf {
        let mut test = self.path.clone();
        while let Some(parent) = java_parent(&test) {
            test = parent;
        }
        test
    }

    fn resource_as_file(&self, _resource_file: &ResourceFile) -> PathBuf {
        // See the module docs: Java's implementation ignores its argument.
        self.path.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn parent_of_multi_segment_relative_path_strips_last_component() {
        let fr = FileResource::new(PathBuf::from("a/b.txt"));
        let parent = fr.parent().expect("should have a parent");
        assert_eq!(parent.get_file(), Some(PathBuf::from("a")));
    }

    #[test]
    fn parent_of_bare_relative_name_falls_back_to_absolute_file_parent() {
        // Java: File("name.txt").getParentFile() is null, so FileResource.getParent() falls
        // back to file.getAbsoluteFile().getParentFile(), i.e. the CWD.
        let fr = FileResource::new(PathBuf::from("name.txt"));
        let parent = fr.parent().expect("bare relative name falls back to the CWD's parent-ish path");
        let expected = std::env::current_dir().unwrap();
        assert_eq!(parent.get_file(), Some(expected));
    }

    #[test]
    fn parent_of_filesystem_root_is_none() {
        let fr = FileResource::new(PathBuf::from("/"));
        assert!(fr.parent().is_none());
    }

    #[test]
    fn file_system_root_of_relative_path_is_its_outermost_component() {
        // Matches Java: getFileSystemRoot() never consults the CWD, so a relative path's "root"
        // is simply its own first path component, not the real filesystem root.
        let fr = FileResource::new(PathBuf::from("a/b/c"));
        assert_eq!(fr.file_system_root(), PathBuf::from("a"));
    }

    #[test]
    fn file_system_root_of_bare_relative_name_is_itself() {
        let fr = FileResource::new(PathBuf::from("name.txt"));
        assert_eq!(fr.file_system_root(), PathBuf::from("name.txt"));
    }

    #[test]
    fn file_system_root_of_absolute_path_is_the_root() {
        let fr = FileResource::new(PathBuf::from("/tmp/a/b"));
        assert_eq!(fr.file_system_root(), PathBuf::from("/"));
    }

    #[test]
    fn resource_as_file_ignores_its_argument_matching_java_quirk() {
        let fr = FileResource::new(PathBuf::from("/tmp/real.txt"));
        let unrelated = ResourceFile::new(PathBuf::from("/somewhere/else/entirely.txt"));
        // Even though `unrelated` is a completely different file, Java's
        // FileResource.getResourceAsFile ignores it and returns this resource's own file.
        assert_eq!(fr.resource_as_file(&unrelated), PathBuf::from("/tmp/real.txt"));
    }

    #[test]
    fn list_files_returns_none_for_a_plain_file() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("plain.txt");
        fs::write(&file_path, "x").unwrap();

        let fr = FileResource::new(file_path);
        assert!(fr.list_files().is_none());
    }

    #[test]
    fn list_files_lists_directory_contents() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "a").unwrap();
        fs::write(dir.path().join("b.txt"), "b").unwrap();

        let fr = FileResource::new(dir.path().to_path_buf());
        let mut names: Vec<String> = fr.list_files().unwrap().iter().map(|f| f.name()).collect();
        names.sort();
        assert_eq!(names, vec!["a.txt".to_string(), "b.txt".to_string()]);
    }

    #[test]
    fn list_files_filtered_applies_the_filter() {
        struct TxtOnly;
        impl ResourceFileFilter for TxtOnly {
            fn accept(&self, file: &ResourceFile) -> bool {
                file.name().ends_with(".txt")
            }
        }

        let dir = tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "a").unwrap();
        fs::write(dir.path().join("b.bin"), "b").unwrap();

        let fr = FileResource::new(dir.path().to_path_buf());
        let filtered = fr.list_files_filtered(&TxtOnly).unwrap();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].name(), "a.txt");
    }

    #[test]
    fn list_files_filtered_returns_none_for_a_plain_file() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("plain.txt");
        fs::write(&file_path, "x").unwrap();

        struct AcceptAll;
        impl ResourceFileFilter for AcceptAll {
            fn accept(&self, _file: &ResourceFile) -> bool {
                true
            }
        }

        let fr = FileResource::new(file_path);
        assert!(fr.list_files_filtered(&AcceptAll).is_none());
    }

    #[test]
    fn delete_removes_a_file() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("doomed.txt");
        fs::write(&file_path, "x").unwrap();

        let fr = FileResource::new(file_path.clone());
        assert!(fr.delete());
        assert!(!file_path.exists());
    }

    #[test]
    fn delete_of_missing_file_returns_false() {
        let fr = FileResource::new(PathBuf::from("/nonexistent/path/for/sure.txt"));
        assert!(!fr.delete());
    }

    #[test]
    fn canonical_path_resolves_an_existing_file() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("real.txt");
        fs::write(&file_path, "x").unwrap();

        let fr = FileResource::new(file_path);
        assert!(fr.canonical_path().is_ok());
    }

    #[test]
    fn canonical_path_errors_for_a_nonexistent_file() {
        let fr = FileResource::new(PathBuf::from("/definitely/does/not/exist.txt"));
        assert!(fr.canonical_path().is_err());
    }

    #[test]
    fn canonical_resource_falls_back_to_self_on_error() {
        let fr = FileResource::new(PathBuf::from("/definitely/does/not/exist.txt"));
        let canon = fr.canonical_resource();
        assert_eq!(canon.get_file(), Some(PathBuf::from("/definitely/does/not/exist.txt")));
    }

    #[test]
    fn canonical_resource_resolves_an_existing_file() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("real.txt");
        fs::write(&file_path, "x").unwrap();

        let fr = FileResource::new(file_path.clone());
        let canon = fr.canonical_resource();
        assert_eq!(canon.get_file(), Some(file_path.canonicalize().unwrap()));
    }

    #[test]
    fn mkdir_creates_a_single_directory() {
        let dir = tempdir().unwrap();
        let new_dir = dir.path().join("child");

        let fr = FileResource::new(new_dir.clone());
        assert!(fr.mkdir());
        assert!(new_dir.is_dir());
    }

    #[test]
    fn mkdir_fails_when_parent_is_missing() {
        let dir = tempdir().unwrap();
        let nested = dir.path().join("missing_parent").join("child");

        let fr = FileResource::new(nested);
        assert!(!fr.mkdir());
    }

    #[test]
    fn can_write_true_for_a_writable_file() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("writable.txt");
        fs::write(&file_path, "x").unwrap();

        let fr = FileResource::new(file_path);
        assert!(fr.can_write());
    }

    #[test]
    fn can_write_false_for_a_readonly_file() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("readonly.txt");
        fs::write(&file_path, "x").unwrap();
        let mut perms = fs::metadata(&file_path).unwrap().permissions();
        perms.set_readonly(true);
        fs::set_permissions(&file_path, perms).unwrap();

        let fr = FileResource::new(file_path.clone());
        assert!(!fr.can_write());

        // Restore write permission so tempdir cleanup can remove it.
        let mut perms = fs::metadata(&file_path).unwrap().permissions();
        perms.set_readonly(false);
        fs::set_permissions(&file_path, perms).unwrap();
    }

    #[test]
    fn to_uri_and_to_url_are_file_prefixed() {
        let fr = FileResource::new(PathBuf::from("/tmp/thing.txt"));
        assert_eq!(fr.to_uri(), "file:///tmp/thing.txt");
        assert_eq!(fr.to_url().unwrap(), "file:///tmp/thing.txt");
    }

    #[test]
    fn equality_and_hash_are_based_on_the_path() {
        use std::collections::HashSet;
        let a = FileResource::new(PathBuf::from("/tmp/a.txt"));
        let b = FileResource::new(PathBuf::from("/tmp/a.txt"));
        let c = FileResource::new(PathBuf::from("/tmp/b.txt"));
        assert_eq!(a, b);
        assert_ne!(a, c);

        let mut set = HashSet::new();
        set.insert(a.clone());
        assert!(set.contains(&b));
        assert!(!set.contains(&c));
    }

    #[test]
    fn display_matches_absolute_path() {
        let fr = FileResource::new(PathBuf::from("/tmp/thing.txt"));
        assert_eq!(fr.to_string(), fr.absolute_path());
    }

    #[test]
    fn get_resource_joins_child_path() {
        let fr = FileResource::new(PathBuf::from("/tmp"));
        let child = fr.get_resource("child.txt");
        assert_eq!(child.get_file(), Some(PathBuf::from("/tmp/child.txt")));
    }
}

//! Port of `ghidra.app.script.ResourceFileJavaFileManager`.
//!
//! Java's version wraps the JDK's `javax.tools.StandardJavaFileManager` (obtained from
//! `ToolProvider.getSystemJavaCompiler()`) so Ghidra's script/bundle compiler can resolve Java
//! sources that live in [`ResourceFile`]-backed script directories, in addition to a plain
//! classpath. Rust has no in-process `javax.tools` compiler to delegate to, so this port keeps
//! the piece that has meaning outside a JVM: resolving `.java`/`.class` files under `source_dirs`
//! while skipping `files_to_avoid`. The JDK delegate surface (`isSupportedOption`,
//! `getClassLoader`, module lookups, `flush`/`close`, ...) has nothing to delegate to in Rust and
//! is not modeled.

use crate::generic::jar::resource_file::ResourceFile;
use crate::script::seam_stubs::{FileKind, ResourceFileJavaFileObject};
use crate::util::exception::AssertException;
use std::fs;

/// The subset of `javax.tools.JavaFileManager.Location` this type distinguishes. Ghidra only
/// ever asks it to resolve `StandardLocation.SOURCE_PATH`; every other location is meaningless
/// without a real JDK compiler behind it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Location {
    SourcePath,
    Other,
}

/// A `JavaFileManager` that works with Ghidra's [`ResourceFile`]s.
///
/// This class is used to dynamically compile Ghidra scripts.
pub struct ResourceFileJavaFileManager {
    source_dirs: Vec<ResourceFile>,
    files_to_avoid: Vec<ResourceFile>,
}

impl ResourceFileJavaFileManager {
    /// Create a `JavaFileManager` for use by the `JavaCompiler`.
    ///
    /// `source_dirs` are the directories containing source; `files_to_avoid` are known "bad"
    /// files to hide from the compiler. Java's constructor also obtains
    /// `ToolProvider.getSystemJavaCompiler()`, throwing [`AssertException`] when no compiler is
    /// available; there is no equivalent in-process compiler to obtain in Rust, so that step is
    /// simply not modeled here.
    pub fn new(source_dirs: Vec<ResourceFile>, files_to_avoid: Vec<ResourceFile>) -> Self {
        Self { source_dirs, files_to_avoid }
    }

    /// Mirrors `list(Location, String, Set<Kind>, boolean)` for `StandardLocation.SOURCE_PATH`
    /// only; every other location has no delegate to answer it here.
    pub fn list(
        &self,
        location: Location,
        package_name: &str,
        kinds: &[FileKind],
        recurse: bool,
    ) -> Vec<ResourceFileJavaFileObject> {
        if location != Location::SourcePath {
            return Vec::new();
        }

        let relative_path = package_name.replace('.', "/");
        let mut result = Vec::new();
        for source_dir in &self.source_dirs {
            let package_dir = if relative_path.is_empty() {
                source_dir.clone()
            } else {
                source_dir.join(&relative_path)
            };
            if package_dir.is_directory() {
                self.gather_files(source_dir, &package_dir, &mut result, kinds, recurse);
            }
        }
        result
    }

    fn gather_files(
        &self,
        root: &ResourceFile,
        dir: &ResourceFile,
        accumulator: &mut Vec<ResourceFileJavaFileObject>,
        kinds: &[FileKind],
        recurse: bool,
    ) {
        for child in list_children(dir) {
            if self.is_avoided(&child) {
                continue;
            }
            if child.is_directory() {
                if recurse {
                    self.gather_files(root, &child, accumulator, kinds, recurse);
                }
                continue;
            }
            for kind in kinds {
                let matches = match kind {
                    FileKind::Class => child.name().ends_with(".class"),
                    FileKind::Source => child.name().ends_with(".java"),
                    FileKind::Html | FileKind::Other => false,
                };
                if matches {
                    accumulator.push(Self::create_file_object(root, child, *kind));
                    break;
                }
            }
        }
    }

    fn is_avoided(&self, file: &ResourceFile) -> bool {
        self.files_to_avoid
            .iter()
            .any(|avoided| avoided.absolute_path() == file.absolute_path())
    }

    fn create_file_object(
        root: &ResourceFile,
        resource_file: ResourceFile,
        kind: FileKind,
    ) -> ResourceFileJavaFileObject {
        ResourceFileJavaFileObject::new(root, resource_file, kind)
    }

    /// Mirrors `inferBinaryName(Location, JavaFileObject)`. Java falls back to the JDK delegate
    /// when `file` is not a `ResourceFileJavaFileObject`; since that is the only kind of
    /// `JavaFileObject` this manager ever produces, `file` is typed concretely here and that
    /// fallback branch does not apply.
    pub fn infer_binary_name(
        &self,
        file: &ResourceFileJavaFileObject,
    ) -> Result<String, AssertException> {
        let name = file.get_name();
        match name.rfind(".java") {
            Some(last_index_of) => {
                let path = &name[..last_index_of];
                Ok(path.replace('/', ".").replace('\\', "."))
            }
            None => Err(AssertException::with_message(format!(
                "Expected name to end in .java but got {name}"
            ))),
        }
    }

    /// Mirrors `isSameFile(FileObject, FileObject)`.
    pub fn is_same_file(a: &ResourceFileJavaFileObject, b: &ResourceFileJavaFileObject) -> bool {
        a.to_uri() == b.to_uri()
    }

    /// Mirrors `hasLocation(Location)`.
    pub fn has_location(&self, location: Location) -> bool {
        location == Location::SourcePath
    }

    /// Mirrors `getJavaFileForInput(Location, String, Kind)` for `StandardLocation.SOURCE_PATH`;
    /// every other location has no delegate to answer it here.
    pub fn get_java_file_for_input(
        &self,
        location: Location,
        class_name: &str,
        kind: FileKind,
    ) -> Option<ResourceFileJavaFileObject> {
        if location != Location::SourcePath || class_name == "module-info" {
            return None;
        }
        let relative_path = class_name.replace('.', "/");
        for source_dir in &self.source_dirs {
            let file = source_dir.join(&relative_path);
            if file.exists() {
                return Some(Self::create_file_object(source_dir, file, kind));
            }
        }
        None
    }
}

fn list_children(dir: &ResourceFile) -> Vec<ResourceFile> {
    let Some(path) = dir.get_file(false) else {
        return Vec::new();
    };
    let Ok(entries) = fs::read_dir(path) else {
        return Vec::new();
    };
    entries
        .filter_map(|entry| entry.ok())
        .map(|entry| ResourceFile::new(entry.path()))
        .collect()
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
    fn list_finds_java_sources_recursively_and_skips_avoided_files() {
        let dir = tempdir().unwrap();
        write(dir.path(), "com/example/Foo.java", "class Foo {}");
        write(dir.path(), "com/example/Bar.class", "not really bytecode");
        write(dir.path(), "com/example/nested/Baz.java", "class Baz {}");
        write(dir.path(), "com/example/Skip.java", "class Skip {}");

        let source_dir = ResourceFile::new(dir.path().to_path_buf());
        let skip = ResourceFile::new(dir.path().join("com/example/Skip.java"));
        let manager = ResourceFileJavaFileManager::new(vec![source_dir], vec![skip]);

        let found = manager.list(Location::SourcePath, "com.example", &[FileKind::Source], true);
        let mut names: Vec<&str> = found.iter().map(|f| f.get_name()).collect();
        names.sort();

        assert_eq!(names, vec!["com/example/Foo.java", "com/example/nested/Baz.java"]);
    }

    #[test]
    fn list_non_recursive_skips_nested_directories() {
        let dir = tempdir().unwrap();
        write(dir.path(), "Foo.java", "class Foo {}");
        write(dir.path(), "nested/Baz.java", "class Baz {}");

        let source_dir = ResourceFile::new(dir.path().to_path_buf());
        let manager = ResourceFileJavaFileManager::new(vec![source_dir], vec![]);

        let found = manager.list(Location::SourcePath, "", &[FileKind::Source], false);
        let names: Vec<&str> = found.iter().map(|f| f.get_name()).collect();

        assert_eq!(names, vec!["Foo.java"]);
    }

    #[test]
    fn list_returns_nothing_for_non_source_path_locations() {
        let dir = tempdir().unwrap();
        write(dir.path(), "Foo.java", "class Foo {}");

        let source_dir = ResourceFile::new(dir.path().to_path_buf());
        let manager = ResourceFileJavaFileManager::new(vec![source_dir], vec![]);

        assert!(manager
            .list(Location::Other, "", &[FileKind::Source], true)
            .is_empty());
    }

    #[test]
    fn infer_binary_name_converts_relative_java_path_to_dotted_name() {
        let dir = tempdir().unwrap();
        write(dir.path(), "com/example/Foo.java", "class Foo {}");
        let source_dir = ResourceFile::new(dir.path().to_path_buf());
        let manager = ResourceFileJavaFileManager::new(vec![source_dir.clone()], vec![]);

        let file = ResourceFile::new(dir.path().join("com/example/Foo.java"));
        let file_object = ResourceFileJavaFileObject::new(&source_dir, file, FileKind::Source);

        assert_eq!(
            manager.infer_binary_name(&file_object).unwrap(),
            "com.example.Foo"
        );
    }

    #[test]
    fn infer_binary_name_rejects_names_without_dot_java() {
        let dir = tempdir().unwrap();
        write(dir.path(), "com/example/Foo.txt", "not java");
        let source_dir = ResourceFile::new(dir.path().to_path_buf());
        let manager = ResourceFileJavaFileManager::new(vec![source_dir.clone()], vec![]);

        let file = ResourceFile::new(dir.path().join("com/example/Foo.txt"));
        let file_object = ResourceFileJavaFileObject::new(&source_dir, file, FileKind::Source);

        assert!(manager.infer_binary_name(&file_object).is_err());
    }

    #[test]
    fn has_location_is_true_only_for_source_path() {
        let manager = ResourceFileJavaFileManager::new(vec![], vec![]);
        assert!(manager.has_location(Location::SourcePath));
        assert!(!manager.has_location(Location::Other));
    }

    #[test]
    fn get_java_file_for_input_finds_existing_file_under_source_dirs() {
        let dir = tempdir().unwrap();
        write(dir.path(), "com/example/Foo", "class Foo {}");
        let source_dir = ResourceFile::new(dir.path().to_path_buf());
        let manager = ResourceFileJavaFileManager::new(vec![source_dir], vec![]);

        let found = manager.get_java_file_for_input(
            Location::SourcePath,
            "com.example.Foo",
            FileKind::Source,
        );
        assert!(found.is_some());
        assert_eq!(found.unwrap().get_name(), "com/example/Foo");
    }

    #[test]
    fn get_java_file_for_input_returns_none_for_module_info_and_missing_files() {
        let dir = tempdir().unwrap();
        let source_dir = ResourceFile::new(dir.path().to_path_buf());
        let manager = ResourceFileJavaFileManager::new(vec![source_dir], vec![]);

        assert!(manager
            .get_java_file_for_input(Location::SourcePath, "module-info", FileKind::Source)
            .is_none());
        assert!(manager
            .get_java_file_for_input(Location::SourcePath, "does.not.Exist", FileKind::Source)
            .is_none());
    }

    #[test]
    fn is_same_file_compares_by_uri() {
        let dir = tempdir().unwrap();
        write(dir.path(), "Foo.java", "class Foo {}");
        let source_dir = ResourceFile::new(dir.path().to_path_buf());

        let a = ResourceFileJavaFileObject::new(
            &source_dir,
            ResourceFile::new(dir.path().join("Foo.java")),
            FileKind::Source,
        );
        let b = ResourceFileJavaFileObject::new(
            &source_dir,
            ResourceFile::new(dir.path().join("Foo.java")),
            FileKind::Source,
        );
        let c = ResourceFileJavaFileObject::new(
            &source_dir,
            source_dir.join("Other.java"),
            FileKind::Source,
        );

        assert!(ResourceFileJavaFileManager::is_same_file(&a, &b));
        assert!(!ResourceFileJavaFileManager::is_same_file(&a, &c));
    }
}

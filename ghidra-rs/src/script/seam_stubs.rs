//! Minimal placeholder types for `ghidra.app.script` classes that a ported type references before
//! the real Rust port of that class exists. Each stub exposes only the members needed by the
//! type(s) that currently reference it, and is expected to be replaced by (or grown into) the real
//! port once that Java class is ported. See `STUBS.tsv` for provenance.

use crate::generic::jar::resource_file::ResourceFile;
use crate::util::classfinder::class_exclusion_filter::ClassExclusionFilter;
use std::sync::Arc;

/// Placeholder for `ghidra.app.script.GhidraScriptProvider`, referenced by
/// [`ghidra_script_util`](crate::script::ghidra_script_util) before the real class is ported.
///
/// Java's version is an abstract class whose concrete subclasses (`JavaScriptProvider`,
/// `UnsupportedScriptProvider`, the Jython/PyGhidra providers in other modules, ...) are what
/// `ClassSearcher` discovers at runtime, so the seam is genuinely polymorphic and is modeled as a
/// trait. Only the three members `GhidraScriptUtil` calls are modeled.
pub trait GhidraScriptProvider: Send + Sync {
    /// Mirrors `GhidraScriptProvider.getExtension()`: the file extension this provider handles,
    /// including the leading dot (for example `".java"`).
    fn get_extension(&self) -> String;

    /// Mirrors `GhidraScriptProvider.getRuntimeEnvironmentName()`: the optional runtime a script
    /// can require via its `@runtime` tag, used to disambiguate providers that share a file
    /// extension. Java's base implementation returns `null`, hence the `None` default here.
    fn get_runtime_environment_name(&self) -> Option<String> {
        None
    }

    /// Mirrors the deprecated `GhidraScriptProvider.fixupName(String)`, which turns a
    /// user-supplied script name into a path relative to a script directory. Java's base
    /// implementation returns the name unchanged.
    fn fixup_name(&self, script_name: &str) -> String {
        script_name.to_string()
    }
}

/// Placeholder for `ghidra.app.script.GhidraScript`, referenced by
/// [`JavaScriptProvider`](crate::script::java_script_provider::JavaScriptProvider) before the
/// real class is ported.
///
/// Java's version is abstract, with one concrete subclass generated per user script, so the seam
/// is genuinely polymorphic and is modeled as a trait, matching [`GhidraScriptProvider`]'s
/// convention. Only the one member a script provider sets after instantiating a script is
/// modeled.
pub trait GhidraScript: Send + Sync {
    /// Mirrors `GhidraScript.setSourceFile(ResourceFile)`.
    fn set_source_file(&mut self, source_file: ResourceFile);
}

/// Placeholder for `ghidra.app.script.UnsupportedScriptProvider`, referenced by
/// [`ghidra_script_util`](crate::script::ghidra_script_util) before the real class is ported.
///
/// Java's version wraps a base provider with a compatible extension but an incompatible (or
/// not-yet-readable) `@runtime` tag, delegating the extension-related members to that base and
/// failing every attempt to actually load the script. Only the delegation
/// `GhidraScriptUtil` depends on is modeled; note that Java does *not* override
/// `getRuntimeEnvironmentName()`, so the wrapper reports no runtime of its own.
pub struct UnsupportedScriptProvider {
    base_provider: Arc<dyn GhidraScriptProvider>,
}

impl UnsupportedScriptProvider {
    /// Creates a provider derived from `base_provider`, mirroring
    /// `UnsupportedScriptProvider(GhidraScriptProvider)`.
    pub fn new(base_provider: Arc<dyn GhidraScriptProvider>) -> Self {
        Self { base_provider }
    }

    /// The provider this one was derived from.
    pub fn base_provider(&self) -> &Arc<dyn GhidraScriptProvider> {
        &self.base_provider
    }
}

impl GhidraScriptProvider for UnsupportedScriptProvider {
    fn get_extension(&self) -> String {
        self.base_provider.get_extension()
    }
}

/// Placeholder for `ghidra.app.script.ScriptInfo`, referenced by
/// [`ghidra_script_util`](crate::script::ghidra_script_util) before the real class is ported.
///
/// Java's version parses a script's metadata header (`@author`, `@category`, `@runtime`, ...) and
/// caches the result. `GhidraScriptUtil` only ever constructs one to read the `@runtime` tag, so
/// that is the only member modeled here; header parsing itself belongs to the real port, so this
/// stub reports no runtime.
pub struct ScriptInfo {
    provider: Option<Arc<dyn GhidraScriptProvider>>,
    source_file: ResourceFile,
}

impl ScriptInfo {
    /// Mirrors `ScriptInfo(GhidraScriptProvider, ResourceFile)`. The provider is optional because
    /// the Rust port of `GhidraScriptUtil::get_provider` returns `None` where Java returns `null`.
    /// Java's constructor additionally rejects a non-existent source file; that check belongs to
    /// the real port, since it is a property of header parsing rather than of this seam.
    pub fn new(provider: Option<Arc<dyn GhidraScriptProvider>>, source_file: ResourceFile) -> Self {
        Self { provider, source_file }
    }

    /// Mirrors `ScriptInfo.getRuntimeEnvironmentName()`: the value of the script's `@runtime` tag,
    /// or `None` when the script does not declare one. Always `None` until header parsing is
    /// ported, which is the same answer Java gives for the (common) untagged script.
    pub fn get_runtime_environment_name(&self) -> Option<String> {
        None
    }

    /// Mirrors `ScriptInfo.getProvider()`, minus Java's re-resolution side effect.
    pub fn get_provider(&self) -> Option<&Arc<dyn GhidraScriptProvider>> {
        self.provider.as_ref()
    }

    /// Mirrors `ScriptInfo.getSourceFile()`.
    pub fn get_source_file(&self) -> &ResourceFile {
        &self.source_file
    }
}

/// Placeholder for the `ghidra.util.classfinder.ClassSearcher` lookup that
/// [`ghidra_script_util`](crate::script::ghidra_script_util) needs, before the real class is
/// ported. Modeled as a statics holder (Java's version is a class of static methods), matching
/// [`format::seam_stubs::ClassSearcher`](crate::format::seam_stubs::ClassSearcher).
pub struct ClassSearcher;

impl ClassSearcher {
    /// Mirrors `ClassSearcher.getInstances(GhidraScriptProvider.class, filter)`, priority-sorted.
    /// Java discovers implementations by scanning the classpath for extension points; Rust has no
    /// equivalent runtime scan, so this yields nothing until a provider registry is ported.
    pub fn get_script_provider_instances(
        _filter: &ClassExclusionFilter,
    ) -> Vec<Arc<dyn GhidraScriptProvider>> {
        Vec::new()
    }
}

/// Placeholder for the `utilities.util.FileUtilities` helper that
/// [`ghidra_script_util`](crate::script::ghidra_script_util) needs, before the real class is
/// ported. Java's version is a class of static methods, so this is a statics holder too.
pub struct FileUtilities;

impl FileUtilities {
    /// Mirrors `FileUtilities.relativizePath(ResourceFile, ResourceFile)`: the path of `f2`
    /// relative to `f1`, or `None` when `f1` is not a parent of `f2` (including when they are the
    /// same file). Java walks `f2`'s parents comparing them to `f1`; comparing absolute paths is
    /// equivalent and, like Java's `ResourceFile` overload, does not resolve symbolic links.
    pub fn relativize_path(f1: &ResourceFile, f2: &ResourceFile) -> Option<String> {
        let mut parent_path = f1.absolute_path();
        let other_path = f2.absolute_path();
        if !parent_path.ends_with(std::path::MAIN_SEPARATOR) {
            parent_path.push(std::path::MAIN_SEPARATOR);
        }
        other_path.strip_prefix(&parent_path).map(str::to_string)
    }
}

/// Mirrors just enough of `javax.tools.JavaFileObject.Kind` for
/// [`ResourceFileJavaFileObject`] and
/// [`ResourceFileJavaFileManager`](crate::script::resource_file_java_file_manager::ResourceFileJavaFileManager)
/// to distinguish source/class files by extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    Source,
    Class,
    Html,
    Other,
}

/// Placeholder for `ghidra.app.script.ResourceFileJavaFileObject`, referenced by
/// [`ResourceFileJavaFileManager`](crate::script::resource_file_java_file_manager::ResourceFileJavaFileManager)
/// before the real class is ported.
///
/// Java's version implements `javax.tools.JavaFileObject` so a `ResourceFile` can stand in for a
/// compiler input; only the two members `ResourceFileJavaFileManager` needs (the file's path
/// relative to its source root, and a URI-like identity for `isSameFile`) are modeled here.
pub struct ResourceFileJavaFileObject {
    file: ResourceFile,
    kind: FileKind,
    path_name: String,
}

impl ResourceFileJavaFileObject {
    /// Mirrors `ResourceFileJavaFileObject(ResourceFile sourceRoot, ResourceFile file, Kind kind)`:
    /// `path_name` is `file`'s absolute path with `sourceRoot`'s absolute path (and the following
    /// separator) stripped off.
    pub fn new(source_root: &ResourceFile, file: ResourceFile, kind: FileKind) -> Self {
        let source_root_path = source_root.absolute_path();
        let file_path = file.absolute_path();
        let path_name = file_path
            .strip_prefix(&source_root_path)
            .map(|s| s.trim_start_matches(std::path::MAIN_SEPARATOR).to_string())
            .unwrap_or(file_path);
        Self { file, kind, path_name }
    }

    /// Mirrors `ResourceFileJavaFileObject.getName()`.
    pub fn get_name(&self) -> &str {
        &self.path_name
    }

    /// Mirrors `ResourceFileJavaFileObject.toUri()`. Java returns a real `java.net.URI`; since
    /// nothing here needs to resolve or parse it (only compare it, via `isSameFile`), a stable
    /// string identity is enough.
    pub fn to_uri(&self) -> String {
        format!("file://{}", self.file.absolute_path())
    }

    /// Mirrors `ResourceFileJavaFileObject.getKind()`.
    pub fn kind(&self) -> FileKind {
        self.kind
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    struct FakeProvider;

    impl GhidraScriptProvider for FakeProvider {
        fn get_extension(&self) -> String {
            ".java".to_string()
        }
    }

    #[test]
    fn unsupported_provider_delegates_extension_but_not_runtime() {
        let base: Arc<dyn GhidraScriptProvider> = Arc::new(FakeProvider);
        let unsupported = UnsupportedScriptProvider::new(base);
        assert_eq!(unsupported.get_extension(), ".java");
        assert_eq!(unsupported.get_runtime_environment_name(), None);
    }

    #[test]
    fn relativize_path_returns_child_path() {
        let parent = ResourceFile::new(PathBuf::from("/a/b"));
        let child = ResourceFile::new(PathBuf::from("/a/b/c"));
        assert_eq!(FileUtilities::relativize_path(&parent, &child), Some("c".to_string()));
    }

    #[test]
    fn relativize_path_returns_none_for_same_or_unrelated_files() {
        let parent = ResourceFile::new(PathBuf::from("/a/b"));
        assert_eq!(FileUtilities::relativize_path(&parent, &parent), None);

        let unrelated = ResourceFile::new(PathBuf::from("/a/d/c"));
        assert_eq!(FileUtilities::relativize_path(&parent, &unrelated), None);
    }
}

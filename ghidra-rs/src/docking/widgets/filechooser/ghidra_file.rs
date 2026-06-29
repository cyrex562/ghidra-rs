use std::io;
use std::path::PathBuf;

fn translate_separator(s: &str, from: char, to: char) -> String {
    s.chars().map(|c| if c == from { to } else { c }).collect()
}

/// A file path representation that preserves a caller-specified path separator,
/// preventing translation to the native OS separator.
///
/// On Windows, `PathBuf` normalizes `/` to `\`. `GhidraFile` bypasses this by
/// storing the chosen separator and substituting it into string output whenever
/// it differs from `std::path::MAIN_SEPARATOR`.
///
/// Corresponds to `docking.widgets.filechooser.GhidraFile`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GhidraFile {
    pub path: PathBuf,
    pub separator: char,
}

impl GhidraFile {
    /// Creates a `GhidraFile` by joining `parent` and `child` with the OS separator internally.
    pub fn new(parent: &str, child: &str, separator: char) -> Self {
        let mut p = PathBuf::from(parent);
        p.push(child);
        Self { path: p, separator }
    }

    /// Creates a `GhidraFile` from a single path string.
    pub fn from_path(path: &str, separator: char) -> Self {
        Self { path: PathBuf::from(path), separator }
    }

    /// Creates a `GhidraFile` from a parent `GhidraFile` and a child name.
    pub fn from_file(parent: &GhidraFile, name: &str, separator: char) -> Self {
        let mut p = parent.path.clone();
        p.push(name);
        Self { path: p, separator }
    }

    fn os_separator() -> char {
        std::path::MAIN_SEPARATOR
    }

    fn uses_native_separator(&self) -> bool {
        self.separator == Self::os_separator()
    }

    /// Returns the path string with the separator specified at construction.
    pub fn get_path(&self) -> String {
        let s = self.path.to_string_lossy().into_owned();
        if self.uses_native_separator() {
            s
        } else {
            translate_separator(&s, Self::os_separator(), self.separator)
        }
    }

    /// Returns the absolute path with the separator specified at construction.
    ///
    /// When the separator matches the OS separator, a relative path is resolved
    /// against the current directory. Otherwise returns `get_path()` unchanged.
    pub fn get_absolute_path(&self) -> String {
        if self.uses_native_separator() {
            self.absolute_path_buf().to_string_lossy().into_owned()
        } else {
            self.get_path()
        }
    }

    /// Returns the canonical path with the separator specified at construction.
    ///
    /// When the separator matches the OS separator, symlinks and `.`/`..` are
    /// resolved via the filesystem. Otherwise returns `get_path()` unchanged.
    pub fn get_canonical_path(&self) -> io::Result<String> {
        if self.uses_native_separator() {
            Ok(self.path.canonicalize()?.to_string_lossy().into_owned())
        } else {
            Ok(self.get_path())
        }
    }

    /// Returns the parent directory path, or `None` for a root path.
    ///
    /// When the separator differs from the OS separator, the parent string is
    /// translated to use the custom separator.
    pub fn get_parent(&self) -> Option<String> {
        let parent = self.path.parent()?;
        let s = parent.to_string_lossy().into_owned();
        if self.uses_native_separator() {
            Some(s)
        } else {
            Some(translate_separator(&s, Self::os_separator(), self.separator))
        }
    }

    /// Returns the parent directory as a `GhidraFile`, or `None` for a root path.
    pub fn get_parent_file(&self) -> Option<GhidraFile> {
        if self.uses_native_separator() {
            self.path.parent().map(|p| GhidraFile { path: p.to_path_buf(), separator: self.separator })
        } else {
            self.get_parent().map(|s| GhidraFile::from_path(&s, self.separator))
        }
    }

    /// Returns the absolute path as a `GhidraFile`.
    ///
    /// When the separator matches the OS separator, resolves to an absolute path.
    /// Otherwise returns a clone of `self`.
    pub fn get_absolute_file(&self) -> GhidraFile {
        if self.uses_native_separator() {
            GhidraFile { path: self.absolute_path_buf(), separator: self.separator }
        } else {
            self.clone()
        }
    }

    /// Returns the canonical path as a `GhidraFile`.
    ///
    /// When the separator matches the OS separator, symlinks are resolved.
    /// Otherwise returns a clone of `self`.
    pub fn get_canonical_file(&self) -> io::Result<GhidraFile> {
        if self.uses_native_separator() {
            Ok(GhidraFile { path: self.path.canonicalize()?, separator: self.separator })
        } else {
            Ok(self.clone())
        }
    }

    fn absolute_path_buf(&self) -> PathBuf {
        if self.path.is_absolute() {
            self.path.clone()
        } else {
            let mut abs = std::env::current_dir().unwrap_or_default();
            abs.push(&self.path);
            abs
        }
    }
}

impl std::fmt::Display for GhidraFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.get_path())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::MAIN_SEPARATOR;

    const CUSTOM_SEP: char = if cfg!(windows) { '/' } else { '\\' };

    #[test]
    fn from_path_native_separator_get_path_unchanged() {
        let f = GhidraFile::from_path("a/b/c.txt", MAIN_SEPARATOR);
        assert_eq!(f.get_path(), "a/b/c.txt");
    }

    #[test]
    fn new_joins_parent_and_child() {
        let f = GhidraFile::new("parent", "child.txt", MAIN_SEPARATOR);
        let p = f.get_path();
        assert!(p.contains("parent"));
        assert!(p.contains("child.txt"));
    }

    #[test]
    fn get_path_translates_os_sep_to_custom() {
        // Build a path using OS separators, then ask for it with CUSTOM_SEP.
        let mut pb = PathBuf::from("a");
        pb.push("b");
        pb.push("c.txt");
        let native_str = pb.to_string_lossy().into_owned();
        let f = GhidraFile::from_path(&native_str, CUSTOM_SEP);
        let result = f.get_path();
        assert!(!result.contains(MAIN_SEPARATOR), "should not contain OS sep");
        assert!(result.contains(CUSTOM_SEP), "should contain custom sep");
    }

    #[test]
    fn get_parent_native_separator() {
        let mut pb = PathBuf::from("a");
        pb.push("b");
        pb.push("c.txt");
        let f = GhidraFile::from_path(&pb.to_string_lossy(), MAIN_SEPARATOR);
        let parent = f.get_parent().unwrap();
        let expected: PathBuf = ["a", "b"].iter().collect();
        assert_eq!(parent, expected.to_string_lossy().as_ref());
    }

    #[test]
    fn get_parent_custom_separator_translates() {
        let mut pb = PathBuf::from("a");
        pb.push("b");
        pb.push("c.txt");
        let native_str = pb.to_string_lossy().into_owned();
        let f = GhidraFile::from_path(&native_str, CUSTOM_SEP);
        let parent = f.get_parent().unwrap();
        assert!(!parent.contains(MAIN_SEPARATOR));
        assert!(parent.contains(CUSTOM_SEP));
    }

    #[test]
    fn get_parent_returns_none_for_filename_only() {
        let f = GhidraFile::from_path("file.txt", MAIN_SEPARATOR);
        assert!(f.get_parent().is_none());
    }

    #[test]
    fn get_parent_file_custom_separator_preserves_sep() {
        let mut pb = PathBuf::from("a");
        pb.push("b");
        pb.push("c.txt");
        let native_str = pb.to_string_lossy().into_owned();
        let f = GhidraFile::from_path(&native_str, CUSTOM_SEP);
        let parent_file = f.get_parent_file().unwrap();
        assert_eq!(parent_file.separator, CUSTOM_SEP);
        assert!(!parent_file.get_path().contains(MAIN_SEPARATOR));
    }

    #[test]
    fn get_parent_file_native_separator() {
        let mut pb = PathBuf::from("a");
        pb.push("b");
        pb.push("c.txt");
        let f = GhidraFile::from_path(&pb.to_string_lossy(), MAIN_SEPARATOR);
        let parent = f.get_parent_file().unwrap();
        assert_eq!(parent.separator, MAIN_SEPARATOR);
    }

    #[test]
    fn get_parent_file_returns_none_for_filename_only() {
        let f = GhidraFile::from_path("file.txt", MAIN_SEPARATOR);
        assert!(f.get_parent_file().is_none());
    }

    #[test]
    fn get_absolute_path_custom_separator_returns_get_path() {
        let mut pb = PathBuf::from("a");
        pb.push("b.txt");
        let f = GhidraFile::from_path(&pb.to_string_lossy(), CUSTOM_SEP);
        assert_eq!(f.get_absolute_path(), f.get_path());
    }

    #[test]
    fn get_absolute_path_native_absolute_is_unchanged() {
        let abs = std::env::current_dir()
            .unwrap()
            .join("some_file.txt")
            .to_string_lossy()
            .into_owned();
        let f = GhidraFile::from_path(&abs, MAIN_SEPARATOR);
        assert_eq!(f.get_absolute_path(), abs);
    }

    #[test]
    fn get_absolute_file_custom_separator_equals_self() {
        let mut pb = PathBuf::from("x");
        pb.push("y.txt");
        let f = GhidraFile::from_path(&pb.to_string_lossy(), CUSTOM_SEP);
        let abs = f.get_absolute_file();
        assert_eq!(abs.get_path(), f.get_path());
        assert_eq!(abs.separator, CUSTOM_SEP);
    }

    #[test]
    fn from_file_constructor_joins_parent_and_name() {
        let parent = GhidraFile::from_path("dir", MAIN_SEPARATOR);
        let child = GhidraFile::from_file(&parent, "file.txt", MAIN_SEPARATOR);
        let p = child.get_path();
        assert!(p.contains("dir"));
        assert!(p.contains("file.txt"));
    }

    #[test]
    fn display_returns_get_path() {
        let mut pb = PathBuf::from("a");
        pb.push("b.txt");
        let f = GhidraFile::from_path(&pb.to_string_lossy(), MAIN_SEPARATOR);
        assert_eq!(f.to_string(), f.get_path());
    }

    #[test]
    fn display_custom_separator() {
        let mut pb = PathBuf::from("a");
        pb.push("b.txt");
        let f = GhidraFile::from_path(&pb.to_string_lossy(), CUSTOM_SEP);
        assert_eq!(f.to_string(), f.get_path());
        assert!(!f.to_string().contains(MAIN_SEPARATOR));
    }

    #[test]
    fn equality_same_path_same_sep() {
        let a = GhidraFile::from_path("a/b.txt", MAIN_SEPARATOR);
        let b = GhidraFile::from_path("a/b.txt", MAIN_SEPARATOR);
        assert_eq!(a, b);
    }

    #[test]
    fn equality_different_sep_not_equal() {
        let a = GhidraFile::from_path("a/b.txt", MAIN_SEPARATOR);
        let b = GhidraFile::from_path("a/b.txt", CUSTOM_SEP);
        assert_ne!(a, b);
    }
}

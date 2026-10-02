//! Finds the image file behind an icon resource name, mirroring the lookup rules of Java's
//! `resources.ResourceManager.loadIcon` (`doLoadIcon`) with an explicit list of resource
//! roots standing in for the classpath.
//!
//! A resource root is a directory such as `Ghidra/Framework/Gui/src/main/resources` that
//! contains an `images/` folder; Java finds the same files as classpath resources.

use std::fs;
use std::path::{Path, PathBuf};

/// `ResourceManager.EXTERNAL_ICON_PREFIX`: marks an icon stored in the user settings
/// directory.
pub const EXTERNAL_ICON_PREFIX: &str = "[EXTERNAL]";

/// Resolves icon resource names to files.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IconResourceLocator {
    resource_roots: Vec<PathBuf>,
    user_settings_dir: Option<PathBuf>,
}

impl IconResourceLocator {
    /// A locator searching `resource_roots` in order (the classpath order).
    pub fn new(resource_roots: Vec<PathBuf>) -> Self {
        Self {
            resource_roots,
            user_settings_dir: None,
        }
    }

    /// Sets the directory `[EXTERNAL]` icon paths are relative to (Java's
    /// `Application.getUserSettingsDirectory()`).
    pub fn with_user_settings_dir(mut self, dir: PathBuf) -> Self {
        self.user_settings_dir = Some(dir);
        self
    }

    /// The resource roots, in search order.
    pub fn resource_roots(&self) -> &[PathBuf] {
        &self.resource_roots
    }

    /// Java's `doLoadIcon(path)` lookup:
    /// 1. `[EXTERNAL]rel` resolves only against the user settings directory;
    /// 2. a bare name (no `/`) is first looked up as `images/<name>` on all roots;
    /// 3. then the path itself on all roots;
    /// 4. finally the path as a plain file path.
    pub fn locate(&self, path: &str) -> Option<PathBuf> {
        if let Some(relative) = path.strip_prefix(EXTERNAL_ICON_PREFIX) {
            let file = self.user_settings_dir.as_ref()?.join(relative);
            return file.is_file().then_some(file);
        }
        if !path.contains('/') {
            if let Some(found) = self.find_resource(&format!("images/{path}")) {
                return Some(found);
            }
        }
        if let Some(found) = self.find_resource(path) {
            return Some(found);
        }
        let file = PathBuf::from(path);
        file.is_file().then_some(file)
    }

    /// `ResourceManager.getResource(name)`: the first root containing `name`.
    fn find_resource(&self, name: &str) -> Option<PathBuf> {
        self.resource_roots
            .iter()
            .map(|root| root.join(name))
            .find(|p| p.is_file())
    }
}

/// Every `src/main/resources` directory under `root`, sorted by path.
pub fn discover_resource_roots(root: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    walk_dirs(root, &mut |dir| {
        if dir.ends_with("src/main/resources") {
            found.push(dir.to_path_buf());
        }
    });
    found.sort();
    found
}

/// Every `*.theme.properties` file directly inside a `data` directory under `root`
/// (where Ghidra modules keep them), sorted by path.
pub fn discover_theme_property_files(root: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    walk_dirs(root, &mut |dir| {
        if dir.file_name().is_some_and(|n| n == "data") {
            let Ok(entries) = fs::read_dir(dir) else {
                return;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                let is_theme = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.ends_with(".theme.properties"));
                if is_theme && path.is_file() {
                    found.push(path);
                }
            }
        }
    });
    found.sort();
    found
}

/// Depth-first walk over real (non-symlink), non-hidden directories.
fn walk_dirs(dir: &Path, visit: &mut dyn FnMut(&Path)) {
    visit(dir);
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        let hidden = entry
            .file_name()
            .to_str()
            .is_some_and(|n| n.starts_with('.'));
        if file_type.is_dir() && !hidden {
            walk_dirs(&entry.path(), visit);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn touch(path: &Path) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, b"png").unwrap();
    }

    #[test]
    fn bare_name_is_searched_under_images_first() {
        let dir = tempfile::tempdir().unwrap();
        let root_a = dir.path().join("a/src/main/resources");
        let root_b = dir.path().join("b/src/main/resources");
        touch(&root_b.join("images/left.png"));
        touch(&root_a.join("left.png"));
        let locator = IconResourceLocator::new(vec![root_a.clone(), root_b.clone()]);
        // "images/" + name is tried on the whole classpath before the plain name
        assert_eq!(
            locator.locate("left.png"),
            Some(root_b.join("images/left.png"))
        );
    }

    #[test]
    fn path_with_slash_is_looked_up_directly_in_root_order() {
        let dir = tempfile::tempdir().unwrap();
        let root_a = dir.path().join("a");
        let root_b = dir.path().join("b");
        touch(&root_a.join("images/x.png"));
        touch(&root_b.join("images/x.png"));
        let locator = IconResourceLocator::new(vec![root_a.clone(), root_b]);
        assert_eq!(
            locator.locate("images/x.png"),
            Some(root_a.join("images/x.png"))
        );
        assert_eq!(locator.locate("images/missing.png"), None);
    }

    #[test]
    fn falls_back_to_plain_file_path() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("loose/icon.png");
        touch(&file);
        let locator = IconResourceLocator::new(Vec::new());
        assert_eq!(locator.locate(file.to_str().unwrap()), Some(file));
    }

    #[test]
    fn external_prefix_uses_user_settings_dir_only() {
        let dir = tempfile::tempdir().unwrap();
        let settings = dir.path().join("settings");
        touch(&settings.join("images/mine.png"));
        let root = dir.path().join("root");
        touch(&root.join("images/mine.png"));
        let locator = IconResourceLocator::new(vec![root]);
        assert_eq!(locator.locate("[EXTERNAL]images/mine.png"), None);
        let locator = locator.with_user_settings_dir(settings.clone());
        assert_eq!(
            locator.locate("[EXTERNAL]images/mine.png"),
            Some(settings.join("images/mine.png"))
        );
    }

    #[test]
    fn discovers_resource_roots_sorted() {
        let dir = tempfile::tempdir().unwrap();
        touch(&dir.path().join("Z/src/main/resources/images/z.png"));
        touch(&dir.path().join("A/src/main/resources/images/a.png"));
        touch(&dir.path().join("A/src/test/resources/images/t.png"));
        assert_eq!(
            discover_resource_roots(dir.path()),
            [
                dir.path().join("A/src/main/resources"),
                dir.path().join("Z/src/main/resources")
            ]
        );
    }

    #[test]
    fn discovers_theme_property_files_in_data_dirs() {
        let dir = tempfile::tempdir().unwrap();
        touch(&dir.path().join("B/data/b.theme.properties"));
        touch(&dir.path().join("A/data/a.icons.theme.properties"));
        touch(&dir.path().join("A/data/other.properties"));
        touch(&dir.path().join("A/src/x.theme.properties"));
        assert_eq!(
            discover_theme_property_files(dir.path()),
            [
                dir.path().join("A/data/a.icons.theme.properties"),
                dir.path().join("B/data/b.theme.properties")
            ]
        );
    }
}

use std::path::{Path, PathBuf};
use std::fs;

/// Collects URLs/paths from module directories for class loading purposes.
/// Mirrors the behavior of Java's GClassLoader, which extends URLClassLoader.
pub struct GClassLoader {
    urls: Vec<PathBuf>,
}

impl GClassLoader {
    /// Creates a new GClassLoader from a list of module directories.
    /// Searches for "bin/main" directories and JAR files in "lib" directories.
    pub fn new<P: AsRef<Path>>(module_dirs: &[P]) -> Self {
        let mut urls = Vec::new();
        Self::find_urls(&mut urls, module_dirs);
        Self { urls }
    }

    /// Returns the collected URLs/paths.
    pub fn urls(&self) -> &[PathBuf] {
        &self.urls
    }

    /// Consumes the loader and returns the collected URLs/paths.
    pub fn into_urls(self) -> Vec<PathBuf> {
        self.urls
    }

    fn find_urls<P: AsRef<Path>>(urls: &mut Vec<PathBuf>, module_dirs: &[P]) {
        for module_dir in module_dirs {
            let module_dir = module_dir.as_ref();
            let bin_dir = module_dir.join("bin/main");
            if bin_dir.exists() {
                Self::add_file_url(urls, &bin_dir);
            }
            Self::add_module_jars(urls, &module_dir.join("lib"));
        }
    }

    fn add_file_url(urls: &mut Vec<PathBuf>, path: &Path) {
        urls.push(path.to_path_buf());
    }

    fn add_module_jars(urls: &mut Vec<PathBuf>, lib_dir: &Path) {
        if !lib_dir.is_dir() {
            return;
        }
        if let Ok(entries) = fs::read_dir(lib_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if Self::is_jar_file(&path) {
                    Self::add_file_url(urls, &path);
                }
            }
        }
    }

    fn is_jar_file(file: &Path) -> bool {
        file.exists() && file.file_name()
            .and_then(|n| n.to_str())
            .map(|s| s.ends_with(".jar"))
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_empty_dirs() {
        let temp_dir = TempDir::new().unwrap();
        let loader = GClassLoader::new(&[temp_dir.path()]);
        assert_eq!(loader.urls().len(), 0);
    }

    #[test]
    fn test_finds_bin_main_directory() {
        let temp_dir = TempDir::new().unwrap();
        let bin_main = temp_dir.path().join("bin/main");
        fs::create_dir_all(&bin_main).unwrap();

        let loader = GClassLoader::new(&[temp_dir.path()]);
        assert_eq!(loader.urls().len(), 1);
        assert_eq!(loader.urls()[0], bin_main);
    }

    #[test]
    fn test_finds_jar_files_in_lib() {
        let temp_dir = TempDir::new().unwrap();
        let lib_dir = temp_dir.path().join("lib");
        fs::create_dir(&lib_dir).unwrap();

        let jar1 = lib_dir.join("module1.jar");
        let jar2 = lib_dir.join("module2.jar");
        fs::File::create(&jar1).unwrap();
        fs::File::create(&jar2).unwrap();

        let loader = GClassLoader::new(&[temp_dir.path()]);
        assert_eq!(loader.urls().len(), 2);
    }

    #[test]
    fn test_ignores_non_jar_files_in_lib() {
        let temp_dir = TempDir::new().unwrap();
        let lib_dir = temp_dir.path().join("lib");
        fs::create_dir(&lib_dir).unwrap();

        let jar = lib_dir.join("module.jar");
        let txt = lib_dir.join("readme.txt");
        fs::File::create(&jar).unwrap();
        fs::File::create(&txt).unwrap();

        let loader = GClassLoader::new(&[temp_dir.path()]);
        assert_eq!(loader.urls().len(), 1);
        assert_eq!(loader.urls()[0], jar);
    }

    #[test]
    fn test_multiple_module_dirs() {
        let temp_dir1 = TempDir::new().unwrap();
        let temp_dir2 = TempDir::new().unwrap();

        let bin_main1 = temp_dir1.path().join("bin/main");
        fs::create_dir_all(&bin_main1).unwrap();

        let lib_dir2 = temp_dir2.path().join("lib");
        fs::create_dir(&lib_dir2).unwrap();
        let jar = lib_dir2.join("module.jar");
        fs::File::create(&jar).unwrap();

        let loader = GClassLoader::new(&[temp_dir1.path(), temp_dir2.path()]);
        assert_eq!(loader.urls().len(), 2);
    }

    #[test]
    fn test_ignores_missing_lib_directory() {
        let temp_dir = TempDir::new().unwrap();
        let loader = GClassLoader::new(&[temp_dir.path()]);
        assert_eq!(loader.urls().len(), 0);
    }

    #[test]
    fn test_into_urls() {
        let temp_dir = TempDir::new().unwrap();
        let bin_main = temp_dir.path().join("bin/main");
        fs::create_dir_all(&bin_main).unwrap();

        let loader = GClassLoader::new(&[temp_dir.path()]);
        let urls = loader.into_urls();
        assert_eq!(urls.len(), 1);
        assert_eq!(urls[0], bin_main);
    }
}

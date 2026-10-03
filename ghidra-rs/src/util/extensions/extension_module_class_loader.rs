//! Port of `ghidra.util.extensions.ExtensionModuleClassLoader`.

use std::fmt;
use std::path::PathBuf;

use crate::framework::Application;
use crate::util::extensions::ExtensionDetails;

/// A class loader used with Ghidra extensions.
///
/// Port of `ghidra.util.extensions.ExtensionModuleClassLoader`, a concrete class extending
/// `URLClassLoader`. Rust has no JVM-style classloading to port, so -- mirroring the same
/// simplification already made for
/// [`GClassLoader`](crate::generic::jar::g_class_loader::GClassLoader) (which "mirrors the
/// behavior of Java's `GClassLoader`, which extends `URLClassLoader`" by collecting the resolved
/// URLs/paths only) -- this collects the resolved library paths (via
/// [`ExtensionDetails::libraries`]) rather than modeling any actual class resolution. Java's
/// `super(getURLs(extensionDir), ExtensionModuleClassLoader.class.getClassLoader())` parent-
/// classloader argument has no Rust equivalent either and is dropped for the same reason.
pub struct ExtensionModuleClassLoader<'a> {
    extension_dir: &'a dyn ExtensionDetails,
    urls: Vec<PathBuf>,
}

impl<'a> ExtensionModuleClassLoader<'a> {
    /// Port of `ExtensionModuleClassLoader(ExtensionDetails)`.
    ///
    /// `app` resolves the process-wide `Application` state (`Application.inSingleJarMode()`
    /// transitively, via [`ExtensionDetails::libraries`]) that the private static `getURLs`
    /// helper reached for implicitly in Java; see
    /// [`ExtensionDetails`](crate::util::extensions::ExtensionDetails)'s own docs for why trait
    /// methods here take it as an explicit parameter instead.
    pub fn new(extension_dir: &'a dyn ExtensionDetails, app: &dyn Application) -> Self {
        let urls = Self::get_urls(extension_dir, app);
        ExtensionModuleClassLoader { extension_dir, urls }
    }

    /// Port of the private static `ExtensionModuleClassLoader.getURLs(ExtensionDetails)`:
    /// `extensionDir.getLibraries().toArray(URL[]::new)`.
    fn get_urls(extension_dir: &dyn ExtensionDetails, app: &dyn Application) -> Vec<PathBuf> {
        extension_dir.libraries(app)
    }

    /// The resolved library paths this loader was constructed with, standing in for the URLs a
    /// real `URLClassLoader` would have been constructed from. See the struct's own docs.
    pub fn urls(&self) -> &[PathBuf] {
        &self.urls
    }
}

impl<'a> fmt::Display for ExtensionModuleClassLoader<'a> {
    /// Port of `ExtensionModuleClassLoader.toString()`: `"Extension ClassLoader for " +
    /// extensionDir.getName()`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Extension ClassLoader for {}", self.extension_dir.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::seam_stubs::{ApplicationLayoutLike, Architecture};
    use crate::framework::{OperatingSystem, Platform};
    use crate::generic::jar::ResourceFile;

    #[derive(Default)]
    struct MockExtensionDetails {
        name: String,
        install_dir: Option<PathBuf>,
    }

    impl ExtensionDetails for MockExtensionDetails {
        fn name(&self) -> String {
            self.name.clone()
        }
        fn set_name(&mut self, name: String) {
            self.name = name;
        }
        fn description(&self) -> Option<String> {
            None
        }
        fn set_description(&mut self, _description: Option<String>) {}
        fn author(&self) -> Option<String> {
            None
        }
        fn set_author(&mut self, _author: Option<String>) {}
        fn created_on(&self) -> Option<String> {
            None
        }
        fn set_created_on(&mut self, _created_on: Option<String>) {}
        fn version(&self) -> Option<String> {
            None
        }
        fn set_version(&mut self, _version: Option<String>) {}
        fn install_dir(&self) -> Option<PathBuf> {
            self.install_dir.clone()
        }
        fn set_install_dir(&mut self, install_dir: Option<PathBuf>) {
            self.install_dir = install_dir;
        }
        fn archive_path(&self) -> Option<String> {
            None
        }
        fn set_archive_path(&mut self, _archive_path: Option<String>) {}
    }

    struct MockArchitecture;
    impl fmt::Display for MockArchitecture {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "x86_64")
        }
    }
    impl Architecture for MockArchitecture {}

    struct MockPlatform;
    impl Platform for MockPlatform {
        fn operating_system(&self) -> OperatingSystem {
            OperatingSystem::Linux
        }
        fn architecture(&self) -> Box<dyn Architecture> {
            Box::new(MockArchitecture)
        }
        fn directory_name(&self) -> Option<&str> {
            Some("linux_x86_64")
        }
        fn library_extension(&self) -> Option<&str> {
            Some(".so")
        }
        fn executable_extension(&self) -> &str {
            ""
        }
    }

    struct MockApplicationLayout {
        single_jar_mode: bool,
    }

    impl ApplicationLayoutLike for MockApplicationLayout {
        fn application_properties(&self) -> &dyn crate::framework::ApplicationProperties {
            unimplemented!("not exercised by this test")
        }
        fn application_installation_dir(&self) -> Option<&ResourceFile> {
            None
        }
        fn in_single_jar_mode(&self) -> bool {
            self.single_jar_mode
        }
        fn extension_installation_dirs(&self) -> Vec<ResourceFile> {
            Vec::new()
        }
    }

    struct MockApplication {
        single_jar_mode: bool,
    }

    impl Application for MockApplication {
        fn application_layout(&self) -> Box<dyn ApplicationLayoutLike> {
            Box::new(MockApplicationLayout { single_jar_mode: self.single_jar_mode })
        }
        fn current_platform(&self) -> Box<dyn Platform> {
            Box::new(MockPlatform)
        }
    }

    fn setup_installed_extension_with_jars() -> (tempfile::TempDir, MockExtensionDetails) {
        let dir = tempfile::tempdir().unwrap();
        let install_dir = dir.path().join("MyExtension");
        std::fs::create_dir_all(install_dir.join("lib")).unwrap();
        std::fs::write(
            install_dir.join(crate::util::seam_stubs::MODULE_MANIFEST_FILE_NAME),
            b"",
        )
        .unwrap();
        std::fs::write(install_dir.join("lib").join("one.jar"), b"jar").unwrap();
        std::fs::write(install_dir.join("lib").join("two.jar"), b"jar").unwrap();

        let mut ext = MockExtensionDetails { name: "MyExtension".to_string(), ..Default::default() };
        ext.set_install_dir(Some(install_dir));
        (dir, ext)
    }

    #[test]
    fn urls_collects_the_extensions_libraries() {
        let (_dir, ext) = setup_installed_extension_with_jars();
        let app = MockApplication { single_jar_mode: false };
        let loader = ExtensionModuleClassLoader::new(&ext, &app);
        assert_eq!(loader.urls().len(), 2);
        assert!(loader.urls().iter().any(|p| p.ends_with("one.jar")));
        assert!(loader.urls().iter().any(|p| p.ends_with("two.jar")));
    }

    #[test]
    fn urls_is_empty_when_not_installed() {
        let ext = MockExtensionDetails { name: "NoDir".to_string(), ..Default::default() };
        let app = MockApplication { single_jar_mode: false };
        let loader = ExtensionModuleClassLoader::new(&ext, &app);
        assert!(loader.urls().is_empty());
    }

    #[test]
    fn to_string_matches_java_format() {
        let ext = MockExtensionDetails { name: "MyExtension".to_string(), ..Default::default() };
        let app = MockApplication { single_jar_mode: false };
        let loader = ExtensionModuleClassLoader::new(&ext, &app);
        assert_eq!(loader.to_string(), "Extension ClassLoader for MyExtension");
    }

    #[test]
    fn single_jar_mode_still_reports_libraries() {
        let (_dir, ext) = setup_installed_extension_with_jars();
        let app = MockApplication { single_jar_mode: true };
        let loader = ExtensionModuleClassLoader::new(&ext, &app);
        // `is_installed` (which `libraries` guards on) is unconditionally true in single-jar
        // mode, so the jars are still found.
        assert_eq!(loader.urls().len(), 2);
    }
}

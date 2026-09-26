use std::io;
use std::path::{Path, PathBuf};

use crate::framework::OperatingSystem;
use crate::util::exception::NotFoundException;

/// File extension for a project's marker file, mirroring `ProjectLocator.PROJECT_FILE_SUFFIX`.
pub const PROJECT_FILE_SUFFIX: &str = ".gpr";

/// File extension for a project's storage directory, mirroring
/// `ProjectLocator.PROJECT_DIR_SUFFIX`.
pub const PROJECT_DIR_SUFFIX: &str = ".rep";

/// File extension for a project's lock file, mirroring the private
/// `ProjectLocator.LOCK_FILE_SUFFIX`.
const LOCK_FILE_SUFFIX: &str = ".lock";

/// Lightweight descriptor of a local Project storage location.
///
/// Port of `ghidra.framework.model.ProjectLocator`.
///
/// This trait was promoted from a minimal placeholder (see
/// [`seam_stubs`](crate::framework::seam_stubs)) that declared only [`Self::exists`] and
/// [`Self::url`] (the two members needed by
/// [`GhidraURL`](crate::framework::protocol::ghidra::GhidraURL)); both are kept with their
/// original signatures and "nothing here" defaults so existing bare `impl ProjectLocator for X {}`
/// blocks scattered across [`DomainFile`](crate::framework::model::DomainFile),
/// [`DomainFolder`](crate::framework::model::DomainFolder),
/// [`ProjectData`](crate::framework::model::ProjectData),
/// [`Project`](crate::framework::model::Project),
/// [`ProjectManager`](crate::framework::model::ProjectManager), and
/// [`GhidraFolderData`](crate::framework::data::GhidraFolderData) keep compiling unmodified.
///
/// Selected as a dependency-cycle cut-point: the original class's `path`/`name`/`url` fields and
/// its `checkLocalAbsolutePath`/`isWindowsOnlyPath`/`makeURL` construction logic (all provided by
/// [`GhidraURL`](crate::framework::protocol::ghidra::GhidraURL)) become per-implementor state and
/// construction logic here instead of a single shared constructor -- mirroring how `GhidraURL`
/// itself exposes
/// [`make_project_locator`](crate::framework::protocol::ghidra::GhidraURL::make_project_locator)
/// as a required seam rather than calling back into a concrete `ProjectLocator::new`. The two Java
/// constructors accordingly have no counterpart here; implementors are expected to perform their
/// own path validation/normalization (optionally reusing
/// [`check_local_absolute_path`](crate::framework::protocol::ghidra::GhidraURL::check_local_absolute_path)
/// and
/// [`is_windows_only_path`](crate::framework::protocol::ghidra::GhidraURL::is_windows_only_path))
/// before constructing their concrete type.
///
/// `equals`/`hashCode`/`toString` are not carried over as trait methods: identity in the Java
/// class is defined entirely by the project [`Self::url`], which callers can already compare
/// directly, and `toString` delegates to `GhidraURL.getDisplayString(URL)` -- reproducing that
/// here would require a `GhidraURL` instance and reintroduce the cycle this trait exists to break.
pub trait ProjectLocator {
    /// Determine if the project directory and marker file exist, mirroring
    /// `ProjectLocator.exists()`.
    fn exists(&self) -> bool {
        if self.is_windows_only_location() && OperatingSystem::CURRENT != OperatingSystem::Windows {
            // Do not try to evaluate a Windows-only path on other platforms.
            return false;
        }
        self.get_marker_file().is_file() && self.get_project_dir().is_dir()
    }

    /// Gets the URL for this project, mirroring `ProjectLocator.getURL()`. Defaults to an empty
    /// string, matching the "nothing here" semantics of this crate's existing placeholder
    /// locators.
    fn url(&self) -> String {
        String::new()
    }

    /// Gets the name of the project identified by this project locator, mirroring
    /// `ProjectLocator.getName()`. Defaults to empty.
    fn get_name(&self) -> String {
        String::new()
    }

    /// Gets the absolute path of the directory which contains the project marker file
    /// ([`Self::get_marker_file`]) and project directory ([`Self::get_project_dir`]) (i.e. parent
    /// directory), mirroring `ProjectLocator.getLocation()`. Defaults to empty.
    fn get_location(&self) -> String {
        String::new()
    }

    /// Determine if this project location is only valid on a Windows platform, mirroring
    /// `ProjectLocator.isWindowsOnlyLocation()`. Defaults to `false`.
    fn is_windows_only_location(&self) -> bool {
        false
    }

    /// Determine if this project URL corresponds to a transient project (e.g. corresponds to a
    /// remote Ghidra URL), mirroring `ProjectLocator.isTransient()`. Defaults to `false`.
    fn is_transient(&self) -> bool {
        false
    }

    /// Get the project storage directory associated with this project locator.
    ///
    /// NOTE: [`Self::exists`] or [`Self::check_project_existence`] should be used prior to relying
    /// on the returned path's existence. Mirrors `ProjectLocator.getProjectDir()`.
    fn get_project_dir(&self) -> PathBuf {
        parent_dir(&self.get_location()).join(format!("{}{PROJECT_DIR_SUFFIX}", self.get_name()))
    }

    /// Get the project marker file associated with this project locator, i.e. the file that
    /// indicates a Ghidra project.
    ///
    /// NOTE: [`Self::exists`] or [`Self::check_project_existence`] should be used prior to relying
    /// on the returned path's existence. Mirrors `ProjectLocator.getMarkerFile()`.
    fn get_marker_file(&self) -> PathBuf {
        parent_dir(&self.get_location()).join(format!("{}{PROJECT_FILE_SUFFIX}", self.get_name()))
    }

    /// Get the project lock file used to prevent multiple accesses to the same project at once,
    /// mirroring `ProjectLocator.getProjectLockFile()`.
    fn get_project_lock_file(&self) -> PathBuf {
        parent_dir(&self.get_location()).join(format!("{}{LOCK_FILE_SUFFIX}", self.get_name()))
    }

    /// Verify that this project exists with its required marker file and data storage directory,
    /// mirroring `ProjectLocator.checkProjectExistence()`.
    ///
    /// # Errors
    /// Returns `Err` if the project does not exist.
    fn check_project_existence(&self) -> Result<(), NotFoundException> {
        if self.is_windows_only_location() && OperatingSystem::CURRENT != OperatingSystem::Windows {
            return Err(NotFoundException::with_message(format!(
                "The project location is only valid on Windows: {}",
                self.get_location()
            )));
        }

        let marker_file = self.get_marker_file();
        if !marker_file.is_file() {
            return Err(NotFoundException::with_message(format!(
                "Project marker file not found: {}",
                marker_file.display()
            )));
        }

        let project_dir = self.get_project_dir();
        if !project_dir.is_dir() {
            return Err(NotFoundException::with_message(format!(
                "Project directory not found: {}",
                project_dir.display()
            )));
        }

        Ok(())
    }

    /// Verify that the specified project location directory exists, in preparation for creating a
    /// new project, mirroring `ProjectLocator.checkLocationExistence()`.
    ///
    /// # Errors
    /// Returns `io::Error` with kind [`io::ErrorKind::NotFound`] if the project location does not
    /// exist, mirroring the Java method's thrown `IOException`.
    fn check_location_existence(&self) -> io::Result<()> {
        if self.is_windows_only_location() && OperatingSystem::CURRENT != OperatingSystem::Windows {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("The project location is only valid on Windows: {}", self.get_location()),
            ));
        }

        let dir = parent_dir(&self.get_location());
        if !dir.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("Project location not found: {}", dir.display()),
            ));
        }

        Ok(())
    }
}

/// Stands in for the private `ProjectLocator.getParentDir()`.
fn parent_dir(location: &str) -> PathBuf {
    PathBuf::from(location)
}

/// Determine if the given path is a project directory, mirroring the static
/// `ProjectLocator.isProjectDir(File)`.
pub fn is_project_dir(path: &Path) -> bool {
    path.is_dir()
        && path
            .file_name()
            .and_then(|name| name.to_str())
            .map(|name| name.ends_with(PROJECT_DIR_SUFFIX))
            .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct SimpleProjectLocator {
        location: String,
        name: String,
    }

    impl ProjectLocator for SimpleProjectLocator {
        fn url(&self) -> String {
            format!("ghidra:{}/{}", self.location, self.name)
        }

        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn get_location(&self) -> String {
            self.location.clone()
        }
    }

    #[test]
    fn bare_default_impl_compiles_and_reports_nothing_here() {
        struct BareLocator;
        impl ProjectLocator for BareLocator {}

        let locator = BareLocator;
        let dyn_locator: &dyn ProjectLocator = &locator;

        assert!(!dyn_locator.exists());
        assert_eq!(dyn_locator.url(), "");
        assert_eq!(dyn_locator.get_name(), "");
        assert!(!dyn_locator.is_windows_only_location());
        assert!(!dyn_locator.is_transient());
        assert!(dyn_locator.check_project_existence().is_err());
        assert!(dyn_locator.check_location_existence().is_err());
    }

    #[test]
    fn derives_project_paths_from_location_and_name() {
        let locator = SimpleProjectLocator {
            location: "/tmp/proj_parent".to_string(),
            name: "MyProject".to_string(),
        };

        assert_eq!(locator.get_project_dir(), PathBuf::from("/tmp/proj_parent/MyProject.rep"));
        assert_eq!(locator.get_marker_file(), PathBuf::from("/tmp/proj_parent/MyProject.gpr"));
        assert_eq!(
            locator.get_project_lock_file(),
            PathBuf::from("/tmp/proj_parent/MyProject.lock")
        );
    }

    #[test]
    fn exists_and_check_project_existence_reflect_real_filesystem_state() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let locator = SimpleProjectLocator {
            location: dir.path().to_string_lossy().into_owned(),
            name: "MyProject".to_string(),
        };

        assert!(!locator.exists());
        assert!(locator.check_project_existence().is_err());
        assert!(locator.check_location_existence().is_ok());

        std::fs::create_dir_all(locator.get_project_dir()).expect("create project dir");
        std::fs::write(locator.get_marker_file(), b"").expect("create marker file");

        assert!(locator.exists());
        assert!(locator.check_project_existence().is_ok());
    }

    #[test]
    fn check_location_existence_fails_for_missing_parent_directory() {
        let locator = SimpleProjectLocator {
            location: "/nonexistent/ghidra_rs_project_locator_parent".to_string(),
            name: "MyProject".to_string(),
        };

        let err = locator.check_location_existence().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn is_project_dir_checks_suffix_and_directory() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let rep_dir = dir.path().join("MyProject.rep");
        std::fs::create_dir_all(&rep_dir).expect("create .rep dir");

        assert!(is_project_dir(&rep_dir));
        assert!(!is_project_dir(dir.path()));
    }
}

//! Port of `ghidra.app.util.opinion.Loaded`.
//!
//! A loaded [`DomainObject`] produced by a [`Loader`](crate::app::util::opinion::loader::Loader).
//! In addition to storing the loaded domain object, it also stores the loader's desired name and
//! project folder path for the loaded domain object, should it get saved to a project.
//!
//! Java's `Loaded<T extends DomainObject>` generic parameter is dropped in favor of `dyn
//! DomainObject` uniformly, the same simplification already used for `LoadResults<? extends
//! DomainObject>` (see [`LoadResultsLike`](crate::app::seam_stubs::LoadResultsLike)) and other
//! generic-but-erasable core types in this crate.
//!
//! The class's private state (`domainObject`, `name`, `fsrl`, `project`, `projectRootPath`,
//! `mirrorFsLayout`, `loadedConsumer`, `domainFile`) is exposed as a set of required accessor
//! methods, following the same "promote to a fully-defaulted trait backed by minimal required
//! accessors" style used for [`DomainFile`], [`DomainFolder`], and [`Project`] in this crate.
//!
//! `mirror()` (the private helper backing `save()`'s `mirrorFsLayout` branch) is a *required*
//! trait method with no default body: its real implementation walks a concrete filesystem
//! (`GFileSystem`/`RefdFile`/`FileSystemService`, all already ported but parameterized by
//! filesystem-specific generic types that are not compatible with the object-safe [`Fsrl`] trait
//! used here) and creates project link-files via `FolderLinkContentHandler`/
//! `ProgramLinkContentHandler` (both still unported). Modeling it as an abstract method mirrors
//! how [`Loader::load`](crate::app::util::opinion::loader::Loader::load) is required rather than
//! defaulted: the behavior is fundamentally format/filesystem specific and only a concrete
//! implementation can supply it.
//!
//! `Object.toString()` becomes [`Loaded::to_display_string`] rather than an `impl
//! std::fmt::Display`, matching how `Comparable<T>` became `compare_to` methods on
//! [`DomainFile`]/[`DomainFolder`]/[`Project`] elsewhere in this crate, to keep the trait
//! unambiguous when used as `dyn Loaded`.

use std::any::TypeId;
use std::io;

use crate::filesystem::gfilesystem::fs_utilities;
use crate::filesystem::gfilesystem::fsrl::Fsrl;
use crate::framework::model::domain_folder::{CreateFileError, CreateFolderError};
use crate::framework::model::{
    DomainFile, DomainFolder, DomainObject, DomainObjectConsumer, Project,
};
use crate::util::exception::{CancelledException, ClosedException, InvalidNameException};
use crate::util::task::TaskMonitor;

/// Combines the checked exceptions declared on `Loaded.save(TaskMonitor)`: `IOException`,
/// `CancelledException`, `ClosedException`, and `InvalidNameException`.
#[derive(Debug, thiserror::Error)]
pub enum SaveError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Cancelled(#[from] CancelledException),
    #[error(transparent)]
    Closed(#[from] ClosedException),
    #[error(transparent)]
    InvalidName(#[from] InvalidNameException),
}

/// A loaded [`DomainObject`], plus the loader's desired name and project folder path for it,
/// should it get saved to a project.
///
/// Port of `ghidra.app.util.opinion.Loaded`.
pub trait Loaded {
    // -- Required accessors (mirror the class's private/protected fields) --------------------

    /// The loaded domain object.
    ///
    /// Mirrors the protected field `domainObject`.
    fn domain_object(&self) -> &dyn DomainObject;

    /// Mutable access to the loaded domain object.
    fn domain_object_mut(&mut self) -> &mut dyn DomainObject;

    /// The loaded domain object's type.
    ///
    /// Stands in for `Loaded.getDomainObjectType()`'s use of Java reflection (`getClass()`),
    /// since `dyn DomainObject` carries no type information of its own in this crate.
    fn domain_object_type(&self) -> TypeId;

    /// The name of the loaded domain object.
    ///
    /// Mirrors the protected final field `name`, exposed publicly via `getName()`.
    fn get_name(&self) -> String;

    /// The [`FSRL`](Fsrl) of the loaded domain object, if any.
    ///
    /// Mirrors the protected field `fsrl` (no public getter exists in Java; it is only consulted
    /// internally by `save()`/`mirror()`).
    fn fsrl(&self) -> Option<&dyn Fsrl>;

    /// The [`Project`] this will get saved to during a [`Loaded::save`] operation, if any.
    ///
    /// Mirrors the protected field `project`, exposed publicly via `getProject()`.
    fn get_project(&self) -> Option<&dyn Project>;

    /// The project folder path all saves are relative to. Always ends with `"/"`.
    ///
    /// Mirrors the protected field `projectRootPath`, exposed publicly via
    /// `getProjectFolderPath()`.
    fn get_project_folder_path(&self) -> &str;

    /// Internal setter for the already-normalized project folder path.
    ///
    /// Used by [`Loaded::set_project_folder_path`]'s default implementation; not part of the
    /// Java public API (which only exposes the normalizing `setProjectFolderPath(String)`).
    fn store_project_folder_path(&mut self, project_root_path: String);

    /// True if the filesystem layout should be mirrored when [`Loaded::save`]ing.
    ///
    /// Mirrors the protected field `mirrorFsLayout`.
    fn mirror_fs_layout(&self) -> bool;

    /// The consumer reference used by [`Loaded::close`]/[`Loaded::release`] to release the
    /// underlying domain object.
    ///
    /// Mirrors the protected field `loadedConsumer`.
    fn loaded_consumer(&self) -> Option<&DomainObjectConsumer>;

    /// The domain file this was [`Loaded::save`]d to, if any.
    ///
    /// Mirrors the protected field `domainFile`.
    fn saved_domain_file(&self) -> Option<&dyn DomainFile>;

    /// Internal setter recording the result of a [`Loaded::save`].
    ///
    /// Not part of the Java public API; used by [`Loaded::save`]'s default implementation.
    fn store_saved_domain_file(&mut self, domain_file: Option<Box<dyn DomainFile>>);

    /// Saves the loaded domain object to the given [`Project`], mirroring this object's
    /// filesystem path in the project.
    ///
    /// A required (not defaulted) method: mirrors `Loaded.mirror(TaskMonitor)`, whose real
    /// implementation walks a concrete `GFileSystem`, which needs filesystem-specific generic
    /// parameters this object-safe trait cannot supply generically. See the module docs.
    ///
    /// # Errors
    /// Returns `Err` if the operation was cancelled, or an IO/naming error occurred.
    fn mirror(&mut self, monitor: &dyn TaskMonitor) -> Result<Box<dyn DomainFile>, SaveError>;

    // -- Defaulted business logic --------------------------------------------------------------

    /// Gets the loaded domain object, registering `consumer` as a new user of it.
    ///
    /// Stands in for `Loaded.getDomainObject(Object)`, which adds `consumer` to the domain
    /// object and returns it. Since this trait cannot fabricate an owned `T`, the same reference
    /// is returned (with `consumer` now registered) rather than a fresh owned value.
    fn get_domain_object(&mut self, consumer: DomainObjectConsumer) -> &mut dyn DomainObject {
        self.domain_object_mut().add_consumer(consumer);
        self.domain_object_mut()
    }

    /// Gets the loaded domain object with unsafe resource management.
    ///
    /// Stands in for the deprecated no-arg `Loaded.getDomainObject()`.
    #[deprecated(note = "use get_domain_object instead, and release the returned consumer \
                          separately when done")]
    fn get_domain_object_unsafe(&self) -> &dyn DomainObject {
        self.domain_object()
    }

    /// Safely applies `operation` to the loaded domain object.
    ///
    /// Mirrors `Loaded.apply(Consumer<T>)`.
    fn apply(&mut self, operation: &mut dyn FnMut(&mut dyn DomainObject)) {
        operation(self.domain_object_mut());
    }

    /// Safely tests `predicate` against the loaded domain object.
    ///
    /// Mirrors `Loaded.check(Predicate<T>)`.
    fn check(&self, predicate: &dyn Fn(&dyn DomainObject) -> bool) -> bool {
        predicate(self.domain_object())
    }

    /// Sets the project folder path this will get saved to during a [`Loaded::save`] operation.
    ///
    /// Mirrors `Loaded.setProjectFolderPath(String)`: `None`/blank becomes `"/"`, a missing
    /// trailing `"/"` is appended, and (when [`Loaded::mirror_fs_layout`] is set) the result is
    /// run through [`mirrored_project_path`].
    fn set_project_folder_path(&mut self, project_root_path: Option<&str>) {
        let mut path = match project_root_path {
            Some(p) if !p.trim().is_empty() => p.to_string(),
            _ => "/".to_string(),
        };
        if !path.ends_with('/') {
            path.push('/');
        }
        if self.mirror_fs_layout() {
            path = mirrored_project_path(&path);
        }
        self.store_project_folder_path(path);
    }

    /// Gets the loaded domain object's associated domain file that was [`Loaded::save`]d.
    ///
    /// Mirrors `Loaded.getSavedDomainFile()`.
    ///
    /// # Errors
    /// Returns `Err` if the loaded domain object was saved but the associated domain file no
    /// longer exists (standing in for Java's `FileNotFoundException`, not ported as its own
    /// type).
    fn get_saved_domain_file(&self) -> io::Result<Option<&dyn DomainFile>> {
        if let Some(file) = self.saved_domain_file() {
            if !file.exists() {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("Saved DomainFile no longer exists: {}", file.get_pathname()),
                ));
            }
        }
        Ok(self.saved_domain_file())
    }

    /// Unsafely notifies the loaded domain object that `consumer` is no longer using it.
    ///
    /// Stands in for the deprecated `Loaded.release(Object)`.
    #[deprecated(note = "use close() instead")]
    fn release(&mut self, consumer: DomainObjectConsumer) {
        if !self.domain_object().is_closed() && self.domain_object().is_used_by(&consumer) {
            self.domain_object_mut().release(consumer);
        }
    }

    /// Closes this loaded domain object, releasing the reference held by the consumer that
    /// created it.
    ///
    /// Mirrors `Loaded.close()`.
    fn close(&mut self) {
        if let Some(consumer) = self.loaded_consumer().cloned() {
            if !self.domain_object().is_closed() && self.domain_object().is_used_by(&consumer) {
                self.domain_object_mut().release(consumer);
            }
        }
    }

    /// A short display string combining the project folder path and name.
    ///
    /// Stands in for `Loaded.toString()`.
    fn to_display_string(&self) -> String {
        format!("{}{}", self.get_project_folder_path(), self.get_name())
    }

    /// Saves the loaded domain object to its [`Project`] at this object's project folder path,
    /// using this object's name.
    ///
    /// Mirrors `Loaded.save(TaskMonitor)`.
    ///
    /// # Errors
    /// Returns `Err` if the operation was cancelled, the loaded domain object was already
    /// closed, there is no project, an invalid name was given, or an IO error occurred.
    fn save(&mut self, monitor: &dyn TaskMonitor) -> Result<&dyn DomainFile, SaveError> {
        if self.get_project().is_none() {
            return Err(SaveError::Io(io::Error::new(
                io::ErrorKind::Other,
                "Cannot save to null project",
            )));
        }
        if self.domain_object().is_closed() {
            let name = self.domain_object().get_name();
            return Err(SaveError::Closed(ClosedException::with_resource(format!(
                "Cannot save closed DomainObject: {name}"
            ))));
        }

        // Extract owned data out of the borrow immediately so the borrow checker doesn't see a
        // live reference into `self` across the later mutable `store_saved_domain_file` call.
        enum ExistingState {
            AlreadySaved(String),
            NeedsReset,
            Ok,
        }
        let state = match self.get_saved_domain_file() {
            Ok(Some(existing)) => ExistingState::AlreadySaved(existing.get_pathname()),
            Ok(None) => ExistingState::Ok,
            Err(_not_found) => ExistingState::NeedsReset,
        };
        match state {
            ExistingState::AlreadySaved(path) => {
                return Err(SaveError::Io(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("Already saved to {path}"),
                )));
            }
            ExistingState::NeedsReset => self.store_saved_domain_file(None),
            ExistingState::Ok => {}
        }

        if self.mirror_fs_layout() && self.fsrl().is_some() {
            let file = self.mirror(monitor)?;
            self.store_saved_domain_file(Some(file));
            return Ok(self.saved_domain_file().expect("just stored"));
        }

        let name = self.get_name();
        let (path_only, unique_base) = filename_parts(&name);
        let root_folder = self
            .get_project()
            .expect("checked for None above")
            .get_project_data()
            .get_root_folder();
        let full_path =
            fs_utilities::append_path(&[Some(self.get_project_folder_path()), Some(&path_only)])
                .unwrap_or_default();
        let mut program_folder = create_domain_folder_path(root_folder, &full_path)?;

        let mut unique_name = unique_base;
        let mut unique_name_index = 0;
        loop {
            if monitor.is_cancelled() {
                return Err(SaveError::Cancelled(CancelledException::default()));
            }
            match program_folder.create_file(&unique_name, self.domain_object(), monitor) {
                Ok(file) => {
                    self.store_saved_domain_file(Some(file));
                    return Ok(self.saved_domain_file().expect("just stored"));
                }
                Err(CreateFileError::Duplicate(_)) => {
                    unique_name = format!("{name}.{unique_name_index}");
                    unique_name_index += 1;
                }
                Err(CreateFileError::InvalidName(e)) => return Err(SaveError::InvalidName(e)),
                Err(CreateFileError::Io(e)) => return Err(SaveError::Io(e)),
                Err(CreateFileError::Cancelled(e)) => return Err(SaveError::Cancelled(e)),
            }
        }
    }
}

/// Walks (creating as needed) the domain folder path made of `path`'s `/`-separated components,
/// starting from `root`, returning the folder at the end of the path.
///
/// Stands in for the slice of `ProjectDataUtils.createDomainFolderPath(DomainFolder, String)`
/// that [`Loaded::save`] needs (the full class is not yet ported); built only from
/// [`DomainFolder`] methods already available in this crate.
fn create_domain_folder_path(
    root: Box<dyn DomainFolder>,
    path: &str,
) -> Result<Box<dyn DomainFolder>, SaveError> {
    let mut current = root;
    for segment in path.split('/') {
        if segment.is_empty() {
            continue;
        }
        let next = match current.get_folder(segment) {
            Some(folder) => folder,
            None => match current.create_folder(segment) {
                Ok(folder) => folder,
                Err(CreateFolderError::Duplicate(_)) => {
                    current.get_folder(segment).ok_or_else(|| {
                        SaveError::Io(io::Error::new(
                            io::ErrorKind::Other,
                            format!("Failed to create or find folder '{segment}'"),
                        ))
                    })?
                }
                Err(CreateFolderError::InvalidName(e)) => return Err(SaveError::InvalidName(e)),
                Err(CreateFolderError::Io(e)) => return Err(SaveError::Io(e)),
            },
        };
        current = next;
    }
    Ok(current)
}

/// Splits `path` into `(path_only, name_only)`, mirroring Apache Commons
/// `FilenameUtils.getFullPath`/`getName` for `/` and `\` separated paths.
///
/// A duplicate of the identical helper in
/// [`loader`](crate::app::util::opinion::loader), kept local since that one is private to its
/// module.
fn filename_parts(path: &str) -> (String, String) {
    match path.rfind(['/', '\\']) {
        Some(idx) => (path[..=idx].to_string(), path[idx + 1..].to_string()),
        None => (String::new(), path.to_string()),
    }
}

/// Replaces `\` with `/`, then ensures the result starts with `/`.
///
/// Mirrors `FSUtilities.normalizeNativePath(String)`.
fn normalize_native_path(path: &str) -> String {
    let unix_path = path.replace('\\', "/");
    fs_utilities::append_path(&[Some("/"), Some(&unix_path)]).unwrap_or_default()
}

/// Converts `path` to a valid mirrored project path by normalizing separators and, for an
/// absolute Windows-style path, dropping the drive letter's colon (not a valid project
/// character).
///
/// Mirrors `FSUtilities.mirroredProjectPath(String)`.
fn mirrored_project_path(path: &str) -> String {
    let normalized = normalize_native_path(path);
    let chars: Vec<char> = normalized.chars().collect();
    if chars.len() >= 3 && chars[0] == '/' && chars[1].is_alphabetic() && chars[2] == ':' {
        format!("/{}{}", chars[1], &normalized[3..])
    } else {
        normalized
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;
    use std::sync::Arc;

    use crate::framework::model::ProjectData;
    use crate::util::exception::DuplicateFileException;
    use crate::util::task::DummyMonitor;

    // -- Mock DomainObject with real consumer bookkeeping ---------------------------------

    struct MockDomainObject {
        name: String,
        consumers: Vec<DomainObjectConsumer>,
        closed: bool,
    }

    impl MockDomainObject {
        fn new(name: &str) -> Self {
            Self { name: name.to_string(), consumers: Vec::new(), closed: false }
        }
    }

    impl DomainObject for MockDomainObject {
        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn is_closed(&self) -> bool {
            self.closed
        }

        fn add_consumer(&mut self, consumer: DomainObjectConsumer) -> bool {
            if self.closed {
                return false;
            }
            self.consumers.push(consumer);
            true
        }

        fn is_used_by(&self, consumer: &DomainObjectConsumer) -> bool {
            self.consumers.iter().any(|c| Arc::ptr_eq(c, consumer))
        }

        fn release(&mut self, consumer: DomainObjectConsumer) {
            self.consumers.retain(|c| !Arc::ptr_eq(c, &consumer));
            if self.consumers.is_empty() {
                self.closed = true;
            }
        }
    }

    // -- Mock project/folder/file plumbing for save() -------------------------------------

    struct RecordingFolder {
        created_names: Rc<RefCell<Vec<String>>>,
    }

    struct SavedFile {
        name: String,
    }

    impl DomainFile for SavedFile {
        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn get_pathname(&self) -> String {
            format!("/{}", self.name)
        }

        fn exists(&self) -> bool {
            true
        }
    }

    impl DomainFolder for RecordingFolder {
        fn get_folder(&self, _name: &str) -> Option<Box<dyn DomainFolder>> {
            None
        }

        fn create_folder(
            &mut self,
            _folder_name: &str,
        ) -> Result<Box<dyn DomainFolder>, CreateFolderError> {
            Ok(Box::new(RecordingFolder { created_names: Rc::clone(&self.created_names) }))
        }

        fn create_file(
            &mut self,
            name: &str,
            _obj: &dyn DomainObject,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Box<dyn DomainFile>, CreateFileError> {
            let mut names = self.created_names.borrow_mut();
            if names.iter().any(|n| n == name) {
                return Err(CreateFileError::Duplicate(DuplicateFileException::new(name)));
            }
            names.push(name.to_string());
            Ok(Box::new(SavedFile { name: name.to_string() }))
        }
    }

    struct MockProjectData {
        names: Rc<RefCell<Vec<String>>>,
    }

    impl ProjectData for MockProjectData {
        fn get_root_folder(&self) -> Box<dyn DomainFolder> {
            Box::new(RecordingFolder { created_names: Rc::clone(&self.names) })
        }
    }

    struct MockProject {
        names: Rc<RefCell<Vec<String>>>,
    }

    impl Project for MockProject {
        fn get_project_data(&self) -> Box<dyn ProjectData> {
            Box::new(MockProjectData { names: Rc::clone(&self.names) })
        }
    }

    // -- MockLoaded ---------------------------------------------------------------------------

    struct MockLoaded {
        domain_object: MockDomainObject,
        name: String,
        project: Option<Box<dyn Project>>,
        project_root_path: String,
        mirror_fs_layout: bool,
        loaded_consumer: Option<DomainObjectConsumer>,
        saved_domain_file: Option<Box<dyn DomainFile>>,
        mirror_result: Option<SaveError>,
    }

    impl MockLoaded {
        fn new(name: &str, project: Option<Box<dyn Project>>, consumer: DomainObjectConsumer) -> Self {
            // Mirrors how a real `Loader` registers its caller's consumer on the domain object
            // before ever wrapping it in a `Loaded`; `Loaded`'s own constructor never adds one.
            let mut domain_object = MockDomainObject::new(name);
            domain_object.add_consumer(consumer.clone());
            let mut loaded = Self {
                domain_object,
                name: name.to_string(),
                project,
                project_root_path: String::new(),
                mirror_fs_layout: false,
                loaded_consumer: Some(consumer),
                saved_domain_file: None,
                mirror_result: None,
            };
            loaded.set_project_folder_path(None);
            loaded
        }
    }

    impl Loaded for MockLoaded {
        fn domain_object(&self) -> &dyn DomainObject {
            &self.domain_object
        }

        fn domain_object_mut(&mut self) -> &mut dyn DomainObject {
            &mut self.domain_object
        }

        fn domain_object_type(&self) -> TypeId {
            TypeId::of::<MockDomainObject>()
        }

        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn fsrl(&self) -> Option<&dyn Fsrl> {
            None
        }

        fn get_project(&self) -> Option<&dyn Project> {
            self.project.as_deref()
        }

        fn get_project_folder_path(&self) -> &str {
            &self.project_root_path
        }

        fn store_project_folder_path(&mut self, project_root_path: String) {
            self.project_root_path = project_root_path;
        }

        fn mirror_fs_layout(&self) -> bool {
            self.mirror_fs_layout
        }

        fn loaded_consumer(&self) -> Option<&DomainObjectConsumer> {
            self.loaded_consumer.as_ref()
        }

        fn saved_domain_file(&self) -> Option<&dyn DomainFile> {
            self.saved_domain_file.as_deref()
        }

        fn store_saved_domain_file(&mut self, domain_file: Option<Box<dyn DomainFile>>) {
            self.saved_domain_file = domain_file;
        }

        fn mirror(&mut self, _monitor: &dyn TaskMonitor) -> Result<Box<dyn DomainFile>, SaveError> {
            match self.mirror_result.take() {
                Some(err) => Err(err),
                None => Ok(Box::new(SavedFile { name: self.name.clone() })),
            }
        }
    }

    fn consumer() -> DomainObjectConsumer {
        Arc::new(42i32)
    }

    /// Unwraps the `Err` side of a `Result` whose `Ok` type isn't `Debug` (so `unwrap_err()`
    /// itself won't compile), panicking with a fixed message if the result was `Ok`.
    fn expect_err<T, E>(result: Result<T, E>) -> E {
        match result {
            Ok(_) => panic!("expected an error"),
            Err(e) => e,
        }
    }

    // -- Tests --------------------------------------------------------------------------------

    #[test]
    fn usable_as_trait_object_and_manages_consumers() {
        let owner = consumer();
        let mut loaded: Box<dyn Loaded> = Box::new(MockLoaded::new("prog.bin", None, owner.clone()));

        assert_eq!(loaded.get_name(), "prog.bin");
        assert_eq!(loaded.domain_object_type(), TypeId::of::<MockDomainObject>());
        assert!(!loaded.domain_object().is_closed());

        let fetch_consumer: DomainObjectConsumer = Arc::new(7i32);
        loaded.get_domain_object(fetch_consumer.clone());
        assert!(loaded.domain_object().is_used_by(&fetch_consumer));

        // `close()` only ever releases the original loaded-consumer (mirroring
        // `Loaded.close()`); a separate `get_domain_object` consumer must be released on its own.
        loaded.domain_object_mut().release(fetch_consumer);
        loaded.close();
        assert!(loaded.domain_object().is_closed());
    }

    #[test]
    fn apply_and_check_operate_on_domain_object() {
        let mut loaded = MockLoaded::new("a.bin", None, consumer());

        assert!(loaded.check(&|obj| obj.get_name() == "a.bin"));

        let mut seen_name = String::new();
        loaded.apply(&mut |obj| seen_name = obj.get_name());
        assert_eq!(seen_name, "a.bin");
    }

    #[test]
    fn release_only_affects_registered_consumer() {
        let owner = consumer();
        let mut loaded = MockLoaded::new("b.bin", None, owner.clone());

        let other: DomainObjectConsumer = Arc::new(99i32);
        loaded.get_domain_object(other.clone());

        #[allow(deprecated)]
        loaded.release(other.clone());
        assert!(!loaded.domain_object().is_closed());
        assert!(!loaded.domain_object().is_used_by(&other));
    }

    #[test]
    fn set_project_folder_path_defaults_blank_to_root() {
        let mut loaded = MockLoaded::new("a.bin", None, consumer());
        loaded.set_project_folder_path(None);
        assert_eq!(loaded.get_project_folder_path(), "/");

        loaded.set_project_folder_path(Some("   "));
        assert_eq!(loaded.get_project_folder_path(), "/");
    }

    #[test]
    fn set_project_folder_path_appends_trailing_slash() {
        let mut loaded = MockLoaded::new("a.bin", None, consumer());
        loaded.set_project_folder_path(Some("/foo/bar"));
        assert_eq!(loaded.get_project_folder_path(), "/foo/bar/");
    }

    #[test]
    fn set_project_folder_path_mirrors_windows_drive_letter_when_mirroring() {
        let mut loaded = MockLoaded::new("a.bin", None, consumer());
        loaded.mirror_fs_layout = true;
        loaded.set_project_folder_path(Some("C:/foo"));
        assert_eq!(loaded.get_project_folder_path(), "/C/foo/");
    }

    #[test]
    fn to_display_string_combines_path_and_name() {
        let mut loaded = MockLoaded::new("foo.bin", None, consumer());
        loaded.set_project_folder_path(Some("/subdir"));
        assert_eq!(loaded.to_display_string(), "/subdir/foo.bin");
    }

    #[test]
    fn get_saved_domain_file_errors_when_no_longer_exists() {
        struct GoneFile;
        impl DomainFile for GoneFile {
            fn exists(&self) -> bool {
                false
            }
        }

        let mut loaded = MockLoaded::new("a.bin", None, consumer());
        loaded.store_saved_domain_file(Some(Box::new(GoneFile)));
        let err = expect_err(loaded.get_saved_domain_file());
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn save_fails_when_project_is_none() {
        let mut loaded = MockLoaded::new("a.bin", None, consumer());
        let monitor = DummyMonitor;
        let err = expect_err(loaded.save(&monitor));
        assert!(matches!(err, SaveError::Io(_)));
    }

    #[test]
    fn save_fails_when_domain_object_already_closed() {
        let owner = consumer();
        let names = Rc::new(RefCell::new(Vec::new()));
        let project: Box<dyn Project> = Box::new(MockProject { names });
        let mut loaded = MockLoaded::new("a.bin", Some(project), owner.clone());
        loaded.domain_object.release(owner);
        assert!(loaded.domain_object.is_closed());

        let monitor = DummyMonitor;
        let err = expect_err(loaded.save(&monitor));
        assert!(matches!(err, SaveError::Closed(_)));
    }

    #[test]
    fn save_creates_file_and_returns_reference() {
        let names = Rc::new(RefCell::new(Vec::new()));
        let project: Box<dyn Project> = Box::new(MockProject { names: Rc::clone(&names) });
        let mut loaded = MockLoaded::new("foo.bin", Some(project), consumer());

        let monitor = DummyMonitor;
        let file = loaded.save(&monitor).unwrap();
        assert_eq!(file.get_name(), "foo.bin");
        assert_eq!(names.borrow().as_slice(), ["foo.bin".to_string()]);
    }

    #[test]
    fn save_retries_with_unique_name_on_duplicate() {
        let names = Rc::new(RefCell::new(vec!["foo.bin".to_string()]));
        let project: Box<dyn Project> = Box::new(MockProject { names: Rc::clone(&names) });
        let mut loaded = MockLoaded::new("foo.bin", Some(project), consumer());

        let monitor = DummyMonitor;
        let file = loaded.save(&monitor).unwrap();
        assert_eq!(file.get_name(), "foo.bin.0");
    }

    #[test]
    fn save_twice_fails_already_saved() {
        let names = Rc::new(RefCell::new(Vec::new()));
        let project: Box<dyn Project> = Box::new(MockProject { names });
        let mut loaded = MockLoaded::new("foo.bin", Some(project), consumer());

        let monitor = DummyMonitor;
        loaded.save(&monitor).unwrap();
        let err = expect_err(loaded.save(&monitor));
        assert!(matches!(err, SaveError::Io(_)));
    }

    #[test]
    fn save_delegates_to_mirror_when_mirroring_with_fsrl() {
        // fsrl() always returns None in this mock, so mirroring is never triggered even when
        // mirror_fs_layout is set; this documents that `save`'s mirror branch requires both.
        let names = Rc::new(RefCell::new(Vec::new()));
        let project: Box<dyn Project> = Box::new(MockProject { names: Rc::clone(&names) });
        let mut loaded = MockLoaded::new("foo.bin", Some(project), consumer());
        loaded.mirror_fs_layout = true;

        let monitor = DummyMonitor;
        loaded.save(&monitor).unwrap();
        // Took the non-mirror path since fsrl() is None.
        assert_eq!(names.borrow().as_slice(), ["foo.bin".to_string()]);
    }

    #[test]
    fn mirror_required_method_is_called_directly() {
        let mut loaded = MockLoaded::new("foo.bin", None, consumer());
        let monitor = DummyMonitor;
        let file = loaded.mirror(&monitor).unwrap();
        assert_eq!(file.get_name(), "foo.bin");
    }

    #[test]
    fn mirror_propagates_error() {
        let mut loaded = MockLoaded::new("foo.bin", None, consumer());
        loaded.mirror_result = Some(SaveError::Io(io::Error::new(io::ErrorKind::Other, "boom")));
        let monitor = DummyMonitor;
        let err = expect_err(loaded.mirror(&monitor));
        assert!(matches!(err, SaveError::Io(_)));
    }

    #[test]
    fn filename_parts_splits_on_last_separator() {
        assert_eq!(filename_parts("a/b/c.bin"), ("a/b/".to_string(), "c.bin".to_string()));
        assert_eq!(filename_parts("plain.bin"), (String::new(), "plain.bin".to_string()));
    }

    #[test]
    fn mirrored_project_path_drops_windows_drive_colon() {
        assert_eq!(mirrored_project_path("C:/foo/bar"), "/C/foo/bar");
        assert_eq!(mirrored_project_path("/already/unix"), "/already/unix");
    }
}

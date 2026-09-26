//! Port of `ghidra.formats.gfilesystem.factory.FileSystemFactoryMgr`.
//!
//! The registry of filesystem implementations and their factories, used to probe container
//! files and mount filesystems.
//!
//! Java fills the registry by scanning the classpath (`ClassSearcher`) for `GFileSystem`
//! classes and reading their `@FileSystemInfo` annotations. Here filesystems are registered
//! explicitly with [`register`](FileSystemFactoryMgr::register) (the metadata struct and
//! factory instance the annotation named), and the manager is an ordinary value owned by the
//! [`FileSystemService`] rather than a singleton.

use std::any::{type_name, TypeId};
use std::cmp::Ordering;
use std::collections::HashMap;
use std::io;
use std::rc::Rc;

use crate::app::util::bin::byte_provider::ByteProvider;
use crate::filesystem::gfilesystem::annotations::file_system_info::{FileSystemInfo, PRIORITY_LOWEST};
use crate::filesystem::gfilesystem::file_system_probe_conflict_resolver::{
    ChooseFirstResolver, FileSystemProbeConflictResolver,
};
use crate::filesystem::gfilesystem::file_system_service::FileSystemService;
use crate::filesystem::gfilesystem::fsrl_root::FsrlRoot;
use crate::filesystem::gfilesystem::g_file_system::{FsHandle, GFileSystem, GFileSystemError};
use crate::util::msg::Msg;
use crate::util::task::TaskMonitor;

use super::file_system_factory_dependency_exception::FileSystemFactoryDependencyException;
use super::file_system_info_rec::{by_priority, FileSystemInfoRec};
use super::g_file_system_factory::GFileSystemFactory;
use super::g_file_system_probe_bytes_only::MAX_BYTES_REQUIRED;

/// Statically registers filesystem implementations and their factories, and uses them to
/// probe container files and mount filesystems.
///
/// Mirrors `ghidra.formats.gfilesystem.factory.FileSystemFactoryMgr`.
#[derive(Default)]
pub struct FileSystemFactoryMgr {
    largest_bytes_required: usize,
    sorted_factories: Vec<FileSystemInfoRec>,
    fs_by_type: HashMap<String, FileSystemInfoRec>,
}

fn close_quietly(mut bp: Box<dyn ByteProvider>) {
    // Mirrors FSUtilities.uncheckedClose: close errors are ignored.
    let _ = bp.close();
}

impl FileSystemFactoryMgr {
    /// Creates an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers the filesystem type `FS`, described by `info`, created by `factory`.
    ///
    /// Mirrors the private `addFactory(Class)`, called for each class the Java constructor
    /// finds: a bad type string, a duplicate type, or a [`GFileSystemFactoryIgnore`] factory
    /// leaves the registry unchanged, and a bytes-only probe asking for more than
    /// [`MAX_BYTES_REQUIRED`] bytes is registered but its probe is skipped (logged as an error,
    /// as in Java). Registration keeps the factories sorted by descending priority.
    ///
    /// [`GFileSystemFactoryIgnore`]: super::g_file_system_factory_ignore::GFileSystemFactoryIgnore
    pub fn register<FS: GFileSystem>(&mut self, info: &FileSystemInfo, factory: Rc<dyn GFileSystemFactory>) {
        let Some(fsir) = FileSystemInfoRec::from_class::<FS>(info, factory) else {
            Msg::error(
                "FileSystemFactoryMgr",
                &format!("No valid FileSystemInfo found for {}", type_name::<FS>()),
            );
            return;
        };
        if let Some(prev) = self.fs_by_type.get(fsir.get_type()) {
            Msg::error(
                "FileSystemFactoryMgr",
                &format!(
                    "GFileSystem type '{}' registered more than one time: {}, {}, ommitting second instance.",
                    fsir.get_type(),
                    type_name::<FS>(),
                    prev.get_fs_class_name()
                ),
            );
            return;
        }
        if fsir.get_factory().is_ignore() {
            // don't register any filesystem that uses this factory
            return;
        }
        if let Some(pbo) = fsir.get_factory().as_probe_bytes_only() {
            if pbo.bytes_required() > MAX_BYTES_REQUIRED {
                Msg::error(
                    "FileSystemFactoryMgr",
                    &format!(
                        "GFileSystemProbeBytesOnly for {} specifies too large value for bytes_required: {}, skipping this probe.",
                        type_name::<FS>(),
                        pbo.bytes_required()
                    ),
                );
            } else {
                self.largest_bytes_required = self.largest_bytes_required.max(pbo.bytes_required());
            }
        }
        self.fs_by_type.insert(fsir.get_type().to_string(), fsir.clone());
        self.sorted_factories.push(fsir);
        // Stable, like Java's List.sort: equal priorities keep registration order.
        self.sorted_factories.sort_by(by_priority);
    }

    /// The descriptions of all registered filesystem types, sorted case-insensitively.
    /// Mirrors `getAllFilesystemNames()`.
    pub fn get_all_filesystem_names(&self) -> Vec<String> {
        let mut names: Vec<String> =
            self.fs_by_type.values().map(|f| f.get_description().to_string()).collect();
        names.sort_by(|a, b| {
            a.to_lowercase().cmp(&b.to_lowercase()).then(Ordering::Equal)
        });
        names
    }

    /// The registered type string of filesystem type `FS`, or `None` if it was not
    /// registered. Mirrors `getFileSystemType(Class)`.
    pub fn get_file_system_type<FS: GFileSystem>(&self) -> Option<String> {
        let id = TypeId::of::<FS>();
        self.fs_by_type.values().find(|f| f.get_fs_class() == id).map(|f| f.get_type().to_string())
    }

    /// Creates a new filesystem of type `fs_type` from `byte_provider` (which the new
    /// filesystem, or this method on error, takes ownership of). Mirrors
    /// `mountFileSystem(String, ByteProvider, FileSystemService, TaskMonitor)`.
    ///
    /// # Errors
    /// If the type is unknown, the provider has no FSRL, or the factory fails.
    pub fn mount_file_system(
        &self,
        fs_type: &str,
        byte_provider: Box<dyn ByteProvider>,
        fs_service: &FileSystemService,
        monitor: &dyn TaskMonitor,
    ) -> Result<FsHandle, GFileSystemError> {
        let Some(fsir) = self.fs_by_type.get(fs_type) else {
            close_quietly(byte_provider);
            return Err(io::Error::other(format!("Unknown file system type {fs_type}")).into());
        };
        let Some(target_fsrl) = byte_provider.get_fsrl().map(|f| f.make_nested(fs_type)) else {
            close_quietly(byte_provider);
            return Err(io::Error::other("ByteProvider has no FSRL").into());
        };
        self.mount_using_factory(fsir, byte_provider, &target_fsrl, fs_service, monitor)
    }

    fn mount_using_factory(
        &self,
        fsir: &FileSystemInfoRec,
        byte_provider: Box<dyn ByteProvider>,
        target_fsrl: &FsrlRoot,
        fs_service: &FileSystemService,
        monitor: &dyn TaskMonitor,
    ) -> Result<FsHandle, GFileSystemError> {
        let Some(bp_factory) = fsir.get_factory().as_byte_provider_factory() else {
            // Java falls through with a null result when no factory flavor applies.
            close_quietly(byte_provider);
            return Err(io::Error::other(format!(
                "No usable factory for file system type {}",
                fsir.get_type()
            ))
            .into());
        };
        bp_factory.create(target_fsrl, byte_provider, fs_service, monitor).inspect_err(|e| {
            let dependency = matches!(e, GFileSystemError::Io(io)
                if io.get_ref().is_some_and(|inner| inner.is::<FileSystemFactoryDependencyException>()));
            if dependency {
                Msg::warn(
                    "FileSystemFactoryMgr",
                    &format!("File system dependency error: {e} ({})", fsir.get_type()),
                );
            } else {
                Msg::warn(
                    "FileSystemFactoryMgr",
                    &format!(
                        "Error during fs factory create: {}, {}: {e}",
                        fsir.get_type(),
                        fsir.get_fs_class_name()
                    ),
                );
            }
        })
    }

    fn start_bytes(&self, byte_provider: &dyn ByteProvider) -> io::Result<Vec<u8>> {
        let pbo_byte_count =
            (byte_provider.length().min(MAX_BYTES_REQUIRED as u64) as usize).min(self.largest_bytes_required);
        byte_provider.read_bytes(0, pbo_byte_count as u64)
    }

    /// Returns `true` if any registered probe recognizes `byte_provider`'s contents. Mirrors
    /// `test(ByteProvider, FileSystemService, TaskMonitor)`.
    ///
    /// # Errors
    /// If the start bytes cannot be read, or a probe is cancelled.
    pub fn test(
        &self,
        byte_provider: &dyn ByteProvider,
        fs_service: &FileSystemService,
        monitor: &dyn TaskMonitor,
    ) -> Result<bool, GFileSystemError> {
        let start_bytes = self.start_bytes(byte_provider)?;
        let container_fsrl = byte_provider.get_fsrl();
        for fsir in &self.sorted_factories {
            if let (Some(probe), Some(fsrl)) = (fsir.get_factory().as_probe_bytes_only(), container_fsrl) {
                if probe.bytes_required() <= start_bytes.len() && probe.probe_start_bytes(fsrl, &start_bytes) {
                    return Ok(true);
                }
            }
            if let Some(probe) = fsir.get_factory().as_probe_byte_provider() {
                match probe.probe(byte_provider, fs_service, monitor) {
                    Ok(true) => return Ok(true),
                    Ok(false) => {}
                    Err(GFileSystemError::Io(e)) => Msg::trace(
                        "FileSystemFactoryMgr",
                        &format!("File system probe error for {}: {e}", fsir.get_description()),
                    ),
                    Err(e) => return Err(e),
                }
            }
        }
        Ok(false)
    }

    /// Probes `byte_provider` with every registered factory whose priority is at least
    /// `priority_filter`, lets `conflict_resolver` (default: choose first) pick among the
    /// matches, and mounts the chosen filesystem. Returns `Ok(None)` if nothing matched.
    ///
    /// Takes ownership of `byte_provider`: it ends up owned by the new filesystem, or is
    /// closed. Mirrors `probe(ByteProvider, FileSystemService,
    /// FileSystemProbeConflictResolver, int, TaskMonitor)`.
    ///
    /// # Errors
    /// If reading fails, a probe is cancelled, or the chosen factory fails.
    pub fn probe(
        &self,
        byte_provider: Box<dyn ByteProvider>,
        fs_service: &FileSystemService,
        conflict_resolver: Option<&dyn FileSystemProbeConflictResolver>,
        priority_filter: i32,
        monitor: &dyn TaskMonitor,
    ) -> Result<Option<FsHandle>, GFileSystemError> {
        let conflict_resolver = conflict_resolver.unwrap_or(&ChooseFirstResolver);
        let Some(container_fsrl) = byte_provider.get_fsrl().cloned() else {
            close_quietly(byte_provider);
            return Err(io::Error::other("ByteProvider has no FSRL").into());
        };
        let start_bytes = match self.start_bytes(&*byte_provider) {
            Ok(b) => b,
            Err(e) => {
                close_quietly(byte_provider);
                return Err(e.into());
            }
        };
        let mut probe_matches: Vec<&FileSystemInfoRec> = Vec::new();
        for fsir in &self.sorted_factories {
            if fsir.get_priority() < priority_filter {
                break;
            }
            if let Some(probe) = fsir.get_factory().as_probe_bytes_only() {
                if probe.bytes_required() <= start_bytes.len()
                    && probe.probe_start_bytes(&container_fsrl, &start_bytes)
                {
                    probe_matches.push(fsir);
                    continue;
                }
            }
            if let Some(probe) = fsir.get_factory().as_probe_byte_provider() {
                match probe.probe(&*byte_provider, fs_service, monitor) {
                    Ok(true) => {
                        probe_matches.push(fsir);
                        continue;
                    }
                    Ok(false) => {}
                    Err(GFileSystemError::Io(e)) => Msg::trace(
                        "FileSystemFactoryMgr",
                        &format!(
                            "File system probe error for {} with {container_fsrl}: {e}",
                            fsir.get_description()
                        ),
                    ),
                    Err(e) => {
                        close_quietly(byte_provider);
                        return Err(e);
                    }
                }
            }
        }
        monitor.set_message("Choosing filesystem");
        let Some(fsir) = conflict_resolver.resolve_fsir(&probe_matches) else {
            close_quietly(byte_provider);
            return Ok(None);
        };
        // From here the byte provider belongs to the new filesystem (or the factory closes it
        // on error).
        let target = container_fsrl.make_nested(fsir.get_type());
        let fs = self.mount_using_factory(fsir, byte_provider, &target, fs_service, monitor)?;
        monitor.set_message(&format!("Found file system {}", fs.get_description()));
        Ok(Some(fs))
    }

    /// [`probe`](Self::probe) with no priority filter. Mirrors the four-argument
    /// `probe(ByteProvider, FileSystemService, FileSystemProbeConflictResolver, TaskMonitor)`.
    ///
    /// # Errors
    /// See [`probe`](Self::probe).
    pub fn probe_default(
        &self,
        byte_provider: Box<dyn ByteProvider>,
        fs_service: &FileSystemService,
        conflict_resolver: Option<&dyn FileSystemProbeConflictResolver>,
        monitor: &dyn TaskMonitor,
    ) -> Result<Option<FsHandle>, GFileSystemError> {
        self.probe(byte_provider, fs_service, conflict_resolver, PRIORITY_LOWEST, monitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::gfilesystem::annotations::file_system_info::{PRIORITY_HIGH, PRIORITY_LOW};
    use crate::filesystem::gfilesystem::factory::g_file_system_factory_ignore::GFileSystemFactoryIgnore;
    use crate::filesystem::gfilesystem::factory::g_file_system_probe::GFileSystemProbe;
    use crate::filesystem::gfilesystem::factory::g_file_system_probe_bytes_only::GFileSystemProbeBytesOnly;
    use crate::filesystem::gfilesystem::file_system_ref_manager::test_support::EmptyFs;
    use crate::filesystem::gfilesystem::fsrl::Fsrl;
    use crate::filesystem::gfilesystem::local_file_system::LocalFileSystem;

    struct BytesProbe(usize);
    impl GFileSystemFactory for BytesProbe {
        fn as_probe_bytes_only(&self) -> Option<&dyn GFileSystemProbeBytesOnly> {
            Some(self)
        }
    }
    impl GFileSystemProbe for BytesProbe {}
    impl GFileSystemProbeBytesOnly for BytesProbe {
        fn bytes_required(&self) -> usize {
            self.0
        }
        fn probe_start_bytes(&self, _c: &Fsrl, _b: &[u8]) -> bool {
            true
        }
    }

    #[test]
    fn register_sorts_by_priority_and_rejects_duplicates_and_ignored() {
        let mut mgr = FileSystemFactoryMgr::new();
        mgr.register::<EmptyFs>(&FileSystemInfo::with("low", "Low", PRIORITY_LOW), Rc::new(BytesProbe(4)));
        mgr.register::<LocalFileSystem>(&FileSystemInfo::with("high", "high", PRIORITY_HIGH), Rc::new(BytesProbe(8)));
        // Duplicate type string: ignored.
        mgr.register::<EmptyFs>(&FileSystemInfo::with("low", "Other", 0), Rc::new(BytesProbe(2)));
        // Ignore factory: never registered.
        mgr.register::<EmptyFs>(&FileSystemInfo::new("ign"), Rc::new(GFileSystemFactoryIgnore));
        // Bad type string.
        mgr.register::<EmptyFs>(&FileSystemInfo::new("Bad-Type"), Rc::new(BytesProbe(2)));

        let types: Vec<&str> = mgr.sorted_factories.iter().map(|f| f.get_type()).collect();
        assert_eq!(types, ["high", "low"]);
        assert_eq!(mgr.largest_bytes_required, 8);
        assert_eq!(mgr.get_all_filesystem_names(), ["high", "Low"]);
        assert_eq!(mgr.get_file_system_type::<LocalFileSystem>().as_deref(), Some("high"));
    }

    #[test]
    fn oversized_bytes_only_probe_is_registered_but_not_counted() {
        let mut mgr = FileSystemFactoryMgr::new();
        mgr.register::<EmptyFs>(&FileSystemInfo::new("big"), Rc::new(BytesProbe(MAX_BYTES_REQUIRED + 1)));
        assert_eq!(mgr.largest_bytes_required, 0);
        assert_eq!(mgr.get_file_system_type::<EmptyFs>().as_deref(), Some("big"));
    }
}

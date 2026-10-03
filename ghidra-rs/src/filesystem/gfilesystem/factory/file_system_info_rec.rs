//! Port of `ghidra.formats.gfilesystem.factory.FileSystemInfoRec`.

use std::any::{type_name, TypeId};
use std::cmp::Ordering;
use std::fmt;
use std::rc::Rc;

use crate::filesystem::gfilesystem::annotations::file_system_info::FileSystemInfo;
use crate::filesystem::gfilesystem::g_file_system::GFileSystem;
use crate::util::msg::Msg;

use super::g_file_system_factory::GFileSystemFactory;

/// Holds information read from a filesystem's [`FileSystemInfo`] metadata, plus its factory.
///
/// Mirrors `ghidra.formats.gfilesystem.factory.FileSystemInfoRec`. Java's `Class<? extends
/// GFileSystem>` becomes the filesystem's [`TypeId`] (used by
/// [`FileSystemFactoryMgr::get_file_system_type`](super::file_system_factory_mgr::FileSystemFactoryMgr::get_file_system_type))
/// plus its type name (used where Java logs `getFSClass().getName()`).
#[derive(Clone)]
pub struct FileSystemInfoRec {
    fs_type: String,
    description: String,
    priority: i32,
    fs_class: TypeId,
    fs_class_name: &'static str,
    factory: Rc<dyn GFileSystemFactory>,
}

/// `[a-z0-9]+`, Java's `FSTYPE_VALID_REGEX`.
fn is_valid_fs_type(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

impl FileSystemInfoRec {
    /// Creates a record directly. Mirrors the private Java constructor.
    pub fn new(
        fs_type: &str,
        description: &str,
        priority: i32,
        fs_class: TypeId,
        fs_class_name: &'static str,
        factory: Rc<dyn GFileSystemFactory>,
    ) -> Self {
        FileSystemInfoRec {
            fs_type: fs_type.to_string(),
            description: description.to_string(),
            priority,
            fs_class,
            fs_class_name,
            factory,
        }
    }

    /// Builds a record for the filesystem type `FS` from its metadata and factory, or `None`
    /// (after logging an error) if the type string is not `[a-z0-9]+`.
    ///
    /// Mirrors `fromClass(Class)`, with the annotation and factory instance supplied by the
    /// caller instead of found by reflection.
    pub fn from_class<FS: GFileSystem>(
        info: &FileSystemInfo,
        factory: Rc<dyn GFileSystemFactory>,
    ) -> Option<Self> {
        if !is_valid_fs_type(info.fs_type) {
            Msg::error(
                "FileSystemInfoRec",
                &format!(
                    "Bad GFileSystem type specified for {}: {}, skipping.",
                    type_name::<FS>(),
                    info.fs_type
                ),
            );
            return None;
        }
        Some(Self::new(
            info.fs_type,
            info.description,
            info.priority,
            TypeId::of::<FS>(),
            type_name::<FS>(),
            factory,
        ))
    }

    /// Filesystem 'type', ie. "file", or "zip", etc. Mirrors `getType()`.
    pub fn get_type(&self) -> &str {
        &self.fs_type
    }

    /// Filesystem description. Mirrors `getDescription()`.
    pub fn get_description(&self) -> &str {
        &self.description
    }

    /// Filesystem relative priority; higher values are considered first. Mirrors
    /// `getPriority()`.
    pub fn get_priority(&self) -> i32 {
        self.priority
    }

    /// The filesystem implementation type. Mirrors `getFSClass()`.
    pub fn get_fs_class(&self) -> TypeId {
        self.fs_class
    }

    /// The filesystem implementation type's name (Java's `getFSClass().getName()`).
    pub fn get_fs_class_name(&self) -> &str {
        self.fs_class_name
    }

    /// The factory that creates instances of this filesystem. Mirrors `getFactory()`.
    pub fn get_factory(&self) -> &dyn GFileSystemFactory {
        &*self.factory
    }
}

impl fmt::Debug for FileSystemInfoRec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileSystemInfoRec")
            .field("type", &self.fs_type)
            .field("description", &self.description)
            .field("priority", &self.priority)
            .field("class", &self.fs_class_name)
            .finish()
    }
}

/// Sorts records by descending priority. Mirrors `FileSystemInfoRec.BY_PRIORITY`.
pub fn by_priority(a: &FileSystemInfoRec, b: &FileSystemInfoRec) -> Ordering {
    b.priority.cmp(&a.priority)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::gfilesystem::annotations::file_system_info::{
        PRIORITY_HIGH, PRIORITY_LOW,
    };
    use crate::filesystem::gfilesystem::file_system_ref_manager::test_support::EmptyFs;

    struct DummyFactory;
    impl GFileSystemFactory for DummyFactory {}

    #[test]
    fn from_class_reads_metadata() {
        let info = FileSystemInfo::with("zip", "Zip", PRIORITY_HIGH);
        let rec = FileSystemInfoRec::from_class::<EmptyFs>(&info, Rc::new(DummyFactory)).unwrap();
        assert_eq!(rec.get_type(), "zip");
        assert_eq!(rec.get_description(), "Zip");
        assert_eq!(rec.get_priority(), PRIORITY_HIGH);
        assert_eq!(rec.get_fs_class(), TypeId::of::<EmptyFs>());
        assert!(rec.get_fs_class_name().ends_with("EmptyFs"));
    }

    #[test]
    fn from_class_rejects_bad_type_strings() {
        for bad in ["", "Zip", "a-b", "a b"] {
            let info = FileSystemInfo::new(bad);
            assert!(FileSystemInfoRec::from_class::<EmptyFs>(&info, Rc::new(DummyFactory)).is_none());
        }
    }

    #[test]
    fn by_priority_sorts_descending() {
        let f: Rc<dyn GFileSystemFactory> = Rc::new(DummyFactory);
        let lo = FileSystemInfoRec::from_class::<EmptyFs>(&FileSystemInfo::with("lo", "", PRIORITY_LOW), f.clone()).unwrap();
        let hi = FileSystemInfoRec::from_class::<EmptyFs>(&FileSystemInfo::with("hi", "", PRIORITY_HIGH), f).unwrap();
        let mut v = vec![lo, hi];
        v.sort_by(by_priority);
        assert_eq!(v[0].get_type(), "hi");
        assert_eq!(v[1].get_type(), "lo");
    }
}

use std::cmp::Ordering;

use crate::filesystem::seam_stubs::GFileSystemLike;

use super::g_file_system_factory::GFileSystemFactory;

/// Holds information read from a `FileSystemInfo` annotation.
///
/// This is the Rust equivalent of `ghidra.formats.gfilesystem.factory.FileSystemInfoRec`.
///
/// The Java class is materialized by reflecting on a `FileSystemInfo` annotation attached to
/// a `GFileSystem` implementation class (`FileSystemInfoRec.fromClass`): it reads the
/// annotation's `type`/`description`/`priority`/`factory` elements, instantiates the factory
/// via its no-arg constructor, and records the `Class<? extends GFileSystem>` it came from.
/// Rust has no annotations or reflection, so there is no equivalent of `fromClass` here --
/// whatever registry assembles filesystem metadata (the eventual port of
/// `FileSystemFactoryMgr`) is responsible for constructing instances of this trait directly,
/// the same way [`FileSystemInfo`](crate::filesystem::gfilesystem::annotations::file_system_info::FileSystemInfo)
/// already stands in for the annotation itself.
///
/// `fsClass.getName()` (used only for logging/identification in the Java code, never
/// reflected on further) is represented here as [`get_fs_class_name`](Self::get_fs_class_name)
/// rather than pulling in a `Class<?>`-style seam.
pub trait FileSystemInfoRec<FSTYPE: GFileSystemLike> {
    /// Filesystem 'type', ie. "file", or "zip", etc.
    fn get_type(&self) -> &str;

    /// Filesystem description, ie. "XYZ Vendor Filesystem Type 1".
    fn get_description(&self) -> &str;

    /// Filesystem relative priority. Higher numeric values are considered before lower
    /// values.
    fn get_priority(&self) -> i32;

    /// The name of the `GFileSystem` implementation class this record describes.
    fn get_fs_class_name(&self) -> &str;

    /// The [`GFileSystemFactory`] instance that will create new filesystem instances when
    /// needed.
    fn get_factory(&self) -> &dyn GFileSystemFactory<FSTYPE>;
}

/// Orders [`FileSystemInfoRec`]s by [`FileSystemInfoRec::get_priority`], with the highest
/// priority elements sorted to the beginning of the list.
///
/// This is the Rust equivalent of the static `FileSystemInfoRec.BY_PRIORITY` `Comparator`.
pub fn by_priority<FSTYPE: GFileSystemLike>(
    a: &dyn FileSystemInfoRec<FSTYPE>,
    b: &dyn FileSystemInfoRec<FSTYPE>,
) -> Ordering {
    b.get_priority().cmp(&a.get_priority())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DummyFileSystem;
    impl GFileSystemLike for DummyFileSystem {}

    struct DummyFactory;
    impl GFileSystemFactory<DummyFileSystem> for DummyFactory {}

    struct MockRec {
        fs_type: &'static str,
        description: &'static str,
        priority: i32,
        fs_class_name: &'static str,
        factory: DummyFactory,
    }

    impl FileSystemInfoRec<DummyFileSystem> for MockRec {
        fn get_type(&self) -> &str {
            self.fs_type
        }

        fn get_description(&self) -> &str {
            self.description
        }

        fn get_priority(&self) -> i32 {
            self.priority
        }

        fn get_fs_class_name(&self) -> &str {
            self.fs_class_name
        }

        fn get_factory(&self) -> &dyn GFileSystemFactory<DummyFileSystem> {
            &self.factory
        }
    }

    #[test]
    fn accessors_return_constructed_values() {
        let rec = MockRec {
            fs_type: "zip",
            description: "Zip filesystem",
            priority: 5,
            fs_class_name: "ghidra.ZipGFileSystem",
            factory: DummyFactory,
        };
        assert_eq!(rec.get_type(), "zip");
        assert_eq!(rec.get_description(), "Zip filesystem");
        assert_eq!(rec.get_priority(), 5);
        assert_eq!(rec.get_fs_class_name(), "ghidra.ZipGFileSystem");
        let _factory = rec.get_factory();
    }

    #[test]
    fn by_priority_sorts_highest_first() {
        let low = MockRec {
            fs_type: "low",
            description: "",
            priority: -10,
            fs_class_name: "Low",
            factory: DummyFactory,
        };
        let high = MockRec {
            fs_type: "high",
            description: "",
            priority: 10,
            fs_class_name: "High",
            factory: DummyFactory,
        };
        let default_rec = MockRec {
            fs_type: "def",
            description: "",
            priority: 0,
            fs_class_name: "Default",
            factory: DummyFactory,
        };

        let mut recs: Vec<&dyn FileSystemInfoRec<DummyFileSystem>> = vec![&low, &high, &default_rec];
        recs.sort_by(|a, b| by_priority::<DummyFileSystem>(*a, *b));

        let types: Vec<&str> = recs.iter().map(|r| r.get_type()).collect();
        assert_eq!(types, vec!["high", "def", "low"]);
    }

    #[test]
    fn boxed_dyn_file_system_info_rec_is_accepted() {
        let rec: Box<dyn FileSystemInfoRec<DummyFileSystem>> = Box::new(MockRec {
            fs_type: "myfs",
            description: "desc",
            priority: 0,
            fs_class_name: "MyFs",
            factory: DummyFactory,
        });
        assert_eq!(rec.get_type(), "myfs");
    }
}

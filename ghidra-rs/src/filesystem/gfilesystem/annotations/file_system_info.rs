use crate::filesystem::gfilesystem::factory::g_file_system_factory::GFileSystemFactory;
use crate::filesystem::seam_stubs::GFileSystemLike;

/// Default relative probing priority.
pub const PRIORITY_DEFAULT: i32 = 0;
/// A higher-than-default relative probing priority.
pub const PRIORITY_HIGH: i32 = 10;
/// A lower-than-default relative probing priority.
pub const PRIORITY_LOW: i32 = -10;
/// The lowest possible relative probing priority.
pub const PRIORITY_LOWEST: i32 = i32::MIN;

/// Specifies the info needed of a `GFileSystem` implementation.
///
/// This is the Rust equivalent of `ghidra.formats.gfilesystem.annotations.FileSystemInfo`,
/// a Java annotation used to attach static metadata to `GFileSystem` implementation classes.
/// Rust has no annotation mechanism, so this port becomes a trait that a filesystem
/// implementation (or a metadata descriptor for one) implements to expose that same
/// information at runtime.
///
/// `FSTYPE` mirrors the annotation's `Class<? extends GFileSystemFactory<?>>` element by
/// parameterizing the associated [`GFileSystemFactory`] the same way
/// [`GFileSystemFactory`](crate::filesystem::gfilesystem::factory::g_file_system_factory::GFileSystemFactory)
/// itself is parameterized, keeping this trait object-safe.
pub trait FileSystemInfo<FSTYPE: GFileSystemLike> {
    /// The 'type' of this filesystem, a short 1 word, lowercase string used in FSRLs to
    /// reference this filesystem, "[a-z0-9]+" only.
    fn fs_type(&self) -> &str;

    /// A longer description of this filesystem. Defaults to an empty string if not set.
    fn description(&self) -> &str {
        ""
    }

    /// The [`GFileSystemFactory`] responsible for probing and creating instances of this
    /// filesystem.
    fn factory(&self) -> Box<dyn GFileSystemFactory<FSTYPE>>;

    /// The relative priority of this filesystem during probing. Higher numeric values are
    /// considered before lower values. Defaults to [`PRIORITY_DEFAULT`].
    fn priority(&self) -> i32 {
        PRIORITY_DEFAULT
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DummyFileSystem;
    impl GFileSystemLike for DummyFileSystem {}

    struct DummyFactory;
    impl GFileSystemFactory<DummyFileSystem> for DummyFactory {}

    struct MyFsInfo;
    impl FileSystemInfo<DummyFileSystem> for MyFsInfo {
        fn fs_type(&self) -> &str {
            "myfs"
        }

        fn factory(&self) -> Box<dyn GFileSystemFactory<DummyFileSystem>> {
            Box::new(DummyFactory)
        }
    }

    struct HighPriorityFsInfo;
    impl FileSystemInfo<DummyFileSystem> for HighPriorityFsInfo {
        fn fs_type(&self) -> &str {
            "hp"
        }

        fn description(&self) -> &str {
            "high priority fs"
        }

        fn factory(&self) -> Box<dyn GFileSystemFactory<DummyFileSystem>> {
            Box::new(DummyFactory)
        }

        fn priority(&self) -> i32 {
            PRIORITY_HIGH
        }
    }

    #[test]
    fn defaults_apply_when_not_overridden() {
        let info = MyFsInfo;
        assert_eq!(info.fs_type(), "myfs");
        assert_eq!(info.description(), "");
        assert_eq!(info.priority(), PRIORITY_DEFAULT);
        let _factory = info.factory();
    }

    #[test]
    fn overrides_are_honored() {
        let info = HighPriorityFsInfo;
        assert_eq!(info.fs_type(), "hp");
        assert_eq!(info.description(), "high priority fs");
        assert_eq!(info.priority(), PRIORITY_HIGH);
    }

    #[test]
    fn boxed_dyn_file_system_info_is_accepted() {
        let info: Box<dyn FileSystemInfo<DummyFileSystem>> = Box::new(MyFsInfo);
        assert_eq!(info.fs_type(), "myfs");
        assert_eq!(info.priority(), PRIORITY_DEFAULT);
    }
}

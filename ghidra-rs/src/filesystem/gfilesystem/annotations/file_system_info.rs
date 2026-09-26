//! Port of the `ghidra.formats.gfilesystem.annotations.FileSystemInfo` annotation.
//!
//! Java attaches `@FileSystemInfo(type, description, priority, factory)` to each `GFileSystem`
//! class and discovers it by reflection. Per the recorded R4 decision (annotation types become
//! a plain metadata struct), each filesystem exposes a `const` [`FileSystemInfo`] and is
//! registered together with its factory in
//! [`FileSystemFactoryMgr`](crate::filesystem::gfilesystem::factory::file_system_factory_mgr::FileSystemFactoryMgr);
//! the annotation's `factory` element becomes the factory instance supplied at registration.

/// Default priority.
pub const PRIORITY_DEFAULT: i32 = 0;
/// High priority.
pub const PRIORITY_HIGH: i32 = 10;
/// Low priority.
pub const PRIORITY_LOW: i32 = -10;
/// Lowest priority.
pub const PRIORITY_LOWEST: i32 = i32::MIN;

/// The metadata Java's `@FileSystemInfo` annotation carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileSystemInfo {
    /// The 'type' of this filesystem, a short (`[a-z0-9]+`) string. Mirrors `type()`.
    pub fs_type: &'static str,
    /// A longer description of this filesystem type. Mirrors `description()` (default `""`).
    pub description: &'static str,
    /// Probe priority, higher first. Mirrors `priority()` (default [`PRIORITY_DEFAULT`]).
    pub priority: i32,
}

impl FileSystemInfo {
    /// Info with the annotation's defaults for `description` and `priority`.
    pub const fn new(fs_type: &'static str) -> Self {
        FileSystemInfo { fs_type, description: "", priority: PRIORITY_DEFAULT }
    }

    /// Info with every element specified.
    pub const fn with(fs_type: &'static str, description: &'static str, priority: i32) -> Self {
        FileSystemInfo { fs_type, description, priority }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_annotation_defaults() {
        const INFO: FileSystemInfo = FileSystemInfo::new("myfs");
        assert_eq!(INFO.fs_type, "myfs");
        assert_eq!(INFO.description, "");
        assert_eq!(INFO.priority, PRIORITY_DEFAULT);
    }

    #[test]
    fn priority_constants_match_java() {
        assert_eq!(PRIORITY_DEFAULT, 0);
        assert_eq!(PRIORITY_HIGH, 10);
        assert_eq!(PRIORITY_LOW, -10);
        assert_eq!(PRIORITY_LOWEST, i32::MIN);
        let hp = FileSystemInfo::with("hp", "high priority fs", PRIORITY_HIGH);
        assert_eq!(hp.priority, 10);
    }
}

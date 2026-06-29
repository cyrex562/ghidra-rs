/// Constants for iOS extended attribute (xattr) names.
///
/// Mirrors `ghidra.file.formats.ios.xattr.XattrConstants`.

/// Extended attribute name for the resource fork.
pub const RESOURCE_XATTR_NAME: &str = "com.apple.ResourceFork";

/// Extended attribute name for the decmpfs compression metadata.
pub const DECMPFS_XATTR_NAME: &str = "com.apple.decmpfs";

/// Extended attribute name for the kernel authorization file security blob.
pub const KAUTH_FILESEC_XATTR_NAME: &str = "com.apple.system.Security";

/// Extended attribute scope name for the kauth process scope.
pub const KAUTH_SCOPE_PROCESS: &str = "com.apple.kauth.process";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_xattr_name_matches_java_source() {
        assert_eq!(RESOURCE_XATTR_NAME, "com.apple.ResourceFork");
    }

    #[test]
    fn decmpfs_xattr_name_matches_java_source() {
        assert_eq!(DECMPFS_XATTR_NAME, "com.apple.decmpfs");
    }

    #[test]
    fn kauth_filesec_xattr_name_matches_java_source() {
        assert_eq!(KAUTH_FILESEC_XATTR_NAME, "com.apple.system.Security");
    }

    #[test]
    fn kauth_scope_process_matches_java_source() {
        assert_eq!(KAUTH_SCOPE_PROCESS, "com.apple.kauth.process");
    }

    #[test]
    fn all_names_are_apple_reverse_dns() {
        for name in [
            RESOURCE_XATTR_NAME,
            DECMPFS_XATTR_NAME,
            KAUTH_FILESEC_XATTR_NAME,
            KAUTH_SCOPE_PROCESS,
        ] {
            assert!(name.starts_with("com.apple."), "{name} should start with com.apple.");
        }
    }
}

/// Constants for extended attribute (xattr) names used by macOS/HFS+.
pub struct XattrConstants;

impl XattrConstants {
    /// Extended attribute name for the resource fork.
    pub const RESOURCE_XATTR_NAME: &'static str = "com.apple.ResourceFork";

    /// Extended attribute name for `decmpfs` compression metadata.
    pub const DECMPFS_XATTR_NAME: &'static str = "com.apple.decmpfs";

    /// Extended attribute name for the kernel authorization file security blob.
    pub const KAUTH_FILESEC_XATTR_NAME: &'static str = "com.apple.system.Security";

    /// Kernel authorization scope identifier for process-level access.
    pub const KAUTH_SCOPE_PROCESS: &'static str = "com.apple.kauth.process";
}

#[cfg(test)]
mod tests {
    use super::XattrConstants;

    #[test]
    fn resource_xattr_name_matches_java_source() {
        assert_eq!(XattrConstants::RESOURCE_XATTR_NAME, "com.apple.ResourceFork");
    }

    #[test]
    fn decmpfs_xattr_name_matches_java_source() {
        assert_eq!(XattrConstants::DECMPFS_XATTR_NAME, "com.apple.decmpfs");
    }

    #[test]
    fn kauth_filesec_xattr_name_matches_java_source() {
        assert_eq!(XattrConstants::KAUTH_FILESEC_XATTR_NAME, "com.apple.system.Security");
    }

    #[test]
    fn kauth_scope_process_matches_java_source() {
        assert_eq!(XattrConstants::KAUTH_SCOPE_PROCESS, "com.apple.kauth.process");
    }
}

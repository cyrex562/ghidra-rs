/// Title string for iOS Prelink.
pub const TITLE: &str = "iOS Prelink";

/// Prelink segment name used on iOS 1.x.
pub const K_PRELINK_SEGMENT_IOS_1X: &str = "__PRELINK";

/// Prelink text segment name.
pub const K_PRELINK_TEXT_SEGMENT: &str = "__PRELINK_TEXT";

/// Prelink text section name.
pub const K_PRELINK_TEXT_SECTION: &str = "__text";

/// Prelink state segment name.
pub const K_PRELINK_STATE_SEGMENT: &str = "__PRELINK_STATE";

/// Prelink kernel link-state section name.
pub const K_PRELINK_KERNEL_LINK_STATE_SECTION: &str = "__kernel";

/// Prelink kexts link-state section name.
pub const K_PRELINK_KEXTS_LINK_STATE_SECTION: &str = "__kexts";

/// Prelink info segment name.
pub const K_PRELINK_INFO_SEGMENT: &str = "__PRELINK_INFO";

/// Prelink info section name.
pub const K_PRELINK_INFO_SECTION: &str = "__info";

/// Prelink bundle-path plist key.
pub const K_PRELINK_BUNDLE_PATH_KEY: &str = "_PrelinkBundlePath";

/// Prelink executable plist key.
pub const K_PRELINK_EXECUTABLE_KEY: &str = "_PrelinkExecutable";

/// Prelink executable load-address plist key.
pub const K_PRELINK_EXECUTABLE_LOAD_KEY: &str = "_PrelinkExecutableLoadAddr";

/// Prelink executable source-address plist key.
pub const K_PRELINK_EXECUTABLE_SOURCE_KEY: &str = "_PrelinkExecutableSourceAddr";

/// Prelink executable size plist key.
pub const K_PRELINK_EXECUTABLE_SIZE_KEY: &str = "_PrelinkExecutableSize";

/// Prelink info-dictionary plist key.
pub const K_PRELINK_INFO_DICTIONARY_KEY: &str = "_PrelinkInfoDictionary";

/// Prelink interface UUID plist key.
pub const K_PRELINK_INTERFACE_UUID_KEY: &str = "_PrelinkInterfaceUUID";

/// Prelink kmod-info plist key.
pub const K_PRELINK_KMOD_INFO_KEY: &str = "_PrelinkKmodInfo";

/// Prelink link-state plist key.
pub const K_PRELINK_LINK_STATE_KEY: &str = "_PrelinkLinkState";

/// Prelink link-state size plist key.
pub const K_PRELINK_LINK_STATE_SIZE_KEY: &str = "_PrelinkLinkStateSize";

/// Prelink personalities plist key.
pub const K_PRELINK_PERSONALITIES_KEY: &str = "_PrelinkPersonalities";

/// Prelink module-index plist key.
pub const K_PRELINK_MODULE_INDEX_KEY: &str = "ModuleIndex";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn title() {
        assert_eq!(TITLE, "iOS Prelink");
    }

    #[test]
    fn segment_names() {
        assert_eq!(K_PRELINK_SEGMENT_IOS_1X, "__PRELINK");
        assert_eq!(K_PRELINK_TEXT_SEGMENT, "__PRELINK_TEXT");
        assert_eq!(K_PRELINK_STATE_SEGMENT, "__PRELINK_STATE");
        assert_eq!(K_PRELINK_INFO_SEGMENT, "__PRELINK_INFO");
    }

    #[test]
    fn section_names() {
        assert_eq!(K_PRELINK_TEXT_SECTION, "__text");
        assert_eq!(K_PRELINK_KERNEL_LINK_STATE_SECTION, "__kernel");
        assert_eq!(K_PRELINK_KEXTS_LINK_STATE_SECTION, "__kexts");
        assert_eq!(K_PRELINK_INFO_SECTION, "__info");
    }

    #[test]
    fn plist_keys() {
        assert_eq!(K_PRELINK_BUNDLE_PATH_KEY, "_PrelinkBundlePath");
        assert_eq!(K_PRELINK_EXECUTABLE_KEY, "_PrelinkExecutable");
        assert_eq!(K_PRELINK_EXECUTABLE_LOAD_KEY, "_PrelinkExecutableLoadAddr");
        assert_eq!(K_PRELINK_EXECUTABLE_SOURCE_KEY, "_PrelinkExecutableSourceAddr");
        assert_eq!(K_PRELINK_EXECUTABLE_SIZE_KEY, "_PrelinkExecutableSize");
        assert_eq!(K_PRELINK_INFO_DICTIONARY_KEY, "_PrelinkInfoDictionary");
        assert_eq!(K_PRELINK_INTERFACE_UUID_KEY, "_PrelinkInterfaceUUID");
        assert_eq!(K_PRELINK_KMOD_INFO_KEY, "_PrelinkKmodInfo");
        assert_eq!(K_PRELINK_LINK_STATE_KEY, "_PrelinkLinkState");
        assert_eq!(K_PRELINK_LINK_STATE_SIZE_KEY, "_PrelinkLinkStateSize");
        assert_eq!(K_PRELINK_PERSONALITIES_KEY, "_PrelinkPersonalities");
        assert_eq!(K_PRELINK_MODULE_INDEX_KEY, "ModuleIndex");
    }
}

/// Support for the "XDG Base Directory Specification"
///
/// Based off version 0.8
///
/// See <https://specifications.freedesktop.org/basedir-spec/basedir-spec-0.8.html>
pub struct XdgUtils;

impl XdgUtils {
    /// $XDG_DATA_HOME defines the base directory relative to which user-specific data files should
    /// be stored. If $XDG_DATA_HOME is either not set or empty, a default equal to
    /// $HOME/.local/share should be used.
    pub const XDG_DATA_HOME: &'static str = "XDG_DATA_HOME";

    /// $XDG_CONFIG_HOME defines the base directory relative to which user-specific configuration
    /// files should be stored. If $XDG_CONFIG_HOME is either not set or empty, a default equal to
    /// $HOME/.config should be used.
    pub const XDG_CONFIG_HOME: &'static str = "XDG_CONFIG_HOME";

    /// $XDG_STATE_HOME defines the base directory relative to which user-specific state files should
    /// be stored. If $XDG_STATE_HOME is either not set or empty, a default equal to
    /// $HOME/.local/state should be used.
    pub const XDG_STATE_HOME: &'static str = "XDG_STATE_HOME";

    /// $XDG_DATA_DIRS defines the preference-ordered set of base directories to search for data
    /// files in addition to the $XDG_DATA_HOME base directory. The directories in $XDG_DATA_DIRS
    /// should be separated with a colon ':'.
    pub const XDG_DATA_DIRS: &'static str = "XDG_DATA_DIRS";

    /// $XDG_CONFIG_DIRS defines the preference-ordered set of base directories to search for
    /// configuration files in addition to the $XDG_CONFIG_HOME base directory. The directories in
    /// $XDG_CONFIG_DIRS should be separated with a colon ':'.
    pub const XDG_CONFIG_DIRS: &'static str = "XDG_CONFIG_DIRS";

    /// $XDG_CACHE_HOME defines the base directory relative to which user-specific non-essential
    /// data files should be stored. If $XDG_CACHE_HOME is either not set or empty, a default equal
    /// to $HOME/.cache should be used.
    pub const XDG_CACHE_HOME: &'static str = "XDG_CACHE_HOME";

    pub const XDG_CACHE_HOME_DEFAULT_SUBDIRNAME: &'static str = ".cache";

    /// $XDG_RUNTIME_DIR defines the base directory relative to which user-specific non-essential
    /// runtime files and other file objects (such as sockets, named pipes, ...) should be stored.
    /// The directory MUST be owned by the user, and he MUST be the only one having read and write
    /// access to it. Its Unix access mode MUST be 0700.
    pub const XDG_RUNTIME_DIR: &'static str = "XDG_RUNTIME_DIR";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xdg_data_home() {
        assert_eq!(XdgUtils::XDG_DATA_HOME, "XDG_DATA_HOME");
    }

    #[test]
    fn test_xdg_config_home() {
        assert_eq!(XdgUtils::XDG_CONFIG_HOME, "XDG_CONFIG_HOME");
    }

    #[test]
    fn test_xdg_state_home() {
        assert_eq!(XdgUtils::XDG_STATE_HOME, "XDG_STATE_HOME");
    }

    #[test]
    fn test_xdg_data_dirs() {
        assert_eq!(XdgUtils::XDG_DATA_DIRS, "XDG_DATA_DIRS");
    }

    #[test]
    fn test_xdg_config_dirs() {
        assert_eq!(XdgUtils::XDG_CONFIG_DIRS, "XDG_CONFIG_DIRS");
    }

    #[test]
    fn test_xdg_cache_home() {
        assert_eq!(XdgUtils::XDG_CACHE_HOME, "XDG_CACHE_HOME");
    }

    #[test]
    fn test_xdg_cache_home_default_subdirname() {
        assert_eq!(
            XdgUtils::XDG_CACHE_HOME_DEFAULT_SUBDIRNAME,
            ".cache"
        );
    }

    #[test]
    fn test_xdg_runtime_dir() {
        assert_eq!(XdgUtils::XDG_RUNTIME_DIR, "XDG_RUNTIME_DIR");
    }
}

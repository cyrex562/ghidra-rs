//! Constants for Ghidra script-related functionality.
//!
//! This module holds constants shared by clients of the script package, without depending on
//! other script package classes to prevent static loading of data.

/// The system property that overrides the location of the source directory used to store
/// Ghidra scripts.
pub const USER_SCRIPTS_DIR_PROPERTY: &str = "ghidra.user.scripts.dir";

/// Default name of new scripts.
pub const DEFAULT_SCRIPT_NAME: &str = "NewScript";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_scripts_dir_property_constant() {
        assert_eq!(USER_SCRIPTS_DIR_PROPERTY, "ghidra.user.scripts.dir");
    }

    #[test]
    fn test_default_script_name_constant() {
        assert_eq!(DEFAULT_SCRIPT_NAME, "NewScript");
    }

    #[test]
    fn test_constants_are_strings() {
        // Ensure constants are accessible and have correct types
        let _dir_prop: &str = USER_SCRIPTS_DIR_PROPERTY;
        let _script_name: &str = DEFAULT_SCRIPT_NAME;
    }
}

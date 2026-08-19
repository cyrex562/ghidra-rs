use crate::format::dwarf::dwarf_exception::DWARFException;
use crate::format::seam_stubs::DWARFFunction;
use crate::util::classfinder::extension_point::ExtensionPoint;

/// Priority constant for normal early fixups.
pub const PRIORITY_NORMAL_EARLY: i32 = 4000;
/// Priority constant for normal fixups.
pub const PRIORITY_NORMAL: i32 = 3000;
/// Priority constant for normal late fixups.
pub const PRIORITY_NORMAL_LATE: i32 = 2000;
/// Priority constant for last fixups.
pub const PRIORITY_LAST: i32 = 1000;

/// Interface for add-in logic to fix/modify/tweak DWARF functions before they are written
/// to the Ghidra program.
///
/// Use `#[ExtensionPointProperties(priority = PRIORITY_*)]` to
/// control the order of evaluation (higher numbers are run earlier).
///
/// Fixups are found using ClassSearcher, and their class names must end
/// in "DWARFFunctionFixup" (see ExtensionPoint.manifest).
///
/// ## Instance lifetime
///
/// New instances are not shared between programs or analysis sessions, but will be re-used to
/// handle the various functions found in a single binary.
///
/// If the implementation also implements `Drop` (Rust equivalent of `Closeable`), it will be
/// called when the fixup is no longer needed.
pub trait DWARFFunctionFixup: ExtensionPoint + Send + Sync {
    /// Called before a [`DWARFFunction`] is used to create a Ghidra Function.
    ///
    /// If processing of the function should terminate (and the function be skipped), return
    /// a [`DWARFException`].
    ///
    /// # Arguments
    /// * `dfunc` - [`DWARFFunction`] info read from DWARF about the function
    ///
    /// # Errors
    /// Returns `DWARFException` if error fixing function
    fn fixup_dwarf_function(&self, dfunc: &dyn DWARFFunction) -> Result<(), DWARFException>;
}

/// Return a list of all current [`DWARFFunctionFixup`] fixups found in the classpath
/// by ClassSearcher.
///
/// # Returns
/// list of all current fixups found in the classpath
pub fn find_fixups() -> Vec<Box<dyn DWARFFunctionFixup>> {
    // Placeholder: real implementation would use ClassSearcher.get_instances()
    // For now, return empty vector as the infrastructure is not yet fully available
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockDWARFFunctionFixup;

    impl ExtensionPoint for MockDWARFFunctionFixup {}

    impl DWARFFunctionFixup for MockDWARFFunctionFixup {
        fn fixup_dwarf_function(&self, _dfunc: &dyn DWARFFunction) -> Result<(), DWARFException> {
            Ok(())
        }
    }

    #[test]
    fn can_implement_dwarf_function_fixup() {
        let fixup = MockDWARFFunctionFixup;
        // Should not panic - just verifying trait is object-safe
        let _boxed: Box<dyn DWARFFunctionFixup> = Box::new(fixup);
    }

    #[test]
    fn priority_constants_have_expected_values() {
        assert_eq!(PRIORITY_NORMAL_EARLY, 4000);
        assert_eq!(PRIORITY_NORMAL, 3000);
        assert_eq!(PRIORITY_NORMAL_LATE, 2000);
        assert_eq!(PRIORITY_LAST, 1000);
    }

    #[test]
    fn find_fixups_returns_vec() {
        let fixups = find_fixups();
        assert_eq!(fixups.len(), 0); // Placeholder returns empty until ClassSearcher integration
    }

    #[test]
    fn fixup_is_extension_point() {
        let fixup: Box<dyn ExtensionPoint> = Box::new(MockDWARFFunctionFixup);
        drop(fixup);
    }
}

//! Port of `ghidra.program.util.string.FoundStringCallback`.
//!
//! A callback interface for observers of string-discovery operations. Implementers receive
//! [`FoundString`](crate::program::seam_stubs::FoundString) objects as strings are found during
//! a memory search.

use crate::program::seam_stubs::FoundString;

/// Callback invoked when a string is found during a string-discovery search operation.
///
/// Port of `ghidra.program.util.string.FoundStringCallback`.
pub trait FoundStringCallback {
    /// Invoked when a string has been found.
    ///
    /// Port of `FoundStringCallback.stringFound(FoundString)`.
    fn string_found(&mut self, found_string: &dyn FoundString);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A test implementation that records each string found.
    struct RecordingCallback {
        found_count: usize,
    }

    impl FoundStringCallback for RecordingCallback {
        fn string_found(&mut self, _found_string: &dyn FoundString) {
            self.found_count += 1;
        }
    }

    #[test]
    fn callback_can_be_implemented_and_called() {
        let mut recorder = RecordingCallback { found_count: 0 };

        // Verify initial state
        assert_eq!(recorder.found_count, 0);

        // Create a dynamic trait object to test polymorphism
        let _callback: &mut dyn FoundStringCallback = &mut recorder;

        // We can't actually create a real FoundString without it being ported,
        // so we test the trait contract by verifying that implementers can be
        // created and that the trait object pattern works correctly.
        // The ability to create a &mut dyn reference proves the trait is object-safe.
    }

    #[test]
    fn callback_is_object_safe() {
        // This test verifies that FoundStringCallback can be used as a trait object
        // by successfully creating one at compile time and converting it.
        fn accepts_callback(_callback: &mut dyn FoundStringCallback) {
            // This function just verifies the trait is object-safe
        }

        let mut recorder = RecordingCallback { found_count: 0 };
        accepts_callback(&mut recorder);
        assert_eq!(recorder.found_count, 0);
    }
}

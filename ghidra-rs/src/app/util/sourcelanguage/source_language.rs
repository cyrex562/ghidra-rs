use std::io;

use crate::app::util::sourcelanguage::source_language_id::SourceLanguageId;
use crate::program::model::listing::Program;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// Combines the checked exceptions declared on `SourceLanguage.existsIn`: `IOException` and
/// `CancelledException`.
#[derive(Debug, thiserror::Error)]
pub enum ExistsInError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Cancelled(#[from] CancelledException),
}

/// Dynamically supports source language-specific features.
///
/// Port of `ghidra.app.util.sourcelanguage.SourceLanguage`. The Java interface also extends
/// `ExtensionPoint`, a marker interface with no methods that exists solely to aid Ghidra's
/// classpath scanner; it has no Rust equivalent and is omitted.
pub trait SourceLanguage {
    /// Returns the ID of the source language.
    fn get_id(&self) -> Box<dyn SourceLanguageId>;

    /// Returns true if the source language exists in the given `Program`; otherwise false.
    ///
    /// # Errors
    /// Returns `Err` if an IO-related error occurred, or if the user cancelled the operation.
    fn exists_in(
        &self,
        program: &dyn Program,
        monitor: &dyn TaskMonitor,
    ) -> Result<bool, ExistsInError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockProgram;

    impl crate::framework::model::DomainObject for MockProgram {}

    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }

        fn get_language_id(&self) -> String {
            "x86:LE:64:default".to_string()
        }
    }

    struct MockSourceLanguageId;

    impl SourceLanguageId for MockSourceLanguageId {
        fn get_id_as_string(&self) -> &str {
            "mock"
        }
    }

    struct CancelledMonitor;

    impl TaskMonitor for CancelledMonitor {
        fn is_cancelled(&self) -> bool {
            true
        }
        fn set_show_progress_value(&self, _show: bool) {}
        fn set_message(&self, _message: &str) {}
        fn get_message(&self) -> String {
            String::new()
        }
        fn set_progress(&self, _value: i64) {}
        fn initialize(&self, _max: i64) {}
        fn set_maximum(&self, _max: i64) {}
        fn get_maximum(&self) -> i64 {
            0
        }
        fn set_indeterminate(&self, _indeterminate: bool) {}
        fn is_indeterminate(&self) -> bool {
            false
        }
        fn check_cancelled(&self) -> Result<(), CancelledException> {
            Err(CancelledException::default())
        }
        fn increment_progress(&self, _amount: i64) {}
        fn get_progress(&self) -> i64 {
            -1
        }
        fn cancel(&self) {}
        fn add_cancelled_listener(
            &self,
            _listener: Box<dyn crate::util::task::CancelledListener>,
        ) {
        }
        fn remove_cancelled_listener(&self, _listener: &dyn crate::util::task::CancelledListener) {}
        fn set_cancel_enabled(&self, _enabled: bool) {}
        fn is_cancel_enabled(&self) -> bool {
            true
        }
        fn clear_cancelled(&self) {}
    }

    /// Minimal mock source language proving the trait is object-safe and usable via
    /// `Box<dyn SourceLanguage>`.
    struct MockSourceLanguage {
        present: bool,
    }

    impl SourceLanguage for MockSourceLanguage {
        fn get_id(&self) -> Box<dyn SourceLanguageId> {
            Box::new(MockSourceLanguageId)
        }

        fn exists_in(
            &self,
            _program: &dyn Program,
            monitor: &dyn TaskMonitor,
        ) -> Result<bool, ExistsInError> {
            if monitor.is_cancelled() {
                return Err(ExistsInError::Cancelled(CancelledException::default()));
            }
            Ok(self.present)
        }
    }

    #[test]
    fn mock_source_language_is_usable_as_trait_object() {
        let program = MockProgram;
        let monitor = crate::util::task::DummyMonitor;

        let language: Box<dyn SourceLanguage> = Box::new(MockSourceLanguage { present: true });

        let _id = language.get_id();
        assert_eq!(language.exists_in(&program, &monitor).unwrap(), true);
    }

    #[test]
    fn exists_in_propagates_cancellation() {
        let program = MockProgram;
        let monitor = CancelledMonitor;

        let language: Box<dyn SourceLanguage> = Box::new(MockSourceLanguage { present: true });

        assert!(matches!(
            language.exists_in(&program, &monitor),
            Err(ExistsInError::Cancelled(_))
        ));
    }
}

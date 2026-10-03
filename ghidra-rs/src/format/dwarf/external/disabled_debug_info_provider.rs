use crate::format::dwarf::external::debug_info_provider::DebugInfoProvider;
use crate::format::dwarf::external::debug_info_provider_creator_context::DebugInfoProviderCreatorContext;
use crate::format::dwarf::external::debug_info_provider_status::DebugInfoProviderStatus;
use crate::util::task::TaskMonitor;

/// Wrapper around a [`DebugInfoProvider`] that prevents it from being queried, but retains it in
/// the configuration list.
///
/// Mirrors `ghidra.app.util.bin.format.dwarf.external.DisabledDebugInfoProvider`.
pub struct DisabledDebugInfoProvider {
    delegate: Box<dyn DebugInfoProvider>,
}

impl DisabledDebugInfoProvider {
    /// Mirrors `DisabledDebugInfoProvider.DISABLED_PREFIX`.
    pub const DISABLED_PREFIX: &'static str = "disabled://";

    /// Predicate that tests if the name string is an instance of a disabled name.
    ///
    /// Mirrors `DisabledDebugInfoProvider.matches(String)`.
    pub fn matches(name: &str) -> bool {
        name.starts_with(Self::DISABLED_PREFIX)
    }

    /// Factory method to create new instances from a name string.
    ///
    /// `name` should previously have been returned by [`DebugInfoProvider::get_name`] on a
    /// `DisabledDebugInfoProvider` instance. `context` is used to access the
    /// [`DebugInfoProviderRegistry`](crate::format::seam_stubs::DebugInfoProviderRegistry) that
    /// can create the un-prefixed delegate provider.
    ///
    /// Mirrors `DisabledDebugInfoProvider.create(String, DebugInfoProviderCreatorContext)`.
    /// Returns `None` if the registry could not create a delegate for the un-prefixed name (e.g.
    /// because it does not match any registered provider).
    ///
    /// # Panics
    /// Mirrors Java's `name.substring(DISABLED_PREFIX.length())`, which throws
    /// `StringIndexOutOfBoundsException` if `name` is shorter than [`Self::DISABLED_PREFIX`]:
    /// this panics on byte-index slicing in that same case. Neither the Java method nor this port
    /// validates `name` with [`Self::matches`] first -- both rely on the documented precondition
    /// that `name` was earlier produced by [`DebugInfoProvider::get_name`], which always carries
    /// the prefix.
    pub fn create(
        name: &str,
        context: &DebugInfoProviderCreatorContext,
    ) -> Option<Box<dyn DebugInfoProvider>> {
        let delegate_name = &name[Self::DISABLED_PREFIX.len()..];
        let delegate = context.registry.create(delegate_name, context)?;
        Some(Box::new(DisabledDebugInfoProvider::new(delegate)))
    }

    /// Mirrors `DisabledDebugInfoProvider(DebugInfoProvider)`.
    pub fn new(delegate: Box<dyn DebugInfoProvider>) -> Self {
        DisabledDebugInfoProvider { delegate }
    }

    /// Mirrors `DisabledDebugInfoProvider.getDelegate()`.
    pub fn get_delegate(&self) -> &dyn DebugInfoProvider {
        self.delegate.as_ref()
    }
}

impl DebugInfoProvider for DisabledDebugInfoProvider {
    /// Mirrors `DisabledDebugInfoProvider.getName()`.
    fn get_name(&self) -> String {
        format!("{}{}", Self::DISABLED_PREFIX, self.delegate.get_name())
    }

    /// Mirrors `DisabledDebugInfoProvider.getDescriptiveName()`.
    fn get_descriptive_name(&self) -> String {
        format!("Disabled - {}", self.delegate.get_descriptive_name())
    }

    /// Mirrors `DisabledDebugInfoProvider.getStatus(TaskMonitor)`, which always reports
    /// [`DebugInfoProviderStatus::Unknown`] regardless of the delegate's actual status --
    /// deliberately, since a disabled provider should not be probed.
    fn get_status(&self, _monitor: &dyn TaskMonitor) -> DebugInfoProviderStatus {
        DebugInfoProviderStatus::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::seam_stubs::DebugInfoProviderRegistry;
    use crate::program::model::listing::Program;
    use std::sync::Arc;

    struct MockProvider {
        name: String,
        descriptive_name: String,
    }

    impl DebugInfoProvider for MockProvider {
        fn get_name(&self) -> String {
            self.name.clone()
        }
        fn get_descriptive_name(&self) -> String {
            self.descriptive_name.clone()
        }
        fn get_status(&self, _monitor: &dyn TaskMonitor) -> DebugInfoProviderStatus {
            DebugInfoProviderStatus::Valid
        }
    }

    struct MockRegistry;

    impl DebugInfoProviderRegistry for MockRegistry {
        fn get_instance(&self) -> Box<dyn DebugInfoProviderRegistry> {
            Box::new(MockRegistry)
        }

        fn register(&self, _test_func: &dyn std::any::Any, _create_func: &dyn std::any::Any) {}

        fn new_context(&self, _program: &dyn Program) -> Box<dyn std::any::Any> {
            Box::new(())
        }

        fn create(
            &self,
            name: &str,
            _context: &dyn std::any::Any,
        ) -> Option<Box<dyn DebugInfoProvider>> {
            if name == "unknown://nope" {
                return None;
            }
            Some(Box::new(MockProvider {
                name: name.to_string(),
                descriptive_name: format!("Descriptive({name})"),
            }))
        }
    }

    struct MockProgram;

    impl crate::framework::model::DomainObject for MockProgram {}

    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "test_program".to_string()
        }
        fn get_language_id(&self) -> String {
            "x86".to_string()
        }
    }

    fn test_context() -> DebugInfoProviderCreatorContext {
        DebugInfoProviderCreatorContext::new(Arc::new(MockRegistry), Arc::new(MockProgram))
    }

    #[test]
    fn matches_recognizes_disabled_prefix() {
        assert!(DisabledDebugInfoProvider::matches("disabled://foo://bar"));
        assert!(!DisabledDebugInfoProvider::matches("foo://bar"));
        assert!(!DisabledDebugInfoProvider::matches(""));
    }

    #[test]
    fn get_name_prepends_disabled_prefix_to_delegate_name() {
        let delegate = Box::new(MockProvider {
            name: "foo://bar".to_string(),
            descriptive_name: "Foo Provider".to_string(),
        });
        let provider = DisabledDebugInfoProvider::new(delegate);

        assert_eq!(provider.get_name(), "disabled://foo://bar");
        assert!(DisabledDebugInfoProvider::matches(&provider.get_name()));
    }

    #[test]
    fn get_descriptive_name_prefixes_with_disabled_dash() {
        let delegate = Box::new(MockProvider {
            name: "foo://bar".to_string(),
            descriptive_name: "Foo Provider".to_string(),
        });
        let provider = DisabledDebugInfoProvider::new(delegate);

        assert_eq!(provider.get_descriptive_name(), "Disabled - Foo Provider");
    }

    #[test]
    fn get_status_always_reports_unknown_even_if_delegate_is_valid() {
        let delegate = Box::new(MockProvider {
            name: "foo://bar".to_string(),
            descriptive_name: "Foo".to_string(),
        });
        let provider = DisabledDebugInfoProvider::new(delegate);

        struct NoOpMonitor;
        impl TaskMonitor for NoOpMonitor {
            fn is_cancelled(&self) -> bool {
                false
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
            fn check_cancelled(&self) -> Result<(), crate::util::exception::CancelledException> {
                Ok(())
            }
            fn increment_progress(&self, _amount: i64) {}
            fn get_progress(&self) -> i64 {
                0
            }
            fn cancel(&self) {}
            fn add_cancelled_listener(
                &self,
                _listener: Box<dyn crate::util::task::CancelledListener>,
            ) {
            }
            fn remove_cancelled_listener(
                &self,
                _listener: &dyn crate::util::task::CancelledListener,
            ) {
            }
            fn set_cancel_enabled(&self, _enabled: bool) {}
            fn is_cancel_enabled(&self) -> bool {
                false
            }
            fn clear_cancelled(&self) {}
        }

        assert_eq!(provider.get_status(&NoOpMonitor), DebugInfoProviderStatus::Unknown);
    }

    #[test]
    fn get_delegate_returns_wrapped_provider() {
        let delegate = Box::new(MockProvider {
            name: "foo://bar".to_string(),
            descriptive_name: "Foo".to_string(),
        });
        let provider = DisabledDebugInfoProvider::new(delegate);

        assert_eq!(provider.get_delegate().get_name(), "foo://bar");
    }

    #[test]
    fn create_builds_disabled_wrapper_around_registry_delegate() {
        let context = test_context();
        let provider = DisabledDebugInfoProvider::create("disabled://foo://bar", &context)
            .expect("registry should create a delegate for a non-'unknown' name");

        assert_eq!(provider.get_name(), "disabled://foo://bar");
        assert_eq!(provider.get_descriptive_name(), "Disabled - Descriptive(foo://bar)");
    }

    #[test]
    fn create_returns_none_when_registry_cannot_create_delegate() {
        let context = test_context();
        let provider = DisabledDebugInfoProvider::create("disabled://unknown://nope", &context);
        assert!(provider.is_none());
    }

    #[test]
    #[should_panic]
    fn create_panics_on_name_without_disabled_prefix() {
        // Mirrors `String.substring(int)` throwing `StringIndexOutOfBoundsException` in Java when
        // `name` is shorter than `DISABLED_PREFIX`: neither implementation validates the
        // precondition that `name` carries the prefix before slicing it off.
        let context = test_context();
        let _ = DisabledDebugInfoProvider::create("short", &context);
    }
}

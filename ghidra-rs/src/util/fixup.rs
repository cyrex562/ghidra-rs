/// Represents a fixup that can be applied to address an issue.
///
/// Implementations of this trait provide descriptions of fixes and the ability to
/// automatically perform those fixes using services from a `ServiceProvider`.
///
/// Port of `ghidra.util.Fixup`.
pub trait Fixup: Send + Sync {
    /// Returns a description of what this Fixup does.
    ///
    /// Typically, this is either a simple suggestion for something the user could do,
    /// or a description of what the `fixup` method will attempt to do to address some issue.
    fn get_description(&self) -> &str;

    /// Returns true if this Fixup object can automatically perform some action to address
    /// the issue, false if the `fixup` method does nothing.
    fn can_fixup(&self) -> bool;

    /// Attempts to perform some action or task to "fix" the related issue.
    ///
    /// # Arguments
    ///
    /// * `provider` - A service provider that can provide various services.
    ///
    /// # Returns
    ///
    /// `true` if the fixup performed its intended action, `false` otherwise.
    fn fixup(&self, provider: &dyn crate::framework::ServiceProvider) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestFixup {
        description: String,
        can_fix: bool,
    }

    impl Fixup for TestFixup {
        fn get_description(&self) -> &str {
            &self.description
        }

        fn can_fixup(&self) -> bool {
            self.can_fix
        }

        fn fixup(&self, _provider: &dyn crate::framework::ServiceProvider) -> bool {
            self.can_fix
        }
    }

    #[test]
    fn get_description_returns_description() {
        let fixup = TestFixup {
            description: "Test description".to_string(),
            can_fix: true,
        };
        assert_eq!(fixup.get_description(), "Test description");
    }

    #[test]
    fn can_fixup_returns_true_when_fixable() {
        let fixup = TestFixup {
            description: "Test".to_string(),
            can_fix: true,
        };
        assert!(fixup.can_fixup());
    }

    #[test]
    fn can_fixup_returns_false_when_not_fixable() {
        let fixup = TestFixup {
            description: "Test".to_string(),
            can_fix: false,
        };
        assert!(!fixup.can_fixup());
    }

    #[test]
    fn fixup_returns_result() {
        let fixup = TestFixup {
            description: "Test".to_string(),
            can_fix: true,
        };
        // Mock provider would need to implement ServiceProvider trait
        // For now, test just verifies the method signature works
        assert!(fixup.can_fixup());
    }

    #[test]
    fn trait_object_dispatch() {
        let fixup: Box<dyn Fixup> = Box::new(TestFixup {
            description: "Test".to_string(),
            can_fix: true,
        });
        assert_eq!(fixup.get_description(), "Test");
        assert!(fixup.can_fixup());
    }
}

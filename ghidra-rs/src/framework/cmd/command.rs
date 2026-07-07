use crate::framework::model::DomainObject;

/// Interface to define a change made to a domain object.
///
/// A `Command<T>` encapsulates a single operation that can be applied to a domain object
/// of type `T`. The command can either succeed or fail, providing status information
/// about the outcome.
///
/// # Generic Parameters
///
/// * `T` - A type implementing `DomainObject` that this command operates on.
pub trait Command<T: DomainObject + ?Sized> {
    /// Applies the command to the given domain object.
    ///
    /// # Arguments
    ///
    /// * `obj` - The domain object to apply this command to.
    ///
    /// # Returns
    ///
    /// `true` if the command applied successfully, `false` otherwise.
    fn apply_to(&mut self, obj: &mut T) -> bool;

    /// Returns the status message indicating the status of the command.
    ///
    /// # Returns
    ///
    /// A status message describing why the command failed, or `None` if the command
    /// was successful.
    fn status_msg(&self) -> Option<String>;

    /// Returns the name of this command.
    ///
    /// # Returns
    ///
    /// The name of this command.
    fn name(&self) -> String;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct MockDomainObject {
        changed: bool,
    }

    impl DomainObject for MockDomainObject {
        fn is_changed(&self) -> bool {
            self.changed
        }
    }

    struct SuccessfulCommand {
        name: String,
    }

    impl Command<MockDomainObject> for SuccessfulCommand {
        fn apply_to(&mut self, obj: &mut MockDomainObject) -> bool {
            obj.changed = true;
            true
        }

        fn status_msg(&self) -> Option<String> {
            None
        }

        fn name(&self) -> String {
            self.name.clone()
        }
    }

    struct FailingCommand {
        name: String,
        error: String,
    }

    impl Command<MockDomainObject> for FailingCommand {
        fn apply_to(&mut self, _obj: &mut MockDomainObject) -> bool {
            false
        }

        fn status_msg(&self) -> Option<String> {
            Some(self.error.clone())
        }

        fn name(&self) -> String {
            self.name.clone()
        }
    }

    #[test]
    fn test_successful_command_apply() {
        let mut cmd = SuccessfulCommand {
            name: "test_cmd".to_string(),
        };
        let mut obj = MockDomainObject { changed: false };

        assert!(!obj.is_changed());
        assert!(cmd.apply_to(&mut obj));
        assert!(obj.is_changed());
    }

    #[test]
    fn test_successful_command_status() {
        let cmd = SuccessfulCommand {
            name: "test_cmd".to_string(),
        };
        assert_eq!(cmd.status_msg(), None);
    }

    #[test]
    fn test_successful_command_name() {
        let cmd = SuccessfulCommand {
            name: "my_command".to_string(),
        };
        assert_eq!(cmd.name(), "my_command");
    }

    #[test]
    fn test_failing_command_apply() {
        let mut cmd = FailingCommand {
            name: "fail_cmd".to_string(),
            error: "Operation failed".to_string(),
        };
        let mut obj = MockDomainObject { changed: false };

        assert!(!cmd.apply_to(&mut obj));
        assert!(!obj.is_changed());
    }

    #[test]
    fn test_failing_command_status() {
        let cmd = FailingCommand {
            name: "fail_cmd".to_string(),
            error: "Operation failed".to_string(),
        };
        assert_eq!(cmd.status_msg(), Some("Operation failed".to_string()));
    }

    #[test]
    fn test_failing_command_name() {
        let cmd = FailingCommand {
            name: "fail_cmd".to_string(),
            error: "Operation failed".to_string(),
        };
        assert_eq!(cmd.name(), "fail_cmd");
    }

    #[test]
    fn test_command_chain() {
        let mut cmd1 = SuccessfulCommand {
            name: "cmd1".to_string(),
        };
        let mut cmd2 = SuccessfulCommand {
            name: "cmd2".to_string(),
        };
        let mut obj = MockDomainObject { changed: false };

        assert!(cmd1.apply_to(&mut obj));
        assert!(obj.is_changed());

        obj.changed = false;
        assert!(cmd2.apply_to(&mut obj));
        assert!(obj.is_changed());
    }
}

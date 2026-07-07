use crate::framework::cmd::command::Command;
use crate::framework::model::DomainObject;

/// Implementation for multiple commands that are done as a unit.
///
/// Multiple commands may be added to this one so that multiple changes can be applied to the
/// domain object as unit.
///
/// Port of `ghidra.framework.cmd.CompoundCmd`.
pub struct CompoundCmd<T: DomainObject + ?Sized> {
    cmds: Vec<Box<dyn Command<T>>>,
    status_msg: Option<String>,
    name: String,
}

impl<T: DomainObject + ?Sized> CompoundCmd<T> {
    /// Constructor for `CompoundCmd`.
    ///
    /// # Arguments
    ///
    /// * `name` - the name of the command
    pub fn new(name: impl Into<String>) -> Self {
        CompoundCmd {
            cmds: Vec::new(),
            status_msg: None,
            name: name.into(),
        }
    }

    /// Add the given command to this command.
    pub fn add(&mut self, cmd: Box<dyn Command<T>>) {
        self.cmds.push(cmd);
    }

    /// Return the number of commands that are part of this compound command.
    ///
    /// # Returns
    ///
    /// the number of commands that have been added to this one.
    pub fn size(&self) -> usize {
        self.cmds.len()
    }

    /// Returns the commands in this compound command.
    pub fn commands(&self) -> &[Box<dyn Command<T>>] {
        &self.cmds
    }
}

impl<T: DomainObject + ?Sized> Command<T> for CompoundCmd<T> {
    fn apply_to(&mut self, obj: &mut T) -> bool {
        for cmd in &mut self.cmds {
            if !cmd.apply_to(obj) {
                self.status_msg = cmd.status_msg();
                return false;
            }
        }
        true
    }

    fn status_msg(&self) -> Option<String> {
        self.status_msg.clone()
    }

    fn name(&self) -> String {
        self.name.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockDomainObject {
        changed: bool,
    }

    impl DomainObject for MockDomainObject {
        fn is_changed(&self) -> bool {
            self.changed
        }
    }

    struct SuccessfulCommand;

    impl Command<MockDomainObject> for SuccessfulCommand {
        fn apply_to(&mut self, obj: &mut MockDomainObject) -> bool {
            obj.changed = true;
            true
        }

        fn status_msg(&self) -> Option<String> {
            None
        }

        fn name(&self) -> String {
            "successful".to_string()
        }
    }

    struct FailingCommand {
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
            "failing".to_string()
        }
    }

    #[test]
    fn new_starts_empty() {
        let cmd: CompoundCmd<MockDomainObject> = CompoundCmd::new("my_compound");
        assert_eq!(cmd.size(), 0);
        assert_eq!(cmd.name(), "my_compound");
        assert_eq!(cmd.status_msg(), None);
    }

    #[test]
    fn add_increases_size() {
        let mut cmd: CompoundCmd<MockDomainObject> = CompoundCmd::new("my_compound");
        cmd.add(Box::new(SuccessfulCommand));
        cmd.add(Box::new(SuccessfulCommand));
        assert_eq!(cmd.size(), 2);
        assert_eq!(cmd.commands().len(), 2);
    }

    #[test]
    fn apply_to_runs_all_successful_commands() {
        let mut cmd: CompoundCmd<MockDomainObject> = CompoundCmd::new("my_compound");
        cmd.add(Box::new(SuccessfulCommand));
        cmd.add(Box::new(SuccessfulCommand));
        let mut obj = MockDomainObject { changed: false };

        assert!(cmd.apply_to(&mut obj));
        assert!(obj.is_changed());
        assert_eq!(cmd.status_msg(), None);
    }

    #[test]
    fn apply_to_stops_at_first_failure() {
        let mut cmd: CompoundCmd<MockDomainObject> = CompoundCmd::new("my_compound");
        cmd.add(Box::new(SuccessfulCommand));
        cmd.add(Box::new(FailingCommand {
            error: "boom".to_string(),
        }));
        cmd.add(Box::new(SuccessfulCommand));
        let mut obj = MockDomainObject { changed: false };

        assert!(!cmd.apply_to(&mut obj));
        assert_eq!(cmd.status_msg(), Some("boom".to_string()));
    }
}

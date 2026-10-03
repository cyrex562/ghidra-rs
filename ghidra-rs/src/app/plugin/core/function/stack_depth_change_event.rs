//! Port of `ghidra.app.plugin.core.function.StackDepthChangeEvent`.

/// Event id meaning the stack depth change at an address is being removed.
pub const REMOVE_STACK_DEPTH_CHANGE: i32 = 0;
/// Event id meaning the stack depth change at an address is being set or updated.
pub const UPDATE_STACK_DEPTH_CHANGE: i32 = 1;

/// Event describing a user edit of the stack depth change recorded at an instruction.
///
/// Port of `ghidra.app.plugin.core.function.StackDepthChangeEvent`. The Java class extends
/// `java.awt.event.ActionEvent` purely to reuse its `(source, id, command)` triple; the id and
/// command are kept here as plain fields. The AWT `source` object (an untyped `Object` naming the
/// Swing component that fired the event) has no meaning outside Swing and is not carried.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StackDepthChangeEvent {
    /// Event id: [`REMOVE_STACK_DEPTH_CHANGE`] or [`UPDATE_STACK_DEPTH_CHANGE`] (Java
    /// `ActionEvent.getID()`).
    pub id: i32,
    /// Command string associated with the event (Java `ActionEvent.getActionCommand()`).
    pub command: String,
    stack_depth_change: i32,
}

impl StackDepthChangeEvent {
    /// Creates an event with the given id, command and new stack depth change.
    pub fn new(id: i32, command: impl Into<String>, stack_depth_change: i32) -> Self {
        Self { id, command: command.into(), stack_depth_change }
    }

    /// The stack depth change value carried by this event.
    pub fn get_stack_depth_change(&self) -> i32 {
        self.stack_depth_change
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_match_java() {
        assert_eq!(REMOVE_STACK_DEPTH_CHANGE, 0);
        assert_eq!(UPDATE_STACK_DEPTH_CHANGE, 1);
    }

    #[test]
    fn carries_id_command_and_depth_change() {
        let e = StackDepthChangeEvent::new(UPDATE_STACK_DEPTH_CHANGE, "update", -8);
        assert_eq!(e.id, UPDATE_STACK_DEPTH_CHANGE);
        assert_eq!(e.command, "update");
        assert_eq!(e.get_stack_depth_change(), -8);
    }
}

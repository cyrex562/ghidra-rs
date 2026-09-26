//! Port of `ghidra.app.plugin.core.function.StackDepthChangeListener`.

use super::stack_depth_change_event::StackDepthChangeEvent;

/// Listener notified when the user changes (or removes) a stack depth change value.
///
/// Port of `ghidra.app.plugin.core.function.StackDepthChangeListener` (a
/// `java.util.EventListener`).
pub trait StackDepthChangeListener {
    /// Invoked when an action occurs.
    fn action_performed(&self, e: &StackDepthChangeEvent);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::plugin::core::function::stack_depth_change_event::{
        REMOVE_STACK_DEPTH_CHANGE, UPDATE_STACK_DEPTH_CHANGE,
    };
    use std::cell::RefCell;

    /// Tracks the stack depth change applied at one address, as the function plugin does.
    #[derive(Default)]
    struct DepthTracker {
        current: RefCell<Option<i32>>,
    }

    impl StackDepthChangeListener for DepthTracker {
        fn action_performed(&self, e: &StackDepthChangeEvent) {
            let mut cur = self.current.borrow_mut();
            match e.id {
                UPDATE_STACK_DEPTH_CHANGE => *cur = Some(e.get_stack_depth_change()),
                REMOVE_STACK_DEPTH_CHANGE => *cur = None,
                _ => {}
            }
        }
    }

    #[test]
    fn update_then_remove() {
        let t = DepthTracker::default();
        let listeners: Vec<&dyn StackDepthChangeListener> = vec![&t];
        for l in &listeners {
            l.action_performed(&StackDepthChangeEvent::new(UPDATE_STACK_DEPTH_CHANGE, "", 16));
        }
        assert_eq!(*t.current.borrow(), Some(16));
        for l in &listeners {
            l.action_performed(&StackDepthChangeEvent::new(REMOVE_STACK_DEPTH_CHANGE, "", 0));
        }
        assert_eq!(*t.current.borrow(), None);
    }
}

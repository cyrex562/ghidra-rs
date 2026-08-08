use crate::program::model::address::AddressSetView;
use crate::trace::seam_stubs::{TraceStack, TraceStackFrame, TraceThread};

/// Manages the stacks of threads observed over time in a trace.
///
/// Port of `ghidra.trace.model.stack.TraceStackManager`.
pub trait TraceStackManager {
    /// Get the stack of a given thread at a given snap.
    ///
    /// # Arguments
    /// * `thread` - the thread
    /// * `snap` - the snap
    /// * `create_if_absent` - create a new (empty) stack if it doesn't already exist
    ///
    /// Returns the stack, or `None` if absent and not created.
    fn get_stack(
        &self,
        thread: &dyn TraceThread,
        snap: i64,
        create_if_absent: bool,
    ) -> Option<Box<dyn TraceStack>>;

    /// Get the most recent stack of a given thread since a given snap.
    ///
    /// Returns the stack, or `None`.
    fn get_latest_stack(&self, thread: &dyn TraceThread, snap: i64) -> Option<Box<dyn TraceStack>>;

    /// Get the frames whose program counters are within a given address set.
    fn get_frames_in(&self, set: &dyn AddressSetView) -> Vec<Box<dyn TraceStackFrame>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSet, AddressSpace, AddressSpaceType};
    use std::sync::Mutex;

    struct MockThread(&'static str);
    impl TraceThread for MockThread {}

    struct MockFrame(i32);
    impl TraceStackFrame for MockFrame {}

    struct MockStack(i32);
    impl TraceStack for MockStack {}

    struct MockStackManager {
        stacks: Mutex<Vec<(&'static str, i64, i32)>>,
    }

    impl TraceStackManager for MockStackManager {
        fn get_stack(
            &self,
            thread: &dyn TraceThread,
            snap: i64,
            create_if_absent: bool,
        ) -> Option<Box<dyn TraceStack>> {
            let _ = thread;
            let mut stacks = self.stacks.lock().unwrap();
            if let Some((_, _, id)) = stacks.iter().find(|(t, s, _)| *t == "t1" && *s == snap) {
                return Some(Box::new(MockStack(*id)));
            }
            if create_if_absent {
                let id = stacks.len() as i32;
                stacks.push(("t1", snap, id));
                return Some(Box::new(MockStack(id)));
            }
            None
        }

        fn get_latest_stack(
            &self,
            thread: &dyn TraceThread,
            snap: i64,
        ) -> Option<Box<dyn TraceStack>> {
            let _ = thread;
            let stacks = self.stacks.lock().unwrap();
            stacks
                .iter()
                .filter(|(t, s, _)| *t == "t1" && *s <= snap)
                .max_by_key(|(_, s, _)| *s)
                .map(|(_, _, id)| Box::new(MockStack(*id)) as Box<dyn TraceStack>)
        }

        fn get_frames_in(&self, set: &dyn AddressSetView) -> Vec<Box<dyn TraceStackFrame>> {
            if set.is_empty() {
                Vec::new()
            } else {
                vec![Box::new(MockFrame(0))]
            }
        }
    }

    #[test]
    fn usable_as_trait_object_and_tracks_stacks() {
        let manager: Box<dyn TraceStackManager> = Box::new(MockStackManager {
            stacks: Mutex::new(Vec::new()),
        });
        let thread = MockThread("t1");

        assert!(manager.get_stack(&thread, 0, false).is_none());
        assert!(manager.get_stack(&thread, 0, true).is_some());
        assert!(manager.get_stack(&thread, 0, false).is_some());

        manager.get_stack(&thread, 5, true);
        let latest = manager.get_latest_stack(&thread, 100);
        assert!(latest.is_some());
        assert!(manager.get_latest_stack(&thread, -1).is_none());
    }

    #[test]
    fn get_frames_in_reflects_address_set_emptiness() {
        let manager = MockStackManager {
            stacks: Mutex::new(Vec::new()),
        };
        let empty = AddressSet::new();
        assert!(manager.get_frames_in(&empty).is_empty());

        let space = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 0);
        let mut non_empty = AddressSet::new();
        non_empty.add_range(&space.address(0x1000), &space.address(0x1010));
        assert_eq!(manager.get_frames_in(&non_empty).len(), 1);
    }
}

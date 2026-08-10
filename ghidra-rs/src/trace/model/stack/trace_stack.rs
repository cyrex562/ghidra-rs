//! A trace of the connected debugger's stack unwind.
//!
//! Port of `ghidra.trace.model.stack.TraceStack`.
//!
//! Most of the information stored here is ancillary, since with sufficient analysis of
//! associated images, it could be recovered, in the same fashion as the connected debugger did.
//! Nevertheless, during a debug session, this information should be recorded if offered, as it
//! makes it immediately accessible, before sufficient analysis has been performed, and provides
//! some check for that analysis. If this information wasn't recorded during a session, this can
//! store the result of that analysis.
//!
//! Conventionally, if the debugger can also unwind register values, then each frame should
//! present a register bank. Otherwise, the same object presenting this stack should present the
//! register bank (see `TraceMemoryManager::get_memory_register_space`, not yet ported).

use crate::trace::model::stack::trace_stack_frame::TraceStackFrame;
use crate::trace::model::target::iface::TraceObjectInterface;
use crate::trace::model::target::info::trace_object_info::TraceObjectInfo;
use crate::trace::model::trace_unique_object::TraceUniqueObject;
use crate::trace::model::thread::TraceThread;

/// A trace of the connected debugger's stack unwind.
pub trait TraceStack: TraceUniqueObject + TraceObjectInterface {
    /// Returns the `@TraceObjectInfo` metadata mirrored from the Java annotation on `TraceStack`.
    fn trace_object_info() -> TraceObjectInfo
    where
        Self: Sized,
    {
        TraceObjectInfo::new("Stack", "stack", [] as [&str; 0], [] as [&str; 0])
    }

    /// Get the thread whose stack this is.
    fn get_thread(&self) -> Box<dyn TraceThread>;

    /// Get the depth (as recorded) of this stack at the given snap.
    fn get_depth(&self, snap: i64) -> i32;

    /// Set the depth of the stack by adding or deleting frames to or from the specified end.
    ///
    /// Note that pushing new frames onto a stack does not adjust the frame level of any
    /// frame-associated managers or spaces, e.g., that returned by
    /// `TraceMemoryManager::get_memory_register_space` (not yet ported).
    ///
    /// If the experimental object mode is successful, this method should be deleted.
    ///
    /// `at_inner`: true if frames should be "pushed".
    fn set_depth(&mut self, snap: i64, depth: i32, at_inner: bool);

    /// Get the frame at the given level.
    ///
    /// `level`: 0 indicates the inner-most frame. `ensure_depth`: true to expand the depth to
    /// accommodate the requested frame. Returns `None` if `level` exceeds the depth without
    /// `ensure_depth` set.
    ///
    /// # Panics
    /// If `level` is negative.
    fn get_frame(&self, snap: i64, level: i32, ensure_depth: bool) -> Option<Box<dyn TraceStackFrame>>;

    /// Get all (known) frames in this stack.
    ///
    /// The snap is only relevant in the experimental objects mode. Ordinarily, the frames are
    /// fixed over the stack's lifetime.
    fn get_frames(&self, snap: i64) -> Vec<Box<dyn TraceStackFrame>>;

    /// Delete this stack and its frames.
    fn delete(&mut self);

    /// Remove this stack and its frames from the given snapshot on.
    fn remove(&mut self, snap: i64);

    /// Check if this stack is valid at the given snap.
    fn is_valid(&self, snap: i64) -> bool;

    /// Check if this stack's frames are fixed for its lifetime.
    ///
    /// This is a transitional method, since the experimental objects mode breaks with the normal
    /// stack/frame model. Essentially, this returns true if the normal model is being used, and
    /// false if the object-based model is being used.
    fn has_fixed_frames(&self) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::model::target::trace_object::TraceObject;
    use crate::trace::seam_stubs::ObjectKey;
    use std::sync::Mutex;

    struct MockKey(i32);
    impl ObjectKey for MockKey {
        fn equals(&self, obj: &dyn std::any::Any) -> bool {
            obj.downcast_ref::<MockKey>().is_some_and(|o| o.0 == self.0)
        }
        fn hash_code(&self) -> i32 {
            self.0
        }
        fn compare_to(&self, that: &dyn ObjectKey) -> i32 {
            self.hash_code() - that.hash_code()
        }
    }

    struct MockThread(&'static str);

    impl TraceUniqueObject for MockThread {
        fn get_object_key(&self) -> Box<dyn ObjectKey> {
            Box::new(MockKey(0))
        }
        fn is_deleted(&self) -> bool {
            false
        }
    }

    impl TraceObjectInterface for MockThread {
        fn get_object(&self) -> Box<dyn TraceObject> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    impl TraceThread for MockThread {
        fn get_trace(&self) -> Box<dyn crate::trace::model::trace::Trace> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_key(&self) -> i64 {
            0
        }
        fn get_path(&self) -> String {
            self.0.to_string()
        }
        fn get_name(&self, _snap: i64) -> String {
            self.0.to_string()
        }
        fn set_name(&mut self, _lifespan: crate::trace::model::lifespan::Lifespan, _name: &str) {}
        fn set_name_at(&mut self, _snap: i64, _name: &str) {}
        fn set_comment(&mut self, _snap: i64, _comment: Option<&str>) {}
        fn get_comment(&self, _snap: i64) -> Option<String> {
            None
        }
        fn delete(&mut self) {}
        fn remove(&mut self, _snap: i64) {}
        fn is_valid(&self, _snap: i64) -> bool {
            true
        }
        fn is_alive(&self, _span: crate::trace::model::lifespan::Lifespan) -> bool {
            true
        }
    }

    struct MockStack {
        frames: Mutex<Vec<i32>>,
        deleted: Mutex<bool>,
    }

    impl TraceUniqueObject for MockStack {
        fn get_object_key(&self) -> Box<dyn ObjectKey> {
            Box::new(MockKey(0))
        }
        fn is_deleted(&self) -> bool {
            *self.deleted.lock().unwrap()
        }
    }

    impl TraceObjectInterface for MockStack {
        fn get_object(&self) -> Box<dyn TraceObject> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    impl TraceStack for MockStack {
        fn get_thread(&self) -> Box<dyn TraceThread> {
            Box::new(MockThread("t1"))
        }

        fn get_depth(&self, _snap: i64) -> i32 {
            self.frames.lock().unwrap().len() as i32
        }

        fn set_depth(&mut self, _snap: i64, depth: i32, at_inner: bool) {
            let mut frames = self.frames.lock().unwrap();
            let depth = depth as usize;
            if at_inner {
                while frames.len() < depth {
                    let next = frames.len() as i32;
                    frames.insert(0, next);
                }
                while frames.len() > depth {
                    frames.remove(0);
                }
            } else {
                frames.resize(depth, 0);
            }
        }

        fn get_frame(
            &self,
            _snap: i64,
            level: i32,
            ensure_depth: bool,
        ) -> Option<Box<dyn TraceStackFrame>> {
            assert!(level >= 0, "level must not be negative");
            let mut frames = self.frames.lock().unwrap();
            if (level as usize) >= frames.len() {
                if ensure_depth {
                    frames.resize(level as usize + 1, 0);
                } else {
                    return None;
                }
            }
            None
        }

        fn get_frames(&self, _snap: i64) -> Vec<Box<dyn TraceStackFrame>> {
            Vec::new()
        }

        fn delete(&mut self) {
            *self.deleted.lock().unwrap() = true;
            self.frames.lock().unwrap().clear();
        }

        fn remove(&mut self, _snap: i64) {
            *self.deleted.lock().unwrap() = true;
        }

        fn is_valid(&self, _snap: i64) -> bool {
            !*self.deleted.lock().unwrap()
        }

        fn has_fixed_frames(&self) -> bool {
            true
        }
    }

    fn make_stack() -> MockStack {
        MockStack {
            frames: Mutex::new(Vec::new()),
            deleted: Mutex::new(false),
        }
    }

    #[test]
    fn trace_object_info_matches_java_annotation() {
        let info = <MockStack as TraceStack>::trace_object_info();
        assert_eq!(info.schema_name, "Stack");
        assert_eq!(info.short_name, "stack");
        assert!(info.attributes.is_empty());
        assert!(info.fixed_keys.is_empty());
    }

    #[test]
    fn set_depth_at_inner_pushes_and_pops() {
        let mut stack = make_stack();
        assert_eq!(stack.get_depth(0), 0);

        stack.set_depth(0, 2, true);
        assert_eq!(stack.get_depth(0), 2);

        stack.set_depth(0, 1, true);
        assert_eq!(stack.get_depth(0), 1);
    }

    #[test]
    fn get_frame_respects_ensure_depth() {
        let mut stack = make_stack();
        assert!(stack.get_frame(0, 0, false).is_none());
        assert_eq!(stack.get_depth(0), 0);

        stack.get_frame(0, 2, true);
        assert_eq!(stack.get_depth(0), 3);
    }

    #[test]
    fn delete_marks_invalid_and_clears_frames() {
        let mut stack = make_stack();
        stack.set_depth(0, 3, true);
        assert!(stack.is_valid(0));

        stack.delete();
        assert!(!stack.is_valid(0));
        assert_eq!(stack.get_depth(0), 0);
    }

    #[test]
    fn trait_object_is_object_safe() {
        let stack: Box<dyn TraceStack> = Box::new(make_stack());
        assert!(stack.has_fixed_frames());
        assert!(stack.is_valid(0));
    }
}

//! A frame in a [`TraceStack`](crate::trace::model::stack::trace_stack::TraceStack).
//!
//! Port of `ghidra.trace.model.stack.TraceStackFrame`.

use crate::program::model::address::Address;
use crate::trace::model::lifespan::Lifespan;
use crate::trace::model::target::iface::TraceObjectInterface;
use crate::trace::model::target::info::trace_object_info::TraceObjectInfo;
use crate::trace::model::trace::Trace;
use crate::trace::model::stack::trace_stack::TraceStack;

/// Key for the frame's program-counter attribute.
pub const KEY_PC: &str = "_pc";
/// Key for the frame's stack-pointer attribute.
pub const KEY_SP: &str = "_sp";

/// A frame in a [`TraceStack`].
pub trait TraceStackFrame: TraceObjectInterface {
    /// Returns the `@TraceObjectInfo` metadata mirrored from the Java annotation on
    /// `TraceStackFrame`.
    fn trace_object_info() -> TraceObjectInfo
    where
        Self: Sized,
    {
        TraceObjectInfo::new("StackFrame", "frame", [KEY_PC, KEY_SP], [] as [&str; 0])
    }

    /// Get the trace containing this frame.
    fn get_trace(&self) -> Box<dyn Trace>;

    /// Get the containing stack.
    fn get_stack(&self) -> Box<dyn TraceStack>;

    /// Get the frame's position in the containing stack.
    ///
    /// 0 represents the innermost frame or top of the stack.
    fn get_level(&self) -> i32;

    /// Get the program counter at the given snap.
    ///
    /// The snap is only relevant in the experimental objects mode. Ordinarily, the PC is fixed
    /// over the containing stack's lifetime.
    fn get_program_counter(&self, snap: i64) -> Address;

    /// Set the program counter over the given span.
    ///
    /// The span is only relevant in the experimental objects mode. Ordinarily, the PC is fixed
    /// over the containing stack's lifetime.
    fn set_program_counter(&mut self, span: Lifespan, pc: Address);

    /// Get the stack pointer at the given snap.
    fn get_stack_pointer(&self, snap: i64) -> Address;

    /// Set the stack pointer over the given span.
    fn set_stack_pointer(&mut self, span: Lifespan, sp: Address);

    /// Get the user comment for the frame, if any.
    ///
    /// In the experimental objects mode, this actually gets the comment in the listing at the
    /// frame's program counter for the given snap.
    fn get_comment(&self, snap: i64) -> Option<String>;

    /// Set the user comment for the frame.
    ///
    /// In the experimental objects mode, this actually sets the comment in the listing at the
    /// frame's program counter for the given snap.
    fn set_comment(&mut self, snap: i64, comment: Option<String>);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::trace::model::target::trace_object::TraceObject;
    use std::sync::Mutex;

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0);
        Address::new(space, offset)
    }

    struct MockFrame {
        level: i32,
        pc: Mutex<Address>,
        sp: Mutex<Address>,
        comment: Mutex<Option<String>>,
    }

    impl TraceObjectInterface for MockFrame {
        fn get_object(&self) -> Box<dyn TraceObject> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    impl TraceStackFrame for MockFrame {
        fn get_trace(&self) -> Box<dyn Trace> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_stack(&self) -> Box<dyn TraceStack> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_level(&self) -> i32 {
            self.level
        }

        fn get_program_counter(&self, _snap: i64) -> Address {
            self.pc.lock().unwrap().clone()
        }

        fn set_program_counter(&mut self, _span: Lifespan, pc: Address) {
            *self.pc.lock().unwrap() = pc;
        }

        fn get_stack_pointer(&self, _snap: i64) -> Address {
            self.sp.lock().unwrap().clone()
        }

        fn set_stack_pointer(&mut self, _span: Lifespan, sp: Address) {
            *self.sp.lock().unwrap() = sp;
        }

        fn get_comment(&self, _snap: i64) -> Option<String> {
            self.comment.lock().unwrap().clone()
        }

        fn set_comment(&mut self, _snap: i64, comment: Option<String>) {
            *self.comment.lock().unwrap() = comment;
        }
    }

    fn make_frame() -> MockFrame {
        MockFrame {
            level: 0,
            pc: Mutex::new(addr(0x1000)),
            sp: Mutex::new(addr(0x2000)),
            comment: Mutex::new(None),
        }
    }

    #[test]
    fn trace_object_info_matches_java_annotation() {
        let info = <MockFrame as TraceStackFrame>::trace_object_info();
        assert_eq!(info.schema_name, "StackFrame");
        assert_eq!(info.short_name, "frame");
        assert_eq!(info.attributes, vec![KEY_PC.to_string(), KEY_SP.to_string()]);
        assert!(info.fixed_keys.is_empty());
    }

    #[test]
    fn constants_match_expected_values() {
        assert_eq!(KEY_PC, "_pc");
        assert_eq!(KEY_SP, "_sp");
    }

    #[test]
    fn set_program_counter_and_stack_pointer_round_trip() {
        let mut frame = make_frame();
        assert_eq!(frame.get_level(), 0);
        assert_eq!(frame.get_program_counter(0), addr(0x1000));

        frame.set_program_counter(Lifespan::since(0), addr(0x1234));
        assert_eq!(frame.get_program_counter(0), addr(0x1234));

        frame.set_stack_pointer(Lifespan::since(0), addr(0x3000));
        assert_eq!(frame.get_stack_pointer(0), addr(0x3000));
    }

    #[test]
    fn comment_defaults_to_none_and_can_be_set() {
        let mut frame = make_frame();
        assert_eq!(frame.get_comment(0), None);

        frame.set_comment(0, Some("stopped here".to_string()));
        assert_eq!(frame.get_comment(0), Some("stopped here".to_string()));

        frame.set_comment(0, None);
        assert_eq!(frame.get_comment(0), None);
    }

    #[test]
    fn trait_object_is_object_safe() {
        let frame: Box<dyn TraceStackFrame> = Box::new(make_frame());
        assert_eq!(frame.get_level(), 0);
    }
}

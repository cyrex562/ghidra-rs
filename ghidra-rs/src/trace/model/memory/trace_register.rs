//! A register.
//!
//! Port of `ghidra.trace.model.memory.TraceRegister`.
//!
//! There are two conventions for presenting registers and their values, both described in the
//! Java type's documentation: via the [`TraceMemoryManager`](crate::trace::model::memory::trace_memory_manager::TraceMemoryManager)
//! (using a register address space), or via the [`TraceObjectManager`](crate::trace::model::target::trace_object_manager::TraceObjectManager)
//! object tree, where each register is presented through this interface.
//!
//! Reuses [`TraceThread`](crate::trace::model::thread::TraceThread), matching
//! [`TraceMemoryManager`](crate::trace::model::memory::trace_memory_manager::TraceMemoryManager)'s
//! usage.

use crate::trace::model::lifespan::Lifespan;
use crate::trace::model::memory::trace_memory_state::TraceMemoryState;
use crate::trace::model::target::iface::TraceObjectInterface;
use crate::trace::model::target::info::trace_object_info::TraceObjectInfo;
use crate::trace::model::thread::TraceThread;

/// Key for the register's bit-length attribute.
pub const KEY_BITLENGTH: &str = "_length";
/// Key for the register's state attribute.
pub const KEY_STATE: &str = "_state";

/// A register.
///
/// Port of `ghidra.trace.model.memory.TraceRegister`. See the module documentation for the two
/// presentation conventions and the `TraceThread` stub deviation from a literal translation.
pub trait TraceRegister: TraceObjectInterface {
    /// Returns the `@TraceObjectInfo` metadata mirrored from the Java annotation on
    /// `TraceRegister`.
    fn trace_object_info() -> TraceObjectInfo
    where
        Self: Sized,
    {
        TraceObjectInfo::new("Register", "register", [KEY_BITLENGTH, KEY_STATE], [KEY_BITLENGTH])
    }

    /// Get the thread whose context this register belongs to.
    fn get_thread(&self) -> Box<dyn TraceThread>;

    /// Get the name of this register.
    fn get_name(&self) -> String;

    /// Get the length of this register, in bits, at the given snap.
    fn get_bit_length(&self, snap: i64) -> i32;

    /// Get the length of this register, in bytes, at the given snap.
    ///
    /// Mirrors Java's default `getByteLength(long)`: `(getBitLength(snap) + 7) / 8`.
    fn get_byte_length(&self, snap: i64) -> i32 {
        (self.get_bit_length(snap) + 7) / 8
    }

    /// Set the value of this register across the given span of time.
    fn set_value(&mut self, lifespan: Lifespan, value: &[u8]);

    /// Get the value of this register at the given snap.
    fn get_value(&self, snap: i64) -> Vec<u8>;

    /// Set the observation state of this register across the given span of time.
    fn set_state(&mut self, lifespan: Lifespan, state: TraceMemoryState);

    /// Get the observation state of this register at the given snap.
    fn get_state(&self, snap: i64) -> TraceMemoryState;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct MockRegister {
        thread_key: i64,
        name: String,
        bit_length: i32,
        value: Mutex<Vec<u8>>,
        state: Mutex<TraceMemoryState>,
    }

    struct MockThread(i64);

    impl crate::trace::model::trace_unique_object::TraceUniqueObject for MockThread {
        fn get_object_key(&self) -> Box<dyn crate::trace::seam_stubs::ObjectKey> {
            unimplemented!("not exercised by this smoke test")
        }
        fn is_deleted(&self) -> bool {
            false
        }
    }

    impl TraceObjectInterface for MockThread {
        fn get_object(&self) -> Box<dyn crate::trace::model::target::trace_object::TraceObject> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    impl TraceThread for MockThread {
        fn get_trace(&self) -> Box<dyn crate::trace::model::trace::Trace> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_key(&self) -> i64 {
            self.0
        }
        fn get_path(&self) -> String {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_name(&self, _snap: i64) -> String {
            unimplemented!("not exercised by this smoke test")
        }
        fn set_name(&mut self, _lifespan: Lifespan, _name: &str) {}
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
        fn is_alive(&self, _span: Lifespan) -> bool {
            true
        }
    }

    impl TraceObjectInterface for MockRegister {
        fn get_object(&self) -> Box<dyn crate::trace::model::target::trace_object::TraceObject> {
            unimplemented!("mock")
        }
    }

    impl TraceRegister for MockRegister {
        fn get_thread(&self) -> Box<dyn TraceThread> {
            Box::new(MockThread(self.thread_key))
        }

        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn get_bit_length(&self, _snap: i64) -> i32 {
            self.bit_length
        }

        fn set_value(&mut self, _lifespan: Lifespan, value: &[u8]) {
            *self.value.lock().unwrap() = value.to_vec();
        }

        fn get_value(&self, _snap: i64) -> Vec<u8> {
            self.value.lock().unwrap().clone()
        }

        fn set_state(&mut self, _lifespan: Lifespan, state: TraceMemoryState) {
            *self.state.lock().unwrap() = state;
        }

        fn get_state(&self, _snap: i64) -> TraceMemoryState {
            *self.state.lock().unwrap()
        }
    }

    fn mock_register(bit_length: i32) -> MockRegister {
        MockRegister {
            thread_key: 7,
            name: "RAX".to_string(),
            bit_length,
            value: Mutex::new(Vec::new()),
            state: Mutex::new(TraceMemoryState::Unknown),
        }
    }

    #[test]
    fn is_object_safe() {
        let register = mock_register(64);
        let _dyn_ref: &dyn TraceRegister = &register;
    }

    #[test]
    fn trace_object_info_matches_java_annotation() {
        let info = <MockRegister as TraceRegister>::trace_object_info();
        assert_eq!(info.schema_name, "Register");
        assert_eq!(info.short_name, "register");
        assert_eq!(
            info.attributes,
            vec![KEY_BITLENGTH.to_string(), KEY_STATE.to_string()]
        );
        assert_eq!(info.fixed_keys, vec![KEY_BITLENGTH.to_string()]);
    }

    #[test]
    fn byte_length_rounds_up_from_bit_length() {
        // Matches Java's `(getBitLength(snap) + 7) / 8` for a non-byte-aligned width, e.g. a
        // 1-bit flag register still occupies a whole byte, and a 64-bit register occupies
        // exactly 8 bytes with no rounding.
        assert_eq!(mock_register(1).get_byte_length(0), 1);
        assert_eq!(mock_register(33).get_byte_length(0), 5);
        assert_eq!(mock_register(64).get_byte_length(0), 8);
    }

    #[test]
    fn value_and_state_roundtrip_over_lifespan() {
        let mut register = mock_register(32);
        let lifespan = Lifespan::at(0);
        register.set_value(lifespan, &[0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(register.get_value(0), vec![0xDE, 0xAD, 0xBE, 0xEF]);

        register.set_state(lifespan, TraceMemoryState::Known);
        assert_eq!(register.get_state(0), TraceMemoryState::Known);
    }

    #[test]
    fn thread_key_is_reachable_through_trait_object() {
        let register = mock_register(16);
        let dyn_register: &dyn TraceRegister = &register;
        assert_eq!(dyn_register.get_thread().get_key(), 7);
    }
}

//! Centralized service for modifying machine states.
//!
//! Port of `ghidra.app.services.DebuggerControlService`. The Java `@ServiceInfo` annotation
//! (default provider `DebuggerControlServicePlugin`) has no Rust equivalent and is omitted.
//!
//! Java's overloaded `createStateEditor` methods are each given a distinct Rust name, since Rust
//! traits cannot overload on parameter type alone: the `DebuggerCoordinates` overload stays
//! `create_state_editor`, while the `Trace` and `TraceProgramView` overloads become
//! `create_state_editor_for_trace`/`create_state_editor_for_view`.

use std::future::Future;
use std::pin::Pin;

use crate::app::seam_stubs::{ControlMode, DebuggerCoordinates};
use crate::program::model::address::Address;
use crate::program::model::lang::Register;
use crate::program::seam_stubs::RegisterValue;
use crate::trace::model::trace::Trace;
use crate::trace::seam_stubs::TraceProgramView;

/// A future representing an asynchronous, possibly-failable machine-state edit.
///
/// Port of Java's `CompletableFuture<Void>` return type used throughout `StateEditor`.
pub type StateEditFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

/// Converts an unsigned value into a big-endian or little-endian byte array of the given length,
/// truncating or zero-padding as needed.
///
/// Port of `ghidra.pcode.utils.Utils.bigIntegerToBytes`, used by [`StateEditor::set_register`]'s
/// default implementation.
fn unsigned_value_to_bytes(value: u128, num_bytes: i32, big_endian: bool) -> Vec<u8> {
    let num_bytes = num_bytes.max(0) as usize;
    let mut be_bytes = value.to_be_bytes().to_vec();
    if be_bytes.len() < num_bytes {
        let mut padded = vec![0u8; num_bytes - be_bytes.len()];
        padded.append(&mut be_bytes);
        be_bytes = padded;
    } else if be_bytes.len() > num_bytes {
        let start = be_bytes.len() - num_bytes;
        be_bytes = be_bytes[start..].to_vec();
    }
    if !big_endian {
        be_bytes.reverse();
    }
    be_bytes
}

/// Edits machine state (memory and register values) for a particular set of debugger
/// coordinates.
///
/// Port of `DebuggerControlService.StateEditor`.
pub trait StateEditor {
    /// Returns the service that created this editor.
    fn get_service(&self) -> Box<dyn DebuggerControlService>;

    /// Returns the coordinates this editor is bound to.
    fn get_coordinates(&self) -> Box<dyn DebuggerCoordinates>;

    /// Checks whether the variable at the given address and length can currently be edited.
    fn is_variable_editable(&self, address: &Address, length: i32) -> bool;

    /// Checks whether the given register can currently be edited.
    fn is_register_editable(&self, register: &Register) -> bool {
        self.is_variable_editable(register.address(), register.num_bytes())
    }

    /// Sets the value of the variable at the given address.
    fn set_variable(&self, address: &Address, data: &[u8]) -> StateEditFuture;

    /// Sets the value of a register.
    fn set_register(&self, value: &dyn RegisterValue) -> StateEditFuture {
        let register_ref = value.get_register();
        let register = register_ref.borrow();
        let bytes = unsigned_value_to_bytes(
            value.get_unsigned_value_ignore_mask(),
            register.num_bytes(),
            register.is_big_endian(),
        );
        let address = register.address().clone();
        drop(register);
        self.set_variable(&address, &bytes)
    }
}

/// Notified when the control mode changes for a trace.
///
/// Port of `DebuggerControlService.ControlModeChangeListener`.
pub trait ControlModeChangeListener {
    /// Called when the control mode changes for the given trace.
    fn mode_changed(&self, trace: &dyn Trace, mode: Box<dyn ControlMode>);
}

/// Centralized service for modifying machine states.
///
/// Port of `ghidra.app.services.DebuggerControlService`.
pub trait DebuggerControlService {
    /// Gets the current control mode for the given trace.
    fn get_current_mode(&self, trace: &dyn Trace) -> Box<dyn ControlMode>;

    /// Sets the current control mode for the given trace.
    fn set_current_mode(&mut self, trace: &dyn Trace, mode: Box<dyn ControlMode>);

    /// Adds a listener to be notified of control mode changes.
    fn add_mode_change_listener(&mut self, listener: Box<dyn ControlModeChangeListener>);

    /// Removes a previously-added control mode change listener.
    fn remove_mode_change_listener(&mut self, listener: &dyn ControlModeChangeListener);

    /// Creates a state editor bound to the given coordinates.
    fn create_state_editor(&self, coordinates: Box<dyn DebuggerCoordinates>) -> Box<dyn StateEditor>;

    /// Creates a state editor whose coordinates follow the trace manager for the given trace.
    fn create_state_editor_for_trace(&self, trace: &dyn Trace) -> Box<dyn StateEditor>;

    /// Creates a state editor bound to the coordinates of the given trace program view.
    fn create_state_editor_for_view(&self, view: &dyn TraceProgramView) -> Box<dyn StateEditor>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockCoordinates;
    impl DebuggerCoordinates for MockCoordinates {}

    struct MockControlMode;
    impl ControlMode for MockControlMode {}

    struct MockStateEditor;

    impl StateEditor for MockStateEditor {
        fn get_service(&self) -> Box<dyn DebuggerControlService> {
            Box::new(MockDebuggerControlService)
        }

        fn get_coordinates(&self) -> Box<dyn DebuggerCoordinates> {
            Box::new(MockCoordinates)
        }

        fn is_variable_editable(&self, _address: &Address, _length: i32) -> bool {
            true
        }

        fn set_variable(&self, _address: &Address, _data: &[u8]) -> StateEditFuture {
            Box::pin(async {})
        }
    }

    struct MockDebuggerControlService;

    impl DebuggerControlService for MockDebuggerControlService {
        fn get_current_mode(&self, _trace: &dyn Trace) -> Box<dyn ControlMode> {
            Box::new(MockControlMode)
        }

        fn set_current_mode(&mut self, _trace: &dyn Trace, _mode: Box<dyn ControlMode>) {}

        fn add_mode_change_listener(&mut self, _listener: Box<dyn ControlModeChangeListener>) {}

        fn remove_mode_change_listener(&mut self, _listener: &dyn ControlModeChangeListener) {}

        fn create_state_editor(
            &self,
            _coordinates: Box<dyn DebuggerCoordinates>,
        ) -> Box<dyn StateEditor> {
            Box::new(MockStateEditor)
        }

        fn create_state_editor_for_trace(&self, _trace: &dyn Trace) -> Box<dyn StateEditor> {
            Box::new(MockStateEditor)
        }

        fn create_state_editor_for_view(&self, _view: &dyn TraceProgramView) -> Box<dyn StateEditor> {
            Box::new(MockStateEditor)
        }
    }

    #[test]
    fn is_object_safe_as_boxed_trait() {
        let service: Box<dyn DebuggerControlService> = Box::new(MockDebuggerControlService);
        let _ = service;
    }

    #[test]
    fn is_register_editable_default_delegates_to_is_variable_editable() {
        use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};

        let editor = MockStateEditor;
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let address = Address::new(space, 0);
        let register_ref = Register::new("r0", "", address, 4, false, 0);
        let register = register_ref.borrow();
        assert!(editor.is_register_editable(&register));
    }

    #[test]
    fn unsigned_value_to_bytes_pads_and_truncates() {
        assert_eq!(unsigned_value_to_bytes(0x1234, 4, true), vec![0x00, 0x00, 0x12, 0x34]);
        assert_eq!(unsigned_value_to_bytes(0x1234, 4, false), vec![0x34, 0x12, 0x00, 0x00]);
        assert_eq!(unsigned_value_to_bytes(0x1234, 1, true), vec![0x34]);
    }

    #[test]
    fn mode_change_listener_is_object_safe() {
        struct RecordingListener;
        impl ControlModeChangeListener for RecordingListener {
            fn mode_changed(&self, _trace: &dyn Trace, _mode: Box<dyn ControlMode>) {}
        }
        let listener: Box<dyn ControlModeChangeListener> = Box::new(RecordingListener);
        let _ = listener;
    }
}

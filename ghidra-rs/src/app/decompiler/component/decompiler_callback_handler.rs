//! Port of `ghidra.app.decompiler.component.DecompilerCallbackHandler`.
//!
//! Java is an `interface` with 12 abstract methods and 2 in-repo implementors, so this becomes a
//! `trait` (rule R-interface-open-ext-point). It is the callback surface a decompiler component
//! (e.g. `DecompilerPanel`) uses to notify its owner of user interaction and data changes.
//!
//! # Seams
//!
//! * **`ProgramSelection`.** Two unrelated placeholders for this Java class already exist
//!   crate-wide: [`crate::util::seam_stubs::ProgramSelection`] (an empty marker) and
//!   [`crate::app::seam_stubs::ProgramSelection`] (carries `is_empty()`, used by four other
//!   `ghidra.app.*`-package files, e.g. `DisassemblerPlugin`). Since this interface lives in
//!   `ghidra.app.decompiler.component`, it reuses the `app` one for consistency with its
//!   package-mates rather than the `util` one.
//! * **`DecompileData`/`AnnotatedTextFieldElement`.** Both unported, both concrete classes (not
//!   interfaces -- see each placeholder's own doc comment in `crate::app::seam_stubs`), and
//!   neither has any of its methods called by this interface (they are pure pass-through
//!   parameters), so both are minimal unit-struct placeholders.

use crate::app::seam_stubs::{AnnotatedTextFieldElement, DecompileData, ProgramSelection};
use crate::program::model::address::Address;
use crate::program::model::listing::Function;
use crate::program::util::ProgramLocation;
use crate::util::function::Callback;

/// Port of the Java interface `ghidra.app.decompiler.component.DecompilerCallbackHandler`.
pub trait DecompilerCallbackHandler {
    /// Mirrors `decompileDataChanged(DecompileData)`.
    fn decompile_data_changed(&mut self, decompile_data: &DecompileData);

    /// Mirrors `contextChanged()`.
    fn context_changed(&mut self);

    /// Mirrors `setStatusMessage(String)`.
    fn set_status_message(&mut self, message: &str);

    /// Mirrors `locationChanged(ProgramLocation)`.
    fn location_changed(&mut self, program_location: &dyn ProgramLocation);

    /// Mirrors `selectionChanged(ProgramSelection)`.
    fn selection_changed(&mut self, program_selection: &dyn ProgramSelection);

    /// Mirrors `annotationClicked(AnnotatedTextFieldElement, boolean)`.
    fn annotation_clicked(&mut self, annotation: &AnnotatedTextFieldElement, new_window: bool);

    /// Mirrors `goToLabel(String, boolean)`.
    fn go_to_label(&mut self, label_name: &str, new_window: bool);

    /// Mirrors `goToAddress(Address, boolean)`.
    fn go_to_address(&mut self, addr: &Address, new_window: bool);

    /// Mirrors `goToScalar(long, boolean)`.
    fn go_to_scalar(&mut self, value: i64, new_window: bool);

    /// Mirrors `exportLocation()`.
    fn export_location(&mut self);

    /// Mirrors `goToFunction(Function, boolean)`.
    fn go_to_function(&mut self, function: &dyn Function, new_window: bool);

    /// Mirrors `doWhenNotBusy(Callback)`.
    fn do_when_not_busy(&mut self, c: Callback);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// Minimal recording implementation, used to verify dispatch and trait-object usability.
    #[derive(Default)]
    struct RecordingHandler {
        events: RefCell<Vec<&'static str>>,
        last_status_message: RefCell<Option<String>>,
        not_busy_calls: RefCell<usize>,
    }

    impl DecompilerCallbackHandler for RecordingHandler {
        fn decompile_data_changed(&mut self, _decompile_data: &DecompileData) {
            self.events.borrow_mut().push("decompile_data_changed");
        }
        fn context_changed(&mut self) {
            self.events.borrow_mut().push("context_changed");
        }
        fn set_status_message(&mut self, message: &str) {
            *self.last_status_message.borrow_mut() = Some(message.to_string());
        }
        fn location_changed(&mut self, _program_location: &dyn ProgramLocation) {
            self.events.borrow_mut().push("location_changed");
        }
        fn selection_changed(&mut self, _program_selection: &dyn ProgramSelection) {
            self.events.borrow_mut().push("selection_changed");
        }
        fn annotation_clicked(&mut self, _annotation: &AnnotatedTextFieldElement, _new_window: bool) {
            self.events.borrow_mut().push("annotation_clicked");
        }
        fn go_to_label(&mut self, _label_name: &str, _new_window: bool) {
            self.events.borrow_mut().push("go_to_label");
        }
        fn go_to_address(&mut self, _addr: &Address, _new_window: bool) {
            self.events.borrow_mut().push("go_to_address");
        }
        fn go_to_scalar(&mut self, _value: i64, _new_window: bool) {
            self.events.borrow_mut().push("go_to_scalar");
        }
        fn export_location(&mut self) {
            self.events.borrow_mut().push("export_location");
        }
        fn go_to_function(&mut self, _function: &dyn Function, _new_window: bool) {
            self.events.borrow_mut().push("go_to_function");
        }
        fn do_when_not_busy(&mut self, c: Callback) {
            *self.not_busy_calls.borrow_mut() += 1;
            c();
        }
    }

    #[test]
    fn dispatches_simple_callbacks() {
        let mut handler = RecordingHandler::default();
        handler.context_changed();
        handler.export_location();
        assert_eq!(*handler.events.borrow(), vec!["context_changed", "export_location"]);
    }

    #[test]
    fn set_status_message_stores_message() {
        let mut handler = RecordingHandler::default();
        handler.set_status_message("compiling...");
        assert_eq!(
            handler.last_status_message.borrow().as_deref(),
            Some("compiling...")
        );
    }

    #[test]
    fn do_when_not_busy_invokes_callback() {
        let mut handler = RecordingHandler::default();
        // `Callback = Box<dyn Fn() + Send + Sync>`, so the closure must capture a `Sync` cell;
        // `Arc<Mutex<_>>` rather than `Rc<RefCell<_>>`.
        let flag = std::sync::Arc::new(std::sync::Mutex::new(false));
        let flag2 = flag.clone();
        let cb: Callback = Box::new(move || {
            *flag2.lock().unwrap() = true;
        });
        handler.do_when_not_busy(cb);
        assert!(*flag.lock().unwrap());
        assert_eq!(*handler.not_busy_calls.borrow(), 1);
    }

    #[test]
    fn usable_as_trait_object() {
        let mut handler: Box<dyn DecompilerCallbackHandler> = Box::new(RecordingHandler::default());
        handler.go_to_label("main", false);
        handler.go_to_scalar(42, true);
    }
}

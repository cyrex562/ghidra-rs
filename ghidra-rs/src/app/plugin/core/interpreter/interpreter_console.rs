use crate::app::seam_stubs::DockingAction;
use crate::util::disposable::Disposable;
use crate::util::function::Callback;
use std::io::{Read, Write};

/// Interactive interpreter console.
///
/// Port of `ghidra.app.plugin.core.interpreter.InterpreterConsole`.
pub trait InterpreterConsole: Disposable {
    /// Port of `InterpreterConsole.clear()`.
    fn clear(&mut self);

    /// Port of `InterpreterConsole.getStdin()`.
    fn get_stdin(&mut self) -> Box<dyn Read>;

    /// Port of `InterpreterConsole.getStdOut()`.
    fn get_std_out(&mut self) -> Box<dyn Write>;

    /// Port of `InterpreterConsole.getStdErr()`.
    fn get_std_err(&mut self) -> Box<dyn Write>;

    /// Port of `InterpreterConsole.getOutWriter()`.
    fn get_out_writer(&mut self) -> Box<dyn Write>;

    /// Port of `InterpreterConsole.getErrWriter()`.
    fn get_err_writer(&mut self) -> Box<dyn Write>;

    /// Port of `InterpreterConsole.setPrompt(String)`.
    fn set_prompt(&mut self, prompt: &str);

    /// Signals that this console is one that the user can remove from the tool as desired. If
    /// this method is not called, then the user cannot remove the console from the tool, which
    /// means that closing the console only hides it.
    ///
    /// Port of `InterpreterConsole.setTransient()`.
    fn set_transient(&mut self);

    /// Port of `InterpreterConsole.addAction(DockingAction)`.
    fn add_action(&mut self, action: DockingAction);

    /// Adds the given callback which will get called the first time the interpreter console is
    /// activated.
    ///
    /// Port of `InterpreterConsole.addFirstActivationCallback(Callback)`.
    fn add_first_activation_callback(&mut self, activation_callback: Callback);

    /// Checks whether the user can input commands.
    ///
    /// Port of `InterpreterConsole.isInputPermitted()`.
    fn is_input_permitted(&self) -> bool;

    /// Controls whether the user can input commands.
    ///
    /// Port of `InterpreterConsole.setInputPermitted(boolean)`.
    fn set_input_permitted(&mut self, permitted: bool);

    /// Check if the console is visible.
    ///
    /// Note if the console is on-screen, but occluded by other windows, this still returns
    /// `true`.
    ///
    /// Port of `InterpreterConsole.isVisible()`.
    fn is_visible(&self) -> bool;

    /// Show the console's provider in the tool.
    ///
    /// Port of `InterpreterConsole.show()`.
    fn show(&mut self);

    /// Notify the tool that this console's title has changed.
    ///
    /// Port of `InterpreterConsole.updateTitle()`.
    fn update_title(&mut self);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    struct FakeConsole {
        prompt: String,
        transient: bool,
        input_permitted: bool,
        visible: bool,
        title_updates: u32,
        first_activation_callbacks: Vec<Callback>,
    }

    impl FakeConsole {
        fn new() -> Self {
            FakeConsole {
                prompt: String::new(),
                transient: false,
                input_permitted: true,
                visible: false,
                title_updates: 0,
                first_activation_callbacks: Vec::new(),
            }
        }
    }

    impl Disposable for FakeConsole {
        fn dispose(&mut self) {
            self.input_permitted = false;
        }
    }

    impl InterpreterConsole for FakeConsole {
        fn clear(&mut self) {}

        fn get_stdin(&mut self) -> Box<dyn Read> {
            Box::new(Cursor::new(Vec::new()))
        }

        fn get_std_out(&mut self) -> Box<dyn Write> {
            Box::new(Cursor::new(Vec::new()))
        }

        fn get_std_err(&mut self) -> Box<dyn Write> {
            Box::new(Cursor::new(Vec::new()))
        }

        fn get_out_writer(&mut self) -> Box<dyn Write> {
            Box::new(Cursor::new(Vec::new()))
        }

        fn get_err_writer(&mut self) -> Box<dyn Write> {
            Box::new(Cursor::new(Vec::new()))
        }

        fn set_prompt(&mut self, prompt: &str) {
            self.prompt = prompt.to_string();
        }

        fn set_transient(&mut self) {
            self.transient = true;
        }

        fn add_action(&mut self, _action: DockingAction) {}

        fn add_first_activation_callback(&mut self, activation_callback: Callback) {
            self.first_activation_callbacks.push(activation_callback);
        }

        fn is_input_permitted(&self) -> bool {
            self.input_permitted
        }

        fn set_input_permitted(&mut self, permitted: bool) {
            self.input_permitted = permitted;
        }

        fn is_visible(&self) -> bool {
            self.visible
        }

        fn show(&mut self) {
            self.visible = true;
        }

        fn update_title(&mut self) {
            self.title_updates += 1;
        }
    }

    #[test]
    fn set_prompt_stores_prompt() {
        let mut console = FakeConsole::new();
        console.set_prompt("> ");
        assert_eq!(console.prompt, "> ");
    }

    #[test]
    fn set_transient_flips_flag_once_set() {
        let mut console = FakeConsole::new();
        assert!(!console.transient);
        console.set_transient();
        assert!(console.transient);
    }

    #[test]
    fn input_permitted_defaults_true_and_is_settable() {
        let mut console = FakeConsole::new();
        assert!(console.is_input_permitted());
        console.set_input_permitted(false);
        assert!(!console.is_input_permitted());
    }

    #[test]
    fn show_makes_console_visible() {
        let mut console = FakeConsole::new();
        assert!(!console.is_visible());
        console.show();
        assert!(console.is_visible());
    }

    #[test]
    fn update_title_increments_counter() {
        let mut console = FakeConsole::new();
        console.update_title();
        console.update_title();
        assert_eq!(console.title_updates, 2);
    }

    #[test]
    fn dispose_prohibits_input() {
        let mut console = FakeConsole::new();
        console.dispose();
        assert!(!console.is_input_permitted());
    }

    #[test]
    fn first_activation_callback_is_invoked_when_called() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let mut console = FakeConsole::new();
        let called = Arc::new(AtomicBool::new(false));
        let called_clone = Arc::clone(&called);
        console.add_first_activation_callback(Box::new(move || {
            called_clone.store(true, Ordering::SeqCst);
        }));

        assert_eq!(console.first_activation_callbacks.len(), 1);
        (console.first_activation_callbacks[0])();
        assert!(called.load(Ordering::SeqCst));
    }

    #[test]
    fn trait_object_dispatch() {
        let mut console = FakeConsole::new();
        let obj: &mut dyn InterpreterConsole = &mut console;
        obj.set_prompt("$ ");
        obj.set_transient();
        assert!(obj.is_input_permitted());
    }
}

//! Port of `ghidra.pyghidra.interpreter.PyGhidraConsole`.

use crate::app::plugin::core::console::code_completion::CodeCompletion;
use crate::util::disposable::Disposable;

/// Console interface providing only the methods which need to be implemented in Python.
///
/// Port of `ghidra.pyghidra.interpreter.PyGhidraConsole`. In Java this interface is public only
/// so that the Python side can implement it; it is the seam between the interpreter plumbing and
/// the embedded Python runtime, so it stays an open trait.
pub trait PyGhidraConsole: Disposable {
    /// Generates code completions for the PyGhidra interpreter.
    ///
    /// `caret_pos` is the position of the caret in `cmd`; it should satisfy
    /// `0 <= caret_pos <= cmd.len()`.
    ///
    /// Port of `getCompletions(String, int)`.
    fn get_completions(&self, cmd: &str, caret_pos: usize) -> Vec<CodeCompletion>;

    /// Restarts the PyGhidra console.
    ///
    /// Port of `restart()`.
    fn restart(&mut self);

    /// Interrupts the code running in the PyGhidra console. Takes `&self` because, as in Java,
    /// it is issued while the console is busy running code.
    ///
    /// Port of `interrupt()`.
    fn interrupt(&self);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    /// Completes names from a fixed vocabulary against the identifier ending at the caret.
    #[derive(Default)]
    struct FakeConsole {
        restarts: u32,
        interrupted: AtomicBool,
        disposed: bool,
    }

    impl Disposable for FakeConsole {
        fn dispose(&mut self) {
            self.disposed = true;
        }
    }

    impl PyGhidraConsole for FakeConsole {
        fn get_completions(&self, cmd: &str, caret_pos: usize) -> Vec<CodeCompletion> {
            let prefix = &cmd[..caret_pos];
            let start = prefix
                .rfind(|c: char| !(c.is_alphanumeric() || c == '_'))
                .map_or(0, |i| i + 1);
            let word = &prefix[start..];
            ["currentProgram", "currentAddress", "askString"]
                .iter()
                .filter(|n| !word.is_empty() && n.starts_with(word))
                .map(|n| {
                    CodeCompletion::with_chars_to_remove(
                        n.to_string(),
                        Some(n.to_string()),
                        None,
                        word.len(),
                    )
                })
                .collect()
        }

        fn restart(&mut self) {
            self.restarts += 1;
            self.interrupted.store(false, Ordering::SeqCst);
        }

        fn interrupt(&self) {
            self.interrupted.store(true, Ordering::SeqCst);
        }
    }

    #[test]
    fn completions_respect_caret_position() {
        let console = FakeConsole::default();
        let all = console.get_completions("x = curr", 8);
        let names: Vec<&str> = all.iter().map(|c| c.description()).collect();
        assert_eq!(names, ["currentProgram", "currentAddress"]);
        assert!(all.iter().all(|c| c.chars_to_remove() == 4));
        // Caret at the start of the word: nothing to complete.
        assert!(console.get_completions("x = curr", 4).is_empty());
        // Caret at 0 is the lower bound of the documented range.
        assert!(console.get_completions("ask", 0).is_empty());
    }

    #[test]
    fn lifecycle_through_trait_object() {
        fn drive(console: &mut dyn PyGhidraConsole) {
            console.interrupt();
            console.restart();
            console.interrupt();
            console.dispose();
        }
        let mut fake = FakeConsole::default();
        drive(&mut fake);
        assert_eq!(fake.restarts, 1);
        assert!(fake.interrupted.load(Ordering::SeqCst));
        assert!(fake.disposed);
    }
}

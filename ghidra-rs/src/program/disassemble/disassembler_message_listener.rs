use crate::util::msg::Msg;

/// Trait for reporting disassembly messages.
///
/// Implementations of this trait receive notifications of messages produced
/// during the disassembly process. See [`IGNORE`] and [`CONSOLE`] for
/// pre-built implementations.
pub trait DisassemblerMessageListener: Send + Sync {
    /// Called to display disassembly progress messages.
    ///
    /// # Arguments
    /// * `msg` - The message to display
    fn disassemble_message_reported(&self, msg: &str);
}

/// A [`DisassemblerMessageListener`] that ignores all disassembly messages.
pub struct Ignore;

impl DisassemblerMessageListener for Ignore {
    fn disassemble_message_reported(&self, _msg: &str) {}
}

/// A [`DisassemblerMessageListener`] that writes all disassembly messages to the console.
pub struct Console;

impl DisassemblerMessageListener for Console {
    fn disassemble_message_reported(&self, msg: &str) {
        Msg::debug("DisassemblerMessageListener", &msg);
    }
}

/// Singleton instance that ignores all messages from the disassembler.
pub static IGNORE: &(dyn DisassemblerMessageListener) = &Ignore;

/// Singleton instance that writes all messages from disassembler to the console.
pub static CONSOLE: &(dyn DisassemblerMessageListener) = &Console;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn ignore_listener_does_nothing() {
        let listener = Ignore;
        listener.disassemble_message_reported("test message");
    }

    #[test]
    fn console_listener_accepts_message() {
        let listener = Console;
        listener.disassemble_message_reported("test message");
    }

    #[test]
    fn ignore_static_works() {
        IGNORE.disassemble_message_reported("test message");
    }

    #[test]
    fn console_static_works() {
        CONSOLE.disassemble_message_reported("test message");
    }

    #[test]
    fn trait_object_from_ignore() {
        let listener: &dyn DisassemblerMessageListener = &Ignore;
        listener.disassemble_message_reported("test message");
    }

    #[test]
    fn trait_object_from_console() {
        let listener: &dyn DisassemblerMessageListener = &Console;
        listener.disassemble_message_reported("test message");
    }

    #[test]
    fn arc_trait_object_works() {
        let listener: Arc<dyn DisassemblerMessageListener> = Arc::new(Ignore);
        listener.disassemble_message_reported("test message");
    }
}

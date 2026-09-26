//! An exception thrown when decoding an instruction for execution fails.
//!
//! Corresponds to `ghidra.pcode.exec.DecodePcodeExecutionException`.
//!
//! Java's class extends [`PcodeExecutionException`], adding the program counter where decode was
//! attempted. Following this crate's composition-over-inheritance convention, this wraps a
//! [`PcodeExecutionException`] instead of extending it.

use crate::pcode::exec::pcode_execution_exception::PcodeExecutionException;
use crate::program::model::address::Address;

/// An exception thrown when decoding an instruction for execution fails.
#[derive(Debug)]
pub struct DecodePcodeExecutionException {
    inner: PcodeExecutionException,
    pc: Address,
}

impl DecodePcodeExecutionException {
    /// Construct the exception with the given message and program counter.
    ///
    /// Port of `DecodePcodeExecutionException(String message, Address pc)`.
    ///
    /// # Quirk faithfully reproduced
    ///
    /// Java's constructor appends `" (PC=<pc>)"` to the message *unless the message already
    /// contains the literal substring `"PC="`*:
    /// ```java
    /// super(message.contains("PC=") ? message : "%s (PC=%s)".formatted(message, pc));
    /// ```
    /// This is a substring check, not a check that the message mentions *this* `pc` -- a caller
    /// that builds a message mentioning an unrelated `PC=...` (or even just the literal text
    /// `"PC="` with no address at all) gets that message back verbatim, with the real `pc` passed
    /// to this constructor silently dropped from the displayed message (though still recoverable
    /// via [`get_program_counter`](Self::get_program_counter)). See
    /// [`message_containing_pc_marker_is_left_verbatim`] below for a test proving this exact
    /// behavior.
    pub fn new(message: impl AsRef<str>, pc: Address) -> Self {
        let message = message.as_ref();
        let formatted = if message.contains("PC=") {
            message.to_string()
        } else {
            format!("{} (PC={})", message, pc)
        };
        Self { inner: PcodeExecutionException::with_message(formatted), pc }
    }

    /// The program counter where decode was attempted.
    ///
    /// Port of `getProgramCounter()`.
    pub fn get_program_counter(&self) -> &Address {
        &self.pc
    }

    /// The wrapped execution exception, standing in for Java's `super`.
    pub fn as_execution_exception(&self) -> &PcodeExecutionException {
        &self.inner
    }

    /// Stands in for the inherited `Throwable.getMessage()`.
    pub fn message(&self) -> &str {
        self.inner.message()
    }
}

impl std::fmt::Display for DecodePcodeExecutionException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.inner)
    }
}

impl std::error::Error for DecodePcodeExecutionException {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.inner.source()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    fn pc(offset: i64) -> Address {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0).address(offset)
    }

    #[test]
    fn appends_the_program_counter_when_absent_from_the_message() {
        let e = DecodePcodeExecutionException::new("decode failed", pc(0x1000));
        assert_eq!(e.message(), "decode failed (PC=ram:0x1000)");
        assert_eq!(e.get_program_counter(), &pc(0x1000));
    }

    #[test]
    fn message_containing_pc_marker_is_left_verbatim() {
        // Java: `message.contains("PC=")` is a substring test, not a check that the message
        // mentions *this* `pc` -- so a message that merely contains the literal text "PC=" (here,
        // for an address that has nothing to do with the real `pc` argument) is passed through
        // unmodified, and the real `pc` is dropped from the displayed message even though it is
        // still recorded on the exception.
        let e = DecodePcodeExecutionException::new("already has PC=ram:0xdead in it", pc(0x2000));
        assert_eq!(e.message(), "already has PC=ram:0xdead in it");
        // The real pc is still recoverable, just not reflected in the message.
        assert_eq!(e.get_program_counter(), &pc(0x2000));
    }

    #[test]
    fn bare_pc_marker_with_no_address_still_suppresses_formatting() {
        // An extreme case of the same quirk: the message contains "PC=" as bare text, not even
        // followed by anything resembling an address.
        let e = DecodePcodeExecutionException::new("bogus PC= marker", pc(0x3000));
        assert_eq!(e.message(), "bogus PC= marker");
    }

    #[test]
    fn display_matches_message() {
        let e = DecodePcodeExecutionException::new("bad opcode", pc(0x400));
        assert_eq!(e.to_string(), e.message());
    }

    #[test]
    fn has_no_source() {
        let e = DecodePcodeExecutionException::new("bad opcode", pc(0x400));
        let dyn_err: &dyn std::error::Error = &e;
        assert!(dyn_err.source().is_none());
    }
}

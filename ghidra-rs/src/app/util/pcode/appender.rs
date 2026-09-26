use std::sync::Arc;

use crate::program::model::address::AddressSpace;
use crate::program::model::lang::language::Language;
use crate::program::model::lang::register::Register;

/// An appender to receive formatted p-code ops.
///
/// Java source: `ghidra.app.util.pcode.Appender`.
///
/// Using `AbstractAppender` (not yet ported) is highly recommended, as it makes available
/// methods for displaying elements according to established Ghidra conventions.
///
/// The associated type `Output` is the type of the final formatted result, corresponding to the
/// Java interface's type parameter `T`.
pub trait Appender {
    /// The type of the final formatted output.
    type Output;

    /// Get the language of the p-code being formatted.
    fn get_language(&self) -> Arc<dyn Language>;

    /// Append a line label, usually meant to be on its own line.
    fn append_line_label(&mut self, label: i64) {
        self.append_line_label_ref(label);
    }

    /// Append indentation, usually meant for the beginning of a line.
    fn append_indent(&mut self) {
        self.append_character(' ');
        self.append_character(' ');
    }

    /// Append a reference to the given line label.
    fn append_line_label_ref(&mut self, label: i64);

    /// Append the given opcode.
    fn append_mnemonic(&mut self, opcode: i32);

    /// Append the given userop.
    fn append_userop(&mut self, id: i32);

    /// Append the given varnode in raw form.
    ///
    /// `space` is the address space, `offset` is the offset in the space, and `size` is the
    /// size in bytes.
    fn append_raw_varnode(&mut self, space: &AddressSpace, offset: i64, size: i64);

    /// Append a character.
    ///
    /// NOTE: if extra spacing is desired, esp. surrounding the equals sign, it must be appended
    /// manually.
    fn append_character(&mut self, c: char);

    /// Append an address in word-offcut form.
    ///
    /// `word_offset` is the word offset, and `offcut` is the byte within the word.
    fn append_address_word_offcut(&mut self, word_offset: i64, offcut: i64);

    /// Append a local label, e.g., `instr_next`.
    fn append_label(&mut self, label: &str);

    /// Append a register.
    fn append_register(&mut self, register: &Register);

    /// Append a scalar value.
    fn append_scalar(&mut self, value: i64);

    /// Append an address space.
    fn append_space(&mut self, space: &AddressSpace);

    /// Append a unique variable, given its offset in the unique space.
    fn append_unique(&mut self, offset: i64);

    /// Finish formatting and return the final result.
    fn finish(&mut self) -> Self::Output;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::AddressSpaceType;

    /// A minimal appender that just accumulates a string, mirroring
    /// `AbstractAppender`'s intended usage without depending on the (not yet ported)
    /// `SleighLanguage`.
    struct StringAppender {
        buf: String,
    }

    impl StringAppender {
        fn new() -> Self {
            StringAppender { buf: String::new() }
        }
    }

    impl Appender for StringAppender {
        type Output = String;

        fn get_language(&self) -> Arc<dyn Language> {
            unimplemented!("not exercised by this test")
        }

        fn append_line_label_ref(&mut self, label: i64) {
            self.buf.push_str(&format!("<{}>", label));
        }

        fn append_mnemonic(&mut self, opcode: i32) {
            self.buf.push_str(&format!("op{}", opcode));
        }

        fn append_userop(&mut self, id: i32) {
            self.buf.push_str(&format!("userop{}", id));
        }

        fn append_raw_varnode(&mut self, space: &AddressSpace, offset: i64, size: i64) {
            self.buf
                .push_str(&format!("({}, 0x{:x}, {})", space.name(), offset, size));
        }

        fn append_character(&mut self, c: char) {
            self.buf.push(c);
        }

        fn append_address_word_offcut(&mut self, word_offset: i64, offcut: i64) {
            self.buf.push_str(&format!("0x{:x}.{}", word_offset, offcut));
        }

        fn append_label(&mut self, label: &str) {
            self.buf.push_str(label);
        }

        fn append_register(&mut self, register: &Register) {
            self.buf.push_str(register.name());
        }

        fn append_scalar(&mut self, value: i64) {
            self.buf.push_str(&format!("{}", value));
        }

        fn append_space(&mut self, space: &AddressSpace) {
            self.buf.push_str(space.name());
        }

        fn append_unique(&mut self, offset: i64) {
            self.buf.push_str(&format!("$U{:x}", offset));
        }

        fn finish(&mut self) -> String {
            std::mem::take(&mut self.buf)
        }
    }

    #[test]
    fn test_default_append_indent_appends_two_spaces() {
        let mut appender = StringAppender::new();
        appender.append_indent();
        assert_eq!(appender.finish(), "  ");
    }

    #[test]
    fn test_default_append_line_label_delegates_to_ref() {
        let mut appender = StringAppender::new();
        appender.append_line_label(7);
        assert_eq!(appender.finish(), "<7>");
    }

    #[test]
    fn test_append_space_and_raw_varnode() {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let mut appender = StringAppender::new();
        appender.append_space(&space);
        appender.append_character(' ');
        appender.append_raw_varnode(&space, 0x1000, 4);
        assert_eq!(appender.finish(), "ram (ram, 0x1000, 4)");
    }
}

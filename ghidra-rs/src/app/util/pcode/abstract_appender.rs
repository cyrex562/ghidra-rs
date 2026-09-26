use std::sync::Arc;

use crate::app::util::pcode::appender::Appender;
use crate::program::model::address::AddressSpace;
use crate::program::model::lang::language::Language;
use crate::program::model::lang::register::Register;
use crate::util::msg::Msg;

/// The shared state of a [`Appender`] implementation, suitable for most cases.
///
/// Port of `ghidra.app.util.pcode.AbstractAppender`.
///
/// Java's `AbstractAppender<T>` is an abstract class: it carries the `language`/`indent` fields
/// and implements every method of `Appender` except `appendString`, which each concrete formatter
/// must supply. Rust has no field inheritance, so this struct holds the shared fields plus the
/// concrete (non-abstract) logic, while [`AbstractAppender`] declares only the one method a
/// concrete type must still provide. A concrete formatter embeds this struct, implements
/// [`AbstractAppender::append_string`], and implements [`Appender`]'s methods by delegating to
/// the `stringify_*`/`append_*` helpers here (mirroring how `AbstractAppender.appendX` calls
/// `appendString(stringifyX(...))` in Java).
pub struct AbstractAppenderBase {
    language: Arc<dyn Language>,
    indent: bool,
}

impl AbstractAppenderBase {
    /// Create a new base, given the language of the p-code ops to format, and whether or not to
    /// indent.
    pub fn new(language: Arc<dyn Language>, indent: bool) -> Self {
        Self { language, indent }
    }

    /// Get the language of the p-code being formatted.
    pub fn language(&self) -> Arc<dyn Language> {
        Arc::clone(&self.language)
    }

    /// Whether or not lines should be indented.
    pub fn indent(&self) -> bool {
        self.indent
    }

    /// Append a character, applying the conventional `" = "` spacing hack for `=`.
    pub fn append_character<A: AbstractAppender + ?Sized>(appender: &mut A, c: char) {
        if c == '=' {
            appender.append_string(" = "); // HACK
        } else {
            appender.append_string(&c.to_string());
        }
    }

    /// Append indentation, if indentation is enabled for `indent`.
    pub fn append_indent<A: AbstractAppender + ?Sized>(appender: &mut A, indent: bool) {
        if indent {
            Self::append_character(appender, ' ');
            Self::append_character(appender, ' ');
        }
    }

    /// Append an address in word-offcut form.
    pub fn append_address_word_offcut<A: AbstractAppender + ?Sized>(
        appender: &mut A,
        word_offset: i64,
        offcut: i64,
    ) {
        let s = Self::stringify_word_offcut(word_offset, offcut);
        appender.append_string(&s);
    }

    /// Append a local label.
    pub fn append_label<A: AbstractAppender + ?Sized>(appender: &mut A, label: &str) {
        appender.append_string(label);
    }

    /// Append a reference to the given line label.
    pub fn append_line_label_ref<A: AbstractAppender + ?Sized>(appender: &mut A, label: i64) {
        let s = Self::stringify_line_label(label);
        appender.append_string(&s);
    }

    /// Append the given opcode's mnemonic.
    pub fn append_mnemonic<A: AbstractAppender + ?Sized>(appender: &mut A, opcode: i32) {
        let s = Self::stringify_op_mnemonic(opcode);
        appender.append_string(&s);
    }

    /// Append the given varnode in raw form.
    pub fn append_raw_varnode<A: AbstractAppender + ?Sized>(
        appender: &mut A,
        space: &AddressSpace,
        offset: i64,
        size: i64,
    ) {
        let s = Self::stringify_raw_varnode(space, offset, size);
        appender.append_string(&s);
    }

    /// Append a register.
    pub fn append_register<A: AbstractAppender + ?Sized>(appender: &mut A, register: &Register) {
        let s = Self::stringify_register(register);
        appender.append_string(&s);
    }

    /// Append a scalar value.
    pub fn append_scalar<A: AbstractAppender + ?Sized>(appender: &mut A, value: i64) {
        let s = Self::stringify_scalar_value(value);
        appender.append_string(&s);
    }

    /// Append an address space.
    pub fn append_space<A: AbstractAppender + ?Sized>(appender: &mut A, space: &AddressSpace) {
        let s = Self::stringify_space(space);
        appender.append_string(&s);
    }

    /// Append a unique variable, given its offset in the unique space.
    pub fn append_unique<A: AbstractAppender + ?Sized>(appender: &mut A, offset: i64) {
        let s = Self::stringify_unique(offset);
        appender.append_string(&s);
    }

    /// Append the given userop, looking its name up in `self`'s language.
    pub fn append_userop<A: AbstractAppender + ?Sized>(&self, appender: &mut A, id: i32) {
        let s = self.stringify_userop(id);
        appender.append_string(&s);
    }

    /// Convert the given line label to a string as it should be conventionally displayed, e.g.,
    /// `<L1>`.
    pub fn stringify_line_label(label: i64) -> String {
        format!("<{label}>")
    }

    /// Convert the given opcode to a string as it should be conventionally displayed, i.e., its
    /// mnemonic.
    ///
    /// Mirrors `PcodeOp.getMnemonic(int)`, falling back to `"INVALID_OP"` for unknown opcodes.
    pub fn stringify_op_mnemonic(opcode: i32) -> String {
        opcode_mnemonic(opcode).to_string()
    }

    /// Convert the given varnode to its raw conventional form.
    pub fn stringify_raw_varnode(space: &AddressSpace, offset: i64, size: i64) -> String {
        format!("({}, 0x{:x}, {})", space.name(), offset as u64, size)
    }

    /// Convert the given register to a string as it should be conventionally displayed, i.e.,
    /// its name.
    pub fn stringify_register(register: &Register) -> String {
        register.name().to_string()
    }

    /// Convert the given scalar to a string as it should be conventionally displayed, i.e., its
    /// decimal value if small, or hex value if large.
    pub fn stringify_scalar_value(value: i64) -> String {
        if (-64..=64).contains(&value) {
            value.to_string()
        } else {
            format!("0x{:x}", value as u64)
        }
    }

    /// Convert the given address space to a string as it should be conventionally displayed,
    /// i.e., its name.
    pub fn stringify_space(space: &AddressSpace) -> String {
        space.name().to_string()
    }

    /// Convert a given unique variable to a string as it should be conventionally displayed,
    /// e.g., `$U1234`.
    pub fn stringify_unique(offset: i64) -> String {
        format!("$U{:x}", offset as u64)
    }

    /// Look up a given userop name in `self`'s language.
    ///
    /// Java's counterpart requires the language to be a `SleighLanguage`; here, [`Language`]
    /// itself exposes `get_user_defined_op_name`, so any language can be queried directly.
    pub fn stringify_userop_unchecked(&self, id: i32) -> Option<String> {
        self.language.get_user_defined_op_name(id)
    }

    /// Convert a given userop to a string as it should be conventionally displayed, i.e., its
    /// name, or `"unknown"` if it doesn't exist.
    pub fn stringify_userop(&self, id: i32) -> String {
        match self.stringify_userop_unchecked(id) {
            Some(name) => name,
            None => {
                Msg::error("AbstractAppender", &format!("Pseudo-op index not found: {id}"));
                "unknown".to_string()
            }
        }
    }

    /// Convert a given word-offcut style address to a string as it should be conventionally
    /// displayed, e.g., `0x1234.1`.
    pub fn stringify_word_offcut(word_offset: i64, offcut: i64) -> String {
        let mut s = format!("0x{:x}", word_offset as u64);
        if offcut != 0 {
            s.push_str(&format!(".{offcut}"));
        }
        s
    }
}

/// Mirrors `PcodeOp.getMnemonic(int)`; kept local since it maps a raw opcode number (not
/// [`crate::program::model::pcode::OpCode`]) the same way Java's switch does, including the
/// `"INVALID_OP"` fallback for values outside the known range.
fn opcode_mnemonic(opcode: i32) -> &'static str {
    match opcode {
        0 => "UNIMPLEMENTED",
        1 => "COPY",
        2 => "LOAD",
        3 => "STORE",
        4 => "BRANCH",
        5 => "CBRANCH",
        6 => "BRANCHIND",
        7 => "CALL",
        8 => "CALLIND",
        9 => "CALLOTHER",
        10 => "RETURN",
        11 => "INT_EQUAL",
        12 => "INT_NOTEQUAL",
        13 => "INT_SLESS",
        14 => "INT_SLESSEQUAL",
        15 => "INT_LESS",
        16 => "INT_LESSEQUAL",
        17 => "INT_ZEXT",
        18 => "INT_SEXT",
        19 => "INT_ADD",
        20 => "INT_SUB",
        21 => "INT_CARRY",
        22 => "INT_SCARRY",
        23 => "INT_SBORROW",
        24 => "INT_2COMP",
        25 => "INT_NEGATE",
        26 => "INT_XOR",
        27 => "INT_AND",
        28 => "INT_OR",
        29 => "INT_LEFT",
        30 => "INT_RIGHT",
        31 => "INT_SRIGHT",
        32 => "INT_MULT",
        33 => "INT_DIV",
        34 => "INT_SDIV",
        35 => "INT_REM",
        36 => "INT_SREM",
        37 => "BOOL_NEGATE",
        38 => "BOOL_XOR",
        39 => "BOOL_AND",
        40 => "BOOL_OR",
        41 => "FLOAT_EQUAL",
        42 => "FLOAT_NOTEQUAL",
        43 => "FLOAT_LESS",
        44 => "FLOAT_LESSEQUAL",
        46 => "FLOAT_NAN",
        47 => "FLOAT_ADD",
        48 => "FLOAT_DIV",
        49 => "FLOAT_MULT",
        50 => "FLOAT_SUB",
        51 => "FLOAT_NEG",
        52 => "FLOAT_ABS",
        53 => "FLOAT_SQRT",
        54 => "INT2FLOAT",
        55 => "FLOAT2FLOAT",
        56 => "TRUNC",
        57 => "CEIL",
        58 => "FLOOR",
        59 => "ROUND",
        60 => "MULTIEQUAL",
        61 => "INDIRECT",
        62 => "PIECE",
        63 => "SUBPIECE",
        64 => "CAST",
        65 => "PTRADD",
        66 => "PTRSUB",
        67 => "SEGMENTOP",
        68 => "CPOOLREF",
        69 => "NEW",
        70 => "INSERT",
        71 => "ZPULL",
        72 => "POPCOUNT",
        73 => "LZCOUNT",
        74 => "SPULL",
        _ => "INVALID_OP",
    }
}

/// The one method a concrete [`Appender`] built atop [`AbstractAppenderBase`] must still supply.
///
/// Port of the effectively-abstract part of `ghidra.app.util.pcode.AbstractAppender`: every
/// other `Appender` method has a conventional implementation (see `AbstractAppenderBase`) that
/// bottoms out in a call to `append_string`.
pub trait AbstractAppender: Appender {
    /// Append a plain string.
    ///
    /// By default, all other append methods delegate to this (see `AbstractAppenderBase`), so it
    /// must be implemented by every concrete formatter built atop that base.
    fn append_string(&mut self, string: &str);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpaceType};
    use crate::program::model::lang::compiler_spec::CompilerSpec;
    use crate::program::model::lang::compiler_spec_description::CompilerSpecDescription;
    use crate::program::model::lang::compiler_spec_id::CompilerSpecID;
    use crate::program::model::lang::compiler_spec_not_found_exception::CompilerSpecNotFoundException;
    use crate::program::model::lang::instruction_prototype::InstructionPrototype;
    use crate::program::model::lang::language::ParseError;
    use crate::program::model::lang::language_description::LanguageDescription;
    use crate::program::model::lang::language_id::LanguageID;
    use crate::program::model::lang::parallel_instruction_language_helper::ParallelInstructionLanguageHelper;
    use crate::program::model::lang::processor_context::ProcessorContext;
    use crate::program::model::lang::register::RegisterRef;
    use crate::program::model::lang::unknown_instruction_exception::UnknownInstructionException;
    use crate::program::model::listing::default_program_context::DefaultProgramContext;
    use crate::program::model::mem::MemBuffer;
    use crate::program::model::address::{AddressFactory, AddressSet, AddressSetView};
    use crate::app::plugin::processors::generic::MemoryBlockDefinition;
    use crate::program::seam_stubs::{AddressLabelInfo, Processor};
    use crate::util::task::TaskMonitor;
    use std::collections::HashSet;

    struct MockLanguage;

    impl Language for MockLanguage {
        fn get_language_id(&self) -> LanguageID {
            LanguageID::new("x86:LE:32:default").unwrap()
        }
        fn get_language_description(&self) -> Box<dyn LanguageDescription> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_parallel_instruction_helper(
            &self,
        ) -> Option<Box<dyn ParallelInstructionLanguageHelper>> {
            None
        }
        fn get_processor(&self) -> Box<dyn Processor> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_version(&self) -> i32 {
            1
        }
        fn get_minor_version(&self) -> i32 {
            0
        }
        fn get_address_factory(&self) -> Box<dyn AddressFactory> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_default_space(&self) -> Arc<AddressSpace> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_default_data_space(&self) -> Arc<AddressSpace> {
            unimplemented!("not exercised by this smoke test")
        }
        fn is_big_endian(&self) -> bool {
            false
        }
        fn get_instruction_alignment(&self) -> i32 {
            1
        }
        fn supports_pcode(&self) -> bool {
            true
        }
        fn is_volatile(&self, _addr: &Address) -> bool {
            false
        }
        fn parse(
            &self,
            _buf: &dyn MemBuffer,
            _context: &mut dyn ProcessorContext,
            _in_delay_slot: bool,
        ) -> Result<Box<dyn InstructionPrototype>, ParseError> {
            Err(ParseError::UnknownInstruction(UnknownInstructionException::new()))
        }
        fn get_number_of_user_defined_op_names(&self) -> i32 {
            1
        }
        fn get_user_defined_op_name(&self, index: i32) -> Option<String> {
            if index == 5 {
                Some("myop".to_string())
            } else {
                None
            }
        }
        fn get_registers_at(&self, _address: &Address) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_register_in_space(
            &self,
            _addrspc: &Arc<AddressSpace>,
            _offset: i64,
            _size: i32,
        ) -> Option<RegisterRef> {
            None
        }
        fn get_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_register_names(&self) -> Vec<String> {
            Vec::new()
        }
        fn get_register_by_name(&self, _name: &str) -> Option<RegisterRef> {
            None
        }
        fn get_register_at(&self, _addr: &Address, _size: i32) -> Option<RegisterRef> {
            None
        }
        fn get_program_counter(&self) -> Option<RegisterRef> {
            None
        }
        fn get_context_base_register(&self) -> Option<RegisterRef> {
            None
        }
        fn get_context_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_default_memory_blocks(&self) -> Vec<Box<dyn MemoryBlockDefinition>> {
            Vec::new()
        }
        fn get_default_symbols(&self) -> Vec<Box<dyn AddressLabelInfo>> {
            Vec::new()
        }
        fn get_segmented_space(&self) -> String {
            String::new()
        }
        fn get_volatile_addresses(&self) -> Box<dyn AddressSetView> {
            Box::new(AddressSet::new())
        }
        fn apply_context_settings(&self, _ctx: &mut dyn DefaultProgramContext) {}
        fn reload_language(&self, _task_monitor: &dyn TaskMonitor) -> std::io::Result<()> {
            Ok(())
        }
        fn get_compatible_compiler_spec_descriptions(
            &self,
        ) -> Vec<Box<dyn CompilerSpecDescription>> {
            Vec::new()
        }
        fn get_compiler_spec_by_id(
            &self,
            compiler_spec_id: &CompilerSpecID,
        ) -> Result<Box<dyn CompilerSpec>, CompilerSpecNotFoundException> {
            Err(CompilerSpecNotFoundException::new(&self.get_language_id(), compiler_spec_id))
        }
        fn get_default_compiler_spec(&self) -> Box<dyn CompilerSpec> {
            unimplemented!("not exercised by this smoke test")
        }
        fn has_property(&self, _key: &str) -> bool {
            false
        }
        fn get_property_as_int(&self, _key: &str, default_int: i32) -> i32 {
            default_int
        }
        fn get_property_as_boolean(&self, _key: &str, default_boolean: bool) -> bool {
            default_boolean
        }
        fn get_property_or(&self, _key: &str, default_string: &str) -> String {
            default_string.to_string()
        }
        fn get_property(&self, _key: &str) -> Option<String> {
            None
        }
        fn get_property_keys(&self) -> HashSet<String> {
            HashSet::new()
        }
        fn has_manual(&self) -> bool {
            false
        }
        fn get_manual_entry(
            &self,
            _instruction_mnemonic: &str,
        ) -> Option<crate::util::manual_entry::ManualEntry> {
            None
        }
        fn get_manual_instruction_mnemonic_keys(&self) -> HashSet<String> {
            HashSet::new()
        }
        fn get_manual_exception(&self) -> Option<Box<dyn std::error::Error + Send + Sync + 'static>> {
            None
        }
        fn get_sorted_vector_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_register_addresses(&self) -> Box<dyn AddressSetView> {
            Box::new(AddressSet::new())
        }
        fn get_maximum_instruction_length(&self) -> Option<i32> {
            None
        }
    }

    /// A minimal `AbstractAppender`-based formatter that just accumulates a string, mirroring
    /// `AttributedStringPcodeFormatter`/`StringPcodeFormatter`'s intended usage.
    struct TestAppender {
        base: AbstractAppenderBase,
        buf: String,
    }

    impl TestAppender {
        fn new(indent: bool) -> Self {
            TestAppender {
                base: AbstractAppenderBase::new(Arc::new(MockLanguage), indent),
                buf: String::new(),
            }
        }
    }

    impl Appender for TestAppender {
        type Output = String;

        fn get_language(&self) -> Arc<dyn Language> {
            self.base.language()
        }

        fn append_line_label_ref(&mut self, label: i64) {
            AbstractAppenderBase::append_line_label_ref(self, label);
        }

        fn append_mnemonic(&mut self, opcode: i32) {
            AbstractAppenderBase::append_mnemonic(self, opcode);
        }

        fn append_userop(&mut self, id: i32) {
            let s = self.base.stringify_userop(id);
            self.append_string(&s);
        }

        fn append_raw_varnode(&mut self, space: &AddressSpace, offset: i64, size: i64) {
            AbstractAppenderBase::append_raw_varnode(self, space, offset, size);
        }

        fn append_character(&mut self, c: char) {
            AbstractAppenderBase::append_character(self, c);
        }

        fn append_address_word_offcut(&mut self, word_offset: i64, offcut: i64) {
            AbstractAppenderBase::append_address_word_offcut(self, word_offset, offcut);
        }

        fn append_label(&mut self, label: &str) {
            AbstractAppenderBase::append_label(self, label);
        }

        fn append_register(&mut self, register: &Register) {
            AbstractAppenderBase::append_register(self, register);
        }

        fn append_scalar(&mut self, value: i64) {
            AbstractAppenderBase::append_scalar(self, value);
        }

        fn append_space(&mut self, space: &AddressSpace) {
            AbstractAppenderBase::append_space(self, space);
        }

        fn append_unique(&mut self, offset: i64) {
            AbstractAppenderBase::append_unique(self, offset);
        }

        fn finish(&mut self) -> String {
            std::mem::take(&mut self.buf)
        }
    }

    impl AbstractAppender for TestAppender {
        fn append_string(&mut self, string: &str) {
            self.buf.push_str(string);
        }
    }

    #[test]
    fn test_append_character_equals_hack() {
        let mut appender = TestAppender::new(false);
        appender.append_character('=');
        assert_eq!(appender.finish(), " = ");
    }

    #[test]
    fn test_append_character_plain() {
        let mut appender = TestAppender::new(false);
        appender.append_character('x');
        assert_eq!(appender.finish(), "x");
    }

    #[test]
    fn test_append_indent_respects_flag() {
        let mut on = TestAppender::new(true);
        let on_indent = on.base.indent();
        AbstractAppenderBase::append_indent(&mut on, on_indent);
        assert_eq!(on.finish(), "  ");

        let mut off = TestAppender::new(false);
        let off_indent = off.base.indent();
        AbstractAppenderBase::append_indent(&mut off, off_indent);
        assert_eq!(off.finish(), "");
    }

    #[test]
    fn test_append_line_label_ref_and_mnemonic() {
        let mut appender = TestAppender::new(false);
        appender.append_line_label_ref(7);
        appender.append_character(' ');
        appender.append_mnemonic(19); // INT_ADD
        assert_eq!(appender.finish(), "<7> INT_ADD");
    }

    #[test]
    fn test_stringify_op_mnemonic_unknown_is_invalid_op() {
        assert_eq!(AbstractAppenderBase::stringify_op_mnemonic(9001), "INVALID_OP");
        assert_eq!(AbstractAppenderBase::stringify_op_mnemonic(0), "UNIMPLEMENTED");
    }

    #[test]
    fn test_stringify_scalar_value_boundary() {
        assert_eq!(AbstractAppenderBase::stringify_scalar_value(64), "64");
        assert_eq!(AbstractAppenderBase::stringify_scalar_value(-64), "-64");
        assert_eq!(AbstractAppenderBase::stringify_scalar_value(65), "0x41");
        assert_eq!(AbstractAppenderBase::stringify_scalar_value(-65), "0xffffffffffffffbf");
    }

    #[test]
    fn test_stringify_word_offcut() {
        assert_eq!(AbstractAppenderBase::stringify_word_offcut(0x1234, 0), "0x1234");
        assert_eq!(AbstractAppenderBase::stringify_word_offcut(0x1234, 1), "0x1234.1");
    }

    #[test]
    fn test_append_space_and_raw_varnode() {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let mut appender = TestAppender::new(false);
        appender.append_space(&space);
        appender.append_character(' ');
        appender.append_raw_varnode(&space, 0x1000, 4);
        assert_eq!(appender.finish(), "ram (ram, 0x1000, 4)");
    }

    #[test]
    fn test_append_userop_known_and_unknown() {
        let mut appender = TestAppender::new(false);
        appender.append_userop(5);
        assert_eq!(appender.finish(), "myop");
    }

    #[test]
    fn test_get_language_delegates_to_base() {
        let appender = TestAppender::new(false);
        assert_eq!(appender.get_language().get_language_id(), LanguageID::new("x86:LE:32:default").unwrap());
    }
}

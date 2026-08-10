//! A p-code program to be executed by a [`PcodeExecutor`].
//!
//! Corresponds to `ghidra.pcode.exec.PcodeProgram`.
//!
//! This is a list of p-code operations together with a map of expected userops.
//!
//! # Divergences from Java
//!
//! * **The bound language.** Java's field is a `SleighLanguage` (the
//!   `ghidra.app.plugin.processors.sleigh` implementor of `Language`), used only for formatting and
//!   userop-name lookups -- all of which are declared on `Language` itself. This crate's
//!   [`SleighLanguage`](crate::program::model::lang::sleigh::SleighLanguage) is a partial,
//!   `.sla`-only port that does not implement [`Language`], so, exactly as documented on
//!   [`PcodeExecutor`], this binds to `Arc<dyn Language>` instead. Consequently
//!   [`from_instruction`](PcodeProgram::from_instruction) drops Java's `instanceof SleighLanguage`
//!   runtime check (there is nothing in this crate to downcast to), taking whatever language the
//!   instruction's prototype reports.
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use crate::app::util::pcode::abstract_appender::{AbstractAppender, AbstractAppenderBase};
use crate::app::util::pcode::abstract_pcode_formatter::{
    is_line_label, AbstractPcodeFormatter, FormatResult,
};
use crate::app::util::pcode::appender::Appender;
use crate::app::util::pcode::pcode_formatter::PcodeFormatter;
use crate::decompiler::slghsymbol::user_op_symbol::UserOpSymbol;
use crate::pcode::exec::pcode_executor::PcodeExecutor;
use crate::pcode::exec::pcode_userop_library::PcodeUseropLibrary;
use crate::program::model::address::AddressSpace;
use crate::program::model::lang::inject_payload::InjectPayloadError;
use crate::program::model::lang::language::Language;
use crate::program::model::lang::register::Register;
use crate::program::model::lang::sleigh::template::OpTpl;
use crate::program::model::listing::instruction::Instruction;
use crate::program::model::listing::program::Program;
use crate::program::model::pcode::PcodeOp;
use crate::util::exception::NotFoundException;
use crate::util::msg::Msg;

/// A p-code program to be executed by a [`PcodeExecutor`].
pub struct PcodeProgram {
    language: Arc<dyn Language>,
    code: Vec<PcodeOp>,
    userop_names: HashMap<i32, String>,
}

impl PcodeProgram {
    /// Construct a p-code program with the given bindings.
    ///
    /// Port of the protected `PcodeProgram(SleighLanguage, List<PcodeOp>, Map<Integer,
    /// UserOpSymbol>)`. `userop_symbols` names userops beyond those the language itself declares;
    /// for indices the language already knows, the language's own name wins (mirroring Java, which
    /// looks the name up by index rather than trusting the symbol).
    pub(crate) fn new(
        language: Arc<dyn Language>,
        code: Vec<PcodeOp>,
        userop_symbols: HashMap<i32, UserOpSymbol>,
    ) -> Self {
        let lang_op_count = language.get_number_of_user_defined_op_names();
        let mut userop_names = HashMap::new();
        for (index, symbol) in userop_symbols {
            if index < lang_op_count {
                if let Some(name) = language.get_user_defined_op_name(index) {
                    userop_names.insert(index, name);
                }
            } else {
                userop_names.insert(index, symbol.symbol().name().to_string());
            }
        }
        PcodeProgram { language, code, userop_names }
    }

    /// Construct a p-code program from a derivative of the given one.
    ///
    /// `code` must not be empty. Port of `PcodeProgram(PcodeProgram, List<PcodeOp>)`.
    pub fn from_program(program: &PcodeProgram, code: Vec<PcodeOp>) -> Self {
        debug_assert!(!code.is_empty());
        PcodeProgram {
            language: Arc::clone(&program.language),
            code,
            userop_names: program.userop_names.clone(),
        }
    }

    /// Generate a p-code program from the given instruction, without overrides.
    ///
    /// Port of `fromInstruction(Instruction)`.
    pub fn from_instruction(instruction: &dyn Instruction) -> Self {
        Self::from_instruction_with_overrides(instruction, false)
    }

    /// Generate a p-code program from the given instruction.
    ///
    /// `include_overrides` is as in [`Instruction::get_pcode_with_overrides`]. Port of
    /// `fromInstruction(Instruction, boolean)`.
    pub fn from_instruction_with_overrides(
        instruction: &dyn Instruction,
        include_overrides: bool,
    ) -> Self {
        let language = instruction.get_prototype().get_language();
        let code = instruction.get_pcode_with_overrides(include_overrides);
        Self::new(language, code, HashMap::new())
    }

    /// Generate a p-code program from a given program's inject library.
    ///
    /// `name` is the name of the snippet and `inject_type` its type. Port of `fromInject(Program,
    /// String, int)`.
    ///
    /// # Panics
    ///
    /// If `program` has no compiler spec or no language, mirroring the `NullPointerException` Java
    /// would raise for the same missing architecture.
    pub fn from_inject(
        program: &dyn Program,
        name: &str,
        inject_type: i32,
    ) -> Result<Self, InjectPayloadError> {
        let compiler_spec =
            program.get_compiler_spec().expect("program has no compiler spec");
        let library = compiler_spec.get_pcode_inject_library();
        let ctx = library.build_inject_context();
        let payload = library.get_payload(inject_type, name).ok_or_else(|| {
            InjectPayloadError::NotFound(NotFoundException::with_message(format!(
                "no such inject payload: {name}"
            )))
        })?;
        let pcode = payload.get_pcode(program, ctx.as_ref())?;
        let language = program.get_language().expect("program has no language");
        Ok(Self::new(language, pcode, HashMap::new()))
    }

    /// Get the language generating this program.
    ///
    /// Port of `getLanguage()`.
    pub fn get_language(&self) -> Arc<dyn Language> {
        Arc::clone(&self.language)
    }

    /// Get the p-code ops comprising this program.
    ///
    /// Port of `getCode()`.
    pub fn code(&self) -> &[PcodeOp] {
        &self.code
    }

    /// Get the map of userop numbers to names, beyond those the language itself declares.
    ///
    /// Java exposes these only indirectly, through [`get_userop_name`](Self::get_userop_name); a
    /// direct accessor is needed by [`PcodeExecutor`], which (like Java's package-private field
    /// access) reads the map to build a [`PcodeFrame`](crate::pcode::exec::pcode_frame::PcodeFrame).
    pub fn userop_names(&self) -> &HashMap<i32, String> {
        &self.userop_names
    }

    /// Execute this program using the given executor and library.
    ///
    /// Port of `<T> void execute(PcodeExecutor<T>, PcodeUseropLibrary<T>)`. Java declares this
    /// `void` and lets any `PcodeExecutionException` propagate as unchecked; the nearest Rust
    /// equivalent is to panic, matching
    /// [`AbstractSleighPcodeUseropDefinitionBase::execute`](crate::pcode::exec::abstract_sleigh_pcode_userop_definition::AbstractSleighPcodeUseropDefinitionBase::execute),
    /// which faces the same situation.
    pub fn execute<T: 'static>(
        &self,
        executor: &PcodeExecutor<T>,
        library: &dyn PcodeUseropLibrary<T>,
    ) {
        if let Err(e) = executor.execute(self, library) {
            panic!("PcodeProgram execution failed: {}", e.message());
        }
    }

    /// For display purposes, get the header above the frame, usually the class name.
    ///
    /// Port of `getHead()`, which is Java's `getClass().getSimpleName()`. This crate has no
    /// reflection and no subclasses of `PcodeProgram` yet, so the name is fixed.
    fn get_head(&self) -> &'static str {
        "PcodeProgram"
    }

    /// Format this program's p-code ops, optionally numbering each with its op index and sequence
    /// number.
    ///
    /// Port of `format(boolean)`; Java's no-arg `format()` (`format(false)`) and `toString()`
    /// (`format()`) are covered by this crate's [`Display`](fmt::Display) impl instead of a second
    /// method, since Rust has no overloading.
    pub fn format(&self, number_ops: bool) -> String {
        let formatter = ProgramFormatter { program: self, number_ops };
        formatter.format_ops(self.language.as_ref(), &self.code)
    }

    /// Get the name of the userop for the given number, as expressed in the Sleigh source.
    ///
    /// Port of `getUseropName(int)`.
    pub fn get_userop_name(&self, op_no: i32) -> Option<String> {
        if op_no < self.language.get_number_of_user_defined_op_names() {
            return self.language.get_user_defined_op_name(op_no);
        }
        self.userop_names.get(&op_no).cloned()
    }

    /// For testing/debug only: get the userop number for a given name.
    ///
    /// There is no index by name, so this exhaustively searches the language- and library-defined
    /// userops. Port of `getUseropNumber(String)`.
    pub fn get_userop_number(&self, name: &str) -> i32 {
        for i in 0..self.language.get_number_of_user_defined_op_names() {
            if self.language.get_user_defined_op_name(i).as_deref() == Some(name) {
                return i;
            }
        }
        for (&index, op_name) in &self.userop_names {
            if op_name == name {
                return index;
            }
        }
        -1
    }
}

impl fmt::Display for PcodeProgram {
    /// Port of `toString()`, which formats the program's ops with its private `MyFormatter`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.format(false))
    }
}

/// Port of `PcodeProgram.MyAppender`, an `AbstractAppender<String>` that optionally numbers each
/// op with its index and sequence number.
struct ProgramAppender<'a> {
    base: AbstractAppenderBase,
    program: &'a PcodeProgram,
    number_ops: bool,
    buf: String,
    op_idx: i32,
}

impl<'a> ProgramAppender<'a> {
    fn new(program: &'a PcodeProgram, language: Arc<dyn Language>, number_ops: bool) -> Self {
        let mut buf = String::new();
        buf.push('<');
        buf.push_str(program.get_head());
        buf.push_str(":\n");
        ProgramAppender {
            base: AbstractAppenderBase::new(language, true),
            program,
            number_ops,
            buf,
            op_idx: 0,
        }
    }

    /// Port of `MyAppender.stringifyUseropUnchecked`, which falls back to the program's own
    /// userop names when the language doesn't know the id.
    fn stringify_userop_unchecked(&self, id: i32) -> Option<String> {
        self.base
            .stringify_userop_unchecked(id)
            .or_else(|| self.program.userop_names.get(&id).cloned())
    }
}

impl Appender for ProgramAppender<'_> {
    type Output = String;

    fn get_language(&self) -> Arc<dyn Language> {
        self.base.language()
    }

    fn append_indent(&mut self) {
        AbstractAppenderBase::append_indent(self, self.base.indent());
        if self.number_ops {
            let op = &self.program.code[self.op_idx as usize];
            self.buf.push_str(&self.op_idx.to_string());
            self.op_idx += 1;
            self.buf.push(',');
            self.buf.push_str(&op.seqnum.pc.to_string());
            self.buf.push('.');
            self.buf.push_str(&op.seqnum.uniq.to_string());
            self.buf.push_str(": ");
        }
    }

    fn append_line_label_ref(&mut self, label: i64) {
        AbstractAppenderBase::append_line_label_ref(self, label);
    }

    fn append_mnemonic(&mut self, opcode: i32) {
        AbstractAppenderBase::append_mnemonic(self, opcode);
    }

    fn append_userop(&mut self, id: i32) {
        let name = match self.stringify_userop_unchecked(id) {
            Some(name) => name,
            None => {
                Msg::error("PcodeProgram", &format!("Pseudo-op index not found: {id}"));
                "unknown".to_string()
            }
        };
        self.append_string(&name);
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
        self.buf.push('>');
        std::mem::take(&mut self.buf)
    }
}

impl AbstractAppender for ProgramAppender<'_> {
    fn append_string(&mut self, string: &str) {
        self.buf.push_str(string);
    }
}

/// Port of `PcodeProgram.MyFormatter`.
struct ProgramFormatter<'a> {
    program: &'a PcodeProgram,
    number_ops: bool,
}

impl<'a> AbstractPcodeFormatter for ProgramFormatter<'a> {
    type Appender = ProgramAppender<'a>;

    fn create_appender(&self, language: Arc<dyn Language>, _indent: bool) -> ProgramAppender<'a> {
        ProgramAppender::new(self.program, language, self.number_ops)
    }

    /// Java overrides `formatOpTemplate` to call `super` and then end the line. Rust can't call a
    /// trait's default method body from an override, so the wrapping happens in the loop instead,
    /// exactly as [`PcodeFrame`](crate::pcode::exec::pcode_frame::PcodeFrame)'s own formatter does;
    /// the observable order -- format, end line, then honour `Terminate` -- is identical.
    fn format_op_templates(
        &self,
        language: Arc<dyn Language>,
        pcode_op_templates: &[OpTpl],
    ) -> String {
        let indent = pcode_op_templates.iter().any(is_line_label);
        let mut appender = self.create_appender(language, indent);

        for template in pcode_op_templates {
            let result = self.format_op_template(&mut appender, template);
            appender.end_line();
            if result == FormatResult::Terminate {
                break;
            }
        }
        appender.finish()
    }
}

impl ProgramAppender<'_> {
    /// Port of `MyAppender.endLine()`.
    fn end_line(&mut self) {
        self.buf.push('\n');
    }
}

impl PcodeFormatter<String> for ProgramFormatter<'_> {
    fn format_templates(&self, _language: &dyn Language, pcode_op_templates: &[OpTpl]) -> String {
        // The appender needs an owned `Arc<dyn Language>`, which the program already holds; it is
        // the same language `format_ops` was handed.
        self.format_op_templates(Arc::clone(&self.program.language), pcode_op_templates)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::plugin::processors::generic::MemoryBlockDefinition;
    use crate::program::model::address::{
        Address, AddressFactory, AddressSet, AddressSetView, AddressSpaceType,
        DefaultAddressFactory,
    };
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
    use crate::program::model::pcode::{OpCode, SequenceNumber, Varnode};
    use crate::program::seam_stubs::{AddressLabelInfo, Processor};
    use crate::util::task::TaskMonitor;
    use std::collections::HashSet;

    struct Spaces {
        ram: Arc<AddressSpace>,
        constant: Arc<AddressSpace>,
    }

    fn spaces() -> Spaces {
        Spaces {
            ram: AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0),
            constant: AddressSpace::new("const", 64, 1, AddressSpaceType::Constant, 1),
        }
    }

    /// A language that knows one op name (index 0), mirroring the fixture used by
    /// [`pcode_frame`](crate::pcode::exec::pcode_frame)'s own tests.
    struct MockLanguage {
        factory: DefaultAddressFactory,
    }

    impl MockLanguage {
        fn new(spaces: &Spaces) -> Self {
            MockLanguage {
                factory: DefaultAddressFactory::new(vec![spaces.ram.clone(), spaces.constant.clone()]),
            }
        }
    }

    impl Language for MockLanguage {
        fn get_language_id(&self) -> LanguageID {
            LanguageID::new("x86:LE:32:default").unwrap()
        }
        fn get_language_description(&self) -> Box<dyn LanguageDescription> {
            unimplemented!("not exercised by these tests")
        }
        fn get_parallel_instruction_helper(
            &self,
        ) -> Option<Box<dyn ParallelInstructionLanguageHelper>> {
            None
        }
        fn get_processor(&self) -> Box<dyn Processor> {
            unimplemented!("not exercised by these tests")
        }
        fn get_version(&self) -> i32 {
            1
        }
        fn get_minor_version(&self) -> i32 {
            0
        }
        fn get_address_factory(&self) -> Box<dyn AddressFactory> {
            Box::new(self.factory.clone())
        }
        fn get_default_space(&self) -> Arc<AddressSpace> {
            self.factory.get_default_address_space().unwrap()
        }
        fn get_default_data_space(&self) -> Arc<AddressSpace> {
            self.get_default_space()
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
            if index == 0 {
                Some("lang_op".to_string())
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
            unimplemented!("not exercised by these tests")
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

    /// `r0 = COPY r1`, in terms of two RAM locations (the mock language has no registers).
    fn copy_op(s: &Spaces, at: i64) -> PcodeOp {
        PcodeOp::new(
            OpCode::Copy,
            SequenceNumber::new(Address::new(s.ram.clone(), at), 0),
            vec![Varnode::new(Address::new(s.ram.clone(), 0x10), 1)],
            Some(Varnode::new(Address::new(s.ram.clone(), 0x14), 1)),
        )
    }

    fn program(s: &Spaces, code: Vec<PcodeOp>, userops: HashMap<i32, String>) -> PcodeProgram {
        PcodeProgram {
            language: Arc::new(MockLanguage::new(s)),
            code,
            userop_names: userops,
        }
    }

    #[test]
    fn code_and_language_return_what_was_given() {
        let s = spaces();
        let code = vec![copy_op(&s, 0x1000)];
        let p = program(&s, code.clone(), HashMap::new());

        assert_eq!(p.code(), code.as_slice());
        assert_eq!(p.get_language().get_language_id(), LanguageID::new("x86:LE:32:default").unwrap());
    }

    #[test]
    fn from_program_copies_language_and_useropnames_but_replaces_code() {
        let s = spaces();
        let original = program(
            &s,
            vec![copy_op(&s, 0x1000)],
            HashMap::from([(7, "frame_op".to_string())]),
        );
        let new_code = vec![copy_op(&s, 0x2000)];

        let derived = PcodeProgram::from_program(&original, new_code.clone());

        assert_eq!(derived.code(), new_code.as_slice());
        assert_eq!(derived.get_userop_name(7), Some("frame_op".to_string()));
    }

    #[test]
    fn get_userop_name_prefers_the_language_within_its_count() {
        let s = spaces();
        // Index 0 is known to the language ("lang_op"); the program's own map disagrees, but the
        // language wins because 0 < getNumberOfUserDefinedOpNames().
        let p = program(&s, Vec::new(), HashMap::from([(0, "program_op".to_string())]));

        assert_eq!(p.get_userop_name(0), Some("lang_op".to_string()));
        assert_eq!(p.get_userop_name(1), None);

        let p2 = program(&s, Vec::new(), HashMap::from([(3, "extra_op".to_string())]));
        assert_eq!(p2.get_userop_name(3), Some("extra_op".to_string()));
    }

    #[test]
    fn get_userop_number_searches_language_then_program_map() {
        let s = spaces();
        let p = program(&s, Vec::new(), HashMap::from([(5, "extra_op".to_string())]));

        assert_eq!(p.get_userop_number("lang_op"), 0);
        assert_eq!(p.get_userop_number("extra_op"), 5);
        assert_eq!(p.get_userop_number("nonexistent"), -1);
    }

    #[test]
    fn to_string_formats_ops_like_java() {
        let s = spaces();
        let p = program(&s, vec![copy_op(&s, 0x1000)], HashMap::new());

        assert_eq!(
            p.to_string(),
            "<PcodeProgram:\n  *[ram]0x14:1 = COPY *[ram]0x10:1\n>"
        );
    }

    #[test]
    fn format_numbered_includes_op_index_and_sequence_number() {
        let s = spaces();
        let p = program(
            &s,
            vec![copy_op(&s, 0x1000), copy_op(&s, 0x1004)],
            HashMap::new(),
        );

        assert_eq!(
            p.format(true),
            concat!(
                "<PcodeProgram:\n",
                "  0,ram:0x1000.0: *[ram]0x14:1 = COPY *[ram]0x10:1\n",
                "  1,ram:0x1004.0: *[ram]0x14:1 = COPY *[ram]0x10:1\n",
                ">"
            )
        );
    }

    #[test]
    fn to_string_resolves_callother_via_the_program_userop_map() {
        let s = spaces();
        let callother = PcodeOp::new(
            OpCode::CallOther,
            SequenceNumber::new(Address::new(s.ram.clone(), 0x1000), 0),
            vec![Varnode::new(Address::new(s.constant.clone(), 7), 4)],
            None,
        );
        let p = program(&s, vec![callother], HashMap::from([(7, "program_op".to_string())]));

        // Userop 7 is unknown to the language, so the name comes from the program's own map.
        assert_eq!(p.to_string(), "<PcodeProgram:\n  CALLOTHER \"program_op\"\n>");
    }
}

/// Test-only helper shared by other modules that need an opaque, never-formatted `PcodeProgram`
/// (e.g. as a placeholder return value in a test double), so each doesn't have to hand-roll its
/// own throwaway [`Language`] implementation.
#[cfg(test)]
pub(crate) mod testing {
    use super::*;

    /// A [`Language`] whose methods are never meant to be called: it exists only so a
    /// [`PcodeProgram`] can be constructed for identity/presence checks in tests that never
    /// format or otherwise inspect the program's content.
    pub(crate) struct NullLanguage;

    impl Language for NullLanguage {
        fn get_language_id(&self) -> crate::program::model::lang::language_id::LanguageID {
            unimplemented!("NullLanguage is not meant to be called")
        }
        fn get_language_description(
            &self,
        ) -> Box<dyn crate::program::model::lang::language_description::LanguageDescription> {
            unimplemented!("NullLanguage is not meant to be called")
        }
        fn get_parallel_instruction_helper(
            &self,
        ) -> Option<
            Box<
                dyn crate::program::model::lang::parallel_instruction_language_helper::ParallelInstructionLanguageHelper,
            >,
        > {
            unimplemented!("NullLanguage is not meant to be called")
        }
        fn get_processor(&self) -> Box<dyn crate::program::seam_stubs::Processor> {
            unimplemented!("NullLanguage is not meant to be called")
        }
        fn get_version(&self) -> i32 {
            unimplemented!("NullLanguage is not meant to be called")
        }
        fn get_minor_version(&self) -> i32 {
            unimplemented!("NullLanguage is not meant to be called")
        }
        fn get_address_factory(&self) -> Box<dyn crate::program::model::address::AddressFactory> {
            unimplemented!("NullLanguage is not meant to be called")
        }
        fn get_default_space(&self) -> Arc<AddressSpace> {
            unimplemented!("NullLanguage is not meant to be called")
        }
        fn get_default_data_space(&self) -> Arc<AddressSpace> {
            unimplemented!("NullLanguage is not meant to be called")
        }
        fn is_big_endian(&self) -> bool {
            unimplemented!("NullLanguage is not meant to be called")
        }
        fn get_instruction_alignment(&self) -> i32 {
            unimplemented!("NullLanguage is not meant to be called")
        }
        fn supports_pcode(&self) -> bool {
            unimplemented!("NullLanguage is not meant to be called")
        }
        fn is_volatile(&self, _addr: &crate::program::model::address::Address) -> bool {
            unimplemented!("NullLanguage is not meant to be called")
        }
        fn parse(
            &self,
            _buf: &dyn crate::program::model::mem::MemBuffer,
            _context: &mut dyn crate::program::model::lang::processor_context::ProcessorContext,
            _in_delay_slot: bool,
        ) -> Result<
            Box<dyn crate::program::model::lang::instruction_prototype::InstructionPrototype>,
            crate::program::model::lang::language::ParseError,
        > {
            unimplemented!("NullLanguage is not meant to be called")
        }
        fn get_number_of_user_defined_op_names(&self) -> i32 {
            // `PcodeProgram::new` always calls this while resolving userop names, even for an
            // empty userop map, so it must not panic.
            0
        }
        fn get_user_defined_op_name(&self, _index: i32) -> Option<String> {
            unimplemented!("NullLanguage is not meant to be called")
        }
        fn get_registers_at(
            &self,
            _address: &crate::program::model::address::Address,
        ) -> Vec<crate::program::model::lang::register::RegisterRef> {
            unimplemented!("NullLanguage is not meant to be called")
        }
        fn get_register_in_space(
            &self,
            _addrspc: &Arc<AddressSpace>,
            _offset: i64,
            _size: i32,
        ) -> Option<crate::program::model::lang::register::RegisterRef> {
            unimplemented!("NullLanguage is not meant to be called")
        }
        fn get_registers(&self) -> Vec<crate::program::model::lang::register::RegisterRef> {
            unimplemented!("NullLanguage is not meant to be called")
        }
        fn get_register_names(&self) -> Vec<String> {
            unimplemented!("NullLanguage is not meant to be called")
        }
        fn get_register_by_name(
            &self,
            _name: &str,
        ) -> Option<crate::program::model::lang::register::RegisterRef> {
            unimplemented!("NullLanguage is not meant to be called")
        }
        fn get_register_at(
            &self,
            _addr: &crate::program::model::address::Address,
            _size: i32,
        ) -> Option<crate::program::model::lang::register::RegisterRef> {
            unimplemented!("NullLanguage is not meant to be called")
        }
        fn get_program_counter(&self) -> Option<crate::program::model::lang::register::RegisterRef> {
            unimplemented!("NullLanguage is not meant to be called")
        }
        fn get_context_base_register(
            &self,
        ) -> Option<crate::program::model::lang::register::RegisterRef> {
            unimplemented!("NullLanguage is not meant to be called")
        }
        fn get_context_registers(&self) -> Vec<crate::program::model::lang::register::RegisterRef> {
            unimplemented!("NullLanguage is not meant to be called")
        }
        fn get_default_memory_blocks(
            &self,
        ) -> Vec<Box<dyn crate::app::plugin::processors::generic::MemoryBlockDefinition>> {
            unimplemented!("NullLanguage is not meant to be called")
        }
        fn get_default_symbols(&self) -> Vec<Box<dyn crate::program::seam_stubs::AddressLabelInfo>> {
            unimplemented!("NullLanguage is not meant to be called")
        }
        fn get_segmented_space(&self) -> String {
            unimplemented!("NullLanguage is not meant to be called")
        }
        fn get_volatile_addresses(
            &self,
        ) -> Box<dyn crate::program::model::address::AddressSetView> {
            unimplemented!("NullLanguage is not meant to be called")
        }
        fn apply_context_settings(
            &self,
            _ctx: &mut dyn crate::program::model::listing::default_program_context::DefaultProgramContext,
        ) {
            unimplemented!("NullLanguage is not meant to be called")
        }
        fn reload_language(&self, _task_monitor: &dyn crate::util::task::TaskMonitor) -> std::io::Result<()> {
            unimplemented!("NullLanguage is not meant to be called")
        }
        fn get_compatible_compiler_spec_descriptions(
            &self,
        ) -> Vec<Box<dyn crate::program::model::lang::compiler_spec_description::CompilerSpecDescription>>
        {
            unimplemented!("NullLanguage is not meant to be called")
        }
        fn get_compiler_spec_by_id(
            &self,
            _compiler_spec_id: &crate::program::model::lang::compiler_spec_id::CompilerSpecID,
        ) -> Result<
            Box<dyn crate::program::model::lang::compiler_spec::CompilerSpec>,
            crate::program::model::lang::compiler_spec_not_found_exception::CompilerSpecNotFoundException,
        > {
            unimplemented!("NullLanguage is not meant to be called")
        }
        fn get_default_compiler_spec(
            &self,
        ) -> Box<dyn crate::program::model::lang::compiler_spec::CompilerSpec> {
            unimplemented!("NullLanguage is not meant to be called")
        }
        fn has_property(&self, _key: &str) -> bool {
            unimplemented!("NullLanguage is not meant to be called")
        }
        fn get_property_as_int(&self, _key: &str, _default_int: i32) -> i32 {
            unimplemented!("NullLanguage is not meant to be called")
        }
        fn get_property_as_boolean(&self, _key: &str, _default_boolean: bool) -> bool {
            unimplemented!("NullLanguage is not meant to be called")
        }
        fn get_property_or(&self, _key: &str, _default_string: &str) -> String {
            unimplemented!("NullLanguage is not meant to be called")
        }
        fn get_property(&self, _key: &str) -> Option<String> {
            unimplemented!("NullLanguage is not meant to be called")
        }
        fn get_property_keys(&self) -> std::collections::HashSet<String> {
            unimplemented!("NullLanguage is not meant to be called")
        }
        fn has_manual(&self) -> bool {
            unimplemented!("NullLanguage is not meant to be called")
        }
        fn get_manual_entry(
            &self,
            _instruction_mnemonic: &str,
        ) -> Option<crate::util::manual_entry::ManualEntry> {
            unimplemented!("NullLanguage is not meant to be called")
        }
        fn get_manual_instruction_mnemonic_keys(&self) -> std::collections::HashSet<String> {
            unimplemented!("NullLanguage is not meant to be called")
        }
        fn get_manual_exception(&self) -> Option<Box<dyn std::error::Error + Send + Sync + 'static>> {
            unimplemented!("NullLanguage is not meant to be called")
        }
        fn get_sorted_vector_registers(&self) -> Vec<crate::program::model::lang::register::RegisterRef> {
            unimplemented!("NullLanguage is not meant to be called")
        }
        fn get_register_addresses(&self) -> Box<dyn crate::program::model::address::AddressSetView> {
            unimplemented!("NullLanguage is not meant to be called")
        }
        fn get_maximum_instruction_length(&self) -> Option<i32> {
            unimplemented!("NullLanguage is not meant to be called")
        }
    }

    /// A [`PcodeProgram`] with no ops and no userops, backed by [`NullLanguage`]. Suitable only
    /// as an opaque placeholder value in tests that check presence/absence, not content.
    pub(crate) fn empty_program() -> PcodeProgram {
        PcodeProgram::new(Arc::new(NullLanguage), Vec::new(), HashMap::new())
    }
}

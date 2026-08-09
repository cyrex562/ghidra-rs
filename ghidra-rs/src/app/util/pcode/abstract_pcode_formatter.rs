use std::sync::Arc;

use crate::app::util::pcode::appender::Appender;
use crate::decompiler::opcodes::OpCode;
use crate::program::model::address::{AddressSpace, AddressSpaceType};
use crate::program::model::lang::language::Language;
use crate::program::model::lang::sleigh::template::{ConstTpl, ConstTplType, OpTpl, VarnodeTpl};
use crate::util::msg::Msg;

/// Mirrors `PcodeOp.PCODE_MAX`: one past the largest valid p-code opcode number.
const PCODE_MAX: i32 = 75;

/// A result instructing the formatter whether or not to continue.
///
/// Port of `AbstractPcodeFormatter.FormatResult`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatResult {
    Continue,
    Terminate,
}

/// An abstract p-code formatter which can take a list of p-code op templates and consistently
/// format them.
///
/// Port of `ghidra.app.util.pcode.AbstractPcodeFormatter`.
///
/// The general pattern is to implement this trait alongside an [`Appender`] (usually built on
/// [`AbstractAppenderBase`](super::abstract_appender::AbstractAppenderBase)). In most cases it is
/// only necessary to override [`format_op_template`](Self::format_op_template); otherwise, most
/// formatting logic is implemented by the appender.
///
/// Java's `AbstractPcodeFormatter<T, A extends Appender<T>>` is an abstract class, but -- unlike
/// most -- it declares no instance fields: it is pure behaviour. So there is no shared state for a
/// companion base struct to hold, and every concrete (non-abstract) Java method maps directly to a
/// provided method here, which an implementor may override exactly as a Java subclass would. The
/// Java type parameters `T` and `A` become the associated type [`Appender`](Self::Appender) and its
/// [`Appender::Output`].
///
/// Java's `implements PcodeFormatter<T>` cannot be expressed on a Rust trait; concrete formatters
/// implement [`PcodeFormatter`](super::pcode_formatter::PcodeFormatter) themselves and delegate
/// `format_templates` to [`format_op_templates`](Self::format_op_templates). (The two differ in one
/// respect: creating an appender needs an owned `Arc<dyn Language>`, since
/// [`Appender::get_language`] hands one back, whereas `PcodeFormatter::format_templates` only
/// borrows the language.)
pub trait AbstractPcodeFormatter {
    /// The appender this formatter creates, corresponding to Java's type parameter `A`.
    type Appender: Appender;

    /// Create the appender for a formatting invocation.
    ///
    /// `language` is the language of the p-code to format, and `indent` indicates whether each
    /// line should be indented to accommodate line labels.
    fn create_appender(&self, language: Arc<dyn Language>, indent: bool) -> Self::Appender;

    /// Check if this formatter is configured to display raw p-code.
    fn is_format_raw(&self) -> bool {
        false
    }

    /// Format the given p-code op templates.
    ///
    /// Port of `AbstractPcodeFormatter.formatTemplates(Language, List<OpTpl>)`, which is that
    /// class's implementation of `PcodeFormatter.formatTemplates`.
    fn format_op_templates(
        &self,
        language: Arc<dyn Language>,
        pcode_op_templates: &[OpTpl],
    ) -> <Self::Appender as Appender>::Output {
        let indent = has_label(pcode_op_templates);
        let mut appender = self.create_appender(language, indent);

        for template in pcode_op_templates {
            if self.format_op_template(&mut appender, template) == FormatResult::Terminate {
                break;
            }
        }
        appender.finish()
    }

    /// Format a single op template.
    ///
    /// The loop in [`format_op_templates`](Self::format_op_templates) is terminated if this
    /// returns [`FormatResult::Terminate`].
    fn format_op_template(&self, appender: &mut Self::Appender, op: &OpTpl) -> FormatResult {
        let opcode = op.opc as i32;
        if op.opc == OpCode::CpuiPtradd {
            appender.append_line_label(op.input[0].offset.value_real as i64);
            return FormatResult::Continue;
        }

        appender.append_indent();

        if opcode >= PCODE_MAX {
            panic!("Unsupported opcode encountered: {opcode}");
        }
        if let Some(output) = &op.output {
            self.format_output(appender, opcode, output);
            appender.append_character('=');
        }
        appender.append_mnemonic(opcode);

        let inputs = &op.input;
        // Java advances the index inside the loop body for LOAD/STORE, so this is a `while`.
        let mut i = 0usize;
        while i < inputs.len() {
            if i > 0 {
                appender.append_character(',');
            }
            appender.append_character(' ');
            if i == 0 {
                if !self.is_format_raw() {
                    if op.opc == OpCode::CpuiLoad || op.opc == OpCode::CpuiStore {
                        self.format_memory_input(appender, &inputs[0], &inputs[1]);
                        i += 2;
                        continue;
                    }
                    if op.opc == OpCode::CpuiCallother {
                        self.format_call_other_name(appender, &inputs[0]);
                        i += 1;
                        continue;
                    }
                }
                if op.opc == OpCode::CpuiBranch || op.opc == OpCode::CpuiCbranch {
                    if self.format_label_input(appender, &inputs[i]) {
                        i += 1;
                        continue;
                    }
                }
            }
            self.format_input(appender, opcode, i as i32, &inputs[i]);
            i += 1;
        }
        FormatResult::Continue
    }

    /// Format an output varnode.
    fn format_output(&self, appender: &mut Self::Appender, opcode: i32, output: &VarnodeTpl) {
        self.format_varnode(appender, opcode, -1, output);
    }

    /// Format an input varnode, given the operand's index.
    fn format_input(
        &self,
        appender: &mut Self::Appender,
        opcode: i32,
        op_index: i32,
        input: &VarnodeTpl,
    ) {
        self.format_varnode(appender, opcode, op_index, input);
    }

    /// Format a varnode. `op_index` is -1 for the output, 0 for the first input.
    fn format_varnode(
        &self,
        appender: &mut Self::Appender,
        _opcode: i32,
        _op_index: i32,
        v_tpl: &VarnodeTpl,
    ) {
        let space = &v_tpl.space;
        let offset = &v_tpl.offset;
        let size = &v_tpl.size;

        match space.tp {
            ConstTplType::JCurSpace => match offset.tp {
                ConstTplType::JStart => appender.append_label("inst_start"),
                ConstTplType::JNext => appender.append_label("inst_next"),
                ConstTplType::JNext2 => appender.append_label("inst_next2"),
                _ => self.format_address(appender, None, offset, size),
            },
            ConstTplType::SpaceId => {
                let space_id = space
                    .value_spaceid
                    .as_ref()
                    .expect("spaceid-typed ConstTpl must have a space");
                if self.is_format_raw()
                    && offset.tp == ConstTplType::Real
                    && size.tp == ConstTplType::Real
                {
                    self.format_varnode_raw(appender, space_id, offset, size);
                } else {
                    self.format_varnode_nice(appender, space_id, offset, size);
                }
            }
            tp => panic!("Unsupported space template type: {tp:?}"),
        }
    }

    /// Format a varnode in nice (non-raw) form.
    fn format_varnode_nice(
        &self,
        appender: &mut Self::Appender,
        space: &Arc<AddressSpace>,
        offset: &ConstTpl,
        size: &ConstTpl,
    ) {
        match space.space_type() {
            AddressSpaceType::Constant => self.format_constant(appender, offset, size),
            AddressSpaceType::Unique => self.format_unique(appender, offset, size),
            _ => self.format_address(appender, Some(space), offset, size),
        }
    }

    /// Format a varnode in raw form.
    fn format_varnode_raw(
        &self,
        appender: &mut Self::Appender,
        space: &AddressSpace,
        offset: &ConstTpl,
        size: &ConstTpl,
    ) {
        appender.append_raw_varnode(space, offset.value_real as i64, size.value_real as i64);
    }

    /// Format a unique variable.
    fn format_unique(&self, appender: &mut Self::Appender, offset: &ConstTpl, size: &ConstTpl) {
        if offset.tp != ConstTplType::Real {
            panic!("Unsupported unique offset type: {:?}", offset.tp);
        }
        if size.tp != ConstTplType::Real {
            panic!("Unsupported unique size type: {:?}", size.tp);
        }
        appender.append_unique(offset.value_real as i64);
        self.format_size(appender, size);
    }

    /// Format a memory variable. A `None` `addr_space` means the varnode is in the current
    /// (instruction's) space, which is displayed as a dereference.
    fn format_address(
        &self,
        appender: &mut Self::Appender,
        addr_space: Option<&Arc<AddressSpace>>,
        offset: &ConstTpl,
        size: &ConstTpl,
    ) {
        if offset.tp != ConstTplType::Real {
            panic!("Unsupported address offset type: {:?}", offset.tp);
        }

        let offset_value = offset.value_real as i64;
        let Some(addr_space) = addr_space else {
            appender.append_character('*');
            appender.append_address_word_offcut(offset_value, 0);
            if size.tp != ConstTplType::JCurSpaceSize {
                self.format_size(appender, size);
            }
            return;
        };

        let size_value = size.value_real as i64;
        let language = appender.get_language();
        let register =
            language.get_register_at(&addr_space.address(offset_value), size_value as i32);
        if let Some(register) = register {
            let register = register.borrow();
            appender.append_register(&register);
            if register.minimum_byte_size() as i64 > size_value {
                appender.append_character(':');
                appender.append_scalar(size_value);
            }
            return;
        }
        appender.append_character('*');
        appender.append_character('[');
        appender.append_space(addr_space);
        appender.append_character(']');

        let unit_size = addr_space.unit_size() as i64;
        let word_offset = offset_value / unit_size;
        let offcut = offset_value % unit_size;
        appender.append_address_word_offcut(word_offset, offcut);
        self.format_size(appender, size);
    }

    /// Format a constant.
    fn format_constant(&self, appender: &mut Self::Appender, offset: &ConstTpl, size: &ConstTpl) {
        if offset.tp != ConstTplType::Real {
            panic!("Unsupported constant offset type: {:?}", offset.tp);
        }
        appender.append_scalar(offset.value_real as i64);
        self.format_size(appender, size);
    }

    /// Format a size indicator.
    fn format_size(&self, appender: &mut Self::Appender, size: &ConstTpl) {
        if size.tp != ConstTplType::Real {
            panic!("Unsupported address size type: {:?}", size.tp);
        }
        if size.value_real != 0 {
            appender.append_character(':');
            appender.append_scalar(size.value_real as i64);
        }
    }

    /// Format a p-code userop name (CALLOTHER), given the constant varnode holding the userop id.
    fn format_call_other_name(&self, appender: &mut Self::Appender, input0: &VarnodeTpl) {
        if !is_const_space(&input0.space) || input0.offset.tp != ConstTplType::Real {
            panic!("Expected constant input[0] for CALLOTHER pcode op");
        }

        let id = input0.offset.value_real as i32;
        appender.append_character('"');
        appender.append_userop(id);
        appender.append_character('"');
    }

    /// Try to format a local label (e.g., `instr_next`) for the relative jump varnode `input0`.
    /// Returns true if the varnode was formatted, false if not.
    fn format_label_input(&self, appender: &mut Self::Appender, input0: &VarnodeTpl) -> bool {
        if is_const_space(&input0.space) && input0.offset.tp == ConstTplType::JRelative {
            appender.append_line_label_ref(input0.offset.value_real as i64);
            return true;
        }
        false
    }

    /// Format the memory location for a LOAD or STORE op. `input0` is the const varnode giving
    /// the address space id, and `input1` the varnode giving the address offset.
    fn format_memory_input(
        &self,
        appender: &mut Self::Appender,
        input0: &VarnodeTpl,
        input1: &VarnodeTpl,
    ) {
        if !is_const_space(&input0.space) || input0.offset.tp != ConstTplType::Real {
            panic!("Expected constant input[0] for LOAD/STORE pcode op");
        }
        let id = input0.offset.value_real as i32;
        let language = appender.get_language();
        let space = language.get_address_factory().get_address_space_by_id(id);
        let space = match space {
            Some(space) => space,
            None => {
                Msg::error(
                    "AbstractPcodeFormatter",
                    &format!("Address space id not found: {id}"),
                );
                // Java carries the null through to `appendSpace`, which then NPEs.
                panic!("Address space id not found: {id}");
            }
        };
        appender.append_space(&space);
        appender.append_character('(');
        self.format_varnode(appender, -1, 0, input1);
        appender.append_character(')');
    }
}

/// Check if the given template represents a line label.
///
/// The `PTRADD` op is ordinarily only used in high p-code. We reuse (read "abuse") it to hold a
/// display slot for line labels later referred to in `BRANCH` and `CBRANCH` ops. This checks if
/// the given op template is one of those placeholders.
///
/// Port of the static `AbstractPcodeFormatter.isLineLabel(OpTpl)`.
pub fn is_line_label(template: &OpTpl) -> bool {
    // Overloaded: PTRADD is high p-code
    template.opc == OpCode::CpuiPtradd
}

/// Port of the private static `AbstractPcodeFormatter.hasLabel(List<OpTpl>)`.
fn has_label(pcode_op_templates: &[OpTpl]) -> bool {
    pcode_op_templates.iter().any(is_line_label)
}

/// Mirrors `ConstTpl.isConstSpace()`.
fn is_const_space(c: &ConstTpl) -> bool {
    c.tp == ConstTplType::SpaceId
        && c.value_spaceid
            .as_ref()
            .is_some_and(|s| s.space_type() == AddressSpaceType::Constant)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::plugin::processors::generic::MemoryBlockDefinition;
    use crate::app::util::pcode::abstract_appender::{AbstractAppender, AbstractAppenderBase};
    use crate::program::model::address::{
        Address, AddressFactory, AddressSet, AddressSetView, DefaultAddressFactory,
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
    use crate::program::model::lang::register::{Register, RegisterRef};
    use crate::program::model::lang::unknown_instruction_exception::UnknownInstructionException;
    use crate::program::model::listing::default_program_context::DefaultProgramContext;
    use crate::program::model::mem::MemBuffer;
    use crate::program::seam_stubs::{AddressLabelInfo, Processor};
    use crate::util::task::TaskMonitor;
    use std::collections::HashSet;

    struct Spaces {
        ram: Arc<AddressSpace>,
        constant: Arc<AddressSpace>,
        unique: Arc<AddressSpace>,
        register: Arc<AddressSpace>,
    }

    fn spaces() -> Spaces {
        Spaces {
            ram: AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0),
            constant: AddressSpace::new("const", 64, 1, AddressSpaceType::Constant, 1),
            unique: AddressSpace::new("unique", 32, 1, AddressSpaceType::Unique, 2),
            register: AddressSpace::new("register", 32, 1, AddressSpaceType::Register, 3),
        }
    }

    struct MockLanguage {
        factory: DefaultAddressFactory,
        eax: RegisterRef,
    }

    impl MockLanguage {
        fn new(spaces: &Spaces) -> Self {
            // A single 4-byte register at register-space offset 0.
            let eax = Register::new(
                "EAX",
                "accumulator",
                Address::new(spaces.register.clone(), 0),
                4,
                false,
                0,
            );
            MockLanguage {
                factory: DefaultAddressFactory::new(vec![
                    spaces.ram.clone(),
                    spaces.constant.clone(),
                    spaces.unique.clone(),
                    spaces.register.clone(),
                ]),
                eax,
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
            vec![self.eax.clone()]
        }
        fn get_register_names(&self) -> Vec<String> {
            vec!["EAX".to_string()]
        }
        fn get_register_by_name(&self, name: &str) -> Option<RegisterRef> {
            (name == "EAX").then(|| self.eax.clone())
        }
        /// Any lookup landing exactly on EAX's address resolves to EAX, whatever the requested
        /// size -- enough to exercise both the plain and truncated (`EAX:2`) register branches.
        fn get_register_at(&self, addr: &Address, _size: i32) -> Option<RegisterRef> {
            (*addr == *self.eax.borrow().address()).then(|| self.eax.clone())
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

    /// A string-accumulating appender, standing in for `StringPcodeFormatter`'s.
    struct TestAppender {
        base: AbstractAppenderBase,
        buf: String,
    }

    impl Appender for TestAppender {
        type Output = String;

        fn get_language(&self) -> Arc<dyn Language> {
            self.base.language()
        }

        fn append_indent(&mut self) {
            let indent = self.base.indent();
            AbstractAppenderBase::append_indent(self, indent);
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

    struct TestFormatter {
        raw: bool,
    }

    impl AbstractPcodeFormatter for TestFormatter {
        type Appender = TestAppender;

        fn create_appender(&self, language: Arc<dyn Language>, indent: bool) -> TestAppender {
            TestAppender {
                base: AbstractAppenderBase::new(language, indent),
                buf: String::new(),
            }
        }

        fn is_format_raw(&self) -> bool {
            self.raw
        }
    }

    fn real(value: u64) -> ConstTpl {
        ConstTpl {
            tp: ConstTplType::Real,
            value_real: value,
            value_spaceid: None,
            handle_index: 0,
            select: None,
        }
    }

    fn typed(tp: ConstTplType, value: u64) -> ConstTpl {
        ConstTpl {
            tp,
            value_real: value,
            value_spaceid: None,
            handle_index: 0,
            select: None,
        }
    }

    fn space_id(space: &Arc<AddressSpace>) -> ConstTpl {
        ConstTpl {
            tp: ConstTplType::SpaceId,
            value_real: 0,
            value_spaceid: Some(space.clone()),
            handle_index: 0,
            select: None,
        }
    }

    fn vn(space: &Arc<AddressSpace>, offset: u64, size: u64) -> VarnodeTpl {
        VarnodeTpl {
            space: space_id(space),
            offset: real(offset),
            size: real(size),
        }
    }

    fn format(formatter: &TestFormatter, spaces: &Spaces, templates: &[OpTpl]) -> String {
        let language: Arc<dyn Language> = Arc::new(MockLanguage::new(spaces));
        formatter.format_op_templates(language, templates)
    }

    #[test]
    fn formats_unique_output_and_constant_input() {
        let s = spaces();
        let op = OpTpl {
            opc: OpCode::CpuiCopy,
            output: Some(vn(&s.unique, 0x100, 4)),
            input: vec![vn(&s.constant, 0x2a, 4)],
        };

        // Java: unique offsets print as $U<hex>, small scalars in decimal, size suffixed with ':'.
        // No line labels present, so no indent.
        assert_eq!(
            format(&TestFormatter { raw: false }, &s, &[op]),
            "$U100:4 = COPY 42:4"
        );
    }

    #[test]
    fn formats_line_label_and_relative_branch_target() {
        let s = spaces();
        let label = OpTpl {
            opc: OpCode::CpuiPtradd,
            output: None,
            input: vec![vn(&s.constant, 0, 8)],
        };
        let cbranch = OpTpl {
            opc: OpCode::CpuiCbranch,
            output: None,
            input: vec![
                VarnodeTpl {
                    space: space_id(&s.constant),
                    offset: typed(ConstTplType::JRelative, 0),
                    size: real(8),
                },
                vn(&s.register, 0, 4),
            ],
        };

        // The PTRADD placeholder emits `<0>`; its presence turns indentation on for the CBRANCH.
        // input[0] is a relative branch target, so it prints as a label reference, and input[1]
        // resolves to the register living at register:0.
        assert_eq!(
            format(&TestFormatter { raw: false }, &s, &[label, cbranch]),
            "<0>  CBRANCH <0>, EAX"
        );
    }

    #[test]
    fn formats_load_space_and_pointer_as_one_operand() {
        let s = spaces();
        // LOAD's input[0] is the const-space id of the space being loaded from; it and input[1]
        // are collapsed into `space(pointer)`.
        let op = OpTpl {
            opc: OpCode::CpuiLoad,
            output: Some(vn(&s.unique, 0, 4)),
            input: vec![
                vn(&s.constant, s.ram.space_id() as u64, 8),
                vn(&s.register, 0, 4),
            ],
        };

        assert_eq!(
            format(&TestFormatter { raw: false }, &s, &[op]),
            "$U0:4 = LOAD ram(EAX)"
        );
    }

    #[test]
    fn formats_callother_userop_name_in_quotes() {
        let s = spaces();
        let op = OpTpl {
            opc: OpCode::CpuiCallother,
            output: None,
            input: vec![vn(&s.constant, 5, 4), vn(&s.register, 0, 4)],
        };

        assert_eq!(
            format(&TestFormatter { raw: false }, &s, &[op]),
            "CALLOTHER \"myop\", EAX"
        );
    }

    #[test]
    fn raw_mode_prints_varnode_triples_and_skips_load_collapsing() {
        let s = spaces();
        let op = OpTpl {
            opc: OpCode::CpuiLoad,
            output: Some(vn(&s.unique, 0x100, 4)),
            input: vec![
                vn(&s.constant, s.ram.space_id() as u64, 8),
                vn(&s.register, 0, 4),
            ],
        };

        assert_eq!(
            format(&TestFormatter { raw: true }, &s, &[op]),
            format!(
                "(unique, 0x100, 4) = LOAD (const, 0x{:x}, 8), (register, 0x0, 4)",
                s.ram.space_id()
            )
        );
    }

    #[test]
    fn formats_truncated_register_and_plain_memory() {
        let s = spaces();
        // A 2-byte read at EAX's address: the register is wider, so a `:2` truncation is added.
        let truncated = OpTpl {
            opc: OpCode::CpuiCopy,
            output: None,
            input: vec![vn(&s.register, 0, 2)],
        };
        assert_eq!(
            format(&TestFormatter { raw: false }, &s, &[truncated]),
            "COPY EAX:2"
        );

        // A ram address with no register covering it falls back to `*[space]addr:size`.
        let memory = OpTpl {
            opc: OpCode::CpuiCopy,
            output: None,
            input: vec![vn(&s.ram, 0x1234, 4)],
        };
        assert_eq!(
            format(&TestFormatter { raw: false }, &s, &[memory]),
            "COPY *[ram]0x1234:4"
        );
    }

    #[test]
    fn formats_current_space_offsets_as_inst_labels() {
        let s = spaces();
        let cur_space = |offset_tp: ConstTplType| VarnodeTpl {
            space: typed(ConstTplType::JCurSpace, 0),
            offset: typed(offset_tp, 0),
            size: typed(ConstTplType::JCurSpaceSize, 0),
        };
        let op = OpTpl {
            opc: OpCode::CpuiBranch,
            output: None,
            input: vec![cur_space(ConstTplType::JNext)],
        };

        // BRANCH's input[0] isn't const-space-relative here, so it falls through to the varnode
        // formatter, which recognizes the J_NEXT offset.
        assert_eq!(
            format(&TestFormatter { raw: false }, &s, &[op]),
            "BRANCH inst_next"
        );

        let start = OpTpl {
            opc: OpCode::CpuiCopy,
            output: None,
            input: vec![cur_space(ConstTplType::JStart)],
        };
        assert_eq!(
            format(&TestFormatter { raw: false }, &s, &[start]),
            "COPY inst_start"
        );
    }

    #[test]
    fn current_space_real_offset_formats_as_dereference_without_size() {
        let s = spaces();
        let op = OpTpl {
            opc: OpCode::CpuiCopy,
            output: None,
            input: vec![VarnodeTpl {
                space: typed(ConstTplType::JCurSpace, 0),
                offset: real(0x40),
                // J_CURSPACE_SIZE suppresses the trailing size.
                size: typed(ConstTplType::JCurSpaceSize, 0),
            }],
        };
        assert_eq!(
            format(&TestFormatter { raw: false }, &s, &[op]),
            "COPY *0x40"
        );
    }

    #[test]
    fn terminate_stops_the_template_loop() {
        struct StopAfterFirst;

        impl AbstractPcodeFormatter for StopAfterFirst {
            type Appender = TestAppender;

            fn create_appender(&self, language: Arc<dyn Language>, indent: bool) -> TestAppender {
                TestAppender {
                    base: AbstractAppenderBase::new(language, indent),
                    buf: String::new(),
                }
            }

            fn format_op_template(
                &self,
                appender: &mut TestAppender,
                op: &OpTpl,
            ) -> FormatResult {
                if op.opc == OpCode::CpuiIntAdd {
                    return FormatResult::Terminate;
                }
                appender.append_mnemonic(op.opc as i32);
                FormatResult::Continue
            }
        }

        let s = spaces();
        let language: Arc<dyn Language> = Arc::new(MockLanguage::new(&s));
        let templates = vec![
            OpTpl::with_opcode(OpCode::CpuiCopy),
            OpTpl::with_opcode(OpCode::CpuiIntAdd),
            OpTpl::with_opcode(OpCode::CpuiIntSub),
        ];

        assert_eq!(
            StopAfterFirst.format_op_templates(language, &templates),
            "COPY"
        );
    }

    #[test]
    fn is_line_label_only_matches_ptradd() {
        assert!(is_line_label(&OpTpl::with_opcode(OpCode::CpuiPtradd)));
        assert!(!is_line_label(&OpTpl::with_opcode(OpCode::CpuiCopy)));
        assert!(has_label(&[
            OpTpl::with_opcode(OpCode::CpuiCopy),
            OpTpl::with_opcode(OpCode::CpuiPtradd),
        ]));
        assert!(!has_label(&[OpTpl::with_opcode(OpCode::CpuiCopy)]));
    }

    #[test]
    #[should_panic(expected = "Unsupported opcode encountered")]
    fn rejects_opcodes_at_or_above_pcode_max() {
        let s = spaces();
        format(
            &TestFormatter { raw: false },
            &s,
            &[OpTpl::with_opcode(OpCode::CpuiMax)],
        );
    }
}

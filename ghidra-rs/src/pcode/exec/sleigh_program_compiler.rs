//! Methods for compiling p-code programs for various purposes.
//!
//! Port of `ghidra.pcode.exec.SleighProgramCompiler`, a Java `enum` with no constants used purely
//! as a namespace of statics; per the shape rules it is a plain module of free functions here, with
//! the nested types (`PcodeLogEntry`, `DetailedSleighException`, `ErrorCollectingPcodeParser`) as
//! items of the module.
//!
//! Depending on the purpose, special provisions may be necessary around the execution of the
//! resulting program. The main entry points all start with `compile_`.
//!
//! # Divergences from Java
//!
//! * **Errors are returned.** Java throws `SleighException` (or its `DetailedSleighException`
//!   subclass) out of every `compile*` method. Here they return a [`SleighProgramCompileError`],
//!   which is one or the other.
//! * **One address-space set.** Java compiles into pcodeCPort templates over a private copy of the
//!   language's spaces and translates them back, so [`param_sym`] maps the argument's space to the
//!   parser's copy by its unique index. This crate's [`PcodeParser`] uses the language's own
//!   [`AddressSpace`]s; the lookup by unique index is kept so a space the parser does not know is
//!   still refused.
//! * **The program's language.** [`PcodeProgram`] binds an `Arc<dyn Language>` (see its module
//!   docs), so the language is taken as `&Arc<SleighLanguage>`.

use std::collections::HashMap;
use std::fmt;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;

use crate::app::plugin::processors::sleigh::pcode_emit::{PcodeEmit, PcodeEmitBuildError};
use crate::app::plugin::processors::sleigh::pcode_emit_objects::PcodeEmitObjects;
use crate::app::plugin::processors::sleigh::sleigh_exception::SleighException;
use crate::app::plugin::processors::sleigh::sleigh_parser_context::SleighParserContext;
use crate::app::plugin::processors::sleigh::unique_layout::UniqueLayout;
use crate::decompiler::slgh_compile::pcode_compile::{PcodeCompile, SemanticSymbol};
use crate::decompiler::slghsymbol::user_op_symbol::UserOpSymbol;
use crate::decompiler::slghsymbol::VarnodeSymbol;
use crate::pcode::exec::pcode_expression::{self, PcodeExpression};
use crate::pcode::exec::pcode_program::PcodeProgram;
use crate::pcode::exec::pcode_userop_library::PcodeUseropLibrary;
use crate::pcode::utils::message_formatting_utils;
use crate::program::model::address::{AddressFactory, SpecialAddress};
use crate::program::model::lang::language::Language;
use crate::program::model::lang::pcode_parser::{PcodeParser, PcodeTranslate};
use crate::program::model::lang::sleigh::template::ConstructTpl;
use crate::program::model::lang::sleigh::{ParserWalker, SleighLanguage};
use crate::program::model::pcode::{PcodeOp, Varnode};
use crate::sleigh::grammar::Location;
use crate::util::Msg;

/// The diagnostic source name of a compiled expression. Port of `EXPRESSION_SOURCE_NAME`.
const EXPRESSION_SOURCE_NAME: &str = "expression";

/// The name of the symbol standing for an unwanted result. Port of `NIL_SYMBOL_NAME`.
pub const NIL_SYMBOL_NAME: &str = "__nil";

/// An error or warning reported while compiling Sleigh source.
///
/// Port of the interface `SleighProgramCompiler.PcodeLogEntry` together with its two record
/// implementations, `PcodeError` and `PcodeWarning`, which differ only in [`type_name`](Self::type_name).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PcodeLogEntry {
    /// Port of the record `PcodeError`.
    Error { loc: Option<Location>, msg: String },
    /// Port of the record `PcodeWarning`.
    Warning { loc: Option<Location>, msg: String },
}

impl PcodeLogEntry {
    /// Where the problem is. Port of `loc()`.
    pub fn loc(&self) -> Option<&Location> {
        match self {
            Self::Error { loc, .. } | Self::Warning { loc, .. } => loc.as_ref(),
        }
    }

    /// The message. Port of `msg()`.
    pub fn msg(&self) -> &str {
        match self {
            Self::Error { msg, .. } | Self::Warning { msg, .. } => msg,
        }
    }

    /// `"ERROR"` or `"WARNING"`. Port of `type()`.
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::Error { .. } => "ERROR",
            Self::Warning { .. } => "WARNING",
        }
    }

    /// Port of `format()`: `"<type>: <location>: <msg>"`.
    pub fn format(&self) -> String {
        format!("{}: {}", self.type_name(), message_formatting_utils::format(self.loc(), self.msg()))
    }

    /// Format each entry on its own line. Port of the static `PcodeLogEntry.formatList(List)`.
    pub fn format_list(list: &[PcodeLogEntry]) -> String {
        list.iter().map(PcodeLogEntry::format).collect::<Vec<_>>().join("\n")
    }
}

/// A Sleigh compilation failure carrying every error and warning reported.
///
/// Port of `SleighProgramCompiler.DetailedSleighException`, whose message is
/// [`PcodeLogEntry::format_list`] of the details.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetailedSleighException {
    message: String,
    details: Vec<PcodeLogEntry>,
}

impl DetailedSleighException {
    /// Port of `DetailedSleighException(List<PcodeLogEntry>)`.
    pub fn new(details: Vec<PcodeLogEntry>) -> Self {
        Self { message: PcodeLogEntry::format_list(&details), details }
    }

    /// Port of `getDetails()`.
    pub fn get_details(&self) -> &[PcodeLogEntry] {
        &self.details
    }

    /// The formatted details.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for DetailedSleighException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for DetailedSleighException {}

/// Why compiling Sleigh source failed: Java's `SleighException`, which is sometimes the
/// `DetailedSleighException` subclass.
#[derive(Debug)]
pub enum SleighProgramCompileError {
    /// The parser reported errors; see [`DetailedSleighException::get_details`].
    Detailed(DetailedSleighException),
    /// Any other failure (a syntax error, or a template that is not a valid fragment).
    Sleigh(SleighException),
}

impl SleighProgramCompileError {
    /// The error's message.
    pub fn message(&self) -> &str {
        match self {
            Self::Detailed(e) => e.message(),
            Self::Sleigh(e) => e.message(),
        }
    }
}

impl fmt::Display for SleighProgramCompileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for SleighProgramCompileError {}

impl From<SleighException> for SleighProgramCompileError {
    fn from(e: SleighException) -> Self {
        Self::Sleigh(e)
    }
}

/// A p-code parser that provides programmatic access to error diagnostics.
///
/// Port of `SleighProgramCompiler.ErrorCollectingPcodeParser extends PcodeParser`. Java overrides
/// `reportError`/`reportWarning` to collect each report; the base parser here already records them
/// (see [`PcodeCompileBase::reports`](crate::decompiler::slgh_compile::pcode_compile::PcodeCompileBase::reports)),
/// so this only reads them back. It dereferences to the [`PcodeParser`] it extends.
pub struct ErrorCollectingPcodeParser {
    parser: PcodeParser,
}

impl ErrorCollectingPcodeParser {
    /// Port of `ErrorCollectingPcodeParser(SleighLanguage)`: temporaries are allocated from the
    /// language's [`UniqueLayout::Inject`] range.
    ///
    /// # Errors
    /// If the language lacks a space the parser needs (see [`PcodeTranslate::new`]).
    pub fn new(language: &SleighLanguage) -> Result<Self, SleighException> {
        let parser = PcodeParser::new(language, UniqueLayout::Inject.get_offset(Some(language)))?;
        Ok(Self { parser })
    }

    /// Every error and warning reported so far, in report order.
    pub fn entries(&self) -> Vec<PcodeLogEntry> {
        self.parser
            .base()
            .reports()
            .iter()
            .map(|r| match r.is_error {
                true => PcodeLogEntry::Error { loc: r.location.clone(), msg: r.message.clone() },
                false => PcodeLogEntry::Warning { loc: r.location.clone(), msg: r.message.clone() },
            })
            .collect()
    }

    /// Compile p-code statements, failing with the collected diagnostics if any error was
    /// reported. Port of the overridden `compilePcode(String, String, int)`.
    ///
    /// # Errors
    /// [`SleighProgramCompileError::Detailed`] if the parser reported errors (whatever else
    /// failed), otherwise any failure of [`PcodeParser::compile_pcode`].
    pub fn compile_pcode(
        &mut self,
        pcode_statements: &str,
        src_file: &str,
        src_line: i32,
    ) -> Result<ConstructTpl, SleighProgramCompileError> {
        let result = self.parser.compile_pcode(pcode_statements, src_file, src_line);
        // Java: `finally { if (getErrors() != 0) throw new DetailedSleighException(entries); }`
        if self.parser.get_errors() != 0 {
            return Err(SleighProgramCompileError::Detailed(DetailedSleighException::new(self.entries())));
        }
        Ok(result?)
    }
}

impl Deref for ErrorCollectingPcodeParser {
    type Target = PcodeParser;

    fn deref(&self) -> &PcodeParser {
        &self.parser
    }
}

impl DerefMut for ErrorCollectingPcodeParser {
    fn deref_mut(&mut self) -> &mut PcodeParser {
        &mut self.parser
    }
}

/// Create a p-code parser for the given language. Port of `createParser(SleighLanguage)`.
///
/// # Errors
/// See [`ErrorCollectingPcodeParser::new`].
pub fn create_parser(language: &SleighLanguage) -> Result<ErrorCollectingPcodeParser, SleighProgramCompileError> {
    Ok(ErrorCollectingPcodeParser::new(language)?)
}

/// Compile the given source into a p-code template. Blank source compiles to an empty template.
///
/// Port of `compileTemplate(Language, PcodeParser, String, String)`; the language parameter is
/// unused in Java and omitted here.
///
/// # Errors
/// See [`ErrorCollectingPcodeParser::compile_pcode`].
pub fn compile_template(
    parser: &mut ErrorCollectingPcodeParser,
    source_name: &str,
    source: &str,
) -> Result<ConstructTpl, SleighProgramCompileError> {
    if source.trim().is_empty() {
        return Ok(ConstructTpl::new());
    }
    parser.compile_pcode(source, source_name, 1)
}

/// Construct a list of p-code ops from the given template. Port of `buildOps(Language,
/// ConstructTpl)`.
///
/// As in Java, the ops are built at `Address.NO_ADDRESS`, which also stands for `inst_start`,
/// `inst_next`, `inst_ref` and `inst_dest`.
///
/// # Errors
/// If the template cannot be emitted (Java's `UnknownInstructionException`,
/// `MemoryAccessException` or `IOException`).
pub fn build_ops(language: &SleighLanguage, template: &ConstructTpl) -> Result<Vec<PcodeOp>, PcodeEmitBuildError> {
    let zero = SpecialAddress::no_address();
    let context = SleighParserContext::for_snippet(
        zero.clone(),
        Some(zero.clone()),
        Some(zero.clone()),
        Some(zero),
        language.get_address_factory().get_constant_space(),
    );
    let walker = ParserWalker::new(&context);
    let mut emit = PcodeEmitObjects::for_walker(walker);
    emit.build(template, 0)?;
    emit.resolve_relatives().map_err(PcodeEmitBuildError::Sleigh)?;
    Ok(emit.into_pcode_ops())
}

/// Add extra user-op symbols to the parser's table. The map cannot contain symbols whose user-op
/// indices are already defined by the language. Port of `addParserSymbols(PcodeParser, Map)`.
///
/// # Errors
/// If a symbol's name is already taken (Java's `SleighError`).
pub fn add_parser_symbols(
    parser: &mut PcodeParser,
    symbols: &HashMap<i32, UserOpSymbol>,
) -> Result<(), SleighProgramCompileError> {
    // Java iterates the map's values in hash order; ordering by index keeps the result stable.
    let mut ordered: Vec<(&i32, &UserOpSymbol)> = symbols.iter().collect();
    ordered.sort_by_key(|(index, _)| **index);
    for (_, sym) in ordered {
        let mut copy = UserOpSymbol::with_name(sym.symbol().location().clone(), sym.symbol().name());
        copy.set_index(sym.index());
        parser.add_symbol(SemanticSymbol::UserOp(copy)).map_err(sleigh_error)?;
    }
    Ok(())
}

/// Add a symbol for an unwanted result, or find the one already added. This is basically a hack
/// to avoid failures when no output varnode is given. Port of `addNilSymbol(PcodeParser)`.
///
/// Returns a copy of the nil symbol (symbols are owned by the parser's table).
///
/// # Panics
/// If a symbol of that name exists but is not a varnode symbol, as Java throws `AssertionError`.
pub fn add_nil_symbol(parser: &mut PcodeParser) -> Result<VarnodeSymbol, SleighProgramCompileError> {
    let loc = Location::new("<util>", 0);
    if let Some(exists) = parser.find_symbol(&loc, NIL_SYMBOL_NAME) {
        let SemanticSymbol::Varnode(nil) = exists else {
            panic!(
                "Symbol '{NIL_SYMBOL_NAME}' already exists, but has the wrong type ({})",
                semantic_kind(exists)
            );
        };
        return Ok(copy_varnode_symbol(nil));
    }
    let offset = parser.allocate_temp();
    let unique = parser.get_unique_space();
    let nil = VarnodeSymbol::with_fixed(loc.clone(), NIL_SYMBOL_NAME, unique.clone(), offset, 1);
    parser.add_symbol(SemanticSymbol::Varnode(nil)).map_err(sleigh_error)?;
    Ok(VarnodeSymbol::with_fixed(loc, NIL_SYMBOL_NAME, unique, offset, 1))
}

/// Invoke the given constructor with the given template and library symbols. `ctor` stands for
/// Java's `PcodeProgramConstructor<T>` (often a method reference to `::new`).
///
/// Port of `constructProgram(PcodeProgramConstructor, SleighLanguage, ConstructTpl, Map)`.
///
/// # Panics
/// If the template cannot be emitted, as Java wraps the checked exceptions in `AssertionError`.
pub fn construct_program<P>(
    ctor: impl FnOnce(Arc<dyn Language>, Vec<PcodeOp>, HashMap<i32, UserOpSymbol>) -> P,
    language: &Arc<SleighLanguage>,
    template: &ConstructTpl,
    lib_syms: HashMap<i32, UserOpSymbol>,
) -> P {
    let ops = build_ops(language, template).unwrap_or_else(|e| panic!("{e}"));
    ctor(Arc::clone(language) as Arc<dyn Language>, ops, lib_syms)
}

/// Compile the given Sleigh source into a simple p-code program with the given parser.
///
/// This is suitable for modifying program state using Sleigh statements. Most likely, in
/// scripting, or perhaps in a Sleigh repl. The library given during compilation must match the
/// library given for execution, at least in its binding of userop IDs to symbols.
///
/// Port of `compileProgram(PcodeParser, SleighLanguage, String, String, PcodeUseropLibrary)`.
///
/// # Errors
/// If the source does not compile.
pub fn compile_program_with_parser<T: 'static>(
    parser: &mut ErrorCollectingPcodeParser,
    language: &Arc<SleighLanguage>,
    source_name: &str,
    source: &str,
    library: &dyn PcodeUseropLibrary<T>,
) -> Result<PcodeProgram, SleighProgramCompileError> {
    let symbols = library.get_symbols(language);
    add_parser_symbols(parser, &symbols)?;
    let template = compile_template(parser, source_name, source)?;
    Ok(construct_program(PcodeProgram::new, language, &template, symbols))
}

/// Compile the given Sleigh source into a simple p-code program, with a fresh parser.
///
/// Port of `compileProgram(SleighLanguage, String, String, PcodeUseropLibrary)`.
///
/// # Errors
/// If the source does not compile.
pub fn compile_program<T: 'static>(
    language: &Arc<SleighLanguage>,
    source_name: &str,
    source: &str,
    library: &dyn PcodeUseropLibrary<T>,
) -> Result<PcodeProgram, SleighProgramCompileError> {
    compile_program_with_parser(&mut create_parser(language)?, language, source_name, source, library)
}

/// Compile the given Sleigh expression into a p-code program that can evaluate it, using the
/// given parser. Expressions cannot (yet, as in Java) be compiled for a user-supplied library: the
/// evaluator uses its own library to capture the result.
///
/// Port of `compileExpression(PcodeParser, SleighLanguage, String)`.
///
/// # Errors
/// If the expression does not compile.
pub fn compile_expression_with_parser(
    parser: &mut ErrorCollectingPcodeParser,
    language: &Arc<SleighLanguage>,
    expression: &str,
) -> Result<PcodeExpression, SleighProgramCompileError> {
    let symbols = pcode_expression::capturing_symbols(language);
    add_parser_symbols(parser, &symbols)?;
    let source = format!("{}({expression});", PcodeExpression::RESULT_NAME);
    let template = compile_template(parser, EXPRESSION_SOURCE_NAME, &source)?;
    Ok(construct_program(PcodeExpression::new, language, &template, symbols))
}

/// Compile the given Sleigh expression into a p-code program that can evaluate it, with a fresh
/// parser. Port of `compileExpression(SleighLanguage, String)`.
///
/// # Errors
/// If the expression does not compile.
pub fn compile_expression(
    language: &Arc<SleighLanguage>,
    expression: &str,
) -> Result<PcodeExpression, SleighProgramCompileError> {
    compile_expression_with_parser(&mut create_parser(language)?, language, expression)
}

/// Generate a Sleigh symbol for context when compiling a userop definition: `param_name` bound
/// to the varnode `arg`. `op_name` is a diagnostic name for the userop in which this parameter
/// applies.
///
/// Port of `paramSym(Language, SleighBase, String, String, Varnode)`; the parser's
/// [`PcodeTranslate`] stands for the `SleighBase`, and the argument's space is found there by its
/// unique index, as Java does.
///
/// # Panics
/// If the parser has no space for the argument, where Java would fail dereferencing `null`.
pub fn param_sym(sleigh: &PcodeTranslate, op_name: &str, param_name: &str, arg: &Varnode) -> VarnodeSymbol {
    let g_space = arg.get_address().space();
    let s_space = sleigh
        .get_spaces()
        .iter()
        .find(|s| s.unique() == g_space.unique())
        .unwrap_or_else(|| panic!("no space {} for parameter '{param_name}' of {op_name}", g_space.name()))
        .clone();
    VarnodeSymbol::with_fixed(
        Location::new(op_name, 0),
        param_name,
        s_space,
        arg.get_offset() as u64,
        arg.get_size(),
    )
}

/// Compile the definition of a p-code userop from Sleigh source into a p-code program.
///
/// Parameters are passed by reference: each name in `params` is aliased to the varnode at the same
/// index of `args`. Index 0 names the output symbol, and is the only argument that may be `None`
/// (bound then to the [nil symbol](add_nil_symbol)). See the Java documentation for the caveats of
/// this scheme around temporaries.
///
/// Port of `compileUserop(SleighLanguage, String, List, String, PcodeUseropLibrary, List)`.
///
/// # Errors
/// If the source does not compile; the source is logged, as in Java.
///
/// # Panics
/// If `params` and `args` differ in length ("Mismatch of params and args sizes"), or a non-output
/// argument is `None`.
pub fn compile_userop<T: 'static>(
    language: &Arc<SleighLanguage>,
    op_name: &str,
    params: &[String],
    source: &str,
    library: &dyn PcodeUseropLibrary<T>,
    args: &[Option<Varnode>],
) -> Result<PcodeProgram, SleighProgramCompileError> {
    let mut parser = create_parser(language)?;
    let symbols = library.get_symbols(language);
    add_parser_symbols(&mut parser, &symbols)?;

    assert_eq!(args.len(), params.len(), "Mismatch of params and args sizes");
    let nil = add_nil_symbol(&mut parser)?;
    let nil_vn = nil.get_fixed_varnode().clone();
    for (i, (p, a)) in params.iter().zip(args).enumerate() {
        let sym = match a {
            // Only allow output to be omitted
            None if i == 0 => VarnodeSymbol::with_fixed(
                nil.symbol().location().clone(),
                p.as_str(),
                nil_vn.space.clone(),
                nil_vn.offset,
                nil_vn.size,
            ),
            None => panic!("argument {i} ({p}) of {op_name} is missing"),
            Some(a) => param_sym(parser.get_sleigh(), op_name, p, a),
        };
        parser.add_symbol(SemanticSymbol::Varnode(sym)).map_err(sleigh_error)?;
    }

    match compile_template(&mut parser, op_name, source) {
        Ok(template) => Ok(construct_program(PcodeProgram::new, language, &template, symbols)),
        Err(e) => {
            Msg::error("SleighProgramCompiler", &format!("Error trying to compile userop:\n{source}"));
            Err(e)
        }
    }
}

fn sleigh_error(e: crate::decompiler::context::SleighError) -> SleighProgramCompileError {
    SleighProgramCompileError::Sleigh(SleighException::with_message(message_formatting_utils::format(
        Some(&e.location),
        e.message(),
    )))
}

/// Java's `getClass().getSimpleName()` of a symbol, for diagnostics.
fn semantic_kind(sym: &SemanticSymbol) -> &'static str {
    match sym {
        SemanticSymbol::Varnode(_) => "VarnodeSymbol",
        SemanticSymbol::UserOp(_) => "UserOpSymbol",
        SemanticSymbol::Space { .. } => "SpaceSymbol",
        SemanticSymbol::Label(_) => "LabelSymbol",
        SemanticSymbol::Operand { .. } => "OperandSymbol",
        SemanticSymbol::Start(_) => "StartSymbol",
        SemanticSymbol::End(_) => "EndSymbol",
        SemanticSymbol::Next2(_) => "Next2Symbol",
        SemanticSymbol::FlowRef(_) => "FlowRefSymbol",
        SemanticSymbol::FlowDest(_) => "FlowDestSymbol",
        _ => "SleighSymbol",
    }
}

fn copy_varnode_symbol(sym: &VarnodeSymbol) -> VarnodeSymbol {
    let fix = sym.get_fixed_varnode();
    VarnodeSymbol::with_fixed(sym.symbol().location().clone(), sym.symbol().name(), fix.space.clone(), fix.offset, fix.size)
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::app::plugin::processors::sleigh::sleigh_instruction_prototype::decode_tests;
    use crate::pcode::exec::bytes_pcode_arithmetic::BytesPcodeArithmetic;
    use crate::pcode::exec::bytes_pcode_executor_state::BytesPcodeExecutorState;
    use crate::pcode::exec::pcode_executor::PcodeExecutor;
    use crate::pcode::exec::pcode_executor_state::PcodeExecutorState;
    use crate::pcode::exec::pcode_executor_state_piece::{PcodeExecutorStatePiece, Reason};
    use crate::pcode::exec::pcode_state_callbacks::NONE;
    use crate::pcode::exec::pcode_userop_library::nil;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::pcode::OpCode;

    /// The fixture's big-endian 4-byte registers: `r0` at `register:0`, `r1` at `register:4`.
    struct Machine {
        language: Arc<SleighLanguage>,
        register: Arc<AddressSpace>,
        executor: PcodeExecutor<Vec<u8>>,
    }

    impl Machine {
        fn new() -> Self {
            let language = decode_tests::language();
            let register = language.get_address_factory().get_address_space_by_name("register").unwrap();
            let dyn_language: Arc<dyn Language> = Arc::clone(&language) as Arc<dyn Language>;
            let state = BytesPcodeExecutorState::new(Arc::clone(&dyn_language), Arc::new(NONE));
            let state: Arc<Mutex<dyn PcodeExecutorState<Vec<u8>>>> = Arc::new(Mutex::new(state));
            let arithmetic = Arc::new(BytesPcodeArithmetic::for_sleigh_language(&language));
            let executor = PcodeExecutor::new(dyn_language, arithmetic, state, Reason::ExecuteRead);
            Self { language, register, executor }
        }

        fn set(&self, offset: i64, value: u32) {
            let mut state = self.executor.get_state().lock().unwrap();
            state.set_var(&self.register, offset, 4, false, &value.to_be_bytes().to_vec());
        }

        fn get(&self, offset: i64) -> u32 {
            let state = self.executor.get_state().lock().unwrap();
            let bytes = state.get_var(&self.register, offset, 4, false, Reason::Inspect);
            u32::from_be_bytes(bytes.try_into().unwrap())
        }

        fn run(&self, source: &str) {
            let program = compile_program(&self.language, "test", source, &nil::<Vec<u8>>()).unwrap();
            program.execute(&self.executor, &nil::<Vec<u8>>());
        }

        fn register_varnode(&self, offset: i64) -> Varnode {
            Varnode::new(self.register.address(offset), 4)
        }
    }

    #[test]
    fn a_compiled_program_computes_register_values() {
        let m = Machine::new();
        m.set(4, 0x10);
        m.run("r0 = r1 + 5;");
        assert_eq!(0x15, m.get(0));
        assert_eq!(0x10, m.get(4));

        // Temporaries and several statements: r1 = (r0 * 3) - r1 = 0x3f - 0x10.
        m.run("local t:4 = r0 * 3; r1 = t - r1;");
        assert_eq!(0x2f, m.get(4));
    }

    #[test]
    fn labels_resolve_to_relative_branches() {
        let m = Machine::new();
        let source = "if (r1 == 0) goto <skip>; r0 = 1; <skip> r1 = r1 + 1;";
        let program = compile_program(&m.language, "test", source, &nil::<Vec<u8>>()).unwrap();
        // CBRANCH's target is a relative (constant) offset once resolved: past the one COPY.
        let cbranch = program.code().iter().find(|op| op.opcode == OpCode::CBranch).unwrap();
        assert!(cbranch.inputs[0].is_constant());
        assert_eq!(2, cbranch.inputs[0].get_offset());

        m.set(4, 0);
        program.execute(&m.executor, &nil::<Vec<u8>>());
        assert_eq!((0, 1), (m.get(0), m.get(4)));

        m.set(4, 3);
        program.execute(&m.executor, &nil::<Vec<u8>>());
        assert_eq!((1, 4), (m.get(0), m.get(4)));
    }

    #[test]
    fn ops_are_built_at_no_address() {
        let m = Machine::new();
        let program = compile_program(&m.language, "test", "r0 = r1;", &nil::<Vec<u8>>()).unwrap();
        assert_eq!(1, program.code().len());
        assert_eq!(SpecialAddress::no_address(), program.code()[0].seqnum.pc);
    }

    #[test]
    fn blank_source_compiles_to_an_empty_program() {
        let m = Machine::new();
        let program = compile_program(&m.language, "test", "  \n\t", &nil::<Vec<u8>>()).unwrap();
        assert!(program.code().is_empty());
    }

    #[test]
    fn an_expression_evaluates_through_the_capturing_userop() {
        let m = Machine::new();
        m.set(4, 7);
        let expression = compile_expression(&m.language, "r1 * 6").unwrap();
        // The fixture declares no userops, so `___result` is bound at index 0.
        assert_eq!(Some(PcodeExpression::RESULT_NAME), expression.userop_names().get(&0).map(String::as_str));
        assert_eq!(vec![0, 0, 0, 42], expression.evaluate(&m.executor));
    }

    #[test]
    fn library_userops_are_bound_after_the_language_userops() {
        use crate::pcode::emu::default_pcode_thread::PcodeEmulationLibrary;
        let m = Machine::new();
        let library = PcodeEmulationLibrary::<Vec<u8>>::new(None);
        let program =
            compile_program(&m.language, "inject", "emu_swi(); emu_exec_decoded();", &library).unwrap();
        // Name order: emu_exec_decoded 0, emu_injection_err 1, emu_skip_decoded 2, emu_swi 3.
        let callothers: Vec<i64> = program
            .code()
            .iter()
            .filter(|op| op.opcode == OpCode::CallOther)
            .map(|op| op.inputs[0].get_offset())
            .collect();
        assert_eq!(vec![3, 0], callothers);
        assert_eq!(Some("emu_swi"), program.get_userop_name(3).as_deref());
        assert_eq!(Some("emu_exec_decoded"), program.get_userop_name(0).as_deref());
    }

    #[test]
    fn reported_errors_carry_their_details() {
        let m = Machine::new();
        let Err(err) = compile_program(&m.language, "test", "r0 = nosuchreg;", &nil::<Vec<u8>>()) else {
            panic!("an undefined symbol must not compile");
        };
        let SleighProgramCompileError::Detailed(detailed) = &err else {
            panic!("expected detailed errors, got {err}");
        };
        let details = detailed.get_details();
        assert!(!details.is_empty());
        assert_eq!("ERROR", details[0].type_name());
        assert!(details[0].msg().contains("nosuchreg"), "{}", details[0].msg());
        assert!(detailed.message().starts_with("ERROR: "), "{}", detailed.message());
        assert_eq!(PcodeLogEntry::format_list(details), err.to_string());
    }

    #[test]
    fn a_syntax_error_fails_the_compile() {
        let m = Machine::new();
        assert!(compile_program(&m.language, "test", "r0 = ;", &nil::<Vec<u8>>()).is_err());
    }

    #[test]
    fn log_entries_format_as_java_does() {
        let loc = Location::new("inject", 3);
        let error = PcodeLogEntry::Error { loc: Some(loc.clone()), msg: "bad".into() };
        let warning = PcodeLogEntry::Warning { loc: Some(loc.clone()), msg: "meh".into() };
        assert_eq!(format!("ERROR: {}", message_formatting_utils::format(Some(&loc), "bad")), error.format());
        assert_eq!(format!("WARNING: {}", message_formatting_utils::format(Some(&loc), "meh")), warning.format());
        assert_eq!(
            format!("{}\n{}", error.format(), warning.format()),
            PcodeLogEntry::format_list(&[error.clone(), warning])
        );
        let detailed = DetailedSleighException::new(vec![error.clone()]);
        assert_eq!(error.format(), detailed.to_string());
    }

    #[test]
    fn a_userop_body_aliases_its_parameters_to_the_arguments() {
        let m = Machine::new();
        m.set(4, 9);
        let params = vec!["__op_output".to_string(), "a".to_string()];
        let args = vec![Some(m.register_varnode(0)), Some(m.register_varnode(4))];
        let program =
            compile_userop(&m.language, "inc", &params, "__op_output = a + 1;", &nil::<Vec<u8>>(), &args).unwrap();
        program.execute(&m.executor, &nil::<Vec<u8>>());
        assert_eq!(10, m.get(0));
    }

    #[test]
    fn an_omitted_output_is_bound_to_the_nil_symbol() {
        let m = Machine::new();
        m.set(4, 9);
        let params = vec!["__op_output".to_string(), "a".to_string()];
        let args = vec![None, Some(m.register_varnode(4))];
        let program =
            compile_userop(&m.language, "inc", &params, "__op_output = a:1; a = a + 1;", &nil::<Vec<u8>>(), &args)
                .unwrap();
        program.execute(&m.executor, &nil::<Vec<u8>>());
        assert_eq!(10, m.get(4));
        // The output went to the one-byte nil temporary in the unique space.
        let out = program.code()[0].output.as_ref().unwrap();
        assert_eq!(AddressSpaceType::Unique, out.get_address().space().space_type());
        assert_eq!(1, out.get_size());
    }

    #[test]
    #[should_panic(expected = "Mismatch of params and args sizes")]
    fn a_userop_needs_one_argument_per_parameter() {
        let m = Machine::new();
        let params = vec!["__op_output".to_string()];
        let _ = compile_userop(&m.language, "x", &params, "", &nil::<Vec<u8>>(), &[]);
    }

    #[test]
    fn the_nil_symbol_is_added_once() {
        let m = Machine::new();
        let mut parser = create_parser(&m.language).unwrap();
        let first = add_nil_symbol(&mut parser).unwrap();
        let again = add_nil_symbol(&mut parser).unwrap();
        assert_eq!(first.get_fixed_varnode().offset, again.get_fixed_varnode().offset);
        // Temporaries come from the INJECT range of the unique space.
        assert_eq!(UniqueLayout::Inject.get_offset(Some(&m.language)), first.get_fixed_varnode().offset);
    }
}

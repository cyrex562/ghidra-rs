//! Port of `ghidra.program.model.lang.PcodeParser`: compiles p-code snippets -- the bodies of
//! compiler-spec `<callfixup>`/`<callotherfixup>`/`<pcode>` injections and other extensions --
//! into a [`ConstructTpl`], outside the normal SLEIGH compilation process, on top of an existing
//! [`SleighLanguage`].
//!
//! Parsing uses the hand-written SLEIGH front-end ([`SemanticParser`] in SEMANTIC mode, as Java
//! pushes its lexer into `SEMANTIC` mode and calls `parser.semantic()`), and the statements are
//! compiled by the `SleighCompiler.g` semantic pass ([`compile_semantic`]) against this parser's
//! [`PcodeCompile`] implementation.
//!
//! # Differences from Java
//!
//! - **No `translate*` step.** Java compiles into pcodeCPort templates over a private copy of the
//!   language's spaces ([`PcodeTranslate`]) and then translates them, space by name, into the
//!   runtime templates. This crate has one template type set whose spaces are the language's own
//!   [`AddressSpace`]s, so the compiled templates are returned directly.
//! - **Reported errors fail the compile.** When the walker reported errors, Java's
//!   `compilePcode` logs them and returns `null`, which `PcodeInjectLibrary.parseInject` then
//!   installs as the payload's template (to fail later, when the payload is used). Here
//!   [`PcodeParser::compile_pcode`] returns a [`SleighException`] carrying the error messages.
//! - **`PcodeTranslate` is not a `SleighBase`.** The `SleighBase` trait in this crate is expressed
//!   over the pcodeCPort `AddrSpace` trait and an untyped `SleighSymbol` header, neither of which
//!   can hold what the parser needs to look up; [`PcodeTranslate`] keeps the same data (spaces,
//!   the copied user-op and varnode symbols, one space symbol per space) as plain fields.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::app::plugin::processors::sleigh::sleigh_exception::SleighException;
use crate::decompiler::context::SleighError;
use crate::decompiler::sleigh_base::MAX_UNIQUE_SIZE;
use crate::decompiler::slgh_compile::pcode_compile::{delay_slot, PcodeCompile, PcodeCompileBase, SemanticSymbol};
use crate::decompiler::slgh_compile::ExprTreeImpl;
use crate::decompiler::slghsymbol::{
    EndSymbol, FlowDestSymbol, FlowRefSymbol, Next2Symbol, StartSymbol, UserOpSymbol,
    VarnodeSymbol,
};
use crate::pcode::utils::message_formatting_utils;
use crate::program::model::address::{AddressFactory, AddressSpace, AddressSpaceType};
use crate::program::model::lang::sleigh::symbol::SleighSymbol as LangSymbol;
use crate::program::model::lang::sleigh::template::{ConstructTpl, OpTpl, VarnodeTpl};
use crate::program::model::lang::sleigh::SleighLanguage;
use crate::sleigh::grammar::frontend::{compile_semantic, BaseLexer, SemanticParser, SemanticResult};
use crate::sleigh::grammar::location::INTERNALLY_DEFINED;
use crate::sleigh::grammar::Location;

/// The name Java's `SpaceNames.OTHER_SPACE_NAME` gives the `OTHER` space.
const OTHER_SPACE_NAME: &str = "OTHER";

/// The language-derived half of the parser's symbol table: Java's `PcodeParser.PcodeTranslate`,
/// which wraps an existing [`SleighLanguage`] with the `SleighBase` view `PcodeCompile` expects.
/// It holds the language's address spaces, a clone of every user-defined op and global varnode
/// symbol (typically all the general purpose registers), and one space symbol per space.
pub struct PcodeTranslate {
    spaces: Vec<Arc<AddressSpace>>,
    default_space: Arc<AddressSpace>,
    constant_space: Arc<AddressSpace>,
    unique_space: Arc<AddressSpace>,
    unique_base: u64,
    big_endian: bool,
    symbols: HashMap<String, SemanticSymbol>,
}

impl PcodeTranslate {
    /// Builds the translator for `language`, allocating temporaries from `ubase` (Java's
    /// `PcodeTranslate(SleighLanguage, long)`).
    ///
    /// # Errors
    /// Fails if the language has no constant, unique, or default space.
    pub fn new(language: &SleighLanguage, ubase: u64) -> Result<Self, SleighException> {
        let factory = language.get_address_factory();
        let missing = |what: &str| {
            SleighException::with_message(format!(
                "PcodeParser: language {} has no {what} space",
                language.get_id()
            ))
        };
        let constant_space = factory.get_constant_space().ok_or_else(|| missing("constant"))?;
        let default_space =
            factory.get_default_address_space().ok_or_else(|| missing("default"))?;

        // copySpaces: the constant and OTHER spaces, then every real space of a supported type.
        let mut spaces = vec![constant_space.clone()];
        if let Some(other) = factory.get_address_space_by_name(OTHER_SPACE_NAME) {
            spaces.push(other);
        }
        let mut unique_space = None;
        for spc in factory.get_all_address_spaces() {
            if spc.unique() < 2 {
                continue;
            }
            match spc.space_type() {
                AddressSpaceType::Unique => unique_space = Some(spc.clone()),
                AddressSpaceType::Other | AddressSpaceType::Ram | AddressSpaceType::Register => {}
                // Java stops copying at the first space of any other type.
                _ => break,
            }
            spaces.push(spc);
        }
        let unique_space = unique_space.ok_or_else(|| missing("unique"))?;

        let mut symbols = HashMap::new();
        // copySymbols: user-defined ops and global varnodes (not the context register).
        for sym in language.get_symbol_table().symbols.iter().flatten() {
            let copied = match sym {
                LangSymbol::Userop(op) => {
                    let mut clone = UserOpSymbol::with_name(INTERNALLY_DEFINED.clone(), sym.get_name());
                    clone.set_index(op.index);
                    SemanticSymbol::UserOp(clone)
                }
                LangSymbol::Varnode(vn) => {
                    if sym.get_name() == "contextreg" {
                        continue;
                    }
                    let Some(space) = vn.space.clone() else {
                        continue;
                    };
                    SemanticSymbol::Varnode(VarnodeSymbol::with_fixed(
                        INTERNALLY_DEFINED.clone(),
                        sym.get_name(),
                        space,
                        vn.offset,
                        vn.size,
                    ))
                }
                _ => continue,
            };
            symbols.entry(sym.get_name().to_string()).or_insert(copied);
        }
        for space in &spaces {
            symbols.entry(space.name().to_string()).or_insert(SemanticSymbol::Space {
                location: INTERNALLY_DEFINED.clone(),
                space: space.clone(),
            });
        }

        Ok(Self {
            spaces,
            default_space,
            constant_space,
            unique_space,
            unique_base: ubase,
            big_endian: language.is_big_endian(),
            symbols,
        })
    }

    /// Looks up a language symbol (Java's `SleighBase.findSymbol(String)`).
    pub fn find_symbol(&self, name: &str) -> Option<&SemanticSymbol> {
        self.symbols.get(name)
    }

    /// The first unique-space offset for temporaries.
    pub fn get_unique_base(&self) -> u64 {
        self.unique_base
    }

    /// The copied address spaces, in Java's `insertSpace` order.
    pub fn get_spaces(&self) -> &[Arc<AddressSpace>] {
        &self.spaces
    }

    pub fn get_default_space(&self) -> Arc<AddressSpace> {
        self.default_space.clone()
    }

    pub fn get_constant_space(&self) -> Arc<AddressSpace> {
        self.constant_space.clone()
    }

    pub fn get_unique_space(&self) -> Arc<AddressSpace> {
        self.unique_space.clone()
    }

    pub fn is_big_endian(&self) -> bool {
        self.big_endian
    }
}

/// Compiles p-code snippets against an existing [`SleighLanguage`]. See the module docs.
pub struct PcodeParser {
    base: PcodeCompileBase,
    sleigh: PcodeTranslate,
    tempbase: u64,
    symbol_map: HashMap<String, SemanticSymbol>,
    /// Symbols added so that they can be removed to reset the parser.
    current_symbols: HashSet<String>,
}

impl PcodeParser {
    /// Builds a parser from an existing language; `ubase` is the starting offset for allocating
    /// temporary registers.
    ///
    /// # Errors
    /// Fails if the language lacks a space the parser needs (see [`PcodeTranslate::new`]).
    pub fn new(language: &SleighLanguage, ubase: u64) -> Result<Self, SleighException> {
        let sleigh = PcodeTranslate::new(language, ubase)?;
        let mut parser = Self {
            base: PcodeCompileBase::new(),
            sleigh,
            tempbase: 0,
            symbol_map: HashMap::new(),
            current_symbols: HashSet::new(),
        };
        parser.initialize_symbols();
        Ok(parser)
    }

    fn initialize_symbols(&mut self) {
        self.tempbase = self.sleigh.get_unique_base();
        let loc = INTERNALLY_DEFINED.clone();
        let cs = self.get_constant_space();
        self.symbol_map.insert(
            "inst_start".into(),
            SemanticSymbol::Start(StartSymbol::with_name(loc.clone(), "inst_start", cs.clone())),
        );
        self.symbol_map.insert(
            "inst_next".into(),
            SemanticSymbol::End(EndSymbol::with_name(loc.clone(), "inst_next", cs.clone())),
        );
        self.symbol_map.insert(
            "inst_next2".into(),
            SemanticSymbol::Next2(Next2Symbol::with_name(loc.clone(), "inst_next2", cs.clone())),
        );
        self.symbol_map.insert(
            "inst_ref".into(),
            SemanticSymbol::FlowRef(FlowRefSymbol::new(loc.clone(), "inst_ref", cs.clone())),
        );
        self.symbol_map.insert(
            "inst_dest".into(),
            SemanticSymbol::FlowDest(FlowDestSymbol::new(loc, "inst_dest", cs)),
        );
    }

    /// Injects a symbol representing an "operand" of the p-code snippet: a placeholder in the
    /// resulting template, filled in with the context-specific storage location when final p-code
    /// is generated.
    ///
    /// # Errors
    /// Fails if `name` already names a symbol.
    pub fn add_operand(&mut self, loc: &Location, name: &str, index: i32) -> Result<(), SleighError> {
        self.add_symbol(SemanticSymbol::Operand {
            location: loc.clone(),
            name: name.to_string(),
            index,
        })
    }

    /// Removes every symbol added since construction (or the last clear).
    pub fn clear_symbols(&mut self) {
        for symbol in self.current_symbols.drain() {
            self.symbol_map.remove(&symbol);
        }
    }

    /// The next free temporary offset in the unique space.
    pub fn get_next_temp_offset(&self) -> u64 {
        self.tempbase
    }

    /// The language view the parser was built on.
    pub fn get_sleigh(&self) -> &PcodeTranslate {
        &self.sleigh
    }

    /// Makes sure label symbols are used properly, returning the joined error messages (empty
    /// when all is well).
    fn check_labels(&self) -> String {
        let mut errors = Vec::new();
        for sym in self.symbol_map.values() {
            let SemanticSymbol::Label(labsym) = sym else {
                continue;
            };
            let location = labsym.symbol().location();
            if labsym.ref_count() == 0 {
                errors.push(message_formatting_utils::format(
                    Some(location),
                    &format!("Label <{}> was placed but never used", labsym.symbol().name()),
                ));
            } else if !labsym.is_placed() {
                errors.push(message_formatting_utils::format(
                    Some(location),
                    &format!("Label <{}> was referenced but never placed", labsym.symbol().name()),
                ));
            }
        }
        errors.join("  ")
    }

    fn build_constructor(&mut self, mut rtl: ConstructTpl) -> Result<ConstructTpl, SleighException> {
        let mut errstring = self.check_labels();
        if errstring.is_empty() && !self.propagate_size(&mut rtl).map_err(sleigh_error)? {
            errstring = "   Could not resolve at least 1 variable size".to_string();
        }
        if errstring.is_empty() && delay_slot(&rtl) != 0 {
            // Delay slot is present in this
            errstring = "   delayslot not permitted in pcode fragment".to_string();
        }
        if rtl.result.is_some() {
            errstring = "   export not permitted in pcode fragment".to_string();
        }
        if !errstring.is_empty() {
            return Err(SleighException::with_message(errstring));
        }
        Ok(rtl)
    }

    /// Compiles p-code semantic statements. `src_file`/`src_line` locate `pcode_statements` for
    /// error reporting.
    ///
    /// # Errors
    /// Fails on a syntax error, on any error the compile reported, or when the result is not a
    /// valid fragment (misused labels, unresolvable sizes, a delay slot, an export).
    pub fn compile_pcode(
        &mut self,
        pcode_statements: &str,
        src_file: &str,
        src_line: i32,
    ) -> Result<ConstructTpl, SleighException> {
        // Inject the p-code statement lines, each newline-terminated (as Java's writer does).
        let mut text = String::with_capacity(pcode_statements.len() + 1);
        for line in pcode_statements.lines() {
            text.push_str(line);
            text.push('\n');
        }
        let location = Location::new(src_file, src_line);

        let mut lexer = BaseLexer::new(&text);
        let body = SemanticParser::new(&mut lexer)
            .parse_semantic_snippet()
            .map_err(|e| {
                SleighException::with_message(format!(
                    "Semantic compilation error: {}",
                    message_formatting_utils::format(Some(&location), &e.to_string())
                ))
            })?;

        let rtl = compile_semantic(self, &body, &location, false, false).map_err(sleigh_error)?;

        if self.get_errors() != 0 {
            return Err(SleighException::with_message(format!(
                "Errors compiling p-code at {location}: {}",
                self.base.error_messages().join("; ")
            )));
        }
        match rtl {
            Some(SemanticResult::Sections(main)) => self.build_constructor(main),
            Some(SemanticResult::MacroBody(_)) | None => Err(SleighException::with_message(
                "Unrecoverable error(s), halting compilation",
            )),
        }
    }
}

fn sleigh_error(e: SleighError) -> SleighException {
    SleighException::with_message(message_formatting_utils::format(Some(&e.location), e.message()))
}

impl PcodeCompile for PcodeParser {
    /// A p-code fragment has no named sections: just the main section.
    type Sections = ConstructTpl;

    fn base(&self) -> &PcodeCompileBase {
        &self.base
    }

    fn base_mut(&mut self) -> &mut PcodeCompileBase {
        &mut self.base
    }

    fn get_default_space(&self) -> Arc<AddressSpace> {
        self.sleigh.get_default_space()
    }

    fn get_constant_space(&self) -> Arc<AddressSpace> {
        self.sleigh.get_constant_space()
    }

    fn get_default_space_is_big_endian(&self) -> bool {
        self.sleigh.is_big_endian()
    }

    /// No particular size: try to resolve in context.
    fn get_default_constant_size(&self) -> i32 {
        0
    }

    fn get_unique_space(&self) -> Arc<AddressSpace> {
        self.sleigh.get_unique_space()
    }

    fn allocate_temp(&mut self) -> u64 {
        let base = self.tempbase;
        self.tempbase = base + MAX_UNIQUE_SIZE;
        base
    }

    fn add_symbol(&mut self, sym: SemanticSymbol) -> Result<(), SleighError> {
        let name = sym.name().to_string();
        let existing = self
            .sleigh
            .find_symbol(&name)
            .or_else(|| self.symbol_map.get(&name));
        if let Some(s) = existing {
            return Err(SleighError::new(
                format!(
                    "Duplicate symbol name: {name} (previously defined at {})",
                    s.location()
                ),
                sym.location().clone(),
            ));
        }
        self.symbol_map.insert(name.clone(), sym);
        self.current_symbols.insert(name);
        Ok(())
    }

    fn find_symbol(&self, _loc: &Location, nm: &str) -> Option<&SemanticSymbol> {
        self.symbol_map.get(nm).or_else(|| self.sleigh.find_symbol(nm))
    }

    fn find_symbol_mut(&mut self, nm: &str) -> Option<&mut SemanticSymbol> {
        // Only the parser's own symbols (labels among them) are ever mutated.
        self.symbol_map.get_mut(nm)
    }

    fn new_section_symbol(&mut self, where_: &Location, _text: &str) -> Result<(), SleighError> {
        Err(sections_unsupported(where_))
    }

    fn create_cross_build(
        &mut self,
        where_: &Location,
        _v: VarnodeTpl,
        _second: &str,
    ) -> Result<Vec<OpTpl>, SleighError> {
        Err(sections_unsupported(where_))
    }

    fn enter_section(&mut self, _where: &Location) -> ConstructTpl {
        self.reset_label_count();
        ConstructTpl::new()
    }

    fn standalone_section(&mut self, main: ConstructTpl) -> ConstructTpl {
        main
    }

    fn first_named_section(
        &mut self,
        _main: ConstructTpl,
        sym: &str,
    ) -> Result<ConstructTpl, SleighError> {
        Err(sections_unsupported(&self.section_location(sym)))
    }

    fn next_named_section(
        &mut self,
        _vec: ConstructTpl,
        _section: ConstructTpl,
        sym: &str,
    ) -> Result<ConstructTpl, SleighError> {
        Err(sections_unsupported(&self.section_location(sym)))
    }

    fn final_named_section(
        &mut self,
        _vec: ConstructTpl,
        _section: ConstructTpl,
    ) -> Result<ConstructTpl, SleighError> {
        // Can never get here: no named section can be opened.
        Err(sections_unsupported(&INTERNALLY_DEFINED))
    }

    fn create_macro_use(
        &mut self,
        location: &Location,
        _macro_name: &str,
        _param: Vec<ExprTreeImpl>,
    ) -> Result<Vec<OpTpl>, SleighError> {
        Err(SleighError::new(
            "Pcode snippet parsing does not support use of macros",
            location.clone(),
        ))
    }

    /// No NOP statistics are collected for snippet parsing.
    fn record_nop(&mut self, _location: &Location) {}
}

impl PcodeParser {
    fn section_location(&self, sym: &str) -> Location {
        self.symbol_map
            .get(sym)
            .map(|s| s.location().clone())
            .unwrap_or_else(|| INTERNALLY_DEFINED.clone())
    }
}

fn sections_unsupported(where_: &Location) -> SleighError {
    SleighError::new("Pcode snippet parsing does not support use of sections", where_.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::opcodes::OpCode;
    use crate::program::model::lang::sleigh::template::{ConstTpl, ConstTplType};
    use crate::program::model::pcode::encoder::Encoder;
    use crate::program::model::pcode::ids::*;
    use crate::program::model::pcode::{PackedDecode, PackedEncode};

    /// Register-space offsets as the real ARM `.sinc` lays them out (`define register
    /// offset=0x0020 size=4 [ r0 ... r12 sp lr pc ]`, `TB` in the byte-sized flag block at 0x60).
    const ARM_REGISTERS: &[(&str, u64, i64)] = &[
        ("r0", 0x20, 4),
        ("r1", 0x24, 4),
        ("r2", 0x28, 4),
        ("r3", 0x2c, 4),
        ("r12", 0x50, 4),
        ("sp", 0x54, 4),
        ("lr", 0x58, 4),
        ("pc", 0x5c, 4),
        ("TB", 0x69, 1),
    ];

    /// A real [`SleighLanguage`] decoded from a generated `.sla`: a 4-byte little-endian `ram`
    /// (the default space), a `register` space holding `regs`, a `unique` space with temporaries
    /// starting at 0x1000, and the user ops `userops` (indices in order).
    fn language(regs: &[(&str, u64, i64)], userops: &[&str], ram_size: i64) -> SleighLanguage {
        language_with_endian(regs, userops, ram_size, false)
    }

    fn language_with_endian(
        regs: &[(&str, u64, i64)],
        userops: &[&str],
        ram_size: i64,
        big_endian: bool,
    ) -> SleighLanguage {
        // Real .sla space indices: const is 0 and OTHER is 1.
        const RAM: i32 = 2;
        const REGISTER: i32 = 3;
        const UNIQUE: i32 = 4;
        let mut e = PackedEncode::new(Vec::<u8>::new());
        let space = |e: &mut PackedEncode<Vec<u8>>, elem: ElementId, name: &str, index: i64, size: i64, delay: i64| {
            e.open_element(elem).unwrap();
            e.write_string(ATTRIB_NAME, name).unwrap();
            e.write_signed_integer(ATTRIB_INDEX, index).unwrap();
            e.write_signed_integer(ATTRIB_SIZE, size).unwrap();
            e.write_signed_integer(ATTRIB_DELAY, delay).unwrap();
            e.close_element(elem).unwrap();
        };
        e.open_element(ELEM_SLEIGH).unwrap();
        e.write_signed_integer(ATTRIB_VERSION, 4).unwrap();
        e.write_bool(ATTRIB_BIGENDIAN, big_endian).unwrap();
        e.write_signed_integer(ATTRIB_ALIGN, 1).unwrap();
        e.write_unsigned_integer(ATTRIB_UNIQBASE, 0x1000).unwrap();
        e.write_unsigned_integer(ATTRIB_UNIQMASK, 0xff).unwrap();
        e.write_unsigned_integer(ATTRIB_NUMSECTIONS, 1).unwrap();
        e.open_element(ELEM_SPACES).unwrap();
        e.write_string(ATTRIB_DEFAULTSPACE, "ram").unwrap();
        e.open_element(ELEM_SPACE_OTHER).unwrap();
        e.close_element(ELEM_SPACE_OTHER).unwrap();
        space(&mut e, ELEM_SPACE, "ram", RAM as i64, ram_size, 1);
        space(&mut e, ELEM_SPACE, "register", REGISTER as i64, 4, 0);
        space(&mut e, ELEM_SPACE_UNIQUE, "unique", UNIQUE as i64, 4, 0);
        e.close_element(ELEM_SPACES).unwrap();

        let nregs = regs.len() as u64;
        e.open_element(ELEM_SYMBOL_TABLE).unwrap();
        e.write_signed_integer(ATTRIB_SCOPESIZE, 1).unwrap();
        e.write_signed_integer(ATTRIB_SYMBOLSIZE, (nregs + userops.len() as u64) as i64).unwrap();
        e.open_element(ELEM_SCOPE).unwrap();
        e.write_unsigned_integer(ATTRIB_ID, 0).unwrap();
        e.write_unsigned_integer(ATTRIB_PARENT, 0).unwrap();
        e.close_element(ELEM_SCOPE).unwrap();
        let head = |e: &mut PackedEncode<Vec<u8>>, elem: ElementId, name: &str, id: u64| {
            e.open_element(elem).unwrap();
            e.write_string(ATTRIB_NAME, name).unwrap();
            e.write_unsigned_integer(ATTRIB_ID, id).unwrap();
            e.write_unsigned_integer(ATTRIB_SCOPE, 0).unwrap();
            e.close_element(elem).unwrap();
        };
        for (i, (name, _, _)) in regs.iter().enumerate() {
            head(&mut e, ELEM_VARNODE_SYM_HEAD, name, i as u64);
        }
        for (i, name) in userops.iter().enumerate() {
            head(&mut e, ELEM_USEROP_HEAD, name, nregs + i as u64);
        }
        for (i, (_, off, size)) in regs.iter().enumerate() {
            e.open_element(ELEM_VARNODE_SYM).unwrap();
            e.write_unsigned_integer(ATTRIB_ID, i as u64).unwrap();
            e.write_space_indexed(ATTRIB_SPACE, REGISTER, "").unwrap();
            e.write_unsigned_integer(ATTRIB_OFF, *off).unwrap();
            e.write_signed_integer(ATTRIB_SIZE, *size).unwrap();
            e.close_element(ELEM_VARNODE_SYM).unwrap();
        }
        for i in 0..userops.len() {
            e.open_element(ELEM_USEROP).unwrap();
            e.write_unsigned_integer(ATTRIB_ID, nregs + i as u64).unwrap();
            e.write_signed_integer(ATTRIB_INDEX, i as i64).unwrap();
            e.close_element(ELEM_USEROP).unwrap();
        }
        e.close_element(ELEM_SYMBOL_TABLE).unwrap();
        e.close_element(ELEM_SLEIGH).unwrap();

        let decoder = PackedDecode::new(
            Arc::new(crate::program::model::address::DefaultAddressFactory::new(vec![])),
            e.into_inner(),
        );
        SleighLanguage::decode(&decoder, "test:LE:32:default".to_string()).expect("well-formed test .sla")
    }

    fn arm() -> SleighLanguage {
        language(ARM_REGISTERS, &["setISAMode"], 4)
    }

    fn describe_const(c: &ConstTpl) -> String {
        match c.tp {
            ConstTplType::Real => format!("{:#x}", c.value_real),
            ConstTplType::SpaceId => c.value_spaceid.as_ref().unwrap().name().to_string(),
            ConstTplType::Handle => format!("handle{}.{:?}", c.handle_index, c.select.unwrap()),
            ConstTplType::JRelative => format!("rel{}", c.value_real),
            other => format!("{other:?}"),
        }
    }

    /// `space:offset:size` of a varnode template.
    fn vn(v: &VarnodeTpl) -> String {
        format!(
            "{}:{}:{}",
            describe_const(&v.space),
            describe_const(&v.offset),
            describe_const(&v.size)
        )
    }

    /// `OPCODE out = in, in` for each op.
    fn render(ct: &ConstructTpl) -> Vec<String> {
        ct.vec
            .iter()
            .map(|op| {
                let ins: Vec<String> = op.input.iter().map(vn).collect();
                match op.get_out() {
                    Some(out) => format!("{:?} {} = {}", op.get_opcode(), vn(out), ins.join(", ")),
                    None => format!("{:?} {}", op.get_opcode(), ins.join(", ")),
                }
            })
            .collect()
    }

    fn compile(lang: &SleighLanguage, src: &str) -> Result<ConstructTpl, SleighException> {
        PcodeParser::new(lang, lang.get_unique_base()).unwrap().compile_pcode(src, "test.cspec", 1)
    }

    /// ARM.cspec `<callfixup name="switch8_r0">`, verbatim.
    const ARM_SWITCH8_R0: &str = "
            tmpptr = lr & 0xfffffffe;

            offset = *:1 (tmpptr + r0);
            lr = lr + 2 * zext(offset);
 
            TB = (lr & 1) != 0;
            pc = lr & 0xfffffffe;
            goto [pc];
";

    #[test]
    fn compiles_arm_switch8_r0_callfixup() {
        let lang = arm();
        let mut parser = PcodeParser::new(&lang, 0x1000).unwrap();
        let ct = parser.compile_pcode(ARM_SWITCH8_R0, "ARM.cspec", 353).unwrap();
        assert_eq!(
            render(&ct),
            vec![
                "CpuiIntAnd unique:0x1100:0x4 = register:0x58:0x4, constant:0xfffffffe:0x4",
                "CpuiIntAdd unique:0x1200:0x4 = unique:0x1100:0x4, register:0x20:0x4",
                "CpuiLoad unique:0x1400:0x1 = constant:ram:0x8, unique:0x1200:0x4",
                "CpuiIntZext unique:0x1500:0x4 = unique:0x1400:0x1",
                "CpuiIntMult unique:0x1600:0x4 = constant:0x2:0x4, unique:0x1500:0x4",
                "CpuiIntAdd register:0x58:0x4 = register:0x58:0x4, unique:0x1600:0x4",
                "CpuiIntAnd unique:0x1800:0x4 = register:0x58:0x4, constant:0x1:0x4",
                "CpuiIntNotequal register:0x69:0x1 = unique:0x1800:0x4, constant:0x0:0x4",
                "CpuiIntAnd register:0x5c:0x4 = register:0x58:0x4, constant:0xfffffffe:0x4",
                "CpuiBranchind register:0x5c:0x4",
            ]
        );
        assert_eq!(ct.num_labels, 0);
        assert!(ct.result.is_none());
        // Eleven temporaries were allocated (one per built expression result and named local).
        assert_eq!(parser.get_next_temp_offset(), 0x1000 + 11 * MAX_UNIQUE_SIZE);
        // The spaces are the language's own.
        let ram = lang.get_address_factory().get_address_space_by_name("ram").unwrap();
        assert!(Arc::ptr_eq(ct.vec[2].input[0].offset.value_spaceid.as_ref().unwrap(), &ram));
    }

    /// ARM.cspec `<callfixup name="switch8_r3">`, verbatim: labels and conditional branches.
    const ARM_SWITCH8_R3: &str = "
            tmpptr = lr - 1;
            tblsize = *:1 tmpptr;
            r12 = zext(tblsize);

            inbounds = r3 < r12;
            
            if (!inbounds) goto <next1>;
            offset = *:1 (lr + r3);
            r3 = zext(offset);
            <next1>
            
            if (inbounds) goto <next2>;
            offset = *:1 (lr + r12);
            r3 = zext(offset);
            <next2>
            
            r3 = r3 * 2;
            
            tmpptr = lr + r3;
            r12 = tmpptr & 0x1;
            pc = r12 & 0xfffffffe;
            goto [pc];
";

    #[test]
    fn compiles_arm_switch8_r3_callfixup_with_labels() {
        let lang = arm();
        let ct = compile(&lang, ARM_SWITCH8_R3).unwrap();
        let ops = render(&ct);
        assert_eq!(ct.num_labels, 2);
        assert_eq!(
            ops[0..6],
            [
                "CpuiIntSub unique:0x1100:0x4 = register:0x58:0x4, constant:0x1:0x4",
                "CpuiLoad unique:0x1300:0x1 = constant:ram:0x8, unique:0x1100:0x4",
                "CpuiIntZext register:0x50:0x4 = unique:0x1300:0x1",
                "CpuiIntLess unique:0x1600:0x1 = register:0x2c:0x4, register:0x50:0x4",
                "CpuiBoolNegate unique:0x1700:0x1 = unique:0x1600:0x1",
                "CpuiCbranch constant:rel0:0x4, unique:0x1700:0x1",
            ]
        );
        // `<next1>` is placed as a PTRADD placeholder carrying label index 0, `<next2>` index 1.
        assert!(ops.contains(&"CpuiPtradd constant:0x0:0x4".to_string()));
        assert!(ops.contains(&"CpuiCbranch constant:rel1:0x4, unique:0x1600:0x1".to_string()));
        assert!(ops.contains(&"CpuiPtradd constant:0x1:0x4".to_string()));
        assert_eq!(ops.last().unwrap(), "CpuiBranchind register:0x5c:0x4");
    }

    #[test]
    fn compiles_x86_64_return_thunk_callfixup() {
        // x86-64-gcc.cspec `<callfixup name="x86_return_thunk">`, verbatim.
        let lang = language(&[("RAX", 0, 8), ("RSP", 0x20, 8), ("RIP", 0x288, 8)], &[], 8);
        let ct = compile(
            &lang,
            "\n\t  RIP = *:8 RSP;\n\t  RSP = RSP + 8;\n\t  return [RIP];\n        ",
        )
        .unwrap();
        assert_eq!(
            render(&ct),
            vec![
                "CpuiLoad register:0x288:0x8 = constant:ram:0x8, register:0x20:0x8",
                "CpuiIntAdd register:0x20:0x8 = register:0x20:0x8, constant:0x8:0x8",
                "CpuiReturn register:0x288:0x8",
            ]
        );
    }

    #[test]
    fn compiles_x86_64_indirect_thunk_and_fentry_callfixups() {
        let lang = language(&[("RAX", 0, 8), ("RSP", 0x20, 8)], &[], 8);
        // `<callfixup name="x86_indirect_thunk_rax">`
        assert_eq!(
            render(&compile(&lang, "\n\t  call [RAX];\n        ").unwrap()),
            vec!["CpuiCallind register:0x0:0x8"]
        );
        // `<callfixup name="fentry">`: a sized local, the constant takes the declared size.
        assert_eq!(
            render(&compile(&lang, "\n\t  temp:1 = 0;\n        ").unwrap()),
            vec!["CpuiCopy unique:0x1000:0x1 = constant:0x0:0x1"]
        );
    }

    #[test]
    fn user_ops_operands_and_inst_symbols() {
        let lang = arm();
        let mut parser = PcodeParser::new(&lang, 0x1000).unwrap();
        let loc = Location::new("test.cspec", 1);
        parser.add_operand(&loc, "in0", 0).unwrap();
        parser.add_operand(&loc, "out", 1).unwrap();
        let ct = parser
            .compile_pcode("setISAMode(in0); out = in0; r0 = inst_next; call inst_start;", "t", 1)
            .unwrap();
        assert_eq!(
            render(&ct),
            vec![
                "CpuiCallother constant:0x0:0x4, handle0.VSpace:handle0.VOffset:handle0.VSize",
                "CpuiCopy handle1.VSpace:handle1.VOffset:handle1.VSize = handle0.VSpace:handle0.VOffset:handle0.VSize",
                "CpuiCopy register:0x20:0x4 = constant:JNext:0x4",
                "CpuiCall JCurSpace:JStart:JCurSpaceSize",
            ]
        );
        // Operand names cannot be redefined.
        let err = parser.add_operand(&loc, "in0", 2).unwrap_err();
        assert!(err.message().starts_with("Duplicate symbol name: in0"), "{}", err.message());
        // clear_symbols forgets them again.
        parser.clear_symbols();
        parser.add_operand(&loc, "in0", 2).unwrap();
        // ...but a language register can never be shadowed.
        assert!(parser.add_operand(&loc, "r0", 3).is_err());
    }

    #[test]
    fn builtins_bitranges_and_stores() {
        let lang = arm();
        let ct = compile(
            &lang,
            "r0 = sext(r1:1); *[ram]:2 r2 = r3; r1 = popcount(r0); r2 = r3[8,8]; r3 = &r0;",
        )
        .unwrap();
        assert_eq!(
            render(&ct),
            vec![
                // `r1:1` is the low byte of r1 (a truncated varnode, no op needed).
                "CpuiIntSext register:0x20:0x4 = register:0x24:0x1",
                "CpuiStore constant:ram:0x8, register:0x28:0x4, register:0x2c:0x4",
                "CpuiPopcount register:0x24:0x4 = register:0x20:0x4",
                // `r3[8,8]` is byte 1 of r3 (little-endian truncation).
                "CpuiCopy register:0x28:0x4 = register:0x2d:0x1",
                // `&r0` is the register offset as a constant of the space's address size.
                "CpuiCopy register:0x2c:0x4 = constant:0x20:0x4",
            ]
        );
    }

    #[test]
    fn unaligned_bit_ranges_mask_and_shift() {
        let lang = arm();
        // Assigning bits 3..4 of r0: clear them, then OR in r1 zero-extended and shifted.
        assert_eq!(
            render(&compile(&lang, "r0[3,2] = r1;").unwrap()),
            vec![
                "CpuiIntAnd unique:0x1000:0x4 = register:0x20:0x4, constant:0xffffffffffffffe7:0x4",
                "CpuiIntZext unique:0x1100:0x4 = register:0x24:0x4",
                "CpuiIntLeft unique:0x1200:0x4 = unique:0x1100:0x4, constant:0x3:0x4",
                "CpuiIntOr register:0x20:0x4 = unique:0x1000:0x4, unique:0x1200:0x4",
            ]
        );
        // Reading bits 3..4 of r0: shift, truncate, mask.
        assert_eq!(
            render(&compile(&lang, "r1 = r0[3,2];").unwrap()),
            vec![
                "CpuiIntRight unique:0x1000:0x4 = register:0x20:0x4, constant:0x3:0x4",
                "CpuiSubpiece unique:0x1100:0x4 = unique:0x1000:0x4, constant:0x0:0x4",
                "CpuiIntAnd register:0x24:0x4 = unique:0x1100:0x4, constant:0x3:0x1",
            ]
        );
    }

    #[test]
    fn big_endian_truncation_counts_from_the_high_end() {
        let lang = language_with_endian(ARM_REGISTERS, &[], 4, true);
        // Byte 1 (bits 8..15) of the 4-byte r3 at 0x2c lives at 0x2c + 4 - 2 when big-endian.
        assert_eq!(
            render(&compile(&lang, "r2 = r3[8,8];").unwrap()),
            vec!["CpuiCopy register:0x28:0x4 = register:0x2e:0x1"]
        );
    }

    #[test]
    fn undefined_symbol_is_an_error() {
        let err = compile(&arm(), "r0 = nosuchreg;").unwrap_err();
        assert!(
            err.message().contains("unknown varnode or bitrange symbol 'nosuchreg' in expression"),
            "{}",
            err.message()
        );
        let err = compile(&arm(), "nosuchop(r0);").unwrap_err();
        assert!(err.message().contains("unknown macro, userop, or specific symbol 'nosuchop'"));
    }

    #[test]
    fn size_mismatch_is_an_error() {
        // `t` is stored as 2 bytes, then copied from a 4-byte register.
        let err = compile(&arm(), "local t; t = r0; *:2 r1 = t;").unwrap_err();
        assert!(err.message().contains("Input size mismatch: 2 vs 4"), "{}", err.message());
        // A size nothing can resolve.
        let err = compile(&arm(), "local t; r0 = zext(t);").unwrap_err();
        assert!(err.message().contains("Could not resolve at least 1 variable size"));
    }

    #[test]
    fn fragment_restrictions() {
        let lang = arm();
        assert!(compile(&lang, "<lab> r0 = 1;")
            .unwrap_err()
            .message()
            .contains("Label <lab> was placed but never used"));
        assert!(compile(&lang, "goto <lab>;")
            .unwrap_err()
            .message()
            .contains("Label <lab> was referenced but never placed"));
        assert!(compile(&lang, "export r0;")
            .unwrap_err()
            .message()
            .contains("export not permitted in pcode fragment"));
        assert!(compile(&lang, "delayslot(1);")
            .unwrap_err()
            .message()
            .contains("delayslot not permitted in pcode fragment"));
        assert!(compile(&lang, "<<sect>> r0 = 1;")
            .unwrap_err()
            .message()
            .contains("does not support use of sections"));
        assert!(compile(&lang, "r0 = r1 +;")
            .unwrap_err()
            .message()
            .starts_with("Semantic compilation error"));
        assert!(compile(&lang, "if (r0) goto [r1];")
            .unwrap_err()
            .message()
            .contains("invalid dynamic target used in goto destination"));
        assert!(compile(&lang, "r0 = zext(r1, r2);")
            .unwrap_err()
            .message()
            .contains("zext() expects 1 argument; found 2"));
    }

    #[test]
    fn translate_copies_spaces_symbols_and_skips_contextreg() {
        let lang = language(&[("r0", 0x20, 4), ("contextreg", 0x100, 4)], &["op0"], 4);
        let t = PcodeTranslate::new(&lang, 0x40).unwrap();
        let names: Vec<&str> = t.get_spaces().iter().map(|s| s.name()).collect();
        assert_eq!(names, vec!["constant", "OTHER", "ram", "register", "unique"]);
        assert!(matches!(t.find_symbol("r0"), Some(SemanticSymbol::Varnode(_))));
        assert!(matches!(t.find_symbol("op0"), Some(SemanticSymbol::UserOp(u)) if u.index() == 0));
        assert!(matches!(t.find_symbol("ram"), Some(SemanticSymbol::Space { .. })));
        assert!(t.find_symbol("contextreg").is_none());
        assert_eq!(t.get_unique_base(), 0x40);
        assert_eq!(t.get_default_space().name(), "ram");
        assert_eq!(t.get_unique_space().name(), "unique");
    }

    /// Every `<body><![CDATA[...]]></body>` p-code snippet shipped in the processor `.cspec` and
    /// `.pspec` files parses (syntax only: symbols are language-specific). Skipped when the
    /// reference sources are not checked out next to the crate.
    #[test]
    fn every_shipped_snippet_parses() {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../orig_src/Ghidra/Processors");
        if !root.is_dir() {
            eprintln!("skipping: orig_src not present");
            return;
        }
        let mut files = Vec::new();
        let mut dirs = vec![root];
        while let Some(dir) = dirs.pop() {
            for entry in std::fs::read_dir(&dir).unwrap().flatten() {
                let path = entry.path();
                if path.is_dir() {
                    dirs.push(path);
                } else if matches!(path.extension().and_then(|e| e.to_str()), Some("cspec" | "pspec")) {
                    files.push(path);
                }
            }
        }
        let (mut parsed, mut failures) = (0, Vec::new());
        for file in files {
            let text = std::fs::read_to_string(&file).unwrap_or_default();
            for chunk in text.split("<body>").skip(1) {
                let Some(body) = chunk.split("</body>").next() else { continue };
                let body = body.trim();
                let body = body
                    .strip_prefix("<![CDATA[")
                    .and_then(|b| b.strip_suffix("]]>"))
                    .unwrap_or(body);
                let mut src = String::new();
                for line in body.lines() {
                    src.push_str(line);
                    src.push('\n');
                }
                let mut lexer = BaseLexer::new(&src);
                match SemanticParser::new(&mut lexer).parse_semantic_snippet() {
                    Ok(_) => parsed += 1,
                    Err(e) => failures.push(format!("{}: {e}", file.display())),
                }
            }
        }
        assert!(parsed > 100, "only {parsed} snippets found");
        assert!(failures.is_empty(), "{} of {} snippets failed:\n{}", failures.len(), parsed + failures.len(), failures.join("\n"));
    }
}

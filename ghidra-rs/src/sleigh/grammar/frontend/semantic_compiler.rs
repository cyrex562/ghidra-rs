//! The semantic-section pass of `SleighCompiler.g` (the ANTLR tree grammar that drives the
//! pcodeCPort backend), over the hand-written [`SemanticBody`] AST.
//!
//! Java walks the parser's `OP_SEMANTIC` tree with the `semantic` rule and its sub-rules
//! (`code_block`, `statement`, `assignment`, `expr`, `jumpdest`, `expr_apply`, ...), calling a
//! [`PcodeCompile`] for every node. [`compile_semantic`] does the same walk over the typed
//! statements, rule for rule, with the same symbol checks and error messages
//! (`AbstractSleighCompiler`'s `wrongSymbolTypeError`, `unknownSymbolError`, ...).
//!
//! Differences from the tree grammar, all forced by the input being a typed AST rather than a
//! token tree:
//!
//! - **Locations.** The AST carries no per-node positions, so every location the walker reports
//!   (Java's `find(tree)`) is the container location passed in.
//! - **Error recovery.** When Java's walker reports an error it leaves the rule's value `null`
//!   and carries on; the next action that touches the value usually dies with a
//!   `NullPointerException` (which `PcodeParser.compilePcode` turns into "Unrecoverable
//!   error(s)"). Here a failed sub-rule yields `None` and the enclosing statement contributes no
//!   ops; the caller sees the reported errors through [`PcodeCompile::get_errors`].
//! - **Shapes the tree grammar has no alternative for** (`local *p = ...`, `local x[0,1] = ...`,
//!   an `export` of something that is not a varnode) are Java `RecognitionException`s; they are
//!   returned as a [`SleighError`].

use crate::decompiler::context::SleighError;
use crate::decompiler::opcodes::OpCode;
use crate::decompiler::slgh_compile::pcode_compile::{
    addr_size, const_of_type, const_real, const_space, ApplyResult, PcodeCompile, SemanticSymbol,
};
use crate::decompiler::slgh_compile::pcode_compile::add_op_list;
use crate::decompiler::slgh_compile::{ExprTree, ExprTreeImpl, StarQuality};
use crate::decompiler::slghsymbol::SymbolType;
use crate::program::model::lang::sleigh::template::{
    ConstTplType, ConstructTpl, OpTpl, VarnodeTpl,
};
use crate::sleigh::grammar::Location;

use super::ast::*;

/// What the `semantic` rule produced.
pub enum SemanticResult<S> {
    /// The sections of a constructor body or p-code snippet (`$semantic::sections`).
    Sections(S),
    /// The body of a `macro` (`$macrodef::macrobody`), when compiled with `is_macro_parse`.
    MacroBody(ConstructTpl),
}

/// Compiles one semantic section (Java's `SleighCompiler.semantic(env, containerLoc, pcode,
/// where, sectionsAllowed, isMacroParse)`).
///
/// Errors the walker reports go to `pcode` ([`PcodeCompile::report_error`]); `Err` is returned
/// only for what Java throws (a `SleighError` from the builder, or a tree shape the grammar
/// rejects).
pub fn compile_semantic<P: PcodeCompile>(
    pcode: &mut P,
    body: &SemanticBody,
    container_loc: &Location,
    sections_allowed: bool,
    is_macro_parse: bool,
) -> Result<Option<SemanticResult<P::Sections>>, SleighError> {
    let mut walker = Walker {
        pcode,
        loc: container_loc.clone(),
        sections: None,
        contains_multiple_sections: false,
        next_statement_must_be_section_label: false,
        can_contain_sections: sections_allowed,
        jump: Vec::new(),
    };
    walker.semantic(body, is_macro_parse)
}

struct Walker<'p, P: PcodeCompile> {
    pcode: &'p mut P,
    /// Every location this walker reports (see the module docs).
    loc: Location,
    sections: Option<P::Sections>,
    contains_multiple_sections: bool,
    next_statement_must_be_section_label: bool,
    can_contain_sections: bool,
    /// The `Jump` scope stack: whether the innermost `goto`/`call` target is indirect.
    jump: Vec<bool>,
}

/// A statement's contribution to the block (Java's `ops` local of the `statement` rule).
type StmtOps = Option<Vec<OpTpl>>;

impl<P: PcodeCompile> Walker<'_, P> {
    fn report_error(&mut self, msg: &str) {
        let loc = self.loc.clone();
        self.pcode.report_error(Some(&loc), msg);
    }

    fn wrong_symbol_type_error(&mut self, sym: (SymbolType, String, Location), ty: &str, purpose: &str) {
        let (kind, name, defined) = sym;
        self.report_error(&format!(
            "{kind:?} '{name}' (defined at {defined}) is wrong type (should be {ty}) in {purpose}"
        ));
    }

    fn undeclared_symbol_error(&mut self, name: &str, purpose: &str) {
        self.report_error(&format!(
            "'{name}' (used in {purpose}) is not declared in the pattern list"
        ));
    }

    fn unknown_symbol_error(&mut self, text: &str, ty: &str, purpose: &str) {
        self.report_error(&format!("unknown {ty} '{text}' in {purpose}"));
    }

    fn redefined_error(&mut self, sym: (SymbolType, String, Location), what: &str) {
        let (_, name, defined) = sym;
        self.report_error(&format!("symbol '{name}' (from {defined}) redefined as {what}"));
    }

    /// `(type, name, location)` of the symbol named `name`, if any.
    fn describe(&self, name: &str) -> Option<(SymbolType, String, Location)> {
        self.pcode
            .find_symbol(&self.loc, name)
            .map(|s| (s.symbol_type(), s.name().to_string(), s.location().clone()))
    }

    /// Java's `toUInt`: sizes, bit offsets and the like must fit an unsigned 32-bit value.
    fn to_uint(&mut self, i: Integer) -> i32 {
        if i.value < 0 || i.value > u32::MAX as i64 {
            self.report_error(&format!("Integer cannot be represented as unsigned int: {}", i.value));
        }
        i.value as i32
    }

    // ----- semantic / code_block / statement ----------------------------------------------

    fn semantic(
        &mut self,
        body: &SemanticBody,
        is_macro_parse: bool,
    ) -> Result<Option<SemanticResult<P::Sections>>, SleighError> {
        let c = self.code_block(body)?;
        if c.vec.is_empty() && c.result.is_none() {
            let loc = self.loc.clone();
            self.pcode.record_nop(&loc);
        }
        if self.contains_multiple_sections {
            let sections = self.sections.take().expect("a named section was opened");
            return Ok(Some(SemanticResult::Sections(
                self.pcode.final_named_section(sections, c)?,
            )));
        }
        if is_macro_parse {
            return Ok(Some(SemanticResult::MacroBody(c)));
        }
        Ok(Some(SemanticResult::Sections(self.pcode.standalone_section(c))))
    }

    fn code_block(&mut self, body: &SemanticBody) -> Result<ConstructTpl, SleighError> {
        let loc = self.loc.clone();
        let mut ct = self.pcode.enter_section(&loc);
        for stmt in &body.statements {
            ct = self.statement(stmt, ct)?;
        }
        Ok(ct)
    }

    fn statement(&mut self, stmt: &PcodeStmt, mut ct: ConstructTpl) -> Result<ConstructTpl, SleighError> {
        let mut ops: StmtOps = Some(Vec::new());
        let mut was_section_label = false;
        let looking_for_section_label = self.next_statement_must_be_section_label;
        match stmt {
            PcodeStmt::Assign { local, lvalue, rhs } => ops = self.assignment(*local, lvalue, rhs)?,
            PcodeStmt::LocalDecl { name, size } => {
                self.declaration(name, *size)?;
                ops = None;
            }
            PcodeStmt::Funcall { name, args } => ops = self.funcall(name, args)?,
            PcodeStmt::Build { operand } => ops = self.build_stmt(operand),
            PcodeStmt::CrossBuild { address, section } => {
                ops = self.crossbuild_stmt(address, section)?
            }
            PcodeStmt::Goto { dest } => {
                self.jump.push(false);
                let j = self.jumpdest(dest, "goto destination");
                let indirect = self.jump.pop().unwrap_or(false);
                let j = j?;
                ops = j.map(|j| {
                    let opc = if indirect { OpCode::CpuiBranchind } else { OpCode::CpuiBranch };
                    self.pcode.create_op_no_out(&self.loc.clone(), opc, j)
                });
            }
            PcodeStmt::IfGoto { cond, dest } => {
                let e = self.expr(cond)?;
                // cond_stmt opens no Jump scope: a dynamic target is invalid here.
                let j = self.jumpdest(dest, "goto destination")?;
                ops = match (j, e) {
                    (Some(j), Some(e)) => Some(self.pcode.create_op_no_out2(
                        &self.loc.clone(),
                        OpCode::CpuiCbranch,
                        j,
                        e,
                    )),
                    _ => None,
                };
            }
            PcodeStmt::Call { dest } => {
                self.jump.push(false);
                let j = self.jumpdest(dest, "call destination");
                let indirect = self.jump.pop().unwrap_or(false);
                ops = j?.map(|j| {
                    let opc = if indirect { OpCode::CpuiCallind } else { OpCode::CpuiCall };
                    self.pcode.create_op_no_out(&self.loc.clone(), opc, j)
                });
            }
            PcodeStmt::Return { dest } => {
                ops = self.expr(dest)?.map(|e| {
                    self.pcode.create_op_no_out(&self.loc.clone(), OpCode::CpuiReturn, e)
                });
            }
            PcodeStmt::Label { name } => {
                if let Some(name) = self.label(name)? {
                    let loc = self.loc.clone();
                    ops = Some(self.pcode.place_label(&loc, &name));
                }
            }
            PcodeStmt::Export(export) => {
                ct = self.export(export, ct)?;
                if self.contains_multiple_sections {
                    self.report_error("Export only allowed in default section");
                }
                self.next_statement_must_be_section_label = true;
            }
            PcodeStmt::SectionLabel { name } => {
                if !self.can_contain_sections {
                    self.report_error("No sections allowed");
                }
                was_section_label = true;
                if let Some(section) = self.section_label(name)? {
                    let finished = std::mem::replace(&mut ct, ConstructTpl::new());
                    let was_empty = finished.vec.is_empty() && finished.result.is_none();
                    self.sections = Some(if self.contains_multiple_sections {
                        let sections = self.sections.take().expect("a named section was opened");
                        self.pcode.next_named_section(sections, finished, &section)?
                    } else {
                        self.pcode.first_named_section(finished, &section)?
                    });
                    let loc = self.loc.clone();
                    if was_empty {
                        self.pcode.record_nop(&loc);
                    }
                    self.contains_multiple_sections = true;
                    ct = self.pcode.enter_section(&loc);
                }
            }
        }
        // @after
        if looking_for_section_label && !was_section_label {
            self.report_error("No statements allowed after export");
        }
        self.next_statement_must_be_section_label = false;
        if let Some(ops) = ops {
            if !add_op_list(&mut ct, ops) {
                self.report_error("Multiple delayslot declarations");
            }
        }
        Ok(ct)
    }

    /// `unbound_identifier`: `name` must not name an existing symbol.
    fn unbound_identifier(&mut self, name: &str, purpose: &str) -> bool {
        match self.describe(name) {
            Some(sym) => {
                self.redefined_error(sym, purpose);
                false
            }
            None => true,
        }
    }

    fn declaration(&mut self, name: &str, size: Option<Integer>) -> Result<(), SleighError> {
        let purpose = if size.is_some() { "sized local declaration" } else { "local declaration" };
        if !self.unbound_identifier(name, purpose) {
            return Ok(());
        }
        let size = size.map(|i| self.to_uint(i)).unwrap_or(0);
        let loc = self.loc.clone();
        self.pcode.new_local_definition(&loc, name, size)
    }

    /// `label`: the label named `name`, found or newly defined. `None` if `name` names some other
    /// kind of symbol (reported).
    fn label(&mut self, name: &str) -> Result<Option<String>, SleighError> {
        match self.describe(name) {
            Some((SymbolType::LabelSymbol, _, _)) => Ok(Some(name.to_string())),
            Some(sym) => {
                self.wrong_symbol_type_error(sym, "label", "label");
                Ok(None)
            }
            None => {
                let loc = self.loc.clone();
                self.pcode.define_label(&loc, name)?;
                Ok(Some(name.to_string()))
            }
        }
    }

    /// `section_label` / `section_symbol`: the section named `name`, found or newly created.
    fn section_label(&mut self, name: &str) -> Result<Option<String>, SleighError> {
        match self.describe(name) {
            Some((SymbolType::SectionSymbol, _, _)) => Ok(Some(name.to_string())),
            Some(sym) => {
                self.wrong_symbol_type_error(sym, "section", "section");
                Ok(None)
            }
            None => {
                let loc = self.loc.clone();
                self.pcode.new_section_symbol(&loc, name)?;
                Ok(Some(name.to_string()))
            }
        }
    }

    /// `specific_symbol`: the varnode of the start/end/next2/flowref/flowdest/operand/epsilon/
    /// varnode symbol `name`, with its location.
    fn specific_symbol(&mut self, name: &str, purpose: &str) -> Option<(VarnodeTpl, Location)> {
        let found = self
            .pcode
            .find_symbol(&self.loc, name)
            .map(|s| (s.specific_varnode(), s.location().clone()));
        match found {
            None => {
                self.unknown_symbol_error(
                    name,
                    "start, end, next2, operand, epsilon, or varnode",
                    purpose,
                );
                None
            }
            Some((None, _)) => {
                self.undeclared_symbol_error(name, purpose);
                None
            }
            Some((Some(vn), loc)) => Some((vn, loc)),
        }
    }

    /// `space_symbol`: the address space named `name`.
    fn space_symbol(
        &mut self,
        name: &str,
        purpose: &str,
    ) -> Option<std::sync::Arc<crate::program::model::address::AddressSpace>> {
        match self.pcode.find_symbol(&self.loc, name) {
            Some(SemanticSymbol::Space { space, .. }) => Some(space.clone()),
            Some(_) => {
                let sym = self.describe(name).expect("found above");
                self.wrong_symbol_type_error(sym, "space", purpose);
                None
            }
            None => {
                self.unknown_symbol_error(name, "space", purpose);
                None
            }
        }
    }

    fn assignment(
        &mut self,
        local: bool,
        lvalue: &Lvalue,
        rhs: &PcodeExpr,
    ) -> Result<StmtOps, SleighError> {
        let loc = self.loc.clone();
        match lvalue {
            Lvalue::BitRange { name, lsb, size } => {
                if local {
                    return Err(SleighError::new(
                        "no viable alternative: 'local' bit range assignment",
                        loc,
                    ));
                }
                let ss = self.specific_symbol(name, "bit range assignment");
                let a = self.to_uint(*lsb);
                let b = self.to_uint(*size);
                let e = self.expr(rhs)?;
                match (ss, e) {
                    (Some((vn, _)), Some(e)) => {
                        Ok(Some(self.pcode.assign_bit_range(&loc, vn, a, b, e)?))
                    }
                    _ => Ok(None),
                }
            }
            Lvalue::SizedId { name, size } => {
                let bound = self.unbound_identifier(name, "variable declaration/assignment");
                let size = self.to_uint(*size);
                let e = self.expr(rhs)?;
                match e {
                    Some(e) if bound => {
                        Ok(Some(self.pcode.new_output(&loc, true, e, name, size)?))
                    }
                    _ => Ok(None),
                }
            }
            Lvalue::Id(name) if local => {
                let bound = self.unbound_identifier(name, "variable declaration/assignment");
                let e = self.expr(rhs)?;
                match e {
                    Some(e) if bound => Ok(Some(self.pcode.new_output(&loc, true, e, name, 0)?)),
                    _ => Ok(None),
                }
            }
            Lvalue::Id(name) => {
                let e = self.expr(rhs)?;
                let Some(mut e) = e else {
                    return Ok(None);
                };
                let found = self
                    .pcode
                    .find_symbol(&loc, name)
                    .map(|s| (s.specific_varnode(), s.symbol_type(), s.name().to_string(), s.location().clone()));
                match found {
                    None => Ok(Some(self.pcode.new_output(&loc, false, e, name, 0)?)),
                    Some((Some(v), _, _, _)) => {
                        e.set_output(loc, v)?;
                        Ok(e.to_vector())
                    }
                    Some((None, kind, sname, sloc)) => {
                        self.wrong_symbol_type_error(
                            (kind, sname, sloc),
                            "start, end, next2, operand, epsilon, or varnode",
                            "assignment",
                        );
                        Ok(None)
                    }
                }
            }
            Lvalue::Deref { star, addr } => {
                if local {
                    return Err(SleighError::new(
                        "no viable alternative: 'local' dereference assignment",
                        loc,
                    ));
                }
                let q = self.sizedstar(star);
                let ptr = self.expr(addr)?;
                let f = self.expr(rhs)?;
                match (q, ptr, f) {
                    (Some(q), Some(ptr), Some(f)) => {
                        Ok(Some(self.pcode.create_store(&loc, &q, ptr, f)?))
                    }
                    _ => Ok(None),
                }
            }
        }
    }

    /// The `StarQuality` half of `sizedstar` / `sizedstarv`.
    fn sizedstar(&mut self, star: &SizedStar) -> Option<StarQuality> {
        let mut q = StarQuality::new(self.loc.clone());
        let id = match &star.space {
            Some(space) => const_space(self.space_symbol(space, "sized star operator")?),
            None => const_space(self.pcode.get_default_space()),
        };
        let size = star.size.map(|i| self.to_uint(i)).unwrap_or(0);
        q.set_size(size);
        q.set_id(id);
        Some(q)
    }

    fn funcall(&mut self, name: &str, args: &[PcodeExpr]) -> Result<StmtOps, SleighError> {
        // $Return::noReturn = true
        match self.expr_apply(name, args, true)? {
            Some(ApplyResult::Ops(ops)) => Ok(Some(ops)),
            Some(ApplyResult::Expr(_)) => {
                self.report_error("Functional operator requires a return value");
                Ok(None)
            }
            None => {
                self.report_error("Functional operator requires a return value");
                Ok(None)
            }
        }
    }

    fn build_stmt(&mut self, operand: &str) -> StmtOps {
        let index = match self.pcode.find_symbol(&self.loc, operand) {
            Some(SemanticSymbol::Operand { index, .. }) => *index,
            Some(_) => {
                let sym = self.describe(operand).expect("found above");
                self.wrong_symbol_type_error(sym, "operand", "build statement");
                return None;
            }
            None => {
                self.unknown_symbol_error(operand, "operand", "build statement");
                return None;
            }
        };
        let loc = self.loc.clone();
        Some(self.pcode.create_op_const(&loc, OpCode::CpuiMultiequal, index as u64))
    }

    fn crossbuild_stmt(&mut self, address: &PcodeExpr, section: &str) -> Result<StmtOps, SleighError> {
        let v = self.varnode(address, "varnode reference")?;
        let s = self.section_label(section)?;
        match (v, s) {
            (Some(v), Some(s)) => {
                let loc = self.loc.clone();
                Ok(Some(self.pcode.create_cross_build(&loc, v, &s)?))
            }
            _ => Ok(None),
        }
    }

    /// `jump_symbol` + `jumpdest`.
    fn jumpdest(&mut self, dest: &JumpDest, purpose: &str) -> Result<Option<ExprTreeImpl>, SleighError> {
        let loc = self.loc.clone();
        match dest {
            JumpDest::Symbol(name) => {
                let found = self
                    .pcode
                    .find_symbol(&loc, name)
                    .map(|s| (s.symbol_type(), s.specific_varnode()));
                let vn = match found {
                    None => {
                        self.unknown_symbol_error(name, "start, end, or operand", purpose);
                        return Ok(None);
                    }
                    Some((
                        SymbolType::StartSymbol
                        | SymbolType::EndSymbol
                        | SymbolType::Next2Symbol
                        | SymbolType::FlowdestSymbol
                        | SymbolType::FlowrefSymbol,
                        Some(ss),
                    )) => VarnodeTpl::with_fields(
                        const_of_type(ConstTplType::JCurSpace),
                        ss.offset,
                        const_of_type(ConstTplType::JCurSpaceSize),
                    ),
                    // Java also marks the operand as a code address (`setCodeAddress`), which
                    // only matters to a full .slaspec compile's operand bookkeeping.
                    Some((SymbolType::OperandSymbol, Some(vn))) => vn,
                    Some(_) => {
                        let sym = self.describe(name).expect("found above");
                        self.wrong_symbol_type_error(sym, "start, end, or operand", purpose);
                        return Ok(None);
                    }
                };
                Ok(Some(ExprTreeImpl::with_varnode(loc, vn)))
            }
            JumpDest::Dynamic(e) => {
                let e = self.expr(e)?;
                match self.jump.last_mut() {
                    None => {
                        self.report_error(&format!("invalid dynamic target used in {purpose}"));
                    }
                    Some(indirect) => *indirect = true,
                }
                Ok(e)
            }
            JumpDest::Absolute(i) => Ok(Some(ExprTreeImpl::with_varnode(
                loc,
                VarnodeTpl::with_fields(
                    const_of_type(ConstTplType::JCurSpace),
                    const_real(i.value as u64),
                    const_of_type(ConstTplType::JCurSpaceSize),
                ),
            ))),
            JumpDest::Relative { offset, space } => {
                let Some(spc) = self.space_symbol(space, purpose) else {
                    return Ok(None);
                };
                let size = addr_size(&spc);
                Ok(Some(ExprTreeImpl::with_varnode(
                    loc,
                    VarnodeTpl::with_fields(
                        const_space(spc),
                        const_real(offset.value as u64),
                        const_real(size as u64),
                    ),
                )))
            }
            JumpDest::Label(name) => {
                let Some(name) = self.label(name)? else {
                    return Ok(None);
                };
                let mut index = 0;
                if let Some(SemanticSymbol::Label(labsym)) = self.pcode.find_symbol_mut(&name) {
                    index = labsym.index();
                    labsym.increment_ref_count();
                }
                let mut rel = const_of_type(ConstTplType::JRelative);
                rel.value_real = index as u64;
                Ok(Some(ExprTreeImpl::with_varnode(
                    loc,
                    VarnodeTpl::with_fields(
                        const_space(self.pcode.get_constant_space()),
                        rel,
                        const_real(4),
                    ),
                )))
            }
        }
    }

    fn export(&mut self, export: &Export, ct: ConstructTpl) -> Result<ConstructTpl, SleighError> {
        match export {
            Export::Sized { star, name } => {
                let q = self.sizedstar(star);
                let ss = self.specific_symbol(name, "varnode reference");
                match (q, ss) {
                    (Some(q), Some((vn, _))) => Ok(self.pcode.set_result_star_varnode(ct, &q, vn)),
                    _ => Ok(ct),
                }
            }
            Export::Varnode(v) => match self.varnode(v, "varnode reference")? {
                Some(vn) => Ok(self.pcode.set_result_varnode(ct, vn)),
                None => Ok(ct),
            },
        }
    }

    // ----- expressions -----------------------------------------------------------------------

    fn expr(&mut self, e: &PcodeExpr) -> Result<Option<ExprTreeImpl>, SleighError> {
        let loc = self.loc.clone();
        match e {
            PcodeExpr::Binary { op, lhs, rhs } => {
                let l = self.expr(lhs)?;
                let r = self.expr(rhs)?;
                let (Some(l), Some(r)) = (l, r) else {
                    return Ok(None);
                };
                use PcodeBinOp as B;
                // (opcode, operands swapped)
                let (opc, swap) = match op {
                    B::BoolOr => (OpCode::CpuiBoolOr, false),
                    B::BoolXor => (OpCode::CpuiBoolXor, false),
                    B::BoolAnd => (OpCode::CpuiBoolAnd, false),
                    B::Or => (OpCode::CpuiIntOr, false),
                    B::Xor => (OpCode::CpuiIntXor, false),
                    B::And => (OpCode::CpuiIntAnd, false),
                    B::Equal => (OpCode::CpuiIntEqual, false),
                    B::NotEqual => (OpCode::CpuiIntNotequal, false),
                    B::FEqual => (OpCode::CpuiFloatEqual, false),
                    B::FNotEqual => (OpCode::CpuiFloatNotequal, false),
                    B::Less => (OpCode::CpuiIntLess, false),
                    B::GreatEqual => (OpCode::CpuiIntLessequal, true),
                    B::LessEqual => (OpCode::CpuiIntLessequal, false),
                    B::Great => (OpCode::CpuiIntLess, true),
                    B::SLess => (OpCode::CpuiIntSless, false),
                    B::SGreatEqual => (OpCode::CpuiIntSlessequal, true),
                    B::SLessEqual => (OpCode::CpuiIntSlessequal, false),
                    B::SGreat => (OpCode::CpuiIntSless, true),
                    B::FLess => (OpCode::CpuiFloatLess, false),
                    B::FGreatEqual => (OpCode::CpuiFloatLessequal, true),
                    B::FLessEqual => (OpCode::CpuiFloatLessequal, false),
                    B::FGreat => (OpCode::CpuiFloatLess, true),
                    B::Left => (OpCode::CpuiIntLeft, false),
                    B::Right => (OpCode::CpuiIntRight, false),
                    B::SRight => (OpCode::CpuiIntSright, false),
                    B::Add => (OpCode::CpuiIntAdd, false),
                    B::Sub => (OpCode::CpuiIntSub, false),
                    B::FAdd => (OpCode::CpuiFloatAdd, false),
                    B::FSub => (OpCode::CpuiFloatSub, false),
                    B::Mult => (OpCode::CpuiIntMult, false),
                    B::Div => (OpCode::CpuiIntDiv, false),
                    B::Rem => (OpCode::CpuiIntRem, false),
                    B::SDiv => (OpCode::CpuiIntSdiv, false),
                    B::SRem => (OpCode::CpuiIntSrem, false),
                    B::FMult => (OpCode::CpuiFloatMult, false),
                    B::FDiv => (OpCode::CpuiFloatDiv, false),
                };
                Ok(Some(if swap {
                    self.pcode.create_op2(&loc, opc, r, l)
                } else {
                    self.pcode.create_op2(&loc, opc, l, r)
                }))
            }
            PcodeExpr::Unary { op, operand } => {
                let Some(l) = self.expr(operand)? else {
                    return Ok(None);
                };
                let opc = match op {
                    PcodeUnaryOp::Not => OpCode::CpuiBoolNegate,
                    PcodeUnaryOp::Invert => OpCode::CpuiIntNegate,
                    PcodeUnaryOp::Negate => OpCode::CpuiInt2comp,
                    PcodeUnaryOp::FNegate => OpCode::CpuiFloatNeg,
                };
                Ok(Some(self.pcode.create_op(&loc, opc, l)))
            }
            PcodeExpr::Deref { star, operand } => {
                let q = self.sizedstar(star);
                let e = self.expr(operand)?;
                match (q, e) {
                    (Some(q), Some(e)) => Ok(Some(self.pcode.create_load(&q.location.clone(), &q, e)?)),
                    _ => Ok(None),
                }
            }
            PcodeExpr::Apply { name, args } => match self.expr_apply(name, args, false)? {
                Some(ApplyResult::Expr(e)) => Ok(Some(e)),
                Some(ApplyResult::Ops(_)) => {
                    // Java's `(ExprTree) $a.value` cast fails on an op list.
                    self.report_error(&format!("{name}() does not produce a value"));
                    Ok(None)
                }
                None => Ok(None),
            },
            PcodeExpr::Parenthesized(inner) => self.expr(inner),
            PcodeExpr::BitRange { name, lsb, size } => {
                let ss = self.specific_symbol(name, "bit range");
                let a = self.to_uint(*lsb);
                let b = self.to_uint(*size);
                let Some((vn, sloc)) = ss else {
                    return Ok(None);
                };
                Ok(Some(self.pcode.create_bit_range(&loc, vn, name, &sloc, a, b)?))
            }
            PcodeExpr::Integer(i) => {
                let size = self.pcode.get_default_constant_size();
                Ok(Some(ExprTreeImpl::with_varnode(
                    loc,
                    VarnodeTpl::with_fields(
                        const_space(self.pcode.get_constant_space()),
                        const_real(i.value as u64),
                        const_real(size as u64),
                    ),
                )))
            }
            PcodeExpr::Identifier(name) => self.varnode_or_bitsym(name, "expression"),
            PcodeExpr::Truncation { .. } | PcodeExpr::AddressOf { .. } => {
                Ok(self.varnode_adorned(e)?.map(|vn| ExprTreeImpl::with_varnode(loc, vn)))
            }
            PcodeExpr::SizedId { name, size } => {
                let ss = self.specific_symbol(name, "expression");
                let i = self.to_uint(*size);
                let Some((vn, sloc)) = ss else {
                    return Ok(None);
                };
                Ok(Some(self.pcode.create_bit_range(&loc, vn, name, &sloc, 0, i * 8)?))
            }
        }
    }

    fn varnode_or_bitsym(&mut self, name: &str, purpose: &str) -> Result<Option<ExprTreeImpl>, SleighError> {
        let found = self
            .pcode
            .find_symbol(&self.loc, name)
            .map(|s| s.specific_varnode());
        match found {
            None => {
                self.unknown_symbol_error(name, "varnode or bitrange symbol", purpose);
                Ok(None)
            }
            Some(Some(vn)) => Ok(Some(ExprTreeImpl::with_varnode(self.loc.clone(), vn))),
            Some(None) => {
                self.undeclared_symbol_error(name, purpose);
                Ok(None)
            }
        }
    }

    /// `expr_apply`: a built-in function, user op, macro, or sub-piece application. `no_return`
    /// is `$Return::noReturn` -- set only when the application is a whole statement.
    fn expr_apply(
        &mut self,
        name: &str,
        args: &[PcodeExpr],
        no_return: bool,
    ) -> Result<Option<ApplyResult>, SleighError> {
        // expr_operands (a fresh Return scope with noReturn = false)
        let mut o = Vec::with_capacity(args.len());
        let mut failed = false;
        for a in args {
            match self.expr(a)? {
                Some(e) => o.push(e),
                None => failed = true,
            }
        }
        if failed {
            return Ok(None);
        }
        let loc = self.loc.clone();
        if let Some(internal) = self.pcode.find_internal_function(&loc, name, &mut o) {
            return Ok(Some(internal));
        }
        let found = self.pcode.find_symbol(&loc, name).map(|s| {
            let index = match s {
                SemanticSymbol::UserOp(u) => u.index(),
                _ => 0,
            };
            (s.symbol_type(), s.specific_varnode(), index)
        });
        match found {
            None => {
                self.unknown_symbol_error(
                    name,
                    "macro, userop, or specific symbol",
                    "macro, user operation, or subpiece application",
                );
                Ok(None)
            }
            Some((SymbolType::UseropSymbol, _, index)) => Ok(Some(if no_return {
                ApplyResult::Ops(self.pcode.create_user_op_no_out(&loc, index, o))
            } else {
                ApplyResult::Expr(self.pcode.create_user_op(&loc, index, o))
            })),
            Some((SymbolType::MacroSymbol, _, _)) => {
                if no_return {
                    Ok(Some(ApplyResult::Ops(self.pcode.create_macro_use(&loc, name, o)?)))
                } else {
                    self.report_error("macro invocation not allowed as expression");
                    Ok(None)
                }
            }
            Some((_, Some(vn), _)) => {
                if o.len() != 1 {
                    self.report_error("subpiece operation requires a single operand");
                    return Ok(None);
                }
                let arg = o.pop().expect("length checked");
                let base = ExprTreeImpl::with_varnode(loc.clone(), vn);
                Ok(Some(ApplyResult::Expr(
                    self.pcode.create_op2(&loc, OpCode::CpuiSubpiece, base, arg),
                )))
            }
            Some(_) => {
                let sym = self.describe(name).expect("found above");
                self.wrong_symbol_type_error(
                    sym,
                    "macro, userop, or specific symbol",
                    "macro, user operation, or subpiece application",
                );
                Ok(None)
            }
        }
    }

    /// `varnode : specific_symbol | varnode_adorned`.
    fn varnode(&mut self, e: &PcodeExpr, purpose: &str) -> Result<Option<VarnodeTpl>, SleighError> {
        match e {
            PcodeExpr::Identifier(name) => Ok(self.specific_symbol(name, purpose).map(|(vn, _)| vn)),
            PcodeExpr::Truncation { .. } | PcodeExpr::AddressOf { .. } => self.varnode_adorned(e),
            _ => Err(SleighError::new(
                "no viable alternative: expected a varnode",
                self.loc.clone(),
            )),
        }
    }

    /// `varnode_adorned`: a truncated constant (`val:size`) or an address-of (`&var`).
    fn varnode_adorned(&mut self, e: &PcodeExpr) -> Result<Option<VarnodeTpl>, SleighError> {
        match e {
            PcodeExpr::Truncation { value, size } => {
                if size.value as u64 > 8 {
                    self.report_error(&format!(
                        "Constant varnode size must not exceed 8 ({}:{})",
                        value.value, size.value
                    ));
                }
                Ok(Some(VarnodeTpl::with_fields(
                    const_space(self.pcode.get_constant_space()),
                    const_real(value.value as u64),
                    const_real(size.value as u64),
                )))
            }
            PcodeExpr::AddressOf { size, operand } => {
                let size = size.map(|i| self.to_uint(i)).unwrap_or(0);
                let Some(v) = self.varnode(operand, "varnode reference")? else {
                    return Ok(None);
                };
                Ok(Some(self.pcode.address_of(&v, size)))
            }
            _ => self.varnode(e, "varnode reference"),
        }
    }
}

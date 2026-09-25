//! Port of `ghidra.pcodeCPort.slgh_compile.PcodeCompile`: the builder that turns the parsed
//! statements of a SLEIGH semantic section into p-code templates (`OpTpl`/`VarnodeTpl`/
//! `ConstructTpl`).
//!
//! # Shape
//!
//! Java's `PcodeCompile` is an abstract class with instance state (`noplist`, the local label
//! counter, error/warning counts, `enforceLocalKey`) and two subclasses -- `PcodeParser` (p-code
//! snippets in compiler specs) and `SleighCompile.SleighPcode` (the full `.slaspec` compiler). Per
//! the shape rules this is split into [`PcodeCompileBase`] (the state) and the [`PcodeCompile`]
//! trait, which declares the Java abstract methods as required methods and every concrete Java
//! method as a provided method working through [`PcodeCompile::base`]/[`PcodeCompile::base_mut`].
//!
//! # Templates
//!
//! The pcodeCPort compiler and the SLEIGH runtime share one set of template types in this crate
//! ([`crate::program::model::lang::sleigh::template`]), whose `ConstTpl` refers to spaces as
//! [`AddressSpace`]s. So the templates built here are directly the runtime ones; Java's
//! `PcodeParser.translate*` copy step (pcodeCPort `AddrSpace` -> `AddressSpace`, by name) has
//! nothing left to do.
//!
//! # Symbols
//!
//! Java's `findSymbol` returns a `SleighSymbol` which the tree walker then down-casts by
//! `getType()`. [`SemanticSymbol`] is the closed set of symbol kinds a semantic section can
//! resolve, each wrapping the real `pcodeCPort.slghsymbol` port where one is usable. Symbols live in
//! the implementor's table; the walker only ever borrows them long enough to read what it needs,
//! and mutations (placing/referencing a label) go through [`PcodeCompile::find_symbol_mut`].
//!
//! # Aliasing
//!
//! Java shares `VarnodeTpl` objects by reference between an expression's `outvn` and the op that
//! consumes it, so `forceSize` on one is visible through the other. Rust templates are values:
//! wherever Java relies on that sharing ([`PcodeCompile::create_store`], and every
//! `fillinZero`/`matchSize` slot), the forced size is written back to the op's own slot explicitly.
//! Local temporaries are additionally propagated by offset across the op list, exactly as Java's
//! `forceSize` loop does.

use std::sync::Arc;

use crate::decompiler::context::SleighError;
use crate::decompiler::opcodes::OpCode;
use crate::decompiler::slgh_compile::expr_tree::{ExprTree, ExprTreeImpl};
use crate::decompiler::slgh_compile::StarQuality;
use crate::decompiler::slghsymbol::{
    EndSymbol, FlowDestSymbol, FlowRefSymbol, LabelSymbol, MacroSymbol, Next2Symbol,
    SectionSymbol, SpecificSymbol, StartSymbol, SymbolType, UserOpSymbol, VarnodeSymbol,
};
use crate::pcode::utils::message_formatting_utils;
use crate::program::model::address::{AddressSpace, AddressSpaceType};
use crate::program::model::lang::sleigh::template::{
    ConstTpl, ConstTplSelect, ConstTplType, ConstructTpl, HandleTpl, OpTpl, VarnodeTpl,
};
use crate::sleigh::grammar::Location;
use crate::util::msg::Msg;

/// A symbol a semantic section can resolve by name.
///
/// The Java tree walker (`SleighCompiler.g`) receives a `SleighSymbol` from `findSymbol` and
/// switches on its `symbol_type`; these are the kinds it distinguishes. `BitrangeSymbol` and
/// `EpsilonSymbol` (only ever defined by a full `.slaspec` compile, never by a p-code snippet) are
/// not represented yet.
pub enum SemanticSymbol {
    /// A global (fixed) varnode: a register, or a named local temporary.
    Varnode(VarnodeSymbol),
    /// A user-defined p-code op (`define pcodeop`).
    UserOp(UserOpSymbol),
    /// An address space, usable in `*[space]` and `constant[space]`.
    Space {
        location: Location,
        space: Arc<AddressSpace>,
    },
    /// A p-code label (`<name>`).
    Label(LabelSymbol),
    /// An operand placeholder filled in at p-code generation time (a constructor operand, or an
    /// inject payload's input/output parameter). Java's `OperandSymbol` built with a `null`
    /// constructor: its varnode is always the dynamic handle `index`.
    Operand {
        location: Location,
        name: String,
        index: i32,
    },
    /// `inst_start`.
    Start(StartSymbol),
    /// `inst_next`.
    End(EndSymbol),
    /// `inst_next2`.
    Next2(Next2Symbol),
    /// `inst_ref`.
    FlowRef(FlowRefSymbol),
    /// `inst_dest`.
    FlowDest(FlowDestSymbol),
    /// A `macro` definition.
    Macro(MacroSymbol),
    /// A named p-code section (`<<name>>`).
    Section(SectionSymbol),
}

impl SemanticSymbol {
    /// The symbol's name (Java's `getName()`).
    pub fn name(&self) -> &str {
        match self {
            Self::Varnode(s) => s.symbol().name(),
            Self::UserOp(s) => s.symbol().name(),
            Self::Space { space, .. } => space.name(),
            Self::Label(s) => s.symbol().name(),
            Self::Operand { name, .. } => name,
            Self::Start(s) => s.symbol().name(),
            Self::End(s) => s.symbol().name(),
            Self::Next2(s) => s.symbol().name(),
            Self::FlowRef(s) => s.patternless().symbol().name(),
            Self::FlowDest(s) => s.patternless().symbol().name(),
            Self::Macro(s) => s.symbol().name(),
            Self::Section(s) => s.symbol().name(),
        }
    }

    /// Where the symbol was defined (Java's `getLocation()`).
    pub fn location(&self) -> &Location {
        match self {
            Self::Varnode(s) => s.symbol().location(),
            Self::UserOp(s) => s.symbol().location(),
            Self::Space { location, .. } => location,
            Self::Label(s) => s.symbol().location(),
            Self::Operand { location, .. } => location,
            Self::Start(s) => s.symbol().location(),
            Self::End(s) => s.symbol().location(),
            Self::Next2(s) => s.symbol().location(),
            Self::FlowRef(s) => s.patternless().symbol().location(),
            Self::FlowDest(s) => s.patternless().symbol().location(),
            Self::Macro(s) => s.symbol().location(),
            Self::Section(s) => s.symbol().location(),
        }
    }

    /// The Java `symbol_type` of this symbol.
    pub fn symbol_type(&self) -> SymbolType {
        match self {
            Self::Varnode(_) => SymbolType::VarnodeSymbol,
            Self::UserOp(_) => SymbolType::UseropSymbol,
            Self::Space { .. } => SymbolType::SpaceSymbol,
            Self::Label(_) => SymbolType::LabelSymbol,
            Self::Operand { .. } => SymbolType::OperandSymbol,
            Self::Start(_) => SymbolType::StartSymbol,
            Self::End(_) => SymbolType::EndSymbol,
            Self::Next2(_) => SymbolType::Next2Symbol,
            Self::FlowRef(_) => SymbolType::FlowrefSymbol,
            Self::FlowDest(_) => SymbolType::FlowdestSymbol,
            Self::Macro(_) => SymbolType::MacroSymbol,
            Self::Section(_) => SymbolType::SectionSymbol,
        }
    }

    /// The varnode of a `SpecificSymbol` (start, end, next2, flowref, flowdest, operand, or
    /// varnode), or `None` for any other kind -- Java's `((SpecificSymbol) sym).getVarnode()`
    /// guarded by the walker's `symbol_type` checks.
    pub fn specific_varnode(&self) -> Option<VarnodeTpl> {
        match self {
            Self::Varnode(s) => Some(s.get_varnode()),
            Self::Operand { index, .. } => Some(VarnodeTpl::with_handle(*index, false)),
            Self::Start(s) => Some(*s.get_varnode()),
            Self::End(s) => Some(*s.get_varnode()),
            Self::Next2(s) => Some(*s.get_varnode()),
            Self::FlowRef(s) => Some(*s.get_varnode()),
            Self::FlowDest(s) => Some(*s.get_varnode()),
            _ => None,
        }
    }
}

/// The result of a functional-syntax application (`name(args)`): Java's `Object` return of
/// `findInternalFunction` and of the walker's `expr_apply`, which is either an expression or (for
/// `delayslot`, user ops and macros called as statements) a bare op list.
pub enum ApplyResult {
    Expr(ExprTreeImpl),
    Ops(Vec<OpTpl>),
}

/// The instance state of Java's abstract `PcodeCompile`.
#[derive(Debug, Default)]
pub struct PcodeCompileBase {
    /// Java's public `noplist`.
    pub noplist: Vec<String>,
    local_labelcount: i32,
    errors: i32,
    warnings: i32,
    enforce_local_key: bool,
    /// Every reported error, formatted as Java logs it. Java only logs them; they are kept here
    /// so a caller can say *why* a compile failed.
    error_messages: Vec<String>,
}

impl PcodeCompileBase {
    pub fn new() -> Self {
        Self::default()
    }

    /// The formatted messages of every error reported so far.
    pub fn error_messages(&self) -> &[String] {
        &self.error_messages
    }
}

/// A real-valued constant template (Java's `new ConstTpl(const_type.real, val)`).
pub fn const_real(val: u64) -> ConstTpl {
    ConstTpl {
        tp: ConstTplType::Real,
        value_real: val,
        value_spaceid: None,
        handle_index: 0,
        select: None,
    }
}

/// A space-id constant template (Java's `new ConstTpl(AddrSpace)`).
pub fn const_space(space: Arc<AddressSpace>) -> ConstTpl {
    ConstTpl {
        tp: ConstTplType::SpaceId,
        value_real: 0,
        value_spaceid: Some(space),
        handle_index: 0,
        select: None,
    }
}

/// A constant template of a value-less type such as `j_curspace` (Java's `new
/// ConstTpl(const_type)`).
pub fn const_of_type(tp: ConstTplType) -> ConstTpl {
    ConstTpl {
        tp,
        value_real: 0,
        value_spaceid: None,
        handle_index: 0,
        select: None,
    }
}

/// Java's `ConstTpl.equals`: types must match; then reals compare values, handles compare index
/// and selector, space ids compare the space; every other type is equal by type alone.
pub fn const_tpl_equals(a: &ConstTpl, b: &ConstTpl) -> bool {
    if a.tp != b.tp {
        return false;
    }
    match a.tp {
        ConstTplType::Real => a.value_real == b.value_real,
        ConstTplType::Handle => a.handle_index == b.handle_index && a.select == b.select,
        ConstTplType::SpaceId => match (&a.value_spaceid, &b.value_spaceid) {
            (Some(x), Some(y)) => x.name() == y.name() && x.space_id() == y.space_id(),
            (None, None) => true,
            _ => false,
        },
        _ => true,
    }
}

/// Java's `VarnodeTpl.isLocalTemp()`: the varnode lives in the unique (`IPTR_INTERNAL`) space.
pub fn is_local_temp(vn: &VarnodeTpl) -> bool {
    vn.space.tp == ConstTplType::SpaceId
        && vn
            .space
            .value_spaceid
            .as_ref()
            .is_some_and(|s| s.space_type() == AddressSpaceType::Unique)
}

/// The pcodeCPort `AddrSpace.getAddrSize()` of `space`, in bytes: 8 for the constant space and
/// `OTHER`-typed spaces, 4 for the unique space (`UNIQUE_SPACE_SIZE`), otherwise the bytes needed
/// for an offset, capped at 8 (as `PcodeParser.PcodeTranslate.copySpaces` computes it).
pub fn addr_size(space: &AddressSpace) -> i32 {
    match space.space_type() {
        AddressSpaceType::Constant | AddressSpaceType::Other => 8,
        AddressSpaceType::Unique => 4,
        _ => space.pointer_size().min(8),
    }
}

/// The pcodeCPort `AddrSpace.getScale()` of `space`: log2 of its word size.
pub fn scale(space: &AddressSpace) -> u32 {
    let mut scale = 0;
    let mut wd = space.unit_size();
    while wd > 1 {
        scale += 1;
        wd >>= 1;
    }
    scale
}

/// Java's private `forceSize`: give `vt` the size `size` if it has none yet (a zero real size),
/// and if `vt` is a local temporary propagate that size to every use of the same temporary in
/// `ops`, rejecting a conflicting explicit size.
fn force_size(
    location: &Location,
    vt: &mut VarnodeTpl,
    size: &ConstTpl,
    ops: &mut [OpTpl],
) -> Result<(), SleighError> {
    if vt.size.tp != ConstTplType::Real || vt.size.value_real != 0 {
        return Ok(()); // Size already exists
    }
    vt.size = size.clone();
    if !is_local_temp(vt) {
        return Ok(());
    }
    // If the variable is a local temporary, the size may need to be propagated to the various
    // uses of the variable.
    let conflicts = |vn: &VarnodeTpl| {
        size.tp == ConstTplType::Real
            && vn.size.tp == ConstTplType::Real
            && vn.size.value_real != 0
            && vn.size.value_real != size.value_real
    };
    for op in ops.iter_mut() {
        if let Some(vn) = op.output.as_mut() {
            if is_local_temp(vn) && const_tpl_equals(&vn.offset, &vt.offset) {
                if conflicts(vn) {
                    return Err(SleighError::new(
                        format!(
                            "Localtemp size mismatch: {} vs {}",
                            vn.size.value_real as i64, size.value_real as i64
                        ),
                        location.clone(),
                    ));
                }
                vn.size = size.clone();
            }
        }
        for vn in op.input.iter_mut() {
            if is_local_temp(vn) && const_tpl_equals(&vn.offset, &vt.offset) {
                if conflicts(vn) {
                    return Err(SleighError::new(
                        format!(
                            "Input size mismatch: {} vs {}",
                            vn.size.value_real as i64, size.value_real as i64
                        ),
                        location.clone(),
                    ));
                }
                vn.size = size.clone();
            }
        }
    }
    Ok(())
}

/// Identifies one varnode slot of an op: `None` for the output, `Some(i)` for input `i`.
type Slot = Option<usize>;

fn slot_ref(op: &OpTpl, slot: Slot) -> Option<&VarnodeTpl> {
    match slot {
        None => op.output.as_ref(),
        Some(i) => op.input.get(i),
    }
}

/// `forceSize` applied to a varnode that lives *inside* `ops[op_index]` (Java passes the op's own
/// varnode object): the size is forced on a copy against the whole list, then written back to the
/// slot, which is what Java's shared reference achieves.
fn force_size_in_slot(
    location: &Location,
    ops: &mut [OpTpl],
    op_index: usize,
    slot: Slot,
    size: &ConstTpl,
) -> Result<(), SleighError> {
    let Some(mut vt) = slot_ref(&ops[op_index], slot).cloned() else {
        return Ok(());
    };
    force_size(location, &mut vt, size, ops)?;
    let op = &mut ops[op_index];
    match slot {
        None => op.output = Some(vt),
        Some(i) => op.input[i] = vt,
    }
    Ok(())
}

/// Java's `matchSize`: find a sized varnode in `ops[op_index]` to fill in the zero-size varnode
/// in slot `slot` (the output is not considered as a size source when `inputonly`).
fn match_size(
    location: &Location,
    slot: Slot,
    ops: &mut [OpTpl],
    op_index: usize,
    inputonly: bool,
) -> Result<(), SleighError> {
    let op = &ops[op_index];
    let mut matched: Option<ConstTpl> = None;
    if !inputonly {
        if let Some(out) = op.output.as_ref() {
            if !out.is_zero_size() {
                matched = Some(out.size.clone());
            }
        }
    }
    if matched.is_none() {
        matched = op
            .input
            .iter()
            .find(|vn| !vn.is_zero_size())
            .map(|vn| vn.size.clone());
    }
    if let Some(size) = matched {
        force_size_in_slot(location, ops, op_index, slot, &size)?;
    }
    Ok(())
}

/// Java's `fillinZero`: try to get rid of zero-size varnodes in `ops[op_index]` using the
/// size relationships its opcode implies.
fn fillin_zero(location: &Location, ops: &mut [OpTpl], op_index: usize) -> Result<(), SleighError> {
    use OpCode::*;
    let opc = ops[op_index].get_opcode();
    let out_zero = |ops: &[OpTpl]| ops[op_index].output.as_ref().is_some_and(|o| o.is_zero_size());
    let in_zero = |ops: &[OpTpl], i: usize| ops[op_index].input[i].is_zero_size();
    let num_in = ops[op_index].num_input();
    match opc {
        // Instructions where all inputs and output are same size
        CpuiCopy | CpuiIntAdd | CpuiIntSub | CpuiInt2comp | CpuiIntNegate | CpuiIntXor
        | CpuiIntAnd | CpuiIntOr | CpuiIntMult | CpuiIntDiv | CpuiIntSdiv | CpuiIntRem
        | CpuiIntSrem | CpuiFloatAdd | CpuiFloatDiv | CpuiFloatMult | CpuiFloatSub
        | CpuiFloatNeg | CpuiFloatAbs | CpuiFloatSqrt | CpuiFloatCeil | CpuiFloatFloor
        | CpuiFloatRound => {
            if out_zero(ops) {
                match_size(location, None, ops, op_index, false)?;
            }
            for i in 0..num_in {
                if in_zero(ops, i) {
                    match_size(location, Some(i), ops, op_index, false)?;
                }
            }
        }
        // Instructions with bool output
        CpuiIntEqual | CpuiIntNotequal | CpuiIntSless | CpuiIntSlessequal | CpuiIntLess
        | CpuiIntLessequal | CpuiIntCarry | CpuiIntScarry | CpuiIntSborrow | CpuiFloatEqual
        | CpuiFloatNotequal | CpuiFloatLess | CpuiFloatLessequal | CpuiFloatNan
        | CpuiBoolNegate | CpuiBoolXor | CpuiBoolAnd | CpuiBoolOr => {
            if out_zero(ops) {
                force_size_in_slot(location, ops, op_index, None, &const_real(1))?;
            }
            for i in 0..num_in {
                if in_zero(ops, i) {
                    match_size(location, Some(i), ops, op_index, true)?;
                }
            }
        }
        // The shift amount does not necessarily have to be the same size, but if no size is
        // specified, assume it is the same size.
        CpuiIntLeft | CpuiIntRight | CpuiIntSright | CpuiSubpiece => {
            if opc != CpuiSubpiece {
                if out_zero(ops) {
                    if !in_zero(ops, 0) {
                        let size = ops[op_index].input[0].size.clone();
                        force_size_in_slot(location, ops, op_index, None, &size)?;
                    }
                } else if in_zero(ops, 0) {
                    let size = ops[op_index].output.as_ref().map(|o| o.size.clone());
                    if let Some(size) = size {
                        force_size_in_slot(location, ops, op_index, Some(0), &size)?;
                    }
                }
            }
            // fallthru to subpiece constant check
            if in_zero(ops, 1) {
                force_size_in_slot(location, ops, op_index, Some(1), &const_real(4))?;
            }
        }
        CpuiCpoolref => {
            if out_zero(ops) && !in_zero(ops, 0) {
                let size = ops[op_index].input[0].size.clone();
                force_size_in_slot(location, ops, op_index, None, &size)?;
            }
            if in_zero(ops, 0) && !out_zero(ops) {
                let size = ops[op_index].output.as_ref().map(|o| o.size.clone());
                if let Some(size) = size {
                    force_size_in_slot(location, ops, op_index, Some(0), &size)?;
                }
            }
            for i in 1..num_in {
                force_size_in_slot(location, ops, op_index, Some(i), &const_real(8))?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Java's `ConstructTpl.addOpList` (with `addOp`): append `ops` to `ct`, counting labels
/// (`PTRADD` placeholders) and rejecting a second delay slot. Returns `false` -- leaving the op
/// that failed and everything after it unappended -- when a delay slot is already declared.
///
/// The runtime `ConstructTpl` does not store Java's `delayslot` field; it is recomputed from the
/// op list (the operand of the last `INDIRECT` placeholder, which is exactly the value `addOp`
/// would hold).
pub fn add_op_list(ct: &mut ConstructTpl, ops: Vec<OpTpl>) -> bool {
    for op in ops {
        match op.get_opcode() {
            OpCode::CpuiIndirect => {
                if delay_slot(ct) != 0 {
                    return false; // Cannot have multiple delay slots
                }
            }
            OpCode::CpuiPtradd => ct.num_labels += 1, // Count labels
            _ => {}
        }
        ct.vec.push(op);
    }
    true
}

/// Java's `ConstructTpl.delaySlot()`, recomputed from the op list (see [`add_op_list`]).
pub fn delay_slot(ct: &ConstructTpl) -> i32 {
    ct.vec
        .iter()
        .rev()
        .find(|op| op.get_opcode() == OpCode::CpuiIndirect)
        .map(|op| op.get_in(0).offset.value_real as i32)
        .unwrap_or(0)
}

/// Java's `PcodeCompile.isInternalFunction`: whether `name` is a SLEIGH built-in function.
pub fn is_internal_function(name: &str) -> bool {
    matches!(
        name,
        "zext"
            | "carry"
            | "sext"
            | "scarry"
            | "sborrow"
            | "abs"
            | "nan"
            | "sqrt"
            | "ceil"
            | "floor"
            | "round"
            | "int2float"
            | "float2float"
            | "trunc"
            | "delayslot"
            | "cpool"
            | "newobject"
            | "popcount"
            | "lzcount"
    )
}

fn take_out(expr: &mut ExprTreeImpl) -> VarnodeTpl {
    expr.take_out_varnode().unwrap_or_default()
}

fn take_ops(expr: &mut ExprTreeImpl) -> Vec<OpTpl> {
    expr.take_ops().unwrap_or_default()
}

/// The p-code builder of the SLEIGH compiler. See the module docs.
pub trait PcodeCompile {
    /// What the section callbacks produce: Java's `SectionVector` for the full compiler; a p-code
    /// snippet parser, which allows no named sections, can use the main section alone.
    type Sections;

    /// The shared instance state.
    fn base(&self) -> &PcodeCompileBase;

    /// The shared instance state, mutably.
    fn base_mut(&mut self) -> &mut PcodeCompileBase;

    // ----- Java abstract methods ------------------------------------------------------------

    fn get_default_space(&self) -> Arc<AddressSpace>;

    fn get_constant_space(&self) -> Arc<AddressSpace>;

    /// Whether the default space is big-endian (Java's `getDefaultSpace().isBigEndian()`; the
    /// runtime `AddressSpace` does not record endianness, so the implementor answers).
    fn get_default_space_is_big_endian(&self) -> bool;

    fn get_default_constant_size(&self) -> i32;

    fn get_unique_space(&self) -> Arc<AddressSpace>;

    /// Allocates the offset of a new temporary in the unique space.
    fn allocate_temp(&mut self) -> u64;

    /// Adds a symbol to the current (local) scope.
    fn add_symbol(&mut self, sym: SemanticSymbol) -> Result<(), SleighError>;

    /// Looks up a symbol by name.
    fn find_symbol(&self, loc: &Location, nm: &str) -> Option<&SemanticSymbol>;

    /// Looks up a symbol by name for mutation (placing or referencing a label). Not a Java
    /// method: Java mutates the object `findSymbol` returned.
    fn find_symbol_mut(&mut self, nm: &str) -> Option<&mut SemanticSymbol>;

    /// Creates (and registers) a new section symbol named `text`.
    fn new_section_symbol(&mut self, where_: &Location, text: &str) -> Result<(), SleighError>;

    /// Builds a `crossbuild` of `v` into the section named `second`.
    fn create_cross_build(
        &mut self,
        where_: &Location,
        v: VarnodeTpl,
        second: &str,
    ) -> Result<Vec<OpTpl>, SleighError>;

    /// Starts a new (main or named) section.
    fn enter_section(&mut self, where_: &Location) -> ConstructTpl;

    /// Wraps a body with no named sections.
    fn standalone_section(&mut self, main: ConstructTpl) -> Self::Sections;

    /// Closes the main section at the first named-section label `sym`.
    fn first_named_section(
        &mut self,
        main: ConstructTpl,
        sym: &str,
    ) -> Result<Self::Sections, SleighError>;

    /// Closes a named section at the next named-section label `sym`.
    fn next_named_section(
        &mut self,
        vec: Self::Sections,
        section: ConstructTpl,
        sym: &str,
    ) -> Result<Self::Sections, SleighError>;

    /// Closes the last named section.
    fn final_named_section(
        &mut self,
        vec: Self::Sections,
        section: ConstructTpl,
    ) -> Result<Self::Sections, SleighError>;

    /// Handles a sleigh `macro` invocation, returning the resulting p-code op templates.
    fn create_macro_use(
        &mut self,
        location: &Location,
        macro_name: &str,
        param: Vec<ExprTreeImpl>,
    ) -> Result<Vec<OpTpl>, SleighError>;

    /// Records a section with no p-code (a NOP).
    fn record_nop(&mut self, location: &Location);

    // ----- Java concrete methods ------------------------------------------------------------

    fn set_enforce_local_key(&mut self, val: bool) {
        self.base_mut().enforce_local_key = val;
    }

    /// Reports (logs and counts) an error.
    fn report_error(&mut self, location: Option<&Location>, msg: &str) {
        let formatted = message_formatting_utils::format(location, msg);
        Msg::error("PcodeCompile", &formatted);
        let base = self.base_mut();
        base.errors += 1;
        base.error_messages.push(formatted);
    }

    fn get_errors(&self) -> i32 {
        self.base().errors
    }

    /// Reports (logs and counts) a warning.
    fn report_warning(&mut self, location: Option<&Location>, msg: &str) {
        Msg::warn("PcodeCompile", &message_formatting_utils::format(location, msg));
        self.base_mut().warnings += 1;
    }

    fn get_warnings(&self) -> i32 {
        self.base().warnings
    }

    fn reset_label_count(&mut self) {
        self.base_mut().local_labelcount = 0;
    }

    /// Builds a temporary variable with zero size. The returned varnode is unnamed.
    fn build_temporary(&mut self, _location: &Location) -> VarnodeTpl {
        let offset = self.allocate_temp();
        VarnodeTpl::with_fields(
            const_space(self.get_unique_space()),
            const_real(offset),
            const_real(0),
        )
    }

    /// Creates a label symbol, adds it to the local scope, and returns its index.
    fn define_label(&mut self, location: &Location, name: &str) -> Result<i32, SleighError> {
        let index = self.base().local_labelcount;
        self.base_mut().local_labelcount += 1;
        let labsym = LabelSymbol::new(location.clone(), name, index);
        self.add_symbol(SemanticSymbol::Label(labsym))?; // Add symbol to local scope
        Ok(index)
    }

    /// Creates the placeholder op for the label named `name` and marks it placed.
    fn place_label(&mut self, _location: &Location, name: &str) -> Vec<OpTpl> {
        let mut placed_twice: Option<Location> = None;
        let mut index = 0;
        if let Some(SemanticSymbol::Label(labsym)) = self.find_symbol_mut(name) {
            if labsym.is_placed() {
                placed_twice = Some(labsym.symbol().location().clone());
            }
            labsym.set_placed();
            index = labsym.index();
        }
        if let Some(loc) = placed_twice {
            self.report_error(
                Some(&loc),
                &format!("Label '{name}' is placed more than once"),
            );
        }
        let mut op = OpTpl::with_opcode(OpCode::CpuiPtradd);
        op.add_input(VarnodeTpl::with_fields(
            const_space(self.get_constant_space()),
            const_real(index as u64),
            const_real(4),
        ));
        vec![op]
    }

    /// Sets the constructor's handle to indicate the given varnode.
    fn set_result_varnode(&mut self, mut ct: ConstructTpl, vn: VarnodeTpl) -> ConstructTpl {
        ct.result = Some(HandleTpl {
            space: vn.space.clone(),
            size: vn.size.clone(),
            ptrspace: const_real(0),
            ptroffset: vn.offset.clone(),
            ptrsize: ConstTpl::new(),
            temp_space: ConstTpl::new(),
            temp_offset: ConstTpl::new(),
        });
        ct
    }

    /// Sets the constructor's handle to be the value pointed at by `vn`.
    fn set_result_star_varnode(
        &mut self,
        mut ct: ConstructTpl,
        star: &StarQuality,
        vn: VarnodeTpl,
    ) -> ConstructTpl {
        let temp_offset = self.allocate_temp();
        ct.result = Some(HandleTpl {
            space: star.get_id().cloned().unwrap_or_else(ConstTpl::new),
            size: const_real(star.get_size() as u64),
            ptrspace: vn.space.clone(),
            ptroffset: vn.offset.clone(),
            ptrsize: vn.size.clone(),
            temp_space: const_space(self.get_unique_space()),
            temp_offset: const_real(temp_offset),
        });
        ct
    }

    /// Creates a new local temporary symbol `varname` of `size` bytes (0 = not yet known),
    /// without generating any p-code (both Java `newLocalDefinition` overloads).
    fn new_local_definition(
        &mut self,
        location: &Location,
        varname: &str,
        size: i32,
    ) -> Result<(), SleighError> {
        let mut tmpvn = self.build_temporary(location);
        if size != 0 {
            tmpvn.size = const_real(size as u64); // Size was explicitly specified
        }
        let sym = VarnodeSymbol::with_fixed(
            location.clone(),
            varname,
            self.get_unique_space(),
            tmpvn.offset.value_real,
            tmpvn.size.value_real as i32,
        );
        self.add_symbol(SemanticSymbol::Varnode(sym))
    }

    /// Assigns `rhs` to a new local temporary `varname` of `size` bytes (0 = inherit from the
    /// expression if known), returning the expression's ops (both Java `newOutput` overloads).
    fn new_output(
        &mut self,
        location: &Location,
        uses_local_key: bool,
        mut rhs: ExprTreeImpl,
        varname: &str,
        size: i32,
    ) -> Result<Vec<OpTpl>, SleighError> {
        let mut tmpvn = self.build_temporary(location);
        if size != 0 {
            tmpvn.size = const_real(size as u64); // Size
        } else if let Some(rsize) = rhs.get_size() {
            // Inherit size from unnamed expression result. Only inherit if the size is real,
            // otherwise we cannot build the VarnodeSymbol with a placeholder constant.
            if rsize.tp == ConstTplType::Real && rsize.value_real != 0 {
                tmpvn.size = rsize.clone();
            }
        }
        rhs.set_output(location.clone(), tmpvn.clone())?;
        // Create new symbol regardless
        let sym = VarnodeSymbol::with_fixed(
            location.clone(),
            varname,
            self.get_unique_space(),
            tmpvn.offset.value_real,
            tmpvn.size.value_real as i32,
        );
        self.add_symbol(SemanticSymbol::Varnode(sym))?;
        if !uses_local_key && self.base().enforce_local_key {
            self.report_error(
                Some(location),
                &format!("Must use 'local' keyword to define symbol '{varname}'"),
            );
        }
        Ok(rhs.to_vector().unwrap_or_default())
    }

    /// Creates a new expression performing `opc` on `vn`, with a fresh temporary output.
    fn create_op(&mut self, location: &Location, opc: OpCode, mut vn: ExprTreeImpl) -> ExprTreeImpl {
        let outvn = self.build_temporary(location);
        let mut op = OpTpl::with_opcode(opc);
        op.add_input(take_out(&mut vn));
        op.set_output(outvn.clone());
        vn.push_op(op);
        vn.set_out(Some(outvn), true);
        vn
    }

    /// Creates a new expression performing `opc` on `vn1` and `vn2`, with a fresh temporary
    /// output.
    fn create_op2(
        &mut self,
        location: &Location,
        opc: OpCode,
        vn1: ExprTreeImpl,
        vn2: ExprTreeImpl,
    ) -> ExprTreeImpl {
        let outvn = self.build_temporary(location);
        let mut vn1 = self.create_op_out(location, outvn, opc, vn1, vn2);
        // The output is the fresh (unnamed) temporary, not an explicit named varnode.
        let out = vn1.take_out_varnode();
        vn1.set_out(out, true);
        vn1
    }

    /// Creates an op with explicit output `outvn` and two inputs.
    fn create_op_out(
        &mut self,
        _location: &Location,
        outvn: VarnodeTpl,
        opc: OpCode,
        mut vn1: ExprTreeImpl,
        mut vn2: ExprTreeImpl,
    ) -> ExprTreeImpl {
        let mut ops2 = take_ops(&mut vn2);
        let ops1 = vn1.ops_mut().get_or_insert_with(Vec::new);
        ops1.append(&mut ops2);
        let mut op = OpTpl::with_opcode(opc);
        op.add_input(take_out(&mut vn1));
        op.add_input(take_out(&mut vn2));
        op.set_output(outvn.clone());
        vn1.push_op(op);
        vn1.set_out(Some(outvn), false);
        vn1
    }

    /// Creates an op with explicit output `outvn` and one input.
    fn create_op_out_unary(
        &mut self,
        _location: &Location,
        outvn: VarnodeTpl,
        opc: OpCode,
        mut vn: ExprTreeImpl,
    ) -> ExprTreeImpl {
        let mut op = OpTpl::with_opcode(opc);
        op.add_input(take_out(&mut vn));
        op.set_output(outvn.clone());
        vn.push_op(op);
        vn.set_out(Some(outvn), false);
        vn
    }

    /// Creates an op `opc` with the single input `vn` and no output.
    fn create_op_no_out(&mut self, _location: &Location, opc: OpCode, mut vn: ExprTreeImpl) -> Vec<OpTpl> {
        let mut op = OpTpl::with_opcode(opc);
        op.add_input(take_out(&mut vn)); // There is no longer an output to this expression
        let mut res = take_ops(&mut vn);
        res.push(op);
        res
    }

    /// Creates an op `opc` with inputs `vn1` and `vn2` and no output.
    fn create_op_no_out2(
        &mut self,
        _location: &Location,
        opc: OpCode,
        mut vn1: ExprTreeImpl,
        mut vn2: ExprTreeImpl,
    ) -> Vec<OpTpl> {
        let mut res = take_ops(&mut vn1);
        res.append(&mut take_ops(&mut vn2));
        let mut op = OpTpl::with_opcode(opc);
        op.add_input(take_out(&mut vn1));
        op.add_input(take_out(&mut vn2));
        res.push(op);
        res
    }

    /// Creates an op `opc` whose only input is the 4-byte constant `val`.
    fn create_op_const(&mut self, _location: &Location, opc: OpCode, val: u64) -> Vec<OpTpl> {
        let vn = VarnodeTpl::with_fields(
            const_space(self.get_constant_space()),
            const_real(val),
            const_real(4),
        );
        let mut op = OpTpl::with_opcode(opc);
        op.add_input(vn);
        vec![op]
    }

    /// Creates a load through `ptr` described by `qual`.
    fn create_load(
        &mut self,
        location: &Location,
        qual: &StarQuality,
        mut ptr: ExprTreeImpl,
    ) -> Result<ExprTreeImpl, SleighError> {
        let mut outvn = self.build_temporary(location);
        let mut op = OpTpl::with_opcode(OpCode::CpuiLoad);
        let spcvn = VarnodeTpl::with_fields(
            const_space(self.get_constant_space()),
            qual.get_id().cloned().unwrap_or_else(ConstTpl::new),
            const_real(8),
        );
        op.add_input(spcvn);
        op.add_input(take_out(&mut ptr));
        op.set_output(outvn.clone());
        ptr.push_op(op);
        if qual.get_size() > 0 {
            let ops = ptr.ops_mut().get_or_insert_with(Vec::new);
            force_size(location, &mut outvn, &const_real(qual.get_size() as u64), ops)?;
        }
        ptr.set_out(Some(outvn), true);
        Ok(ptr)
    }

    /// Creates a store of `val` through `ptr` described by `qual`.
    fn create_store(
        &mut self,
        location: &Location,
        qual: &StarQuality,
        mut ptr: ExprTreeImpl,
        mut val: ExprTreeImpl,
    ) -> Result<Vec<OpTpl>, SleighError> {
        let mut res = take_ops(&mut ptr);
        res.append(&mut take_ops(&mut val));
        let mut op = OpTpl::with_opcode(OpCode::CpuiStore);
        let spcvn = VarnodeTpl::with_fields(
            const_space(self.get_constant_space()),
            qual.get_id().cloned().unwrap_or_else(ConstTpl::new),
            const_real(8),
        );
        op.add_input(spcvn);
        op.add_input(take_out(&mut ptr));
        op.add_input(take_out(&mut val));
        res.push(op);
        // Java forces the size on val's output object, which is the STORE's third input.
        let last = res.len() - 1;
        force_size_in_slot(
            location,
            &mut res,
            last,
            Some(2),
            &const_real(qual.get_size() as u64),
        )?;
        Ok(res)
    }

    /// Creates a user-defined p-code op (index `sym_index`) with the given parameters, producing
    /// a value.
    fn create_user_op(
        &mut self,
        location: &Location,
        sym_index: i32,
        param: Vec<ExprTreeImpl>,
    ) -> ExprTreeImpl {
        let outvn = self.build_temporary(location);
        let mut ops = self.create_user_op_no_out(location, sym_index, param);
        if let Some(last) = ops.last_mut() {
            last.set_output(outvn.clone());
        }
        ExprTreeImpl::with_output(location.clone(), ops, outvn, true)
    }

    /// Creates a user-defined p-code op (index `sym_index`) with the given parameters and no
    /// output.
    fn create_user_op_no_out(
        &mut self,
        _location: &Location,
        sym_index: i32,
        param: Vec<ExprTreeImpl>,
    ) -> Vec<OpTpl> {
        let mut op = OpTpl::with_opcode(OpCode::CpuiCallother);
        op.add_input(VarnodeTpl::with_fields(
            const_space(self.get_constant_space()),
            const_real(sym_index as u64),
            const_real(4),
        ));
        append_params(op, param)
    }

    /// Creates a variadic op `opc` over `param`, producing a value.
    fn create_variadic(
        &mut self,
        location: &Location,
        opc: OpCode,
        param: Vec<ExprTreeImpl>,
    ) -> ExprTreeImpl {
        let outvn = self.build_temporary(location);
        let op = OpTpl::with_opcode(opc);
        let mut ops = append_params(op, param);
        if let Some(last) = ops.last_mut() {
            last.set_output(outvn.clone());
        }
        ExprTreeImpl::with_output(location.clone(), ops, outvn, true)
    }

    /// Builds a truncated form of `basevn` matching the bit range `[bitoffset, numbits]` using
    /// just `ConstTpl` (offset_plus) mechanics if possible, otherwise returns `None`.
    fn build_truncated_varnode(
        &self,
        loc: &Location,
        basevn: &VarnodeTpl,
        bitoffset: i32,
        numbits: i32,
    ) -> Result<Option<VarnodeTpl>, SleighError> {
        let byteoffset = bitoffset / 8; // Convert to byte units
        let numbytes = numbits / 8;
        let mut fullsz: i64 = 0;
        if basevn.size.tp == ConstTplType::Real {
            // If we know the size of base, make sure the bit range is in bounds
            fullsz = basevn.size.value_real as i64;
            if fullsz == 0 {
                return Ok(None);
            }
            if (byteoffset + numbytes) as i64 > fullsz {
                return Err(SleighError::new(
                    format!(
                        "Requested bit range out of bounds -- {} > {}",
                        byteoffset + numbytes,
                        fullsz
                    ),
                    loc.clone(),
                ));
            }
        }

        if bitoffset % 8 != 0 || numbits % 8 != 0 {
            return Ok(None);
        }

        let offset_type = basevn.offset.tp;
        if offset_type != ConstTplType::Real && offset_type != ConstTplType::Handle {
            return Ok(None);
        }

        let specialoff = if offset_type == ConstTplType::Handle {
            // We put in the correct adjustment to offset assuming things are little endian. We
            // defer the correct big endian calculation until after the consistency check
            // because we need to know the subtable export sizes.
            ConstTpl {
                tp: ConstTplType::Handle,
                value_real: byteoffset as u64,
                value_spaceid: None,
                handle_index: basevn.offset.handle_index,
                select: Some(ConstTplSelect::VOffsetPlus),
            }
        } else {
            if basevn.size.tp != ConstTplType::Real {
                return Err(SleighError::new(
                    "Could not construct requested bit range",
                    loc.clone(),
                ));
            }
            let plus = if self.get_default_space_is_big_endian() {
                fullsz - (byteoffset + numbytes) as i64
            } else {
                byteoffset as i64
            };
            const_real(basevn.offset.value_real.wrapping_add(plus as u64))
        };
        Ok(Some(VarnodeTpl::with_fields(
            basevn.space.clone(),
            specialoff,
            const_real(numbytes as u64),
        )))
    }

    /// Takes the output of `res`, combines it with the constant `constval` of size `constsz`
    /// using `opc`, and makes that the new output of `res`.
    fn append_op(
        &mut self,
        location: &Location,
        opc: OpCode,
        res: &mut ExprTreeImpl,
        constval: u64,
        constsz: i32,
    ) {
        let mut op = OpTpl::with_opcode(opc);
        let constvn = VarnodeTpl::with_fields(
            const_space(self.get_constant_space()),
            const_real(constval),
            const_real(constsz as u64),
        );
        let outvn = self.build_temporary(location);
        op.add_input(take_out(res));
        op.add_input(constvn);
        op.set_output(outvn.clone());
        res.push_op(op);
        res.set_out(Some(outvn), true);
    }

    /// Creates the ops assigning `rhs` to the bit range `[bitoffset, numbits]` within `vn`.
    fn assign_bit_range(
        &mut self,
        location: &Location,
        vn: VarnodeTpl,
        bitoffset: i32,
        numbits: i32,
        mut rhs: ExprTreeImpl,
    ) -> Result<Vec<OpTpl>, SleighError> {
        let mut errmsg = String::new();
        if numbits == 0 {
            errmsg = "Size of bitrange is zero".to_string();
        }
        let smallsize = (numbits + 7) / 8; // Size of input (output of rhs)
        let shiftneeded = bitoffset != 0;
        let mut zextneeded = true;
        let mask: u64 = 2;
        let mask = !(((mask.wrapping_shl((numbits - 1) as u32)).wrapping_sub(1))
            .wrapping_shl(bitoffset as u32));

        if vn.size.tp == ConstTplType::Real {
            // If we know the size of the bitranged varnode, we can do some immediate checks, and
            // possibly simplify things
            let mut symsize = vn.size.value_real as i32;
            if symsize > 0 {
                zextneeded = symsize > smallsize;
            }
            symsize *= 8; // Convert to number of bits
            if bitoffset >= symsize || bitoffset + numbits > symsize {
                errmsg = "Assigned bitrange is bad".to_string();
            } else if bitoffset == 0 && numbits == symsize {
                errmsg = "Assigning to bitrange is superfluous".to_string();
            }
        }

        if !errmsg.is_empty() {
            // Was there an error condition
            self.report_error(Some(location), &errmsg); // Report the error
            return Ok(take_ops(&mut rhs)); // Passthru old expression
        }

        // We know what the size of the input has to be
        {
            let unnamed = rhs.out_is_unnamed();
            let mut outvn = rhs.take_out_varnode().unwrap_or_default();
            let ops = rhs.ops_mut().get_or_insert_with(Vec::new);
            force_size(location, &mut outvn, &const_real(smallsize as u64), ops)?;
            rhs.set_out(Some(outvn), unnamed);
        }

        let res = match self.build_truncated_varnode(location, &vn, bitoffset, numbits)? {
            Some(finalout) => self.create_op_out_unary(location, finalout, OpCode::CpuiCopy, rhs),
            None => {
                if bitoffset + numbits > 64 {
                    errmsg = "Assigned bitrange extends past first 64 bits".to_string();
                }
                let mut res = ExprTreeImpl::with_varnode(location.clone(), vn.clone());
                self.append_op(location, OpCode::CpuiIntAnd, &mut res, mask, 0);
                if zextneeded {
                    rhs = self.create_op(location, OpCode::CpuiIntZext, rhs);
                }
                if shiftneeded {
                    self.append_op(location, OpCode::CpuiIntLeft, &mut rhs, bitoffset as u64, 4);
                }
                self.create_op_out(location, vn, OpCode::CpuiIntOr, res, rhs)
            }
        };
        if !errmsg.is_empty() {
            self.report_error(Some(location), &errmsg);
        }
        let mut res = res;
        Ok(take_ops(&mut res))
    }

    /// Creates an expression computing the bit range `[bitoffset, numbits]` of the specific
    /// symbol whose varnode is `vn` (named `sym_name`, defined at `sym_location`). The result is
    /// truncated to the smallest byte size that can contain the bits, shifted all the way right.
    fn create_bit_range(
        &mut self,
        location: &Location,
        mut vn: VarnodeTpl,
        sym_name: &str,
        sym_location: &Location,
        mut bitoffset: i32,
        numbits: i32,
    ) -> Result<ExprTreeImpl, SleighError> {
        let mut errmsg = String::new();
        if numbits == 0 {
            errmsg = "Size of bitrange is zero".to_string();
        }
        let finalsize = (numbits + 7) / 8; // Round up to nearest byte size
        let mut truncshift = 0;
        let mut maskneeded = numbits % 8 != 0;
        let mut truncneeded = true;

        // Special case where we can set the size, without invoking a truncation operator
        if errmsg.is_empty()
            && bitoffset == 0
            && !maskneeded
            && vn.space.tp == ConstTplType::Handle
            && vn.is_zero_size()
        {
            vn.size = const_real(finalsize as u64);
            return Ok(ExprTreeImpl::with_varnode(sym_location.clone(), vn));
        }

        if errmsg.is_empty() {
            if let Some(truncvn) = self.build_truncated_varnode(location, &vn, bitoffset, numbits)? {
                // If we are able to construct a simple truncated varnode, return just the
                // varnode as an expression
                return Ok(ExprTreeImpl::with_varnode(location.clone(), truncvn));
            }
        }

        if vn.size.tp == ConstTplType::Real {
            // If we know the size of the input varnode, we can do some immediate checks, and
            // possibly simplify things
            let mut insize = vn.size.value_real as i32;
            if insize > 0 {
                truncneeded = finalsize < insize;
                insize *= 8; // Convert to number of bits
                if bitoffset >= insize || bitoffset + numbits > insize {
                    errmsg = "Bitrange is bad".to_string();
                }
                if maskneeded && bitoffset + numbits == insize {
                    maskneeded = false;
                }
            }
        }

        let mask: u64 = 2;
        let mask = mask.wrapping_shl((numbits - 1) as u32).wrapping_sub(1);

        if truncneeded && bitoffset % 8 == 0 {
            truncshift = bitoffset / 8;
            bitoffset = 0;
        }

        if bitoffset == 0 && !truncneeded && !maskneeded {
            errmsg = "Superfluous bitrange".to_string();
        }

        if maskneeded && finalsize > 8 {
            errmsg = format!(
                "Illegal masked bitrange producing varnode larger than 64 bits: {sym_name}"
            );
        }

        let mut res = ExprTreeImpl::with_varnode(sym_location.clone(), vn);

        if !errmsg.is_empty() {
            // Check for error condition
            self.report_error(Some(location), &errmsg);
            return Ok(res);
        }

        if bitoffset != 0 {
            self.append_op(location, OpCode::CpuiIntRight, &mut res, bitoffset as u64, 4);
        }
        if truncneeded {
            self.append_op(location, OpCode::CpuiSubpiece, &mut res, truncshift as u64, 4);
        }
        if maskneeded {
            self.append_op(location, OpCode::CpuiIntAnd, &mut res, mask, finalsize);
        }
        let unnamed = res.out_is_unnamed();
        let mut outvn = res.take_out_varnode().unwrap_or_default();
        let ops = res.ops_mut().get_or_insert_with(Vec::new);
        force_size(location, &mut outvn, &const_real(finalsize as u64), ops)?;
        res.set_out(Some(outvn), unnamed);
        Ok(res)
    }

    /// Produces the constant varnode that is the offset portion of `var` (`&var`), of `size`
    /// bytes (0 = the space's address size when known).
    fn address_of(&self, var: &VarnodeTpl, mut size: i32) -> VarnodeTpl {
        if size == 0 {
            // If no size specified, look to the particular space to see if it has a standard
            // address size
            if var.space.tp == ConstTplType::SpaceId {
                if let Some(spc) = var.space.value_spaceid.as_ref() {
                    size = addr_size(spc);
                }
            }
        }
        if var.offset.tp == ConstTplType::Real && var.space.tp == ConstTplType::SpaceId {
            let shift = var.space.value_spaceid.as_ref().map(|s| scale(s)).unwrap_or(0);
            VarnodeTpl::with_fields(
                const_space(self.get_constant_space()),
                const_real(var.offset.value_real >> shift),
                const_real(size as u64),
            )
        } else {
            VarnodeTpl::with_fields(
                const_space(self.get_constant_space()),
                var.offset.clone(),
                const_real(size as u64),
            )
        }
    }

    /// Fills in the size of zero-size varnodes throughout `ct`. Returns `false` if some varnode's
    /// size could not be resolved.
    fn propagate_size(&mut self, ct: &mut ConstructTpl) -> Result<bool, SleighError> {
        let location = crate::sleigh::grammar::location::INTERNALLY_DEFINED.clone();
        let mut zerovec: Vec<usize> = Vec::new();
        for i in 0..ct.vec.len() {
            if ct.vec[i].is_zero_size() {
                fillin_zero(&location, &mut ct.vec, i)?;
                if ct.vec[i].is_zero_size() {
                    zerovec.push(i);
                }
            }
        }
        let mut lastsize = zerovec.len() + 1;
        while zerovec.len() < lastsize {
            lastsize = zerovec.len();
            let mut zerovec2 = Vec::new();
            for &i in &zerovec {
                fillin_zero(&location, &mut ct.vec, i)?;
                if ct.vec[i].is_zero_size() {
                    zerovec2.push(i);
                }
            }
            zerovec = zerovec2;
        }
        Ok(lastsize == 0)
    }

    /// Looks up `name` as a SLEIGH built-in function applied to `operands`, building the
    /// resulting expression (or op list, for `delayslot`). Returns `None` -- leaving `operands`
    /// untouched -- when `name` is not a built-in or its operand count is wrong (the latter is
    /// reported as an error). Keep in step with [`is_internal_function`].
    fn find_internal_function(
        &mut self,
        location: &Location,
        name: &str,
        operands: &mut Vec<ExprTreeImpl>,
    ) -> Option<ApplyResult> {
        let unary = |opc| (opc, 1usize);
        let binary = |opc| (opc, 2usize);
        let fixed = match name {
            "zext" => Some(unary(OpCode::CpuiIntZext)),
            "carry" => Some(binary(OpCode::CpuiIntCarry)),
            "sext" => Some(unary(OpCode::CpuiIntSext)),
            "scarry" => Some(binary(OpCode::CpuiIntScarry)),
            "sborrow" => Some(binary(OpCode::CpuiIntSborrow)),
            "abs" => Some(unary(OpCode::CpuiFloatAbs)),
            "nan" => Some(unary(OpCode::CpuiFloatNan)),
            "sqrt" => Some(unary(OpCode::CpuiFloatSqrt)),
            "ceil" => Some(unary(OpCode::CpuiFloatCeil)),
            "floor" => Some(unary(OpCode::CpuiFloatFloor)),
            "round" => Some(unary(OpCode::CpuiFloatRound)),
            "int2float" => Some(unary(OpCode::CpuiFloatInt2float)),
            "float2float" => Some(unary(OpCode::CpuiFloatFloat2float)),
            "trunc" => Some(unary(OpCode::CpuiFloatTrunc)),
            "popcount" => Some(unary(OpCode::CpuiPopcount)),
            "lzcount" => Some(unary(OpCode::CpuiLzcount)),
            _ => None,
        };
        if let Some((opc, arity)) = fixed {
            if !self.has_operands(arity, operands.len(), location, name) {
                return None;
            }
            let mut ops = std::mem::take(operands).into_iter();
            let r = ops.next().expect("arity checked");
            return Some(ApplyResult::Expr(match ops.next() {
                Some(s) => self.create_op2(location, opc, r, s),
                None => self.create_op(location, opc, r),
            }));
        }
        match name {
            "delayslot" => {
                if !self.has_operands(1, operands.len(), location, name) {
                    return None;
                }
                let val = operands[0]
                    .out_varnode()
                    .map(|vn| vn.offset.value_real)
                    .unwrap_or(0);
                operands.clear();
                Some(ApplyResult::Ops(self.create_op_const(location, OpCode::CpuiIndirect, val)))
            }
            "cpool" => {
                if operands.len() >= 2 {
                    let params = std::mem::take(operands);
                    return Some(ApplyResult::Expr(self.create_variadic(
                        location,
                        OpCode::CpuiCpoolref,
                        params,
                    )));
                }
                self.report_error(Some(location), &format!("{name}() expects at least two arguments"));
                None
            }
            "newobject" => {
                if !operands.is_empty() {
                    let params = std::mem::take(operands);
                    return Some(ApplyResult::Expr(self.create_variadic(
                        location,
                        OpCode::CpuiNew,
                        params,
                    )));
                }
                self.report_error(Some(location), &format!("{name}() expects at least one argument"));
                None
            }
            _ => None,
        }
    }

    /// Java's private `hasOperands`: reports an error unless `found == target`.
    fn has_operands(&mut self, target: usize, found: usize, location: &Location, name: &str) -> bool {
        if found == target {
            return true;
        }
        self.report_error(
            Some(location),
            &format!(
                "{name}() expects {target} argument{}; found {found}",
                if target == 1 { "" } else { "s" }
            ),
        );
        false
    }

    /// Whether `name` is a SLEIGH built-in function (see [`is_internal_function`]).
    fn is_internal_function(&self, name: &str) -> bool {
        is_internal_function(name)
    }
}

/// Java's `ExprTree.appendParams` over concrete expressions: flatten every parameter's ops into
/// the result, wire each parameter's output as an input to `op`, then append `op`.
fn append_params(mut op: OpTpl, params: Vec<ExprTreeImpl>) -> Vec<OpTpl> {
    let mut res = Vec::new();
    for mut param in params {
        res.append(&mut take_ops(&mut param));
        op.add_input(take_out(&mut param));
    }
    res.push(op);
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique() -> Arc<AddressSpace> {
        AddressSpace::new("unique", 32, 1, AddressSpaceType::Unique, 4)
    }

    fn temp(offset: u64, size: u64) -> VarnodeTpl {
        VarnodeTpl::with_fields(const_space(unique()), const_real(offset), const_real(size))
    }

    fn loc() -> Location {
        Location::new("t", 1)
    }

    #[test]
    fn const_equality_follows_java_equals() {
        assert!(const_tpl_equals(&const_real(4), &const_real(4)));
        assert!(!const_tpl_equals(&const_real(4), &const_real(5)));
        assert!(const_tpl_equals(&const_space(unique()), &const_space(unique())));
        assert!(const_tpl_equals(
            &const_of_type(ConstTplType::JStart),
            &const_of_type(ConstTplType::JStart)
        ));
        assert!(!const_tpl_equals(&const_real(0), &const_of_type(ConstTplType::JStart)));
    }

    #[test]
    fn force_size_propagates_to_every_use_of_a_local_temp() {
        let mut op1 = OpTpl::with_opcode(OpCode::CpuiCopy);
        op1.set_output(temp(0x100, 0));
        op1.add_input(temp(0x200, 0));
        let mut op2 = OpTpl::with_opcode(OpCode::CpuiIntAdd);
        op2.add_input(temp(0x100, 0));
        let mut ops = vec![op1, op2];
        let mut vt = temp(0x100, 0);
        force_size(&loc(), &mut vt, &const_real(4), &mut ops).unwrap();
        assert_eq!(vt.size.value_real, 4);
        assert_eq!(ops[0].get_out().unwrap().size.value_real, 4);
        assert_eq!(ops[1].get_in(0).size.value_real, 4);
        // A different temporary is untouched.
        assert_eq!(ops[0].get_in(0).size.value_real, 0);
        // A conflicting explicit size is rejected.
        ops[1].input[0] = temp(0x200, 2);
        let mut vt = temp(0x200, 0);
        let err = force_size(&loc(), &mut vt, &const_real(4), &mut ops).unwrap_err();
        assert_eq!(err.message(), "Input size mismatch: 2 vs 4");
    }

    #[test]
    fn fillin_zero_sizes_boolean_outputs_and_shift_amounts() {
        let mut eq = OpTpl::with_opcode(OpCode::CpuiIntEqual);
        eq.set_output(temp(0x100, 0));
        eq.add_input(temp(0x200, 8));
        eq.add_input(temp(0x300, 0));
        let mut shl = OpTpl::with_opcode(OpCode::CpuiIntLeft);
        shl.set_output(temp(0x400, 0));
        shl.add_input(temp(0x200, 8));
        shl.add_input(VarnodeTpl::with_fields(const_real(0), const_real(3), const_real(0)));
        let mut ops = vec![eq, shl];
        fillin_zero(&loc(), &mut ops, 0).unwrap();
        fillin_zero(&loc(), &mut ops, 1).unwrap();
        assert_eq!(ops[0].get_out().unwrap().size.value_real, 1);
        assert_eq!(ops[0].get_in(1).size.value_real, 8);
        assert_eq!(ops[1].get_out().unwrap().size.value_real, 8);
        assert_eq!(ops[1].get_in(1).size.value_real, 4);
    }

    #[test]
    fn op_lists_count_labels_and_allow_one_delay_slot() {
        let indirect = |n: u64| {
            let mut op = OpTpl::with_opcode(OpCode::CpuiIndirect);
            op.add_input(VarnodeTpl::with_fields(const_real(0), const_real(n), const_real(4)));
            op
        };
        let mut ct = ConstructTpl::new();
        assert!(add_op_list(&mut ct, vec![OpTpl::with_opcode(OpCode::CpuiPtradd), indirect(2)]));
        assert_eq!(ct.num_labels, 1);
        assert_eq!(delay_slot(&ct), 2);
        assert!(!add_op_list(&mut ct, vec![indirect(1), OpTpl::with_opcode(OpCode::CpuiPtradd)]));
        assert_eq!(ct.vec.len(), 2, "the rejected op and its successors are not appended");
        assert_eq!(ct.num_labels, 1);
    }

    #[test]
    fn internal_functions_and_space_sizes() {
        for name in ["zext", "carry", "delayslot", "cpool", "newobject", "popcount", "lzcount"] {
            assert!(is_internal_function(name), "{name}");
        }
        assert!(!is_internal_function("myop"));
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 2);
        let wordram = AddressSpace::new("data", 16, 2, AddressSpaceType::Ram, 5);
        let constant = AddressSpace::new("const", 64, 1, AddressSpaceType::Constant, 0);
        assert_eq!(addr_size(&ram), 4);
        assert_eq!(addr_size(&unique()), 4);
        assert_eq!(addr_size(&constant), 8);
        assert_eq!(scale(&ram), 0);
        assert_eq!(scale(&wordram), 1);
    }
}

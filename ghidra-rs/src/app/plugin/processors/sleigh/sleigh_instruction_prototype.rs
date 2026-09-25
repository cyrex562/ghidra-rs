//! Port of `ghidra.app.plugin.processors.sleigh.SleighInstructionPrototype`: the
//! [`InstructionPrototype`] of sleigh languages.
//!
//! # Shape
//! Java's class is concrete, so this is a struct. Java hands the prototype object itself to the
//! parser contexts it creates (`new SleighParserContext(buf, this, context)`) and caches
//! prototypes by hash; here [`SleighInstructionPrototype`] is a cheap, cloneable handle on the
//! shared, immutable prototype data, so a context can hold its prototype and hand it out as an
//! `Arc<dyn InstructionPrototype>`. The constructor tree is an arena ([`ConstructTree`]); tree
//! nodes (Java `ConstructState`s) are addressed by index.
//!
//! # Parser contexts
//! Java casts `InstructionContext.getParserContext()` to `SleighParserContext`; here the parser
//! context is downcast through `ParserContext::as_any`, and when an instruction context supplies
//! some other kind of parser context one is rebuilt from the instruction context's memory and
//! processor context -- which is what every Java `InstructionContext` does to produce it.
//!
//! # Not ported
//! * Instruction and operand masks (`cacheInstructionMasks`) need a concrete
//!   `SleighDebugLogger`, which is not ported: [`InstructionPrototype::get_instruction_mask`] and
//!   [`InstructionPrototype::get_operand_value_mask`] report `None`, which Java reports when the
//!   mask computation fails.
//! * Overlay spaces (`handleOverlayAddress`, `getOverlayAddress`) and spaces with mapped
//!   registers: this crate's `AddressSpace` models neither, so addresses are used as computed.

use std::sync::{Arc, Mutex};

use crate::app::plugin::processors::sleigh::op_tpl_walker::{NextOpTpl, OpTplWalker};
use crate::app::plugin::processors::sleigh::pcode_emit::{PcodeEmit, PcodeEmitBuildError};
use crate::app::plugin::processors::sleigh::pcode_emit_objects::PcodeEmitObjects;
use crate::app::plugin::processors::sleigh::pcode_emit_packed::PcodeEmitPacked;
use crate::util::msg::Msg;
use crate::app::plugin::processors::sleigh::sleigh_exception::SleighException;
use crate::app::plugin::processors::sleigh::sleigh_parser_context::{
    read_context_words, snapshot_mem_buffer, SleighParserContext,
};
use crate::decompiler::opcodes::OpCode;
use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
use crate::program::model::lang::instruction_prototype::GetPseudoParserContextError;
use crate::program::model::lang::language::Language;
use crate::program::model::lang::operand_type::OperandType;
use crate::program::model::lang::register::RegisterRef;
use crate::program::model::lang::sleigh::symbol::{PrintListItem, SleighSymbol, SymbolTable};
use crate::program::model::lang::sleigh::template::{ConstTplType, OpTpl};
use crate::program::model::lang::sleigh::walker::{ConstructTree, ParserWalker, SleighError};
use crate::program::model::lang::sleigh::{FixedHandle, SleighLanguage};
use crate::program::model::lang::unknown_instruction_exception::UnknownInstructionException;
use crate::program::model::lang::{InstructionContext, InstructionPrototype, Mask, ProcessorContextView};
use crate::program::model::listing::instruction::OperandValue;
use crate::program::model::mem::{MemBuffer, MemoryAccessException};
use crate::program::model::pcode::{
    PatchEncoder, PcodeOp, PcodeOverride, Varnode, ATTRIB_OFFSET, ELEM_UNIMPL,
};
use crate::program::model::scalar::Scalar;
use crate::program::model::symbol::RefType;
use crate::program::seam_stubs::FlowOverride;

/// Port of `SleighInstructionPrototype.RETURN`.
pub const RETURN: i32 = 0x01;
/// Port of `SleighInstructionPrototype.CALL_INDIRECT`.
pub const CALL_INDIRECT: i32 = 0x02;
/// Port of `SleighInstructionPrototype.BRANCH_INDIRECT`.
pub const BRANCH_INDIRECT: i32 = 0x04;
/// Port of `SleighInstructionPrototype.CALL`.
pub const CALL: i32 = 0x08;
/// Port of `SleighInstructionPrototype.JUMPOUT`.
pub const JUMPOUT: i32 = 0x10;
/// Port of `SleighInstructionPrototype.NO_FALLTHRU` (op does not fall through).
pub const NO_FALLTHRU: i32 = 0x20;
/// Port of `SleighInstructionPrototype.BRANCH_TO_END`.
pub const BRANCH_TO_END: i32 = 0x40;
/// Port of `SleighInstructionPrototype.CROSSBUILD`.
pub const CROSSBUILD: i32 = 0x80;
/// Port of `SleighInstructionPrototype.LABEL`.
pub const LABEL: i32 = 0x100;

/// A single flow (branch/call/crossbuild/...) discovered while walking a constructor's p-code
/// templates.
///
/// Port of `SleighInstructionPrototype.FlowRecord`.
#[derive(Clone, Debug)]
pub struct FlowRecord {
    /// The constructor tree node containing the destination address of the flow, if this flow
    /// leaves the instruction and its address is statically resolvable from the parse tree.
    pub addressnode: Option<usize>,
    /// The p-code template op producing the flow.
    pub op: OpTpl,
    /// Flags describing this flow; a combination of the flow-flag constants in this module.
    pub flow_flags: i32,
}

/// A summary of the flow information gathered while walking a constructor's p-code templates.
///
/// Port of `SleighInstructionPrototype.FlowSummary`.
#[derive(Clone, Debug, Default)]
pub struct FlowSummary {
    /// The largest delay-slot byte count encoded via a delay-slot (`INDIRECT`) directive.
    pub delay: i32,
    /// True if any crossbuild (`PTRSUB`) directive was encountered.
    pub has_cross_builds: bool,
    /// True if any input references `inst_next2`.
    pub has_next2: bool,
    /// The flow records gathered, in traversal order, or `None` if none were gathered.
    pub flow_state: Option<Vec<FlowRecord>>,
    /// The last p-code template op visited.
    pub lastop: Option<OpTpl>,
}

/// Records a single flow discovered during [`walk_templates`], resolving its destination tree
/// node when the flow leaves the instruction and is statically determinable.
///
/// Port of the private `SleighInstructionPrototype.addExplicitFlow`; `tree`/`table` give access
/// to the constructor at `state` and its operand symbols.
fn add_explicit_flow(
    tree: Option<&ConstructTree>,
    table: &SymbolTable,
    state: Option<usize>,
    op: &OpTpl,
    flags: i32,
    summary: &mut FlowSummary,
) {
    let mut record = FlowRecord {
        addressnode: None,
        op: op.clone(),
        flow_flags: flags,
    };
    // First varnode input contains the destination address
    let dest = op.get_in(0);
    // If the flow is out of the instruction, store the node so we can easily calculate address
    if (flags & (JUMPOUT | CALL | CROSSBUILD)) != 0 {
        if let (Some(tree), Some(state)) = (tree, state) {
            if (flags & CROSSBUILD) != 0 {
                record.addressnode = Some(state);
            } else if dest.offset.tp == ConstTplType::Handle {
                let oper = dest.offset.handle_index as usize;
                let node = tree.get(state);
                let is_code = node
                    .ct
                    .as_ref()
                    .and_then(|ct| ct.get_operand(table, oper))
                    .is_some_and(|sym| sym.is_code_address());
                if is_code {
                    record.addressnode = node.sub_states.get(oper).copied();
                }
            }
        }
    }
    summary.flow_state.get_or_insert_with(Vec::new).push(record);
}

/// Walks the p-code templates in the order they would be emitted, collecting flow-flag
/// [`FlowRecord`]s into a [`FlowSummary`]. `tree` is the tree the walker walks (if any) and
/// `table` the language's symbol table, through which operand symbols are resolved.
///
/// Port of `SleighInstructionPrototype.walkTemplates(OpTplWalker)`.
pub fn walk_templates(
    walker: &mut OpTplWalker<'_>,
    tree: Option<&ConstructTree>,
    table: &SymbolTable,
) -> FlowSummary {
    let mut res = FlowSummary::default();

    while walker.is_state() {
        let op = match walker.next_op_tpl() {
            None => {
                walker.pop_build();
                continue;
            }
            Some(NextOpTpl::OperandIndex(buildnum)) => {
                walker.push_build(buildnum);
                continue;
            }
            Some(NextOpTpl::Op(op)) => op,
        };
        res.lastop = Some(op.clone());
        match op.get_opcode() {
            OpCode::CpuiPtrsub => {
                // encoded crossbuild directive
                res.has_cross_builds = true;
                add_explicit_flow(tree, table, walker.get_state(), op, CROSSBUILD, &mut res);
            }
            OpCode::CpuiBranchind => {
                add_explicit_flow(tree, table, None, op, BRANCH_INDIRECT | NO_FALLTHRU, &mut res);
            }
            OpCode::CpuiBranch => {
                let dest_type = op.get_in(0).offset.tp;
                let flags = if dest_type == ConstTplType::JNext {
                    BRANCH_TO_END
                } else if dest_type == ConstTplType::JStart || dest_type == ConstTplType::JRelative {
                    NO_FALLTHRU
                } else {
                    JUMPOUT | NO_FALLTHRU
                };
                add_explicit_flow(tree, table, walker.get_state(), op, flags, &mut res);
            }
            OpCode::CpuiCbranch => {
                let dest_type = op.get_in(0).offset.tp;
                let flags = if dest_type == ConstTplType::JNext {
                    BRANCH_TO_END
                } else if dest_type == ConstTplType::JNext2 {
                    JUMPOUT
                } else if dest_type != ConstTplType::JStart && dest_type != ConstTplType::JRelative {
                    JUMPOUT
                } else {
                    0
                };
                add_explicit_flow(tree, table, walker.get_state(), op, flags, &mut res);
            }
            OpCode::CpuiCall => {
                add_explicit_flow(tree, table, walker.get_state(), op, CALL, &mut res);
            }
            OpCode::CpuiCallind => {
                add_explicit_flow(tree, table, None, op, CALL_INDIRECT, &mut res);
            }
            OpCode::CpuiReturn => {
                add_explicit_flow(tree, table, None, op, RETURN | NO_FALLTHRU, &mut res);
            }
            OpCode::CpuiPtradd => {
                // Encoded label build directive
                add_explicit_flow(tree, table, None, op, LABEL, &mut res);
            }
            OpCode::CpuiIndirect => {
                // Encode delayslot
                let dest_type = op.get_in(0).offset.get_real() as i32;
                if dest_type > res.delay {
                    res.delay = dest_type;
                }
            }
            _ => {}
        }
        if op.input.iter().any(|i| i.offset.tp == ConstTplType::JNext2) {
            res.has_next2 = true;
        }
    }
    res
}

/// Converts normalized flow flags into a [`RefType`].
///
/// Port of the private `SleighInstructionPrototype.convertFlowFlags(int)`.
fn convert_flow_flags(mut flow_flags: i32) -> RefType {
    if (flow_flags & LABEL) != 0 {
        flow_flags |= BRANCH_TO_END;
    }
    flow_flags &= !(CROSSBUILD | LABEL);
    // NOTE: If prototype has cross-build, flow must be determined dynamically
    match flow_flags {
        0 | BRANCH_TO_END => RefType::FallThrough,
        CALL => RefType::UnconditionalCall,
        f if f == CALL | NO_FALLTHRU | RETURN => RefType::CallTerminator,
        f if f == CALL_INDIRECT | NO_FALLTHRU | RETURN => RefType::ComputedCallTerminator,
        // This could be wrong but doesn't matter much
        f if f == CALL | BRANCH_TO_END => RefType::ConditionalCall,
        f if f == CALL | NO_FALLTHRU | JUMPOUT => RefType::ComputedJump,
        f if f == CALL | NO_FALLTHRU | BRANCH_TO_END | RETURN => RefType::UnconditionalCall,
        CALL_INDIRECT => RefType::ComputedCall,
        f if f == BRANCH_INDIRECT | NO_FALLTHRU => RefType::ComputedJump,
        f if f == BRANCH_INDIRECT | BRANCH_TO_END
            || f == BRANCH_INDIRECT | NO_FALLTHRU | BRANCH_TO_END
            || f == BRANCH_INDIRECT | JUMPOUT | NO_FALLTHRU | BRANCH_TO_END =>
        {
            RefType::ConditionalComputedJump
        }
        f if f == CALL_INDIRECT | BRANCH_TO_END || f == CALL_INDIRECT | NO_FALLTHRU | BRANCH_TO_END => {
            RefType::ConditionalComputedCall
        }
        f if f == RETURN | NO_FALLTHRU => RefType::Terminator,
        f if f == RETURN | BRANCH_TO_END || f == RETURN | NO_FALLTHRU | BRANCH_TO_END => {
            RefType::ConditionalTerminator
        }
        JUMPOUT => RefType::ConditionalJump,
        f if f == JUMPOUT | NO_FALLTHRU => RefType::UnconditionalJump,
        f if f == JUMPOUT | NO_FALLTHRU | BRANCH_TO_END => RefType::ConditionalJump,
        f if f == JUMPOUT | NO_FALLTHRU | RETURN => RefType::JumpTerminator,
        // added for tableswitch in jvm
        f if f == JUMPOUT | NO_FALLTHRU | BRANCH_INDIRECT => RefType::ComputedJump,
        f if f == BRANCH_INDIRECT | NO_FALLTHRU | RETURN => RefType::JumpTerminator,
        NO_FALLTHRU => RefType::Terminator,
        f if f == BRANCH_TO_END | JUMPOUT => RefType::ConditionalJump,
        f if f == NO_FALLTHRU | BRANCH_TO_END => RefType::FallThrough,
        _ => RefType::Invalid,
    }
}

/// Reduces a list of [`FlowRecord`]s (as gathered by [`walk_templates`]) to a single overall
/// [`RefType`] for the instruction.
///
/// Port of `SleighInstructionPrototype.flowListToFlowType(List<FlowRecord>)`.
pub fn flow_list_to_flow_type(flowstate: Option<&[FlowRecord]>) -> RefType {
    let Some(flowstate) = flowstate else {
        return RefType::FallThrough;
    };
    let mut flags = 0i32;
    for rec in flowstate {
        flags &= !(NO_FALLTHRU | CROSSBUILD | LABEL);
        flags |= rec.flow_flags;
    }
    convert_flow_flags(flags)
}

/// The shared, immutable data of a prototype.
struct PrototypeData {
    language: Arc<SleighLanguage>,
    isindelayslot: bool,
    /// The flow type, when it does not depend on a cross-build.
    flow_type: RefType,
    /// Operand indexes in the mnemonic constructor, in display order.
    opresolve: Vec<i32>,
    /// Lazily computed default reference types of the operands.
    op_ref_types: Mutex<Vec<Option<RefType>>>,
    /// Flows of the instruction whose destinations are code addresses.
    flow_state_list: Vec<FlowRecord>,
    flow_state_list_named: Option<Vec<Option<Vec<FlowRecord>>>>,
    delay_slot_byte_cnt: i32,
    has_cross_builds: bool,
    has_next2: bool,
    length: i32,
    tree: ConstructTree,
    /// Node of the constructor that prints the mnemonic.
    mnemonic_state: usize,
    hashcode: i32,
}

/// The [`InstructionPrototype`] for sleigh languages. The prototype is unique up to the tree of
/// constructors: variations in the bit pattern that none of the constructor mask/values care
/// about get lumped under the same prototype.
///
/// Port of `ghidra.app.plugin.processors.sleigh.SleighInstructionPrototype`. See the module
/// docs.
#[derive(Clone)]
pub struct SleighInstructionPrototype {
    inner: Arc<PrototypeData>,
}

impl std::fmt::Debug for SleighInstructionPrototype {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SleighInstructionPrototype")
            .field("length", &self.inner.length)
            .field("hashcode", &self.inner.hashcode)
            .field("tree", &self.dump_constructor_tree())
            .finish()
    }
}

impl PartialEq for SleighInstructionPrototype {
    /// Port of `equals(Object)`, which trusts entirely in the hash.
    fn eq(&self, other: &Self) -> bool {
        self.inner.hashcode == other.inner.hashcode
    }
}

fn to_memory_error(e: SleighError) -> MemoryAccessException {
    match e {
        SleighError::MemoryAccess(e) => e,
        other => MemoryAccessException::new(other.to_string()),
    }
}

/// Java-style equality of two operand objects (Java puts them in a `HashSet<Object>`).
fn same_object(a: &OperandValue, b: &OperandValue) -> bool {
    match (a, b) {
        (OperandValue::Register(x), OperandValue::Register(y)) => *x == *y,
        (OperandValue::Address(x), OperandValue::Address(y)) => x == y,
        (OperandValue::Scalar(x), OperandValue::Scalar(y)) => {
            x.get_unsigned_value() == y.get_unsigned_value()
                && x.bit_length() == y.bit_length()
                && x.is_signed() == y.is_signed()
        }
        (OperandValue::Character(x), OperandValue::Character(y)) => x == y,
        (OperandValue::Text(x), OperandValue::Text(y)) => x == y,
        _ => false,
    }
}

fn add_unique(set: &mut Vec<OperandValue>, obj: OperandValue) {
    if !set.iter().any(|o| same_object(o, &obj)) {
        set.push(obj);
    }
}

fn contains(set: &[OperandValue], obj: &OperandValue) -> bool {
    set.iter().any(|o| same_object(o, obj))
}

/// `new Scalar(bits, value, signed)` for a size in bytes, clamped to the 64 bits a `Scalar`
/// can hold (Java would reject a wider size with an `IllegalArgumentException`).
fn scalar(size: i32, value: i64) -> Scalar {
    let bits = (size.max(0) * 8).min(64) as u8;
    Scalar::new_with_signedness(bits, if bits == 0 { 0 } else { value }, value < 0)
}

impl SleighInstructionPrototype {
    /// Resolves the instruction in `buf` against `language`'s decision tree and caches its flow
    /// and operand information. `context` holds the packed context words at the instruction.
    ///
    /// Port of the constructor `SleighInstructionPrototype(SleighLanguage, MemBuffer,
    /// ProcessorContextView, ContextCache, boolean, SleighDebugLogger)` followed by `cacheInfo`
    /// (which Java runs for every prototype it keeps), without a debug logger.
    ///
    /// # Errors
    /// [`SleighError::UnknownInstruction`] if the bytes match no constructor, or
    /// [`SleighError::MemoryAccess`] if they cannot be read.
    pub fn new(
        language: Arc<SleighLanguage>,
        buf: Arc<dyn MemBuffer>,
        context: Vec<i32>,
        in_delay_slot: bool,
    ) -> Result<Self, SleighError> {
        let proto_context = SleighParserContext::for_resolve(buf, language.clone(), context);
        Self::resolve(&language, &proto_context)?;
        let tree = proto_context.take_tree();
        let mut hashcode = tree.hash_code(ConstructTree::ROOT);
        if in_delay_slot {
            hashcode = hashcode.wrapping_add(0xFABFAB);
        }
        let length = tree.get(ConstructTree::ROOT).length;
        let table = language.get_symbol_table();

        // cacheTreeInfo: walk the constructor tree gathering flow destinations, flow flags
        // and delay slot directives
        let mut walker = OpTplWalker::new(&tree, ConstructTree::ROOT, -1);
        let summary = walk_templates(&mut walker, Some(&tree), table);
        let delay_slot_byte_cnt = summary.delay;
        let has_cross_builds = summary.has_cross_builds;
        let has_next2 = summary.has_next2;
        let (flow_state_list, flow_type) = match summary.flow_state {
            Some(list) => {
                let flow_type = flow_list_to_flow_type(Some(&list));
                (list, flow_type)
            }
            None => (Vec::new(), RefType::FallThrough),
        };
        let numsects = language.num_sections();
        let flow_state_list_named = (numsects > 0).then(|| {
            (0..numsects)
                .map(|i| {
                    let mut walker = OpTplWalker::new(&tree, ConstructTree::ROOT, i);
                    walk_templates(&mut walker, Some(&tree), table).flow_state
                })
                .collect()
        });

        // cacheMnemonicState: the node that prints the mnemonic, and its operands in printing
        // order
        let mut mnemonic_state = ConstructTree::ROOT;
        let mut ct = tree.get(mnemonic_state).ct.clone();
        let mut index = ct.as_ref().map_or(-1, |c| c.get_flowthru_index());
        while index >= 0 {
            mnemonic_state = tree.get_sub_state(mnemonic_state, index as usize);
            ct = tree.get(mnemonic_state).ct.clone();
            index = ct.as_ref().map_or(-1, |c| c.get_flowthru_index());
        }
        let opresolve = ct.map(|c| c.get_ops_print_order()).unwrap_or_default();
        let op_ref_types = Mutex::new(vec![None; opresolve.len()]);

        Ok(Self {
            inner: Arc::new(PrototypeData {
                language,
                isindelayslot: in_delay_slot,
                flow_type,
                opresolve,
                op_ref_types,
                flow_state_list,
                flow_state_list_named,
                delay_slot_byte_cnt,
                has_cross_builds,
                has_next2,
                length,
                tree,
                mnemonic_state,
                hashcode,
            }),
        })
    }

    /// Builds the constructor tree in `proto_context` by walking the decision trees. Port of the
    /// private `resolve(DecisionNode, SleighParserContext, SleighDebugLogger)`.
    fn resolve(
        language: &SleighLanguage,
        proto_context: &SleighParserContext,
    ) -> Result<(), SleighError> {
        let table = language.get_symbol_table();
        let root = language.get_root_subtable().ok_or_else(|| {
            UnknownInstructionException::with_message("language has no instruction table")
        })?;
        let mut walker = ParserWalker::new(proto_context);
        walker.base_state();
        walker.set_offset(0);
        let ct = root.resolve(&walker)?; // Base constructor
        walker.set_constructor(ct.clone());
        ct.apply_context(&walker)?;

        while walker.is_state() {
            let ct = walker
                .get_constructor()
                .expect("every node on the walk has been resolved");
            let mut oper = walker.get_operand() as usize;
            let numoper = ct.get_num_operands();
            while oper < numoper {
                let sym = ct.get_operand(table, oper).ok_or_else(|| {
                    SleighException::with_message(format!(
                        "operand {oper} of {} is not an operand symbol",
                        ct.to_display_string()
                    ))
                })?;
                let off = walker.get_offset(sym.get_offset_base()) + sym.get_relative_offset();
                walker.allocate_operand()?;
                walker.set_offset(off);
                if let Some(tsym) = sym.get_defining_symbol(table) {
                    if let Some(subct) = tsym.resolve(&walker)? {
                        walker.set_constructor(subct.clone());
                        subct.apply_context(&walker)?;
                        break;
                    }
                }
                walker.set_current_length(sym.get_minimum_length());
                walker.pop_operand();
                oper += 1;
            }
            if oper >= numoper {
                // Finished processing constructor
                walker.calc_current_length(ct.get_minimum_length(), numoper);
                walker.pop_operand();
            }
        }
        Ok(())
    }

    /// The language this prototype belongs to.
    pub fn language(&self) -> &Arc<SleighLanguage> {
        &self.inner.language
    }

    /// The constructor tree of this prototype.
    pub fn tree(&self) -> &ConstructTree {
        &self.inner.tree
    }

    /// Port of `getRootState()`: the root node of the constructor tree.
    pub fn get_root_state(&self) -> usize {
        ConstructTree::ROOT
    }

    /// Port of the package-private `getMnemonicState()`.
    pub fn get_mnemonic_state(&self) -> usize {
        self.inner.mnemonic_state
    }

    /// Port of `hashCode()`: the hash of the constructor tree, offset for a delay-slot
    /// instruction.
    pub fn java_hash_code(&self) -> i32 {
        self.inner.hashcode
    }

    /// Lists the constructor line numbers used to resolve this encoding, with brackets
    /// describing the tree structure. Port of `dumpConstructorTree()`.
    pub fn dump_constructor_tree(&self) -> String {
        self.inner
            .tree
            .dump_constructor_tree(ConstructTree::ROOT)
            .unwrap_or_default()
    }

    /// Port of `getLength()`.
    pub fn get_length(&self) -> i32 {
        self.inner.length
    }

    /// Port of `getDelaySlotByteCount()`.
    pub fn get_delay_slot_byte_count(&self) -> i32 {
        self.inner.delay_slot_byte_cnt
    }

    /// The flow records of section `secnum` (`-1` for the main section).
    fn flow_list(&self, secnum: i32) -> Option<&[FlowRecord]> {
        if secnum < 0 {
            return Some(&self.inner.flow_state_list);
        }
        self.inner
            .flow_state_list_named
            .as_ref()?
            .get(secnum as usize)?
            .as_deref()
    }

    /// A parser context for this prototype over `buf`, with context recovered from the tree
    /// and every operand handle resolved. Port of `getParserContext(MemBuffer,
    /// ProcessorContextView)`, given the packed context words.
    ///
    /// # Errors
    /// A [`SleighError`] if the context or a handle cannot be recovered.
    pub fn new_parser_context(
        &self,
        buf: Arc<dyn MemBuffer>,
        context: Vec<i32>,
    ) -> Result<SleighParserContext, SleighError> {
        let new_context = SleighParserContext::new(buf, self.clone(), context);
        Self::reconstruct_context(&new_context)?;
        Self::resolve_handles(&new_context)?;
        Ok(new_context)
    }

    /// Reconstructs the parser context's packed context words and global context commits by
    /// walking the already resolved tree. Port of the private
    /// `reconstructContext(SleighParserContext, SleighDebugLogger)`.
    fn reconstruct_context(proto_context: &SleighParserContext) -> Result<(), SleighError> {
        let mut walker = ParserWalker::new(proto_context);
        walker.base_state();
        while walker.is_state() {
            if let Some(ct) = walker.get_constructor() {
                let oper = walker.get_operand() as usize;
                let numoper = ct.get_num_operands();
                if oper == 0 {
                    // Upon first entry to this Constructor, apply its context changes
                    ct.apply_context(&walker)?;
                }
                if oper < numoper {
                    walker.push_operand(oper);
                    continue;
                }
            }
            walker.pop_operand();
        }
        Ok(())
    }

    /// Resolves the handle of every operand of the tree. Port of the private
    /// `resolveHandles(SleighParserContext)`.
    fn resolve_handles(proto_context: &SleighParserContext) -> Result<(), SleighError> {
        let table = proto_context
            .language()
            .map(|l| l.get_symbol_table())
            .ok_or_else(|| SleighException::with_message("parser context has no language"))?;
        let mut walker = ParserWalker::new(proto_context);
        walker.base_state();
        while walker.is_state() {
            let ct = walker
                .get_constructor()
                .expect("every node of a resolved tree has a constructor");
            let mut oper = walker.get_operand() as usize;
            let numoper = ct.get_num_operands();
            while oper < numoper {
                let sym = ct.get_operand(table, oper).ok_or_else(|| {
                    SleighException::with_message("constructor operand is not an operand symbol")
                })?;
                walker.push_operand(oper); // Descend into node
                match sym.get_defining_symbol(table) {
                    Some(SleighSymbol::Subtable(_)) => break,
                    Some(triple) => {
                        let mut handle = walker.get_parent_handle();
                        triple.get_fixed_handle(&mut handle, &walker)?;
                        walker.set_parent_handle(handle);
                    }
                    None => {
                        // Must be an expression
                        let patexp = sym.get_defining_expression().ok_or_else(|| {
                            SleighException::with_message("operand has no definition")
                        })?;
                        let res = patexp.get_value(&walker)?;
                        let mut hand = walker.get_parent_handle();
                        hand.space = Some(proto_context.get_const_space());
                        hand.offset_space = None;
                        hand.offset_offset = res;
                        hand.size = 0;
                        walker.set_parent_handle(hand);
                    }
                }
                walker.pop_operand();
                oper += 1;
            }
            if oper >= numoper {
                if let Some(templ) = ct.get_templ() {
                    let mut hand = walker.get_parent_handle();
                    match &templ.result {
                        // Pop up handle to containing operand
                        Some(res) => res.fix(&mut hand, &walker)?,
                        None => hand.set_invalid(),
                    }
                    walker.set_parent_handle(hand);
                }
                walker.pop_operand();
            }
        }
        Ok(())
    }

    /// The parser context of `context`'s instruction, as a [`SleighParserContext`]. Java casts
    /// `context.getParserContext()`; a context of another kind is rebuilt from the instruction
    /// context's memory and processor context, as every Java `InstructionContext` does.
    fn with_parser_context<R>(
        &self,
        context: &dyn InstructionContext,
        f: impl FnOnce(&SleighParserContext) -> R,
    ) -> Result<R, SleighError> {
        let boxed = context.get_parser_context()?;
        if let Some(ctx) = boxed
            .as_any()
            .and_then(|a| a.downcast_ref::<SleighParserContext>())
        {
            return Ok(f(ctx));
        }
        let ctx = self.new_parser_context(
            snapshot_mem_buffer(context.get_mem_buffer(), 0)?,
            read_context_words(&self.inner.language, context.get_processor_context()),
        )?;
        Ok(f(&ctx))
    }

    /// The fixed handle of display operand `op_index` (operand `opresolve[op_index]` of the
    /// mnemonic constructor).
    fn operand_handle(&self, proto_context: &SleighParserContext, op_index: usize) -> FixedHandle {
        let op_state = self
            .inner
            .tree
            .get_sub_state(self.inner.mnemonic_state, self.inner.opresolve[op_index] as usize);
        proto_context.get_fixed_handle(op_state)
    }

    fn op_index_in_range(&self, op_index: i32) -> bool {
        op_index >= 0 && (op_index as usize) < self.inner.opresolve.len()
    }

    /// Port of the private `isIndirect(int)`: whether the mnemonic constructor's semantics use
    /// operand `sleigh_op_index` as the space of an indirect branch or call.
    fn is_indirect(&self, sleigh_op_index: i32) -> bool {
        let Some(ct) = self.inner.tree.get(self.inner.mnemonic_state).ct.as_ref() else {
            return false;
        };
        let Some(templ) = ct.get_templ() else {
            return false;
        };
        templ.vec.iter().any(|op| {
            (op.get_opcode() == OpCode::CpuiCallind || op.get_opcode() == OpCode::CpuiBranchind)
                && op.get_in(0).space.tp == ConstTplType::Handle
                && op.get_in(0).space.handle_index as i32 == sleigh_op_index
        })
    }

    /// Port of the private `getHandleAddr(FixedHandle, AddressSpace)`.
    fn get_handle_addr(hand: &FixedHandle, _cur_space: &Arc<AddressSpace>) -> Option<Address> {
        let space = hand.space.as_ref()?;
        if space.space_type() == AddressSpaceType::Unique || hand.offset_space.is_some() {
            return None;
        }
        Some(Address::new(space.clone(), space.truncate_offset(hand.offset_offset)))
    }

    fn register_in_space(&self, space: &Arc<AddressSpace>, offset: i64, size: i32) -> Option<RegisterRef> {
        self.inner.language.get_register_in_space(space, offset, size)
    }

    /// Port of the private `addHandleObject(AddressSpace, FixedHandle, ArrayList<Object>)`.
    fn add_handle_object(
        &self,
        cur_space: &Arc<AddressSpace>,
        handle: &FixedHandle,
        list: &mut Vec<OperandValue>,
    ) -> bool {
        let Some(space) = handle.space.as_ref() else {
            return false;
        };
        match space.space_type() {
            AddressSpaceType::Register => {
                match self.register_in_space(space, handle.offset_offset, handle.size) {
                    Some(reg) => list.push(OperandValue::Register(reg)),
                    None => list.push(OperandValue::Text(format!(
                        "<BAD_register_{}:{}>",
                        handle.offset_offset, handle.size
                    ))),
                }
                true
            }
            AddressSpaceType::Constant => {
                let mut size = handle.size;
                if size == 0 {
                    size = handle.offset_size;
                    if size == 0 {
                        size = self.inner.language.get_default_space().pointer_size();
                    }
                }
                list.push(OperandValue::Scalar(scalar(size, handle.offset_offset)));
                true
            }
            AddressSpaceType::Ram => {
                match &handle.offset_space {
                    None => {
                        if let Some(addr) = Self::get_handle_addr(handle, cur_space) {
                            list.push(OperandValue::Address(addr));
                            return true;
                        }
                    }
                    // could be simply taking the value of a register as an address
                    Some(offset_space) if offset_space.space_type() == AddressSpaceType::Register => {
                        if let Some(reg) = self.register_in_space(
                            offset_space,
                            handle.offset_offset,
                            handle.offset_size,
                        ) {
                            list.push(OperandValue::Register(reg));
                        }
                        return true;
                    }
                    Some(_) => {}
                }
                false
            }
            _ => false,
        }
    }

    /// Port of the private `gatherFlags(int, InstructionContext, int)`.
    fn gather_flags(
        &self,
        mut curflags: i32,
        context: &dyn InstructionContext,
        secnum: i32,
    ) -> Result<i32, SleighError> {
        let Some(curlist) = self.flow_list(secnum) else {
            return Ok(curflags);
        };
        for rec in curlist {
            if (rec.flow_flags & CROSSBUILD) != 0 {
                let (crossproto, newsecnum) = self.with_parser_context(context, |pc| {
                    self.cross_build_target(pc, context, rec)
                })??;
                curflags = crossproto.gather_flags(curflags, context, newsecnum)?;
            } else {
                curflags &= !(CROSSBUILD | LABEL | NO_FALLTHRU);
                curflags |= rec.flow_flags;
            }
        }
        Ok(curflags)
    }

    /// The prototype a CROSSBUILD flow record refers to, and the section it builds.
    fn cross_build_target(
        &self,
        parsecontext: &SleighParserContext,
        context: &dyn InstructionContext,
        rec: &FlowRecord,
    ) -> Result<(SleighInstructionPrototype, i32), SleighError> {
        let addr = self.cross_build_address(parsecontext, rec)?;
        let cross_box = context.get_parser_context_at(addr).map_err(|e| {
            UnknownInstructionException::with_message(format!("crossbuild target: {e}"))
        })?;
        let crosscontext = cross_box
            .as_any()
            .and_then(|a| a.downcast_ref::<SleighParserContext>())
            .ok_or_else(|| {
                UnknownInstructionException::with_message("crossbuild target is not a sleigh instruction")
            })?;
        let newsecnum = rec.op.get_in(1).offset.get_real() as i32;
        let crossproto = crosscontext
            .get_sleigh_prototype()
            .cloned()
            .ok_or_else(|| SleighException::with_message("crossbuild target has no prototype"))?;
        Ok((crossproto, newsecnum))
    }

    /// The address a CROSSBUILD flow record's first input names, evaluated at its node.
    fn cross_build_address(
        &self,
        parsecontext: &SleighParserContext,
        rec: &FlowRecord,
    ) -> Result<Address, SleighError> {
        let mut walker = ParserWalker::new(parsecontext);
        walker.sub_tree_state(rec.addressnode.unwrap_or(ConstructTree::ROOT));
        let vn = rec.op.get_in(0);
        let spc = vn.space.fix_space(&walker)?;
        let off = vn.offset.fix(&walker)?;
        Ok(Address::new(spc.clone(), spc.truncate_offset(off)))
    }

    /// Port of the private `gatherFlows(ArrayList<Address>, SleighParserContext,
    /// InstructionContext, int)`.
    fn gather_flows(
        &self,
        res: &mut Vec<Address>,
        parsecontext: &SleighParserContext,
        context: &dyn InstructionContext,
        secnum: i32,
    ) -> Result<(), SleighError> {
        let Some(curlist) = self.flow_list(secnum) else {
            return Ok(());
        };
        for rec in curlist {
            if (rec.flow_flags & CROSSBUILD) != 0 {
                let addr = self.cross_build_address(parsecontext, rec)?;
                let cross_box = context.get_parser_context_at(addr).map_err(|e| {
                    UnknownInstructionException::with_message(format!("crossbuild target: {e}"))
                })?;
                let crosscontext = cross_box
                    .as_any()
                    .and_then(|a| a.downcast_ref::<SleighParserContext>())
                    .ok_or_else(|| {
                        UnknownInstructionException::with_message(
                            "crossbuild target is not a sleigh instruction",
                        )
                    })?;
                let newsecnum = rec.op.get_in(1).offset.get_real() as i32;
                let crossproto = crosscontext.get_sleigh_prototype().cloned().ok_or_else(|| {
                    SleighException::with_message("crossbuild target has no prototype")
                })?;
                crossproto.gather_flows(res, crosscontext, context, newsecnum)?;
            } else if (rec.flow_flags & (JUMPOUT | CALL)) != 0 {
                let hand = match rec.addressnode {
                    Some(node) => parsecontext.get_fixed_handle(node),
                    None => FixedHandle::new(),
                };
                if !hand.is_invalid() && hand.offset_space.is_none() {
                    if let Some(addr) = Self::get_handle_addr(&hand, &parsecontext.get_cur_space()) {
                        res.push(addr);
                    }
                } else if rec.op.get_in(0).offset.tp == ConstTplType::JNext2 {
                    res.push(parsecontext.get_n2addr());
                }
            }
        }
        Ok(())
    }

    /// Parses the delay-slot instructions following this one (with this instruction's context,
    /// as Java's read-only processor context does), returning the offset past them.
    fn delay_slot_end(&self, context: &dyn InstructionContext) -> Result<i32, SleighError> {
        let words = read_context_words(&self.inner.language, context.get_processor_context());
        let mut offset = self.get_length();
        let mut bytecount = 0;
        loop {
            let delaymem = snapshot_mem_buffer(context.get_mem_buffer(), offset)?;
            let proto = self
                .inner
                .language
                .parse_prototype(delaymem, words.clone(), true)?;
            let len = proto.get_length();
            offset += len;
            bytecount += len;
            if bytecount >= self.inner.delay_slot_byte_cnt {
                break;
            }
        }
        Ok(offset)
    }

    fn unimplemented_pcode(context: &dyn InstructionContext) -> Vec<PcodeOp> {
        vec![PcodeOp::with_address_no_inputs(
            context.get_address(),
            0,
            crate::program::model::pcode::OpCode::Unimplemented,
        )]
    }

    /// The fall offset including every delay-slot instruction, and the delay-slot byte count
    /// when the instruction has delay slots (the shared prologue of `getPcode` and
    /// `getPcodePacked`).
    fn fall_offset_with_delay_slots(
        &self,
        context: &dyn InstructionContext,
    ) -> Result<(i32, Option<i32>), PcodeEmitBuildError> {
        let mut fall_offset = self.get_length();
        let mut delay_bytes = None;
        if self.inner.delay_slot_byte_cnt > 0 {
            let mut bytecount = 0;
            loop {
                let addr = context
                    .get_address()
                    .add(fall_offset as i64)
                    .map_err(|e| SleighException::with_message(e.to_string()))?;
                let delay = context.get_parser_context_at(addr).map_err(|e| {
                    UnknownInstructionException::with_message(format!(
                        "Could not find delay slot parser context: {e}"
                    ))
                })?;
                let len = delay.get_prototype().get_length();
                fall_offset += len;
                bytecount += len;
                if bytecount >= self.inner.delay_slot_byte_cnt {
                    break;
                }
            }
            delay_bytes = Some(bytecount);
        }
        Ok((fall_offset, delay_bytes))
    }

    /// The body of `getPcode(InstructionContext, PcodeOverride)`.
    fn build_pcode(
        &self,
        context: &dyn InstructionContext,
        pcode_override: Option<&dyn PcodeOverride>,
    ) -> Result<Vec<PcodeOp>, PcodeEmitBuildError> {
        let (fall_offset, delay_bytes) = self.fall_offset_with_delay_slots(context)?;
        self.with_parser_context(context, |proto_context| {
            let delay_context;
            let proto_context = match delay_bytes {
                Some(bytecount) => {
                    delay_context = SleighParserContext::for_delay_slot(proto_context, bytecount);
                    &delay_context
                }
                None => proto_context,
            };
            let mut walker = ParserWalker::new(proto_context);
            walker.base_state();
            let mut emit =
                PcodeEmitObjects::new(walker, Some(context), fall_offset, pcode_override);
            emit.build_current()?;
            emit.resolve_relatives()?;
            if !self.inner.isindelayslot {
                emit.resolve_final_fallthrough()?;
            }
            Ok(emit.into_pcode_ops())
        })?
    }

    /// The body of `getPcodePacked(PatchEncoder, InstructionContext, PcodeOverride)`'s `try`.
    fn build_pcode_packed(
        &self,
        encoder: &mut dyn PatchEncoder,
        context: &dyn InstructionContext,
        pcode_override: Option<&dyn PcodeOverride>,
    ) -> Result<(), PcodeEmitBuildError> {
        let (fall_offset, delay_bytes) = self.fall_offset_with_delay_slots(context)?;
        self.with_parser_context(context, |proto_context| {
            let delay_context;
            let proto_context = match delay_bytes {
                Some(bytecount) => {
                    delay_context = SleighParserContext::for_delay_slot(proto_context, bytecount);
                    &delay_context
                }
                None => proto_context,
            };
            let mut walker = ParserWalker::new(proto_context);
            walker.base_state();
            let mut emit =
                PcodeEmitPacked::new(encoder, walker, Some(context), fall_offset, pcode_override);
            emit.emit_header()?;
            emit.build_current()?;
            emit.resolve_relatives()?;
            if !self.inner.isindelayslot {
                emit.resolve_final_fallthrough()?;
            }
            emit.emit_tail()?;
            Ok(())
        })?
    }

    /// The default reference type of every operand, cached. Port of the private
    /// `cacheDefaultOperandRefTypes(InstructionContext)`.
    fn cache_default_operand_ref_types(&self, context: &dyn InstructionContext) {
        let pcode = self.get_pcode(context, None);
        if pcode.is_empty() {
            return;
        }
        let Ok(op_handles) = self.with_parser_context(context, |pc| {
            (0..self.inner.opresolve.len())
                .map(|i| self.operand_handle(pc, i))
                .collect::<Vec<_>>()
        }) else {
            return;
        };
        let mut op_ref_types = self.inner.op_ref_types.lock().expect("ref type cache poisoned");
        for index in 0..op_handles.len() {
            if op_handles[index].is_invalid() || op_ref_types[index].is_some() {
                continue;
            }
            let ref_type = Self::operand_ref_type(&op_handles[index], &pcode);
            op_ref_types[index] = Some(ref_type);
            for n in (index + 1)..op_handles.len() {
                if op_handles[index] == op_handles[n] {
                    op_ref_types[n] = Some(ref_type);
                }
            }
        }
    }

    fn operand_ref_type(hand: &FixedHandle, pcode: &[PcodeOp]) -> RefType {
        if hand.is_dynamic() {
            Self::get_dynamic_operand_ref_type(hand, pcode)
        } else {
            match hand.get_static_varnode() {
                Some(var) => Self::get_static_operand_ref_type(&var, pcode),
                None => RefType::Data,
            }
        }
    }

    /// Port of the private `getStaticOperandRefType(Varnode, PcodeOp[])`.
    fn get_static_operand_ref_type(var: &Varnode, pcode: &[PcodeOp]) -> RefType {
        use crate::program::model::pcode::OpCode as P;
        if var.is_constant() {
            return RefType::Data;
        }
        let mut is_read = false;
        let mut is_write = false;
        for element in pcode {
            let inputs = element.get_inputs();
            let first_is_var = inputs.first() == Some(var);
            match element.get_opcode() {
                P::BranchInd | P::CallInd | P::Return if first_is_var => return RefType::Indirection,
                P::Branch if first_is_var => return RefType::UnconditionalJump,
                P::CBranch if first_is_var => return RefType::ConditionalJump,
                P::Call if first_is_var => return RefType::UnconditionalCall,
                _ => {}
            }
            if !var.is_unique() {
                if element.get_output() == Some(var) {
                    is_write = true;
                }
                if inputs.iter().any(|i| i == var) {
                    is_read = true;
                }
            }
        }
        Self::read_write_ref_type(is_read, is_write)
    }

    fn read_write_ref_type(is_read: bool, is_write: bool) -> RefType {
        match (is_read, is_write) {
            (true, true) => RefType::ReadWrite,
            (true, false) => RefType::Read,
            (false, true) => RefType::Write,
            (false, false) => RefType::Data,
        }
    }

    /// Port of the private `getDynamicOperandRefType(FixedHandle, PcodeOp[])`.
    fn get_dynamic_operand_ref_type(hand: &FixedHandle, pcode: &[PcodeOp]) -> RefType {
        use crate::program::model::pcode::OpCode as P;
        let offset = hand.get_dynamic_offset();
        let static_addr = hand.get_static_varnode();
        let temp = hand.get_dynamic_temp();
        let mut is_read = false;
        let mut is_write = false;
        for element in pcode {
            let inputs = element.get_inputs();
            match element.get_opcode() {
                P::Load => {
                    if temp.is_some() && temp.as_ref() == element.get_output() {
                        is_read = true;
                    }
                }
                P::Store => {
                    if offset.is_some()
                        && offset.as_ref() == inputs.get(1)
                        && temp.is_some()
                        && temp.as_ref() == inputs.get(2)
                    {
                        is_write = true;
                    }
                }
                P::BranchInd | P::CallInd | P::Return => {
                    if (temp.is_some() && inputs.first() == temp.as_ref())
                        || (static_addr.is_some() && inputs.first() == static_addr.as_ref())
                    {
                        return RefType::Indirection;
                    }
                }
                P::Branch if static_addr.is_some() && inputs.first() == static_addr.as_ref() => {
                    return RefType::UnconditionalJump;
                }
                P::CBranch if static_addr.is_some() && inputs.first() == static_addr.as_ref() => {
                    return RefType::ConditionalJump;
                }
                P::Call if static_addr.is_some() && inputs.first() == static_addr.as_ref() => {
                    return RefType::UnconditionalCall;
                }
                _ => {}
            }
        }
        Self::read_write_ref_type(is_read, is_write)
    }

    /// Port of the private `getVarnodeObject(Varnode)`.
    fn get_varnode_object(&self, node: Option<&Varnode>) -> Option<OperandValue> {
        let node = node?;
        if node.is_constant() {
            return Some(OperandValue::Scalar(scalar(
                node.get_size(),
                node.get_offset(),
            )));
        }
        if node.is_address() || node.is_register() {
            let reg = self
                .inner
                .language
                .get_register_at(node.get_address(), node.get_size());
            return Some(match reg {
                Some(reg) => OperandValue::Register(reg),
                None => OperandValue::Address(node.get_address().clone()),
            });
        }
        None
    }

    fn space_by_id(&self, id: i64) -> Option<Arc<AddressSpace>> {
        self.inner
            .language
            .get_address_factory()
            .get_address_space_by_id(id as i32)
    }

    /// Port of the private `getInputObjects(PcodeOp, HashSet<Object>, HashSet<Object>)`.
    fn gather_input_objects(
        &self,
        pcode: &PcodeOp,
        input_objects: &mut Vec<OperandValue>,
        written_objects: &[OperandValue],
    ) {
        use crate::program::model::pcode::OpCode as P;
        let var_node = pcode.get_inputs();
        let mut vi = 0;
        // if this is a store or load instruction, skip over address space
        match pcode.get_opcode() {
            P::Call | P::Branch => return, // flow only
            P::CBranch => vi += 1,         // ignore flow address
            P::Store => vi += 1,           // ignore space ID
            P::Load => {
                if var_node.get(1).is_some_and(|v| v.is_constant()) {
                    if let Some(space) = self.space_by_id(var_node[0].get_offset()) {
                        let in_addr =
                            OperandValue::Address(Address::new(space, var_node[1].get_offset()));
                        // check that we didn't write to the location
                        if !contains(written_objects, &in_addr) {
                            add_unique(input_objects, in_addr);
                        }
                        return;
                    }
                }
                vi += 1; // ignore space ID
            }
            _ => {}
        }
        for node in var_node.iter().skip(vi) {
            if let Some(obj) = self.get_varnode_object(Some(node)) {
                if !contains(written_objects, &obj) {
                    add_unique(input_objects, obj);
                }
            }
        }
    }

    /// Port of the private `getResultObject(PcodeOp, HashSet<Object>)`.
    fn gather_result_object(&self, pcode: &PcodeOp, results: &mut Vec<OperandValue>) {
        let var_node = pcode.get_inputs();
        if pcode.get_opcode() == crate::program::model::pcode::OpCode::Store {
            if var_node.get(1).is_some_and(|v| v.is_constant()) {
                if let Some(space) = self.space_by_id(var_node[0].get_offset()) {
                    add_unique(
                        results,
                        OperandValue::Address(Address::new(space, var_node[1].get_offset())),
                    );
                }
            }
        } else if let Some(obj) = self.get_varnode_object(pcode.get_output()) {
            add_unique(results, obj);
        }
    }

    /// The representation list of display operand `op_index`, before conversion to objects.
    fn print_list_for(
        &self,
        proto_context: &SleighParserContext,
        op_index: usize,
    ) -> Vec<PrintListItem> {
        let mut list = Vec::new();
        // If the instruction produces memory errors, treat as if it has no representation list
        let _ = (|| -> Result<(), SleighError> {
            let table = self.inner.language.get_symbol_table();
            let ct = self
                .inner
                .tree
                .get(self.inner.mnemonic_state)
                .ct
                .clone()
                .ok_or_else(|| SleighException::with_message("unresolved mnemonic constructor"))?;
            let sym = ct
                .get_operand(table, self.inner.opresolve[op_index] as usize)
                .ok_or_else(|| SleighException::with_message("operand is not an operand symbol"))?;
            let mut walker = ParserWalker::new(proto_context);
            walker.sub_tree_state(self.inner.mnemonic_state);
            sym.print_list(&mut walker, &mut list)
        })();
        list
    }
}

impl InstructionPrototype for SleighInstructionPrototype {
    /// Port of `getParserContext(MemBuffer, ProcessorContextView)`.
    fn get_parser_context(
        &self,
        buf: &dyn MemBuffer,
        processor_context: &dyn ProcessorContextView,
    ) -> Result<Box<dyn crate::program::seam_stubs::ParserContext>, MemoryAccessException> {
        let words = read_context_words(&self.inner.language, processor_context);
        let ctx = self
            .new_parser_context(snapshot_mem_buffer(buf, 0)?, words)
            .map_err(to_memory_error)?;
        Ok(Box::new(ctx))
    }

    /// Port of `getPseudoParserContext(Address, MemBuffer, ProcessorContextView)`: parses the
    /// instruction at `address` within `buffer` and builds its parser context.
    fn get_pseudo_parser_context(
        &self,
        address: &Address,
        buffer: &dyn MemBuffer,
        processor_context: &dyn ProcessorContextView,
    ) -> Result<Box<dyn crate::program::seam_stubs::ParserContext>, GetPseudoParserContextError> {
        let words = read_context_words(&self.inner.language, processor_context);
        let offset = address.subtract(&buffer.get_address()) as i32;
        let nearbymem = snapshot_mem_buffer(buffer, offset)?;
        let proto = self
            .inner
            .language
            .parse_prototype(nearbymem.clone(), words.clone(), true)
            .map_err(|e| match e {
                SleighError::MemoryAccess(e) => GetPseudoParserContextError::MemoryAccess(e),
                SleighError::UnknownInstruction(e) => GetPseudoParserContextError::UnknownInstruction(e),
                SleighError::Sleigh(e) => GetPseudoParserContextError::UnknownInstruction(
                    UnknownInstructionException::with_message(e.message()),
                ),
            })?;
        let ctx = proto
            .new_parser_context(nearbymem, words)
            .map_err(to_memory_error)?;
        Ok(Box::new(ctx))
    }

    fn has_delay_slots(&self) -> bool {
        self.inner.delay_slot_byte_cnt != 0
    }

    fn has_cross_build_dependency(&self) -> bool {
        self.inner.has_cross_builds
    }

    fn has_next2_dependency(&self) -> bool {
        self.inner.has_next2
    }

    /// Port of `getMnemonic(InstructionContext)`; `"UNKNOWN"` if it cannot be printed.
    fn get_mnemonic(&self, context: &dyn InstructionContext) -> String {
        let res = self.with_parser_context(context, |pc| {
            let mut walker = ParserWalker::new(pc);
            walker.base_state();
            let ct = walker
                .get_constructor()
                .ok_or_else(|| SleighException::with_message("unresolved instruction"))?;
            ct.print_mnemonic(&mut walker)
        });
        match res {
            Ok(Ok(mnemonic)) if self.inner.isindelayslot => format!("_{mnemonic}"),
            Ok(Ok(mnemonic)) => mnemonic,
            _ => "UNKNOWN".to_string(),
        }
    }

    fn get_length(&self) -> i32 {
        self.inner.length
    }

    /// See the module docs: instruction masks are not computed.
    fn get_instruction_mask(&self) -> Option<Box<dyn Mask>> {
        None
    }

    /// See the module docs: operand masks are not computed.
    fn get_operand_value_mask(&self, _operand_index: i32) -> Option<Box<dyn Mask>> {
        None
    }

    /// Port of `getFlowType(InstructionContext)`.
    fn get_flow_type(&self, context: &dyn InstructionContext) -> RefType {
        if !self.inner.has_cross_builds {
            return self.inner.flow_type;
        }
        match self.gather_flags(0, context, -1) {
            Ok(flags) => convert_flow_flags(flags),
            Err(_) => RefType::Invalid,
        }
    }

    /// Port of `getDelaySlotDepth(InstructionContext)`; bad instructions are treated as not
    /// part of the delay slot.
    fn get_delay_slot_depth(&self, context: &dyn InstructionContext) -> i32 {
        if self.inner.delay_slot_byte_cnt == 1 {
            return 1;
        }
        // Java counts the instructions parsed before the first failure
        let words = read_context_words(&self.inner.language, context.get_processor_context());
        let mut delay_instr_cnt = 0;
        let mut byte_cnt = 0;
        let mut offset = self.get_length();
        while byte_cnt < self.inner.delay_slot_byte_cnt {
            let parsed = snapshot_mem_buffer(context.get_mem_buffer(), offset)
                .map_err(SleighError::from)
                .and_then(|mem| self.inner.language.parse_prototype(mem, words.clone(), true));
            let Ok(proto) = parsed else {
                break;
            };
            let len = proto.get_length();
            offset += len;
            byte_cnt += len;
            delay_instr_cnt += 1;
        }
        delay_instr_cnt
    }

    fn get_delay_slot_byte_count(&self) -> i32 {
        self.inner.delay_slot_byte_cnt
    }

    fn is_in_delay_slot(&self) -> bool {
        self.inner.isindelayslot
    }

    fn get_num_operands(&self) -> i32 {
        self.inner.opresolve.len() as i32
    }

    /// Port of `getOpType(int, InstructionContext)`.
    fn get_op_type(&self, op_index: i32, context: &dyn InstructionContext) -> i32 {
        if !self.op_index_in_range(op_index) {
            return OperandType::DYNAMIC as i32;
        }
        let Ok(hand) = self.with_parser_context(context, |pc| self.operand_handle(pc, op_index as usize))
        else {
            return OperandType::DYNAMIC as i32;
        };
        let Some(space) = hand.space.as_ref() else {
            return OperandType::DYNAMIC as i32;
        };
        let sleigh_op = self.inner.opresolve[op_index as usize];
        let indirect = if self.is_indirect(sleigh_op) { OperandType::INDIRECT } else { 0 };
        if hand.offset_space.is_none() {
            // Static handle
            match space.space_type() {
                AddressSpaceType::Register => return (OperandType::REGISTER | indirect) as i32,
                AddressSpaceType::Constant => return (OperandType::SCALAR | indirect) as i32,
                space_type => {
                    let is_code = self
                        .inner
                        .tree
                        .get(self.inner.mnemonic_state)
                        .ct
                        .as_ref()
                        .and_then(|ct| {
                            ct.get_operand(self.inner.language.get_symbol_table(), sleigh_op as usize)
                        })
                        .is_some_and(|sym| sym.is_code_address());
                    if is_code {
                        return (OperandType::ADDRESS | OperandType::CODE | indirect) as i32;
                    }
                    if space_type == AddressSpaceType::Ram {
                        return (OperandType::ADDRESS | OperandType::DATA | indirect) as i32;
                    }
                }
            }
        }
        (OperandType::DYNAMIC | indirect) as i32
    }

    /// Port of `getFallThrough(InstructionContext)`.
    fn get_fall_through(&self, context: &dyn InstructionContext) -> Option<Address> {
        if self.inner.flow_type.has_fallthrough() {
            // None if fallthru goes beyond boundary of address space
            return context
                .get_address()
                .add_no_wrap(self.get_fall_through_offset(context) as i64)
                .ok();
        }
        None
    }

    /// Port of `getFallThroughOffset(InstructionContext)`.
    fn get_fall_through_offset(&self, context: &dyn InstructionContext) -> i32 {
        if self.inner.delay_slot_byte_cnt <= 0 {
            return self.get_length();
        }
        self.delay_slot_end(context).unwrap_or_else(|_| self.get_length())
    }

    /// Port of `getFlows(InstructionContext)`; `None` for no flows.
    fn get_flows(&self, context: &dyn InstructionContext) -> Option<Vec<Address>> {
        if self.inner.flow_state_list.is_empty() {
            return None;
        }
        let mut addresses = Vec::new();
        let res = self.with_parser_context(context, |pc| {
            self.gather_flows(&mut addresses, pc, context, -1)
        });
        match res {
            Ok(Ok(())) if !addresses.is_empty() => Some(addresses),
            _ => None,
        }
    }

    /// Port of `getSeparator(int)`.
    fn get_separator(&self, op_index: i32) -> Option<String> {
        if op_index < 0 || op_index as usize > self.inner.opresolve.len() {
            return None;
        }
        self.inner
            .tree
            .get(self.inner.mnemonic_state)
            .ct
            .as_ref()?
            .print_separator(op_index)
    }

    /// Port of `getOpRepresentationList(int, InstructionContext)`.
    fn get_op_representation_list(
        &self,
        op_index: i32,
        context: &dyn InstructionContext,
    ) -> Option<Vec<OperandValue>> {
        if !self.op_index_in_range(op_index) {
            return None;
        }
        let list = self
            .with_parser_context(context, |pc| self.print_list_for(pc, op_index as usize))
            .unwrap_or_default();
        let cur_space = context.get_address().space().clone();
        let mut obj_list = Vec::new();
        for obj in list {
            match obj {
                PrintListItem::Char(c) => obj_list.push(OperandValue::Character(c)),
                PrintListItem::Handle { handle, .. } => {
                    self.add_handle_object(&cur_space, &handle, &mut obj_list);
                }
            }
        }
        Some(obj_list)
    }

    /// Port of `getAddress(int, InstructionContext)`.
    fn get_address(&self, op_index: i32, context: &dyn InstructionContext) -> Option<Address> {
        if !self.op_index_in_range(op_index) {
            return None;
        }
        let hand = self
            .with_parser_context(context, |pc| self.operand_handle(pc, op_index as usize))
            .ok()?;
        let space = hand.space.as_ref()?;
        if hand.offset_space.is_none() && space.space_type() == AddressSpaceType::Ram {
            return Self::get_handle_addr(&hand, context.get_address().space());
        }
        None
    }

    /// Port of `getRegister(int, InstructionContext)`.
    fn get_register(&self, op_index: i32, context: &dyn InstructionContext) -> Option<RegisterRef> {
        if !self.op_index_in_range(op_index) {
            return None;
        }
        let hand = self
            .with_parser_context(context, |pc| self.operand_handle(pc, op_index as usize))
            .ok()?;
        let space = hand.space.as_ref()?;
        if space.space_type() == AddressSpaceType::Register {
            return self.register_in_space(space, hand.offset_offset, hand.size);
        }
        None
    }

    /// Port of `getScalar(int, InstructionContext)`.
    fn get_scalar(&self, op_index: i32, context: &dyn InstructionContext) -> Option<Scalar> {
        if !self.op_index_in_range(op_index) {
            return None;
        }
        let hand = self
            .with_parser_context(context, |pc| self.operand_handle(pc, op_index as usize))
            .ok()?;
        let space = hand.space.as_ref()?;
        if space.space_type() == AddressSpaceType::Constant {
            let mut size = hand.size;
            if size == 0 {
                size = hand.offset_size;
                if size == 0 {
                    size = self.inner.language.get_default_space().pointer_size();
                }
            }
            return Some(scalar(size, hand.offset_offset));
        }
        None
    }

    /// Port of `getOpObjects(int, InstructionContext)`.
    fn get_op_objects(&self, op_index: i32, context: &dyn InstructionContext) -> Vec<OperandValue> {
        if !self.op_index_in_range(op_index) {
            return Vec::new();
        }
        self.get_op_representation_list(op_index, context)
            .unwrap_or_default()
            .into_iter()
            .filter(|o| !matches!(o, OperandValue::Character(_)))
            .collect()
    }

    /// Port of `getOperandRefType(int, InstructionContext, PcodeOverride)`.
    fn get_operand_ref_type(
        &self,
        op_index: i32,
        context: &dyn InstructionContext,
        pcode_override: Option<&dyn PcodeOverride>,
    ) -> RefType {
        if !self.op_index_in_range(op_index) {
            // Java returns null
            return RefType::Data;
        }
        let has_override = pcode_override.is_some_and(|o| {
            o.get_flow_override() != FlowOverride::None || o.get_fall_through_override().is_some()
        });
        if !has_override {
            // try to use cached value
            if let Some(r) = self.inner.op_ref_types.lock().expect("poisoned")[op_index as usize] {
                return r;
            }
            self.cache_default_operand_ref_types(context);
            return self.inner.op_ref_types.lock().expect("poisoned")[op_index as usize]
                .unwrap_or(RefType::Data);
        }
        // Override exists - unable to use cached value
        let Ok(op_handle) =
            self.with_parser_context(context, |pc| self.operand_handle(pc, op_index as usize))
        else {
            return RefType::Data;
        };
        let pcode = self.get_pcode(context, pcode_override);
        if pcode.is_empty() || op_handle.is_invalid() {
            return RefType::Data;
        }
        Self::operand_ref_type(&op_handle, &pcode)
    }

    /// Port of `hasDelimeter(int)`.
    fn has_delimeter(&self, op_index: i32) -> bool {
        op_index < self.inner.opresolve.len() as i32 - 1
    }

    /// Port of `getInputObjects(InstructionContext)`.
    fn get_input_objects(&self, context: &dyn InstructionContext) -> Vec<OperandValue> {
        let Ok(pcode) = self.build_pcode(context, None) else {
            return Vec::new();
        };
        let mut inlist = Vec::new();
        let mut outlist = Vec::new();
        for element in &pcode {
            self.gather_input_objects(element, &mut inlist, &outlist);
            self.gather_result_object(element, &mut outlist);
        }
        inlist
    }

    /// Port of `getResultObjects(InstructionContext)`.
    fn get_result_objects(&self, context: &dyn InstructionContext) -> Vec<OperandValue> {
        let Ok(pcode) = self.build_pcode(context, None) else {
            return Vec::new();
        };
        let mut results = Vec::new();
        for element in &pcode {
            self.gather_result_object(element, &mut results);
        }
        results
    }

    /// Port of `getPcode(InstructionContext, PcodeOverride)`: a single `UNIMPLEMENTED` op if
    /// the semantics cannot be built.
    fn get_pcode(
        &self,
        context: &dyn InstructionContext,
        pcode_override: Option<&dyn PcodeOverride>,
    ) -> Vec<PcodeOp> {
        match self.build_pcode(context, pcode_override) {
            Ok(ops) => ops,
            Err(_) => Self::unimplemented_pcode(context),
        }
    }

    /// Port of `getPcodePacked(PatchEncoder, InstructionContext, PcodeOverride)`: encodes the
    /// instruction's p-code as an `<inst>` element, or -- when the semantics cannot be built --
    /// an `<unimpl>` element carrying the instruction length (after logging the failure, unless
    /// the constructor simply has no semantics).
    fn get_pcode_packed(
        &self,
        encoder: &mut dyn PatchEncoder,
        context: &dyn InstructionContext,
        pcode_override: Option<&dyn PcodeOverride>,
    ) -> std::io::Result<()> {
        match self.build_pcode_packed(encoder, context, pcode_override) {
            Ok(()) => return Ok(()),
            Err(PcodeEmitBuildError::NotYetImplemented(_)) => {} // unimpl
            Err(e) => Msg::error(
                "SleighInstructionPrototype",
                &format!("Pcode error at {}: {e}", context.get_address()),
            ),
        }
        encoder.clear();
        encoder.open_element(ELEM_UNIMPL)?;
        encoder.write_signed_integer(ATTRIB_OFFSET, self.get_length() as i64)?;
        encoder.close_element(ELEM_UNIMPL)
    }

    /// Port of `getPcode(InstructionContext, int)`: the p-code computing a subtable operand's
    /// value.
    fn get_pcode_for_operand(&self, context: &dyn InstructionContext, op_index: i32) -> Vec<PcodeOp> {
        if !self.op_index_in_range(op_index) {
            return Vec::new();
        }
        let sleigh_op = self.inner.opresolve[op_index as usize] as usize;
        let table = self.inner.language.get_symbol_table();
        let is_subtable = self
            .inner
            .tree
            .get(self.inner.mnemonic_state)
            .ct
            .as_ref()
            .and_then(|ct| ct.get_operand(table, sleigh_op))
            .and_then(|sym| sym.get_defining_symbol(table))
            .is_some_and(|s| matches!(s, SleighSymbol::Subtable(_)));
        if !is_subtable {
            return Vec::new();
        }
        let res = self.with_parser_context(context, |pc| -> Result<Vec<PcodeOp>, PcodeEmitBuildError> {
            let mut walker = ParserWalker::new(pc);
            walker.sub_tree_state(self.inner.mnemonic_state);
            walker.push_operand(sleigh_op);
            let mut emit = PcodeEmitObjects::for_walker(walker);
            emit.build_current()?;
            emit.resolve_relatives()?;
            if !self.inner.isindelayslot {
                emit.resolve_final_fallthrough()?;
            }
            Ok(emit.into_pcode_ops())
        });
        match res {
            Ok(Ok(ops)) => ops,
            _ => Vec::new(),
        }
    }

    fn get_language(&self) -> Arc<dyn Language> {
        self.inner.language.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::lang::sleigh::template::const_tpl::{ConstTpl, ConstTplType as CTT};
    use crate::program::model::lang::sleigh::template::VarnodeTpl;

    fn real_varnode(offset: u64) -> VarnodeTpl {
        VarnodeTpl {
            space: ConstTpl::new(),
            offset: ConstTpl {
                tp: CTT::Real,
                value_real: offset,
                value_spaceid: None,
                handle_index: 0,
                select: None,
            },
            size: ConstTpl::new(),
        }
    }

    #[test]
    fn walk_templates_collects_crossbuild_delay_and_call_flow_records() {
        let mut ptrsub_op = OpTpl::with_opcode(OpCode::CpuiPtrsub);
        ptrsub_op.add_input(real_varnode(0));
        let mut indirect_op = OpTpl::with_opcode(OpCode::CpuiIndirect);
        indirect_op.add_input(real_varnode(2)); // delay slot byte count
        let mut call_op = OpTpl::with_opcode(OpCode::CpuiCall);
        call_op.add_input(real_varnode(0));

        let mut ct = crate::program::model::lang::sleigh::constructor::Constructor::new();
        let mut tpl = crate::program::model::lang::sleigh::template::ConstructTpl::new();
        tpl.vec = vec![ptrsub_op, indirect_op, call_op];
        ct.templ = Some(tpl);
        let mut tree = ConstructTree::new();
        tree.get_mut(ConstructTree::ROOT).ct = Some(Arc::new(ct));
        let table = SymbolTable::new();

        let mut walker = OpTplWalker::new(&tree, ConstructTree::ROOT, -1);
        let summary = walk_templates(&mut walker, Some(&tree), &table);

        assert!(summary.has_cross_builds);
        assert!(!summary.has_next2);
        assert_eq!(summary.delay, 2);
        assert_eq!(summary.lastop.unwrap().get_opcode(), OpCode::CpuiCall);

        let records = summary.flow_state.expect("expected flow records");
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].flow_flags, CROSSBUILD);
        assert_eq!(records[0].addressnode, Some(ConstructTree::ROOT));
        // a CALL through a constant (not a handle) has no destination node
        assert_eq!(records[1].flow_flags, CALL);
        assert!(records[1].addressnode.is_none());
    }

    #[test]
    fn flow_list_to_flow_type_maps_known_flag_combinations() {
        let rec = |flags: i32| FlowRecord {
            addressnode: None,
            op: OpTpl::with_opcode(OpCode::CpuiCall),
            flow_flags: flags,
        };

        assert_eq!(flow_list_to_flow_type(None), RefType::FallThrough);
        assert_eq!(flow_list_to_flow_type(Some(&[rec(CALL)])), RefType::UnconditionalCall);
        assert_eq!(
            flow_list_to_flow_type(Some(&[rec(JUMPOUT | NO_FALLTHRU)])),
            RefType::UnconditionalJump
        );
        assert_eq!(
            flow_list_to_flow_type(Some(&[rec(RETURN | NO_FALLTHRU)])),
            RefType::Terminator
        );
        // LABEL alone folds into BRANCH_TO_END once CROSSBUILD/LABEL bits are stripped.
        assert_eq!(flow_list_to_flow_type(Some(&[rec(LABEL)])), RefType::FallThrough);
        // a conditional branch past a return: NO_FALLTHRU of the earlier record is cleared
        assert_eq!(
            flow_list_to_flow_type(Some(&[rec(RETURN | NO_FALLTHRU), rec(BRANCH_TO_END)])),
            RefType::ConditionalTerminator
        );
    }

    #[test]
    fn convert_flow_flags_covers_the_java_table() {
        assert_eq!(convert_flow_flags(CALL | NO_FALLTHRU | RETURN), RefType::CallTerminator);
        assert_eq!(convert_flow_flags(CALL_INDIRECT), RefType::ComputedCall);
        assert_eq!(convert_flow_flags(BRANCH_INDIRECT | NO_FALLTHRU), RefType::ComputedJump);
        assert_eq!(convert_flow_flags(JUMPOUT), RefType::ConditionalJump);
        assert_eq!(convert_flow_flags(NO_FALLTHRU), RefType::Terminator);
        assert_eq!(convert_flow_flags(CALL | CROSSBUILD), RefType::UnconditionalCall);
        assert_eq!(convert_flow_flags(RETURN), RefType::Invalid);
    }
}

/// End-to-end tests: a small sleigh language, encoded with the real `PackedEncode` the way the
/// sleigh compiler writes a `.sla` file, is decoded and used to parse and inspect instructions.
///
/// The language has 2-byte instructions; byte 0's high nibble is the opcode and its low nibble a
/// register index (`r0`/`r1`, attached through a varnode list), byte 1 an immediate:
///
/// ```text
/// mov reg, imm8     is op=1 & reg ; imm8          { reg = imm8; }            (line 10)
/// jmp rel           is op=2 ; rel                 { build rel; goto rel; }   (line 20)
/// ret               is op=3                       { return [r1]; }           (line 30)
/// jd rel            is op=4 ; rel                 { build rel; delayslot(2); goto rel; } (line 50)
/// ld reg, mem       is op=5 & reg ; mem           { build mem; reg = mem; } (line 60)
/// mem: [reg2]       is reg2                       { export *[ram]:4 reg2; }   (line 70)
/// add reg, reg2     is op=6 & reg ; reg2          { reg = reg + reg2; }      (line 80)
/// bz reg, rel       is op=7 & reg ; rel           { build rel; if (reg == 0) goto rel; } (line 90)
/// rel: reloc        is simm8 [ reloc = inst_start + 2 + simm8; ] { export *[ram]:4 reloc; } (line 40)
/// ```
#[cfg(test)]
pub(crate) mod decode_tests {
    use super::*;
    use crate::program::model::address::DefaultAddressFactory;
    use crate::program::model::lang::instruction_context::InstructionContextError;
    use crate::program::model::lang::language::ParseError;
    use crate::program::model::lang::parser_context::ParserContext as LangParserContext;
    use crate::program::model::lang::processor_context_impl::ProcessorContextImpl;
    use crate::program::model::lang::sleigh::template::{
        ConstTpl, ConstTplSelect, ConstructTpl, HandleTpl, VarnodeTpl,
    };
    use crate::program::model::lang::unknown_context_exception::UnknownContextException;
    use crate::program::model::mem::ByteMemBufferImpl;
    use crate::program::model::pcode::encoder::Encoder;
    use crate::program::model::pcode::ids::*;
    use crate::program::model::pcode::{ElementId, OpCode as P, PackedDecode, PackedEncode};

    type Enc = PackedEncode<Vec<u8>>;

    const CONSTANT: i32 = 0;
    const RAM: i32 = 1;
    const REGISTER: i32 = 2;
    const UNIQUE: i32 = 3;

    // Symbol ids
    const INSTRUCTION: u64 = 0;
    const R0: u64 = 1;
    const R1: u64 = 2;
    const REG: u64 = 3;
    const IMM8: u64 = 4;
    const REL: u64 = 5;
    const REG_OP: u64 = 6;
    const IMM_OP: u64 = 7;
    const REL_OP: u64 = 8;
    const RELOC_OP: u64 = 9;
    const DREL_OP: u64 = 10;
    const REG2: u64 = 11;
    const MEM: u64 = 12;
    const LD_REG_OP: u64 = 13;
    const LD_MEM_OP: u64 = 14;
    const REG2_OP: u64 = 15;
    const ADD_DST_OP: u64 = 16;
    const ADD_SRC_OP: u64 = 17;
    const BZ_REG_OP: u64 = 18;
    const BZ_REL_OP: u64 = 19;

    fn encoding_space(name: &str, ty: AddressSpaceType, index: i32) -> Arc<AddressSpace> {
        AddressSpace::new(name, if ty == AddressSpaceType::Constant { 64 } else { 32 }, 1, ty, index)
    }

    fn space(e: &mut Enc, elem: ElementId, name: &str, index: i64, size: i64, delay: i64) {
        e.open_element(elem).unwrap();
        e.write_string(ATTRIB_NAME, name).unwrap();
        e.write_signed_integer(ATTRIB_INDEX, index).unwrap();
        e.write_signed_integer(ATTRIB_SIZE, size).unwrap();
        e.write_signed_integer(ATTRIB_DELAY, delay).unwrap();
        e.close_element(elem).unwrap();
    }

    fn head(e: &mut Enc, elem: ElementId, name: &str, id: u64) {
        e.open_element(elem).unwrap();
        e.write_string(ATTRIB_NAME, name).unwrap();
        e.write_unsigned_integer(ATTRIB_ID, id).unwrap();
        e.write_unsigned_integer(ATTRIB_SCOPE, 0).unwrap();
        e.close_element(elem).unwrap();
    }

    fn varnode(e: &mut Enc, id: u64, space: i32, offset: u64, size: i64) {
        e.open_element(ELEM_VARNODE_SYM).unwrap();
        e.write_unsigned_integer(ATTRIB_ID, id).unwrap();
        e.write_space_indexed(ATTRIB_SPACE, space, "").unwrap();
        e.write_unsigned_integer(ATTRIB_OFF, offset).unwrap();
        e.write_signed_integer(ATTRIB_SIZE, size).unwrap();
        e.close_element(ELEM_VARNODE_SYM).unwrap();
    }

    /// A one-byte token field of instruction byte `byte`, bits `start..=end` (bit 0 = lsb).
    fn token_field(e: &mut Enc, signed: bool, start: i64, end: i64, byte: i64) {
        e.open_element(ELEM_TOKENFIELD).unwrap();
        e.write_bool(ATTRIB_BIGENDIAN, true).unwrap();
        e.write_bool(ATTRIB_SIGNBIT, signed).unwrap();
        e.write_signed_integer(ATTRIB_STARTBIT, start).unwrap();
        e.write_signed_integer(ATTRIB_ENDBIT, end).unwrap();
        e.write_signed_integer(ATTRIB_STARTBYTE, byte).unwrap();
        e.write_signed_integer(ATTRIB_ENDBYTE, byte).unwrap();
        e.write_signed_integer(ATTRIB_SHIFT, start).unwrap();
        e.close_element(ELEM_TOKENFIELD).unwrap();
    }

    fn operand_sym(
        e: &mut Enc,
        id: u64,
        index: i64,
        subsym: Option<u64>,
        code: bool,
        table: u64,
        defexp: Option<&dyn Fn(&mut Enc)>,
    ) {
        e.open_element(ELEM_OPERAND_SYM).unwrap();
        e.write_unsigned_integer(ATTRIB_ID, id).unwrap();
        if let Some(sub) = subsym {
            e.write_unsigned_integer(ATTRIB_SUBSYM, sub).unwrap();
        }
        e.write_signed_integer(ATTRIB_OFF, 0).unwrap();
        e.write_signed_integer(ATTRIB_BASE, -1).unwrap();
        e.write_signed_integer(ATTRIB_MINLEN, 0).unwrap();
        if code {
            e.write_bool(ATTRIB_CODE, true).unwrap();
        }
        e.write_signed_integer(ATTRIB_INDEX, index).unwrap();
        // localexp: the operand's own value
        e.open_element(ELEM_OPERAND_EXP).unwrap();
        e.write_signed_integer(ATTRIB_INDEX, index).unwrap();
        e.write_unsigned_integer(ATTRIB_TABLE, table).unwrap();
        e.write_unsigned_integer(ATTRIB_CT, 0).unwrap();
        e.close_element(ELEM_OPERAND_EXP).unwrap();
        if let Some(defexp) = defexp {
            defexp(e);
        }
        e.close_element(ELEM_OPERAND_SYM).unwrap();
    }

    enum Piece {
        Text(&'static str),
        Op(i64),
    }

    #[allow(clippy::too_many_arguments)]
    fn constructor(
        e: &mut Enc,
        parent: u64,
        first: i64,
        length: i64,
        line: i64,
        opers: &[u64],
        pieces: &[Piece],
        templ: &ConstructTpl,
    ) {
        e.open_element(ELEM_CONSTRUCTOR).unwrap();
        e.write_unsigned_integer(ATTRIB_PARENT, parent).unwrap();
        e.write_signed_integer(ATTRIB_FIRST, first).unwrap();
        e.write_signed_integer(ATTRIB_LENGTH, length).unwrap();
        e.write_signed_integer(ATTRIB_SOURCE, 0).unwrap();
        e.write_signed_integer(ATTRIB_LINE, line).unwrap();
        for &op in opers {
            e.open_element(ELEM_OPER).unwrap();
            e.write_unsigned_integer(ATTRIB_ID, op).unwrap();
            e.close_element(ELEM_OPER).unwrap();
        }
        for piece in pieces {
            match piece {
                Piece::Text(t) => {
                    e.open_element(ELEM_PRINT).unwrap();
                    e.write_string(ATTRIB_PIECE, t).unwrap();
                    e.close_element(ELEM_PRINT).unwrap();
                }
                Piece::Op(i) => {
                    e.open_element(ELEM_OPPRINT).unwrap();
                    e.write_signed_integer(ATTRIB_ID, *i).unwrap();
                    e.close_element(ELEM_OPPRINT).unwrap();
                }
            }
        }
        templ.encode(e, -1).unwrap();
        e.close_element(ELEM_CONSTRUCTOR).unwrap();
    }

    /// A terminal decision node with one pair per `(constructor, mask, value)` over the first
    /// instruction word (a zero mask matches everything).
    fn decision(e: &mut Enc, pairs: &[(u64, u64, u64)]) {
        e.open_element(ELEM_DECISION).unwrap();
        e.write_bool(ATTRIB_CONTEXT, false).unwrap();
        e.write_signed_integer(ATTRIB_STARTBIT, 0).unwrap();
        e.write_signed_integer(ATTRIB_SIZE, 0).unwrap();
        for &(ct, mask, val) in pairs {
            e.open_element(ELEM_PAIR).unwrap();
            e.write_unsigned_integer(ATTRIB_ID, ct).unwrap();
            e.open_element(ELEM_INSTRUCT_PAT).unwrap();
            e.open_element(ELEM_PAT_BLOCK).unwrap();
            e.write_signed_integer(ATTRIB_OFF, 0).unwrap();
            e.write_signed_integer(ATTRIB_NONZERO, if mask == 0 { 0 } else { 1 }).unwrap();
            if mask != 0 {
                e.open_element(ELEM_MASK_WORD).unwrap();
                e.write_unsigned_integer(ATTRIB_MASK, mask).unwrap();
                e.write_unsigned_integer(ATTRIB_VAL, val).unwrap();
                e.close_element(ELEM_MASK_WORD).unwrap();
            }
            e.close_element(ELEM_PAT_BLOCK).unwrap();
            e.close_element(ELEM_INSTRUCT_PAT).unwrap();
            e.close_element(ELEM_PAIR).unwrap();
        }
        e.close_element(ELEM_DECISION).unwrap();
    }

    fn real(v: u64) -> ConstTpl {
        ConstTpl {
            tp: ConstTplType::Real,
            value_real: v,
            value_spaceid: None,
            handle_index: 0,
            select: None,
        }
    }

    fn handle(hand: i16, select: ConstTplSelect) -> ConstTpl {
        ConstTpl {
            tp: ConstTplType::Handle,
            value_real: 0,
            value_spaceid: None,
            handle_index: hand,
            select: Some(select),
        }
    }

    fn space_id(space: Arc<AddressSpace>) -> ConstTpl {
        ConstTpl {
            tp: ConstTplType::SpaceId,
            value_real: 0,
            value_spaceid: Some(space),
            handle_index: 0,
            select: None,
        }
    }

    fn op(opc: OpCode, out: Option<VarnodeTpl>, inputs: Vec<VarnodeTpl>) -> OpTpl {
        let mut op = OpTpl::with_opcode(opc);
        if let Some(out) = out {
            op.set_output(out);
        }
        for i in inputs {
            op.add_input(i);
        }
        op
    }

    fn templ(result: Option<HandleTpl>, ops: Vec<OpTpl>) -> ConstructTpl {
        let mut t = ConstructTpl::new();
        t.result = result;
        t.vec = ops;
        t
    }

    fn sla() -> Vec<u8> {
        let ram = encoding_space("ram", AddressSpaceType::Ram, RAM);
        let register = encoding_space("register", AddressSpaceType::Register, REGISTER);
        let constant = encoding_space("constant", AddressSpaceType::Constant, CONSTANT);

        let mut e = PackedEncode::new(Vec::<u8>::new());
        e.open_element(ELEM_SLEIGH).unwrap();
        e.write_signed_integer(ATTRIB_VERSION, 4).unwrap();
        e.write_bool(ATTRIB_BIGENDIAN, true).unwrap();
        e.write_signed_integer(ATTRIB_ALIGN, 1).unwrap();
        e.write_unsigned_integer(ATTRIB_UNIQBASE, 0x1000).unwrap();
        e.write_unsigned_integer(ATTRIB_UNIQMASK, 0xff).unwrap();
        e.write_unsigned_integer(ATTRIB_NUMSECTIONS, 0).unwrap();

        e.open_element(ELEM_SPACES).unwrap();
        e.write_string(ATTRIB_DEFAULTSPACE, "ram").unwrap();
        e.open_element(ELEM_SPACE_OTHER).unwrap();
        e.close_element(ELEM_SPACE_OTHER).unwrap();
        space(&mut e, ELEM_SPACE, "ram", RAM as i64, 4, 1);
        space(&mut e, ELEM_SPACE, "register", REGISTER as i64, 4, 0);
        space(&mut e, ELEM_SPACE_UNIQUE, "unique", UNIQUE as i64, 4, 0);
        e.close_element(ELEM_SPACES).unwrap();

        e.open_element(ELEM_SYMBOL_TABLE).unwrap();
        e.write_signed_integer(ATTRIB_SCOPESIZE, 1).unwrap();
        e.write_signed_integer(ATTRIB_SYMBOLSIZE, 20).unwrap();
        e.open_element(ELEM_SCOPE).unwrap();
        e.write_unsigned_integer(ATTRIB_ID, 0).unwrap();
        e.write_unsigned_integer(ATTRIB_PARENT, 0).unwrap();
        e.close_element(ELEM_SCOPE).unwrap();

        head(&mut e, ELEM_SUBTABLE_SYM_HEAD, "instruction", INSTRUCTION);
        head(&mut e, ELEM_VARNODE_SYM_HEAD, "r0", R0);
        head(&mut e, ELEM_VARNODE_SYM_HEAD, "r1", R1);
        head(&mut e, ELEM_VARLIST_SYM_HEAD, "reg", REG);
        head(&mut e, ELEM_VALUE_SYM_HEAD, "imm8", IMM8);
        head(&mut e, ELEM_SUBTABLE_SYM_HEAD, "rel", REL);
        // (a real .sla puts operands in their constructor's own scope; distinct names keep this
        // fixture to one scope)
        head(&mut e, ELEM_OPERAND_SYM_HEAD, "dst", REG_OP);
        head(&mut e, ELEM_OPERAND_SYM_HEAD, "src", IMM_OP);
        head(&mut e, ELEM_OPERAND_SYM_HEAD, "target", REL_OP);
        head(&mut e, ELEM_OPERAND_SYM_HEAD, "reloc", RELOC_OP);
        head(&mut e, ELEM_OPERAND_SYM_HEAD, "dtarget", DREL_OP);
        head(&mut e, ELEM_VARLIST_SYM_HEAD, "reg2", REG2);
        head(&mut e, ELEM_SUBTABLE_SYM_HEAD, "mem", MEM);
        head(&mut e, ELEM_OPERAND_SYM_HEAD, "ldst", LD_REG_OP);
        head(&mut e, ELEM_OPERAND_SYM_HEAD, "ldsrc", LD_MEM_OP);
        head(&mut e, ELEM_OPERAND_SYM_HEAD, "base", REG2_OP);
        head(&mut e, ELEM_OPERAND_SYM_HEAD, "adst", ADD_DST_OP);
        head(&mut e, ELEM_OPERAND_SYM_HEAD, "asrc", ADD_SRC_OP);
        head(&mut e, ELEM_OPERAND_SYM_HEAD, "breg", BZ_REG_OP);
        head(&mut e, ELEM_OPERAND_SYM_HEAD, "btarget", BZ_REL_OP);

        varnode(&mut e, R0, REGISTER, 0, 4);
        varnode(&mut e, R1, REGISTER, 4, 4);

        // reg: attach variables [ r0 r1 ] to the low nibble of byte 0
        e.open_element(ELEM_VARLIST_SYM).unwrap();
        e.write_unsigned_integer(ATTRIB_ID, REG).unwrap();
        token_field(&mut e, false, 0, 3, 0);
        for id in [R0, R1] {
            e.open_element(ELEM_VAR).unwrap();
            e.write_unsigned_integer(ATTRIB_ID, id).unwrap();
            e.close_element(ELEM_VAR).unwrap();
        }
        e.close_element(ELEM_VARLIST_SYM).unwrap();

        // reg2: attach variables [ r0 r1 ] to the low nibble of byte 1
        e.open_element(ELEM_VARLIST_SYM).unwrap();
        e.write_unsigned_integer(ATTRIB_ID, REG2).unwrap();
        token_field(&mut e, false, 0, 3, 1);
        for id in [R0, R1] {
            e.open_element(ELEM_VAR).unwrap();
            e.write_unsigned_integer(ATTRIB_ID, id).unwrap();
            e.close_element(ELEM_VAR).unwrap();
        }
        e.close_element(ELEM_VARLIST_SYM).unwrap();

        // imm8: byte 1
        e.open_element(ELEM_VALUE_SYM).unwrap();
        e.write_unsigned_integer(ATTRIB_ID, IMM8).unwrap();
        token_field(&mut e, false, 0, 7, 1);
        e.close_element(ELEM_VALUE_SYM).unwrap();

        operand_sym(&mut e, REG_OP, 0, Some(REG), false, INSTRUCTION, None);
        operand_sym(&mut e, IMM_OP, 1, Some(IMM8), false, INSTRUCTION, None);
        operand_sym(&mut e, REL_OP, 0, Some(REL), true, INSTRUCTION, None);
        operand_sym(&mut e, DREL_OP, 0, Some(REL), true, INSTRUCTION, None);
        operand_sym(&mut e, LD_REG_OP, 0, Some(REG), false, INSTRUCTION, None);
        operand_sym(&mut e, LD_MEM_OP, 1, Some(MEM), false, INSTRUCTION, None);
        operand_sym(&mut e, REG2_OP, 0, Some(REG2), false, MEM, None);
        operand_sym(&mut e, ADD_DST_OP, 0, Some(REG), false, INSTRUCTION, None);
        operand_sym(&mut e, ADD_SRC_OP, 1, Some(REG2), false, INSTRUCTION, None);
        operand_sym(&mut e, BZ_REG_OP, 0, Some(REG), false, INSTRUCTION, None);
        operand_sym(&mut e, BZ_REL_OP, 1, Some(REL), true, INSTRUCTION, None);
        // reloc = inst_start + 2 + simm8
        let reloc_exp = |e: &mut Enc| {
            e.open_element(ELEM_PLUS_EXP).unwrap();
            e.open_element(ELEM_PLUS_EXP).unwrap();
            e.open_element(ELEM_START_EXP).unwrap();
            e.close_element(ELEM_START_EXP).unwrap();
            e.open_element(ELEM_INTB).unwrap();
            e.write_signed_integer(ATTRIB_VAL, 2).unwrap();
            e.close_element(ELEM_INTB).unwrap();
            e.close_element(ELEM_PLUS_EXP).unwrap();
            token_field(e, true, 0, 7, 1);
            e.close_element(ELEM_PLUS_EXP).unwrap();
        };
        operand_sym(&mut e, RELOC_OP, 0, None, false, REL, Some(&reloc_exp));

        // instruction table
        e.open_element(ELEM_SUBTABLE_SYM).unwrap();
        e.write_unsigned_integer(ATTRIB_ID, INSTRUCTION).unwrap();
        e.write_signed_integer(ATTRIB_NUMCT, 7).unwrap();
        // mov reg, imm8 { reg = imm8; }
        let mov = templ(
            None,
            vec![op(
                OpCode::CpuiCopy,
                Some(VarnodeTpl::with_handle(0, false)),
                vec![VarnodeTpl::with_fields(
                    handle(1, ConstTplSelect::VSpace),
                    handle(1, ConstTplSelect::VOffset),
                    real(4),
                )],
            )],
        );
        constructor(
            &mut e,
            INSTRUCTION,
            1,
            2,
            10,
            &[REG_OP, IMM_OP],
            &[Piece::Text("mov"), Piece::Text(" "), Piece::Op(0), Piece::Text(", "), Piece::Op(1)],
            &mov,
        );
        // jmp rel { build rel; goto rel; }
        let jmp = templ(
            None,
            vec![
                op(OpCode::CpuiMultiequal, None, vec![VarnodeTpl::with_fields(real(0), real(0), real(0))]),
                op(OpCode::CpuiBranch, None, vec![VarnodeTpl::with_handle(0, false)]),
            ],
        );
        constructor(
            &mut e,
            INSTRUCTION,
            1,
            2,
            20,
            &[REL_OP],
            &[Piece::Text("jmp"), Piece::Text(" "), Piece::Op(0)],
            &jmp,
        );
        // ret { return [r1]; }
        let ret = templ(
            None,
            vec![op(
                OpCode::CpuiReturn,
                None,
                vec![VarnodeTpl::with_fields(space_id(register.clone()), real(4), real(4))],
            )],
        );
        constructor(&mut e, INSTRUCTION, -1, 2, 30, &[], &[Piece::Text("ret")], &ret);
        // jd rel { build rel; delayslot(2); goto rel; }
        let jd = templ(
            None,
            vec![
                op(OpCode::CpuiMultiequal, None, vec![VarnodeTpl::with_fields(real(0), real(0), real(0))]),
                op(OpCode::CpuiIndirect, None, vec![VarnodeTpl::with_fields(real(0), real(2), real(0))]),
                op(OpCode::CpuiBranch, None, vec![VarnodeTpl::with_handle(0, false)]),
            ],
        );
        constructor(
            &mut e,
            INSTRUCTION,
            1,
            2,
            50,
            &[DREL_OP],
            &[Piece::Text("jd"), Piece::Text(" "), Piece::Op(0)],
            &jd,
        );
        // ld reg, mem { build mem; reg = mem; }
        let ld = templ(
            None,
            vec![
                op(OpCode::CpuiMultiequal, None, vec![VarnodeTpl::with_fields(real(0), real(1), real(0))]),
                op(
                    OpCode::CpuiCopy,
                    Some(VarnodeTpl::with_handle(0, false)),
                    vec![VarnodeTpl::with_handle(1, false)],
                ),
            ],
        );
        constructor(
            &mut e,
            INSTRUCTION,
            1,
            2,
            60,
            &[LD_REG_OP, LD_MEM_OP],
            &[Piece::Text("ld"), Piece::Text(" "), Piece::Op(0), Piece::Text(","), Piece::Op(1)],
            &ld,
        );
        // add reg, reg2 { reg = reg + reg2; }
        let add = templ(
            None,
            vec![op(
                OpCode::CpuiIntAdd,
                Some(VarnodeTpl::with_handle(0, false)),
                vec![VarnodeTpl::with_handle(0, false), VarnodeTpl::with_handle(1, false)],
            )],
        );
        constructor(
            &mut e,
            INSTRUCTION,
            1,
            2,
            80,
            &[ADD_DST_OP, ADD_SRC_OP],
            &[Piece::Text("add"), Piece::Text(" "), Piece::Op(0), Piece::Text(","), Piece::Op(1)],
            &add,
        );
        // bz reg, rel { build rel; if (reg == 0) goto rel; }
        let zero = encoding_space("unique", AddressSpaceType::Unique, UNIQUE);
        let is_zero = || VarnodeTpl::with_fields(space_id(zero.clone()), real(0x20), real(1));
        let bz = templ(
            None,
            vec![
                op(OpCode::CpuiMultiequal, None, vec![VarnodeTpl::with_fields(real(0), real(1), real(0))]),
                op(
                    OpCode::CpuiIntEqual,
                    Some(is_zero()),
                    vec![
                        VarnodeTpl::with_handle(0, false),
                        VarnodeTpl::with_fields(space_id(constant.clone()), real(0), real(4)),
                    ],
                ),
                op(OpCode::CpuiCbranch, None, vec![VarnodeTpl::with_handle(1, false), is_zero()]),
            ],
        );
        constructor(
            &mut e,
            INSTRUCTION,
            1,
            2,
            90,
            &[BZ_REG_OP, BZ_REL_OP],
            &[Piece::Text("bz"), Piece::Text(" "), Piece::Op(0), Piece::Text(","), Piece::Op(1)],
            &bz,
        );
        decision(
            &mut e,
            &[
                (0, 0xf000_0000, 0x1000_0000),
                (1, 0xf000_0000, 0x2000_0000),
                (2, 0xf000_0000, 0x3000_0000),
                (3, 0xf000_0000, 0x4000_0000),
                (4, 0xf000_0000, 0x5000_0000),
                (5, 0xf000_0000, 0x6000_0000),
                (6, 0xf000_0000, 0x7000_0000),
            ],
        );
        e.close_element(ELEM_SUBTABLE_SYM).unwrap();

        // rel table: export *[ram]:4 reloc
        e.open_element(ELEM_SUBTABLE_SYM).unwrap();
        e.write_unsigned_integer(ATTRIB_ID, REL).unwrap();
        e.write_signed_integer(ATTRIB_NUMCT, 1).unwrap();
        let export = HandleTpl {
            space: space_id(ram),
            size: real(4),
            ptrspace: space_id(constant),
            ptroffset: handle(0, ConstTplSelect::VOffset),
            ptrsize: real(0),
            temp_space: real(0),
            temp_offset: real(0),
        };
        constructor(&mut e, REL, -1, 2, 40, &[RELOC_OP], &[Piece::Op(0)], &templ(Some(export), vec![]));
        decision(&mut e, &[(0, 0, 0)]);
        e.close_element(ELEM_SUBTABLE_SYM).unwrap();

        // mem table: export *[ram]:4 reg2 (a dynamic handle through a unique temporary)
        e.open_element(ELEM_SUBTABLE_SYM).unwrap();
        e.write_unsigned_integer(ATTRIB_ID, MEM).unwrap();
        e.write_signed_integer(ATTRIB_NUMCT, 1).unwrap();
        let unique = encoding_space("unique", AddressSpaceType::Unique, UNIQUE);
        let export = HandleTpl {
            space: space_id(encoding_space("ram", AddressSpaceType::Ram, RAM)),
            size: real(4),
            ptrspace: handle(0, ConstTplSelect::VSpace),
            ptroffset: handle(0, ConstTplSelect::VOffset),
            ptrsize: handle(0, ConstTplSelect::VSize),
            temp_space: space_id(unique),
            temp_offset: real(0x10),
        };
        constructor(
            &mut e,
            MEM,
            -1,
            2,
            70,
            &[REG2_OP],
            &[Piece::Text("["), Piece::Op(0), Piece::Text("]")],
            &templ(Some(export), vec![]),
        );
        decision(&mut e, &[(0, 0, 0)]);
        e.close_element(ELEM_SUBTABLE_SYM).unwrap();

        e.close_element(ELEM_SYMBOL_TABLE).unwrap();
        e.close_element(ELEM_SLEIGH).unwrap();
        e.into_inner()
    }

    /// The language described in this module's docs, shared (as `parse` requires). Also the
    /// fixture the emulator's tests step real instructions with.
    pub(crate) fn language() -> Arc<SleighLanguage> {
        let decoder = PackedDecode::new(Arc::new(DefaultAddressFactory::new(vec![])), sla());
        SleighLanguage::decode(&decoder, "toy:BE:32:default".to_string())
            .unwrap()
            .into_shared()
    }

    /// Mirrors `InstructionDB`'s bridge from the prototype's parser context to the one an
    /// instruction context hands out.
    struct Bridge(Box<dyn crate::program::seam_stubs::ParserContext>);

    impl LangParserContext for Bridge {
        fn get_prototype(&self) -> Arc<dyn InstructionPrototype> {
            self.0.get_prototype()
        }
        fn as_any(&self) -> Option<&dyn std::any::Any> {
            self.0.as_any()
        }
    }

    /// An instruction parsed at an address, as an instruction context; the instructions at the
    /// following addresses of the same bytes (delay slots) are parsed on request.
    struct Parsed {
        lang: Arc<SleighLanguage>,
        bytes: Vec<u8>,
        proto: Box<dyn InstructionPrototype>,
        mem: ByteMemBufferImpl,
        processor: ProcessorContextImpl,
    }

    impl InstructionContext for Parsed {
        fn get_address(&self) -> Address {
            self.mem.get_address()
        }
        fn get_processor_context(&self) -> &dyn ProcessorContextView {
            &self.processor
        }
        fn get_mem_buffer(&self) -> &dyn MemBuffer {
            &self.mem
        }
        fn get_parser_context(&self) -> Result<Box<dyn LangParserContext>, MemoryAccessException> {
            Ok(Box::new(Bridge(self.proto.get_parser_context(&self.mem, &self.processor)?)))
        }
        fn get_parser_context_at(
            &self,
            instruction_address: Address,
        ) -> Result<Box<dyn LangParserContext>, InstructionContextError> {
            let offset = instruction_address.subtract(&self.mem.get_address());
            let other = || UnknownContextException::with_message("no instruction there");
            if offset <= 0 || offset as usize >= self.bytes.len() {
                return Err(other().into());
            }
            let mem = ByteMemBufferImpl::new(
                instruction_address,
                self.bytes[offset as usize..].to_vec(),
                true,
            );
            let mut processor = ProcessorContextImpl::new(self.lang.clone());
            let proto = self
                .lang
                .parse(&mem, &mut processor, true)
                .map_err(|_| other())?;
            Ok(Box::new(Bridge(proto.get_parser_context(&mem, &processor)?)))
        }
    }

    fn parse(lang: &Arc<SleighLanguage>, offset: i64, bytes: &[u8]) -> Result<Parsed, ParseError> {
        let addr = Address::new(lang.get_default_space(), offset);
        let mem = ByteMemBufferImpl::new(addr, bytes.to_vec(), true);
        let mut processor = ProcessorContextImpl::new(lang.clone());
        let proto = lang.parse(&mem, &mut processor, false)?;
        Ok(Parsed {
            lang: lang.clone(),
            bytes: bytes.to_vec(),
            proto,
            mem,
            processor,
        })
    }

    fn register_name(reg: &RegisterRef) -> String {
        reg.name().to_string()
    }

    #[test]
    fn add_and_bz_decode_to_their_pcode() {
        let lang = language();
        // add r1, r0  ->  INT_ADD register:4:4 <- register:4:4, register:0:4
        let insn = parse(&lang, 0x1000, &[0x61, 0x00]).unwrap();
        assert_eq!(insn.proto.get_mnemonic(&insn), "add");
        let pcode = insn.proto.get_pcode(&insn, None);
        assert_eq!(pcode.len(), 1);
        assert_eq!(pcode[0].get_opcode(), P::IntAdd);
        let offsets = |vns: &[crate::program::model::pcode::Varnode]| {
            vns.iter().map(|v| (v.get_offset(), v.get_size())).collect::<Vec<_>>()
        };
        let out = pcode[0].get_output().unwrap();
        assert_eq!((out.get_offset(), out.get_size()), (4, 4));
        assert_eq!(offsets(pcode[0].get_inputs()), vec![(4, 4), (0, 4)]);

        // bz r0, +4  ->  INT_EQUAL unique <- r0, 0 ; CBRANCH *[ram]0x1006, unique
        let insn = parse(&lang, 0x1000, &[0x70, 0x04]).unwrap();
        assert_eq!(insn.proto.get_mnemonic(&insn), "bz");
        let pcode = insn.proto.get_pcode(&insn, None);
        assert_eq!(
            pcode.iter().map(|op| op.get_opcode()).collect::<Vec<_>>(),
            vec![P::IntEqual, P::CBranch]
        );
        assert_eq!(offsets(pcode[0].get_inputs()), vec![(0, 4), (0, 4)]);
        let target = &pcode[1].get_inputs()[0];
        assert_eq!((target.get_offset(), target.get_size()), (0x1006, 4));
        assert_eq!(pcode[1].get_inputs()[1], *pcode[0].get_output().unwrap());
        assert_eq!(insn.proto.get_flow_type(&insn), RefType::ConditionalJump);
    }

    #[test]
    fn mov_decodes_register_and_immediate_operands() {
        let lang = language();
        let insn = parse(&lang, 0x1000, &[0x11, 0x2a]).unwrap();
        let proto = &insn.proto;

        assert_eq!(proto.get_length(), 2);
        assert_eq!(proto.get_mnemonic(&insn), "mov");
        assert_eq!(proto.get_num_operands(), 2);
        assert_eq!(proto.get_op_type(0, &insn), OperandType::REGISTER as i32);
        assert_eq!(proto.get_op_type(1, &insn), OperandType::SCALAR as i32);
        assert_eq!(proto.get_op_type(2, &insn), OperandType::DYNAMIC as i32);
        assert_eq!(register_name(&proto.get_register(0, &insn).unwrap()), "r1");
        let imm = proto.get_scalar(1, &insn).unwrap();
        assert_eq!(imm.get_unsigned_value(), 0x2a);
        // a value symbol has no size, so the default space's pointer size (4) is used
        assert_eq!(imm.bit_length(), 32);
        assert!(proto.get_address(1, &insn).is_none());
        assert_eq!(proto.get_separator(0), None);
        assert_eq!(proto.get_separator(1).as_deref(), Some(","));
        assert!(proto.has_delimeter(0));
        assert!(!proto.has_delimeter(1));

        match proto.get_op_representation_list(0, &insn).unwrap().as_slice() {
            [OperandValue::Register(r)] => assert_eq!(register_name(r), "r1"),
            other => panic!("unexpected representation {other:?}"),
        }
        match proto.get_op_objects(1, &insn).as_slice() {
            [OperandValue::Scalar(s)] => assert_eq!(s.get_unsigned_value(), 0x2a),
            other => panic!("unexpected objects {other:?}"),
        }

        assert_eq!(proto.get_flow_type(&insn), RefType::FallThrough);
        assert!(proto.get_flows(&insn).is_none());
        assert_eq!(proto.get_fall_through(&insn).unwrap().offset(), 0x1002);
        assert!(!proto.has_delay_slots());

        // reg = imm8  ->  COPY register:4:4 <- const:0x2a:4
        let pcode = proto.get_pcode(&insn, None);
        assert_eq!(pcode.len(), 1);
        assert_eq!(pcode[0].get_opcode(), P::Copy);
        let out = pcode[0].get_output().unwrap();
        assert!(out.is_register());
        assert_eq!((out.get_offset(), out.get_size()), (4, 4));
        let input = &pcode[0].get_inputs()[0];
        assert!(input.is_constant());
        assert_eq!((input.get_offset(), input.get_size()), (0x2a, 4));
        assert_eq!(pcode[0].seqnum.get_target().offset(), 0x1000);

        match proto.get_result_objects(&insn).as_slice() {
            [OperandValue::Register(r)] => assert_eq!(register_name(r), "r1"),
            other => panic!("unexpected results {other:?}"),
        }
        match proto.get_input_objects(&insn).as_slice() {
            [OperandValue::Scalar(s)] => assert_eq!(s.get_unsigned_value(), 0x2a),
            other => panic!("unexpected inputs {other:?}"),
        }
        assert_eq!(proto.get_operand_ref_type(0, &insn, None), RefType::Write);
    }

    #[test]
    fn mov_selects_the_register_from_the_varnode_list() {
        let lang = language();
        let insn = parse(&lang, 0x1000, &[0x10, 0x01]).unwrap();
        assert_eq!(register_name(&insn.proto.get_register(0, &insn).unwrap()), "r0");
        // index 2 has no entry in the list: no such instruction
        match parse(&lang, 0x1000, &[0x12, 0x01]) {
            Err(ParseError::UnknownInstruction(e)) => {
                assert!(e.message().contains("Failed to resolve varnode <reg>, index=2"))
            }
            other => panic!("expected an unknown instruction, got {:?}", other.map(|_| ())),
        }
    }

    #[test]
    fn jmp_resolves_a_relative_target_through_a_subtable() {
        let lang = language();
        let insn = parse(&lang, 0x1000, &[0x20, 0x05]).unwrap();
        let proto = &insn.proto;

        assert_eq!(proto.get_length(), 2);
        assert_eq!(proto.get_mnemonic(&insn), "jmp");
        assert_eq!(proto.get_num_operands(), 1);
        assert_eq!(
            proto.get_op_type(0, &insn),
            (OperandType::ADDRESS | OperandType::CODE) as i32
        );
        let target = proto.get_address(0, &insn).unwrap();
        assert_eq!(target.offset(), 0x1007);
        assert_eq!(target.space().name(), "ram");

        assert_eq!(proto.get_flow_type(&insn), RefType::UnconditionalJump);
        let flows = proto.get_flows(&insn).unwrap();
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].offset(), 0x1007);
        assert!(proto.get_fall_through(&insn).is_none());
        // the fall-through offset is still the length
        assert_eq!(proto.get_fall_through_offset(&insn), 2);

        match proto.get_op_representation_list(0, &insn).unwrap().as_slice() {
            // the exported constant was "fixed" into a code address
            [OperandValue::Address(a)] => assert_eq!(a.offset(), 0x1007),
            other => panic!("unexpected representation {other:?}"),
        }

        // build rel; goto rel  ->  BRANCH ram:0x1007:4
        let pcode = proto.get_pcode(&insn, None);
        assert_eq!(pcode.len(), 1);
        assert_eq!(pcode[0].get_opcode(), P::Branch);
        let dest = &pcode[0].get_inputs()[0];
        assert!(dest.is_address());
        assert_eq!((dest.get_offset(), dest.get_size()), (0x1007, 4));
        assert_eq!(proto.get_operand_ref_type(0, &insn, None), RefType::UnconditionalJump);

        // the subtable operand's own p-code is empty (rel only exports)
        assert!(proto.get_pcode_for_operand(&insn, 0).is_empty());
    }

    #[test]
    fn jmp_with_a_negative_displacement_branches_backwards() {
        let lang = language();
        let insn = parse(&lang, 0x2000, &[0x20, 0xfc]).unwrap();
        assert_eq!(insn.proto.get_address(0, &insn).unwrap().offset(), 0x1ffe);
        assert_eq!(insn.proto.get_flows(&insn).unwrap()[0].offset(), 0x1ffe);
    }

    #[test]
    fn ret_is_a_terminator() {
        let lang = language();
        let insn = parse(&lang, 0x1000, &[0x31, 0x00]).unwrap();
        let proto = &insn.proto;
        assert_eq!(proto.get_mnemonic(&insn), "ret");
        assert_eq!(proto.get_num_operands(), 0);
        assert_eq!(proto.get_flow_type(&insn), RefType::Terminator);
        assert!(proto.get_fall_through(&insn).is_none());
        let pcode = proto.get_pcode(&insn, None);
        assert_eq!(pcode.len(), 1);
        assert_eq!(pcode[0].get_opcode(), P::Return);
        let target = &pcode[0].get_inputs()[0];
        assert!(target.is_register());
        assert_eq!((target.get_offset(), target.get_size()), (4, 4));
        assert!(proto.get_op_representation_list(0, &insn).is_none());
    }

    #[test]
    fn prototypes_are_identified_by_their_constructor_tree() {
        let lang = language();
        let words = Vec::new();
        let mem = |offset: i64, bytes: &[u8]| -> Arc<dyn MemBuffer> {
            Arc::new(ByteMemBufferImpl::new(
                Address::new(lang.get_default_space(), offset),
                bytes.to_vec(),
                true,
            ))
        };
        let mov1 = SleighInstructionPrototype::new(lang.clone(), mem(0, &[0x11, 0x2a]), words.clone(), false)
            .unwrap();
        let mov2 = SleighInstructionPrototype::new(lang.clone(), mem(8, &[0x10, 0x07]), words.clone(), false)
            .unwrap();
        let jmp = SleighInstructionPrototype::new(lang.clone(), mem(0, &[0x20, 0x05]), words.clone(), false)
            .unwrap();
        let delayed = SleighInstructionPrototype::new(lang.clone(), mem(0, &[0x11, 0x2a]), words, true)
            .unwrap();

        assert_eq!(mov1.dump_constructor_tree(), "10");
        assert_eq!(jmp.dump_constructor_tree(), "20[40]");
        // Only the constructors matter, not the bits they do not care about
        assert_eq!(mov1, mov2);
        assert_ne!(mov1, jmp);
        // A delay-slot instruction is a different prototype
        assert_eq!(delayed.java_hash_code(), mov1.java_hash_code().wrapping_add(0xFABFAB));
        assert!(delayed.is_in_delay_slot());
        // and prints its mnemonic with a leading underscore
        let insn = Parsed {
            lang: lang.clone(),
            bytes: vec![0x11, 0x2a],
            proto: Box::new(delayed),
            mem: ByteMemBufferImpl::new(Address::new(lang.get_default_space(), 0), vec![0x11, 0x2a], true),
            processor: ProcessorContextImpl::new(lang.clone()),
        };
        assert_eq!(insn.proto.get_mnemonic(&insn), "_mov");
    }

    #[test]
    fn parse_reports_unknown_and_unreadable_instructions() {
        let lang = language();
        assert!(matches!(
            parse(&lang, 0x1000, &[0xf0, 0x00]),
            Err(ParseError::UnknownInstruction(_))
        ));
        assert!(matches!(
            parse(&lang, 0x1000, &[]),
            Err(ParseError::InsufficientBytes(_))
        ));
    }

    #[test]
    fn parse_needs_a_shared_language() {
        let decoder = PackedDecode::new(Arc::new(DefaultAddressFactory::new(vec![])), sla());
        let lang = SleighLanguage::decode(&decoder, "toy:BE:32:default".to_string()).unwrap();
        let mem = ByteMemBufferImpl::new(
            Address::new(lang.get_default_space(), 0),
            vec![0x11, 0x2a],
            true,
        );
        let shared = language();
        let mut processor = ProcessorContextImpl::new(shared);
        match lang.parse(&mem, &mut processor, false) {
            Err(ParseError::UnknownInstruction(e)) => assert!(e.message().contains("into_shared")),
            other => panic!("expected an error, got {:?}", other.map(|_| ())),
        }
    }

    #[test]
    fn pseudo_parser_context_parses_the_requested_address() {
        let lang = language();
        let insn = parse(&lang, 0x1000, &[0x11, 0x2a]).unwrap();
        // bytes for two instructions: mov at 0x1000, jmp at 0x1002
        let buffer = ByteMemBufferImpl::new(
            Address::new(lang.get_default_space(), 0x1000),
            vec![0x11, 0x2a, 0x20, 0x05],
            true,
        );
        let ctx = insn
            .proto
            .get_pseudo_parser_context(
                &Address::new(lang.get_default_space(), 0x1002),
                &buffer,
                &insn.processor,
            )
            .unwrap();
        let sleigh = ctx
            .as_any()
            .and_then(|a| a.downcast_ref::<SleighParserContext>())
            .unwrap();
        assert_eq!(sleigh.get_addr().offset(), 0x1002);
        assert_eq!(sleigh.get_naddr().unwrap().offset(), 0x1004);
        assert_eq!(sleigh.get_sleigh_prototype().unwrap().dump_constructor_tree(), "20[40]");
    }

    #[test]
    fn delay_slot_pcode_is_woven_in_before_the_branch() {
        let lang = language();
        // jd 0x1012 ; delay slot: mov r1, #0x2a
        let insn = parse(&lang, 0x1000, &[0x40, 0x10, 0x11, 0x2a]).unwrap();
        let proto = &insn.proto;

        assert_eq!(proto.get_mnemonic(&insn), "jd");
        assert!(proto.has_delay_slots());
        assert_eq!(proto.get_delay_slot_byte_count(), 2);
        assert_eq!(proto.get_delay_slot_depth(&insn), 1);
        assert_eq!(proto.get_fall_through_offset(&insn), 4);
        assert_eq!(proto.get_flow_type(&insn), RefType::UnconditionalJump);
        assert_eq!(proto.get_flows(&insn).unwrap()[0].offset(), 0x1012);

        let pcode = proto.get_pcode(&insn, None);
        assert_eq!(pcode.len(), 2);
        assert_eq!(pcode[0].get_opcode(), P::Copy);
        assert_eq!(pcode[0].get_inputs()[0].get_offset(), 0x2a);
        assert_eq!(pcode[1].get_opcode(), P::Branch);
        assert_eq!(pcode[1].get_inputs()[0].get_offset(), 0x1012);
        // every op belongs to the branch instruction, in order
        assert!(pcode.iter().all(|op| op.seqnum.get_target().offset() == 0x1000));
        assert_eq!(pcode[1].seqnum.get_time(), 1);

        // a delay-slot instruction may not itself have delay slots
        let mem = ByteMemBufferImpl::new(
            Address::new(lang.get_default_space(), 0x1000),
            vec![0x40, 0x10],
            true,
        );
        let mut processor = ProcessorContextImpl::new(lang.clone());
        assert!(matches!(
            lang.parse(&mem, &mut processor, true),
            Err(ParseError::UnknownInstruction(_))
        ));
    }

    #[test]
    fn delay_slot_without_a_following_instruction_is_unimplemented() {
        let lang = language();
        let insn = parse(&lang, 0x1000, &[0x40, 0x10]).unwrap();
        // no bytes follow: the delay slot cannot be parsed
        assert_eq!(insn.proto.get_delay_slot_depth(&insn), 0);
        assert_eq!(insn.proto.get_fall_through_offset(&insn), 2);
        let pcode = insn.proto.get_pcode(&insn, None);
        assert_eq!(pcode.len(), 1);
        assert_eq!(pcode[0].get_opcode(), P::Unimplemented);
    }

    /// Decodes `bytes` (a packed stream) against the toy language's spaces.
    fn packed_decoder(lang: &Arc<SleighLanguage>, bytes: Vec<u8>) -> PackedDecode {
        PackedDecode::new(Arc::from(lang.get_address_factory()), bytes)
    }

    fn packed_pcode(insn: &Parsed) -> Vec<u8> {
        use crate::program::model::pcode::{CachedEncoder, PatchPackedEncode};
        let mut enc = PatchPackedEncode::new();
        insn.proto.get_pcode_packed(&mut enc, insn, None).unwrap();
        let mut bytes = Vec::new();
        enc.write_to(&mut bytes).unwrap();
        bytes
    }

    /// `jmp 0x1007` packs as `<inst offset=2><addr ram:0x1000/><op code=BRANCH size=1><void/>
    /// <addr ram:0x1007 size=4/></op></inst>` -- the same op `get_pcode` builds as an object.
    #[test]
    fn packed_pcode_of_jmp_matches_the_object_pcode() {
        use crate::program::model::pcode::Decoder;
        let lang = language();
        let insn = parse(&lang, 0x1000, &[0x20, 0x05]).unwrap();
        let d = packed_decoder(&lang, packed_pcode(&insn));

        let inst = d.open_element_with_id(ELEM_INST).unwrap();
        assert_eq!(d.read_signed_integer_with_id(ATTRIB_OFFSET).unwrap(), 2);
        let addr = d.open_element_with_id(ELEM_ADDR).unwrap();
        assert_eq!(d.read_space_with_id(ATTRIB_SPACE).unwrap().name(), "ram");
        assert_eq!(d.read_unsigned_integer_with_id(ATTRIB_OFFSET).unwrap(), 0x1000);
        d.close_element(addr).unwrap();

        let op = d.open_element_with_id(ELEM_OP).unwrap();
        assert_eq!(
            d.read_signed_integer_with_id(ATTRIB_CODE).unwrap(),
            OpCode::CpuiBranch.ordinal() as i64
        );
        assert_eq!(d.read_signed_integer_with_id(ATTRIB_SIZE).unwrap(), 1);
        let void = d.open_element_with_id(ELEM_VOID).unwrap();
        d.close_element(void).unwrap();
        let dest = d.open_element_with_id(ELEM_ADDR).unwrap();
        assert_eq!(d.read_space_with_id(ATTRIB_SPACE).unwrap().name(), "ram");
        assert_eq!(d.read_unsigned_integer_with_id(ATTRIB_OFFSET).unwrap(), 0x1007);
        assert_eq!(d.read_signed_integer_with_id(ATTRIB_SIZE).unwrap(), 4);
        d.close_element(dest).unwrap();
        d.close_element(op).unwrap();
        d.close_element(inst).unwrap();
    }

    /// The delay slot is woven in: the fall offset covers both instructions, and the delay
    /// slot's COPY precedes the BRANCH.
    #[test]
    fn packed_pcode_of_a_delay_slot_branch_covers_both_instructions() {
        use crate::program::model::pcode::Decoder;
        let lang = language();
        let insn = parse(&lang, 0x1000, &[0x40, 0x10, 0x11, 0x2a]).unwrap();
        let d = packed_decoder(&lang, packed_pcode(&insn));
        let inst = d.open_element_with_id(ELEM_INST).unwrap();
        assert_eq!(d.read_signed_integer_with_id(ATTRIB_OFFSET).unwrap(), 4);
        let addr = d.open_element_with_id(ELEM_ADDR).unwrap();
        d.close_element_skipping(addr).unwrap();
        let mut codes = Vec::new();
        while d.peek_element().unwrap() != 0 {
            let op = d.open_element_with_id(ELEM_OP).unwrap();
            codes.push(d.read_signed_integer_with_id(ATTRIB_CODE).unwrap());
            d.close_element_skipping(op).unwrap();
        }
        d.close_element(inst).unwrap();
        assert_eq!(
            codes,
            vec![OpCode::CpuiCopy.ordinal() as i64, OpCode::CpuiBranch.ordinal() as i64]
        );
    }

    /// Semantics that cannot be built (the delay slot is missing) pack as `<unimpl>` carrying
    /// the instruction length.
    #[test]
    fn packed_pcode_of_an_unbuildable_instruction_is_unimpl() {
        use crate::program::model::pcode::Decoder;
        let lang = language();
        let insn = parse(&lang, 0x1000, &[0x40, 0x10]).unwrap();
        let d = packed_decoder(&lang, packed_pcode(&insn));
        let el = d.open_element_with_id(ELEM_UNIMPL).unwrap();
        assert_eq!(d.read_signed_integer_with_id(ATTRIB_OFFSET).unwrap(), 2);
        d.close_element(el).unwrap();
    }

    #[test]
    fn a_dynamic_operand_loads_through_its_pointer() {
        let lang = language();
        // ld r0, [r1]
        let insn = parse(&lang, 0x1000, &[0x50, 0x01]).unwrap();
        let proto = &insn.proto;
        assert_eq!(proto.get_mnemonic(&insn), "ld");
        let ctx = insn.get_parser_context().unwrap();
        let sleigh = ctx.as_any().and_then(|a| a.downcast_ref::<SleighParserContext>()).unwrap();
        assert_eq!(sleigh.get_sleigh_prototype().unwrap().dump_constructor_tree(), "60[70]");
        assert_eq!(proto.get_op_type(1, &insn), OperandType::DYNAMIC as i32);
        assert!(proto.get_address(1, &insn).is_none());

        let pcode = proto.get_pcode(&insn, None);
        assert_eq!(pcode.len(), 2);
        // LOAD unique:0x10:4 <- (spaceid of ram), register:4:4
        assert_eq!(pcode[0].get_opcode(), P::Load);
        let tmp = pcode[0].get_output().unwrap().clone();
        assert!(tmp.is_unique());
        assert_eq!((tmp.get_offset(), tmp.get_size()), (0x10, 4));
        let loads = pcode[0].get_inputs();
        assert!(loads[0].is_constant());
        assert_eq!(loads[0].get_offset(), lang.get_default_space().space_id() as i64);
        assert!(loads[1].is_register());
        assert_eq!((loads[1].get_offset(), loads[1].get_size()), (4, 4));
        // COPY register:0:4 <- unique:0x10:4
        assert_eq!(pcode[1].get_opcode(), P::Copy);
        assert_eq!(pcode[1].get_inputs()[0], tmp);
        assert_eq!(pcode[1].get_output().unwrap().get_offset(), 0);

        // [r1] is displayed through the subtable
        match proto.get_op_representation_list(1, &insn).unwrap().as_slice() {
            [OperandValue::Character('['), OperandValue::Register(r), OperandValue::Character(']')] => {
                assert_eq!(register_name(r), "r1")
            }
            other => panic!("unexpected representation {other:?}"),
        }
        assert_eq!(proto.get_operand_ref_type(1, &insn, None), RefType::Read);
        assert_eq!(proto.get_operand_ref_type(0, &insn, None), RefType::Write);
        match proto.get_input_objects(&insn).as_slice() {
            [OperandValue::Register(r)] => assert_eq!(register_name(r), "r1"),
            other => panic!("unexpected inputs {other:?}"),
        }
        match proto.get_result_objects(&insn).as_slice() {
            [OperandValue::Register(r)] => assert_eq!(register_name(r), "r0"),
            other => panic!("unexpected results {other:?}"),
        }
    }

    /// A p-code override steering flow and fall-through.
    struct Override {
        flow: FlowOverride,
        start: Address,
        fall: Option<Address>,
    }

    impl PcodeOverride for Override {
        fn get_instruction_start(&self) -> Address {
            self.start.clone()
        }
        fn get_flow_override(&self) -> FlowOverride {
            self.flow
        }
        fn get_overriding_reference(&self, _ref_type: RefType) -> Option<Address> {
            None
        }
        fn get_fall_through_override(&self) -> Option<Address> {
            self.fall.clone()
        }
        fn has_call_fixup(&self, _call_dest_addr: Address) -> bool {
            false
        }
        fn get_call_fixup(
            &self,
            _call_dest_addr: Address,
        ) -> Option<Box<dyn crate::program::model::lang::InjectPayload>> {
            None
        }
        fn set_call_override_ref_applied(&self) {}
        fn is_call_override_ref_applied(&self) -> bool {
            false
        }
        fn set_jump_override_ref_applied(&self) {}
        fn is_jump_override_ref_applied(&self) -> bool {
            false
        }
        fn set_call_other_call_override_ref_applied(&self) {}
        fn is_call_other_call_override_ref_applied(&self) -> bool {
            false
        }
        fn set_call_other_jump_override_ref_applied(&self) {}
        fn is_call_other_jump_override_applied(&self) -> bool {
            false
        }
        fn has_potential_override(&self) -> bool {
            true
        }
        fn get_primary_call_reference(&self) -> Option<Address> {
            None
        }
    }

    #[test]
    fn flow_overrides_rewrite_the_branch() {
        let lang = language();
        let insn = parse(&lang, 0x1000, &[0x20, 0x05]).unwrap();
        let start = insn.get_address();
        let with = |flow: FlowOverride| {
            let over = Override { flow, start: start.clone(), fall: None };
            insn.proto.get_pcode(&insn, Some(&over))
        };

        let call = with(FlowOverride::Call);
        assert_eq!(call.len(), 1);
        assert_eq!(call[0].get_opcode(), P::Call);
        assert_eq!(call[0].get_inputs()[0].get_offset(), 0x1007);

        let call_return = with(FlowOverride::CallReturn);
        assert_eq!(
            call_return.iter().map(|o| o.get_opcode()).collect::<Vec<_>>(),
            vec![P::Call, P::Return]
        );
        // RETURN to a null (constant zero) address of the constant space's size
        let null = &call_return[1].get_inputs()[0];
        assert!(null.is_constant());
        assert_eq!((null.get_offset(), null.get_size()), (0, 8));

        // BRANCH <dest> -> tmp = COPY &<dest>; RETURN tmp
        let ret = with(FlowOverride::Return);
        assert_eq!(
            ret.iter().map(|o| o.get_opcode()).collect::<Vec<_>>(),
            vec![P::Copy, P::Return]
        );
        let tmp = ret[0].get_output().unwrap();
        assert!(tmp.is_unique());
        // uniqbase 0x1000 + RUNTIME_RETURN_LOCATION (0x80)
        assert_eq!((tmp.get_offset(), tmp.get_size()), (0x1080, 4));
        assert_eq!(ret[0].get_inputs()[0].get_offset(), 0x1007);
        assert_eq!(&ret[1].get_inputs()[0], tmp);

        // BRANCH -> BRANCH is unchanged
        assert_eq!(with(FlowOverride::Branch)[0].get_opcode(), P::Branch);
        // with an override, the operand's reference type is recomputed from the p-code
        let over = Override { flow: FlowOverride::Call, start, fall: None };
        assert_eq!(
            insn.proto.get_operand_ref_type(0, &insn, Some(&over)),
            RefType::UnconditionalCall
        );
    }

    #[test]
    fn a_fall_through_override_appends_a_final_branch() {
        let lang = language();
        let insn = parse(&lang, 0x1000, &[0x11, 0x2a]).unwrap();
        let over = Override {
            flow: FlowOverride::None,
            start: insn.get_address(),
            fall: Some(Address::new(lang.get_default_space(), 0x2000)),
        };
        let pcode = insn.proto.get_pcode(&insn, Some(&over));
        assert_eq!(
            pcode.iter().map(|o| o.get_opcode()).collect::<Vec<_>>(),
            vec![P::Copy, P::Branch]
        );
        assert_eq!(pcode[1].get_inputs()[0].get_offset(), 0x2000);
    }
}

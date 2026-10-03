//! Ports of `ghidra.app.plugin.processors.sleigh.ConstructState` and
//! `ghidra.app.plugin.processors.sleigh.ParserWalker`.
//!
//! # Ownership shape
//! Java builds the constructor tree of a parsed instruction as a graph of `ConstructState`
//! objects linked by `parent` pointers and `resolvedStates` child lists, and the
//! `SleighParserContext` keys its `FixedHandle` map by `ConstructState` identity. Here the tree is
//! an arena ([`ConstructTree`]) and a state is addressed by its `usize` index, which plays the
//! role of Java's object identity: handles are keyed by that index, flow records remember it, and
//! [`ParserWalker`] walks by it. Index [`ConstructTree::ROOT`] is Java's `rootState`.
//!
//! A [`ParserWalker`] borrows the [`SleighParserContext`] it walks. The context owns the tree it
//! is walking (built in place while an instruction is resolved, or copied from the prototype
//! afterwards) together with the packed context words, the pending context commits and the handle
//! map, all behind `RefCell`s: exactly as in Java, several walkers over one context mutate those
//! pieces while other walkers read them (e.g. an `OperandValue` evaluates a sub-expression with a
//! second, out-of-band walker while the resolving walker is live).

use crate::app::plugin::processors::sleigh::sleigh_exception::SleighException;
use crate::app::plugin::processors::sleigh::sleigh_parser_context::SleighParserContext;
use crate::generic::hash::simple_crc32::CRC32_TABLE;
use crate::program::model::address::{Address, AddressSpace};
use crate::program::model::lang::sleigh::constructor::Constructor;
use crate::program::model::lang::sleigh::symbol::{SleighSymbol, SymbolTable};
use crate::program::model::lang::sleigh::FixedHandle;
use crate::program::model::lang::unknown_instruction_exception::UnknownInstructionException;
use crate::program::model::mem::MemoryAccessException;
use std::fmt;
use std::sync::Arc;

// `MemBuffer` was defined here, four methods deep, while Java puts it in
// `ghidra.program.model.mem` -- and a second, unrelated definition lived in program/seam_stubs.rs.
// The canonical port now lives in program/model/mem/mem_buffer.rs; this re-export keeps the 19
// call sites that reached for it here working unchanged.
pub use crate::program::model::mem::MemBuffer;

/// Error raised while resolving, printing or emitting a sleigh instruction.
///
/// Folds together the checked exceptions the Java parse/print/emit paths declare
/// (`UnknownInstructionException`, `MemoryAccessException`) and the unchecked `SleighException`
/// several of them throw (an undefined `inst_ref`, a subtable used in an expression, ...).
#[derive(Debug)]
pub enum SleighError {
    /// No constructor matches the instruction bytes (Java `UnknownInstructionException`).
    UnknownInstruction(UnknownInstructionException),
    /// The instruction bytes could not be read (Java `MemoryAccessException`).
    MemoryAccess(MemoryAccessException),
    /// The specification was used in a way it does not support (Java `SleighException`).
    Sleigh(SleighException),
}

impl fmt::Display for SleighError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SleighError::UnknownInstruction(e) => write!(f, "{e}"),
            SleighError::MemoryAccess(e) => write!(f, "{e}"),
            SleighError::Sleigh(e) => write!(f, "{}", e.message()),
        }
    }
}

impl std::error::Error for SleighError {}

impl From<UnknownInstructionException> for SleighError {
    fn from(e: UnknownInstructionException) -> Self {
        SleighError::UnknownInstruction(e)
    }
}

impl From<MemoryAccessException> for SleighError {
    fn from(e: MemoryAccessException) -> Self {
        SleighError::MemoryAccess(e)
    }
}

impl From<SleighException> for SleighError {
    fn from(e: SleighException) -> Self {
        SleighError::Sleigh(e)
    }
}

/// One node of a parsed instruction's constructor tree.
///
/// Port of `ghidra.app.plugin.processors.sleigh.ConstructState`. `parent` and `sub_states` are
/// indices into the owning [`ConstructTree`] (Java's `parent` / `resolvedStates` references).
#[derive(Clone, Default)]
pub struct ConstructState {
    /// The constructor matched at this node (`ct`), if resolved.
    pub ct: Option<Arc<Constructor>>,
    /// Index of the parent node (`parent`), `None` for a root.
    pub parent: Option<usize>,
    /// Indices of the operand nodes, in operand order (`resolvedStates`).
    pub sub_states: Vec<usize>,
    /// Absolute offset of this node from the start of the instruction (`offset`).
    pub offset: i32,
    /// Length of this instantiation of the constructor (`length`).
    pub length: i32,
}

impl ConstructState {
    /// A fresh, unresolved node under `parent`. The caller links it into the parent's
    /// `sub_states` (see [`ConstructTree::add_state`], the port of `new ConstructState(parent)`).
    pub fn new(parent: Option<usize>) -> Self {
        Self {
            ct: None,
            parent,
            sub_states: Vec::new(),
            offset: 0,
            length: 0,
        }
    }

    /// Port of `ConstructState.getConstructor()`.
    pub fn get_constructor(&self) -> Option<&Arc<Constructor>> {
        self.ct.as_ref()
    }

    /// Port of `ConstructState.getNumSubStates()`.
    pub fn get_num_sub_states(&self) -> usize {
        self.sub_states.len()
    }

    /// Port of `ConstructState.getParent()`.
    pub fn get_parent(&self) -> Option<usize> {
        self.parent
    }

    /// Port of `ConstructState.getLength()`.
    pub fn get_length(&self) -> i32 {
        self.length
    }

    /// Port of `ConstructState.getOffset()`.
    pub fn get_offset(&self) -> i32 {
        self.offset
    }
}

/// The constructor tree of one parsed instruction: an arena of [`ConstructState`] nodes.
///
/// Java has no class of its own for this; the tree is the object graph reachable from
/// `SleighInstructionPrototype.rootState`. See the module docs.
#[derive(Clone)]
pub struct ConstructTree {
    states: Vec<ConstructState>,
}

impl Default for ConstructTree {
    fn default() -> Self {
        Self::new()
    }
}

impl ConstructTree {
    /// Index of the root node (Java's `rootState`).
    pub const ROOT: usize = 0;

    /// A tree holding just an unresolved root (Java `new ConstructState(null)`).
    pub fn new() -> Self {
        Self {
            states: vec![ConstructState::new(None)],
        }
    }

    /// Adds a new node under `parent`, appending it to the parent's operand list, and returns its
    /// index. Port of the `ConstructState(ConstructState parent)` constructor, which registers
    /// itself with `parent.addSubState(this)`.
    pub fn add_state(&mut self, parent: Option<usize>) -> usize {
        let idx = self.states.len();
        self.states.push(ConstructState::new(parent));
        if let Some(p) = parent {
            self.states[p].sub_states.push(idx);
        }
        idx
    }

    /// The node at `idx`.
    pub fn get(&self, idx: usize) -> &ConstructState {
        &self.states[idx]
    }

    /// Mutable access to the node at `idx`.
    pub fn get_mut(&mut self, idx: usize) -> &mut ConstructState {
        &mut self.states[idx]
    }

    /// Number of nodes in the arena.
    pub fn len(&self) -> usize {
        self.states.len()
    }

    /// True if the arena has no nodes (never the case for a tree built by [`ConstructTree::new`]).
    pub fn is_empty(&self) -> bool {
        self.states.is_empty()
    }

    /// Port of `ConstructState.getSubState(int)` for the node at `idx`.
    ///
    /// # Panics
    /// If `index` is not an operand of that node (Java's `IndexOutOfBoundsException`).
    pub fn get_sub_state(&self, idx: usize, index: usize) -> usize {
        self.states[idx].sub_states[index]
    }

    /// Port of `ConstructState.hashCode()` for the node at `idx`: a CRC32 over the constructor
    /// ids of the subtree, which is "statistically unique" per distinct constructor tree.
    pub fn hash_code(&self, idx: usize) -> i32 {
        self.compute_hash_code(idx, 0x56c93c59)
    }

    fn compute_hash_code(&self, idx: usize, mut hashcode: i32) -> i32 {
        let state = &self.states[idx];
        let Some(ct) = &state.ct else {
            return hashcode;
        };
        let id = ct.id;
        hashcode = (CRC32_TABLE[((hashcode ^ (id >> 8)) & 0xff) as usize] as i32) ^ (hashcode >> 8);
        hashcode = (CRC32_TABLE[((hashcode ^ id) & 0xff) as usize] as i32) ^ (hashcode >> 8);
        for &sub in &state.sub_states {
            hashcode = self.compute_hash_code(sub, hashcode);
        }
        hashcode
    }

    /// Port of `ConstructState.dumpConstructorTree()`: the constructor line numbers of the
    /// subtree at `idx`, with brackets describing the tree structure, or `None` if the node is
    /// unresolved.
    pub fn dump_constructor_tree(&self, idx: usize) -> Option<String> {
        let state = &self.states[idx];
        let ct = state.ct.as_ref()?;
        let mut sb = ct.lineno.to_string();
        let subs: Vec<String> = state
            .sub_states
            .iter()
            .filter_map(|&s| self.dump_constructor_tree(s))
            .collect();
        if subs.is_empty() {
            return Some(sb);
        }
        sb.push('[');
        sb.push_str(&subs.join(","));
        sb.push(']');
        Some(sb)
    }
}

/// `ParserWalker.MAX_PARSE_DEPTH`.
pub const MAX_PARSE_DEPTH: usize = 64;

/// Handle-map key used for a walker positioned on an out-of-band state (Java keys the handle
/// map by the temporary `ConstructState` object itself).
pub const OUT_OF_BAND_STATE: usize = usize::MAX;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Point {
    Tree(usize),
    OutOfBand,
}

/// Class for walking the Sleigh Parser tree.
///
/// Port of `ghidra.app.plugin.processors.sleigh.ParserWalker`. The walker is positioned on a
/// node of its context's [`ConstructTree`] (or on a detached, out-of-band node created by
/// [`ParserWalker::set_out_of_band_state`]).
pub struct ParserWalker<'a> {
    context: &'a SleighParserContext,
    /// If in the midst of cross-build, the context from the original instruction.
    cross_context: Option<&'a SleighParserContext>,
    point: Option<Point>,
    out_of_band: ConstructState,
    depth: i32,
    breadcrumb: [i32; MAX_PARSE_DEPTH + 1],
}

impl<'a> ParserWalker<'a> {
    /// Port of `ParserWalker(SleighParserContext)`.
    pub fn new(context: &'a SleighParserContext) -> Self {
        Self {
            context,
            cross_context: None,
            point: None,
            out_of_band: ConstructState::new(None),
            depth: 0,
            breadcrumb: [0; MAX_PARSE_DEPTH + 1],
        }
    }

    /// Port of `ParserWalker(SleighParserContext, SleighParserContext)`, for use with p-code
    /// cross-build: `cross` is the context of the instruction doing the cross-build.
    pub fn with_cross_context(
        context: &'a SleighParserContext,
        cross: &'a SleighParserContext,
    ) -> Self {
        let mut walker = Self::new(context);
        walker.cross_context = Some(cross);
        walker
    }

    /// Port of `ParserWalker.getParserContext()`.
    pub fn get_parser_context(&self) -> &'a SleighParserContext {
        self.context
    }

    /// The sleigh symbol table of the language being parsed, if the context belongs to a
    /// language (snippet contexts do not). Constructors refer to their operand symbols by id,
    /// which is resolved through this table.
    pub fn symbol_table(&self) -> Option<&'a SymbolTable> {
        self.context.language().map(|l| l.get_symbol_table())
    }

    /// Initialize a walk of the tree. Port of `ParserWalker.baseState()`.
    pub fn base_state(&mut self) {
        self.point = Some(Point::Tree(ConstructTree::ROOT));
        self.depth = 0;
        self.breadcrumb[0] = 0;
    }

    /// Port of `ParserWalker.subTreeState(ConstructState)`.
    pub fn sub_tree_state(&mut self, subtree: usize) {
        self.point = Some(Point::Tree(subtree));
        self.depth = 0;
        self.breadcrumb[0] = 0;
    }

    /// Create state suitable for parsing just a p-code semantics snippet. Port of
    /// `ParserWalker.snippetState()`: the walker is positioned on a fresh, detached node.
    pub fn snippet_state(&mut self) {
        let idx = self.context.tree().borrow_mut().add_state(None);
        self.point = Some(Point::Tree(idx));
        self.depth = 0;
        self.breadcrumb[0] = 0;
    }

    /// True if there is more walk to go. Port of `ParserWalker.isState()`.
    pub fn is_state(&self) -> bool {
        self.point.is_some()
    }

    /// The tree node the walker is on, or `None` at the end of the walk (or on an out-of-band
    /// node, which is not part of the tree). Port of `ParserWalker.getState()`.
    pub fn get_state(&self) -> Option<usize> {
        match self.point {
            Some(Point::Tree(idx)) => Some(idx),
            _ => None,
        }
    }

    fn with_point<R>(&self, f: impl FnOnce(&ConstructState) -> R) -> R {
        match self.point.expect("ParserWalker is not positioned on a state") {
            Point::Tree(idx) => f(self.context.tree().borrow().get(idx)),
            Point::OutOfBand => f(&self.out_of_band),
        }
    }

    fn with_point_mut<R>(&mut self, f: impl FnOnce(&mut ConstructState) -> R) -> R {
        match self.point.expect("ParserWalker is not positioned on a state") {
            Point::Tree(idx) => f(self.context.tree().borrow_mut().get_mut(idx)),
            Point::OutOfBand => f(&mut self.out_of_band),
        }
    }

    /// The handle-map key of the current node.
    fn point_key(&self) -> usize {
        match self.point.expect("ParserWalker is not positioned on a state") {
            Point::Tree(idx) => idx,
            Point::OutOfBand => OUT_OF_BAND_STATE,
        }
    }

    fn sub_state(&self, i: usize) -> usize {
        self.with_point(|s| s.sub_states[i])
    }

    /// Move down to a particular child of the current node, storing what would be the next
    /// sibling to walk. Port of `ParserWalker.pushOperand(int)`.
    ///
    /// # Panics
    /// If the maximum parse depth is exceeded (Java's `AssertException`); the tree could not
    /// have been built that deep.
    pub fn push_operand(&mut self, i: usize) {
        assert!(
            (self.depth as usize) < MAX_PARSE_DEPTH,
            "Exceeded maximum parse depth"
        );
        self.breadcrumb[self.depth as usize] = i as i32 + 1;
        self.depth += 1;
        let next = self.sub_state(i);
        self.point = Some(Point::Tree(next));
        self.breadcrumb[self.depth as usize] = 0;
    }

    /// Adds a new operand node under the current node and moves to it. Port of
    /// `ParserWalker.allocateOperand()`.
    ///
    /// # Errors
    /// [`UnknownInstructionException`] if the maximum parse depth is exceeded.
    pub fn allocate_operand(&mut self) -> Result<(), UnknownInstructionException> {
        if self.depth as usize == MAX_PARSE_DEPTH {
            return Err(UnknownInstructionException::with_message(
                "Exceeded maximum parse depth",
            ));
        }
        let parent = match self.point {
            Some(Point::Tree(idx)) => idx,
            _ => panic!("allocateOperand requires a walker positioned on the tree"),
        };
        let opstate = self.context.tree().borrow_mut().add_state(Some(parent));
        self.breadcrumb[self.depth as usize] += 1;
        self.depth += 1;
        self.point = Some(Point::Tree(opstate));
        self.breadcrumb[self.depth as usize] = 0;
        Ok(())
    }

    /// Move to the parent of the current node. Port of `ParserWalker.popOperand()`.
    pub fn pop_operand(&mut self) {
        let parent = self.with_point(|s| s.parent);
        self.point = parent.map(Point::Tree);
        self.depth -= 1;
    }

    /// Find the next child that needs to be traversed. Port of `ParserWalker.getOperand()`.
    pub fn get_operand(&self) -> i32 {
        self.breadcrumb[self.depth as usize]
    }

    /// The handle of child `i` of the current node. Port of `ParserWalker.getFixedHandle(int)`;
    /// Java hands out the map entry itself, this returns a copy (see
    /// [`ParserWalker::set_fixed_handle`] to write one back).
    pub fn get_fixed_handle(&self, i: usize) -> FixedHandle {
        self.context.get_fixed_handle(self.sub_state(i))
    }

    /// Stores the handle of child `i` of the current node.
    pub fn set_fixed_handle(&self, i: usize, hand: FixedHandle) {
        self.context.set_fixed_handle(self.sub_state(i), hand);
    }

    /// The handle of the current node. Port of `ParserWalker.getParentHandle()` (a copy; see
    /// [`ParserWalker::set_parent_handle`]).
    pub fn get_parent_handle(&self) -> FixedHandle {
        self.context.get_fixed_handle(self.point_key())
    }

    /// Stores the handle of the current node.
    pub fn set_parent_handle(&self, hand: FixedHandle) {
        self.context.set_fixed_handle(self.point_key(), hand);
    }

    /// The handle-map key of the current node, so a copied handle can be written back later.
    pub fn parent_handle_key(&self) -> usize {
        self.point_key()
    }

    /// The offset into the instruction for the current node (`i < 0`) or the end of child `i`.
    /// Port of `ParserWalker.getOffset(int)`.
    pub fn get_offset(&self, i: i32) -> i32 {
        if i < 0 {
            return self.with_point(|s| s.offset);
        }
        let op = self.sub_state(i as usize);
        let tree = self.context.tree().borrow();
        let st = tree.get(op);
        st.offset + st.length
    }

    /// Port of `ParserWalker.setOffset(int)`.
    pub fn set_offset(&mut self, off: i32) {
        self.with_point_mut(|s| s.offset = off);
    }

    /// Port of `ParserWalker.getCurrentLength()`.
    pub fn get_current_length(&self) -> i32 {
        self.with_point(|s| s.length)
    }

    /// Port of `ParserWalker.setCurrentLength(int)`.
    pub fn set_current_length(&mut self, len: i32) {
        self.with_point_mut(|s| s.length = len);
    }

    /// Calculate the length of the current constructor state assuming all its operands are
    /// constructed. Port of `ParserWalker.calcCurrentLength(int, int)`.
    pub fn calc_current_length(&mut self, min_length: i32, numopers: usize) {
        let idx = match self.point {
            Some(Point::Tree(idx)) => idx,
            _ => panic!("calcCurrentLength requires a walker positioned on the tree"),
        };
        let mut tree = self.context.tree().borrow_mut();
        let offset = tree.get(idx).offset;
        // Convert relative length to absolute length
        let mut min_length = min_length + offset;
        for i in 0..numopers {
            let sub = tree.get(tree.get_sub_state(idx, i));
            // Since subpoint.offset is an absolute offset (relative to beginning of
            // instruction), sublength is absolute and must be compared to absolute length
            let sublength = sub.length + sub.offset;
            if sublength > min_length {
                min_length = sublength;
            }
        }
        // Convert back to relative length
        tree.get_mut(idx).length = min_length - offset;
    }

    /// The constructor of the current node. Port of `ParserWalker.getConstructor()`.
    pub fn get_constructor(&self) -> Option<Arc<Constructor>> {
        self.with_point(|s| s.ct.clone())
    }

    /// Port of `ParserWalker.setConstructor(Constructor)`.
    pub fn set_constructor(&mut self, ct: Arc<Constructor>) {
        self.with_point_mut(|s| s.ct = Some(ct));
    }

    /// Port of `ParserWalker.getAddr()`.
    pub fn get_addr(&self) -> Address {
        match self.cross_context {
            Some(cross) => cross.get_addr(),
            None => self.context.get_addr(),
        }
    }

    /// Port of `ParserWalker.getNaddr()`; `None` where Java returns `null`.
    pub fn get_naddr(&self) -> Option<Address> {
        match self.cross_context {
            Some(cross) => cross.get_naddr(),
            None => self.context.get_naddr(),
        }
    }

    /// Port of `ParserWalker.getN2addr()`.
    pub fn get_n2addr(&self) -> Address {
        match self.cross_context {
            Some(cross) => cross.get_n2addr(),
            None => self.context.get_n2addr(),
        }
    }

    /// Port of `ParserWalker.getCurSpace()`.
    pub fn get_cur_space(&self) -> Arc<AddressSpace> {
        self.context.get_cur_space()
    }

    /// Port of `ParserWalker.getConstSpace()`.
    pub fn get_const_space(&self) -> Arc<AddressSpace> {
        self.context.get_const_space()
    }

    /// Port of `ParserWalker.getFlowRefAddr()`.
    ///
    /// # Errors
    /// [`SleighException`] if `inst_ref` is undefined in this context.
    pub fn get_flow_ref_addr(&self) -> Result<Address, SleighException> {
        self.context.get_flow_ref_addr()
    }

    /// Port of `ParserWalker.getFlowDestAddr()`.
    ///
    /// # Errors
    /// [`SleighException`] if `inst_dest` is undefined in this context.
    pub fn get_flow_dest_addr(&self) -> Result<Address, SleighException> {
        self.context.get_flow_dest_addr()
    }

    /// Port of `ParserWalker.getInstructionBytes(int, int)`, relative to the current node.
    ///
    /// # Errors
    /// [`MemoryAccessException`] if the first instruction byte cannot be read.
    pub fn get_instruction_bytes(
        &self,
        byteoff: i32,
        numbytes: i32,
    ) -> Result<i32, MemoryAccessException> {
        let offset = self.with_point(|s| s.offset);
        self.context.get_instruction_bytes(offset, byteoff, numbytes)
    }

    /// Port of `ParserWalker.getContextBytes(int, int)`.
    pub fn get_context_bytes(&self, byteoff: i32, numbytes: i32) -> i32 {
        self.context.get_context_bytes(byteoff, numbytes)
    }

    /// Port of `ParserWalker.getInstructionBits(int, int)`, relative to the current node.
    ///
    /// # Errors
    /// [`MemoryAccessException`] if the first instruction byte cannot be read.
    pub fn get_instruction_bits(&self, startbit: i32, size: i32) -> Result<i32, MemoryAccessException> {
        let offset = self.with_point(|s| s.offset);
        self.context.get_instruction_bits(offset, startbit, size)
    }

    /// Port of `ParserWalker.getContextBits(int, int)`.
    pub fn get_context_bits(&self, startbit: i32, size: i32) -> i32 {
        self.context.get_context_bits(startbit, size)
    }

    /// Positions this walker on a detached node standing for operand `index` of the constructor
    /// `ct`, as seen from `otherwalker`'s position, so the operand's defining expression can be
    /// evaluated before the operand's own branch has been built. Port of
    /// `ParserWalker.setOutOfBandState(Constructor, int, ConstructState, ParserWalker)`; the Java
    /// `tempstate` argument is the walker's own out-of-band node here.
    ///
    /// As in Java, if no node on `otherwalker`'s path uses `ct` the walker is left unchanged.
    pub fn set_out_of_band_state(
        &mut self,
        ct: &Arc<Constructor>,
        index: usize,
        otherwalker: &ParserWalker<'_>,
    ) {
        let (pt_offset, pt_length, pt_index_offset) = {
            // Walk up from the other walker's position to the node using `ct`.
            let mut curdepth = otherwalker.depth;
            let mut pt = otherwalker.point.expect("other walker is not positioned");
            let tree = otherwalker.context.tree().borrow();
            loop {
                let (pt_ct, parent) = match pt {
                    Point::Tree(idx) => (tree.get(idx).ct.clone(), tree.get(idx).parent),
                    Point::OutOfBand => (otherwalker.out_of_band.ct.clone(), None),
                };
                if pt_ct.as_ref().is_some_and(|c| Arc::ptr_eq(c, ct)) {
                    break;
                }
                if curdepth <= 0 {
                    return;
                }
                curdepth -= 1;
                match parent {
                    Some(p) => pt = Point::Tree(p),
                    None => return,
                }
            }
            let state = match pt {
                Point::Tree(idx) => tree.get(idx).clone(),
                Point::OutOfBand => otherwalker.out_of_band.clone(),
            };
            let sub_offset = state.sub_states.get(index).map(|&s| tree.get(s).offset);
            (state.offset, state.length, sub_offset)
        };
        let sym = self
            .symbol_table()
            .and_then(|t| ct.get_operand(t, index))
            .expect("constructor operand is not an OperandSymbol");
        // if i<0, i.e. the offset of the operand is constructor relative its possible that the
        // branch corresponding to the operand has not been constructed yet. Context expressions
        // are evaluated BEFORE the constructors branches are created. So we have to construct
        // the offset explicitly.
        let offset = if sym.offset_base < 0 {
            pt_offset + sym.rel_offset
        } else {
            pt_index_offset.expect("operand branch has not been constructed")
        };
        self.out_of_band = ConstructState {
            ct: Some(ct.clone()),
            parent: None,
            sub_states: Vec::new(),
            offset,
            length: pt_length,
        };
        self.point = Some(Point::OutOfBand);
        self.depth = 0;
        self.breadcrumb[0] = 0;
    }

    /// The name of the subtable the current node was resolved from, if any. Port of
    /// `ParserWalker.getCurrentSubtableName()`.
    pub fn get_current_subtable_name(&self) -> Option<String> {
        let parent = self.with_point(|s| s.parent)?;
        let ct = self.context.tree().borrow().get(parent).ct.clone()?;
        let curindex = (self.breadcrumb[(self.depth - 1) as usize] - 1) as usize;
        let table = self.symbol_table()?;
        let operand = ct.get_operand(table, curindex)?;
        let sym = table.find_symbol(operand.triple_id?)?;
        match sym {
            SleighSymbol::Subtable(s) => Some(s.header.name.clone()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::mem::ByteMemBufferImpl;

    fn constructor(id: i32, lineno: i32) -> Arc<Constructor> {
        let mut ct = Constructor::new();
        ct.id = id;
        ct.lineno = lineno;
        Arc::new(ct)
    }

    fn context(bytes: &[u8]) -> SleighParserContext {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        let mem: Arc<dyn MemBuffer> =
            Arc::new(ByteMemBufferImpl::new(Address::new(space, 0x100), bytes.to_vec(), true));
        SleighParserContext::for_tests(mem, vec![0x1234_5678])
    }

    #[test]
    fn add_state_links_children_in_operand_order() {
        let mut tree = ConstructTree::new();
        let a = tree.add_state(Some(ConstructTree::ROOT));
        let b = tree.add_state(Some(ConstructTree::ROOT));
        let c = tree.add_state(Some(a));
        assert_eq!(tree.get(ConstructTree::ROOT).sub_states, vec![a, b]);
        assert_eq!(tree.get_sub_state(a, 0), c);
        assert_eq!(tree.get(c).get_parent(), Some(a));
        assert_eq!(tree.len(), 4);
    }

    #[test]
    fn dump_constructor_tree_brackets_resolved_children() {
        let mut tree = ConstructTree::new();
        tree.get_mut(ConstructTree::ROOT).ct = Some(constructor(0, 10));
        let a = tree.add_state(Some(ConstructTree::ROOT));
        let _unresolved = tree.add_state(Some(ConstructTree::ROOT));
        tree.get_mut(a).ct = Some(constructor(1, 20));
        let c = tree.add_state(Some(a));
        tree.get_mut(c).ct = Some(constructor(2, 30));
        assert_eq!(tree.dump_constructor_tree(ConstructTree::ROOT).as_deref(), Some("10[20[30]]"));
        assert_eq!(tree.dump_constructor_tree(_unresolved), None);
    }

    #[test]
    fn hash_code_is_a_crc_over_constructor_ids() {
        let mut tree = ConstructTree::new();
        // An unresolved tree hashes to the seed
        assert_eq!(tree.hash_code(ConstructTree::ROOT), 0x56c93c59);
        tree.get_mut(ConstructTree::ROOT).ct = Some(constructor(0, 1));
        // id 0: two CRC steps of a zero byte from the seed
        let seed = 0x56c93c59i32;
        let step = |h: i32, v: i32| (CRC32_TABLE[((h ^ v) & 0xff) as usize] as i32) ^ (h >> 8);
        let expected = step(step(seed, 0), 0);
        assert_eq!(tree.hash_code(ConstructTree::ROOT), expected);
        // A different constructor id gives a different hash
        tree.get_mut(ConstructTree::ROOT).ct = Some(constructor(1, 1));
        assert_ne!(tree.hash_code(ConstructTree::ROOT), expected);
    }

    #[test]
    fn walker_allocates_pops_and_computes_lengths() {
        let ctx = context(&[0xab, 0xcd, 0xef]);
        let mut walker = ParserWalker::new(&ctx);
        walker.base_state();
        walker.set_offset(0);
        walker.set_constructor(constructor(0, 1));
        assert_eq!(walker.get_operand(), 0);

        // operand 0 at offset 1, length 2
        walker.allocate_operand().unwrap();
        walker.set_offset(1);
        assert_eq!(walker.get_instruction_bytes(0, 1).unwrap(), 0xcd);
        assert_eq!(walker.get_instruction_bits(4, 8).unwrap(), 0xde);
        walker.set_current_length(2);
        walker.pop_operand();
        assert_eq!(walker.get_state(), Some(ConstructTree::ROOT));
        // the breadcrumb moved on to operand 1
        assert_eq!(walker.get_operand(), 1);
        // end of operand 0: 1 + 2
        assert_eq!(walker.get_offset(0), 3);

        // the constructor's own minimum length is 1; its operand ends at byte 3
        walker.calc_current_length(1, 1);
        assert_eq!(walker.get_current_length(), 3);
        walker.pop_operand();
        assert!(!walker.is_state());

        walker.base_state();
        walker.push_operand(0);
        assert_eq!(walker.get_state(), Some(1));
        assert_eq!(walker.get_offset(-1), 1);
    }

    #[test]
    fn walker_reads_context_and_handles_through_its_context() {
        let ctx = context(&[0]);
        let mut walker = ParserWalker::new(&ctx);
        walker.base_state();
        assert_eq!(walker.get_context_bits(0, 8), 0x12);
        assert_eq!(walker.get_context_bytes(1, 2), 0x3456);
        walker.allocate_operand().unwrap();
        let mut hand = FixedHandle::new();
        hand.offset_offset = 7;
        walker.set_parent_handle(hand.clone());
        walker.pop_operand();
        assert_eq!(walker.get_fixed_handle(0), hand);
        assert_eq!(walker.get_addr().offset(), 0x100);
    }

    #[test]
    fn allocate_operand_stops_at_the_maximum_depth() {
        let ctx = context(&[0]);
        let mut walker = ParserWalker::new(&ctx);
        walker.base_state();
        for _ in 0..MAX_PARSE_DEPTH {
            walker.allocate_operand().unwrap();
        }
        let err = walker.allocate_operand().unwrap_err();
        assert!(err.message().contains("Exceeded maximum parse depth"));
    }
}

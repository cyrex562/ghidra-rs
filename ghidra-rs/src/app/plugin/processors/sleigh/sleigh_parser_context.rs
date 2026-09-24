//! Port of `ghidra.app.plugin.processors.sleigh.SleighParserContext`: all the recovered context
//! for a single instruction (memory, addresses, packed context words, pending context commits,
//! and the [`FixedHandle`] of every node of the instruction's constructor tree).
//!
//! # Shape
//! Java's class is concrete, so this is a struct. Several [`ParserWalker`]s over one context
//! mutate its context words, commit list, handle map and (while an instruction is being
//! resolved) its constructor tree while others read them, exactly as the Java walkers share one
//! `SleighParserContext` object; those four pieces therefore live behind `RefCell`s. The context
//! is a short-lived, single-threaded scratch object and is never shared across threads.
//!
//! The context owns its constructor tree: while an instruction is being resolved the tree is
//! built in place, and a context made for an existing prototype holds a copy of the prototype's
//! (immutable) tree, so node indices -- which key the handle map -- are the prototype's.
//!
//! # Memory
//! Java keeps a reference to the caller's `MemBuffer`. A context here must be `'static` (it is
//! handed out as a `Box<dyn ParserContext>`), so it holds an `Arc<dyn MemBuffer>`;
//! [`snapshot_mem_buffer`] captures the bytes of a borrowed buffer for that purpose.

use std::any::Any;
use std::cell::{OnceCell, RefCell};
use std::collections::HashMap;
use std::sync::Arc;

use crate::app::plugin::processors::sleigh::context_cache::ContextCache;
use crate::app::plugin::processors::sleigh::sleigh_exception::SleighException;
use crate::app::plugin::processors::sleigh::sleigh_instruction_prototype::SleighInstructionPrototype;
use crate::app::seam_stubs::RegisterValueBuilder;
use crate::program::model::address::special_address::SpecialAddress;
use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
use crate::program::model::lang::disassembler_context::DisassemblerContext;
use crate::program::model::lang::instruction_prototype::InstructionPrototype;
use crate::program::model::lang::parser_context::ParserContext;
use crate::program::model::lang::sleigh::symbol::SleighSymbol;
use crate::program::model::lang::sleigh::walker::{ConstructTree, ParserWalker, SleighError};
use crate::program::model::lang::sleigh::{FixedHandle, SleighLanguage};
use crate::program::model::mem::{ByteMemBufferImpl, MemBuffer, MemoryAccessException};

/// Number of bytes [`snapshot_mem_buffer`] captures: enough for the longest instruction of any
/// supported processor together with its delay slots and the following instruction (needed for
/// `inst_next2`).
pub const SNAPSHOT_SIZE: usize = 64;

/// Captures up to [`SNAPSHOT_SIZE`] bytes of `buf` starting at `offset`, as a buffer positioned
/// at `buf`'s address plus `offset` (Java's `new WrappedMemBuffer(buf, offset)`, detached from
/// `buf`'s lifetime). Bytes `buf` cannot supply are simply absent from the snapshot, which reads
/// them the way `SleighParserContext` treats unavailable memory.
///
/// # Errors
/// [`MemoryAccessException`] if `offset` moves the address out of its space.
pub fn snapshot_mem_buffer(
    buf: &dyn MemBuffer,
    offset: i32,
) -> Result<Arc<dyn MemBuffer>, MemoryAccessException> {
    let addr = buf
        .get_address()
        .add(offset as i64)
        .map_err(|e| MemoryAccessException::new(e.to_string()))?;
    let mut bytes = vec![0u8; SNAPSHOT_SIZE];
    let n = buf.get_bytes(&mut bytes, offset);
    bytes.truncate(n);
    Ok(Arc::new(ByteMemBufferImpl::with_memory(
        buf.get_memory(),
        addr,
        bytes,
        buf.is_big_endian(),
    )))
}

/// A pending change to global context. Port of `SleighParserContext.ContextSet`.
#[derive(Clone, Debug)]
pub struct ContextSet {
    /// Id of the symbol that resolves to the address where the set takes effect (`sym`).
    pub sym: i32,
    /// Context word being affected (`num`).
    pub num: i32,
    /// Bits being affected (`mask`).
    pub mask: i32,
    /// New value being set (`value`).
    pub value: i32,
    /// Tree node of the constructor making the change (`point`).
    pub point: usize,
}

/// All the recovered context for a single instruction. See the module docs.
///
/// Port of `ghidra.app.plugin.processors.sleigh.SleighParserContext`.
pub struct SleighParserContext {
    mem_buffer: Option<Arc<dyn MemBuffer>>,
    /// Address of start of instruction (`inst_start`).
    addr: Address,
    /// Address of next instruction (`inst_next`).
    next_instr_addr: Option<Address>,
    /// Address of instruction after next instruction (`inst_next2`), computed on first use.
    next2_inst_addr: OnceCell<Address>,
    /// Corresponds to `inst_ref` for call-fixup use.
    ref_addr: Option<Address>,
    /// Corresponds to `inst_dest` for call-fixup use.
    dest_addr: Option<Address>,
    prototype: Option<SleighInstructionPrototype>,
    language: Option<Arc<SleighLanguage>>,
    constant_space: Option<Arc<AddressSpace>>,
    handle_map: RefCell<HashMap<usize, FixedHandle>>,
    /// Pending changes to context (`contextcommit`).
    contextcommit: RefCell<Vec<ContextSet>>,
    /// Packed context bits (`context`).
    context: RefCell<Vec<i32>>,
    tree: RefCell<ConstructTree>,
}

impl SleighParserContext {
    /// The context in which a new instruction is resolved: the constructor tree starts as a bare
    /// root and is built in place. This is the part of Java's
    /// `SleighParserContext(MemBuffer, SleighInstructionPrototype, ProcessorContextView)` that
    /// runs inside the prototype's constructor, before the prototype has a length: `inst_next`
    /// is therefore the instruction's own address, as in Java. `context` holds the packed context
    /// words (`ContextCache.getContext`).
    pub fn for_resolve(
        mem_buffer: Arc<dyn MemBuffer>,
        language: Arc<SleighLanguage>,
        context: Vec<i32>,
    ) -> Self {
        let addr = mem_buffer.get_address();
        Self {
            next_instr_addr: Some(addr.clone()),
            addr,
            mem_buffer: Some(mem_buffer),
            next2_inst_addr: OnceCell::new(),
            ref_addr: None,
            dest_addr: None,
            prototype: None,
            constant_space: Some(language.constant_space()),
            language: Some(language),
            handle_map: RefCell::new(HashMap::new()),
            contextcommit: RefCell::new(Vec::new()),
            context: RefCell::new(context),
            tree: RefCell::new(ConstructTree::new()),
        }
    }

    /// Port of `SleighParserContext(MemBuffer, SleighInstructionPrototype,
    /// ProcessorContextView)` for an already resolved prototype; `context` holds the packed
    /// context words read from the processor context (`ContextCache.getContext`).
    pub fn new(
        mem_buffer: Arc<dyn MemBuffer>,
        prototype: SleighInstructionPrototype,
        context: Vec<i32>,
    ) -> Self {
        let addr = mem_buffer.get_address();
        // no next instruction if this is the last instruction in memory
        let next_instr_addr = addr.add(prototype.get_length() as i64).ok();
        let language = prototype.language().clone();
        Self {
            addr,
            next_instr_addr,
            mem_buffer: Some(mem_buffer),
            next2_inst_addr: OnceCell::new(),
            ref_addr: None,
            dest_addr: None,
            constant_space: Some(language.constant_space()),
            language: Some(language),
            tree: RefCell::new(prototype.tree().clone()),
            prototype: Some(prototype),
            handle_map: RefCell::new(HashMap::new()),
            contextcommit: RefCell::new(Vec::new()),
            context: RefCell::new(context),
        }
    }

    /// Constructor for building precompiled templates. This form does not support use of
    /// `inst_next2`.
    ///
    /// Port of `SleighParserContext(Address, Address, Address, Address)`: `a_addr` is what
    /// `inst_start` resolves to, `n_addr` what `inst_next` resolves to, `r_addr` the special
    /// address associated with the original call and `d_addr` the destination address of the
    /// original call being replaced. `constant_space` is the language's constant space (Java
    /// leaves the field unset here and the walker never asks for it while building snippets).
    pub fn for_snippet(
        a_addr: Address,
        n_addr: Option<Address>,
        r_addr: Option<Address>,
        d_addr: Option<Address>,
        constant_space: Option<Arc<AddressSpace>>,
    ) -> Self {
        Self {
            mem_buffer: None,
            addr: a_addr,
            next_instr_addr: n_addr,
            next2_inst_addr: OnceCell::new(),
            ref_addr: r_addr,
            dest_addr: d_addr,
            prototype: None,
            language: None,
            constant_space,
            handle_map: RefCell::new(HashMap::new()),
            contextcommit: RefCell::new(Vec::new()),
            context: RefCell::new(Vec::new()),
            tree: RefCell::new(ConstructTree::new()),
        }
    }

    /// Generate context specifically for an instruction that has a delay slot: SLEIGH's
    /// `inst_next` then takes the delay slot instruction(s) into account.
    ///
    /// Port of `SleighParserContext(SleighParserContext, int)`. Java shares the original's
    /// handle map, commit list and context array; the p-code emitter only reads them, so this
    /// copies them.
    pub fn for_delay_slot(orig: &SleighParserContext, delay_byte_count: i32) -> Self {
        let length = orig.prototype.as_ref().map_or(0, |p| p.get_length());
        Self {
            mem_buffer: orig.mem_buffer.clone(),
            addr: orig.addr.clone(),
            next_instr_addr: orig.addr.add((length + delay_byte_count) as i64).ok(),
            next2_inst_addr: OnceCell::new(),
            ref_addr: orig.ref_addr.clone(),
            dest_addr: orig.dest_addr.clone(),
            prototype: orig.prototype.clone(),
            language: orig.language.clone(),
            constant_space: orig.constant_space.clone(),
            handle_map: RefCell::new(orig.handle_map.borrow().clone()),
            contextcommit: RefCell::new(orig.contextcommit.borrow().clone()),
            context: RefCell::new(orig.context.borrow().clone()),
            tree: RefCell::new(orig.tree.borrow().clone()),
        }
    }

    /// A context over `mem_buffer` with the given packed context words and no language, for
    /// exercising walkers and patterns in tests.
    #[cfg(test)]
    pub(crate) fn for_tests(mem_buffer: Arc<dyn MemBuffer>, context: Vec<i32>) -> Self {
        let addr = mem_buffer.get_address();
        let mut ctx = Self::for_snippet(addr.clone(), Some(addr), None, None, None);
        ctx.mem_buffer = Some(mem_buffer);
        *ctx.context.borrow_mut() = context;
        ctx
    }

    /// `ctx` reading `mem_buffer`, with the given packed context words, for tests.
    #[cfg(test)]
    pub(crate) fn with_mem_for_tests(
        mut ctx: Self,
        mem_buffer: Arc<dyn MemBuffer>,
        context: Vec<i32>,
    ) -> Self {
        ctx.mem_buffer = Some(mem_buffer);
        *ctx.context.borrow_mut() = context;
        ctx
    }

    /// The prototype this context belongs to (`getPrototype()`), `None` for a context still
    /// being resolved or built for a snippet.
    pub fn get_sleigh_prototype(&self) -> Option<&SleighInstructionPrototype> {
        self.prototype.as_ref()
    }

    /// The language the instruction belongs to, `None` for a snippet context.
    pub fn language(&self) -> Option<&Arc<SleighLanguage>> {
        self.language.as_ref()
    }

    /// The constructor tree this context is walking. See the module docs.
    pub fn tree(&self) -> &RefCell<ConstructTree> {
        &self.tree
    }

    /// Takes the tree built by a resolve, leaving an empty one behind.
    pub(crate) fn take_tree(&self) -> ConstructTree {
        std::mem::take(&mut *self.tree.borrow_mut())
    }

    /// Context commits recorded by a normal instruction parse. Port of the package-private
    /// `getContextCommits()`.
    pub fn get_context_commits(&self) -> Vec<ContextSet> {
        self.contextcommit.borrow().clone()
    }

    /// Records a pending context change to be applied at the address `sym` resolves to.
    ///
    /// Port of `addCommit(ConstructState, TripleSymbol, int, int)`; `point` is the tree node of
    /// the constructor making the change and `sym` the id of the symbol.
    pub fn add_commit(&self, point: usize, sym: i32, num: i32, mask: i32) {
        let value = self.context.borrow()[num as usize] & mask;
        self.contextcommit.borrow_mut().push(ContextSet {
            sym,
            num,
            mask,
            value,
            point,
        });
    }

    /// Applies all pending context commits to `ctx`, then clears them.
    ///
    /// Port of `applyCommits(ProcessorContext)`. Java only writes anything when the processor
    /// context is a `DisassemblerContext`; [`ContextCache::set_context`] takes that type
    /// directly (see its docs), and `builder` constructs the `RegisterValue` it stores.
    ///
    /// # Errors
    /// A [`SleighError`] if a commit's target address cannot be computed.
    pub fn apply_commits(
        &self,
        ctx: &mut dyn DisassemblerContext,
        builder: &dyn RegisterValueBuilder,
    ) -> Result<(), SleighError> {
        if self.contextcommit.borrow().is_empty() {
            return Ok(());
        }
        let language = self
            .language
            .clone()
            .ok_or_else(|| SleighException::with_message("no language to apply commits"))?;
        let context_cache = language.new_context_cache();
        let table = language.get_symbol_table();
        let mut walker = ParserWalker::new(self);
        walker.base_state();
        let commits = self.contextcommit.borrow().clone();
        for set in &commits {
            let hand = match table.find_symbol(set.sym) {
                // value of OperandSymbol is already calculated, find right node
                Some(SleighSymbol::Operand(op)) => {
                    let node = self.tree.borrow().get_sub_state(set.point, op.hand as usize);
                    self.get_fixed_handle(node)
                }
                Some(sym) => {
                    let mut hand = FixedHandle::new();
                    sym.get_fixed_handle(&mut hand, &walker)?;
                    hand
                }
                None => {
                    return Err(SleighException::with_message(format!(
                        "context commit names unknown symbol {}",
                        set.sym
                    ))
                    .into())
                }
            };
            // Java marks this as a hack: addresses that are computed end up in the constant
            // space and we must factor-in the wordsize.
            let mut offset = hand.offset_offset;
            let cur_space = self.addr.space().clone();
            if hand.space.as_ref().map(|s| s.space_type()) == Some(AddressSpaceType::Constant) {
                offset = offset.wrapping_mul(cur_space.unit_size() as i64);
            }
            let address = cur_space.address(offset);
            context_cache.set_context(ctx, builder, address, set.num, set.mask, set.value);
        }
        self.contextcommit.borrow_mut().clear();
        Ok(())
    }

    /// The handle of tree node `construct_state`, created (empty) on first access. Port of
    /// `getFixedHandle(ConstructState)`; returns a copy of the stored handle.
    pub fn get_fixed_handle(&self, construct_state: usize) -> FixedHandle {
        self.handle_map
            .borrow_mut()
            .entry(construct_state)
            .or_default()
            .clone()
    }

    /// Stores the handle of tree node `construct_state` (Java mutates the shared object in
    /// place).
    pub fn set_fixed_handle(&self, construct_state: usize, hand: FixedHandle) {
        self.handle_map.borrow_mut().insert(construct_state, hand);
    }

    /// Address of the current instruction. Port of `getAddr()`.
    pub fn get_addr(&self) -> Address {
        self.addr.clone()
    }

    /// Address of the instruction after this one, or `None` if this context does not support
    /// `inst_next` or the next address falls beyond the end of the address space. Port of
    /// `getNaddr()`.
    pub fn get_naddr(&self) -> Option<Address> {
        self.next_instr_addr.clone()
    }

    /// The address of the instruction after the next instruction, or
    /// [`SpecialAddress::no_address`] if the next instruction cannot be parsed or `inst_next2`
    /// is not supported in this context. Port of `getN2addr()` (memoized, as in Java).
    pub fn get_n2addr(&self) -> Address {
        self.next2_inst_addr
            .get_or_init(|| self.compute_next2_address())
            .clone()
    }

    /// Port of the private `computeNext2Address()`: parses the next instruction, assuming the
    /// same context as the current instruction (a limitation shared with Java, which copies this
    /// context's register value into a fresh `ProcessorContextImpl`), and returns the address
    /// after it.
    fn compute_next2_address(&self) -> Address {
        let (Some(mem), Some(next), Some(language)) =
            (&self.mem_buffer, &self.next_instr_addr, &self.language)
        else {
            return SpecialAddress::no_address(); // not supported without memBuffer for parse
        };
        let offset = next.subtract(&self.addr) as i32;
        let parsed = snapshot_mem_buffer(mem.as_ref(), offset)
            .map_err(SleighError::from)
            .and_then(|nearby| {
                language.parse_prototype(nearby, self.context.borrow().clone(), true)
            });
        match parsed.and_then(|proto| {
            next.add_no_wrap(proto.get_length() as i64)
                .map_err(|e| SleighError::Sleigh(SleighException::with_message(e.to_string())))
        }) {
            Ok(addr) => addr,
            // Unsupported use of inst_next2 or parse failure on next instruction. This CANNOT
            // fall back to inst_next: a jump to inst_next2 intends to *skip* that instruction.
            Err(_) => SpecialAddress::no_address(),
        }
    }

    /// Address space containing the current instruction. Port of `getCurSpace()`.
    pub fn get_cur_space(&self) -> Arc<AddressSpace> {
        self.addr.space().clone()
    }

    /// The constant address space. Port of `getConstSpace()`.
    ///
    /// # Panics
    /// For a snippet context built without one (Java returns `null`).
    pub fn get_const_space(&self) -> Arc<AddressSpace> {
        self.constant_space
            .clone()
            .expect("this parser context has no constant space")
    }

    /// Memory buffer for the current instruction. Port of `getMemBuffer()`.
    pub fn get_mem_buffer(&self) -> Option<&Arc<dyn MemBuffer>> {
        self.mem_buffer.as_ref()
    }

    /// Gets bytes from the instruction stream into an `int` (packed in big endian format).
    /// Uninitialized or undefined memory returns zero byte values. Port of
    /// `getInstructionBytes(int, int, int)`.
    ///
    /// # Errors
    /// [`MemoryAccessException`] if no bytes are available at the first byte when
    /// `offset + bytestart == 0`.
    pub fn get_instruction_bytes(
        &self,
        offset: i32,
        bytestart: i32,
        size: i32,
    ) -> Result<i32, MemoryAccessException> {
        let offset = offset + bytestart;
        let mut bytes = vec![0u8; size.max(0) as usize]; // unavailable bytes stay 0
        let read_size = self.read_bytes(&mut bytes, offset);
        if offset == 0 && read_size == 0 {
            return Err(MemoryAccessException::new("invalid memory"));
        }
        let mut result = 0i32;
        for b in bytes {
            result = result.wrapping_shl(8);
            result |= b as i32;
        }
        Ok(result)
    }

    /// Gets bits from the instruction stream into an `int` (packed in big endian format).
    /// Uninitialized or undefined memory returns zero bit values. Port of
    /// `getInstructionBits(int, int, int)`.
    ///
    /// # Errors
    /// [`MemoryAccessException`] if no bytes are available at the first byte when
    /// `offset + startbit/8 == 0`.
    pub fn get_instruction_bits(
        &self,
        offset: i32,
        startbit: i32,
        size: i32,
    ) -> Result<i32, MemoryAccessException> {
        let offset = offset + startbit / 8;
        let startbit = startbit % 8;
        let bytesize = (startbit + size - 1) / 8 + 1;
        let mut bytes = vec![0u8; bytesize.max(0) as usize]; // unavailable bytes stay 0
        let read_size = self.read_bytes(&mut bytes, offset);
        if offset == 0 && read_size == 0 {
            return Err(MemoryAccessException::new("invalid memory"));
        }
        let mut res = 0i32;
        for b in bytes {
            res = res.wrapping_shl(8);
            res |= b as i32;
        }
        // Move starting bit to highest position, then shift to the bottom of the int
        res = res.wrapping_shl((8 * (4 - bytesize) + startbit) as u32);
        res = (res as u32).wrapping_shr((32 - size) as u32) as i32;
        Ok(res)
    }

    fn read_bytes(&self, bytes: &mut [u8], offset: i32) -> usize {
        match &self.mem_buffer {
            Some(mem) => mem.get_bytes(bytes, offset),
            None => 0,
        }
    }

    /// The processor context as a value of the language's context base register: every bit
    /// masked in, holding the packed context words. `None` if the language has no context
    /// register (or this context has no language).
    ///
    /// Port of `getContextRegisterValue()`. Building a `RegisterValue` from raw bytes is
    /// delegated to `builder`, as [`ContextCache::set_context`] does, since the concrete
    /// `RegisterValue` class is not ported.
    pub fn get_context_register_value(
        &self,
        builder: &dyn RegisterValueBuilder,
    ) -> Option<Box<dyn crate::program::seam_stubs::RegisterValue>> {
        use crate::program::model::lang::language::Language;
        let base = self.language.as_ref()?.get_context_base_register()?;
        let ctx_byte_len = base.minimum_byte_size().max(0) as usize;
        // convert context int words to byte array for RegisterValue use
        let mut ctx_value_bytes = vec![0u8; ctx_byte_len];
        for (i, &word) in self.context.borrow().iter().enumerate() {
            let mut word = word;
            for n in (0..4).rev() {
                let byte_index = i * 4 + n;
                if byte_index < ctx_value_bytes.len() {
                    ctx_value_bytes[byte_index] = word as u8;
                }
                word >>= 8;
            }
        }
        // mask (all bits) followed by the value
        let mut mask_value = vec![0xffu8; ctx_byte_len];
        mask_value.extend_from_slice(&ctx_value_bytes);
        Some(builder.build_register_value(base, mask_value))
    }

    /// Gets bytes from context into an `int`. Port of `getContextBytes(int, int)`.
    pub fn get_context_bytes(&self, bytestart: i32, bytesize: i32) -> i32 {
        let context = self.context.borrow();
        let mut intstart = (bytestart / 4) as usize;
        let Some(&word) = context.get(intstart) else {
            return 0;
        };
        let byte_offset = bytestart % 4;
        let unused_bytes = 4 - bytesize;
        let mut res = word.wrapping_shl((byte_offset * 8) as u32);
        res = (res as u32).wrapping_shr((unused_bytes * 8) as u32) as i32;
        let remaining = bytesize - 4 + byte_offset;
        intstart += 1;
        if remaining > 0 && intstart < context.len() {
            let unused_bytes = 4 - remaining;
            let res2 = (context[intstart] as u32).wrapping_shr((unused_bytes * 8) as u32) as i32;
            res |= res2;
        }
        res
    }

    /// The full set of packed context words. Port of `getContextBytes()`.
    pub fn get_context_words(&self) -> Vec<i32> {
        self.context.borrow().clone()
    }

    /// Gets bits from context into an `int`. Port of `getContextBits(int, int)`.
    ///
    /// Java indexes past the end of an empty context array (an exception); a missing word reads
    /// as zero here.
    pub fn get_context_bits(&self, startbit: i32, bitsize: i32) -> i32 {
        let context = self.context.borrow();
        let mut intstart = (startbit / 32) as usize;
        let Some(&word) = context.get(intstart) else {
            return 0;
        };
        let bit_offset = startbit % 32;
        let unused_bits = 32 - bitsize;
        let mut res = word.wrapping_shl(bit_offset as u32); // Shift startbit to highest position
        res = (res as u32).wrapping_shr(unused_bits as u32) as i32;
        let remaining = bitsize - 32 + bit_offset;
        intstart += 1;
        if remaining > 0 && intstart < context.len() {
            let unused_bits = 32 - remaining;
            let res2 = (context[intstart] as u32).wrapping_shr(unused_bits as u32) as i32;
            res |= res2;
        }
        res
    }

    /// Overwrites the masked bits of context word `i`. Port of `setContextWord(int, int, int)`.
    pub fn set_context_word(&self, i: i32, val: i32, mask: i32) {
        let mut context = self.context.borrow_mut();
        let word = &mut context[i as usize];
        *word = (*word & !mask) | (mask & val);
    }

    /// True if `buf` is the very buffer this context reads from, positioned at this context's
    /// address. Port of `isValid(MemBuffer)` (an identity test).
    pub fn is_valid(&self, buf: &Arc<dyn MemBuffer>) -> bool {
        match &self.mem_buffer {
            Some(mine) => Arc::ptr_eq(mine, buf) && self.addr == buf.get_address(),
            None => false,
        }
    }

    /// The flow reference address (`inst_ref`), for call-fixup use. Port of `getFlowRefAddr()`.
    ///
    /// # Errors
    /// [`SleighException`] if `inst_ref` is undefined in this context.
    pub fn get_flow_ref_addr(&self) -> Result<Address, SleighException> {
        self.ref_addr.clone().ok_or_else(|| {
            SleighException::with_message(format!(
                "Flow reference (inst_ref) is undefined at {}",
                self.get_addr()
            ))
        })
    }

    /// The flow destination address (`inst_dest`), for call-fixup use. Port of
    /// `getFlowDestAddr()`.
    ///
    /// # Errors
    /// [`SleighException`] if `inst_dest` is undefined in this context.
    pub fn get_flow_dest_addr(&self) -> Result<Address, SleighException> {
        self.dest_addr.clone().ok_or_else(|| {
            SleighException::with_message(format!(
                "Flow destination (inst_dest) is undefined at {}",
                self.get_addr()
            ))
        })
    }
}

impl ParserContext for SleighParserContext {
    /// Port of `getPrototype()`.
    ///
    /// # Panics
    /// For a context that has no prototype (one built for a snippet), where Java returns `null`.
    fn get_prototype(&self) -> Arc<dyn InstructionPrototype> {
        Arc::new(
            self.prototype
                .clone()
                .expect("this parser context has no instruction prototype"),
        )
    }

    fn as_any(&self) -> Option<&dyn Any> {
        Some(self)
    }
}

impl crate::program::seam_stubs::ParserContext for SleighParserContext {
    fn get_prototype(&self) -> Arc<dyn InstructionPrototype> {
        ParserContext::get_prototype(self)
    }

    fn as_any(&self) -> Option<&dyn Any> {
        Some(self)
    }
}

/// Reads the packed context words of `ctx` for `language` (Java's
/// `prototype.getContextCache().getContext(processorContext, context)`).
pub fn read_context_words(
    language: &SleighLanguage,
    ctx: &dyn crate::program::model::lang::ProcessorContextView,
) -> Vec<i32> {
    let mut cache = language.new_context_cache();
    let mut words = vec![0i32; cache.get_context_size().max(0) as usize];
    cache.get_context(ctx, &mut words);
    words
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::AddressSpaceType;

    fn ram() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    fn snippet(bytes: &[u8], context: Vec<i32>) -> SleighParserContext {
        let addr = Address::new(ram(), 0x1000);
        let mem: Arc<dyn MemBuffer> =
            Arc::new(ByteMemBufferImpl::new(addr, bytes.to_vec(), true));
        SleighParserContext::for_tests(mem, context)
    }

    #[test]
    fn instruction_bytes_are_packed_big_endian() {
        let ctx = snippet(&[0x12, 0x34, 0x56, 0x78, 0x9a], vec![]);
        assert_eq!(ctx.get_instruction_bytes(0, 0, 4).unwrap(), 0x12345678);
        assert_eq!(ctx.get_instruction_bytes(1, 1, 2).unwrap(), 0x5678);
        // unavailable bytes read as zero
        assert_eq!(ctx.get_instruction_bytes(3, 0, 4).unwrap(), 0x789a0000);
    }

    #[test]
    fn instruction_bits_extract_big_endian_bit_ranges() {
        let ctx = snippet(&[0xa5, 0xf0], vec![]);
        // 0xa5 = 1010_0101: bits 0..3 (msb first) are 1010
        assert_eq!(ctx.get_instruction_bits(0, 0, 4).unwrap(), 0xa);
        assert_eq!(ctx.get_instruction_bits(0, 4, 8).unwrap(), 0x5f);
        assert_eq!(ctx.get_instruction_bits(0, 0, 32).unwrap(), 0xa5f0_0000u32 as i32);
    }

    #[test]
    fn reading_nothing_at_offset_zero_is_an_error() {
        let ctx = snippet(&[], vec![]);
        assert!(ctx.get_instruction_bytes(0, 0, 1).is_err());
        assert!(ctx.get_instruction_bits(0, 0, 8).is_err());
        // past the start, missing bytes are just zero
        assert_eq!(ctx.get_instruction_bytes(1, 0, 1).unwrap(), 0);
    }

    #[test]
    fn context_bits_span_word_boundaries() {
        let ctx = snippet(&[0], vec![0x0000_0003, 0x8000_0000u32 as i32]);
        assert_eq!(ctx.get_context_bits(30, 2), 3);
        // bits 31..32 straddle the two words: 1 then 1
        assert_eq!(ctx.get_context_bits(31, 2), 3);
        assert_eq!(ctx.get_context_bytes(3, 2), 0x0380);
        assert_eq!(ctx.get_context_bits(64, 4), 0);
    }

    #[test]
    fn set_context_word_only_touches_masked_bits() {
        let ctx = snippet(&[0], vec![0x1234_5678]);
        ctx.set_context_word(0, 0x0000_ff00, 0x0000_ff00);
        assert_eq!(ctx.get_context_words(), vec![0x1234_ff78]);
    }

    #[test]
    fn add_commit_captures_the_masked_current_value() {
        let ctx = snippet(&[0], vec![0x0f0f_0f0f]);
        ctx.add_commit(0, 7, 0, 0x00ff_0000);
        let commits = ctx.get_context_commits();
        assert_eq!(commits.len(), 1);
        assert_eq!(commits[0].value, 0x000f_0000);
        assert_eq!(commits[0].sym, 7);
    }

    #[test]
    fn fixed_handles_are_created_on_first_use_and_stored() {
        let ctx = snippet(&[0], vec![]);
        assert!(ctx.get_fixed_handle(3).is_invalid());
        let mut h = FixedHandle::new();
        h.space = Some(ram());
        h.offset_offset = 0x40;
        ctx.set_fixed_handle(3, h.clone());
        assert_eq!(ctx.get_fixed_handle(3), h);
    }

    #[test]
    fn undefined_flow_addresses_are_errors() {
        let ctx = snippet(&[0], vec![]);
        assert!(ctx
            .get_flow_ref_addr()
            .unwrap_err()
            .message()
            .contains("inst_ref"));
        assert!(ctx.get_flow_dest_addr().is_err());
        // snippet contexts cannot compute inst_next2
        assert_eq!(ctx.get_n2addr(), SpecialAddress::no_address());
    }

    #[test]
    fn snapshot_captures_bytes_at_an_offset() {
        let addr = Address::new(ram(), 0x2000);
        let src = ByteMemBufferImpl::new(addr, vec![1, 2, 3, 4], false);
        let snap = snapshot_mem_buffer(&src, 2).unwrap();
        assert_eq!(snap.get_address().offset(), 0x2002);
        let mut b = [0u8; 4];
        assert_eq!(snap.get_bytes(&mut b, 0), 2);
        assert_eq!(&b[..2], &[3, 4]);
    }
}

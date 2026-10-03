//! The program's code-unit store: the concrete half of Java's `CodeManager` that holds the
//! instructions of a `ProgramDB`, keyed by address, on the instruction arena
//! (`OWNERSHIP_MIGRATION.md`, "Instruction/CodeUnit arena").
//!
//! An instruction is stored as an [`InstructionRecord`] (address, prototype, overrides) plus the
//! context register value it was decoded under, and named by a `Copy` [`InstructionId`] — the
//! record key, monotonic and never reused. Behaviour is answered by resolving the record against
//! a [`ProgramInstructionSnapshot`] (the instruction's bytes read from program memory plus its
//! context) through an [`InstructionView`]; nothing in the store holds a back-reference to the
//! program.
//!
//! Undefined data is implied, as in Java: every address of memory not covered by an instruction
//! is an undefined 1-byte code unit (`??` / `XXh`). [`ListingStore::code_units`] walks a range in
//! address order yielding [`CodeUnitSummary`]s, the flattened, UI-facing description of each code
//! unit.
//!
//! # What of `CodeManager` is here
//!
//! `createCodeUnit(Address, InstructionPrototype, MemBuffer, ProcessorContextView, int)` with its
//! `checkValidAddressRange` conflict checks and messages, `getInstructionAt` /
//! `getInstructionContaining` / `getInstructionAfter` / `getInstructionBefore`,
//! `getNumInstructions`, `isUndefined`, and `clearCodeUnits` for instructions. Defined data
//! (`createCodeUnit(Address, DataType, int)`), comments, properties, and the change events
//! Java fires through the program are not in this store yet; the [`CodeManager`] trait remains the
//! full Java surface.
//!
//! [`CodeManager`]: super::code_manager::CodeManager

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use crate::app::util::pseudo_instruction::byte_cache_size;
use crate::program::disassemble::DisassemblerInstructionContext;
use crate::program::model::address::{Address, AddressSet, AddressSetView};
use crate::program::model::lang::instruction_context::InstructionContextError;
use crate::program::model::lang::instruction_prototype::GetPseudoParserContextError;
use crate::program::model::lang::parser_context::ParserContext;
use crate::program::model::lang::processor_context_view::ProcessorContextView;
use crate::program::model::lang::register_value::RegisterValue;
use crate::program::model::lang::sleigh::SleighLanguage;
use crate::program::model::lang::unknown_context_exception::UnknownContextException;
use crate::program::model::listing::instruction_record::{
    InstructionRecord, InstructionSnapshot, InstructionView, SharedPrototype,
};
use crate::program::model::mem::{ByteMemBufferImpl, MemBuffer, Memory, MemoryAccessException};
use crate::program::util::CodeUnitInsertionException;

/// Names an instruction in a [`ListingStore`]: the record key, assigned in creation order and
/// never reused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct InstructionId(u64);

/// What the store keeps per instruction.
struct StoredInstruction {
    record: InstructionRecord,
    /// The base context register value the instruction was decoded under (Java saves it to the
    /// program context over the instruction's range).
    context: Option<RegisterValue>,
}

/// The instructions of one program, in address order. See the module docs.
pub struct ListingStore {
    language: Arc<SleighLanguage>,
    next_id: u64,
    records: HashMap<InstructionId, StoredInstruction>,
    by_address: BTreeMap<Address, InstructionId>,
}

impl ListingStore {
    /// An empty listing for a program in `language`.
    pub fn new(language: Arc<SleighLanguage>) -> Self {
        ListingStore { language, next_id: 1, records: HashMap::new(), by_address: BTreeMap::new() }
    }

    /// Creates an instruction at `address` decoded by `prototype` under `context` (the base
    /// context register value, if the language has one). A `length` of 0 uses the prototype's
    /// length; a shorter positive `length` becomes the record's length override.
    ///
    /// Port of `CodeManager.createCodeUnit(Address, InstructionPrototype, MemBuffer,
    /// ProcessorContextView, int)`: the bytes are the program's (`memory`), not a caller buffer.
    ///
    /// # Errors
    /// A [`CodeUnitInsertionException`], with Java's messages, when the instruction would run off
    /// its address space or out of `memory`, overlap an existing instruction, or `length` is
    /// longer than the prototype.
    pub fn create_instruction(
        &mut self,
        memory: &dyn Memory,
        address: Address,
        prototype: SharedPrototype,
        context: Option<RegisterValue>,
        length: i32,
    ) -> Result<InstructionId, CodeUnitInsertionException> {
        let parsed_length = prototype.get_length();
        if length < 0 || length > parsed_length {
            // InstructionDB.checkLengthOverride
            return Err(CodeUnitInsertionException::new(format!(
                "Invalid length override {length} for instruction of length {parsed_length}"
            )));
        }
        let length = if length == 0 { parsed_length } else { length };
        let end = address
            .add_no_wrap(i64::from(length) - 1)
            .map_err(|_| CodeUnitInsertionException::new("Code unit would extend beyond Address space"))?;
        self.check_valid_address_range(memory, &address, &end)?;

        let mut record = InstructionRecord::new(address.clone(), prototype);
        if length != parsed_length {
            record.set_length_override(length);
        }
        let id = InstructionId(self.next_id);
        self.next_id += 1;
        self.records.insert(id, StoredInstruction { record, context });
        self.by_address.insert(address, id);
        Ok(id)
    }

    /// Port of the private `CodeManager.checkValidAddressRange` for instructions.
    fn check_valid_address_range(
        &self,
        memory: &dyn Memory,
        start: &Address,
        end: &Address,
    ) -> Result<(), CodeUnitInsertionException> {
        let length = end.subtract(start) + 1;
        let mut addr = start.clone();
        loop {
            if !memory.contains(&addr) {
                return Err(CodeUnitInsertionException::new(format!(
                    "Insufficent memory at address {start} (length: {length} bytes)"
                )));
            }
            if &addr == end {
                break;
            }
            addr = addr.add_wrap(1);
        }
        let conflict = self
            .by_address
            .range(start.clone()..=end.clone())
            .next()
            .map(|(_, id)| *id)
            .or_else(|| self.instruction_containing(start));
        if let Some(id) = conflict {
            let record = &self.records[&id].record;
            return Err(CodeUnitInsertionException::new(format!(
                "Conflicting instruction exists at address {} to {}",
                record.address(),
                Self::max_address(record)
            )));
        }
        Ok(())
    }

    fn max_address(record: &InstructionRecord) -> Address {
        record.address().add_wrap(i64::from(record.length()) - 1)
    }

    /// The instruction starting at `address`. Port of `CodeManager.getInstructionAt`.
    pub fn instruction_at(&self, address: &Address) -> Option<InstructionId> {
        self.by_address.get(address).copied()
    }

    /// The instruction whose range contains `address`. Port of
    /// `CodeManager.getInstructionContaining(Address, boolean)` (no length-override pass-through).
    pub fn instruction_containing(&self, address: &Address) -> Option<InstructionId> {
        let (start, id) = self.by_address.range(..=address.clone()).next_back()?;
        if !start.same_address_space(address) {
            return None;
        }
        let record = &self.records[id].record;
        (Self::max_address(record) >= *address).then_some(*id)
    }

    /// The first instruction starting after `address`. Port of `CodeManager.getInstructionAfter`.
    pub fn instruction_after(&self, address: &Address) -> Option<InstructionId> {
        use std::ops::Bound::{Excluded, Unbounded};
        self.by_address.range((Excluded(address.clone()), Unbounded)).next().map(|(_, id)| *id)
    }

    /// The last instruction starting before `address`. Port of
    /// `CodeManager.getInstructionBefore`.
    pub fn instruction_before(&self, address: &Address) -> Option<InstructionId> {
        self.by_address.range(..address.clone()).next_back().map(|(_, id)| *id)
    }

    /// The instructions starting in `[start, end]`, in address order.
    pub fn instructions_in<'a>(
        &'a self,
        start: &Address,
        end: &Address,
    ) -> impl Iterator<Item = InstructionId> + 'a {
        self.by_address.range(start.clone()..=end.clone()).map(|(_, id)| *id)
    }

    /// The number of instructions. Port of `CodeManager.getNumInstructions`.
    pub fn num_instructions(&self) -> usize {
        self.records.len()
    }

    /// Whether no instruction intersects `[start, end]`. Port of `CodeManager.isUndefined` (the
    /// store has no defined data).
    pub fn is_undefined(&self, start: &Address, end: &Address) -> bool {
        self.by_address.range(start.clone()..=end.clone()).next().is_none()
            && self.instruction_containing(start).is_none()
    }

    /// The addresses of `set` in initialized memory that no instruction covers. Port of
    /// `CodeManager.getUndefinedRanges(AddressSetView, boolean initializedMemoryOnly = true,
    /// TaskMonitor)` (the store has no defined data).
    pub fn undefined_ranges(&self, memory: &dyn Memory, set: &dyn AddressSetView) -> AddressSet {
        let mut undefined = set.intersect(&*memory.get_all_initialized_address_set());
        for range in set.address_ranges() {
            let (min, max) = (range.min_address(), range.max_address());
            let first = self.instruction_containing(min).into_iter();
            for id in first.chain(self.instructions_in(min, max)) {
                let record = &self.records[&id].record;
                undefined.delete_range(record.address(), &Self::max_address(record));
            }
        }
        undefined
    }

    /// Removes every instruction intersecting `[start, end]`. Port of
    /// `CodeManager.clearCodeUnits(Address, Address, boolean, TaskMonitor)` for instructions,
    /// without clearing context.
    pub fn clear_code_units(&mut self, start: &Address, end: &Address) {
        let mut doomed: Vec<Address> =
            self.by_address.range(start.clone()..=end.clone()).map(|(a, _)| a.clone()).collect();
        if let Some(id) = self.instruction_containing(start) {
            doomed.push(self.records[&id].record.address().clone());
        }
        for addr in doomed {
            if let Some(id) = self.by_address.remove(&addr) {
                self.records.remove(&id);
            }
        }
    }

    /// The record of `id`.
    ///
    /// # Panics
    /// If `id` is not (or no longer) in this store.
    pub fn record(&self, id: InstructionId) -> &InstructionRecord {
        &self.entry(id).record
    }

    /// The context register value `id` was decoded under.
    ///
    /// # Panics
    /// As [`ListingStore::record`].
    pub fn context_value(&self, id: InstructionId) -> Option<&RegisterValue> {
        self.entry(id).context.as_ref()
    }

    fn entry(&self, id: InstructionId) -> &StoredInstruction {
        self.records.get(&id).unwrap_or_else(|| panic!("{id:?} is not in this listing"))
    }

    /// The snapshot `id` is resolved against: its bytes read from `memory` now, and its context.
    /// Build an [`InstructionView`] over it (`InstructionView::new(store.record(id), &snapshot)`)
    /// to ask the instruction anything.
    ///
    /// # Panics
    /// As [`ListingStore::record`].
    pub fn snapshot(&self, id: InstructionId, memory: &dyn Memory) -> ProgramInstructionSnapshot {
        let entry = self.entry(id);
        let address = entry.record.address().clone();
        let mut bytes = vec![0u8; byte_cache_size(entry.record.prototype().as_ref()).max(0) as usize];
        let read = memory.get_bytes(&address, &mut bytes);
        bytes.truncate(read);
        ProgramInstructionSnapshot {
            mem: ByteMemBufferImpl::new(address, bytes, self.language.is_big_endian()),
            context: DisassemblerInstructionContext::new(Arc::clone(&self.language), entry.context.clone()),
            own_context: std::cell::OnceCell::new(),
        }
    }

    /// The code units intersecting `[start, end]` of `memory`, in address order: each
    /// instruction (the one containing `start` included), and an undefined 1-byte unit at every
    /// other memory address. Addresses outside memory are skipped. See [`CodeUnitSummary`].
    pub fn code_units<'a>(&'a self, memory: &'a dyn Memory, start: &Address, end: &Address) -> CodeUnits<'a> {
        let mut blocks: Vec<(Address, Address, bool)> = memory
            .get_blocks()
            .iter()
            .map(|b| (b.get_start(), b.get_end(), b.is_initialized()))
            .filter(|(s, e, _)| s.same_address_space(start) && *e >= *start && *s <= *end)
            .collect();
        blocks.sort_by(|a, b| a.0.cmp(&b.0));
        let first = self
            .instruction_containing(start)
            .map(|id| self.records[&id].record.address().clone())
            .unwrap_or_else(|| start.clone());
        CodeUnits { store: self, memory, blocks, cursor: Some(first), end: end.clone() }
    }

    /// The summaries of the instructions starting in `[start, end]`, in address order, without
    /// walking the undefined bytes between them (what a listing snapshot of a large program
    /// wants).
    pub fn instruction_summaries<'a>(
        &'a self,
        memory: &'a dyn Memory,
        start: &Address,
        end: &Address,
    ) -> impl Iterator<Item = CodeUnitSummary> + 'a {
        self.instructions_in(start, end).map(move |id| self.instruction_summary(id, memory))
    }

    /// The summary of instruction `id`.
    ///
    /// # Panics
    /// As [`ListingStore::record`].
    pub fn instruction_summary(&self, id: InstructionId, memory: &dyn Memory) -> CodeUnitSummary {
        let record = self.record(id);
        let snapshot = self.snapshot(id, memory);
        let view = InstructionView::new(record, &snapshot);
        let length = record.length().max(1) as usize;
        let mut bytes = vec![0u8; length];
        let read = memory.get_bytes(record.address(), &mut bytes);
        bytes.truncate(read);
        // one pass over the operands, laid out as InstructionView::display_string does
        let mnemonic = view.mnemonic();
        let num_operands = view.num_operands();
        let mut operands = Vec::with_capacity(num_operands.max(0) as usize);
        let mut operand_text = view.separator(0).unwrap_or_default();
        for i in 0..num_operands {
            let rep = view.default_operand_representation(i);
            operand_text.push_str(&rep);
            operands.push(rep);
            if let Some(sep) = view.separator(i + 1) {
                operand_text.push_str(&sep);
            }
        }
        CodeUnitSummary {
            address: record.address().clone(),
            length,
            bytes,
            kind: CodeUnitKind::Instruction(id),
            mnemonic,
            operands,
            operand_text,
        }
    }
}

/// The snapshot a program instruction is resolved against: its bytes (read from program memory
/// when the snapshot was taken) and the context it was decoded under.
pub struct ProgramInstructionSnapshot {
    mem: ByteMemBufferImpl,
    context: DisassemblerInstructionContext,
    /// The instruction's own parser context, built on first use: every prototype query asks
    /// for it, and building it dominates the cost of describing an instruction.
    own_context: std::cell::OnceCell<Option<Box<dyn ParserContext>>>,
}

impl InstructionSnapshot for ProgramInstructionSnapshot {
    fn mem_buffer(&self) -> &dyn MemBuffer {
        &self.mem
    }

    /// Built once per snapshot and handed out as copies ([`ParserContext::clone_box`]); a
    /// context that cannot be copied is built on every call.
    fn own_parser_context(&self, record: &InstructionRecord) -> Result<Box<dyn ParserContext>, MemoryAccessException> {
        if let Some(cached) = self.own_context.get() {
            if let Some(copy) = cached.as_ref().and_then(|context| context.clone_box()) {
                return Ok(copy);
            }
            return record.prototype().get_parser_context(&self.mem, &self.context);
        }
        let built = record.prototype().get_parser_context(&self.mem, &self.context)?;
        let _ = self.own_context.set(built.clone_box());
        Ok(built)
    }

    fn processor_context(&self) -> &dyn ProcessorContextView {
        &self.context
    }

    /// A delay-slot or cross-build instruction parsed out of this instruction's cached bytes, as
    /// `PseudoInstruction` does (Java's `InstructionDB` asks the listing; the bytes are the same).
    fn parser_context_at(
        &self,
        record: &InstructionRecord,
        address: &Address,
    ) -> Result<Box<dyn ParserContext>, InstructionContextError> {
        record
            .prototype()
            .get_pseudo_parser_context(address, &self.mem, &self.context)
            .map_err(|e| match e {
                GetPseudoParserContextError::UnknownContext(e) => e.into(),
                GetPseudoParserContextError::MemoryAccess(e) => e.into(),
                _ => UnknownContextException::with_message(format!(
                    "Could not generate ParserContext for instruction at: {address}"
                ))
                .into(),
            })
    }
}

/// What kind of code unit a [`CodeUnitSummary`] describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeUnitKind {
    /// An instruction in the store.
    Instruction(InstructionId),
    /// An undefined byte (Java's `DefaultDataType`, mnemonic `??`).
    Undefined,
}

/// One code unit, flattened for display.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeUnitSummary {
    /// The code unit's (minimum) address.
    pub address: Address,
    /// Its length in bytes.
    pub length: usize,
    /// Its bytes; shorter than `length` (empty for uninitialized memory) where unreadable.
    pub bytes: Vec<u8>,
    /// Instruction or undefined.
    pub kind: CodeUnitKind,
    /// The mnemonic: the instruction's, or `??` for undefined data.
    pub mnemonic: String,
    /// Each operand's default representation (`getDefaultOperandRepresentation`); for undefined
    /// data, the one value representation (`6Ah`, or `??` if unreadable).
    pub operands: Vec<String>,
    /// Everything after the mnemonic as Java's `toString` lays it out, separators included
    /// (`RAX,qword ptr [0x1000]`).
    pub operand_text: String,
}

impl CodeUnitSummary {
    /// Whether this is an instruction.
    pub fn is_instruction(&self) -> bool {
        matches!(self.kind, CodeUnitKind::Instruction(_))
    }

    fn undefined(address: Address, byte: Option<u8>) -> Self {
        // DefaultDataType.getMnemonic / Undefined1DataType.getRepresentation
        let value = byte.map_or_else(|| "??".to_string(), |b| format!("{b:02X}h"));
        CodeUnitSummary {
            address,
            length: 1,
            bytes: byte.into_iter().collect(),
            kind: CodeUnitKind::Undefined,
            mnemonic: "??".to_string(),
            operands: vec![value.clone()],
            operand_text: value,
        }
    }
}

/// The code units of a range; see [`ListingStore::code_units`].
pub struct CodeUnits<'a> {
    store: &'a ListingStore,
    memory: &'a dyn Memory,
    /// The memory blocks intersecting the range: start, end, initialized.
    blocks: Vec<(Address, Address, bool)>,
    cursor: Option<Address>,
    end: Address,
}

impl Iterator for CodeUnits<'_> {
    type Item = CodeUnitSummary;

    fn next(&mut self) -> Option<CodeUnitSummary> {
        loop {
            let cur = self.cursor.take()?;
            if cur > self.end {
                return None;
            }
            let Some(&(_, ref block_end, initialized)) =
                self.blocks.iter().find(|(s, e, _)| *s <= cur && cur <= *e)
            else {
                // skip to the next block, if any
                self.cursor = self.blocks.iter().map(|(s, _, _)| s).find(|s| **s > cur).cloned();
                continue;
            };
            let block_end = block_end.clone();
            if let Some(id) = self.store.instruction_at(&cur) {
                let summary = self.store.instruction_summary(id, self.memory);
                self.cursor = cur.add_no_wrap(summary.length as i64).ok();
                return Some(summary);
            }
            let byte = if initialized { self.memory.get_byte(&cur).ok() } else { None };
            self.cursor = if cur >= block_end { cur.next().ok() } else { Some(cur.add_wrap(1)) };
            return Some(CodeUnitSummary::undefined(cur, byte));
        }
    }
}

#[cfg(test)]
mod tests;

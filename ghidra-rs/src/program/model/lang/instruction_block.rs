//! Port of `ghidra.program.model.lang.InstructionBlock`.
//!
//! A run of consecutive (fall-through) instructions, as the disassembler produces them, together
//! with the flows leaving it and at most one error that terminated it. Blocks are gathered into an
//! [`InstructionSet`](super::instruction_set::InstructionSet) to be laid down in a program, or
//! returned on their own by
//! [`Disassembler::pseudo_disassemble_block`](crate::program::disassemble::Disassembler::pseudo_disassemble_block).
//!
//! # Shape
//!
//! Java's `InstructionBlock` is a concrete class (`shape_rules.py`: struct). It stores
//! `Instruction`s, and every instruction a real caller puts in one is a `PseudoInstruction` the
//! disassembler just decoded; the block is generic over that element type `I` so it owns its
//! instructions outright (they are ephemeral values with no id, per `OWNERSHIP_MIGRATION.md`,
//! "Instruction/CodeUnit arena": "their ephemeral container is `InstructionBlock`").
//!
//! The [`InstructionError`] a block raises no longer points back at the block (see that module's
//! docs); the block owns it.

use std::collections::HashMap;
use std::fmt;

use crate::program::model::address::Address;
use crate::program::model::lang::instruction_block_flow::InstructionBlockFlow;
use crate::program::model::lang::instruction_error::{InstructionError, InstructionErrorType};
use crate::program::model::lang::register_value::RegisterValue;
use crate::program::model::listing::Instruction;

/// A block of consecutive instructions. Used as part of an
/// [`InstructionSet`](super::instruction_set::InstructionSet) to be added to the program.
///
/// Port of `ghidra.program.model.lang.InstructionBlock`; see the module docs.
pub struct InstructionBlock<I> {
    is_start_of_flow: bool,
    start_addr: Address,
    max_address: Option<Address>,
    flow_from: Option<Address>,
    last_instruction_address: Option<Address>,
    fallthrough_address: Option<Address>,
    /// Java's `LinkedHashMap<Address, Instruction>`: the instructions in insertion order, plus
    /// an index by minimum address.
    instructions: Vec<I>,
    instruction_index: HashMap<Address, usize>,
    flow_addresses: Vec<Address>,
    block_flows: Option<Vec<InstructionBlockFlow>>,
    instruction_error: Option<InstructionError>,
    instructions_added_count: i32,
}

impl<I> InstructionBlock<I> {
    /// Port of `InstructionBlock(Address)`: an empty block starting at `start_addr`.
    pub fn new(start_addr: Address) -> Self {
        InstructionBlock {
            is_start_of_flow: false,
            start_addr,
            max_address: None,
            flow_from: None,
            last_instruction_address: None,
            fallthrough_address: None,
            instructions: Vec::new(),
            instruction_index: HashMap::new(),
            flow_addresses: Vec::new(),
            block_flows: None,
            instruction_error: None,
            instructions_added_count: 0,
        }
    }

    /// Allows the block to be tagged as start of flow to force the `InstructionSet` iterator to
    /// treat it as a flow start. This method should not be used after this block has been added
    /// to an `InstructionSet`.
    pub fn set_start_of_flow(&mut self, is_start: bool) {
        self.is_start_of_flow = is_start;
    }

    /// True if this block should be treated as the start of a new flow when added to an
    /// `InstructionSet`.
    pub fn is_flow_start(&self) -> bool {
        self.is_start_of_flow
    }

    /// The minimum/start address of the block.
    pub fn get_start_address(&self) -> Address {
        self.start_addr.clone()
    }

    /// The maximum address of the block, or the start address if the block is empty.
    pub fn get_max_address(&self) -> Address {
        self.max_address.clone().unwrap_or_else(|| self.start_addr.clone())
    }

    /// The instruction at the specified address within this block, or `None` if not found.
    pub fn get_instruction_at(&self, address: &Address) -> Option<&I> {
        self.instruction_index.get(address).map(|&i| &self.instructions[i])
    }

    /// Adds a block flow specified by an [`InstructionBlockFlow`]. These flows include all calls,
    /// branches, and fall-throughs and may span across multiple `InstructionSet`s; they are not
    /// used by the block flow iterator within the associated `InstructionSet`.
    pub fn add_block_flow(&mut self, block_flow: InstructionBlockFlow) {
        self.block_flows.get_or_insert_with(Vec::new).push(block_flow);
    }

    /// Adds a branch type flow to this instruction block, used by the block flow iterator of the
    /// associated `InstructionSet`.
    pub fn add_branch_flow(&mut self, destination_address: Address) {
        self.flow_addresses.push(destination_address);
    }

    /// Sets the fall-through address for this block, used by the block flow iterator of the
    /// associated `InstructionSet`. The fallthrough should not be set if it is added as a block
    /// flow.
    pub fn set_fall_through(&mut self, fallthrough_address: Option<Address>) {
        self.fallthrough_address = fallthrough_address;
    }

    /// All of the branch flows that were added to this instruction block and flow to other
    /// blocks within the associated `InstructionSet`.
    pub fn get_branch_flows(&self) -> &[Address] {
        &self.flow_addresses
    }

    /// All block flows that were added to this instruction block, or `None` if none were ever
    /// added. NOTE: these flows may not be contained within the associated `InstructionSet`.
    pub fn get_block_flows(&self) -> Option<&[InstructionBlockFlow]> {
        self.block_flows.as_deref()
    }

    /// The fallthrough address, or `None` if there is no fall-through.
    pub fn get_fall_through(&self) -> Option<Address> {
        self.fallthrough_address.clone()
    }

    /// Sets this block to have an instruction error.
    ///
    /// # Arguments
    /// * `error_type` - the type of instruction error/conflict
    /// * `intended_instruction_address` - address of intended instruction which failed to be
    ///   created
    /// * `conflict_address` - the address of the existing code unit that is preventing the
    ///   instruction in this block from being laid down (required for CODE_UNIT or DUPLICATE
    ///   conflict errors)
    /// * `flow_from_address` - the flow-from instruction address, or `None` if unknown
    /// * `message` - a message that describes the conflict to a user
    ///
    /// # Panics
    /// If `error_type` is [`InstructionErrorType::Parse`] (Java's `IllegalArgumentException`:
    /// "use setParseConflict for PARSE conflicts").
    pub fn set_instruction_error(
        &mut self,
        error_type: InstructionErrorType,
        intended_instruction_address: Address,
        conflict_address: Option<Address>,
        flow_from_address: Option<Address>,
        message: String,
    ) {
        if error_type == InstructionErrorType::Parse {
            panic!("use setParseConflict for PARSE conflicts");
        }
        self.instruction_error = Some(InstructionError::new(
            error_type,
            intended_instruction_address,
            conflict_address,
            flow_from_address,
            message,
        ));
    }

    /// Set instruction memory error.
    pub fn set_instruction_memory_error(
        &mut self,
        instr_addr: Address,
        flow_from_addr: Option<Address>,
        error_msg: String,
    ) {
        self.set_instruction_error(
            InstructionErrorType::Memory,
            instr_addr.clone(),
            Some(instr_addr),
            flow_from_addr,
            error_msg,
        );
    }

    /// Set inconsistent instruction prototype CODE_UNIT conflict.
    pub fn set_inconsistent_prototype_conflict(
        &mut self,
        instr_addr: Address,
        flow_from_addr: Option<Address>,
    ) {
        let message = format!(
            "Multiple flows produced inconsistent instruction prototype at {instr_addr} - possibly due to inconsistent context"
        );
        self.set_instruction_error(
            InstructionErrorType::InstructionConflict,
            instr_addr.clone(),
            Some(instr_addr),
            flow_from_addr,
            message,
        );
    }

    /// Set offcut-instruction or data CODE_UNIT conflict.
    ///
    /// # Arguments
    /// * `code_unit_addr` - existing instruction/data address
    /// * `new_instr_addr` - new disassembled instruction address
    /// * `flow_from_addr` - flow-from address
    /// * `is_instruction` - true if conflict is due to offcut-instruction, otherwise data is
    ///   assumed
    /// * `is_offcut` - true if conflict is due to offcut instruction
    pub fn set_code_unit_conflict(
        &mut self,
        code_unit_addr: Address,
        new_instr_addr: Address,
        flow_from_addr: Option<Address>,
        is_instruction: bool,
        is_offcut: bool,
    ) {
        // NOTE: CodeManager relies on conflict address being the address of the existing code
        // unit which triggered the conflict - any conflict bookmark on an undefined code unit
        // runs the risk of becoming offcut within a subsequent larger code unit.
        let error_type = if is_instruction {
            if is_offcut {
                InstructionErrorType::OffcutInstruction
            } else {
                InstructionErrorType::InstructionConflict
            }
        } else {
            InstructionErrorType::DataConflict
        };
        let message = format!(
            "Failed to disassemble at {new_instr_addr} due to conflicting {} at {code_unit_addr}",
            if is_instruction { "instruction" } else { "data" },
        );
        self.set_instruction_error(
            error_type,
            new_instr_addr,
            Some(code_unit_addr),
            flow_from_addr,
            message,
        );
    }

    /// Sets this block to have a PARSE conflict, meaning the instruction parse failed at the
    /// specified conflict address using the specified context value.
    ///
    /// # Arguments
    /// * `conflict_address` - the address at which the parse failed
    /// * `context_value` - the context-register value used during the failed parse attempt
    ///   (`None`, Java's `null`, for a language without a context register)
    /// * `flow_from_address` - the flow-from instruction address, or `None`
    /// * `message` - a message that describes the conflict to a user
    pub fn set_parse_conflict(
        &mut self,
        conflict_address: Address,
        context_value: Option<RegisterValue>,
        flow_from_address: Option<Address>,
        message: String,
    ) {
        self.instruction_error = Some(InstructionError::new_parse_error(
            context_value,
            conflict_address,
            flow_from_address,
            message,
        ));
    }

    /// Clears any conflict associated with this block.
    pub fn clear_conflict(&mut self) {
        self.instruction_error = None;
    }

    /// The current conflict associated with this block, if any.
    pub fn get_instruction_conflict(&self) -> Option<&InstructionError> {
        self.instruction_error.as_ref()
    }

    /// The instructions in this block, in the order they were added. Port of `iterator()`.
    pub fn iter(&self) -> std::slice::Iter<'_, I> {
        self.instructions.iter()
    }

    /// Address of the last instruction contained within this block (delay-slot instructions
    /// excluded), or `None` if none has been added yet.
    pub fn get_last_instruction_address(&self) -> Option<Address> {
        self.last_instruction_address.clone()
    }

    /// True if no instructions exist within this block.
    pub fn is_empty(&self) -> bool {
        self.instructions.is_empty()
    }

    /// Number of instructions contained within this block.
    pub fn get_instruction_count(&self) -> usize {
        self.instructions.len()
    }

    /// Number of instructions which were added to the program successfully.
    pub fn get_instructions_added_count(&self) -> i32 {
        self.instructions_added_count
    }

    /// Set the number of instructions which were added to the program.
    pub fn set_instructions_added_count(&mut self, count: i32) {
        self.instructions_added_count = count;
    }

    /// The flow-from address, or `None` if unset.
    pub fn get_flow_from_address(&self) -> Option<Address> {
        self.flow_from.clone()
    }

    /// Sets the flow-from address.
    pub fn set_flow_from_address(&mut self, flow_from: Option<Address>) {
        self.flow_from = flow_from;
    }

    /// True if this block currently has an associated instruction error/conflict.
    pub fn has_instruction_error(&self) -> bool {
        self.instruction_error.is_some()
    }
}

impl<I: Instruction> InstructionBlock<I> {
    /// Find the first instruction within this block which intersects the specified range. This
    /// method should be used sparingly since it uses a brute-force search. Returns `None` if no
    /// instruction within this block intersects the range.
    ///
    /// Java's loop keeps the intersecting instruction with the smallest address, preferring the
    /// later one on a tie (which cannot happen: instructions are keyed by address).
    pub fn find_first_intersecting_instruction(&self, min: &Address, max: &Address) -> Option<&I> {
        let mut intersect_instr: Option<&I> = None;
        for instr in &self.instructions {
            let instr_min = instr.get_min_address();
            if instr_min > *max {
                continue;
            }
            let instr_max = instr.get_max_address();
            if instr_max < *min {
                continue;
            }
            if let Some(current) = intersect_instr {
                if current.get_min_address() < instr_min {
                    continue;
                }
            }
            intersect_instr = Some(instr);
        }
        intersect_instr
    }

    /// Adds an instruction to this block. If the block is not empty, the newly added instruction
    /// must be directly after the current block maximum address. In other words, all
    /// instructions in the block must be consecutive.
    ///
    /// # Panics
    /// If the new instruction does not start the block (when empty) or immediately follow the
    /// last instruction added (Java's `IllegalArgumentException`).
    pub fn add_instruction(&mut self, instruction: I) {
        let instruction_min_addr = instruction.get_min_address();
        match &self.max_address {
            None => {
                if instruction_min_addr != self.start_addr {
                    panic!(
                        "First instruction to block had address {}, expected address {}",
                        instruction_min_addr, self.start_addr
                    );
                }
            }
            Some(max_address) => {
                // Java's `maxAddress.isSuccessor(instructionMinAddr)`: does the new instruction
                // immediately follow the block? This crate's `Address::is_successor(other)` asks
                // whether `self` immediately follows `other`.
                if !instruction_min_addr.is_successor(max_address) {
                    panic!(
                        "Newly added instruction at address {} is not the immediate succesor to address {}",
                        instruction_min_addr, max_address
                    );
                }
            }
        }
        if !instruction.is_in_delay_slot() {
            self.last_instruction_address = Some(instruction_min_addr.clone());
        }
        self.max_address = Some(instruction.get_max_address());
        // `LinkedHashMap.put` of an existing key replaces the value in place; the consecutive
        // address check above means the key is always new.
        self.instruction_index.insert(instruction_min_addr, self.instructions.len());
        self.instructions.push(instruction);
    }
}

impl<'a, I> IntoIterator for &'a InstructionBlock<I> {
    type Item = &'a I;
    type IntoIter = std::slice::Iter<'a, I>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<I> fmt::Display for InstructionBlock<I> {
    /// Port of `toString()`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.max_address {
            Some(max) => write!(f, "[ {}-{}]", self.start_addr, max),
            None => write!(f, "[ {}: <empty>]", self.start_addr),
        }
    }
}

impl<I> fmt::Debug for InstructionBlock<I> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// Instructions of arbitrary geometry for the block and set tests: an address range and whether
/// the instruction sits in a delay slot, which is all a block asks of its instructions.
#[cfg(test)]
pub(crate) mod test_support {
    use crate::program::model::address::Address;
    use crate::program::model::listing::instruction_stub::InstructionStub;

    /// An instruction covering `min..=max`.
    pub(crate) struct RangeInstruction {
        pub(crate) min: Address,
        pub(crate) max: Address,
        pub(crate) in_delay_slot: bool,
    }

    impl RangeInstruction {
        pub(crate) fn new(min: Address, max: Address) -> Self {
            RangeInstruction { min, max, in_delay_slot: false }
        }

        pub(crate) fn in_delay_slot(min: Address, max: Address) -> Self {
            RangeInstruction { min, max, in_delay_slot: true }
        }
    }

    impl InstructionStub for RangeInstruction {
        fn get_min_address(&self) -> Address {
            self.min.clone()
        }
        fn get_max_address(&self) -> Address {
            self.max.clone()
        }
        fn is_in_delay_slot(&self) -> bool {
            self.in_delay_slot
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::RangeInstruction;
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::lang::instruction_block_flow::InstructionBlockFlowType;
    use crate::program::model::lang::register::Register;

    fn ram_addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    fn range(min: i64, max: i64) -> RangeInstruction {
        RangeInstruction::new(ram_addr(min), ram_addr(max))
    }

    #[test]
    fn add_instruction_extends_block_and_reports_addresses() {
        let mut block = InstructionBlock::new(ram_addr(0x1000));

        assert!(block.is_empty());
        assert_eq!(block.get_start_address(), ram_addr(0x1000));
        // An empty block reports its start address as its max address too.
        assert_eq!(block.get_max_address(), ram_addr(0x1000));
        assert_eq!(block.to_string(), "[ ram:0x1000: <empty>]");

        block.add_instruction(range(0x1000, 0x1001));
        assert_eq!(block.get_instruction_count(), 1);
        assert_eq!(block.get_max_address(), ram_addr(0x1001));
        assert!(!block.is_empty());

        block.add_instruction(range(0x1002, 0x1003));
        assert_eq!(block.get_instruction_count(), 2);
        assert_eq!(block.get_max_address(), ram_addr(0x1003));
        assert_eq!(block.get_last_instruction_address(), Some(ram_addr(0x1002)));

        let found = block.get_instruction_at(&ram_addr(0x1000)).unwrap();
        assert_eq!(found.min, ram_addr(0x1000));
        // Only instruction starts are keys.
        assert!(block.get_instruction_at(&ram_addr(0x1001)).is_none());

        let hit = block
            .find_first_intersecting_instruction(&ram_addr(0x1001), &ram_addr(0x1003))
            .unwrap();
        assert_eq!(hit.min, ram_addr(0x1000), "the lowest intersecting instruction wins");
        assert!(block
            .find_first_intersecting_instruction(&ram_addr(0x2000), &ram_addr(0x2001))
            .is_none());

        assert_eq!(block.to_string(), "[ ram:0x1000-ram:0x1003]");
        assert_eq!(
            block.iter().map(|i| i.min.offset()).collect::<Vec<_>>(),
            vec![0x1000, 0x1002]
        );

        block.set_instructions_added_count(2);
        assert_eq!(block.get_instructions_added_count(), 2);
        block.set_flow_from_address(Some(ram_addr(0x0ffe)));
        assert_eq!(block.get_flow_from_address(), Some(ram_addr(0x0ffe)));
    }

    #[test]
    fn delay_slot_instructions_do_not_move_the_last_instruction_address() {
        let mut block = InstructionBlock::new(ram_addr(0x1000));
        block.add_instruction(range(0x1000, 0x1001));
        block.add_instruction(RangeInstruction::in_delay_slot(ram_addr(0x1002), ram_addr(0x1003)));
        assert_eq!(block.get_last_instruction_address(), Some(ram_addr(0x1000)));
        assert_eq!(block.get_max_address(), ram_addr(0x1003));
    }

    #[test]
    #[should_panic(expected = "First instruction to block had address ram:0x1002, expected address ram:0x1000")]
    fn first_instruction_must_start_the_block() {
        let mut block = InstructionBlock::new(ram_addr(0x1000));
        block.add_instruction(range(0x1002, 0x1003));
    }

    #[test]
    #[should_panic(expected = "is not the immediate succesor to address ram:0x1001")]
    fn add_instruction_rejects_non_consecutive_address() {
        let mut block = InstructionBlock::new(ram_addr(0x1000));
        block.add_instruction(range(0x1000, 0x1001));
        block.add_instruction(range(0x2000, 0x2001));
    }

    #[test]
    fn flows_and_fall_through_are_recorded() {
        let mut block: InstructionBlock<RangeInstruction> = InstructionBlock::new(ram_addr(0x1000));
        assert!(block.get_block_flows().is_none(), "Java's blockFlows is null until one is added");
        block.add_block_flow(InstructionBlockFlow::new(
            ram_addr(0x2000),
            Some(ram_addr(0x1000)),
            InstructionBlockFlowType::Branch,
        ));
        block.add_branch_flow(ram_addr(0x2000));
        block.set_fall_through(Some(ram_addr(0x1002)));
        assert_eq!(block.get_block_flows().unwrap().len(), 1);
        assert_eq!(block.get_block_flows().unwrap()[0].get_type(), InstructionBlockFlowType::Branch);
        assert_eq!(block.get_branch_flows(), &[ram_addr(0x2000)]);
        assert_eq!(block.get_fall_through(), Some(ram_addr(0x1002)));
        block.set_start_of_flow(true);
        assert!(block.is_flow_start());
    }

    #[test]
    fn errors_are_raised_replaced_and_cleared() {
        let mut block: InstructionBlock<RangeInstruction> = InstructionBlock::new(ram_addr(0x1000));
        assert!(!block.has_instruction_error());

        block.set_instruction_memory_error(ram_addr(0x1004), None, "boom".to_string());
        let err = block.get_instruction_conflict().unwrap();
        assert_eq!(err.get_instruction_error_type(), InstructionErrorType::Memory);
        assert_eq!(err.get_conflict_address(), Some(ram_addr(0x1004)));
        assert_eq!(err.get_conflict_message(), "boom");

        block.set_code_unit_conflict(ram_addr(0x1003), ram_addr(0x1004), Some(ram_addr(0x1000)), true, true);
        let err = block.get_instruction_conflict().unwrap();
        assert_eq!(err.get_instruction_error_type(), InstructionErrorType::OffcutInstruction);
        assert_eq!(err.get_instruction_address(), ram_addr(0x1004));
        assert_eq!(err.get_conflict_address(), Some(ram_addr(0x1003)));
        assert_eq!(
            err.get_conflict_message(),
            "Failed to disassemble at ram:0x1004 due to conflicting instruction at ram:0x1003"
        );

        block.set_code_unit_conflict(ram_addr(0x1003), ram_addr(0x1004), None, false, false);
        assert_eq!(
            block.get_instruction_conflict().unwrap().get_instruction_error_type(),
            InstructionErrorType::DataConflict
        );

        block.set_inconsistent_prototype_conflict(ram_addr(0x1004), None);
        assert_eq!(
            block.get_instruction_conflict().unwrap().get_conflict_message(),
            "Multiple flows produced inconsistent instruction prototype at ram:0x1004 - possibly due to inconsistent context"
        );

        let space = AddressSpace::new("register", 32, 1, AddressSpaceType::Register, 0);
        let ctx = Register::new("ctx", "", Address::new(space, 0), 4, false, Register::TYPE_CONTEXT);
        block.set_parse_conflict(
            ram_addr(0x1004),
            Some(RegisterValue::with_value(ctx, 5)),
            Some(ram_addr(0x1002)),
            "Unable to resolve constructor".to_string(),
        );
        let err = block.get_instruction_conflict().unwrap();
        assert_eq!(err.get_instruction_error_type(), InstructionErrorType::Parse);
        assert_eq!(err.get_parse_context_value().unwrap().unsigned_value(), Some(5));
        assert_eq!(err.get_flow_from_address(), Some(ram_addr(0x1002)));

        block.clear_conflict();
        assert!(!block.has_instruction_error());
    }

    #[test]
    #[should_panic(expected = "use setParseConflict for PARSE conflicts")]
    fn parse_errors_must_go_through_set_parse_conflict() {
        let mut block: InstructionBlock<RangeInstruction> = InstructionBlock::new(ram_addr(0x1000));
        block.set_instruction_error(InstructionErrorType::Parse, ram_addr(0x1000), None, None, String::new());
    }
}

use std::sync::Arc;

use crate::program::model::address::Address;
use crate::program::model::listing::Instruction;
use crate::program::seam_stubs::{InstructionBlockFlow, InstructionError, InstructionErrorType, RegisterValue};

/// Represents a block of instructions. Used as part of an InstructionSet to be added to the
/// program.
///
/// Port of `ghidra.program.model.lang.InstructionBlock`, cut to a trait at this cycle
/// break-point: the real `InstructionError` constructor takes the owning `InstructionBlock` back
/// (`new InstructionError(this, type, ...)`), so a concrete `InstructionBlock` can't be defined
/// without `InstructionError` first existing, and vice versa. `InstructionBlockFlow` and
/// `InstructionError`/`InstructionErrorType` are not yet ported; minimal placeholders live in
/// [`crate::program::seam_stubs`].
pub trait InstructionBlock {
    /// Allows the block to be tagged as start of flow to force InstructionSet iterator to treat
    /// it as a flow start. This method should not be used after this block has been added to an
    /// InstructionSet.
    fn set_start_of_flow(&mut self, is_start: bool);

    /// True if this block should be treated as the start of a new flow when added to an
    /// InstructionSet.
    fn is_flow_start(&self) -> bool;

    /// Returns the minimum/start address of the block.
    fn get_start_address(&self) -> Address;

    /// Returns the maximum address of the block, or the start address if the block is empty.
    fn get_max_address(&self) -> Address;

    /// Returns the instruction at the specified address within this block, or `None` if not
    /// found.
    fn get_instruction_at(&self, address: &Address) -> Option<Arc<dyn Instruction>>;

    /// Find the first instruction within this block which intersects the specified range. This
    /// method should be used sparingly since it uses a brute-force search. Returns `None` if no
    /// instruction within this block intersects the range.
    fn find_first_intersecting_instruction(
        &self,
        min: &Address,
        max: &Address,
    ) -> Option<Arc<dyn Instruction>>;

    /// Adds an instruction to this block. If the block is not empty, the newly added
    /// instruction must be directly after the current block maximum address. In other words,
    /// all instructions in the block must be consecutive.
    ///
    /// # Panics
    /// Panics if the new instruction does not immediately follow the last instruction added
    /// (mirrors the Java `IllegalArgumentException`).
    fn add_instruction(&mut self, instruction: Arc<dyn Instruction>);

    /// Add a block flow specified by an `InstructionBlockFlow` object. These flows include all
    /// calls, branches, and fall-throughs and may span across multiple InstructionSets and are
    /// not used by the block flow iterator within the associated InstructionSet.
    fn add_block_flow(&mut self, block_flow: Box<dyn InstructionBlockFlow>);

    /// Adds a branch type flow to this instruction block and is used by the block flow iterator
    /// of the associated InstructionSet.
    fn add_branch_flow(&mut self, destination_address: Address);

    /// Sets the fall-through address for this block and is used by the block flow iterator of
    /// the associated InstructionSet. The fallthrough should not be set if it is added as a
    /// block flow.
    fn set_fall_through(&mut self, fallthrough_address: Option<Address>);

    /// Returns all of the branch flows that were added to this instruction block and flow to
    /// other blocks within the associated InstructionSet.
    fn get_branch_flows(&self) -> Vec<Address>;

    /// Returns all block flows that were added to this instruction block, or `None` if none were
    /// ever added. NOTE: these flows may not be contained within the associated InstructionSet.
    fn get_block_flows(&self) -> Option<Vec<Box<dyn InstructionBlockFlow>>>;

    /// Returns the fallthrough address, or `None` if there is no fall-through.
    fn get_fall_through(&self) -> Option<Address>;

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
    /// Panics if `error_type` is [`InstructionErrorType::Parse`] (mirrors the Java
    /// `IllegalArgumentException`; use [`InstructionBlock::set_parse_conflict`] for PARSE
    /// conflicts).
    fn set_instruction_error(
        &mut self,
        error_type: InstructionErrorType,
        intended_instruction_address: Address,
        conflict_address: Address,
        flow_from_address: Option<Address>,
        message: String,
    );

    /// Set instruction memory error.
    fn set_instruction_memory_error(
        &mut self,
        instr_addr: Address,
        flow_from_addr: Option<Address>,
        error_msg: String,
    ) {
        self.set_instruction_error(
            InstructionErrorType::Memory,
            instr_addr.clone(),
            instr_addr,
            flow_from_addr,
            error_msg,
        );
    }

    /// Set inconsistent instruction prototype CODE_UNIT conflict.
    fn set_inconsistent_prototype_conflict(&mut self, instr_addr: Address, flow_from_addr: Option<Address>) {
        let message = format!(
            "Multiple flows produced inconsistent instruction prototype at {} - possibly due to inconsistent context",
            instr_addr
        );
        self.set_instruction_error(
            InstructionErrorType::InstructionConflict,
            instr_addr.clone(),
            instr_addr,
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
    fn set_code_unit_conflict(
        &mut self,
        code_unit_addr: Address,
        new_instr_addr: Address,
        flow_from_addr: Option<Address>,
        is_instruction: bool,
        is_offcut: bool,
    ) {
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
            "Failed to disassemble at {} due to conflicting {} at {}",
            new_instr_addr,
            if is_instruction { "instruction" } else { "data" },
            code_unit_addr
        );
        self.set_instruction_error(error_type, new_instr_addr, code_unit_addr, flow_from_addr, message);
    }

    /// Sets this block to have a PARSE conflict, meaning the instruction parse failed at the
    /// specified conflict address using the specified context value.
    ///
    /// # Arguments
    /// * `conflict_address` - the address of the existing code unit that is preventing the
    ///   instruction in this block from being laid down
    /// * `context_value` - the context-register value used during the failed parse attempt
    /// * `flow_from_address` - the flow-from instruction address, or `None`
    /// * `message` - a message that describes the conflict to a user
    fn set_parse_conflict(
        &mut self,
        conflict_address: Address,
        context_value: Box<dyn RegisterValue>,
        flow_from_address: Option<Address>,
        message: String,
    );

    /// Clears any conflict associated with this block.
    fn clear_conflict(&mut self);

    /// Returns the current conflict associated with this block, if any.
    fn get_instruction_conflict(&self) -> Option<Box<dyn InstructionError>>;

    /// Returns an iterator over all the instructions in this block.
    fn iter_instructions(&self) -> Box<dyn Iterator<Item = Arc<dyn Instruction>> + '_>;

    /// Address of the last instruction contained within this block, or `None` if no instruction
    /// outside a delay slot has been added yet.
    fn get_last_instruction_address(&self) -> Option<Address>;

    /// True if no instructions exist within this block.
    fn is_empty(&self) -> bool;

    /// Number of instructions contained within this block.
    fn get_instruction_count(&self) -> usize;

    /// Number of instructions which were added to the program successfully.
    fn get_instructions_added_count(&self) -> i32;

    /// Set the number of instructions which were added to the program.
    fn set_instructions_added_count(&mut self, count: i32);

    /// Returns the flow-from address, or `None` if unset.
    fn get_flow_from_address(&self) -> Option<Address>;

    /// Sets the flow-from address.
    fn set_flow_from_address(&mut self, flow_from: Option<Address>);

    /// True if this block currently has an associated instruction error/conflict.
    fn has_instruction_error(&self) -> bool;

    /// Port of `InstructionBlock.toString()`.
    fn to_display_string(&self) -> String {
        if self.is_empty() {
            format!("[ {}: <empty>]", self.get_start_address())
        } else {
            format!("[ {}-{}]", self.get_start_address(), self.get_max_address())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::listing::code_unit::CodeUnit;
    use crate::program::model::listing::instruction::tests::mock_instruction;
    use std::sync::Arc;

    fn ram_addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    struct MockInstructionBlock {
        start_addr: Address,
        max_addr: Option<Address>,
        instructions: Vec<Arc<dyn Instruction>>,
        is_start_of_flow: bool,
        block_flows: Option<Vec<Box<dyn InstructionBlockFlow>>>,
        flow_addresses: Vec<Address>,
        fallthrough: Option<Address>,
        flow_from: Option<Address>,
        instructions_added_count: i32,
        has_error: bool,
    }

    impl MockInstructionBlock {
        fn new(start_addr: Address) -> Self {
            MockInstructionBlock {
                start_addr,
                max_addr: None,
                instructions: Vec::new(),
                is_start_of_flow: false,
                block_flows: None,
                flow_addresses: Vec::new(),
                fallthrough: None,
                flow_from: None,
                instructions_added_count: 0,
                has_error: false,
            }
        }
    }

    impl InstructionBlock for MockInstructionBlock {
        fn set_start_of_flow(&mut self, is_start: bool) {
            self.is_start_of_flow = is_start;
        }

        fn is_flow_start(&self) -> bool {
            self.is_start_of_flow
        }

        fn get_start_address(&self) -> Address {
            self.start_addr.clone()
        }

        fn get_max_address(&self) -> Address {
            self.max_addr.clone().unwrap_or_else(|| self.start_addr.clone())
        }

        fn get_instruction_at(&self, address: &Address) -> Option<Arc<dyn Instruction>> {
            self.instructions
                .iter()
                .find(|i| &i.get_min_address() == address)
                .cloned()
        }

        fn find_first_intersecting_instruction(
            &self,
            min: &Address,
            max: &Address,
        ) -> Option<Arc<dyn Instruction>> {
            self.instructions
                .iter()
                .find(|i| i.get_min_address() <= *max && i.get_max_address() >= *min)
                .cloned()
        }

        fn add_instruction(&mut self, instruction: Arc<dyn Instruction>) {
            let min_addr = instruction.get_min_address();
            match &self.max_addr {
                None => {
                    if min_addr != self.start_addr {
                        panic!(
                            "First instruction to block had address {}, expected address {}",
                            min_addr, self.start_addr
                        );
                    }
                }
                Some(max_addr) => {
                    // `min_addr.is_successor(max_addr)` asks whether `min_addr` immediately
                    // follows `max_addr` (this crate's `Address::is_successor` checks
                    // `self == other + 1`), matching Java's `maxAddress.isSuccessor(minAddr)`
                    // ("tests whether the given address immediately follows this address").
                    if !min_addr.is_successor(max_addr) {
                        panic!(
                            "Newly added instruction at address {} is not the immediate successor to address {}",
                            min_addr, max_addr
                        );
                    }
                }
            }
            self.max_addr = Some(instruction.get_max_address());
            self.instructions.push(instruction);
        }

        fn add_block_flow(&mut self, block_flow: Box<dyn InstructionBlockFlow>) {
            self.block_flows.get_or_insert_with(Vec::new).push(block_flow);
        }

        fn add_branch_flow(&mut self, destination_address: Address) {
            self.flow_addresses.push(destination_address);
        }

        fn set_fall_through(&mut self, fallthrough_address: Option<Address>) {
            self.fallthrough = fallthrough_address;
        }

        fn get_branch_flows(&self) -> Vec<Address> {
            self.flow_addresses.clone()
        }

        fn get_block_flows(&self) -> Option<Vec<Box<dyn InstructionBlockFlow>>> {
            None
        }

        fn get_fall_through(&self) -> Option<Address> {
            self.fallthrough.clone()
        }

        fn set_instruction_error(
            &mut self,
            error_type: InstructionErrorType,
            _intended_instruction_address: Address,
            _conflict_address: Address,
            _flow_from_address: Option<Address>,
            _message: String,
        ) {
            assert_ne!(error_type, InstructionErrorType::Parse);
            self.has_error = true;
        }

        fn set_parse_conflict(
            &mut self,
            _conflict_address: Address,
            _context_value: Box<dyn RegisterValue>,
            _flow_from_address: Option<Address>,
            _message: String,
        ) {
            self.has_error = true;
        }

        fn clear_conflict(&mut self) {
            self.has_error = false;
        }

        fn get_instruction_conflict(&self) -> Option<Box<dyn InstructionError>> {
            None
        }

        fn iter_instructions(&self) -> Box<dyn Iterator<Item = Arc<dyn Instruction>> + '_> {
            Box::new(self.instructions.iter().cloned())
        }

        fn get_last_instruction_address(&self) -> Option<Address> {
            self.instructions.last().map(|i| i.get_min_address())
        }

        fn is_empty(&self) -> bool {
            self.instructions.is_empty()
        }

        fn get_instruction_count(&self) -> usize {
            self.instructions.len()
        }

        fn get_instructions_added_count(&self) -> i32 {
            self.instructions_added_count
        }

        fn set_instructions_added_count(&mut self, count: i32) {
            self.instructions_added_count = count;
        }

        fn get_flow_from_address(&self) -> Option<Address> {
            self.flow_from.clone()
        }

        fn set_flow_from_address(&mut self, flow_from: Option<Address>) {
            self.flow_from = flow_from;
        }

        fn has_instruction_error(&self) -> bool {
            self.has_error
        }
    }

    #[test]
    fn add_instruction_extends_block_and_reports_addresses() {
        let mut block: Box<dyn InstructionBlock> =
            Box::new(MockInstructionBlock::new(ram_addr(0x1000)));

        assert!(block.is_empty());
        assert_eq!(block.get_start_address(), ram_addr(0x1000));
        // Empty block reports its start address as its max address too.
        assert_eq!(block.get_max_address(), ram_addr(0x1000));

        let first = mock_instruction(ram_addr(0x1000), ram_addr(0x1001));
        block.add_instruction(first);
        assert_eq!(block.get_instruction_count(), 1);
        assert_eq!(block.get_max_address(), ram_addr(0x1001));
        assert!(!block.is_empty());

        let second = mock_instruction(ram_addr(0x1002), ram_addr(0x1003));
        block.add_instruction(second);
        assert_eq!(block.get_instruction_count(), 2);
        assert_eq!(block.get_max_address(), ram_addr(0x1003));
        assert_eq!(block.get_last_instruction_address(), Some(ram_addr(0x1002)));

        let found = block.get_instruction_at(&ram_addr(0x1000));
        assert!(found.is_some());
        assert_eq!(found.unwrap().get_min_address(), ram_addr(0x1000));

        assert!(block.find_first_intersecting_instruction(&ram_addr(0x1002), &ram_addr(0x1003)).is_some());
        assert!(block.find_first_intersecting_instruction(&ram_addr(0x2000), &ram_addr(0x2001)).is_none());

        assert_eq!(block.to_display_string(), "[ ram:0x1000-ram:0x1003]");

        block.set_instructions_added_count(2);
        assert_eq!(block.get_instructions_added_count(), 2);

        block.set_flow_from_address(Some(ram_addr(0x0ffe)));
        assert_eq!(block.get_flow_from_address(), Some(ram_addr(0x0ffe)));

        assert!(!block.has_instruction_error());
        block.set_instruction_error(
            InstructionErrorType::Memory,
            ram_addr(0x1004),
            ram_addr(0x1004),
            None,
            "boom".to_string(),
        );
        assert!(block.has_instruction_error());
        block.clear_conflict();
        assert!(!block.has_instruction_error());
    }

    #[test]
    #[should_panic(expected = "is not the immediate successor")]
    fn add_instruction_rejects_non_consecutive_address() {
        let mut block: Box<dyn InstructionBlock> =
            Box::new(MockInstructionBlock::new(ram_addr(0x1000)));
        let first = mock_instruction(ram_addr(0x1000), ram_addr(0x1001));
        block.add_instruction(first);

        let non_consecutive = mock_instruction(ram_addr(0x2000), ram_addr(0x2001));
        block.add_instruction(non_consecutive);
    }
}

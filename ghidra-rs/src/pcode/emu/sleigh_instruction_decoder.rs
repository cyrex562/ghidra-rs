//! Port of `ghidra.pcode.emu.SleighInstructionDecoder`.
//!
//! The default instruction decoder, based on Sleigh: it pseudo-disassembles the machine's memory
//! with a [`Disassembler`], reading the bytes at the counter through the state's concrete buffer,
//! and keeps the last block it decoded so that stepping within it reuses its instructions.
//!
//! # Shape
//!
//! A concrete class, so a struct. Java holds a `PcodeExecutorState<?>`; here the state is the
//! type parameter `S`, any state piece whose values are `T` (the decoder only asks it for a
//! concrete buffer). The decoded instruction is a [`DisassembledInstruction`]
//! (`PseudoInstruction<DisassemblerInstructionContext>`), which owns its bytes and context, so the
//! decoder hands out copies of the one it keeps.
//!
//! # Deviations
//!
//! * Java's disassembly listener logs through `Msg.warn(this, msg)` and records the message; the
//!   recorded message is shared with the listener the disassembler holds.

use std::marker::PhantomData;
use std::sync::{Arc, Mutex};

use crate::pcode::emu::instruction_decoder::InstructionDecoder;
// Java throws this (deprecated) exception from `computeLength()` too.
#[allow(deprecated)]
use crate::pcode::emulate::instruction_decode_exception::InstructionDecodeException;
use crate::pcode::exec::decode_pcode_execution_exception::DecodePcodeExecutionException;
use crate::pcode::exec::pcode_arithmetic::Purpose;
use crate::pcode::exec::pcode_executor_state_piece::PcodeExecutorStatePiece;
use crate::pcode::seam_stubs::PseudoInstruction as DecodedInstruction;
use crate::program::disassemble::disassembler::{DisassembledBlock, DisassembledInstruction, Disassembler};
use crate::program::disassemble::disassembler_message_listener::DisassemblerMessageListener;
use crate::program::model::address::{Address, AddressFactory};
use crate::program::model::lang::language::Language;
use crate::program::model::lang::register_value::RegisterValue;
use crate::program::model::lang::sleigh::SleighLanguage;
use crate::program::model::listing::code_unit::CodeUnit;
use crate::program::model::listing::instruction::Instruction;
use crate::util::task::DummyMonitor;
use crate::util::Msg;

const DEFAULT_ERROR: &str = "Unknown disassembly error";

/// Java's listener lambda: warn, and remember the message as the decoder's `lastMsg`.
struct LastMessage(Arc<Mutex<String>>);

impl DisassemblerMessageListener for LastMessage {
    fn disassemble_message_reported(&self, msg: &str) {
        Msg::warn("SleighInstructionDecoder", &msg);
        *self.0.lock().expect("last message lock poisoned") = msg.to_string();
    }
}

/// The default instruction decoder, based on Sleigh; see the module docs.
///
/// Port of `ghidra.pcode.emu.SleighInstructionDecoder`.
pub struct SleighInstructionDecoder<T, S> {
    language: Arc<SleighLanguage>,
    state: S,
    disassembler: Disassembler,
    last_msg: Arc<Mutex<String>>,
    block: Option<DisassembledBlock>,
    length_with_delays: i32,
    instruction: Option<Arc<DisassembledInstruction>>,
    _values: PhantomData<fn() -> T>,
}

impl<T, S: PcodeExecutorStatePiece<T, T>> SleighInstructionDecoder<T, S> {
    /// Construct a Sleigh instruction decoder. Port of
    /// `SleighInstructionDecoder(Language, PcodeExecutorState<?>)`.
    ///
    /// # Arguments
    /// * `language` - the language to decode
    /// * `state` - the state containing the target program, probably the shared state of the
    ///   p-code machine. It must be possible to obtain concrete buffers on this state.
    pub fn new(language: Arc<SleighLanguage>, state: S) -> Self {
        let last_msg = Arc::new(Mutex::new(DEFAULT_ERROR.to_string()));
        let addr_factory: Arc<dyn AddressFactory> = SleighLanguage::get_address_factory(&language);
        let disassembler = Disassembler::get_disassembler(
            Arc::clone(&language),
            addr_factory,
            Arc::new(DummyMonitor),
            Some(Arc::new(LastMessage(Arc::clone(&last_msg)))),
        );
        SleighInstructionDecoder {
            language,
            state,
            disassembler,
            last_msg,
            block: None,
            length_with_delays: 0,
            instruction: None,
            _values: PhantomData,
        }
    }

    /// The last block decoded, if it is still in use.
    pub fn block(&self) -> Option<&DisassembledBlock> {
        self.block.as_ref()
    }

    /// Port of `useCachedInstruction(Address, RegisterValue)`: always use an instruction within
    /// the last block decoded, assuming the flow came from another instruction within the same
    /// block. The block is `None` when starting a new flow.
    fn use_cached_instruction(&mut self, address: &Address) -> bool {
        let Some(block) = &self.block else {
            return false;
        };
        self.instruction = block.get_instruction_at(address).cloned().map(Arc::new);
        self.instruction.is_some()
    }

    /// Port of `parseNewBlock(Address, RegisterValue)`: parse as few instructions as possible. If
    /// more are returned, they form a parallel instruction group, within which self-modifying
    /// code need not be considered.
    fn parse_new_block(
        &mut self,
        address: &Address,
        context: Option<&RegisterValue>,
    ) -> Result<(), DecodePcodeExecutionException> {
        let buffer = self.state.get_concrete_buffer(address, Purpose::Decode);
        self.block = self.disassembler.pseudo_disassemble_block(buffer, context, 1);
        let Some(block) = self.block.as_ref().filter(|b| !b.is_empty()) else {
            let last_msg = self.last_msg.lock().expect("last message lock poisoned").clone();
            return Err(DecodePcodeExecutionException::new(last_msg, address.clone()));
        };
        self.instruction = block.get_instruction_at(address).cloned().map(Arc::new);
        Ok(())
    }

    /// Computes the "length" of the instruction, including any delay-slotted instructions that
    /// follow. Port of `computeLength()`.
    #[allow(deprecated)]
    fn compute_length(&self) -> Result<i32, InstructionDecodeException> {
        let instruction = self.instruction.as_ref().expect("an instruction was decoded");
        let block = self.block.as_ref().expect("an instruction comes from a block");
        let mut length = instruction.get_length();
        let slots = instruction.get_delay_slot_depth();
        let mut ins_address = instruction.get_min_address();
        let mut ins_length = instruction.get_length();
        for _ in 0..slots {
            let next = ins_address.add_no_wrap(ins_length as i64).map_err(|_| {
                InstructionDecodeException::new("Delay slot would exceed address space", ins_address.clone())
            })?;
            let ni = block.get_instruction_at(&next).ok_or_else(|| {
                InstructionDecodeException::new("Failed to parse delay slot instruction", next.clone())
            })?;
            ins_address = next;
            ins_length = ni.get_length();
            length += ins_length;
        }
        Ok(length)
    }
}

impl<T, S: PcodeExecutorStatePiece<T, T>> InstructionDecoder for SleighInstructionDecoder<T, S> {
    fn get_language(&self) -> Arc<dyn Language> {
        Arc::clone(&self.language) as Arc<dyn Language>
    }

    /// Port of `decodeInstruction(Address, RegisterValue)`.
    ///
    /// # Errors
    /// A `DecodePcodeExecutionException` if no instruction could be decoded at `address`, or an
    /// `InstructionDecodeException` if its delay slots could not be.
    fn decode_instruction(
        &mut self,
        address: &Address,
        context: Option<&RegisterValue>,
    ) -> Result<Box<dyn DecodedInstruction>, Box<dyn std::error::Error>> {
        *self.last_msg.lock().expect("last message lock poisoned") = DEFAULT_ERROR.to_string();
        if !self.use_cached_instruction(address) {
            self.parse_new_block(address, context)?;
        }
        self.length_with_delays = self.compute_length()?;
        let instruction = self.instruction.as_ref().expect("an instruction was decoded");
        Ok(Box::new(DisassembledInstruction::clone(instruction)))
    }

    /// Port of `branched(Address)`. There may be internal branching within a decoded block,
    /// which should not clear it; a branch out of it starts a new block.
    fn branched(&mut self, address: &Address) {
        if self.block.as_ref().is_none_or(|block| block.get_instruction_at(address).is_none()) {
            self.block = None;
        }
    }

    fn get_last_instruction(&self) -> Option<Arc<dyn Instruction>> {
        self.instruction.clone().map(|i| i as Arc<dyn Instruction>)
    }

    fn get_last_length_with_delays(&self) -> i32 {
        self.length_with_delays
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::plugin::processors::sleigh::sleigh_instruction_prototype::decode_tests;
    use crate::pcode::emu::bytes_pcode_thread::BytesState;
    use crate::pcode::emu::thread_pcode_executor_state::SharedPcodeExecutorState;
    use crate::pcode::exec::bytes_pcode_executor_state::BytesPcodeExecutorState;
    use crate::pcode::exec::pcode_state_callbacks::NONE;
    use crate::program::model::address::AddressSpace;

    /// A machine memory holding the toy language's program, and a decoder over it.
    struct Fixture {
        ram: Arc<AddressSpace>,
        memory: SharedPcodeExecutorState<BytesState>,
        decoder: SleighInstructionDecoder<Vec<u8>, SharedPcodeExecutorState<BytesState>>,
    }

    impl Fixture {
        fn new() -> Self {
            let language = decode_tests::language();
            let ram = Language::get_default_space(language.as_ref());
            let memory = SharedPcodeExecutorState::new(BytesPcodeExecutorState::new(
                Arc::clone(&language) as Arc<dyn Language>,
                Arc::new(NONE),
            ));
            let decoder = SleighInstructionDecoder::new(language, memory.clone());
            Fixture { ram, memory, decoder }
        }

        fn write(&mut self, offset: i64, bytes: &[u8]) {
            self.memory.set_var(&self.ram, offset, bytes.len() as i32, false, &bytes.to_vec());
        }

        fn decode(&mut self, offset: i64) -> Result<Box<dyn DecodedInstruction>, Box<dyn std::error::Error>> {
            let address = self.ram.address(offset);
            self.decoder.decode_instruction(&address, None)
        }

        /// The last instruction decoded, as Java's `toString()` shows it.
        fn text(&self) -> String {
            self.decoder.instruction.as_ref().unwrap().to_string()
        }

        fn last(&self) -> (i64, String, i32) {
            let insn = self.decoder.get_last_instruction().unwrap();
            (insn.get_min_address().offset(), insn.get_mnemonic_string(), self.decoder.get_last_length_with_delays())
        }
    }

    #[test]
    fn decodes_the_instruction_at_the_counter_from_machine_memory() {
        let mut f = Fixture::new();
        // mov r1, 0x2a ; jmp 0x1009
        f.write(0x1000, &[0x11, 0x2a, 0x20, 0x05]);
        assert_eq!(f.decoder.get_language().get_language_id().to_string(), "toy:BE:32:default");

        let decoded = f.decode(0x1000).unwrap();
        assert_eq!(decoded.get_max_address().offset(), 0x1001);
        assert_eq!(decoded.decode_error_message(), None);
        assert_eq!(f.last(), (0x1000, "mov".to_string(), 2));
        let insn = f.decoder.get_last_instruction().unwrap();
        assert_eq!(insn.get_pcode().len(), 1);

        // Java parses as few instructions as possible: one per block.
        assert_eq!(f.decoder.block().unwrap().get_instruction_count(), 1);
        f.decode(0x1002).unwrap();
        assert_eq!(f.last(), (0x1002, "jmp".to_string(), 2));
        assert_eq!(f.decoder.get_last_instruction().unwrap().get_flows().unwrap()[0].offset(), 0x1009);
    }

    /// Java keeps the last block and reuses an instruction in it without re-reading memory,
    /// until a branch leaves the block.
    #[test]
    fn caches_the_last_block_until_a_branch_leaves_it() {
        let mut f = Fixture::new();
        f.write(0x1000, &[0x11, 0x2a]);
        f.decode(0x1000).unwrap();
        assert_eq!(f.text(), "mov r1,0x2a");

        // Self-modifying code within the cached block is not seen...
        f.write(0x1000, &[0x10, 0x07]);
        f.decode(0x1000).unwrap();
        assert_eq!(f.text(), "mov r1,0x2a");
        // ...nor after a branch within the block...
        f.decoder.branched(&f.ram.address(0x1000));
        f.decode(0x1000).unwrap();
        assert_eq!(f.text(), "mov r1,0x2a");
        // ...but a branch elsewhere drops the block, and the next decode re-reads memory.
        f.decoder.branched(&f.ram.address(0x2000));
        assert!(f.decoder.block().is_none());
        f.decode(0x1000).unwrap();
        assert_eq!(f.text(), "mov r0,0x7");
    }

    #[test]
    fn a_delay_slotted_branch_is_as_long_as_its_slots() {
        let mut f = Fixture::new();
        // jd 0x1012 ; delay slot: mov r1, 0x2a
        f.write(0x1000, &[0x40, 0x10, 0x11, 0x2a]);
        f.decode(0x1000).unwrap();
        assert_eq!(f.last(), (0x1000, "jd".to_string(), 4));
        // The block holds the slot, so decoding it reuses the block.
        assert_eq!(f.decoder.block().unwrap().get_instruction_count(), 2);
        f.decode(0x1002).unwrap();
        assert_eq!(f.last(), (0x1002, "_mov".to_string(), 2));
    }

    #[test]
    fn undecodable_bytes_are_a_decode_error_at_the_counter() {
        let mut f = Fixture::new();
        f.write(0x1000, &[0x00, 0x00]);
        let Err(err) = f.decode(0x1000) else {
            panic!("zeros decode to nothing");
        };
        let err = err.downcast_ref::<DecodePcodeExecutionException>().expect("a decode exception");
        assert_eq!(err.get_program_counter().offset(), 0x1000);
        // The disassembler records a parse conflict in the block, reporting nothing, so the
        // message is the default.
        assert_eq!(err.to_string(), "Unknown disassembly error (PC=ram:0x1000)");
        assert!(f.decoder.block().unwrap().has_instruction_error());
    }
}

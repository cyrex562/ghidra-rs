//! Port of `ghidra.app.plugin.processors.sleigh.SleighParserContext`.
//!
//! `SleighParserContext` was selected as a dependency-cycle cut-point, so instead of a single
//! concrete struct its public API is modeled as the [`SleighParserContext`] trait: all the
//! recovered context for a single instruction (memory, addresses, packed context bits, and
//! pending context commits), exposed over object-safe methods. It extends the pre-existing
//! [`ParserContext`] trait, mirroring `implements ParserContext` on the Java class.
//!
//! The private constructors and the package-private `getContextCommits`/`getRootState` helpers
//! (used only by [`SleighInstructionPrototype`], not yet ported) are left out of the trait; only
//! the genuinely public instance API is modeled.

use std::sync::Arc;

use crate::app::plugin::processors::sleigh::sleigh_exception::SleighException;
use crate::app::seam_stubs::TripleSymbol;
use crate::program::model::address::special_address::SpecialAddress;
use crate::program::model::address::{Address, AddressSpace};
use crate::program::model::lang::parser_context::ParserContext;
use crate::program::model::lang::processor_context::ProcessorContext;
use crate::program::model::lang::sleigh::walker::{ConstructState, MemBuffer};
use crate::program::model::lang::sleigh::FixedHandle;
use crate::program::model::mem::MemoryAccessException;
use crate::program::seam_stubs::RegisterValue;

/// All the recovered context for a single instruction.
///
/// Port of `ghidra.app.plugin.processors.sleigh.SleighParserContext`.
pub trait SleighParserContext: ParserContext {
    /// Address of the start of the instruction (`inst_start`).
    ///
    /// Port of `SleighParserContext.getAddr()`.
    fn get_addr(&self) -> Address;

    /// Address of the instruction after this one (`inst_next`), or `None` if this context
    /// instance does not support `inst_next` or the next address falls beyond the end of the
    /// address space.
    ///
    /// Port of `SleighParserContext.getNaddr()`.
    fn get_naddr(&self) -> Option<Address>;

    /// Address of the instruction after the next instruction (`inst_next2`), or
    /// [`SpecialAddress::no_address`] if `inst_next2` cannot be determined or is not supported in
    /// this context.
    ///
    /// Port of `SleighParserContext.getN2addr()`. Implementers are expected to memoize this the
    /// way the Java class caches `next2InstAddr` in a field on first access.
    fn get_n2addr(&self) -> Address {
        SpecialAddress::no_address()
    }

    /// Address space containing the current instruction.
    ///
    /// Port of `SleighParserContext.getCurSpace()`.
    fn get_cur_space(&self) -> Arc<AddressSpace> {
        self.get_addr().space().clone()
    }

    /// The constant address space.
    ///
    /// Port of `SleighParserContext.getConstSpace()`.
    fn get_const_space(&self) -> Arc<AddressSpace>;

    /// Memory buffer for the current instruction, which may also be used to parse the next
    /// instruction or delay slot instructions.
    ///
    /// Port of `SleighParserContext.getMemBuffer()`.
    fn get_mem_buffer(&self) -> Arc<dyn MemBuffer>;

    /// Gets bytes from the instruction stream into an `int` (packed in big-endian format).
    /// Uninitialized or undefined memory returns zero byte values.
    ///
    /// # Errors
    /// Returns [`MemoryAccessException`] if no bytes are available at the first byte when
    /// `offset + bytestart == 0`.
    ///
    /// Port of `SleighParserContext.getInstructionBytes(int, int, int)`.
    fn get_instruction_bytes(
        &self,
        offset: i32,
        bytestart: i32,
        size: i32,
    ) -> Result<i32, MemoryAccessException>;

    /// Gets bits from the instruction stream into an `int` (packed in big-endian format).
    /// Uninitialized or undefined memory returns zero bit values.
    ///
    /// # Errors
    /// Returns [`MemoryAccessException`] if no bytes are available at the first byte when
    /// `offset + bytestart/8 == 0`.
    ///
    /// Port of `SleighParserContext.getInstructionBits(int, int, int)`.
    fn get_instruction_bits(
        &self,
        offset: i32,
        startbit: i32,
        size: i32,
    ) -> Result<i32, MemoryAccessException>;

    /// The processor context value as a [`RegisterValue`], or `None` if this language has no
    /// context base register.
    ///
    /// Port of `SleighParserContext.getContextRegisterValue()`.
    fn get_context_register_value(&self) -> Option<Box<dyn RegisterValue>>;

    /// Gets bytes from context into an `int`.
    ///
    /// # Arguments
    /// * `bytestart` - index of the first byte to fetch
    /// * `bytesize` - number of bytes (range: 1 - 4)
    ///
    /// Port of `SleighParserContext.getContextBytes(int, int)`.
    fn get_context_bytes(&self, bytestart: i32, bytesize: i32) -> i32;

    /// Full set of packed context words. SLEIGH only supports context which is a multiple of
    /// 4 bytes (i.e. the size of an `int`).
    ///
    /// Port of `SleighParserContext.getContextBytes()` (renamed to avoid an ambiguous-method
    /// clash with [`SleighParserContext::get_context_bytes`], which ports the two-argument
    /// overload of the same Java method name).
    fn get_context_words(&self) -> Vec<i32>;

    /// Gets bits from context into an `int`.
    ///
    /// # Arguments
    /// * `startbit` - index of the first bit to fetch
    /// * `bitsize` - number of bits (range: 1 - 32)
    ///
    /// Port of `SleighParserContext.getContextBits(int, int)`.
    fn get_context_bits(&self, startbit: i32, bitsize: i32) -> i32;

    /// Overwrites the masked bits of context word `i` with the corresponding bits of `val`.
    ///
    /// Port of `SleighParserContext.setContextWord(int, int, int)`.
    fn set_context_word(&mut self, i: usize, val: i32, mask: i32);

    /// True if `buf` is the memory buffer this context was built from, positioned at this
    /// context's address.
    ///
    /// Port of `SleighParserContext.isValid(MemBuffer)`.
    fn is_valid(&self, buf: &dyn MemBuffer) -> bool;

    /// The flow reference address (`inst_ref`), used for call-fixup purposes.
    ///
    /// # Errors
    /// Returns [`SleighException`] if `inst_ref` is undefined in this context.
    ///
    /// Port of `SleighParserContext.getFlowRefAddr()`.
    fn get_flow_ref_addr(&self) -> Result<Address, SleighException>;

    /// The flow destination address (`inst_dest`), used for call-fixup purposes.
    ///
    /// # Errors
    /// Returns [`SleighException`] if `inst_dest` is undefined in this context.
    ///
    /// Port of `SleighParserContext.getFlowDestAddr()`.
    fn get_flow_dest_addr(&self) -> Result<Address, SleighException>;

    /// Records a pending context change to be applied once parsing/resolution completes at
    /// `point`.
    ///
    /// Port of `SleighParserContext.addCommit(ConstructState, TripleSymbol, int, int)`.
    fn add_commit(&mut self, point: &ConstructState, sym: Arc<dyn TripleSymbol>, num: i32, mask: i32);

    /// Applies all pending context commits recorded via [`SleighParserContext::add_commit`] to
    /// `ctx`, then clears the pending list.
    ///
    /// # Errors
    /// Returns [`MemoryAccessException`] if a commit's resolved address cannot be applied.
    ///
    /// Port of `SleighParserContext.applyCommits(ProcessorContext)`.
    fn apply_commits(&mut self, ctx: &mut dyn ProcessorContext) -> Result<(), MemoryAccessException>;

    /// Gets (creating on first access, like the Java `handleMap.computeIfAbsent`-style lookup)
    /// the [`FixedHandle`] associated with `construct_state`.
    ///
    /// Port of `SleighParserContext.getFixedHandle(ConstructState)`.
    fn get_fixed_handle(&mut self, construct_state: &ConstructState) -> FixedHandle;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::AddressSpaceType;
    use crate::program::model::lang::instruction_prototype::InstructionPrototype;
    use std::collections::HashMap;

    fn mock_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    fn mock_addr(offset: i64) -> Address {
        Address::new(mock_space(), offset)
    }

    struct MockPrototype;
    impl InstructionPrototype for MockPrototype {
        fn get_parser_context(
            &self,
            _buf: &dyn crate::program::seam_stubs::MemBuffer,
            _processor_context: &dyn crate::program::model::lang::ProcessorContextView,
        ) -> Result<
            Box<dyn crate::program::seam_stubs::ParserContext>,
            crate::program::model::mem::MemoryAccessException,
        > {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_pseudo_parser_context(
            &self,
            _address: &Address,
            _buffer: &dyn crate::program::seam_stubs::MemBuffer,
            _processor_context: &dyn crate::program::model::lang::ProcessorContextView,
        ) -> Result<
            Box<dyn crate::program::seam_stubs::ParserContext>,
            crate::program::model::lang::instruction_prototype::GetPseudoParserContextError,
        > {
            unimplemented!("not exercised by this smoke test")
        }

        fn has_delay_slots(&self) -> bool {
            false
        }

        fn has_cross_build_dependency(&self) -> bool {
            false
        }

        fn has_next2_dependency(&self) -> bool {
            false
        }

        fn get_mnemonic(&self, _context: &dyn crate::program::model::lang::InstructionContext) -> String {
            "TEST".to_string()
        }

        fn get_length(&self) -> i32 {
            4
        }

        fn get_instruction_mask(&self) -> Option<Box<dyn crate::program::model::lang::Mask>> {
            None
        }

        fn get_operand_value_mask(
            &self,
            _operand_index: i32,
        ) -> Option<Box<dyn crate::program::model::lang::Mask>> {
            None
        }

        fn get_flow_type(
            &self,
            _context: &dyn crate::program::model::lang::InstructionContext,
        ) -> crate::program::model::symbol::RefType {
            unimplemented!()
        }

        fn get_delay_slot_depth(&self, _context: &dyn crate::program::model::lang::InstructionContext) -> i32 {
            0
        }

        fn get_delay_slot_byte_count(&self) -> i32 {
            0
        }

        fn is_in_delay_slot(&self) -> bool {
            false
        }

        fn get_num_operands(&self) -> i32 {
            0
        }

        fn get_op_type(
            &self,
            _operand_index: i32,
            _context: &dyn crate::program::model::lang::InstructionContext,
        ) -> i32 {
            0
        }

        fn get_fall_through(
            &self,
            _context: &dyn crate::program::model::lang::InstructionContext,
        ) -> Option<Address> {
            None
        }

        fn get_fall_through_offset(
            &self,
            _context: &dyn crate::program::model::lang::InstructionContext,
        ) -> i32 {
            4
        }

        fn get_flows(
            &self,
            _context: &dyn crate::program::model::lang::InstructionContext,
        ) -> Option<Vec<Address>> {
            None
        }

        fn get_separator(&self, _operand_index: i32) -> Option<String> {
            None
        }

        fn get_op_representation_list(
            &self,
            _operand_index: i32,
            _context: &dyn crate::program::model::lang::InstructionContext,
        ) -> Option<Vec<crate::program::model::listing::instruction::OperandValue>> {
            None
        }

        fn get_address(
            &self,
            _operand_index: i32,
            _context: &dyn crate::program::model::lang::InstructionContext,
        ) -> Option<Address> {
            None
        }

        fn get_register(
            &self,
            _operand_index: i32,
            _context: &dyn crate::program::model::lang::InstructionContext,
        ) -> Option<crate::program::model::lang::RegisterRef> {
            None
        }

        fn get_scalar(
            &self,
            _operand_index: i32,
            _context: &dyn crate::program::model::lang::InstructionContext,
        ) -> Option<crate::program::model::scalar::Scalar> {
            None
        }

        fn get_op_objects(
            &self,
            _operand_index: i32,
            _context: &dyn crate::program::model::lang::InstructionContext,
        ) -> Vec<crate::program::model::listing::instruction::OperandValue> {
            Vec::new()
        }

        fn get_operand_ref_type(
            &self,
            _operand_index: i32,
            _context: &dyn crate::program::model::lang::InstructionContext,
            _override_: Option<&dyn crate::program::model::pcode::PcodeOverride>,
        ) -> crate::program::model::symbol::RefType {
            unimplemented!()
        }

        fn has_delimeter(&self, _operand_index: i32) -> bool {
            false
        }

        fn get_input_objects(
            &self,
            _context: &dyn crate::program::model::lang::InstructionContext,
        ) -> Vec<crate::program::model::listing::instruction::OperandValue> {
            Vec::new()
        }

        fn get_result_objects(
            &self,
            _context: &dyn crate::program::model::lang::InstructionContext,
        ) -> Vec<crate::program::model::listing::instruction::OperandValue> {
            Vec::new()
        }

        fn get_pcode(
            &self,
            _context: &dyn crate::program::model::lang::InstructionContext,
            _override_: Option<&dyn crate::program::model::pcode::PcodeOverride>,
        ) -> Vec<crate::program::model::pcode::PcodeOp> {
            Vec::new()
        }

        fn get_pcode_packed(
            &self,
            _encoder: &mut dyn crate::program::model::pcode::PatchEncoder,
            _context: &dyn crate::program::model::lang::InstructionContext,
            _override_: Option<&dyn crate::program::model::pcode::PcodeOverride>,
        ) -> std::io::Result<()> {
            Ok(())
        }

        fn get_pcode_for_operand(
            &self,
            _context: &dyn crate::program::model::lang::InstructionContext,
            _operand_index: i32,
        ) -> Vec<crate::program::model::pcode::PcodeOp> {
            Vec::new()
        }

        fn get_language(&self) -> Arc<dyn crate::program::model::lang::language::Language> {
            unimplemented!()
        }
    }

    struct MockMemBuffer {
        address: Address,
        bytes: Vec<u8>,
    }

    impl MemBuffer for MockMemBuffer {
        fn get_address(&self) -> Address {
            self.address.clone()
        }

        fn get_byte(&self, offset: i32) -> Result<u8, MemoryAccessException> {
            self.bytes
                .get(offset as usize)
                .copied()
                .ok_or_else(MemoryAccessException::default)
        }

        fn get_bytes(&self, buf: &mut [u8], offset: i32) -> usize {
            let start = offset.max(0) as usize;
            let mut n = 0;
            for (dst, src) in buf.iter_mut().zip(self.bytes.iter().skip(start)) {
                *dst = *src;
                n += 1;
            }
            n
        }

        fn is_big_endian(&self) -> bool {
            true
        }
    }

    /// A minimal, in-memory implementation used purely to prove the trait is object-safe and
    /// that its default methods behave sensibly -- not a full behavioral port.
    struct MockSleighParserContext {
        addr: Address,
        mem_buffer: Arc<MockMemBuffer>,
        context: Vec<i32>,
        commits: Vec<i32>,
        handles: HashMap<usize, FixedHandle>,
    }

    impl ParserContext for MockSleighParserContext {
        fn get_prototype(&self) -> Arc<dyn InstructionPrototype> {
            Arc::new(MockPrototype)
        }
    }

    impl SleighParserContext for MockSleighParserContext {
        fn get_addr(&self) -> Address {
            self.addr.clone()
        }

        fn get_naddr(&self) -> Option<Address> {
            self.addr.clone().add(4).ok()
        }

        fn get_const_space(&self) -> Arc<AddressSpace> {
            AddressSpace::new("const", 32, 1, AddressSpaceType::Constant, 0)
        }

        fn get_mem_buffer(&self) -> Arc<dyn MemBuffer> {
            self.mem_buffer.clone()
        }

        fn get_instruction_bytes(
            &self,
            offset: i32,
            bytestart: i32,
            size: i32,
        ) -> Result<i32, MemoryAccessException> {
            let mut bytes = vec![0u8; size as usize];
            let read = self.mem_buffer.get_bytes(&mut bytes, offset + bytestart);
            if offset + bytestart == 0 && read == 0 {
                return Err(MemoryAccessException::new("invalid memory"));
            }
            let mut result: i32 = 0;
            for b in bytes {
                result = (result << 8) | (b as i32);
            }
            Ok(result)
        }

        fn get_instruction_bits(
            &self,
            _offset: i32,
            _startbit: i32,
            _size: i32,
        ) -> Result<i32, MemoryAccessException> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_context_register_value(&self) -> Option<Box<dyn RegisterValue>> {
            None
        }

        fn get_context_bytes(&self, bytestart: i32, _bytesize: i32) -> i32 {
            self.context[(bytestart / 4) as usize]
        }

        fn get_context_words(&self) -> Vec<i32> {
            self.context.clone()
        }

        fn get_context_bits(&self, _startbit: i32, _bitsize: i32) -> i32 {
            unimplemented!("not exercised by this smoke test")
        }

        fn set_context_word(&mut self, i: usize, val: i32, mask: i32) {
            self.context[i] = (self.context[i] & !mask) | (mask & val);
        }

        fn is_valid(&self, buf: &dyn MemBuffer) -> bool {
            buf.get_address() == self.addr
        }

        fn get_flow_ref_addr(&self) -> Result<Address, SleighException> {
            Err(SleighException::with_message(format!(
                "Flow reference (inst_ref) is undefined at {}",
                self.addr
            )))
        }

        fn get_flow_dest_addr(&self) -> Result<Address, SleighException> {
            Err(SleighException::with_message(format!(
                "Flow destination (inst_dest) is undefined at {}",
                self.addr
            )))
        }

        fn add_commit(
            &mut self,
            _point: &ConstructState,
            _sym: Arc<dyn TripleSymbol>,
            num: i32,
            _mask: i32,
        ) {
            self.commits.push(num);
        }

        fn apply_commits(
            &mut self,
            _ctx: &mut dyn ProcessorContext,
        ) -> Result<(), MemoryAccessException> {
            self.commits.clear();
            Ok(())
        }

        fn get_fixed_handle(&mut self, construct_state: &ConstructState) -> FixedHandle {
            let key = construct_state as *const ConstructState as usize;
            self.handles.entry(key).or_default().clone()
        }
    }

    fn mock_context() -> MockSleighParserContext {
        MockSleighParserContext {
            addr: mock_addr(0x1000),
            mem_buffer: Arc::new(MockMemBuffer {
                address: mock_addr(0x1000),
                bytes: vec![0xDE, 0xAD, 0xBE, 0xEF],
            }),
            context: vec![0],
            commits: Vec::new(),
            handles: HashMap::new(),
        }
    }

    #[test]
    fn get_prototype_comes_from_parser_context_supertrait() {
        let ctx = mock_context();
        assert_eq!(ParserContext::get_prototype(&ctx).get_length(), 4);
    }

    #[test]
    fn n2addr_defaults_to_no_address() {
        let ctx = mock_context();
        assert_eq!(ctx.get_n2addr(), SpecialAddress::no_address());
    }

    #[test]
    fn cur_space_defaults_to_addr_space() {
        let ctx = mock_context();
        assert_eq!(ctx.get_cur_space(), *ctx.get_addr().space());
    }

    #[test]
    fn get_instruction_bytes_reads_big_endian_packed_value() {
        let ctx = mock_context();
        assert_eq!(ctx.get_instruction_bytes(0, 0, 2).unwrap(), 0xDEAD);
    }

    #[test]
    fn set_context_word_masks_in_place() {
        let mut ctx = mock_context();
        ctx.context[0] = 0xFF00_FF00u32 as i32;
        ctx.set_context_word(0, 0x0000_00AAu32 as i32, 0x0000_00FFu32 as i32);
        assert_eq!(ctx.context[0], 0xFF00_FFAAu32 as i32);
    }

    #[test]
    fn is_valid_checks_address_identity() {
        let ctx = mock_context();
        let same = MockMemBuffer {
            address: mock_addr(0x1000),
            bytes: vec![],
        };
        let different = MockMemBuffer {
            address: mock_addr(0x2000),
            bytes: vec![],
        };
        assert!(ctx.is_valid(&same));
        assert!(!ctx.is_valid(&different));
    }

    #[test]
    fn flow_ref_and_dest_addr_fail_when_undefined() {
        let ctx = mock_context();
        assert!(ctx.get_flow_ref_addr().is_err());
        assert!(ctx.get_flow_dest_addr().is_err());
    }

    #[test]
    fn fixed_handle_is_created_once_and_reused_by_identity() {
        let mut ctx = mock_context();
        let state = ConstructState::new(None);
        let first = ctx.get_fixed_handle(&state);
        let second = ctx.get_fixed_handle(&state);
        assert_eq!(first, second);
        assert_eq!(ctx.handles.len(), 1);
    }

    #[test]
    fn apply_commits_clears_pending_list() {
        struct MockProcessorContext;
        impl crate::program::model::lang::ProcessorContextView for MockProcessorContext {
            fn get_base_context_register(&self) -> Option<crate::program::model::lang::RegisterRef> {
                None
            }
            fn get_registers(&self) -> Vec<crate::program::model::lang::RegisterRef> {
                Vec::new()
            }
            fn get_register(&self, _name: &str) -> Option<crate::program::model::lang::RegisterRef> {
                None
            }
            fn get_value(
                &self,
                _register: &crate::program::model::lang::register::Register,
                _signed: bool,
            ) -> Option<i128> {
                None
            }
            fn get_register_value(
                &self,
                _register: &crate::program::model::lang::register::Register,
            ) -> Option<Box<dyn RegisterValue>> {
                None
            }
            fn has_value(&self, _register: &crate::program::model::lang::register::Register) -> bool {
                false
            }
        }
        impl ProcessorContext for MockProcessorContext {
            fn set_value(
                &mut self,
                _register: &crate::program::model::lang::register::Register,
                _value: i128,
            ) -> Result<(), crate::program::model::listing::context_change_exception::ContextChangeException> {
                Ok(())
            }
            fn set_register_value(
                &mut self,
                _value: Box<dyn RegisterValue>,
            ) -> Result<(), crate::program::model::listing::context_change_exception::ContextChangeException> {
                Ok(())
            }
            fn clear_register(
                &mut self,
                _register: &crate::program::model::lang::register::Register,
            ) -> Result<(), crate::program::model::listing::context_change_exception::ContextChangeException> {
                Ok(())
            }
        }

        let mut ctx = mock_context();
        ctx.commits.push(1);
        let mut pctx = MockProcessorContext;
        ctx.apply_commits(&mut pctx).unwrap();
        assert!(ctx.commits.is_empty());
    }

    #[test]
    fn usable_as_trait_object() {
        let ctx: Box<dyn SleighParserContext> = Box::new(mock_context());
        assert_eq!(ctx.get_addr(), mock_addr(0x1000));
    }
}

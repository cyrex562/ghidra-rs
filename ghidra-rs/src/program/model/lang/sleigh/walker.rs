use crate::program::model::address::Address;
use crate::program::model::lang::sleigh::constructor::Constructor;
use crate::program::model::lang::sleigh::FixedHandle;
use crate::program::model::mem::MemoryAccessException;
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum SleighError {
    #[error("Unknown instruction at {0}")]
    UnknownInstruction(Address),
    #[error("Memory access error: {0}")]
    MemoryAccess(#[from] MemoryAccessException),
}

pub trait MemBuffer: Send + Sync {
    fn get_address(&self) -> Address;
    fn get_byte(&self, offset: i32) -> Result<u8, MemoryAccessException>;
    fn get_bytes(&self, buf: &mut [u8], offset: i32) -> usize;
    fn is_big_endian(&self) -> bool;
}

pub struct ParserContext {
    pub addr: Address,
    pub naddr: Address,
    pub n2addr: Address,
    pub context: Vec<u32>,
    pub mem_buffer: Arc<dyn MemBuffer>,
    pub handle_map: HashMap<usize, FixedHandle>, // Map from ConstructState unique ID to handle
}

impl ParserContext {
    pub fn get_instruction_bits(
        &self,
        offset: i32,
        startbit: i32,
        size: i32,
    ) -> Result<u32, MemoryAccessException> {
        let byte_offset = offset + (startbit / 8);
        let bit_offset = startbit % 8;
        let byte_size = (bit_offset + size - 1) / 8 + 1;

        let mut bytes = vec![0u8; byte_size as usize];
        let read_size = self.mem_buffer.get_bytes(&mut bytes, byte_offset);
        if byte_offset == 0 && read_size == 0 {
            return Err(MemoryAccessException("invalid memory".to_string()));
        }

        let mut res = 0u32;
        for i in 0..byte_size {
            res <<= 8;
            res |= bytes[i as usize] as u32;
        }

        res <<= 8 * (4 - byte_size) + bit_offset;
        res >>= 32 - size;
        Ok(res)
    }

    pub fn get_context_bits(&self, startbit: i32, size: i32) -> u32 {
        let int_start = (startbit / 32) as usize;
        if int_start >= self.context.len() {
            return 0;
        }
        let mut res = self.context[int_start];
        let bit_offset = (startbit % 32) as u32;
        let unused_bits = 32 - size as u32;
        res <<= bit_offset;
        res >>= unused_bits;

        let remaining = size as i32 - 32 + bit_offset as i32;
        if remaining > 0 && int_start + 1 < self.context.len() {
            let mut res2 = self.context[int_start + 1];
            res2 >>= 32 - remaining;
            res |= res2;
        }
        res
    }
}

pub struct ConstructState {
    pub ct: Option<Arc<Constructor>>,
    pub parent: Option<usize>, // Index in a flat list for safety
    pub sub_states: Vec<usize>,
    pub offset: i32,
    pub length: i32,
}

impl ConstructState {
    pub fn new(parent: Option<usize>) -> Self {
        Self {
            ct: None,
            parent,
            sub_states: Vec::new(),
            offset: 0,
            length: 0,
        }
    }
}

pub struct ParserWalker {
    pub context: Arc<ParserContext>,
    pub states: Vec<ConstructState>,
    pub current_state: usize,
    pub depth: i32,
    pub breadcrumb: Vec<usize>,
    pub offset: i32,
}

impl ParserWalker {
    pub fn new(context: Arc<ParserContext>) -> Self {
        Self {
            context,
            states: vec![ConstructState::new(None)],
            current_state: 0,
            depth: 0,
            breadcrumb: vec![0; 65],
            offset: 0,
        }
    }

    pub fn allocate_operand(&mut self, i: usize) -> usize {
        let parent_idx = self.current_state;
        let new_idx = self.states.len();
        self.states.push(ConstructState::new(Some(parent_idx)));

        let parent = &mut self.states[parent_idx];
        if parent.sub_states.len() <= i {
            parent.sub_states.resize(i + 1, 0);
        }
        parent.sub_states[i] = new_idx;
        new_idx
    }

    pub fn base_state(&mut self) {
        self.current_state = 0;
        self.depth = 0;
        self.breadcrumb[0] = 0;
    }

    pub fn push_operand(&mut self, i: usize) {
        self.breadcrumb[self.depth as usize] = i + 1;
        self.depth += 1;
        self.current_state = self.states[self.current_state].sub_states[i];
        self.breadcrumb[self.depth as usize] = 0;
    }

    pub fn pop_operand(&mut self) {
        if let Some(parent) = self.states[self.current_state].parent {
            self.current_state = parent;
            self.depth -= 1;
        }
    }

    pub fn get_instruction_bits(
        &self,
        startbit: i32,
        size: i32,
    ) -> Result<u32, MemoryAccessException> {
        self.context
            .get_instruction_bits(self.offset, startbit, size)
    }

    pub fn get_context_bits(&self, startbit: i32, size: i32) -> u32 {
        self.context.get_context_bits(startbit, size)
    }

    pub fn get_fixed_handle(&self, i: usize) -> Option<&FixedHandle> {
        let sub_id = self.states[self.current_state].sub_states[i];
        self.context.handle_map.get(&sub_id)
    }

    pub fn get_parent_handle(&self) -> Option<&FixedHandle> {
        self.context.handle_map.get(&self.current_state)
    }
}

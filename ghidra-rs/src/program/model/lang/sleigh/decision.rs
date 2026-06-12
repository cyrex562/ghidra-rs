use super::constructor::Constructor;
use super::pattern::DisjointPattern;
use super::symbol::SubtableSymbol;
use super::SleighLanguage;
use crate::program::model::lang::sleigh::pattern::Pattern;
use crate::program::model::lang::sleigh::walker::{ParserWalker, SleighError};
use crate::program::model::pcode::decoder::{Decoder, DecoderError};
use crate::program::model::pcode::ids::*;
use std::sync::Arc;

pub struct DecisionNode {
    pub context_decision: bool,
    pub start_bit: i32,
    pub bit_size: i32,
    pub patterns: Vec<DisjointPattern>,
    pub constructors: Vec<i32>, // Constructor IDs within subtable
    pub children: Vec<DecisionNode>,
}

impl DecisionNode {
    pub fn new() -> Self {
        Self {
            context_decision: false,
            start_bit: 0,
            bit_size: 0,
            patterns: Vec::new(),
            constructors: Vec::new(),
            children: Vec::new(),
        }
    }

    pub fn decode(
        &mut self,
        decoder: &dyn Decoder,
        sleigh: &SleighLanguage,
        sub: &SubtableSymbol,
    ) -> Result<(), DecoderError> {
        let el = decoder.open_element_with_id(ELEM_DECISION)?;

        self.context_decision = decoder.read_bool_with_id(ATTRIB_CONTEXT)?;
        self.start_bit = decoder.read_signed_integer_with_id(ATTRIB_STARTBIT)? as i32;
        self.bit_size = decoder.read_signed_integer_with_id(ATTRIB_SIZE)? as i32;

        while decoder.peek_element()? != 0 {
            let subel = decoder.peek_element()?;
            if subel == ELEM_PAIR.id {
                let pair_open = decoder.open_element()?;
                let id = decoder.read_unsigned_integer_with_id(ATTRIB_ID)? as i32;
                self.constructors.push(id);
                self.patterns.push(DisjointPattern::decode(decoder)?);
                decoder.close_element(pair_open)?;
            } else if subel == ELEM_DECISION.id {
                let mut subnode = DecisionNode::new();
                subnode.decode(decoder, sleigh, sub)?;
                self.children.push(subnode);
            } else {
                return Err(DecoderError::Generic(format!(
                    "Unknown decision sub-element: {}",
                    subel
                )));
            }
        }

        decoder.close_element(el)?;
        Ok(())
    }

    pub fn resolve(
        &self,
        walker: &ParserWalker,
        subtable: &SubtableSymbol,
    ) -> Result<Arc<Constructor>, SleighError> {
        if self.bit_size == 0 {
            for (i, pattern) in self.patterns.iter().enumerate() {
                if pattern.is_match(walker) {
                    return Ok(subtable.constructors[self.constructors[i] as usize].clone());
                }
            }
            return Err(SleighError::UnknownInstruction(walker.context.addr.clone()));
        }

        let val = if self.context_decision {
            walker.get_context_bits(self.start_bit, self.bit_size)
        } else {
            walker.get_instruction_bits(self.start_bit, self.bit_size)?
        };

        if (val as usize) < self.children.len() {
            self.children[val as usize].resolve(walker, subtable)
        } else {
            Err(SleighError::UnknownInstruction(walker.context.addr.clone()))
        }
    }
}

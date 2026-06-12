pub mod block;
pub use self::block::PatternBlock;
use crate::program::model::pcode::{
    Decoder, DecoderError, ELEM_COMBINE_PAT, ELEM_CONTEXT_PAT, ELEM_INSTRUCT_PAT,
};

use crate::program::model::lang::sleigh::walker::ParserWalker;

pub trait Pattern: Send + Sync {
    fn is_always_true(&self) -> bool;
    fn is_always_false(&self) -> bool;
    fn is_always_instruction_true(&self) -> bool;
    fn is_match(&self, walker: &ParserWalker) -> bool;
}

pub trait DisjointPatternTrait: Pattern {
    fn get_block(&self, context: bool) -> Option<&PatternBlock>;
}

pub enum DisjointPattern {
    Instruction(InstructionPattern),
    Context(ContextPattern),
    Combine(CombinePattern),
}

impl Pattern for DisjointPattern {
    fn is_always_true(&self) -> bool {
        match self {
            Self::Instruction(p) => p.is_always_true(),
            Self::Context(p) => p.is_always_true(),
            Self::Combine(p) => p.is_always_true(),
        }
    }

    fn is_always_false(&self) -> bool {
        match self {
            Self::Instruction(p) => p.is_always_false(),
            Self::Context(p) => p.is_always_false(),
            Self::Combine(p) => p.is_always_false(),
        }
    }

    fn is_always_instruction_true(&self) -> bool {
        match self {
            Self::Instruction(p) => p.is_always_instruction_true(),
            Self::Context(p) => p.is_always_instruction_true(),
            Self::Combine(p) => p.is_always_instruction_true(),
        }
    }

    fn is_match(&self, walker: &ParserWalker) -> bool {
        match self {
            Self::Instruction(p) => p.is_match(walker),
            Self::Context(p) => p.is_match(walker),
            Self::Combine(p) => p.is_match(walker),
        }
    }
}

impl DisjointPattern {
    pub fn decode(decoder: &dyn Decoder) -> Result<Self, DecoderError> {
        let el = decoder.peek_element()?;
        if el == ELEM_INSTRUCT_PAT.id {
            Ok(Self::Instruction(InstructionPattern::decode(decoder)?))
        } else if el == ELEM_CONTEXT_PAT.id {
            Ok(Self::Context(ContextPattern::decode(decoder)?))
        } else if el == ELEM_COMBINE_PAT.id {
            Ok(Self::Combine(CombinePattern::decode(decoder)?))
        } else {
            Err(DecoderError::Generic(format!(
                "Unknown disjoint pattern type: {}",
                el
            )))
        }
    }

    pub fn get_block(&self, context: bool) -> Option<&PatternBlock> {
        match self {
            Self::Instruction(p) => p.get_block(context),
            Self::Context(p) => p.get_block(context),
            Self::Combine(p) => p.get_block(context),
        }
    }
}

pub struct InstructionPattern {
    maskvalue: PatternBlock,
}

impl InstructionPattern {
    pub fn decode(decoder: &dyn Decoder) -> Result<Self, DecoderError> {
        let el = decoder.open_element_with_id(ELEM_INSTRUCT_PAT)?;
        let maskvalue = PatternBlock::decode(decoder)?;
        decoder.close_element(el)?;
        Ok(Self { maskvalue })
    }

    pub fn get_block(&self, context: bool) -> Option<&PatternBlock> {
        if context {
            None
        } else {
            Some(&self.maskvalue)
        }
    }

    pub fn is_match(&self, walker: &ParserWalker) -> bool {
        self.maskvalue.is_instruction_match(walker)
    }
}

impl Pattern for InstructionPattern {
    fn is_always_true(&self) -> bool {
        self.maskvalue.is_always_true()
    }
    fn is_always_false(&self) -> bool {
        self.maskvalue.is_always_false()
    }
    fn is_always_instruction_true(&self) -> bool {
        self.maskvalue.is_always_true()
    }
    fn is_match(&self, walker: &ParserWalker) -> bool {
        self.maskvalue.is_instruction_match(walker)
    }
}

pub struct ContextPattern {
    maskvalue: PatternBlock,
}

impl ContextPattern {
    pub fn decode(decoder: &dyn Decoder) -> Result<Self, DecoderError> {
        let el = decoder.open_element_with_id(ELEM_CONTEXT_PAT)?;
        let maskvalue = PatternBlock::decode(decoder)?;
        decoder.close_element(el)?;
        Ok(Self { maskvalue })
    }

    pub fn get_block(&self, context: bool) -> Option<&PatternBlock> {
        if context {
            Some(&self.maskvalue)
        } else {
            None
        }
    }

    pub fn is_match(&self, walker: &ParserWalker) -> bool {
        self.maskvalue.is_context_match(walker)
    }
}

impl Pattern for ContextPattern {
    fn is_always_true(&self) -> bool {
        self.maskvalue.is_always_true()
    }
    fn is_always_false(&self) -> bool {
        self.maskvalue.is_always_false()
    }
    fn is_always_instruction_true(&self) -> bool {
        true
    }
    fn is_match(&self, walker: &ParserWalker) -> bool {
        self.maskvalue.is_context_match(walker)
    }
}

pub struct CombinePattern {
    context: ContextPattern,
    instr: InstructionPattern,
}

impl CombinePattern {
    pub fn decode(decoder: &dyn Decoder) -> Result<Self, DecoderError> {
        let el = decoder.open_element_with_id(ELEM_COMBINE_PAT)?;
        let context = ContextPattern::decode(decoder)?;
        let instr = InstructionPattern::decode(decoder)?;
        decoder.close_element(el)?;
        Ok(Self { context, instr })
    }

    pub fn get_block(&self, context: bool) -> Option<&PatternBlock> {
        if context {
            self.context.get_block(true)
        } else {
            self.instr.get_block(false)
        }
    }

    pub fn is_match(&self, walker: &ParserWalker) -> bool {
        self.context.is_match(walker) && self.instr.is_match(walker)
    }
}

impl Pattern for CombinePattern {
    fn is_always_true(&self) -> bool {
        self.context.is_always_true() && self.instr.is_always_true()
    }
    fn is_always_false(&self) -> bool {
        self.context.is_always_false() || self.instr.is_always_false()
    }
    fn is_always_instruction_true(&self) -> bool {
        self.instr.is_always_instruction_true()
    }
    fn is_match(&self, walker: &ParserWalker) -> bool {
        self.context.is_match(walker) && self.instr.is_match(walker)
    }
}

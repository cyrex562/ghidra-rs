use crate::program::model::address::AddressSpace;
use crate::program::model::pcode::{
    Decoder, DecoderError, Encoder, ATTRIB_PLUS, ATTRIB_S, ATTRIB_SPACE, ATTRIB_VAL,
    ELEM_CONST_CURSPACE, ELEM_CONST_CURSPACE_SIZE, ELEM_CONST_FLOWDEST, ELEM_CONST_FLOWDEST_SIZE,
    ELEM_CONST_FLOWREF, ELEM_CONST_FLOWREF_SIZE, ELEM_CONST_HANDLE, ELEM_CONST_NEXT,
    ELEM_CONST_NEXT2, ELEM_CONST_REAL, ELEM_CONST_RELATIVE, ELEM_CONST_SPACEID, ELEM_CONST_START,
};
use std::io;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConstTplType {
    Real = 0,
    Handle = 1,
    JStart = 2,
    JNext = 3,
    JNext2 = 4,
    JCurSpace = 5,
    JCurSpaceSize = 6,
    SpaceId = 7,
    JRelative = 8,
    JFlowRef = 9,
    JFlowRefSize = 10,
    JFlowDest = 11,
    JFlowDestSize = 12,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConstTplSelect {
    VSpace = 0,
    VOffset = 1,
    VSize = 2,
    VOffsetPlus = 3,
}

#[derive(Debug, Clone)]
pub struct ConstTpl {
    pub tp: ConstTplType,
    pub value_real: u64,
    pub value_spaceid: Option<Arc<AddressSpace>>,
    pub handle_index: i16,
    pub select: Option<ConstTplSelect>,
}

impl ConstTpl {
    pub fn new() -> Self {
        Self {
            tp: ConstTplType::Real,
            value_real: 0,
            value_spaceid: None,
            handle_index: 0,
            select: None,
        }
    }

    pub fn decode(&mut self, decoder: &dyn Decoder) -> Result<(), DecoderError> {
        let el = decoder.open_element()?;
        if el == ELEM_CONST_REAL.id {
            self.tp = ConstTplType::Real;
            self.value_real = decoder.read_unsigned_integer_with_id(ATTRIB_VAL)?;
        } else if el == ELEM_CONST_HANDLE.id {
            self.tp = ConstTplType::Handle;
            self.handle_index = decoder.read_signed_integer_with_id(ATTRIB_VAL)? as i16;
            let s = decoder.read_signed_integer_with_id(ATTRIB_S)? as i32;
            self.select = match s {
                0 => Some(ConstTplSelect::VSpace),
                1 => Some(ConstTplSelect::VOffset),
                2 => Some(ConstTplSelect::VSize),
                3 => Some(ConstTplSelect::VOffsetPlus),
                _ => {
                    return Err(DecoderError::Generic(
                        "Bad handle selector encoding".to_string(),
                    ))
                }
            };
            if self.select == Some(ConstTplSelect::VOffsetPlus) {
                self.value_real = decoder.read_unsigned_integer_with_id(ATTRIB_PLUS)?;
            }
        } else if el == ELEM_CONST_START.id {
            self.tp = ConstTplType::JStart;
        } else if el == ELEM_CONST_NEXT.id {
            self.tp = ConstTplType::JNext;
        } else if el == ELEM_CONST_NEXT2.id {
            self.tp = ConstTplType::JNext2;
        } else if el == ELEM_CONST_CURSPACE.id {
            self.tp = ConstTplType::JCurSpace;
        } else if el == ELEM_CONST_CURSPACE_SIZE.id {
            self.tp = ConstTplType::JCurSpaceSize;
        } else if el == ELEM_CONST_SPACEID.id {
            self.tp = ConstTplType::SpaceId;
            self.value_spaceid = Some(decoder.read_space_with_id(ATTRIB_SPACE)?);
        } else if el == ELEM_CONST_RELATIVE.id {
            self.tp = ConstTplType::JRelative;
            self.value_real = decoder.read_unsigned_integer_with_id(ATTRIB_VAL)?;
        } else if el == ELEM_CONST_FLOWREF.id {
            self.tp = ConstTplType::JFlowRef;
        } else if el == ELEM_CONST_FLOWREF_SIZE.id {
            self.tp = ConstTplType::JFlowRefSize;
        } else if el == ELEM_CONST_FLOWDEST.id {
            self.tp = ConstTplType::JFlowDest;
        } else if el == ELEM_CONST_FLOWDEST_SIZE.id {
            self.tp = ConstTplType::JFlowDestSize;
        } else {
            return Err(DecoderError::Generic(
                "Bad encoding for ConstTpl".to_string(),
            ));
        }
        decoder.close_element(el)?;
        Ok(())
    }

    /// Returns true if this is a real constant with value zero.
    pub fn is_zero(&self) -> bool {
        self.tp == ConstTplType::Real && self.value_real == 0
    }

    /// Remaps a handle-typed constant's index through `handmap` (replaces old handles with new
    /// handles, e.g. when a macro's operands are substituted into its caller).
    pub fn change_handle_index(&mut self, handmap: &[i32]) {
        if self.tp == ConstTplType::Handle {
            self.handle_index = handmap[self.handle_index as usize] as i16;
        }
    }

    pub fn encode(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
        match self.tp {
            ConstTplType::Real => {
                encoder.open_element(ELEM_CONST_REAL)?;
                encoder.write_unsigned_integer(ATTRIB_VAL, self.value_real)?;
                encoder.close_element(ELEM_CONST_REAL)
            }
            ConstTplType::Handle => {
                encoder.open_element(ELEM_CONST_HANDLE)?;
                encoder.write_signed_integer(ATTRIB_VAL, self.handle_index as i64)?;
                let select = self
                    .select
                    .expect("handle-typed ConstTpl must have a select field");
                encoder.write_signed_integer(ATTRIB_S, select as i64)?;
                if select == ConstTplSelect::VOffsetPlus {
                    encoder.write_unsigned_integer(ATTRIB_PLUS, self.value_real)?;
                }
                encoder.close_element(ELEM_CONST_HANDLE)
            }
            ConstTplType::JStart => {
                encoder.open_element(ELEM_CONST_START)?;
                encoder.close_element(ELEM_CONST_START)
            }
            ConstTplType::JNext => {
                encoder.open_element(ELEM_CONST_NEXT)?;
                encoder.close_element(ELEM_CONST_NEXT)
            }
            ConstTplType::JNext2 => {
                encoder.open_element(ELEM_CONST_NEXT2)?;
                encoder.close_element(ELEM_CONST_NEXT2)
            }
            ConstTplType::JCurSpace => {
                encoder.open_element(ELEM_CONST_CURSPACE)?;
                encoder.close_element(ELEM_CONST_CURSPACE)
            }
            ConstTplType::JCurSpaceSize => {
                encoder.open_element(ELEM_CONST_CURSPACE_SIZE)?;
                encoder.close_element(ELEM_CONST_CURSPACE_SIZE)
            }
            ConstTplType::SpaceId => {
                encoder.open_element(ELEM_CONST_SPACEID)?;
                let spc = self
                    .value_spaceid
                    .as_ref()
                    .expect("spaceid-typed ConstTpl must have a space");
                encoder.write_space(ATTRIB_SPACE, spc)?;
                encoder.close_element(ELEM_CONST_SPACEID)
            }
            ConstTplType::JRelative => {
                encoder.open_element(ELEM_CONST_RELATIVE)?;
                encoder.write_unsigned_integer(ATTRIB_VAL, self.value_real)?;
                encoder.close_element(ELEM_CONST_RELATIVE)
            }
            ConstTplType::JFlowRef => {
                encoder.open_element(ELEM_CONST_FLOWREF)?;
                encoder.close_element(ELEM_CONST_FLOWREF)
            }
            ConstTplType::JFlowRefSize => {
                encoder.open_element(ELEM_CONST_FLOWREF_SIZE)?;
                encoder.close_element(ELEM_CONST_FLOWREF_SIZE)
            }
            ConstTplType::JFlowDest => {
                encoder.open_element(ELEM_CONST_FLOWDEST)?;
                encoder.close_element(ELEM_CONST_FLOWDEST)
            }
            ConstTplType::JFlowDestSize => {
                encoder.open_element(ELEM_CONST_FLOWDEST_SIZE)?;
                encoder.close_element(ELEM_CONST_FLOWDEST_SIZE)
            }
        }
    }
}

/// `ConstTpl.calc_mask`: the mask of the low `n` bytes, for `n` in `0..=8`.
pub const CALC_MASK: [u64; 9] = [
    0,
    0xff,
    0xffff,
    0xff_ffff,
    0xffff_ffff,
    0xff_ffff_ffff,
    0xffff_ffff_ffff,
    0xff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
];

/// Run-time evaluation of a constant template against a parsed instruction (the
/// `ghidra.app.plugin.processors.sleigh.template.ConstTpl` half of this shared type).
impl ConstTpl {
    /// Port of `ConstTpl.getReal()`.
    pub fn get_real(&self) -> i64 {
        self.value_real as i64
    }

    /// Port of `ConstTpl.isUniqueSpace()`.
    pub fn is_unique_space(&self) -> bool {
        self.tp == ConstTplType::SpaceId
            && self
                .value_spaceid
                .as_ref()
                .is_some_and(|s| s.space_type() == crate::program::model::address::AddressSpaceType::Unique)
    }

    /// The handle this constant refers to, for a `HANDLE` constant.
    fn handle(
        &self,
        walker: &crate::program::model::lang::sleigh::walker::ParserWalker<'_>,
    ) -> crate::program::model::lang::sleigh::FixedHandle {
        walker.get_fixed_handle(self.handle_index as usize)
    }

    /// The value of this constant for the instruction the walker is on. Port of
    /// `ConstTpl.fix(ParserWalker)`.
    ///
    /// # Errors
    /// A [`SleighError`](crate::program::model::lang::sleigh::walker::SleighError) if the
    /// constant needs an address or space the context does not define (Java throws a
    /// `SleighException` or dereferences `null`).
    pub fn fix(
        &self,
        walker: &crate::program::model::lang::sleigh::walker::ParserWalker<'_>,
    ) -> Result<i64, crate::program::model::lang::sleigh::walker::SleighError> {
        use crate::app::plugin::processors::sleigh::sleigh_exception::SleighException;
        use crate::program::model::address::AddressSpaceType;
        let missing = |what: &str| SleighException::with_message(format!("{what} is undefined"));
        Ok(match self.tp {
            ConstTplType::JStart => walker.get_addr().offset(),
            ConstTplType::JNext => walker.get_naddr().ok_or_else(|| missing("inst_next"))?.offset(),
            ConstTplType::JNext2 => walker.get_n2addr().offset(),
            ConstTplType::JFlowRef => walker.get_flow_ref_addr()?.offset(),
            ConstTplType::JFlowRefSize => walker.get_flow_ref_addr()?.space().pointer_size() as i64,
            ConstTplType::JFlowDest => walker.get_flow_dest_addr()?.offset(),
            ConstTplType::JFlowDestSize => {
                walker.get_flow_dest_addr()?.space().pointer_size() as i64
            }
            ConstTplType::JCurSpaceSize => walker.get_cur_space().pointer_size() as i64,
            ConstTplType::JCurSpace => walker.get_cur_space().space_id() as i64,
            ConstTplType::Handle => {
                let hand = self.handle(walker);
                let space_of = |s: &Option<Arc<AddressSpace>>| {
                    s.clone().ok_or_else(|| missing("handle space"))
                };
                match self.select {
                    Some(ConstTplSelect::VSpace) => {
                        if hand.offset_space.is_none() {
                            space_of(&hand.space)?.space_id() as i64
                        } else {
                            space_of(&hand.temp_space)?.space_id() as i64
                        }
                    }
                    Some(ConstTplSelect::VOffset) => {
                        if hand.offset_space.is_none() {
                            hand.offset_offset
                        } else {
                            hand.temp_offset
                        }
                    }
                    Some(ConstTplSelect::VSize) => hand.size as i64,
                    Some(ConstTplSelect::VOffsetPlus) => {
                        let value_real = self.value_real as i64;
                        if space_of(&hand.space)?.space_type() != AddressSpaceType::Constant {
                            // Adjust offset by truncation amount
                            if hand.offset_space.is_none() {
                                hand.offset_offset.wrapping_add(value_real & 0xffff)
                            } else {
                                hand.temp_offset.wrapping_add(value_real & 0xffff)
                            }
                        } else {
                            // If we are a constant, shift by the truncation amount
                            let val = if hand.offset_space.is_none() {
                                hand.offset_offset
                            } else {
                                hand.temp_offset
                            };
                            val.wrapping_shr((8 * (value_real >> 16)) as u32)
                        }
                    }
                    None => 0,
                }
            }
            ConstTplType::JRelative | ConstTplType::Real => self.value_real as i64,
            ConstTplType::SpaceId => self
                .value_spaceid
                .as_ref()
                .ok_or_else(|| missing("space id"))?
                .space_id() as i64,
        })
    }

    /// The address space this constant denotes. Port of `ConstTpl.fixSpace(ParserWalker)`.
    ///
    /// # Errors
    /// "ConstTpl is not a spaceid as expected" if the constant does not name a space.
    pub fn fix_space(
        &self,
        walker: &crate::program::model::lang::sleigh::walker::ParserWalker<'_>,
    ) -> Result<Arc<AddressSpace>, crate::program::model::lang::sleigh::walker::SleighError> {
        use crate::app::plugin::processors::sleigh::sleigh_exception::SleighException;
        let space = match self.tp {
            ConstTplType::JCurSpace => Some(walker.get_cur_space()),
            ConstTplType::Handle if self.select == Some(ConstTplSelect::VSpace) => {
                let hand = self.handle(walker);
                if hand.offset_space.is_none() {
                    hand.space
                } else {
                    hand.temp_space
                }
            }
            ConstTplType::SpaceId => self.value_spaceid.clone(),
            ConstTplType::JFlowRef => Some(walker.get_flow_ref_addr()?.space().clone()),
            _ => None,
        };
        space.ok_or_else(|| {
            SleighException::with_message("ConstTpl is not a spaceid as expected").into()
        })
    }

    /// Fills in the space of `hand` from this (space) constant. Port of
    /// `ConstTpl.fillinSpace(FixedHandle, ParserWalker)`.
    ///
    /// # Errors
    /// "ConstTpl is not a spaceid as expected" if the constant does not name a space.
    pub fn fillin_space(
        &self,
        hand: &mut crate::program::model::lang::sleigh::FixedHandle,
        walker: &crate::program::model::lang::sleigh::walker::ParserWalker<'_>,
    ) -> Result<(), crate::program::model::lang::sleigh::walker::SleighError> {
        use crate::app::plugin::processors::sleigh::sleigh_exception::SleighException;
        match self.tp {
            ConstTplType::JCurSpace => {
                hand.space = Some(walker.get_cur_space());
                return Ok(());
            }
            ConstTplType::Handle if self.select == Some(ConstTplSelect::VSpace) => {
                hand.space = self.handle(walker).space;
                return Ok(());
            }
            // Java falls through from a non-space HANDLE select into the SPACEID case
            ConstTplType::Handle | ConstTplType::SpaceId => {
                hand.space = self.value_spaceid.clone();
                return Ok(());
            }
            _ => {}
        }
        Err(SleighException::with_message("ConstTpl is not a spaceid as expected").into())
    }

    /// Fills in the offset of `hand` from this (offset) constant. Port of
    /// `ConstTpl.fillinOffset(FixedHandle, ParserWalker)`.
    ///
    /// # Errors
    /// Whatever [`ConstTpl::fix`] reports.
    pub fn fillin_offset(
        &self,
        hand: &mut crate::program::model::lang::sleigh::FixedHandle,
        walker: &crate::program::model::lang::sleigh::walker::ParserWalker<'_>,
    ) -> Result<(), crate::program::model::lang::sleigh::walker::SleighError> {
        if self.tp == ConstTplType::Handle {
            let otherhand = self.handle(walker);
            hand.offset_space = otherhand.offset_space;
            hand.offset_offset = otherhand.offset_offset;
            hand.offset_size = otherhand.offset_size;
            hand.temp_space = otherhand.temp_space;
            hand.temp_offset = otherhand.temp_offset;
        } else {
            hand.offset_space = None;
            let off = self.fix(walker)?;
            hand.offset_offset = match &hand.space {
                Some(space) => space.truncate_offset(off),
                None => off,
            };
        }
        Ok(())
    }
}

#[cfg(test)]
mod runtime_tests {
    use super::*;
    use crate::app::plugin::processors::sleigh::sleigh_parser_context::SleighParserContext;
    use crate::program::model::address::{Address, AddressSpaceType};
    use crate::program::model::lang::sleigh::walker::ParserWalker;
    use crate::program::model::lang::sleigh::FixedHandle;
    use crate::program::model::mem::{ByteMemBufferImpl, MemBuffer};

    fn ram() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    fn context() -> SleighParserContext {
        let mem: Arc<dyn MemBuffer> =
            Arc::new(ByteMemBufferImpl::new(Address::new(ram(), 0x400), vec![0; 4], true));
        SleighParserContext::for_tests(mem, Vec::new())
    }

    fn handle(select: ConstTplSelect, plus: u64) -> ConstTpl {
        ConstTpl {
            tp: ConstTplType::Handle,
            value_real: plus,
            value_spaceid: None,
            handle_index: 0,
            select: Some(select),
        }
    }

    /// A walker on the root, whose operand 0 has handle `hand`.
    fn with_operand_handle(ctx: &SleighParserContext, hand: FixedHandle) -> ParserWalker<'_> {
        let mut walker = ParserWalker::new(ctx);
        walker.base_state();
        walker.allocate_operand().unwrap();
        walker.set_parent_handle(hand);
        walker.pop_operand();
        walker
    }

    #[test]
    fn address_constants_come_from_the_context() {
        let ctx = context();
        let mut walker = ParserWalker::new(&ctx);
        walker.base_state();
        let mut c = ConstTpl::new();
        c.tp = ConstTplType::JStart;
        assert_eq!(c.fix(&walker).unwrap(), 0x400);
        c.tp = ConstTplType::JNext; // for_tests: inst_next is the instruction itself
        assert_eq!(c.fix(&walker).unwrap(), 0x400);
        c.tp = ConstTplType::JCurSpaceSize;
        assert_eq!(c.fix(&walker).unwrap(), 4);
        c.tp = ConstTplType::JCurSpace;
        assert_eq!(c.fix(&walker).unwrap(), ram().space_id() as i64);
        assert_eq!(c.fix_space(&walker).unwrap().name(), "ram");
        c.tp = ConstTplType::JFlowRef; // undefined in this context
        assert!(c.fix(&walker).is_err());
        c.tp = ConstTplType::Real;
        c.value_real = 0x1234;
        assert_eq!(c.fix(&walker).unwrap(), 0x1234);
        assert!(c.fix_space(&walker).is_err());
    }

    #[test]
    fn handle_offsets_prefer_the_temporary_of_a_dynamic_handle() {
        let ctx = context();
        let mut hand = FixedHandle::new();
        hand.space = Some(ram());
        hand.offset_offset = 0x10;
        hand.size = 2;
        let walker = with_operand_handle(&ctx, hand.clone());
        assert_eq!(handle(ConstTplSelect::VOffset, 0).fix(&walker).unwrap(), 0x10);
        assert_eq!(handle(ConstTplSelect::VSize, 0).fix(&walker).unwrap(), 2);
        // plus the low 16 bits of the truncation amount
        assert_eq!(handle(ConstTplSelect::VOffsetPlus, 0x3_0002).fix(&walker).unwrap(), 0x12);

        let ctx = context();
        hand.offset_space = Some(ram());
        hand.temp_space = Some(AddressSpace::new("unique", 32, 1, AddressSpaceType::Unique, 3));
        hand.temp_offset = 0x80;
        let walker = with_operand_handle(&ctx, hand);
        assert_eq!(handle(ConstTplSelect::VOffset, 0).fix(&walker).unwrap(), 0x80);
        assert_eq!(
            handle(ConstTplSelect::VSpace, 0).fix_space(&walker).unwrap().name(),
            "unique"
        );
    }

    #[test]
    fn offset_plus_on_a_constant_shifts_out_truncated_bytes() {
        let ctx = context();
        let mut hand = FixedHandle::new();
        hand.space = Some(AddressSpace::new("const", 64, 1, AddressSpaceType::Constant, 0));
        hand.offset_offset = 0x1122_3344;
        let walker = with_operand_handle(&ctx, hand);
        // truncation amount 2 bytes (high 16 bits of value_real)
        assert_eq!(handle(ConstTplSelect::VOffsetPlus, 0x2_0000).fix(&walker).unwrap(), 0x1122);
    }
}

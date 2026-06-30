pub mod byte_ingest;
pub mod decoder;
pub mod ids;
pub mod list_linked;
pub mod packed;

use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
use std::fmt;
use std::sync::Arc;

pub use byte_ingest::ByteIngest;
pub use decoder::{Decoder, DecoderError};
pub use ids::*;
pub use list_linked::{LinkedIter, ListLinked};
pub use packed::PackedDecode;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum OpCode {
    Unimplemented = 0,
    Copy = 1,
    Load = 2,
    Store = 3,
    Branch = 4,
    CBranch = 5,
    BranchInd = 6,
    Call = 7,
    CallInd = 8,
    CallOther = 9,
    Return = 10,
    IntEqual = 11,
    IntNotEqual = 12,
    IntSless = 13,
    IntSlessEqual = 14,
    IntLess = 15,
    IntLessEqual = 16,
    IntZext = 17,
    IntSext = 18,
    IntAdd = 19,
    IntSub = 20,
    IntCarry = 21,
    IntScarry = 22,
    IntSborrow = 23,
    Int2Comp = 24,
    IntNegate = 25,
    IntXor = 26,
    IntAnd = 27,
    IntOr = 28,
    IntLeft = 29,
    IntRight = 30,
    IntSright = 31,
    IntMult = 32,
    IntDiv = 33,
    IntSdiv = 34,
    IntRem = 35,
    IntSrem = 36,
    BoolNegate = 37,
    BoolXor = 38,
    BoolAnd = 39,
    BoolOr = 40,
    FloatEqual = 41,
    FloatNotEqual = 42,
    FloatLess = 43,
    FloatLessEqual = 44,
    FloatNan = 46,
    FloatAdd = 47,
    FloatDiv = 48,
    FloatMult = 49,
    FloatSub = 50,
    FloatNeg = 51,
    FloatAbs = 52,
    FloatSqrt = 53,
    FloatInt2Float = 54,
    FloatFloat2Float = 55,
    FloatTrunc = 56,
    FloatCeil = 57,
    FloatFloor = 58,
    FloatRound = 59,
    MultiEqual = 60,
    Indirect = 61,
    Piece = 62,
    Subpiece = 63,
    Cast = 64,
    PtrAdd = 65,
    PtrSub = 66,
    SegmentOp = 67,
    CpoolRef = 68,
    New = 69,
    Insert = 70,
    Zpull = 71,
    Popcount = 72,
    Lzcount = 73,
    Spull = 74,
}

impl OpCode {
    pub fn mnemonic(&self) -> &'static str {
        match self {
            Self::Unimplemented => "UNIMPLEMENTED",
            Self::Copy => "COPY",
            Self::Load => "LOAD",
            Self::Store => "STORE",
            Self::Branch => "BRANCH",
            Self::CBranch => "CBRANCH",
            Self::BranchInd => "BRANCHIND",
            Self::Call => "CALL",
            Self::CallInd => "CALLIND",
            Self::CallOther => "CALLOTHER",
            Self::Return => "RETURN",
            Self::IntEqual => "INT_EQUAL",
            Self::IntNotEqual => "INT_NOTEQUAL",
            Self::IntSless => "INT_SLESS",
            Self::IntSlessEqual => "INT_SLESSEQUAL",
            Self::IntLess => "INT_LESS",
            Self::IntLessEqual => "INT_LESSEQUAL",
            Self::IntZext => "INT_ZEXT",
            Self::IntSext => "INT_SEXT",
            Self::IntAdd => "INT_ADD",
            Self::IntSub => "INT_SUB",
            Self::IntCarry => "INT_CARRY",
            Self::IntScarry => "INT_SCARRY",
            Self::IntSborrow => "INT_SBORROW",
            Self::Int2Comp => "INT_2COMP",
            Self::IntNegate => "INT_NEGATE",
            Self::IntXor => "INT_XOR",
            Self::IntAnd => "INT_AND",
            Self::IntOr => "INT_OR",
            Self::IntLeft => "INT_LEFT",
            Self::IntRight => "INT_RIGHT",
            Self::IntSright => "INT_SRIGHT",
            Self::IntMult => "INT_MULT",
            Self::IntDiv => "INT_DIV",
            Self::IntSdiv => "INT_SDIV",
            Self::IntRem => "INT_REM",
            Self::IntSrem => "INT_SREM",
            Self::BoolNegate => "BOOL_NEGATE",
            Self::BoolXor => "BOOL_XOR",
            Self::BoolAnd => "BOOL_AND",
            Self::BoolOr => "BOOL_OR",
            Self::FloatEqual => "FLOAT_EQUAL",
            Self::FloatNotEqual => "FLOAT_NOTEQUAL",
            Self::FloatLess => "FLOAT_LESS",
            Self::FloatLessEqual => "FLOAT_LESSEQUAL",
            Self::FloatNan => "FLOAT_NAN",
            Self::FloatAdd => "FLOAT_ADD",
            Self::FloatDiv => "FLOAT_DIV",
            Self::FloatMult => "FLOAT_MULT",
            Self::FloatSub => "FLOAT_SUB",
            Self::FloatNeg => "FLOAT_NEG",
            Self::FloatAbs => "FLOAT_ABS",
            Self::FloatSqrt => "FLOAT_SQRT",
            Self::FloatInt2Float => "INT2FLOAT",
            Self::FloatFloat2Float => "FLOAT2FLOAT",
            Self::FloatTrunc => "TRUNC",
            Self::FloatCeil => "CEIL",
            Self::FloatFloor => "FLOOR",
            Self::FloatRound => "ROUND",
            Self::MultiEqual => "MULTIEQUAL",
            Self::Indirect => "INDIRECT",
            Self::Piece => "PIECE",
            Self::Subpiece => "SUBPIECE",
            Self::Cast => "CAST",
            Self::PtrAdd => "PTRADD",
            Self::PtrSub => "PTRSUB",
            Self::SegmentOp => "SEGMENTOP",
            Self::CpoolRef => "CPOOLREF",
            Self::New => "NEW",
            Self::Insert => "INSERT",
            Self::Zpull => "ZPULL",
            Self::Popcount => "POPCOUNT",
            Self::Lzcount => "LZCOUNT",
            Self::Spull => "SPULL",
        }
    }

    pub fn is_commutative(&self) -> bool {
        match self {
            Self::IntEqual
            | Self::IntNotEqual
            | Self::IntAdd
            | Self::IntXor
            | Self::IntAnd
            | Self::IntOr
            | Self::IntMult
            | Self::BoolXor
            | Self::BoolAnd
            | Self::BoolOr
            | Self::FloatEqual
            | Self::FloatNotEqual
            | Self::FloatAdd
            | Self::FloatMult
            | Self::IntCarry
            | Self::IntScarry => true,
            _ => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SequenceNumber {
    pub pc: Address,
    pub uniq: i32,
    pub order: i32,
}

impl SequenceNumber {
    pub fn new(pc: Address, uniq: i32) -> Self {
        Self { pc, uniq, order: 0 }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VarnodeData {
    pub space: Arc<AddressSpace>,
    pub offset: u64,
    pub size: i32,
}

#[derive(Clone, Debug)]
pub struct Varnode {
    address: Address,
    size: i32,
}

impl Varnode {
    pub fn new(address: Address, size: i32) -> Self {
        Self { address, size }
    }

    pub fn get_address(&self) -> &Address {
        &self.address
    }

    pub fn get_size(&self) -> i32 {
        self.size
    }

    pub fn get_offset(&self) -> i64 {
        self.address.offset()
    }

    pub fn get_space_id(&self) -> i32 {
        self.address.space().space_id()
    }

    pub fn is_constant(&self) -> bool {
        self.address.space().space_type() == AddressSpaceType::Constant
    }

    pub fn is_unique(&self) -> bool {
        self.address.space().space_type() == AddressSpaceType::Unique
    }

    pub fn is_register(&self) -> bool {
        self.address.space().space_type() == AddressSpaceType::Register
    }

    pub fn is_address(&self) -> bool {
        self.address.space().space_type() == AddressSpaceType::Ram
    }

    pub fn contains(&self, addr: &Address) -> bool {
        if self.get_space_id() != addr.space().space_id() {
            return false;
        }
        if self.is_constant() {
            return self.get_offset() == addr.offset();
        }
        let end_offset = self.get_offset() + (self.size as i64) - 1;
        let addr_offset = addr.offset();

        if self.get_offset() > end_offset {
            return addr_offset >= self.get_offset();
        }
        addr_offset >= self.get_offset() && addr_offset <= end_offset
    }

    pub fn intersects(&self, other: &Varnode) -> bool {
        if self.get_space_id() != other.get_space_id() {
            return false;
        }
        if self.is_constant() {
            return self.get_offset() == other.get_offset();
        }
        let end_offset = self.get_offset() + (self.size as i64) - 1;
        let other_end_offset = other.get_offset() + (other.size as i64) - 1;

        self.range_intersects(
            self.get_offset(),
            end_offset,
            other.get_offset(),
            other_end_offset,
        )
    }

    fn range_intersects(&self, start1: i64, end1: i64, start2: i64, end2: i64) -> bool {
        if start1 > end1 {
            if start2 > end2 {
                return true;
            }
            return start1 <= end2;
        }
        if start2 > end2 {
            return end1 >= start2;
        }
        start1 <= end2 && end1 >= start2
    }
}

impl fmt::Display for Varnode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "({}, 0x{:x}, {})",
            self.address.space().name(),
            self.address.offset(),
            self.size
        )
    }
}

impl PartialEq for Varnode {
    fn eq(&self, other: &Self) -> bool {
        self.address == other.address && self.size == other.size
    }
}

impl Eq for Varnode {}

#[derive(Debug, Clone)]
pub struct PcodeOp {
    pub opcode: OpCode,
    pub seqnum: SequenceNumber,
    pub inputs: Vec<Varnode>,
    pub output: Option<Varnode>,
}

impl PcodeOp {
    pub fn new(
        opcode: OpCode,
        seqnum: SequenceNumber,
        inputs: Vec<Varnode>,
        output: Option<Varnode>,
    ) -> Self {
        Self {
            opcode,
            seqnum,
            inputs,
            output,
        }
    }
}

impl fmt::Display for PcodeOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(out) = &self.output {
            write!(f, "{} = ", out)?;
        } else {
            write!(f, " ---  ")?;
        }
        write!(f, "{} ", self.opcode.mnemonic())?;
        for (i, input) in self.inputs.iter().enumerate() {
            write!(f, "{}", input)?;
            if i < self.inputs.len() - 1 {
                write!(f, " , ")?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, DefaultAddressFactory};
    use std::sync::Arc;

    #[test]
    fn test_varnode() {
        let ram = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 1);
        let addr = Address::new(ram.clone(), 0x1000);
        let vn = Varnode::new(addr, 4);

        assert_eq!(vn.get_size(), 4);
        assert_eq!(vn.get_offset(), 0x1000);
        assert!(vn.is_address());
    }

    #[test]
    fn test_varnode_contains() {
        let ram = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 1);
        let vn = Varnode::new(Address::new(ram.clone(), 0x1000), 4);

        assert!(vn.contains(&Address::new(ram.clone(), 0x1000)));
        assert!(vn.contains(&Address::new(ram.clone(), 0x1003)));
        assert!(!vn.contains(&Address::new(ram.clone(), 0x1004)));
    }

    #[test]
    fn test_pcode_op() {
        let ram = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 1);
        let pc = Address::new(ram.clone(), 0x100);
        let seq = SequenceNumber::new(pc, 0);

        let out = Varnode::new(Address::new(ram.clone(), 0x1000), 4);
        let in1 = Varnode::new(Address::new(ram.clone(), 0x2000), 4);
        let in2 = Varnode::new(Address::new(ram.clone(), 0x3000), 4);

        let op = PcodeOp::new(OpCode::IntAdd, seq, vec![in1, in2], Some(out));
        assert_eq!(op.opcode, OpCode::IntAdd);
        assert_eq!(op.inputs.len(), 2);
        assert!(op.output.is_some());

        let s = format!("{}", op);
        assert!(s.contains("INT_ADD"));
    }

    #[test]
    fn test_packed_decode_basic() {
        let ram = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 1);
        let factory = Arc::new(DefaultAddressFactory::new(vec![ram.clone()]));

        // ELEM_DATA = 100. Needs extension: 0x60, 0x80 | 100 = 0xE4
        let data = vec![0x60, 0xE4, 0xC3, 0x41, 0x7B, 0xA0, 0xE4];
        let decoder = PackedDecode::new(factory, data);

        let id = decoder.open_element().unwrap();
        assert_eq!(id, ELEM_DATA.id);

        let attr_id = decoder.get_next_attribute_id().unwrap();
        assert_eq!(attr_id, ATTRIB_ID.id);

        let val = decoder.read_unsigned_integer().unwrap();
        assert_eq!(val, 123);

        decoder.close_element(id).unwrap();
    }
}

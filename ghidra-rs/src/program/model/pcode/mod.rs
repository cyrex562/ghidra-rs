pub mod address_xml;
pub mod block_condition;
pub mod block_copy;
pub mod block_do_while;
pub mod block_goto;
pub mod block_graph;
pub mod block_if_else;
pub mod block_if_goto;
pub mod block_inf_loop;
pub mod block_list;
pub mod block_map;
pub mod block_multi_goto;
pub mod block_proper_if;
pub mod block_switch;
pub mod block_while_do;
pub mod byte_ingest;
pub mod cached_encoder;
pub mod data_type_symbol;
pub mod decoder;
pub mod decoder_exception;
pub mod dynamic_entry;
pub mod dynamic_hash;
pub mod encoder;
pub mod equate_symbol;
pub mod function_prototype;
pub mod global_symbol_map;
pub mod high_code_symbol;
pub mod high_constant;
pub mod high_external_symbol;
pub mod high_function;
pub mod high_function_db_util;
pub mod high_function_shell_symbol;
pub mod high_function_symbol;
pub mod high_global;
pub mod high_label_symbol;
pub mod high_local;
pub mod high_other;
pub mod high_param;
pub mod high_param_id;
pub mod high_symbol;
pub mod high_variable;
pub mod ids;
pub mod linked_byte_buffer;
pub mod list_linked;
pub mod mapped_data_entry;
pub mod mapped_entry;
pub mod packed;
pub mod packed_bytes;
pub mod packed_decode_overlay;
pub mod packed_encode_overlay;
pub mod param_measure;
pub mod partial_union;
pub mod patch_encoder;
pub mod patch_packed_encode;
pub mod pcode_block;
pub mod pcode_block_basic;
pub mod pcode_data_type_manager;
pub mod pcode_exception;
pub mod pcode_factory;
pub mod pcode_op_ast;
pub mod pcode_op_bank;
pub mod pcode_override;
pub mod sequence_number;
pub mod string_ingest;
pub mod symbol_entry;
pub mod union_facet_symbol;
pub mod varnode_translator;

use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
use std::fmt;
use std::sync::Arc;

pub use address_xml::{
    decode, decode_from_attributes, decode_storage_from_attributes, encode_addr,
    encode_addr_with_size, encode_attributes, encode_attributes_range, encode_attributes_with_size,
    encode_varnodes, restore_range_xml, restore_xml, restore_xml_with_language, AddressXml,
    DefaultAddressXml, MAX_PIECES,
};
pub use block_condition::BlockCondition;
pub use block_copy::BlockCopy;
pub use block_do_while::BlockDoWhile;
pub use block_goto::{block_goto_decode_body, BlockGoto};
pub use block_graph::BlockGraph;
pub use block_if_else::BlockIfElse;
pub use block_if_goto::{block_if_goto_decode_body, BlockIfGoto};
pub use block_inf_loop::BlockInfLoop;
pub use block_list::BlockList;
pub use block_map::BlockMap;
pub use block_multi_goto::{block_multi_goto_decode_body, BlockMultiGoto};
pub use block_proper_if::BlockProperIf;
pub use block_switch::BlockSwitch;
pub use block_while_do::BlockWhileDo;
pub use byte_ingest::ByteIngest;
pub use cached_encoder::CachedEncoder;
pub use data_type_symbol::DataTypeSymbol;
pub use decoder::{Decoder, DecoderError};
pub use decoder_exception::DecoderException;
pub use dynamic_entry::{DefaultDynamicEntry, DynamicEntry};
pub use dynamic_hash::DynamicHash;
pub use encoder::Encoder;
pub use equate_symbol::EquateSymbol;
pub use function_prototype::FunctionPrototype;
pub use global_symbol_map::GlobalSymbolMap;
pub use high_code_symbol::HighCodeSymbol;
pub use high_constant::HighConstant;
pub use high_external_symbol::HighExternalSymbol;
pub use high_function::{
    collapse_to_global, encode_namespace, find_create_override_space, find_override_space,
    is_override_namespace, tag_find_exclude, HighFunction, OVERRIDE_NAMESPACE_NAME,
};
pub use high_function_db_util::{HighFunctionDb, HighFunctionDBUtil, ReturnCommitOption, AUTO_CAT};
pub use high_function_shell_symbol::HighFunctionShellSymbol;
pub use high_function_symbol::HighFunctionSymbol;
pub use high_global::HighGlobal;
pub use high_label_symbol::HighLabelSymbol;
pub use high_local::HighLocal;
pub use high_other::HighOther;
pub use high_param::HighParam;
pub use high_param_id::{HighParamID, DECOMPILER_TAG_MAP};
pub use high_symbol::{HighSymbol, ID_BASE};
pub use high_variable::{HighVariable, HighVariableKind};
pub use ids::*;
pub use linked_byte_buffer::{LinkedByteBuffer, Position as LinkedBufferPosition};
pub use list_linked::{LinkedIter, ListLinked};
pub use mapped_data_entry::MappedDataEntry;
pub use mapped_entry::MappedEntry;
pub use packed::{PackedDecode, PackedEncode};
pub use packed_bytes::PackedBytes;
pub use packed_decode_overlay::PackedDecodeOverlay;
pub use packed_encode_overlay::PackedEncodeOverlay;
pub use param_measure::ParamMeasure;
pub use partial_union::PartialUnion;
pub use patch_encoder::PatchEncoder;
pub use patch_packed_encode::PatchPackedEncode;
pub use pcode_block::{
    decode_edges, decode_next_in_edge, get_front_leaf, pcode_block_name_to_type,
    pcode_block_type_to_name, BlockEdge, PcodeBlock, PCODE_BLOCK_BASIC, PCODE_BLOCK_CONDITION,
    PCODE_BLOCK_COPY, PCODE_BLOCK_DOWHILE, PCODE_BLOCK_GOTO, PCODE_BLOCK_GRAPH, PCODE_BLOCK_IFELSE,
    PCODE_BLOCK_IFGOTO, PCODE_BLOCK_INFLOOP, PCODE_BLOCK_LIST, PCODE_BLOCK_MULTIGOTO,
    PCODE_BLOCK_PLAIN, PCODE_BLOCK_PROPERIF, PCODE_BLOCK_SWITCH, PCODE_BLOCK_WHILEDO,
};
pub use pcode_block_basic::PcodeBlockBasic;
pub use pcode_data_type_manager::{
    find_pointer_relative_inner, get_metatype, get_metatype_from_string, get_metatype_string,
    CoreTypeEntry, PcodeDataTypeManager,
};
pub use pcode_exception::PcodeException;
pub use pcode_factory::PcodeFactory;
pub use pcode_op_ast::PcodeOpAST;
pub use pcode_op_bank::PcodeOpBank;
pub use pcode_override::PcodeOverride;
pub use sequence_number::SequenceNumber;
pub use string_ingest::StringIngest;
pub use symbol_entry::SymbolEntry;
pub use union_facet_symbol::UnionFacetSymbol;
pub use varnode_translator::VarnodeTranslator;

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

    /// Resolve a mnemonic string back to an opcode.
    ///
    /// Port of `ghidra.program.model.pcode.PcodeOp.getOpcode(String)`, which builds a
    /// `mnemonic -> opcode` lookup table by calling `getMnemonic(i)` for every `i` in
    /// `0..PCODE_MAX` (`PCODE_MAX = 75`) plus four extra template-directive aliases
    /// (`BUILD`/`DELAY_SLOT`/`LABEL`/`CROSSBUILD`), then looks `s` up in it, throwing
    /// `UnknownInstructionException` on a miss. Modeled here as `Option<OpCode>` (`None` standing
    /// in for that exception) since callers (e.g. `BlockCondition.decodeHeader`) already handle
    /// the "unknown mnemonic" case by catching the exception and substituting a fallback opcode.
    ///
    /// Real Java gap **not** reproduced here: `PcodeOp`'s opcode space includes an unused slot at
    /// index 45 (between `FLOAT_LESSEQUAL` = 44 and `FLOAT_NAN` = 46) whose `getMnemonic(45)`
    /// falls through to `"INVALID_OP"`; since that slot is included in the `0..PCODE_MAX` table-
    /// building loop, Java's `opcodeTable` actually contains a real `"INVALID_OP" -> 45` entry.
    /// This enum has no variant for that unused slot at all, so `from_mnemonic("INVALID_OP")`
    /// returns `None` here instead of matching that entry. No real opcode ever legitimately
    /// mnemonic-round-trips through `"INVALID_OP"`, so this has no practical effect on any current
    /// caller, but it is a genuine, deliberate divergence worth flagging.
    pub fn from_mnemonic(s: &str) -> Option<OpCode> {
        Some(match s {
            "UNIMPLEMENTED" => Self::Unimplemented,
            "COPY" => Self::Copy,
            "LOAD" => Self::Load,
            "STORE" => Self::Store,
            "BRANCH" => Self::Branch,
            "CBRANCH" => Self::CBranch,
            "BRANCHIND" => Self::BranchInd,
            "CALL" => Self::Call,
            "CALLIND" => Self::CallInd,
            "CALLOTHER" => Self::CallOther,
            "RETURN" => Self::Return,
            "INT_EQUAL" => Self::IntEqual,
            "INT_NOTEQUAL" => Self::IntNotEqual,
            "INT_SLESS" => Self::IntSless,
            "INT_SLESSEQUAL" => Self::IntSlessEqual,
            "INT_LESS" => Self::IntLess,
            "INT_LESSEQUAL" => Self::IntLessEqual,
            "INT_ZEXT" => Self::IntZext,
            "INT_SEXT" => Self::IntSext,
            "INT_ADD" => Self::IntAdd,
            "INT_SUB" => Self::IntSub,
            "INT_CARRY" => Self::IntCarry,
            "INT_SCARRY" => Self::IntScarry,
            "INT_SBORROW" => Self::IntSborrow,
            "INT_2COMP" => Self::Int2Comp,
            "INT_NEGATE" => Self::IntNegate,
            "INT_XOR" => Self::IntXor,
            "INT_AND" => Self::IntAnd,
            "INT_OR" => Self::IntOr,
            "INT_LEFT" => Self::IntLeft,
            "INT_RIGHT" => Self::IntRight,
            "INT_SRIGHT" => Self::IntSright,
            "INT_MULT" => Self::IntMult,
            "INT_DIV" => Self::IntDiv,
            "INT_SDIV" => Self::IntSdiv,
            "INT_REM" => Self::IntRem,
            "INT_SREM" => Self::IntSrem,
            "BOOL_NEGATE" => Self::BoolNegate,
            "BOOL_XOR" => Self::BoolXor,
            "BOOL_AND" => Self::BoolAnd,
            "BOOL_OR" => Self::BoolOr,
            "FLOAT_EQUAL" => Self::FloatEqual,
            "FLOAT_NOTEQUAL" => Self::FloatNotEqual,
            "FLOAT_LESS" => Self::FloatLess,
            "FLOAT_LESSEQUAL" => Self::FloatLessEqual,
            "FLOAT_NAN" => Self::FloatNan,
            "FLOAT_ADD" => Self::FloatAdd,
            "FLOAT_DIV" => Self::FloatDiv,
            "FLOAT_MULT" => Self::FloatMult,
            "FLOAT_SUB" => Self::FloatSub,
            "FLOAT_NEG" => Self::FloatNeg,
            "FLOAT_ABS" => Self::FloatAbs,
            "FLOAT_SQRT" => Self::FloatSqrt,
            "INT2FLOAT" => Self::FloatInt2Float,
            "FLOAT2FLOAT" => Self::FloatFloat2Float,
            "TRUNC" => Self::FloatTrunc,
            "CEIL" => Self::FloatCeil,
            "FLOOR" => Self::FloatFloor,
            "ROUND" => Self::FloatRound,
            "MULTIEQUAL" | "BUILD" => Self::MultiEqual,
            "INDIRECT" | "DELAY_SLOT" => Self::Indirect,
            "PIECE" => Self::Piece,
            "SUBPIECE" => Self::Subpiece,
            "CAST" => Self::Cast,
            "PTRADD" | "LABEL" => Self::PtrAdd,
            "PTRSUB" | "CROSSBUILD" => Self::PtrSub,
            "SEGMENTOP" => Self::SegmentOp,
            "CPOOLREF" => Self::CpoolRef,
            "NEW" => Self::New,
            "INSERT" => Self::Insert,
            "ZPULL" => Self::Zpull,
            "POPCOUNT" => Self::Popcount,
            "LZCOUNT" => Self::Lzcount,
            "SPULL" => Self::Spull,
            _ => return None,
        })
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

    /// True if `self` immediately follows `lo` (endian aware): `self` holds the more significant
    /// bytes when `big_endian` is true, otherwise `self` holds the less significant bytes.
    ///
    /// Port of `ghidra.program.model.pcode.Varnode.isContiguous`. Needed by
    /// [`ParameterPieces::merge_sequence`](crate::program::seam_stubs::ParameterPieces::merge_sequence)
    /// to detect adjacent pieces that can be coalesced into a single storage location.
    pub fn is_contiguous(&self, lo: &Varnode, big_endian: bool) -> bool {
        let space = self.address.space();
        if space.as_ref() != lo.address.space().as_ref() {
            return false;
        }
        if big_endian {
            let nextoff = space.truncate_offset(self.get_offset() + self.size as i64);
            nextoff == lo.get_offset()
        } else {
            let nextoff = space.truncate_offset(lo.get_offset() + lo.size as i64);
            nextoff == self.get_offset()
        }
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

/// Counterpart to Java's `Varnode.hashCode()`, which hashes the same address/size pair that
/// `equals` compares. Needed so varnodes can key hashed collections, as they do in Java (e.g.
/// `JitVarScopeModel`'s live-varnode sets).
impl std::hash::Hash for Varnode {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.address.hash(state);
        self.size.hash(state);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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

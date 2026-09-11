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

use crate::program::model::address::{Address, AddressFactory, AddressSetView, AddressSpace, AddressSpaceType};
use crate::program::model::lang::language::Language;
use std::fmt;
use std::io;
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

/// Set of Varnode pieces referred to by a single Varnode in join space, as returned by
/// [`Varnode::decode_pieces`]. Port of the nested `Varnode.Join` class.
#[derive(Clone, Debug)]
pub struct VarnodeJoin {
    /// The list of individual Varnodes being joined. Port of `Join.pieces`.
    pub pieces: Vec<Varnode>,
    /// The size (in bytes) of the logical whole. Port of `Join.logicalSize`.
    pub logical_size: i32,
}

/// Adapt a [`DecoderError`] from the low-level [`Decoder`] trait to the [`DecoderException`] that
/// `Varnode`'s decode-related methods report, mirroring the `throws DecoderException` signatures
/// on the Java side. Same pattern as `address_xml::decode_err`/`symbol_entry::decode_err`.
fn decode_err(e: DecoderError) -> DecoderException {
    DecoderException::with_cause("failed to decode Varnode", e)
}

impl Varnode {
    pub fn new(address: Address, size: i32) -> Self {
        Self { address, size }
    }

    /// Port of `Varnode(Address, int, int)`. Real Java ignores `symbol_key` too -- it delegates
    /// straight to the two-argument constructor without storing it anywhere.
    pub fn new_with_symbol_key(address: Address, size: i32, symbol_key: i32) -> Self {
        let _ = symbol_key;
        Self::new(address, size)
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

    /// Get the word offset into the address space this Varnode is defined within. Port of
    /// `Varnode.getWordOffset()`.
    pub fn get_word_offset(&self) -> i64 {
        self.address.addressable_word_offset()
    }

    /// Port of `Varnode.isFree()`. Always `true`: this type only models the "raw" free Varnode
    /// (Java's `VarnodeAST`, the AST-linked subclass that can report `false`, is not yet ported).
    pub fn is_free(&self) -> bool {
        true
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

    /// Port of `Varnode.isHash()`. Always `false`: real Java compares `spaceID` against the
    /// singleton `AddressSpace.HASH_SPACE`, but this crate's
    /// [`AddressSpaceType`] has no `Hash` variant yet (the same gap documented by
    /// [`VariableStorage`](crate::program::model::listing::variable_storage)'s module docs), so a
    /// hash-space Varnode cannot currently be constructed and this always reports `false`.
    pub fn is_hash(&self) -> bool {
        false
    }

    /// Port of `Varnode.isInput()`. Always `false` for this "free" Varnode -- not a valid query
    /// until the AST-linked subclass exists (see [`is_free`](Self::is_free)).
    pub fn is_input(&self) -> bool {
        false
    }

    /// Port of `Varnode.isPersistent()`. Always `false` -- see [`is_input`](Self::is_input).
    pub fn is_persistent(&self) -> bool {
        false
    }

    /// Port of `Varnode.isAddrTied()`. Always `false` -- see [`is_input`](Self::is_input).
    pub fn is_addr_tied(&self) -> bool {
        false
    }

    /// Port of `Varnode.isUnaffected()`. Always `false` -- see [`is_input`](Self::is_input).
    pub fn is_unaffected(&self) -> bool {
        false
    }

    /// Get the PcodeOp this varnode belongs to. Port of `Varnode.getDef()`. Always `None` --
    /// see [`is_input`](Self::is_input).
    pub fn get_def(&self) -> Option<&PcodeOp> {
        None
    }

    /// Get the address where this varnode is defined, or the sentinel "no address" if this
    /// varnode is an input. Port of `Varnode.getPCAddress()`.
    ///
    /// # Panics
    /// Real Java's base `Varnode.getPCAddress()` is `isInput() ? Address.NO_ADDRESS :
    /// getDef().getSeqnum().getTarget()`. Since [`is_input`](Self::is_input) always returns
    /// `false` and [`get_def`](Self::get_def) always returns `None` on this "free" Varnode (the
    /// AST-linked subclass that overrides both with real values is not yet ported), the real Java
    /// method unconditionally dereferences a `null` `getDef()` result here and throws a
    /// `NullPointerException` for every base `Varnode` -- this is a genuine, if surprising, quirk
    /// of the real class (the method is only meaningful once overridden). Faithfully reproduced
    /// as a panic rather than silently returning a placeholder address; see the `#[should_panic]`
    /// test below.
    pub fn get_pc_address(&self) -> Address {
        if self.is_input() {
            return crate::program::model::address::special_address::SpecialAddress::no_address();
        }
        self.get_def()
            .expect("Varnode.getPCAddress() on a free Varnode dereferences a null getDef() in real Ghidra too (NPE)")
            .seqnum
            .get_target()
            .clone()
    }

    /// Iterator over all PcodeOps that take this varnode as input. Port of
    /// `Varnode.getDescendants()`. Always `None` -- matching the literal `null` Java returns here
    /// (a real caller dereferencing that null would NPE); see [`is_input`](Self::is_input).
    pub fn get_descendants(&self) -> Option<std::vec::IntoIter<PcodeOp>> {
        None
    }

    /// If there is only one PcodeOp taking this varnode as input, return it; otherwise `None`.
    /// Port of `Varnode.getLoneDescend()`. Always `None` -- see [`is_input`](Self::is_input).
    pub fn get_lone_descend(&self) -> Option<PcodeOp> {
        None
    }

    /// Port of `Varnode.hasNoDescend()`. Always `true` -- see [`is_input`](Self::is_input).
    pub fn has_no_descend(&self) -> bool {
        true
    }

    /// Get the high-level variable this varnode represents. Port of `Varnode.getHigh()`. Always
    /// `None` -- see [`is_input`](Self::is_input).
    pub fn get_high(&self) -> Option<Arc<dyn HighVariable>> {
        None
    }

    /// Port of `Varnode.getMergeGroup()`. Always `0` -- see [`is_input`](Self::is_input).
    pub fn get_merge_group(&self) -> i16 {
        0
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

    /// The end-of-range offset used by `contains`/`intersects`, matching Java's
    /// `size > 0 ? offset + size - 1 : offset` guard (an all-zero-size Varnode's range is a single
    /// point at `offset`, not an empty/inverted range).
    fn end_offset(&self) -> i64 {
        if self.size > 0 {
            self.get_offset() + (self.size as i64) - 1
        } else {
            self.get_offset()
        }
    }

    pub fn contains(&self, addr: &Address) -> bool {
        if self.get_space_id() != addr.space().space_id() {
            return false;
        }
        if self.is_constant() || self.is_hash() {
            return self.get_offset() == addr.offset();
        }
        let end_offset = self.end_offset();
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
        if self.is_constant() || self.is_hash() {
            return self.get_offset() == other.get_offset();
        }
        let other_end_offset = other.end_offset();

        self.range_intersects(
            self.get_offset(),
            self.end_offset(),
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

    /// Determine if this varnode intersects the specified address set. Port of
    /// `Varnode.intersects(AddressSetView)`. Named `intersects_set` rather than an `intersects`
    /// overload since Rust has no method overloading by parameter type.
    pub fn intersects_set(&self, set: &dyn AddressSetView) -> bool {
        if self.is_constant() || self.is_unique() || self.is_hash() || set.is_empty() {
            return false;
        }
        for range in set.address_ranges() {
            let min_addr = range.min_address();
            if min_addr.space().space_id() != self.get_space_id() {
                continue;
            }
            let max_addr = range.max_address();
            if self.range_intersects(
                self.get_offset(),
                self.end_offset(),
                min_addr.offset(),
                max_addr.offset(),
            ) {
                return true;
            }
        }
        false
    }

    /// Encode just the raw storage info for this Varnode to stream. Port of
    /// `Varnode.encodeRaw(Encoder)`.
    ///
    /// # Errors
    /// Returns an error for problems writing to the underlying stream.
    pub fn encode_raw(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
        address_xml::encode_addr_with_size(encoder, &self.address, self.size)
    }

    /// Encode details of the Varnode as a formatted string with three colon-separated fields:
    /// `space:offset:size`. Port of `Varnode.encodePiece()`.
    pub fn encode_piece(&self) -> String {
        format!(
            "{}:0x{:x}:{}",
            self.address.space().name(),
            self.address.unsigned_offset(),
            self.size
        )
    }

    /// Decode a Varnode from a stream. Port of `Varnode.decode(Decoder, PcodeFactory)`.
    ///
    /// Returns `None` for an empty `<void>` element (Java's `null` return); otherwise the decoded
    /// Varnode (which may be a pre-existing one retrieved by reference id via
    /// [`PcodeFactory::get_ref`]).
    ///
    /// # Errors
    /// Returns an error if the Varnode is improperly encoded.
    pub fn decode(
        decoder: &dyn Decoder,
        factory: &dyn PcodeFactory,
    ) -> Result<Option<Varnode>, DecoderException> {
        let peeked = decoder.peek_element().map_err(decode_err)?;
        if peeked == ELEM_VOID.id {
            let el = decoder.open_element().map_err(decode_err)?;
            decoder.close_element(el).map_err(decode_err)?;
            return Ok(None);
        } else if peeked == ELEM_SPACEID.id || peeked == ELEM_IOP.id {
            let addr = address_xml::decode(decoder)?;
            return Ok(Some(factory.new_varnode(4, addr)));
        }

        let el = decoder.open_element().map_err(decode_err)?;
        let mut ref_id: i32 = -1;
        let mut sz: i32 = 4;
        loop {
            let attrib_id = decoder.get_next_attribute_id().map_err(decode_err)?;
            if attrib_id == 0 {
                break;
            }
            if attrib_id == ATTRIB_REF.id {
                ref_id = decoder.read_unsigned_integer().map_err(decode_err)? as i32;
                if let Some(vn) = factory.get_ref(ref_id) {
                    decoder.close_element(el).map_err(decode_err)?;
                    return Ok(Some(vn));
                }
            } else if attrib_id == ATTRIB_SIZE.id {
                sz = decoder.read_signed_integer().map_err(decode_err)? as i32;
            }
        }
        decoder.rewind_attributes();
        let mut addr = address_xml::decode_from_attributes(decoder)?;
        let spc_type = addr.space().space_type();
        if spc_type == AddressSpaceType::Variable {
            // Composite ("join") Address: pieces are physically split across multiple storage
            // locations.
            decoder.rewind_attributes();
            let join = Varnode::decode_pieces(decoder)?;
            let logical_size = join.logical_size;
            let storage = factory
                .get_join_storage(join.pieces)
                .map_err(|e| DecoderException::new(&format!("Invalid varnode pieces: {}", e)))?;
            // Update the "join" address to the one just registered with the pieces.
            addr = factory.get_join_address(storage.as_ref()).ok_or_else(|| {
                DecoderException::new("Invalid varnode pieces: PcodeFactory returned no join address")
            })?;
            // Update size to be the size of the pieces.
            sz = logical_size;
        }
        let mut vn = if ref_id != -1 {
            factory.new_varnode_with_ref(sz, addr, ref_id)
        } else {
            factory.new_varnode(sz, addr)
        };
        decoder.rewind_attributes();
        loop {
            let attrib_id = decoder.get_next_attribute_id().map_err(decode_err)?;
            if attrib_id == 0 {
                break;
            }
            if attrib_id == ATTRIB_GRP.id {
                let val = decoder.read_signed_integer().map_err(decode_err)? as i16;
                factory.set_merge_group(&vn, val);
            } else if attrib_id == ATTRIB_PERSISTS.id {
                if decoder.read_bool().map_err(decode_err)? {
                    factory.set_persistent(&vn, true);
                }
            } else if attrib_id == ATTRIB_ADDRTIED.id {
                if decoder.read_bool().map_err(decode_err)? {
                    factory.set_addr_tied(&vn, true);
                }
            } else if attrib_id == ATTRIB_UNAFF.id {
                if decoder.read_bool().map_err(decode_err)? {
                    factory.set_unaffected(&vn, true);
                }
            } else if attrib_id == ATTRIB_INPUT.id {
                if decoder.read_bool().map_err(decode_err)? {
                    vn = factory.set_input(vn, true);
                }
            } else if attrib_id == ATTRIB_VOLATILE.id {
                if decoder.read_bool().map_err(decode_err)? {
                    factory.set_volatile(&vn, true);
                }
            }
        }
        decoder.close_element(el).map_err(decode_err)?;
        Ok(Some(vn))
    }

    /// Decode a Varnode from a description in a string: three colon-separated fields
    /// `space:offset:size`. Port of the private `Varnode.decodePiece(String, AddressFactory)`.
    ///
    /// Real Java has a `// TODO` noting it can't handle register names since `addrFactory` can't
    /// resolve them -- not modeled here either, for the same reason.
    fn decode_piece(piece_str: &str, addr_factory: &dyn AddressFactory) -> Result<Varnode, DecoderException> {
        let tokens: Vec<&str> = piece_str.split(':').collect();
        if tokens.len() != 3 {
            return Err(DecoderException::new(&format!(
                "Invalid \"join\" address piece: {piece_str}"
            )));
        }
        let space = addr_factory.get_address_space_by_name(tokens[0]).ok_or_else(|| {
            DecoderException::new(&format!("Invalid space for \"join\" address piece: {piece_str}"))
        })?;
        let hex = tokens[1].strip_prefix("0x").ok_or_else(|| {
            DecoderException::new(&format!("Invalid offset for \"join\" address piece: {piece_str}"))
        })?;
        let offset = u64::from_str_radix(hex, 16).map_err(|_| {
            DecoderException::new(&format!("Invalid offset for \"join\" address piece: {piece_str}"))
        })?;
        let size: i32 = tokens[2].parse().map_err(|_| {
            DecoderException::new(&format!("Invalid size for \"join\" address piece: {piece_str}"))
        })?;
        Ok(Varnode::new(space.address(offset as i64), size))
    }

    /// Decode a sequence of Varnodes from "piece" attributes for the current open element. Port
    /// of `Varnode.decodePieces(Decoder)`.
    ///
    /// Real Java also handles `ATTRIB_UNKNOWN` via `decoder.getIndexedAttributeId(ATTRIB_PIECE)`
    /// as a fallback for decoders that can't resolve an attribute name up front; not modeled here
    /// since every `Decoder` implementation in this crate resolves attribute ids directly (this
    /// crate's [`Decoder`] trait has no `get_indexed_attribute_id` method at all).
    ///
    /// # Errors
    /// Returns an error for any errors in the encoding.
    pub fn decode_pieces(decoder: &dyn Decoder) -> Result<VarnodeJoin, DecoderException> {
        let mut pieces = Vec::new();
        let mut size_accum: i32 = 0;
        let mut logical_size: i32 = 0;
        loop {
            let attrib_id = decoder.get_next_attribute_id().map_err(decode_err)?;
            if attrib_id == 0 {
                break;
            }
            if attrib_id == ATTRIB_LOGICALSIZE.id {
                logical_size = decoder.read_unsigned_integer().map_err(decode_err)? as i32;
                continue;
            }
            if attrib_id >= ATTRIB_PIECE.id {
                let index = (attrib_id - ATTRIB_PIECE.id) as usize;
                if index > MAX_PIECES {
                    continue;
                }
                if index != pieces.len() {
                    return Err(DecoderException::new("\"piece\" attributes must be in order"));
                }
                let piece_str = decoder.read_string().map_err(decode_err)?;
                let addr_factory = decoder.get_address_factory();
                let vn = Varnode::decode_piece(&piece_str, addr_factory.as_ref())?;
                size_accum += vn.get_size();
                pieces.push(vn);
            }
        }
        let total = if logical_size != 0 { logical_size } else { size_accum };
        Ok(VarnodeJoin { pieces, logical_size: total })
    }

    /// Trim a varnode in a constant space to the correct starting offset by masking off the
    /// constant to its proper size. Port of `Varnode.trim()`.
    ///
    /// # Panics
    /// Real Java indexes a fixed 9-entry `masks[]` array (sizes `0..=8`) with no bounds check,
    /// throwing `ArrayIndexOutOfBoundsException` for a constant Varnode whose size is negative or
    /// greater than 8. Faithfully reproduced: this also panics (a Rust array-index panic) for the
    /// same out-of-range sizes rather than silently clamping or masking with the wrong width.
    pub fn trim(&mut self) {
        const MASKS: [u64; 9] = [
            0,
            0xff,
            0xffff,
            0xffffff,
            0xffffffff,
            0xffffffffff,
            0xffffffffffff,
            0xffffffffffffff,
            0xffffffffffffffff,
        ];
        if self.address.space().space_type() == AddressSpaceType::Constant {
            let masked = (self.get_offset() as u64 & MASKS[self.size as usize]) as i64;
            self.address = self.address.space().address(masked);
        }
    }

    /// Convert this varnode to an alternate String representation based on a specified language.
    /// Port of `Varnode.toString(Language)`.
    pub fn to_string_with_language(&self, language: &dyn Language) -> String {
        if self.is_address() || self.is_register() {
            if let Some(reg) = language.get_register_at(&self.address, self.size) {
                return reg.borrow().name().to_string();
            }
        }
        if self.is_unique() {
            return format!("u_{:x}:{}", self.get_offset(), self.size);
        }
        if self.is_constant() {
            return format!("0x{:x}", self.get_offset());
        }
        format!("A_{}:{}", self.address, self.size)
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
    use crate::program::model::listing::variable_storage::VariableStorage;
    use crate::program::seam_stubs::{HighSymbol, VarnodeListStorage};
    use crate::util::exception::InvalidInputException;
    use std::cell::RefCell;
    use std::collections::HashMap;
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

    // --- New Varnode surface: contains/intersects zero-size fix, is_hash, intersects_set ---

    #[test]
    fn contains_zero_size_varnode_is_a_single_point() {
        // Real Java's `contains` only extends `endOffset` when `size > 0`; a zero-size Varnode's
        // range collapses to a single point at `offset`, not an inverted/empty range.
        let ram = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 1);
        let vn = Varnode::new(Address::new(ram.clone(), 0x1000), 0);
        assert!(vn.contains(&Address::new(ram.clone(), 0x1000)));
        assert!(!vn.contains(&Address::new(ram.clone(), 0x1001)));
        assert!(!vn.contains(&Address::new(ram, 0xfff)));
    }

    #[test]
    fn intersects_zero_size_varnodes_only_at_exact_offset() {
        let ram = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 1);
        let a = Varnode::new(Address::new(ram.clone(), 0x1000), 0);
        let b = Varnode::new(Address::new(ram.clone(), 0x1000), 0);
        let c = Varnode::new(Address::new(ram, 0x1001), 0);
        assert!(a.intersects(&b));
        assert!(!a.intersects(&c));
    }

    #[test]
    fn is_hash_always_false_pending_hash_address_space_support() {
        let ram = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 1);
        let vn = Varnode::new(Address::new(ram, 0x1000), 4);
        assert!(!vn.is_hash());
    }

    #[test]
    fn intersects_set_matches_java_overlap_semantics() {
        let ram = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 1);
        let const_space = AddressSpace::new("const", 32, 1, AddressSpaceType::Constant, 2);
        // [0x1000, 0x100f]
        let vn = Varnode::new(Address::new(ram.clone(), 0x1000), 0x10);

        let mut overlapping = crate::program::model::address::AddressSet::new();
        overlapping.add_range(&Address::new(ram.clone(), 0x1005), &Address::new(ram.clone(), 0x1020));
        assert!(vn.intersects_set(&overlapping));

        let mut disjoint = crate::program::model::address::AddressSet::new();
        disjoint.add_range(&Address::new(ram.clone(), 0x2000), &Address::new(ram.clone(), 0x2010));
        assert!(!vn.intersects_set(&disjoint));

        let empty = crate::program::model::address::AddressSet::new();
        assert!(!vn.intersects_set(&empty));

        // isConstant() short-circuits to false regardless of overlap.
        let const_vn = Varnode::new(Address::new(const_space, 5), 1);
        assert!(!const_vn.intersects_set(&overlapping));
    }

    // --- New Varnode surface: stub queries matching the real "free" Varnode's Java defaults ---

    #[test]
    fn free_varnode_stub_queries_match_java_defaults() {
        let ram = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 1);
        let vn = Varnode::new(Address::new(ram, 0x100), 4);
        assert!(vn.is_free());
        assert!(!vn.is_input());
        assert!(!vn.is_persistent());
        assert!(!vn.is_addr_tied());
        assert!(!vn.is_unaffected());
        assert!(vn.get_def().is_none());
        assert!(vn.get_descendants().is_none());
        assert!(vn.get_lone_descend().is_none());
        assert!(vn.has_no_descend());
        assert!(vn.get_high().is_none());
        assert_eq!(vn.get_merge_group(), 0);
    }

    #[test]
    #[should_panic(expected = "null getDef()")]
    fn get_pc_address_on_free_varnode_panics_like_real_java_npe() {
        let ram = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 1);
        let vn = Varnode::new(Address::new(ram, 0x100), 4);
        let _ = vn.get_pc_address();
    }

    #[test]
    fn get_word_offset_delegates_to_address() {
        let ram = AddressSpace::new("RAM", 32, 2, AddressSpaceType::Ram, 1);
        let vn = Varnode::new(Address::new(ram.clone(), 0x10), 2);
        assert_eq!(vn.get_word_offset(), ram.address(0x10).addressable_word_offset());
    }

    #[test]
    fn new_with_symbol_key_ignores_the_key_like_java() {
        let ram = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 1);
        let addr = Address::new(ram, 0x100);
        let vn = Varnode::new_with_symbol_key(addr.clone(), 4, 999);
        assert_eq!(vn, Varnode::new(addr, 4));
    }

    // --- New Varnode surface: trim() ---

    #[test]
    fn trim_masks_constant_varnode_to_its_size() {
        let const_space = AddressSpace::new("const", 32, 1, AddressSpaceType::Constant, 3);
        let mut vn = Varnode::new(Address::new(const_space, 0x1_2345_6789), 2);
        vn.trim();
        assert_eq!(vn.get_offset(), 0x6789);
    }

    #[test]
    fn trim_is_noop_for_non_constant_varnode() {
        let ram = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 1);
        let mut vn = Varnode::new(Address::new(ram, 0x1_2345), 2);
        vn.trim();
        assert_eq!(vn.get_offset(), 0x1_2345);
    }

    // --- New Varnode surface: encode_piece / decode_pieces ---

    #[test]
    fn encode_piece_formats_space_offset_size() {
        let ram = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 1);
        let vn = Varnode::new(Address::new(ram, 0x20), 4);
        assert_eq!(vn.encode_piece(), "RAM:0x20:4");
    }

    #[test]
    fn decode_pieces_reads_ordered_pieces_and_sums_size_by_default() {
        let ram = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 1);
        let addr_factory = Arc::new(DefaultAddressFactory::new(vec![ram.clone()]));
        let attrs = vec![
            (ATTRIB_PIECE.id, MockAttr::Str("RAM:0x10:2".to_string())),
            (ATTRIB_PIECE.id + 1, MockAttr::Str("RAM:0x20:4".to_string())),
        ];
        let decoder = MockVarnodeDecoder::new(addr_factory, ELEM_VARNODE.id, ELEM_VARNODE.id, attrs);
        let join = Varnode::decode_pieces(&decoder).unwrap();
        assert_eq!(join.pieces, vec![
            Varnode::new(ram.address(0x10), 2),
            Varnode::new(ram.address(0x20), 4),
        ]);
        assert_eq!(join.logical_size, 6);
    }

    #[test]
    fn decode_pieces_explicit_logical_size_overrides_sum() {
        let ram = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 1);
        let addr_factory = Arc::new(DefaultAddressFactory::new(vec![ram.clone()]));
        let attrs = vec![
            (ATTRIB_PIECE.id, MockAttr::Str("RAM:0x10:2".to_string())),
            (ATTRIB_LOGICALSIZE.id, MockAttr::UInt(8)),
        ];
        let decoder = MockVarnodeDecoder::new(addr_factory, ELEM_VARNODE.id, ELEM_VARNODE.id, attrs);
        let join = Varnode::decode_pieces(&decoder).unwrap();
        assert_eq!(join.logical_size, 8);
    }

    #[test]
    fn decode_pieces_out_of_order_index_errors() {
        let ram = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 1);
        let addr_factory = Arc::new(DefaultAddressFactory::new(vec![ram]));
        // Index 1 appears without index 0 first.
        let attrs = vec![(ATTRIB_PIECE.id + 1, MockAttr::Str("RAM:0x10:2".to_string()))];
        let decoder = MockVarnodeDecoder::new(addr_factory, ELEM_VARNODE.id, ELEM_VARNODE.id, attrs);
        let err = Varnode::decode_pieces(&decoder).unwrap_err();
        assert!(err.to_string().contains("must be in order"));
    }

    // --- Varnode::decode(Decoder, PcodeFactory) ---

    #[derive(Clone)]
    enum MockAttr {
        Space(Arc<AddressSpace>),
        UInt(u64),
        SInt(i64),
        Str(String),
        Bool(bool),
    }

    /// Minimal `Decoder` whose `peek_element`/`open_element` report fixed, test-supplied element
    /// ids, and whose attribute stream cycles through a fixed list, resettable via
    /// `rewind_attributes` -- exactly the shape `Varnode::decode` needs, since it re-scans the
    /// same wire attributes across up to three passes (ref/size, address, and the
    /// grp/persists/addrtied/unaff/input/volatile pass).
    struct MockVarnodeDecoder {
        factory: Arc<dyn AddressFactory>,
        peek_id: i32,
        open_id: i32,
        attrs: Vec<(i32, MockAttr)>,
        pos: std::sync::atomic::AtomicUsize,
    }

    impl MockVarnodeDecoder {
        fn new(factory: Arc<dyn AddressFactory>, peek_id: i32, open_id: i32, attrs: Vec<(i32, MockAttr)>) -> Self {
            Self { factory, peek_id, open_id, attrs, pos: std::sync::atomic::AtomicUsize::new(0) }
        }

        fn pos(&self) -> usize {
            self.pos.load(std::sync::atomic::Ordering::SeqCst)
        }

        fn set_pos(&self, v: usize) {
            self.pos.store(v, std::sync::atomic::Ordering::SeqCst);
        }

        /// Look up an attribute by id directly, independent of `pos` -- needed by the `_with_id`
        /// `Decoder` methods, which (per `address_xml::decode`'s `ELEM_SPACEID`/`ELEM_IOP`
        /// handling) may be called without a preceding `get_next_attribute_id()` call.
        fn find_attr(&self, id: i32) -> &MockAttr {
            self.attrs
                .iter()
                .find(|(aid, _)| *aid == id)
                .map(|(_, v)| v)
                .unwrap_or_else(|| panic!("mock decoder has no attribute with id {id}"))
        }
    }

    impl Decoder for MockVarnodeDecoder {
        fn get_address_factory(&self) -> Arc<dyn AddressFactory> {
            self.factory.clone()
        }
        fn set_address_factory(&self, _factory: Arc<dyn AddressFactory>) {}
        fn peek_element(&self) -> Result<i32, DecoderError> {
            Ok(self.peek_id)
        }
        fn open_element(&self) -> Result<i32, DecoderError> {
            Ok(self.open_id)
        }
        fn open_element_with_id(&self, _elem_id: ElementId) -> Result<i32, DecoderError> {
            Ok(self.open_id)
        }
        fn close_element(&self, _id: i32) -> Result<(), DecoderError> {
            Ok(())
        }
        fn close_element_skipping(&self, _id: i32) -> Result<(), DecoderError> {
            Ok(())
        }
        fn get_next_attribute_id(&self) -> Result<i32, DecoderError> {
            let idx = self.pos();
            if idx >= self.attrs.len() {
                return Ok(0);
            }
            self.set_pos(idx + 1);
            Ok(self.attrs[idx].0)
        }
        fn rewind_attributes(&self) {
            self.set_pos(0);
        }
        fn read_bool(&self) -> Result<bool, DecoderError> {
            match &self.attrs[self.pos() - 1].1 {
                MockAttr::Bool(v) => Ok(*v),
                _ => panic!("not a bool attribute"),
            }
        }
        fn read_bool_with_id(&self, attrib_id: AttributeId) -> Result<bool, DecoderError> {
            match self.find_attr(attrib_id.id) {
                MockAttr::Bool(v) => Ok(*v),
                _ => panic!("not a bool attribute"),
            }
        }
        fn read_signed_integer(&self) -> Result<i64, DecoderError> {
            match &self.attrs[self.pos() - 1].1 {
                MockAttr::SInt(v) => Ok(*v),
                _ => panic!("not a signed integer attribute"),
            }
        }
        fn read_signed_integer_with_id(&self, attrib_id: AttributeId) -> Result<i64, DecoderError> {
            match self.find_attr(attrib_id.id) {
                MockAttr::SInt(v) => Ok(*v),
                _ => panic!("not a signed integer attribute"),
            }
        }
        fn read_unsigned_integer(&self) -> Result<u64, DecoderError> {
            match &self.attrs[self.pos() - 1].1 {
                MockAttr::UInt(v) => Ok(*v),
                _ => panic!("not an unsigned integer attribute"),
            }
        }
        fn read_unsigned_integer_with_id(&self, attrib_id: AttributeId) -> Result<u64, DecoderError> {
            match self.find_attr(attrib_id.id) {
                MockAttr::UInt(v) => Ok(*v),
                _ => panic!("not an unsigned integer attribute"),
            }
        }
        fn read_string(&self) -> Result<String, DecoderError> {
            match &self.attrs[self.pos() - 1].1 {
                MockAttr::Str(v) => Ok(v.clone()),
                _ => panic!("not a string attribute"),
            }
        }
        fn read_string_with_id(&self, attrib_id: AttributeId) -> Result<String, DecoderError> {
            match self.find_attr(attrib_id.id) {
                MockAttr::Str(v) => Ok(v.clone()),
                _ => panic!("not a string attribute"),
            }
        }
        fn read_space(&self) -> Result<Arc<AddressSpace>, DecoderError> {
            match &self.attrs[self.pos() - 1].1 {
                MockAttr::Space(v) => Ok(v.clone()),
                _ => panic!("not a space attribute"),
            }
        }
        fn read_space_with_id(&self, attrib_id: AttributeId) -> Result<Arc<AddressSpace>, DecoderError> {
            match self.find_attr(attrib_id.id) {
                MockAttr::Space(v) => Ok(v.clone()),
                _ => panic!("not a space attribute"),
            }
        }
    }

    /// Real, RefCell-backed `PcodeFactory` recording every `set_*` call so tests can assert
    /// `Varnode::decode`'s second attribute pass invokes the right ones -- same pattern as
    /// `pcode_factory::tests::MockPcodeFactory`.
    #[derive(Default)]
    struct TestPcodeFactory {
        address_factory: Option<Arc<dyn AddressFactory>>,
        refs: RefCell<HashMap<i32, Varnode>>,
        join_address: Option<Address>,
        persistent_calls: RefCell<Vec<Varnode>>,
        addr_tied_calls: RefCell<Vec<Varnode>>,
        unaffected_calls: RefCell<Vec<Varnode>>,
        volatile_calls: RefCell<Vec<Varnode>>,
        merge_group_calls: RefCell<Vec<(Varnode, i16)>>,
        input_calls: RefCell<Vec<Varnode>>,
    }

    impl TestPcodeFactory {
        fn new(address_factory: Arc<dyn AddressFactory>) -> Self {
            Self { address_factory: Some(address_factory), ..Default::default() }
        }
        fn with_ref(self, ref_id: i32, vn: Varnode) -> Self {
            self.refs.borrow_mut().insert(ref_id, vn);
            self
        }
        fn with_join_address(mut self, addr: Address) -> Self {
            self.join_address = Some(addr);
            self
        }
    }

    impl PcodeFactory for TestPcodeFactory {
        fn get_address_factory(&self) -> Arc<dyn AddressFactory> {
            self.address_factory.clone().expect("address_factory not configured")
        }
        fn get_data_type_manager(&self) -> Arc<dyn PcodeDataTypeManager> {
            unimplemented!("not exercised by these tests")
        }
        fn new_varnode_with_ref(&self, sz: i32, addr: Address, ref_id: i32) -> Varnode {
            let vn = Varnode::new(addr, sz);
            self.refs.borrow_mut().insert(ref_id, vn.clone());
            vn
        }
        fn get_join_address(&self, _storage: &dyn VariableStorage) -> Option<Address> {
            self.join_address.clone()
        }
        fn build_storage(&self, vn: &Varnode) -> Result<Box<dyn VariableStorage>, InvalidInputException> {
            Ok(Box::new(VarnodeListStorage(vec![vn.clone()])))
        }
        fn get_ref(&self, refid: i32) -> Option<Varnode> {
            self.refs.borrow().get(&refid).cloned()
        }
        fn get_op_ref(&self, _refid: i32) -> Option<PcodeOp> {
            None
        }
        fn get_symbol(&self, _symbol_id: i64) -> Option<Arc<dyn HighSymbol>> {
            None
        }
        fn set_input(&self, vn: Varnode, val: bool) -> Varnode {
            if val {
                self.input_calls.borrow_mut().push(vn.clone());
            }
            vn
        }
        fn set_addr_tied(&self, vn: &Varnode, val: bool) {
            if val {
                self.addr_tied_calls.borrow_mut().push(vn.clone());
            }
        }
        fn set_persistent(&self, vn: &Varnode, val: bool) {
            if val {
                self.persistent_calls.borrow_mut().push(vn.clone());
            }
        }
        fn set_unaffected(&self, vn: &Varnode, val: bool) {
            if val {
                self.unaffected_calls.borrow_mut().push(vn.clone());
            }
        }
        fn set_volatile(&self, vn: &Varnode, val: bool) {
            if val {
                self.volatile_calls.borrow_mut().push(vn.clone());
            }
        }
        fn set_merge_group(&self, vn: &Varnode, val: i16) {
            self.merge_group_calls.borrow_mut().push((vn.clone(), val));
        }
        fn new_op(
            &self,
            sq: SequenceNumber,
            opc: OpCode,
            inputs: Vec<Varnode>,
            output: Option<Varnode>,
        ) -> PcodeOp {
            PcodeOp::new(opc, sq, inputs, output)
        }
    }

    #[test]
    fn decode_void_element_returns_none() {
        let ram = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 1);
        let addr_factory = Arc::new(DefaultAddressFactory::new(vec![ram]));
        let decoder = MockVarnodeDecoder::new(addr_factory.clone(), ELEM_VOID.id, ELEM_VOID.id, vec![]);
        let factory = TestPcodeFactory::new(addr_factory);
        assert!(Varnode::decode(&decoder, &factory).unwrap().is_none());
    }

    #[test]
    fn decode_normal_varnode_reads_space_offset_size() {
        let ram = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 1);
        let addr_factory = Arc::new(DefaultAddressFactory::new(vec![ram.clone()]));
        let attrs = vec![
            (ATTRIB_SPACE.id, MockAttr::Space(ram.clone())),
            (ATTRIB_OFFSET.id, MockAttr::UInt(0x2000)),
            (ATTRIB_SIZE.id, MockAttr::SInt(4)),
        ];
        let decoder = MockVarnodeDecoder::new(addr_factory.clone(), ELEM_VARNODE.id, ELEM_VARNODE.id, attrs);
        let factory = TestPcodeFactory::new(addr_factory);
        let vn = Varnode::decode(&decoder, &factory).unwrap().expect("expected a varnode");
        assert_eq!(vn.get_offset(), 0x2000);
        assert_eq!(vn.get_size(), 4);
        assert_eq!(vn.get_address().space().as_ref(), ram.as_ref());
    }

    #[test]
    fn decode_defaults_size_to_four_when_no_size_attribute() {
        let ram = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 1);
        let addr_factory = Arc::new(DefaultAddressFactory::new(vec![ram.clone()]));
        let attrs = vec![
            (ATTRIB_SPACE.id, MockAttr::Space(ram.clone())),
            (ATTRIB_OFFSET.id, MockAttr::UInt(0x40)),
        ];
        let decoder = MockVarnodeDecoder::new(addr_factory.clone(), ELEM_VARNODE.id, ELEM_VARNODE.id, attrs);
        let factory = TestPcodeFactory::new(addr_factory);
        let vn = Varnode::decode(&decoder, &factory).unwrap().unwrap();
        assert_eq!(vn.get_size(), 4);
    }

    #[test]
    fn decode_known_ref_returns_cached_varnode_without_reading_address() {
        let ram = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 1);
        let addr_factory = Arc::new(DefaultAddressFactory::new(vec![ram.clone()]));
        let cached = Varnode::new(ram.address(0x5000), 8);
        let factory = TestPcodeFactory::new(addr_factory.clone()).with_ref(7, cached.clone());
        // Only a "ref" attribute; if the cache hit didn't short-circuit, decode_from_attributes
        // would find no space and this would decode into a "no address" Varnode instead.
        let attrs = vec![(ATTRIB_REF.id, MockAttr::UInt(7))];
        let decoder = MockVarnodeDecoder::new(addr_factory, ELEM_VARNODE.id, ELEM_VARNODE.id, attrs);
        let vn = Varnode::decode(&decoder, &factory).unwrap().expect("expected cached varnode");
        assert_eq!(vn, cached);
    }

    #[test]
    fn decode_unknown_ref_registers_new_varnode_for_later_lookup() {
        let ram = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 1);
        let addr_factory = Arc::new(DefaultAddressFactory::new(vec![ram.clone()]));
        let factory = TestPcodeFactory::new(addr_factory.clone());
        let attrs = vec![
            (ATTRIB_REF.id, MockAttr::UInt(42)),
            (ATTRIB_SPACE.id, MockAttr::Space(ram.clone())),
            (ATTRIB_OFFSET.id, MockAttr::UInt(0x10)),
        ];
        let decoder = MockVarnodeDecoder::new(addr_factory, ELEM_VARNODE.id, ELEM_VARNODE.id, attrs);
        let vn = Varnode::decode(&decoder, &factory).unwrap().unwrap();
        assert_eq!(vn.get_offset(), 0x10);
        assert_eq!(factory.get_ref(42), Some(vn));
    }

    #[test]
    fn decode_second_pass_attributes_invoke_factory_setters() {
        let ram = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 1);
        let addr_factory = Arc::new(DefaultAddressFactory::new(vec![ram.clone()]));
        let attrs = vec![
            (ATTRIB_SPACE.id, MockAttr::Space(ram.clone())),
            (ATTRIB_OFFSET.id, MockAttr::UInt(0x30)),
            (ATTRIB_GRP.id, MockAttr::SInt(5)),
            (ATTRIB_PERSISTS.id, MockAttr::Bool(true)),
            (ATTRIB_ADDRTIED.id, MockAttr::Bool(true)),
            (ATTRIB_UNAFF.id, MockAttr::Bool(true)),
            (ATTRIB_INPUT.id, MockAttr::Bool(true)),
            (ATTRIB_VOLATILE.id, MockAttr::Bool(true)),
        ];
        let decoder = MockVarnodeDecoder::new(addr_factory.clone(), ELEM_VARNODE.id, ELEM_VARNODE.id, attrs);
        let factory = TestPcodeFactory::new(addr_factory);
        let vn = Varnode::decode(&decoder, &factory).unwrap().unwrap();

        assert_eq!(factory.merge_group_calls.borrow().as_slice(), &[(vn.clone(), 5)]);
        assert_eq!(factory.persistent_calls.borrow().as_slice(), &[vn.clone()]);
        assert_eq!(factory.addr_tied_calls.borrow().as_slice(), &[vn.clone()]);
        assert_eq!(factory.unaffected_calls.borrow().as_slice(), &[vn.clone()]);
        assert_eq!(factory.input_calls.borrow().as_slice(), &[vn.clone()]);
        assert_eq!(factory.volatile_calls.borrow().as_slice(), &[vn]);
    }

    #[test]
    fn decode_false_boolean_attributes_do_not_invoke_setters() {
        let ram = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 1);
        let addr_factory = Arc::new(DefaultAddressFactory::new(vec![ram.clone()]));
        let attrs = vec![
            (ATTRIB_SPACE.id, MockAttr::Space(ram.clone())),
            (ATTRIB_OFFSET.id, MockAttr::UInt(0x30)),
            (ATTRIB_PERSISTS.id, MockAttr::Bool(false)),
        ];
        let decoder = MockVarnodeDecoder::new(addr_factory.clone(), ELEM_VARNODE.id, ELEM_VARNODE.id, attrs);
        let factory = TestPcodeFactory::new(addr_factory);
        let _ = Varnode::decode(&decoder, &factory).unwrap().unwrap();
        assert!(factory.persistent_calls.borrow().is_empty());
    }

    #[test]
    fn decode_join_variable_space_builds_storage_and_uses_join_address() {
        let ram = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 1);
        // `DefaultAddressFactory` deliberately refuses to register a `Variable`-typed space (see
        // its `validate_space`); that's fine here since the "join" space only needs to be a real
        // `AddressSpace` value returned by `read_space()` -- it's never looked up by name.
        let variable_space = AddressSpace::new("VARIABLE", 32, 1, AddressSpaceType::Variable, 4);
        let addr_factory = Arc::new(DefaultAddressFactory::new(vec![ram.clone()]));
        // Real wire format for a join address (see `address_xml::encode_varnodes`) carries a
        // "space" attribute (naming the VARIABLE space) plus indexed "piece" attributes -- no
        // "offset"/"size" attribute at all.
        let attrs = vec![
            (ATTRIB_SPACE.id, MockAttr::Space(variable_space)),
            (ATTRIB_PIECE.id, MockAttr::Str("RAM:0x10:2".to_string())),
        ];
        let decoder = MockVarnodeDecoder::new(addr_factory.clone(), ELEM_VARNODE.id, ELEM_VARNODE.id, attrs);
        let expected_join_addr = ram.address(0x9999);
        let factory = TestPcodeFactory::new(addr_factory).with_join_address(expected_join_addr.clone());

        let vn = Varnode::decode(&decoder, &factory).unwrap().unwrap();
        assert_eq!(vn.get_address(), &expected_join_addr);
        // Logical size defaults to the sum of the piece sizes (one 2-byte piece here).
        assert_eq!(vn.get_size(), 2);
    }

    #[test]
    fn decode_spaceid_element_delegates_to_address_xml_decode() {
        let ram = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 1);
        let const_space = AddressSpace::new("const", 32, 1, AddressSpaceType::Constant, 2);
        let addr_factory = Arc::new(DefaultAddressFactory::new(vec![ram.clone(), const_space]));
        let attrs = vec![(ATTRIB_NAME.id, MockAttr::Space(ram.clone()))];
        let decoder = MockVarnodeDecoder::new(addr_factory.clone(), ELEM_SPACEID.id, ELEM_SPACEID.id, attrs);
        let factory = TestPcodeFactory::new(addr_factory);
        let vn = Varnode::decode(&decoder, &factory).unwrap().unwrap();
        // Per `Varnode.decode`'s ELEM_SPACEID branch: `factory.newVarnode(4, addr)`.
        assert_eq!(vn.get_size(), 4);
        assert_eq!(vn.get_offset(), ram.space_id() as i64);
        assert!(vn.is_constant());
    }

    // --- Varnode::to_string_with_language ---

    /// `Language` mock whose only exercised method is `get_register_at`; everything else is
    /// unreachable from these tests.
    struct MockLanguage {
        registers: Vec<crate::program::model::lang::register::RegisterRef>,
    }

    impl Language for MockLanguage {
        fn get_language_id(&self) -> crate::program::model::lang::language_id::LanguageID {
            unimplemented!("not exercised by these tests")
        }
        fn get_language_description(
            &self,
        ) -> Box<dyn crate::program::model::lang::language_description::LanguageDescription> {
            unimplemented!("not exercised by these tests")
        }
        fn get_parallel_instruction_helper(
            &self,
        ) -> Option<Box<dyn crate::program::model::lang::parallel_instruction_language_helper::ParallelInstructionLanguageHelper>>
        {
            None
        }
        fn get_processor(&self) -> Box<dyn crate::program::seam_stubs::Processor> {
            unimplemented!("not exercised by these tests")
        }
        fn get_version(&self) -> i32 {
            1
        }
        fn get_minor_version(&self) -> i32 {
            0
        }
        fn get_address_factory(&self) -> Box<dyn AddressFactory> {
            unimplemented!("not exercised by these tests")
        }
        fn get_default_space(&self) -> Arc<AddressSpace> {
            unimplemented!("not exercised by these tests")
        }
        fn get_default_data_space(&self) -> Arc<AddressSpace> {
            unimplemented!("not exercised by these tests")
        }
        fn is_big_endian(&self) -> bool {
            false
        }
        fn get_instruction_alignment(&self) -> i32 {
            1
        }
        fn supports_pcode(&self) -> bool {
            true
        }
        fn is_volatile(&self, _addr: &Address) -> bool {
            false
        }
        fn parse(
            &self,
            _buf: &dyn crate::program::model::mem::MemBuffer,
            _context: &mut dyn crate::program::model::lang::processor_context::ProcessorContext,
            _in_delay_slot: bool,
        ) -> Result<
            Box<dyn crate::program::model::lang::instruction_prototype::InstructionPrototype>,
            crate::program::model::lang::language::ParseError,
        > {
            unimplemented!("not exercised by these tests")
        }
        fn get_number_of_user_defined_op_names(&self) -> i32 {
            0
        }
        fn get_user_defined_op_name(&self, _index: i32) -> Option<String> {
            None
        }
        fn get_registers_at(
            &self,
            _address: &Address,
        ) -> Vec<crate::program::model::lang::register::RegisterRef> {
            Vec::new()
        }
        fn get_register_in_space(
            &self,
            _addrspc: &Arc<AddressSpace>,
            _offset: i64,
            _size: i32,
        ) -> Option<crate::program::model::lang::register::RegisterRef> {
            None
        }
        fn get_registers(&self) -> Vec<crate::program::model::lang::register::RegisterRef> {
            self.registers.clone()
        }
        fn get_register_names(&self) -> Vec<String> {
            Vec::new()
        }
        fn get_register_by_name(
            &self,
            _name: &str,
        ) -> Option<crate::program::model::lang::register::RegisterRef> {
            None
        }
        fn get_register_at(
            &self,
            addr: &Address,
            size: i32,
        ) -> Option<crate::program::model::lang::register::RegisterRef> {
            self.registers
                .iter()
                .find(|r| r.borrow().address() == addr && r.borrow().minimum_byte_size() == size)
                .cloned()
        }
        fn get_program_counter(&self) -> Option<crate::program::model::lang::register::RegisterRef> {
            None
        }
        fn get_context_base_register(&self) -> Option<crate::program::model::lang::register::RegisterRef> {
            None
        }
        fn get_context_registers(&self) -> Vec<crate::program::model::lang::register::RegisterRef> {
            Vec::new()
        }
        fn get_default_memory_blocks(
            &self,
        ) -> Vec<Box<dyn crate::app::plugin::processors::generic::MemoryBlockDefinition>> {
            Vec::new()
        }
        fn get_default_symbols(&self) -> Vec<Box<dyn crate::program::seam_stubs::AddressLabelInfo>> {
            Vec::new()
        }
        fn get_segmented_space(&self) -> String {
            String::new()
        }
        fn get_volatile_addresses(&self) -> Box<dyn AddressSetView> {
            unimplemented!("not exercised by these tests")
        }
        fn apply_context_settings(&self, _ctx: &mut dyn crate::program::model::listing::default_program_context::DefaultProgramContext) {}
        fn reload_language(&self, _task_monitor: &dyn crate::util::task::TaskMonitor) -> std::io::Result<()> {
            Ok(())
        }
        fn get_compatible_compiler_spec_descriptions(
            &self,
        ) -> Vec<Box<dyn crate::program::model::lang::compiler_spec_description::CompilerSpecDescription>> {
            Vec::new()
        }
        fn get_compiler_spec_by_id(
            &self,
            _compiler_spec_id: &crate::program::model::lang::compiler_spec_id::CompilerSpecID,
        ) -> Result<
            Box<dyn crate::program::model::lang::compiler_spec::CompilerSpec>,
            crate::program::model::lang::compiler_spec_not_found_exception::CompilerSpecNotFoundException,
        > {
            unimplemented!("not exercised by these tests")
        }
        fn get_default_compiler_spec(&self) -> Box<dyn crate::program::model::lang::compiler_spec::CompilerSpec> {
            unimplemented!("not exercised by these tests")
        }
        fn has_property(&self, _key: &str) -> bool {
            false
        }
        fn get_property_as_int(&self, _key: &str, default_int: i32) -> i32 {
            default_int
        }
        fn get_property_as_boolean(&self, _key: &str, default_boolean: bool) -> bool {
            default_boolean
        }
        fn get_property_or(&self, _key: &str, default_string: &str) -> String {
            default_string.to_string()
        }
        fn get_property(&self, _key: &str) -> Option<String> {
            None
        }
        fn get_property_keys(&self) -> std::collections::HashSet<String> {
            std::collections::HashSet::new()
        }
        fn has_manual(&self) -> bool {
            false
        }
        fn get_manual_entry(&self, _instruction_mnemonic: &str) -> Option<crate::util::manual_entry::ManualEntry> {
            None
        }
        fn get_manual_instruction_mnemonic_keys(&self) -> std::collections::HashSet<String> {
            std::collections::HashSet::new()
        }
        fn get_manual_exception(&self) -> Option<Box<dyn std::error::Error + Send + Sync + 'static>> {
            None
        }
        fn get_sorted_vector_registers(&self) -> Vec<crate::program::model::lang::register::RegisterRef> {
            Vec::new()
        }
        fn get_register_addresses(&self) -> Box<dyn AddressSetView> {
            unimplemented!("not exercised by these tests")
        }
        fn get_maximum_instruction_length(&self) -> Option<i32> {
            None
        }
    }

    #[test]
    fn to_string_with_language_uses_register_name_when_found() {
        let reg_space = AddressSpace::new("register", 32, 1, AddressSpaceType::Register, 5);
        let reg = crate::program::model::lang::register::Register::new(
            "EAX",
            "accumulator",
            Address::new(reg_space.clone(), 0),
            4,
            false,
            0,
        );
        let language = MockLanguage { registers: vec![reg] };
        let vn = Varnode::new(Address::new(reg_space, 0), 4);
        assert_eq!(vn.to_string_with_language(&language), "EAX");
    }

    #[test]
    fn to_string_with_language_falls_back_to_address_form_when_no_register_match() {
        let ram = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 1);
        let language = MockLanguage { registers: vec![] };
        let vn = Varnode::new(Address::new(ram, 0x40), 4);
        let s = vn.to_string_with_language(&language);
        assert!(s.starts_with("A_"), "expected fallback \"A_\" form, got {s:?}");
    }

    #[test]
    fn to_string_with_language_unique_and_constant_never_consult_the_language() {
        let unique = AddressSpace::new("unique", 32, 1, AddressSpaceType::Unique, 6);
        let const_space = AddressSpace::new("const", 32, 1, AddressSpaceType::Constant, 7);
        let language = MockLanguage { registers: vec![] };

        let unique_vn = Varnode::new(Address::new(unique, 0x10), 4);
        assert_eq!(unique_vn.to_string_with_language(&language), "u_10:4");

        let const_vn = Varnode::new(Address::new(const_space, 0x10), 4);
        assert_eq!(const_vn.to_string_with_language(&language), "0x10");
    }

    // --- Varnode::encode_raw ---

    #[derive(Default)]
    struct RecordingEncoder {
        events: Vec<String>,
    }

    impl Encoder for RecordingEncoder {
        fn open_element(&mut self, elem_id: ElementId) -> io::Result<()> {
            self.events.push(format!("open:{}", elem_id.name));
            Ok(())
        }
        fn close_element(&mut self, elem_id: ElementId) -> io::Result<()> {
            self.events.push(format!("close:{}", elem_id.name));
            Ok(())
        }
        fn write_bool(&mut self, attrib_id: AttributeId, val: bool) -> io::Result<()> {
            self.events.push(format!("attr:{}={}", attrib_id.name, val));
            Ok(())
        }
        fn write_signed_integer(&mut self, attrib_id: AttributeId, val: i64) -> io::Result<()> {
            self.events.push(format!("attr:{}={}", attrib_id.name, val));
            Ok(())
        }
        fn write_unsigned_integer(&mut self, attrib_id: AttributeId, val: u64) -> io::Result<()> {
            self.events.push(format!("attr:{}={}", attrib_id.name, val));
            Ok(())
        }
        fn write_string(&mut self, attrib_id: AttributeId, val: &str) -> io::Result<()> {
            self.events.push(format!("attr:{}={}", attrib_id.name, val));
            Ok(())
        }
        fn write_string_indexed(&mut self, attrib_id: AttributeId, index: i32, val: &str) -> io::Result<()> {
            self.events.push(format!("attr:{}[{}]={}", attrib_id.name, index, val));
            Ok(())
        }
        fn write_space(&mut self, attrib_id: AttributeId, spc: &AddressSpace) -> io::Result<()> {
            self.events.push(format!("attr:{}={}", attrib_id.name, spc.name()));
            Ok(())
        }
        fn write_space_indexed(&mut self, attrib_id: AttributeId, index: i32, name: &str) -> io::Result<()> {
            self.events.push(format!("attr:{}[{}]={}", attrib_id.name, index, name));
            Ok(())
        }
        fn write_opcode(
            &mut self,
            _attrib_id: AttributeId,
            _opcode: crate::decompiler::opcodes::op_code::OpCode,
        ) -> io::Result<()> {
            Ok(())
        }
        fn write_opcode_ordinal(&mut self, _attrib_id: AttributeId, _opcode: i32) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn encode_raw_writes_a_plain_sized_addr_element() {
        let ram = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 1);
        let vn = Varnode::new(Address::new(ram, 0x100), 4);
        let mut encoder = RecordingEncoder::default();
        vn.encode_raw(&mut encoder).unwrap();
        assert_eq!(
            encoder.events,
            vec![
                "open:addr".to_string(),
                "attr:space=RAM".to_string(),
                "attr:offset=256".to_string(),
                "attr:size=4".to_string(),
                "close:addr".to_string(),
            ]
        );
    }
}

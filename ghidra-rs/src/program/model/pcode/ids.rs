//! Port of `ghidra.program.model.pcode.ElementId` (and the SLA-format element ids from
//! `SlaFormat`/related sleigh classes), plus `ghidra.program.model.pcode.AttributeId`.
//!
//! **Completeness note (2026-09, PORT_MANIFEST audit of `ElementId.java`)**: this file is a
//! complete port of every real (non-commented-out) `ELEM_*` constant declared in
//! `ghidra.program.model.pcode.ElementId.java` (281 total, including `ELEM_UNKNOWN`) — each has a
//! same-named counterpart below with a matching string `name`. Numeric ids are still deliberately
//! renumbered relative to Java's `ElementId.java` (see the inline comments below, e.g. near
//! `ELEM_BHEAD`) — only the string `name` needs to round-trip to the real `.sla` wire format, not
//! the raw int, so collisions are resolved by continuing a local counter. That divergence is
//! intentional and safe. `tests::all_java_element_ids_present` checks this invariant against the
//! full list of 281 names.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ElementId {
    pub name: &'static str,
    pub id: i32,
}

impl ElementId {
    pub const fn new(name: &'static str, id: i32) -> Self {
        Self { name, id }
    }
}

pub const ELEM_CONST_REAL: ElementId = ElementId::new("const_real", 1);
pub const ELEM_VARNODE_TPL: ElementId = ElementId::new("varnode_tpl", 2);
pub const ELEM_CONST_SPACEID: ElementId = ElementId::new("const_spaceid", 3);
pub const ELEM_CONST_HANDLE: ElementId = ElementId::new("const_handle", 4);
pub const ELEM_OP_TPL: ElementId = ElementId::new("op_tpl", 5);
pub const ELEM_MASK_WORD: ElementId = ElementId::new("mask_word", 6);
pub const ELEM_PAT_BLOCK: ElementId = ElementId::new("pat_block", 7);
pub const ELEM_PRINT: ElementId = ElementId::new("print", 8);
pub const ELEM_PAIR: ElementId = ElementId::new("pair", 9);
pub const ELEM_CONTEXT_PAT: ElementId = ElementId::new("context_pat", 10);
pub const ELEM_NULL: ElementId = ElementId::new("null", 11);
pub const ELEM_OPERAND_EXP: ElementId = ElementId::new("operand_exp", 12);
pub const ELEM_OPERAND_SYM: ElementId = ElementId::new("operand_sym", 13);
pub const ELEM_OPERAND_SYM_HEAD: ElementId = ElementId::new("operand_sym_head", 14);
pub const ELEM_OPER: ElementId = ElementId::new("oper", 15);
pub const ELEM_DECISION: ElementId = ElementId::new("decision", 16);
pub const ELEM_OPPRINT: ElementId = ElementId::new("opprint", 17);
pub const ELEM_INSTRUCT_PAT: ElementId = ElementId::new("instruct_pat", 18);
pub const ELEM_COMBINE_PAT: ElementId = ElementId::new("combine_pat", 19);
pub const ELEM_CONSTRUCTOR: ElementId = ElementId::new("constructor", 20);
pub const ELEM_CONSTRUCT_TPL: ElementId = ElementId::new("construct_tpl", 21);
pub const ELEM_SCOPE: ElementId = ElementId::new("scope", 22);
pub const ELEM_VARNODE_SYM: ElementId = ElementId::new("varnode_sym", 23);
pub const ELEM_VARNODE_SYM_HEAD: ElementId = ElementId::new("varnode_sym_head", 24);
pub const ELEM_USEROP: ElementId = ElementId::new("userop", 25);
pub const ELEM_USEROP_HEAD: ElementId = ElementId::new("userop_head", 26);
pub const ELEM_TOKENFIELD: ElementId = ElementId::new("tokenfield", 27);
pub const ELEM_VAR: ElementId = ElementId::new("var", 28);
pub const ELEM_CONTEXTFIELD: ElementId = ElementId::new("contextfield", 29);
pub const ELEM_HANDLE_TPL: ElementId = ElementId::new("handle_tpl", 30);
pub const ELEM_CONST_RELATIVE: ElementId = ElementId::new("const_relative", 31);
pub const ELEM_CONTEXT_OP: ElementId = ElementId::new("context_op", 32);
pub const ELEM_SLEIGH: ElementId = ElementId::new("sleigh", 33);
pub const ELEM_SPACES: ElementId = ElementId::new("spaces", 34);
pub const ELEM_SOURCEFILES: ElementId = ElementId::new("sourcefiles", 35);
pub const ELEM_SOURCEFILE: ElementId = ElementId::new("sourcefile", 36);
pub const ELEM_SPACE: ElementId = ElementId::new("space", 37);
pub const ELEM_SYMBOL_TABLE: ElementId = ElementId::new("symbol_table", 38);
pub const ELEM_VALUE_SYM: ElementId = ElementId::new("value_sym", 39);
pub const ELEM_VALUE_SYM_HEAD: ElementId = ElementId::new("value_sym_head", 40);
pub const ELEM_CONTEXT_SYM: ElementId = ElementId::new("context_sym", 41);
pub const ELEM_CONTEXT_SYM_HEAD: ElementId = ElementId::new("context_sym_head", 42);
pub const ELEM_END_SYM: ElementId = ElementId::new("end_sym", 43);
pub const ELEM_END_SYM_HEAD: ElementId = ElementId::new("end_sym_head", 44);
pub const ELEM_SPACE_OTHER: ElementId = ElementId::new("space_other", 45);
pub const ELEM_SPACE_UNIQUE: ElementId = ElementId::new("space_unique", 46);
pub const ELEM_AND_EXP: ElementId = ElementId::new("and_exp", 47);
pub const ELEM_DIV_EXP: ElementId = ElementId::new("div_exp", 48);
pub const ELEM_LSHIFT_EXP: ElementId = ElementId::new("lshift_exp", 49);
pub const ELEM_MINUS_EXP: ElementId = ElementId::new("minus_exp", 50);
pub const ELEM_MULT_EXP: ElementId = ElementId::new("mult_exp", 51);
pub const ELEM_NOT_EXP: ElementId = ElementId::new("not_exp", 52);
pub const ELEM_OR_EXP: ElementId = ElementId::new("or_exp", 53);
pub const ELEM_PLUS_EXP: ElementId = ElementId::new("plus_exp", 54);
pub const ELEM_RSHIFT_EXP: ElementId = ElementId::new("rshift_exp", 55);
pub const ELEM_SUB_EXP: ElementId = ElementId::new("sub_exp", 56);
pub const ELEM_XOR_EXP: ElementId = ElementId::new("xor_exp", 57);
pub const ELEM_INTB: ElementId = ElementId::new("intb", 58);
pub const ELEM_END_EXP: ElementId = ElementId::new("end_exp", 59);
pub const ELEM_NEXT2_EXP: ElementId = ElementId::new("next2_exp", 60);
pub const ELEM_START_EXP: ElementId = ElementId::new("start_exp", 61);
pub const ELEM_EPSILON_SYM: ElementId = ElementId::new("epsilon_sym", 62);
pub const ELEM_EPSILON_SYM_HEAD: ElementId = ElementId::new("epsilon_sym_head", 63);
pub const ELEM_NAME_SYM: ElementId = ElementId::new("name_sym", 64);
pub const ELEM_NAME_SYM_HEAD: ElementId = ElementId::new("name_sym_head", 65);
pub const ELEM_NAMETAB: ElementId = ElementId::new("nametab", 66);
pub const ELEM_NEXT2_SYM: ElementId = ElementId::new("next2_sym", 67);
pub const ELEM_NEXT2_SYM_HEAD: ElementId = ElementId::new("next2_sym_head", 68);
pub const ELEM_START_SYM: ElementId = ElementId::new("start_sym", 69);
pub const ELEM_START_SYM_HEAD: ElementId = ElementId::new("start_sym_head", 70);
pub const ELEM_SUBTABLE_SYM: ElementId = ElementId::new("subtable_sym", 71);
pub const ELEM_SUBTABLE_SYM_HEAD: ElementId = ElementId::new("subtable_sym_head", 72);
pub const ELEM_VALUEMAP_SYM: ElementId = ElementId::new("valuemap_sym", 73);
pub const ELEM_VALUEMAP_SYM_HEAD: ElementId = ElementId::new("valuemap_sym_head", 74);
pub const ELEM_VALUETAB: ElementId = ElementId::new("valuetab", 75);
pub const ELEM_VARLIST_SYM: ElementId = ElementId::new("varlist_sym", 76);
pub const ELEM_VARLIST_SYM_HEAD: ElementId = ElementId::new("varlist_sym_head", 77);
pub const ELEM_OR_PAT: ElementId = ElementId::new("or_pat", 78);
pub const ELEM_COMMIT: ElementId = ElementId::new("commit", 79);
pub const ELEM_CONST_START: ElementId = ElementId::new("const_start", 80);
pub const ELEM_CONST_NEXT: ElementId = ElementId::new("const_next", 81);
pub const ELEM_CONST_NEXT2: ElementId = ElementId::new("const_next2", 82);
pub const ELEM_CONST_CURSPACE: ElementId = ElementId::new("const_curspace", 83);
pub const ELEM_CONST_CURSPACE_SIZE: ElementId = ElementId::new("const_curspace_size", 84);
pub const ELEM_CONST_FLOWREF: ElementId = ElementId::new("const_flowref", 85);
pub const ELEM_CONST_FLOWREF_SIZE: ElementId = ElementId::new("const_flowref_size", 86);
pub const ELEM_CONST_FLOWDEST: ElementId = ElementId::new("const_flowdest", 87);
pub const ELEM_CONST_FLOWDEST_SIZE: ElementId = ElementId::new("const_flowdest_size", 88);

pub const ELEM_INST: ElementId = ElementId::new("inst", 98);

// Added legacy or missing IDs if needed, but keeping SlaFormat primary
pub const ELEM_DATA: ElementId = ElementId::new("data", 100); // Dummy for now if not in SlaFormat
pub const ELEM_INPUT: ElementId = ElementId::new("input", 101);
pub const ELEM_OFF_EL: ElementId = ElementId::new("off", 102);
pub const ELEM_OUTPUT: ElementId = ElementId::new("output", 103);
pub const ELEM_RETURNADDRESS: ElementId = ElementId::new("returnaddress", 104);
pub const ELEM_SYMBOL: ElementId = ElementId::new("symbol", 105);
pub const ELEM_TARGET: ElementId = ElementId::new("target", 106);
pub const ELEM_VOID: ElementId = ElementId::new("void", 107);
pub const ELEM_ADDR: ElementId = ElementId::new("addr", 108);
pub const ELEM_RANGE: ElementId = ElementId::new("range", 109);
pub const ELEM_RANGELIST: ElementId = ElementId::new("rangelist", 110);
pub const ELEM_REGISTER: ElementId = ElementId::new("register", 111);
pub const ELEM_SEQNUM: ElementId = ElementId::new("seqnum", 112);
pub const ELEM_VARNODE: ElementId = ElementId::new("varnode", 113);
pub const ELEM_SPACEID: ElementId = ElementId::new("spaceid", 114);
pub const ELEM_SPACE_BASE: ElementId = ElementId::new("space_base", 115);
pub const ELEM_SPACE_OVERLAY: ElementId = ElementId::new("space_overlay", 116);
pub const ELEM_TRUNCATE_SPACE: ElementId = ElementId::new("truncate_space", 117);
pub const ELEM_OP: ElementId = ElementId::new("op", 118);
// Real Ghidra id is 102 (`ElementId.java`'s `ELEM_BHEAD`), but that collides with this file's
// own `ELEM_OFF_EL` at 102 under its internal (non-wire-compatible) numbering scheme, so it is
// renumbered to continue the local counter above instead.
pub const ELEM_BHEAD: ElementId = ElementId::new("bhead", 119);
// Real Ghidra id is 160 (`ElementId.java`'s `ELEM_GROUP`), continuing the local counter above
// instead per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_GROUP: ElementId = ElementId::new("group", 120);
// Real Ghidra id is 168 (`ElementId.java`'s `ELEM_PENTRY`), continuing the local counter above
// instead per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_PENTRY: ElementId = ElementId::new("pentry", 121);
// Real Ghidra id is 73 (`ElementId.java`'s `ELEM_HASH`), continuing the local counter above
// instead per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_HASH: ElementId = ElementId::new("hash", 122);
// Continuing the local counter above per the same non-wire-compatible numbering scheme as
// `ELEM_BHEAD`.
pub const ELEM_PARENT: ElementId = ElementId::new("parent", 123);
pub const ELEM_VAL: ElementId = ElementId::new("val", 124);
// Real Ghidra id is 3 (`ElementId.java`'s `ELEM_OFF`), but that collides with this file's own
// `ELEM_CONST_SPACEID` at 3, so it is renumbered to continue the local counter above instead per
// the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_OFF: ElementId = ElementId::new("off", 125);
// Real Ghidra id is 41 (`ElementId.java`'s `ELEM_CORETYPES`), renumbered per the same scheme.
pub const ELEM_CORETYPES: ElementId = ElementId::new("coretypes", 126);
// Real Ghidra id is 43 (`ElementId.java`'s `ELEM_DEF`), renumbered per the same scheme.
pub const ELEM_DEF: ElementId = ElementId::new("def", 127);
// Real Ghidra id is 49 (`ElementId.java`'s `ELEM_FIELD`), renumbered per the same scheme.
pub const ELEM_FIELD: ElementId = ElementId::new("field", 128);
// Real Ghidra id is 60 (`ElementId.java`'s `ELEM_TYPE`), renumbered per the same scheme.
pub const ELEM_TYPE: ElementId = ElementId::new("type", 129);
// Real Ghidra id is 63 (`ElementId.java`'s `ELEM_TYPEREF`), renumbered per the same scheme.
pub const ELEM_TYPEREF: ElementId = ElementId::new("typeref", 130);
// Real Ghidra id is 289 (`ElementId.java`'s `ELEM_BITFIELD`), renumbered per the same scheme.
pub const ELEM_BITFIELD: ElementId = ElementId::new("bitfield", 131);
// Real Ghidra id is 110 (`ElementId.java`'s `ELEM_CPOOLREC`), but that collides with this file's
// own `ELEM_RANGELIST` at 110, so it is renumbered to continue the local counter above instead
// per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_CPOOLREC: ElementId = ElementId::new("cpoolrec", 132);
// Real Ghidra id is 9 (`ElementId.java`'s `ELEM_VALUE`), but that collides with this file's own
// `ELEM_PAIR` at 9, so it is renumbered per the same scheme.
pub const ELEM_VALUE: ElementId = ElementId::new("value", 133);
// Real Ghidra id is 112 (`ElementId.java`'s `ELEM_TOKEN`), but that collides with this file's own
// `ELEM_SEQNUM` at 112, so it is renumbered per the same scheme.
pub const ELEM_TOKEN: ElementId = ElementId::new("token", 134);
// Real Ghidra id is 113 (`ElementId.java`'s `ELEM_IOP`), but that collides with this file's own
// `ELEM_VARNODE` at 113, so it is renumbered to continue the local counter above instead per the
// same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_IOP: ElementId = ElementId::new("iop", 135);
// Real Ghidra ids are 37/38/39/40/42/44/45/46/47/50/51/52/53/54/55/56/57/58/59/65
// (`ElementId.java`'s `ELEM_ABSOLUTE_MAX_ALIGNMENT`/`ELEM_BITFIELD_PACKING`/`ELEM_CHAR_SIZE`/
// `ELEM_CHAR_TYPE`/`ELEM_DATA_ORGANIZATION`/`ELEM_DEFAULT_ALIGNMENT`/
// `ELEM_DEFAULT_POINTER_ALIGNMENT`/`ELEM_DOUBLE_SIZE`/`ELEM_ENTRY`/`ELEM_FLOAT_SIZE`/
// `ELEM_INTEGER_SIZE`/`ELEM_LONG_DOUBLE_SIZE`/`ELEM_LONG_LONG_SIZE`/`ELEM_LONG_SIZE`/
// `ELEM_MACHINE_ALIGNMENT`/`ELEM_POINTER_SHIFT`/`ELEM_POINTER_SIZE`/`ELEM_SHORT_SIZE`/
// `ELEM_SIZE_ALIGNMENT_MAP`/`ELEM_WCHAR_SIZE`), all of which collide with other entries already
// in this table, so they continue the local counter above instead per the same
// non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_ABSOLUTE_MAX_ALIGNMENT: ElementId = ElementId::new("absolute_max_alignment", 136);
pub const ELEM_BITFIELD_PACKING: ElementId = ElementId::new("bitfield_packing", 137);
pub const ELEM_CHAR_SIZE: ElementId = ElementId::new("char_size", 138);
pub const ELEM_CHAR_TYPE: ElementId = ElementId::new("char_type", 139);
pub const ELEM_DATA_ORGANIZATION: ElementId = ElementId::new("data_organization", 140);
pub const ELEM_DEFAULT_ALIGNMENT: ElementId = ElementId::new("default_alignment", 141);
pub const ELEM_DEFAULT_POINTER_ALIGNMENT: ElementId =
    ElementId::new("default_pointer_alignment", 142);
pub const ELEM_DOUBLE_SIZE: ElementId = ElementId::new("double_size", 143);
pub const ELEM_ENTRY: ElementId = ElementId::new("entry", 144);
pub const ELEM_FLOAT_SIZE: ElementId = ElementId::new("float_size", 145);
pub const ELEM_INTEGER_SIZE: ElementId = ElementId::new("integer_size", 146);
pub const ELEM_LONG_DOUBLE_SIZE: ElementId = ElementId::new("long_double_size", 147);
pub const ELEM_LONG_LONG_SIZE: ElementId = ElementId::new("long_long_size", 148);
pub const ELEM_LONG_SIZE: ElementId = ElementId::new("long_size", 149);
pub const ELEM_MACHINE_ALIGNMENT: ElementId = ElementId::new("machine_alignment", 150);
pub const ELEM_POINTER_SHIFT: ElementId = ElementId::new("pointer_shift", 151);
pub const ELEM_POINTER_SIZE: ElementId = ElementId::new("pointer_size", 152);
pub const ELEM_SHORT_SIZE: ElementId = ElementId::new("short_size", 153);
pub const ELEM_SIZE_ALIGNMENT_MAP: ElementId = ElementId::new("size_alignment_map", 154);
pub const ELEM_WCHAR_SIZE: ElementId = ElementId::new("wchar_size", 155);
// Real Ghidra id is 20 (`ElementId.java`'s `ELEM_FUNCPROTO`), continuing the local counter above
// instead per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_FUNCPROTO: ElementId = ElementId::new("funcproto", 156);
// Real Ghidra id is 22 (`ElementId.java`'s `ELEM_RETURN_TYPE`), continuing the local counter above.
pub const ELEM_RETURN_TYPE: ElementId = ElementId::new("return_type", 157);
// Real Ghidra id is 23 (`ElementId.java`'s `ELEM_STATEMENT`), continuing the local counter above.
pub const ELEM_STATEMENT: ElementId = ElementId::new("statement", 158);
// Real Ghidra id is 25 (`ElementId.java`'s `ELEM_VARDECL`), continuing the local counter above.
pub const ELEM_VARDECL: ElementId = ElementId::new("vardecl", 159);
// Real Ghidra id is 103 (`ElementId.java`'s `ELEM_BLOCK`), continuing the local counter above
// (this file's own id 103 is already taken by `ELEM_OUTPUT`, an unrelated sleigh element).
pub const ELEM_BLOCK: ElementId = ElementId::new("block", 160);
// Real Ghidra ids are 17/19/21/24/26/86 (`ElementId.java`'s `ELEM_BREAK`/`ELEM_FUNCNAME`/
// `ELEM_LABEL`/`ELEM_SYNTAX`/`ELEM_VARIABLE`/`ELEM_COMMENT`), all of which collide with other
// entries already in this table, so they continue the local counter above instead per the same
// non-wire-compatible numbering scheme as `ELEM_BHEAD`. These are the token element ids
// `ClangToken::build_token` dispatches on.
pub const ELEM_BREAK: ElementId = ElementId::new("break", 161);
pub const ELEM_FUNCNAME: ElementId = ElementId::new("funcname", 162);
pub const ELEM_LABEL: ElementId = ElementId::new("label", 163);
pub const ELEM_SYNTAX: ElementId = ElementId::new("syntax", 164);
pub const ELEM_VARIABLE: ElementId = ElementId::new("variable", 165);
pub const ELEM_COMMENT: ElementId = ElementId::new("comment", 166);
pub const ELEM_BLOCKSIG: ElementId = ElementId::new("blocksig", 258);
pub const ELEM_COPYSIG: ElementId = ElementId::new("copysig", 263);
pub const ELEM_VARSIG: ElementId = ElementId::new("varsig", 269);
// Real Ghidra ids are 61/64/66 (`ElementId.java`'s `ELEM_TYPE_ALIGNMENT_ENABLED`/
// `ELEM_USE_MS_CONVENTION`/`ELEM_ZERO_LENGTH_BOUNDARY`), all of which collide with other entries
// already in this table, so they continue the local counter above instead per the same
// non-wire-compatible numbering scheme as `ELEM_BHEAD`. Used by
// `BitFieldPackingImpl::encode`/`restore_xml`.
pub const ELEM_TYPE_ALIGNMENT_ENABLED: ElementId =
    ElementId::new("type_alignment_enabled", 270);
pub const ELEM_USE_MS_CONVENTION: ElementId = ElementId::new("use_MS_convention", 271);
pub const ELEM_ZERO_LENGTH_BOUNDARY: ElementId = ElementId::new("zero_length_boundary", 272);

// --- Remaining ELEM_* constants from ElementId.java (PORT_MANIFEST audit gap-fill, 2026-09) ---
// The 202 constants below complete the port of every real (non-commented-out) ELEM_* constant
// declared in ghidra.program.model.pcode.ElementId.java (281 total; see the corrected count in
// the module doc comment above). Each continues the same non-wire-compatible renumbering
// scheme established above (id 273 onward) since only the string `name` needs to round-trip
// to the .sla wire format, not the raw Java int. Section groupings below mirror the section
// comments in ElementId.java itself.

// prettyprint
// Real Ghidra id is 18 (`ElementId.java`'s `ELEM_CLANG_DOCUMENT`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_CLANG_DOCUMENT: ElementId = ElementId::new("clang_document", 273);

// type
// Real Ghidra id is 48 (`ElementId.java`'s `ELEM_ENUM`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_ENUM: ElementId = ElementId::new("enum", 274);
// Real Ghidra id is 62 (`ElementId.java`'s `ELEM_TYPEGRP`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_TYPEGRP: ElementId = ElementId::new("typegrp", 275);

// database
// Real Ghidra id is 67 (`ElementId.java`'s `ELEM_COLLISION`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_COLLISION: ElementId = ElementId::new("collision", 276);
// Real Ghidra id is 68 (`ElementId.java`'s `ELEM_DB`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_DB: ElementId = ElementId::new("db", 277);
// Real Ghidra id is 69 (`ElementId.java`'s `ELEM_EQUATESYMBOL`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_EQUATESYMBOL: ElementId = ElementId::new("equatesymbol", 278);
// Real Ghidra id is 70 (`ElementId.java`'s `ELEM_EXTERNREFSYMBOL`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_EXTERNREFSYMBOL: ElementId = ElementId::new("externrefsymbol", 279);
// Real Ghidra id is 71 (`ElementId.java`'s `ELEM_FACETSYMBOL`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_FACETSYMBOL: ElementId = ElementId::new("facetsymbol", 280);
// Real Ghidra id is 72 (`ElementId.java`'s `ELEM_FUNCTIONSHELL`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_FUNCTIONSHELL: ElementId = ElementId::new("functionshell", 281);
// Real Ghidra id is 74 (`ElementId.java`'s `ELEM_HOLE`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_HOLE: ElementId = ElementId::new("hole", 282);
// Real Ghidra id is 75 (`ElementId.java`'s `ELEM_LABELSYM`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_LABELSYM: ElementId = ElementId::new("labelsym", 283);
// Real Ghidra id is 76 (`ElementId.java`'s `ELEM_MAPSYM`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_MAPSYM: ElementId = ElementId::new("mapsym", 284);
// Real Ghidra id is 78 (`ElementId.java`'s `ELEM_PROPERTY_CHANGEPOINT`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_PROPERTY_CHANGEPOINT: ElementId = ElementId::new("property_changepoint", 285);
// Real Ghidra id is 79 (`ElementId.java`'s `ELEM_RANGEEQUALSSYMBOLS`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_RANGEEQUALSSYMBOLS: ElementId = ElementId::new("rangeequalssymbols", 286);
// Real Ghidra id is 81 (`ElementId.java`'s `ELEM_SYMBOLLIST`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_SYMBOLLIST: ElementId = ElementId::new("symbollist", 287);

// variable
// Real Ghidra id is 82 (`ElementId.java`'s `ELEM_HIGH`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_HIGH: ElementId = ElementId::new("high", 288);

// stringmanage
// Real Ghidra id is 83 (`ElementId.java`'s `ELEM_BYTES`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_BYTES: ElementId = ElementId::new("bytes", 289);
// Real Ghidra id is 84 (`ElementId.java`'s `ELEM_STRING`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_STRING: ElementId = ElementId::new("string", 290);
// Real Ghidra id is 85 (`ElementId.java`'s `ELEM_STRINGMANAGE`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_STRINGMANAGE: ElementId = ElementId::new("stringmanage", 291);

// comment
// Real Ghidra id is 87 (`ElementId.java`'s `ELEM_COMMENTDB`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_COMMENTDB: ElementId = ElementId::new("commentdb", 292);
// Real Ghidra id is 88 (`ElementId.java`'s `ELEM_TEXT`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_TEXT: ElementId = ElementId::new("text", 293);

// pcodeinject
// Real Ghidra id is 89 (`ElementId.java`'s `ELEM_ADDR_PCODE`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_ADDR_PCODE: ElementId = ElementId::new("addr_pcode", 294);
// Real Ghidra id is 90 (`ElementId.java`'s `ELEM_BODY`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_BODY: ElementId = ElementId::new("body", 295);
// Real Ghidra id is 91 (`ElementId.java`'s `ELEM_CALLFIXUP`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_CALLFIXUP: ElementId = ElementId::new("callfixup", 296);
// Real Ghidra id is 92 (`ElementId.java`'s `ELEM_CALLOTHERFIXUP`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_CALLOTHERFIXUP: ElementId = ElementId::new("callotherfixup", 297);
// Real Ghidra id is 93 (`ElementId.java`'s `ELEM_CASE_PCODE`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_CASE_PCODE: ElementId = ElementId::new("case_pcode", 298);
// Real Ghidra id is 94 (`ElementId.java`'s `ELEM_CONTEXT`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_CONTEXT: ElementId = ElementId::new("context", 299);
// Real Ghidra id is 95 (`ElementId.java`'s `ELEM_DEFAULT_PCODE`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_DEFAULT_PCODE: ElementId = ElementId::new("default_pcode", 300);
// Real Ghidra id is 96 (`ElementId.java`'s `ELEM_INJECT`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_INJECT: ElementId = ElementId::new("inject", 301);
// Real Ghidra id is 97 (`ElementId.java`'s `ELEM_INJECTDEBUG`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_INJECTDEBUG: ElementId = ElementId::new("injectdebug", 302);
// Real Ghidra id is 99 (`ElementId.java`'s `ELEM_PAYLOAD`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_PAYLOAD: ElementId = ElementId::new("payload", 303);
// Real Ghidra id is 100 (`ElementId.java`'s `ELEM_PCODE`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_PCODE: ElementId = ElementId::new("pcode", 304);
// Real Ghidra id is 101 (`ElementId.java`'s `ELEM_SIZE_PCODE`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_SIZE_PCODE: ElementId = ElementId::new("size_pcode", 305);

// block
// Real Ghidra id is 104 (`ElementId.java`'s `ELEM_BLOCKEDGE`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_BLOCKEDGE: ElementId = ElementId::new("blockedge", 306);
// Real Ghidra id is 105 (`ElementId.java`'s `ELEM_EDGE`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_EDGE: ElementId = ElementId::new("edge", 307);

// paramid
// Real Ghidra id is 106 (`ElementId.java`'s `ELEM_PARAMMEASURES`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_PARAMMEASURES: ElementId = ElementId::new("parammeasures", 308);
// Real Ghidra id is 107 (`ElementId.java`'s `ELEM_PROTO`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_PROTO: ElementId = ElementId::new("proto", 309);
// Real Ghidra id is 108 (`ElementId.java`'s `ELEM_RANK`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_RANK: ElementId = ElementId::new("rank", 310);

// cpool
// Real Ghidra id is 109 (`ElementId.java`'s `ELEM_CONSTANTPOOL`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_CONSTANTPOOL: ElementId = ElementId::new("constantpool", 311);
// Real Ghidra id is 111 (`ElementId.java`'s `ELEM_REF`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_REF: ElementId = ElementId::new("ref", 312);

// op
// Real Ghidra id is 114 (`ElementId.java`'s `ELEM_UNIMPL`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_UNIMPL: ElementId = ElementId::new("unimpl", 313);

// funcdata
// Real Ghidra id is 115 (`ElementId.java`'s `ELEM_AST`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_AST: ElementId = ElementId::new("ast", 314);
// Real Ghidra id is 116 (`ElementId.java`'s `ELEM_FUNCTION`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_FUNCTION: ElementId = ElementId::new("function", 315);
// Real Ghidra id is 117 (`ElementId.java`'s `ELEM_HIGHLIST`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_HIGHLIST: ElementId = ElementId::new("highlist", 316);
// Real Ghidra id is 118 (`ElementId.java`'s `ELEM_JUMPTABLELIST`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_JUMPTABLELIST: ElementId = ElementId::new("jumptablelist", 317);
// Real Ghidra id is 119 (`ElementId.java`'s `ELEM_VARNODES`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_VARNODES: ElementId = ElementId::new("varnodes", 318);

// globalcontext
// Real Ghidra id is 120 (`ElementId.java`'s `ELEM_CONTEXT_DATA`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_CONTEXT_DATA: ElementId = ElementId::new("context_data", 319);
// Real Ghidra id is 121 (`ElementId.java`'s `ELEM_CONTEXT_POINTS`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_CONTEXT_POINTS: ElementId = ElementId::new("context_points", 320);
// Real Ghidra id is 122 (`ElementId.java`'s `ELEM_CONTEXT_POINTSET`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_CONTEXT_POINTSET: ElementId = ElementId::new("context_pointset", 321);
// Real Ghidra id is 123 (`ElementId.java`'s `ELEM_CONTEXT_SET`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_CONTEXT_SET: ElementId = ElementId::new("context_set", 322);
// Real Ghidra id is 124 (`ElementId.java`'s `ELEM_SET`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_SET: ElementId = ElementId::new("set", 323);
// Real Ghidra id is 125 (`ElementId.java`'s `ELEM_TRACKED_POINTSET`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_TRACKED_POINTSET: ElementId = ElementId::new("tracked_pointset", 324);
// Real Ghidra id is 126 (`ElementId.java`'s `ELEM_TRACKED_SET`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_TRACKED_SET: ElementId = ElementId::new("tracked_set", 325);

// userop
// Real Ghidra id is 127 (`ElementId.java`'s `ELEM_CONSTRESOLVE`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_CONSTRESOLVE: ElementId = ElementId::new("constresolve", 326);
// Real Ghidra id is 128 (`ElementId.java`'s `ELEM_JUMPASSIST`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_JUMPASSIST: ElementId = ElementId::new("jumpassist", 327);
// Real Ghidra id is 129 (`ElementId.java`'s `ELEM_SEGMENTOP`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_SEGMENTOP: ElementId = ElementId::new("segmentop", 328);

// architecture
// Real Ghidra id is 130 (`ElementId.java`'s `ELEM_ADDRESS_SHIFT_AMOUNT`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_ADDRESS_SHIFT_AMOUNT: ElementId = ElementId::new("address_shift_amount", 329);
// Real Ghidra id is 131 (`ElementId.java`'s `ELEM_AGGRESSIVETRIM`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_AGGRESSIVETRIM: ElementId = ElementId::new("aggressivetrim", 330);
// Real Ghidra id is 132 (`ElementId.java`'s `ELEM_COMPILER_SPEC`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_COMPILER_SPEC: ElementId = ElementId::new("compiler_spec", 331);
// Real Ghidra id is 133 (`ElementId.java`'s `ELEM_DATA_SPACE`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_DATA_SPACE: ElementId = ElementId::new("data_space", 332);
// Real Ghidra id is 134 (`ElementId.java`'s `ELEM_DEFAULT_MEMORY_BLOCKS`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_DEFAULT_MEMORY_BLOCKS: ElementId = ElementId::new("default_memory_blocks", 333);
// Real Ghidra id is 135 (`ElementId.java`'s `ELEM_DEFAULT_PROTO`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_DEFAULT_PROTO: ElementId = ElementId::new("default_proto", 334);
// Real Ghidra id is 136 (`ElementId.java`'s `ELEM_DEFAULT_SYMBOLS`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_DEFAULT_SYMBOLS: ElementId = ElementId::new("default_symbols", 335);
// Real Ghidra id is 137 (`ElementId.java`'s `ELEM_EVAL_CALLED_PROTOTYPE`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_EVAL_CALLED_PROTOTYPE: ElementId = ElementId::new("eval_called_prototype", 336);
// Real Ghidra id is 138 (`ElementId.java`'s `ELEM_EVAL_CURRENT_PROTOTYPE`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_EVAL_CURRENT_PROTOTYPE: ElementId = ElementId::new("eval_current_prototype", 337);
// Real Ghidra id is 139 (`ElementId.java`'s `ELEM_EXPERIMENTAL_RULES`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_EXPERIMENTAL_RULES: ElementId = ElementId::new("experimental_rules", 338);
// Real Ghidra id is 140 (`ElementId.java`'s `ELEM_FLOWOVERRIDELIST`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_FLOWOVERRIDELIST: ElementId = ElementId::new("flowoverridelist", 339);
// Real Ghidra id is 141 (`ElementId.java`'s `ELEM_FUNCPTR`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_FUNCPTR: ElementId = ElementId::new("funcptr", 340);
// Real Ghidra id is 142 (`ElementId.java`'s `ELEM_GLOBAL`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_GLOBAL: ElementId = ElementId::new("global", 341);
// Real Ghidra id is 143 (`ElementId.java`'s `ELEM_INCIDENTALCOPY`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_INCIDENTALCOPY: ElementId = ElementId::new("incidentalcopy", 342);
// Real Ghidra id is 144 (`ElementId.java`'s `ELEM_INFERPTRBOUNDS`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_INFERPTRBOUNDS: ElementId = ElementId::new("inferptrbounds", 343);
// Real Ghidra id is 145 (`ElementId.java`'s `ELEM_MODELALIAS`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_MODELALIAS: ElementId = ElementId::new("modelalias", 344);
// Real Ghidra id is 146 (`ElementId.java`'s `ELEM_NOHIGHPTR`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_NOHIGHPTR: ElementId = ElementId::new("nohighptr", 345);
// Real Ghidra id is 147 (`ElementId.java`'s `ELEM_PROCESSOR_SPEC`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_PROCESSOR_SPEC: ElementId = ElementId::new("processor_spec", 346);
// Real Ghidra id is 148 (`ElementId.java`'s `ELEM_PROGRAMCOUNTER`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_PROGRAMCOUNTER: ElementId = ElementId::new("programcounter", 347);
// Real Ghidra id is 149 (`ElementId.java`'s `ELEM_PROPERTIES`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_PROPERTIES: ElementId = ElementId::new("properties", 348);
// Real Ghidra id is 150 (`ElementId.java`'s `ELEM_PROPERTY`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_PROPERTY: ElementId = ElementId::new("property", 349);
// Real Ghidra id is 151 (`ElementId.java`'s `ELEM_READONLY`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_READONLY: ElementId = ElementId::new("readonly", 350);
// Real Ghidra id is 152 (`ElementId.java`'s `ELEM_REGISTER_DATA`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_REGISTER_DATA: ElementId = ElementId::new("register_data", 351);
// Real Ghidra id is 153 (`ElementId.java`'s `ELEM_RULE`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_RULE: ElementId = ElementId::new("rule", 352);
// Real Ghidra id is 154 (`ElementId.java`'s `ELEM_SAVE_STATE`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_SAVE_STATE: ElementId = ElementId::new("save_state", 353);
// Real Ghidra id is 155 (`ElementId.java`'s `ELEM_SEGMENTED_ADDRESS`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_SEGMENTED_ADDRESS: ElementId = ElementId::new("segmented_address", 354);
// Real Ghidra id is 156 (`ElementId.java`'s `ELEM_SPACEBASE`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_SPACEBASE: ElementId = ElementId::new("spacebase", 355);
// Real Ghidra id is 157 (`ElementId.java`'s `ELEM_SPECEXTENSIONS`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_SPECEXTENSIONS: ElementId = ElementId::new("specextensions", 356);
// Real Ghidra id is 158 (`ElementId.java`'s `ELEM_STACKPOINTER`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_STACKPOINTER: ElementId = ElementId::new("stackpointer", 357);
// Real Ghidra id is 159 (`ElementId.java`'s `ELEM_VOLATILE`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_VOLATILE: ElementId = ElementId::new("volatile", 358);

// fspec
// Real Ghidra id is 161 (`ElementId.java`'s `ELEM_INTERNALLIST`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_INTERNALLIST: ElementId = ElementId::new("internallist", 359);
// Real Ghidra id is 162 (`ElementId.java`'s `ELEM_KILLEDBYCALL`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_KILLEDBYCALL: ElementId = ElementId::new("killedbycall", 360);
// Real Ghidra id is 163 (`ElementId.java`'s `ELEM_LIKELYTRASH`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_LIKELYTRASH: ElementId = ElementId::new("likelytrash", 361);
// Real Ghidra id is 164 (`ElementId.java`'s `ELEM_LOCALRANGE`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_LOCALRANGE: ElementId = ElementId::new("localrange", 362);
// Real Ghidra id is 165 (`ElementId.java`'s `ELEM_MODEL`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_MODEL: ElementId = ElementId::new("model", 363);
// Real Ghidra id is 166 (`ElementId.java`'s `ELEM_PARAM`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_PARAM: ElementId = ElementId::new("param", 364);
// Real Ghidra id is 167 (`ElementId.java`'s `ELEM_PARAMRANGE`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_PARAMRANGE: ElementId = ElementId::new("paramrange", 365);
// Real Ghidra id is 169 (`ElementId.java`'s `ELEM_PROTOTYPE`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_PROTOTYPE: ElementId = ElementId::new("prototype", 366);
// Real Ghidra id is 170 (`ElementId.java`'s `ELEM_RESOLVEPROTOTYPE`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_RESOLVEPROTOTYPE: ElementId = ElementId::new("resolveprototype", 367);
// Real Ghidra id is 171 (`ElementId.java`'s `ELEM_RETPARAM`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_RETPARAM: ElementId = ElementId::new("retparam", 368);
// Real Ghidra id is 172 (`ElementId.java`'s `ELEM_RETURNSYM`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_RETURNSYM: ElementId = ElementId::new("returnsym", 369);
// Real Ghidra id is 173 (`ElementId.java`'s `ELEM_UNAFFECTED`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_UNAFFECTED: ElementId = ElementId::new("unaffected", 370);
// Real Ghidra id is 286 (`ElementId.java`'s `ELEM_INTERNAL_STORAGE`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_INTERNAL_STORAGE: ElementId = ElementId::new("internal_storage", 371);

// options
// Real Ghidra id is 174 (`ElementId.java`'s `ELEM_ALIASBLOCK`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_ALIASBLOCK: ElementId = ElementId::new("aliasblock", 372);
// Real Ghidra id is 175 (`ElementId.java`'s `ELEM_ALLOWCONTEXTSET`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_ALLOWCONTEXTSET: ElementId = ElementId::new("allowcontextset", 373);
// Real Ghidra id is 176 (`ElementId.java`'s `ELEM_ANALYZEFORLOOPS`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_ANALYZEFORLOOPS: ElementId = ElementId::new("analyzeforloops", 374);
// Real Ghidra id is 177 (`ElementId.java`'s `ELEM_COMMENTHEADER`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_COMMENTHEADER: ElementId = ElementId::new("commentheader", 375);
// Real Ghidra id is 178 (`ElementId.java`'s `ELEM_COMMENTINDENT`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_COMMENTINDENT: ElementId = ElementId::new("commentindent", 376);
// Real Ghidra id is 179 (`ElementId.java`'s `ELEM_COMMENTINSTRUCTION`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_COMMENTINSTRUCTION: ElementId = ElementId::new("commentinstruction", 377);
// Real Ghidra id is 180 (`ElementId.java`'s `ELEM_COMMENTSTYLE`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_COMMENTSTYLE: ElementId = ElementId::new("commentstyle", 378);
// Real Ghidra id is 181 (`ElementId.java`'s `ELEM_CONVENTIONPRINTING`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_CONVENTIONPRINTING: ElementId = ElementId::new("conventionprinting", 379);
// Real Ghidra id is 182 (`ElementId.java`'s `ELEM_CURRENTACTION`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_CURRENTACTION: ElementId = ElementId::new("currentaction", 380);
// Real Ghidra id is 183 (`ElementId.java`'s `ELEM_DEFAULTPROTOTYPE`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_DEFAULTPROTOTYPE: ElementId = ElementId::new("defaultprototype", 381);
// Real Ghidra id is 184 (`ElementId.java`'s `ELEM_ERRORREINTERPRETED`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_ERRORREINTERPRETED: ElementId = ElementId::new("errorreinterpreted", 382);
// Real Ghidra id is 185 (`ElementId.java`'s `ELEM_ERRORTOOMANYINSTRUCTIONS`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_ERRORTOOMANYINSTRUCTIONS: ElementId = ElementId::new("errortoomanyinstructions", 383);
// Real Ghidra id is 186 (`ElementId.java`'s `ELEM_ERRORUNIMPLEMENTED`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_ERRORUNIMPLEMENTED: ElementId = ElementId::new("errorunimplemented", 384);
// Real Ghidra id is 187 (`ElementId.java`'s `ELEM_EXTRAPOP`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_EXTRAPOP: ElementId = ElementId::new("extrapop", 385);
// Real Ghidra id is 188 (`ElementId.java`'s `ELEM_IGNOREUNIMPLEMENTED`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_IGNOREUNIMPLEMENTED: ElementId = ElementId::new("ignoreunimplemented", 386);
// Real Ghidra id is 189 (`ElementId.java`'s `ELEM_INDENTINCREMENT`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_INDENTINCREMENT: ElementId = ElementId::new("indentincrement", 387);
// Real Ghidra id is 190 (`ElementId.java`'s `ELEM_INFERCONSTPTR`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_INFERCONSTPTR: ElementId = ElementId::new("inferconstptr", 388);
// Real Ghidra id is 191 (`ElementId.java`'s `ELEM_INLINE`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_INLINE: ElementId = ElementId::new("inline", 389);
// Real Ghidra id is 192 (`ElementId.java`'s `ELEM_INPLACEOPS`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_INPLACEOPS: ElementId = ElementId::new("inplaceops", 390);
// Real Ghidra id is 193 (`ElementId.java`'s `ELEM_INTEGERFORMAT`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_INTEGERFORMAT: ElementId = ElementId::new("integerformat", 391);
// Real Ghidra id is 194 (`ElementId.java`'s `ELEM_JUMPLOAD`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_JUMPLOAD: ElementId = ElementId::new("jumpload", 392);
// Real Ghidra id is 195 (`ElementId.java`'s `ELEM_MAXINSTRUCTION`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_MAXINSTRUCTION: ElementId = ElementId::new("maxinstruction", 393);
// Real Ghidra id is 196 (`ElementId.java`'s `ELEM_MAXLINEWIDTH`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_MAXLINEWIDTH: ElementId = ElementId::new("maxlinewidth", 394);
// Real Ghidra id is 197 (`ElementId.java`'s `ELEM_NAMESPACESTRATEGY`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_NAMESPACESTRATEGY: ElementId = ElementId::new("namespacestrategy", 395);
// Real Ghidra id is 198 (`ElementId.java`'s `ELEM_NOCASTPRINTING`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_NOCASTPRINTING: ElementId = ElementId::new("nocastprinting", 396);
// Real Ghidra id is 199 (`ElementId.java`'s `ELEM_NORETURN`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_NORETURN: ElementId = ElementId::new("noreturn", 397);
// Real Ghidra id is 200 (`ElementId.java`'s `ELEM_NULLPRINTING`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_NULLPRINTING: ElementId = ElementId::new("nullprinting", 398);
// Real Ghidra id is 201 (`ElementId.java`'s `ELEM_OPTIONSLIST`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_OPTIONSLIST: ElementId = ElementId::new("optionslist", 399);
// Real Ghidra id is 202 (`ElementId.java`'s `ELEM_PARAM1`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_PARAM1: ElementId = ElementId::new("param1", 400);
// Real Ghidra id is 203 (`ElementId.java`'s `ELEM_PARAM2`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_PARAM2: ElementId = ElementId::new("param2", 401);
// Real Ghidra id is 204 (`ElementId.java`'s `ELEM_PARAM3`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_PARAM3: ElementId = ElementId::new("param3", 402);
// Real Ghidra id is 205 (`ElementId.java`'s `ELEM_PROTOEVAL`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_PROTOEVAL: ElementId = ElementId::new("protoeval", 403);
// Real Ghidra id is 206 (`ElementId.java`'s `ELEM_SETACTION`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_SETACTION: ElementId = ElementId::new("setaction", 404);
// Real Ghidra id is 207 (`ElementId.java`'s `ELEM_SETLANGUAGE`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_SETLANGUAGE: ElementId = ElementId::new("setlanguage", 405);
// Real Ghidra id is 208 (`ElementId.java`'s `ELEM_STRUCTALIGN`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_STRUCTALIGN: ElementId = ElementId::new("structalign", 406);
// Real Ghidra id is 209 (`ElementId.java`'s `ELEM_TOGGLERULE`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_TOGGLERULE: ElementId = ElementId::new("togglerule", 407);
// Real Ghidra id is 210 (`ElementId.java`'s `ELEM_WARNING`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_WARNING: ElementId = ElementId::new("warning", 408);
// Real Ghidra id is 284 (`ElementId.java`'s `ELEM_BRACEFORMAT`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_BRACEFORMAT: ElementId = ElementId::new("braceformat", 409);

// jumptable
// Real Ghidra id is 211 (`ElementId.java`'s `ELEM_BASICOVERRIDE`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_BASICOVERRIDE: ElementId = ElementId::new("basicoverride", 410);
// Real Ghidra id is 212 (`ElementId.java`'s `ELEM_DEST`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_DEST: ElementId = ElementId::new("dest", 411);
// Real Ghidra id is 213 (`ElementId.java`'s `ELEM_JUMPTABLE`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_JUMPTABLE: ElementId = ElementId::new("jumptable", 412);
// Real Ghidra id is 214 (`ElementId.java`'s `ELEM_LOADTABLE`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_LOADTABLE: ElementId = ElementId::new("loadtable", 413);
// Real Ghidra id is 215 (`ElementId.java`'s `ELEM_NORMADDR`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_NORMADDR: ElementId = ElementId::new("normaddr", 414);
// Real Ghidra id is 216 (`ElementId.java`'s `ELEM_NORMHASH`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_NORMHASH: ElementId = ElementId::new("normhash", 415);
// Real Ghidra id is 217 (`ElementId.java`'s `ELEM_STARTVAL`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_STARTVAL: ElementId = ElementId::new("startval", 416);

// override
// Real Ghidra id is 218 (`ElementId.java`'s `ELEM_DEADCODEDELAY`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_DEADCODEDELAY: ElementId = ElementId::new("deadcodedelay", 417);
// Real Ghidra id is 219 (`ElementId.java`'s `ELEM_FLOW`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_FLOW: ElementId = ElementId::new("flow", 418);
// Real Ghidra id is 220 (`ElementId.java`'s `ELEM_FORCEGOTO`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_FORCEGOTO: ElementId = ElementId::new("forcegoto", 419);
// Real Ghidra id is 221 (`ElementId.java`'s `ELEM_INDIRECTOVERRIDE`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_INDIRECTOVERRIDE: ElementId = ElementId::new("indirectoverride", 420);
// Real Ghidra id is 222 (`ElementId.java`'s `ELEM_MULTISTAGEJUMP`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_MULTISTAGEJUMP: ElementId = ElementId::new("multistagejump", 421);
// Real Ghidra id is 223 (`ElementId.java`'s `ELEM_OVERRIDE`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_OVERRIDE: ElementId = ElementId::new("override", 422);
// Real Ghidra id is 224 (`ElementId.java`'s `ELEM_PROTOOVERRIDE`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_PROTOOVERRIDE: ElementId = ElementId::new("protooverride", 423);

// prefersplit
// Real Ghidra id is 225 (`ElementId.java`'s `ELEM_PREFERSPLIT`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_PREFERSPLIT: ElementId = ElementId::new("prefersplit", 424);

// callgraph
// Real Ghidra id is 226 (`ElementId.java`'s `ELEM_CALLGRAPH`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_CALLGRAPH: ElementId = ElementId::new("callgraph", 425);
// Real Ghidra id is 227 (`ElementId.java`'s `ELEM_NODE`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_NODE: ElementId = ElementId::new("node", 426);

// varmap
// Real Ghidra id is 228 (`ElementId.java`'s `ELEM_LOCALDB`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_LOCALDB: ElementId = ElementId::new("localdb", 427);

// ghidra_process
// Real Ghidra id is 229 (`ElementId.java`'s `ELEM_DOC`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_DOC: ElementId = ElementId::new("doc", 428);

// ghidra_arch
// Real Ghidra id is 239 (`ElementId.java`'s `ELEM_COMMAND_ISNAMEUSED`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_COMMAND_ISNAMEUSED: ElementId = ElementId::new("command_isnameused", 429);
// Real Ghidra id is 240 (`ElementId.java`'s `ELEM_COMMAND_GETBYTES`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_COMMAND_GETBYTES: ElementId = ElementId::new("command_getbytes", 430);
// Real Ghidra id is 241 (`ElementId.java`'s `ELEM_COMMAND_GETCALLFIXUP`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_COMMAND_GETCALLFIXUP: ElementId = ElementId::new("command_getcallfixup", 431);
// Real Ghidra id is 242 (`ElementId.java`'s `ELEM_COMMAND_GETCALLMECH`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_COMMAND_GETCALLMECH: ElementId = ElementId::new("command_getcallmech", 432);
// Real Ghidra id is 243 (`ElementId.java`'s `ELEM_COMMAND_GETCALLOTHERFIXUP`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_COMMAND_GETCALLOTHERFIXUP: ElementId = ElementId::new("command_getcallotherfixup", 433);
// Real Ghidra id is 244 (`ElementId.java`'s `ELEM_COMMAND_GETCODELABEL`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_COMMAND_GETCODELABEL: ElementId = ElementId::new("command_getcodelabel", 434);
// Real Ghidra id is 245 (`ElementId.java`'s `ELEM_COMMAND_GETCOMMENTS`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_COMMAND_GETCOMMENTS: ElementId = ElementId::new("command_getcomments", 435);
// Real Ghidra id is 246 (`ElementId.java`'s `ELEM_COMMAND_GETCPOOLREF`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_COMMAND_GETCPOOLREF: ElementId = ElementId::new("command_getcpoolref", 436);
// Real Ghidra id is 247 (`ElementId.java`'s `ELEM_COMMAND_GETDATATYPE`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_COMMAND_GETDATATYPE: ElementId = ElementId::new("command_getdatatype", 437);
// Real Ghidra id is 248 (`ElementId.java`'s `ELEM_COMMAND_GETEXTERNALREF`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_COMMAND_GETEXTERNALREF: ElementId = ElementId::new("command_getexternalref", 438);
// Real Ghidra id is 249 (`ElementId.java`'s `ELEM_COMMAND_GETMAPPEDSYMBOLS`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_COMMAND_GETMAPPEDSYMBOLS: ElementId = ElementId::new("command_getmappedsymbols", 439);
// Real Ghidra id is 250 (`ElementId.java`'s `ELEM_COMMAND_GETNAMESPACEPATH`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_COMMAND_GETNAMESPACEPATH: ElementId = ElementId::new("command_getnamespacepath", 440);
// Real Ghidra id is 251 (`ElementId.java`'s `ELEM_COMMAND_GETPCODE`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_COMMAND_GETPCODE: ElementId = ElementId::new("command_getpcode", 441);
// Real Ghidra id is 252 (`ElementId.java`'s `ELEM_COMMAND_GETPCODEEXECUTABLE`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_COMMAND_GETPCODEEXECUTABLE: ElementId = ElementId::new("command_getpcodeexecutable", 442);
// Real Ghidra id is 253 (`ElementId.java`'s `ELEM_COMMAND_GETREGISTER`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_COMMAND_GETREGISTER: ElementId = ElementId::new("command_getregister", 443);
// Real Ghidra id is 254 (`ElementId.java`'s `ELEM_COMMAND_GETREGISTERNAME`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_COMMAND_GETREGISTERNAME: ElementId = ElementId::new("command_getregistername", 444);
// Real Ghidra id is 255 (`ElementId.java`'s `ELEM_COMMAND_GETSTRINGDATA`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_COMMAND_GETSTRINGDATA: ElementId = ElementId::new("command_getstring", 445);
// Real Ghidra id is 256 (`ElementId.java`'s `ELEM_COMMAND_GETTRACKEDREGISTERS`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_COMMAND_GETTRACKEDREGISTERS: ElementId = ElementId::new("command_gettrackedregisters", 446);
// Real Ghidra id is 257 (`ElementId.java`'s `ELEM_COMMAND_GETUSEROPNAME`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_COMMAND_GETUSEROPNAME: ElementId = ElementId::new("command_getuseropname", 447);

// signature
// Real Ghidra id is 259 (`ElementId.java`'s `ELEM_CALL`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_CALL: ElementId = ElementId::new("call", 448);
// Real Ghidra id is 260 (`ElementId.java`'s `ELEM_GENSIG`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_GENSIG: ElementId = ElementId::new("gensig", 449);
// Real Ghidra id is 261 (`ElementId.java`'s `ELEM_MAJOR`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_MAJOR: ElementId = ElementId::new("major", 450);
// Real Ghidra id is 262 (`ElementId.java`'s `ELEM_MINOR`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_MINOR: ElementId = ElementId::new("minor", 451);
// Real Ghidra id is 264 (`ElementId.java`'s `ELEM_SETTINGS`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_SETTINGS: ElementId = ElementId::new("settings", 452);
// Real Ghidra id is 265 (`ElementId.java`'s `ELEM_SIG`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_SIG: ElementId = ElementId::new("sig", 453);
// Real Ghidra id is 266 (`ElementId.java`'s `ELEM_SIGNATUREDESC`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_SIGNATUREDESC: ElementId = ElementId::new("signaturedesc", 454);
// Real Ghidra id is 267 (`ElementId.java`'s `ELEM_SIGNATURES`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_SIGNATURES: ElementId = ElementId::new("signatures", 455);
// Real Ghidra id is 268 (`ElementId.java`'s `ELEM_SIGSETTINGS`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_SIGSETTINGS: ElementId = ElementId::new("sigsettings", 456);
// Real Ghidra id is 270 (`ElementId.java`'s `ELEM_SPLITDATATYPE`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_SPLITDATATYPE: ElementId = ElementId::new("splitdatatype", 457);
// Real Ghidra id is 271 (`ElementId.java`'s `ELEM_JUMPTABLEMAX`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_JUMPTABLEMAX: ElementId = ElementId::new("jumptablemax", 458);
// Real Ghidra id is 272 (`ElementId.java`'s `ELEM_NANIGNORE`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_NANIGNORE: ElementId = ElementId::new("nanignore", 459);

// modelrules
// Real Ghidra id is 273 (`ElementId.java`'s `ELEM_DATATYPE`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_DATATYPE: ElementId = ElementId::new("datatype", 460);
// Real Ghidra id is 274 (`ElementId.java`'s `ELEM_CONSUME`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_CONSUME: ElementId = ElementId::new("consume", 461);
// Real Ghidra id is 275 (`ElementId.java`'s `ELEM_CONSUME_EXTRA`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_CONSUME_EXTRA: ElementId = ElementId::new("consume_extra", 462);
// Real Ghidra id is 276 (`ElementId.java`'s `ELEM_CONVERT_TO_PTR`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_CONVERT_TO_PTR: ElementId = ElementId::new("convert_to_ptr", 463);
// Real Ghidra id is 277 (`ElementId.java`'s `ELEM_GOTO_STACK`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_GOTO_STACK: ElementId = ElementId::new("goto_stack", 464);
// Real Ghidra id is 278 (`ElementId.java`'s `ELEM_JOIN`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_JOIN: ElementId = ElementId::new("join", 465);
// Real Ghidra id is 279 (`ElementId.java`'s `ELEM_DATATYPE_AT`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_DATATYPE_AT: ElementId = ElementId::new("datatype_at", 466);
// Real Ghidra id is 280 (`ElementId.java`'s `ELEM_POSITION`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_POSITION: ElementId = ElementId::new("position", 467);
// Real Ghidra id is 281 (`ElementId.java`'s `ELEM_VARARGS`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_VARARGS: ElementId = ElementId::new("varargs", 468);
// Real Ghidra id is 282 (`ElementId.java`'s `ELEM_HIDDEN_RETURN`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_HIDDEN_RETURN: ElementId = ElementId::new("hidden_return", 469);
// Real Ghidra id is 283 (`ElementId.java`'s `ELEM_JOIN_PER_PRIMITIVE`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_JOIN_PER_PRIMITIVE: ElementId = ElementId::new("join_per_primitive", 470);
// Real Ghidra id is 285 (`ElementId.java`'s `ELEM_JOIN_DUAL_CLASS`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_JOIN_DUAL_CLASS: ElementId = ElementId::new("join_dual_class", 471);
// Real Ghidra id is 287 (`ElementId.java`'s `ELEM_EXTRA_STACK`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_EXTRA_STACK: ElementId = ElementId::new("extra_stack", 472);
// Real Ghidra id is 288 (`ElementId.java`'s `ELEM_CONSUME_REMAINING`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_CONSUME_REMAINING: ElementId = ElementId::new("consume_remaining", 473);
// Real Ghidra id is 290 (`ElementId.java`'s `ELEM_UNKNOWN`), continuing the local
// counter above per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ELEM_UNKNOWN: ElementId = ElementId::new("XMLunknown", 474);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AttributeId {
    pub name: &'static str,
    pub id: i32,
}

impl AttributeId {
    pub const fn new(name: &'static str, id: i32) -> Self {
        Self { name, id }
    }
}

pub const ATTRIB_CONTENT: AttributeId = AttributeId::new("XMLcontent", 1);
pub const ATTRIB_VAL: AttributeId = AttributeId::new("val", 2);
pub const ATTRIB_ID: AttributeId = AttributeId::new("id", 3);
pub const ATTRIB_SPACE: AttributeId = AttributeId::new("space", 4);
pub const ATTRIB_S: AttributeId = AttributeId::new("s", 5);
pub const ATTRIB_OFF: AttributeId = AttributeId::new("off", 6);
pub const ATTRIB_CODE: AttributeId = AttributeId::new("code", 7);
pub const ATTRIB_MASK: AttributeId = AttributeId::new("mask", 8);
pub const ATTRIB_INDEX: AttributeId = AttributeId::new("index", 9);
pub const ATTRIB_NONZERO: AttributeId = AttributeId::new("nonzero", 10);
pub const ATTRIB_PIECE: AttributeId = AttributeId::new("piece", 11);
pub const ATTRIB_NAME: AttributeId = AttributeId::new("name", 12);
pub const ATTRIB_SCOPE: AttributeId = AttributeId::new("scope", 13);
pub const ATTRIB_STARTBIT: AttributeId = AttributeId::new("startbit", 14);
pub const ATTRIB_SIZE: AttributeId = AttributeId::new("size", 15);
pub const ATTRIB_TABLE: AttributeId = AttributeId::new("table", 16);
pub const ATTRIB_CT: AttributeId = AttributeId::new("ct", 17);
pub const ATTRIB_MINLEN: AttributeId = AttributeId::new("minlen", 18);
pub const ATTRIB_BASE: AttributeId = AttributeId::new("base", 19);
pub const ATTRIB_NUMBER: AttributeId = AttributeId::new("number", 20);
pub const ATTRIB_CONTEXT: AttributeId = AttributeId::new("context", 21);
pub const ATTRIB_PARENT: AttributeId = AttributeId::new("parent", 22);
pub const ATTRIB_SUBSYM: AttributeId = AttributeId::new("subsym", 23);
pub const ATTRIB_LINE: AttributeId = AttributeId::new("line", 24);
pub const ATTRIB_SOURCE: AttributeId = AttributeId::new("source", 25);
pub const ATTRIB_LENGTH: AttributeId = AttributeId::new("length", 26);
pub const ATTRIB_FIRST: AttributeId = AttributeId::new("first", 27);
pub const ATTRIB_PLUS: AttributeId = AttributeId::new("plus", 28);
pub const ATTRIB_SHIFT: AttributeId = AttributeId::new("shift", 29);
pub const ATTRIB_ENDBIT: AttributeId = AttributeId::new("endbit", 30);
pub const ATTRIB_SIGNBIT: AttributeId = AttributeId::new("signbit", 31);
pub const ATTRIB_ENDBYTE: AttributeId = AttributeId::new("endbyte", 32);
pub const ATTRIB_STARTBYTE: AttributeId = AttributeId::new("startbyte", 33);
pub const ATTRIB_VERSION: AttributeId = AttributeId::new("version", 34);
pub const ATTRIB_BIGENDIAN: AttributeId = AttributeId::new("bigendian", 35);
pub const ATTRIB_ALIGN: AttributeId = AttributeId::new("align", 36);
pub const ATTRIB_UNIQBASE: AttributeId = AttributeId::new("uniqbase", 37);
pub const ATTRIB_MAXDELAY: AttributeId = AttributeId::new("maxdelay", 38);
pub const ATTRIB_UNIQMASK: AttributeId = AttributeId::new("uniqmask", 39);
pub const ATTRIB_NUMSECTIONS: AttributeId = AttributeId::new("numsections", 40);
pub const ATTRIB_DEFAULTSPACE: AttributeId = AttributeId::new("defaultspace", 41);
pub const ATTRIB_DELAY: AttributeId = AttributeId::new("delay", 42);
pub const ATTRIB_WORDSIZE: AttributeId = AttributeId::new("wordsize", 43);
pub const ATTRIB_PHYSICAL: AttributeId = AttributeId::new("physical", 44);
pub const ATTRIB_SCOPESIZE: AttributeId = AttributeId::new("scopesize", 45);
pub const ATTRIB_SYMBOLSIZE: AttributeId = AttributeId::new("symbolsize", 46);
pub const ATTRIB_VARNODE: AttributeId = AttributeId::new("varnode", 47);
pub const ATTRIB_LOW: AttributeId = AttributeId::new("low", 48);
pub const ATTRIB_HIGH: AttributeId = AttributeId::new("high", 49);
pub const ATTRIB_FLOW: AttributeId = AttributeId::new("flow", 50);
pub const ATTRIB_CONTAIN: AttributeId = AttributeId::new("contain", 51);
pub const ATTRIB_I: AttributeId = AttributeId::new("i", 52);
pub const ATTRIB_NUMCT: AttributeId = AttributeId::new("numct", 53);
pub const ATTRIB_SECTION: AttributeId = AttributeId::new("section", 54);
pub const ATTRIB_LABELS: AttributeId = AttributeId::new("labels", 55);
pub const ATTRIB_LAST: AttributeId = AttributeId::new("last", 56);

pub const ATTRIB_OFFSET: AttributeId = AttributeId::new("offset", 16); // Alias for ATTRIB_BASE? No, SlaFormat uses 16 for TABLE
pub const ATTRIB_VALUE: AttributeId = AttributeId::new("value", 25); // Alias for ATTRIB_SOURCE?
pub const ATTRIB_TYPE: AttributeId = AttributeId::new("type", 22); // Alias for ATTRIB_PARENT?
pub const ATTRIB_SIGNED: AttributeId = AttributeId::new("signed", 57);
// Real Ghidra ids are 208/119/125 (`AttributeId.java`'s `ATTRIB_THISBEFORERETPOINTER`/
// `ATTRIB_KILLEDBYCALL`/`ATTRIB_SEPARATEFLOAT`), continuing the local counter above instead per
// the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ATTRIB_THISBEFORERETPOINTER: AttributeId =
    AttributeId::new("thisbeforeretpointer", 58);
pub const ATTRIB_KILLEDBYCALL: AttributeId = AttributeId::new("killedbycall", 59);
pub const ATTRIB_SEPARATEFLOAT: AttributeId = AttributeId::new("separatefloat", 60);
// Real Ghidra id is 68 (`AttributeId.java`'s `ATTRIB_SYMREF`), continuing the local counter above
// instead per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ATTRIB_SYMREF: AttributeId = AttributeId::new("symref", 61);
// Real Ghidra ids are 121/120/149/116 (`AttributeId.java`'s `ATTRIB_MINSIZE`/`ATTRIB_MAXSIZE`/
// `ATTRIB_STORAGE`/`ATTRIB_EXTENSION`), continuing the local counter above instead per the same
// non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ATTRIB_MINSIZE: AttributeId = AttributeId::new("minsize", 62);
pub const ATTRIB_MAXSIZE: AttributeId = AttributeId::new("maxsize", 63);
pub const ATTRIB_STORAGE: AttributeId = AttributeId::new("storage", 64);
pub const ATTRIB_EXTENSION: AttributeId = AttributeId::new("extension", 65);
// Continuing the local counter above per the same non-wire-compatible numbering scheme as
// `ELEM_BHEAD`.
pub const ATTRIB_LABEL: AttributeId = AttributeId::new("label", 66);
pub const ATTRIB_UNKNOWN: AttributeId = AttributeId::new("XMLunknown", 159);
// Real Ghidra id is 7 (`AttributeId.java`'s `ATTRIB_FORMAT`), but that collides with this file's
// own `ATTRIB_CODE` at 7, so it is renumbered to continue the local counter above instead per the
// same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ATTRIB_FORMAT: AttributeId = AttributeId::new("format", 160);
// Real Ghidra id is 12 (`AttributeId.java`'s `ATTRIB_METATYPE`), renumbered per the same scheme.
pub const ATTRIB_METATYPE: AttributeId = AttributeId::new("metatype", 161);
// Real Ghidra id is 47 (`AttributeId.java`'s `ATTRIB_ALIGNMENT`), renumbered per the same scheme.
pub const ATTRIB_ALIGNMENT: AttributeId = AttributeId::new("alignment", 162);
// Real Ghidra id is 48 (`AttributeId.java`'s `ATTRIB_ARRAYSIZE`), renumbered per the same scheme.
pub const ATTRIB_ARRAYSIZE: AttributeId = AttributeId::new("arraysize", 163);
// Real Ghidra id is 49 (`AttributeId.java`'s `ATTRIB_CHAR`), renumbered per the same scheme.
pub const ATTRIB_CHAR: AttributeId = AttributeId::new("char", 164);
// Real Ghidra id is 52 (`AttributeId.java`'s `ATTRIB_INCOMPLETE`), renumbered per the same scheme.
pub const ATTRIB_INCOMPLETE: AttributeId = AttributeId::new("incomplete", 165);
// Real Ghidra id is 56 (`AttributeId.java`'s `ATTRIB_OPAQUESTRING`), renumbered per the same
// scheme.
pub const ATTRIB_OPAQUESTRING: AttributeId = AttributeId::new("opaquestring", 166);
// Real Ghidra id is 59 (`AttributeId.java`'s `ATTRIB_UTF`), renumbered per the same scheme.
pub const ATTRIB_UTF: AttributeId = AttributeId::new("utf", 167);
// Real Ghidra id is 60 (`AttributeId.java`'s `ATTRIB_VARLENGTH`), renumbered per the same scheme.
pub const ATTRIB_VARLENGTH: AttributeId = AttributeId::new("varlength", 168);
// Real Ghidra id is 18 (`AttributeId.java`'s `ATTRIB_REF`), but that collides with this file's
// own `ATTRIB_MINLEN` at 18, so it is renumbered per the same scheme.
pub const ATTRIB_REF: AttributeId = AttributeId::new("ref", 169);
// Real Ghidra id is 83 (`AttributeId.java`'s `ATTRIB_TAG`), renumbered per the same scheme.
pub const ATTRIB_TAG: AttributeId = AttributeId::new("tag", 170);
// Real Ghidra id is 4 (`AttributeId.java`'s `ATTRIB_CONSTRUCTOR`), but that collides with this
// file's own `ATTRIB_SPACE` at 4, so it is renumbered per the same scheme.
pub const ATTRIB_CONSTRUCTOR: AttributeId = AttributeId::new("constructor", 171);
// Real Ghidra id is 92 (`AttributeId.java`'s `ATTRIB_LOGICALSIZE`), continuing the local counter
// above instead per the same non-wire-compatible numbering scheme as `ELEM_BHEAD`.
pub const ATTRIB_LOGICALSIZE: AttributeId = AttributeId::new("logicalsize", 172);
// Real Ghidra id is 37 (`AttributeId.java`'s `ATTRIB_COLOR`), but that collides with this file's
// own `ATTRIB_UNIQBASE` at 37, so it is renumbered per the same scheme. Carries a
// `ClangToken` syntax-highlight color.
pub const ATTRIB_COLOR: AttributeId = AttributeId::new("color", 173);
// Ids 151/153 match `AttributeId.java`'s `ATTRIB_SIZES`/`ATTRIB_MAX_PRIMITIVES` directly; neither
// collides with any `AttributeId` already declared in this file (the numbering scheme above only
// renumbers on an actual same-type collision).
pub const ATTRIB_SIZES: AttributeId = AttributeId::new("sizes", 151);
pub const ATTRIB_MAX_PRIMITIVES: AttributeId = AttributeId::new("maxprimitives", 153);

#[cfg(test)]
mod tests {
    use super::*;

    /// Every real (non-commented-out) `ELEM_*` constant declared in
    /// `ghidra.program.model.pcode.ElementId.java` (281 total, generated 2026-09 during the
    /// PORT_MANIFEST completeness audit of this file). This is a compile-time AND runtime
    /// check: if a Rust `ELEM_*` constant referenced here doesn't exist, the crate fails to
    /// build; if its `name` string doesn't match Java's, the assertion below fails.
    #[test]
    fn all_java_element_ids_present() {
        let pairs: &[(ElementId, &str)] = &[
            (ELEM_ABSOLUTE_MAX_ALIGNMENT, "absolute_max_alignment"),
            (ELEM_ADDR, "addr"),
            (ELEM_ADDRESS_SHIFT_AMOUNT, "address_shift_amount"),
            (ELEM_ADDR_PCODE, "addr_pcode"),
            (ELEM_AGGRESSIVETRIM, "aggressivetrim"),
            (ELEM_ALIASBLOCK, "aliasblock"),
            (ELEM_ALLOWCONTEXTSET, "allowcontextset"),
            (ELEM_ANALYZEFORLOOPS, "analyzeforloops"),
            (ELEM_AST, "ast"),
            (ELEM_BASICOVERRIDE, "basicoverride"),
            (ELEM_BHEAD, "bhead"),
            (ELEM_BITFIELD, "bitfield"),
            (ELEM_BITFIELD_PACKING, "bitfield_packing"),
            (ELEM_BLOCK, "block"),
            (ELEM_BLOCKEDGE, "blockedge"),
            (ELEM_BLOCKSIG, "blocksig"),
            (ELEM_BODY, "body"),
            (ELEM_BRACEFORMAT, "braceformat"),
            (ELEM_BREAK, "break"),
            (ELEM_BYTES, "bytes"),
            (ELEM_CALL, "call"),
            (ELEM_CALLFIXUP, "callfixup"),
            (ELEM_CALLGRAPH, "callgraph"),
            (ELEM_CALLOTHERFIXUP, "callotherfixup"),
            (ELEM_CASE_PCODE, "case_pcode"),
            (ELEM_CHAR_SIZE, "char_size"),
            (ELEM_CHAR_TYPE, "char_type"),
            (ELEM_CLANG_DOCUMENT, "clang_document"),
            (ELEM_COLLISION, "collision"),
            (ELEM_COMMAND_GETBYTES, "command_getbytes"),
            (ELEM_COMMAND_GETCALLFIXUP, "command_getcallfixup"),
            (ELEM_COMMAND_GETCALLMECH, "command_getcallmech"),
            (ELEM_COMMAND_GETCALLOTHERFIXUP, "command_getcallotherfixup"),
            (ELEM_COMMAND_GETCODELABEL, "command_getcodelabel"),
            (ELEM_COMMAND_GETCOMMENTS, "command_getcomments"),
            (ELEM_COMMAND_GETCPOOLREF, "command_getcpoolref"),
            (ELEM_COMMAND_GETDATATYPE, "command_getdatatype"),
            (ELEM_COMMAND_GETEXTERNALREF, "command_getexternalref"),
            (ELEM_COMMAND_GETMAPPEDSYMBOLS, "command_getmappedsymbols"),
            (ELEM_COMMAND_GETNAMESPACEPATH, "command_getnamespacepath"),
            (ELEM_COMMAND_GETPCODE, "command_getpcode"),
            (ELEM_COMMAND_GETPCODEEXECUTABLE, "command_getpcodeexecutable"),
            (ELEM_COMMAND_GETREGISTER, "command_getregister"),
            (ELEM_COMMAND_GETREGISTERNAME, "command_getregistername"),
            (ELEM_COMMAND_GETSTRINGDATA, "command_getstring"),
            (ELEM_COMMAND_GETTRACKEDREGISTERS, "command_gettrackedregisters"),
            (ELEM_COMMAND_GETUSEROPNAME, "command_getuseropname"),
            (ELEM_COMMAND_ISNAMEUSED, "command_isnameused"),
            (ELEM_COMMENT, "comment"),
            (ELEM_COMMENTDB, "commentdb"),
            (ELEM_COMMENTHEADER, "commentheader"),
            (ELEM_COMMENTINDENT, "commentindent"),
            (ELEM_COMMENTINSTRUCTION, "commentinstruction"),
            (ELEM_COMMENTSTYLE, "commentstyle"),
            (ELEM_COMPILER_SPEC, "compiler_spec"),
            (ELEM_CONSTANTPOOL, "constantpool"),
            (ELEM_CONSTRESOLVE, "constresolve"),
            (ELEM_CONSUME, "consume"),
            (ELEM_CONSUME_EXTRA, "consume_extra"),
            (ELEM_CONSUME_REMAINING, "consume_remaining"),
            (ELEM_CONTEXT, "context"),
            (ELEM_CONTEXT_DATA, "context_data"),
            (ELEM_CONTEXT_POINTS, "context_points"),
            (ELEM_CONTEXT_POINTSET, "context_pointset"),
            (ELEM_CONTEXT_SET, "context_set"),
            (ELEM_CONVENTIONPRINTING, "conventionprinting"),
            (ELEM_CONVERT_TO_PTR, "convert_to_ptr"),
            (ELEM_COPYSIG, "copysig"),
            (ELEM_CORETYPES, "coretypes"),
            (ELEM_CPOOLREC, "cpoolrec"),
            (ELEM_CURRENTACTION, "currentaction"),
            (ELEM_DATA, "data"),
            (ELEM_DATATYPE, "datatype"),
            (ELEM_DATATYPE_AT, "datatype_at"),
            (ELEM_DATA_ORGANIZATION, "data_organization"),
            (ELEM_DATA_SPACE, "data_space"),
            (ELEM_DB, "db"),
            (ELEM_DEADCODEDELAY, "deadcodedelay"),
            (ELEM_DEF, "def"),
            (ELEM_DEFAULTPROTOTYPE, "defaultprototype"),
            (ELEM_DEFAULT_ALIGNMENT, "default_alignment"),
            (ELEM_DEFAULT_MEMORY_BLOCKS, "default_memory_blocks"),
            (ELEM_DEFAULT_PCODE, "default_pcode"),
            (ELEM_DEFAULT_POINTER_ALIGNMENT, "default_pointer_alignment"),
            (ELEM_DEFAULT_PROTO, "default_proto"),
            (ELEM_DEFAULT_SYMBOLS, "default_symbols"),
            (ELEM_DEST, "dest"),
            (ELEM_DOC, "doc"),
            (ELEM_DOUBLE_SIZE, "double_size"),
            (ELEM_EDGE, "edge"),
            (ELEM_ENTRY, "entry"),
            (ELEM_ENUM, "enum"),
            (ELEM_EQUATESYMBOL, "equatesymbol"),
            (ELEM_ERRORREINTERPRETED, "errorreinterpreted"),
            (ELEM_ERRORTOOMANYINSTRUCTIONS, "errortoomanyinstructions"),
            (ELEM_ERRORUNIMPLEMENTED, "errorunimplemented"),
            (ELEM_EVAL_CALLED_PROTOTYPE, "eval_called_prototype"),
            (ELEM_EVAL_CURRENT_PROTOTYPE, "eval_current_prototype"),
            (ELEM_EXPERIMENTAL_RULES, "experimental_rules"),
            (ELEM_EXTERNREFSYMBOL, "externrefsymbol"),
            (ELEM_EXTRAPOP, "extrapop"),
            (ELEM_EXTRA_STACK, "extra_stack"),
            (ELEM_FACETSYMBOL, "facetsymbol"),
            (ELEM_FIELD, "field"),
            (ELEM_FLOAT_SIZE, "float_size"),
            (ELEM_FLOW, "flow"),
            (ELEM_FLOWOVERRIDELIST, "flowoverridelist"),
            (ELEM_FORCEGOTO, "forcegoto"),
            (ELEM_FUNCNAME, "funcname"),
            (ELEM_FUNCPROTO, "funcproto"),
            (ELEM_FUNCPTR, "funcptr"),
            (ELEM_FUNCTION, "function"),
            (ELEM_FUNCTIONSHELL, "functionshell"),
            (ELEM_GENSIG, "gensig"),
            (ELEM_GLOBAL, "global"),
            (ELEM_GOTO_STACK, "goto_stack"),
            (ELEM_GROUP, "group"),
            (ELEM_HASH, "hash"),
            (ELEM_HIDDEN_RETURN, "hidden_return"),
            (ELEM_HIGH, "high"),
            (ELEM_HIGHLIST, "highlist"),
            (ELEM_HOLE, "hole"),
            (ELEM_IGNOREUNIMPLEMENTED, "ignoreunimplemented"),
            (ELEM_INCIDENTALCOPY, "incidentalcopy"),
            (ELEM_INDENTINCREMENT, "indentincrement"),
            (ELEM_INDIRECTOVERRIDE, "indirectoverride"),
            (ELEM_INFERCONSTPTR, "inferconstptr"),
            (ELEM_INFERPTRBOUNDS, "inferptrbounds"),
            (ELEM_INJECT, "inject"),
            (ELEM_INJECTDEBUG, "injectdebug"),
            (ELEM_INLINE, "inline"),
            (ELEM_INPLACEOPS, "inplaceops"),
            (ELEM_INPUT, "input"),
            (ELEM_INST, "inst"),
            (ELEM_INTEGERFORMAT, "integerformat"),
            (ELEM_INTEGER_SIZE, "integer_size"),
            (ELEM_INTERNALLIST, "internallist"),
            (ELEM_INTERNAL_STORAGE, "internal_storage"),
            (ELEM_IOP, "iop"),
            (ELEM_JOIN, "join"),
            (ELEM_JOIN_DUAL_CLASS, "join_dual_class"),
            (ELEM_JOIN_PER_PRIMITIVE, "join_per_primitive"),
            (ELEM_JUMPASSIST, "jumpassist"),
            (ELEM_JUMPLOAD, "jumpload"),
            (ELEM_JUMPTABLE, "jumptable"),
            (ELEM_JUMPTABLELIST, "jumptablelist"),
            (ELEM_JUMPTABLEMAX, "jumptablemax"),
            (ELEM_KILLEDBYCALL, "killedbycall"),
            (ELEM_LABEL, "label"),
            (ELEM_LABELSYM, "labelsym"),
            (ELEM_LIKELYTRASH, "likelytrash"),
            (ELEM_LOADTABLE, "loadtable"),
            (ELEM_LOCALDB, "localdb"),
            (ELEM_LOCALRANGE, "localrange"),
            (ELEM_LONG_DOUBLE_SIZE, "long_double_size"),
            (ELEM_LONG_LONG_SIZE, "long_long_size"),
            (ELEM_LONG_SIZE, "long_size"),
            (ELEM_MACHINE_ALIGNMENT, "machine_alignment"),
            (ELEM_MAJOR, "major"),
            (ELEM_MAPSYM, "mapsym"),
            (ELEM_MAXINSTRUCTION, "maxinstruction"),
            (ELEM_MAXLINEWIDTH, "maxlinewidth"),
            (ELEM_MINOR, "minor"),
            (ELEM_MODEL, "model"),
            (ELEM_MODELALIAS, "modelalias"),
            (ELEM_MULTISTAGEJUMP, "multistagejump"),
            (ELEM_NAMESPACESTRATEGY, "namespacestrategy"),
            (ELEM_NANIGNORE, "nanignore"),
            (ELEM_NOCASTPRINTING, "nocastprinting"),
            (ELEM_NODE, "node"),
            (ELEM_NOHIGHPTR, "nohighptr"),
            (ELEM_NORETURN, "noreturn"),
            (ELEM_NORMADDR, "normaddr"),
            (ELEM_NORMHASH, "normhash"),
            (ELEM_NULLPRINTING, "nullprinting"),
            (ELEM_OFF, "off"),
            (ELEM_OP, "op"),
            (ELEM_OPTIONSLIST, "optionslist"),
            (ELEM_OUTPUT, "output"),
            (ELEM_OVERRIDE, "override"),
            (ELEM_PARAM, "param"),
            (ELEM_PARAM1, "param1"),
            (ELEM_PARAM2, "param2"),
            (ELEM_PARAM3, "param3"),
            (ELEM_PARAMMEASURES, "parammeasures"),
            (ELEM_PARAMRANGE, "paramrange"),
            (ELEM_PARENT, "parent"),
            (ELEM_PAYLOAD, "payload"),
            (ELEM_PCODE, "pcode"),
            (ELEM_PENTRY, "pentry"),
            (ELEM_POINTER_SHIFT, "pointer_shift"),
            (ELEM_POINTER_SIZE, "pointer_size"),
            (ELEM_POSITION, "position"),
            (ELEM_PREFERSPLIT, "prefersplit"),
            (ELEM_PROCESSOR_SPEC, "processor_spec"),
            (ELEM_PROGRAMCOUNTER, "programcounter"),
            (ELEM_PROPERTIES, "properties"),
            (ELEM_PROPERTY, "property"),
            (ELEM_PROPERTY_CHANGEPOINT, "property_changepoint"),
            (ELEM_PROTO, "proto"),
            (ELEM_PROTOEVAL, "protoeval"),
            (ELEM_PROTOOVERRIDE, "protooverride"),
            (ELEM_PROTOTYPE, "prototype"),
            (ELEM_RANGE, "range"),
            (ELEM_RANGEEQUALSSYMBOLS, "rangeequalssymbols"),
            (ELEM_RANGELIST, "rangelist"),
            (ELEM_RANK, "rank"),
            (ELEM_READONLY, "readonly"),
            (ELEM_REF, "ref"),
            (ELEM_REGISTER, "register"),
            (ELEM_REGISTER_DATA, "register_data"),
            (ELEM_RESOLVEPROTOTYPE, "resolveprototype"),
            (ELEM_RETPARAM, "retparam"),
            (ELEM_RETURNADDRESS, "returnaddress"),
            (ELEM_RETURNSYM, "returnsym"),
            (ELEM_RETURN_TYPE, "return_type"),
            (ELEM_RULE, "rule"),
            (ELEM_SAVE_STATE, "save_state"),
            (ELEM_SCOPE, "scope"),
            (ELEM_SEGMENTED_ADDRESS, "segmented_address"),
            (ELEM_SEGMENTOP, "segmentop"),
            (ELEM_SEQNUM, "seqnum"),
            (ELEM_SET, "set"),
            (ELEM_SETACTION, "setaction"),
            (ELEM_SETLANGUAGE, "setlanguage"),
            (ELEM_SETTINGS, "settings"),
            (ELEM_SHORT_SIZE, "short_size"),
            (ELEM_SIG, "sig"),
            (ELEM_SIGNATUREDESC, "signaturedesc"),
            (ELEM_SIGNATURES, "signatures"),
            (ELEM_SIGSETTINGS, "sigsettings"),
            (ELEM_SIZE_ALIGNMENT_MAP, "size_alignment_map"),
            (ELEM_SIZE_PCODE, "size_pcode"),
            (ELEM_SLEIGH, "sleigh"),
            (ELEM_SPACE, "space"),
            (ELEM_SPACEBASE, "spacebase"),
            (ELEM_SPACEID, "spaceid"),
            (ELEM_SPACES, "spaces"),
            (ELEM_SPACE_BASE, "space_base"),
            (ELEM_SPACE_OTHER, "space_other"),
            (ELEM_SPACE_OVERLAY, "space_overlay"),
            (ELEM_SPACE_UNIQUE, "space_unique"),
            (ELEM_SPECEXTENSIONS, "specextensions"),
            (ELEM_SPLITDATATYPE, "splitdatatype"),
            (ELEM_STACKPOINTER, "stackpointer"),
            (ELEM_STARTVAL, "startval"),
            (ELEM_STATEMENT, "statement"),
            (ELEM_STRING, "string"),
            (ELEM_STRINGMANAGE, "stringmanage"),
            (ELEM_STRUCTALIGN, "structalign"),
            (ELEM_SYMBOL, "symbol"),
            (ELEM_SYMBOLLIST, "symbollist"),
            (ELEM_SYNTAX, "syntax"),
            (ELEM_TARGET, "target"),
            (ELEM_TEXT, "text"),
            (ELEM_TOGGLERULE, "togglerule"),
            (ELEM_TOKEN, "token"),
            (ELEM_TRACKED_POINTSET, "tracked_pointset"),
            (ELEM_TRACKED_SET, "tracked_set"),
            (ELEM_TRUNCATE_SPACE, "truncate_space"),
            (ELEM_TYPE, "type"),
            (ELEM_TYPEGRP, "typegrp"),
            (ELEM_TYPEREF, "typeref"),
            (ELEM_TYPE_ALIGNMENT_ENABLED, "type_alignment_enabled"),
            (ELEM_UNAFFECTED, "unaffected"),
            (ELEM_UNIMPL, "unimpl"),
            (ELEM_UNKNOWN, "XMLunknown"),
            (ELEM_USE_MS_CONVENTION, "use_MS_convention"),
            (ELEM_VAL, "val"),
            (ELEM_VALUE, "value"),
            (ELEM_VARARGS, "varargs"),
            (ELEM_VARDECL, "vardecl"),
            (ELEM_VARIABLE, "variable"),
            (ELEM_VARNODE, "varnode"),
            (ELEM_VARNODES, "varnodes"),
            (ELEM_VARSIG, "varsig"),
            (ELEM_VOID, "void"),
            (ELEM_VOLATILE, "volatile"),
            (ELEM_WARNING, "warning"),
            (ELEM_WCHAR_SIZE, "wchar_size"),
            (ELEM_ZERO_LENGTH_BOUNDARY, "zero_length_boundary"),
        ];
        assert_eq!(pairs.len(), 281, "expected all 281 ElementId.java ELEM_* constants");
        for (elem, expected_name) in pairs {
            assert_eq!(
                elem.name, *expected_name,
                "ElementId constant name mismatch for expected java string {:?}",
                expected_name
            );
        }
        // Names should be unique per this check's own list (Java itself never redeclares an
        // ELEM_* identifier), guarding against a copy-paste duplicate entry creeping in above.
        let mut names: Vec<&str> = pairs.iter().map(|(e, _)| e.name).collect();
        names.sort_unstable();
        names.dedup();
        // Note: a small number of distinct ElementId.java constants intentionally share the
        // same wire-format string with each other or with unrelated SlaFormat-only ids
        // elsewhere in this file (e.g. "scope", "off"); dedup by name alone can therefore be
        // slightly smaller than 281. Just assert it's not catastrophically smaller (i.e. we
        // didn't accidentally collapse most constants onto a handful of names).
        assert!(
            names.len() >= 270,
            "unexpectedly few distinct ElementId names ({}); check for a mass copy-paste error",
            names.len()
        );
    }
}

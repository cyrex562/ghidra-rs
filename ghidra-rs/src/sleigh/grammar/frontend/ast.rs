//! AST types for the top-level SLEIGH grammar (`SleighParser.g`).
//!
//! The ANTLR grammar builds a homogeneous `CommonTree` of `OP_*` nodes; this
//! port uses typed Rust structures instead. Node names map to the grammar
//! rules that produce them (noted per item).
//!
//! Display sections are structured printpieces ([`DisplaySection`] /
//! [`PrintPiece`]), mirroring `DisplayParser.g`. Semantic bodies are typed
//! p-code statement lists ([`SemanticBody`] / [`PcodeStmt`] / [`PcodeExpr`]),
//! mirroring `SemanticParser.g`.

use crate::sleigh::grammar::Location;

/// `endian` rule: `big` / `little`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endian {
    Big,
    Little,
}

/// Root of a parsed `.slaspec`: `spec : endiandef (definition | constructorlike)* EOF`.
#[derive(Debug, Clone)]
pub struct Spec {
    pub endian: EndianDef,
    pub items: Vec<SpecItem>,
}

/// `endiandef : define endian = <endian> ;`
#[derive(Debug, Clone)]
pub struct EndianDef {
    pub endian: Endian,
    pub location: Option<Location>,
}

/// One top-level item after the endian definition.
#[derive(Debug, Clone)]
pub enum SpecItem {
    Definition(Definition),
    Constructorlike(Constructorlike),
}

/// `definition` rule alternatives.
#[derive(Debug, Clone)]
pub enum Definition {
    /// `aligndef : define alignment = <int> ;`
    Align(AlignDef),
    /// `tokendef : define token <id> ( <int> ) [endian = <e>] fielddefs ;`
    Token(TokenDef),
    /// `contextdef : define context <id> contextfielddefs ;`
    Context(ContextDef),
    /// `spacedef : define space <id> spacemods ;`
    Space(SpaceDef),
    /// `varnodedef : define <space> offset = <int> size = <int> idlist ;`
    Varnode(VarnodeDef),
    /// `bitrangedef : define bitrange bitrange+ ;`
    Bitrange(BitrangeDef),
    /// `pcodeopdef : define pcodeop idlist ;`
    PcodeOp(PcodeOpDef),
    /// `valueattach : attach values idlist intblist ;`
    ValueAttach(ValueAttach),
    /// `nameattach : attach names idlist stringoridentlist ;`
    NameAttach(NameAttach),
    /// `varattach : attach variables idlist idlist ;`
    VarAttach(VarAttach),
}

#[derive(Debug, Clone)]
pub struct AlignDef {
    pub alignment: Integer,
    pub location: Option<Location>,
}

#[derive(Debug, Clone)]
pub struct TokenDef {
    pub name: String,
    pub size: Integer,
    /// Set for the `define token ... endian = <e>` form (`OP_TOKEN_ENDIAN`).
    pub endian: Option<Endian>,
    pub fields: Vec<FieldDef>,
    pub location: Option<Location>,
}

/// `fielddef` / `contextfielddef`: `<name> = ( <start> , <end> ) mods*`.
#[derive(Debug, Clone)]
pub struct FieldDef {
    pub name: String,
    pub start: Integer,
    pub end: Integer,
    pub mods: Vec<FieldMod>,
    pub location: Option<Location>,
}

/// `fieldmod` / `contextfieldmod` (`noflow` is context-only; the parser
/// enforces that, not the type).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldMod {
    Signed,
    Noflow,
    Hex,
    Dec,
}

#[derive(Debug, Clone)]
pub struct ContextDef {
    pub varnode: String,
    pub fields: Vec<FieldDef>,
    pub location: Option<Location>,
}

#[derive(Debug, Clone)]
pub struct SpaceDef {
    pub name: String,
    pub mods: Vec<SpaceMod>,
    pub location: Option<Location>,
}

/// `spacemod : typemod | sizemod | wordsizemod | 'default'`.
#[derive(Debug, Clone)]
pub enum SpaceMod {
    Type(String),
    Size(Integer),
    WordSize(Integer),
    Default,
}

#[derive(Debug, Clone)]
pub struct VarnodeDef {
    pub space: String,
    pub offset: Integer,
    pub size: Integer,
    pub names: Vec<IdOrWild>,
    pub location: Option<Location>,
}

#[derive(Debug, Clone)]
pub struct BitrangeDef {
    pub bitranges: Vec<Bitrange>,
    pub location: Option<Location>,
}

/// `bitrange : <name> = <register> [ <start> , <width> ]`.
#[derive(Debug, Clone)]
pub struct Bitrange {
    pub name: String,
    pub register: String,
    pub start: Integer,
    pub width: Integer,
    pub location: Option<Location>,
}

#[derive(Debug, Clone)]
pub struct PcodeOpDef {
    pub names: Vec<IdOrWild>,
    pub location: Option<Location>,
}

#[derive(Debug, Clone)]
pub struct ValueAttach {
    pub fields: Vec<IdOrWild>,
    pub values: Vec<IntBPart>,
    pub location: Option<Location>,
}

#[derive(Debug, Clone)]
pub struct NameAttach {
    pub fields: Vec<IdOrWild>,
    pub names: Vec<StringOrIdent>,
    pub location: Option<Location>,
}

#[derive(Debug, Clone)]
pub struct VarAttach {
    pub fields: Vec<IdOrWild>,
    pub registers: Vec<IdOrWild>,
    pub location: Option<Location>,
}

/// `id_or_wild : identifier | '_'`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdOrWild {
    Id(String),
    Wildcard,
}

/// `stringorident : id_or_wild | qstring`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StringOrIdent {
    IdOrWild(IdOrWild),
    String(String),
}

/// `intbpart : [-]integer | '_'`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntBPart {
    Value(i64),
    Wildcard,
}

/// Integer literal (`integer : HEX_INT | DEF_INT | BIN_INT`).
///
/// // TODO(sleigh-frontend): the Java front-end carries these as
/// // `RadixBigInteger` (arbitrary precision, radix-tagged). `i64` covers all
/// // real processor specs seen so far; switch to
/// // `crate::sleigh::grammar::RadixBigInteger` when the backend needs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Integer {
    pub value: i64,
    /// 2, 10, or 16, matching the literal's radix.
    pub radix: u32,
}

/// `constructorlike : macrodef | withblock | constructor`.
#[derive(Debug, Clone)]
pub enum Constructorlike {
    Macro(MacroDef),
    With(WithBlock),
    Constructor(Constructor),
}

/// `macrodef : macro <id> ( args ) semanticbody`.
#[derive(Debug, Clone)]
pub struct MacroDef {
    pub name: String,
    pub args: Vec<String>,
    pub body: SemanticBody,
    pub location: Option<Location>,
}

/// `withblock : with id? : bitpattern? contextblock { constructorlikelist }`.
#[derive(Debug, Clone)]
pub struct WithBlock {
    pub table: Option<String>,
    pub pattern: Option<PatternEquation>,
    pub context: Vec<ContextStmt>,
    /// `def_or_conslike*`
    pub body: Vec<SpecItem>,
    pub location: Option<Location>,
}

/// `constructor : ctorstart bitpattern contextblock ctorsemantic`.
#[derive(Debug, Clone)]
pub struct Constructor {
    /// `Some(name)` for a subtable constructor (`name: display is ...`),
    /// `None` for the root instruction table (`:display is ...`).
    pub table: Option<String>,
    pub display: DisplaySection,
    pub pattern: PatternEquation,
    pub context: Vec<ContextStmt>,
    pub semantic: CtorSemantic,
    pub location: Option<Location>,
}

/// `ctorsemantic : semanticbody | 'unimpl'`.
#[derive(Debug, Clone)]
pub enum CtorSemantic {
    Body(SemanticBody),
    Unimpl,
}

/// `display : ':' pieces 'is'` (DisplayParser.g, `OP_DISPLAY`): the
/// structured printpieces of a constructor display section, lexed in the
/// whitespace-significant DISPLAY mode.
///
/// The pieces are kept exactly as the grammar produces them: whitespace
/// runs keep their raw text, leading/trailing whitespace pieces are
/// preserved, and `^` appears as an explicit [`PrintPiece::Concatenate`].
/// Collapsing whitespace to single separators and extracting the mnemonic
/// (the first non-whitespace piece) are compile-pass concerns, exactly as
/// in Ghidra's `SleighCompiler.g`/`SleighCompile` -- not parse-time ones.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DisplaySection {
    pub pieces: Vec<PrintPiece>,
}

/// `printpiece : identifier | whitespace | concatenate | qstring | special`
/// (DisplayParser.g).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrintPiece {
    /// `identifier` -- a symbol reference (operand/table/register name),
    /// resolved against the pattern/table symbols by the compile pass;
    /// prints verbatim when it resolves to nothing. Keywords used as
    /// identifiers (key_as_id) land here too.
    Identifier(String),
    /// `whitespace` (`OP_WHITESPACE`) -- a significant whitespace run,
    /// raw text preserved.
    Whitespace(String),
    /// `concatenate` (`OP_CONCATENATE`) -- `^`: joins the adjacent pieces
    /// with no separating whitespace and is itself not printed.
    Concatenate,
    /// `qstring` (`OP_QSTRING`) -- quoted string, printed verbatim (quotes
    /// stripped, escapes kept as lexed).
    QString(String),
    /// `special` (`OP_STRING`) -- punctuation, operator, `@$?#`, or integer
    /// lexeme used for its literal characters.
    Literal(String),
}

/// `semanticbody : { semantic }` with `semantic : code_block`
/// (SemanticParser.g, `OP_SEMANTIC`): the typed p-code statements of a
/// constructor or `macro` body. An empty statement list is the grammar's
/// `OP_NOP` (empty `code_block`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SemanticBody {
    pub statements: Vec<PcodeStmt>,
}

/// `statement` (SemanticParser.g). Statement-terminating `;` and the
/// `label`/`section_def` forms (which take no `;`) are handled by the
/// parser, not the types.
#[derive(Debug, Clone, PartialEq)]
pub enum PcodeStmt {
    /// `assignment : KEY_LOCAL? lvalue = expr` (`OP_ASSIGN`, wrapped in
    /// `OP_LOCAL` for the `local` form).
    Assign {
        local: bool,
        lvalue: Lvalue,
        rhs: PcodeExpr,
    },
    /// `declaration : local <id> (: <size>)?` (`OP_LOCAL`).
    LocalDecl { name: String, size: Option<Integer> },
    /// `funcall : expr_apply` -- macro invocation or user-pcodeop call whose
    /// value is discarded (`OP_APPLY` at statement level).
    Funcall { name: String, args: Vec<PcodeExpr> },
    /// `build_stmt : build <id>` (`OP_BUILD`).
    Build { operand: String },
    /// `crossbuild_stmt : crossbuild varnode , <id>` (`OP_CROSSBUILD`).
    CrossBuild { address: PcodeExpr, section: String },
    /// `goto_stmt : goto jumpdest` (`OP_GOTO`).
    Goto { dest: JumpDest },
    /// `cond_stmt : if expr goto_stmt` (`OP_IF`).
    IfGoto { cond: PcodeExpr, dest: JumpDest },
    /// `call_stmt : call jumpdest` (`OP_CALL`).
    Call { dest: JumpDest },
    /// `return_stmt : return [ expr ]` (`OP_RETURN`).
    Return { dest: PcodeExpr },
    /// `export` (`OP_EXPORT`).
    Export(Export),
    /// `label : < <id> >` (`OP_LABEL`); takes no `;`.
    Label { name: String },
    /// `section_def : << <id> >>` (`OP_SECTION_LABEL`); takes no `;`.
    SectionLabel { name: String },
}

/// `export : export sizedexport | export varnode` alternatives.
#[derive(Debug, Clone, PartialEq)]
pub enum Export {
    /// `sizedexport : sizedstar identifier`
    Sized { star: SizedStar, name: String },
    /// `export varnode`
    Varnode(PcodeExpr),
}

/// `lvalue` (SemanticParser.g).
#[derive(Debug, Clone, PartialEq)]
pub enum Lvalue {
    /// `sembitrange : <id> [ <lsb> , <size> ]` (`OP_BITRANGE`)
    BitRange {
        name: String,
        lsb: Integer,
        size: Integer,
    },
    /// `<id> : <size>` (`OP_DECLARATIVE_SIZE`) -- declares-and-assigns,
    /// e.g. `tmp:2 = inst_next`.
    SizedId { name: String, size: Integer },
    /// `<id>`
    Id(String),
    /// `sizedstar expr` (`OP_DEREFERENCE`) -- store through a pointer.
    Deref { star: SizedStar, addr: PcodeExpr },
}

/// `sizedstar : * ([<space>])? (: <size>)?` (`OP_DEREFERENCE` decorations).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SizedStar {
    pub space: Option<String>,
    pub size: Option<Integer>,
}

/// `jumpdest` (SemanticParser.g).
#[derive(Debug, Clone, PartialEq)]
pub enum JumpDest {
    /// `identifier` (`OP_JUMPDEST_SYMBOL`)
    Symbol(String),
    /// `[ expr ]` (`OP_JUMPDEST_DYNAMIC`)
    Dynamic(PcodeExpr),
    /// `integer` (`OP_JUMPDEST_ABSOLUTE`)
    Absolute(Integer),
    /// `constant [ <space> ]` (`OP_JUMPDEST_RELATIVE`)
    Relative { offset: Integer, space: String },
    /// `label : < <id> >` (`OP_JUMPDEST_LABEL`)
    Label(String),
}

/// Binary operators of the semantic expression ladder (`expr_boolor` ..
/// `expr_mult` in SemanticParser.g), loosest to tightest:
/// `||` < `&&`/`^^` < `|` < `^` < `&` < equality < comparison < shift <
/// additive < multiplicative.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcodeBinOp {
    BoolOr,      // `||`  (OP_BOOL_OR)
    BoolAnd,     // `&&`  (OP_BOOL_AND)
    BoolXor,     // `^^`  (OP_BOOL_XOR)
    Or,          // `|`   (OP_OR)
    Xor,         // `^`   (OP_XOR)
    And,         // `&`   (OP_AND)
    Equal,       // `==`  (OP_EQUAL)
    NotEqual,    // `!=`  (OP_NOTEQUAL)
    FEqual,      // `f==` (OP_FEQUAL)
    FNotEqual,   // `f!=` (OP_FNOTEQUAL)
    Less,        // `<`   (OP_LESS)
    GreatEqual,  // `>=`  (OP_GREATEQUAL)
    LessEqual,   // `<=`  (OP_LESSEQUAL)
    Great,       // `>`   (OP_GREAT)
    SLess,       // `s<`  (OP_SLESS)
    SGreatEqual, // `s>=` (OP_SGREATEQUAL)
    SLessEqual,  // `s<=` (OP_SLESSEQUAL)
    SGreat,      // `s>`  (OP_SGREAT)
    FLess,       // `f<`  (OP_FLESS)
    FGreatEqual, // `f>=` (OP_FGREATEQUAL)
    FLessEqual,  // `f<=` (OP_FLESSEQUAL)
    FGreat,      // `f>`  (OP_FGREAT)
    Left,        // `<<`  (OP_LEFT)
    Right,       // `>>`  (OP_RIGHT)
    SRight,      // `s>>` (OP_SRIGHT)
    Add,         // `+`   (OP_ADD)
    Sub,         // `-`   (OP_SUB)
    FAdd,        // `f+`  (OP_FADD)
    FSub,        // `f-`  (OP_FSUB)
    Mult,        // `*`   (OP_MULT)
    Div,         // `/`   (OP_DIV)
    Rem,         // `%`   (OP_REM)
    SDiv,        // `s/`  (OP_SDIV)
    SRem,        // `s%`  (OP_SREM)
    FMult,       // `f*`  (OP_FMULT)
    FDiv,        // `f/`  (OP_FDIV)
}

/// `unary_op` alternatives other than `sizedstar` (which carries payload and
/// is [`PcodeExpr::Deref`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcodeUnaryOp {
    Not,     // `!` (OP_NOT)
    Invert,  // `~` (OP_INVERT)
    Negate,  // `-` (OP_NEGATE)
    FNegate, // `f-` (OP_FNEGATE)
}

/// Semantic (p-code) expression (`expr` rules of SemanticParser.g).
#[derive(Debug, Clone, PartialEq)]
pub enum PcodeExpr {
    Binary {
        op: PcodeBinOp,
        lhs: Box<PcodeExpr>,
        rhs: Box<PcodeExpr>,
    },
    Unary {
        op: PcodeUnaryOp,
        operand: Box<PcodeExpr>,
    },
    /// `sizedstar expr_func` in unary position (`OP_DEREFERENCE`) -- load
    /// through a pointer, e.g. `*:2 SP` or `*[ram]:4 ptr`.
    Deref {
        star: SizedStar,
        operand: Box<PcodeExpr>,
    },
    /// `expr_apply : identifier ( operands )` (`OP_APPLY`) -- built-in op
    /// (`zext`, `sext`, `carry`, ...), macro, or user pcodeop.
    Apply { name: String, args: Vec<PcodeExpr> },
    /// `( expr )` (`OP_PARENTHESIZED`).
    Parenthesized(Box<PcodeExpr>),
    /// `sembitrange : <id> [ <lsb> , <size> ]` (`OP_BITRANGE`).
    BitRange {
        name: String,
        lsb: Integer,
        size: Integer,
    },
    /// `varnode : int_lit` (`OP_*_CONSTANT`).
    Integer(Integer),
    /// `varnode : identifier`.
    Identifier(String),
    /// `varnode : int_lit : <size>` (`OP_TRUNCATION_SIZE`), e.g. `0x1234:2`.
    Truncation { value: Integer, size: Integer },
    /// `varnode : identifier : <size>` (`OP_BITRANGE2`), e.g. `val:1`.
    SizedId { name: String, size: Integer },
    /// `varnode : & (: <size>)? varnode` (`OP_ADDRESS_OF`, with
    /// `OP_SIZING_SIZE` for the sized form).
    AddressOf {
        size: Option<Integer>,
        operand: Box<PcodeExpr>,
    },
}

/// `ctxstmt : ctxassign | pfuncall`.
#[derive(Debug, Clone)]
pub enum ContextStmt {
    /// `ctxassign : <id> = pexpression`
    Assign { lhs: String, rhs: PExpression },
    /// `pfuncall : <id> ( pexpression* )`
    Funcall { name: String, args: Vec<PExpression> },
}

/// Binary operators of `pexpression` / `pexpression2`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PExprBinOp {
    Or,
    Xor,
    And,
    Left,
    Right,
    Add,
    Sub,
    Mult,
    Div,
}

/// Unary operators of `pexpression`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PExprUnaryOp {
    Negate,
    Invert,
}

/// Pattern-context expression (`pexpression` rules).
#[derive(Debug, Clone)]
pub enum PExpression {
    Binary {
        op: PExprBinOp,
        lhs: Box<PExpression>,
        rhs: Box<PExpression>,
    },
    Unary {
        op: PExprUnaryOp,
        operand: Box<PExpression>,
    },
    /// `pexpression_apply : identifier ( operands )`
    Apply {
        name: String,
        args: Vec<PExpression>,
    },
    Identifier(String),
    Integer(Integer),
}

/// Comparison operators of `constraint`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConstraintOp {
    Equal,
    NotEqual,
    Less,
    LessEqual,
    Great,
    GreatEqual,
}

/// Pattern equation (`pequation` rules).
#[derive(Debug, Clone)]
pub enum PatternEquation {
    /// `a | b`
    Or(Box<PatternEquation>, Box<PatternEquation>),
    /// `a ; b`
    Sequence(Box<PatternEquation>, Box<PatternEquation>),
    /// `a & b`
    And(Box<PatternEquation>, Box<PatternEquation>),
    /// `... a`
    EllipsisLeft(Box<PatternEquation>),
    /// `a ...`
    EllipsisRight(Box<PatternEquation>),
    /// `( a )`
    Parenthesized(Box<PatternEquation>),
    /// `constraint : identifier (op pexpression2)?`
    Constraint {
        symbol: String,
        op: Option<ConstraintOp>,
        expr: Option<PExpression>,
    },
}

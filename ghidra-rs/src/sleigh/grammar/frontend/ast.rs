//! AST types for the top-level SLEIGH grammar (`SleighParser.g`).
//!
//! The ANTLR grammar builds a homogeneous `CommonTree` of `OP_*` nodes; this
//! port uses typed Rust structures instead. Node names map to the grammar
//! rules that produce them (noted per item).
//!
//! Display sections are structured printpieces ([`DisplaySection`] /
//! [`PrintPiece`]), mirroring `DisplayParser.g`.
//!
//! // TODO(sleigh-frontend): semantic bodies are represented as raw token
//! // runs ([`SemanticBody`]) until the semantic sub-lexer mode and its
//! // parser (SemanticLexer.g / SemanticParser.g) are ported.

use crate::sleigh::grammar::{Location, SleighToken};

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

/// Raw token run between balanced `{` `}`.
///
/// // TODO(sleigh-frontend): replace with a real p-code statement AST once
/// // SemanticLexer/SemanticParser are ported.
#[derive(Debug, Clone, Default)]
pub struct SemanticBody {
    pub tokens: Vec<SleighToken>,
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

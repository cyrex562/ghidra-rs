//! Recursive-descent parser for the top-level SLEIGH grammar
//! (`SleighParser.g`), producing the typed AST in [`super::ast`].
//!
//! Implemented: `spec`, `endiandef`, all `definition` alternatives
//! (alignment, token, context, space, varnode, bitrange, pcodeop, and the
//! three `attach` forms), pattern equations (`pequation`), pattern
//! expressions (`pexpression`/`pexpression2`), context blocks, macro
//! definitions, `with` blocks, constructors, and constructor display
//! sections (`DisplayParser.g`, structured printpieces).
//!
//! Lexing is pull-based: the parser owns the [`BaseLexer`] and buffers
//! base-mode tokens only as far as its lookahead needs, so that when a
//! constructor's `:` is consumed it can switch the *unlexed remainder* into
//! DISPLAY mode (whitespace-significant; see [`super::display_lexer`]) and
//! back to base mode at the reserved word `is` -- the Rust equivalent of
//! `DisplayParser.g`'s `lexer.pushMode(DISPLAY) ... lexer.popMode()`
//! parser actions. Semantic bodies switch the same way: the `{` opening a
//! constructor or `macro` body pushes SEMANTIC mode and hands off to
//! [`super::semantic_parser::SemanticParser`], which parses the typed
//! p-code statement AST through the matching `}` (SemanticParser.g /
//! SemanticLexer.g).

use crate::sleigh::grammar::{Location, ParsingEnvironment, SleighToken};

use super::ast::*;
use super::display_lexer::DisplayLexer;
use super::lexer::{BaseLexer, TokenType};
use super::semantic_parser::SemanticParser;

/// Parse error with source position information.
#[derive(Debug, thiserror::Error)]
#[error("{message} at line {line}{}", location.as_ref().map(|l| format!(" ({l})")).unwrap_or_default())]
pub struct ParseError {
    pub message: String,
    pub line: i32,
    pub location: Option<Location>,
}

type PResult<T> = Result<T, ParseError>;

/// Recursive-descent parser pulling tokens on demand from a [`BaseLexer`],
/// switching the lexer into DISPLAY mode inside constructor display
/// sections.
pub struct SleighParser {
    lexer: BaseLexer,
    /// Base-mode default-channel tokens buffered for lookahead. Consumed
    /// tokens are kept (indexed by `pos`); the buffer is only ever filled as
    /// far as `peek`/`peek_ty_at` require, so no base-mode token is lexed
    /// past a constructor `:` before the mode switch.
    tokens: Vec<SleighToken>,
    pos: usize,
}

impl SleighParser {
    /// Builds a parser over (already preprocessed) SLEIGH source text.
    pub fn new(input: &str) -> Self {
        Self {
            lexer: BaseLexer::new(input),
            tokens: Vec::new(),
            pos: 0,
        }
    }

    /// Like [`SleighParser::new`], with a [`ParsingEnvironment`] attached so
    /// tokens (and thus errors) carry original-source [`Location`]s from the
    /// preprocessor's position markers.
    pub fn with_env(input: &str, env: ParsingEnvironment) -> Self {
        Self {
            lexer: BaseLexer::with_env(input, env),
            tokens: Vec::new(),
            pos: 0,
        }
    }

    /// Convenience: parse `input` as a full spec.
    pub fn parse_str(input: &str) -> PResult<Spec> {
        Self::new(input).parse_spec()
    }

    // ----- token utilities -------------------------------------------------

    /// Ensures the lookahead buffer holds a token at `pos + n` (or ends with
    /// EOF), pulling base-mode default-channel tokens as needed.
    fn ensure(&mut self, n: usize) {
        while self.tokens.len() <= self.pos + n {
            if let Some(last) = self.tokens.last() {
                if last.token_type() == TokenType::Eof.as_i32() {
                    return;
                }
            }
            loop {
                let t = self.lexer.next_token();
                // Hidden/comment/preproc channels are invisible to the
                // base-mode parse (as in `BaseLexer.g`).
                if t.channel() == 0 || t.token_type() == TokenType::Eof.as_i32() {
                    self.tokens.push(t);
                    break;
                }
            }
        }
    }

    fn peek(&mut self) -> &SleighToken {
        self.ensure(0);
        self.tokens
            .get(self.pos)
            .or_else(|| self.tokens.last())
            .expect("token stream always ends with EOF")
    }

    fn peek_ty(&mut self) -> TokenType {
        TokenType::from_i32(self.peek().token_type()).unwrap_or(TokenType::Unknown)
    }

    fn peek_ty_at(&mut self, offset: usize) -> TokenType {
        self.ensure(offset);
        self.tokens
            .get(self.pos + offset)
            .and_then(|t| TokenType::from_i32(t.token_type()))
            .unwrap_or(TokenType::Eof)
    }

    fn bump(&mut self) -> SleighToken {
        let t = self.peek().clone();
        if t.token_type() != TokenType::Eof.as_i32() {
            self.pos += 1;
        }
        t
    }

    /// The token at the current position, for error reporting. Does not pull
    /// from the lexer; error paths always follow a peek that filled it.
    fn current(&self) -> Option<&SleighToken> {
        self.tokens.get(self.pos).or_else(|| self.tokens.last())
    }

    fn err_here(&self, message: impl Into<String>) -> ParseError {
        match self.current() {
            Some(t) => ParseError {
                message: message.into(),
                line: t.line(),
                location: t.location().cloned(),
            },
            None => ParseError {
                message: message.into(),
                line: 0,
                location: None,
            },
        }
    }

    fn err_at(t: &SleighToken, message: impl Into<String>) -> ParseError {
        ParseError {
            message: message.into(),
            line: t.line(),
            location: t.location().cloned(),
        }
    }

    fn expect(&mut self, ty: TokenType, what: &str) -> PResult<SleighToken> {
        if self.peek_ty() == ty {
            Ok(self.bump())
        } else {
            let found = self.peek().text().unwrap_or("<?>").to_string();
            Err(self.err_here(format!("expected {what}, found '{found}'")))
        }
    }

    fn at(&mut self, ty: TokenType) -> bool {
        self.peek_ty() == ty
    }

    fn eat(&mut self, ty: TokenType) -> bool {
        if self.at(ty) {
            self.bump();
            return true;
        }
        false
    }

    /// `identifier : strict_id | key_as_id` -- any keyword may be used as an
    /// identifier (its text is used); `with` (RES_WITH) may not.
    /// Shared with the semantic-body parser ([`super::semantic_parser`]).
    pub(super) fn is_identifier_like(ty: TokenType) -> bool {
        matches!(ty, TokenType::Identifier)
            || matches!(
                ty,
                TokenType::KeyAlignment
                    | TokenType::KeyAttach
                    | TokenType::KeyBig
                    | TokenType::KeyBitrange
                    | TokenType::KeyBuild
                    | TokenType::KeyCall
                    | TokenType::KeyContext
                    | TokenType::KeyCrossbuild
                    | TokenType::KeyDec
                    | TokenType::KeyDefault
                    | TokenType::KeyDefine
                    | TokenType::KeyEndian
                    | TokenType::KeyExport
                    | TokenType::KeyGoto
                    | TokenType::KeyHex
                    | TokenType::KeyLittle
                    | TokenType::KeyLocal
                    | TokenType::KeyMacro
                    | TokenType::KeyNames
                    | TokenType::KeyNoflow
                    | TokenType::KeyOffset
                    | TokenType::KeyPcodeop
                    | TokenType::KeyReturn
                    | TokenType::KeySigned
                    | TokenType::KeySize
                    | TokenType::KeySpace
                    | TokenType::KeyToken
                    | TokenType::KeyType
                    | TokenType::KeyUnimpl
                    | TokenType::KeyValues
                    | TokenType::KeyVariables
                    | TokenType::KeyWordsize
            )
    }

    fn parse_identifier(&mut self) -> PResult<String> {
        if Self::is_identifier_like(self.peek_ty()) {
            let t = self.bump();
            Ok(t.text().unwrap_or("").to_string())
        } else {
            Err(self.err_here("expected identifier"))
        }
    }

    /// `strict_id : IDENTIFIER` (keywords not allowed).
    fn parse_strict_id(&mut self) -> PResult<String> {
        let t = self.expect(TokenType::Identifier, "identifier")?;
        Ok(t.text().unwrap_or("").to_string())
    }

    /// `integer : HEX_INT | DEF_INT | BIN_INT`.
    fn parse_integer(&mut self) -> PResult<Integer> {
        let ty = self.peek_ty();
        let (radix, skip) = match ty {
            TokenType::HexInt => (16, 2),
            TokenType::BinInt => (2, 2),
            TokenType::DefInt => (10, 0),
            _ => return Err(self.err_here("expected integer")),
        };
        let t = self.bump();
        let text = t.text().unwrap_or("");
        let digits = &text[skip..];
        let value = i64::from_str_radix(digits, radix).map_err(|e| ParseError {
            message: format!("invalid integer literal '{text}': {e}"),
            line: t.line(),
            location: t.location().cloned(),
        })?;
        Ok(Integer { value, radix })
    }

    /// `neginteger : integer | MINUS integer`.
    fn parse_neg_integer(&mut self) -> PResult<i64> {
        if self.eat(TokenType::Minus) {
            Ok(-self.parse_integer()?.value)
        } else {
            Ok(self.parse_integer()?.value)
        }
    }

    fn loc_of(t: &SleighToken) -> Option<Location> {
        t.location()
            .cloned()
            .or_else(|| Some(Location::new("<input>", t.line())))
    }

    // ----- spec ------------------------------------------------------------

    /// `spec : endiandef (definition | constructorlike)* EOF`.
    pub fn parse_spec(&mut self) -> PResult<Spec> {
        let endian = self.parse_endiandef()?;
        let mut items = Vec::new();
        while !self.at(TokenType::Eof) {
            match self.peek_ty() {
                TokenType::KeyDefine | TokenType::KeyAttach => {
                    items.push(SpecItem::Definition(self.parse_definition()?));
                }
                _ => {
                    items.push(SpecItem::Constructorlike(self.parse_constructorlike()?));
                }
            }
        }
        // Lexing errors surface lazily (tokens are pulled on demand); any
        // that did not already derail the parse are still hard errors.
        if let Some(msg) = self.lexer.errors().first() {
            return Err(ParseError {
                message: format!("lexing error: {msg}"),
                line: 0,
                location: None,
            });
        }
        Ok(Spec { endian, items })
    }

    /// `endiandef : KEY_DEFINE KEY_ENDIAN ASSIGN endian SEMI`.
    fn parse_endiandef(&mut self) -> PResult<EndianDef> {
        let lc = self.expect(TokenType::KeyDefine, "'define'")?;
        self.expect(TokenType::KeyEndian, "'endian'")?;
        self.expect(TokenType::Assign, "'='")?;
        let endian = self.parse_endian()?;
        self.expect(TokenType::Semi, "';'")?;
        Ok(EndianDef {
            endian,
            location: Self::loc_of(&lc),
        })
    }

    fn parse_endian(&mut self) -> PResult<Endian> {
        match self.peek_ty() {
            TokenType::KeyBig => {
                self.bump();
                Ok(Endian::Big)
            }
            TokenType::KeyLittle => {
                self.bump();
                Ok(Endian::Little)
            }
            _ => Err(self.err_here("expected 'big' or 'little'")),
        }
    }

    // ----- definitions -----------------------------------------------------

    /// `definition : (aligndef | tokendef | ... | varattach) SEMI!`.
    fn parse_definition(&mut self) -> PResult<Definition> {
        let def = if self.at(TokenType::KeyDefine) {
            match self.peek_ty_at(1) {
                TokenType::KeyAlignment => self.parse_aligndef()?,
                TokenType::KeyToken => self.parse_tokendef()?,
                TokenType::KeyContext => self.parse_contextdef()?,
                TokenType::KeySpace => self.parse_spacedef()?,
                TokenType::KeyBitrange => self.parse_bitrangedef()?,
                TokenType::KeyPcodeop => self.parse_pcodeopdef()?,
                _ => self.parse_varnodedef()?,
            }
        } else {
            self.parse_attach()?
        };
        self.expect(TokenType::Semi, "';'")?;
        Ok(def)
    }

    fn parse_aligndef(&mut self) -> PResult<Definition> {
        let lc = self.bump(); // define
        self.expect(TokenType::KeyAlignment, "'alignment'")?;
        self.expect(TokenType::Assign, "'='")?;
        let alignment = self.parse_integer()?;
        Ok(Definition::Align(AlignDef {
            alignment,
            location: Self::loc_of(&lc),
        }))
    }

    /// `tokendef : define token <id> ( <int> ) [endian = e] fielddefs`.
    fn parse_tokendef(&mut self) -> PResult<Definition> {
        let lc = self.bump(); // define
        self.expect(TokenType::KeyToken, "'token'")?;
        let name = self.parse_identifier()?;
        self.expect(TokenType::LParen, "'('")?;
        let size = self.parse_integer()?;
        self.expect(TokenType::RParen, "')'")?;
        let endian = if self.at(TokenType::KeyEndian) {
            self.bump();
            self.expect(TokenType::Assign, "'='")?;
            Some(self.parse_endian()?)
        } else {
            None
        };
        let mut fields = Vec::new();
        // fielddefs : fielddef*  (a fielddef starts with strict_id '=')
        while self.at(TokenType::Identifier) && self.peek_ty_at(1) == TokenType::Assign {
            fields.push(self.parse_fielddef(false)?);
        }
        Ok(Definition::Token(TokenDef {
            name,
            size,
            endian,
            fields,
            location: Self::loc_of(&lc),
        }))
    }

    /// `fielddef : id = ( s , e ) fieldmods` (`context` allows `noflow` and a
    /// non-strict identifier).
    fn parse_fielddef(&mut self, context: bool) -> PResult<FieldDef> {
        let name = if context {
            self.parse_identifier()?
        } else {
            self.parse_strict_id()?
        };
        let lc = self.expect(TokenType::Assign, "'='")?;
        self.expect(TokenType::LParen, "'('")?;
        let start = self.parse_integer()?;
        self.expect(TokenType::Comma, "','")?;
        let end = self.parse_integer()?;
        self.expect(TokenType::RParen, "')'")?;
        let mut mods = Vec::new();
        loop {
            match self.peek_ty() {
                TokenType::KeySigned => {
                    self.bump();
                    mods.push(FieldMod::Signed);
                }
                TokenType::KeyHex => {
                    self.bump();
                    mods.push(FieldMod::Hex);
                }
                TokenType::KeyDec => {
                    self.bump();
                    mods.push(FieldMod::Dec);
                }
                TokenType::KeyNoflow if context => {
                    self.bump();
                    mods.push(FieldMod::Noflow);
                }
                _ => break,
            }
        }
        Ok(FieldDef {
            name,
            start,
            end,
            mods,
            location: Self::loc_of(&lc),
        })
    }

    /// `contextdef : define context <id> contextfielddefs`.
    fn parse_contextdef(&mut self) -> PResult<Definition> {
        let lc = self.bump(); // define
        self.expect(TokenType::KeyContext, "'context'")?;
        let varnode = self.parse_identifier()?;
        let mut fields = Vec::new();
        while Self::is_identifier_like(self.peek_ty()) && self.peek_ty_at(1) == TokenType::Assign {
            fields.push(self.parse_fielddef(true)?);
        }
        Ok(Definition::Context(ContextDef {
            varnode,
            fields,
            location: Self::loc_of(&lc),
        }))
    }

    /// `spacedef : define space <id> spacemod*`.
    fn parse_spacedef(&mut self) -> PResult<Definition> {
        let lc = self.bump(); // define
        self.expect(TokenType::KeySpace, "'space'")?;
        let name = self.parse_identifier()?;
        let mut mods = Vec::new();
        loop {
            match self.peek_ty() {
                TokenType::KeyType => {
                    self.bump();
                    self.expect(TokenType::Assign, "'='")?;
                    mods.push(SpaceMod::Type(self.parse_identifier()?));
                }
                TokenType::KeySize => {
                    self.bump();
                    self.expect(TokenType::Assign, "'='")?;
                    mods.push(SpaceMod::Size(self.parse_integer()?));
                }
                TokenType::KeyWordsize => {
                    self.bump();
                    self.expect(TokenType::Assign, "'='")?;
                    mods.push(SpaceMod::WordSize(self.parse_integer()?));
                }
                TokenType::KeyDefault => {
                    self.bump();
                    mods.push(SpaceMod::Default);
                }
                _ => break,
            }
        }
        Ok(Definition::Space(SpaceDef {
            name,
            mods,
            location: Self::loc_of(&lc),
        }))
    }

    /// `varnodedef : define <space> offset = <int> size = <int> idlist`.
    fn parse_varnodedef(&mut self) -> PResult<Definition> {
        let lc = self.bump(); // define
        let space = self.parse_identifier()?;
        self.expect(TokenType::KeyOffset, "'offset'")?;
        self.expect(TokenType::Assign, "'='")?;
        let offset = self.parse_integer()?;
        self.expect(TokenType::KeySize, "'size'")?;
        self.expect(TokenType::Assign, "'='")?;
        let size = self.parse_integer()?;
        let names = self.parse_identifierlist()?;
        Ok(Definition::Varnode(VarnodeDef {
            space,
            offset,
            size,
            names,
            location: Self::loc_of(&lc),
        }))
    }

    /// `bitrangedef : define bitrange bitrange+`.
    fn parse_bitrangedef(&mut self) -> PResult<Definition> {
        let lc = self.bump(); // define
        self.expect(TokenType::KeyBitrange, "'bitrange'")?;
        let mut bitranges = Vec::new();
        loop {
            let name = self.parse_identifier()?;
            let assign = self.expect(TokenType::Assign, "'='")?;
            let register = self.parse_identifier()?;
            self.expect(TokenType::LBracket, "'['")?;
            let start = self.parse_integer()?;
            self.expect(TokenType::Comma, "','")?;
            let width = self.parse_integer()?;
            self.expect(TokenType::RBracket, "']'")?;
            bitranges.push(Bitrange {
                name,
                register,
                start,
                width,
                location: Self::loc_of(&assign),
            });
            if !Self::is_identifier_like(self.peek_ty()) {
                break;
            }
        }
        Ok(Definition::Bitrange(BitrangeDef {
            bitranges,
            location: Self::loc_of(&lc),
        }))
    }

    fn parse_pcodeopdef(&mut self) -> PResult<Definition> {
        let lc = self.bump(); // define
        self.expect(TokenType::KeyPcodeop, "'pcodeop'")?;
        let names = self.parse_identifierlist()?;
        Ok(Definition::PcodeOp(PcodeOpDef {
            names,
            location: Self::loc_of(&lc),
        }))
    }

    /// `valueattach | nameattach | varattach`.
    fn parse_attach(&mut self) -> PResult<Definition> {
        let lc = self.expect(TokenType::KeyAttach, "'attach'")?;
        match self.peek_ty() {
            TokenType::KeyValues => {
                self.bump();
                let fields = self.parse_identifierlist()?;
                let values = self.parse_intblist()?;
                Ok(Definition::ValueAttach(ValueAttach {
                    fields,
                    values,
                    location: Self::loc_of(&lc),
                }))
            }
            TokenType::KeyNames => {
                self.bump();
                let fields = self.parse_identifierlist()?;
                let names = self.parse_stringoridentlist()?;
                Ok(Definition::NameAttach(NameAttach {
                    fields,
                    names,
                    location: Self::loc_of(&lc),
                }))
            }
            TokenType::KeyVariables => {
                self.bump();
                let fields = self.parse_identifierlist()?;
                let registers = self.parse_identifierlist()?;
                Ok(Definition::VarAttach(VarAttach {
                    fields,
                    registers,
                    location: Self::loc_of(&lc),
                }))
            }
            _ => Err(self.err_here("expected 'values', 'names', or 'variables' after 'attach'")),
        }
    }

    // ----- lists -----------------------------------------------------------

    fn parse_id_or_wild(&mut self) -> PResult<IdOrWild> {
        if self.eat(TokenType::Underscore) {
            Ok(IdOrWild::Wildcard)
        } else {
            Ok(IdOrWild::Id(self.parse_identifier()?))
        }
    }

    /// `identifierlist : [ id_or_wild+ ] | id_or_wild`.
    fn parse_identifierlist(&mut self) -> PResult<Vec<IdOrWild>> {
        let mut out = Vec::new();
        if self.eat(TokenType::LBracket) {
            while !self.at(TokenType::RBracket) {
                out.push(self.parse_id_or_wild()?);
            }
            self.expect(TokenType::RBracket, "']'")?;
            if out.is_empty() {
                return Err(self.err_here("identifier list may not be empty"));
            }
        } else {
            out.push(self.parse_id_or_wild()?);
        }
        Ok(out)
    }

    /// `intblist : [ intbpart+ ] | neginteger`.
    fn parse_intblist(&mut self) -> PResult<Vec<IntBPart>> {
        let mut out = Vec::new();
        if self.eat(TokenType::LBracket) {
            while !self.at(TokenType::RBracket) {
                if self.eat(TokenType::Underscore) {
                    out.push(IntBPart::Wildcard);
                } else {
                    out.push(IntBPart::Value(self.parse_neg_integer()?));
                }
            }
            self.expect(TokenType::RBracket, "']'")?;
            if out.is_empty() {
                return Err(self.err_here("integer list may not be empty"));
            }
        } else {
            out.push(IntBPart::Value(self.parse_neg_integer()?));
        }
        Ok(out)
    }

    /// `stringoridentlist : [ stringorident+ ] | stringorident`.
    fn parse_stringoridentlist(&mut self) -> PResult<Vec<StringOrIdent>> {
        let mut out = Vec::new();
        if self.eat(TokenType::LBracket) {
            while !self.at(TokenType::RBracket) {
                out.push(self.parse_stringorident()?);
            }
            self.expect(TokenType::RBracket, "']'")?;
            if out.is_empty() {
                return Err(self.err_here("list may not be empty"));
            }
        } else {
            out.push(self.parse_stringorident()?);
        }
        Ok(out)
    }

    fn parse_stringorident(&mut self) -> PResult<StringOrIdent> {
        if self.at(TokenType::QString) {
            let t = self.bump();
            Ok(StringOrIdent::String(t.text().unwrap_or("").to_string()))
        } else {
            Ok(StringOrIdent::IdOrWild(self.parse_id_or_wild()?))
        }
    }

    // ----- constructor-likes -----------------------------------------------

    /// `constructorlike : macrodef | withblock | constructor`.
    fn parse_constructorlike(&mut self) -> PResult<Constructorlike> {
        match self.peek_ty() {
            TokenType::KeyMacro => Ok(Constructorlike::Macro(self.parse_macrodef()?)),
            TokenType::ResWith => Ok(Constructorlike::With(self.parse_withblock()?)),
            _ => Ok(Constructorlike::Constructor(self.parse_constructor()?)),
        }
    }

    /// `macrodef : macro <id> ( oplist? ) semanticbody`.
    fn parse_macrodef(&mut self) -> PResult<MacroDef> {
        let lc = self.expect(TokenType::KeyMacro, "'macro'")?;
        let name = self.parse_identifier()?;
        self.expect(TokenType::LParen, "'('")?;
        let mut args = Vec::new();
        if !self.at(TokenType::RParen) {
            args.push(self.parse_identifier()?);
            while self.eat(TokenType::Comma) {
                args.push(self.parse_identifier()?);
            }
        }
        self.expect(TokenType::RParen, "')'")?;
        let body = self.parse_semanticbody()?;
        Ok(MacroDef {
            name,
            args,
            body,
            location: Self::loc_of(&lc),
        })
    }

    /// `withblock : with id? : bitpattern? contextblock { def_or_conslike* }`.
    fn parse_withblock(&mut self) -> PResult<WithBlock> {
        let lc = self.expect(TokenType::ResWith, "'with'")?;
        let table = if self.at(TokenType::Colon) {
            None
        } else {
            Some(self.parse_identifier()?)
        };
        self.expect(TokenType::Colon, "':'")?;
        let pattern = if self.at(TokenType::LBracket) || self.at(TokenType::LBrace) {
            None
        } else {
            Some(self.parse_pequation()?)
        };
        let context = self.parse_contextblock()?;
        self.expect(TokenType::LBrace, "'{'")?;
        let mut body = Vec::new();
        while !self.at(TokenType::RBrace) {
            if self.at(TokenType::Eof) {
                return Err(self.err_here("unterminated 'with' block"));
            }
            match self.peek_ty() {
                TokenType::KeyDefine | TokenType::KeyAttach => {
                    body.push(SpecItem::Definition(self.parse_definition()?));
                }
                _ => body.push(SpecItem::Constructorlike(self.parse_constructorlike()?)),
            }
        }
        self.expect(TokenType::RBrace, "'}'")?;
        Ok(WithBlock {
            table,
            pattern,
            context,
            body,
            location: Self::loc_of(&lc),
        })
    }

    /// `constructor : ctorstart bitpattern contextblock ctorsemantic` where
    /// `ctorstart : identifier? display` and `display : ':' pieces 'is'`.
    fn parse_constructor(&mut self) -> PResult<Constructor> {
        let start = self.peek().clone();
        let table = if self.at(TokenType::Colon) {
            None
        } else {
            Some(self.parse_identifier()?)
        };
        self.expect(TokenType::Colon, "':' starting constructor display")?;
        let display = self.parse_display()?;

        let pattern = self.parse_pequation()?;
        let context = self.parse_contextblock()?;
        let semantic = if self.at(TokenType::KeyUnimpl) {
            self.bump();
            CtorSemantic::Unimpl
        } else {
            CtorSemantic::Body(self.parse_semanticbody()?)
        };
        Ok(Constructor {
            table,
            display,
            pattern,
            context,
            semantic,
            location: Self::loc_of(&start),
        })
    }

    /// `display : COLON pieces RES_IS` with
    /// `pieces : printpiece*` (DisplayParser.g); the COLON has already been
    /// consumed by the caller.
    ///
    /// This is where the lexer mode switches: pieces are pulled straight
    /// from the DISPLAY-mode lexer (whitespace on the default channel, `#`
    /// and `@$?` displayable, `is` reserved), bypassing the base-mode
    /// lookahead buffer, and the `is` terminator returns the remaining
    /// input to base mode -- the equivalent of DisplayParser.g's
    /// `lexer.pushMode(DISPLAY) ... lexer.popMode()` actions.
    fn parse_display(&mut self) -> PResult<DisplaySection> {
        // The mode switch is only sound if base-mode lookahead never crossed
        // the ':' (the grammar guarantees at most one-token lookahead, which
        // ends at the ':' itself).
        if self.pos != self.tokens.len() {
            return Err(self.err_here(
                "internal error: base-mode lookahead crossed into a display section",
            ));
        }
        let mut pieces = Vec::new();
        loop {
            let t = self.next_display_token();
            let ty = TokenType::from_i32(t.token_type()).unwrap_or(TokenType::Unknown);
            let text = || t.text().unwrap_or("").to_string();
            match ty {
                // RES_IS terminates the display and pops back to base mode.
                TokenType::ResIs => return Ok(DisplaySection { pieces }),
                TokenType::Eof => {
                    return Err(Self::err_at(&t, "constructor display never reached 'is'"))
                }
                // printpiece : identifier (keywords double as identifiers)
                ty if Self::is_identifier_like(ty) => {
                    pieces.push(PrintPiece::Identifier(text()));
                }
                // printpiece : whitespace (significant in display mode)
                TokenType::Whitespace => pieces.push(PrintPiece::Whitespace(text())),
                // printpiece : concatenate ('^' joins neighbors, not printed)
                TokenType::Caret => pieces.push(PrintPiece::Concatenate),
                // printpiece : qstring
                TokenType::QString => pieces.push(PrintPiece::QString(text())),
                // printpiece : special -- every alternative of the `special`
                // rule prints its literal characters.
                TokenType::DispChar
                | TokenType::LineComment
                | TokenType::LBrace
                | TokenType::RBrace
                | TokenType::LBracket
                | TokenType::RBracket
                | TokenType::LParen
                | TokenType::RParen
                | TokenType::Ellipsis
                | TokenType::Equal
                | TokenType::NotEqual
                | TokenType::Less
                | TokenType::Great
                | TokenType::LessEqual
                | TokenType::GreatEqual
                | TokenType::Assign
                | TokenType::Colon
                | TokenType::Comma
                | TokenType::Asterisk
                | TokenType::BoolOr
                | TokenType::BoolXor
                | TokenType::BoolAnd
                | TokenType::Pipe
                | TokenType::Ampersand
                | TokenType::Left
                | TokenType::Right
                | TokenType::Plus
                | TokenType::Minus
                | TokenType::Slash
                | TokenType::Percent
                | TokenType::Exclaim
                | TokenType::Tilde
                | TokenType::Semi
                | TokenType::SpecOr
                | TokenType::SpecAnd
                | TokenType::SpecXor
                | TokenType::DefInt
                | TokenType::HexInt
                | TokenType::BinInt => pieces.push(PrintPiece::Literal(text())),
                // Not printpieces in DisplayParser.g: UNDERSCORE, DEC_INT
                // (0n...), RES_WITH, CPPCOMMENT, UNKNOWN.
                _ => {
                    return Err(Self::err_at(
                        &t,
                        format!("'{}' is not valid in a constructor display section", text()),
                    ))
                }
            }
        }
    }

    /// Pulls one default-channel token in DISPLAY mode (preprocessor
    /// position markers stay on the PREPROC channel and are skipped).
    fn next_display_token(&mut self) -> SleighToken {
        loop {
            let t = DisplayLexer::new(&mut self.lexer).next_token();
            if t.channel() == 0 || t.token_type() == TokenType::Eof.as_i32() {
                return t;
            }
        }
    }

    /// `semanticbody : LBRACE semantic RBRACE` (SemanticParser.g) -- the
    /// second lexer mode switch: the `{` is consumed in base mode, then
    /// every token through the matching `}` is pulled in SEMANTIC mode
    /// (letter operators like `s<`/`f==` live, `if` reserved) by the
    /// dedicated [`SemanticParser`] -- the equivalent of
    /// `lexer.pushMode(SEMANTIC) ... lexer.popMode()` around `semantic`.
    fn parse_semanticbody(&mut self) -> PResult<SemanticBody> {
        self.expect(TokenType::LBrace, "'{'")?;
        // As with displays, the mode switch is only sound if base-mode
        // lookahead never crossed the '{' (the grammar guarantees at most
        // one-token lookahead here, ending at the '{' itself).
        if self.pos != self.tokens.len() {
            return Err(self.err_here(
                "internal error: base-mode lookahead crossed into a semantic body",
            ));
        }
        SemanticParser::new(&mut self.lexer).parse_semantic()
    }

    /// `contextblock : [ ctxstmt* ] | (nothing)`.
    fn parse_contextblock(&mut self) -> PResult<Vec<ContextStmt>> {
        let mut stmts = Vec::new();
        if self.eat(TokenType::LBracket) {
            while !self.at(TokenType::RBracket) {
                stmts.push(self.parse_ctxstmt()?);
            }
            self.expect(TokenType::RBracket, "']'")?;
        }
        Ok(stmts)
    }

    /// `ctxstmt : ctxassign SEMI | pfuncall SEMI`.
    fn parse_ctxstmt(&mut self) -> PResult<ContextStmt> {
        let name = self.parse_identifier()?;
        let stmt = if self.eat(TokenType::Assign) {
            ContextStmt::Assign {
                lhs: name,
                rhs: self.parse_pexpression()?,
            }
        } else if self.at(TokenType::LParen) {
            ContextStmt::Funcall {
                name,
                args: self.parse_pexpression_operands()?,
            }
        } else {
            return Err(self.err_here("expected '=' or '(' in context statement"));
        };
        self.expect(TokenType::Semi, "';'")?;
        Ok(stmt)
    }

    // ----- pattern equations -------------------------------------------------

    /// `pequation : pequation_or` (`|` < `;` < `&` in binding looseness).
    pub fn parse_pequation(&mut self) -> PResult<PatternEquation> {
        self.parse_pequation_or()
    }

    fn parse_pequation_or(&mut self) -> PResult<PatternEquation> {
        let mut lhs = self.parse_pequation_seq()?;
        while self.eat(TokenType::Pipe) {
            let rhs = self.parse_pequation_seq()?;
            lhs = PatternEquation::Or(Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn parse_pequation_seq(&mut self) -> PResult<PatternEquation> {
        let mut lhs = self.parse_pequation_and()?;
        while self.eat(TokenType::Semi) {
            let rhs = self.parse_pequation_and()?;
            lhs = PatternEquation::Sequence(Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn parse_pequation_and(&mut self) -> PResult<PatternEquation> {
        let mut lhs = self.parse_pequation_ellipsis()?;
        while self.eat(TokenType::Ampersand) {
            let rhs = self.parse_pequation_ellipsis()?;
            lhs = PatternEquation::And(Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn parse_pequation_ellipsis(&mut self) -> PResult<PatternEquation> {
        if self.eat(TokenType::Ellipsis) {
            let rhs = self.parse_pequation_ellipsis_right()?;
            return Ok(PatternEquation::EllipsisLeft(Box::new(rhs)));
        }
        self.parse_pequation_ellipsis_right()
    }

    fn parse_pequation_ellipsis_right(&mut self) -> PResult<PatternEquation> {
        let atomic = self.parse_pequation_atomic()?;
        if self.eat(TokenType::Ellipsis) {
            return Ok(PatternEquation::EllipsisRight(Box::new(atomic)));
        }
        Ok(atomic)
    }

    /// `pequation_atomic : constraint | ( pequation )`.
    fn parse_pequation_atomic(&mut self) -> PResult<PatternEquation> {
        if self.eat(TokenType::LParen) {
            let inner = self.parse_pequation()?;
            self.expect(TokenType::RParen, "')'")?;
            return Ok(PatternEquation::Parenthesized(Box::new(inner)));
        }
        // constraint : identifier (constraint_op pexpression2)?
        let symbol = self.parse_identifier()?;
        let op = match self.peek_ty() {
            TokenType::Assign => Some(ConstraintOp::Equal),
            TokenType::NotEqual => Some(ConstraintOp::NotEqual),
            TokenType::Less => Some(ConstraintOp::Less),
            TokenType::LessEqual => Some(ConstraintOp::LessEqual),
            TokenType::Great => Some(ConstraintOp::Great),
            TokenType::GreatEqual => Some(ConstraintOp::GreatEqual),
            _ => None,
        };
        let expr = if op.is_some() {
            self.bump();
            Some(self.parse_pexpression2()?)
        } else {
            None
        };
        Ok(PatternEquation::Constraint { symbol, op, expr })
    }

    // ----- pattern expressions ----------------------------------------------

    /// `pexpression` -- used in context blocks; allows `|`/`^`/`&` as well as
    /// the `$or`/`$xor`/`$and` spellings.
    pub fn parse_pexpression(&mut self) -> PResult<PExpression> {
        self.parse_pexpr_binary(0, false)
    }

    /// `pexpression2` -- used inside pattern constraints; only the
    /// `$or`/`$xor`/`$and` spellings are allowed for the logical operators
    /// (bare `&`/`|` would be ambiguous with the pattern operators).
    pub fn parse_pexpression2(&mut self) -> PResult<PExpression> {
        self.parse_pexpr_binary(0, true)
    }

    /// Precedence-climbing over the shared operator ladder. Level order
    /// (loosest first): or, xor, and, shift, add, mult.
    fn parse_pexpr_binary(&mut self, level: usize, constrained: bool) -> PResult<PExpression> {
        const LEVELS: usize = 6;
        if level >= LEVELS {
            return self.parse_pexpr_unary(constrained);
        }
        let mut lhs = self.parse_pexpr_binary(level + 1, constrained)?;
        loop {
            let op = match (level, self.peek_ty(), constrained) {
                (0, TokenType::SpecOr, _) => PExprBinOp::Or,
                (0, TokenType::Pipe, false) => PExprBinOp::Or,
                (1, TokenType::SpecXor, _) => PExprBinOp::Xor,
                (1, TokenType::Caret, false) => PExprBinOp::Xor,
                (2, TokenType::SpecAnd, _) => PExprBinOp::And,
                (2, TokenType::Ampersand, false) => PExprBinOp::And,
                (3, TokenType::Left, _) => PExprBinOp::Left,
                (3, TokenType::Right, _) => PExprBinOp::Right,
                (4, TokenType::Plus, _) => PExprBinOp::Add,
                (4, TokenType::Minus, _) => PExprBinOp::Sub,
                (5, TokenType::Asterisk, _) => PExprBinOp::Mult,
                (5, TokenType::Slash, _) => PExprBinOp::Div,
                _ => break,
            };
            self.bump();
            let rhs = self.parse_pexpr_binary(level + 1, constrained)?;
            lhs = PExpression::Binary {
                op,
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
            };
        }
        Ok(lhs)
    }

    fn parse_pexpr_unary(&mut self, constrained: bool) -> PResult<PExpression> {
        if self.eat(TokenType::Minus) {
            return Ok(PExpression::Unary {
                op: PExprUnaryOp::Negate,
                operand: Box::new(self.parse_pexpr_term(constrained)?),
            });
        }
        if self.eat(TokenType::Tilde) {
            return Ok(PExpression::Unary {
                op: PExprUnaryOp::Invert,
                operand: Box::new(self.parse_pexpr_term(constrained)?),
            });
        }
        // pexpression_func : apply | term
        if Self::is_identifier_like(self.peek_ty()) && self.peek_ty_at(1) == TokenType::LParen {
            let name = self.parse_identifier()?;
            let args = self.parse_pexpression_operands()?;
            return Ok(PExpression::Apply { name, args });
        }
        self.parse_pexpr_term(constrained)
    }

    fn parse_pexpr_term(&mut self, constrained: bool) -> PResult<PExpression> {
        match self.peek_ty() {
            TokenType::LParen => {
                self.bump();
                let inner = self.parse_pexpr_binary(0, constrained)?;
                self.expect(TokenType::RParen, "')'")?;
                Ok(inner)
            }
            TokenType::HexInt | TokenType::DefInt | TokenType::BinInt => {
                Ok(PExpression::Integer(self.parse_integer()?))
            }
            ty if Self::is_identifier_like(ty) => {
                Ok(PExpression::Identifier(self.parse_identifier()?))
            }
            _ => Err(self.err_here("expected expression term")),
        }
    }

    /// `pexpression_operands : ( (pexpression (, pexpression)*)? )`.
    fn parse_pexpression_operands(&mut self) -> PResult<Vec<PExpression>> {
        self.expect(TokenType::LParen, "'('")?;
        let mut args = Vec::new();
        if !self.at(TokenType::RParen) {
            args.push(self.parse_pexpression()?);
            while self.eat(TokenType::Comma) {
                args.push(self.parse_pexpression()?);
            }
        }
        self.expect(TokenType::RParen, "')'")?;
        Ok(args)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(input: &str) -> Spec {
        SleighParser::parse_str(input).unwrap()
    }

    #[test]
    fn endian_definition() {
        let spec = parse("define endian=little;");
        assert_eq!(spec.endian.endian, Endian::Little);
        assert!(spec.items.is_empty());
        let spec = parse("define endian=big;");
        assert_eq!(spec.endian.endian, Endian::Big);
    }

    #[test]
    fn missing_endian_is_error() {
        assert!(SleighParser::parse_str("define alignment=1;").is_err());
    }

    #[test]
    fn alignment_definition() {
        let spec = parse("define endian=little; define alignment=2;");
        match &spec.items[0] {
            SpecItem::Definition(Definition::Align(a)) => assert_eq!(a.alignment.value, 2),
            other => panic!("unexpected item: {other:?}"),
        }
    }

    #[test]
    fn space_definition_with_mods() {
        let spec = parse(
            "define endian=little; define space ram type=ram_space size=2 default;",
        );
        match &spec.items[0] {
            SpecItem::Definition(Definition::Space(s)) => {
                assert_eq!(s.name, "ram");
                assert_eq!(s.mods.len(), 3);
                assert!(matches!(&s.mods[0], SpaceMod::Type(t) if t == "ram_space"));
                assert!(matches!(&s.mods[1], SpaceMod::Size(i) if i.value == 2));
                assert!(matches!(&s.mods[2], SpaceMod::Default));
            }
            other => panic!("unexpected item: {other:?}"),
        }
    }

    #[test]
    fn varnode_definition() {
        let spec = parse(
            "define endian=little; define register offset=0x20 size=1 [ A_ F_ _ B_ ];",
        );
        match &spec.items[0] {
            SpecItem::Definition(Definition::Varnode(v)) => {
                assert_eq!(v.space, "register");
                assert_eq!(v.offset.value, 0x20);
                assert_eq!(v.size.value, 1);
                assert_eq!(v.names.len(), 4);
                assert_eq!(v.names[2], IdOrWild::Wildcard);
            }
            other => panic!("unexpected item: {other:?}"),
        }
    }

    #[test]
    fn token_definition_with_fields_and_mods() {
        let spec = parse(
            "define endian=little; \
             define token opbyte(8) op0_8 = (0,7) rp = (4,5) signed dec;",
        );
        match &spec.items[0] {
            SpecItem::Definition(Definition::Token(t)) => {
                assert_eq!(t.name, "opbyte");
                assert_eq!(t.size.value, 8);
                assert_eq!(t.endian, None);
                assert_eq!(t.fields.len(), 2);
                assert_eq!(t.fields[0].name, "op0_8");
                assert_eq!(t.fields[0].start.value, 0);
                assert_eq!(t.fields[0].end.value, 7);
                assert!(t.fields[0].mods.is_empty());
                assert_eq!(t.fields[1].mods, vec![FieldMod::Signed, FieldMod::Dec]);
            }
            other => panic!("unexpected item: {other:?}"),
        }
    }

    #[test]
    fn token_definition_with_endian() {
        let spec = parse(
            "define endian=little; define token t(16) endian=big f = (0,15);",
        );
        match &spec.items[0] {
            SpecItem::Definition(Definition::Token(t)) => {
                assert_eq!(t.endian, Some(Endian::Big));
                assert_eq!(t.fields.len(), 1);
            }
            other => panic!("unexpected item: {other:?}"),
        }
    }

    #[test]
    fn context_definition_with_noflow() {
        let spec = parse(
            "define endian=little; define context contextreg flag = (0,0) noflow;",
        );
        match &spec.items[0] {
            SpecItem::Definition(Definition::Context(c)) => {
                assert_eq!(c.varnode, "contextreg");
                assert_eq!(c.fields[0].mods, vec![FieldMod::Noflow]);
            }
            other => panic!("unexpected item: {other:?}"),
        }
    }

    #[test]
    fn bitrange_definition() {
        let spec = parse(
            "define endian=little; define bitrange zf=F[6,1] cf=F[0,1];",
        );
        match &spec.items[0] {
            SpecItem::Definition(Definition::Bitrange(b)) => {
                assert_eq!(b.bitranges.len(), 2);
                assert_eq!(b.bitranges[0].name, "zf");
                assert_eq!(b.bitranges[0].register, "F");
                assert_eq!(b.bitranges[0].start.value, 6);
                assert_eq!(b.bitranges[1].name, "cf");
            }
            other => panic!("unexpected item: {other:?}"),
        }
    }

    #[test]
    fn pcodeop_definition() {
        let spec = parse("define endian=little; define pcodeop readIRQ;");
        match &spec.items[0] {
            SpecItem::Definition(Definition::PcodeOp(p)) => {
                assert_eq!(p.names, vec![IdOrWild::Id("readIRQ".into())]);
            }
            other => panic!("unexpected item: {other:?}"),
        }
    }

    #[test]
    fn attach_variables() {
        let spec = parse(
            "define endian=little; attach variables [ r0 r1 ] [ A B ];",
        );
        match &spec.items[0] {
            SpecItem::Definition(Definition::VarAttach(v)) => {
                assert_eq!(v.fields.len(), 2);
                assert_eq!(v.registers.len(), 2);
            }
            other => panic!("unexpected item: {other:?}"),
        }
    }

    #[test]
    fn attach_values_with_negatives_and_wildcards() {
        let spec = parse(
            "define endian=little; attach values rp [ 0x10 _ -1 ];",
        );
        match &spec.items[0] {
            SpecItem::Definition(Definition::ValueAttach(v)) => {
                assert_eq!(
                    v.values,
                    vec![
                        IntBPart::Value(0x10),
                        IntBPart::Wildcard,
                        IntBPart::Value(-1)
                    ]
                );
            }
            other => panic!("unexpected item: {other:?}"),
        }
    }

    #[test]
    fn attach_names_with_strings() {
        let spec = parse(
            "define endian=little; attach names f [ \"x\" y ];",
        );
        match &spec.items[0] {
            SpecItem::Definition(Definition::NameAttach(n)) => {
                assert_eq!(n.names[0], StringOrIdent::String("x".into()));
                assert_eq!(
                    n.names[1],
                    StringOrIdent::IdOrWild(IdOrWild::Id("y".into()))
                );
            }
            other => panic!("unexpected item: {other:?}"),
        }
    }

    #[test]
    fn keyword_as_identifier() {
        // 'export' is a keyword but valid as a varnode-space identifier.
        let spec = parse(
            "define endian=little; define token t(8) f=(0,7); attach values export [ 1 ];",
        );
        match &spec.items[1] {
            SpecItem::Definition(Definition::ValueAttach(v)) => {
                assert_eq!(v.fields, vec![IdOrWild::Id("export".into())]);
            }
            other => panic!("unexpected item: {other:?}"),
        }
    }

    #[test]
    fn macro_definition() {
        let spec = parse("define endian=little; macro setflag(a, b) { a = b; }");
        match &spec.items[0] {
            SpecItem::Constructorlike(Constructorlike::Macro(m)) => {
                assert_eq!(m.name, "setflag");
                assert_eq!(m.args, vec!["a", "b"]);
                // macrodef bodies go through the same semanticbody rule as
                // constructors: typed p-code statements.
                assert_eq!(
                    m.body.statements,
                    vec![PcodeStmt::Assign {
                        local: false,
                        lvalue: Lvalue::Id("a".into()),
                        rhs: PcodeExpr::Identifier("b".into()),
                    }]
                );
            }
            other => panic!("unexpected item: {other:?}"),
        }
    }

    #[test]
    fn constructor_semantic_body_is_structured() {
        // The SEMANTIC mode must push at '{' and pop at '}' for each body;
        // signed comparison ops only lex inside the braces.
        let spec = parse(
            "define endian=little; \
             :NEG A is op=1 { A = -A; S_flag = (A s< 0); } \
             :CLR A is op=2 { A = 0; }",
        );
        let bodies: Vec<_> = spec
            .items
            .iter()
            .map(|i| match i {
                SpecItem::Constructorlike(Constructorlike::Constructor(c)) => match &c.semantic {
                    CtorSemantic::Body(b) => b,
                    other => panic!("unexpected semantic: {other:?}"),
                },
                other => panic!("unexpected item: {other:?}"),
            })
            .collect();
        assert_eq!(bodies[0].statements.len(), 2);
        match &bodies[0].statements[1] {
            PcodeStmt::Assign { rhs, .. } => match rhs {
                PcodeExpr::Parenthesized(inner) => {
                    assert!(matches!(
                        **inner,
                        PcodeExpr::Binary {
                            op: PcodeBinOp::SLess,
                            ..
                        }
                    ));
                }
                other => panic!("unexpected rhs: {other:?}"),
            },
            other => panic!("unexpected stmt: {other:?}"),
        }
        assert_eq!(bodies[1].statements.len(), 1);
    }

    #[test]
    fn semantic_body_reserves_if_but_only_inside_braces() {
        // 'if' is an ordinary identifier in base mode (e.g. a table name)
        // but reserved inside a semantic body.
        let spec = parse(
            "define endian=little; :BR rel is op=3 { if (Z_flag) goto rel; }",
        );
        match &spec.items[0] {
            SpecItem::Constructorlike(Constructorlike::Constructor(c)) => match &c.semantic {
                CtorSemantic::Body(b) => {
                    assert!(matches!(b.statements[0], PcodeStmt::IfGoto { .. }));
                }
                other => panic!("unexpected semantic: {other:?}"),
            },
            other => panic!("unexpected item: {other:?}"),
        }
    }

    #[test]
    fn semantic_parse_error_propagates() {
        let err = SleighParser::parse_str(
            "define endian=little; :X is op=1 { A = ; }",
        )
        .unwrap_err();
        assert!(err.message.contains("expected"), "{err}");
    }

    #[test]
    fn root_constructor() {
        let spec = parse(
            "define endian=little; :ret is op=0x9 { return [0]; }",
        );
        match &spec.items[0] {
            SpecItem::Constructorlike(Constructorlike::Constructor(c)) => {
                assert_eq!(c.table, None);
                assert_eq!(
                    c.display.pieces,
                    vec![
                        PrintPiece::Identifier("ret".into()),
                        PrintPiece::Whitespace(" ".into()),
                    ]
                );
                match &c.pattern {
                    PatternEquation::Constraint { symbol, op, expr } => {
                        assert_eq!(symbol, "op");
                        assert_eq!(*op, Some(ConstraintOp::Equal));
                        assert!(matches!(
                            expr,
                            Some(PExpression::Integer(Integer { value: 9, .. }))
                        ));
                    }
                    other => panic!("unexpected pattern: {other:?}"),
                }
                assert!(matches!(c.semantic, CtorSemantic::Body(_)));
            }
            other => panic!("unexpected item: {other:?}"),
        }
    }

    #[test]
    fn subtable_constructor_with_and_pattern() {
        let spec = parse(
            "define endian=little; mode: \"m\" is op=0x1 & rd { }",
        );
        match &spec.items[0] {
            SpecItem::Constructorlike(Constructorlike::Constructor(c)) => {
                assert_eq!(c.table.as_deref(), Some("mode"));
                assert!(matches!(c.pattern, PatternEquation::And(_, _)));
                // Leading whitespace and the quoted string are printpieces.
                assert_eq!(
                    c.display.pieces,
                    vec![
                        PrintPiece::Whitespace(" ".into()),
                        PrintPiece::QString("m".into()),
                        PrintPiece::Whitespace(" ".into()),
                    ]
                );
            }
            other => panic!("unexpected item: {other:?}"),
        }
    }

    #[test]
    fn unimpl_constructor() {
        let spec = parse("define endian=little; :halt is op=0x0 unimpl");
        match &spec.items[0] {
            SpecItem::Constructorlike(Constructorlike::Constructor(c)) => {
                assert!(matches!(c.semantic, CtorSemantic::Unimpl));
            }
            other => panic!("unexpected item: {other:?}"),
        }
    }

    #[test]
    fn constructor_with_context_block() {
        let spec = parse(
            "define endian=little; :op is a=1 [ ctx=2; call(3); ] { }",
        );
        match &spec.items[0] {
            SpecItem::Constructorlike(Constructorlike::Constructor(c)) => {
                assert_eq!(c.context.len(), 2);
                assert!(matches!(&c.context[0], ContextStmt::Assign { lhs, .. } if lhs == "ctx"));
                assert!(
                    matches!(&c.context[1], ContextStmt::Funcall { name, args } if name == "call" && args.len() == 1)
                );
            }
            other => panic!("unexpected item: {other:?}"),
        }
    }

    #[test]
    fn pattern_sequence_and_ellipsis() {
        let spec = parse(
            "define endian=little; :two is op=1; imm8 ... { }",
        );
        match &spec.items[0] {
            SpecItem::Constructorlike(Constructorlike::Constructor(c)) => match &c.pattern {
                PatternEquation::Sequence(_, rhs) => {
                    assert!(matches!(**rhs, PatternEquation::EllipsisRight(_)));
                }
                other => panic!("unexpected pattern: {other:?}"),
            },
            other => panic!("unexpected item: {other:?}"),
        }
    }

    #[test]
    fn with_block_nests_constructors() {
        let spec = parse(
            "define endian=little; with sub: op=2 [ ] { :nop is rd { } define pcodeop x; }",
        );
        match &spec.items[0] {
            SpecItem::Constructorlike(Constructorlike::With(w)) => {
                assert_eq!(w.table.as_deref(), Some("sub"));
                assert!(w.pattern.is_some());
                assert_eq!(w.body.len(), 2);
                assert!(matches!(
                    w.body[0],
                    SpecItem::Constructorlike(Constructorlike::Constructor(_))
                ));
                assert!(matches!(w.body[1], SpecItem::Definition(_)));
            }
            other => panic!("unexpected item: {other:?}"),
        }
    }

    #[test]
    fn pexpression_precedence() {
        // ctx = 1 + 2 * 3 => Add(1, Mult(2, 3))
        let spec = parse(
            "define endian=little; :op is a=1 [ ctx = 1 + 2 * 3; ] { }",
        );
        match &spec.items[0] {
            SpecItem::Constructorlike(Constructorlike::Constructor(c)) => {
                match &c.context[0] {
                    ContextStmt::Assign { rhs, .. } => match rhs {
                        PExpression::Binary { op, rhs, .. } => {
                            assert_eq!(*op, PExprBinOp::Add);
                            assert!(matches!(
                                **rhs,
                                PExpression::Binary {
                                    op: PExprBinOp::Mult,
                                    ..
                                }
                            ));
                        }
                        other => panic!("unexpected expr: {other:?}"),
                    },
                    other => panic!("unexpected stmt: {other:?}"),
                }
            }
            other => panic!("unexpected item: {other:?}"),
        }
    }

    #[test]
    fn constraint_uses_dollar_ops_only() {
        // In a constraint expression, '&' belongs to the pattern, not the
        // expression: a=1&b must parse as And(a=1, b).
        let spec = parse("define endian=little; :op is a=1&b { }");
        match &spec.items[0] {
            SpecItem::Constructorlike(Constructorlike::Constructor(c)) => {
                assert!(matches!(c.pattern, PatternEquation::And(_, _)));
            }
            other => panic!("unexpected item: {other:?}"),
        }
    }

    #[test]
    fn skeleton_slaspec_prefix_parses() {
        // Preprocessed equivalent of the top of skel.slaspec.
        let spec = parse(
            "define endian=little;\n\
             define alignment=1;\n\
             define space ram type=ram_space size=2 default;\n\
             define space io type=ram_space size=2;\n\
             define space register type=register_space size=1;\n\
             define register offset=0x00 size=1 [ F A C B E D L H I R ];\n\
             define register offset=0xf0 size=4 contextreg;\n\
             define context contextreg assume8bitIOSpace = (0,0);\n",
        );
        assert_eq!(spec.items.len(), 7);
    }

    #[test]
    fn parse_error_carries_line() {
        let err = SleighParser::parse_str("define endian=little; define alignment 2;")
            .unwrap_err();
        assert!(err.message.contains("expected"), "{err}");
        assert_eq!(err.line, 1);
    }

    // ----- display sections (DisplayParser.g) -------------------------------

    use PrintPiece::*;

    fn pieces(src: &str) -> Vec<PrintPiece> {
        let spec = parse(src);
        match &spec.items[0] {
            SpecItem::Constructorlike(Constructorlike::Constructor(c)) => {
                c.display.pieces.clone()
            }
            other => panic!("unexpected item: {other:?}"),
        }
    }

    #[test]
    fn display_literal_only() {
        assert_eq!(
            pieces("define endian=little; :nop is op=0 { }"),
            vec![Identifier("nop".into()), Whitespace(" ".into())]
        );
    }

    #[test]
    fn display_symbols_and_punctuation() {
        assert_eq!(
            pieces("define endian=little; :MOV r1,r2 is op=0 { }"),
            vec![
                Identifier("MOV".into()),
                Whitespace(" ".into()),
                Identifier("r1".into()),
                Literal(",".into()),
                Identifier("r2".into()),
                Whitespace(" ".into()),
            ]
        );
    }

    #[test]
    fn display_caret_concatenation() {
        // '^' joins adjacent pieces with no separating whitespace and is
        // itself not printed.
        assert_eq!(
            pieces("define endian=little; :J^cc addr is op=0 { }"),
            vec![
                Identifier("J".into()),
                Concatenate,
                Identifier("cc".into()),
                Whitespace(" ".into()),
                Identifier("addr".into()),
                Whitespace(" ".into()),
            ]
        );
    }

    #[test]
    fn display_whitespace_runs_are_preserved() {
        assert_eq!(
            pieces("define endian=little; :A  B \t C is op=0 { }"),
            vec![
                Identifier("A".into()),
                Whitespace("  ".into()),
                Identifier("B".into()),
                Whitespace(" \t ".into()),
                Identifier("C".into()),
                Whitespace(" ".into()),
            ]
        );
    }

    #[test]
    fn display_special_characters() {
        // '@', '$', '?' (DISPCHAR) and '#' (overridden LINECOMMENT) are
        // literal pieces; '#' does not start a comment in display mode.
        assert_eq!(
            pieces("define endian=little; :LD #imm @$? is op=0 { }"),
            vec![
                Identifier("LD".into()),
                Whitespace(" ".into()),
                Literal("#".into()),
                Identifier("imm".into()),
                Whitespace(" ".into()),
                Literal("@".into()),
                Literal("$".into()),
                Literal("?".into()),
                Whitespace(" ".into()),
            ]
        );
    }

    #[test]
    fn display_numbers_and_operators_print_verbatim() {
        assert_eq!(
            pieces("define endian=little; :X (0x1f+2) is op=0 { }"),
            vec![
                Identifier("X".into()),
                Whitespace(" ".into()),
                Literal("(".into()),
                Literal("0x1f".into()),
                Literal("+".into()),
                Literal("2".into()),
                Literal(")".into()),
                Whitespace(" ".into()),
            ]
        );
    }

    #[test]
    fn display_keywords_are_identifier_pieces() {
        // key_as_id: grammar keywords are ordinary identifiers in a display.
        assert_eq!(
            pieces("define endian=little; :token export is op=0 { }"),
            vec![
                Identifier("token".into()),
                Whitespace(" ".into()),
                Identifier("export".into()),
                Whitespace(" ".into()),
            ]
        );
    }

    #[test]
    fn display_is_terminator_needs_word_boundary() {
        // 'disp' and 'isle' contain 'is' but do not terminate the display.
        assert_eq!(
            pieces("define endian=little; :disp isle is op=0 { }"),
            vec![
                Identifier("disp".into()),
                Whitespace(" ".into()),
                Identifier("isle".into()),
                Whitespace(" ".into()),
            ]
        );
    }

    #[test]
    fn display_leading_whitespace_only() {
        // ': is ...' -- an empty mnemonic is grammatically fine; the lone
        // whitespace run is still a piece.
        assert_eq!(
            pieces("define endian=little; : is op=0 { }"),
            vec![Whitespace(" ".into())]
        );
    }

    #[test]
    fn display_without_is_errors() {
        let err =
            SleighParser::parse_str("define endian=little; :halt op=0 { }").unwrap_err();
        assert!(err.message.contains("'is'"), "{err}");
    }

    #[test]
    fn display_rejects_non_printpieces() {
        // UNDERSCORE and DEC_INT are not printpiece alternatives in
        // DisplayParser.g.
        let err = SleighParser::parse_str("define endian=little; :X _ is op=0 { }")
            .unwrap_err();
        assert!(err.message.contains("not valid"), "{err}");
        let err = SleighParser::parse_str("define endian=little; :X 0n5 is op=0 { }")
            .unwrap_err();
        assert!(err.message.contains("not valid"), "{err}");
    }

    #[test]
    fn display_mode_ends_at_is_for_each_constructor() {
        // Two constructors back to back: mode must pop back to base after
        // each 'is' (patterns lex base-mode) and push again at the next ':'.
        let spec = parse(
            "define endian=little; :INC r1 is op=0x4 { } :DEC r1 is op=0x5 { }",
        );
        assert_eq!(spec.items.len(), 2);
        for (i, mnemonic) in ["INC", "DEC"].iter().enumerate() {
            match &spec.items[i] {
                SpecItem::Constructorlike(Constructorlike::Constructor(c)) => {
                    assert_eq!(
                        c.display.pieces[0],
                        Identifier((*mnemonic).to_string())
                    );
                }
                other => panic!("unexpected item: {other:?}"),
            }
        }
    }

    #[test]
    fn display_inside_with_block() {
        // The with-block ':' is NOT a display; only constructor ':' switches
        // the lexer mode.
        let spec = parse(
            "define endian=little; with sub: op=2 [ ] { :nop^\"!\" is rd { } }",
        );
        match &spec.items[0] {
            SpecItem::Constructorlike(Constructorlike::With(w)) => match &w.body[0] {
                SpecItem::Constructorlike(Constructorlike::Constructor(c)) => {
                    assert_eq!(
                        c.display.pieces,
                        vec![
                            Identifier("nop".into()),
                            Concatenate,
                            QString("!".into()),
                            Whitespace(" ".into()),
                        ]
                    );
                }
                other => panic!("unexpected item: {other:?}"),
            },
            other => panic!("unexpected item: {other:?}"),
        }
    }
}

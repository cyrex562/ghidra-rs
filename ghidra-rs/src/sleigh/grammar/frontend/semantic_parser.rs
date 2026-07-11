//! Recursive-descent parser for the p-code semantic bodies of SLEIGH
//! constructors and macros (`SemanticParser.g`), producing the typed
//! statement AST in [`super::ast`] ([`SemanticBody`], [`PcodeStmt`],
//! [`PcodeExpr`]).
//!
//! The top-level parser ([`super::parser::SleighParser`]) consumes the
//! opening `{` in base mode, then hands the shared [`BaseLexer`] cursor to
//! [`SemanticParser`], which pulls every further token through the SEMANTIC
//! sub-lexer mode ([`super::semantic_lexer::SemanticLexer`]) up to and
//! including the closing `}` -- the Rust equivalent of `SemanticParser.g`'s
//!
//! ```text
//! semanticbody
//!     : LBRACE { lexer.pushMode(SEMANTIC); } semantic RBRACE { lexer.popMode(); }
//!     ;
//! ```
//!
//! Statement and expression rule structure and the operator-precedence
//! ladder follow SemanticParser.g exactly (rule names noted per method).
//! One deliberate divergence: ANTLR's LL(*) can see through a keyword used
//! as an identifier at statement start (e.g. an operand named `call` being
//! assigned); this port approximates that with two-token lookahead --
//! keyword-led statement forms yield to the assignment/funcall path when the
//! keyword is immediately followed by `=` or `(`.
//!
//! // TODO(sleigh-frontend): deeper keyword-as-identifier statement starts
//! // (e.g. `call:2 = ...` or `goto[0,3] = ...`) are not disambiguated; no
//! // shipped spec relies on them.

use crate::sleigh::grammar::SleighToken;

use super::ast::*;
use super::lexer::{BaseLexer, TokenType};
use super::parser::{ParseError, SleighParser};
use super::semantic_lexer::SemanticLexer;

type PResult<T> = Result<T, ParseError>;

/// Parser for one `{ ... }` semantic section, pulling SEMANTIC-mode tokens
/// on demand from the shared base-lexer cursor. The opening `{` must already
/// have been consumed (in base mode) by the caller; [`Self::parse_semantic`]
/// consumes through the matching `}`.
pub struct SemanticParser<'a> {
    lexer: &'a mut BaseLexer,
    /// SEMANTIC-mode default-channel tokens buffered for lookahead; only
    /// ever filled as far as `peek`/`peek_ty_at` require, so no token is
    /// lexed in SEMANTIC mode past the closing `}`.
    tokens: Vec<SleighToken>,
    pos: usize,
}

impl<'a> SemanticParser<'a> {
    pub fn new(lexer: &'a mut BaseLexer) -> Self {
        Self {
            lexer,
            tokens: Vec::new(),
            pos: 0,
        }
    }

    // ----- token utilities (SEMANTIC-mode pulls) ----------------------------

    /// Ensures the lookahead buffer holds a token at `pos + n` (or ends with
    /// EOF), pulling SEMANTIC-mode default-channel tokens as needed.
    fn ensure(&mut self, n: usize) {
        while self.tokens.len() <= self.pos + n {
            if let Some(last) = self.tokens.last() {
                if last.token_type() == TokenType::Eof.as_i32() {
                    return;
                }
            }
            loop {
                let t = SemanticLexer::new(self.lexer).next_token();
                // Hidden/comment/preproc channels stay invisible, as in the
                // base mode.
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

    fn err_here(&mut self, message: impl Into<String>) -> ParseError {
        let t = self.peek();
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

    /// `identifier : strict_id | key_as_id` -- as in the top-level parser,
    /// any keyword may be used as an identifier in a semantic body.
    fn parse_identifier(&mut self) -> PResult<String> {
        if SleighParser::is_identifier_like(self.peek_ty()) {
            let t = self.bump();
            Ok(t.text().unwrap_or("").to_string())
        } else {
            Err(self.err_here("expected identifier"))
        }
    }

    /// `integer : HEX_INT | DEF_INT | BIN_INT` (also used for `constant`).
    fn parse_integer(&mut self) -> PResult<Integer> {
        let ty = self.peek_ty();
        let (radix, skip) = match ty {
            TokenType::HexInt => (16, 2),
            TokenType::BinInt => (2, 2),
            TokenType::DefInt => (10, 0),
            _ => return Err(self.err_here("expected integer")),
        };
        self.lit_from(radix, skip)
    }

    /// `int_lit : HEX_INT | DEC_INT | BIN_INT | DEF_INT` -- unlike
    /// `integer`/`constant`, this also admits the `0n` decimal form.
    fn parse_int_lit(&mut self) -> PResult<Integer> {
        let ty = self.peek_ty();
        let (radix, skip) = match ty {
            TokenType::HexInt => (16, 2),
            TokenType::BinInt => (2, 2),
            TokenType::DecInt => (10, 2),
            TokenType::DefInt => (10, 0),
            _ => return Err(self.err_here("expected integer literal")),
        };
        self.lit_from(radix, skip)
    }

    fn lit_from(&mut self, radix: u32, skip: usize) -> PResult<Integer> {
        let t = self.bump();
        let text = t.text().unwrap_or("");
        // TODO(sleigh-frontend): the Java front-end carries these as
        // RadixBigInteger; i64 covers real specs so far (see ast::Integer).
        let value = i64::from_str_radix(&text[skip..], radix).map_err(|e| ParseError {
            message: format!("invalid integer literal '{text}': {e}"),
            line: t.line(),
            location: t.location().cloned(),
        })?;
        Ok(Integer { value, radix })
    }

    /// `constant : integer`.
    fn parse_constant(&mut self) -> PResult<Integer> {
        self.parse_integer()
    }

    // ----- semantic / statements --------------------------------------------

    /// `semantic : code_block` with `code_block : statements |` (empty is
    /// `OP_NOP`); consumes the closing `}` (SemanticParser.g pops the lexer
    /// mode right after it).
    pub fn parse_semantic(&mut self) -> PResult<SemanticBody> {
        let mut statements = Vec::new();
        loop {
            match self.peek_ty() {
                TokenType::RBrace => {
                    self.bump();
                    // The mode "pop" is implicit: all buffered SEMANTIC-mode
                    // tokens must have been consumed, so the next base-mode
                    // pull continues at the shared cursor.
                    if self.pos != self.tokens.len() {
                        return Err(self.err_here(
                            "internal error: semantic-mode lookahead crossed the closing '}'",
                        ));
                    }
                    return Ok(SemanticBody { statements });
                }
                TokenType::Eof => return Err(self.err_here("unterminated semantic body")),
                _ => statements.push(self.parse_statement()?),
            }
        }
    }

    /// `statement` -- all alternatives, including the empty-statement bail
    /// and (as hard errors) the `outererror` recovery alternative.
    fn parse_statement(&mut self) -> PResult<PcodeStmt> {
        let ty = self.peek_ty();

        // label and section_def take no ';'.
        if ty == TokenType::Less {
            self.bump();
            let name = self.parse_identifier()?;
            self.expect(TokenType::Great, "'>' closing label")?;
            return Ok(PcodeStmt::Label { name });
        }
        if ty == TokenType::Left {
            self.bump();
            let name = self.parse_identifier()?;
            self.expect(TokenType::Right, "'>>' closing section label")?;
            return Ok(PcodeStmt::SectionLabel { name });
        }
        if ty == TokenType::Semi {
            // The grammar's `bail("Empty statement at ...")`.
            return Err(self.err_here("empty statement"));
        }

        // Keyword-led statement forms -- unless the keyword is being used as
        // an identifier lvalue/funcall (see module note).
        let next = self.peek_ty_at(1);
        let keyword_led = !matches!(next, TokenType::Assign | TokenType::LParen);
        let stmt = if keyword_led && ty == TokenType::KeyLocal {
            self.parse_local_stmt()?
        } else if keyword_led && ty == TokenType::KeyBuild {
            self.bump();
            PcodeStmt::Build {
                operand: self.parse_identifier()?,
            }
        } else if keyword_led && ty == TokenType::KeyCrossbuild {
            self.bump();
            let address = self.parse_varnode()?;
            self.expect(TokenType::Comma, "','")?;
            let section = self.parse_identifier()?;
            PcodeStmt::CrossBuild { address, section }
        } else if keyword_led && ty == TokenType::KeyGoto {
            self.bump();
            PcodeStmt::Goto {
                dest: self.parse_jumpdest()?,
            }
        } else if ty == TokenType::ResIf {
            // `cond_stmt : RES_IF expr goto_stmt` ('if' is fully reserved in
            // SEMANTIC mode, so no identifier fallback applies).
            self.bump();
            let cond = self.parse_expr()?;
            self.expect(TokenType::KeyGoto, "'goto' after if condition")?;
            let dest = self.parse_jumpdest()?;
            PcodeStmt::IfGoto { cond, dest }
        } else if keyword_led && ty == TokenType::KeyCall {
            self.bump();
            PcodeStmt::Call {
                dest: self.parse_jumpdest()?,
            }
        } else if keyword_led && ty == TokenType::KeyExport {
            self.bump();
            let export = if self.at(TokenType::Asterisk) {
                // `sizedexport : sizedstar identifier`
                let star = self.parse_sizedstar()?;
                let name = self.parse_identifier()?;
                Export::Sized { star, name }
            } else {
                Export::Varnode(self.parse_varnode()?)
            };
            PcodeStmt::Export(export)
        } else if keyword_led && ty == TokenType::KeyReturn {
            self.bump();
            self.expect(TokenType::LBracket, "'[' after 'return'")?;
            let dest = self.parse_expr()?;
            self.expect(TokenType::RBracket, "']'")?;
            PcodeStmt::Return { dest }
        } else if ty == TokenType::Asterisk {
            // `assignment : lvalue = expr` with `lvalue : sizedstar expr`.
            let star = self.parse_sizedstar()?;
            let addr = self.parse_expr()?;
            self.expect(TokenType::Assign, "'=' in dereference assignment")?;
            let rhs = self.parse_expr()?;
            PcodeStmt::Assign {
                local: false,
                lvalue: Lvalue::Deref { star, addr },
                rhs,
            }
        } else if SleighParser::is_identifier_like(ty) {
            self.parse_ident_led_stmt()?
        } else {
            // `outererror`: a stray operator/punctuation token. The grammar
            // reports it and resynchronizes; this port treats it as a hard
            // error.
            let found = self.peek().text().unwrap_or("<?>").to_string();
            return Err(self.err_here(format!("unexpected '{found}' at start of statement")));
        };
        self.expect(TokenType::Semi, "';'")?;
        Ok(stmt)
    }

    /// `assignment : KEY_LOCAL lvalue = expr` and
    /// `declaration : KEY_LOCAL <id> (: <size>)?`.
    fn parse_local_stmt(&mut self) -> PResult<PcodeStmt> {
        self.bump(); // local
        if self.at(TokenType::Asterisk) {
            let star = self.parse_sizedstar()?;
            let addr = self.parse_expr()?;
            self.expect(TokenType::Assign, "'='")?;
            let rhs = self.parse_expr()?;
            return Ok(PcodeStmt::Assign {
                local: true,
                lvalue: Lvalue::Deref { star, addr },
                rhs,
            });
        }
        let name = self.parse_identifier()?;
        match self.peek_ty() {
            TokenType::LBracket => {
                let lvalue = self.parse_sembitrange_rest(name)?;
                self.expect(TokenType::Assign, "'='")?;
                let rhs = self.parse_expr()?;
                Ok(PcodeStmt::Assign {
                    local: true,
                    lvalue,
                    rhs,
                })
            }
            TokenType::Colon => {
                self.bump();
                let size = self.parse_constant()?;
                if self.eat(TokenType::Assign) {
                    let rhs = self.parse_expr()?;
                    Ok(PcodeStmt::Assign {
                        local: true,
                        lvalue: Lvalue::SizedId { name, size },
                        rhs,
                    })
                } else {
                    Ok(PcodeStmt::LocalDecl {
                        name,
                        size: Some(size),
                    })
                }
            }
            TokenType::Assign => {
                self.bump();
                let rhs = self.parse_expr()?;
                Ok(PcodeStmt::Assign {
                    local: true,
                    lvalue: Lvalue::Id(name),
                    rhs,
                })
            }
            _ => Ok(PcodeStmt::LocalDecl { name, size: None }),
        }
    }

    /// Statements starting with an identifier: `assignment` (plain, sized,
    /// or bitrange lvalue) or `funcall : expr_apply`.
    fn parse_ident_led_stmt(&mut self) -> PResult<PcodeStmt> {
        let name = self.parse_identifier()?;
        match self.peek_ty() {
            TokenType::LParen => {
                let args = self.parse_operands()?;
                Ok(PcodeStmt::Funcall { name, args })
            }
            TokenType::LBracket => {
                let lvalue = self.parse_sembitrange_rest(name)?;
                self.expect(TokenType::Assign, "'='")?;
                let rhs = self.parse_expr()?;
                Ok(PcodeStmt::Assign {
                    local: false,
                    lvalue,
                    rhs,
                })
            }
            TokenType::Colon => {
                self.bump();
                let size = self.parse_constant()?;
                self.expect(TokenType::Assign, "'=' after sized lvalue")?;
                let rhs = self.parse_expr()?;
                Ok(PcodeStmt::Assign {
                    local: false,
                    lvalue: Lvalue::SizedId { name, size },
                    rhs,
                })
            }
            TokenType::Assign => {
                self.bump();
                let rhs = self.parse_expr()?;
                Ok(PcodeStmt::Assign {
                    local: false,
                    lvalue: Lvalue::Id(name),
                    rhs,
                })
            }
            _ => Err(self.err_here("expected '=', ':', '[', or '(' in statement")),
        }
    }

    /// `sembitrange : <id> [ <lsb> , <size> ]`, identifier already consumed.
    fn parse_sembitrange_rest(&mut self, name: String) -> PResult<Lvalue> {
        self.expect(TokenType::LBracket, "'['")?;
        let lsb = self.parse_constant()?;
        self.expect(TokenType::Comma, "','")?;
        let size = self.parse_constant()?;
        self.expect(TokenType::RBracket, "']'")?;
        Ok(Lvalue::BitRange { name, lsb, size })
    }

    /// `sizedstar : * ([<space>])? (: <size>)?`.
    fn parse_sizedstar(&mut self) -> PResult<SizedStar> {
        self.expect(TokenType::Asterisk, "'*'")?;
        let space = if self.eat(TokenType::LBracket) {
            let id = self.parse_identifier()?;
            self.expect(TokenType::RBracket, "']'")?;
            Some(id)
        } else {
            None
        };
        let size = if self.eat(TokenType::Colon) {
            Some(self.parse_constant()?)
        } else {
            None
        };
        Ok(SizedStar { space, size })
    }

    /// `jumpdest`.
    fn parse_jumpdest(&mut self) -> PResult<JumpDest> {
        match self.peek_ty() {
            TokenType::Less => {
                self.bump();
                let name = self.parse_identifier()?;
                self.expect(TokenType::Great, "'>' closing label")?;
                Ok(JumpDest::Label(name))
            }
            TokenType::LBracket => {
                self.bump();
                let expr = self.parse_expr()?;
                self.expect(TokenType::RBracket, "']'")?;
                Ok(JumpDest::Dynamic(expr))
            }
            TokenType::HexInt | TokenType::BinInt | TokenType::DefInt => {
                let offset = self.parse_integer()?;
                if self.eat(TokenType::LBracket) {
                    let space = self.parse_identifier()?;
                    self.expect(TokenType::RBracket, "']'")?;
                    Ok(JumpDest::Relative { offset, space })
                } else {
                    Ok(JumpDest::Absolute(offset))
                }
            }
            ty if SleighParser::is_identifier_like(ty) => {
                Ok(JumpDest::Symbol(self.parse_identifier()?))
            }
            _ => Err(self.err_here("expected jump destination")),
        }
    }

    // ----- expressions -------------------------------------------------------

    /// `expr : expr_boolor` -- the full operator ladder via precedence
    /// climbing; level order matches SemanticParser.g (loosest first):
    /// boolor, booland (`&&`/`^^`), or, xor, and, eq, comp, shift, add, mult.
    pub fn parse_expr(&mut self) -> PResult<PcodeExpr> {
        self.parse_expr_level(0)
    }

    fn parse_expr_level(&mut self, level: usize) -> PResult<PcodeExpr> {
        const LEVELS: usize = 10;
        if level >= LEVELS {
            return self.parse_expr_unary();
        }
        let mut lhs = self.parse_expr_level(level + 1)?;
        loop {
            use PcodeBinOp::*;
            use TokenType as T;
            let op = match (level, self.peek_ty()) {
                (0, T::BoolOr) => BoolOr,
                (1, T::BoolAnd) => BoolAnd,
                (1, T::BoolXor) => BoolXor,
                (2, T::Pipe) => Or,
                (3, T::Caret) => Xor,
                (4, T::Ampersand) => And,
                (5, T::Equal) => Equal,
                (5, T::NotEqual) => NotEqual,
                (5, T::FEqual) => FEqual,
                (5, T::FNotEqual) => FNotEqual,
                (6, T::Less) => Less,
                (6, T::GreatEqual) => GreatEqual,
                (6, T::LessEqual) => LessEqual,
                (6, T::Great) => Great,
                (6, T::SLess) => SLess,
                (6, T::SGreatEqual) => SGreatEqual,
                (6, T::SLessEqual) => SLessEqual,
                (6, T::SGreat) => SGreat,
                (6, T::FLess) => FLess,
                (6, T::FGreatEqual) => FGreatEqual,
                (6, T::FLessEqual) => FLessEqual,
                (6, T::FGreat) => FGreat,
                (7, T::Left) => Left,
                (7, T::Right) => Right,
                (7, T::SRight) => SRight,
                (8, T::Plus) => Add,
                (8, T::Minus) => Sub,
                (8, T::FPlus) => FAdd,
                (8, T::FMinus) => FSub,
                (9, T::Asterisk) => Mult,
                (9, T::Slash) => Div,
                (9, T::Percent) => Rem,
                (9, T::SDiv) => SDiv,
                (9, T::SRem) => SRem,
                (9, T::FMult) => FMult,
                (9, T::FDiv) => FDiv,
                _ => break,
            };
            self.bump();
            let rhs = self.parse_expr_level(level + 1)?;
            lhs = PcodeExpr::Binary {
                op,
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
            };
        }
        Ok(lhs)
    }

    /// `expr_unary : unary_op? expr_func` -- at most ONE unary operator, as
    /// in the grammar (`-(-x)` needs parentheses).
    fn parse_expr_unary(&mut self) -> PResult<PcodeExpr> {
        let op = match self.peek_ty() {
            TokenType::Exclaim => Some(PcodeUnaryOp::Not),
            TokenType::Tilde => Some(PcodeUnaryOp::Invert),
            TokenType::Minus => Some(PcodeUnaryOp::Negate),
            TokenType::FMinus => Some(PcodeUnaryOp::FNegate),
            TokenType::Asterisk => {
                // `unary_op : sizedstar` -- pointer load.
                let star = self.parse_sizedstar()?;
                let operand = self.parse_expr_func()?;
                return Ok(PcodeExpr::Deref {
                    star,
                    operand: Box::new(operand),
                });
            }
            _ => None,
        };
        if let Some(op) = op {
            self.bump();
            let operand = self.parse_expr_func()?;
            return Ok(PcodeExpr::Unary {
                op,
                operand: Box::new(operand),
            });
        }
        self.parse_expr_func()
    }

    /// `expr_func : expr_apply | expr_term`.
    fn parse_expr_func(&mut self) -> PResult<PcodeExpr> {
        if SleighParser::is_identifier_like(self.peek_ty())
            && self.peek_ty_at(1) == TokenType::LParen
        {
            let name = self.parse_identifier()?;
            let args = self.parse_operands()?;
            return Ok(PcodeExpr::Apply { name, args });
        }
        self.parse_expr_term()
    }

    /// `expr_operands : ( (expr (, expr)*)? )`.
    fn parse_operands(&mut self) -> PResult<Vec<PcodeExpr>> {
        self.expect(TokenType::LParen, "'('")?;
        let mut args = Vec::new();
        if !self.at(TokenType::RParen) {
            args.push(self.parse_expr()?);
            while self.eat(TokenType::Comma) {
                args.push(self.parse_expr()?);
            }
        }
        self.expect(TokenType::RParen, "')'")?;
        Ok(args)
    }

    /// `expr_term : varnode | sembitrange | ( expr )`.
    fn parse_expr_term(&mut self) -> PResult<PcodeExpr> {
        let ty = self.peek_ty();
        if ty == TokenType::LParen {
            self.bump();
            let inner = self.parse_expr()?;
            self.expect(TokenType::RParen, "')'")?;
            return Ok(PcodeExpr::Parenthesized(Box::new(inner)));
        }
        if SleighParser::is_identifier_like(ty) && self.peek_ty_at(1) == TokenType::LBracket {
            // `sembitrange : <id> [ <lsb> , <size> ]`
            let name = self.parse_identifier()?;
            match self.parse_sembitrange_rest(name)? {
                Lvalue::BitRange { name, lsb, size } => {
                    return Ok(PcodeExpr::BitRange { name, lsb, size })
                }
                _ => unreachable!("parse_sembitrange_rest only builds BitRange"),
            }
        }
        self.parse_varnode()
    }

    /// `varnode` (recursive through `&`).
    fn parse_varnode(&mut self) -> PResult<PcodeExpr> {
        match self.peek_ty() {
            TokenType::Ampersand => {
                self.bump();
                let size = if self.eat(TokenType::Colon) {
                    Some(self.parse_constant()?)
                } else {
                    None
                };
                let operand = self.parse_varnode()?;
                Ok(PcodeExpr::AddressOf {
                    size,
                    operand: Box::new(operand),
                })
            }
            TokenType::HexInt | TokenType::BinInt | TokenType::DecInt | TokenType::DefInt => {
                let value = self.parse_int_lit()?;
                if self.eat(TokenType::Colon) {
                    let size = self.parse_constant()?;
                    Ok(PcodeExpr::Truncation { value, size })
                } else {
                    Ok(PcodeExpr::Integer(value))
                }
            }
            ty if SleighParser::is_identifier_like(ty) => {
                let name = self.parse_identifier()?;
                if self.eat(TokenType::Colon) {
                    let size = self.parse_constant()?;
                    Ok(PcodeExpr::SizedId { name, size })
                } else {
                    Ok(PcodeExpr::Identifier(name))
                }
            }
            _ => Err(self.err_here("expected expression term")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parses `input` as the inside of a semantic body (the caller-consumed
    /// `{` omitted, closing `}` required).
    fn body(input: &str) -> SemanticBody {
        let mut lexer = BaseLexer::new(input);
        let parsed = SemanticParser::new(&mut lexer)
            .parse_semantic()
            .unwrap_or_else(|e| panic!("parse failed on {input:?}: {e}"));
        assert!(lexer.errors().is_empty(), "lexing errors: {:?}", lexer.errors());
        parsed
    }

    fn one_stmt(input: &str) -> PcodeStmt {
        let mut b = body(input);
        assert_eq!(b.statements.len(), 1, "statements: {:?}", b.statements);
        b.statements.remove(0)
    }

    fn expr_of(input: &str) -> PcodeExpr {
        match one_stmt(&format!("x = {input}; }}")) {
            PcodeStmt::Assign { rhs, .. } => rhs,
            other => panic!("unexpected stmt: {other:?}"),
        }
    }

    fn int(value: i64) -> PcodeExpr {
        PcodeExpr::Integer(Integer { value, radix: 10 })
    }

    #[test]
    fn empty_body_is_nop() {
        assert_eq!(body("}").statements, vec![]);
    }

    #[test]
    fn simple_assignment() {
        assert_eq!(
            one_stmt("A = B; }"),
            PcodeStmt::Assign {
                local: false,
                lvalue: Lvalue::Id("A".into()),
                rhs: PcodeExpr::Identifier("B".into()),
            }
        );
    }

    #[test]
    fn sized_declarative_assignment() {
        assert_eq!(
            one_stmt("tmp:2 = inst_next; }"),
            PcodeStmt::Assign {
                local: false,
                lvalue: Lvalue::SizedId {
                    name: "tmp".into(),
                    size: Integer { value: 2, radix: 10 },
                },
                rhs: PcodeExpr::Identifier("inst_next".into()),
            }
        );
    }

    #[test]
    fn bitrange_assignment() {
        assert_eq!(
            one_stmt("F[6,1] = 1; }"),
            PcodeStmt::Assign {
                local: false,
                lvalue: Lvalue::BitRange {
                    name: "F".into(),
                    lsb: Integer { value: 6, radix: 10 },
                    size: Integer { value: 1, radix: 10 },
                },
                rhs: int(1),
            }
        );
    }

    #[test]
    fn local_declarations_and_assignments() {
        assert_eq!(
            one_stmt("local x; }"),
            PcodeStmt::LocalDecl {
                name: "x".into(),
                size: None
            }
        );
        assert_eq!(
            one_stmt("local x:4; }"),
            PcodeStmt::LocalDecl {
                name: "x".into(),
                size: Some(Integer { value: 4, radix: 10 })
            }
        );
        assert_eq!(
            one_stmt("local notC = ~CY_flag; }"),
            PcodeStmt::Assign {
                local: true,
                lvalue: Lvalue::Id("notC".into()),
                rhs: PcodeExpr::Unary {
                    op: PcodeUnaryOp::Invert,
                    operand: Box::new(PcodeExpr::Identifier("CY_flag".into())),
                },
            }
        );
        assert_eq!(
            one_stmt("local t:1 = 0x7f; }"),
            PcodeStmt::Assign {
                local: true,
                lvalue: Lvalue::SizedId {
                    name: "t".into(),
                    size: Integer { value: 1, radix: 10 },
                },
                rhs: PcodeExpr::Integer(Integer {
                    value: 0x7f,
                    radix: 16
                }),
            }
        );
    }

    #[test]
    fn dereference_assignment_with_space_and_size() {
        assert_eq!(
            one_stmt("*[ram]:2 ptr = val; }"),
            PcodeStmt::Assign {
                local: false,
                lvalue: Lvalue::Deref {
                    star: SizedStar {
                        space: Some("ram".into()),
                        size: Some(Integer { value: 2, radix: 10 }),
                    },
                    addr: PcodeExpr::Identifier("ptr".into()),
                },
                rhs: PcodeExpr::Identifier("val".into()),
            }
        );
        // Bare '*' and sized-only '*:n' forms.
        assert!(matches!(
            one_stmt("*ptr = 1; }"),
            PcodeStmt::Assign {
                lvalue: Lvalue::Deref {
                    star: SizedStar {
                        space: None,
                        size: None
                    },
                    ..
                },
                ..
            }
        ));
        assert!(matches!(
            one_stmt("*:2 SP = HL; }"),
            PcodeStmt::Assign {
                lvalue: Lvalue::Deref {
                    star: SizedStar {
                        space: None,
                        size: Some(Integer { value: 2, .. })
                    },
                    ..
                },
                ..
            }
        ));
    }

    #[test]
    fn dereference_load_in_expression() {
        assert_eq!(
            expr_of("*:1 HL"),
            PcodeExpr::Deref {
                star: SizedStar {
                    space: None,
                    size: Some(Integer { value: 1, radix: 10 }),
                },
                operand: Box::new(PcodeExpr::Identifier("HL".into())),
            }
        );
    }

    #[test]
    fn build_statement() {
        assert_eq!(
            one_stmt("build op1; }"),
            PcodeStmt::Build {
                operand: "op1".into()
            }
        );
    }

    #[test]
    fn crossbuild_statement() {
        assert_eq!(
            one_stmt("crossbuild inst_start, other; }"),
            PcodeStmt::CrossBuild {
                address: PcodeExpr::Identifier("inst_start".into()),
                section: "other".into(),
            }
        );
    }

    #[test]
    fn goto_forms() {
        assert_eq!(
            one_stmt("goto inst_start; }"),
            PcodeStmt::Goto {
                dest: JumpDest::Symbol("inst_start".into())
            }
        );
        assert_eq!(
            one_stmt("goto [HL]; }"),
            PcodeStmt::Goto {
                dest: JumpDest::Dynamic(PcodeExpr::Identifier("HL".into()))
            }
        );
        assert_eq!(
            one_stmt("goto 0x100; }"),
            PcodeStmt::Goto {
                dest: JumpDest::Absolute(Integer {
                    value: 0x100,
                    radix: 16
                })
            }
        );
        assert_eq!(
            one_stmt("goto 8[ram]; }"),
            PcodeStmt::Goto {
                dest: JumpDest::Relative {
                    offset: Integer { value: 8, radix: 10 },
                    space: "ram".into(),
                }
            }
        );
        assert_eq!(
            one_stmt("goto <skip>; }"),
            PcodeStmt::Goto {
                dest: JumpDest::Label("skip".into())
            }
        );
    }

    #[test]
    fn label_statement_takes_no_semicolon() {
        assert_eq!(
            body("<loop> goto <loop>; }").statements,
            vec![
                PcodeStmt::Label {
                    name: "loop".into()
                },
                PcodeStmt::Goto {
                    dest: JumpDest::Label("loop".into())
                },
            ]
        );
    }

    #[test]
    fn section_label() {
        assert_eq!(
            one_stmt("<<extra>> }"),
            PcodeStmt::SectionLabel {
                name: "extra".into()
            }
        );
    }

    #[test]
    fn if_goto_statement() {
        assert_eq!(
            one_stmt("if (cc) goto Addr16; }"),
            PcodeStmt::IfGoto {
                cond: PcodeExpr::Parenthesized(Box::new(PcodeExpr::Identifier("cc".into()))),
                dest: JumpDest::Symbol("Addr16".into()),
            }
        );
        // Unparenthesized condition with a semantic-only operator.
        assert_eq!(
            one_stmt("if A s< 0 goto <neg>; }"),
            PcodeStmt::IfGoto {
                cond: PcodeExpr::Binary {
                    op: PcodeBinOp::SLess,
                    lhs: Box::new(PcodeExpr::Identifier("A".into())),
                    rhs: Box::new(int(0)),
                },
                dest: JumpDest::Label("neg".into()),
            }
        );
    }

    #[test]
    fn call_and_return() {
        assert_eq!(
            one_stmt("call Addr16; }"),
            PcodeStmt::Call {
                dest: JumpDest::Symbol("Addr16".into())
            }
        );
        assert_eq!(
            one_stmt("call [ptr]; }"),
            PcodeStmt::Call {
                dest: JumpDest::Dynamic(PcodeExpr::Identifier("ptr".into()))
            }
        );
        assert_eq!(
            one_stmt("return [tmp]; }"),
            PcodeStmt::Return {
                dest: PcodeExpr::Identifier("tmp".into())
            }
        );
    }

    #[test]
    fn export_forms() {
        assert_eq!(
            one_stmt("export Z_flag; }"),
            PcodeStmt::Export(Export::Varnode(PcodeExpr::Identifier("Z_flag".into())))
        );
        assert_eq!(
            one_stmt("export *[io]:1 imm8; }"),
            PcodeStmt::Export(Export::Sized {
                star: SizedStar {
                    space: Some("io".into()),
                    size: Some(Integer { value: 1, radix: 10 }),
                },
                name: "imm8".into(),
            })
        );
        assert_eq!(
            one_stmt("export *:1 imm16; }"),
            PcodeStmt::Export(Export::Sized {
                star: SizedStar {
                    space: None,
                    size: Some(Integer { value: 1, radix: 10 }),
                },
                name: "imm16".into(),
            })
        );
        // Sized/constant varnode exports.
        assert_eq!(
            one_stmt("export 5:2; }"),
            PcodeStmt::Export(Export::Varnode(PcodeExpr::Truncation {
                value: Integer { value: 5, radix: 10 },
                size: Integer { value: 2, radix: 10 },
            }))
        );
    }

    #[test]
    fn macro_style_funcall() {
        assert_eq!(
            one_stmt("push16(tmp); }"),
            PcodeStmt::Funcall {
                name: "push16".into(),
                args: vec![PcodeExpr::Identifier("tmp".into())],
            }
        );
        assert_eq!(
            one_stmt("disableMaskableInterrupts(); }"),
            PcodeStmt::Funcall {
                name: "disableMaskableInterrupts".into(),
                args: vec![],
            }
        );
    }

    #[test]
    fn apply_in_expression() {
        assert_eq!(
            expr_of("carry(op1, zext(CY_flag))"),
            PcodeExpr::Apply {
                name: "carry".into(),
                args: vec![
                    PcodeExpr::Identifier("op1".into()),
                    PcodeExpr::Apply {
                        name: "zext".into(),
                        args: vec![PcodeExpr::Identifier("CY_flag".into())],
                    },
                ],
            }
        );
    }

    #[test]
    fn address_of_forms() {
        assert_eq!(
            expr_of("&A"),
            PcodeExpr::AddressOf {
                size: None,
                operand: Box::new(PcodeExpr::Identifier("A".into())),
            }
        );
        assert_eq!(
            expr_of("&:4 A"),
            PcodeExpr::AddressOf {
                size: Some(Integer { value: 4, radix: 10 }),
                operand: Box::new(PcodeExpr::Identifier("A".into())),
            }
        );
    }

    #[test]
    fn truncation_and_bitrange2() {
        assert_eq!(
            expr_of("0x1234:2"),
            PcodeExpr::Truncation {
                value: Integer {
                    value: 0x1234,
                    radix: 16
                },
                size: Integer { value: 2, radix: 10 },
            }
        );
        assert_eq!(
            expr_of("val:1"),
            PcodeExpr::SizedId {
                name: "val".into(),
                size: Integer { value: 1, radix: 10 },
            }
        );
        assert_eq!(
            expr_of("F[0,1]"),
            PcodeExpr::BitRange {
                name: "F".into(),
                lsb: Integer { value: 0, radix: 10 },
                size: Integer { value: 1, radix: 10 },
            }
        );
    }

    #[test]
    fn dec_int_literal_is_int_lit_only() {
        // int_lit admits 0n...; the sizes (constant rule) do not.
        assert_eq!(expr_of("0n42"), int(42));
        let mut lexer = BaseLexer::new("x = 1:0n2; }");
        assert!(SemanticParser::new(&mut lexer).parse_semantic().is_err());
    }

    #[test]
    fn precedence_mult_over_add() {
        assert_eq!(
            expr_of("1 + 2 * 3"),
            PcodeExpr::Binary {
                op: PcodeBinOp::Add,
                lhs: Box::new(int(1)),
                rhs: Box::new(PcodeExpr::Binary {
                    op: PcodeBinOp::Mult,
                    lhs: Box::new(int(2)),
                    rhs: Box::new(int(3)),
                }),
            }
        );
    }

    #[test]
    fn precedence_full_ladder() {
        // a || b && c | d ^ e & f == g < h << i + j * k nests strictly
        // rightward: each operator binds tighter than the one to its left.
        let e = expr_of("a || b && c | d ^ e & f == g < h << i + j * k");
        use PcodeBinOp::*;
        let mut expected_ops = vec![
            BoolOr, BoolAnd, Or, Xor, And, Equal, Less, Left, Add, Mult,
        ];
        let mut cur = e;
        while let PcodeExpr::Binary { op, rhs, .. } = cur {
            assert_eq!(op, expected_ops.remove(0));
            cur = *rhs;
        }
        assert!(expected_ops.is_empty(), "missing ops: {expected_ops:?}");
        assert_eq!(cur, PcodeExpr::Identifier("k".into()));
    }

    #[test]
    fn same_level_operators_associate_left() {
        // '&&' and '^^' share the booland level; '+' and '-' share add.
        assert_eq!(
            expr_of("a && b ^^ c"),
            PcodeExpr::Binary {
                op: PcodeBinOp::BoolXor,
                lhs: Box::new(PcodeExpr::Binary {
                    op: PcodeBinOp::BoolAnd,
                    lhs: Box::new(PcodeExpr::Identifier("a".into())),
                    rhs: Box::new(PcodeExpr::Identifier("b".into())),
                }),
                rhs: Box::new(PcodeExpr::Identifier("c".into())),
            }
        );
        assert_eq!(
            expr_of("a - b + c"),
            PcodeExpr::Binary {
                op: PcodeBinOp::Add,
                lhs: Box::new(PcodeExpr::Binary {
                    op: PcodeBinOp::Sub,
                    lhs: Box::new(PcodeExpr::Identifier("a".into())),
                    rhs: Box::new(PcodeExpr::Identifier("b".into())),
                }),
                rhs: Box::new(PcodeExpr::Identifier("c".into())),
            }
        );
    }

    #[test]
    fn signed_and_float_variants_sit_on_their_levels() {
        // s< at comparison level, s>> at shift level, f+ at add level,
        // s% at mult level.
        assert_eq!(
            expr_of("a s< b s>> c f+ d s% e"),
            PcodeExpr::Binary {
                op: PcodeBinOp::SLess,
                lhs: Box::new(PcodeExpr::Identifier("a".into())),
                rhs: Box::new(PcodeExpr::Binary {
                    op: PcodeBinOp::SRight,
                    lhs: Box::new(PcodeExpr::Identifier("b".into())),
                    rhs: Box::new(PcodeExpr::Binary {
                        op: PcodeBinOp::FAdd,
                        lhs: Box::new(PcodeExpr::Identifier("c".into())),
                        rhs: Box::new(PcodeExpr::Binary {
                            op: PcodeBinOp::SRem,
                            lhs: Box::new(PcodeExpr::Identifier("d".into())),
                            rhs: Box::new(PcodeExpr::Identifier("e".into())),
                        }),
                    }),
                }),
            }
        );
    }

    #[test]
    fn unary_operators() {
        assert_eq!(
            expr_of("!cc"),
            PcodeExpr::Unary {
                op: PcodeUnaryOp::Not,
                operand: Box::new(PcodeExpr::Identifier("cc".into())),
            }
        );
        assert_eq!(
            expr_of("-1"),
            PcodeExpr::Unary {
                op: PcodeUnaryOp::Negate,
                operand: Box::new(int(1)),
            }
        );
        assert_eq!(
            expr_of("f- x"),
            PcodeExpr::Unary {
                op: PcodeUnaryOp::FNegate,
                operand: Box::new(PcodeExpr::Identifier("x".into())),
            }
        );
        // Unary binds tighter than binary: -a + b is (-a) + b.
        assert_eq!(
            expr_of("-a + b"),
            PcodeExpr::Binary {
                op: PcodeBinOp::Add,
                lhs: Box::new(PcodeExpr::Unary {
                    op: PcodeUnaryOp::Negate,
                    operand: Box::new(PcodeExpr::Identifier("a".into())),
                }),
                rhs: Box::new(PcodeExpr::Identifier("b".into())),
            }
        );
    }

    #[test]
    fn double_unary_requires_parentheses() {
        // `unary_op? expr_func`: at most one unary operator per the grammar.
        let mut lexer = BaseLexer::new("x = --a; }");
        assert!(SemanticParser::new(&mut lexer).parse_semantic().is_err());
        assert_eq!(
            expr_of("-(-a)"),
            PcodeExpr::Unary {
                op: PcodeUnaryOp::Negate,
                operand: Box::new(PcodeExpr::Parenthesized(Box::new(PcodeExpr::Unary {
                    op: PcodeUnaryOp::Negate,
                    operand: Box::new(PcodeExpr::Identifier("a".into())),
                }))),
            }
        );
    }

    #[test]
    fn deref_is_unary_within_binary_expression() {
        // A & *:1 HL == A & (*(HL)).
        assert_eq!(
            expr_of("A & *:1 HL"),
            PcodeExpr::Binary {
                op: PcodeBinOp::And,
                lhs: Box::new(PcodeExpr::Identifier("A".into())),
                rhs: Box::new(PcodeExpr::Deref {
                    star: SizedStar {
                        space: None,
                        size: Some(Integer { value: 1, radix: 10 }),
                    },
                    operand: Box::new(PcodeExpr::Identifier("HL".into())),
                }),
            }
        );
    }

    #[test]
    fn keywords_are_identifiers_in_semantic_bodies() {
        // 'export' as an operand name being assigned (key_as_id).
        assert_eq!(
            one_stmt("export = 1; }"),
            PcodeStmt::Assign {
                local: false,
                lvalue: Lvalue::Id("export".into()),
                rhs: int(1),
            }
        );
        // keyword-named macro invocation.
        assert_eq!(
            one_stmt("call(A); }"),
            PcodeStmt::Funcall {
                name: "call".into(),
                args: vec![PcodeExpr::Identifier("A".into())],
            }
        );
    }

    #[test]
    fn multi_statement_body() {
        let b = body(
            "nextC:1 = (A >> 7);\n\
             A = (A << 1) | CY_flag;\n\
             CY_flag = nextC;\n\
             AC_flag = 0;\n}",
        );
        assert_eq!(b.statements.len(), 4);
        assert!(matches!(
            &b.statements[1],
            PcodeStmt::Assign {
                rhs: PcodeExpr::Binary {
                    op: PcodeBinOp::Or,
                    ..
                },
                ..
            }
        ));
    }

    #[test]
    fn empty_statement_is_an_error() {
        let mut lexer = BaseLexer::new("; }");
        let err = SemanticParser::new(&mut lexer).parse_semantic().unwrap_err();
        assert!(err.message.contains("empty statement"), "{err}");
    }

    #[test]
    fn stray_operator_is_an_error() {
        // The grammar's `outererror` alternative.
        let mut lexer = BaseLexer::new("== ; }");
        let err = SemanticParser::new(&mut lexer).parse_semantic().unwrap_err();
        assert!(err.message.contains("unexpected"), "{err}");
    }

    #[test]
    fn unterminated_body_is_an_error() {
        let mut lexer = BaseLexer::new("A = B;");
        let err = SemanticParser::new(&mut lexer).parse_semantic().unwrap_err();
        assert!(err.message.contains("unterminated"), "{err}");
    }

    #[test]
    fn missing_semicolon_is_an_error() {
        let mut lexer = BaseLexer::new("A = B }");
        let err = SemanticParser::new(&mut lexer).parse_semantic().unwrap_err();
        assert!(err.message.contains("';'"), "{err}");
    }
}
